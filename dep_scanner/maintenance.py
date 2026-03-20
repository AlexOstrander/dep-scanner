from __future__ import annotations

"""Package maintenance checks based on release recency.

Looks up the **pinned** dependency version's publication or upload time per registry:

- PyPI, npm, crates.io (existing)
- Packagist (p2 API), Go module proxy (``.info``), RubyGems, NuGet (v3 registration),
  pub.dev, Hex.pm, Maven Central (search index timestamp)
- GitHub Actions: GitHub Releases ``published_at`` for ``owner/repo@tag`` (optional token for rate limits)

**SwiftURL** has no stable public “version timestamp” API for arbitrary SPM identities; skipped (no false “healthy”/“stale” signal).
"""

from datetime import UTC, datetime
from collections.abc import Callable
from urllib.parse import quote

import httpx

from dep_scanner.models import Dependency, PackageHealth


def build_package_health(
    dependencies: list[Dependency],
    months_unmaintained: int,
    http_client: httpx.Client,
    *,
    github_token: str | None = None,
) -> list[PackageHealth]:
    """Build per-package maintenance flags using release timestamps for the pinned version."""
    health_report: list[PackageHealth] = []
    for dependency in dependencies:
        last_release_at = fetch_last_release_timestamp(dependency, http_client, github_token=github_token)
        if not last_release_at:
            health_report.append(
                PackageHealth(
                    dependency=dependency,
                    last_release_at=None,
                    is_unmaintained=False,
                    months_since_release=None,
                )
            )
            continue

        months_since_release = months_between(last_release_at, datetime.now(tz=UTC))
        health_report.append(
            PackageHealth(
                dependency=dependency,
                last_release_at=last_release_at,
                is_unmaintained=months_since_release >= months_unmaintained,
                months_since_release=months_since_release,
            )
        )
    return health_report


def fetch_last_release_timestamp(
    dependency: Dependency,
    http_client: httpx.Client,
    *,
    github_token: str | None = None,
) -> datetime | None:
    """Dispatch ecosystem-specific registry API for the exact resolved version."""
    dispatch: dict[str, Callable[[Dependency, httpx.Client], datetime | None]] = {
        "PyPI": fetch_pypi_release,
        "npm": fetch_npm_release,
        "crates.io": fetch_crates_release,
        "Packagist": fetch_packagist_release,
        "Go": fetch_go_proxy_release,
        "RubyGems": fetch_rubygems_release,
        "NuGet": fetch_nuget_release,
        "Pub": fetch_pub_release,
        "Hex": fetch_hex_release,
        "Maven": fetch_maven_release,
        "GitHub Actions": lambda d, c: fetch_github_actions_release(d, c, github_token=github_token),
    }
    fetcher = dispatch.get(dependency.ecosystem)
    if fetcher is None:
        return None
    return fetcher(dependency, http_client)


def github_api_headers(github_token: str | None) -> dict[str, str]:
    """Minimal headers for unauthenticated or token GitHub API calls."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "dep-scanner/0.1",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def fetch_pypi_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch upload time for a pinned PyPI wheel/sdist."""
    response = http_client.get(
        f"https://pypi.org/pypi/{dependency.name}/{dependency.version}/json",
        timeout=20.0,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    urls = payload.get("urls", [])
    if not urls:
        return None
    upload_time = urls[0].get("upload_time_iso_8601")
    if not upload_time:
        return None
    return parse_timestamp(str(upload_time))


def fetch_npm_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch release time for an npm dist-tag / version."""
    encoded_name = quote(dependency.name, safe="")
    response = http_client.get(f"https://registry.npmjs.org/{encoded_name}", timeout=20.0)
    if response.status_code != 200:
        return None
    payload = response.json()
    time_payload = payload.get("time", {})
    release_timestamp = time_payload.get(dependency.version)
    if not release_timestamp:
        release_timestamp = time_payload.get("modified")
    if not release_timestamp:
        return None
    return parse_timestamp(str(release_timestamp))


def fetch_crates_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch `created_at` for a pinned crate version."""
    response = http_client.get(
        f"https://crates.io/api/v1/crates/{dependency.name}",
        timeout=20.0,
        headers={"User-Agent": "dep-scanner/0.1 (maintenance check)"},
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    versions = payload.get("versions", [])
    for version in versions:
        if str(version.get("num")) != dependency.version:
            continue
        created_at = version.get("created_at")
        if created_at:
            return parse_timestamp(str(created_at))
    crate_payload = payload.get("crate", {})
    updated_at = crate_payload.get("updated_at")
    if not updated_at:
        return None
    return parse_timestamp(str(updated_at))


def fetch_packagist_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch release time from Composer's packagist.org p2 JSON."""
    name = dependency.name.strip().lower()
    if "/" not in name:
        return None
    response = http_client.get(
        f"https://repo.packagist.org/p2/{name}.json",
        timeout=20.0,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    packages = payload.get("packages", {})
    versions_list = packages.get(name) or packages.get(dependency.name) or []
    if not isinstance(versions_list, list):
        return None
    for meta in versions_list:
        if not isinstance(meta, dict):
            continue
        if str(meta.get("version", "")).lstrip("v") == dependency.version.lstrip("v"):
            time_value = meta.get("time")
            if time_value:
                return parse_timestamp(str(time_value))
    return None


def escape_go_module_path(module_path: str) -> str:
    """Escape module path segments for proxy.golang.org (uppercase -> !lower)."""
    segments: list[str] = []
    for segment in module_path.strip().split("/"):
        if not segment:
            continue
        escaped: list[str] = []
        for char in segment:
            if char.isupper():
                escaped.append("!")
                escaped.append(char.lower())
            else:
                escaped.append(char)
        segments.append("".join(escaped))
    return "/".join(segments)


def fetch_go_proxy_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch `.info` Time from the Go module proxy for the resolved version."""
    module_path = dependency.name.strip()
    version = dependency.version.strip()
    if not module_path or not version:
        return None
    encoded_path = escape_go_module_path(module_path)
    info_url = f"https://proxy.golang.org/{encoded_path}/@v/{version}.info"
    response = http_client.get(info_url, timeout=20.0)
    if response.status_code != 200 and encoded_path != module_path:
        response = http_client.get(
            f"https://proxy.golang.org/{module_path}/@v/{version}.info",
            timeout=20.0,
        )
    if response.status_code != 200:
        return None
    payload = response.json()
    time_value = payload.get("Time")
    if not time_value:
        return None
    return parse_timestamp(str(time_value))


def fetch_rubygems_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch build time for a gem version via rubygems.org JSON APIs."""
    gem = dependency.name.strip()
    version = dependency.version.strip()
    if not gem or not version:
        return None
    response = http_client.get(
        f"https://rubygems.org/api/v2/rubygems/{quote(gem, safe='')}/versions/{quote(version, safe='')}.json",
        timeout=20.0,
    )
    if response.status_code == 200:
        payload = response.json()
        created = payload.get("created_at")
        if created:
            return parse_timestamp(str(created))

    list_response = http_client.get(
        f"https://rubygems.org/api/v1/versions/{quote(gem, safe='')}.json",
        timeout=20.0,
    )
    if list_response.status_code != 200:
        return None
    for entry in list_response.json():
        if not isinstance(entry, dict):
            continue
        if str(entry.get("number", "")) == version:
            created = entry.get("created_at")
            if created:
                return parse_timestamp(str(created))
    return None


def fetch_nuget_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Find `published` from NuGet v3 registration for the pinned version."""
    package_id = dependency.name.strip()
    version = dependency.version.strip()
    if not package_id or not version:
        return None
    lower_id = package_id.lower()
    registration_url = f"https://api.nuget.org/v3/registration5-gz-semver2/{quote(lower_id, safe='')}/index.json"
    response = http_client.get(registration_url, timeout=30.0)
    if response.status_code != 200:
        return None
    payload = response.json()
    for item in payload.get("items", []):
        for sub in item.get("items") or []:
            catalog = sub.get("catalogEntry") or {}
            if str(catalog.get("version", "")) == version:
                published = catalog.get("published")
                if published:
                    return parse_timestamp(str(published))
        catalog = item.get("catalogEntry") or {}
        if catalog and str(catalog.get("version", "")) == version:
            published = catalog.get("published")
            if published:
                return parse_timestamp(str(published))
    return None


def fetch_pub_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch pub.dev published timestamp for a package version."""
    name = dependency.name.strip()
    version = dependency.version.strip()
    if not name or not version:
        return None
    encoded = quote(name, safe="")
    response = http_client.get(
        f"https://pub.dev/api/packages/{encoded}/versions/{quote(version, safe='')}",
        timeout=20.0,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    published = payload.get("published")
    if not published:
        return None
    return parse_timestamp(str(published))


def fetch_hex_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch Hex.pm `inserted_at` for a package release."""
    name = dependency.name.strip()
    version = dependency.version.strip()
    if not name or not version:
        return None
    response = http_client.get(
        f"https://hex.pm/api/releases/{quote(name, safe='')}/{quote(version, safe='')}",
        timeout=20.0,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    inserted = payload.get("inserted_at")
    if not inserted:
        return None
    return parse_timestamp(str(inserted))


def fetch_maven_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Use Maven Central search index timestamp for g:a:v coordinates."""
    coordinate = dependency.name.strip()
    version = dependency.version.strip()
    if ":" not in coordinate or not version:
        return None
    group_id, _, artifact_id = coordinate.partition(":")
    if not group_id or not artifact_id:
        return None
    query = f'g:"{group_id}"+AND+a:"{artifact_id}"+AND+v:"{version}"'
    response = http_client.get(
        "https://search.maven.org/solrsearch/select",
        params={"q": query, "rows": 1, "wt": "json"},
        timeout=20.0,
    )
    if response.status_code != 200:
        return None
    payload = response.json()
    docs = payload.get("response", {}).get("docs", [])
    if not docs:
        return None
    timestamp_ms = docs[0].get("timestamp")
    if timestamp_ms is None:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp_ms) / 1000.0, tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


def fetch_github_actions_release(
    dependency: Dependency,
    http_client: httpx.Client,
    *,
    github_token: str | None = None,
) -> datetime | None:
    """Use GitHub Releases `published_at` for a tagged action ref (e.g. v4)."""
    name = dependency.name.strip()
    tag = dependency.version.strip()
    if "/" not in name or not tag:
        return None
    headers = github_api_headers(github_token)
    response = http_client.get(
        f"https://api.github.com/repos/{name}/releases/tags/{quote(tag, safe='')}",
        headers=headers,
        timeout=20.0,
    )
    if response.status_code != 200 and tag.startswith("v"):
        response = http_client.get(
            f"https://api.github.com/repos/{name}/releases/tags/{quote(tag[1:], safe='')}",
            headers=headers,
            timeout=20.0,
        )
    if response.status_code != 200:
        return None
    payload = response.json()
    published = payload.get("published_at")
    if not published:
        return None
    return parse_timestamp(str(published))


def parse_timestamp(value: str) -> datetime | None:
    """Parse ISO-like timestamps returned by registry APIs."""
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        return None


def months_between(older: datetime, newer: datetime) -> int:
    """Compute full-month difference between two datetimes (UTC-normalized)."""
    older_utc = older.astimezone(UTC) if older.tzinfo else older.replace(tzinfo=UTC)
    newer_utc = newer.astimezone(UTC) if newer.tzinfo else newer.replace(tzinfo=UTC)
    day_adjust = 1 if newer_utc.day >= older_utc.day else 0
    return max(
        0,
        (newer_utc.year - older_utc.year) * 12 + (newer_utc.month - older_utc.month) - (1 - day_adjust),
    )
