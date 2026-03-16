from __future__ import annotations

"""Package maintenance checks based on release recency."""

from datetime import UTC, datetime

import httpx

from dep_scanner.models import Dependency, PackageHealth


def build_package_health(
    dependencies: list[Dependency],
    months_unmaintained: int,
    http_client: httpx.Client,
) -> list[PackageHealth]:
    """Build per-package maintenance flags using latest release timestamps."""
    health_report: list[PackageHealth] = []
    for dependency in dependencies:
        last_release_at = fetch_last_release_timestamp(dependency, http_client)
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


def fetch_last_release_timestamp(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Dispatch ecosystem-specific logic for release timestamp lookup."""
    if dependency.ecosystem == "PyPI":
        return fetch_pypi_release(dependency, http_client)
    if dependency.ecosystem == "npm":
        return fetch_npm_release(dependency, http_client)
    if dependency.ecosystem == "crates.io":
        return fetch_crates_release(dependency, http_client)
    return None


def fetch_pypi_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch release timestamp for a pinned PyPI package version."""
    response = http_client.get(f"https://pypi.org/pypi/{dependency.name}/{dependency.version}/json", timeout=20.0)
    if response.status_code != 200:
        return None
    payload = response.json()
    urls = payload.get("urls", [])
    if not urls:
        return None
    upload_time = urls[0].get("upload_time_iso_8601")
    if not upload_time:
        return None
    return parse_timestamp(upload_time)


def fetch_npm_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch release timestamp for an npm package version."""
    response = http_client.get(f"https://registry.npmjs.org/{dependency.name}", timeout=20.0)
    if response.status_code != 200:
        return None
    payload = response.json()
    time_payload = payload.get("time", {})
    release_timestamp = time_payload.get(dependency.version)
    if not release_timestamp:
        release_timestamp = time_payload.get("modified")
    if not release_timestamp:
        return None
    return parse_timestamp(release_timestamp)


def fetch_crates_release(dependency: Dependency, http_client: httpx.Client) -> datetime | None:
    """Fetch release timestamp for a Rust crate version from crates.io."""
    response = http_client.get(f"https://crates.io/api/v1/crates/{dependency.name}", timeout=20.0)
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


def parse_timestamp(value: str) -> datetime | None:
    """Parse ISO-like timestamps returned by provider APIs."""
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def months_between(older: datetime, newer: datetime) -> int:
    """Compute full-month difference between two datetimes."""
    day_adjust = 1 if newer.day >= older.day else 0
    return max(0, (newer.year - older.year) * 12 + (newer.month - older.month) - (1 - day_adjust))

