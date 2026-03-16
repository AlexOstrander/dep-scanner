from __future__ import annotations

"""GitHub Security Advisories client and version-range matchers."""

import httpx
import re
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from semantic_version import NpmSpec, Version as SemVersion

from dep_scanner.models import Advisory, Dependency

GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_PER_PAGE = 100
GITHUB_MAX_PAGES = 10

ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "pip",
    "crates.io": "rust",
    "Go": "go",
    "Packagist": "composer",
}

SEMVER_ECOSYSTEMS = {"npm", "crates.io", "Go"}


def query_github_advisories(
    dependencies: list[Dependency],
    http_client: httpx.Client,
    github_token: str | None = None,
) -> dict[tuple[str, str, str], list[Advisory]]:
    """Fetch GH advisories and keep only ones affecting the exact package version."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "dep-scanner/0.1",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    advisories_by_dependency: dict[tuple[str, str, str], list[Advisory]] = {}

    for dependency in dependencies:
        ecosystem = ECOSYSTEM_MAP.get(dependency.ecosystem)
        if not ecosystem:
            advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = []
            continue

        payload = fetch_global_advisories_for_package(
            ecosystem=ecosystem,
            package_name=dependency.name,
            http_client=http_client,
            headers=headers,
        )
        advisories: list[Advisory] = []

        for advisory_payload in payload:
            vulnerability_specs = extract_package_specs(advisory_payload, dependency.name)
            if not vulnerability_specs:
                continue
            if not is_dependency_vulnerable(
                version=dependency.version,
                ecosystem=dependency.ecosystem,
                vulnerability_specs=vulnerability_specs,
            ):
                continue

            fixed_versions: list[str] = []
            for vulnerability in advisory_payload.get("vulnerabilities", []):
                package_payload = vulnerability.get("package", {})
                if not isinstance(package_payload, dict):
                    continue
                package_name = str(package_payload.get("name", ""))
                if package_name.lower() != dependency.name.lower():
                    continue
                fixed_versions.extend(extract_fixed_versions_from_github_vulnerability(vulnerability))

            cve_ids = extract_cve_ids(advisory_payload)
            ghsa_id = str(advisory_payload.get("ghsa_id", "GHSA-UNKNOWN"))
            reference_url = str(advisory_payload.get("html_url", ""))
            advisories.append(
                Advisory(
                    advisory_id=ghsa_id,
                    source="GitHub Security Advisories",
                    severity=extract_advisory_severity(advisory_payload),
                    cve_ids=cve_ids,
                    summary=str(advisory_payload.get("summary", "")),
                    details=str(advisory_payload.get("description", "")),
                    reference_url=reference_url,
                    fixed_versions=sorted(set(fixed_versions)),
                )
            )

        advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = advisories

    return advisories_by_dependency


def fetch_global_advisories_for_package(
    *,
    ecosystem: str,
    package_name: str,
    http_client: httpx.Client,
    headers: dict[str, str],
) -> list[dict]:
    """Paginate global advisory results for an ecosystem/package filter."""
    advisories: list[dict] = []
    for page in range(1, GITHUB_MAX_PAGES + 1):
        response = http_client.get(
            GITHUB_ADVISORY_URL,
            params={
                "ecosystem": ecosystem,
                "affects": package_name,
                "per_page": GITHUB_PER_PAGE,
                "page": page,
            },
            headers=headers,
            timeout=30.0,
        )
        if response.status_code != 200:
            return advisories

        payload = response.json()
        if not isinstance(payload, list):
            return advisories
        advisories.extend(payload)
        if len(payload) < GITHUB_PER_PAGE:
            break
    return advisories


def extract_cve_ids(advisory_payload: dict) -> list[str]:
    """Collect CVE IDs from cve_id and identifiers arrays."""
    cve_ids: set[str] = set()
    cve_id = advisory_payload.get("cve_id")
    if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
        cve_ids.add(cve_id)

    identifiers = advisory_payload.get("identifiers", [])
    if isinstance(identifiers, list):
        for identifier in identifiers:
            if not isinstance(identifier, dict):
                continue
            value = identifier.get("value")
            if isinstance(value, str) and value.startswith("CVE-"):
                cve_ids.add(value)
    return sorted(cve_ids)


def extract_fixed_versions_from_github_vulnerability(vulnerability: dict) -> list[str]:
    """Extract fixed/patch versions from GitHub advisory vulnerability payload."""
    fixed_versions: list[str] = []
    patched = vulnerability.get("first_patched_version")
    if isinstance(patched, str):
        fixed_versions.append(patched)
    elif isinstance(patched, dict):
        identifier = patched.get("identifier")
        if identifier:
            fixed_versions.append(str(identifier))

    patched_many = vulnerability.get("first_patched_versions")
    if isinstance(patched_many, list):
        for patched_item in patched_many:
            if not isinstance(patched_item, dict):
                continue
            identifier = patched_item.get("identifier")
            if identifier:
                fixed_versions.append(str(identifier))

    patched_versions = vulnerability.get("patched_versions")
    if isinstance(patched_versions, str):
        fixed_versions.extend(extract_versions_from_spec_text(patched_versions))
    elif isinstance(patched_versions, list):
        for patched_entry in patched_versions:
            if isinstance(patched_entry, str):
                fixed_versions.extend(extract_versions_from_spec_text(patched_entry))
            elif isinstance(patched_entry, dict):
                patched_value = patched_entry.get("identifier") or patched_entry.get("version")
                if patched_value:
                    fixed_versions.append(str(patched_value))
    return fixed_versions


def extract_versions_from_spec_text(spec_text: str) -> list[str]:
    """Extract version-like values from range text such as '>= 1.2.3'."""
    return re.findall(r"(?<![A-Za-z0-9])(?:\d+!)?\d+(?:\.\d+)*(?:[a-zA-Z0-9._+-]*)", spec_text)


def extract_package_specs(advisory_payload: dict, dependency_name: str) -> list[str]:
    """Extract vulnerable version-range strings for one package."""
    specs: list[str] = []
    for vulnerability in advisory_payload.get("vulnerabilities", []):
        package_payload = vulnerability.get("package", {})
        if not isinstance(package_payload, dict):
            continue
        package_name = str(package_payload.get("name", ""))
        if package_name.lower() != dependency_name.lower():
            continue
        version_range = vulnerability.get("vulnerable_version_range")
        if version_range:
            specs.append(str(version_range))
    return specs


def is_dependency_vulnerable(version: str, ecosystem: str, vulnerability_specs: list[str]) -> bool:
    """Choose ecosystem-appropriate range matching strategy."""
    if ecosystem in SEMVER_ECOSYSTEMS:
        return any(matches_npm_range(version, spec) for spec in vulnerability_specs)
    return any(matches_pep440_range(version, spec) for spec in vulnerability_specs)


def matches_npm_range(version: str, vulnerability_spec: str) -> bool:
    """Evaluate semver-style ranges used by npm and Rust advisories."""
    candidate = normalize_for_semver(version)
    if candidate is None:
        return False

    try:
        return NpmSpec(vulnerability_spec).match(candidate)
    except ValueError:
        return False


def normalize_for_semver(version: str) -> SemVersion | None:
    """Normalize partial versions (e.g. 1.2) to full semver (1.2.0)."""
    normalized_input = version.strip()
    if normalized_input.startswith("v"):
        normalized_input = normalized_input[1:]
    if normalized_input.endswith("/go.mod"):
        normalized_input = normalized_input[: -len("/go.mod")]
    normalized_input = normalized_input.split("+", 1)[0]
    normalized_input = normalized_input.split("-", 1)[0]
    parts = normalized_input.split(".")
    while len(parts) < 3:
        parts.append("0")
    normalized = ".".join(parts[:3])
    try:
        return SemVersion(normalized)
    except ValueError:
        return None


def matches_pep440_range(version: str, vulnerability_spec: str) -> bool:
    """Evaluate PEP440 ranges used by Python advisories."""
    try:
        candidate_version = Version(version)
    except InvalidVersion:
        return False

    for split_spec in vulnerability_spec.split("||"):
        normalized = normalize_pep440_spec(split_spec)
        if not normalized:
            continue
        try:
            specifier_set = SpecifierSet(normalized)
        except InvalidSpecifier:
            continue
        if candidate_version in specifier_set:
            return True
    return False


def normalize_pep440_spec(value: str) -> str:
    """Normalize mixed whitespace/comma separators into packaging-friendly specs."""
    cleaned = re.sub(r"\s*,\s*", ",", value.strip())
    cleaned = re.sub(r"([<>=!~])\s+", r"\1", cleaned)
    cleaned = re.sub(r"\s+([<>=!~])", r",\1", cleaned)
    return cleaned.strip(",")


def extract_advisory_severity(advisory_payload: dict) -> str:
    """Choose severity from advisory level, then CVSS score when available."""
    severity = advisory_payload.get("severity")
    if isinstance(severity, str) and severity.strip():
        return severity.strip().upper()

    cvss_payload = advisory_payload.get("cvss", {})
    if isinstance(cvss_payload, dict):
        score_value = cvss_payload.get("score")
        try:
            score = float(score_value)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MODERATE"
            return "LOW"
    return "UNKNOWN"

