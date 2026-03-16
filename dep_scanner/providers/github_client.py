from __future__ import annotations

"""GitHub Security Advisories client and version-range matchers."""

import httpx
import re
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from semantic_version import NpmSpec, Version as SemVersion

from dep_scanner.models import Advisory, Dependency

GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "pip",
    "crates.io": "rust",
}

SEMVER_ECOSYSTEMS = {"npm", "crates.io"}


def query_github_advisories(
    dependencies: list[Dependency],
    http_client: httpx.Client,
    github_token: str | None = None,
) -> dict[tuple[str, str, str], list[Advisory]]:
    """Fetch GH advisories and keep only ones affecting the exact package version."""
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    advisories_by_dependency: dict[tuple[str, str, str], list[Advisory]] = {}

    for dependency in dependencies:
        ecosystem = ECOSYSTEM_MAP.get(dependency.ecosystem)
        if not ecosystem:
            advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = []
            continue

        response = http_client.get(
            GITHUB_ADVISORY_URL,
            params={"ecosystem": ecosystem, "affects": dependency.name, "per_page": 100},
            headers=headers,
            timeout=30.0,
        )
        if response.status_code != 200:
            advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = []
            continue

        payload = response.json()
        advisories: list[Advisory] = []
        if not isinstance(payload, list):
            advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = advisories
            continue

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
                patched = vulnerability.get("first_patched_version")
                if isinstance(patched, dict):
                    identifier = patched.get("identifier")
                    if identifier:
                        fixed_versions.append(str(identifier))

            cve_id = advisory_payload.get("cve_id")
            cve_ids = [str(cve_id)] if cve_id else []
            ghsa_id = str(advisory_payload.get("ghsa_id", "GHSA-UNKNOWN"))
            reference_url = str(advisory_payload.get("html_url", ""))
            advisories.append(
                Advisory(
                    advisory_id=ghsa_id,
                    source="GitHub Security Advisories",
                    severity=str(advisory_payload.get("severity", "UNKNOWN")).upper(),
                    cve_ids=cve_ids,
                    summary=str(advisory_payload.get("summary", "")),
                    details=str(advisory_payload.get("description", "")),
                    reference_url=reference_url,
                    fixed_versions=sorted(set(fixed_versions)),
                )
            )

        advisories_by_dependency[(dependency.ecosystem, dependency.name.lower(), dependency.version)] = advisories

    return advisories_by_dependency


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
    parts = version.strip().split(".")
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

