from __future__ import annotations

"""Ignore-list loading and finding-level filtering logic."""

import json
from pathlib import Path

from dep_scanner.models import VulnerabilityFinding


def load_ignore_rules(ignore_file: Path | None) -> tuple[set[str], set[tuple[str, str, str]]]:
    """Load ignored advisory IDs/CVEs and package triplets from JSON."""
    if not ignore_file:
        return set(), set()
    if not ignore_file.exists():
        return set(), set()

    payload = json.loads(ignore_file.read_text(encoding="utf-8"))
    ignored_advisories = {
        str(advisory_id).strip().upper()
        for advisory_id in payload.get("ignore_advisories", [])
        if str(advisory_id).strip()
    }

    ignored_packages: set[tuple[str, str, str]] = set()
    for package in payload.get("ignore_packages", []):
        if not isinstance(package, dict):
            continue
        ecosystem = str(package.get("ecosystem", "")).strip()
        name = str(package.get("name", "")).strip().lower()
        version = str(package.get("version", "")).strip()
        if ecosystem and name and version:
            ignored_packages.add((ecosystem, name, version))

    return ignored_advisories, ignored_packages


def apply_ignore_rules(
    findings: list[VulnerabilityFinding],
    ignored_advisories: set[str],
    ignored_packages: set[tuple[str, str, str]],
) -> list[VulnerabilityFinding]:
    """Drop findings matching ignored packages or advisory identifiers."""
    filtered_findings: list[VulnerabilityFinding] = []
    for finding in findings:
        package_key = (
            finding.dependency.ecosystem,
            finding.dependency.name.lower(),
            finding.dependency.version,
        )
        if package_key in ignored_packages:
            continue

        filtered_advisories = [
            advisory
            for advisory in finding.advisories
            if advisory.advisory_id.upper() not in ignored_advisories
            and not any(cve_id.upper() in ignored_advisories for cve_id in advisory.cve_ids)
        ]
        if not filtered_advisories:
            continue
        filtered_findings.append(
            VulnerabilityFinding(
                dependency=finding.dependency,
                advisories=filtered_advisories,
            )
        )
    return filtered_findings

