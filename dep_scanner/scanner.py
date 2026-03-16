from __future__ import annotations

"""Top-level scan orchestration and report assembly."""

from datetime import UTC, datetime
from pathlib import Path

import httpx

from dep_scanner.ignore_rules import apply_ignore_rules, load_ignore_rules
from dep_scanner.maintenance import build_package_health
from dep_scanner.models import ScanReport, ScanSummary, VulnerabilityFinding
from dep_scanner.providers.github_client import query_github_advisories
from dep_scanner.providers.osv_client import query_osv
from dep_scanner.resolver import resolve_dependencies


def run_scan(
    *,
    input_paths: list[Path],
    ignore_file: Path | None,
    months_unmaintained: int,
    github_token: str | None = None,
) -> ScanReport:
    """Resolve packages, query providers, apply ignores, and build a final report."""
    existing_paths = [path for path in input_paths if path.exists()]
    warnings: list[str] = []
    if len(existing_paths) < len(input_paths):
        warnings.append("Some input paths do not exist and were skipped.")

    with httpx.Client(follow_redirects=True) as http_client:
        dependencies, resolver_warnings = resolve_dependencies(existing_paths, http_client)
        warnings.extend(resolver_warnings)

        osv_results = query_osv(dependencies, http_client)
        github_results = query_github_advisories(dependencies, http_client, github_token=github_token)
        findings: list[VulnerabilityFinding] = []
        for dependency in dependencies:
            dependency_key = (dependency.ecosystem, dependency.name.lower(), dependency.version)
            advisories = []
            advisories.extend(osv_results.get(dependency_key, []))
            advisories.extend(github_results.get(dependency_key, []))
            deduped_advisories = dedupe_advisories(advisories)
            if deduped_advisories:
                findings.append(VulnerabilityFinding(dependency=dependency, advisories=deduped_advisories))

        ignored_advisories, ignored_packages = load_ignore_rules(ignore_file)
        filtered_findings = apply_ignore_rules(findings, ignored_advisories, ignored_packages)
        package_health = build_package_health(dependencies, months_unmaintained, http_client)

    total_dependencies = len(dependencies)
    vulnerable_dependencies = len(filtered_findings)
    vulnerable_percentage = (
        (vulnerable_dependencies / total_dependencies) * 100 if total_dependencies else 0.0
    )
    unmaintained_dependencies = sum(1 for item in package_health if item.is_unmaintained)

    summary = ScanSummary(
        total_dependencies=total_dependencies,
        vulnerable_dependencies=vulnerable_dependencies,
        vulnerable_percentage=vulnerable_percentage,
        unmaintained_dependencies=unmaintained_dependencies,
    )
    return ScanReport(
        generated_at=datetime.now(tz=UTC).isoformat(),
        findings=filtered_findings,
        package_health=package_health,
        summary=summary,
        warnings=warnings,
    )


def dedupe_advisories(advisories: list) -> list:
    """Deduplicate advisories by advisory ID while keeping latest payload."""
    deduped = {}
    for advisory in advisories:
        deduped[advisory.advisory_id] = advisory
    return list(deduped.values())

