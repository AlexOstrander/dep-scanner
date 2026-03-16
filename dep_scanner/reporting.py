from __future__ import annotations

"""Report rendering utilities for console and JSON outputs."""

import json
import re
from dataclasses import asdict
from pathlib import Path

from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from dep_scanner.models import ScanReport


def render_human_report(
    scan_report: ScanReport,
    console: Console,
    *,
    show_outdated_upgrade_options: bool = False,
) -> None:
    """Render summary and vulnerability tables in a human-readable format."""
    summary_table = Table(title="Dependency Scan Summary", show_header=False)
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    summary_table.add_row("Total dependencies", str(scan_report.summary.total_dependencies))
    summary_table.add_row("Vulnerable dependencies", str(scan_report.summary.vulnerable_dependencies))
    summary_table.add_row(
        "Vulnerable %",
        f"{scan_report.summary.vulnerable_percentage:.2f}%",
    )
    summary_table.add_row("Unmaintained packages", str(scan_report.summary.unmaintained_dependencies))
    console.print(summary_table)

    vulnerabilities_table = Table(title="Vulnerable Packages")
    vulnerabilities_table.add_column("Package", no_wrap=True)
    vulnerabilities_table.add_column("Version", no_wrap=True)
    vulnerabilities_table.add_column("Ecosystem", no_wrap=True)
    vulnerabilities_table.add_column("Severity", overflow="fold")
    vulnerabilities_table.add_column("Advisory IDs / CVEs", overflow="fold")
    vulnerabilities_table.add_column("Remediation", overflow="fold")
    vulnerabilities_table.add_column("Link", overflow="fold")

    for finding in scan_report.findings:
        advisory_ids = []
        cve_ids = []
        severities = []
        links = []
        fixed_versions: list[str] = []
        for advisory in finding.advisories:
            advisory_ids.append(advisory.advisory_id)
            cve_ids.extend(advisory.cve_ids)
            severities.append(advisory.severity)
            if advisory.fixed_versions:
                fixed_versions.extend(advisory.fixed_versions)
            if advisory.reference_url:
                links.append(advisory.reference_url)

        remediation_text = "No fixed version listed"
        if show_outdated_upgrade_options and fixed_versions:
            remediation_text = format_all_upgrade_options(fixed_versions)
        else:
            latest_fixed_version = pick_latest_version(fixed_versions)
            if latest_fixed_version:
                remediation_text = f"Upgrade to {latest_fixed_version}"

        ordered_advisories = dedupe_preserve_order(advisory_ids)
        ordered_cves = dedupe_preserve_order(cve_ids)
        advisory_and_cve_text = "\n".join([*ordered_advisories, *ordered_cves]) or "N/A"
        vulnerabilities_table.add_row(
            finding.dependency.name,
            finding.dependency.version,
            finding.dependency.ecosystem,
            pick_highest_severity(severities),
            advisory_and_cve_text,
            remediation_text,
            format_terminal_links(links),
        )

    if scan_report.findings:
        console.print(vulnerabilities_table)
    else:
        console.print("[green]No vulnerabilities found.[/green]")

    for warning in scan_report.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")


def write_json_report(scan_report: ScanReport, output_path: Path) -> None:
    """Write the structured scan report to a JSON file."""
    payload = asdict(scan_report)
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def format_terminal_links(links: list[str]) -> str:
    """Render clickable terminal hyperlinks with short labels."""
    unique_links = sorted(set(link for link in links if link))
    if not unique_links:
        return "N/A"
    rendered_links = []
    for index, link in enumerate(unique_links, start=1):
        rendered_links.append(f"[link={escape(link)}]ref-{index}[/link]")
    return ", ".join(rendered_links)


def pick_latest_version(versions: list[str]) -> str | None:
    """Pick the highest valid version, falling back to lexical ordering."""
    unique_versions = sorted(set(version.strip() for version in versions if version and version.strip()))
    if not unique_versions:
        return None

    parsed_versions: list[tuple[Version, str]] = []
    for version in unique_versions:
        normalized_version = version.lstrip("v")
        try:
            parsed_versions.append((Version(normalized_version), version))
        except InvalidVersion:
            continue

    if parsed_versions:
        parsed_versions.sort(key=lambda item: item[0])
        return parsed_versions[-1][1]
    return unique_versions[-1]


def format_all_upgrade_options(versions: list[str]) -> str:
    """Render every available fixed version, including older options."""
    unique_versions = sorted(set(version.strip() for version in versions if version and version.strip()))
    if not unique_versions:
        return "No fixed version listed"
    return f"Upgrade options: {', '.join(unique_versions)}"


def dedupe_preserve_order(values: list[str]) -> list[str]:
    """Deduplicate a list while preserving first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def pick_highest_severity(severities: list[str]) -> str:
    """Select the highest severity value from a list."""
    unique_severities = dedupe_preserve_order([severity.strip() for severity in severities if severity and severity.strip()])
    if not unique_severities:
        return "UNKNOWN"
    return max(unique_severities, key=severity_rank)


def severity_rank(value: str) -> tuple[int, float]:
    """Rank severity labels and numeric prefixes so higher is worse."""
    normalized = value.upper()
    if "CRITICAL" in normalized:
        return (5, 0.0)
    if "HIGH" in normalized:
        return (4, 0.0)
    if "MEDIUM" in normalized or "MODERATE" in normalized:
        return (3, 0.0)
    if "LOW" in normalized:
        return (2, 0.0)
    if "UNKNOWN" in normalized:
        return (0, 0.0)

    number_match = re.match(r"^\s*(\d+(?:\.\d+)?)", value)
    if not number_match:
        return (1, 0.0)

    numeric_severity = float(number_match.group(1))
    if numeric_severity >= 9.0:
        return (5, numeric_severity)
    if numeric_severity >= 7.0:
        return (4, numeric_severity)
    if numeric_severity >= 4.0:
        return (3, numeric_severity)
    if numeric_severity > 0.0:
        return (2, numeric_severity)
    return (1, numeric_severity)

