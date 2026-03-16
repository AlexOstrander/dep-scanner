from __future__ import annotations

"""Report rendering utilities for console and JSON outputs."""

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from dep_scanner.models import ScanReport


def render_human_report(scan_report: ScanReport, console: Console) -> None:
    """Render summary and vulnerability tables in a human-readable format."""
    summary_table = Table(title="Dependency Scan Summary")
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
    vulnerabilities_table.add_column("Package")
    vulnerabilities_table.add_column("Version")
    vulnerabilities_table.add_column("Ecosystem")
    vulnerabilities_table.add_column("Severity")
    vulnerabilities_table.add_column("Advisory IDs / CVEs")
    vulnerabilities_table.add_column("Remediation")
    vulnerabilities_table.add_column("Link")

    for finding in scan_report.findings:
        advisory_ids = []
        severities = []
        remediations = []
        links = []
        for advisory in finding.advisories:
            advisory_ids.append(advisory.advisory_id)
            advisory_ids.extend(advisory.cve_ids)
            severities.append(advisory.severity)
            if advisory.fixed_versions:
                remediations.append(f"Upgrade to {', '.join(advisory.fixed_versions)}")
            if advisory.reference_url:
                links.append(advisory.reference_url)

        vulnerabilities_table.add_row(
            finding.dependency.name,
            finding.dependency.version,
            finding.dependency.ecosystem,
            ", ".join(sorted(set(severities))) or "UNKNOWN",
            ", ".join(sorted(set(advisory_ids))) or "N/A",
            "; ".join(sorted(set(remediations))) or "No fixed version listed",
            "; ".join(sorted(set(links))) or "N/A",
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

