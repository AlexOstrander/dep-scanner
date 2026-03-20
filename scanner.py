#!/usr/bin/env python3
from __future__ import annotations

"""CLI entrypoint for scan and web-server modes."""

import argparse
import os
from datetime import datetime
from pathlib import Path

from rich.console import Console
import uvicorn

from dep_scanner.input_index import detect_package_manager_label
from dep_scanner.reporting import render_human_report, write_json_report
from dep_scanner.scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    """Build command-line flags for scanning and web UI mode."""
    parser = argparse.ArgumentParser(
        description="Scan dependency manifests for known vulnerabilities.",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="Manifest and lockfile paths, e.g. requirements.txt poetry.lock package.json package-lock.json",
    )
    parser.add_argument(
        "--ignore-file",
        default=None,
        help="Path to ignore list JSON file.",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Path for machine-readable JSON report. Defaults to scans/scan-report_<manager>_<ISO8601>.json.",
    )
    parser.add_argument(
        "--months-unmaintained",
        type=int,
        default=18,
        help="Mark package as unmaintained if no release within N months.",
    )
    parser.add_argument(
        "--github-token",
        default=os.getenv("GITHUB_TOKEN"),
        help="GitHub token for advisory API rate-limit increase.",
    )
    parser.add_argument(
        "--show-outdated-upgrade-options",
        action="store_true",
        help="Show all fixed-version upgrade options, including older/outdated ones.",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run FastAPI web UI server instead of CLI scan mode.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for web UI server.")
    parser.add_argument("--port", type=int, default=8000, help="Port for web UI server.")
    return parser


def main() -> int:
    """Parse args and execute either web mode or CLI scan mode."""
    parser = build_parser()
    args = parser.parse_args()

    if args.serve:
        uvicorn.run("dep_scanner.web:app", host=args.host, port=args.port, reload=False)
        return 0

    if not args.inputs:
        parser.error("Provide at least one input path or use --serve for web mode.")

    console = Console()
    report = run_scan(
        input_paths=[Path(input_path) for input_path in args.inputs],
        ignore_file=Path(args.ignore_file) if args.ignore_file else None,
        months_unmaintained=args.months_unmaintained,
        github_token=args.github_token,
    )
    render_human_report(
        report,
        console,
        show_outdated_upgrade_options=args.show_outdated_upgrade_options,
    )
    input_paths = [Path(input_path) for input_path in args.inputs]
    output_path = Path(args.json_out) if args.json_out else build_default_scan_report_path(input_paths)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json_report(report, output_path)
    console.print(f"[blue]JSON report saved to:[/blue] {output_path}")
    return 0


def build_default_scan_report_path(input_paths: list[Path]) -> Path:
    """Build default timestamped report path under scans/ with package manager label."""
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    package_manager_label = detect_package_manager_label(input_paths)
    project_root = Path(__file__).resolve().parent
    return project_root / "scans" / f"scan-report_{package_manager_label}_{timestamp}.json"


if __name__ == "__main__":
    raise SystemExit(main())
