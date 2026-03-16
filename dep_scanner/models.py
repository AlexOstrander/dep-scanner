from __future__ import annotations

"""Shared datamodels used across resolution, scanning, and reporting."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class Dependency:
    """A single resolved package and where it came from."""

    name: str
    version: str
    ecosystem: str
    is_direct: bool
    source: str


@dataclass(slots=True)
class Advisory:
    """Normalized vulnerability advisory from OSV or GitHub."""

    advisory_id: str
    source: str
    severity: str
    cve_ids: list[str]
    summary: str
    details: str
    reference_url: str
    fixed_versions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VulnerabilityFinding:
    """Pairing of one dependency with all matching advisories."""

    dependency: Dependency
    advisories: list[Advisory]


@dataclass(slots=True)
class PackageHealth:
    """Maintenance metadata derived from latest release timestamps."""

    dependency: Dependency
    last_release_at: datetime | None
    is_unmaintained: bool
    months_since_release: int | None


@dataclass(slots=True)
class ScanSummary:
    """Top-level counters used in console and JSON summaries."""

    total_dependencies: int
    vulnerable_dependencies: int
    vulnerable_percentage: float
    unmaintained_dependencies: int


@dataclass(slots=True)
class ScanReport:
    """Complete scan payload returned by CLI and web handlers."""

    generated_at: str
    findings: list[VulnerabilityFinding]
    package_health: list[PackageHealth]
    summary: ScanSummary
    warnings: list[str]

