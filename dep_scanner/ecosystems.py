from __future__ import annotations

"""Canonical OSV ecosystem strings (used as Dependency.ecosystem) and GitHub advisory API mapping.

OSV batch queries use the ecosystem labels from https://github.com/google/osv.dev (e.g. PyPI, RubyGems).
GitHub global advisories filter uses lowercase API enums:
https://docs.github.com/en/rest/security-advisories/global-advisories
"""

from typing import Final

# OSV `package.ecosystem` string -> GitHub `?ecosystem=` query value
GITHUB_ADVISORY_ECOSYSTEM_BY_OSV: Final[dict[str, str]] = {
    "npm": "npm",
    "PyPI": "pip",
    "crates.io": "rust",
    "Go": "go",
    "Packagist": "composer",
    "RubyGems": "rubygems",
    "Maven": "maven",
    "NuGet": "nuget",
    "Pub": "pub",
    "Hex": "erlang",
    "SwiftURL": "swift",
    "GitHub Actions": "actions",
}

# Ecosystems where GitHub `vulnerable_version_range` is typically semver/npm-range shaped.
SEMVER_RANGE_ECOSYSTEMS: Final[frozenset[str]] = frozenset(
    {
        "npm",
        "crates.io",
        "Go",
        "RubyGems",
        "NuGet",
        "Pub",
        "Hex",
        "SwiftURL",
        "GitHub Actions",
    }
)

# GitHub enum `other` has no single OSV ecosystem; not used for resolution here.
GITHUB_ECOSYSTEM_OTHER: Final[str] = "other"
