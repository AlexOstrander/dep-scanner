from __future__ import annotations

"""Shared scan input indexing and report labels (avoids drift across CLI, web, resolver)."""

from pathlib import Path
from typing import Final

# Basenames compared case-insensitively; values are short labels for JSON report filenames.
PACKAGE_MANAGER_LABEL_BY_FILENAME: Final[dict[str, str]] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "pypi",
    "poetry.lock": "pypi",
    "pipfile.lock": "pypi",
    "uv.lock": "pypi",
    "cargo.toml": "cargo",
    "cargo.lock": "cargo",
    "go.mod": "go",
    "go.sum": "go",
    "composer.json": "composer",
    "composer.lock": "composer",
    "gemfile": "rubygems",
    "gemfile.lock": "rubygems",
    "pubspec.yaml": "pub",
    "pubspec.lock": "pub",
    "mix.exs": "hex",
    "mix.lock": "hex",
    "packages.lock.json": "nuget",
    "pom.xml": "maven",
    "package.swift": "swift",
    "package.resolved": "swift",
}


def basename_index(inputs: list[Path]) -> tuple[dict[str, Path], list[str]]:
    """Map lowercase basename -> path. First path wins; later duplicates become warnings."""
    index: dict[str, Path] = {}
    warnings: list[str] = []
    dup_seen: set[str] = set()
    for path in inputs:
        key = path.name.lower()
        if key in index:
            if key not in dup_seen:
                warnings.append(
                    f"Multiple inputs share basename {path.name!r}; using {index[key]} — ignoring {path}",
                )
                dup_seen.add(key)
            continue
        index[key] = path
    return index, warnings


def path_for_basename(index: dict[str, Path], filename: str) -> Path | None:
    """Return path for a manifest basename using the same lowercase keying as ``basename_index``."""
    return index.get(filename.lower())


def detect_package_manager_label(input_paths: list[Path]) -> str:
    """Infer package manager label from known manifest/lockfile names (for report filenames)."""
    managers = {
        label
        for path in input_paths
        for filename, label in PACKAGE_MANAGER_LABEL_BY_FILENAME.items()
        if path.name.lower() == filename
    }
    if not managers:
        return "mixed"
    return "-".join(sorted(managers))
