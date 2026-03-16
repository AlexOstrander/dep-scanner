from __future__ import annotations

"""Manifest and lockfile parsers that normalize dependencies."""

import json
import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

from dep_scanner.models import Dependency


def read_json_file(path: Path) -> dict:
    """Read a UTF-8 JSON file into a dictionary."""
    return json.loads(path.read_text(encoding="utf-8"))


def parse_package_json(path: Path) -> tuple[list[Dependency], dict[str, str]]:
    """Parse direct npm dependencies from package.json sections."""
    payload = read_json_file(path)
    dependencies: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        section_values = payload.get(section, {})
        if isinstance(section_values, dict):
            dependencies.update({name: str(spec) for name, spec in section_values.items()})

    direct_dependencies = [
        Dependency(
            name=name,
            version=spec,
            ecosystem="npm",
            is_direct=True,
            source=str(path),
        )
        for name, spec in dependencies.items()
    ]
    return direct_dependencies, dependencies


def parse_package_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse npm dependency tree from package-lock.json recursively."""
    payload = read_json_file(path)
    lock_dependencies = payload.get("dependencies")
    if not isinstance(lock_dependencies, dict):
        return []

    dependencies: dict[tuple[str, str], Dependency] = {}

    def walk(tree: dict, is_direct: bool) -> None:
        for name, body in tree.items():
            if not isinstance(body, dict):
                continue
            version = str(body.get("version", "unknown"))
            dependency_key = (name, version)
            existing = dependencies.get(dependency_key)
            if existing is None:
                dependencies[dependency_key] = Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_direct=is_direct or (name in direct_dep_names),
                    source=str(path),
                )
            elif is_direct:
                existing.is_direct = True

            nested = body.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, False)

    walk(lock_dependencies, True)
    return list(dependencies.values())


def parse_yarn_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved npm package versions from a yarn.lock file."""
    dependencies: dict[tuple[str, str], Dependency] = {}
    current_keys: list[str] = []
    current_version: str | None = None
    current_name: str | None = None

    def flush_current() -> None:
        """Persist the current yarn entry before moving to next one."""
        nonlocal current_keys, current_version, current_name
        if current_name and current_version:
            key = (current_name, current_version)
            if key not in dependencies:
                dependencies[key] = Dependency(
                    name=current_name,
                    version=current_version,
                    ecosystem="npm",
                    is_direct=current_name in direct_dep_names,
                    source=str(path),
                )
        current_keys = []
        current_version = None
        current_name = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if not line:
            flush_current()
            continue

        if not line.startswith(" "):
            current_keys = [k.strip().strip('"').strip("'") for k in line.rstrip(":").split(",")]
            if current_keys:
                first_key = current_keys[0]
                if first_key.startswith("@"):
                    split_index = first_key.rfind("@")
                    current_name = first_key[:split_index]
                else:
                    current_name = first_key.split("@", 1)[0]
            continue

        if line.lstrip().startswith("version "):
            maybe_version = line.split(" ", 1)[1].strip().strip('"')
            current_version = maybe_version

    flush_current()
    return list(dependencies.values())


def parse_requirements_txt(path: Path) -> list[Requirement]:
    """Parse base requirements entries and ignore comments/options."""
    requirements: list[Requirement] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", "--")):
            continue
        line = re.sub(r"\s+#.*$", "", line)
        try:
            requirements.append(Requirement(line))
        except Exception:
            continue
    return requirements


def parse_pipfile_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse locked Python packages from Pipfile.lock sections."""
    payload = read_json_file(path)
    dependencies: list[Dependency] = []
    for section in ("default", "develop"):
        body = payload.get(section, {})
        if not isinstance(body, dict):
            continue
        for name, meta in body.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version", "")).lstrip("=")
            if not version:
                continue
            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="PyPI",
                    is_direct=name in direct_dep_names,
                    source=str(path),
                )
            )
    return dependencies


def parse_poetry_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved Python package versions from poetry.lock."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("package", [])
    dependencies: list[Dependency] = []
    for package in packages:
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if not name or not version:
            continue
        dependencies.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                is_direct=name in direct_dep_names,
                source=str(path),
            )
        )
    return dependencies


def parse_cargo_toml(path: Path) -> set[str]:
    """Extract direct Rust dependency names from Cargo.toml."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    dependency_names: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        body = payload.get(section, {})
        if isinstance(body, dict):
            dependency_names.update(body.keys())
    return dependency_names


def parse_cargo_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved Rust crates from Cargo.lock package entries."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("package", [])
    dependencies: list[Dependency] = []
    for package in packages:
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if not name or not version:
            continue
        dependencies.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="crates.io",
                is_direct=name in direct_dep_names,
                source=str(path),
            )
        )
    return dependencies

