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
    """Parse npm dependencies from both legacy and npm v7+ lockfile formats."""
    payload = read_json_file(path)
    dependencies: dict[tuple[str, str], Dependency] = {}

    def remember_dependency(name: str, version: str, is_direct: bool) -> None:
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
            return
        if is_direct:
            existing.is_direct = True

    def walk_legacy(tree: dict, is_direct: bool) -> None:
        for name, body in tree.items():
            if not isinstance(body, dict):
                continue
            version = str(body.get("version", "unknown"))
            remember_dependency(name=name, version=version, is_direct=is_direct)

            nested = body.get("dependencies")
            if isinstance(nested, dict):
                walk_legacy(nested, False)

    def walk_modern(packages_map: dict) -> None:
        for package_path, body in packages_map.items():
            if package_path == "" or not isinstance(body, dict):
                continue
            version = str(body.get("version", "")).strip()
            if not version:
                continue
            name = str(body.get("name", "")).strip()
            if not name:
                name = dependency_name_from_path(package_path)
            if not name:
                continue
            is_direct = package_path.startswith("node_modules/") and "/node_modules/" not in package_path
            remember_dependency(name=name, version=version, is_direct=is_direct)

    lock_dependencies = payload.get("dependencies")
    if isinstance(lock_dependencies, dict):
        walk_legacy(lock_dependencies, True)

    packages_map = payload.get("packages")
    if isinstance(packages_map, dict):
        walk_modern(packages_map)

    return list(dependencies.values())


def dependency_name_from_path(package_path: str) -> str:
    """Infer npm package name from lockfile package path."""
    marker = "node_modules/"
    if marker not in package_path:
        return ""
    return package_path.rsplit(marker, 1)[-1].strip("/")


def _extract_package_name_from_berry_key(key: str) -> str:
    """Extract package name from Yarn Berry key like 'lodash@npm:^4.17.0' or '@scope/pkg@npm:^1.0'."""
    for protocol in ("@npm:", "@pnpm:", "@workspace:"):
        if protocol in key:
            return key.split(protocol, 1)[0]
    return key.split("@", 1)[0] if "@" in key else key


def parse_yarn_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved npm package versions from yarn.lock (Yarn v1 classic and Berry v2+)."""
    text = path.read_text(encoding="utf-8")
    first_lines = "\n".join(text.splitlines()[:5])
    is_berry = "__metadata:" in first_lines or re.search(r"^\s+version:\s", text, re.MULTILINE)

    if is_berry:
        return _parse_yarn_berry_lock(text, path, direct_dep_names)
    return _parse_yarn_classic_lock(text, path, direct_dep_names)


def _parse_yarn_berry_lock(text: str, path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse Yarn Berry (v2+) lockfile format (YAML-like with version: / resolution:)."""
    dependencies: dict[tuple[str, str], Dependency] = {}
    current_names: list[str] = []
    current_version: str | None = None
    in_metadata = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if stripped.startswith("__metadata:"):
            in_metadata = True
            continue
        if in_metadata and indent > 0:
            continue
        in_metadata = False

        if not line or line.startswith("#"):
            current_names = []
            current_version = None
            continue

        if not line.startswith(" "):
            current_names = []
            current_version = None
            key_part = line.rstrip(":").strip().strip('"').strip("'")
            if not key_part:
                continue
            for key in (k.strip().strip('"').strip("'") for k in key_part.split(",")):
                if key and "@" in key:
                    current_names.append(_extract_package_name_from_berry_key(key))
            continue

        if stripped.startswith("version:"):
            current_version = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        elif stripped.startswith("resolution:") and current_version is None:
            resolution = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            if "@npm:" in resolution:
                current_version = resolution.split("@npm:", 1)[1].strip()

        if current_names and current_version:
            for name in current_names:
                key = (name, current_version)
                if key not in dependencies:
                    dependencies[key] = Dependency(
                        name=name,
                        version=current_version,
                        ecosystem="npm",
                        is_direct=name in direct_dep_names,
                        source=str(path),
                    )
            current_names = []
            current_version = None

    return list(dependencies.values())


def _parse_yarn_classic_lock(text: str, path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse Yarn v1 classic lockfile format."""
    dependencies: dict[tuple[str, str], Dependency] = {}
    current_keys: list[str] = []
    current_version: str | None = None
    current_name: str | None = None

    def flush_current() -> None:
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

    for raw_line in text.splitlines():
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
            rest = line.split(" ", 1)[1].strip()
            match = re.search(r'"([^"]+)"', rest)
            current_version = match.group(1) if match else rest.strip('"')

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


def parse_go_mod(path: Path) -> set[str]:
    """Extract direct Go module dependency names from go.mod."""
    direct_dependencies: set[str] = set()
    in_require_block = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        is_indirect = "// indirect" in raw_line
        line_no_comment = raw_line.split("//", 1)[0].strip()
        if not line_no_comment:
            continue

        if line_no_comment == "require (":
            in_require_block = True
            continue
        if in_require_block and line_no_comment == ")":
            in_require_block = False
            continue

        if in_require_block:
            parts = line_no_comment.split()
            if len(parts) >= 2 and not is_indirect:
                direct_dependencies.add(parts[0])
            continue

        if line_no_comment.startswith("require "):
            parts = line_no_comment[len("require ") :].split()
            if len(parts) >= 2 and not is_indirect:
                direct_dependencies.add(parts[0])

    return direct_dependencies


def parse_go_sum(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved Go module versions from go.sum entries."""
    dependencies: dict[tuple[str, str], Dependency] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        version = parts[1]
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        if not version:
            continue
        dependency_key = (name, version)
        existing = dependencies.get(dependency_key)
        if existing is None:
            dependencies[dependency_key] = Dependency(
                name=name,
                version=version,
                ecosystem="Go",
                is_direct=name in direct_dep_names,
                source=str(path),
            )
        elif name in direct_dep_names:
            existing.is_direct = True
    return list(dependencies.values())


def parse_composer_json(path: Path) -> set[str]:
    """Extract direct package names from composer.json require sections."""
    payload = read_json_file(path)
    direct_dependencies: set[str] = set()
    for section in ("require", "require-dev"):
        body = payload.get(section, {})
        if not isinstance(body, dict):
            continue
        for name in body.keys():
            if "/" in str(name):
                direct_dependencies.add(str(name))
    return direct_dependencies


def parse_composer_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved PHP packages from composer.lock."""
    payload = read_json_file(path)
    dependencies: dict[tuple[str, str], Dependency] = {}
    for section in ("packages", "packages-dev"):
        packages = payload.get(section, [])
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name", "")).strip()
            version = str(package.get("version", "")).strip()
            if not name or not version:
                continue
            dependency_key = (name, version)
            existing = dependencies.get(dependency_key)
            if existing is None:
                dependencies[dependency_key] = Dependency(
                    name=name,
                    version=version,
                    ecosystem="Packagist",
                    is_direct=name in direct_dep_names,
                    source=str(path),
                )
            elif name in direct_dep_names:
                existing.is_direct = True
    return list(dependencies.values())


def parse_uv_lock(path: Path, direct_dep_names: set[str]) -> list[Dependency]:
    """Parse resolved Python package versions from uv.lock."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("package", [])
    dependencies: list[Dependency] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", "")).strip()
        version = str(package.get("version", "")).strip()
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
    """Extract direct Rust dependency names from Cargo.toml, including target/workspace blocks."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    dependency_names: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        body = payload.get(section, {})
        if isinstance(body, dict):
            dependency_names.update(body.keys())

    workspace = payload.get("workspace", {})
    if isinstance(workspace, dict):
        workspace_deps = workspace.get("dependencies", {})
        if isinstance(workspace_deps, dict):
            dependency_names.update(workspace_deps.keys())

    targets = payload.get("target", {})
    if isinstance(targets, dict):
        for target_payload in targets.values():
            if not isinstance(target_payload, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                body = target_payload.get(section, {})
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

