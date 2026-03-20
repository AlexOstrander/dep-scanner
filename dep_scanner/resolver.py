from __future__ import annotations

"""Dependency resolution orchestration across supported ecosystems."""

from collections import deque
from pathlib import Path

import httpx
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from dep_scanner.models import Dependency
from dep_scanner.parsers import (
    parse_cargo_lock,
    parse_cargo_toml,
    parse_composer_json,
    parse_composer_lock,
    parse_csproj_package_references,
    parse_gemfile_direct_names,
    parse_gemfile_lock,
    parse_github_workflow_actions,
    parse_go_mod,
    parse_go_sum,
    parse_mix_exs_direct_names,
    parse_mix_lock,
    parse_package_json,
    parse_package_lock,
    parse_package_resolved,
    parse_package_swift_direct_names,
    parse_packages_lock_json,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pom_xml,
    parse_pubspec_lock,
    parse_pubspec_yaml_direct_names,
    parse_requirements_txt,
    parse_uv_lock,
    parse_yarn_lock,
)

PYPI_BASE_URL = "https://pypi.org/pypi"


def _first_input_path(inputs: list[Path], filename: str) -> Path | None:
    """Return the first input whose basename matches ``filename``."""
    for path in inputs:
        if path.name == filename:
            return path
    return None


def _github_workflow_paths(inputs: list[Path]) -> list[Path]:
    """Paths under ``.github/workflows`` with YAML extensions."""
    workflow_paths: list[Path] = []
    for path in inputs:
        parts_lower = [part.lower() for part in path.parts]
        if "workflows" in parts_lower and path.suffix.lower() in (".yml", ".yaml"):
            workflow_paths.append(path)
    return workflow_paths


def dedupe_dependencies(dependencies: list[Dependency]) -> list[Dependency]:
    """Deduplicate by ecosystem/name/version and preserve direct markers."""
    deduped: dict[tuple[str, str, str], Dependency] = {}
    for dependency in dependencies:
        key = (dependency.ecosystem, dependency.name.lower(), dependency.version)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = dependency
            continue
        if dependency.is_direct:
            existing.is_direct = True
    return list(deduped.values())


def resolve_dependencies(inputs: list[Path], http_client: httpx.Client) -> tuple[list[Dependency], list[str]]:
    """Resolve dependencies from provided manifests/lockfiles and collect warnings."""
    warnings: list[str] = []
    resolved_dependencies: list[Dependency] = []

    path_set = {path.name: path for path in inputs}
    # Callers (e.g. run_scan) pass only paths that exist; treat ``inputs`` as the scan file list.

    package_json_path = path_set.get("package.json")
    package_lock_path = path_set.get("package-lock.json")
    yarn_lock_path = path_set.get("yarn.lock")

    if package_json_path:
        direct_npm_dependencies, npm_specs = parse_package_json(package_json_path)
        if package_lock_path:
            resolved_dependencies.extend(parse_package_lock(package_lock_path, set(npm_specs.keys())))
        elif yarn_lock_path:
            resolved_dependencies.extend(parse_yarn_lock(yarn_lock_path, set(npm_specs.keys())))
        else:
            warnings.append("package.json provided without lockfile; dependency tree may be incomplete.")
            resolved_dependencies.extend(direct_npm_dependencies)
    elif yarn_lock_path:
        resolved_dependencies.extend(parse_yarn_lock(yarn_lock_path, set()))
        warnings.append("yarn.lock provided without package.json; direct dependency detection may be incomplete.")
    elif package_lock_path:
        resolved_dependencies.extend(parse_package_lock(package_lock_path, set()))
        warnings.append("package-lock.json provided without package.json; direct dependency detection may be incomplete.")

    go_sum_path = path_set.get("go.sum")
    go_mod_path = path_set.get("go.mod")
    if go_sum_path:
        direct_go_dependencies: set[str] = set()
        if go_mod_path:
            direct_go_dependencies = parse_go_mod(go_mod_path)
        else:
            warnings.append("go.sum provided without go.mod; direct dependency detection may be incomplete.")
        resolved_dependencies.extend(parse_go_sum(go_sum_path, direct_go_dependencies))
    elif go_mod_path:
        warnings.append("go.mod provided without go.sum; dependency tree may be incomplete.")

    composer_lock_path = path_set.get("composer.lock")
    composer_json_path = path_set.get("composer.json")
    if composer_lock_path:
        direct_php_dependencies: set[str] = set()
        if composer_json_path:
            direct_php_dependencies = parse_composer_json(composer_json_path)
        else:
            warnings.append("composer.lock provided without composer.json; direct dependency detection may be incomplete.")
        resolved_dependencies.extend(parse_composer_lock(composer_lock_path, direct_php_dependencies))
    elif composer_json_path:
        warnings.append("composer.json provided without composer.lock; dependency tree may be incomplete.")

    requirements_path = path_set.get("requirements.txt")
    poetry_lock_path = path_set.get("poetry.lock")
    pipfile_lock_path = path_set.get("Pipfile.lock")
    uv_lock_path = path_set.get("uv.lock")

    if requirements_path:
        direct_requirements = parse_requirements_txt(requirements_path)
        direct_python_names = {requirement.name for requirement in direct_requirements}
        if uv_lock_path:
            resolved_dependencies.extend(parse_uv_lock(uv_lock_path, direct_python_names))
        elif poetry_lock_path:
            resolved_dependencies.extend(parse_poetry_lock(poetry_lock_path, direct_python_names))
        elif pipfile_lock_path:
            resolved_dependencies.extend(parse_pipfile_lock(pipfile_lock_path, direct_python_names))
        else:
            warnings.append("requirements.txt provided without lockfile; resolving transitives from PyPI metadata.")
            resolved_dependencies.extend(
                resolve_python_dependencies_from_pypi(
                    direct_requirements=direct_requirements,
                    source_path=requirements_path,
                    http_client=http_client,
                )
            )
    elif uv_lock_path:
        warnings.append("uv.lock provided without requirements.txt; direct dependency detection may be incomplete.")
        resolved_dependencies.extend(parse_uv_lock(uv_lock_path, set()))
    elif poetry_lock_path:
        warnings.append("poetry.lock provided without requirements.txt; direct dependency detection may be incomplete.")
        resolved_dependencies.extend(parse_poetry_lock(poetry_lock_path, set()))
    elif pipfile_lock_path:
        warnings.append("Pipfile.lock provided without requirements.txt; direct dependency detection may be incomplete.")
        resolved_dependencies.extend(parse_pipfile_lock(pipfile_lock_path, set()))

    cargo_lock_path = path_set.get("Cargo.lock")
    if cargo_lock_path:
        cargo_toml_path = path_set.get("Cargo.toml")
        direct_cargo_names: set[str] = set()
        if cargo_toml_path:
            direct_cargo_names = parse_cargo_toml(cargo_toml_path)
        else:
            warnings.append("Cargo.lock provided without Cargo.toml; direct dependency detection may be incomplete.")
        resolved_dependencies.extend(parse_cargo_lock(cargo_lock_path, direct_cargo_names))

    gemfile_lock_path = _first_input_path(inputs, "Gemfile.lock")
    if gemfile_lock_path:
        gemfile_path = _first_input_path(inputs, "Gemfile")
        direct_ruby_names = parse_gemfile_direct_names(gemfile_path) if gemfile_path else set()
        resolved_dependencies.extend(parse_gemfile_lock(gemfile_lock_path, direct_ruby_names))
    elif _first_input_path(inputs, "Gemfile"):
        warnings.append("Gemfile provided without Gemfile.lock; Ruby dependency tree may be incomplete.")

    pubspec_lock_path = _first_input_path(inputs, "pubspec.lock")
    if pubspec_lock_path:
        pubspec_yaml_path = _first_input_path(inputs, "pubspec.yaml")
        direct_pub_names = (
            parse_pubspec_yaml_direct_names(pubspec_yaml_path) if pubspec_yaml_path else set()
        )
        resolved_dependencies.extend(parse_pubspec_lock(pubspec_lock_path, direct_pub_names))
    elif _first_input_path(inputs, "pubspec.yaml"):
        warnings.append("pubspec.yaml provided without pubspec.lock; Dart/Flutter resolution skipped.")

    mix_lock_path = _first_input_path(inputs, "mix.lock")
    if mix_lock_path:
        mix_exs_path = _first_input_path(inputs, "mix.exs")
        direct_mix_names = parse_mix_exs_direct_names(mix_exs_path) if mix_exs_path else set()
        resolved_dependencies.extend(parse_mix_lock(mix_lock_path, direct_mix_names))
    elif _first_input_path(inputs, "mix.exs"):
        warnings.append("mix.exs provided without mix.lock; Elixir/Hex resolution skipped.")

    packages_lock_path = _first_input_path(inputs, "packages.lock.json")
    if packages_lock_path:
        resolved_dependencies.extend(parse_packages_lock_json(packages_lock_path, set()))

    for input_path in inputs:
        if input_path.suffix.lower() == ".csproj":
            resolved_dependencies.extend(parse_csproj_package_references(input_path))

    pom_path = _first_input_path(inputs, "pom.xml")
    if pom_path:
        resolved_dependencies.extend(parse_pom_xml(pom_path))

    package_resolved_path = _first_input_path(inputs, "Package.resolved")
    if package_resolved_path:
        package_swift_path = _first_input_path(inputs, "Package.swift")
        direct_swift_names = (
            parse_package_swift_direct_names(package_swift_path) if package_swift_path else set()
        )
        resolved_dependencies.extend(parse_package_resolved(package_resolved_path, direct_swift_names))
    elif _first_input_path(inputs, "Package.swift"):
        warnings.append("Package.swift provided without Package.resolved; Swift resolution skipped.")

    for workflow_path in _github_workflow_paths(inputs):
        resolved_dependencies.extend(parse_github_workflow_actions(workflow_path))

    if not resolved_dependencies:
        warnings.append("No recognized manifest/lockfile inputs found.")

    return dedupe_dependencies(resolved_dependencies), warnings


def resolve_python_dependencies_from_pypi(
    *,
    direct_requirements: list[Requirement],
    source_path: Path,
    http_client: httpx.Client,
) -> list[Dependency]:
    """Best-effort transitive resolution for requirements.txt via PyPI metadata."""
    resolved: dict[tuple[str, str], Dependency] = {}
    queued: deque[tuple[Requirement, bool]] = deque((requirement, True) for requirement in direct_requirements)
    seen_names: set[str] = set()

    while queued:
        requirement, is_direct = queued.popleft()
        package_name = requirement.name
        if package_name.lower() in seen_names:
            continue

        resolved_version = resolve_best_pypi_version(package_name, requirement.specifier, http_client)
        if not resolved_version:
            continue

        seen_names.add(package_name.lower())
        dependency_key = (package_name.lower(), resolved_version)
        existing = resolved.get(dependency_key)
        if existing is None:
            resolved[dependency_key] = Dependency(
                name=package_name,
                version=resolved_version,
                ecosystem="PyPI",
                is_direct=is_direct,
                source=str(source_path),
            )
        elif is_direct:
            existing.is_direct = True

        for transitive_requirement in read_pypi_requires_dist(package_name, resolved_version, http_client):
            queued.append((transitive_requirement, False))

    return list(resolved.values())


def resolve_best_pypi_version(package_name: str, specifier: SpecifierSet, http_client: httpx.Client) -> str | None:
    """Pick the highest available PyPI release matching a requirement specifier."""
    response = http_client.get(f"{PYPI_BASE_URL}/{package_name}/json", timeout=20.0)
    if response.status_code != 200:
        return None
    payload = response.json()
    releases = payload.get("releases", {})
    candidate_versions: list[Version] = []
    for candidate in releases.keys():
        try:
            parsed = Version(candidate)
        except InvalidVersion:
            continue
        if not specifier or parsed in specifier:
            candidate_versions.append(parsed)
    if not candidate_versions:
        return None
    return str(sorted(candidate_versions)[-1])


def read_pypi_requires_dist(package_name: str, version: str, http_client: httpx.Client) -> list[Requirement]:
    """Read transitive requirements from PyPI's requires_dist metadata."""
    response = http_client.get(f"{PYPI_BASE_URL}/{package_name}/{version}/json", timeout=20.0)
    if response.status_code != 200:
        return []
    payload = response.json()
    info = payload.get("info", {})
    requires_dist = info.get("requires_dist", []) or []

    parsed_requirements: list[Requirement] = []
    for raw_requirement in requires_dist:
        try:
            requirement = Requirement(raw_requirement)
        except Exception:
            continue
        if requirement.marker and not requirement.marker.evaluate():
            continue
        parsed_requirements.append(requirement)
    return parsed_requirements

