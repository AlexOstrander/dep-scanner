from dep_scanner.providers.github_client import (
    extract_advisory_severity,
    extract_fixed_versions_from_github_vulnerability,
    is_dependency_vulnerable,
)


def test_crates_io_uses_semver_matching() -> None:
    assert is_dependency_vulnerable(
        version="1.4.2",
        ecosystem="crates.io",
        vulnerability_specs=[">=1.2.0 <2.0.0"],
    )


def test_pypi_uses_pep440_matching() -> None:
    assert is_dependency_vulnerable(
        version="2.5.0",
        ecosystem="PyPI",
        vulnerability_specs=[">=2.0.0,<3.0.0"],
    )


def test_go_uses_semver_matching() -> None:
    assert is_dependency_vulnerable(
        version="v1.42.0",
        ecosystem="Go",
        vulnerability_specs=[">=1.30.0 <1.50.0"],
    )


def test_extract_fixed_versions_supports_string_first_patched_version() -> None:
    fixed_versions = extract_fixed_versions_from_github_vulnerability(
        {
            "first_patched_version": "4.22.0",
            "package": {"ecosystem": "npm", "name": "express"},
            "vulnerable_version_range": "< 4.22.0",
        }
    )
    assert "4.22.0" in fixed_versions


def test_extract_advisory_severity_from_cvss_score() -> None:
    assert extract_advisory_severity({"severity": None, "cvss": {"score": 8.4}}) == "HIGH"

