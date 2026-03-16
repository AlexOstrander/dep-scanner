from dep_scanner.providers.github_client import is_dependency_vulnerable


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

