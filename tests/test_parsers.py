import json
from pathlib import Path

from dep_scanner.parsers import (
    parse_cargo_toml,
    parse_composer_json,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_github_workflow_actions,
    parse_go_mod,
    parse_go_mod_direct_dependencies,
    parse_go_sum,
    parse_mix_lock,
    parse_package_lock,
    parse_package_resolved,
    parse_packages_lock_json,
    parse_pom_xml,
    parse_pubspec_lock,
    parse_requirements_txt,
    parse_uv_lock,
    parse_yarn_lock,
)


def test_parse_requirements_txt_filters_comments_and_options(tmp_path: Path) -> None:
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text(
        "\n".join(
            [
                "# comment",
                "requests==2.31.0",
                "--index-url https://example.com/simple",
                "urllib3>=2.0",
                "",
            ]
        ),
        encoding="utf-8",
    )

    requirements = parse_requirements_txt(requirements_file)
    names = [requirement.name for requirement in requirements]
    assert names == ["requests", "urllib3"]


def test_parse_package_lock_supports_packages_map(tmp_path: Path) -> None:
    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(
        json.dumps(
            {
                "name": "demo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/react": {"version": "18.2.0"},
                    "node_modules/react/node_modules/loose-envify": {"version": "1.4.0"},
                    "node_modules/@types/node": {"version": "20.14.10"},
                },
            }
        ),
        encoding="utf-8",
    )

    dependencies = parse_package_lock(package_lock, {"lodash", "react"})
    by_name = {(dependency.name, dependency.version): dependency for dependency in dependencies}

    assert ("lodash", "4.17.21") in by_name
    assert ("react", "18.2.0") in by_name
    assert ("loose-envify", "1.4.0") in by_name
    assert ("@types/node", "20.14.10") in by_name
    assert by_name[("lodash", "4.17.21")].is_direct is True
    assert by_name[("react", "18.2.0")].is_direct is True
    assert by_name[("loose-envify", "1.4.0")].is_direct is False


def test_parse_uv_lock_extracts_python_dependencies(tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        "\n".join(
            [
                'version = 1',
                "",
                "[[package]]",
                'name = "requests"',
                'version = "2.32.3"',
                "",
                "[[package]]",
                'name = "urllib3"',
                'version = "2.2.2"',
            ]
        ),
        encoding="utf-8",
    )

    dependencies = parse_uv_lock(uv_lock, {"requests"})
    by_name = {(dependency.name, dependency.version): dependency for dependency in dependencies}
    assert ("requests", "2.32.3") in by_name
    assert ("urllib3", "2.2.2") in by_name
    assert by_name[("requests", "2.32.3")].is_direct is True
    assert by_name[("urllib3", "2.2.2")].is_direct is False


def test_parse_cargo_toml_extracts_workspace_and_target_dependencies(tmp_path: Path) -> None:
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_toml.write_text(
        "\n".join(
            [
                "[package]",
                'name = "demo"',
                'version = "0.1.0"',
                "",
                "[dependencies]",
                'serde = "1"',
                "",
                "[workspace.dependencies]",
                'tokio = "1"',
                "",
                '[target."cfg(unix)".dependencies]',
                'libc = "0.2"',
            ]
        ),
        encoding="utf-8",
    )

    dependency_names = parse_cargo_toml(cargo_toml)
    assert {"serde", "tokio", "libc"}.issubset(dependency_names)


def test_parse_go_mod_direct_dependencies_inline_and_block(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "\n".join(
            [
                "module example.com/demo",
                "",
                "go 1.22",
                "",
                "require (",
                "    github.com/gin-gonic/gin v1.10.0",
                "    golang.org/x/net v0.30.0 // indirect",
                ")",
                "",
                "require github.com/stretchr/testify v1.9.0",
            ]
        ),
        encoding="utf-8",
    )
    dependencies = parse_go_mod_direct_dependencies(go_mod)
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("github.com/gin-gonic/gin", "v1.10.0") in by_name
    assert ("github.com/stretchr/testify", "v1.9.0") in by_name
    assert ("golang.org/x/net", "v0.30.0") not in by_name
    assert all(d.ecosystem == "Go" and d.is_direct for d in dependencies)


def test_parse_go_mod_extracts_direct_dependencies(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "\n".join(
            [
                "module example.com/demo",
                "",
                "go 1.22",
                "",
                "require (",
                "  github.com/gin-gonic/gin v1.10.0",
                "  golang.org/x/net v0.30.0 // indirect",
                ")",
                "",
                "require github.com/stretchr/testify v1.9.0",
            ]
        ),
        encoding="utf-8",
    )

    dependency_names = parse_go_mod(go_mod)
    assert "github.com/gin-gonic/gin" in dependency_names
    assert "github.com/stretchr/testify" in dependency_names
    assert "golang.org/x/net" not in dependency_names


def test_parse_go_sum_extracts_versions_and_directness(tmp_path: Path) -> None:
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "\n".join(
            [
                "github.com/gin-gonic/gin v1.10.0 h1:abc",
                "github.com/gin-gonic/gin v1.10.0/go.mod h1:def",
                "golang.org/x/text v0.19.0 h1:ghi",
            ]
        ),
        encoding="utf-8",
    )

    dependencies = parse_go_sum(go_sum, {"github.com/gin-gonic/gin"})
    by_name = {(dependency.name, dependency.version): dependency for dependency in dependencies}
    assert ("github.com/gin-gonic/gin", "v1.10.0") in by_name
    assert ("golang.org/x/text", "v0.19.0") in by_name
    assert ("github.com/gin-gonic/gin", "v1.10.0/go.mod") not in by_name
    assert by_name[("github.com/gin-gonic/gin", "v1.10.0")].is_direct is True
    assert by_name[("golang.org/x/text", "v0.19.0")].is_direct is False


def test_parse_composer_json_extracts_direct_dependencies(tmp_path: Path) -> None:
    composer_json = tmp_path / "composer.json"
    composer_json.write_text(
        json.dumps(
            {
                "require": {"php": "^8.2", "guzzlehttp/guzzle": "^7.0"},
                "require-dev": {"phpunit/phpunit": "^11.0"},
            }
        ),
        encoding="utf-8",
    )

    direct_dependencies = parse_composer_json(composer_json)
    assert "guzzlehttp/guzzle" in direct_dependencies
    assert "phpunit/phpunit" in direct_dependencies
    assert "php" not in direct_dependencies


def test_parse_composer_lock_extracts_dependencies(tmp_path: Path) -> None:
    composer_lock = tmp_path / "composer.lock"
    composer_lock.write_text(
        json.dumps(
            {
                "packages": [
                    {"name": "guzzlehttp/guzzle", "version": "7.8.1"},
                    {"name": "psr/http-client", "version": "1.0.3"},
                ],
                "packages-dev": [{"name": "phpunit/phpunit", "version": "11.4.0"}],
            }
        ),
        encoding="utf-8",
    )

    dependencies = parse_composer_lock(composer_lock, {"guzzlehttp/guzzle", "phpunit/phpunit"})
    by_name = {(dependency.name, dependency.version): dependency for dependency in dependencies}
    assert ("guzzlehttp/guzzle", "7.8.1") in by_name
    assert ("psr/http-client", "1.0.3") in by_name
    assert ("phpunit/phpunit", "11.4.0") in by_name
    assert by_name[("guzzlehttp/guzzle", "7.8.1")].is_direct is True
    assert by_name[("phpunit/phpunit", "11.4.0")].is_direct is True
    assert by_name[("psr/http-client", "1.0.3")].is_direct is False


def test_parse_yarn_lock_yarn_v1_classic(tmp_path: Path) -> None:
    """Parse Yarn v1 classic lockfile format."""
    yarn_lock = tmp_path / "yarn.lock"
    yarn_lock.write_text(
        "\n".join(
            [
                '"lodash@^4.17.0":',
                ' version "4.17.21"',
                ' resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
                "",
                '"chalk@^2.0.0":',
                ' version "2.4.2"',
                ' resolved "https://registry.yarnpkg.com/chalk/-/chalk-2.4.2.tgz"',
            ]
        ),
        encoding="utf-8",
    )

    dependencies = parse_yarn_lock(yarn_lock, {"lodash", "chalk"})
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("lodash", "4.17.21") in by_name
    assert ("chalk", "2.4.2") in by_name
    assert by_name[("lodash", "4.17.21")].is_direct is True
    assert by_name[("chalk", "2.4.2")].is_direct is True


def test_parse_yarn_lock_yarn_berry(tmp_path: Path) -> None:
    """Parse Yarn Berry (v2+) lockfile format."""
    yarn_lock = tmp_path / "yarn.lock"
    yarn_lock.write_text(
        "\n".join(
            [
                "__metadata:",
                "  version: 8",
                "  cacheKey: 10",
                "",
                '"lodash@npm:^4.17.0":',
                "  version: 4.17.21",
                '  resolution: "lodash@npm:4.17.21"',
                "",
                '"chalk@npm:^5.0.0":',
                "  version: 5.3.0",
                '  resolution: "chalk@npm:5.3.0"',
            ]
        ),
        encoding="utf-8",
    )

    dependencies = parse_yarn_lock(yarn_lock, {"lodash", "chalk"})
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("lodash", "4.17.21") in by_name
    assert ("chalk", "5.3.0") in by_name
    assert by_name[("lodash", "4.17.21")].is_direct is True
    assert by_name[("chalk", "5.3.0")].is_direct is True


def test_parse_gemfile_lock_extracts_specs(tmp_path: Path) -> None:
    lock = tmp_path / "Gemfile.lock"
    lock.write_text(
        "\n".join(
            [
                "GEM",
                "  remote: https://rubygems.org/",
                "  specs:",
                "    rack (2.2.8)",
                "      webrick (1.8.1)",
                "",
                "PLATFORMS",
                "  ruby",
                "",
                "DEPENDENCIES",
                "  rack",
                "",
            ]
        ),
        encoding="utf-8",
    )
    dependencies = parse_gemfile_lock(lock, {"rack"})
    by_key = {(d.name, d.version): d for d in dependencies}
    assert ("rack", "2.2.8") in by_key
    assert ("webrick", "1.8.1") in by_key
    assert by_key[("rack", "2.2.8")].ecosystem == "RubyGems"
    assert by_key[("rack", "2.2.8")].is_direct is True
    assert by_key[("webrick", "1.8.1")].is_direct is False


def test_parse_pubspec_lock_extracts_packages(tmp_path: Path) -> None:
    lock = tmp_path / "pubspec.lock"
    lock.write_text(
        "\n".join(
            [
                "# Generated by pub",
                "packages:",
                "  async:",
                '    version: "2.11.0"',
                "    dependency: transitive",
                "  collection:",
                '    version: "1.18.0"',
                "    dependency: direct",
            ]
        ),
        encoding="utf-8",
    )
    dependencies = parse_pubspec_lock(lock, {"collection"})
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("async", "2.11.0") in by_name
    assert ("collection", "1.18.0") in by_name
    assert by_name[("collection", "1.18.0")].ecosystem == "Pub"
    assert by_name[("collection", "1.18.0")].is_direct is True


def test_parse_mix_lock_extracts_hex_packages(tmp_path: Path) -> None:
    lock = tmp_path / "mix.lock"
    lock.write_text(
        '%{"decimal" => {:hex, :decimal, "2.1.1", "abc", [:mix], [], 0, "hexpm"}, '
        '"ecto" => {:hex, :ecto, "3.10.3", "def", [:mix], [], 0, "hexpm"}}',
        encoding="utf-8",
    )
    dependencies = parse_mix_lock(lock, {"ecto"})
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("decimal", "2.1.1") in by_name
    assert ("ecto", "3.10.3") in by_name
    assert by_name[("ecto", "3.10.3")].ecosystem == "Hex"


def test_parse_packages_lock_json_v2(tmp_path: Path) -> None:
    plock = tmp_path / "packages.lock.json"
    plock.write_text(
        json.dumps(
            {
                "version": 2,
                "dependencies": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "resolved": "13.0.3",
                    },
                    "System.Text.Json": {
                        "type": "Transitive",
                        "resolved": "8.0.0",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    dependencies = parse_packages_lock_json(plock, set())
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("Newtonsoft.Json", "13.0.3") in by_name
    assert by_name[("Newtonsoft.Json", "13.0.3")].ecosystem == "NuGet"
    assert by_name[("Newtonsoft.Json", "13.0.3")].is_direct is True
    assert by_name[("System.Text.Json", "8.0.0")].is_direct is False


def test_parse_pom_xml_extracts_maven_coordinates(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    pom.write_text(
        '\n'.join(
            [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<project xmlns="http://maven.apache.org/POM/4.0.0">',
                "  <modelVersion>4.0.0</modelVersion>",
                "  <dependencies>",
                "    <dependency>",
                "      <groupId>com.fasterxml.jackson.core</groupId>",
                "      <artifactId>jackson-databind</artifactId>",
                "      <version>2.15.2</version>",
                "    </dependency>",
                "  </dependencies>",
                "</project>",
            ]
        ),
        encoding="utf-8",
    )
    dependencies = parse_pom_xml(pom)
    assert len(dependencies) == 1
    assert dependencies[0].name == "com.fasterxml.jackson.core:jackson-databind"
    assert dependencies[0].version == "2.15.2"
    assert dependencies[0].ecosystem == "Maven"


def test_parse_package_resolved_swift_pins(tmp_path: Path) -> None:
    resolved = tmp_path / "Package.resolved"
    resolved.write_text(
        json.dumps(
            {
                "pins": [
                    {
                        "identity": "swift-nio",
                        "state": {"version": "2.40.0"},
                    }
                ],
                "version": 2,
            }
        ),
        encoding="utf-8",
    )
    dependencies = parse_package_resolved(resolved, {"swift-nio"})
    assert len(dependencies) == 1
    assert dependencies[0].name == "swift-nio"
    assert dependencies[0].version == "2.40.0"
    assert dependencies[0].ecosystem == "SwiftURL"


def test_parse_github_workflow_actions_uses_pins(tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text(
        "\n".join(
            [
                "jobs:",
                "  build:",
                "    steps:",
                "      - uses: actions/checkout@v4",
                "      - uses: actions/setup-node@v4",
            ]
        ),
        encoding="utf-8",
    )
    dependencies = parse_github_workflow_actions(wf)
    by_name = {(d.name, d.version): d for d in dependencies}
    assert ("actions/checkout", "v4") in by_name
    assert ("actions/setup-node", "v4") in by_name
    assert by_name[("actions/checkout", "v4")].ecosystem == "GitHub Actions"

