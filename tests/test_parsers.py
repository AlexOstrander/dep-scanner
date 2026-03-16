from pathlib import Path

from dep_scanner.parsers import parse_requirements_txt


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

