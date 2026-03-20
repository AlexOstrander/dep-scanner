from __future__ import annotations

from pathlib import Path

from dep_scanner.input_index import basename_index, detect_package_manager_label


def test_basename_index_first_wins_and_warns_on_duplicate(tmp_path: Path) -> None:
    first = tmp_path / "a" / "package.json"
    second = tmp_path / "b" / "package.json"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("{}", encoding="utf-8")
    second.write_text("{}", encoding="utf-8")

    index, warnings = basename_index([first, second])
    assert index["package.json"] == first
    assert len(warnings) == 1
    assert "Multiple inputs share basename" in warnings[0]


def test_detect_package_manager_label_sorted(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("x", encoding="utf-8")
    label = detect_package_manager_label([req])
    assert label == "pypi"
