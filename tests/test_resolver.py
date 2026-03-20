from __future__ import annotations

from pathlib import Path

import httpx

from dep_scanner.resolver import resolve_dependencies


def test_resolve_go_mod_without_sum_returns_direct_requires(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "\n".join(
            [
                "module example.com/demo",
                "go 1.22",
                "",
                "require github.com/gin-gonic/gin v1.10.0",
            ]
        ),
        encoding="utf-8",
    )
    with httpx.Client() as client:
        dependencies, warnings = resolve_dependencies([go_mod], client)
    assert len(dependencies) == 1
    assert dependencies[0].name == "github.com/gin-gonic/gin"
    assert dependencies[0].version == "v1.10.0"
    assert any("go.sum" in warning for warning in warnings)
