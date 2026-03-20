from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import httpx

from dep_scanner.maintenance import (
    build_package_health,
    escape_go_module_path,
    fetch_github_actions_release,
    months_between,
    parse_timestamp,
)
from dep_scanner.models import Dependency


def test_escape_go_module_path_uppercase_segments() -> None:
    assert escape_go_module_path("github.com/Azure/azure-sdk-for-go") == "github.com/!azure/azure-sdk-for-go"


def test_parse_timestamp_adds_utc_for_naive() -> None:
    parsed = parse_timestamp("2024-06-01T12:00:00")
    assert parsed is not None
    assert parsed.tzinfo == UTC


def test_months_between_respects_timezones() -> None:
    older = datetime(2024, 1, 15, tzinfo=UTC)
    newer = datetime(2025, 3, 14, tzinfo=UTC)
    assert months_between(older, newer) == 13


def test_build_package_health_marks_unmaintained() -> None:
    dependency = Dependency(
        name="demo",
        version="1.0.0",
        ecosystem="PyPI",
        is_direct=True,
        source="requirements.txt",
    )

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return {
                "urls": [
                    {"upload_time_iso_8601": "2010-01-01T00:00:00Z"},
                ],
            }

    client = MagicMock(spec=httpx.Client)
    client.get.return_value = FakeResponse()

    health = build_package_health([dependency], months_unmaintained=12, http_client=client)
    assert len(health) == 1
    assert health[0].is_unmaintained is True
    assert health[0].months_since_release is not None


def test_fetch_github_actions_release_parses_published_at() -> None:
    dependency = Dependency(
        name="actions/checkout",
        version="v4",
        ecosystem="GitHub Actions",
        is_direct=True,
        source="ci.yml",
    )

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return {"published_at": "2024-01-15T12:00:00Z"}

    client = MagicMock(spec=httpx.Client)
    client.get.return_value = FakeResponse()

    result = fetch_github_actions_release(dependency, client, github_token=None)
    assert result == datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
