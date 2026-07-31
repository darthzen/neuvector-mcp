"""Shared fixtures. Every test runs fully offline against a respx-mocked controller."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import Client

from neuvector_mcp.config import ALL_TOOLSETS, Settings
from neuvector_mcp.server import build_server

CONTROLLER = "https://nv-controller.test:10443"
FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Any:
    """Load tests/fixtures/<name>.json."""
    return json.loads((FIXTURES / f"{name}.json").read_text())


def make_settings(**overrides: Any) -> Settings:
    """Settings for tests: API-key auth, all toolsets, no confirm token unless asked."""
    base: dict[str, Any] = dict(
        controller_url=CONTROLLER,
        verify_tls=False,
        auth_mode="apikey",
        api_access_key="test-access",
        api_secret_key="test-secret",
        transport="stdio",
        read_only=False,
        toolsets=ALL_TOOLSETS,
        require_confirm_token=True,
        log_level="WARNING",
        log_format="console",
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def nv_mock() -> Iterator[respx.MockRouter]:
    """respx router bound to the controller base URL, with login pre-stubbed."""
    with respx.mock(base_url=CONTROLLER, assert_all_called=False) as router:
        router.get("/v1/system/summary").respond(200, json=fixture("system_summary"))
        yield router


@pytest.fixture
async def client(nv_mock: respx.MockRouter) -> Any:
    """In-process MCP client against a server with every toolset enabled."""
    server = build_server(make_settings())
    async with Client(server) as c:
        yield c
