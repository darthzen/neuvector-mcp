"""Shared fixtures. Every test runs fully offline against a respx-mocked controller."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from neuvector_mcp.client import NeuVectorClient
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


class FakeServices:
    """The service half of the controller, with its two silent failure modes.

    A plain ``respond(200)`` mock cannot catch the bugs these tools exist to
    avoid, because the real controller answers 200 to changes it discards. This
    fake reproduces both measured behaviours:

    * a mode moves only one rung along Discover -> Monitor -> Protect, and a
      two-rung jump is accepted and dropped;
    * with ``apply_writes=False`` nothing is applied at all, which is what a
      caller sees when it aims a payload at an inert route.

    ``GET /v1/service`` answers the prefix name filter the read path uses.
    """

    LADDER = ("Discover", "Monitor", "Protect")

    def __init__(
        self, services: dict[str, dict[str, Any]] | None = None, *, apply_writes: bool = True
    ) -> None:
        self.services: dict[str, dict[str, Any]] = {
            name: {"name": name, "domain": name.rpartition(".")[2], **fields}
            for name, fields in (services or {}).items()
        }
        self.apply_writes = apply_writes
        #: Every ``config`` object received, in order, for asserting the walk.
        self.patches: list[dict[str, Any]] = []

    def install(self, router: respx.MockRouter) -> FakeServices:
        """Bind the read and write routes on ``router`` and return self."""
        self.reads = router.get("/v1/service").mock(side_effect=self._get)
        self.writes = router.patch("/v1/service/config").mock(side_effect=self._patch)
        return self

    def mode(self, service: str, field: str = "policy_mode") -> Any:
        """Current value of one field, for asserting the end state."""
        return self.services[service].get(field)

    def _get(self, request: httpx.Request) -> httpx.Response:
        raw = request.url.params.get("f_name", "")
        prefix = raw.partition(",")[2] if raw.startswith("prefix,") else raw
        matched = [item for name, item in self.services.items() if name.startswith(prefix)]
        return httpx.Response(200, json={"services": matched})

    def _patch(self, request: httpx.Request) -> httpx.Response:
        config = dict(json.loads(request.read()).get("config", {}))
        self.patches.append(config)
        if self.apply_writes:
            for name in config.get("services", []):
                item = self.services.get(name)
                if item is None:
                    continue
                for field, value in config.items():
                    if field == "services":
                        continue
                    if field in ("policy_mode", "profile_mode") and not self._adjacent(
                        item.get(field), value
                    ):
                        continue  # the controller drops it, and still returns 200
                    item[field] = value
        return httpx.Response(200, json={})

    def _adjacent(self, current: Any, target: Any) -> bool:
        if current not in self.LADDER or target not in self.LADDER:
            return False
        return abs(self.LADDER.index(current) - self.LADDER.index(target)) <= 1


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


@pytest.fixture
async def nv_client(nv_mock: respx.MockRouter) -> Any:
    """A bare NeuVectorClient, for exercising helpers below the MCP layer."""
    settings = make_settings()
    http = NeuVectorClient.build_http_client(settings)
    try:
        yield NeuVectorClient(settings, http)
    finally:
        await http.aclose()
