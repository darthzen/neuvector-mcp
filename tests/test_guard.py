"""Write-guard contract tests. These are the safety-critical tests."""
from __future__ import annotations

import json

import pytest
import respx
from conftest import make_settings
from fastmcp import Client

from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

PATCH_GROUP = "/v1/group/nv.api.prod"


async def test_first_call_returns_plan_and_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_GROUP).respond(200, json={})
    result = await client.call_tool(
        "nv_set_group_policy_mode", {"group_name": "nv.api.prod", "mode": "Protect"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "blocked immediately" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_confirmed_call_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_GROUP).respond(200, json={})
    args = {"group_name": "nv.api.prod", "mode": "Protect"}
    plan = await client.call_tool("nv_set_group_policy_mode", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_set_group_policy_mode", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {"name": "nv.api.prod", "policy_mode": "Protect"}
    }


async def test_token_is_bound_to_arguments(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.patch(PATCH_GROUP).respond(200, json={})
    monitor_token = confirm_token(
        "nv_set_group_policy_mode",
        "nv.api.prod",
        {"config": {"name": "nv.api.prod", "policy_mode": "Monitor"}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_group_policy_mode",
            {"group_name": "nv.api.prod", "mode": "Protect", "confirm": monitor_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)


async def test_read_only_hides_mutating_toolsets(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}
    assert "nv_get_system_summary" in names
    assert "nv_set_group_policy_mode" not in names
    assert "nv_delete_group" not in names


async def test_namespace_allowlist_blocks_outside_namespace(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(allowed_namespaces=("staging",)))
    route = nv_mock.patch(PATCH_GROUP).respond(200, json={})
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool(
                "nv_set_group_policy_mode", {"group_name": "nv.api.prod", "mode": "Protect"}
            )
    assert "outside NV_ALLOWED_NAMESPACES" in str(excinfo.value)
    assert route.call_count == 0


async def test_annotations_declare_mutation(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    assert tools["nv_get_system_summary"].annotations.readOnlyHint is True
    assert tools["nv_delete_group"].annotations.readOnlyHint is False
    assert tools["nv_delete_group"].annotations.destructiveHint is True
