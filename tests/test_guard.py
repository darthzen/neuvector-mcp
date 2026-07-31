"""Write-guard contract tests. These are the safety-critical tests."""

from __future__ import annotations

import json

import pytest
import respx
from fastmcp import Client

from conftest import FakeServices, make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

PATCH_SERVICE_CONFIG = "/v1/service/config"


async def test_first_call_returns_plan_and_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_SERVICE_CONFIG).respond(200, json={})
    result = await client.call_tool(
        "nv_set_group_policy_mode", {"group_name": "nv.api.prod", "mode": "Protect"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "blocked immediately" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_confirmed_call_applies(client, nv_mock: respx.MockRouter) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Monitor"}}).install(nv_mock)
    args = {"group_name": "nv.api.prod", "mode": "Protect"}
    plan = await client.call_tool("nv_set_group_policy_mode", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_set_group_policy_mode", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert fake.writes.call_count == 1
    assert json.loads(fake.writes.calls.last.request.read()) == {
        "config": {"services": ["api.prod"], "policy_mode": "Protect"}
    }
    assert fake.mode("api.prod") == "Protect"


async def test_confirmed_call_steps_through_monitor(client, nv_mock: respx.MockRouter) -> None:
    """Discover -> Protect on this endpoint is accepted with 200 and dropped."""
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}).install(nv_mock)
    args = {"group_name": "nv.api.prod", "mode": "Protect"}
    plan = await client.call_tool("nv_set_group_policy_mode", args)

    result = await client.call_tool(
        "nv_set_group_policy_mode",
        {**args, "confirm": plan.structured_content["confirm_token"]},
    )

    assert [config["policy_mode"] for config in fake.patches] == ["Monitor", "Protect"]
    assert fake.mode("api.prod") == "Protect"
    assert "Discover -> Monitor -> Protect" in result.structured_content["effect"]


async def test_confirmed_call_refuses_to_claim_a_dropped_change(
    client, nv_mock: respx.MockRouter
) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}, apply_writes=False).install(
        nv_mock
    )
    args = {"group_name": "nv.api.prod", "mode": "Monitor"}
    plan = await client.call_tool("nv_set_group_policy_mode", args)

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_group_policy_mode",
            {**args, "confirm": plan.structured_content["confirm_token"]},
        )

    assert "did not apply" in str(excinfo.value)
    assert fake.writes.call_count == 1


async def test_confirmed_call_on_an_unknown_service_writes_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}).install(nv_mock)
    args = {"group_name": "nv.typo.prod", "mode": "Monitor"}
    plan = await client.call_tool("nv_set_group_policy_mode", args)

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_group_policy_mode",
            {**args, "confirm": plan.structured_content["confirm_token"]},
        )

    assert "no service named" in str(excinfo.value)
    assert fake.writes.call_count == 0


async def test_confirmed_call_at_target_sends_no_write(client, nv_mock: respx.MockRouter) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Protect"}}).install(nv_mock)
    args = {"group_name": "nv.api.prod", "mode": "Protect"}
    plan = await client.call_tool("nv_set_group_policy_mode", args)

    result = await client.call_tool(
        "nv_set_group_policy_mode",
        {**args, "confirm": plan.structured_content["confirm_token"]},
    )

    assert result.structured_content["status"] == "applied"
    assert "no change" in result.structured_content["effect"]
    assert fake.writes.call_count == 0


async def test_custom_group_is_rejected_without_controller_call(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(PATCH_SERVICE_CONFIG).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_group_policy_mode", {"group_name": "custom-group", "mode": "Protect"}
        )
    assert "not a learned group" in str(excinfo.value)
    assert route.call_count == 0


async def test_token_is_bound_to_arguments(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.patch(PATCH_SERVICE_CONFIG).respond(200, json={})
    monitor_token = confirm_token(
        "nv_set_group_policy_mode",
        "nv.api.prod",
        {"config": {"services": ["api.prod"], "policy_mode": "Monitor"}},
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
    route = nv_mock.patch(PATCH_SERVICE_CONFIG).respond(200, json={})
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
