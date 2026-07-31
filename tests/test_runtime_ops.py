"""runtime_ops toolset contract tests.

These four tools act on live workloads, so every test below exists to prove one
thing: nothing reaches the controller until the operator has confirmed the plan.
"""

from __future__ import annotations

import json

import pytest
import respx
from fastmcp import Client

from conftest import make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

WORKLOAD = "a1b2c3d4e5f6"
QUARANTINE_PATH = f"/v1/workload/request/{WORKLOAD}"
SERVICE_BATCH = "/v1/service/config"
SERVICE_NETWORK = "/v1/service/config/network"
SERVICE_PROFILE = "/v1/service/config/profile"
SNIFFER = "/v1/sniffer"


# -- nv_quarantine_workload -----------------------------------------------------


async def test_quarantine_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(QUARANTINE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_quarantine_workload",
        {"workload_id": WORKLOAD, "namespace": "prod", "action": "quarantine"},
    )
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "fail immediately" in body["effect"]
    assert body["payload"] == {"request": {"command": "quarantine"}}
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_quarantine_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(QUARANTINE_PATH).respond(200, json={})
    args = {"workload_id": WORKLOAD, "namespace": "prod", "action": "quarantine"}
    plan = await client.call_tool("nv_quarantine_workload", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_quarantine_workload", {**args, "confirm": token})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {"request": {"command": "quarantine"}}
    assert "namespace" not in route.calls.last.request.url.params, (
        "namespace is a guard argument and is never sent to the controller"
    )


async def test_unquarantine_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(QUARANTINE_PATH).respond(200, json={})
    args = {"workload_id": WORKLOAD, "namespace": "prod", "action": "unquarantine"}
    plan = await client.call_tool("nv_quarantine_workload", args)
    assert "Restore network connectivity" in plan.structured_content["effect"]
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_quarantine_workload", {**args, "confirm": token})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {"request": {"command": "unquarantine"}}


async def test_quarantine_token_bound_to_action(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(QUARANTINE_PATH).respond(200, json={})
    unquarantine_token = confirm_token(
        "nv_quarantine_workload", WORKLOAD, {"request": {"command": "unquarantine"}}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_quarantine_workload",
            {
                "workload_id": WORKLOAD,
                "namespace": "prod",
                "action": "quarantine",
                "confirm": unquarantine_token,
            },
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_quarantine_outside_allowed_namespace_refused(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(allowed_namespaces=("staging",)))
    route = nv_mock.post(QUARANTINE_PATH).respond(200, json={})
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool(
                "nv_quarantine_workload",
                {"workload_id": WORKLOAD, "namespace": "prod", "action": "quarantine"},
            )
    assert "outside NV_ALLOWED_NAMESPACES" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_set_service_mode --------------------------------------------------------


async def test_set_service_mode_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    result = await client.call_tool(
        "nv_set_service_mode",
        {"services": ["api.prod", "web.prod"], "policy_mode": "Protect"},
    )
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "blocked immediately" in body["effect"]
    assert "api.prod, web.prod" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_set_service_mode_confirmed_applies_to_batch_endpoint(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    args = {
        "services": ["api.prod", "web.prod"],
        "policy_mode": "Monitor",
        "not_scored": False,
    }
    plan = await client.call_tool("nv_set_service_mode", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_set_service_mode", {**args, "confirm": token})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "services": ["api.prod", "web.prod"],
            "policy_mode": "Monitor",
            "not_scored": False,
        }
    }


async def test_set_service_mode_network_scope_uses_network_endpoint(
    client, nv_mock: respx.MockRouter
) -> None:
    batch = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    network = nv_mock.patch(SERVICE_NETWORK).respond(200, json={})
    args = {"services": ["api.prod"], "scope": "network", "policy_mode": "Protect"}
    plan = await client.call_tool("nv_set_service_mode", args)
    token = plan.structured_content["confirm_token"]

    await client.call_tool("nv_set_service_mode", {**args, "confirm": token})

    assert network.call_count == 1
    assert batch.call_count == 0
    assert json.loads(network.calls.last.request.read()) == {
        "config": {"services": ["api.prod"], "policy_mode": "Protect"}
    }


async def test_set_service_mode_profile_scope_uses_profile_endpoint(
    client, nv_mock: respx.MockRouter
) -> None:
    batch = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    profile = nv_mock.patch(SERVICE_PROFILE).respond(200, json={})
    args = {
        "services": ["api.prod"],
        "scope": "profile",
        "baseline_profile": "zero-drift",
    }
    plan = await client.call_tool("nv_set_service_mode", args)
    token = plan.structured_content["confirm_token"]

    await client.call_tool("nv_set_service_mode", {**args, "confirm": token})

    assert profile.call_count == 1
    assert batch.call_count == 0
    assert json.loads(profile.calls.last.request.read()) == {
        "config": {"services": ["api.prod"], "baseline_profile": "zero-drift"}
    }


async def test_set_service_mode_sorts_services_for_stable_token(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    forward = await client.call_tool(
        "nv_set_service_mode",
        {"services": ["api.prod", "web.prod"], "policy_mode": "Monitor"},
    )
    reversed_ = await client.call_tool(
        "nv_set_service_mode",
        {"services": ["web.prod", "api.prod"], "policy_mode": "Monitor"},
    )

    assert forward.structured_content["payload"]["config"]["services"] == [
        "api.prod",
        "web.prod",
    ]
    assert (
        forward.structured_content["confirm_token"] == reversed_.structured_content["confirm_token"]
    )
    assert forward.structured_content["confirm_token"] == confirm_token(
        "nv_set_service_mode",
        "api.prod,web.prod",
        {"config": {"services": ["api.prod", "web.prod"], "policy_mode": "Monitor"}},
    )


async def test_set_service_mode_multi_namespace_refused_outside_allowlist(
    nv_mock: respx.MockRouter,
) -> None:
    server = build_server(make_settings(allowed_namespaces=("prod",)))
    route = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool(
                "nv_set_service_mode",
                {"services": ["api.prod", "web.staging"], "policy_mode": "Protect"},
            )
    assert "outside NV_ALLOWED_NAMESPACES" in str(excinfo.value)
    assert "staging" in str(excinfo.value)
    assert route.call_count == 0, "a batch is never partially applied"


async def test_set_service_mode_no_fields_raises(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_set_service_mode", {"services": ["api.prod"]})
    assert "at least one of policy_mode" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_start_packet_capture ----------------------------------------------------


async def test_start_packet_capture_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SNIFFER).respond(200, json={})
    result = await client.call_tool(
        "nv_start_packet_capture",
        {"workload_id": WORKLOAD, "namespace": "prod", "duration_s": 30, "filter": "tcp port 443"},
    )
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "tcp port 443" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_start_packet_capture_confirmed_applies_with_f_workload(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SNIFFER).respond(200, json={"sniffer": {"id": "cap-1"}})
    args = {
        "workload_id": WORKLOAD,
        "namespace": "prod",
        "duration_s": 30,
        "filter": "tcp port 443",
        "file_number": 2,
    }
    plan = await client.call_tool("nv_start_packet_capture", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_start_packet_capture", {**args, "confirm": token})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.url.params["f_workload"] == WORKLOAD
    assert json.loads(route.calls.last.request.read()) == {
        "sniffer": {"file_number": 2, "duration": 30, "filter": "tcp port 443"}
    }
    assert result.structured_content["controller_response"] == {"sniffer": {"id": "cap-1"}}


async def test_start_packet_capture_unfiltered_effect_warns(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SNIFFER).respond(200, json={})
    result = await client.call_tool(
        "nv_start_packet_capture", {"workload_id": WORKLOAD, "namespace": "prod"}
    )
    assert "NO FILTER IS SET" in result.structured_content["effect"]
    assert route.call_count == 0


async def test_start_packet_capture_never_fetches_pcap(client, nv_mock: respx.MockRouter) -> None:
    start = nv_mock.post(SNIFFER).respond(200, json={"sniffer": {"id": "cap-1"}})
    pcap = nv_mock.get("/v1/sniffer/cap-1/pcap").respond(200, json={})
    args = {"workload_id": WORKLOAD, "namespace": "prod", "filter": "tcp port 443"}
    plan = await client.call_tool("nv_start_packet_capture", args)
    await client.call_tool(
        "nv_start_packet_capture", {**args, "confirm": plan.structured_content["confirm_token"]}
    )

    assert start.call_count == 1
    assert pcap.call_count == 0, "captured packets are never read by this server"


async def test_start_packet_capture_outside_allowed_namespace_refused(
    nv_mock: respx.MockRouter,
) -> None:
    server = build_server(make_settings(allowed_namespaces=("staging",)))
    route = nv_mock.post(SNIFFER).respond(200, json={})
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool(
                "nv_start_packet_capture", {"workload_id": WORKLOAD, "namespace": "prod"}
            )
    assert "outside NV_ALLOWED_NAMESPACES" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_stop_packet_capture -----------------------------------------------------


async def test_stop_packet_capture_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch("/v1/sniffer/stop/cap-1").respond(200, json={})
    result = await client.call_tool("nv_stop_packet_capture", {"capture_id": "cap-1"})
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "stay on the enforcer" in body["effect"]
    assert body["payload"] == {}
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_stop_packet_capture_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch("/v1/sniffer/stop/cap-1").respond(200, json={})
    plan = await client.call_tool("nv_stop_packet_capture", {"capture_id": "cap-1"})
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool(
        "nv_stop_packet_capture", {"capture_id": "cap-1", "confirm": token}
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.read() == b"", "this route takes no request body"


# -- module-wide contracts ------------------------------------------------------


async def test_runtime_ops_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}

    assert "nv_get_system_summary" in names
    assert "nv_quarantine_workload" not in names
    assert "nv_set_service_mode" not in names
    assert "nv_start_packet_capture" not in names
    assert "nv_stop_packet_capture" not in names


async def test_runtime_ops_annotations_declare_traffic_impact(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}

    assert tools["nv_quarantine_workload"].annotations.readOnlyHint is False
    assert tools["nv_quarantine_workload"].annotations.destructiveHint is True
    assert tools["nv_quarantine_workload"].annotations.idempotentHint is True
    assert tools["nv_set_service_mode"].annotations.destructiveHint is False
    assert tools["nv_start_packet_capture"].annotations.destructiveHint is False
    assert tools["nv_stop_packet_capture"].annotations.destructiveHint is False


async def test_runtime_ops_error_codes_classify(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post(QUARANTINE_PATH).respond(
        409, json={"code": 22, "error": "Container not running", "message": "exited"}
    )
    args = {"workload_id": WORKLOAD, "namespace": "prod", "action": "quarantine"}
    plan = await client.call_tool("nv_quarantine_workload", args)
    with pytest.raises(Exception) as not_running:
        await client.call_tool(
            "nv_quarantine_workload",
            {**args, "confirm": plan.structured_content["confirm_token"]},
        )
    assert "code=22" in str(not_running.value)
    assert "Container not running" in str(not_running.value)

    nv_mock.patch("/v1/sniffer/stop/cap-1").respond(
        403, json={"code": 25, "error": "Object access denied", "message": "domain prod"}
    )
    stop_plan = await client.call_tool("nv_stop_packet_capture", {"capture_id": "cap-1"})
    with pytest.raises(Exception) as denied:
        await client.call_tool(
            "nv_stop_packet_capture",
            {"capture_id": "cap-1", "confirm": stop_plan.structured_content["confirm_token"]},
        )
    assert "code=25" in str(denied.value)
    assert "Object access denied" in str(denied.value)
