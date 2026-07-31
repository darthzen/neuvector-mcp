"""runtime_ops toolset contract tests.

These four tools act on live workloads, so every test below exists to prove one
thing: nothing reaches the controller until the operator has confirmed the plan.
"""

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

WORKLOAD = "a1b2c3d4e5f6"
QUARANTINE_PATH = f"/v1/workload/request/{WORKLOAD}"
SERVICE_BATCH = "/v1/service/config"
SERVICE_NETWORK = "/v1/service/config/network"
SERVICE_PROFILE = "/v1/service/config/profile"
SNIFFER = "/v1/sniffer"


async def apply(client, args: dict) -> dict:
    """Preview, then confirm, and return the applied outcome."""
    plan = await client.call_tool("nv_set_service_mode", args)
    token = plan.structured_content["confirm_token"]
    result = await client.call_tool("nv_set_service_mode", {**args, "confirm": token})
    return result.structured_content


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
    fake = FakeServices(
        {"api.prod": {"policy_mode": "Discover"}, "web.prod": {"policy_mode": "Discover"}}
    ).install(nv_mock)
    result = await client.call_tool(
        "nv_set_service_mode",
        {"services": ["api.prod", "web.prod"], "policy_mode": "Protect"},
    )
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "blocked immediately" in body["effect"]
    assert "api.prod, web.prod" in body["effect"]
    assert fake.writes.call_count == 0, "the guard must not touch the controller"
    assert fake.reads.call_count == 0, "not even the read-before-write, which comes after confirm"


async def test_set_service_mode_confirmed_applies_to_batch_endpoint(
    client, nv_mock: respx.MockRouter
) -> None:
    fake = FakeServices(
        {
            "api.prod": {"policy_mode": "Discover", "not_scored": True},
            "web.prod": {"policy_mode": "Discover", "not_scored": True},
        }
    ).install(nv_mock)
    body = await apply(
        client,
        {"services": ["api.prod", "web.prod"], "policy_mode": "Monitor", "not_scored": False},
    )

    assert body["status"] == "applied"
    assert fake.writes.call_count == 1, "Discover -> Monitor is one rung; no stepping needed"
    assert json.loads(fake.writes.calls.last.request.read()) == {
        "config": {
            "services": ["api.prod", "web.prod"],
            "policy_mode": "Monitor",
            "not_scored": False,
        }
    }
    assert fake.mode("api.prod") == "Monitor"


async def test_set_service_mode_profile_mode_selected_by_payload_field(
    client, nv_mock: respx.MockRouter
) -> None:
    """The dimension is the payload field. The two sibling routes are never used."""
    network = nv_mock.patch(SERVICE_NETWORK).respond(200, json={})
    profile = nv_mock.patch(SERVICE_PROFILE).respond(200, json={})
    fake = FakeServices(
        {"api.prod": {"policy_mode": "Discover", "profile_mode": "Discover"}}
    ).install(nv_mock)

    await apply(client, {"services": ["api.prod"], "profile_mode": "Monitor"})

    assert network.call_count == 0 and profile.call_count == 0
    assert json.loads(fake.writes.calls.last.request.read()) == {
        "config": {"services": ["api.prod"], "profile_mode": "Monitor"}
    }
    assert fake.mode("api.prod", "profile_mode") == "Monitor"
    assert fake.mode("api.prod", "policy_mode") == "Discover", "the other dimension is untouched"


async def test_set_service_mode_steps_through_monitor_to_protect(
    client, nv_mock: respx.MockRouter
) -> None:
    """Discover -> Protect direct is accepted and dropped, so it must be walked."""
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}).install(nv_mock)

    body = await apply(client, {"services": ["api.prod"], "policy_mode": "Protect"})

    assert [config["policy_mode"] for config in fake.patches] == ["Monitor", "Protect"]
    assert fake.mode("api.prod") == "Protect"
    assert "verified" in body["effect"]
    assert "1 intermediate mode" in body["effect"]


async def test_set_service_mode_steps_both_dimensions(client, nv_mock: respx.MockRouter) -> None:
    fake = FakeServices(
        {"api.prod": {"policy_mode": "Discover", "profile_mode": "Monitor"}}
    ).install(nv_mock)

    await apply(
        client,
        {"services": ["api.prod"], "policy_mode": "Protect", "profile_mode": "Protect"},
    )

    assert fake.patches == [
        {"services": ["api.prod"], "policy_mode": "Monitor"},
        {"services": ["api.prod"], "policy_mode": "Protect", "profile_mode": "Protect"},
    ], "only the dimension that needs a rung gets one; the final payload carries both"
    assert fake.mode("api.prod") == "Protect"
    assert fake.mode("api.prod", "profile_mode") == "Protect"


async def test_set_service_mode_steps_only_the_services_that_need_it(
    client, nv_mock: respx.MockRouter
) -> None:
    fake = FakeServices(
        {
            "api.prod": {"policy_mode": "Discover"},
            "web.prod": {"policy_mode": "Monitor"},
            "db.prod": {"policy_mode": "Protect"},
        }
    ).install(nv_mock)

    await apply(
        client,
        {"services": ["web.prod", "api.prod", "db.prod"], "policy_mode": "Protect"},
    )

    assert fake.patches[0] == {"services": ["api.prod"], "policy_mode": "Monitor"}, (
        "web.prod is already adjacent and db.prod must not dip out of Protect"
    )
    assert len(fake.patches) == 2
    assert all(fake.mode(name) == "Protect" for name in ("api.prod", "web.prod", "db.prod"))


async def test_set_service_mode_already_at_target_sends_no_write(
    client, nv_mock: respx.MockRouter
) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Protect"}}).install(nv_mock)

    body = await apply(client, {"services": ["api.prod"], "policy_mode": "Protect"})

    assert body["status"] == "applied"
    assert "no change" in body["effect"]
    assert fake.writes.call_count == 0


async def test_set_service_mode_reports_a_silently_dropped_change(
    client, nv_mock: respx.MockRouter
) -> None:
    """A 200 the controller did not honour must never be reported as applied."""
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}, apply_writes=False).install(
        nv_mock
    )

    plan = await client.call_tool(
        "nv_set_service_mode", {"services": ["api.prod"], "policy_mode": "Monitor"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_service_mode",
            {
                "services": ["api.prod"],
                "policy_mode": "Monitor",
                "confirm": plan.structured_content["confirm_token"],
            },
        )

    assert "did not apply" in str(excinfo.value)
    assert "'Discover'" in str(excinfo.value), "the error names the state the service is really in"
    assert fake.writes.call_count == 1


async def test_set_service_mode_unknown_service_writes_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}).install(nv_mock)

    plan = await client.call_tool(
        "nv_set_service_mode", {"services": ["typo.prod"], "policy_mode": "Monitor"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_service_mode",
            {
                "services": ["typo.prod"],
                "policy_mode": "Monitor",
                "confirm": plan.structured_content["confirm_token"],
            },
        )

    assert "found no service named" in str(excinfo.value)
    assert fake.writes.call_count == 0


async def test_set_service_mode_token_distinguishes_the_two_dimensions(
    client, nv_mock: respx.MockRouter
) -> None:
    """Regression: with the dimension in the route, all scopes shared one token."""
    FakeServices({"api.prod": {"policy_mode": "Discover"}}).install(nv_mock)
    network = await client.call_tool(
        "nv_set_service_mode", {"services": ["api.prod"], "policy_mode": "Protect"}
    )
    profile = await client.call_tool(
        "nv_set_service_mode", {"services": ["api.prod"], "profile_mode": "Protect"}
    )

    assert (
        network.structured_content["confirm_token"] != profile.structured_content["confirm_token"]
    )


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
    assert "at least one of policy_mode, profile_mode" in str(excinfo.value)
    assert route.call_count == 0


async def test_set_service_mode_rejects_the_removed_scope_argument(
    client, nv_mock: respx.MockRouter
) -> None:
    """'profile' scope was a silent no-op; a caller still passing it must fail loudly."""
    route = nv_mock.patch(SERVICE_BATCH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_service_mode",
            {"services": ["api.prod"], "scope": "profile", "policy_mode": "Monitor"},
        )
    assert "scope" in str(excinfo.value)
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
