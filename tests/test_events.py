"""Events toolset contract tests.

The whole point of this toolset is that threat, violation and incident logs name
the same concepts with different json tags. A wrong tag returns an empty page
with no error, which reads as "no threats" - so every filter name is asserted
literally here.
"""

from __future__ import annotations

import json

import pytest
import respx
from fastmcp import Client

from conftest import fixture, make_settings
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio


# -- nv_query_security_events ---------------------------------------------------


async def test_query_threats_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/log/threat").respond(200, json=fixture("log_threat"))
    result = await client.call_tool(
        "nv_query_security_events",
        {"kind": "threat", "namespace": "prod", "severity": "Critical", "limit": 2},
    )

    params = route.calls.last.request.url.params
    assert params["f_client_workload_domain"] == "prod"
    assert params["f_severity"] == "Critical"
    assert params["s_reported_timestamp"] == "desc"
    assert params["start"] == "0"
    assert params["limit"] == "3", "must over-fetch by one to detect truncation"

    assert result.data.kind == "threat"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint
    assert result.data.dropped_outside_window == 0

    first = result.data.events[0]
    assert first.id == "th-0001"
    assert first.severity == "Critical"
    assert first.level == "Warning"
    assert first.client_namespace == "prod"
    assert first.client_id == "a1b2c3d4e5f6"
    assert first.server_namespace == "prod"
    assert first.applications == "HTTP"
    assert first.threat_id == 30001
    assert first.matched_rule_id == ""


async def test_query_violations_uses_level_and_client_domain(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/log/violation").respond(200, json=fixture("log_violation"))
    result = await client.call_tool(
        "nv_query_security_events",
        {"kind": "violation", "namespace": "prod", "severity": "Warning", "workload_id": "a1b2"},
    )

    params = route.calls.last.request.url.params
    assert params["f_client_domain"] == "prod"
    assert params["f_client_id"] == "a1b2"
    assert params["f_level"] == "Warning"
    assert "f_severity" not in params, "Violation has no 'severity' field"

    first = result.data.events[0]
    assert first.kind == "violation"
    assert first.severity == "Warning", "violation severity maps to 'level'"
    assert first.action == "deny"
    assert first.applications == "HTTPS, HTTP"
    assert first.matched_rule_id == "1024"
    assert first.count == 47, "violation count comes from 'sessions'"
    assert first.message == "", "Violation carries no message field"


async def test_query_incidents_uses_workload_domain(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/log/incident").respond(200, json=fixture("log_incident"))
    result = await client.call_tool(
        "nv_query_security_events",
        {"kind": "incident", "namespace": "prod", "workload_id": "a1b2c3d4e5f6"},
    )

    params = route.calls.last.request.url.params
    assert params["f_workload_domain"] == "prod"
    assert params["f_workload_id"] == "a1b2c3d4e5f6"

    first = result.data.events[0]
    assert first.kind == "incident"
    assert first.severity == "Critical", "incident severity maps to 'level'"
    assert first.client_id == "a1b2c3d4e5f6"
    assert first.client_namespace == "prod"
    assert first.server_namespace == "prod"
    assert first.proc_name == "nc"
    assert first.proc_path == "/usr/bin/nc"
    assert first.matched_rule_id == "rule-882"


async def test_security_events_kind_selects_path_and_filter_tags(
    client, nv_mock: respx.MockRouter
) -> None:
    """One case per kind: the path and the namespace/severity tags must differ."""
    expected = {
        "threat": ("/v1/log/threat", "threats", "f_client_workload_domain", "f_severity"),
        "violation": ("/v1/log/violation", "violations", "f_client_domain", "f_level"),
        "incident": ("/v1/log/incident", "incidents", "f_workload_domain", "f_level"),
    }
    for kind, (path, envelope, domain_tag, severity_tag) in expected.items():
        route = nv_mock.get(path).respond(200, json={envelope: []})
        await client.call_tool(
            "nv_query_security_events",
            {"kind": kind, "namespace": "prod", "severity": "High"},
        )
        params = route.calls.last.request.url.params
        assert params[domain_tag] == "prod", kind
        assert params[severity_tag] == "High", kind


async def test_side_server_switches_filter_field(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/log/threat").respond(200, json={"threats": []})
    await client.call_tool(
        "nv_query_security_events",
        {"kind": "threat", "namespace": "prod", "workload_id": "f6e5", "side": "server"},
    )
    params = route.calls.last.request.url.params
    assert params["f_server_workload_domain"] == "prod"
    assert params["f_server_workload_id"] == "f6e5"
    assert "f_client_workload_domain" not in params

    incident_route = nv_mock.get("/v1/log/incident").respond(200, json={"incidents": []})
    await client.call_tool(
        "nv_query_security_events",
        {"kind": "incident", "namespace": "prod", "workload_id": "f6e5", "side": "server"},
    )
    params = incident_route.calls.last.request.url.params
    assert params["f_remote_workload_domain"] == "prod"
    assert params["f_remote_workload_id"] == "f6e5"


async def test_both_time_bounds_send_gte_and_trim_client_side(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/log/threat").respond(200, json=fixture("log_threat"))
    result = await client.call_tool(
        "nv_query_security_events",
        {
            "kind": "threat",
            "since_timestamp": 1753700000,
            "until_timestamp": 1753800000,
            "limit": 10,
        },
    )
    params = route.calls.last.request.url.params
    assert params["f_reported_timestamp"] == "gte,1753700000", "lower bound goes server-side"

    # The fixture's newest entry (1753900000) is above until_timestamp and is trimmed.
    assert result.data.dropped_outside_window == 1
    assert [e.id for e in result.data.events] == ["th-0002", "th-0003"]
    assert result.data.page.returned == 2


async def test_security_events_time_window_trims_client_side(
    client, nv_mock: respx.MockRouter
) -> None:
    """until alone goes server-side as lte; both bounds trim after paging."""
    route = nv_mock.get("/v1/log/violation").respond(200, json=fixture("log_violation"))
    result = await client.call_tool(
        "nv_query_security_events", {"kind": "violation", "until_timestamp": 1753800500}
    )
    assert route.calls.last.request.url.params["f_reported_timestamp"] == "lte,1753800500"
    assert result.data.dropped_outside_window == 0, "no client-side trim when only 'until' is set"
    assert len(result.data.events) == 3

    both = await client.call_tool(
        "nv_query_security_events",
        {"kind": "violation", "since_timestamp": 1, "until_timestamp": 1753800500},
    )
    assert both.data.dropped_outside_window == 1
    assert [e.id for e in both.data.events] == ["vi-0002", "vi-0003"]


async def test_security_events_no_time_filter_when_unbounded(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/log/threat").respond(200, json={"threats": []})
    await client.call_tool("nv_query_security_events", {"kind": "threat", "newest_first": False})
    params = route.calls.last.request.url.params
    assert "f_reported_timestamp" not in params
    assert "s_reported_timestamp" not in params


# -- nv_get_threat_detail -------------------------------------------------------


async def test_threat_detail_omits_packet_by_default(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/log/threat/th-0001").respond(200, json=fixture("log_threat_detail"))
    result = await client.call_tool("nv_get_threat_detail", {"threat_id": "th-0001"})

    assert result.data.packet == ""
    assert result.data.packet_truncated is True, "withheld counts as truncated"
    assert result.data.packet_chars == 272
    assert result.data.cap_len == 320
    assert result.data.monitor is True
    assert result.data.target == "server"
    assert result.data.event.id == "th-0001"
    assert result.data.event.severity == "Critical"


async def test_threat_detail_clips_packet_to_budget(nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/log/threat/th-0001").respond(200, json=fixture("log_threat_detail"))
    server = build_server(make_settings(max_response_chars=100))
    async with Client(server) as c:
        result = await c.call_tool(
            "nv_get_threat_detail", {"threat_id": "th-0001", "include_packet": True}
        )
    assert len(result.data.packet) == 50, "clipped to max_response_chars // 2"
    assert result.data.packet_truncated is True
    assert result.data.packet_chars == 272


async def test_threat_detail_packet_is_clipped_when_requested(
    nv_mock: respx.MockRouter,
) -> None:
    """A generous budget returns the packet whole and reports no clipping."""
    nv_mock.get("/v1/log/threat/th-0001").respond(200, json=fixture("log_threat_detail"))
    server = build_server(make_settings(max_response_chars=60_000))
    async with Client(server) as c:
        result = await c.call_tool(
            "nv_get_threat_detail", {"threat_id": "th-0001", "include_packet": True}
        )
    assert len(result.data.packet) == 272
    assert result.data.packet_truncated is False


async def test_threat_detail_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/log/threat/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_threat_detail", {"threat_id": "nope"})
    assert "no threat event" in str(excinfo.value)


# -- nv_query_audit_events ------------------------------------------------------


async def test_query_audit_events_query_and_projection(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/log/audit").respond(200, json=fixture("log_audit"))
    result = await client.call_tool(
        "nv_query_audit_events",
        {
            "namespace": "prod",
            "workload_id": "a1b2c3d4e5f6",
            "level": "Warning",
            "name": "Container.Scan.Report",
            "since_timestamp": 1753000000,
        },
    )

    params = route.calls.last.request.url.params
    assert params["f_workload_domain"] == "prod"
    assert params["f_workload_id"] == "a1b2c3d4e5f6"
    assert params["f_level"] == "Warning"
    assert params["f_name"] == "Container.Scan.Report"
    assert params["f_reported_timestamp"] == "gte,1753000000"
    assert params["s_reported_timestamp"] == "desc"
    assert params["limit"] == "51"

    first = result.data.audits[0]
    assert first.name == "Container.Scan.Report"
    assert first.workload_namespace == "prod"
    assert first.high_vul_cnt == 4
    assert first.medium_vul_cnt == 11
    assert first.cvedb_version == "2026.07.28"
    assert first.registry_name == "example-registry"
    assert first.repository == "api-gateway"
    assert first.tag == "1.4.2"

    serialised = json.dumps(result.structured_content)
    assert "CVE-2026-0001" not in serialised, "CVE id arrays are never projected"


async def test_query_audit_events_truncates(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/log/audit").respond(200, json=fixture("log_audit"))
    result = await client.call_tool("nv_query_audit_events", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint
    assert len(result.data.audits) == 2


# -- nv_query_system_events -----------------------------------------------------


async def test_query_system_events_filters_by_user(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/log/event").respond(200, json=fixture("log_event"))
    result = await client.call_tool(
        "nv_query_system_events",
        {
            "user": "alice",
            "category": "user",
            "level": "Info",
            "namespace": "prod",
            "name": "Controller.API.Call",
        },
    )

    params = route.calls.last.request.url.params
    assert params["f_user"] == "alice"
    assert params["f_category"] == "user"
    assert params["f_level"] == "Info"
    assert params["f_workload_domain"] == "prod"
    assert params["f_name"] == "Controller.API.Call"

    first = result.data.events[0]
    assert first.user == "alice"
    assert first.rest_method == "POST"
    assert first.rest_request == "/v1/scan/registry"
    assert result.data.events[2].enforcer_limit == 20
    assert result.data.events[2].license_expire == "2026-08-30"


async def test_system_event_projection_drops_rest_body(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/log/event").respond(200, json=fixture("log_event"))
    result = await client.call_tool("nv_query_system_events", {})

    serialised = json.dumps(result.structured_content)
    assert "sup3rs3cr3t-do-not-leak" not in serialised
    assert "rest_body" not in serialised


async def test_system_events_never_project_rest_body(client, nv_mock: respx.MockRouter) -> None:
    """rest_body can carry registry passwords and bearer tokens: hard exclusion."""
    nv_mock.get("/v1/log/event").respond(
        200,
        json={
            "events": [
                {
                    "name": "Controller.API.Call",
                    "level": "Info",
                    "reported_timestamp": 1753903000,
                    "category": "user",
                    "user": "mallory",
                    "rest_method": "POST",
                    "rest_request": "/v1/user",
                    "rest_body": '{"user":{"username":"x","password":"pl41nt3xt-pw"}}',
                    "message": "REST request POST /v1/user by mallory",
                }
            ]
        },
    )
    result = await client.call_tool("nv_query_system_events", {})

    assert result.data.events[0].user == "mallory"
    serialised = json.dumps(result.structured_content)
    assert "pl41nt3xt-pw" not in serialised
    assert "password" not in serialised


# -- nv_get_system_alerts -------------------------------------------------------


async def test_system_alerts_reads_alerts_key(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/system/alerts").respond(200, json=fixture("system_alerts"))
    result = await client.call_tool("nv_get_system_alerts", {})

    assert result.data.count == 2
    assert result.data.alerts[0].startswith("The NeuVector licence expires")
    assert result.data.envelope_keys == ["alerts"]


async def test_system_alerts_falls_back_to_first_list_key(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/system/alerts").respond(
        200, json={"nv_alerts": [{"message": "Enforcer limit reached"}, {"name": "cfg.warning"}]}
    )
    result = await client.call_tool("nv_get_system_alerts", {})

    assert result.data.alerts == ["Enforcer limit reached", "cfg.warning"]
    assert result.data.count == 2
    assert result.data.envelope_keys == ["nv_alerts"]


async def test_events_tools_take_no_confirm_argument(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    for name in (
        "nv_query_security_events",
        "nv_get_threat_detail",
        "nv_query_audit_events",
        "nv_query_system_events",
        "nv_get_system_alerts",
    ):
        assert tools[name].annotations.readOnlyHint is True
        assert "confirm" not in (tools[name].inputSchema.get("properties") or {}), name
