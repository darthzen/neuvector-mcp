"""Inventory toolset contract tests."""

from __future__ import annotations

from typing import Any

import pytest
import respx
from fastmcp import Client

from conftest import fixture, make_settings
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def undoc_client(nv_mock: respx.MockRouter) -> Any:
    """MCP client whose server has NV_ALLOW_UNDOCUMENTED=true."""
    server = build_server(make_settings(allow_undocumented=True))
    async with Client(server) as c:
        yield c


async def test_system_summary(client, nv_mock: respx.MockRouter) -> None:
    result = await client.call_tool("nv_get_system_summary", {})
    assert result.data.hosts == 3
    assert result.data.cvedb_version == "2026.07.28"


async def test_list_workloads_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v2/workload").respond(200, json=fixture("workloads_v2"))
    result = await client.call_tool("nv_list_workloads", {"namespace": "prod", "limit": 2})

    request = route.calls.last.request
    assert request.url.params["f_domain"] == "prod"
    assert request.url.params["view"] == "pod"
    assert request.url.params["limit"] == "3", "must over-fetch by one to detect truncation"

    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint
    assert [w.id for w in result.data.workloads] == ["a1b2c3d4e5f6", "f6e5d4c3b2a1"]
    assert result.data.workloads[0].policy_mode == "Protect"


async def test_name_prefix_uses_prefix_operator(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v2/workload").respond(200, json={"workloads": []})
    await client.call_tool("nv_list_workloads", {"name_prefix": "api-"})
    assert route.calls.last.request.url.params["f_name"] == "prefix,api-"


async def test_get_workload_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v2/workload/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_workload", {"workload_id": "nope"})
    assert "no workload" in str(excinfo.value)


async def test_controller_error_is_classified(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v2/workload/x").respond(
        403, json={"code": 25, "error": "Object access denied", "message": "domain prod"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_workload", {"workload_id": "x"})
    assert "code=25" in str(excinfo.value)


async def test_object_not_found_code_is_classified(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/group/ghost").respond(
        404, json={"code": 7, "error": "Object not found", "message": "Group not found"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_group", {"group_name": "ghost"})
    assert "code=7" in str(excinfo.value)


# -- nv_whoami ------------------------------------------------------------------


async def test_whoami_reads_controller_when_undocumented_allowed(
    undoc_client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/selfuser").respond(200, json=fixture("selfuser"))
    result = await undoc_client.call_tool("nv_whoami", {})

    assert route.call_count == 1
    assert result.data.source == "controller"
    assert result.data.role == "admin"
    assert result.data.username == "admin"
    assert result.data.role_domains["ciops"] == ["prod"]
    assert result.data.global_permissions == ["config", "rt_scan"]
    assert result.data.last_login_at == "2026-07-29T18:04:11Z"


async def test_whoami_falls_back_to_cached_identity(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/selfuser").respond(200, json=fixture("selfuser"))
    result = await client.call_tool("nv_whoami", {})

    assert route.call_count == 0, "undocumented route must not be called"
    assert result.data.source == "cached"
    assert result.data.auth_mode == "apikey"
    assert result.data.username == "test-access"
    assert result.data.note


async def test_whoami_degrades_when_route_is_unavailable(
    undoc_client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/selfuser").respond(
        405, json={"code": 2, "error": "Method not allowed", "message": ""}
    )
    result = await undoc_client.call_tool("nv_whoami", {})
    assert result.data.source == "cached"
    assert "unavailable" in result.data.note


# -- nv_list_hosts --------------------------------------------------------------


async def test_list_hosts_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/host").respond(200, json=fixture("hosts"))
    result = await client.call_tool("nv_list_hosts", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3", "must over-fetch by one"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.hosts[0]
    assert first.id == "khyron:aaaa1111"
    assert first.name == "khyron"
    assert first.policy_mode == "Protect"
    assert first.memory_bytes == 67553994752
    assert first.high_vuls == 4
    assert first.med_vuls == 19
    assert first.scan_status == "finished"
    assert first.cap_kube_bench is True
    assert result.data.hosts[1].cap_docker_bench is False


async def test_list_hosts_builds_query(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/host").respond(200, json={"hosts": []})
    await client.call_tool(
        "nv_list_hosts",
        {"name_prefix": "khy", "state": "connected", "policy_mode": "Protect", "limit": 10},
    )
    params = route.calls.last.request.url.params
    assert params["f_name"] == "prefix,khy"
    assert params["f_state"] == "connected"
    assert params["f_policy_mode"] == "Protect"
    assert params["limit"] == "11"


async def test_list_hosts_not_truncated_when_page_fits(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/host").respond(200, json=fixture("hosts"))
    result = await client.call_tool("nv_list_hosts", {"limit": 50})
    assert result.data.page.truncated is False
    assert result.data.page.hint is None
    assert result.data.page.returned == 3


# -- nv_list_groups -------------------------------------------------------------


async def test_list_groups_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/group").respond(200, json=fixture("groups"))
    result = await client.call_tool("nv_list_groups", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3", "must over-fetch by one"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.groups[0]
    assert first.name == "nv.api.prod"
    assert first.namespace == "prod"
    assert first.policy_mode == "Protect"
    assert first.learned is True
    assert first.member_count == 2
    assert first.policy_rule_count == 3
    assert first.response_rule_count == 1


async def test_list_groups_builds_query(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/group").respond(200, json={"groups": []})
    await client.call_tool(
        "nv_list_groups",
        {
            "name_prefix": "nv.",
            "namespace": "prod",
            "policy_mode": "Monitor",
            "kind": "container",
            "limit": 5,
        },
    )
    params = route.calls.last.request.url.params
    assert params["f_name"] == "prefix,nv."
    assert params["f_domain"] == "prod"
    assert params["f_policy_mode"] == "Monitor"
    assert params["f_kind"] == "container"
    assert params["scope"] == "local", "scope is always sent"
    assert params["limit"] == "6"


async def test_list_groups_scope_fed_is_forwarded(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/group").respond(200, json={"groups": []})
    await client.call_tool("nv_list_groups", {"scope": "fed"})
    assert route.calls.last.request.url.params["scope"] == "fed"


# -- nv_get_group ---------------------------------------------------------------


async def test_get_group_projects_criteria_and_rule_ids(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/group/nv.api.prod").respond(200, json=fixture("group_detail"))
    result = await client.call_tool("nv_get_group", {"group_name": "nv.api.prod"})

    assert result.data.name == "nv.api.prod"
    assert result.data.namespace == "prod"
    assert result.data.cfg_type == "learned"
    assert [(c.key, c.value, c.op) for c in result.data.criteria] == [
        ("service", "api.prod", "="),
        ("domain", "prod", "="),
    ]
    assert result.data.policy_rule_ids == [1001, 1002]
    assert result.data.response_rule_ids == [7]
    assert result.data.member_count == 3
    assert result.data.members[0].id == "a1b2c3d4e5f6"
    assert result.data.members[0].high_vuls == 2
    assert result.data.page.start == 0
    assert result.data.page.truncated is False


async def test_get_group_caps_members(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/group/nv.api.prod").respond(200, json=fixture("group_detail"))
    result = await client.call_tool("nv_get_group", {"group_name": "nv.api.prod", "max_members": 2})

    assert result.data.member_count == 3, "member_count is the true total"
    assert len(result.data.members) == 2
    assert result.data.page.start == 0
    assert result.data.page.returned == 2
    assert result.data.page.truncated is True
    assert "3 members exist" in result.data.page.hint


async def test_get_group_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/group/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_group", {"group_name": "nope"})
    assert "no group named" in str(excinfo.value)


# -- nv_list_services -----------------------------------------------------------


async def test_list_services_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/service").respond(200, json=fixture("services"))
    result = await client.call_tool("nv_list_services", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3", "must over-fetch by one"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.services[0]
    assert first.name == "api.prod"
    assert first.namespace == "prod"
    assert first.policy_mode == "Protect"
    assert first.profile_mode == "Protect"
    assert first.baseline_profile == "zero-drift"
    assert first.member_count == 2
    assert first.policy_rule_count == 2
    assert first.ingress_exposure is True
    assert first.egress_exposure is False
    assert result.data.services[1].egress_exposure is True


async def test_list_services_builds_query(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/service").respond(200, json={"services": []})
    await client.call_tool(
        "nv_list_services",
        {"name_prefix": "api", "namespace": "prod", "policy_mode": "Protect", "limit": 7},
    )
    params = route.calls.last.request.url.params
    assert params["f_name"] == "prefix,api"
    assert params["f_domain"] == "prod"
    assert params["f_policy_mode"] == "Protect"
    assert params["limit"] == "8"


# -- nv_list_enforcers ----------------------------------------------------------


async def test_list_enforcers_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/enforcer").respond(200, json=fixture("enforcers"))
    result = await client.call_tool("nv_list_enforcers", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3", "must over-fetch by one"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.enforcers[0]
    assert first.id == "e1111111"
    assert first.host_name == "khyron"
    assert first.namespace == "neuvector"
    assert first.connection_state == "connected"
    assert first.cpus == "0-15", "cpus is a string in RESTAgent"
    assert first.memory_limit == 1073741824


async def test_list_enforcers_builds_query(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/enforcer").respond(200, json={"enforcers": []})
    await client.call_tool(
        "nv_list_enforcers",
        {"host_name": "macross", "connection_state": "disconnected", "limit": 4},
    )
    params = route.calls.last.request.url.params
    assert params["f_host_name"] == "macross"
    assert params["f_connection_state"] == "disconnected"
    assert params["limit"] == "5"


# -- nv_list_namespaces ---------------------------------------------------------


async def test_list_namespaces_projects_and_pages(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/domain").respond(200, json=fixture("domains"))
    result = await client.call_tool("nv_list_namespaces", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3", "must over-fetch by one"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.namespaces[0]
    assert first.name == "prod"
    assert first.workloads == 24
    assert first.running_workloads == 22
    assert first.running_pods == 11
    assert first.services == 6
    assert first.tags == ["PCI", "GDPR"]


async def test_list_namespaces_builds_query(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/domain").respond(200, json={"domains": []})
    await client.call_tool("nv_list_namespaces", {"name_prefix": "pro", "limit": 9})
    params = route.calls.last.request.url.params
    assert params["f_name"] == "prefix,pro"
    assert params["limit"] == "10"


# -- nv_get_network_conversations -----------------------------------------------


async def test_network_conversations_projects_and_pages(
    undoc_client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/conversation").respond(200, json=fixture("conversations"))
    result = await undoc_client.call_tool(
        "nv_get_network_conversations", {"from_group": "nv.api.prod", "limit": 2}
    )

    params = route.calls.last.request.url.params
    assert params["f_from"] == "nv.api.prod"
    assert params["limit"] == "3", "must over-fetch by one"

    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.conversations[0]
    assert first.from_group == "nv.api.prod"
    assert first.to_group == "nv.worker.prod"
    assert first.bytes == 184320
    assert first.sessions == 412
    assert first.policy_action == "allow"
    assert first.applications == ["HTTP"]
    assert first.ports == ["tcp/8080"]


async def test_network_conversations_to_group_filter(
    undoc_client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/conversation").respond(200, json={"conversations": []})
    await undoc_client.call_tool("nv_get_network_conversations", {"to_group": "nv.api.prod"})
    assert route.calls.last.request.url.params["f_to"] == "nv.api.prod"


async def test_network_conversations_blocked_when_undocumented_denied(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/conversation").respond(200, json=fixture("conversations"))
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_network_conversations", {})
    assert route.call_count == 0, "the guard must fire before any network call"
    assert "NV_ALLOW_UNDOCUMENTED" in str(excinfo.value)
