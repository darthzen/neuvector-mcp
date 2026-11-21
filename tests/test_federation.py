"""Federation reads are limited to known members and fixed GET routes."""

import pytest
import respx
from fastmcp import Client

from conftest import make_settings
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

MEMBERS = {
    "fed_role": "master",
    "master_cluster": {"name": "primary", "secret": "hidden"},
    "joint_clusters": [
        {
            "name": "cluster-a",
            "id": "member-a",
            "status": "synced",
            "rest_version": "5",
            "token": "hidden",
        }
    ],
}


async def test_status_projects_safe_fields(client, nv_mock):
    nv_mock.get("/v1/fed/member").respond(200, json=MEMBERS)
    result = await client.call_tool("nv_get_federation_status", {})
    assert result.data["joint_clusters"][0]["name"] == "cluster-a"
    assert "hidden" not in str(result.data)


@pytest.mark.parametrize(
    "resource,path,envelope",
    [
        ("groups", "/v1/group", "groups"),
        ("hosts", "/v1/host", "hosts"),
        ("workloads", "/v2/workload", "workloads"),
        ("threats", "/v1/log/threat", "threats"),
        ("violations", "/v1/log/violation", "violations"),
        ("incidents", "/v1/log/incident", "incidents"),
        ("scan_status", "/v1/scan/status", "status"),
        ("admission_state", "/v1/admission/state", "state"),
    ],
)
async def test_member_read_uses_fixed_get_route(client, nv_mock, resource, path, envelope):
    nv_mock.get("/v1/fed/member").respond(200, json=MEMBERS)
    value = [] if resource not in ("scan_status", "admission_state") else {}
    route = nv_mock.get("/v1/fed/cluster/member-a" + path).respond(200, json={envelope: value})
    result = await client.call_tool(
        "nv_query_federation_member", {"cluster": "cluster-a", "resource": resource}
    )
    assert result.data["cluster"] == "cluster-a"
    assert route.calls.last.request.method == "GET"


async def test_unknown_or_ambiguous_member_never_forwarded(client, nv_mock):
    nv_mock.get("/v1/fed/member").respond(200, json={"fed_role": "master", "joint_clusters": []})
    with pytest.raises(Exception, match="unknown or ambiguous"):
        await client.call_tool(
            "nv_query_federation_member", {"cluster": "cluster-a", "resource": "hosts"}
        )


async def test_proxy_denial_explains_role(client, nv_mock):
    nv_mock.get("/v1/fed/member").respond(200, json=MEMBERS)
    nv_mock.get("/v1/fed/cluster/member-a/v1/host").respond(403, json={})
    with pytest.raises(Exception, match="fedAdmin, fedReader"):
        await client.call_tool(
            "nv_query_federation_member", {"cluster": "cluster-a", "resource": "hosts"}
        )


async def test_optional_read_only_toolset(nv_mock: respx.MockRouter):
    server = build_server(make_settings(read_only=True, toolsets=("federation_read",)))
    async with Client(server) as client:
        tools = await client.list_tools()
        assert {t.name for t in tools} == {"nv_get_federation_status", "nv_query_federation_member"}
        assert all(t.annotations.readOnlyHint for t in tools)


@pytest.mark.parametrize(
    "members",
    [
        [{"name": "cluster-a", "id": "member-a"}, {"name": "cluster-a", "id": "member-b"}],
        [{"name": "cluster-a", "id": "../other"}],
    ],
)
async def test_rejects_ambiguous_name_and_unsafe_member_id(client, nv_mock, members):
    nv_mock.get("/v1/fed/member").respond(
        200, json={"fed_role": "master", "joint_clusters": members}
    )
    with pytest.raises(Exception, match=r"unknown or ambiguous|invalid member id"):
        await client.call_tool(
            "nv_query_federation_member", {"cluster": "cluster-a", "resource": "hosts"}
        )
    assert len(nv_mock.calls) == 2  # startup summary and membership only


async def test_member_page_is_capped(client, nv_mock):
    nv_mock.get("/v1/fed/member").respond(200, json=MEMBERS)
    route = nv_mock.get("/v1/fed/cluster/member-a/v1/host").respond(
        200, json={"hosts": [{"id": "a"}, {"id": "b"}]}
    )
    result = await client.call_tool(
        "nv_query_federation_member", {"cluster": "cluster-a", "resource": "hosts", "limit": 1}
    )
    assert route.calls.last.request.url.params["limit"] == "2"
    assert result.data["truncated"] is True
    assert len(result.data["results"]) == 1
