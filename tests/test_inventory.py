"""Inventory toolset contract tests."""
from __future__ import annotations

import pytest
import respx
from conftest import fixture

pytestmark = pytest.mark.asyncio


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
