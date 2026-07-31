"""Compliance toolset contract tests.

Covers "nv_get_compliance_findings", "nv_get_bench_report",
"nv_list_compliance_profiles" and "nv_get_compliance_profile". Everything runs
offline against the respx-mocked controller.
"""

from __future__ import annotations

import pytest
import respx

from conftest import fixture

pytestmark = pytest.mark.asyncio


# --- nv_get_compliance_findings ---------------------------------------------


async def test_compliance_findings_scope_workload_and_host_hit_different_paths(
    client, nv_mock: respx.MockRouter
) -> None:
    workload_route = nv_mock.get("/v1/workload/a1b2c3d4e5f6/compliance").respond(
        200, json=fixture("compliance_workload")
    )
    host_route = nv_mock.get("/v1/host/node-1/compliance").respond(
        200, json=fixture("compliance_host")
    )

    workload_result = await client.call_tool(
        "nv_get_compliance_findings", {"scope": "workload", "target_id": "a1b2c3d4e5f6"}
    )
    assert workload_route.call_count == 1
    assert host_route.call_count == 0
    assert workload_result.data.scope == "workload"
    assert workload_result.data.target_id == "a1b2c3d4e5f6"

    host_result = await client.call_tool(
        "nv_get_compliance_findings", {"scope": "host", "target_id": "node-1"}
    )
    assert host_route.call_count == 1
    assert host_result.data.scope == "host"
    assert host_result.data.kubernetes_cis_category == "master"


async def test_compliance_findings_defaults_to_failures_only(
    client, nv_mock: respx.MockRouter
) -> None:
    """The default answer leads with the failure picture.

    PART-A pins ``level`` to a ``None`` default, so the default call returns every
    check; ``level_counts`` is what tells the caller how many failed, and it is
    computed over the WHOLE report so a filtered call still reports the true
    pass/fail shape. ``level='WARN'`` narrows the evidence to the failures.
    """
    nv_mock.get("/v1/workload/w1/compliance").respond(200, json=fixture("compliance_workload"))

    default = await client.call_tool(
        "nv_get_compliance_findings", {"scope": "workload", "target_id": "w1"}
    )
    assert default.data.level_counts == {"PASS": 3, "WARN": 2, "INFO": 1}
    assert default.data.matched == 6

    failures = await client.call_tool(
        "nv_get_compliance_findings",
        {"scope": "workload", "target_id": "w1", "level": "warn"},
    )
    # level_counts still covers the whole report, not just the filtered slice.
    assert failures.data.level_counts == {"PASS": 3, "WARN": 2, "INFO": 1}
    assert failures.data.matched == 2
    assert [c.test_number for c in failures.data.checks] == ["I.4.6", "C.5.4"]
    assert all(c.level == "WARN" for c in failures.data.checks)


async def test_compliance_findings_catalog_filter_is_case_insensitive(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/workload/w1/compliance").respond(200, json=fixture("compliance_workload"))
    result = await client.call_tool(
        "nv_get_compliance_findings",
        {"scope": "workload", "target_id": "w1", "catalog": "IMAGE"},
    )
    assert result.data.matched == 3
    assert {c.catalog for c in result.data.checks} == {"image"}


async def test_compliance_findings_caps_and_reports_truncation(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/workload/w1/compliance").respond(200, json=fixture("compliance_workload"))
    result = await client.call_tool(
        "nv_get_compliance_findings",
        {"scope": "workload", "target_id": "w1", "max_checks": 2},
    )
    assert result.data.page.start == 0
    assert result.data.page.returned == 2
    assert result.data.page.truncated is True
    assert result.data.page.hint
    assert "max_checks" in result.data.page.hint


async def test_compliance_findings_zero_max_checks_returns_counts_only(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/host/node-1/compliance").respond(200, json=fixture("compliance_host"))
    result = await client.call_tool(
        "nv_get_compliance_findings",
        {"scope": "host", "target_id": "node-1", "max_checks": 0},
    )
    assert result.data.checks == []
    assert result.data.level_counts == {"PASS": 2, "WARN": 3, "NOTE": 1}


async def test_unwrapped_body_projects_correctly(client, nv_mock: respx.MockRouter) -> None:
    """RESTComplianceData and RESTBenchReport arrive with no envelope key.

    The fixtures are the bare objects; ``raw.get("report") or raw`` is defensive
    only, so the projection must work on the unwrapped body.
    """
    body = fixture("compliance_workload")
    assert "report" not in body, "fixture must be the bare RESTComplianceData object"
    nv_mock.get("/v1/workload/w1/compliance").respond(200, json=body)

    result = await client.call_tool(
        "nv_get_compliance_findings", {"scope": "workload", "target_id": "w1"}
    )
    assert result.data.run_at == "2026-07-30T08:00:00Z"
    assert result.data.run_timestamp == 1753862400
    assert result.data.kubernetes_cis_version == "cis-1.9"
    assert result.data.docker_cis_version == "cis-1.6.0"
    first = result.data.checks[0]
    assert first.test_number == "I.4.1"
    assert first.catalog == "image"
    assert first.type == "image"
    assert first.profile == "Level 1"
    assert first.scored is True
    assert first.automated is True
    assert first.message == ["User is set to 10001"]
    assert first.remediation.startswith("Add a USER directive")

    bench_body = fixture("bench_kubernetes")
    assert "report" not in bench_body, "fixture must be the bare RESTBenchReport object"
    nv_mock.get("/v1/bench/host/node-1/kubernetes").respond(200, json=bench_body)
    bench = await client.call_tool("nv_get_bench_report", {"host_id": "node-1"})
    assert bench.data.cis_version == "cis-1.9"
    assert bench.data.run_timestamp == 1753855200
    assert bench.data.items[0].test_number == "K.1.1.1"


async def test_compliance_findings_empty_body_raises_not_found(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/host/ghost/compliance").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_get_compliance_findings", {"scope": "host", "target_id": "ghost"}
        )
    assert "no compliance report" in str(excinfo.value)


async def test_compliance_findings_access_denied_is_classified(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/workload/secret/compliance").respond(
        403, json={"code": 25, "error": "Object access denied", "message": "domain prod"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_get_compliance_findings", {"scope": "workload", "target_id": "secret"}
        )
    assert "code=25" in str(excinfo.value)


# --- nv_get_bench_report -----------------------------------------------------


async def test_bench_report_benchmark_argument_selects_path(
    client, nv_mock: respx.MockRouter
) -> None:
    kube_route = nv_mock.get("/v1/bench/host/node-1/kubernetes").respond(
        200, json=fixture("bench_kubernetes")
    )
    docker_route = nv_mock.get("/v1/bench/host/node-1/docker").respond(
        200, json=fixture("bench_docker")
    )

    # kubernetes is the default.
    default = await client.call_tool("nv_get_bench_report", {"host_id": "node-1"})
    assert kube_route.call_count == 1
    assert docker_route.call_count == 0
    assert default.data.benchmark == "kubernetes"
    assert default.data.cis_version == "cis-1.9"

    docker = await client.call_tool(
        "nv_get_bench_report", {"host_id": "node-1", "benchmark": "docker"}
    )
    assert docker_route.call_count == 1
    assert docker.data.benchmark == "docker"
    assert docker.data.cis_version == "cis-1.6.0"
    assert docker.data.host_id == "node-1"


async def test_bench_report_invalid_benchmark_rejected_before_request(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/bench/host/node-1/windows").respond(
        200, json=fixture("bench_kubernetes")
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_bench_report", {"host_id": "node-1", "benchmark": "windows"})
    message = str(excinfo.value)
    assert "windows" in message or "kubernetes" in message, message
    assert route.call_count == 0, "the discriminator must be validated before any network call"


async def test_bench_report_level_filter_and_truncation(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/bench/host/node-1/kubernetes").respond(200, json=fixture("bench_kubernetes"))
    result = await client.call_tool(
        "nv_get_bench_report", {"host_id": "node-1", "level": "WARN", "max_items": 1}
    )
    assert result.data.level_counts == {"PASS": 3, "WARN": 2, "INFO": 1}
    assert result.data.matched == 2
    assert result.data.page.start == 0
    assert result.data.page.returned == 1
    assert result.data.page.truncated is True
    assert result.data.page.hint
    assert "max_items" in result.data.page.hint
    assert [i.test_number for i in result.data.items] == ["K.1.2.6"]


async def test_bench_report_empty_body_raises_not_found(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/bench/host/ghost/docker").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_bench_report", {"host_id": "ghost", "benchmark": "docker"})
    assert "no docker benchmark report" in str(excinfo.value)


async def test_bench_report_cis_bench_error_maps_by_http_status(
    client, nv_mock: respx.MockRouter
) -> None:
    """code=23 (ERR_CIS_BENCH_ERROR) has no entry in errors.classify.

    It therefore falls back to the HTTP status; assert only that the controller
    code reaches the caller, not a specific exception class.
    """
    nv_mock.get("/v1/bench/host/node-9/kubernetes").respond(
        400, json={"code": 23, "error": "CIS benchmark error", "message": "not supported"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_bench_report", {"host_id": "node-9"})
    assert "code=23" in str(excinfo.value)


# --- nv_list_compliance_profiles ---------------------------------------------


async def test_list_compliance_profiles_projects_and_over_fetches(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/compliance/profile").respond(200, json=fixture("compliance_profiles"))
    result = await client.call_tool("nv_list_compliance_profiles", {"limit": 1})

    request = route.calls.last.request
    assert request.url.params["start"] == "0"
    assert request.url.params["limit"] == "2", "must over-fetch by one to detect truncation"

    assert result.data.page.truncated is True
    assert result.data.page.returned == 1
    assert result.data.page.hint
    assert "start=1" in result.data.page.hint
    profile = result.data.profiles[0]
    assert profile.name == "default"
    assert profile.disable_system is False
    assert profile.cfg_type == "user_created"
    assert profile.entry_count == 2


async def test_list_compliance_profiles_untruncated_page(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/compliance/profile").respond(200, json=fixture("compliance_profiles"))
    result = await client.call_tool("nv_list_compliance_profiles", {"limit": 10})
    assert result.data.page.truncated is False
    assert result.data.page.hint is None
    assert [p.name for p in result.data.profiles] == ["default", "pci-strict", "audit-only"]
    assert result.data.profiles[1].cfg_type == "ground"
    assert result.data.profiles[1].disable_system is True


# --- nv_get_compliance_profile -----------------------------------------------


async def test_get_compliance_profile_projects_entries(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/compliance/profile/default").respond(200, json=fixture("compliance_profile"))
    result = await client.call_tool("nv_get_compliance_profile", {})
    assert result.data.name == "default"
    assert result.data.disable_system is False
    assert result.data.cfg_type == "user_created"
    assert result.data.entry_count == 4
    assert result.data.page.start == 0
    assert result.data.page.truncated is False
    assert result.data.entries[0].test_number == "K.1.2.6"
    assert result.data.entries[0].tags == ["PCI", "GDPR"]


async def test_get_compliance_profile_caps_entries(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/compliance/profile/default").respond(200, json=fixture("compliance_profile"))
    result = await client.call_tool(
        "nv_get_compliance_profile", {"profile_name": "default", "max_entries": 2}
    )
    assert result.data.entry_count == 4, "entry_count is the true size, before capping"
    assert result.data.page.returned == 2
    assert result.data.page.truncated is True
    assert result.data.page.hint
    assert "max_entries" in result.data.page.hint


async def test_get_compliance_profile_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/compliance/profile/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_compliance_profile", {"profile_name": "nope"})
    assert "no compliance profile" in str(excinfo.value)


async def test_get_compliance_profile_object_not_found_is_classified(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/compliance/profile/gone").respond(
        404, json={"code": 7, "error": "Object not found", "message": "Compliance profile"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_compliance_profile", {"profile_name": "gone"})
    assert "code=7" in str(excinfo.value)
