"""Contract tests for the scan_ops toolset (7 mutating tools).

Every mutating tool gets both mandatory SPEC 10.2 cases:

* preview sends nothing - ``status == "confirmation_required"``, a 12-character
  token, and ``route.call_count == 0`` on the mutating route;
* confirmed applies - ``status == "applied"``, ``route.call_count == 1``, and the
  exact JSON body read back off the wire.

Plus token binding, read-only hiding, error classification, and the three
secret-not-logged tests. Those three use ``capfd`` rather than ``caplog``:
``configure_logging`` builds structlog with ``PrintLoggerFactory(file=sys.stderr)``
and ``cache_logger_on_first_use=True``, so the stream is bound once and only
file-descriptor-level capture sees it.
"""

from __future__ import annotations

import json

import pytest
import respx
from fastmcp import Client

from conftest import fixture, make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.errors import NotFoundError, UpstreamError, classify
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

SECRET = "n0t-a-real-p4ssword"
REGISTRY_URL = "https://registry.example.com"


# --- nv_trigger_scan ---------------------------------------------------------


async def test_trigger_scan_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/scan/workload/w1").respond(200, json={})
    result = await client.call_tool(
        "nv_trigger_scan", {"target": "workload", "target_id": "w1", "namespace": "prod"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_trigger_scan_workload_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/scan/workload/w1").respond(200, json={})
    args = {"target": "workload", "target_id": "w1", "namespace": "prod"}
    plan = await client.call_tool("nv_trigger_scan", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_trigger_scan", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert "nv_get_scan_status" in result.structured_content["effect"]
    assert route.call_count == 1
    assert route.calls.last.request.read() == b"", "these routes take no request body"
    # the namespace is a guard input only; it never reaches the controller
    assert "prod" not in str(route.calls.last.request.url)
    assert route.calls.last.request.extensions["timeout"]["read"] == 30.0


async def test_trigger_scan_host_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/scan/host/h1").respond(200, json={})
    args = {"target": "host", "target_id": "h1"}
    plan = await client.call_tool("nv_trigger_scan", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_trigger_scan", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.read() == b""


async def test_trigger_scan_registry_uses_long_timeout(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/scan/registry/prod-harbor/scan").respond(200, json={})
    args = {"target": "registry", "target_id": "prod-harbor"}
    plan = await client.call_tool("nv_trigger_scan", args)
    assert route.call_count == 0
    assert "shared scanner capacity" in plan.structured_content["effect"]

    result = await client.call_tool(
        "nv_trigger_scan", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.extensions["timeout"]["read"] == 300.0


async def test_trigger_scan_token_bound_to_target(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/scan/workload/w1").respond(200, json={})
    host_token = confirm_token("nv_trigger_scan", "host w1", None)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_trigger_scan",
            {"target": "workload", "target_id": "w1", "confirm": host_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


# --- nv_stop_registry_scan ---------------------------------------------------


async def test_stop_registry_scan_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete("/v1/scan/registry/prod-harbor/scan").respond(200, json={})
    result = await client.call_tool("nv_stop_registry_scan", {"registry_name": "prod-harbor"})
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0


async def test_stop_registry_scan_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete("/v1/scan/registry/prod-harbor/scan").respond(200, json={})
    args = {"registry_name": "prod-harbor"}
    plan = await client.call_tool("nv_stop_registry_scan", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_stop_registry_scan", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert result.structured_content["effect"] == "scan of registry prod-harbor cancelled"
    assert route.call_count == 1
    assert route.calls.last.request.read() == b""


# --- nv_scan_repository ------------------------------------------------------

SCAN_ARGS = {
    "repository": "myorg/api",
    "tag": "1.27.0",
    "registry": REGISTRY_URL,
}
EXPECTED_SCAN_BODY = {
    "request": {
        "metadata": {
            "source": "neuvector-mcp",
            "user": "",
            "job": "",
            "workspace": "",
            "function": "",
            "region": "",
        },
        "registry": REGISTRY_URL,
        "repository": "myorg/api",
        "tag": "1.27.0",
        "scan_layers": False,
        "base_image": "",
        "ignore_proxy": False,
    }
}


async def test_scan_repository_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    result = await client.call_tool("nv_scan_repository", dict(SCAN_ARGS))
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert body["target"] == f"{REGISTRY_URL}/myorg/api:1.27.0"
    assert route.call_count == 0


async def test_scan_repository_confirmed_applies_and_caps_report(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    args = {**SCAN_ARGS, "max_vulnerabilities": 3}
    plan = await client.call_tool("nv_scan_repository", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_scan_repository", {**args, "confirm": token})
    body = result.structured_content
    assert body["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == EXPECTED_SCAN_BODY
    assert route.calls.last.request.extensions["timeout"]["read"] == 300.0

    report = body["controller_response"]
    assert report["image_ref"] == f"{REGISTRY_URL}/myorg/api:1.27.0"
    assert report["counts"]["total"] == 8
    assert report["counts"]["critical"] == 2
    assert report["counts"]["fixable"] == 4
    assert report["matched"] == 8
    assert report["page"]["returned"] == 3
    assert report["page"]["truncated"] is True
    # worst-first ordering survives the cap
    assert [v["name"] for v in report["vulnerabilities"]] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]
    assert report["module_count"] == 3
    assert report["base_os"] == "alpine:3.20"


async def test_scan_repository_filters_by_severity_and_fixability(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    args = {**SCAN_ARGS, "min_severity": "High", "fixable_only": True}
    plan = await client.call_tool("nv_scan_repository", args)
    result = await client.call_tool(
        "nv_scan_repository", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    report = result.structured_content["controller_response"]
    assert report["counts"]["total"] == 8, "counts are over the WHOLE report"
    assert report["matched"] == 2
    assert [v["name"] for v in report["vulnerabilities"]] == ["CVE-2026-0001", "CVE-2026-0003"]


async def test_scan_repository_summary_only_returns_no_cves(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    args = {**SCAN_ARGS, "summary_only": True}
    plan = await client.call_tool("nv_scan_repository", args)
    result = await client.call_tool(
        "nv_scan_repository", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    report = result.structured_content["controller_response"]
    assert report["vulnerabilities"] == []
    assert report["counts"]["total"] == 8


async def test_scan_repository_drops_envs_and_labels(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    plan = await client.call_tool("nv_scan_repository", dict(SCAN_ARGS))
    result = await client.call_tool(
        "nv_scan_repository",
        {**SCAN_ARGS, "confirm": plan.structured_content["confirm_token"]},
    )
    serialised = json.dumps(result.structured_content)
    assert "AKIAnotreal" not in serialised, "container envs routinely carry credentials"
    assert "hunter2-not-real" not in serialised
    assert "dpl-notreal-0000" not in serialised
    report = result.structured_content["controller_response"]
    assert "envs" not in report
    assert "labels" not in report


async def test_scan_repository_password_redacted_in_outcome(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    args = {**SCAN_ARGS, "username": "robot$scan", "password": SECRET}
    plan = await client.call_tool("nv_scan_repository", args)
    assert plan.structured_content["payload"]["request"]["password"] == "***"
    assert plan.structured_content["payload"]["request"]["username"] == "robot$scan"
    assert route.call_count == 0

    result = await client.call_tool(
        "nv_scan_repository", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    assert result.structured_content["payload"]["request"]["password"] == "***"
    sent = json.loads(route.calls.last.request.read())
    assert sent["request"]["password"] == SECRET, "the wire body carries the real credential"
    assert sent["request"]["username"] == "robot$scan"


async def test_scan_repository_password_not_logged(
    client, nv_mock: respx.MockRouter, capfd
) -> None:
    route = nv_mock.post("/v1/scan/repository").respond(200, json=fixture("scan_repo_report"))
    args = {**SCAN_ARGS, "password": SECRET}
    plan = await client.call_tool("nv_scan_repository", args)
    result = await client.call_tool(
        "nv_scan_repository", {**args, "confirm": plan.structured_content["confirm_token"]}
    )

    assert result.structured_content["payload"]["request"]["password"] == "***"
    assert SECRET not in json.dumps(result.structured_content)
    assert json.loads(route.calls.last.request.read())["request"]["password"] == SECRET
    out, err = capfd.readouterr()
    assert SECRET not in out and SECRET not in err


# --- nv_create_registry ------------------------------------------------------

CREATE_ARGS = {
    "name": "prod-harbor",
    "registry_type": "Docker Registry",
    "registry": REGISTRY_URL,
    "filters": ["myorg/*:release-*", "a/*"],
    "username": "robot$scan",
    "password": SECRET,
}
EXPECTED_CREATE_BODY = {
    "config": {
        "name": "prod-harbor",
        "registry_type": "Docker Registry",
        "registry": REGISTRY_URL,
        "filters": ["a/*", "myorg/*:release-*"],
        "scan_layers": False,
        "rescan_after_db_update": False,
        "ignore_proxy": False,
        "auth": {
            "auth_with_token": False,
            "username": "robot$scan",
            "password": SECRET,
        },
    }
}


async def test_create_registry_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v2/scan/registry").respond(200, json={})
    result = await client.call_tool("nv_create_registry", dict(CREATE_ARGS))
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "2 filter(s)" in body["effect"]
    assert route.call_count == 0


async def test_create_registry_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v2/scan/registry").respond(200, json={})
    plan = await client.call_tool("nv_create_registry", dict(CREATE_ARGS))
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_create_registry", {**CREATE_ARGS, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert result.structured_content["effect"] == "registry prod-harbor created"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == EXPECTED_CREATE_BODY
    assert route.calls.last.request.extensions["timeout"]["read"] == 30.0


async def test_create_registry_password_redacted_in_preview_payload(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post("/v2/scan/registry").respond(200, json={})
    plan = await client.call_tool(
        "nv_create_registry", {**CREATE_ARGS, "auth_token": "tok-not-real"}
    )
    config = plan.structured_content["payload"]["config"]
    # redaction has to follow the credentials down into the nested "auth" object
    assert config["auth"]["password"] == "***"
    assert config["auth"]["auth_token"] == "***"
    # every non-secret field stays inspectable
    assert config["registry"] == REGISTRY_URL
    assert config["filters"] == ["a/*", "myorg/*:release-*"]
    assert SECRET not in json.dumps(plan.structured_content)


async def test_create_registry_token_matches_between_preview_and_apply(
    client, nv_mock: respx.MockRouter
) -> None:
    """D.0.4: the token is computed over the redacted payload, so it survives."""
    route = nv_mock.post("/v2/scan/registry").respond(200, json={})
    plan = await client.call_tool("nv_create_registry", dict(CREATE_ARGS))
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_create_registry", {**CREATE_ARGS, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert json.loads(route.calls.last.request.read())["config"]["auth"]["password"] == SECRET
    assert result.structured_content["payload"]["config"]["auth"]["password"] == "***"


async def test_create_registry_password_not_logged(
    client, nv_mock: respx.MockRouter, capfd
) -> None:
    route = nv_mock.post("/v2/scan/registry").respond(200, json={})
    plan = await client.call_tool("nv_create_registry", dict(CREATE_ARGS))
    result = await client.call_tool(
        "nv_create_registry", {**CREATE_ARGS, "confirm": plan.structured_content["confirm_token"]}
    )

    assert result.structured_content["payload"]["config"]["auth"]["password"] == "***"
    assert SECRET not in json.dumps(result.structured_content)
    assert json.loads(route.calls.last.request.read())["config"]["auth"]["password"] == SECRET
    out, err = capfd.readouterr()
    assert SECRET not in out and SECRET not in err


async def test_create_registry_credentials_nest_under_auth(
    client, nv_mock: respx.MockRouter
) -> None:
    """Regression: flat credentials are silently dropped by POST /v2/scan/registry.

    A live 5.4 controller answers 200 to a flat body and stores the entry with no
    credentials at all, so every scan of a private repository then fails with
    nothing in the response to explain why. Nesting is the whole fix; pin it.
    """
    route = nv_mock.post("/v2/scan/registry").respond(200, json={})
    args = {**CREATE_ARGS, "auth_token": "tok-not-real", "auth_with_token": True}
    plan = await client.call_tool("nv_create_registry", args)
    await client.call_tool(
        "nv_create_registry", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    config = json.loads(route.calls.last.request.read())["config"]

    assert config["auth"] == {
        "auth_with_token": True,
        "username": "robot$scan",
        "password": SECRET,
        "auth_token": "tok-not-real",
    }
    # none of them may ALSO appear flat, where the controller ignores them
    for field in ("username", "password", "auth_token", "auth_with_token"):
        assert field not in config, f"{field} must not be sent flat"


# --- nv_update_registry ------------------------------------------------------


async def test_update_registry_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch("/v2/scan/registry/prod-harbor").respond(200, json={})
    result = await client.call_tool(
        "nv_update_registry", {"name": "prod-harbor", "password": SECRET, "scan_layers": True}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert body["effect"] == "Update registry 'prod-harbor': change password, scan_layers."
    assert SECRET not in json.dumps(body), "the effect names fields, never values"
    assert route.call_count == 0


async def test_update_registry_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch("/v2/scan/registry/prod-harbor").respond(200, json={})
    args = {
        "name": "prod-harbor",
        "filters": ["myorg/*:release-*", "a/*"],
        "password": SECRET,
        "repo_limit": 100,
    }
    plan = await client.call_tool("nv_update_registry", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_update_registry", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": "prod-harbor",
            "repo_limit": 100,
            "filters": ["a/*", "myorg/*:release-*"],
            "auth": {"password": SECRET},
        }
    }


async def test_update_registry_credentials_nest_under_auth(
    client, nv_mock: respx.MockRouter
) -> None:
    """Regression: a flat password change is accepted with 200 and changes nothing.

    Worse here than on create - the caller is told the credential was rotated when
    the stored one is untouched.
    """
    route = nv_mock.patch("/v2/scan/registry/prod-harbor").respond(200, json={})
    args = {"name": "prod-harbor", "username": "robot$new", "password": SECRET}
    plan = await client.call_tool("nv_update_registry", args)
    await client.call_tool(
        "nv_update_registry", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    config = json.loads(route.calls.last.request.read())["config"]

    assert config == {
        "name": "prod-harbor",
        "auth": {"username": "robot$new", "password": SECRET},
    }
    # the plan still names the fields the caller passed, not the wire shape
    assert plan.structured_content["effect"] == (
        "Update registry 'prod-harbor': change password, username."
    )


async def test_update_registry_sends_only_changed_fields(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch("/v2/scan/registry/prod-harbor").respond(200, json={})
    args = {"name": "prod-harbor", "scan_layers": True}
    plan = await client.call_tool("nv_update_registry", args)
    await client.call_tool(
        "nv_update_registry", {**args, "confirm": plan.structured_content["confirm_token"]}
    )
    assert json.loads(route.calls.last.request.read()) == {
        "config": {"name": "prod-harbor", "scan_layers": True}
    }


async def test_update_registry_no_fields_raises(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch("/v2/scan/registry/prod-harbor").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_registry", {"name": "prod-harbor"})
    assert "at least one field to change" in str(excinfo.value)
    assert route.call_count == 0


async def test_update_registry_password_not_logged(
    client, nv_mock: respx.MockRouter, capfd
) -> None:
    route = nv_mock.patch("/v2/scan/registry/prod-harbor").respond(200, json={})
    args = {"name": "prod-harbor", "password": SECRET}
    plan = await client.call_tool("nv_update_registry", args)
    result = await client.call_tool(
        "nv_update_registry", {**args, "confirm": plan.structured_content["confirm_token"]}
    )

    assert result.structured_content["payload"]["config"]["auth"]["password"] == "***"
    assert SECRET not in json.dumps(result.structured_content)
    assert json.loads(route.calls.last.request.read())["config"]["auth"]["password"] == SECRET
    out, err = capfd.readouterr()
    assert SECRET not in out and SECRET not in err


# --- nv_delete_registry ------------------------------------------------------


async def test_delete_registry_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete("/v1/scan/registry/prod-harbor").respond(200, json={})
    result = await client.call_tool("nv_delete_registry", {"name": "prod-harbor"})
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "every scan report for its images" in body["effect"]
    assert route.call_count == 0


async def test_delete_registry_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete("/v1/scan/registry/prod-harbor").respond(200, json={})
    plan = await client.call_tool("nv_delete_registry", {"name": "prod-harbor"})
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_delete_registry", {"name": "prod-harbor", "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert result.structured_content["effect"] == "registry prod-harbor deleted"
    assert route.call_count == 1
    assert route.calls.last.request.read() == b""


# --- nv_trigger_bench_run ----------------------------------------------------


async def test_trigger_bench_run_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/bench/host/h1/kubernetes").respond(200, json={})
    result = await client.call_tool(
        "nv_trigger_bench_run", {"host_id": "h1", "benchmark": "kubernetes"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "nothing on the host is modified" in body["effect"]
    assert route.call_count == 0


async def test_trigger_bench_run_kubernetes_confirmed_applies(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/bench/host/h1/kubernetes").respond(200, json={})
    args = {"host_id": "h1", "benchmark": "kubernetes"}
    plan = await client.call_tool("nv_trigger_bench_run", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_trigger_bench_run", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert "nv_get_bench_report" in result.structured_content["effect"]
    assert route.call_count == 1
    assert route.calls.last.request.read() == b""
    assert route.calls.last.request.extensions["timeout"]["read"] == 300.0


async def test_trigger_bench_run_docker_confirmed_applies(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/bench/host/h1/docker").respond(200, json={})
    args = {"host_id": "h1", "benchmark": "docker"}
    plan = await client.call_tool("nv_trigger_bench_run", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_trigger_bench_run", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.extensions["timeout"]["read"] == 300.0


async def test_trigger_bench_run_token_bound_to_benchmark(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/bench/host/h1/docker").respond(200, json={})
    kubernetes_token = confirm_token(
        "nv_trigger_bench_run", "kubernetes benchmark on host h1", None
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_trigger_bench_run",
            {"host_id": "h1", "benchmark": "docker", "confirm": kubernetes_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


# --- module-level contracts --------------------------------------------------


async def test_scan_ops_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}
    assert "nv_get_system_summary" in names
    for tool in (
        "nv_trigger_scan",
        "nv_stop_registry_scan",
        "nv_scan_repository",
        "nv_create_registry",
        "nv_update_registry",
        "nv_delete_registry",
        "nv_trigger_bench_run",
    ):
        assert tool not in names


async def test_scan_ops_annotations(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    for tool in (
        "nv_trigger_scan",
        "nv_stop_registry_scan",
        "nv_scan_repository",
        "nv_create_registry",
        "nv_update_registry",
        "nv_delete_registry",
        "nv_trigger_bench_run",
    ):
        assert tools[tool].annotations.readOnlyHint is False
    # only the data-destroying tool is destructive (SPEC 6.2)
    assert tools["nv_delete_registry"].annotations.destructiveHint is True
    assert tools["nv_trigger_scan"].annotations.destructiveHint is False
    assert tools["nv_create_registry"].annotations.destructiveHint is False
    assert tools["nv_trigger_bench_run"].annotations.destructiveHint is False


async def test_scan_ops_error_codes_classify(client, nv_mock: respx.MockRouter) -> None:
    # code 27 (registry scan failed) is absent from _CODE_MAP -> status fallback
    assert isinstance(classify(500, {"code": 27, "error": "Fail to scan registry"}), UpstreamError)
    nv_mock.post("/v1/scan/registry/prod-harbor/scan").respond(
        500, json={"code": 27, "error": "Fail to scan registry", "message": "scanner busy"}
    )
    args = {"target": "registry", "target_id": "prod-harbor"}
    plan = await client.call_tool("nv_trigger_scan", args)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_trigger_scan", {**args, "confirm": plan.structured_content["confirm_token"]}
        )
    assert "code=27" in str(excinfo.value)

    # code 7 (object not found) -> NotFoundError
    assert isinstance(classify(404, {"code": 7, "error": "Object not found"}), NotFoundError)
    nv_mock.delete("/v1/scan/registry/ghost").respond(
        404, json={"code": 7, "error": "Object not found", "message": "registry ghost"}
    )
    plan = await client.call_tool("nv_delete_registry", {"name": "ghost"})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_registry",
            {"name": "ghost", "confirm": plan.structured_content["confirm_token"]},
        )
    assert "code=7" in str(excinfo.value)
