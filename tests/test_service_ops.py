"""service_ops contract tests: service creation, live-workload config, cluster requests.

Three things are asserted harder here than the usual write-tool contract.

First, that a preview sends NOTHING (``route.call_count == 0``): the tools under
test can move an entire cluster into Protect and release every quarantined
container, so a preview that leaked a request would be the whole failure.

Second, that pointer/omitempty fields the caller did not supply are ABSENT from
the body rather than present with a default. Every optional field on apis.go
RESTServiceConfig, RESTSystemRequest and RESTUnquarReq is a pointer with
omitempty, so a key present with a default value silently overwrites what the
operator has configured.

Third, that ``profile_mode`` never reaches the wire. apis.go declares it on
RESTServiceConfig and RESTSystemRequest but the 5.6.0 apis.yaml and Appendix B
do not, so this server deliberately does not send it; a regression that started
sending it would be a field the controller answers 200 to and drops.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from conftest import make_settings
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

WORKLOAD_ID = "c0ffee1234"
WORKLOAD_PATH = f"/v1/workload/{WORKLOAD_ID}"
SERVICE_PATH = "/v1/service"
SYSTEM_REQUEST_PATH = "/v1/system/request"
DOMAIN_PATH = "/v1/domain"


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- nv_create_service ----------------------------------------------------------


async def test_create_service_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(SERVICE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_service", {"name": "api", "domain": "prod", "policy_mode": "Discover"}
    )

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "nv.api.prod" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_service_confirmed_sends_exact_body(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(SERVICE_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_create_service",
        {
            "name": "api",
            "domain": "prod",
            "comment": "created for the payments rollout",
            "policy_mode": "Monitor",
            "baseline_profile": "zero-drift",
            "not_scored": True,
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": "api",
            "domain": "prod",
            "comment": "created for the payments rollout",
            "policy_mode": "Monitor",
            "baseline_profile": "zero-drift",
            "not_scored": True,
        }
    }


async def test_create_service_omits_unsupplied_optional_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    """policy_mode, baseline_profile and not_scored are pointers with omitempty.

    An absent key means "controller default"; a key present with a default value
    would pin the new service to that value instead.
    """
    route = nv_mock.post(SERVICE_PATH).respond(200, json={})
    await _confirmed(client, "nv_create_service", {"name": "api", "domain": "prod"})

    config = json.loads(route.calls.last.request.read())["config"]
    # comment is a *string WITHOUT omitempty in apis.go, so it is always present.
    assert config == {"name": "api", "domain": "prod", "comment": ""}
    for absent in ("policy_mode", "baseline_profile", "not_scored"):
        assert absent not in config, f"{absent} would override the controller default"


async def test_create_service_never_sends_profile_mode(client, nv_mock: respx.MockRouter) -> None:
    """profile_mode is apis.go-only and must not reach the wire."""
    route = nv_mock.post(SERVICE_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_create_service",
        {"name": "api", "domain": "prod", "policy_mode": "Protect"},
    )
    assert "profile_mode" not in json.loads(route.calls.last.request.read())["config"]


async def test_create_service_protect_warns_about_unlearned_policy(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(SERVICE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_service", {"name": "api", "domain": "prod", "policy_mode": "Protect"}
    )
    assert "CREATED DIRECTLY IN PROTECT" in result.structured_content["effect"]
    assert "BLOCKED" in result.structured_content["effect"]


async def test_create_service_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SERVICE_PATH).respond(200, json={})
    plan = await client.call_tool(
        "nv_create_service", {"name": "api", "domain": "prod", "policy_mode": "Discover"}
    )
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception, match="confirm token mismatch"):
        await client.call_tool(
            "nv_create_service",
            {"name": "api", "domain": "prod", "policy_mode": "Protect", "confirm": token},
        )
    assert route.call_count == 0


# -- nv_update_workload_config --------------------------------------------------


async def test_update_workload_config_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(WORKLOAD_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_workload_config",
        {
            "workload_id": WORKLOAD_ID,
            "namespace": "prod",
            "quarantine": False,
            "wire": "default",
        },
    )

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "ASSERTS quarantine=False" in body["effect"]
    assert "nv_quarantine_workload" in body["effect"]
    assert route.call_count == 0


async def test_update_workload_config_confirmed_sends_exact_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(WORKLOAD_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_workload_config",
        {
            "workload_id": WORKLOAD_ID,
            "namespace": "prod",
            "quarantine": True,
            "wire": "default",
            "quarantine_reason": "incident 4412",
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "quarantine": True,
            "wire": "default",
            "quarantine_reason": "incident 4412",
        }
    }


async def test_update_workload_config_always_sends_quarantine(
    client, nv_mock: respx.MockRouter
) -> None:
    """apis.go RESTWorkloadConfig.Quarantine has no omitempty and apis.yaml marks it required.

    The key must always be present, even when the caller is only changing the
    wire mode, because an omitted key decodes as false on the controller.
    """
    route = nv_mock.patch(WORKLOAD_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_workload_config",
        {
            "workload_id": WORKLOAD_ID,
            "namespace": "prod",
            "quarantine": False,
            "wire": "default",
        },
    )
    config = json.loads(route.calls.last.request.read())["config"]
    assert config == {"quarantine": False, "wire": "default"}
    assert "quarantine_reason" not in config


async def test_update_workload_config_requires_wire(client, nv_mock: respx.MockRouter) -> None:
    """Without a wire mode the call would only assert quarantine, duplicating another tool."""
    route = nv_mock.patch(WORKLOAD_PATH).respond(200, json={})
    with pytest.raises(Exception, match="nv_quarantine_workload"):
        await client.call_tool(
            "nv_update_workload_config",
            {"workload_id": WORKLOAD_ID, "namespace": "prod", "quarantine": True},
        )
    assert route.call_count == 0


async def test_update_workload_config_respects_namespace_allowlist(
    nv_mock: respx.MockRouter,
) -> None:
    route = nv_mock.patch(WORKLOAD_PATH).respond(200, json={})
    server = build_server(make_settings(allowed_namespaces=frozenset({"staging"})))
    async with Client(server) as client:
        with pytest.raises(Exception, match="NV_ALLOWED_NAMESPACES"):
            await client.call_tool(
                "nv_update_workload_config",
                {
                    "workload_id": WORKLOAD_ID,
                    "namespace": "prod",
                    "quarantine": False,
                    "wire": "default",
                },
            )
    assert route.call_count == 0


async def test_update_workload_config_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(WORKLOAD_PATH).respond(200, json={})
    plan = await client.call_tool(
        "nv_update_workload_config",
        {
            "workload_id": WORKLOAD_ID,
            "namespace": "prod",
            "quarantine": True,
            "wire": "default",
        },
    )
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception, match="confirm token mismatch"):
        await client.call_tool(
            "nv_update_workload_config",
            {
                "workload_id": WORKLOAD_ID,
                "namespace": "prod",
                "quarantine": False,
                "wire": "default",
                "confirm": token,
            },
        )
    assert route.call_count == 0


# -- nv_apply_system_request ----------------------------------------------------


async def test_apply_system_request_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    result = await client.call_tool("nv_apply_system_request", {"policy_mode": "Protect"})

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "CLUSTER-WIDE CHANGE" in body["effect"]
    assert "NV_ALLOWED_NAMESPACES DOES NOT CONSTRAIN THIS CALL" in body["effect"]
    assert "nv_set_service_mode" in body["effect"]
    assert route.call_count == 0


async def test_apply_system_request_protect_spells_out_the_consequence(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    result = await client.call_tool("nv_apply_system_request", {"policy_mode": "Protect"})
    effect = result.structured_content["effect"]
    assert "BLOCKING every connection" in effect
    assert "in every namespace" in effect
    assert "Discover" in effect


async def test_apply_system_request_confirmed_sends_exact_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_apply_system_request",
        {"policy_mode": "Monitor", "baseline_profile": "zero-drift"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    assert json.loads(route.calls.last.request.read()) == {
        "request": {"policy_mode": "Monitor", "baseline_profile": "zero-drift"}
    }


async def test_apply_system_request_omits_unsupplied_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    await _confirmed(client, "nv_apply_system_request", {"policy_mode": "Discover"})

    request = json.loads(route.calls.last.request.read())["request"]
    assert request == {"policy_mode": "Discover"}
    for absent in ("baseline_profile", "unquarantine", "profile_mode"):
        assert absent not in request


async def test_apply_system_request_filtered_unquarantine_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_apply_system_request",
        {
            "unquarantine": True,
            "unquarantine_group": "nv.api.prod",
            "unquarantine_response_rule_id": 1007,
        },
    )
    assert json.loads(route.calls.last.request.read()) == {
        "request": {"unquarantine": {"group": "nv.api.prod", "response_rule": 1007}}
    }


async def test_apply_system_request_unfiltered_unquarantine_is_called_out(
    client, nv_mock: respx.MockRouter
) -> None:
    """An unquarantine with no filter releases everything; the plan must say so."""
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    result = await client.call_tool("nv_apply_system_request", {"unquarantine": True})

    assert "EVERY quarantined container in the cluster" in result.structured_content["effect"]
    assert route.call_count == 0

    await _confirmed(client, "nv_apply_system_request", {"unquarantine": True})
    assert json.loads(route.calls.last.request.read()) == {"request": {"unquarantine": {}}}


async def test_apply_system_request_rejects_empty_request(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    with pytest.raises(Exception, match="at least one of policy_mode"):
        await client.call_tool("nv_apply_system_request", {})
    assert route.call_count == 0


async def test_apply_system_request_rejects_filters_without_unquarantine(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    with pytest.raises(Exception, match="unquarantine is false"):
        await client.call_tool(
            "nv_apply_system_request",
            {"policy_mode": "Monitor", "unquarantine_group": "nv.api.prod"},
        )
    assert route.call_count == 0


async def test_apply_system_request_ignores_namespace_allowlist(
    nv_mock: respx.MockRouter,
) -> None:
    """The documented gap, pinned as a test.

    POST /v1/system/request carries no namespace, so authorise_write has none to
    check and NV_ALLOWED_NAMESPACES cannot bound this call. This test exists so
    that the gap is a deliberate, visible property rather than an oversight - if
    the guard ever gains a way to scope it, this test should be the one to fail.
    """
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    server = build_server(make_settings(allowed_namespaces=frozenset({"staging"})))
    async with Client(server) as client:
        result = await _confirmed(client, "nv_apply_system_request", {"policy_mode": "Protect"})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1, "the namespace allowlist did NOT stop this cluster-wide call"


async def test_apply_system_request_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SYSTEM_REQUEST_PATH).respond(200, json={})
    plan = await client.call_tool("nv_apply_system_request", {"policy_mode": "Monitor"})
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception, match="confirm token mismatch"):
        await client.call_tool(
            "nv_apply_system_request", {"policy_mode": "Protect", "confirm": token}
        )
    assert route.call_count == 0


# -- nv_set_namespace_defaults --------------------------------------------------


async def test_set_namespace_defaults_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(DOMAIN_PATH).respond(200, json={})
    result = await client.call_tool("nv_set_namespace_defaults", {"tag_per_domain": False})

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "EVERY namespace in the cluster" in body["effect"]
    assert "nv_set_namespace_tags" in body["effect"]
    assert route.call_count == 0


async def test_set_namespace_defaults_confirmed_sends_exact_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(DOMAIN_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_set_namespace_defaults", {"tag_per_domain": True})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert route.calls.last.request.url.path == DOMAIN_PATH, (
        "must be the cluster-wide route, not PATCH /v1/domain/{name}"
    )
    assert json.loads(route.calls.last.request.read()) == {"config": {"tag_per_domain": True}}


async def test_set_namespace_defaults_off_warns_tags_stop_applying(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(DOMAIN_PATH).respond(200, json={})
    result = await client.call_tool("nv_set_namespace_defaults", {"tag_per_domain": False})
    effect = result.structured_content["effect"]
    assert "stop being honoured everywhere" in effect
    assert "code 4" in effect


async def test_set_namespace_defaults_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(DOMAIN_PATH).respond(200, json={})
    plan = await client.call_tool("nv_set_namespace_defaults", {"tag_per_domain": True})
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception, match="confirm token mismatch"):
        await client.call_tool(
            "nv_set_namespace_defaults", {"tag_per_domain": False, "confirm": token}
        )
    assert route.call_count == 0


# -- toolset gating -------------------------------------------------------------


async def test_each_toolset_gates_its_own_tools(nv_mock: respx.MockRouter) -> None:
    """The module spans three toolsets and each must be gated independently."""
    server = build_server(make_settings(toolsets=("system_write",)))
    async with Client(server) as client:
        names = {tool.name for tool in await client.list_tools()}

    assert "nv_apply_system_request" in names
    assert "nv_set_namespace_defaults" in names
    assert "nv_create_service" not in names, "policy_write tool leaked into system_write"
    assert "nv_update_workload_config" not in names, "runtime_ops tool leaked into system_write"
