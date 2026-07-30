"""Admission toolset contract tests.

Admission control is the widest blast radius in the server: a deny rule blocks
Kubernetes deployments in every namespace. Every test here exists to prove one
of two things - that a preview sends nothing at all, or that a confirmed call
sends exactly the body the preview described.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from conftest import fixture, make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

STATE_PATH = "/v1/admission/state"
RULE_PATH = "/v1/admission/rule"

ROOT_CRITERION = {"name": "runAsRoot", "op": "=", "value": "true"}
REGISTRY_CRITERION = {"name": "imageRegistry", "op": "containsAny", "value": "docker.io"}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- nv_set_admission_state -----------------------------------------------------


async def test_set_admission_state_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(STATE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_set_admission_state",
        {"enable": True, "mode": "protect", "default_action": "deny"},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_set_admission_state_preview_warns_about_blocking_all_deployments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(STATE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_set_admission_state",
        {"enable": True, "mode": "protect", "default_action": "deny"},
    )
    effect = result.structured_content["effect"]
    assert "BLOCK EVERY DEPLOYMENT IN THE CLUSTER" in effect
    assert "nv_assess_admission_rule" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_set_admission_state_monitor_preview_says_nothing_is_blocked(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(STATE_PATH).respond(200, json={})
    result = await client.call_tool("nv_set_admission_state", {"enable": True, "mode": "monitor"})
    effect = result.structured_content["effect"]
    assert "nothing is blocked" in effect
    assert "DANGER" not in effect, "the monitor branch must not borrow the protect warning"


async def test_set_admission_state_disable_preview_says_break_glass(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(STATE_PATH).respond(200, json={})
    result = await client.call_tool("nv_set_admission_state", {"enable": False})
    assert "break-glass" in result.structured_content["effect"]


async def test_set_admission_state_confirmed_sends_state_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(STATE_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_set_admission_state",
        {"enable": True, "mode": "protect", "default_action": "deny"},
    )
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "state": {"enable": True, "mode": "protect", "default_action": "deny"}
    }


async def test_set_admission_state_omits_unset_fields(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(STATE_PATH).respond(200, json={})
    await _confirmed(client, "nv_set_admission_state", {"enable": True})
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {"state": {"enable": True}}


async def test_set_admission_state_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(STATE_PATH).respond(200, json={})
    monitor_token = confirm_token(
        "nv_set_admission_state",
        "cluster admission control",
        {"state": {"enable": True, "mode": "monitor"}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_admission_state",
            {"enable": True, "mode": "protect", "confirm": monitor_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a monitor token must never apply a protect change"


async def test_set_admission_state_non_kubernetes_returns_validation_error(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(STATE_PATH).respond(400, json=fixture("error_admctrl_unsupported"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(client, "nv_set_admission_state", {"enable": True})
    assert "code=30" in str(excinfo.value)


# -- nv_create_admission_rule ---------------------------------------------------


async def test_create_admission_rule_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(RULE_PATH).respond(200, json=fixture("admission_rule_created"))
    result = await client.call_tool(
        "nv_create_admission_rule",
        {
            "rule_type": "deny",
            "criteria": [ROOT_CRITERION, REGISTRY_CRITERION],
            "comment": "block root containers",
        },
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "runAsRoot = true" in body["effect"]
    assert "imageRegistry containsAny docker.io" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_admission_rule_deny_preview_warns_about_rejection(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(RULE_PATH).respond(200, json=fixture("admission_rule_created"))
    result = await client.call_tool(
        "nv_create_admission_rule", {"rule_type": "deny", "criteria": [ROOT_CRITERION]}
    )
    effect = result.structured_content["effect"]
    assert "REJECTED by the" in effect
    assert "nv_assess_admission_rule" in effect


async def test_create_admission_rule_exception_preview_warns_about_exemption(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(RULE_PATH).respond(200, json=fixture("admission_rule_created"))
    result = await client.call_tool(
        "nv_create_admission_rule",
        {"rule_type": "exception", "criteria": [ROOT_CRITERION]},
    )
    effect = result.structured_content["effect"]
    assert "exempts matching requests" in effect
    assert "BLAST RADIUS" not in effect


async def test_create_admission_rule_confirmed_sends_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(RULE_PATH).respond(200, json=fixture("admission_rule_created"))
    result = await _confirmed(
        client,
        "nv_create_admission_rule",
        {
            "rule_type": "deny",
            "criteria": [ROOT_CRITERION],
            "rule_mode": "monitor",
            "comment": "block root containers",
        },
    )
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "category": "Kubernetes",
            "rule_type": "deny",
            "cfg_type": "user_created",
            "criteria": [{"name": "runAsRoot", "op": "=", "value": "true"}],
            "containers": ["containers"],
            "rule_mode": "monitor",
            "comment": "block root containers",
            "disable": False,
        }
    }


async def test_create_admission_rule_returns_new_id(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post(RULE_PATH).respond(200, json=fixture("admission_rule_created"))
    result = await _confirmed(
        client,
        "nv_create_admission_rule",
        {"rule_type": "deny", "criteria": [ROOT_CRITERION]},
    )
    body = result.structured_content
    assert body["target"] == "admission rule 1001"
    assert body["controller_response"]["rule"]["id"] == 1001


async def test_create_admission_rule_rejects_too_many_criteria(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(RULE_PATH).respond(200, json=fixture("admission_rule_created"))
    too_many = [{"name": f"c{i}", "op": "=", "value": "x"} for i in range(17)]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_admission_rule", {"rule_type": "deny", "criteria": too_many}
        )
    assert "16" in str(excinfo.value), "the cap must be named in the error"
    assert route.call_count == 0, "a capped rule must never reach the controller"


# -- nv_update_admission_rule ---------------------------------------------------


async def test_update_admission_rule_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_admission_rule",
        {"rule_id": 1001, "rule_type": "deny", "criteria": [REGISTRY_CRITERION]},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "OVERWRITE admission rule id" in body["effect"]
    assert "REMOVED" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_admission_rule_confirmed_sends_id_in_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_admission_rule",
        {
            "rule_id": 1001,
            "rule_type": "deny",
            "criteria": [REGISTRY_CRITERION],
            "containers": ["containers", "init_containers"],
            "comment": "no public registries",
        },
    )
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert route.calls.last.request.url.path == RULE_PATH
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "id": 1001,
            "category": "Kubernetes",
            "rule_type": "deny",
            "cfg_type": "user_created",
            "criteria": [{"name": "imageRegistry", "op": "containsAny", "value": "docker.io"}],
            "containers": ["containers", "init_containers"],
            "rule_mode": "",
            "comment": "no public registries",
            "disable": False,
        }
    }


async def test_admission_rule_patch_has_no_id_in_path(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_admission_rule",
        {"rule_id": 1001, "rule_type": "exception", "criteria": [ROOT_CRITERION]},
    )
    path = route.calls.last.request.url.path
    assert path == "/v1/admission/rule"
    assert "1001" not in path, "PATCH /v1/admission/rule/{id} does not exist"
    assert json.loads(route.calls.last.request.read())["config"]["id"] == 1001


async def test_update_admission_rule_missing_raises_not_found(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(RULE_PATH).respond(404, json=fixture("error_object_not_found"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(
            client,
            "nv_update_admission_rule",
            {"rule_id": 4242, "rule_type": "deny", "criteria": [ROOT_CRITERION]},
        )
    assert "code=7" in str(excinfo.value)


async def test_update_admission_rule_readonly_rule_returns_permission_error(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(RULE_PATH).respond(403, json=fixture("error_read_only_rules"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(
            client,
            "nv_update_admission_rule",
            {"rule_id": 1, "rule_type": "deny", "criteria": [ROOT_CRITERION]},
        )
    assert "code=46" in str(excinfo.value)


# -- nv_delete_admission_rule ---------------------------------------------------


async def test_delete_admission_rule_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete("/v1/admission/rule/1001").respond(200, json={})
    result = await client.call_tool("nv_delete_admission_rule", {"rule_id": 1001})
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "EXCEPTION" in body["effect"]
    assert "DENY" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_admission_rule_confirmed_calls_delete(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete("/v1/admission/rule/1001").respond(200, json={})
    result = await _confirmed(client, "nv_delete_admission_rule", {"rule_id": 1001})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.url.path == "/v1/admission/rule/1001"
    assert route.calls.last.request.read() == b"", "DELETE must send no body"


async def test_delete_admission_rule_critical_rule_returns_permission_error(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.delete("/v1/admission/rule/2").respond(403, json=fixture("error_op_not_allowed"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(client, "nv_delete_admission_rule", {"rule_id": 2})
    assert "code=4" in str(excinfo.value)


# -- registration ---------------------------------------------------------------


async def test_admission_tools_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}
    assert "nv_set_admission_state" not in names
    assert "nv_create_admission_rule" not in names
    assert "nv_update_admission_rule" not in names
    assert "nv_delete_admission_rule" not in names
    assert "nv_get_admission_state" in names, "the read tool must survive"


async def test_admission_tools_declare_mutation(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    for name in (
        "nv_set_admission_state",
        "nv_create_admission_rule",
        "nv_update_admission_rule",
        "nv_delete_admission_rule",
    ):
        assert tools[name].annotations.readOnlyHint is False
        assert tools[name].annotations.destructiveHint is True
