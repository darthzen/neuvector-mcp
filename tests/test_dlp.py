"""DLP toolset contract tests.

These are the tests that stand between a model and live traffic. Every mutating
tool gets a preview that must send NOTHING, asserted with ``route.call_count ==
0``, and a confirmed call whose exact JSON body is spelled out in full.

The body assertions are the safety-critical ones. The controller answers 200 and
silently drops keys it does not recognise, so "the test passed" only means
anything if the test names every key. Shapes come from apis.go (controller
5.6.0): ``RESTDlpSensorConfigData``, ``RESTDlpGroupConfigData``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from fastmcp import Client

from conftest import make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

SENSOR = "sensor.card-pan"
SENSOR_PATH = "/v1/dlp/sensor"
GROUP_PATH = "/v1/dlp/group"
LEARNED_GROUP = "nv.api.prod"

DLP_RULE = {
    "name": "rule.card-pan",
    "patterns": [{"value": "4[0-9]{12}(?:[0-9]{3})?", "op": "regex"}],
}
DLP_RULE_WITH_CONTEXT = {
    "name": "rule.card-pan",
    "patterns": [{"value": "4[0-9]{12}", "op": "regex", "context": "body"}],
}
DLP_RULE_NEGATIVE = {
    "name": "rule.egress-allowlist",
    "patterns": [{"value": "^allowed-payload$", "op": "!regex"}],
}

SENSOR_FIXTURE = {
    "sensor": {
        "name": SENSOR,
        "comment": "cardholder data",
        "cfg_type": "user_created",
        "predefine": False,
        "groups": [LEARNED_GROUP],
        "rules": [
            {
                "name": "rule.card-pan",
                "id": 20001,
                "cfg_type": "user_created",
                "patterns": [
                    {"key": "pattern", "op": "regex", "value": "4[0-9]{12}", "context": "packet"}
                ],
            }
        ],
    }
}

GROUP_FIXTURE = {
    "dlp_group": {
        "name": LEARNED_GROUP,
        "status": True,
        "cfg_type": "learned",
        "sensors": [
            {
                "name": SENSOR,
                "action": "deny",
                "exist": True,
                "predefine": False,
                "comment": "cardholder data",
                "cfg_type": "user_created",
            }
        ],
    }
}

GROUPS_FIXTURE = {
    "dlp_groups": [
        GROUP_FIXTURE["dlp_group"],
        {"name": "nv.web.staging", "status": False, "cfg_type": "learned", "sensors": []},
    ]
}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- nv_get_dlp_sensor ----------------------------------------------------------


async def test_get_dlp_sensor_returns_pattern_bodies(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{SENSOR_PATH}/{SENSOR}").respond(200, json=SENSOR_FIXTURE)
    result = await client.call_tool("nv_get_dlp_sensor", {"sensor_name": SENSOR})
    body = result.structured_content
    assert body["name"] == SENSOR
    assert body["groups"] == [LEARNED_GROUP]
    assert body["predefined"] is False
    assert body["rules"][0]["patterns"][0]["value"] == "4[0-9]{12}"
    assert body["rules"][0]["id"] == 20001


async def test_get_dlp_sensor_missing_raises_not_found(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_dlp_sensor", {"sensor_name": SENSOR})
    assert "no DLP sensor named" in str(excinfo.value)


# -- nv_list_dlp_groups ---------------------------------------------------------


async def test_list_dlp_groups_unwraps_dlp_groups_envelope(
    client, nv_mock: respx.MockRouter
) -> None:
    # apis.go RESTDlpGroupsData names the envelope 'dlp_groups', not 'groups'.
    nv_mock.get(GROUP_PATH).respond(200, json=GROUPS_FIXTURE)
    result = await client.call_tool("nv_list_dlp_groups", {})
    body = result.structured_content
    assert [g["name"] for g in body["groups"]] == [LEARNED_GROUP, "nv.web.staging"]
    assert body["groups"][0]["sensors"][0]["action"] == "deny"
    assert body["page"]["truncated"] is False


async def test_list_dlp_groups_bound_only_filters_unbound(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(GROUP_PATH).respond(200, json=GROUPS_FIXTURE)
    result = await client.call_tool("nv_list_dlp_groups", {"bound_only": True})
    assert [g["name"] for g in result.structured_content["groups"]] == [LEARNED_GROUP]


async def test_list_dlp_groups_sends_no_scope_parameter(client, nv_mock: respx.MockRouter) -> None:
    # GET /v1/dlp/group documents no 'scope', unlike GET /v1/waf/group.
    route = nv_mock.get(GROUP_PATH).respond(200, json=GROUPS_FIXTURE)
    await client.call_tool("nv_list_dlp_groups", {})
    assert "scope" not in route.calls.last.request.url.params


# -- nv_get_dlp_group -----------------------------------------------------------


async def test_get_dlp_group_returns_bindings(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json=GROUP_FIXTURE)
    body = (
        await client.call_tool("nv_get_dlp_group", {"group_name": LEARNED_GROUP})
    ).structured_content
    assert body["status"] is True
    assert body["sensors"][0]["name"] == SENSOR
    assert body["sensors"][0]["predefined"] is False


async def test_get_dlp_group_missing_raises_not_found(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_dlp_group", {"group_name": LEARNED_GROUP})
    assert "no DLP configuration for group" in str(excinfo.value)


# -- nv_create_dlp_sensor -------------------------------------------------------


async def test_create_dlp_sensor_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_dlp_sensor",
        {"sensor_name": SENSOR, "rules": [DLP_RULE], "comment": "cardholder data"},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "inspects nothing until" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_dlp_sensor_confirmed_sends_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_create_dlp_sensor",
        {"sensor_name": SENSOR, "rules": [DLP_RULE], "comment": "cardholder data"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    # 'context' is omitempty in apis.go RESTDlpCriteriaEntry: absent, not null.
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": SENSOR,
            "cfg_type": "user_created",
            "comment": "cardholder data",
            "rules": [
                {
                    "name": "rule.card-pan",
                    "patterns": [
                        {"key": "pattern", "op": "regex", "value": "4[0-9]{12}(?:[0-9]{3})?"}
                    ],
                }
            ],
        }
    }


async def test_create_dlp_sensor_omits_comment_when_not_given(
    client, nv_mock: respx.MockRouter
) -> None:
    # RESTDlpSensorConfig.Comment is a *string with omitempty. Sending "" would be
    # a value, not an absence, so an unset comment must not appear on the wire.
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    await _confirmed(client, "nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]})
    assert "comment" not in json.loads(route.calls.last.request.read())["config"]


async def test_create_dlp_sensor_sends_context_only_when_set(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    await _confirmed(
        client, "nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE_WITH_CONTEXT]}
    )
    patterns = json.loads(route.calls.last.request.read())["config"]["rules"][0]["patterns"]
    assert patterns == [{"key": "pattern", "op": "regex", "value": "4[0-9]{12}", "context": "body"}]


async def test_create_dlp_sensor_preview_warns_about_negative_regex(
    client, nv_mock: respx.MockRouter
) -> None:
    # '!regex' fires on everything that does NOT match. Getting it backwards drops
    # all legitimate traffic once bound in Protect, so the plan has to say so.
    nv_mock.post(SENSOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE_NEGATIVE]}
    )
    effect = result.structured_content["effect"]
    assert "CAUTION" in effect
    assert "!regex" in effect


async def test_create_dlp_sensor_preview_states_no_negatives(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(SENSOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]}
    )
    assert "All patterns are positive matches." in result.structured_content["effect"]


async def test_create_dlp_sensor_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    plan = await client.call_tool(
        "nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]}
    )
    token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_dlp_sensor",
            {"sensor_name": SENSOR, "rules": [DLP_RULE_NEGATIVE], "confirm": token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_create_dlp_sensor_rejects_pattern_over_total_length(
    client, nv_mock: respx.MockRouter
) -> None:
    # apis.go DlpRulePatternTotalMaxLen = 1024 across one rule's patterns.
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    rule = {
        "name": "rule.too-long",
        "patterns": [{"value": "a" * 400, "op": "regex"} for _ in range(3)],
    }
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [rule]})
    assert "1024" in str(excinfo.value)
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_create_dlp_sensor_rejects_too_many_patterns(
    client, nv_mock: respx.MockRouter
) -> None:
    # apis.go DlpRulePatternMaxNum = 16.
    route = nv_mock.post(SENSOR_PATH).respond(200, json={})
    rule = {
        "name": "rule.too-many",
        "patterns": [{"value": f"pat{i}", "op": "regex"} for i in range(17)],
    }
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_create_dlp_sensor", {"sensor_name": SENSOR, "rules": [rule]})
    assert "patterns" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_update_dlp_sensor -------------------------------------------------------


async def test_update_dlp_sensor_preview_warns_it_replaces(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    result = await client.call_tool(
        "nv_update_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]}
    )
    effect = result.structured_content["effect"]
    assert "REPLACE every rule" in effect
    assert "is deleted and stops detecting" in effect
    assert "start dropping traffic" in effect
    assert route.call_count == 0


async def test_update_dlp_sensor_confirmed_sends_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_dlp_sensor",
        {"sensor_name": SENSOR, "rules": [DLP_RULE], "comment": "updated"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.calls.last.request.method == "PATCH"
    # No 'cfg_type' on PATCH: the sensor already has one.
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": SENSOR,
            "comment": "updated",
            "rules": [
                {
                    "name": "rule.card-pan",
                    "patterns": [
                        {"key": "pattern", "op": "regex", "value": "4[0-9]{12}(?:[0-9]{3})?"}
                    ],
                }
            ],
        }
    }


async def test_update_dlp_sensor_omitted_comment_is_left_unchanged(
    client, nv_mock: respx.MockRouter
) -> None:
    # The pointer field means omission is "leave alone" and "" is "clear it". A
    # tool that always sent comment="" would silently wipe the operator's note.
    route = nv_mock.patch(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    plan = await client.call_tool(
        "nv_update_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]}
    )
    assert "comment is left unchanged" in plan.structured_content["effect"]
    await _confirmed(client, "nv_update_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]})
    assert "comment" not in json.loads(route.calls.last.request.read())["config"]


async def test_update_dlp_sensor_empty_comment_clears_it(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    await _confirmed(
        client, "nv_update_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE], "comment": ""}
    )
    assert json.loads(route.calls.last.request.read())["config"]["comment"] == ""


async def test_update_dlp_sensor_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    plan = await client.call_tool(
        "nv_update_dlp_sensor", {"sensor_name": SENSOR, "rules": [DLP_RULE]}
    )
    token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_dlp_sensor",
            {"sensor_name": SENSOR, "rules": [DLP_RULE], "comment": "x", "confirm": token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_delete_dlp_sensor -------------------------------------------------------


async def test_delete_dlp_sensor_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    result = await client.call_tool("nv_delete_dlp_sensor", {"sensor_name": SENSOR})
    assert result.structured_content["status"] == "confirmation_required"
    assert "silently" in result.structured_content["effect"]
    assert route.call_count == 0


async def test_delete_dlp_sensor_confirmed_calls_delete(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(f"{SENSOR_PATH}/{SENSOR}").respond(200, json={})
    result = await _confirmed(client, "nv_delete_dlp_sensor", {"sensor_name": SENSOR})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"


async def test_delete_dlp_sensor_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(f"{SENSOR_PATH}/other").respond(200, json={})
    plan = await client.call_tool("nv_delete_dlp_sensor", {"sensor_name": SENSOR})
    token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_delete_dlp_sensor", {"sensor_name": "other", "confirm": token})
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_set_dlp_group -----------------------------------------------------------


async def test_set_dlp_group_preview_warns_about_replace_and_protect(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    result = await client.call_tool(
        "nv_set_dlp_group",
        {"group_name": LEARNED_GROUP, "sensors": [{"name": SENSOR, "action": "deny"}]},
    )
    effect = result.structured_content["effect"]
    assert "REPLACE" in effect
    assert "is unbound and stops inspecting" in effect
    assert "will DROP matching traffic" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_set_dlp_group_confirmed_sends_replace_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    result = await _confirmed(
        client,
        "nv_set_dlp_group",
        {
            "group_name": LEARNED_GROUP,
            "sensors": [{"name": SENSOR, "action": "deny"}],
            "status": True,
        },
    )

    assert result.structured_content["status"] == "applied"
    # 'replace' takes {name, action} objects (RESTDlpConfig). The sibling 'delete'
    # key takes bare name strings and is not used here.
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": LEARNED_GROUP,
            "replace": [{"name": SENSOR, "action": "deny"}],
            "status": True,
        }
    }


async def test_set_dlp_group_omits_status_when_not_given(client, nv_mock: respx.MockRouter) -> None:
    # RESTDlpGroupConfig.Status is a *bool with omitempty: omitting it leaves the
    # group's inspection setting alone. Defaulting to true here would silently
    # enable DLP on a group where it was deliberately off.
    route = nv_mock.patch(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    plan = await client.call_tool(
        "nv_set_dlp_group",
        {"group_name": LEARNED_GROUP, "sensors": [{"name": SENSOR, "action": "deny"}]},
    )
    assert "Inspection status is left unchanged." in plan.structured_content["effect"]
    await _confirmed(
        client,
        "nv_set_dlp_group",
        {"group_name": LEARNED_GROUP, "sensors": [{"name": SENSOR, "action": "deny"}]},
    )
    assert json.loads(route.calls.last.request.read()) == {
        "config": {"name": LEARNED_GROUP, "replace": [{"name": SENSOR, "action": "deny"}]}
    }


async def test_set_dlp_group_empty_list_unbinds_everything(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    await _confirmed(client, "nv_set_dlp_group", {"group_name": LEARNED_GROUP, "sensors": []})
    assert json.loads(route.calls.last.request.read())["config"]["replace"] == []


async def test_set_dlp_group_token_is_bound_to_arguments(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(f"{GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    plan = await client.call_tool(
        "nv_set_dlp_group",
        {"group_name": LEARNED_GROUP, "sensors": [{"name": SENSOR, "action": "deny"}]},
    )
    token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_set_dlp_group",
            {
                "group_name": LEARNED_GROUP,
                "sensors": [{"name": SENSOR, "action": "allow"}],
                "confirm": token,
            },
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_set_dlp_group_respects_allowed_namespaces(nv_mock: respx.MockRouter) -> None:
    # LEARNED_GROUP is nv.api.prod, so the namespace is 'prod'.
    server = build_server(make_settings(allowed_namespaces=("staging",)))
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool("nv_set_dlp_group", {"group_name": LEARNED_GROUP, "sensors": []})
    assert "prod" in str(excinfo.value)


# -- registration ---------------------------------------------------------------


async def test_dlp_write_tools_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}
    # The read tools stay: they are what a caller uses to resolve names.
    assert "nv_get_dlp_sensor" in names
    assert "nv_list_dlp_groups" in names
    assert "nv_get_dlp_group" in names
    for tool in (
        "nv_create_dlp_sensor",
        "nv_update_dlp_sensor",
        "nv_delete_dlp_sensor",
        "nv_set_dlp_group",
    ):
        assert tool not in names, f"{tool} must be hidden when NV_READ_ONLY=true"


async def test_dlp_read_tools_take_no_confirm(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    for name in ("nv_get_dlp_sensor", "nv_list_dlp_groups", "nv_get_dlp_group"):
        assert "confirm" not in (tools[name].inputSchema.get("properties") or {})
