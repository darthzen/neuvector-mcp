"""policy_write toolset contract tests.

These are the tests that stand between a model and production traffic. Every
mutating tool gets two of them: a preview that must send NOTHING, asserted with
``route.call_count == 0``, and a confirmed call whose exact JSON body is spelled
out in full. ``nv_set_group_policy_mode`` is covered by ``tests/test_guard.py``
and is deliberately absent here.
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

GROUP = "custom.payments"
LEARNED_GROUP = "nv.api.prod"
GROUP_PATH = f"/v1/group/{GROUP}"
RULE_BATCH_PATH = "/v1/policy/rule"
PROCESS_PATH = f"/v1/process_profile/{LEARNED_GROUP}"
FILE_MONITOR_PATH = f"/v1/file_monitor/{LEARNED_GROUP}"

WAF_SENSOR = "sensor.mcp-hardening"
WAF_SENSOR_PATH = "/v1/waf/sensor"
WAF_GROUP_PATH = "/v1/waf/group"

WAF_RULE = {
    "name": "rule.jsonrpc",
    "patterns": [{"value": "\\$\\{jndi:", "context": "header", "op": "regex"}],
}
WAF_RULE_NEGATIVE = {
    "name": "rule.host-allowlist",
    "patterns": [{"value": "^allowed\\.example$", "context": "header", "op": "!regex"}],
}

DOMAIN_CRITERION = {"key": "domain", "value": "payments", "op": "="}
LABEL_CRITERION = {"key": "label", "value": "tier=web", "op": "="}

NEW_RULE = {
    "from_group": "custom.web",
    "to_group": "custom.db",
    "action": "allow",
    "ports": "tcp/5432",
    "applications": ["PostgreSQL"],
    "comment": "web to db",
}
CONFIGURED_RULE = {
    "id": 22,
    "from_group": "custom.web",
    "to_group": "custom.cache",
    "action": "deny",
    "ports": "tcp/6379",
}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- nv_create_group ------------------------------------------------------------


async def test_create_group_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/group").respond(200, json={})
    result = await client.call_tool(
        "nv_create_group",
        {"group_name": GROUP, "criteria": [DOMAIN_CRITERION, LABEL_CRITERION]},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "domain = payments" in body["effect"]
    assert "label = tier=web" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_group_confirmed_sends_config_body(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post("/v1/group").respond(200, json={})
    result = await _confirmed(
        client, "nv_create_group", {"group_name": GROUP, "criteria": [DOMAIN_CRITERION]}
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": "custom.payments",
            "cfg_type": "user_created",
            "criteria": [{"key": "domain", "value": "payments", "op": "="}],
        }
    }


async def test_create_group_duplicate_name_raises_conflict(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post("/v1/group").respond(400, json=fixture("error_duplicate_name"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(
            client, "nv_create_group", {"group_name": GROUP, "criteria": [DOMAIN_CRITERION]}
        )
    assert "code=13" in str(excinfo.value)


# -- nv_update_group_criteria ---------------------------------------------------


async def test_update_group_criteria_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(GROUP_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_group_criteria",
        {"group_name": GROUP, "criteria": [DOMAIN_CRITERION, LABEL_CRITERION]},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_group_criteria_effect_says_replacement(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(GROUP_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_group_criteria", {"group_name": GROUP, "criteria": [DOMAIN_CRITERION]}
    )
    effect = result.structured_content["effect"]
    assert "REPLACE" in effect
    assert "REMOVED" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_group_criteria_confirmed_replaces_criteria(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(GROUP_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_group_criteria",
        {"group_name": GROUP, "criteria": [DOMAIN_CRITERION, LABEL_CRITERION]},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": "custom.payments",
            "cfg_type": "user_created",
            "criteria": [
                {"key": "domain", "value": "payments", "op": "="},
                {"key": "label", "value": "tier=web", "op": "="},
            ],
        }
    }


async def test_update_group_criteria_learned_group_returns_permission_error(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(f"/v1/group/{LEARNED_GROUP}").respond(403, json=fixture("error_op_not_allowed"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(
            client,
            "nv_update_group_criteria",
            {"group_name": LEARNED_GROUP, "criteria": [DOMAIN_CRITERION]},
        )
    assert "code=4" in str(excinfo.value)


# -- nv_delete_group ------------------------------------------------------------


async def test_delete_group_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(GROUP_PATH).respond(200, json={})
    result = await client.call_tool("nv_delete_group", {"group_name": GROUP})
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert body["confirm_token"] == confirm_token("nv_delete_group", GROUP, None)
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_group_confirmed_calls_delete(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(GROUP_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_group", {"group_name": GROUP})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.read() == b"", "DELETE carries no body"


# -- nv_apply_network_rule_changes ----------------------------------------------


async def test_apply_network_rule_changes_preview_lists_every_change(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_apply_network_rule_changes",
        {
            "insert_rules": [NEW_RULE],
            "insert_after_rule_id": 10,
            "move_rule_id": 7,
            "move_after_rule_id": 3,
            "configure_rules": [CONFIGURED_RULE],
            "delete_rule_ids": [31, 32],
        },
    )
    effect = result.structured_content["effect"]
    assert result.structured_content["status"] == "confirmation_required"
    assert "+ INSERT custom.web -> custom.db" in effect
    assert "~ MOVE rule id 7" in effect
    assert "~ CONFIGURE rule id 22" in effect
    assert "- DELETE rule id 31" in effect
    assert "- DELETE rule id 32" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_apply_network_rule_changes_confirmed_sends_batch_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_apply_network_rule_changes",
        {
            "insert_rules": [NEW_RULE],
            "insert_after_rule_id": 10,
            "configure_rules": [CONFIGURED_RULE],
            "delete_rule_ids": [31, 32],
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "insert": {
            "after": 10,
            "rules": [
                {
                    "from": "custom.web",
                    "to": "custom.db",
                    "ports": "tcp/5432",
                    "action": "allow",
                    "applications": ["PostgreSQL"],
                    "comment": "web to db",
                    "disable": False,
                    "cfg_type": "user_created",
                }
            ],
        },
        "rules": [
            {
                "id": 22,
                "from": "custom.web",
                "to": "custom.cache",
                "ports": "tcp/6379",
                "action": "deny",
                "applications": [],
                "comment": "",
                "disable": False,
                "cfg_type": "user_created",
            }
        ],
        "delete": [31, 32],
    }


async def test_apply_network_rule_changes_sends_scope_param(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_apply_network_rule_changes",
        {"delete_rule_ids": [31], "scope": "fed"},
    )
    assert route.calls.last.request.url.params["scope"] == "fed"


async def test_apply_network_rule_changes_token_is_bound_to_scope(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    local_token = confirm_token(
        "nv_apply_network_rule_changes",
        "network policy rules (scope=local)",
        {"delete": [31]},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_apply_network_rule_changes",
            {"delete_rule_ids": [31], "scope": "fed", "confirm": local_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted for local must not apply to fed"


async def test_apply_network_rule_changes_rejects_oversized_batch(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_apply_network_rule_changes", {"delete_rule_ids": list(range(100, 117))}
        )
    assert "hard cap" in str(excinfo.value)
    assert route.call_count == 0


async def test_apply_network_rule_changes_requires_id_on_configure(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_apply_network_rule_changes", {"configure_rules": [NEW_RULE]})
    assert "must carry the 'id'" in str(excinfo.value)
    assert route.call_count == 0


async def test_apply_network_rule_changes_rejects_id_on_insert(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_apply_network_rule_changes", {"insert_rules": [{**NEW_RULE, "id": 5}]}
        )
    assert "must NOT carry an 'id'" in str(excinfo.value)
    assert route.call_count == 0


async def test_apply_network_rule_changes_rejects_empty_batch(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_apply_network_rule_changes", {"scope": "local"})
    assert "at least one of insert_rules" in str(excinfo.value)
    assert route.call_count == 0


async def test_apply_network_rule_changes_learned_rule_returns_permission_error(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(RULE_BATCH_PATH).respond(403, json=fixture("error_op_not_allowed"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(client, "nv_apply_network_rule_changes", {"delete_rule_ids": [31]})
    assert "code=4" in str(excinfo.value)


async def test_apply_network_rule_changes_fed_scope_returns_permission_error(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(RULE_BATCH_PATH).respond(403, json=fixture("error_read_only_rules"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(
            client,
            "nv_apply_network_rule_changes",
            {"delete_rule_ids": [31], "scope": "fed"},
        )
    assert "code=46" in str(excinfo.value)


# -- nv_delete_network_rule -----------------------------------------------------


async def test_delete_network_rule_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete("/v1/policy/rule/42").respond(200, json={})
    result = await client.call_tool("nv_delete_network_rule", {"rule_id": 42})
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "42" in body["effect"]
    assert "ALLOW" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_network_rule_confirmed_calls_delete(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete("/v1/policy/rule/42").respond(200, json={})
    result = await _confirmed(client, "nv_delete_network_rule", {"rule_id": 42})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.url.path == "/v1/policy/rule/42"
    assert route.calls.last.request.read() == b"", "DELETE carries no body"


async def test_delete_network_rule_missing_raises_not_found(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.delete("/v1/policy/rule/42").respond(404, json=fixture("error_object_not_found"))
    with pytest.raises(Exception) as excinfo:
        await _confirmed(client, "nv_delete_network_rule", {"rule_id": 42})
    assert "code=7" in str(excinfo.value)


# -- nv_update_process_profile --------------------------------------------------

CURL_ENTRY = {"name": "curl", "path": "/usr/bin/curl", "action": "deny"}
NC_ENTRY = {"name": "nc", "path": "/usr/bin/nc", "action": "allow"}


async def test_update_process_profile_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(PROCESS_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_process_profile",
        {
            "group_name": LEARNED_GROUP,
            "add_entries": [CURL_ENTRY],
            "delete_entries": [NC_ENTRY],
        },
    )
    effect = result.structured_content["effect"]
    assert result.structured_content["status"] == "confirmation_required"
    assert "KILLS" in effect
    assert "curl at /usr/bin/curl" in effect
    assert "nc at /usr/bin/nc" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_process_profile_confirmed_sends_process_profile_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(PROCESS_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_process_profile",
        {"group_name": LEARNED_GROUP, "add_entries": [CURL_ENTRY]},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "process_profile_config": {
            "group": "nv.api.prod",
            "process_change_list": [
                {
                    "name": "curl",
                    "path": "/usr/bin/curl",
                    "action": "deny",
                    "group": "nv.api.prod",
                }
            ],
        }
    }


async def test_update_process_profile_fills_group_on_every_entry(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(PROCESS_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_process_profile",
        {
            "group_name": LEARNED_GROUP,
            "add_entries": [CURL_ENTRY],
            "delete_entries": [NC_ENTRY],
        },
    )
    config = json.loads(route.calls.last.request.read())["process_profile_config"]
    entries = config["process_change_list"] + config["process_delete_list"]
    assert [e["group"] for e in entries] == ["nv.api.prod", "nv.api.prod"]


async def test_update_process_profile_omits_unset_flags(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PROCESS_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_process_profile",
        {
            "group_name": LEARNED_GROUP,
            "add_entries": [CURL_ENTRY],
            "alert_disabled": None,
            "hash_enabled": None,
        },
    )
    config = json.loads(route.calls.last.request.read())["process_profile_config"]
    assert "alert_disabled" not in config
    assert "hash_enabled" not in config


async def test_update_process_profile_rejects_empty_change_set(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(PROCESS_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_process_profile", {"group_name": LEARNED_GROUP})
    assert "at least one of add_entries" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_update_file_monitor_profile ---------------------------------------------

BLOCK_FILTER = {
    "filter": "/etc/nginx/*",
    "recursive": True,
    "behavior": "block",
    "applications": ["nginx"],
}
MONITOR_FILTER = {"filter": "/var/log/*", "recursive": False, "behavior": "monitor"}


async def test_update_file_monitor_profile_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(FILE_MONITOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_file_monitor_profile",
        {
            "group_name": LEARNED_GROUP,
            "add_filters": [BLOCK_FILTER],
            "delete_filters": [MONITOR_FILTER],
        },
    )
    effect = result.structured_content["effect"]
    assert result.structured_content["status"] == "confirmation_required"
    blast = effect.split("BLAST RADIUS:", 1)[1]
    assert "/etc/nginx/*" in blast
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_file_monitor_profile_confirmed_sends_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(FILE_MONITOR_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_file_monitor_profile",
        {
            "group_name": LEARNED_GROUP,
            "add_filters": [BLOCK_FILTER],
            "delete_filters": [MONITOR_FILTER],
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "add_filters": [
                {
                    "filter": "/etc/nginx/*",
                    "recursive": True,
                    "behavior": "block",
                    "applications": ["nginx"],
                    "group": "nv.api.prod",
                }
            ],
            "delete_filters": [
                {
                    "filter": "/var/log/*",
                    "recursive": False,
                    "behavior": "monitor",
                    "applications": [],
                    "group": "nv.api.prod",
                }
            ],
        }
    }


async def test_update_file_monitor_profile_omits_empty_lists(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(FILE_MONITOR_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_file_monitor_profile",
        {"group_name": LEARNED_GROUP, "add_filters": [BLOCK_FILTER]},
    )
    config = json.loads(route.calls.last.request.read())["config"]
    assert "update_filters" not in config
    assert "delete_filters" not in config


async def test_update_file_monitor_profile_rejects_empty_change_set(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(FILE_MONITOR_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_file_monitor_profile", {"group_name": LEARNED_GROUP})
    assert "at least one of add_filters" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_create_waf_sensor -------------------------------------------------------


async def test_create_waf_sensor_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(WAF_SENSOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_waf_sensor",
        {"sensor_name": WAF_SENSOR, "rules": [WAF_RULE], "comment": "mcp hardening"},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "inspects nothing until" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_waf_sensor_confirmed_sends_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(WAF_SENSOR_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_create_waf_sensor",
        {"sensor_name": WAF_SENSOR, "rules": [WAF_RULE], "comment": "mcp hardening"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": WAF_SENSOR,
            "comment": "mcp hardening",
            "cfg_type": "user_created",
            "rules": [
                {
                    "name": "rule.jsonrpc",
                    "patterns": [
                        {
                            "key": "pattern",
                            "op": "regex",
                            "value": "\\$\\{jndi:",
                            "context": "header",
                        }
                    ],
                }
            ],
        }
    }


async def test_create_waf_sensor_preview_warns_about_negative_regex(
    client, nv_mock: respx.MockRouter
) -> None:
    # '!regex' fires on every request that does NOT match. Getting it backwards
    # takes out all legitimate traffic, so the plan has to say so out loud.
    nv_mock.post(WAF_SENSOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_waf_sensor",
        {"sensor_name": WAF_SENSOR, "rules": [WAF_RULE_NEGATIVE]},
    )
    effect = result.structured_content["effect"]
    assert "CAUTION" in effect
    assert "!regex" in effect


async def test_create_waf_sensor_preview_states_no_negatives(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(WAF_SENSOR_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_waf_sensor", {"sensor_name": WAF_SENSOR, "rules": [WAF_RULE]}
    )
    assert "All patterns are positive matches." in result.structured_content["effect"]


# -- nv_update_waf_sensor -------------------------------------------------------


async def test_update_waf_sensor_preview_warns_it_replaces(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{WAF_SENSOR_PATH}/{WAF_SENSOR}").respond(200, json={})
    result = await client.call_tool(
        "nv_update_waf_sensor", {"sensor_name": WAF_SENSOR, "rules": [WAF_RULE]}
    )
    effect = result.structured_content["effect"]
    assert "REPLACE every rule" in effect
    assert "is deleted and stops detecting" in effect
    assert route.call_count == 0


async def test_update_waf_sensor_confirmed_sends_config_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{WAF_SENSOR_PATH}/{WAF_SENSOR}").respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_waf_sensor",
        {"sensor_name": WAF_SENSOR, "rules": [WAF_RULE], "comment": "updated"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": WAF_SENSOR,
            "comment": "updated",
            "rules": [
                {
                    "name": "rule.jsonrpc",
                    "patterns": [
                        {
                            "key": "pattern",
                            "op": "regex",
                            "value": "\\$\\{jndi:",
                            "context": "header",
                        }
                    ],
                }
            ],
        }
    }


# -- nv_delete_waf_sensor -------------------------------------------------------


async def test_delete_waf_sensor_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(f"{WAF_SENSOR_PATH}/{WAF_SENSOR}").respond(200, json={})
    result = await client.call_tool("nv_delete_waf_sensor", {"sensor_name": WAF_SENSOR})
    assert result.structured_content["status"] == "confirmation_required"
    assert "silently" in result.structured_content["effect"]
    assert route.call_count == 0


async def test_delete_waf_sensor_confirmed_calls_delete(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(f"{WAF_SENSOR_PATH}/{WAF_SENSOR}").respond(200, json={})
    result = await _confirmed(client, "nv_delete_waf_sensor", {"sensor_name": WAF_SENSOR})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"


# -- nv_set_waf_group -----------------------------------------------------------


async def test_set_waf_group_preview_warns_about_replace_and_protect(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{WAF_GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    result = await client.call_tool(
        "nv_set_waf_group",
        {"group_name": LEARNED_GROUP, "sensors": [{"name": WAF_SENSOR, "action": "deny"}]},
    )
    effect = result.structured_content["effect"]
    assert "REPLACE" in effect
    assert "is unbound and stops inspecting" in effect
    assert "will DENY matching requests if the group is moved to Protect" in effect
    assert route.call_count == 0


async def test_set_waf_group_confirmed_sends_replace_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{WAF_GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    result = await _confirmed(
        client,
        "nv_set_waf_group",
        {"group_name": LEARNED_GROUP, "sensors": [{"name": WAF_SENSOR, "action": "deny"}]},
    )

    assert result.structured_content["status"] == "applied"
    # 'replace' takes {name, action} objects. The sibling 'delete' key takes bare
    # name strings; sending objects there returns code 6.
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": LEARNED_GROUP,
            "status": True,
            "replace": [{"name": WAF_SENSOR, "action": "deny"}],
        }
    }


async def test_set_waf_group_empty_list_unbinds_everything(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{WAF_GROUP_PATH}/{LEARNED_GROUP}").respond(200, json={})
    await _confirmed(client, "nv_set_waf_group", {"group_name": LEARNED_GROUP, "sensors": []})
    assert json.loads(route.calls.last.request.read())["config"]["replace"] == []


async def test_set_waf_group_respects_allowed_namespaces(nv_mock: respx.MockRouter) -> None:
    # LEARNED_GROUP is nv.api.prod, so the namespace is 'prod'.
    server = build_server(make_settings(allowed_namespaces=("staging",)))
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool(
                "nv_set_waf_group",
                {"group_name": LEARNED_GROUP, "sensors": []},
            )
    assert "prod" in str(excinfo.value)


# -- registration ---------------------------------------------------------------


async def test_policy_write_tools_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}
    assert "nv_get_system_summary" in names
    for tool in (
        "nv_create_group",
        "nv_update_group_criteria",
        "nv_apply_network_rule_changes",
        "nv_delete_network_rule",
        "nv_update_process_profile",
        "nv_update_file_monitor_profile",
        "nv_create_waf_sensor",
        "nv_update_waf_sensor",
        "nv_delete_waf_sensor",
        "nv_set_waf_group",
    ):
        assert tool not in names, f"{tool} must be hidden when NV_READ_ONLY=true"
