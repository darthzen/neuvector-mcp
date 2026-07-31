"""ruleset_ops contract tests: single-rule PATCH and the two whole-ruleset deletes.

Two things are asserted harder here than anywhere else. First, that a preview
sends NOTHING - ``route.call_count == 0`` - because the tools under test empty
the network rule list and switch off deployment gating. Second, that
``nv_update_network_rule`` OMITS the fields the caller did not supply: the
controller reads an absent key as "not modified" (apis.go RESTPolicyRuleConfig),
so a key that leaks into the body with a default value silently overwrites
production configuration.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from neuvector_mcp.guard import confirm_token

pytestmark = pytest.mark.asyncio

RULE_ID = 42
RULE_PATH = f"/v1/policy/rule/{RULE_ID}"
ALL_RULES_PATH = "/v1/policy/rule"
ALL_ADMISSION_RULES_PATH = "/v1/admission/rules"


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- nv_update_network_rule -----------------------------------------------------


async def test_update_network_rule_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_network_rule", {"rule_id": RULE_ID, "action": "deny"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "action='deny'" in body["effect"]
    assert "Protect mode DROPS" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_network_rule_confirmed_sends_only_supplied_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_network_rule",
        {"rule_id": RULE_ID, "action": "deny", "comment": "blocked after incident 4412"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "id": 42,
            "cfg_type": "user_created",
            "comment": "blocked after incident 4412",
            "action": "deny",
        }
    }


async def test_update_network_rule_omits_untouched_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    """An unsupplied field must be ABSENT, not null and not a default value.

    apis.go RESTPolicyRuleConfig declares every optional field as a pointer with
    omitempty and documents "Omit fields indicate that it's not modified", so a
    key present with any value is an instruction to overwrite.
    """
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    await _confirmed(client, "nv_update_network_rule", {"rule_id": RULE_ID, "disable": True})

    config = json.loads(route.calls.last.request.read())["config"]
    assert config == {"id": 42, "cfg_type": "user_created", "disable": True}
    for absent in ("from", "to", "ports", "action", "applications", "comment"):
        assert absent not in config, f"{absent} would overwrite the current rule"


async def test_update_network_rule_sends_all_fields_when_all_supplied(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_network_rule",
        {
            "rule_id": RULE_ID,
            "from_group": "custom.web",
            "to_group": "custom.db",
            "action": "allow",
            "ports": "tcp/5432",
            "applications": ["PostgreSQL"],
            "comment": "web to db",
            "disable": False,
        },
    )
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "id": 42,
            "cfg_type": "user_created",
            "comment": "web to db",
            "from": "custom.web",
            "to": "custom.db",
            "ports": "tcp/5432",
            "action": "allow",
            "applications": ["PostgreSQL"],
            "disable": False,
        }
    }


async def test_update_network_rule_empty_applications_is_sent_not_dropped(
    client, nv_mock: respx.MockRouter
) -> None:
    """[] means "any application" and must reach the controller; only None omits."""
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    await _confirmed(client, "nv_update_network_rule", {"rule_id": RULE_ID, "applications": []})
    config = json.loads(route.calls.last.request.read())["config"]
    assert config["applications"] == []


async def test_update_network_rule_rejects_no_change(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_network_rule", {"rule_id": RULE_ID})
    assert "no field to change" in str(excinfo.value)
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_update_network_rule_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    allow_token = confirm_token(
        "nv_update_network_rule",
        f"network policy rule {RULE_ID}",
        {"config": {"id": RULE_ID, "cfg_type": "user_created", "action": "allow"}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_network_rule",
            {"rule_id": RULE_ID, "action": "deny", "confirm": allow_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted for allow must not apply deny"


# -- nv_delete_all_network_rules ------------------------------------------------


async def test_delete_all_network_rules_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_delete_all_network_rules", {"expected_rule_count": 137, "scope": "local"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    effect = body["effect"]
    assert "ALL 137 network policy rules" in effect, "the plan must say how many rules die"
    assert "not verified against the controller" in effect
    assert "Protect mode" in effect and "DROPS" in effect
    assert "no undo" in effect
    assert "THIS cluster's own rules" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_all_network_rules_fed_scope_effect_names_every_member(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_delete_all_network_rules", {"expected_rule_count": 4, "scope": "fed"}
    )
    effect = result.structured_content["effect"]
    assert "FEDERATED rules" in effect
    assert "every member cluster" in effect


async def test_delete_all_network_rules_confirmed_sends_scope_and_no_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_all_network_rules", {"expected_rule_count": 137})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.url.params["scope"] == "local"
    assert route.calls.last.request.read() == b"", "this endpoint takes no body"


async def test_delete_all_network_rules_fed_scope_sends_fed_param(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    await _confirmed(
        client, "nv_delete_all_network_rules", {"expected_rule_count": 4, "scope": "fed"}
    )
    assert route.calls.last.request.url.params["scope"] == "fed"


async def test_delete_all_network_rules_token_is_bound_to_scope(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    local_token = confirm_token(
        "nv_delete_all_network_rules",
        "all network policy rules in scope 'local' (caller asserts 4 rule(s))",
        None,
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_all_network_rules",
            {"expected_rule_count": 4, "scope": "fed", "confirm": local_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted for local must not wipe fed"


async def test_delete_all_network_rules_token_is_bound_to_expected_count(
    client, nv_mock: respx.MockRouter
) -> None:
    """A re-read that returns a different count must force a fresh plan."""
    route = nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    plan = await client.call_tool(
        "nv_delete_all_network_rules", {"expected_rule_count": 137, "scope": "local"}
    )
    stale = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_all_network_rules",
            {"expected_rule_count": 138, "scope": "local", "confirm": stale},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_delete_all_network_rules_rejects_negative_count(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_RULES_PATH).respond(200, json={})
    with pytest.raises(Exception, match="greater than or equal to 0"):
        await client.call_tool("nv_delete_all_network_rules", {"expected_rule_count": -1})
    assert route.call_count == 0


# -- nv_delete_all_admission_rules ----------------------------------------------


async def test_delete_all_admission_rules_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_ADMISSION_RULES_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_delete_all_admission_rules", {"expected_rule_count": 12, "scope": "local"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    effect = body["effect"]
    assert "ALL 12 admission control rules" in effect, "the plan must say how many rules die"
    assert "not verified against the controller" in effect
    assert "STOPS GATING DEPLOYMENTS entirely and immediately" in effect
    assert "critical vulnerabilities" in effect
    assert "no undo" in effect
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_all_admission_rules_effect_warns_state_still_reports_enabled(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.delete(ALL_ADMISSION_RULES_PATH).respond(200, json={})
    result = await client.call_tool("nv_delete_all_admission_rules", {"expected_rule_count": 12})
    assert "nv_get_admission_state" in result.structured_content["effect"]


async def test_delete_all_admission_rules_confirmed_sends_scope_and_no_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_ADMISSION_RULES_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_all_admission_rules", {"expected_rule_count": 12})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.url.params["scope"] == "local"
    assert route.calls.last.request.read() == b"", "this endpoint takes no body"


async def test_delete_all_admission_rules_fed_scope_sends_fed_param(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_ADMISSION_RULES_PATH).respond(200, json={})
    await _confirmed(
        client, "nv_delete_all_admission_rules", {"expected_rule_count": 3, "scope": "fed"}
    )
    assert route.calls.last.request.url.params["scope"] == "fed"


async def test_delete_all_admission_rules_token_is_bound_to_scope(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ALL_ADMISSION_RULES_PATH).respond(200, json={})
    local_token = confirm_token(
        "nv_delete_all_admission_rules",
        "all admission control rules in scope 'local' (caller asserts 3 rule(s))",
        None,
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_all_admission_rules",
            {"expected_rule_count": 3, "scope": "fed", "confirm": local_token},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted for local must not wipe fed"
