"""response_write toolset contract tests.

Response rules automate quarantine and webhook notification, so the two things
these tests defend are (a) a preview must send NOTHING, asserted with
``route.call_count == 0``, and (b) the confirmed call's exact JSON body, spelled
out in full - the controller answers 200 and silently drops fields it does not
recognise, so only a byte-level body assertion proves the wire shape.

The webhook tests additionally pin the secret-handling contract: the real URL
reaches the controller, and only a host-plus-digest form ever reaches the model.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
import respx

from neuvector_mcp.guard import confirm_token

pytestmark = pytest.mark.asyncio

RULE_BATCH_PATH = "/v1/response/rule"
RULE_PATH = "/v1/response/rule/42"
OPTIONS_PATH = "/v1/response/options"
WEBHOOK_PATH = "/v1/system/config/webhook"
WEBHOOK_NAME = "soc-slack"
WEBHOOK_NAME_PATH = f"/v1/system/config/webhook/{WEBHOOK_NAME}"

#: A Slack incoming-webhook URL: the token is in the PATH, which is exactly the
#: case the redaction exists for.
SLACK_URL = "https://hooks.slack.com/services/T00000000/B00000000/s3cr3ttoken"
SLACK_HOST_FORM = "https://hooks.slack.com/***"
SLACK_DIGEST = hashlib.sha256(SLACK_URL.encode()).hexdigest()[:12]
SLACK_SAFE = f"{SLACK_HOST_FORM} (sha256:{SLACK_DIGEST})"

NEW_RULE: dict[str, Any] = {
    "event": "security-event",
    "group": "nv.api.prod",
    "actions": ["webhook"],
    "webhooks": [WEBHOOK_NAME],
    "conditions": [{"type": "name", "value": "Log4Shell"}],
    "comment": "page the SOC on Log4Shell",
}

RULE_WIRE: dict[str, Any] = {
    "event": "security-event",
    "comment": "page the SOC on Log4Shell",
    "group": "nv.api.prod",
    "conditions": [{"type": "name", "value": "Log4Shell"}],
    "actions": ["webhook"],
    "webhooks": [WEBHOOK_NAME],
    "disable": False,
    "cfg_type": "user_created",
}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- nv_get_response_rule_options -----------------------------------------------


async def test_get_response_rule_options_projects_vocabulary(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(OPTIONS_PATH).respond(
        200,
        json={
            "response_rule_options": {
                "security-event": {
                    "types": ["name", "severity"],
                    "name": ["Log4Shell"],
                    "level": ["Critical", "High"],
                    "disabled_props": {"quarantine": ["host"]},
                },
                "incident": {"types": ["name"]},
            },
            "webhooks": [WEBHOOK_NAME, "pager"],
        },
    )
    result = await client.call_tool("nv_get_response_rule_options", {})
    body = result.structured_content

    assert body["events"] == ["incident", "security-event"]
    assert body["webhooks"] == [WEBHOOK_NAME, "pager"]
    security = body["options"]["security-event"]
    assert security["types"] == ["name", "severity"]
    assert security["names"] == ["Log4Shell"]
    assert security["levels"] == ["Critical", "High"]
    assert security["disabled_properties"] == {"quarantine": ["host"]}
    assert body["options"]["incident"]["levels"] == []


# -- nv_apply_response_rule_changes ---------------------------------------------


async def test_apply_response_rule_changes_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_apply_response_rule_changes",
        {"insert_rules": [NEW_RULE], "insert_after_rule_id": 0},
    )
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "+ INSERT on security-event for group=nv.api.prod" in body["effect"]
    assert "conditions=[name=Log4Shell]" in body["effect"]
    assert "placed FIRST in the rule list (after=0)" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_apply_response_rule_changes_confirmed_sends_insert_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_apply_response_rule_changes",
        {"insert_rules": [NEW_RULE], "insert_after_rule_id": 7},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "PATCH"
    assert json.loads(route.calls.last.request.read()) == {
        "insert": {"rules": [RULE_WIRE], "after": 7}
    }


async def test_apply_response_rule_changes_omits_after_when_not_given(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    await _confirmed(client, "nv_apply_response_rule_changes", {"insert_rules": [NEW_RULE]})

    sent = json.loads(route.calls.last.request.read())
    assert "after" not in sent["insert"], "an absent position must not be sent as null"


async def test_apply_response_rule_changes_token_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    stale = confirm_token(
        "nv_apply_response_rule_changes",
        "response rules",
        {"insert": {"rules": [RULE_WIRE]}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_apply_response_rule_changes",
            {"insert_rules": [NEW_RULE], "insert_after_rule_id": 0, "confirm": stale},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted without a position must not apply with one"


async def test_apply_response_rule_changes_rejects_empty_batch(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_apply_response_rule_changes", {"insert_rules": []})
    assert "at least one entry" in str(excinfo.value)
    assert route.call_count == 0


async def test_apply_response_rule_changes_rejects_oversized_batch(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_apply_response_rule_changes", {"insert_rules": [NEW_RULE] * 17})
    assert "hard cap" in str(excinfo.value)
    assert route.call_count == 0


async def test_apply_response_rule_changes_rejects_blank_webhook_name(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_BATCH_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_apply_response_rule_changes",
            {"insert_rules": [{**NEW_RULE, "webhooks": [""]}]},
        )
    assert "webhook NAMES" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_update_response_rule ----------------------------------------------------


async def test_update_response_rule_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    result = await client.call_tool("nv_update_response_rule", {"rule_id": 42, "disable": True})
    assert result.structured_content["status"] == "confirmation_required"
    assert "rule DISABLED" in result.structured_content["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_response_rule_omits_absent_fields(client, nv_mock: respx.MockRouter) -> None:
    """Pointer+omitempty fields must be ABSENT, never null: absence means 'unchanged'."""
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_response_rule",
        {"rule_id": 42, "webhooks": ["pager"], "disable": True},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "id": 42,
            "cfg_type": "user_created",
            "webhooks": ["pager"],
            "disable": True,
        }
    }


async def test_update_response_rule_sends_every_given_field(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    await _confirmed(
        client,
        "nv_update_response_rule",
        {
            "rule_id": 42,
            "event": "incident",
            "group": "",
            "actions": ["quarantine"],
            "webhooks": [],
            "conditions": [{"type": "name", "value": "reverse-shell"}],
            "comment": "contain reverse shells",
            "disable": False,
        },
    )
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "id": 42,
            "cfg_type": "user_created",
            "comment": "contain reverse shells",
            "group": "",
            "event": "incident",
            "conditions": [{"type": "name", "value": "reverse-shell"}],
            "actions": ["quarantine"],
            "webhooks": [],
            "disable": False,
        }
    }


async def test_update_response_rule_rejects_empty_change_set(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_response_rule", {"rule_id": 42})
    assert "nothing to change" in str(excinfo.value)
    assert route.call_count == 0


async def test_update_response_rule_rejects_unknown_condition_key(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_response_rule",
            {"rule_id": 42, "conditions": [{"type": "name", "op": "="}]},
        )
    assert "unknown key" in str(excinfo.value)
    assert route.call_count == 0


async def test_update_response_rule_token_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(RULE_PATH).respond(200, json={})
    stale = confirm_token(
        "nv_update_response_rule",
        "response rule 42",
        {"config": {"id": 42, "cfg_type": "user_created", "disable": True}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_response_rule", {"rule_id": 42, "disable": False, "confirm": stale}
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_delete_response_rule ----------------------------------------------------


async def test_delete_response_rule_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(RULE_PATH).respond(200, json={})
    result = await client.call_tool("nv_delete_response_rule", {"rule_id": 42})
    assert result.structured_content["status"] == "confirmation_required"
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_response_rule_confirmed_calls_route(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(RULE_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_response_rule", {"rule_id": 42})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.read() == b""


async def test_delete_response_rule_token_bound_to_rule_id(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(RULE_PATH).respond(200, json={})
    stale = confirm_token("nv_delete_response_rule", "response rule 7", None)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_delete_response_rule", {"rule_id": 42, "confirm": stale})
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted for rule 7 must not delete rule 42"


# -- nv_delete_all_response_rules -----------------------------------------------


async def test_delete_all_response_rules_preview_warns_and_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(RULE_BATCH_PATH).respond(200, json={})
    result = await client.call_tool("nv_delete_all_response_rules", {})
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert body["target"] == "all response rules (scope=local)"
    assert "automated response" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_all_response_rules_sends_scope_param(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(RULE_BATCH_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_all_response_rules", {"scope": "fed"})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.url.params["scope"] == "fed"


async def test_delete_all_response_rules_token_bound_to_scope(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(RULE_BATCH_PATH).respond(200, json={})
    local_token = confirm_token(
        "nv_delete_all_response_rules", "all response rules (scope=local)", None
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_all_response_rules", {"scope": "fed", "confirm": local_token}
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "a token minted for local must not wipe fed"


# -- nv_create_webhook ----------------------------------------------------------


async def test_create_webhook_preview_never_echoes_the_url(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(WEBHOOK_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_webhook",
        {"name": WEBHOOK_NAME, "url": SLACK_URL, "webhook_type": "Slack"},
    )
    body = result.structured_content
    rendered = json.dumps(body)

    assert body["status"] == "confirmation_required"
    assert "s3cr3ttoken" not in rendered, "the webhook token must never reach the model"
    assert "T00000000" not in rendered, "the URL path must never reach the model"
    assert body["payload"]["config"]["url"] == SLACK_SAFE
    assert "hooks.slack.com" in body["effect"], "the reviewer must still see the destination"
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_webhook_confirmed_sends_the_real_url(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(WEBHOOK_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_create_webhook",
        {"name": WEBHOOK_NAME, "url": SLACK_URL, "webhook_type": "Slack"},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": WEBHOOK_NAME,
            "url": SLACK_URL,
            "enable": True,
            "use_proxy": False,
            "type": "Slack",
            "cfg_type": "user_created",
        }
    }
    assert "s3cr3ttoken" not in json.dumps(result.structured_content)


async def test_create_webhook_token_is_bound_to_the_full_url(
    client, nv_mock: respx.MockRouter
) -> None:
    """Same host, different path: the digest must invalidate the token."""
    route = nv_mock.post(WEBHOOK_PATH).respond(200, json={})
    plan = await client.call_tool(
        "nv_create_webhook", {"name": WEBHOOK_NAME, "url": SLACK_URL, "webhook_type": "Slack"}
    )
    token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_webhook",
            {
                "name": WEBHOOK_NAME,
                "url": "https://hooks.slack.com/services/T00000000/B00000000/otherToken",
                "webhook_type": "Slack",
                "confirm": token,
            },
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_create_webhook_rejects_non_http_url(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(WEBHOOK_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_webhook", {"name": WEBHOOK_NAME, "url": "file:///etc/passwd"}
        )
    message = str(excinfo.value)
    assert "http://" in message
    assert "Nothing was sent to the controller" in message
    assert route.call_count == 0


async def test_create_webhook_rejects_url_without_host(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(WEBHOOK_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_create_webhook", {"name": WEBHOOK_NAME, "url": "https:///x"})
    assert "no host" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_update_webhook ----------------------------------------------------------


async def test_update_webhook_sends_whole_object_and_scope(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(WEBHOOK_NAME_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_webhook",
        {
            "name": WEBHOOK_NAME,
            "url": SLACK_URL,
            "webhook_type": "Slack",
            "enable": False,
            "use_proxy": True,
            "scope": "fed",
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.url.params["scope"] == "fed"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "name": WEBHOOK_NAME,
            "url": SLACK_URL,
            "enable": False,
            "use_proxy": True,
            "type": "Slack",
            "cfg_type": "federal",
        }
    }


async def test_update_webhook_preview_sends_nothing_and_hides_the_token(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(WEBHOOK_NAME_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_webhook", {"name": WEBHOOK_NAME, "url": SLACK_URL, "webhook_type": "Slack"}
    )
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert body["payload"]["config"]["url"] == SLACK_SAFE
    assert "s3cr3ttoken" not in json.dumps(body)
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_update_webhook_rejects_blank_url(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(WEBHOOK_NAME_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_webhook", {"name": WEBHOOK_NAME, "url": "  "})
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_delete_webhook ----------------------------------------------------------


async def test_delete_webhook_preview_warns_about_dangling_rules(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(WEBHOOK_NAME_PATH).respond(200, json={})
    result = await client.call_tool("nv_delete_webhook", {"name": WEBHOOK_NAME})
    body = result.structured_content

    assert body["status"] == "confirmation_required"
    assert "silently stops arriving" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_delete_webhook_confirmed_sends_scope(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(WEBHOOK_NAME_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_webhook", {"name": WEBHOOK_NAME, "scope": "fed"})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert route.calls.last.request.url.params["scope"] == "fed"


async def test_delete_webhook_token_bound_to_name(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(WEBHOOK_NAME_PATH).respond(200, json={})
    stale = confirm_token("nv_delete_webhook", "other-hook", None)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_delete_webhook", {"name": WEBHOOK_NAME, "confirm": stale})
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_delete_webhook_redacts_url_in_controller_response(
    client, nv_mock: respx.MockRouter
) -> None:
    """Even an unexpected echo of the URL must not reach the model."""
    route = nv_mock.delete(WEBHOOK_NAME_PATH).respond(
        200, json={"config": {"name": WEBHOOK_NAME, "url": SLACK_URL}}
    )
    result = await _confirmed(client, "nv_delete_webhook", {"name": WEBHOOK_NAME})

    assert route.call_count == 1
    assert result.structured_content["controller_response"]["config"]["url"] == SLACK_SAFE
    assert "s3cr3ttoken" not in json.dumps(result.structured_content)
