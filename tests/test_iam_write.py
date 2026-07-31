"""Contract tests for the ``iam_write`` toolset (5 mutating tools).

Every tool is checked twice, per SPEC 10.2: a preview call that must send NOTHING
to the controller, and a confirmed call whose exact JSON body is asserted.

The module also carries the credential tests, because these are the two tools
that touch a secret: ``nv_create_user`` sends a password and ``nv_create_api_key``
receives one that the controller shows exactly once.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
import respx
from fastmcp import Client

from conftest import fixture, make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

#: A password that never leaves this file, so any appearance of it in a result,
#: a plan or a log stream is unambiguous evidence of a leak.
PASSWORD = "n0t-a-real-p4ssword"

USER_PATH = "/v1/user"
ROLE_PATH = "/v1/user/alice/role/admin"
#: nv_update_user_role folds the role into the guard's target, because the role
#: travels in the URL path and would otherwise never reach the confirm token.
GUARD_TARGET = "alice role=admin"
DELETE_USER_PATH = "/v1/user/alice"
API_KEY_PATH = "/v1/api_key"
DELETE_API_KEY_PATH = "/v1/api_key/ci-bot"

CREATE_USER_ARGS: dict[str, Any] = {
    "username": "alice",
    "password": PASSWORD,
    "role": "admin",
    "email": "alice@example.test",
}
#: The body ``nv_create_user`` must put on the wire: the REAL password.
CREATE_USER_WIRE_BODY = {
    "user": {
        "fullname": "alice",
        "username": "alice",
        "password": PASSWORD,
        "email": "alice@example.test",
        "role": "admin",
    }
}
#: The same body as the caller must see it: the password masked.
CREATE_USER_SAFE_BODY = {
    "user": {**CREATE_USER_WIRE_BODY["user"], "password": "***"},
}

CREATE_API_KEY_ARGS: dict[str, Any] = {
    "apikey_name": "ci-bot",
    "role": "reader",
    "expiration_type": "hours",
    "expiration_hours": 24,
    "description": "CI pipeline image scans",
}
CREATE_API_KEY_BODY = {
    "apikey": {
        "apikey_name": "ci-bot",
        "role": "reader",
        "expiration_type": "hours",
        "description": "CI pipeline image scans",
        "expiration_hours": 24,
    }
}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake and return the applied result."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


@asynccontextmanager
async def logging_client(sink: io.StringIO) -> AsyncIterator[Any]:
    """A client whose server logs at DEBUG into ``sink``, so 'not logged' means something.

    The audit middleware emits at INFO, so the default WARNING-level test server
    writes nothing at all and every "the secret is absent" assertion would pass
    for the wrong reason. Raising the level is only half of it: ``configure_logging``
    binds ``structlog.PrintLoggerFactory`` to whatever ``sys.stderr`` is at the
    moment ``build_server`` runs, and that binding survives pytest's later
    file-descriptor juggling - which is why ``capfd`` came back empty even though
    the record was demonstrably written. Swapping ``sys.stderr`` for a StringIO
    BEFORE ``build_server`` puts the audit stream somewhere this test owns
    outright, with no fd games.
    """
    real_stderr = sys.stderr
    sys.stderr = sink
    try:
        server = build_server(make_settings(log_level="DEBUG"))
        async with Client(server) as c:
            yield c
    finally:
        sys.stderr = real_stderr


# --------------------------------------------------------------------------
# nv_create_user
# --------------------------------------------------------------------------


async def test_create_user_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(USER_PATH).respond(200, json={})
    body = (await client.call_tool("nv_create_user", CREATE_USER_ARGS)).structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_user_preview_payload_masks_password(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(USER_PATH).respond(200, json={})
    body = (await client.call_tool("nv_create_user", CREATE_USER_ARGS)).structured_content

    assert body["payload"] == CREATE_USER_SAFE_BODY
    assert body["payload"]["user"]["password"] == "***"
    assert PASSWORD not in json.dumps(body)


async def test_create_user_confirmed_sends_real_password(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(USER_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_create_user", CREATE_USER_ARGS)

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == CREATE_USER_WIRE_BODY
    # ...while the caller still only ever sees the redacted copy.
    assert result.structured_content["payload"] == CREATE_USER_SAFE_BODY
    assert PASSWORD not in json.dumps(result.structured_content)


async def test_create_user_role_domains_are_sorted_into_the_payload(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(USER_PATH).respond(200, json={})
    args = {**CREATE_USER_ARGS, "role_domains": {"admin": ["staging", "prod"]}}
    await _confirmed(client, "nv_create_user", args)

    sent = json.loads(route.calls.last.request.read())
    assert sent["user"]["role_domains"] == {"admin": ["prod", "staging"]}


async def test_create_user_token_matches_between_preview_and_apply(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(USER_PATH).respond(200, json={})
    plan = await client.call_tool("nv_create_user", CREATE_USER_ARGS)

    # The guard hashes the REDACTED payload, so the token is reproducible from
    # the arguments without ever handling the password value.
    assert plan.structured_content["confirm_token"] == confirm_token(
        "nv_create_user", "alice", CREATE_USER_SAFE_BODY
    )


async def test_create_user_token_bound_to_role(client, nv_mock: respx.MockRouter) -> None:
    """Token binding: a token issued for one role does not authorise another."""
    route = nv_mock.post(USER_PATH).respond(200, json={})
    reader_token = confirm_token(
        "nv_create_user",
        "alice",
        {"user": {**CREATE_USER_SAFE_BODY["user"], "role": "reader"}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_create_user", {**CREATE_USER_ARGS, "confirm": reader_token})

    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_create_user_token_survives_a_password_change(
    client, nv_mock: respx.MockRouter
) -> None:
    """Documented consequence of hashing the redacted payload (Part D D.0.4).

    Changing only the password does NOT invalidate the token; changing any other
    field does. This is the accepted cost of never echoing the credential back.
    """
    nv_mock.post(USER_PATH).respond(200, json={})
    plan = await client.call_tool("nv_create_user", CREATE_USER_ARGS)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool(
        "nv_create_user",
        {**CREATE_USER_ARGS, "password": "a-completely-different-one", "confirm": token},
    )
    assert result.structured_content["status"] == "applied"


async def test_create_user_password_not_logged(nv_mock: respx.MockRouter, capfd) -> None:
    route = nv_mock.post(USER_PATH).respond(200, json={})
    sink = io.StringIO()
    async with logging_client(sink) as c:
        result = await _confirmed(c, "nv_create_user", CREATE_USER_ARGS)

    assert result.structured_content["payload"]["user"]["password"] == "***"
    assert PASSWORD not in json.dumps(result.structured_content)
    assert json.loads(route.calls.last.request.read())["user"]["password"] == PASSWORD

    logs = sink.getvalue()
    assert "tool.call" in logs, "audit logging must actually be running for this test"
    assert "nv_create_user" in logs
    # Key NAMES are expected in the audit record; values never are.
    assert "password" in logs
    assert PASSWORD not in logs
    # Belt and braces: nothing escaped to the real stdout/stderr either, which
    # also guards the stdio transport (a byte on stdout corrupts the session).
    out, err = capfd.readouterr()
    assert PASSWORD not in out and PASSWORD not in err


# --------------------------------------------------------------------------
# nv_update_user_role
# --------------------------------------------------------------------------


async def test_update_user_role_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(ROLE_PATH).respond(200, json={})
    body = (
        await client.call_tool("nv_update_user_role", {"fullname": "alice", "role": "admin"})
    ).structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "clearing any namespace roles" in body["effect"]
    # The role is in the URL path, so it is folded into the guard's target to
    # make the token bind to it. The plan names it in both places.
    assert body["target"] == GUARD_TARGET
    assert "'admin'" in body["effect"]
    assert route.call_count == 0


async def test_update_user_role_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(ROLE_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_update_user_role", {"fullname": "alice", "role": "admin"})

    assert result.structured_content["status"] == "applied"
    assert result.structured_content["target"] == "alice"
    assert route.call_count == 1
    assert route.calls.last.request.url.path == ROLE_PATH
    assert json.loads(route.calls.last.request.read()) == {
        "config": {"name": "alice", "role_domains": {}}
    }


async def test_update_user_role_token_bound_to_role(client, nv_mock: respx.MockRouter) -> None:
    """A token previewed for one role must not authorise a different one.

    The global role travels in the PATH, not in the payload, so the guard folds it
    into 'target' - otherwise confirm_token(), which hashes operation, target and
    payload only, would never see it and an operator who approved 'reader' would
    be silently granting 'admin'.
    """
    route = nv_mock.patch(ROLE_PATH).respond(200, json={})
    plan = await client.call_tool("nv_update_user_role", {"fullname": "alice", "role": "reader"})
    reader_token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_user_role",
            {"fullname": "alice", "role": "admin", "confirm": reader_token},
        )

    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0, "an escalated role must never reach the controller"


async def test_update_user_role_token_bound_to_role_domains(
    client, nv_mock: respx.MockRouter
) -> None:
    """The token also covers 'role_domains', the other half of the assignment."""
    route = nv_mock.patch(ROLE_PATH).respond(200, json={})
    staging_token = confirm_token(
        "nv_update_user_role",
        GUARD_TARGET,
        {"config": {"name": "alice", "role_domains": {"admin": ["staging"]}}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_user_role",
            {
                "fullname": "alice",
                "role": "admin",
                "role_domains": {"admin": ["prod"]},
                "confirm": staging_token,
            },
        )

    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


# --------------------------------------------------------------------------
# nv_delete_user
# --------------------------------------------------------------------------


async def test_delete_user_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(DELETE_USER_PATH).respond(200, json={})
    body = (await client.call_tool("nv_delete_user", {"fullname": "alice"})).structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "API keys" in body["effect"]
    assert route.call_count == 0


async def test_delete_user_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(DELETE_USER_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_user", {"fullname": "alice"})

    assert result.structured_content["status"] == "applied"
    assert result.structured_content["effect"] == "user alice deleted"
    assert route.call_count == 1
    assert route.calls.last.request.url.path == DELETE_USER_PATH
    assert not route.calls.last.request.read()


# --------------------------------------------------------------------------
# nv_create_api_key
# --------------------------------------------------------------------------


async def test_create_api_key_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(API_KEY_PATH).respond(200, json=fixture("api_key_generated"))
    body = (await client.call_tool("nv_create_api_key", CREATE_API_KEY_ARGS)).structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert body["payload"] == CREATE_API_KEY_BODY
    assert route.call_count == 0, "no key may be minted by a preview"


async def test_create_api_key_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(API_KEY_PATH).respond(200, json=fixture("api_key_generated"))
    result = await _confirmed(client, "nv_create_api_key", CREATE_API_KEY_ARGS)

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == CREATE_API_KEY_BODY
    # The request carries no credential of its own: the controller mints one.
    assert "apikey_secret" not in json.dumps(CREATE_API_KEY_BODY)


async def test_create_api_key_returns_secret_to_caller(client, nv_mock: respx.MockRouter) -> None:
    """The one sanctioned place a secret appears in a result (Part D D.0.4)."""
    generated = fixture("api_key_generated")
    nv_mock.post(API_KEY_PATH).respond(200, json=generated)
    result = await _confirmed(client, "nv_create_api_key", CREATE_API_KEY_ARGS)

    body = result.structured_content
    assert (
        body["controller_response"]["apikey"]["apikey_secret"]
        == generated["apikey"]["apikey_secret"]
    )
    assert "secret returned once" in body["effect"]


async def test_create_api_key_secret_absent_from_the_plan(
    client, nv_mock: respx.MockRouter
) -> None:
    """The secret must not exist yet at preview time, so it cannot be in the plan."""
    generated = fixture("api_key_generated")
    nv_mock.post(API_KEY_PATH).respond(200, json=generated)
    plan = await client.call_tool("nv_create_api_key", CREATE_API_KEY_ARGS)

    assert generated["apikey"]["apikey_secret"] not in json.dumps(plan.structured_content)


async def test_create_api_key_secret_not_logged(nv_mock: respx.MockRouter, capfd) -> None:
    generated = fixture("api_key_generated")
    secret = generated["apikey"]["apikey_secret"]
    nv_mock.post(API_KEY_PATH).respond(200, json=generated)
    sink = io.StringIO()
    async with logging_client(sink) as c:
        result = await _confirmed(c, "nv_create_api_key", CREATE_API_KEY_ARGS)

    assert result.structured_content["controller_response"]["apikey"]["apikey_secret"] == secret

    logs = sink.getvalue()
    assert "tool.call" in logs, "audit logging must actually be running for this test"
    assert "nv_create_api_key" in logs
    # The secret is returned to the caller on purpose; it is still never logged.
    assert secret not in logs
    out, err = capfd.readouterr()
    assert secret not in out and secret not in err


# --------------------------------------------------------------------------
# nv_delete_api_key
# --------------------------------------------------------------------------


async def test_delete_api_key_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(DELETE_API_KEY_PATH).respond(200, json={})
    body = (
        await client.call_tool("nv_delete_api_key", {"access_key": "ci-bot"})
    ).structured_content

    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "failing authentication" in body["effect"]
    assert route.call_count == 0


async def test_delete_api_key_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(DELETE_API_KEY_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_api_key", {"access_key": "ci-bot"})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.url.path == DELETE_API_KEY_PATH
    assert not route.calls.last.request.read()


# --------------------------------------------------------------------------
# module-wide contracts
# --------------------------------------------------------------------------


async def test_no_credential_value_leaks_into_plan_or_outcome(
    client, nv_mock: respx.MockRouter
) -> None:
    """N8, end to end: neither credential reaches the model except the one that must.

    The submitted password is invisible in both the plan and the applied outcome.
    The generated API key secret is invisible in the plan and appears in the
    applied outcome ONLY under controller_response.apikey.apikey_secret.
    """
    nv_mock.post(USER_PATH).respond(200, json={"user": {"password": PASSWORD}})
    generated = fixture("api_key_generated")
    secret = generated["apikey"]["apikey_secret"]
    nv_mock.post(API_KEY_PATH).respond(200, json=generated)

    user_plan = await client.call_tool("nv_create_user", CREATE_USER_ARGS)
    user_applied = await _confirmed(client, "nv_create_user", CREATE_USER_ARGS)
    assert PASSWORD not in json.dumps(user_plan.structured_content)
    assert PASSWORD not in json.dumps(user_applied.structured_content)
    # Even a controller that echoes the password back is masked on the way out.
    assert user_applied.structured_content["controller_response"] == {"user": {"password": "***"}}

    key_plan = await client.call_tool("nv_create_api_key", CREATE_API_KEY_ARGS)
    key_applied = await _confirmed(client, "nv_create_api_key", CREATE_API_KEY_ARGS)
    assert secret not in json.dumps(key_plan.structured_content)
    outcome = key_applied.structured_content
    assert secret not in json.dumps(outcome["payload"])
    assert secret not in outcome["effect"]
    assert outcome["controller_response"]["apikey"]["apikey_secret"] == secret


async def test_iam_write_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}

    assert "nv_get_system_summary" in names, "read tools must survive read-only mode"
    for tool in (
        "nv_create_user",
        "nv_update_user_role",
        "nv_delete_user",
        "nv_create_api_key",
        "nv_delete_api_key",
    ):
        assert tool not in names


async def test_iam_write_annotations_declare_mutation(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    for name in ("nv_create_user", "nv_update_user_role", "nv_create_api_key"):
        assert tools[name].annotations.readOnlyHint is False
        assert tools[name].annotations.destructiveHint is False
    for name in ("nv_delete_user", "nv_delete_api_key"):
        assert tools[name].annotations.readOnlyHint is False
        assert tools[name].annotations.destructiveHint is True


async def test_iam_write_error_codes_classify(client, nv_mock: respx.MockRouter) -> None:
    """Controller codes surface as actionable messages, not tracebacks."""
    # One route, reconfigured between assertions: respx matches routes in the
    # order they were added, so a second route on the same path would be dead.
    user_route = nv_mock.post(USER_PATH)
    user_route.respond(
        400, json={"code": 13, "error": "Duplicate name", "message": "User already exists"}
    )
    with pytest.raises(Exception) as duplicate:
        await _confirmed(client, "nv_create_user", CREATE_USER_ARGS)
    assert "code=13" in str(duplicate.value)
    assert "Duplicate name" in str(duplicate.value)
    assert PASSWORD not in str(duplicate.value)

    user_route.respond(
        400, json={"code": 14, "error": "Password is weak", "message": "password profile"}
    )
    with pytest.raises(Exception) as weak:
        await _confirmed(client, "nv_create_user", CREATE_USER_ARGS)
    assert "code=14" in str(weak.value)
    assert PASSWORD not in str(weak.value)

    nv_mock.delete(DELETE_USER_PATH).respond(
        403, json={"code": 25, "error": "Object access denied"}
    )
    with pytest.raises(Exception) as denied:
        await _confirmed(client, "nv_delete_user", {"fullname": "alice"})
    assert "code=25" in str(denied.value)

    nv_mock.delete(DELETE_API_KEY_PATH).respond(404, json={"code": 7, "error": "Object not found"})
    with pytest.raises(Exception) as missing:
        await _confirmed(client, "nv_delete_api_key", {"access_key": "ci-bot"})
    assert "code=7" in str(missing.value)
