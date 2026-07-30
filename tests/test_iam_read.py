"""iam_read toolset contract tests.

Three of these tests exist purely to keep secrets out of tool output: a planted
password, a planted API-key secret and planted auth-server configuration values
must be absent from the serialised result, not merely undocumented.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from conftest import fixture
from neuvector_mcp.models import ApiKeyBrief, AuthServerBrief, UserBrief

pytestmark = pytest.mark.asyncio


def wire_text(result: Any) -> str:
    """Every byte of a tool result that can reach the client, as one string.

    ``result.data`` is a synthesised ``Root`` wrapper under this fastmcp version,
    not the tool's own Pydantic model, so it has no ``model_dump_json``. A leak
    test must search what actually crosses the wire, which is both channels:
    ``structured_content`` (the JSON object) and every text content block.
    Concatenating them means a planted secret is caught whichever way it escapes.
    """
    parts = [json.dumps(result.structured_content, sort_keys=True)]
    parts.extend(
        block.text for block in (result.content or []) if getattr(block, "text", None) is not None
    )
    return "\n".join(parts)


# -- nv_list_users -------------------------------------------------------------
async def test_list_users_query_and_projection(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/user").respond(200, json=fixture("users"))
    result = await client.call_tool(
        "nv_list_users",
        {"role": "admin", "auth_server": "corp-ldap", "name_prefix": "ad", "limit": 2},
    )

    request = route.calls.last.request
    assert request.url.params["f_role"] == "admin"
    assert request.url.params["f_server"] == "corp-ldap"
    assert request.url.params["f_fullname"] == "prefix,ad"
    assert request.url.params["start"] == "0"
    assert request.url.params["limit"] == "3", "must over-fetch by one to detect truncation"

    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint

    first = result.data.users[0]
    assert first.fullname == "admin"
    assert first.username == "admin"
    assert first.email == "admin@example.test"
    assert first.auth_server == "", "local accounts carry an empty controller 'server'"
    assert first.role == "admin"
    assert first.role_domains == {"reader": ["prod", "staging"]}
    assert first.timeout == 300
    assert first.last_login_timestamp == 1753900000
    assert first.login_count == 42

    second = result.data.users[1]
    assert second.auth_server == "corp-ldap"
    assert second.blocked_for_failed_login is True


async def test_list_users_never_returns_password(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/user").respond(200, json=fixture("users"))
    result = await client.call_tool("nv_list_users", {})

    serialised = wire_text(result)
    assert "admin@example.test" in serialised, (
        "positive control: wire_text must really contain the projected output"
    )
    assert "SuperSecretPlanted123!" in json.dumps(fixture("users")), (
        "guard: the fixture must actually plant a password, or this test proves nothing"
    )
    assert "SuperSecretPlanted123!" not in serialised
    assert "password" not in UserBrief.model_fields, "the projection must have no password field"
    # No emitted user object may carry a 'password' key under any nesting.
    for user in result.structured_content["users"]:
        assert "password" not in user
    assert not hasattr(result.data.users[0], "password")


async def test_list_users_defaults_default_password_true(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/user").respond(200, json=fixture("users"))
    result = await client.call_tool("nv_list_users", {})

    by_name = {u.fullname: u for u in result.data.users}
    assert by_name["admin"].default_password is True
    assert by_name["ci-bot"].default_password is False
    assert by_name["ldap-auditor"].default_password is True, (
        "a missing default_password must not read as safe"
    )


async def test_list_users_no_filters_sends_no_f_params(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/user").respond(200, json={"users": []})
    result = await client.call_tool("nv_list_users", {})
    assert not [k for k in route.calls.last.request.url.params if k.startswith("f_")]
    assert result.data.page.truncated is False
    assert result.data.page.hint is None


# -- nv_list_roles -------------------------------------------------------------
async def test_list_roles_projects_permissions(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/user_role").respond(200, json=fixture("user_roles"))
    result = await client.call_tool("nv_list_roles", {"name_prefix": "ci", "limit": 10})

    request = route.calls.last.request
    assert request.url.params["f_name"] == "prefix,ci"
    assert request.url.params["limit"] == "11", "must over-fetch by one to detect truncation"

    ciops = result.data.roles[0]
    assert ciops.name == "ciops"
    assert ciops.reserved is False
    assert [p.id for p in ciops.permissions] == ["rt_policy", "admctrl", "events"]
    assert ciops.permissions[0].read is True
    assert ciops.permissions[0].write is True
    assert ciops.permissions[2].write is False
    assert ciops.comment.startswith("Pipeline role")

    assert result.data.roles[1].reserved is True


async def test_role_write_permission_count(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/user_role").respond(200, json=fixture("user_roles"))
    result = await client.call_tool("nv_list_roles", {})

    counts = {r.name: r.write_permission_count for r in result.data.roles}
    assert counts["ciops"] == 2
    assert counts["reader"] == 0, "0 identifies a read-only role without walking permissions"
    assert counts["scanner"] == 1


# -- nv_list_auth_servers ------------------------------------------------------
async def test_list_auth_servers_projects_names_only(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/server").respond(200, json=fixture("auth_servers"))
    result = await client.call_tool("nv_list_auth_servers", {"name_prefix": "corp", "limit": 10})

    request = route.calls.last.request
    assert request.url.params["f_name"] == "prefix,corp"
    assert request.url.params["limit"] == "11", "must over-fetch by one to detect truncation"

    ldap = result.data.servers[0]
    assert ldap.name == "corp-ldap"
    assert ldap.config_blocks == ["enable", "ldap"], "block key NAMES only, never their values"
    assert result.data.servers[1].config_blocks == ["enable", "oidc"]
    assert result.data.servers[2].config_blocks == ["enable", "saml"]


async def test_list_auth_servers_redacts_secret_key_names(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/server").respond(200, json=fixture("auth_servers"))
    result = await client.call_tool("nv_list_auth_servers", {})

    by_name = {s.name: s for s in result.data.servers}
    assert by_name["corp-ldap"].redacted_keys == ["bind_password"]
    assert by_name["corp-oidc"].redacted_keys == ["client_secret"]
    assert by_name["corp-saml"].redacted_keys == ["api_token", "signing_private_key"]
    for server in result.data.servers:
        assert not set(server.config_blocks) & set(server.redacted_keys)


async def test_list_auth_servers_result_contains_no_config_values(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/server").respond(200, json=fixture("auth_servers"))
    result = await client.call_tool("nv_list_auth_servers", {})

    serialised = wire_text(result)
    assert "corp-ldap" in serialised, (
        "positive control: wire_text must really contain the projected output"
    )
    raw = json.dumps(fixture("auth_servers"))
    planted_secrets = (
        "TOP-LEVEL-BIND-PW-bbb222",
        "NESTED-LDAP-BIND-PW-aaa111",
        "TOP-LEVEL-OIDC-SECRET-ddd444",
        "NESTED-OIDC-CLIENT-SECRET-ccc333",
        "TOP-LEVEL-SIGNING-KEY-eee555",
        "TOP-LEVEL-API-TOKEN-fff666",
    )
    # No non-allowlisted value of any kind survives, secret-looking or not.
    planted_config = ("ldap.corp.example.test", "https://sso.corp.example.test/saml", "MIIBIjANBg")
    for planted in planted_secrets + planted_config:
        assert planted in raw, (
            f"guard: {planted!r} must actually be in the fixture, or this test proves nothing"
        )
        assert planted not in serialised

    # Structural backstop: 'name' is the ONLY key whose value is ever emitted, so
    # every emitted server object must consist of exactly the projection's fields.
    for server in result.structured_content["servers"]:
        assert set(server) <= set(AuthServerBrief.model_fields)


async def test_list_auth_servers_unknown_envelope_key_degrades_to_empty(
    client, nv_mock: respx.MockRouter
) -> None:
    # The 'servers' key is inferred; a wrong key must give an empty page, never raise.
    nv_mock.get("/v1/server").respond(200, json={"auth_servers": [{"name": "x"}]})
    result = await client.call_tool("nv_list_auth_servers", {})
    assert result.data.servers == []
    assert result.data.page.truncated is False


# -- nv_list_api_keys ----------------------------------------------------------
async def test_list_api_keys_query_and_projection(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/api_key").respond(200, json=fixture("api_keys"))
    result = await client.call_tool(
        "nv_list_api_keys", {"role": "admin", "name_prefix": "ci-", "limit": 10}
    )

    request = route.calls.last.request
    assert request.url.params["f_role"] == "admin"
    assert request.url.params["f_apikey_name"] == "prefix,ci-"
    assert request.url.params["limit"] == "11", "must over-fetch by one to detect truncation"

    first = result.data.api_keys[0]
    assert first.apikey_name == "ci-pipeline"
    assert first.role == "admin"
    assert first.role_domains == {"reader": ["prod"]}
    assert first.expiration_type == "hours"
    assert first.expiration_hours == 720
    assert first.expiration_timestamp == 1756492800
    assert first.created_timestamp == 1753900800
    assert first.created_by_entity == "admin"
    assert first.description.startswith("Used by the release pipeline")

    never = result.data.api_keys[1]
    assert never.expiration_type == "never"
    assert never.expiration_hours == 0
    assert never.expiration_timestamp == 0


async def test_list_api_keys_never_returns_secret(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/api_key").respond(200, json=fixture("api_keys"))
    result = await client.call_tool("nv_list_api_keys", {})

    serialised = wire_text(result)
    assert "ci-pipeline" in serialised, (
        "positive control: wire_text must really contain the projected output"
    )
    assert "PLANTED-APIKEY-SECRET-zzz999" in json.dumps(fixture("api_keys")), (
        "guard: the fixture must actually plant a key secret, or this test proves nothing"
    )
    assert "PLANTED-APIKEY-SECRET-zzz999" not in serialised
    assert "apikey_secret" not in serialised
    assert "apikey_secret" not in ApiKeyBrief.model_fields
    # A key secret is unrecoverable after creation; no emitted key may hint otherwise.
    for key in result.structured_content["api_keys"]:
        assert "apikey_secret" not in key
        assert set(key) <= set(ApiKeyBrief.model_fields)
    assert not hasattr(result.data.api_keys[0], "apikey_secret")


async def test_list_api_keys_truncates(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get("/v1/api_key").respond(200, json=fixture("api_keys"))
    result = await client.call_tool("nv_list_api_keys", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3"
    assert result.data.page.returned == 2
    assert result.data.page.truncated is True
    assert "start=2" in result.data.page.hint
    assert len(result.data.api_keys) == 2
