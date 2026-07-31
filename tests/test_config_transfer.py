"""config_transfer contract tests: YAML export, YAML import, remote repositories.

Four things are asserted harder here than anywhere else.

1. **The export body is not JSON.** ``client.request`` would hand a YAML answer to
   ``_safe_json``, which returns ``response.text[:500]``. Several tests serve a
   document longer than 500 characters and assert the tool saw all of it, so a
   regression that routes an export back through ``request`` fails loudly instead
   of returning a plausible-looking fragment.
2. **The import body is the file itself.** ``request.read()`` must equal the YAML
   bytes verbatim - not a JSON string containing them - and the Content-Type must
   not be application/json.
3. **A preview sends NOTHING.** ``route.call_count == 0`` on every first call,
   because an import replaces a whole ruleset.
4. **The access token never comes back.** Neither the plan nor the applied result
   may contain the literal token value anywhere in its serialised form.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

from neuvector_mcp.guard import confirm_token
from neuvector_mcp.tools.config_transfer import redact_yaml_secrets

pytestmark = pytest.mark.asyncio

GROUP_EXPORT_PATH = "/v1/file/group"
ALL_EXPORT_PATH = "/v1/file/config"
WAF_EXPORT_PATH = "/v1/file/waf"
GROUP_IMPORT_PATH = "/v1/file/group/config"
WAF_IMPORT_PATH = "/v1/file/waf/config"
COMPLIANCE_IMPORT_PATH = "/v1/file/compliance/profile/config"
REPO_PATH = "/v1/system/config/remote_repository"

PAT = "ghp_liveTokenValueThatMustNeverComeBack"

GROUP_YAML = """apiVersion: neuvector.com/v1
kind: NvSecurityRule
metadata:
  name: nv.api.prod
spec:
  target:
    selector:
      name: nv.api.prod
      criteria:
        - key: service
          op: =
          value: api.prod
"""

#: Deliberately longer than the 500-character cut-off in client._safe_json.
LONG_YAML = "groups:\n" + "".join(f"  - name: nv.svc{i:04d}.prod\n" for i in range(200))

IMPORT_TASK = {
    "data": {
        "tid": "c5af897b62a258212ece91c0551d3a4a",
        "ctrler_id": "6e60452b",
        "percentage": 30,
        "status": "importing",
        "triggered_by": "admin",
        "last_update_time": "2026-07-31T10:00:00Z",
        "temp_token": "temp-token-must-not-leak",
        "fail_to_decrypt_key_fields": {},
    }
}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- redact_yaml_secrets (pure) -------------------------------------------------


async def test_redactor_blanks_a_plain_secret_key() -> None:
    text, hits = redact_yaml_secrets("registry: r\npassword: hunter2\nusername: bob\n")
    assert "hunter2" not in text
    assert "password: '***'" in text
    assert "username: bob" in text, "a non-secret key is left alone"
    assert hits == {"password": 1}


async def test_redactor_blanks_at_any_indentation_and_in_sequence_items() -> None:
    document = "registries:\n  - name: a\n    auth_token: tok-a\n  - name: b\n    password: p-b\n"
    text, hits = redact_yaml_secrets(document)
    assert "tok-a" not in text and "p-b" not in text
    assert hits == {"auth_token": 1, "password": 1}


async def test_redactor_blanks_the_first_key_of_a_sequence_item() -> None:
    text, hits = redact_yaml_secrets("creds:\n  - password: leaked\n    user: bob\n")
    assert "leaked" not in text
    assert hits == {"password": 1}


async def test_redactor_drops_a_block_scalar_body() -> None:
    """A multi-line json_key must not survive its own header line."""
    document = (
        "gcr:\n"
        "  json_key: |\n"
        '    {"type": "service_account",\n'
        '     "private_key": "-----BEGIN PRIVATE KEY-----"}\n'
        "  next_key: kept\n"
    )
    text, hits = redact_yaml_secrets(document)
    assert "BEGIN PRIVATE KEY" not in text
    assert "service_account" not in text
    assert "next_key: kept" in text, "the block ends where indentation returns"
    assert hits == {"json_key": 1}


async def test_redactor_counts_zero_when_there_is_nothing_to_redact() -> None:
    text, hits = redact_yaml_secrets(GROUP_YAML)
    assert text == GROUP_YAML
    assert hits == {}, "0 found must be distinguishable from 'did not run'"


async def test_redactor_documented_blind_spots_are_real() -> None:
    """Pin the limits the docstring claims, so the claim cannot silently drift.

    These are NOT desirable behaviours. They are the honest boundary of a line
    filter, asserted here so nobody reads the tool description as a guarantee.
    """
    flow, flow_hits = redact_yaml_secrets("creds: {password: hunter2}\n")
    assert "hunter2" in flow and flow_hits == {}, "flow style is not caught"

    url, url_hits = redact_yaml_secrets("url: https://hooks.example/T00/B00/s3cr3t\n")
    assert "s3cr3t" in url and url_hits == {}, "a token inside a URL is not caught"

    unknown, unknown_hits = redact_yaml_secrets("client_secret: s3cr3t\n")
    assert "s3cr3t" in unknown and unknown_hits == {}, "an unknown key name is not caught"


# -- nv_export_config -----------------------------------------------------------


async def test_export_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(GROUP_EXPORT_PATH).respond(200, text=GROUP_YAML)
    result = await client.call_tool("nv_export_config", {"kind": "group"})

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "POST /v1/file/group" in body["effect"]
    assert "scope='local'" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_export_group_sends_exact_body_and_scope(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(GROUP_EXPORT_PATH).respond(200, text=GROUP_YAML)
    result = await _confirmed(
        client,
        "nv_export_config",
        {"kind": "group", "names": ["nv.api.prod"], "use_name_referral": True},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    request = route.calls.last.request
    assert json.loads(request.read()) == {
        "use_name_referral": True,
        "groups": ["nv.api.prod"],
    }
    assert request.url.params["scope"] == "local"
    assert result.structured_content["controller_response"]["yaml"] == GROUP_YAML


async def test_export_returns_the_whole_document_not_a_500_char_fragment(
    client, nv_mock: respx.MockRouter
) -> None:
    """The bug this module exists to avoid: client._safe_json truncates to 500."""
    assert len(LONG_YAML) > 500
    nv_mock.post(GROUP_EXPORT_PATH).respond(200, text=LONG_YAML)
    result = await _confirmed(client, "nv_export_config", {"kind": "group"})

    response = result.structured_content["controller_response"]
    assert response["document_characters"] == len(LONG_YAML)
    assert response["yaml"] == LONG_YAML
    assert response["truncated"] is False


async def test_export_truncation_is_reported_never_silent(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(GROUP_EXPORT_PATH).respond(200, text=LONG_YAML)
    result = await _confirmed(client, "nv_export_config", {"kind": "group", "max_characters": 1000})

    response = result.structured_content["controller_response"]
    assert response["truncated"] is True
    assert response["returned_characters"] == 1000
    assert response["document_characters"] == len(LONG_YAML)
    assert "NOT importable" in response["hint"]
    assert "TRUNCATED" in result.structured_content["effect"]


async def test_export_redacts_credentials_in_the_returned_document(
    client, nv_mock: respx.MockRouter
) -> None:
    secretful = "registries:\n  - name: prod\n    password: hunter2\n    auth_token: tok\n"
    nv_mock.post(WAF_EXPORT_PATH).respond(200, text=secretful)
    result = await _confirmed(client, "nv_export_config", {"kind": "waf"})

    response = result.structured_content["controller_response"]
    assert "hunter2" not in response["yaml"]
    assert "tok\n" not in response["yaml"]
    assert response["credential_keys_found"] == {"auth_token": 1, "password": 1}


async def test_export_all_uses_get_and_withholds_the_document(
    client, nv_mock: respx.MockRouter
) -> None:
    """POST /v1/file/config is the whole-cluster IMPORT; the export is the GET."""
    get_route = nv_mock.get(ALL_EXPORT_PATH).respond(200, text=LONG_YAML + "password: p\n")
    post_route = nv_mock.post(ALL_EXPORT_PATH).respond(200, text="")

    result = await _confirmed(client, "nv_export_config", {"kind": "all"})

    assert get_route.call_count == 1
    assert post_route.call_count == 0, "POST /v1/file/config would OVERWRITE the cluster"
    response = result.structured_content["controller_response"]
    assert response["yaml"] == ""
    assert response["withheld"] is True
    assert response["truncated"] is True
    assert response["document_characters"] == len(LONG_YAML) + len("password: p\n")
    assert response["credential_keys_found"] == {"password": 1}
    assert "webhook" in response["withheld_reason"]


async def test_export_all_sends_no_scope_and_no_body(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(ALL_EXPORT_PATH).respond(200, text="a: b\n")
    await _confirmed(client, "nv_export_config", {"kind": "all"})

    request = route.calls.last.request
    assert request.read() == b""
    assert "scope" not in request.url.params


async def test_export_rejects_fed_scope_on_an_unscoped_kind(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/file/compliance/profile").respond(200, text="a: b\n")
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_export_config", {"kind": "compliance_profile", "scope": "fed"})
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_export_admission_sends_export_config_and_ids(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post("/v1/file/admission").respond(200, text="a: b\n")
    await _confirmed(
        client,
        "nv_export_config",
        {"kind": "admission", "ids": [3, 1], "include_state": False},
    )
    assert json.loads(route.calls.last.request.read()) == {
        "export_config": False,
        "ids": [3, 1],
    }


async def test_export_token_is_bound_to_arguments(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post(GROUP_EXPORT_PATH).respond(200, text=GROUP_YAML)
    plan = await client.call_tool("nv_export_config", {"kind": "group", "names": ["a"]})
    stale = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_export_config", {"kind": "group", "names": ["b"], "confirm": stale}
        )
    assert "confirm token mismatch" in str(excinfo.value)


# -- nv_import_config -----------------------------------------------------------


async def test_import_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    result = await client.call_tool(
        "nv_import_config", {"kind": "group", "yaml_document": GROUP_YAML}
    )

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "REPLACE" in body["effect"]
    assert "NO UNDO" in body["effect"]
    assert "nv_export_config(kind='group')" in body["effect"]
    assert route.call_count == 0, "a preview must never start an import"


async def test_import_sends_the_yaml_verbatim_as_the_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    result = await _confirmed(
        client, "nv_import_config", {"kind": "group", "yaml_document": GROUP_YAML}
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    request = route.calls.last.request
    assert request.read() == GROUP_YAML.encode("utf-8"), "the body IS the file, not JSON"
    assert request.headers["Content-Type"] == "text/plain; charset=utf-8"
    assert request.url.params["scope"] == "local"


async def test_import_plan_describes_the_body_by_digest_not_by_echoing_it(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    plan = await client.call_tool("nv_import_config", {"kind": "group", "yaml_document": LONG_YAML})
    payload = plan.structured_content["payload"]

    assert payload["document_characters"] == len(LONG_YAML)
    assert len(payload["document_sha256"]) == 64
    assert len(payload["document_head"]) <= 403
    assert "body" not in payload, "a megabyte of YAML must not be echoed into the plan"


async def test_import_token_is_bound_to_the_document(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    plan = await client.call_tool(
        "nv_import_config", {"kind": "group", "yaml_document": GROUP_YAML}
    )
    stale = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_import_config",
            {"kind": "group", "yaml_document": GROUP_YAML + "extra: 1\n", "confirm": stale},
        )
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_import_rejects_an_empty_document(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_import_config", {"kind": "group", "yaml_document": "   \n"})
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_import_refuses_a_document_still_carrying_the_redaction_sentinel(
    client, nv_mock: respx.MockRouter
) -> None:
    """Round-tripping an export without restoring credentials would store '***'."""
    route = nv_mock.post(WAF_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_import_config",
            {"kind": "waf", "yaml_document": "registries:\n  - password: '***'\n"},
        )
    message = str(excinfo.value)
    assert "Nothing was sent to the controller" in message
    assert route.call_count == 0


async def test_import_rejects_fed_scope_on_an_unscoped_kind(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(COMPLIANCE_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_import_config",
            {"kind": "compliance_profile", "yaml_document": GROUP_YAML, "scope": "fed"},
        )
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_import_unscoped_kind_sends_no_scope_param(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(COMPLIANCE_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    await _confirmed(
        client,
        "nv_import_config",
        {"kind": "compliance_profile", "yaml_document": GROUP_YAML},
    )
    assert "scope" not in route.calls.last.request.url.params


async def test_import_fed_scope_is_named_in_the_plan(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post(WAF_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    plan = await client.call_tool(
        "nv_import_config",
        {"kind": "waf", "yaml_document": GROUP_YAML, "scope": "fed"},
    )
    effect = plan.structured_content["effect"]
    assert "/v1/file/waf/config" in effect
    assert "every member cluster" in effect


async def test_import_projects_the_task_and_withholds_temp_token(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    result = await _confirmed(
        client, "nv_import_config", {"kind": "group", "yaml_document": GROUP_YAML}
    )

    response = result.structured_content["controller_response"]
    task = response["import_task"]
    assert task["task_id"] == "c5af897b62a258212ece91c0551d3a4a"
    assert task["percentage"] == 30
    assert task["running"] is True
    assert "temp-token-must-not-leak" not in json.dumps(result.structured_content)
    assert "asynchronous" in result.structured_content["effect"]


# -- nv_get_import_status -------------------------------------------------------


async def test_get_import_status_is_a_plain_read(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(GROUP_IMPORT_PATH).respond(200, json=IMPORT_TASK)
    result = await client.call_tool("nv_get_import_status", {})

    assert route.call_count == 1, "a read tool takes no confirmation handshake"
    body = result.structured_content
    assert body["task_id"] == "c5af897b62a258212ece91c0551d3a4a"
    assert body["status"] == "importing"
    assert body["running"] is True
    assert "temp-token-must-not-leak" not in json.dumps(body)


async def test_get_import_status_reports_decrypt_failures(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(GROUP_IMPORT_PATH).respond(
        200,
        json={
            "data": {
                "tid": "t1",
                "percentage": 100,
                "status": "done",
                "fail_to_decrypt_key_fields": {"registry/prod": ["password"]},
            }
        },
    )
    body = (await client.call_tool("nv_get_import_status", {})).structured_content

    assert body["running"] is False
    assert body["fail_to_decrypt_key_fields"] == {"registry/prod": ["password"]}
    assert "NOT restored" in body["note"]


async def test_get_import_status_with_no_task(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(GROUP_IMPORT_PATH).respond(200, json={})
    body = (await client.call_tool("nv_get_import_status", {})).structured_content

    assert body["task_id"] == ""
    assert body["running"] is False
    assert "No import task" in body["note"]


# -- remote repositories --------------------------------------------------------

CREATE_ARGS: dict[str, Any] = {
    "nickname": "backup",
    "repository_owner": "acme",
    "repository_name": "nv-config",
    "branch": "main",
    "personal_access_token": PAT,
    "committer_name": "nv-bot",
    "committer_email": "nv-bot@acme.example",
    "comment": "rotates 2027-01",
}


async def test_create_remote_repository_preview_sends_nothing_and_hides_the_token(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(REPO_PATH).respond(200, json={})
    plan = await client.call_tool("nv_create_remote_repository", CREATE_ARGS)

    body = plan.structured_content
    assert body["status"] == "confirmation_required"
    assert route.call_count == 0
    assert PAT not in json.dumps(body), "the PAT must never be echoed back"
    assert body["payload"]["github_configuration"]["personal_access_token"] == "***"
    assert "PERSONAL ACCESS TOKEN" in body["effect"]


async def test_create_remote_repository_sends_the_exact_body(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(REPO_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_create_remote_repository", CREATE_ARGS)

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "nickname": "backup",
        "provider": "github",
        "comment": "rotates 2027-01",
        "enable": True,
        "github_configuration": {
            "repository_owner_username": "acme",
            "repository_name": "nv-config",
            "repository_branch_name": "main",
            # apis.go RESTRemoteRepo_GitHubConfig wins over apis.yaml here.
            "personal_access_token": PAT,
            "personal_access_token_committer_name": "nv-bot",
            "personal_access_token_email": "nv-bot@acme.example",
        },
    }
    assert PAT not in json.dumps(result.structured_content), "the real token stays on the wire"


async def test_create_remote_repository_omits_azure_config(
    client, nv_mock: respx.MockRouter
) -> None:
    """A nil pointer field is OMITTED, never sent as null."""
    route = nv_mock.post(REPO_PATH).respond(200, json={})
    await _confirmed(client, "nv_create_remote_repository", CREATE_ARGS)
    assert "azure_devops_configuration" not in json.loads(route.calls.last.request.read())


async def test_update_remote_repository_omits_untouched_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{REPO_PATH}/backup").respond(200, json={})
    await _confirmed(client, "nv_update_remote_repository", {"alias": "backup", "enable": False})

    config = json.loads(route.calls.last.request.read())["config"]
    assert config == {"nickname": "backup", "enable": False}
    for absent in ("comment", "github_configuration"):
        assert absent not in config, f"{absent} would overwrite the stored value"


async def test_update_remote_repository_rotates_the_token(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{REPO_PATH}/backup").respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_remote_repository",
        {"alias": "backup", "personal_access_token": PAT},
    )

    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "nickname": "backup",
            "github_configuration": {"personal_access_token": PAT},
        }
    }
    assert PAT not in json.dumps(result.structured_content)


async def test_update_remote_repository_warns_about_partial_github_config(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(f"{REPO_PATH}/backup").respond(200, json={})
    plan = await client.call_tool(
        "nv_update_remote_repository", {"alias": "backup", "branch": "release"}
    )
    assert "NOT documented" in plan.structured_content["effect"]


async def test_update_remote_repository_rejects_an_empty_change(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(f"{REPO_PATH}/backup").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_remote_repository", {"alias": "backup"})
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_delete_remote_repository_handshake(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(f"{REPO_PATH}/backup").respond(200, json={})

    plan = await client.call_tool("nv_delete_remote_repository", {"alias": "backup"})
    assert plan.structured_content["status"] == "confirmation_required"
    assert route.call_count == 0
    assert "does NOT revoke the token in GitHub" in plan.structured_content["effect"]
    assert plan.structured_content["confirm_token"] == confirm_token(
        "nv_delete_remote_repository", "remote repository 'backup'", None
    )

    result = await client.call_tool(
        "nv_delete_remote_repository",
        {"alias": "backup", "confirm": plan.structured_content["confirm_token"]},
    )
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.read() == b""
