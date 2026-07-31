"""sigstore contract tests: image-signature trust anchors, verifiers, platform scan.

Three things are asserted harder here than elsewhere.

1. A preview sends NOTHING (``route.call_count == 0``). These tools decide which
   image signatures the cluster trusts; a preview that leaked a request would be
   a silent change to that.
2. The PATCH tools OMIT every field the caller did not supply. apis.go declares
   ``REST_SigstoreRootOfTrust_PATCH`` and ``REST_SigstoreVerifier_PATCH`` with
   every field a POINTER carrying ``omitempty``, so an absent key means "not
   modified" and a key that leaks in with a default value silently overwrites a
   trust anchor.
3. The POST bodies match the Go structs exactly - ``REST_SigstoreVerifier``
   declares all six fields without ``omitempty`` (all always sent), while
   ``REST_SigstoreRootOfTrust_POST`` marks only the three PEM fields
   ``omitempty`` (dropped when empty).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx

pytestmark = pytest.mark.asyncio

ROOT = "corp-sigstore"
VERIFIER = "release-signer"
ROOTS_PATH = "/v1/scan/sigstore/root_of_trust"
ROOT_PATH = f"{ROOTS_PATH}/{ROOT}"
VERIFIERS_PATH = f"{ROOT_PATH}/verifier"
VERIFIER_PATH = f"{VERIFIERS_PATH}/{VERIFIER}"
PLATFORM_PATH = "/v1/scan/platform/platform"

PUBKEY = "-----BEGIN PUBLIC KEY-----AAAA-----END PUBLIC KEY-----"
ROOTCERT = "-----BEGIN CERTIFICATE-----BBBB-----END CERTIFICATE-----"
ISSUER = "https://token.actions.githubusercontent.com"
SUBJECT = "https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main"

VERIFIER_RAW: dict[str, Any] = {
    "name": VERIFIER,
    "verifier_type": "keyless",
    "public_key": "",
    "cert_issuer": ISSUER,
    "cert_subject": SUBJECT,
    "comment": "release pipeline",
}
ROOT_RAW: dict[str, Any] = {
    "name": ROOT,
    "is_private": True,
    "rootless_keypairs_only": False,
    "rekor_public_key": PUBKEY,
    "root_cert": ROOTCERT,
    "sct_public_key": "",
    "cfg_type": "user_created",
    "comment": "corporate sigstore",
    "verifiers": [VERIFIER_RAW],
}


async def _confirmed(client: Any, tool: str, args: dict[str, Any]) -> Any:
    """Run the two-step handshake: preview to mint the token, then apply."""
    plan = await client.call_tool(tool, args)
    token = plan.structured_content["confirm_token"]
    return await client.call_tool(tool, {**args, "confirm": token})


# -- reads ----------------------------------------------------------------------


async def test_list_sigstore_roots_projects_roots_and_verifiers(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(ROOTS_PATH).respond(200, json={"roots_of_trust": [ROOT_RAW]})
    result = await client.call_tool("nv_list_sigstore_roots", {})

    body = result.structured_content
    assert body["page"]["returned"] == 1
    assert body["page"]["truncated"] is False
    root = body["roots_of_trust"][0]
    assert root["name"] == ROOT
    assert root["is_private"] is True
    assert root["cfg_type"] == "user_created"
    assert root["rekor_public_key"] == PUBKEY
    assert [v["name"] for v in root["verifiers"]] == [VERIFIER]
    assert root["verifiers"][0]["cert_issuer"] == ISSUER


async def test_list_sigstore_roots_accepts_a_bare_array(client, nv_mock: respx.MockRouter) -> None:
    """apis.yaml declares the collection as a bare array, apis.go as an envelope.

    apis.go wins for what this server SENDS, but the reader must not turn an
    unexpected-but-valid shape into an empty list - "no roots configured" is
    exactly the wrong thing to tell an operator asking whether signatures are
    being verified.
    """
    nv_mock.get(ROOTS_PATH).respond(200, json=[ROOT_RAW])
    result = await client.call_tool("nv_list_sigstore_roots", {})
    assert [r["name"] for r in result.structured_content["roots_of_trust"]] == [ROOT]


async def test_list_sigstore_roots_empty_means_no_verification(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(ROOTS_PATH).respond(200, json={"roots_of_trust": []})
    result = await client.call_tool("nv_list_sigstore_roots", {})
    assert result.structured_content["roots_of_trust"] == []
    assert result.structured_content["page"]["returned"] == 0


async def test_get_sigstore_root_reads_the_bare_object(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(ROOT_PATH).respond(200, json=ROOT_RAW)
    result = await client.call_tool("nv_get_sigstore_root", {"root_name": ROOT})

    body = result.structured_content
    assert body["name"] == ROOT
    assert body["root_cert"] == ROOTCERT
    assert body["verifiers"][0]["cert_subject"] == SUBJECT


async def test_get_sigstore_root_missing_raises_not_found(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(ROOT_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_sigstore_root", {"root_name": ROOT})
    assert "no sigstore root of trust" in str(excinfo.value)


async def test_list_sigstore_verifiers_projects_every_field(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(VERIFIERS_PATH).respond(200, json={"verifiers": [VERIFIER_RAW]})
    result = await client.call_tool("nv_list_sigstore_verifiers", {"root_name": ROOT})

    body = result.structured_content
    assert body["root_name"] == ROOT
    assert body["verifiers"] == [
        {
            "name": VERIFIER,
            "verifier_type": "keyless",
            "public_key": "",
            "cert_issuer": ISSUER,
            "cert_subject": SUBJECT,
            "comment": "release pipeline",
        }
    ]


# -- nv_create_sigstore_root ----------------------------------------------------


async def test_create_sigstore_root_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(ROOTS_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_sigstore_root",
        {"name": ROOT, "is_private": True, "root_cert": ROOTCERT},
    )

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "TRUST ANCHOR" in body["effect"]
    assert "nv_create_sigstore_verifier" in body["effect"]
    assert route.call_count == 0, "the guard must not touch the controller"


async def test_create_sigstore_root_confirmed_body_matches_apis_go(
    client, nv_mock: respx.MockRouter
) -> None:
    """POST body is REST_SigstoreRootOfTrust_POST field for field.

    name, is_private, rootless_keypairs_only and comment have no omitempty and are
    always sent; the three PEM fields have omitempty and are dropped when empty.
    """
    route = nv_mock.post(ROOTS_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_create_sigstore_root",
        {
            "name": ROOT,
            "is_private": True,
            "rootless_keypairs_only": False,
            "rekor_public_key": PUBKEY,
            "root_cert": ROOTCERT,
            "comment": "corporate sigstore",
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "name": ROOT,
        "is_private": True,
        "rootless_keypairs_only": False,
        "comment": "corporate sigstore",
        "rekor_public_key": PUBKEY,
        "root_cert": ROOTCERT,
    }


async def test_create_sigstore_root_omits_empty_pem_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(ROOTS_PATH).respond(200, json={})
    await _confirmed(client, "nv_create_sigstore_root", {"name": ROOT})

    sent = json.loads(route.calls.last.request.read())
    assert sent == {
        "name": ROOT,
        "is_private": False,
        "rootless_keypairs_only": False,
        "comment": "",
    }
    for absent in ("rekor_public_key", "root_cert", "sct_public_key"):
        assert absent not in sent, f"{absent} carries omitempty in apis.go"


async def test_create_sigstore_root_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(ROOTS_PATH).respond(200, json={})
    plan = await client.call_tool("nv_create_sigstore_root", {"name": ROOT, "root_cert": ROOTCERT})
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_sigstore_root",
            {"name": ROOT, "root_cert": "-----BEGIN CERTIFICATE-----EVIL-----", "confirm": token},
        )
    assert "confirm token mismatch" in str(excinfo.value)


# -- nv_update_sigstore_root ----------------------------------------------------


async def test_update_sigstore_root_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(ROOT_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_sigstore_root", {"root_name": ROOT, "root_cert": ROOTCERT}
    )

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "REPLACES TRUST MATERIAL" in body["effect"]
    assert route.call_count == 0


async def test_update_sigstore_root_omits_untouched_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    """An unsupplied field must be ABSENT, not null and not "".

    apis.go REST_SigstoreRootOfTrust_PATCH declares every field as *string with
    omitempty, so a key present with any value is an instruction to overwrite -
    and here the thing overwritten is a trust anchor.
    """
    route = nv_mock.patch(ROOT_PATH).respond(200, json={})
    await _confirmed(client, "nv_update_sigstore_root", {"root_name": ROOT, "root_cert": ROOTCERT})

    sent = json.loads(route.calls.last.request.read())
    assert sent == {"root_cert": ROOTCERT}
    for absent in ("rekor_public_key", "sct_public_key", "comment", "name"):
        assert absent not in sent, f"{absent} would overwrite stored trust material"


async def test_update_sigstore_root_empty_string_is_reported_as_a_clear(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(ROOT_PATH).respond(200, json={})
    plan = await client.call_tool(
        "nv_update_sigstore_root", {"root_name": ROOT, "rekor_public_key": ""}
    )

    assert "CLEARS that trust material" in plan.structured_content["effect"]
    assert route.call_count == 0
    await _confirmed(client, "nv_update_sigstore_root", {"root_name": ROOT, "rekor_public_key": ""})
    assert json.loads(route.calls.last.request.read()) == {"rekor_public_key": ""}


async def test_update_sigstore_root_needs_a_field_and_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(ROOT_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_sigstore_root", {"root_name": ROOT})
    assert "No request was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


# -- nv_delete_sigstore_root ----------------------------------------------------


async def test_delete_sigstore_root_preview_names_the_cascade(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(ROOT_PATH).respond(200, json={})
    result = await client.call_tool("nv_delete_sigstore_root", {"root_name": ROOT})

    effect = result.structured_content["effect"]
    assert result.structured_content["status"] == "confirmation_required"
    assert "EVERY VERIFIER UNDER IT" in effect
    assert "no longer signature-checked" in effect
    assert "report itself as ENABLED" in effect
    assert "no undo" in effect
    assert route.call_count == 0


async def test_delete_sigstore_root_confirmed(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(ROOT_PATH).respond(200, json={})
    result = await _confirmed(client, "nv_delete_sigstore_root", {"root_name": ROOT})

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert not route.calls.last.request.read()


async def test_delete_sigstore_root_token_is_bound_to_the_root(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.delete(ROOT_PATH).respond(200, json={})
    nv_mock.delete(f"{ROOTS_PATH}/other-root").respond(200, json={})
    plan = await client.call_tool("nv_delete_sigstore_root", {"root_name": ROOT})
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_sigstore_root", {"root_name": "other-root", "confirm": token}
        )
    assert "confirm token mismatch" in str(excinfo.value)


# -- nv_create_sigstore_verifier ------------------------------------------------


async def test_create_sigstore_verifier_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(VERIFIERS_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_create_sigstore_verifier",
        {
            "root_name": ROOT,
            "name": VERIFIER,
            "verifier_type": "keypair",
            "public_key": PUBKEY,
        },
    )

    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert "EXPANDS WHAT THE CLUSTER" in body["effect"]
    assert "PRIVATE key" in body["effect"]
    assert route.call_count == 0


async def test_create_sigstore_verifier_sends_all_six_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    """apis.go REST_SigstoreVerifier has no omitempty anywhere: all six always go."""
    route = nv_mock.post(VERIFIERS_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_create_sigstore_verifier",
        {
            "root_name": ROOT,
            "name": VERIFIER,
            "verifier_type": "keyless",
            "cert_issuer": ISSUER,
            "cert_subject": SUBJECT,
            "comment": "release pipeline",
        },
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "name": VERIFIER,
        "verifier_type": "keyless",
        "public_key": "",
        "cert_issuer": ISSUER,
        "cert_subject": SUBJECT,
        "comment": "release pipeline",
    }


async def test_create_sigstore_verifier_keypair_without_key_is_rejected(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(VERIFIERS_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_sigstore_verifier",
            {"root_name": ROOT, "name": VERIFIER, "verifier_type": "keypair"},
        )
    assert "needs a 'public_key'" in str(excinfo.value)
    assert "Nothing was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_create_sigstore_verifier_keyless_wildcard_is_rejected(
    client, nv_mock: respx.MockRouter
) -> None:
    """A blank cert_issuer/cert_subject matches ANY identity; the controller accepts it."""
    route = nv_mock.post(VERIFIERS_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_sigstore_verifier",
            {
                "root_name": ROOT,
                "name": VERIFIER,
                "verifier_type": "keyless",
                "cert_issuer": ISSUER,
            },
        )
    message = str(excinfo.value)
    assert "cert_subject" in message
    assert "WILDCARD" in message
    assert route.call_count == 0


async def test_create_sigstore_verifier_token_is_bound_to_the_key(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.post(VERIFIERS_PATH).respond(200, json={})
    args = {
        "root_name": ROOT,
        "name": VERIFIER,
        "verifier_type": "keypair",
        "public_key": PUBKEY,
    }
    plan = await client.call_tool("nv_create_sigstore_verifier", args)
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_create_sigstore_verifier",
            {**args, "public_key": "-----BEGIN PUBLIC KEY-----EVIL-----", "confirm": token},
        )
    assert "confirm token mismatch" in str(excinfo.value)


# -- nv_update_sigstore_verifier ------------------------------------------------


async def test_update_sigstore_verifier_omits_untouched_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    """apis.go REST_SigstoreVerifier_PATCH is all pointers: omitted means unchanged."""
    route = nv_mock.patch(VERIFIER_PATH).respond(200, json={})
    result = await _confirmed(
        client,
        "nv_update_sigstore_verifier",
        {"root_name": ROOT, "verifier_name": VERIFIER, "cert_subject": SUBJECT},
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    sent = json.loads(route.calls.last.request.read())
    assert sent == {"cert_subject": SUBJECT}
    for absent in ("verifier_type", "public_key", "cert_issuer", "comment", "name"):
        assert absent not in sent, f"{absent} would repoint the trust decision"


async def test_update_sigstore_verifier_preview_warns_about_wildcards(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(VERIFIER_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_sigstore_verifier",
        {"root_name": ROOT, "verifier_name": VERIFIER, "cert_issuer": ""},
    )

    effect = result.structured_content["effect"]
    assert "WILDCARD" in effect
    assert "attacker-signed images" in effect
    assert route.call_count == 0


async def test_update_sigstore_verifier_preview_warns_about_a_new_public_key(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(VERIFIER_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_update_sigstore_verifier",
        {"root_name": ROOT, "verifier_name": VERIFIER, "public_key": PUBKEY},
    )

    assert "PRIVATE key" in result.structured_content["effect"]
    assert route.call_count == 0


async def test_update_sigstore_verifier_needs_a_field_and_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(VERIFIER_PATH).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_sigstore_verifier", {"root_name": ROOT, "verifier_name": VERIFIER}
        )
    assert "No request was sent to the controller" in str(excinfo.value)
    assert route.call_count == 0


async def test_update_sigstore_verifier_token_is_bound_to_arguments(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.patch(VERIFIER_PATH).respond(200, json={})
    args = {"root_name": ROOT, "verifier_name": VERIFIER, "cert_issuer": ISSUER}
    plan = await client.call_tool("nv_update_sigstore_verifier", args)
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_update_sigstore_verifier",
            {**args, "cert_issuer": "https://evil.example.com", "confirm": token},
        )
    assert "confirm token mismatch" in str(excinfo.value)


# -- nv_delete_sigstore_verifier ------------------------------------------------


async def test_delete_sigstore_verifier_preview_names_both_failure_modes(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.delete(VERIFIER_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_delete_sigstore_verifier", {"root_name": ROOT, "verifier_name": VERIFIER}
    )

    effect = result.structured_content["effect"]
    assert result.structured_content["status"] == "confirmation_required"
    assert "BLOCKED" in effect
    assert "LAST verifier" in effect
    assert "still reports itself as enabled" in effect
    assert route.call_count == 0


async def test_delete_sigstore_verifier_confirmed(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.delete(VERIFIER_PATH).respond(200, json={})
    result = await _confirmed(
        client, "nv_delete_sigstore_verifier", {"root_name": ROOT, "verifier_name": VERIFIER}
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert not route.calls.last.request.read()


async def test_delete_sigstore_verifier_token_is_bound_to_the_verifier(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.delete(VERIFIER_PATH).respond(200, json={})
    nv_mock.delete(f"{VERIFIERS_PATH}/other").respond(200, json={})
    plan = await client.call_tool(
        "nv_delete_sigstore_verifier", {"root_name": ROOT, "verifier_name": VERIFIER}
    )
    token = plan.structured_content["confirm_token"]

    with pytest.raises(Exception) as excinfo:
        await client.call_tool(
            "nv_delete_sigstore_verifier",
            {"root_name": ROOT, "verifier_name": "other", "confirm": token},
        )
    assert "confirm token mismatch" in str(excinfo.value)


# -- nv_trigger_scan(target='platform') -----------------------------------------
#
# The platform is a singleton: POST /v1/scan/platform/platform, so target_id is
# not interpolated into the path. Owned by this package (P6), which added the
# 'platform' branch to tools/scan_ops.py.


async def test_trigger_platform_scan_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(PLATFORM_PATH).respond(200, json={})
    result = await client.call_tool(
        "nv_trigger_scan", {"target": "platform", "target_id": "platform"}
    )

    assert result.structured_content["status"] == "confirmation_required"
    assert "Kubernetes platform" in result.structured_content["effect"]
    assert route.call_count == 0


async def test_trigger_platform_scan_posts_the_singleton_route(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.post(PLATFORM_PATH).respond(200, json={})
    result = await _confirmed(
        client, "nv_trigger_scan", {"target": "platform", "target_id": "platform"}
    )

    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert route.calls.last.request.method == "POST"
    assert route.calls.last.request.url.path == PLATFORM_PATH


async def test_trigger_platform_scan_ignores_target_id(client, nv_mock: respx.MockRouter) -> None:
    """target_id names nothing for a platform scan; it must not reach the path."""
    route = nv_mock.post(PLATFORM_PATH).respond(200, json={})
    await _confirmed(client, "nv_trigger_scan", {"target": "platform", "target_id": "ignored"})

    assert route.call_count == 1
    assert route.calls.last.request.url.path == PLATFORM_PATH
