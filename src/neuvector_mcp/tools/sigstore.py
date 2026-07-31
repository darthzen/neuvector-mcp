"""Sigstore image-signature trust: roots of trust and their verifiers.

Two toolsets live here and are gated separately in :func:`register`:

* reads, tagged ``{"vulnerability", "read"}`` - the toolset the other
  scan-adjacent reads (``nv_get_scan_status``, ``nv_list_scanners``) already use;
* writes, tagged ``{"scan_ops", "write"}``.

Why this package is unusually dangerous
---------------------------------------
These objects decide WHICH IMAGE SIGNATURES THE CLUSTER TRUSTS, and every
failure mode is silent. Deleting a root of trust deletes every verifier under
it, so images that were admitted only because one of those verifiers vouched for
them stop being signature-checked - while admission control carries on reporting
itself as enabled, because from its point of view nothing failed; there is
simply no longer a verifier with an opinion. A verifier holding the wrong public
key, or a keyless verifier with a blank ``cert_issuer`` / ``cert_subject``, is
worse than no verifier: it accepts signatures from whoever holds the matching
private key, which for an attacker-supplied key means any image at all. Nothing
in the API rejects any of that. The controller answers 200.

So every write here previews an effect naming the concrete consequence, and
``nv_create_sigstore_verifier`` refuses inputs that would build a
match-anything verifier (see :func:`_validate_verifier_material`).

Every mutating tool follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

Secrets: there are none on this surface. Every wire field of
``REST_SigstoreRootOfTrust_*`` and ``REST_SigstoreVerifier*`` in apis.go is a
name, a flag, a comment, a PEM PUBLIC key or a certificate identity. No private
key, password or token field exists, so these tools deliberately do NOT run
their payloads through ``redact_secrets`` - masking a public key would hide the
one value an operator has to eyeball in the preview.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import NotFoundError, ValidationError_
from ..guard import authorise_write
from ..models import (
    Page,
    SigstoreRootList,
    SigstoreRootOfTrust,
    SigstoreVerifierEntry,
    SigstoreVerifierList,
    WriteOutcome,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Destroys a stored object. A second call fails with controller code 7.
MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
#: Reversible configuration change. Re-applying the same arguments is a no-op.
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Creates something that did not exist before. A second call is rejected.
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)

#: Envelope key of the root-of-trust collection. apis.go
#: ``REST_SigstoreRootOfTrustCollection.RootsOfTrust`` carries
#: ``json:"roots_of_trust"``; apis.yaml declares the same definition as a bare
#: array. apis.go wins (house rule), but the readers below accept either shape:
#: the disagreement cannot be settled offline and guessing wrong would turn a
#: successful read into an empty list, which reads as "no roots configured".
ROOTS_KEY = "roots_of_trust"
#: Same, for apis.go ``REST_SigstoreVerifierCollection.Verifiers``.
VERIFIERS_KEY = "verifiers"


def _unwrap_list(body: Any, key: str) -> list[dict[str, Any]]:
    """Return the object list from either ``{key: [...]}`` or a bare ``[...]``.

    See :data:`ROOTS_KEY` for why both shapes are accepted.
    """
    items: Any = None
    if isinstance(body, dict):
        items = body.get(key)
    elif isinstance(body, list):
        items = body
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _unwrap_root(body: Any) -> dict[str, Any]:
    """Return the root object from a single-root GET.

    apis.yaml declares the 200 schema of
    ``GET /v1/scan/sigstore/root_of_trust/{root_name}`` as a bare
    ``REST_SigstoreRootOfTrust_GET`` and apis.go defines no wrapper struct for
    it, so the bare object is the documented shape and is tried first. A
    ``root_of_trust`` envelope is accepted as a fallback rather than returning an
    empty projection if the controller wraps it after all.
    """
    if not isinstance(body, dict):
        return {}
    if "name" in body:
        return body
    inner = body.get("root_of_trust")
    return inner if isinstance(inner, dict) else {}


def _root_post_body(
    *,
    name: str,
    is_private: bool,
    rootless_keypairs_only: bool,
    rekor_public_key: str,
    root_cert: str,
    sct_public_key: str,
    comment: str,
) -> dict[str, Any]:
    """Render ``REST_SigstoreRootOfTrust_POST`` (apis.go 5.6.0).

    Written field by field rather than with ``model_dump()`` so the wire shape is
    auditable (house rule). Optionality comes straight from the Go struct tags:
    ``name``, ``is_private``, ``rootless_keypairs_only`` and ``comment`` are
    declared WITHOUT ``omitempty``, so the controller always receives them and a
    False or empty value is meaningful rather than "unset". ``rekor_public_key``,
    ``root_cert`` and ``sct_public_key`` carry ``omitempty`` and are therefore
    omitted when empty instead of being sent as "".
    """
    body: dict[str, Any] = {
        "name": name,
        "is_private": is_private,
        "rootless_keypairs_only": rootless_keypairs_only,
        "comment": comment,
    }
    for key, value in (
        ("rekor_public_key", rekor_public_key),
        ("root_cert", root_cert),
        ("sct_public_key", sct_public_key),
    ):
        if value:
            body[key] = value
    return body


def _verifier_post_body(
    *,
    name: str,
    verifier_type: str,
    public_key: str,
    cert_issuer: str,
    cert_subject: str,
    comment: str,
) -> dict[str, Any]:
    """Render ``REST_SigstoreVerifier`` (apis.go 5.6.0) as a POST body.

    All six fields are plain ``string`` without ``omitempty``, so all six are
    always sent - including the ones that do not apply to the chosen
    verifier_type, which the controller stores as empty strings.
    """
    return {
        "name": name,
        "verifier_type": verifier_type,
        "public_key": public_key,
        "cert_issuer": cert_issuer,
        "cert_subject": cert_subject,
        "comment": comment,
    }


def _validate_verifier_material(
    verifier_type: str, public_key: str, cert_issuer: str, cert_subject: str
) -> None:
    """Reject verifier inputs that would trust more than the caller means to.

    Local check only: nothing has been sent to the controller when this raises.
    The controller accepts all of these, which is exactly the problem - a
    'keyless' verifier with a blank issuer or subject matches ANY signing
    identity, and a 'keypair' verifier with no key has nothing to verify against.
    """
    if verifier_type == "keypair":
        if not public_key.strip():
            raise ValidationError_(
                "verifier_type='keypair' needs a 'public_key' (PEM cosign public key). "
                "Without one the verifier has nothing to check signatures against. "
                "Nothing was sent to the controller."
            )
    elif verifier_type == "keyless":
        missing = [
            field
            for field, value in (("cert_issuer", cert_issuer), ("cert_subject", cert_subject))
            if not value.strip()
        ]
        if missing:
            raise ValidationError_(
                f"verifier_type='keyless' needs both 'cert_issuer' and 'cert_subject'; "
                f"missing: {', '.join(missing)}. An empty value is a WILDCARD - the "
                f"verifier would accept a signing certificate from any issuer or any "
                f"subject, which admits attacker-signed images. Nothing was sent to the "
                f"controller."
            )


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the sigstore tools, gating the read and write toolsets separately."""
    if settings.toolset_enabled("vulnerability"):
        _register_reads(mcp)
    if settings.toolset_enabled("scan_ops"):
        _register_writes(mcp)


def _register_reads(mcp: FastMCP) -> None:
    """Read tools tagged ``vulnerability``: the sigstore trust configuration."""

    @mcp.tool(
        name="nv_list_sigstore_roots",
        annotations=READ_ONLY,
        tags={"vulnerability", "read"},
    )
    async def nv_list_sigstore_roots(ctx: Context) -> SigstoreRootList:
        """List every sigstore root of trust and the verifiers under each one.

        This is the complete picture of which image signatures the cluster is willing
        to trust. An empty list means NO signature verification is configured at all,
        whatever admission control reports about itself - read it that way before
        concluding images are being checked. A root with an empty 'verifiers' list is
        equally inert: the root supplies the Fulcio/Rekor material, but only a verifier
        expresses "this key, or this identity, may sign our images".

        Calls GET /v1/scan/sigstore/root_of_trust.
        """
        app = app_context(ctx)
        body = await app.client.request("GET", "/v1/scan/sigstore/root_of_trust")
        items = _unwrap_list(body, ROOTS_KEY)
        limit = app.settings.max_items
        page_items = items[:limit]
        truncated = len(items) > limit
        return SigstoreRootList(
            page=Page(
                start=0,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"The controller returned {len(items)} roots of trust; only the first "
                    f"{limit} are shown (NV_MAX_ITEMS). This route does not page - raise "
                    f"NV_MAX_ITEMS to see the rest."
                    if truncated
                    else None
                ),
            ),
            roots_of_trust=[SigstoreRootOfTrust.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_sigstore_root",
        annotations=READ_ONLY,
        tags={"vulnerability", "read"},
    )
    async def nv_get_sigstore_root(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(min_length=1, description="Root of trust name, from nv_list_sigstore_roots."),
        ],
    ) -> SigstoreRootOfTrust:
        """Read one sigstore root of trust, its trust material and its verifiers.

        Read this before changing anything under the root. 'cfg_type' tells you whether
        you may: a 'ground' or 'federal' root is owned by config import or by the
        federation primary and the controller refuses edits to it. The PEM fields are
        public material and are returned in full deliberately - comparing the exact key
        you expect against the exact key that is installed is the only way to tell a
        correct trust anchor from a plausible-looking wrong one.

        Calls GET /v1/scan/sigstore/root_of_trust/{root_name}.
        """
        app = app_context(ctx)
        body = await app.client.request("GET", f"/v1/scan/sigstore/root_of_trust/{root_name}")
        raw = _unwrap_root(body)
        if not raw:
            raise NotFoundError(
                f"no sigstore root of trust named {root_name!r}. List the configured "
                "roots with nv_list_sigstore_roots."
            )
        return SigstoreRootOfTrust.from_api(raw)

    @mcp.tool(
        name="nv_list_sigstore_verifiers",
        annotations=READ_ONLY,
        tags={"vulnerability", "read"},
    )
    async def nv_list_sigstore_verifiers(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Root of trust whose verifiers to list, from nv_list_sigstore_roots.",
            ),
        ],
    ) -> SigstoreVerifierList:
        """List the verifiers defined under one sigstore root of trust.

        A verifier is the thing that actually accepts a signature: 'keypair' matches a
        cosign public key, 'keyless' matches a signing certificate's OIDC issuer and
        subject. Check that both keyless fields hold real values - the controller stores
        an empty 'cert_issuer' or 'cert_subject' happily, and an empty one matches ANY
        identity, so a verifier that looks configured can be accepting anything signed
        by anyone. An empty list means this root vouches for nothing.

        Calls GET /v1/scan/sigstore/root_of_trust/{root_name}/verifier.
        """
        app = app_context(ctx)
        body = await app.client.request(
            "GET", f"/v1/scan/sigstore/root_of_trust/{root_name}/verifier"
        )
        items = _unwrap_list(body, VERIFIERS_KEY)
        limit = app.settings.max_items
        page_items = items[:limit]
        truncated = len(items) > limit
        return SigstoreVerifierList(
            page=Page(
                start=0,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"The controller returned {len(items)} verifiers; only the first {limit} "
                    f"are shown (NV_MAX_ITEMS). This route does not page - raise NV_MAX_ITEMS "
                    f"to see the rest."
                    if truncated
                    else None
                ),
            ),
            root_name=root_name,
            verifiers=[SigstoreVerifierEntry.from_api(item) for item in page_items],
        )


def _register_writes(mcp: FastMCP) -> None:
    """Write tools tagged ``scan_ops``: creating and destroying image-signature trust."""

    @mcp.tool(
        name="nv_create_sigstore_root",
        annotations=MUTATING_CREATE,
        tags={"scan_ops", "write"},
    )
    async def nv_create_sigstore_root(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for the new root of trust. It is the id every verifier tool "
                "takes. A duplicate name is rejected by the controller.",
            ),
        ],
        is_private: Annotated[
            bool,
            Field(
                description="True when this root anchors to a PRIVATE sigstore deployment and "
                "therefore needs your own 'root_cert' and 'rekor_public_key'. False uses the "
                "public sigstore instance."
            ),
        ] = False,
        rootless_keypairs_only: Annotated[
            bool,
            Field(
                description="True restricts this root to bare cosign keypair verifiers, with no "
                "certificate chain involved. apis.yaml records that it OVERRIDES 'is_private'."
            ),
        ] = False,
        rekor_public_key: Annotated[
            str,
            Field(
                description="PEM public key of the Rekor transparency log this root trusts. "
                "Public material, not a credential. Required in practice for a private root; "
                "omitted from the request body when empty."
            ),
        ] = "",
        root_cert: Annotated[
            str,
            Field(
                description="PEM Fulcio root certificate this root anchors to. Public material. "
                "Omitted from the request body when empty."
            ),
        ] = "",
        sct_public_key: Annotated[
            str,
            Field(
                description="PEM public key used to verify the signed certificate timestamp. "
                "Public material. Omitted from the request body when empty."
            ),
        ] = "",
        comment: Annotated[
            str,
            Field(description="Why this root exists and who owns the material. Shown in the UI."),
        ] = "",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit "
                "on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Create a sigstore root of trust: the trust anchor image signatures chain to.

        Creating a root changes NOTHING about what the cluster admits on its own. A root
        holds only the Fulcio/Rekor material; no image is verified until you add a
        verifier under it with nv_create_sigstore_verifier, and nothing is enforced until
        admission control is configured to require signature verification. That order
        matters: a root created with the wrong 'root_cert' or 'rekor_public_key' looks
        correct in the UI and fails no call - it simply anchors to material an attacker
        may control, and every verifier you later add inherits that. Paste the PEM
        material from the source that owns it, then read it back with
        nv_get_sigstore_root and compare it character for character. All three PEM
        fields are PUBLIC keys and certificates; no private key is ever sent here.

        Calls POST /v1/scan/sigstore/root_of_trust with {"name":..., "is_private":..., "rootless_keypairs_only":..., "comment":..., PEM fields}.
        """
        app = app_context(ctx)
        # 1. build the payload (apis.go REST_SigstoreRootOfTrust_POST).
        payload = _root_post_body(
            name=name,
            is_private=is_private,
            rootless_keypairs_only=rootless_keypairs_only,
            rekor_public_key=rekor_public_key,
            root_cert=root_cert,
            sct_public_key=sct_public_key,
            comment=comment,
        )
        supplied = [
            field
            for field in ("rekor_public_key", "root_cert", "sct_public_key")
            if field in payload
        ]
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_create_sigstore_root",
            toolset="scan_ops",
            target=name,
            effect=(
                f"Create sigstore root of trust {name!r} (is_private={is_private}, "
                f"rootless_keypairs_only={rootless_keypairs_only}) carrying "
                f"{len(supplied)} PEM field(s): {', '.join(supplied) or 'none'}. The root is "
                f"a TRUST ANCHOR: every verifier added under it, and therefore every image "
                f"signature accepted through it, chains to this material. Wrong or "
                f"attacker-supplied material fails no call and shows no error - it just "
                f"makes the cluster trust the wrong signer. "
                + (
                    "No PEM material was supplied, so this root anchors to the public "
                    "sigstore instance's defaults; confirm that is what you intend for a "
                    f"root marked is_private={is_private}. "
                    if not supplied
                    else ""
                )
                + f"The root verifies nothing by itself: no image signature is checked until "
                f"a verifier is added with nv_create_sigstore_verifier. Read the result back "
                f"with nv_get_sigstore_root({name!r}) and compare the PEM material against "
                f"its source."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "POST", "/v1/scan/sigstore/root_of_trust", json=payload
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_create_sigstore_root",
            target=name,
            effect=(
                f"sigstore root of trust {name} created with {len(supplied)} PEM field(s); it "
                f"has no verifiers yet, so it verifies no image signature. Verify the stored "
                f"material with nv_get_sigstore_root({name!r})."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_sigstore_root",
        annotations=MUTATING_IDEMPOTENT,
        tags={"scan_ops", "write"},
    )
    async def nv_update_sigstore_root(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Root of trust to change, from nv_list_sigstore_roots.",
            ),
        ],
        rekor_public_key: Annotated[
            str | None,
            Field(
                description="Replacement PEM Rekor transparency-log public key. Omit to leave "
                "the stored value untouched; an empty string CLEARS it."
            ),
        ] = None,
        root_cert: Annotated[
            str | None,
            Field(
                description="Replacement PEM Fulcio root certificate. Omit to leave the stored "
                "value untouched; an empty string CLEARS it."
            ),
        ] = None,
        sct_public_key: Annotated[
            str | None,
            Field(
                description="Replacement PEM signed-certificate-timestamp public key. Omit to "
                "leave the stored value untouched; an empty string CLEARS it."
            ),
        ] = None,
        comment: Annotated[
            str | None,
            Field(description="Replacement comment. Omit to leave it untouched."),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit "
                "on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Replace the PEM trust material or the comment on one sigstore root of trust.

        Only the fields you pass are changed. apis.go declares every field of
        REST_SigstoreRootOfTrust_PATCH as a POINTER with omitempty - an omitted key means
        "not modified" - so this tool sends nothing it was not given; a key present with
        a default value would silently overwrite a trust anchor. The root's 'name',
        'is_private' and 'rootless_keypairs_only' are NOT in the PATCH struct and cannot
        be changed here: delete the root and create it again if you need different ones.

        Changing this material re-points every verifier under the root at once. Images
        whose signatures chained to the old material stop verifying, and images signed
        against the new material start being accepted - neither transition raises an
        error. Read the current values with nv_get_sigstore_root first and keep a copy.

        Calls PATCH /v1/scan/sigstore/root_of_trust/{root_name} with only the supplied fields.
        """
        app = app_context(ctx)
        # 1. build the payload: apis.go REST_SigstoreRootOfTrust_PATCH is all pointers
        #    with omitempty, so an absent key is "not modified". Only supplied fields
        #    are written; "" is a deliberate clear and is therefore sent.
        payload: dict[str, Any] = {}
        for key, value in (
            ("rekor_public_key", rekor_public_key),
            ("root_cert", root_cert),
            ("sct_public_key", sct_public_key),
            ("comment", comment),
        ):
            if value is not None:
                payload[key] = value
        if not payload:
            raise ValidationError_(
                "nv_update_sigstore_root needs at least one of rekor_public_key, root_cert, "
                "sct_public_key or comment. Note that 'name', 'is_private' and "
                "'rootless_keypairs_only' cannot be changed - they are absent from "
                "REST_SigstoreRootOfTrust_PATCH. No request was sent to the controller."
            )
        trust_fields = sorted(k for k in payload if k != "comment")
        cleared = sorted(k for k, v in payload.items() if k != "comment" and v == "")

        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_update_sigstore_root",
            toolset="scan_ops",
            target=root_name,
            effect=(
                f"Update sigstore root of trust {root_name!r}: overwrite the field(s) "
                f"{', '.join(sorted(payload))}. Fields not listed keep their stored value "
                f"(an omitted key means 'not modified')."
                + (
                    f" This REPLACES TRUST MATERIAL ({', '.join(trust_fields)}). Every "
                    f"verifier under {root_name!r} chains to it, so image signatures that "
                    f"verified against the old material stop verifying and signatures made "
                    f"against the new material start being accepted - both silently, with "
                    f"no error and no admission-control warning."
                    if trust_fields
                    else ""
                )
                + (
                    f" WARNING: {', '.join(cleared)} becomes an EMPTY string, which "
                    f"CLEARS that trust material rather than leaving it alone. If you meant "
                    f"to leave it alone, omit the argument entirely."
                    if cleared
                    else ""
                )
                + f" Read the current values with nv_get_sigstore_root({root_name!r}) and "
                f"keep a copy before confirming."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "PATCH", f"/v1/scan/sigstore/root_of_trust/{root_name}", json=payload
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_update_sigstore_root",
            target=root_name,
            effect=(
                f"sigstore root of trust {root_name} updated: {', '.join(sorted(payload))} "
                f"replaced. Verify with nv_get_sigstore_root({root_name!r})."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_sigstore_root",
        annotations=MUTATING,
        tags={"scan_ops", "write"},
    )
    async def nv_delete_sigstore_root(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Root of trust to delete, from nv_list_sigstore_roots. Read it with "
                "nv_get_sigstore_root first: every verifier listed there goes with it.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit "
                "on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete a sigstore root of trust AND every verifier defined under it.

        This is a cascade, and it silently turns off signature enforcement. Deleting the
        root deletes all of its verifiers, so any image that was admitted because one of
        those verifiers vouched for its signature is no longer signature-checked at all.
        Nothing reports the gap: admission control keeps reporting itself as enabled and
        keeps admitting images, because it has no verifier left with an opinion about
        them - the check does not fail, it stops existing. There is no undo and the
        controller keeps no copy, so recovery means re-creating the root and every
        verifier by hand from the original PEM material.

        Read nv_get_sigstore_root(root_name) first and keep its output - that is the only
        record of what you are about to destroy. If you only want to remove one signer,
        delete that verifier with nv_delete_sigstore_verifier instead.

        Calls DELETE /v1/scan/sigstore/root_of_trust/{root_name}.
        """
        app = app_context(ctx)
        # 1. no request body on this route.
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_delete_sigstore_root",
            toolset="scan_ops",
            target=root_name,
            effect=(
                f"Delete sigstore root of trust {root_name!r} AND EVERY VERIFIER UNDER IT. "
                f"Signature verification stops for every image that relied on those "
                f"verifiers: those images are no longer signature-checked at all, and "
                f"unsigned or attacker-signed images that the verifiers would have rejected "
                f"are admitted. Nothing raises an error and nothing reports the gap - "
                f"admission control continues to report itself as ENABLED, because the check "
                f"does not fail, it stops existing. There is no undo and the controller keeps "
                f"no copy: recovery means re-creating the root and every verifier by hand "
                f"from the original PEM material. Run nv_get_sigstore_root({root_name!r}) "
                f"first and keep its output - it is the only record of what this destroys. "
                f"To remove a single signer, use nv_delete_sigstore_verifier instead."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "DELETE", f"/v1/scan/sigstore/root_of_trust/{root_name}"
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_delete_sigstore_root",
            target=root_name,
            effect=(
                f"sigstore root of trust {root_name} and all of its verifiers deleted; images "
                f"that relied on them are no longer signature-checked and admission control "
                f"still reports itself as enabled"
            ),
            payload={},
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_create_sigstore_verifier",
        annotations=MUTATING_CREATE,
        tags={"scan_ops", "write"},
    )
    async def nv_create_sigstore_verifier(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Root of trust to add the verifier to, from nv_list_sigstore_roots.",
            ),
        ],
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for the new verifier, unique within the root of trust.",
            ),
        ],
        verifier_type: Annotated[
            Literal["keypair", "keyless"],
            Field(
                description="'keypair' accepts signatures made by the cosign private key "
                "matching 'public_key'. 'keyless' accepts signatures whose Fulcio certificate "
                "was issued by 'cert_issuer' to 'cert_subject'."
            ),
        ],
        public_key: Annotated[
            str,
            Field(
                description="Cosign PUBLIC key in PEM form. Required for verifier_type="
                "'keypair'. Whoever holds the matching PRIVATE key can sign any image and have "
                "it accepted, so paste this only from a source you trust."
            ),
        ] = "",
        cert_issuer: Annotated[
            str,
            Field(
                description="Keyless: the exact OIDC issuer the signing certificate must come "
                "from, e.g. 'https://token.actions.githubusercontent.com'. Required for "
                "verifier_type='keyless' - an empty value would match ANY issuer."
            ),
        ] = "",
        cert_subject: Annotated[
            str,
            Field(
                description="Keyless: the exact identity the signing certificate must carry, "
                "e.g. the full workflow URI or a signer's email. Required for "
                "verifier_type='keyless' - an empty value would match ANY subject."
            ),
        ] = "",
        comment: Annotated[
            str,
            Field(description="Which signer this represents and who owns it. Shown in the UI."),
        ] = "",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit "
                "on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Add a verifier to a sigstore root of trust: grant one signer the right to sign your images.

        THIS EXPANDS WHAT THE CLUSTER TRUSTS. A verifier is an accept rule, not a
        restriction: every image carrying a signature this verifier matches becomes
        admissible. A wrong or attacker-supplied 'public_key' means whoever holds the
        matching private key can sign ANY image and have the cluster accept it, and a
        'keyless' verifier whose 'cert_issuer' or 'cert_subject' is broader than you
        meant accepts every identity inside that scope. None of this fails loudly - the
        controller answers 200 and images simply start being admitted.

        This tool refuses a 'keypair' verifier with no public key and a 'keyless'
        verifier with a blank issuer or subject, because the controller accepts both and
        an empty keyless field is a wildcard. Copy the key or the identity from the
        signer's own published source, never from an image or a registry, and confirm it
        afterwards with nv_list_sigstore_verifiers. Only public material is sent.

        Calls POST /v1/scan/sigstore/root_of_trust/{root_name}/verifier with {"name":..., "verifier_type":..., "public_key":..., "cert_issuer":..., "cert_subject":..., "comment":...}.
        """
        app = app_context(ctx)
        # Local input validation first: it must reject before the guard is consulted
        # and without touching the controller.
        _validate_verifier_material(verifier_type, public_key, cert_issuer, cert_subject)

        # 1. build the payload (apis.go REST_SigstoreVerifier; all six always sent).
        payload = _verifier_post_body(
            name=name,
            verifier_type=verifier_type,
            public_key=public_key,
            cert_issuer=cert_issuer,
            cert_subject=cert_subject,
            comment=comment,
        )
        identity = (
            f"cosign public key ({len(public_key)} chars)"
            if verifier_type == "keypair"
            else f"issuer {cert_issuer!r} + subject {cert_subject!r}"
        )
        target = f"{root_name}/{name}"
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_create_sigstore_verifier",
            toolset="scan_ops",
            target=target,
            effect=(
                f"Add {verifier_type} verifier {name!r} to sigstore root of trust "
                f"{root_name!r}, trusting {identity}. THIS EXPANDS WHAT THE CLUSTER "
                f"ACCEPTS: from now on any image carrying a signature this verifier matches "
                f"is admissible. "
                + (
                    "Whoever holds the PRIVATE key matching this public key can sign ANY "
                    "image and have the cluster accept it, so confirm the key came from the "
                    "signer's own published source and not from an image or a registry. "
                    if verifier_type == "keypair"
                    else "Any signing certificate issued by that issuer to that subject is "
                    "accepted, so confirm the subject is as narrow as you intend - a "
                    "broader subject than you meant admits every identity inside it. "
                )
                + f"Nothing about a wrong value fails loudly: the controller answers 200 and "
                f"images simply start being admitted. Verify with "
                f"nv_list_sigstore_verifiers({root_name!r}) afterwards. Only public material "
                f"is sent; no private key is involved."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "POST", f"/v1/scan/sigstore/root_of_trust/{root_name}/verifier", json=payload
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_create_sigstore_verifier",
            target=target,
            effect=(
                f"{verifier_type} verifier {name} added to root of trust {root_name}, "
                f"trusting {identity}; images signed to match it are now admissible. Verify "
                f"with nv_list_sigstore_verifiers({root_name!r})."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_sigstore_verifier",
        annotations=MUTATING_IDEMPOTENT,
        tags={"scan_ops", "write"},
    )
    async def nv_update_sigstore_verifier(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(min_length=1, description="Root of trust the verifier belongs to."),
        ],
        verifier_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Verifier to change, from nv_list_sigstore_verifiers.",
            ),
        ],
        verifier_type: Annotated[
            Literal["keypair", "keyless"] | None,
            Field(
                description="New verifier type. Omit to leave it unchanged. Switching type "
                "changes which fields are consulted without clearing the others."
            ),
        ] = None,
        public_key: Annotated[
            str | None,
            Field(
                description="Replacement cosign PUBLIC key in PEM form. Omit to leave the "
                "stored key untouched; an empty string CLEARS it, which for a keypair verifier "
                "leaves it with nothing to verify against."
            ),
        ] = None,
        cert_issuer: Annotated[
            str | None,
            Field(
                description="Replacement keyless OIDC issuer. Omit to leave it untouched; an "
                "empty string CLEARS it, and a cleared issuer matches ANY issuer."
            ),
        ] = None,
        cert_subject: Annotated[
            str | None,
            Field(
                description="Replacement keyless certificate subject. Omit to leave it "
                "untouched; an empty string CLEARS it, and a cleared subject matches ANY "
                "subject."
            ),
        ] = None,
        comment: Annotated[
            str | None,
            Field(description="Replacement comment. Omit to leave it untouched."),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit "
                "on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Change which signer one sigstore verifier accepts.

        Only the fields you pass are changed. apis.go declares every field of
        REST_SigstoreVerifier_PATCH as a POINTER with omitempty - an omitted key means
        "not modified" - so this tool sends nothing it was not given; a key present with
        a default value would silently repoint a trust decision. The verifier's 'name'
        is not in the PATCH struct and cannot be changed.

        Repointing a verifier changes what the cluster admits, in both directions and
        without any error: images signed by the old signer stop verifying, images signed
        by the new one start being accepted. Two edits are especially easy to get wrong
        and are called out in the plan - setting 'public_key' to a key you have not
        checked hands image-signing authority to whoever holds the matching private key,
        and setting 'cert_issuer' or 'cert_subject' to an empty string turns that field
        into a WILDCARD that matches any identity. Read the current values with
        nv_list_sigstore_verifiers first.

        Calls PATCH /v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name} with only the supplied fields.
        """
        app = app_context(ctx)
        # 1. build the payload: apis.go REST_SigstoreVerifier_PATCH is all pointers with
        #    omitempty, so an absent key is "not modified". "" is a deliberate clear.
        payload: dict[str, Any] = {}
        for key, value in (
            ("verifier_type", verifier_type),
            ("public_key", public_key),
            ("cert_issuer", cert_issuer),
            ("cert_subject", cert_subject),
            ("comment", comment),
        ):
            if value is not None:
                payload[key] = value
        if not payload:
            raise ValidationError_(
                "nv_update_sigstore_verifier needs at least one of verifier_type, "
                "public_key, cert_issuer, cert_subject or comment. The verifier's 'name' "
                "cannot be changed - it is absent from REST_SigstoreVerifier_PATCH. No "
                "request was sent to the controller."
            )
        wildcards = sorted(key for key in ("cert_issuer", "cert_subject") if payload.get(key) == "")
        target = f"{root_name}/{verifier_name}"
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_update_sigstore_verifier",
            toolset="scan_ops",
            target=target,
            effect=(
                f"Update sigstore verifier {verifier_name!r} under root of trust "
                f"{root_name!r}: overwrite the field(s) {', '.join(sorted(payload))}. Not listed "
                f"keep their stored value (an omitted key means 'not modified'). This "
                f"REPOINTS A TRUST DECISION: images signed to match the old settings stop "
                f"verifying and images signed to match the new ones start being accepted, "
                f"both silently and with no admission-control warning."
                + (
                    " Setting 'public_key' hands image-signing authority to whoever holds "
                    "the matching PRIVATE key - confirm it came from the signer's own "
                    "published source."
                    if "public_key" in payload and payload["public_key"] != ""
                    else ""
                )
                + (
                    f" WARNING: {', '.join(wildcards)} becomes an EMPTY string, which "
                    f"is a WILDCARD - the verifier would accept a signing certificate from "
                    f"ANY issuer or ANY subject, admitting attacker-signed images. Omit the "
                    f"argument entirely if you meant to leave it alone."
                    if wildcards
                    else ""
                )
                + f" Read the current values with nv_list_sigstore_verifiers({root_name!r}) "
                f"before confirming."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "PATCH",
            f"/v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name}",
            json=payload,
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_update_sigstore_verifier",
            target=target,
            effect=(
                f"sigstore verifier {verifier_name} under {root_name} updated: "
                f"{', '.join(sorted(payload))} replaced. Verify with "
                f"nv_list_sigstore_verifiers({root_name!r})."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_sigstore_verifier",
        annotations=MUTATING,
        tags={"scan_ops", "write"},
    )
    async def nv_delete_sigstore_verifier(
        ctx: Context,
        root_name: Annotated[
            str,
            Field(min_length=1, description="Root of trust the verifier belongs to."),
        ],
        verifier_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Verifier to delete, from nv_list_sigstore_verifiers.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit "
                "on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete one verifier from a sigstore root of trust: revoke one signer.

        The narrow, correct way to stop trusting a single signer - prefer this over
        nv_delete_sigstore_root, which cascades to every verifier under the root. The
        failure mode still runs both ways. Images that were admitted only because this
        verifier vouched for their signature stop verifying, and if admission control
        requires verification those deployments are BLOCKED the next time they roll;
        but if this was the last verifier under the root, images that relied on it are
        no longer signature-checked at all and unsigned images pass, while admission
        control continues to report itself as enabled.

        Check nv_list_sigstore_verifiers(root_name) first to see which of those two you
        are in, and keep the verifier's material - there is no undo and the controller
        keeps no copy.

        Calls DELETE /v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name}.
        """
        app = app_context(ctx)
        # 1. no request body on this route.
        target = f"{root_name}/{verifier_name}"
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_delete_sigstore_verifier",
            toolset="scan_ops",
            target=target,
            effect=(
                f"Delete sigstore verifier {verifier_name!r} from root of trust "
                f"{root_name!r}. The cluster stops accepting signatures made by that signer: "
                f"images admitted only because this verifier vouched for them stop verifying, "
                f"and where admission control requires verification those deployments are "
                f"BLOCKED on their next roll. If this is the LAST verifier under "
                f"{root_name!r}, the opposite happens instead - images that relied on it are "
                f"no longer signature-checked at all, unsigned and attacker-signed images "
                f"pass, and admission control still reports itself as enabled. Run "
                f"nv_list_sigstore_verifiers({root_name!r}) first to see which case this is, "
                f"and keep a copy of the verifier's material: there is no undo."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "DELETE", f"/v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name}"
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_delete_sigstore_verifier",
            target=target,
            effect=(
                f"sigstore verifier {verifier_name} deleted from root of trust {root_name}; "
                f"signatures from that signer are no longer accepted. Check what remains with "
                f"nv_list_sigstore_verifiers({root_name!r})."
            ),
            payload={},
            controller_response=response if isinstance(response, dict) else {},
        )
