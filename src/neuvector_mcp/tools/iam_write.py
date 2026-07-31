"""Mutating identity and access tools: users and API keys. Toolset ``iam_write``.

Every tool here follows the five-step mutating body of SPEC 7.4, in this order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

Secrets (SPEC 11, rule N8; Part D section D.0.4). Two of these five tools touch a
credential and they treat it in opposite directions:

* ``nv_create_user`` *sends* a password. The real value exists in exactly one
  variable, ``wire_payload``, which is handed to the client and to nothing else.
  Everything the caller ever sees - the plan, the applied outcome, the confirm
  token - is derived from ``safe_payload = redact_secrets(wire_payload)``, where
  the password reads ``"***"``.
* ``nv_create_api_key`` *receives* a secret the controller shows exactly once, so
  its ``controller_response`` is deliberately NOT redacted. That single exception
  is commented at the call site; see the note there before "cleaning it up".

No tool in this module logs an argument value, a payload or a controller body.
Audit records come from ``AuditMiddleware`` alone and carry argument key names
only.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..guard import authorise_write
from ..models import WriteOutcome, redact_secrets

#: Creates something, or starts an action, that did not exist before. Not
#: destructive; not idempotent (a second call creates or starts again).
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
#: Reversible configuration change. Re-applying the same arguments is a no-op.
MUTATING_UPDATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Destroys a stored object. A second call fails with controller code 7.
MUTATING_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
#: Traffic-affecting but converging: re-applying the same arguments is a no-op.
MUTATING_DESTRUCTIVE_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
)

_CONFIRM_DESCRIPTION = (
    "Confirmation token from the plan returned by the first call. Omit on the "
    "first call to preview the change."
)


def _normalise_role_domains(role_domains: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """Sort each role's namespace list so the payload, and its token, are stable.

    ``role_domains`` is ``map<role, array<namespace>>`` in Appendix B
    (``RESTUser.role_domains``, ``RESTApikey.role_domains``). Argument order must
    not change the confirmation token, so the namespaces are sorted before the
    payload is built.
    """
    return {role: sorted(namespaces) for role, namespaces in (role_domains or {}).items()}


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the iam_write toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("iam_write"):
        return

    @mcp.tool(
        name="nv_create_user",
        annotations=MUTATING_CREATE,
        tags={"iam_write", "write"},
    )
    async def nv_create_user(
        ctx: Context,
        username: Annotated[
            str,
            Field(
                min_length=1,
                description="Login name for the new local user. It also becomes the "
                "account's fullname, which is the id nv_update_user_role and "
                "nv_delete_user take.",
            ),
        ],
        password: Annotated[
            str,
            Field(
                min_length=1,
                description="Initial password. It is sent to the controller once, is "
                "never logged, and is shown as '***' in the returned payload - this "
                "server cannot read it back afterwards. A password that fails the "
                "cluster's password profile is rejected with code 14.",
            ),
        ],
        role: Annotated[
            str,
            Field(
                min_length=1,
                description="Global role, e.g. a name from nv_list_roles. This is the "
                "account's ceiling everywhere except the namespaces named in "
                "role_domains.",
            ),
        ],
        email: Annotated[str, Field(description="Contact email for the account.")] = "",
        role_domains: Annotated[
            dict[str, list[str]] | None,
            Field(
                description="Namespace-scoped roles as role name -> list of namespaces, "
                "e.g. {'admin': ['staging']}. Use this instead of a broad global role "
                "wherever it will do."
            ),
        ] = None,
        timeout_s: Annotated[
            int | None,
            Field(description="Idle session timeout in seconds. Omit for the cluster default."),
        ] = None,
        locale: Annotated[
            str | None,
            Field(
                description="UI locale for this account, e.g. 'en'. Omit for the cluster default."
            ),
        ] = None,
        confirm: Annotated[str | None, Field(description=_CONFIRM_DESCRIPTION)] = None,
    ) -> WriteOutcome:
        """Create a local user account with a role.

        The new account can log in immediately with the password you supply, so scope
        'role' to the least it needs and prefer 'role_domains' - a namespace-scoped role
        - over a broad global one. The password is sent to the controller once and is
        write-only from here: it is never logged, the returned payload shows '***', and
        no read tool can retrieve it, so deliver it to the human out of band and have
        them change it. A duplicate username is rejected with code 13 and a password
        that fails the cluster's password profile with code 14. Verify the result with
        nv_list_users, which reports the account's fullname - the id the other IAM tools
        take.

        Calls POST /v1/user with {"user": {...}}.
        """
        app = app_context(ctx)

        # --- 1. build payload -------------------------------------------------
        # 'server' is deliberately omitted: an unset server is what makes the
        # account local. Remote accounts are created by the identity provider.
        user: dict[str, Any] = {
            "fullname": username,
            "username": username,
            "password": password,
            "email": email,
            "role": role,
        }
        if role_domains is not None:
            user["role_domains"] = _normalise_role_domains(role_domains)
        if timeout_s is not None:
            user["timeout"] = timeout_s
        if locale is not None:
            user["locale"] = locale
        wire_payload: dict[str, Any] = {"user": user}
        # The two-payload rule (D.0.4): wire_payload is handed to the client and
        # to nothing else; safe_payload is the only copy the caller, the guard and
        # the confirm token ever see. user.password reads "***" in safe_payload.
        safe_payload = redact_secrets(wire_payload)

        # --- 2. guard, on the REDACTED payload --------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_create_user",
            toolset="iam_write",
            target=username,
            effect=(
                f"Create local user {username!r} with global role {role!r}"
                + (f" and namespace roles {sorted(role_domains or {})}." if role_domains else ".")
                + " The account can log in immediately."
            ),
            payload=safe_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim --------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call, with the REAL password -----------------------
        response = await app.client.request("POST", "/v1/user", json=wire_payload)

        # --- 5. outcome, still redacted ---------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_create_user",
            target=username,
            effect=f"local user {username} created with role {role}",
            payload=safe_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_user_role",
        annotations=MUTATING_UPDATE,
        tags={"iam_write", "write"},
    )
    async def nv_update_user_role(
        ctx: Context,
        fullname: Annotated[
            str,
            Field(
                min_length=1,
                description="Account id from nv_list_users. For a local account this is "
                "the username; for a remote one it also identifies the auth server.",
            ),
        ],
        role: Annotated[
            str,
            Field(
                min_length=1,
                description="New global role, e.g. a name from nv_list_roles. This "
                "replaces the account's current global role outright.",
            ),
        ],
        role_domains: Annotated[
            dict[str, list[str]] | None,
            Field(
                description="Namespace-scoped roles as role name -> list of namespaces, "
                "e.g. {'admin': ['staging']}. Passing this REPLACES the account's "
                "existing namespace roles; omit it to send none."
            ),
        ] = None,
        confirm: Annotated[str | None, Field(description=_CONFIRM_DESCRIPTION)] = None,
    ) -> WriteOutcome:
        """Change a user account's global role, and optionally its namespace roles.

        This replaces the account's global role outright rather than adding to it, so a
        downgrade takes effect immediately and the person loses whatever the old role
        allowed. Two ways to hurt yourself: changing your own account's role can remove
        your ability to change it back, and removing the last admin leaves nobody who
        can administer the cluster - the controller refuses that second one with code 4,
        but not the first. Read the account's current role with nv_list_users before
        calling, and prefer role_domains, which scopes power to named namespaces, over a
        broad global role.

        Calls PATCH /v1/user/{fullname}/role/{role} with {"config": {...}}.
        """
        app = app_context(ctx)

        # --- 1. build payload -------------------------------------------------
        # Endpoint choice (Part D): PATCH /v1/user/{fullname}/role/{role} is used
        # rather than PATCH /v1/user/{fullname} because the role travels in a
        # VERIFIED path, so even if this defensive body shape is wrong the
        # controller still receives an unambiguous global-role assignment; and
        # because the general user route shares its body with 'password', 'email'
        # and 'timeout', where a malformed partial body could clear an unrelated
        # field, including a credential. The role route has no such reach.
        #
        # BLOCKED (schema): RESTUserRoleDomainsConfigData is absent from Appendix
        # B. Field names below come from types that ARE in B - role_domains is
        # map<role, array<namespace>> on RESTUser and RESTApikey - and the
        # {"config": {"name": ...}} wrapper follows every REST*ConfigData in B.
        # No secret field here, so the safe payload IS the wire payload.
        wire_payload: dict[str, Any] = {
            "config": {
                "name": fullname,
                "role_domains": _normalise_role_domains(role_domains),
            }
        }

        # --- 2. guard ---------------------------------------------------------
        # The role travels in the URL PATH, so it is in neither the payload nor
        # the bare account name. confirm_token() hashes operation, target and
        # payload only, so with target=fullname a token previewed for one role
        # would also authorise any other role - the handshake would fail to gate
        # the single field this tool exists to change. Folding the role into the
        # guard's target is what binds the token to it. The controller call and
        # the request body are untouched by this.
        guard_target = f"{fullname} role={role}"
        plan = authorise_write(
            app.settings,
            operation="nv_update_user_role",
            toolset="iam_write",
            target=guard_target,
            effect=(
                f"Set global role of account {fullname!r} to {role!r}"
                + (
                    f", with namespace roles {sorted(role_domains or {})}"
                    if role_domains
                    else ", clearing any namespace roles"
                )
                + ". The change takes effect on the account's next request."
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim --------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call -----------------------------------------------
        response = await app.client.request(
            "PATCH", f"/v1/user/{fullname}/role/{role}", json=wire_payload
        )

        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_update_user_role",
            target=fullname,
            effect=f"global role of account {fullname} set to {role}",
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_user",
        annotations=MUTATING_DESTRUCTIVE,
        tags={"iam_write", "write"},
    )
    async def nv_delete_user(
        ctx: Context,
        fullname: Annotated[
            str,
            Field(
                min_length=1,
                description="Account id from nv_list_users. For a local account this is "
                "the username.",
            ),
        ],
        confirm: Annotated[str | None, Field(description=_CONFIRM_DESCRIPTION)] = None,
    ) -> WriteOutcome:
        """Delete a user account.

        Data-destroying: the account, its role assignments and its namespace roles go
        away and the person can no longer log in. API keys are separate objects and are
        NOT removed with the account - audit them with nv_list_api_keys and delete them
        with nv_delete_api_key, or the account's automation keeps working after the
        account is gone. Deleting the last admin, or your own account, is refused with
        code 4 on some controllers and permitted on others, so read nv_list_users first
        and be certain which account this is.

        Calls DELETE /v1/user/{fullname}.
        """
        app = app_context(ctx)

        # --- 1. build payload: none for a DELETE ------------------------------
        # --- 2. guard ---------------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_delete_user",
            toolset="iam_write",
            target=fullname,
            effect=(
                f"Delete user account {fullname!r} and its role assignments. Any API "
                "keys the person created are NOT deleted."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim --------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call -----------------------------------------------
        response = await app.client.request("DELETE", f"/v1/user/{fullname}")

        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_delete_user",
            target=fullname,
            effect=f"user {fullname} deleted",
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_create_api_key",
        annotations=MUTATING_CREATE,
        tags={"iam_write", "write"},
    )
    async def nv_create_api_key(
        ctx: Context,
        apikey_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for the key. It is also the access key half of the "
                "credential and the id nv_delete_api_key takes.",
            ),
        ],
        role: Annotated[
            str,
            Field(
                min_length=1,
                description="Global role the key carries, e.g. a name from "
                "nv_list_roles. This is the key's ceiling; a key with 'admin' can do "
                "anything to the cluster with no human in the loop.",
            ),
        ],
        expiration_type: Annotated[
            str,
            Field(
                min_length=1,
                description="How the key expires, as the controller spells it; see "
                "'expiration_type' on an existing key via nv_list_api_keys for the "
                "accepted values. A non-expiring key is a permanent credential - "
                "justify it.",
            ),
        ],
        role_domains: Annotated[
            dict[str, list[str]] | None,
            Field(
                description="Namespace-scoped roles as role name -> list of namespaces. "
                "Prefer this to a broad global role for automation."
            ),
        ] = None,
        expiration_hours: Annotated[
            int | None,
            Field(
                description="Lifetime in hours, when 'expiration_type' is hour-based. "
                "Set the shortest that works."
            ),
        ] = None,
        description: Annotated[
            str,
            Field(
                description="What this key is for and who owns it. Write it; in six "
                "months it is the only way to know whether the key is still needed."
            ),
        ] = "",
        confirm: Annotated[str | None, Field(description=_CONFIRM_DESCRIPTION)] = None,
    ) -> WriteOutcome:
        """Create an API key and return its secret - the only copy that will ever exist.

        The secret half is generated by the controller, returned once in
        controller_response.apikey.apikey_secret, and is not retrievable afterwards by
        any route: nv_list_api_keys shows metadata only. Store it in a secret manager
        the moment you get it; if you lose it, delete the key and make a new one. Scope
        it hard - the key's role is its ceiling and nobody confirms its requests, so a
        non-expiring admin key is a standing compromise waiting to happen. Prefer a
        short 'expiration_hours' and namespace-scoped 'role_domains'. An expired key
        surfaces to its holder as controller error code 3.

        Calls POST /v1/api_key with {"apikey": {...}}.
        """
        app = app_context(ctx)

        # --- 1. build payload -------------------------------------------------
        # RESTApikeyCreation has no apikey_secret field: the controller generates
        # the secret. The REQUEST therefore carries no credential and the safe
        # payload IS the wire payload.
        apikey: dict[str, Any] = {
            "apikey_name": apikey_name,
            "role": role,
            "expiration_type": expiration_type,
            "description": description,
        }
        if expiration_hours is not None:
            apikey["expiration_hours"] = expiration_hours
        if role_domains is not None:
            apikey["role_domains"] = _normalise_role_domains(role_domains)
        wire_payload: dict[str, Any] = {"apikey": apikey}

        # --- 2. guard ---------------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_create_api_key",
            toolset="iam_write",
            target=apikey_name,
            effect=(
                f"Create API key {apikey_name!r} with global role {role!r} and "
                f"expiration_type {expiration_type!r}. The secret is returned once and "
                "cannot be retrieved again."
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim --------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call -----------------------------------------------
        response = await app.client.request("POST", "/v1/api_key", json=wire_payload)

        # --- 5. outcome -------------------------------------------------------
        # DELIBERATE EXCEPTION, do not "fix" this for consistency (Part D D.0.4):
        # this is the ONLY tool whose controller_response is not passed through
        # redact_secrets. RESTApikeyGenerated.apikey_secret is shown by the
        # controller exactly once and no route can fetch it again, so redacting it
        # here would destroy the credential the caller just asked us to create.
        # 'apikey_secret' stays in SECRET_FIELDS precisely so that every OTHER
        # tool masks it by default; the exception is opt-in, per tool, and visible.
        # The secret is returned to the caller and is still never logged: the audit
        # record carries argument key names only, never a response body.
        return WriteOutcome(
            status="applied",
            operation="nv_create_api_key",
            target=apikey_name,
            effect=f"API key {apikey_name} created with role {role}; secret returned once",
            payload=wire_payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_api_key",
        annotations=MUTATING_DESTRUCTIVE,
        tags={"iam_write", "write"},
    )
    async def nv_delete_api_key(
        ctx: Context,
        access_key: Annotated[
            str,
            Field(
                min_length=1,
                description="The key's access key, which is its apikey_name from nv_list_api_keys.",
            ),
        ],
        confirm: Annotated[str | None, Field(description=_CONFIRM_DESCRIPTION)] = None,
    ) -> WriteOutcome:
        """Revoke an API key immediately.

        Data-destroying and instant: every client still using this key starts failing
        authentication on its next request, which is the point when revoking a leaked
        credential and a self-inflicted outage when the key belonged to a pipeline
        someone forgot to tell you about. Check 'description' and 'created_by_entity' in
        nv_list_api_keys first. There is no undo - the secret cannot be recreated, only
        a new key issued. Note this is also how you revoke the key this MCP server
        itself authenticates with, so make sure it is not that one.

        Calls DELETE /v1/api_key/{accesskey}.
        """
        app = app_context(ctx)

        # --- 1. build payload: none for a DELETE ------------------------------
        # --- 2. guard ---------------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_delete_api_key",
            toolset="iam_write",
            target=access_key,
            effect=(
                f"Revoke API key {access_key!r}. Every client using it starts failing "
                "authentication immediately; the secret cannot be recovered."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim --------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call -----------------------------------------------
        # The documented route takes the ACCESS KEY, which is the key's
        # apikey_name. The undocumented DELETE /v1/api_key/{name} route must not
        # be used: it is not in UNDOCUMENTED_ALLOWLIST and does the same job.
        response = await app.client.request("DELETE", f"/v1/api_key/{access_key}")

        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_delete_api_key",
            target=access_key,
            effect=f"API key {access_key} revoked",
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )
