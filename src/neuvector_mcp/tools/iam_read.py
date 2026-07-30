"""Read-only identity and access tools: users, roles, auth servers, API keys.

Every tool in this module is read-only and tagged ``iam_read``.

Registration contract (identical in every tools/*.py module):

    def register(mcp: FastMCP, settings: Settings) -> None: ...

``register`` adds tools only when their toolset is enabled, so a disabled
toolset is absent from ``tools/list`` rather than present-and-failing.

Secret handling (SPEC N8, §11). Three controller objects reachable from here
carry secrets, and none of them is ever projected:

* ``RESTUser.password`` - omitted from ``UserBrief``.
* ``RESTApikey.apikey_secret`` - omitted from ``ApiKeyBrief``. The controller
  shows a key secret once, at creation; there is no retrieval path.
* Auth server bind passwords and client secrets - ``AuthServerBrief`` reads the
  value of exactly one allowlisted key (``name``) and reports every other key by
  name only, diverting secret-looking names to ``redacted_keys``.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..models import (
    ApiKeyBrief,
    ApiKeyList,
    AuthServerBrief,
    AuthServerList,
    Page,
    RoleBrief,
    RoleList,
    UserBrief,
    UserList,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the iam_read toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("iam_read"):
        return

    @mcp.tool(
        name="nv_list_users",
        annotations=READ_ONLY,
        tags={"iam_read", "read"},
    )
    async def nv_list_users(
        ctx: Context,
        role: Annotated[
            str | None,
            Field(
                description="Return only users holding this global role, e.g. 'admin' or "
                "'reader'. Get names from nv_list_roles."
            ),
        ] = None,
        auth_server: Annotated[
            str | None,
            Field(
                description="Return only users from this authentication server (controller "
                "field 'server'); empty on a user means local."
            ),
        ] = None,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only users whose full name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum users to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> UserList:
        """NeuVector user accounts with their roles and login state.

        Use this to audit who can change policy, spot accounts still on a default
        password, and find accounts blocked by failed logins or password expiry.
        Password material is never returned. Namespace-scoped roles appear in
        role_domains as role -> namespaces.

        Calls GET /v1/user with f_role, f_server and f_fullname.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if role:
            filters["role"] = role
        if auth_server:
            filters["server"] = auth_server
        if name_prefix:
            filters["fullname"] = f"prefix,{name_prefix}"

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        items = await app.client.get_list("/v1/user", "users", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return UserList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More users exist. Call again with start={start + len(page_items)}, "
                    "or narrow with role/auth_server."
                    if truncated
                    else None
                ),
            ),
            users=[UserBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_roles",
        annotations=READ_ONLY,
        tags={"iam_read", "read"},
    )
    async def nv_list_roles(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only roles whose name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum roles to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> RoleList:
        """Roles and the read/write permissions each one grants.

        Pair this with nv_list_users to answer "who can actually change policy": a
        user's role name means nothing until you see its permission set. 'reserved'
        marks built-in roles, which cannot be edited or deleted. Each permission entry
        is a controller permission id with independent read and write flags.

        Calls GET /v1/user_role with f_name.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        items = await app.client.get_list("/v1/user_role", "roles", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return RoleList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More roles exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            roles=[RoleBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_auth_servers",
        annotations=READ_ONLY,
        tags={"iam_read", "read"},
    )
    async def nv_list_auth_servers(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only servers whose name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum servers to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> AuthServerList:
        """Configured external authentication servers, by name and kind only.

        Use this to see whether LDAP, SAML or OIDC login is configured and under what
        name, then pair it with nv_list_users (auth_server filter) to see who logs in
        through it. Configuration values are deliberately NOT returned: these objects
        carry bind passwords and client secrets, so this tool reports only the server
        name and which configuration blocks are present.

        Calls GET /v1/server with f_name.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        # Envelope key 'servers' is inferred from SPEC §3.3: Appendix B has no
        # RESTServersData. A wrong key degrades to [] rather than raising.
        items = await app.client.get_list("/v1/server", "servers", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return AuthServerList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    "More authentication servers exist. Call again with "
                    f"start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            servers=[AuthServerBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_api_keys",
        annotations=READ_ONLY,
        tags={"iam_read", "read"},
    )
    async def nv_list_api_keys(
        ctx: Context,
        role: Annotated[
            str | None,
            Field(
                description="Return only keys holding this global role. Get names from "
                "nv_list_roles."
            ),
        ] = None,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only keys whose name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Maximum keys to return. Capped by NV_MAX_ITEMS.")
        ] = 50,
    ) -> ApiKeyList:
        """API key metadata: name, role, creator and expiry. Never the secret.

        Use this to audit non-human access — which keys exist, how much they can do, and
        which have expired or never expire. The secret half of a key is shown once at
        creation and is not retrievable afterwards, so it is absent here by design: an
        expiring key must be replaced, not recovered. An expired key surfaces to its
        holder as controller error code 3.

        Calls GET /v1/api_key with f_role and f_apikey_name.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if role:
            filters["role"] = role
        if name_prefix:
            filters["apikey_name"] = f"prefix,{name_prefix}"

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        items = await app.client.get_list("/v1/api_key", "apikeys", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return ApiKeyList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More API keys exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            api_keys=[ApiKeyBrief.from_api(item) for item in page_items],
        )
