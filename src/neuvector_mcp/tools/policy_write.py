"""Mutating group and network-policy tools. Toolset ``policy_write``.

Every tool here follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..guard import authorise_write
from ..models import WriteOutcome

MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the policy_write toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("policy_write"):
        return

    @mcp.tool(
        name="nv_set_group_policy_mode",
        annotations=MUTATING_IDEMPOTENT,
        tags={"policy_write", "write"},
    )
    async def nv_set_group_policy_mode(
        ctx: Context,
        group_name: Annotated[
            str, Field(min_length=1, description="Group name, e.g. 'nv.api.prod'.")
        ],
        mode: Annotated[
            Literal["Discover", "Monitor", "Protect"],
            Field(description="Discover learns behaviour, Monitor alerts, Protect blocks."),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Change the policy mode of one group.

        Moving a group to Protect starts BLOCKING traffic and process activity
        that the learned policy does not allow. Preview first: call without
        'confirm', read the returned plan, then call again with the token.

        Calls PATCH /v1/group/{name} with {"config": {"name":..., "policy_mode":...}}.
        """
        app = app_context(ctx)
        payload: dict[str, Any] = {
            "config": {"name": group_name, "policy_mode": mode}
        }
        namespace = group_name.split(".")[-1] if group_name.startswith("nv.") else None

        plan = authorise_write(
            app.settings,
            operation="nv_set_group_policy_mode",
            toolset="policy_write",
            target=group_name,
            effect=(
                f"Set policy mode of group {group_name!r} to {mode}."
                + (
                    " Traffic and process activity outside the learned policy will be "
                    "blocked immediately."
                    if mode == "Protect"
                    else ""
                )
            ),
            payload=payload,
            confirm=confirm,
            namespace=namespace,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH", f"/v1/group/{group_name}", json=payload
        )
        return WriteOutcome(
            status="applied",
            operation="nv_set_group_policy_mode",
            target=group_name,
            effect=f"policy_mode of {group_name} set to {mode}",
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_group",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_group(
        ctx: Context,
        group_name: Annotated[str, Field(min_length=1, description="Group to delete.")],
        confirm: Annotated[
            str | None, Field(description="Confirmation token from the preview call.")
        ] = None,
    ) -> WriteOutcome:
        """Delete a custom group.

        Rules that reference the group are removed with it. Learned groups
        (names beginning 'nv.') cannot be deleted; the controller rejects those
        with code 4 (Operation not allowed).

        Calls DELETE /v1/group/{name}.
        """
        app = app_context(ctx)
        plan = authorise_write(
            app.settings,
            operation="nv_delete_group",
            toolset="policy_write",
            target=group_name,
            effect=f"Delete group {group_name!r} and every rule that references it.",
            payload=None,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("DELETE", f"/v1/group/{group_name}")
        return WriteOutcome(
            status="applied",
            operation="nv_delete_group",
            target=group_name,
            effect=f"group {group_name} deleted",
            controller_response=response if isinstance(response, dict) else {},
        )
