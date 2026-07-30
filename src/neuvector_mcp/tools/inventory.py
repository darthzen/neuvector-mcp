"""Inventory tools: workloads, hosts, groups, services, system summary.

Every tool in this module is read-only and tagged ``inventory``.

Registration contract (identical in every tools/*.py module):

    def register(mcp: FastMCP, settings: Settings) -> None: ...

``register`` adds tools only when their toolset is enabled, so a disabled
toolset is absent from ``tools/list`` rather than present-and-failing.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..models import Page, SystemSummary, WorkloadBrief, WorkloadList

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the inventory toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("inventory"):
        return

    @mcp.tool(
        name="nv_get_system_summary",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_get_system_summary(ctx: Context) -> SystemSummary:
        """Cluster-wide NeuVector posture counters.

        Start here when asked "how is the cluster doing" or before any deeper
        query, because it reveals scale (how many workloads, namespaces, rules)
        and the vulnerability database version.

        Calls GET /v1/system/summary.
        """
        app = app_context(ctx)
        raw = await app.client.request("GET", "/v1/system/summary")
        return SystemSummary.from_api(raw)

    @mcp.tool(
        name="nv_list_workloads",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_list_workloads(
        ctx: Context,
        namespace: Annotated[
            str | None,
            Field(description="Filter to one Kubernetes namespace (controller field 'domain')."),
        ] = None,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only workloads whose name starts with this prefix."),
        ] = None,
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(description="Filter by effective policy mode."),
        ] = None,
        pods_only: Annotated[
            bool,
            Field(description="True returns one entry per pod; False returns every container."),
        ] = True,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Maximum workloads to return.")
        ] = 50,
    ) -> WorkloadList:
        """List running workloads with their policy mode and vulnerability counts.

        Use this to find the workload id needed by nv_get_workload,
        nv_get_scan_report and the runtime operations tools.

        Calls GET /v2/workload with NeuVector filter conventions
        (f_domain, f_name with prefix operator, f_policy_mode) and view=pod.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if namespace:
            filters["domain"] = namespace
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"
        if policy_mode:
            filters["policy_mode"] = policy_mode

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            extra={"view": "pod"} if pods_only else None,
        )
        items = await app.client.get_list("/v2/workload", "workloads", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return WorkloadList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More workloads exist. Call again with start={start + len(page_items)}, "
                    "or narrow with namespace/name_prefix/policy_mode."
                    if truncated
                    else None
                ),
            ),
            workloads=[WorkloadBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_workload",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_get_workload(
        ctx: Context,
        workload_id: Annotated[
            str, Field(min_length=1, description="Workload id from nv_list_workloads.")
        ],
    ) -> WorkloadBrief:
        """Detail for one workload, including its group and node placement.

        Calls GET /v2/workload/{id}.
        """
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v2/workload/{workload_id}", "workload")
        if not raw:
            from ..errors import NotFoundError

            raise NotFoundError(f"no workload with id {workload_id!r}")
        return WorkloadBrief.from_api(raw)
