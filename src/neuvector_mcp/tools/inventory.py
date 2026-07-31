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
from ..models import (
    Conversation,
    ConversationList,
    EnforcerBrief,
    EnforcerList,
    GroupBrief,
    GroupDetail,
    GroupList,
    HostBrief,
    HostList,
    Identity,
    NamespaceBrief,
    NamespaceList,
    Page,
    ServiceBrief,
    ServiceList,
    SystemSummary,
    WorkloadBrief,
    WorkloadList,
)

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

    @mcp.tool(
        name="nv_whoami",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_whoami(ctx: Context) -> Identity:
        """Identity and permissions of the credential this server authenticates with.

        Call this first when a later tool returns a permission error (controller code
        25), to see which role and which namespaces the configured credential actually
        covers. Every controller call this server makes is limited by that role, so a
        missing object may simply be invisible to this identity. When
        NV_ALLOW_UNDOCUMENTED is false, or the route is unavailable, the answer falls
        back to the identity cached at startup and 'source' says so.

        Calls GET /v1/selfuser.
        """
        app = app_context(ctx)
        if not app.settings.allow_undocumented:
            return Identity.from_cached(
                app.identity,
                note="GET /v1/selfuser was not called: it is an undocumented route and "
                "NV_ALLOW_UNDOCUMENTED is false. Reporting the identity cached at startup.",
            )
        from ..errors import NeuVectorMCPError

        try:
            raw = await app.client.get_object("/v1/selfuser", "user")
        except NeuVectorMCPError as exc:
            return Identity.from_cached(
                app.identity,
                note=f"GET /v1/selfuser is unavailable on this controller ({type(exc).__name__}). "
                "Reporting the identity cached at startup.",
            )
        if not raw:
            return Identity.from_cached(
                app.identity,
                note="GET /v1/selfuser returned no 'user' object. "
                "Reporting the identity cached at startup.",
            )
        return Identity.from_api(raw)

    @mcp.tool(
        name="nv_list_hosts",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_list_hosts(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only nodes whose name starts with this prefix."),
        ] = None,
        state: Annotated[
            str | None,
            Field(
                description="Filter by node state as the controller reports it, "
                "e.g. connected or disconnected."
            ),
        ] = None,
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(description="Filter by the node's effective policy mode."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[int, Field(ge=1, le=1000, description="Maximum nodes to return.")] = 50,
    ) -> HostList:
        """List cluster nodes with their runtime, capacity and CIS benchmark capability.

        Use this to get the host id required by nv_get_bench_report,
        nv_get_compliance_findings(scope='host') and nv_get_scan_report(target='host').
        Check cap_kube_bench and cap_docker_bench before asking for a benchmark: a node
        that reports False cannot produce that report.

        Calls GET /v1/host with f_name, f_state and f_policy_mode.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"
        if state:
            filters["state"] = state
        if policy_mode:
            filters["policy_mode"] = policy_mode

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        items = await app.client.get_list("/v1/host", "hosts", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return HostList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More nodes exist. Call again with start={start + len(page_items)}, "
                    "or narrow with name_prefix/state."
                    if truncated
                    else None
                ),
            ),
            hosts=[HostBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_groups",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_list_groups(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(
                description="Return only groups whose name starts with this prefix, "
                "e.g. 'nv.' for learned groups."
            ),
        ] = None,
        namespace: Annotated[
            str | None,
            Field(description="Filter to one Kubernetes namespace (controller field 'domain')."),
        ] = None,
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(description="Filter by the group's policy mode."),
        ] = None,
        kind: Annotated[
            str | None,
            Field(
                description="Filter by group kind as the controller reports it, "
                "e.g. container, node or address."
            ),
        ] = None,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' returns this cluster's groups; 'fed' returns federated "
                "groups and is empty unless this cluster is part of a federation."
            ),
        ] = "local",
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[int, Field(ge=1, le=1000, description="Maximum groups to return.")] = 50,
    ) -> GroupList:
        """List security groups with their policy mode and rule counts.

        A group is what NeuVector attaches policy to, so this is the entry point for
        every policy question. Learned groups are named 'nv.<service>.<namespace>';
        pass a group name to nv_get_group for its criteria, members and rules. Groups
        in Discover mode are still learning and enforce nothing.

        Calls GET /v1/group with f_name, f_domain, f_policy_mode, f_kind and scope.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"
        if namespace:
            filters["domain"] = namespace
        if policy_mode:
            filters["policy_mode"] = policy_mode
        if kind:
            filters["kind"] = kind

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            extra={"scope": scope},
        )
        items = await app.client.get_list("/v1/group", "groups", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return GroupList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More groups exist. Call again with start={start + len(page_items)}, "
                    "or narrow with name_prefix/namespace/policy_mode."
                    if truncated
                    else None
                ),
            ),
            groups=[GroupBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_group",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_get_group(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(min_length=1, description="Group name from nv_list_groups, e.g. 'nv.api.prod'."),
        ],
        max_members: Annotated[
            int,
            Field(
                ge=0,
                le=200,
                description="Maximum member workloads to include. 0 returns counts only.",
            ),
        ] = 20,
    ) -> GroupDetail:
        """Full definition of one group: criteria, members and the rules bound to it.

        Read this before changing anything about a group, because 'criteria' is what
        decides membership and 'reserved' groups cannot be modified at all. The
        returned policy_rule_ids and response_rule_ids are the ids nv_get_network_rule
        and the policy write tools take. Member workloads are capped by max_members;
        member_count is always the true total.

        Calls GET /v1/group/{name}.
        """
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/group/{group_name}", "group")
        if not raw:
            from ..errors import NotFoundError

            raise NotFoundError(f"no group named {group_name!r}")
        return GroupDetail.from_api(raw, max_members=min(max_members, app.settings.max_items))

    @mcp.tool(
        name="nv_list_services",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_list_services(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only services whose name starts with this prefix."),
        ] = None,
        namespace: Annotated[
            str | None,
            Field(description="Filter to one Kubernetes namespace (controller field 'domain')."),
        ] = None,
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(description="Filter by the service's policy mode."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[int, Field(ge=1, le=1000, description="Maximum services to return.")] = 50,
    ) -> ServiceList:
        """List services with their policy mode and network exposure.

        A NeuVector service is the auto-derived grouping of one Kubernetes workload,
        and it is the unit nv_set_service_mode changes. ingress_exposure or
        egress_exposure True means the service talks to endpoints outside the cluster,
        which is the usual first filter when hunting for risk.

        Calls GET /v1/service with f_name, f_domain and f_policy_mode.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"
        if namespace:
            filters["domain"] = namespace
        if policy_mode:
            filters["policy_mode"] = policy_mode

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        items = await app.client.get_list("/v1/service", "services", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return ServiceList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More services exist. Call again with start={start + len(page_items)}, "
                    "or narrow with namespace/name_prefix."
                    if truncated
                    else None
                ),
            ),
            services=[ServiceBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_enforcers",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_list_enforcers(
        ctx: Context,
        host_name: Annotated[
            str | None,
            Field(description="Filter to enforcers running on one node."),
        ] = None,
        connection_state: Annotated[
            str | None,
            Field(
                description="Filter by controller connection state, e.g. connected or disconnected."
            ),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Maximum enforcers to return.")
        ] = 50,
    ) -> EnforcerList:
        """List enforcer pods and whether each is connected to the controller.

        Check this when policy appears not to be applied: a node whose enforcer is
        disconnected enforces nothing and reports no traffic, so its workloads look
        quiet for the wrong reason. Compare the count here with 'enforcers' from
        nv_get_system_summary.

        Calls GET /v1/enforcer with f_host_name and f_connection_state.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if host_name:
            filters["host_name"] = host_name
        if connection_state:
            filters["connection_state"] = connection_state

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
        )
        items = await app.client.get_list("/v1/enforcer", "enforcers", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return EnforcerList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More enforcers exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            enforcers=[EnforcerBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_namespaces",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_list_namespaces(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only namespaces whose name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Maximum namespaces to return.")
        ] = 50,
    ) -> NamespaceList:
        """List Kubernetes namespaces with workload counts and compliance tags.

        Use this to discover the exact namespace strings the 'namespace' argument of
        every other tool expects, and to see where the workloads actually are before
        running a broad query. 'tags' are the compliance standards (PCI, GDPR, HIPAA
        and so on) an operator attached to the namespace.

        Calls GET /v1/domain with f_name.
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
        items = await app.client.get_list("/v1/domain", "domains", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return NamespaceList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More namespaces exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            namespaces=[NamespaceBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_network_conversations",
        annotations=READ_ONLY,
        tags={"inventory", "read"},
    )
    async def nv_get_network_conversations(
        ctx: Context,
        from_group: Annotated[
            str | None,
            Field(
                description="Keep only conversations whose source group matches this name exactly."
            ),
        ] = None,
        to_group: Annotated[
            str | None,
            Field(
                description="Keep only conversations whose destination group matches this "
                "name exactly."
            ),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=1000, description="Maximum conversations to return.")
        ] = 50,
    ) -> ConversationList:
        """Observed network conversations between groups: who actually talks to whom.

        This is the only view of real traffic, so use it to justify or question a
        network rule: a rule with no matching conversation is unused, and a
        conversation with policy_action 'violate' is traffic a Protect-mode group would
        have dropped. Group names come from nv_list_groups. This route is undocumented
        and requires NV_ALLOW_UNDOCUMENTED=true; every field degrades to a default
        rather than failing when the controller shape differs.

        Calls GET /v1/conversation with f_from and f_to.
        """
        app = app_context(ctx)
        if not app.settings.allow_undocumented:
            from ..errors import GuardError

            raise GuardError(
                "nv_get_network_conversations uses GET /v1/conversation, an undocumented "
                "controller route. Set NV_ALLOW_UNDOCUMENTED=true to enable it. There is no "
                "documented endpoint that returns the network graph."
            )
        effective_limit = min(limit, app.settings.max_items)
        filters: dict[str, str] = {}
        if from_group:
            filters["from"] = from_group
        if to_group:
            filters["to"] = to_group
        params = build_query(start=start, limit=effective_limit + 1, filters=filters)
        items = await app.client.get_list("/v1/conversation", "conversations", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return ConversationList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More conversations exist. Call again with start={start + len(page_items)}, "
                    "or narrow with from_group/to_group."
                    if truncated
                    else None
                ),
            ),
            conversations=[Conversation.from_api(item) for item in page_items],
        )
