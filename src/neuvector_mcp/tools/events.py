"""Security event tools: threats, violations, incidents, audits, system events, alerts.

Every tool in this module is read-only and tagged ``events``.

Registration contract (identical in every tools/*.py module):

    def register(mcp: FastMCP, settings: Settings) -> None: ...
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..errors import NotFoundError
from ..models import (
    AuditEvent,
    AuditEventList,
    Page,
    SecurityEvent,
    SecurityEventList,
    SystemAlerts,
    SystemEvent,
    SystemEventList,
    ThreatDetail,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

#: (path, envelope key) per kind. Paths verified against spec_endpoints.json;
#: envelope keys verified against RESTThreatsData / RESTPolicyViolationsData /
#: RESTIncidentsData in appendix B.
_KIND_ENDPOINT: dict[str, tuple[str, str]] = {
    "threat": ("/v1/log/threat", "threats"),
    "violation": ("/v1/log/violation", "violations"),
    "incident": ("/v1/log/incident", "incidents"),
}

#: Severity lives in a DIFFERENT json tag per type: Threat has both 'level' and
#: 'severity'; Violation and Incident have only 'level'.
_SEVERITY_FIELD: dict[str, str] = {
    "threat": "severity",
    "violation": "level",
    "incident": "level",
}

#: Namespace json tag per (kind, side). All names from appendix B.
_DOMAIN_FIELD: dict[tuple[str, str], str] = {
    ("threat", "client"): "client_workload_domain",
    ("threat", "server"): "server_workload_domain",
    ("violation", "client"): "client_domain",
    ("violation", "server"): "server_domain",
    ("incident", "client"): "workload_domain",
    ("incident", "server"): "remote_workload_domain",
}

#: Workload-id json tag per (kind, side). All names from appendix B.
_WORKLOAD_ID_FIELD: dict[tuple[str, str], str] = {
    ("threat", "client"): "client_workload_id",
    ("threat", "server"): "server_workload_id",
    ("violation", "client"): "client_id",
    ("violation", "server"): "server_id",
    ("incident", "client"): "workload_id",
    ("incident", "server"): "remote_workload_id",
}


def _reported_time_filter(
    since_timestamp: int | None, until_timestamp: int | None
) -> tuple[dict[str, str], int | None]:
    """Split a time window into a server-side filter plus a residual client bound.

    ``build_query`` renders exactly one value per field, so ONE request cannot
    carry both ``gte`` and ``lte`` on ``reported_timestamp``. Rule:

    * ``since`` only  -> ``f_reported_timestamp=gte,<since>``, no residual
    * ``until`` only  -> ``f_reported_timestamp=lte,<until>``, no residual
    * both            -> ``f_reported_timestamp=gte,<since>`` and ``until`` is
      returned as the residual bound, applied client-side after paging.

    Returns:
        ``(filters_fragment, residual_until)``.
    """
    if since_timestamp is not None:
        return {"reported_timestamp": f"gte,{since_timestamp}"}, until_timestamp
    if until_timestamp is not None:
        return {"reported_timestamp": f"lte,{until_timestamp}"}, None
    return {}, None


def _trim_window(
    items: list[dict[str, Any]], residual_until: int | None
) -> tuple[list[dict[str, Any]], int]:
    """Drop items newer than ``residual_until``. Returns ``(kept, dropped_count)``."""
    if residual_until is None:
        return items, 0
    kept = [i for i in items if int(i.get("reported_timestamp") or 0) <= residual_until]
    return kept, len(items) - len(kept)


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the events toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("events"):
        return

    @mcp.tool(
        name="nv_query_security_events",
        annotations=READ_ONLY,
        tags={"events", "read"},
    )
    async def nv_query_security_events(
        ctx: Context,
        kind: Annotated[
            Literal["threat", "violation", "incident"],
            Field(
                description="Which log to read. 'threat' is network IDS/IPS and DLP/WAF "
                "detections, 'violation' is network traffic outside the learned or declared "
                "network policy, 'incident' is process, file and privilege-escalation activity "
                "outside the process profile."
            ),
        ],
        namespace: Annotated[
            str | None,
            Field(
                description="Filter to one Kubernetes namespace. Applied to the side selected "
                "by 'side'."
            ),
        ] = None,
        severity: Annotated[
            str | None,
            Field(
                description="Filter by severity. For kind='threat' this filters the 'severity' "
                "field (Critical, High, Medium, Low, Info). For kind='violation' and "
                "kind='incident' it filters 'level' instead, whose vocabulary the controller "
                "does not publish; an unrecognised value returns an empty page rather than an "
                "error."
            ),
        ] = None,
        workload_id: Annotated[
            str | None,
            Field(
                description="Filter to one workload id, on the side selected by 'side'. Get ids "
                "from nv_list_workloads."
            ),
        ] = None,
        side: Annotated[
            Literal["client", "server"],
            Field(
                description="Which endpoint of the event the 'namespace' and 'workload_id' "
                "filters apply to. Controller filters are ANDed, so one call can constrain one "
                "side only; query twice to cover both. For kind='incident', 'client' means the "
                "subject workload and 'server' means the remote peer."
            ),
        ] = "client",
        since_timestamp: Annotated[
            int | None,
            Field(
                ge=0,
                description="Lower bound on 'reported_timestamp', Unix epoch seconds, inclusive.",
            ),
        ] = None,
        until_timestamp: Annotated[
            int | None,
            Field(
                ge=0,
                description="Upper bound on 'reported_timestamp', Unix epoch seconds, inclusive. "
                "When both bounds are given the controller applies the lower bound and the "
                "server trims the upper bound after paging; see 'dropped_outside_window' in the "
                "result.",
            ),
        ] = None,
        newest_first: Annotated[
            bool,
            Field(
                description="Sort by 'reported_timestamp' descending. The controller ignores an "
                "unsupported sort silently, so treat ordering as best effort."
            ),
        ] = True,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum events to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> SecurityEventList:
        """Query one of NeuVector's three runtime security event logs.

        Pick 'kind' first: threat = network IDS/IPS, DLP and WAF detections;
        violation = connections outside the learned or declared network policy;
        incident = process, file and escalation activity outside the process profile.
        Each log names the same concepts with different fields, so the namespace and
        workload filters are translated per kind; 'side' chooses which end of the event
        they constrain because controller filters are ANDed. Get workload ids from
        nv_list_workloads. For a threat's captured packet call nv_get_threat_detail —
        the list form has the packet stripped by the controller.

        Calls GET /v1/log/threat with f_client_workload_domain, f_client_workload_id,
        f_severity, f_reported_timestamp.
        Calls GET /v1/log/violation with f_client_domain, f_client_id, f_level,
        f_reported_timestamp.
        Calls GET /v1/log/incident with f_workload_domain, f_workload_id, f_level,
        f_reported_timestamp.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)
        path, envelope = _KIND_ENDPOINT[kind]

        filters: dict[str, str] = {}
        if namespace:
            filters[_DOMAIN_FIELD[(kind, side)]] = namespace
        if workload_id:
            filters[_WORKLOAD_ID_FIELD[(kind, side)]] = workload_id
        if severity:
            filters[_SEVERITY_FIELD[kind]] = severity
        time_filters, residual_until = _reported_time_filter(since_timestamp, until_timestamp)
        filters.update(time_filters)

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            sort={"reported_timestamp": "desc"} if newest_first else None,
        )
        items = await app.client.get_list(path, envelope, params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        kept, dropped = _trim_window(page_items, residual_until)
        return SecurityEventList(
            page=Page(
                start=start,
                returned=len(kept),
                truncated=truncated,
                hint=(
                    f"More {kind} events exist. Call again with start={start + len(page_items)}, "
                    "or narrow with namespace/workload_id/severity/since_timestamp."
                    if truncated
                    else None
                ),
            ),
            kind=kind,
            dropped_outside_window=dropped,
            events=[SecurityEvent.from_api(i, kind=kind) for i in kept],
        )

    @mcp.tool(
        name="nv_get_threat_detail",
        annotations=READ_ONLY,
        tags={"events", "read"},
    )
    async def nv_get_threat_detail(
        ctx: Context,
        threat_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Event id from nv_query_security_events with kind='threat' (the 'id' "
                "field, not 'threat_id').",
            ),
        ],
        include_packet: Annotated[
            bool,
            Field(
                description="True returns the captured packet as the controller encoded it, "
                "clipped to half of NV_MAX_RESPONSE_CHARS. Leave False unless you are inspecting "
                "payload bytes; captures routinely exceed the whole response budget."
            ),
        ] = False,
    ) -> ThreatDetail:
        """One threat event including its captured packet.

        Unlike the list form, this route returns the packet the enforcer captured, which
        can be tens of kilobytes and will exhaust a client's context if returned whole.
        The packet is therefore omitted unless include_packet=True and is always clipped
        to half of NV_MAX_RESPONSE_CHARS, with packet_truncated reporting the clip. Get
        the id from nv_query_security_events with kind='threat'.

        Calls GET /v1/log/threat/{id}.
        """
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/log/threat/{threat_id}", "threat")
        if not raw:
            raise NotFoundError(f"no threat event with id {threat_id!r}")
        budget = max(0, app.settings.max_response_chars // 2) if include_packet else 0
        return ThreatDetail.from_api(raw, packet_budget=budget)

    @mcp.tool(
        name="nv_query_audit_events",
        annotations=READ_ONLY,
        tags={"events", "read"},
    )
    async def nv_query_audit_events(
        ctx: Context,
        namespace: Annotated[
            str | None,
            Field(
                description="Filter to one Kubernetes namespace (controller field "
                "'workload_domain')."
            ),
        ] = None,
        workload_id: Annotated[
            str | None,
            Field(description="Filter to one workload id from nv_list_workloads."),
        ] = None,
        level: Annotated[
            str | None,
            Field(description="Filter by controller log level, verbatim."),
        ] = None,
        name: Annotated[
            str | None,
            Field(
                description="Filter by audit event name, e.g. the scan or compliance event type."
            ),
        ] = None,
        since_timestamp: Annotated[
            int | None,
            Field(
                ge=0,
                description="Lower bound on 'reported_timestamp', Unix epoch seconds, inclusive.",
            ),
        ] = None,
        until_timestamp: Annotated[
            int | None,
            Field(
                ge=0,
                description="Upper bound on 'reported_timestamp', Unix epoch seconds, inclusive. "
                "Applied after paging when a lower bound is also given.",
            ),
        ] = None,
        newest_first: Annotated[
            bool,
            Field(description="Sort by 'reported_timestamp' descending. Best effort."),
        ] = True,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(
                ge=1,
                le=1000,
                description="Maximum audit events to return. Capped by NV_MAX_ITEMS.",
            ),
        ] = 50,
    ) -> AuditEventList:
        """Audit log: scan results, compliance findings and admission decisions per asset.

        Reach for this to answer "what did NeuVector conclude about this image or
        workload and when", including vulnerability counts at the time of the scan.
        This is not the API-activity log — that is nv_query_system_events. Filters are
        ANDed and use the controller's json tags, so namespace is 'workload_domain'.

        Calls GET /v1/log/audit with f_workload_domain, f_workload_id, f_level, f_name,
        f_reported_timestamp.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if namespace:
            filters["workload_domain"] = namespace
        if workload_id:
            filters["workload_id"] = workload_id
        if level:
            filters["level"] = level
        if name:
            filters["name"] = name
        time_filters, residual_until = _reported_time_filter(since_timestamp, until_timestamp)
        filters.update(time_filters)

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            sort={"reported_timestamp": "desc"} if newest_first else None,
        )
        items = await app.client.get_list("/v1/log/audit", "audits", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        kept, dropped = _trim_window(page_items, residual_until)
        return AuditEventList(
            page=Page(
                start=start,
                returned=len(kept),
                truncated=truncated,
                hint=(
                    f"More audit events exist. Call again with start={start + len(page_items)}, "
                    "or narrow with namespace/level/since_timestamp."
                    if truncated
                    else None
                ),
            ),
            dropped_outside_window=dropped,
            audits=[AuditEvent.from_api(i) for i in kept],
        )

    @mcp.tool(
        name="nv_query_system_events",
        annotations=READ_ONLY,
        tags={"events", "read"},
    )
    async def nv_query_system_events(
        ctx: Context,
        namespace: Annotated[
            str | None,
            Field(
                description="Filter to one Kubernetes namespace (controller field "
                "'workload_domain')."
            ),
        ] = None,
        category: Annotated[
            str | None,
            Field(description="Filter by event category, verbatim as the controller reports it."),
        ] = None,
        level: Annotated[
            str | None,
            Field(description="Filter by controller log level, verbatim."),
        ] = None,
        user: Annotated[
            str | None,
            Field(
                description="Filter to events attributed to one user, for auditing who changed "
                "what."
            ),
        ] = None,
        name: Annotated[
            str | None,
            Field(description="Filter by system event name."),
        ] = None,
        since_timestamp: Annotated[
            int | None,
            Field(
                ge=0,
                description="Lower bound on 'reported_timestamp', Unix epoch seconds, inclusive.",
            ),
        ] = None,
        until_timestamp: Annotated[
            int | None,
            Field(
                ge=0,
                description="Upper bound on 'reported_timestamp', Unix epoch seconds, inclusive. "
                "Applied after paging when a lower bound is also given.",
            ),
        ] = None,
        newest_first: Annotated[
            bool,
            Field(description="Sort by 'reported_timestamp' descending. Best effort."),
        ] = True,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(
                ge=1,
                le=1000,
                description="Maximum system events to return. Capped by NV_MAX_ITEMS.",
            ),
        ] = 50,
    ) -> SystemEventList:
        """System event log: controller and enforcer lifecycle plus REST API activity.

        Use this to see who changed configuration and when, whether an enforcer
        disconnected, or whether the licence or enforcer limit fired. Filter by 'user'
        for an accountability trail. For per-asset scan and compliance conclusions use
        nv_query_audit_events instead; for runtime detections use
        nv_query_security_events.

        Calls GET /v1/log/event with f_workload_domain, f_category, f_level, f_user,
        f_name, f_reported_timestamp.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if namespace:
            filters["workload_domain"] = namespace
        if category:
            filters["category"] = category
        if level:
            filters["level"] = level
        if user:
            filters["user"] = user
        if name:
            filters["name"] = name
        time_filters, residual_until = _reported_time_filter(since_timestamp, until_timestamp)
        filters.update(time_filters)

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            sort={"reported_timestamp": "desc"} if newest_first else None,
        )
        items = await app.client.get_list("/v1/log/event", "events", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        kept, dropped = _trim_window(page_items, residual_until)
        return SystemEventList(
            page=Page(
                start=start,
                returned=len(kept),
                truncated=truncated,
                hint=(
                    f"More system events exist. Call again with start={start + len(page_items)}, "
                    "or narrow with category/level/user/since_timestamp."
                    if truncated
                    else None
                ),
            ),
            dropped_outside_window=dropped,
            events=[SystemEvent.from_api(i) for i in kept],
        )

    @mcp.tool(
        name="nv_get_system_alerts",
        annotations=READ_ONLY,
        tags={"events", "read"},
    )
    async def nv_get_system_alerts(ctx: Context) -> SystemAlerts:
        """Standing NeuVector platform alerts, such as licence and configuration warnings.

        Call this early in a health check: these are the conditions the controller
        itself considers wrong, independent of any workload. Alert text is returned
        verbatim as strings because the controller's alert schema is not published; use
        nv_query_system_events for the timestamped history behind an alert.

        Calls GET /v1/system/alerts.
        """
        app = app_context(ctx)
        raw = await app.client.request("GET", "/v1/system/alerts")
        return SystemAlerts.from_api(raw if isinstance(raw, dict) else {})
