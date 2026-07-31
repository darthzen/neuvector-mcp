"""Read-only policy tools: network, process, file, response, DLP, WAF, admission.

Every tool in this module is read-only and tagged ``policy_read``.

``nv_assess_admission_rule`` issues an HTTP POST but is still a read tool: the
route evaluates a candidate admission rule against current cluster objects and
returns verdicts. Nothing is created, updated or deleted, so it carries
``readOnlyHint=True`` and takes no ``confirm`` argument (gate rule R5 forbids one
on a read tool).

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
    AdmissionAssessment,
    AdmissionCriterionInput,
    AdmissionRule,
    AdmissionRuleList,
    AdmissionState,
    DlpSensorList,
    FileMonitorProfile,
    NetworkRule,
    NetworkRuleList,
    Page,
    ProcessProfile,
    ResponseRule,
    ResponseRuleList,
    SensorBrief,
    WafGroup,
    WafGroupList,
    WafRuleCatalogEntry,
    WafRuleList,
    WafSensorDetail,
    WafSensorList,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the policy_read toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("policy_read"):
        return

    @mcp.tool(
        name="nv_list_network_rules",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_network_rules(
        ctx: Context,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' returns this cluster's rules, 'fed' returns rules pushed "
                "from a federation primary. Federated rules cannot be edited on this cluster."
            ),
        ] = "local",
        from_group: Annotated[
            str | None,
            Field(
                description="Return only rules whose source is this group name (controller "
                "field 'from'). Get names from nv_list_groups."
            ),
        ] = None,
        to_group: Annotated[
            str | None,
            Field(
                description="Return only rules whose destination is this group name "
                "(controller field 'to')."
            ),
        ] = None,
        action: Annotated[
            Literal["allow", "deny"] | None,
            Field(description="Return only rules with this action."),
        ] = None,
        cfg_type: Annotated[
            Literal["learned", "user_created", "ground", "federal"] | None,
            Field(
                description="Return only rules of this provenance: 'learned' was inferred in "
                "Discover mode, 'user_created' was added through the API or UI, 'ground' came "
                "from a Kubernetes CRD, 'federal' was pushed by a federation primary."
            ),
        ] = None,
        start: Annotated[
            int, Field(ge=0, description="Zero-based paging offset into the ordered rule list.")
        ] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum rules to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> NetworkRuleList:
        """Network policy rules in controller evaluation order.

        Rules are evaluated top-down in the order returned and the first match wins, so
        list position is semantically load-bearing: paging with 'start' preserves that
        order, and a rule's effect depends on everything above it. Read 'order' for the
        position within this page and 'priority' for the controller's own ordering
        weight. Provenance comes from 'cfg_type' and 'learned', never from the id value.
        Filters are ANDed, so a from_group + to_group query returns only rules matching
        both endpoints. Rules that cannot be modified (federal, ground) answer controller
        code 46 on a write attempt, so check 'cfg_type' before reaching for Phase 7's
        nv_apply_network_rule_changes.

        Calls GET /v1/policy/rule with scope, f_from, f_to, f_action and f_cfg_type.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if from_group:
            filters["from"] = from_group
        if to_group:
            filters["to"] = to_group
        if action:
            filters["action"] = action
        if cfg_type:
            filters["cfg_type"] = cfg_type

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            extra={"scope": scope},
        )
        items = await app.client.get_list("/v1/policy/rule", "rules", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return NetworkRuleList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More rules exist. Call again with start={start + len(page_items)} "
                    "to continue in evaluation order."
                    if truncated
                    else None
                ),
            ),
            scope=scope,
            rules=[
                NetworkRule.from_api(item, order=start + offset)
                for offset, item in enumerate(page_items)
            ],
        )

    @mcp.tool(
        name="nv_get_network_rule",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_network_rule(
        ctx: Context,
        rule_id: Annotated[int, Field(ge=0, description="Rule id from nv_list_network_rules.")],
    ) -> NetworkRule:
        """One network policy rule by id, including its match counters.

        Use this to confirm a rule's exact source, destination, ports and provenance
        before changing or deleting it. It cannot tell you the rule's evaluation
        position: that comes from the ordered list, so call nv_list_network_rules when
        position matters.

        Calls GET /v1/policy/rule/{id}.
        """
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/policy/rule/{rule_id}", "rule")
        if not raw:
            raise NotFoundError(f"no network rule with id {rule_id}")
        return NetworkRule.from_api(raw)

    @mcp.tool(
        name="nv_get_process_profile",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_process_profile(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group whose process profile to read, e.g. 'nv.api.prod'. "
                "Get names from nv_list_groups.",
            ),
        ],
        max_entries: Annotated[
            int,
            Field(
                ge=1,
                le=1000,
                description="Maximum process entries to return. A learned profile can hold "
                "hundreds; entries beyond this are dropped and entries_truncated is set.",
            ),
        ] = 100,
    ) -> ProcessProfile:
        """Allowed-process profile for one group, with its enforcement mode.

        This is the allowlist NeuVector compares running processes against; anything
        outside it produces a 'process' incident, visible through
        nv_query_security_events with kind='incident'. 'mode' decides whether a
        violation is only logged (Discover, Monitor) or blocked (Protect). The
        controller returns the whole profile in one body, so entries are capped
        client-side by max_entries rather than paged.

        Calls GET /v1/process_profile/{name}.
        """
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/process_profile/{group_name}", "process_profile")
        if not raw:
            raise NotFoundError(f"no process profile for group {group_name!r}")
        return ProcessProfile.from_api(raw, max_entries=max_entries)

    @mcp.tool(
        name="nv_get_file_monitor_profile",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_file_monitor_profile(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group whose file-monitor profile to read, e.g. 'nv.api.prod'. "
                "Get names from nv_list_groups.",
            ),
        ],
        max_filters: Annotated[
            int,
            Field(
                ge=1,
                le=1000,
                description="Maximum file filters to return. Filters beyond this are dropped "
                "and filters_truncated is set.",
            ),
        ] = 100,
    ) -> FileMonitorProfile:
        """File-monitor filters for one group: which paths NeuVector watches and how.

        Each filter names a path or glob, whether it recurses, and the behaviour on a
        hit (monitor or block). Matches surface as file incidents through
        nv_query_security_events with kind='incident'; the file_path field there
        corresponds to a filter here.

        Calls GET /v1/file_monitor/{name}.
        """
        # BLOCKED (schema): RESTFileMonitorFile / RESTFileMonitorFileData are absent
        # from appendix/B-schema-reference.md, so the response envelope is unknown.
        # The body is fetched raw and probed; FileMonitorProfile.from_api reports the
        # observed top-level keys in 'envelope_keys'. Confirm against a live
        # controller before hardening this into a get_object() call.
        app = app_context(ctx)
        body = await app.client.request("GET", f"/v1/file_monitor/{group_name}")
        raw = body if isinstance(body, dict) else {}
        if not raw:
            raise NotFoundError(f"no file monitor profile for group {group_name!r}")
        return FileMonitorProfile.from_api(raw, group_name=group_name, max_filters=max_filters)

    @mcp.tool(
        name="nv_list_response_rules",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_response_rules(
        ctx: Context,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' returns this cluster's response rules, 'fed' returns "
                "rules pushed from a federation primary."
            ),
        ] = "local",
        event: Annotated[
            str | None,
            Field(
                description="Return only rules that react to this event type, verbatim as the "
                "controller names it."
            ),
        ] = None,
        group: Annotated[
            str | None,
            Field(description="Return only rules scoped to this group name."),
        ] = None,
        start: Annotated[
            int, Field(ge=0, description="Zero-based paging offset into the ordered rule list.")
        ] = 0,
        limit: Annotated[
            int,
            Field(
                ge=1,
                le=1000,
                description="Maximum response rules to return. Capped by NV_MAX_ITEMS.",
            ),
        ] = 50,
    ) -> ResponseRuleList:
        """Response rules: the automated reactions NeuVector takes when an event fires.

        Read this to explain why a workload was quarantined or suppressed, or why a
        webhook fired. Like network rules these are evaluated in the order returned, so
        'order' matters. 'actions' names what happens and 'webhooks' names the
        configured webhook targets by name only.

        Calls GET /v1/response/rule with scope, f_event and f_group.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if event:
            filters["event"] = event
        if group:
            filters["group"] = group

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            extra={"scope": scope},
        )
        items = await app.client.get_list("/v1/response/rule", "rules", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return ResponseRuleList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More response rules exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            scope=scope,
            rules=[
                ResponseRule.from_api(item, order=start + offset)
                for offset, item in enumerate(page_items)
            ],
        )

    @mcp.tool(
        name="nv_list_dlp_sensors",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_dlp_sensors(
        ctx: Context,
        name_prefix: Annotated[
            str | None,
            Field(description="Return only sensors whose name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum sensors to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> DlpSensorList:
        """Data-loss-prevention sensors configured on this cluster.

        A sensor is a named bundle of patterns; groups opt into sensors, and a match
        raises a threat event visible through nv_query_security_events with
        kind='threat', where the 'sensor' field carries the name returned here. Pattern
        bodies are not returned: they are large and frequently contain the regexes that
        describe protected data.

        Calls GET /v1/dlp/sensor with f_name.
        """
        # Appendix A documents NO 'scope' parameter on GET /v1/dlp/sensor, unlike
        # GET /v1/waf/sensor. The asymmetry is upstream's; do not add one here.
        # BLOCKED (schema): RESTDlpSensorsData / RESTDlpSensor are absent from
        # appendix/B-schema-reference.md, so the envelope key 'sensors' is inferred
        # from SPEC §3.3 and must be confirmed against a live controller.
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
        items = await app.client.get_list("/v1/dlp/sensor", "sensors", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return DlpSensorList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More DLP sensors exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            sensors=[SensorBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_list_waf_sensors",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_waf_sensors(
        ctx: Context,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' returns this cluster's sensors, 'fed' returns sensors "
                "pushed from a federation primary."
            ),
        ] = "local",
        name_prefix: Annotated[
            str | None,
            Field(description="Return only sensors whose name starts with this prefix."),
        ] = None,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum sensors to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> WafSensorList:
        """Web-application-firewall sensors configured on this cluster.

        A WAF sensor is a named bundle of request patterns that groups opt into; a match
        raises a threat event visible through nv_query_security_events with
        kind='threat'. Pattern bodies are not returned. Unlike the DLP sensor route this
        one accepts a scope, so federated sensors can be listed separately.

        Calls GET /v1/waf/sensor with scope and f_name.
        """
        # BLOCKED (schema): RESTWafSensorsData / RESTWafSensor are absent from
        # appendix/B-schema-reference.md; the envelope key 'sensors' is inferred and
        # SensorBrief reads every field through .get() with a default.
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if name_prefix:
            filters["name"] = f"prefix,{name_prefix}"

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            extra={"scope": scope},
        )
        items = await app.client.get_list("/v1/waf/sensor", "sensors", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return WafSensorList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More WAF sensors exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            scope=scope,
            sensors=[SensorBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_waf_sensor",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_waf_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Sensor to read. Get exact names from nv_list_waf_sensors.",
            ),
        ],
    ) -> WafSensorDetail:
        """One WAF sensor including its rules and regex bodies.

        This is the only tool that returns WAF pattern bodies; the list tool omits them.
        Read a sensor before updating it: nv_update_waf_sensor replaces the rule list
        wholesale, so an update built without seeing the current rules silently drops
        the ones it omits. The 'groups' field tells you whether the sensor is actually
        inspecting anything - a sensor bound to no group matches nothing.

        Calls GET /v1/waf/sensor/{name}.
        """
        # VERIFIED (live controller 5.4): envelope key 'sensor'; the sensor carries
        # name, comment, cfg_type, predefine, groups and rules[].patterns[].
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/waf/sensor/{sensor_name}", "sensor")
        if not raw:
            raise NotFoundError(f"no WAF sensor named {sensor_name!r}")
        return WafSensorDetail.from_api(raw)

    @mcp.tool(
        name="nv_list_waf_groups",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_waf_groups(
        ctx: Context,
        scope: Annotated[
            Literal["local", "fed"],
            Field(description="'local' returns this cluster's groups, 'fed' federated ones."),
        ] = "local",
        bound_only: Annotated[
            bool,
            Field(
                description="True returns only groups that have at least one sensor bound. "
                "Most clusters have hundreds of groups and almost none bound, so this is "
                "usually what you want."
            ),
        ] = False,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum groups to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> WafGroupList:
        """Which groups have WAF inspection enabled and which sensors are bound to them.

        A sensor only inspects traffic once it is bound to a group here, and it only
        BLOCKS once that group's policy mode is Protect - in Discover or Monitor a
        match raises a threat event and the request proceeds. Use this to answer
        'is this sensor actually doing anything'.

        Calls GET /v1/waf/group with scope.
        """
        # VERIFIED (live controller 5.4): envelope key 'waf_groups'; each entry carries
        # name, status, cfg_type and sensors[] of {name, action, exist}.
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        params = build_query(extra={"scope": scope})
        items = await app.client.get_list("/v1/waf/group", "waf_groups", params=params)
        if bound_only:
            items = [item for item in items if (item.get("sensors") or [])]

        window = items[start : start + effective_limit + 1]
        truncated = len(window) > effective_limit
        page_items = window[:effective_limit]
        return WafGroupList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More WAF groups exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            scope=scope,
            groups=[WafGroup.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_waf_group",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_waf_group(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group to read, e.g. 'nv.api.prod'. Names come from nv_list_groups.",
            ),
        ],
    ) -> WafGroup:
        """WAF configuration for one group: inspection status and bound sensors.

        Read this before nv_set_waf_group. That tool's 'sensors' argument REPLACES the
        binding list rather than adding to it, so an update built without the current
        list unbinds whatever it leaves out.

        Calls GET /v1/waf/group/{name}.
        """
        # VERIFIED (live controller 5.4): envelope key 'waf_group'.
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/waf/group/{group_name}", "waf_group")
        if not raw:
            raise NotFoundError(f"no WAF configuration for group {group_name!r}")
        return WafGroup.from_api(raw)

    @mcp.tool(
        name="nv_list_waf_rules",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_waf_rules(
        ctx: Context,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum rules to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> WafRuleList:
        """The cluster-wide WAF rule catalogue, across every sensor.

        Rules are owned by sensors, so nv_get_waf_sensor is the better tool when you
        know which sensor you care about. This one answers the cross-cutting question:
        which rule ids exist, and does the name I am about to create collide.

        Calls GET /v1/waf/rule.
        """
        # VERIFIED (live controller 5.4): envelope key 'rules'. Catalogue entries name
        # rules '<sensor>_<hash>.<rule>' and carry no separate 'sensor' field, so
        # WafRuleCatalogEntry.sensor stays empty unless a controller starts sending one.
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        items = await app.client.get_list("/v1/waf/rule", "rules")
        window = items[start : start + effective_limit + 1]
        truncated = len(window) > effective_limit
        page_items = window[:effective_limit]
        return WafRuleList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More WAF rules exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            rules=[WafRuleCatalogEntry.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_admission_state",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_admission_state(ctx: Context) -> AdmissionState:
        """Whether Kubernetes admission control is enabled, and in which mode.

        Check this before reading or reasoning about admission rules: when 'enable' is
        false the rules exist but nothing is enforced, and in mode 'monitor' denials are
        only logged. 'default_action' is what happens to a request no rule matches.
        'k8s_env' false means the cluster is not Kubernetes and admission control cannot
        work at all.

        Calls GET /v1/admission/state.
        """
        app = app_context(ctx)
        raw = await app.client.request("GET", "/v1/admission/state")
        return AdmissionState.from_api(raw if isinstance(raw, dict) else {})

    @mcp.tool(
        name="nv_list_admission_rules",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_admission_rules(
        ctx: Context,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' returns this cluster's rules, 'fed' returns rules pushed "
                "from a federation primary."
            ),
        ] = "local",
        rule_type: Annotated[
            Literal["deny", "exception"] | None,
            Field(
                description="'deny' rules block matching deployments, 'exception' rules allow "
                "them through."
            ),
        ] = None,
        cfg_type: Annotated[
            Literal["user_created", "ground", "federal"] | None,
            Field(
                description="Provenance: 'user_created' added through the API or UI, 'ground' "
                "from a Kubernetes CRD, 'federal' pushed by a federation primary."
            ),
        ] = None,
        category: Annotated[
            str | None,
            Field(description="Filter by rule category, verbatim as the controller reports it."),
        ] = None,
        max_criteria: Annotated[
            int,
            Field(
                ge=1,
                le=50,
                description="Maximum criteria to return per rule. A rule can carry deeply "
                "nested criteria; extras are dropped and criteria_truncated is set on that rule.",
            ),
        ] = 10,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=1000, description="Maximum rules to return. Capped by NV_MAX_ITEMS."),
        ] = 50,
    ) -> AdmissionRuleList:
        """Admission control rules: what NeuVector blocks or exempts at deploy time.

        Read nv_get_admission_state first - these rules do nothing while admission
        control is disabled or in monitor mode. Criteria are flattened to
        'name op value' strings, nested sub-criteria included as 'name op value
        (sub: ...)'. To find out what a candidate rule would match without changing
        anything, use nv_assess_admission_rule.

        Calls GET /v1/admission/rules with scope, f_rule_type, f_cfg_type and f_category.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        filters: dict[str, str] = {}
        if rule_type:
            filters["rule_type"] = rule_type
        if cfg_type:
            filters["cfg_type"] = cfg_type
        if category:
            filters["category"] = category

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
            filters=filters,
            extra={"scope": scope},
        )
        items = await app.client.get_list("/v1/admission/rules", "rules", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return AdmissionRuleList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    "More admission rules exist. Call again with "
                    f"start={start + len(page_items)}, or narrow with rule_type/cfg_type."
                    if truncated
                    else None
                ),
            ),
            scope=scope,
            rules=[AdmissionRule.from_api(item, max_criteria=max_criteria) for item in page_items],
        )

    @mcp.tool(
        name="nv_assess_admission_rule",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_assess_admission_rule(
        ctx: Context,
        rule_type: Annotated[
            Literal["deny", "exception"],
            Field(
                description="'deny' evaluates a candidate blocking rule, 'exception' evaluates "
                "a candidate allow rule."
            ),
        ],
        criteria: Annotated[
            list[AdmissionCriterionInput],
            Field(
                min_length=1,
                description="Match criteria of the candidate rule. Each needs name, op and "
                "value; nested sub_criteria are optional. Get valid names from an existing "
                "rule via nv_list_admission_rules.",
            ),
        ],
        category: Annotated[
            str,
            Field(
                description="Rule category the controller expects; leave at the default unless "
                "an existing rule shows otherwise."
            ),
        ] = "Kubernetes",
        containers: Annotated[
            list[Literal["containers", "init_containers", "ephemeral_containers"]],
            Field(description="Which container classes the candidate rule would inspect."),
        ] = ["containers"],  # noqa: B006 - pydantic copies defaults per call
        rule_mode: Annotated[
            Literal["", "monitor", "protect"],
            Field(
                description="Per-rule mode of the candidate rule; empty inherits the global "
                "admission mode."
            ),
        ] = "",
        comment: Annotated[
            str, Field(description="Free-text comment carried on the candidate rule.")
        ] = "",
        max_results: Annotated[
            int,
            Field(
                ge=1,
                le=200,
                description="Maximum matched objects to return. The controller evaluates every "
                "current cluster object, so a broad rule can match hundreds.",
            ),
        ] = 50,
    ) -> AdmissionAssessment:
        """Evaluate a candidate admission rule against the cluster and report what it would match.

        This is a dry run: it creates nothing, changes nothing and does not touch the
        admission configuration. Use it before nv_create_admission_rule to see which
        running or pending objects a candidate deny rule would have blocked, and which
        existing rules already match them. 'allowed' per result is the verdict the
        webhook would return. A broad criterion set matches a lot, so raise max_results
        deliberately.

        Calls POST /v1/assess/admission/rule with a {"config": {...}} body carrying
        rule_type, category, criteria, containers, rule_mode and comment.
        """
        app = app_context(ctx)
        payload: dict[str, Any] = {
            "config": {
                "category": category,
                "rule_type": rule_type,
                "cfg_type": "user_created",
                "criteria": [c.model_dump(exclude_defaults=False) for c in criteria],
                "containers": list(containers),
                "rule_mode": rule_mode,
                "comment": comment,
                "disable": False,
            }
        }
        raw = await app.client.request("POST", "/v1/assess/admission/rule", json=payload)
        return AdmissionAssessment.from_api(
            raw if isinstance(raw, dict) else {}, max_results=max_results
        )
