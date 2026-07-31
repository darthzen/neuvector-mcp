"""Data-loss-prevention sensors and group bindings.

Two toolsets live here and are gated independently, so a read tool can never
ship under a write toolset:

* ``policy_read`` - ``nv_get_dlp_sensor``, ``nv_list_dlp_groups``,
  ``nv_get_dlp_group``. These exist so a caller can resolve a sensor or group
  by name, and read the CURRENT state, before any of the write tools replace
  it. ``nv_list_dlp_sensors`` already lives in ``tools/policy_read.py`` and is
  deliberately not duplicated here.
* ``policy_write`` - ``nv_create_dlp_sensor``, ``nv_update_dlp_sensor``,
  ``nv_delete_dlp_sensor``, ``nv_set_dlp_group``.

Every write tool follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3. Input
validation that rejects bad arguments runs BEFORE step 2 and never touches the
controller.

Wire shapes come from the upstream Go structs in ``apis.go`` (controller 5.6.0),
which carry the real json tags including ``omitempty``. That distinction is
load-bearing on PATCH: ``RESTDlpSensorConfig.Comment`` and
``RESTDlpGroupConfig.Status`` are POINTERS, so omitting them means "leave
unchanged" while sending a zero value means "clear it" / "disable it". These
tools therefore omit those keys entirely unless the caller supplied a value.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import NotFoundError, ValidationError_
from ..guard import authorise_write
from ..models import (
    DLP_COMMENT_MAX_LEN,
    DLP_NAME_MAX_LEN,
    DLP_RULE_PATTERN_MAX_LEN,
    DLP_RULE_PATTERN_MAX_NUM,
    DLP_RULE_PATTERN_TOTAL_MAX_LEN,
    DlpGroup,
    DlpGroupList,
    DlpRuleInput,
    DlpSensorBindingInput,
    DlpSensorDetail,
    Page,
    WriteOutcome,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)


def _namespace_from_group_name(group_name: str) -> str | None:
    """Namespace a learned group belongs to, for NV_ALLOWED_NAMESPACES.

    Learned groups are named ``nv.<service>.<namespace>``; anything else is a
    custom group whose namespace cannot be derived from its name. Deliberately a
    local copy of the identically named helper in ``tools/policy_write.py``:
    each tool module owns its own file, and a cross-module import of another
    package's private helper would couple two independently owned modules.
    """
    return group_name.split(".")[-1] if group_name.startswith("nv.") else None


def _dlp_rule_body(rule: DlpRuleInput) -> dict[str, Any]:
    """Render one ``RESTDlpRule`` request object.

    Field names from apis.go ``RESTDlpRule`` / ``RESTDlpCriteriaEntry``. Built
    field by field rather than with ``model_dump()`` so the wire shape stays
    auditable - a house rule, because the controller answers 200 and silently
    drops keys it does not recognise.

    ``key`` is always the literal ``"pattern"``: it is the only value apis.yaml
    documents for a DLP criteria entry. ``id`` and ``cfg_type`` exist on
    ``RESTDlpRule`` but are controller-assigned, so they are not sent. ``context``
    is ``omitempty`` in apis.go and is omitted whenever the caller left it unset,
    rather than being sent as null or as an invented default.
    """
    patterns: list[dict[str, Any]] = []
    for pattern in rule.patterns:
        entry: dict[str, Any] = {"key": "pattern", "op": pattern.op, "value": pattern.value}
        if pattern.context is not None:
            entry["context"] = pattern.context
        patterns.append(entry)
    return {"name": rule.name, "patterns": patterns}


def _describe_dlp_rules(rules: list[DlpRuleInput]) -> str:
    """One-line human summary of a rule list, for the confirmation plan."""
    return "; ".join(
        f"{r.name} [{', '.join(f'{p.op} {p.value}' for p in r.patterns)}]" for r in rules
    )


def _validate_dlp_rules(rules: list[DlpRuleInput]) -> None:
    """Reject rule lists the controller's own limits would reject.

    Limits are the ``Dlp*`` constants in apis.go: at most
    ``DlpRulePatternMaxNum`` patterns per rule, ``DlpRulePatternMaxLen``
    characters per pattern, and ``DlpRulePatternTotalMaxLen`` characters across
    one rule's patterns combined. Checked here so an over-long sensor fails
    before the guard runs, with a message naming the offending rule.

    Raises:
        ValidationError_: when any limit is exceeded. Nothing is sent.
    """
    for rule in rules:
        if len(rule.patterns) > DLP_RULE_PATTERN_MAX_NUM:
            raise ValidationError_(
                f"DLP rule {rule.name!r} has {len(rule.patterns)} patterns; the controller "
                f"allows at most {DLP_RULE_PATTERN_MAX_NUM} per rule. Nothing was sent to "
                f"the controller."
            )
        for pattern in rule.patterns:
            if len(pattern.value) > DLP_RULE_PATTERN_MAX_LEN:
                raise ValidationError_(
                    f"a pattern on DLP rule {rule.name!r} is {len(pattern.value)} characters; "
                    f"the controller allows at most {DLP_RULE_PATTERN_MAX_LEN}. Nothing was "
                    f"sent to the controller."
                )
        total = sum(len(pattern.value) for pattern in rule.patterns)
        if total > DLP_RULE_PATTERN_TOTAL_MAX_LEN:
            raise ValidationError_(
                f"DLP rule {rule.name!r} has {total} characters of pattern in total; the "
                f"controller allows at most {DLP_RULE_PATTERN_TOTAL_MAX_LEN} across one "
                f"rule. Split it into several rules. Nothing was sent to the controller."
            )


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the DLP read and write tools, each gated on its own toolset."""
    if settings.toolset_enabled("policy_read"):
        _register_reads(mcp)
    if settings.toolset_enabled("policy_write"):
        _register_writes(mcp)


def _register_reads(mcp: FastMCP) -> None:
    """DLP read tools. Tagged ``policy_read``; none of them takes 'confirm'."""

    @mcp.tool(
        name="nv_get_dlp_sensor",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_dlp_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Sensor to read. Get exact names from nv_list_dlp_sensors.",
            ),
        ],
    ) -> DlpSensorDetail:
        """One DLP sensor including its rules and regex bodies.

        This is the only tool that returns DLP pattern bodies; nv_list_dlp_sensors omits
        them. Read a sensor before updating it: nv_update_dlp_sensor replaces the rule
        list wholesale, so an update built without seeing the current rules silently
        drops the ones it omits along with the data they protect.

        The 'groups' field tells you whether the sensor inspects anything at all - a
        sensor bound to no group matches nothing. 'predefined' sensors ship with
        NeuVector and cannot be updated or deleted.

        Calls GET /v1/dlp/sensor/{name}.
        """
        # apis.go RESTDlpSensorData: envelope key 'sensor'.
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/dlp/sensor/{sensor_name}", "sensor")
        if not raw:
            raise NotFoundError(f"no DLP sensor named {sensor_name!r}")
        return DlpSensorDetail.from_api(raw)

    @mcp.tool(
        name="nv_list_dlp_groups",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_list_dlp_groups(
        ctx: Context,
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
    ) -> DlpGroupList:
        """Which groups have DLP inspection enabled and which sensors are bound to them.

        A DLP sensor only inspects traffic once it is bound to a group here, and a
        binding with action='deny' only DROPS traffic once that group's policy mode is
        Protect - in Discover or Monitor a match raises a threat event and the traffic
        passes. Use this to answer 'is this sensor actually doing anything'.

        Calls GET /v1/dlp/group.
        """
        # apis.go RESTDlpGroupsData: envelope key 'dlp_groups'. Unlike GET /v1/waf/group,
        # apis.yaml documents NO 'scope' parameter on this route, so none is sent and
        # paging is done client-side. The asymmetry is upstream's.
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        items = await app.client.get_list("/v1/dlp/group", "dlp_groups")
        if bound_only:
            items = [item for item in items if (item.get("sensors") or [])]

        window = items[start : start + effective_limit + 1]
        truncated = len(window) > effective_limit
        page_items = window[:effective_limit]
        return DlpGroupList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More DLP groups exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            groups=[DlpGroup.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_dlp_group",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_dlp_group(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group to read, e.g. 'nv.api.prod'. Names come from nv_list_groups.",
            ),
        ],
    ) -> DlpGroup:
        """DLP configuration for one group: inspection status and bound sensors.

        Read this before nv_set_dlp_group. That tool's 'sensors' argument REPLACES the
        binding list rather than adding to it, so an update built without the current
        list unbinds whatever it leaves out and stops the inspection that binding
        provided, without any error.

        'status' tells you whether DLP is enabled for the group at all; a group can
        carry bindings with status=false and inspect nothing.

        Calls GET /v1/dlp/group/{name}.
        """
        # apis.go RESTDlpGroupData: envelope key 'dlp_group'.
        app = app_context(ctx)
        raw = await app.client.get_object(f"/v1/dlp/group/{group_name}", "dlp_group")
        if not raw:
            raise NotFoundError(f"no DLP configuration for group {group_name!r}")
        return DlpGroup.from_api(raw)


def _register_writes(mcp: FastMCP) -> None:
    """DLP write tools. Tagged ``policy_write``; every one takes 'confirm'."""

    @mcp.tool(
        name="nv_create_dlp_sensor",
        annotations=MUTATING_CREATE,
        tags={"policy_write", "write"},
    )
    async def nv_create_dlp_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=DLP_NAME_MAX_LEN,
                description="Name for the new sensor. NeuVector's own sensors use a 'sensor.' "
                "prefix; a duplicate name is rejected by the controller.",
            ),
        ],
        rules: Annotated[
            list[DlpRuleInput],
            Field(
                min_length=1,
                description="Rules the sensor carries. Rules are ORed - traffic matching ANY "
                "rule fires the sensor. Patterns within one rule are ANDed.",
            ),
        ],
        comment: Annotated[
            str | None,
            Field(
                max_length=DLP_COMMENT_MAX_LEN,
                description="Why this sensor exists. Shown in the NeuVector UI. Omit to send "
                "no comment field at all.",
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Create a DLP sensor: a named bundle of regexes matched against traffic.

        Creating a sensor changes NOTHING on its own. It inspects traffic only once
        nv_set_dlp_group binds it to a group, and it DROPS traffic only when that
        binding uses action='deny' AND the group is in Protect mode - in Discover or
        Monitor a match raises a threat event and the traffic proceeds. Test a new
        sensor against a Monitor-mode group first.

        Two regex cautions. An 'op' of '!regex' fires when the expression does NOT
        match, which is how allowlists are written and is very easy to get backwards -
        an over-narrow '!regex' fires on every legitimate byte. And the enforcer runs
        these on live packets, so an expression that backtracks catastrophically costs
        real latency.

        Calls POST /v1/dlp/sensor with {"config": {"name":..., "cfg_type": "user_created", "rules": [{"name","patterns":[{"key","op","value"}]}], "comment":...}}.
        """
        # Body shape from apis.go RESTDlpSensorConfigData / RESTDlpSensorConfig.
        # 'comment' is a *string with omitempty there, so it is omitted rather than
        # sent as "" when the caller gave none - sending "" would clear it on PATCH,
        # and this tool and nv_update_dlp_sensor keep the same rule.
        _validate_dlp_rules(rules)
        app = app_context(ctx)
        config: dict[str, Any] = {
            "name": sensor_name,
            "cfg_type": "user_created",
            "rules": [_dlp_rule_body(r) for r in rules],
        }
        if comment is not None:
            config["comment"] = comment
        payload: dict[str, Any] = {"config": config}
        negatives = [f"{r.name}/{p.value}" for r in rules for p in r.patterns if p.op == "!regex"]
        plan = authorise_write(
            app.settings,
            operation="nv_create_dlp_sensor",
            toolset="policy_write",
            target=sensor_name,
            effect=(
                f"Create DLP sensor {sensor_name!r} with {len(rules)} rule(s): "
                f"{_describe_dlp_rules(rules)}. The sensor is bound to no group, so it "
                f"inspects nothing until nv_set_dlp_group binds it, and drops nothing "
                f"until that binding uses action='deny' and the group is in Protect mode. "
                + (
                    f"CAUTION: {len(negatives)} pattern(s) use '!regex' and therefore fire on "
                    f"all traffic that does NOT match ({', '.join(negatives)}). Verify the "
                    f"expression covers all legitimate traffic before binding."
                    if negatives
                    else "All patterns are positive matches."
                )
            ),
            payload=payload,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("POST", "/v1/dlp/sensor", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_create_dlp_sensor",
            target=sensor_name,
            effect=(
                f"DLP sensor {sensor_name} created with {len(rules)} rule(s); "
                f"not yet bound to any group"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_dlp_sensor",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_update_dlp_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=DLP_NAME_MAX_LEN,
                description="Sensor to update. It must already exist and must not be predefined.",
            ),
        ],
        rules: Annotated[
            list[DlpRuleInput],
            Field(
                min_length=1,
                description="The COMPLETE rule list after the update. This REPLACES the "
                "sensor's rules; any existing rule you omit is deleted. Read the current "
                "rules with nv_get_dlp_sensor and send them back plus your changes.",
            ),
        ],
        comment: Annotated[
            str | None,
            Field(
                max_length=DLP_COMMENT_MAX_LEN,
                description="Replacement comment. Omit to leave the existing comment "
                "untouched; pass an empty string to clear it.",
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Replace a DLP sensor's rules.

        This is a REPLACE, not a merge: the rule list you send becomes the sensor's
        entire rule list, and anything omitted is silently dropped along with the
        detection it provided. Call nv_get_dlp_sensor first and build the new list from
        what is actually there.

        If the sensor is already bound with action='deny' to a Protect-mode group, the
        new patterns start dropping matching traffic immediately - check bindings with
        nv_get_dlp_sensor. Predefined sensors that ship with NeuVector cannot be updated.

        Calls PATCH /v1/dlp/sensor/{name} with {"config": {"name":..., "rules": [...], "comment":...}}.
        """
        # apis.go RESTDlpSensorConfig: 'rules' is *[]RESTDlpRule (the GUI replace list),
        # 'comment' is *string. Both are omitempty pointers, so an omitted 'comment' is
        # "leave unchanged" and an empty string is "clear it". 'cfg_type' is not sent on
        # PATCH: the sensor already has one and the controller does not re-derive it.
        _validate_dlp_rules(rules)
        app = app_context(ctx)
        config: dict[str, Any] = {
            "name": sensor_name,
            "rules": [_dlp_rule_body(r) for r in rules],
        }
        if comment is not None:
            config["comment"] = comment
        payload: dict[str, Any] = {"config": config}
        negatives = [f"{r.name}/{p.value}" for r in rules for p in r.patterns if p.op == "!regex"]
        plan = authorise_write(
            app.settings,
            operation="nv_update_dlp_sensor",
            toolset="policy_write",
            target=sensor_name,
            effect=(
                f"REPLACE every rule on DLP sensor {sensor_name!r} with {len(rules)} rule(s): "
                f"{_describe_dlp_rules(rules)}. Any rule currently on the sensor and absent "
                f"from this list is deleted and stops detecting. If the sensor is bound with "
                f"action='deny' to a Protect-mode group these patterns start dropping traffic "
                f"immediately. "
                + (
                    f"CAUTION: {len(negatives)} pattern(s) use '!regex' and fire on all "
                    f"traffic that does NOT match ({', '.join(negatives)}). "
                    if negatives
                    else ""
                )
                + (
                    "The sensor's comment is left unchanged. "
                    if comment is None
                    else f"The comment becomes {comment!r}. "
                )
                + f"Confirm the current rules with nv_get_dlp_sensor({sensor_name!r}) first."
            ),
            payload=payload,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/dlp/sensor/{sensor_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_update_dlp_sensor",
            target=sensor_name,
            effect=f"DLP sensor {sensor_name} now carries {len(rules)} rule(s)",
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_dlp_sensor",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_dlp_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str,
            Field(min_length=1, max_length=DLP_NAME_MAX_LEN, description="Sensor to delete."),
        ],
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Delete a DLP sensor and every rule it carries.

        Deletion ends detection silently: any group the sensor was bound to keeps
        running with one fewer sensor, the data it protected stops being watched, and
        nothing reports the gap. Check nv_get_dlp_sensor for the 'groups' list before
        deleting - if it is non-empty you are removing live inspection from those
        groups. Predefined sensors cannot be deleted.

        Calls DELETE /v1/dlp/sensor/{name}.
        """
        app = app_context(ctx)
        plan = authorise_write(
            app.settings,
            operation="nv_delete_dlp_sensor",
            toolset="policy_write",
            target=sensor_name,
            effect=(
                f"Delete DLP sensor {sensor_name!r} and all of its rules. Every group it is "
                f"bound to loses that inspection immediately and silently. Run "
                f"nv_get_dlp_sensor({sensor_name!r}) and read its 'groups' field before "
                f"confirming."
            ),
            payload=None,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("DELETE", f"/v1/dlp/sensor/{sensor_name}")
        return WriteOutcome(
            status="applied",
            operation="nv_delete_dlp_sensor",
            target=sensor_name,
            effect=f"DLP sensor {sensor_name} deleted",
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_set_dlp_group",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_set_dlp_group(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group to configure, e.g. 'nv.api.prod'. From nv_list_groups.",
            ),
        ],
        sensors: Annotated[
            list[DlpSensorBindingInput],
            Field(
                description="The COMPLETE binding list after the change. This REPLACES the "
                "group's bindings; an empty list unbinds every sensor. Read the current "
                "bindings with nv_get_dlp_group first.",
            ),
        ],
        status: Annotated[
            bool | None,
            Field(
                description="True enables DLP inspection for the group, False disables it "
                "without changing the bindings. Omit to leave the current setting alone - "
                "the field is optional on the controller and is then not sent at all."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Bind DLP sensors to a group and enable or disable inspection.

        This is the tool that makes a DLP sensor live, and it is the most dangerous one
        in this module: a sensor bound with action='deny' to a group already in Protect
        mode starts DROPPING matching traffic the moment this call returns. Data-loss
        patterns are broad by design, so a false positive here silently breaks a working
        application rather than merely logging.

        Binding is a REPLACE: the list you send becomes the group's entire binding set,
        and an omitted sensor is unbound. Bind in Monitor first, watch
        nv_query_security_events with kind='threat' for false positives, and only then
        move the group to Protect with nv_set_group_policy_mode.

        Calls PATCH /v1/dlp/group/{name} with {"config": {"name":..., "replace": [{"name","action"}], "status":...}}.
        """
        # apis.go RESTDlpGroupConfig: 'replace' (*[]RESTDlpConfig) is the GUI replace
        # list and is always sent, so an empty list is how you unbind everything. The
        # sibling 'delete' key is *[]string - bare NAMES, not objects - and is not used
        # here. 'status' is a *bool with omitempty, so it is omitted when the caller
        # passed nothing rather than defaulting to true and silently enabling inspection.
        app = app_context(ctx)
        config: dict[str, Any] = {
            "name": group_name,
            "replace": [{"name": s.name, "action": s.action} for s in sensors],
        }
        if status is not None:
            config["status"] = status
        payload: dict[str, Any] = {"config": config}
        denying = [s.name for s in sensors if s.action == "deny"]
        binding_text = ", ".join(f"{s.name} ({s.action})" for s in sensors) if sensors else "none"
        status_text = (
            "Inspection status is left unchanged."
            if status is None
            else f"DLP inspection for the group is set to status={status}."
        )
        plan = authorise_write(
            app.settings,
            operation="nv_set_dlp_group",
            toolset="policy_write",
            target=group_name,
            effect=(
                f"REPLACE the DLP sensor bindings on group {group_name!r} with: "
                f"{binding_text}. {status_text} Any sensor currently bound and absent from "
                f"this list is unbound and stops inspecting. "
                + (
                    f"{len(denying)} sensor(s) bind with action='deny' ({', '.join(denying)}): "
                    f"these only raise threat events while the group is in Discover or Monitor "
                    f"mode, and will DROP matching traffic if the group is in, or is later "
                    f"moved to, Protect mode. "
                    if denying
                    else ""
                )
                + f"Check the group's current mode with nv_get_group({group_name!r}) and its "
                f"current bindings with nv_get_dlp_group({group_name!r}) before confirming."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_group_name(group_name),
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/dlp/group/{group_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_set_dlp_group",
            target=group_name,
            effect=(
                f"DLP on group {group_name}: bindings replaced with {binding_text}"
                + ("" if status is None else f", status={status}")
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )
