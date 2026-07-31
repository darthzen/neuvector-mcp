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

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..errors import ValidationError_
from ..guard import authorise_write
from ..models import (
    FileMonitorFilterInput,
    GroupCriterionInput,
    NetworkRuleInput,
    ProcessProfileEntryInput,
    WafRuleInput,
    WafSensorBindingInput,
    WriteOutcome,
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

#: Hard cap on one batch of network-rule changes. A batch that is wrong drops
#: traffic for every connection the reordered rules no longer cover, so batches
#: stay small enough for a human to read the preview in full.
MAX_RULE_CHANGES = 16


def _namespace_from_group_name(group_name: str) -> str | None:
    """Namespace a learned group belongs to, for NV_ALLOWED_NAMESPACES.

    Learned groups are named ``nv.<service>.<namespace>``; anything else is a
    custom group whose namespace cannot be derived from its name. Mirrors the
    inline expression in ``nv_set_group_policy_mode`` exactly - do not change
    that tool to call this helper (rule N3).
    """
    return group_name.split(".")[-1] if group_name.startswith("nv.") else None


def _namespace_from_criteria(criteria: list[GroupCriterionInput]) -> str | None:
    """Namespace a group's criteria pin it to, or None.

    ``domain`` is the controller's field name for a Kubernetes namespace
    (``RESTGroup.domain``), so a criterion on ``domain`` is what makes a group
    namespace-scoped. The first such criterion wins.
    """
    for criterion in criteria:
        if criterion.key == "domain":
            return criterion.value
    return None


def _rule_body(rule: NetworkRuleInput) -> dict[str, Any]:
    """Render one ``RESTPolicyRule`` request object.

    ``from`` and ``to`` are Python keywords, so the input model names them
    ``from_group`` / ``to_group`` and this function writes the controller's
    field names by string key. Built explicitly rather than by
    ``model_dump()`` so the wire shape is auditable field by field.
    """
    body: dict[str, Any] = {
        "from": rule.from_group,
        "to": rule.to_group,
        "ports": rule.ports,
        "action": rule.action,
        "applications": list(rule.applications),
        "comment": rule.comment,
        "disable": rule.disable,
        "cfg_type": "user_created",
    }
    if rule.id is not None:
        body["id"] = rule.id
    return body


def _process_entry_body(entry: ProcessProfileEntryInput, group_name: str) -> dict[str, Any]:
    """Render one ``RESTProcessProfileEntryConfig``; all four fields are required."""
    return {
        "name": entry.name,
        "path": entry.path,
        "action": entry.action,
        "group": group_name,
    }


def _waf_rule_body(rule: WafRuleInput) -> dict[str, Any]:
    """Render one WAF rule request object.

    Field names were confirmed by writing to a live controller and reading the
    sensor back unchanged; Appendix B documents no WAF config schema. ``key`` is
    always the literal ``"pattern"`` - the controller emits nothing else for WAF.
    """
    return {
        "name": rule.name,
        "patterns": [
            {"key": "pattern", "op": p.op, "value": p.value, "context": p.context}
            for p in rule.patterns
        ],
    }


def _describe_waf_rules(rules: list[WafRuleInput]) -> str:
    """One-line human summary of a rule list, for the confirmation plan."""
    return "; ".join(
        f"{r.name} [{', '.join(f'{p.op} on {p.context}' for p in r.patterns)}]" for r in rules
    )


def _file_filter_body(item: FileMonitorFilterInput, group_name: str) -> dict[str, Any]:
    """Render one ``RESTFileMonitorFilterConfig``; all five fields are required."""
    return {
        "filter": item.filter,
        "recursive": item.recursive,
        "behavior": item.behavior,
        "applications": list(item.applications),
        "group": group_name,
    }


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
        payload: dict[str, Any] = {"config": {"name": group_name, "policy_mode": mode}}
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

        response = await app.client.request("PATCH", f"/v1/group/{group_name}", json=payload)
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

    @mcp.tool(
        name="nv_create_group",
        annotations=MUTATING_CREATE,
        tags={"policy_write", "write"},
    )
    async def nv_create_group(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for the new group. Must not begin 'nv.' - that prefix is "
                "reserved for groups NeuVector learns, and the controller rejects it with "
                "code 15.",
            ),
        ],
        criteria: Annotated[
            list[GroupCriterionInput],
            Field(
                min_length=1,
                description="Match criteria defining membership. A workload joins the group "
                "when it satisfies ALL of them. Copy exact keys and operators from an existing "
                "group via nv_get_group; at least one criterion is required or the group would "
                "match everything.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Create a custom group defined by membership criteria.

        A group is the unit every policy attaches to: network rules, process profiles and
        file-monitor profiles all reference groups, not workloads. Membership is
        re-evaluated continuously, so every current and future workload matching the
        criteria joins. Creating a group changes no enforcement on its own - it becomes
        live only when a rule or a policy mode references it. Get exact criterion keys
        and operators by reading an existing group with nv_get_group; a name beginning
        'nv.' is reserved for learned groups and is rejected with code 15, and a
        duplicate name is rejected with code 13.

        Calls POST /v1/group with {"config": {"name":..., "criteria":[{"key","value","op"}], "cfg_type": "user_created"}}.
        """
        app = app_context(ctx)
        payload: dict[str, Any] = {
            "config": {
                "name": group_name,
                "cfg_type": "user_created",
                "criteria": [{"key": c.key, "value": c.value, "op": c.op} for c in criteria],
            }
        }
        criteria_text = "; ".join(f"{c.key} {c.op} {c.value}" for c in criteria)
        plan = authorise_write(
            app.settings,
            operation="nv_create_group",
            toolset="policy_write",
            target=group_name,
            effect=(
                f"Create user-created group {group_name!r} with {len(criteria)} criterion(s): "
                f"{criteria_text}. Membership is re-evaluated continuously, so every current "
                f"and future workload matching ALL of those criteria joins the group. No "
                f"policy rule references the new group yet, so no traffic changes until one "
                f"does."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_criteria(criteria),
        )
        if plan is not None:
            return plan

        response = await app.client.request("POST", "/v1/group", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_create_group",
            target=group_name,
            effect=(
                f"group {group_name} created with {len(criteria)} criterion(s): {criteria_text}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_group_criteria",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_update_group_criteria(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group whose criteria to replace. Learned groups (names beginning "
                "'nv.') have controller-owned criteria and are rejected with code 4.",
            ),
        ],
        criteria: Annotated[
            list[GroupCriterionInput],
            Field(
                min_length=1,
                description="The COMPLETE new criteria set. This REPLACES the existing set - it "
                "is not merged, so any criterion you omit is removed. Read the current set with "
                "nv_get_group and echo back everything you intend to keep.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Replace the membership criteria of one custom group.

        This is a whole-set replacement, not a merge: criteria you do not send are
        removed. Call nv_get_group first, then send the criteria you want to keep plus
        your change. Membership changes take effect at once, so every network rule,
        process profile and file-monitor profile attached to this group starts applying
        to a different set of workloads - a workload that leaves the group loses its
        allow rules, and if its new group is in Protect mode its traffic is dropped.
        Learned groups ('nv.' prefix) have controller-owned criteria and are rejected
        with code 4.

        Calls PATCH /v1/group/{name} with {"config": {"name":..., "criteria":[{"key","value","op"}], "cfg_type": "user_created"}}.
        """
        app = app_context(ctx)
        payload: dict[str, Any] = {
            "config": {
                "name": group_name,
                "cfg_type": "user_created",
                "criteria": [{"key": c.key, "value": c.value, "op": c.op} for c in criteria],
            }
        }
        criteria_text = "; ".join(f"{c.key} {c.op} {c.value}" for c in criteria)
        plan = authorise_write(
            app.settings,
            operation="nv_update_group_criteria",
            toolset="policy_write",
            target=group_name,
            effect=(
                f"REPLACE all match criteria of group {group_name!r} with {len(criteria)} "
                f"criterion(s): {criteria_text}. This is a whole-set replacement, not a "
                f"merge: any criterion not listed here is REMOVED. Group membership changes "
                f"immediately, so every network rule, process profile and file monitor "
                f"attached to {group_name!r} starts applying to a different set of "
                f"workloads - workloads that leave the group lose its allow rules and, in "
                f"Protect mode, have their traffic dropped. Call "
                f"nv_get_group({group_name!r}) first and echo back the criteria you intend "
                f"to keep."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_group_name(group_name) or _namespace_from_criteria(criteria),
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/group/{group_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_update_group_criteria",
            target=group_name,
            effect=(
                f"criteria of {group_name} replaced with {len(criteria)} criterion(s): "
                f"{criteria_text}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_apply_network_rule_changes",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_apply_network_rule_changes(
        ctx: Context,
        insert_rules: Annotated[
            list[NetworkRuleInput],
            Field(
                default_factory=list,
                description="New rules to insert, in the order they should appear. Omit 'id' on "
                "every entry - the controller assigns ids. Insert risky rules with disable=true "
                "first, verify with nv_list_network_rules, then enable them.",
            ),
        ],
        configure_rules: Annotated[
            list[NetworkRuleInput],
            Field(
                default_factory=list,
                description="Existing rules to overwrite in place. Every entry MUST carry the "
                "'id' of the rule it replaces; the whole rule is overwritten, so send every "
                "field you want to keep. Read current values with nv_get_network_rule first.",
            ),
        ],
        delete_rule_ids: Annotated[
            list[int],
            Field(
                default_factory=list,
                description="Ids of rules to delete. Learned rules cannot be deleted and are "
                "rejected with code 4.",
            ),
        ],
        insert_after_rule_id: Annotated[
            int | None,
            Field(
                description="Existing rule id that the inserted rules are positioned relative "
                "to (controller field 'insert.after'). Omit to let the controller choose the "
                "position. The controller's interpretation of this value is not documented - "
                "verify the resulting order with nv_list_network_rules immediately after "
                "applying."
            ),
        ] = None,
        move_rule_id: Annotated[
            int | None,
            Field(
                ge=0,
                description="Id of one existing rule to move. The controller accepts at most "
                "one move per batch. Moving a rule changes which connections the rules above "
                "it no longer see.",
            ),
        ] = None,
        move_after_rule_id: Annotated[
            int | None,
            Field(
                description="Existing rule id that move_rule_id is positioned relative to "
                "(controller field 'move.after'). Requires move_rule_id. Omit to let the "
                "controller choose."
            ),
        ] = None,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' edits this cluster's rules. 'fed' edits federated rules, "
                "which only a federation primary may change - elsewhere the controller rejects "
                "them with code 46."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the whole batch as a diff."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Apply one atomic batch of network policy rule changes: insert, move, configure and delete.

        HIGHEST-RISK TOOL IN THIS SERVER. Network rules are an ORDERED list evaluated
        top-down, first match wins, so inserting, moving or deleting a rule changes the
        verdict for every connection the rules above it no longer see. Any group in
        Protect mode then DROPS the connections no surviving rule allows, with no warning
        and no rollback. Read the current list with nv_list_network_rules first, keep the
        batch small, insert risky rules with disable=true, and re-read the list
        immediately after applying to confirm the order you got is the order you wanted.
        Every entry in configure_rules must carry the id of the rule it overwrites, and
        the whole rule is overwritten - send every field you want to keep. At most 16
        changes per call and at most one move per call.

        Calls PATCH /v1/policy/rule with scope and {"insert": {"after":..., "rules":[...]}, "move": {"id":..., "after":...}, "rules": [...], "delete": [...]}.
        """
        app = app_context(ctx)

        inserts = list(insert_rules)
        configures = list(configure_rules)
        deletes = list(delete_rule_ids)
        change_count = (
            len(inserts) + len(configures) + len(deletes) + (1 if move_rule_id is not None else 0)
        )

        # --- step 1 validation: local only, no network call (invariant C6) ----
        if change_count == 0:
            raise ValidationError_(
                "nv_apply_network_rule_changes needs at least one of insert_rules, "
                "move_rule_id, configure_rules or delete_rule_ids."
            )
        if change_count > MAX_RULE_CHANGES:
            raise ValidationError_(
                f"batch of {change_count} rule changes exceeds the hard cap of "
                f"{MAX_RULE_CHANGES}. Split it into smaller batches and verify with "
                "nv_list_network_rules between them: a large batch that is wrong drops "
                "production traffic before anyone reads the result."
            )
        if any(r.id is None for r in configures):
            raise ValidationError_(
                "every entry in configure_rules must carry the 'id' of the rule it "
                "overwrites. Get ids from nv_list_network_rules. Sending unidentified "
                "rules risks being interpreted as a replacement of the whole rule list."
            )
        if any(r.id is not None for r in inserts):
            raise ValidationError_(
                "entries in insert_rules must NOT carry an 'id'; the controller assigns "
                "ids to inserted rules. Use configure_rules to change an existing rule."
            )
        if move_after_rule_id is not None and move_rule_id is None:
            raise ValidationError_(
                "move_after_rule_id was given without move_rule_id; there is nothing to move."
            )
        if insert_after_rule_id is not None and not inserts:
            raise ValidationError_(
                "insert_after_rule_id was given without insert_rules; there is nothing to insert."
            )

        payload: dict[str, Any] = {}
        if inserts:
            insert_body: dict[str, Any] = {"rules": [_rule_body(r) for r in inserts]}
            if insert_after_rule_id is not None:
                insert_body["after"] = insert_after_rule_id
            payload["insert"] = insert_body
        if move_rule_id is not None:
            move_body: dict[str, Any] = {"id": move_rule_id}
            if move_after_rule_id is not None:
                move_body["after"] = move_after_rule_id
            payload["move"] = move_body
        if configures:
            payload["rules"] = [_rule_body(r) for r in configures]
        if deletes:
            payload["delete"] = [int(i) for i in deletes]

        # --- the diff-style preview ------------------------------------------
        lines: list[str] = []
        for rule in inserts:
            lines.append(
                f"  + INSERT {rule.from_group} -> {rule.to_group} "
                f"ports={rule.ports or 'any'} "
                f"applications={','.join(rule.applications) or 'any'} "
                f"action={rule.action.upper()}"
                f"{' [disabled]' if rule.disable else ''}"
            )
        if inserts:
            lines.append(
                "  = POSITION inserted rules are placed "
                + (
                    f"relative to existing rule id {insert_after_rule_id}"
                    if insert_after_rule_id is not None
                    else "at the position the controller chooses (no 'after' given)"
                )
            )
        if move_rule_id is not None:
            lines.append(
                f"  ~ MOVE rule id {move_rule_id} "
                + (
                    f"relative to existing rule id {move_after_rule_id}"
                    if move_after_rule_id is not None
                    else "to the position the controller chooses (no 'after' given)"
                )
            )
        for rule in configures:
            lines.append(
                f"  ~ CONFIGURE rule id {rule.id}: OVERWRITE with "
                f"{rule.from_group} -> {rule.to_group} "
                f"ports={rule.ports or 'any'} "
                f"applications={','.join(rule.applications) or 'any'} "
                f"action={rule.action.upper()}"
                f"{' [disabled]' if rule.disable else ''}"
            )
        for rule_id in deletes:
            lines.append(f"  - DELETE rule id {rule_id}")
        diff = "\n".join(lines)

        target = f"network policy rules (scope={scope})"
        plan = authorise_write(
            app.settings,
            operation="nv_apply_network_rule_changes",
            toolset="policy_write",
            target=target,
            effect=(
                f"Apply {change_count} network policy rule change(s) to scope {scope!r} as "
                f"ONE atomic batch:\n{diff}\n"
                f"Rule order IS evaluation order: the list is evaluated top-down and the "
                f"first matching rule decides the connection, so inserting, moving or "
                f"deleting a rule changes the verdict for every connection the rules above "
                f"it no longer see. Any group in Protect mode then DROPS the connections no "
                f"surviving rule allows. CONFIGURE entries are sent in the batch's 'rules' "
                f"array and OVERWRITE the whole rule at that id - fields you did not send "
                f"are reset. Re-read the list with nv_list_network_rules straight after "
                f"applying and confirm the order you got is the order you wanted."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH",
            "/v1/policy/rule",
            params=build_query(extra={"scope": scope}),
            json=payload,
        )
        return WriteOutcome(
            status="applied",
            operation="nv_apply_network_rule_changes",
            target=target,
            effect=(
                f"applied {change_count} network policy rule change(s) to scope {scope}:\n"
                f"{diff}\n"
                f"Verify the resulting order with nv_list_network_rules(scope={scope!r})."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_network_rule",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_network_rule(
        ctx: Context,
        rule_id: Annotated[
            int,
            Field(
                ge=0,
                description="Id of the network policy rule to delete. Get ids from "
                "nv_list_network_rules, and read the rule with nv_get_network_rule first to "
                "see what it allows or denies.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete one network policy rule by id.

        Rules are an ordered list evaluated top-down, first match wins, so deleting one
        makes its traffic fall through to the rules below it. Deleting an allow rule can
        DROP production traffic the moment the source group is in Protect mode and
        nothing below matches; deleting a deny rule can permit traffic that was being
        blocked. Read the rule with nv_get_network_rule first to see which case you are
        in. Learned rules cannot be deleted - the controller rejects those with code 4.
        To remove several rules atomically, or to remove and reorder in one step, use
        nv_apply_network_rule_changes instead.

        Calls DELETE /v1/policy/rule/{id}.
        """
        app = app_context(ctx)
        plan = authorise_write(
            app.settings,
            operation="nv_delete_network_rule",
            toolset="policy_write",
            target=str(rule_id),
            effect=(
                f"Delete network policy rule id {rule_id}. Rules are evaluated top-down, "
                f"first match wins, so this rule's traffic falls through to the rules below "
                f"it: if it was an ALLOW rule, connections it permitted are DROPPED as soon "
                f"as no lower rule matches and the source group is in Protect mode; if it "
                f"was a DENY rule, connections it blocked may now be permitted. Call "
                f"nv_get_network_rule({rule_id}) first to see which. Learned rules cannot be "
                f"deleted (controller code 4)."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("DELETE", f"/v1/policy/rule/{rule_id}")
        return WriteOutcome(
            status="applied",
            operation="nv_delete_network_rule",
            target=str(rule_id),
            effect=f"network policy rule {rule_id} deleted",
            payload={},
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_process_profile",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_update_process_profile(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group whose process profile to change, e.g. 'nv.api.prod'. Read "
                "the current profile with nv_get_process_profile and the group's enforcement "
                "mode with nv_get_group first.",
            ),
        ],
        add_entries: Annotated[
            list[ProcessProfileEntryInput],
            Field(
                default_factory=list,
                description="Entries to add or change. An entry with the same name and path as "
                "an existing one replaces it, so this is how you flip an entry from allow to "
                "deny.",
            ),
        ],
        delete_entries: Annotated[
            list[ProcessProfileEntryInput],
            Field(
                default_factory=list,
                description="Entries to remove. Removing an 'allow' entry means the process is "
                "no longer permitted - in Protect mode the enforcer kills it.",
            ),
        ],
        alert_disabled: Annotated[
            bool | None,
            Field(
                description="True stops this profile raising alerts on a violation. Omit to "
                "leave the current setting alone. Disabling alerts hides process incidents you "
                "would otherwise see in nv_query_security_events."
            ),
        ] = None,
        hash_enabled: Annotated[
            bool | None,
            Field(
                description="True makes the enforcer verify executable hashes as well as paths. "
                "Omit to leave the current setting alone. Enabling it can start blocking "
                "processes whose binaries were legitimately updated."
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
        """Add, change or remove allowed-process entries in one group's process profile.

        BLAST RADIUS: the process profile is an allowlist the enforcer checks every
        process against, and in Protect mode it acts immediately. A 'deny' entry, or
        removing the 'allow' entry that covers a process running right now, KILLS that
        process in EVERY container in the group - including sidecars, entrypoints and
        health checks. In Discover or Monitor mode the same change only raises a
        'process' incident. Read the current entries with nv_get_process_profile and the
        group's mode with nv_get_group before you confirm. The request body's envelope
        key is 'process_profile_config', not 'config'.

        Calls PATCH /v1/process_profile/{name} with {"process_profile_config": {"group":..., "process_change_list":[...], "process_delete_list":[...]}}.
        """
        app = app_context(ctx)

        if (
            not add_entries
            and not delete_entries
            and alert_disabled is None
            and hash_enabled is None
        ):
            raise ValidationError_(
                "nv_update_process_profile needs at least one of add_entries, "
                "delete_entries, alert_disabled or hash_enabled."
            )

        config: dict[str, Any] = {"group": group_name}
        if alert_disabled is not None:
            config["alert_disabled"] = alert_disabled
        if hash_enabled is not None:
            config["hash_enabled"] = hash_enabled
        if add_entries:
            config["process_change_list"] = [
                _process_entry_body(e, group_name) for e in add_entries
            ]
        if delete_entries:
            config["process_delete_list"] = [
                _process_entry_body(e, group_name) for e in delete_entries
            ]
        payload: dict[str, Any] = {"process_profile_config": config}

        add_text = (
            "; ".join(f"{e.action.upper()} {e.name} at {e.path}" for e in add_entries) or "none"
        )
        del_text = (
            "; ".join(f"{e.action.upper()} {e.name} at {e.path}" for e in delete_entries) or "none"
        )
        flags_text = (
            ", ".join(
                part
                for part in (
                    None if alert_disabled is None else f"alert_disabled={alert_disabled}",
                    None if hash_enabled is None else f"hash_enabled={hash_enabled}",
                )
                if part is not None
            )
            or "unchanged"
        )

        plan = authorise_write(
            app.settings,
            operation="nv_update_process_profile",
            toolset="policy_write",
            target=group_name,
            effect=(
                f"Update the process profile of group {group_name!r}. "
                f"Add or change {len(add_entries)} entry(ies): {add_text}. "
                f"Remove {len(delete_entries)} entry(ies): {del_text}. "
                f"Profile flags: {flags_text}. "
                f"BLAST RADIUS: if group {group_name!r} is in Protect mode the enforcer acts "
                f"on this profile immediately - a 'deny' entry, or removing the 'allow' "
                f"entry covering a process that is running right now, KILLS that process in "
                f"every container in the group. In Discover or Monitor mode the same change "
                f"only raises a 'process' incident. Check the mode with "
                f"nv_get_group({group_name!r}) and the current entries with "
                f"nv_get_process_profile({group_name!r}) before confirming."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_group_name(group_name),
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH", f"/v1/process_profile/{group_name}", json=payload
        )
        return WriteOutcome(
            status="applied",
            operation="nv_update_process_profile",
            target=group_name,
            effect=(
                f"process profile of {group_name} updated: added/changed {len(add_entries)} "
                f"({add_text}), removed {len(delete_entries)} ({del_text}), flags {flags_text}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_file_monitor_profile",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_update_file_monitor_profile(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group whose file-monitor profile to change, e.g. 'nv.api.prod'. "
                "Read the current filters with nv_get_file_monitor_profile first.",
            ),
        ],
        add_filters: Annotated[
            list[FileMonitorFilterInput],
            Field(
                default_factory=list,
                description="Filters to add. Each names a path or glob, whether it recurses, "
                "and the behaviour on a hit.",
            ),
        ],
        update_filters: Annotated[
            list[FileMonitorFilterInput],
            Field(
                default_factory=list,
                description="Existing filters to change in place, matched by their 'filter' "
                "path. Send every field you want to keep - the filter is overwritten.",
            ),
        ],
        delete_filters: Annotated[
            list[FileMonitorFilterInput],
            Field(
                default_factory=list,
                description="Filters to remove, matched by their 'filter' path. Removing a "
                "filter silently ends detection for that path.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Add, change or remove watched paths in one group's file-monitor profile.

        Each filter names a path or glob the enforcer watches and what to do on a hit:
        'monitor' records a file incident and allows the write, 'block' denies it. BLAST
        RADIUS: a 'block' filter in a Protect-mode group breaks every process in the
        group that writes to a matching path - package managers, log rotation, config
        reloads and anything that writes a pid or lock file. Deleting a filter has the
        opposite failure mode: detection for that path stops silently and nothing tells
        you. Read the current filters with nv_get_file_monitor_profile and the group's
        mode with nv_get_group before you confirm.

        Calls PATCH /v1/file_monitor/{name} with {"config": {"add_filters":[...], "update_filters":[...], "delete_filters":[...]}}.
        """
        app = app_context(ctx)

        if not add_filters and not update_filters and not delete_filters:
            raise ValidationError_(
                "nv_update_file_monitor_profile needs at least one of add_filters, "
                "update_filters or delete_filters."
            )

        config: dict[str, Any] = {}
        if add_filters:
            config["add_filters"] = [_file_filter_body(f, group_name) for f in add_filters]
        if update_filters:
            config["update_filters"] = [_file_filter_body(f, group_name) for f in update_filters]
        if delete_filters:
            config["delete_filters"] = [_file_filter_body(f, group_name) for f in delete_filters]
        payload: dict[str, Any] = {"config": config}

        def _describe(items: list[FileMonitorFilterInput]) -> str:
            return (
                "; ".join(
                    f"{i.filter} (recursive={i.recursive}, behavior={i.behavior}, "
                    f"applications={','.join(i.applications) or 'any'})"
                    for i in items
                )
                or "none"
            )

        blocking = [
            item.filter
            for item in list(add_filters) + list(update_filters)
            if item.behavior == "block"
        ]
        plan = authorise_write(
            app.settings,
            operation="nv_update_file_monitor_profile",
            toolset="policy_write",
            target=group_name,
            effect=(
                f"Update the file-monitor profile of group {group_name!r}. "
                f"Add {len(add_filters)}: {_describe(list(add_filters))}. "
                f"Update {len(update_filters)}: {_describe(list(update_filters))}. "
                f"Delete {len(delete_filters)}: "
                f"{'; '.join(item.filter for item in delete_filters) or 'none'}. "
                + (
                    f"BLAST RADIUS: {len(blocking)} filter(s) use behavior='block' "
                    f"({', '.join(blocking)}). In a Protect-mode group the enforcer DENIES "
                    f"writes to those paths, which breaks any process in the group that "
                    f"writes there - package managers, log rotation, config reloads, pid and "
                    f"lock files. "
                    if blocking
                    else "No filter in this change uses behavior='block', so no write is denied. "
                )
                + f"Deleting a filter ends detection for that path silently. Check the mode "
                f"with nv_get_group({group_name!r}) and the current filters with "
                f"nv_get_file_monitor_profile({group_name!r}) before confirming."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_group_name(group_name),
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/file_monitor/{group_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_update_file_monitor_profile",
            target=group_name,
            effect=(
                f"file-monitor profile of {group_name} updated: {len(add_filters)} added, "
                f"{len(update_filters)} updated, {len(delete_filters)} deleted"
                + (f"; blocking filters: {', '.join(blocking)}" if blocking else "")
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_create_waf_sensor",
        annotations=MUTATING_CREATE,
        tags={"policy_write", "write"},
    )
    async def nv_create_waf_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for the new sensor. NeuVector's own sensors use a 'sensor.' "
                "prefix; a duplicate name is rejected by the controller.",
            ),
        ],
        rules: Annotated[
            list[WafRuleInput],
            Field(
                min_length=1,
                description="Rules the sensor carries. Rules are ORed - a request matching ANY "
                "rule fires the sensor. Patterns within one rule are ANDed.",
            ),
        ],
        comment: Annotated[
            str, Field(description="Why this sensor exists. Shown in the NeuVector UI.")
        ] = "",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Create a WAF sensor: a named bundle of regexes matched against requests.

        Creating a sensor changes NOTHING on its own. It inspects traffic only once
        nv_set_waf_group binds it to a group, and it BLOCKS only when that group is in
        Protect mode - in Discover or Monitor a match raises a threat event and the
        request proceeds. Test a new sensor against a Monitor-mode group first.

        Two regex cautions. An 'op' of '!regex' fires when the expression does NOT
        match, which is how allowlists are written and is very easy to get backwards -
        an over-narrow '!regex' fires on every legitimate request. And the enforcer
        runs these on live traffic, so an expression that backtracks catastrophically
        costs real latency.

        Calls POST /v1/waf/sensor with {"config": {"name":..., "comment":..., "cfg_type": "user_created", "rules": [{"name","patterns":[{"key","op","value","context"}]}]}}.
        """
        # VERIFIED (live controller 5.4): this body shape round-trips unchanged.
        # Appendix A claims RESTDlpSensorConfigData for this route and Appendix B
        # documents neither type, so behaviour is the only source of truth here.
        app = app_context(ctx)
        payload: dict[str, Any] = {
            "config": {
                "name": sensor_name,
                "comment": comment,
                "cfg_type": "user_created",
                "rules": [_waf_rule_body(r) for r in rules],
            }
        }
        negatives = [f"{r.name}/{p.value}" for r in rules for p in r.patterns if p.op == "!regex"]
        plan = authorise_write(
            app.settings,
            operation="nv_create_waf_sensor",
            toolset="policy_write",
            target=sensor_name,
            effect=(
                f"Create WAF sensor {sensor_name!r} with {len(rules)} rule(s): "
                f"{_describe_waf_rules(rules)}. The sensor is bound to no group, so it "
                f"inspects nothing until nv_set_waf_group binds it, and blocks nothing "
                f"until that group is in Protect mode. "
                + (
                    f"CAUTION: {len(negatives)} pattern(s) use '!regex' and therefore fire on "
                    f"every request that does NOT match ({', '.join(negatives)}). Verify the "
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

        response = await app.client.request("POST", "/v1/waf/sensor", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_create_waf_sensor",
            target=sensor_name,
            effect=(
                f"WAF sensor {sensor_name} created with {len(rules)} rule(s); "
                f"not yet bound to any group"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_waf_sensor",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_update_waf_sensor(
        ctx: Context,
        sensor_name: Annotated[
            str, Field(min_length=1, description="Sensor to update. It must already exist.")
        ],
        rules: Annotated[
            list[WafRuleInput],
            Field(
                min_length=1,
                description="The COMPLETE rule list after the update. This REPLACES the "
                "sensor's rules; any existing rule you omit is deleted. Read the current "
                "rules with nv_get_waf_sensor and send them back plus your changes.",
            ),
        ],
        comment: Annotated[
            str | None,
            Field(
                description="Replacement comment. Omit to leave the existing comment "
                "unchanged; pass an empty string to clear it."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Replace a WAF sensor's rules.

        This is a REPLACE, not a merge: the rule list you send becomes the sensor's
        entire rule list, and anything omitted is silently dropped along with the
        detection it provided. Call nv_get_waf_sensor first and build the new list from
        what is actually there.

        The comment is NOT replaced unless you pass one, because a sensor's comment is
        often the only record of why it exists (which CVE it mitigates, who asked for
        it). Pass comment="" to deliberately clear it.

        If the sensor is already bound to a Protect-mode group the new rules take effect
        on live traffic immediately - check bindings with nv_get_waf_sensor. Predefined
        sensors that ship with NeuVector cannot be updated.

        Calls PATCH /v1/waf/sensor/{name} with {"config": {"name":..., "rules": [...]}}.
        """
        # VERIFIED (live controller 5.4): 'rules' replaces the list wholesale.
        # RESTWafSensorConfig.Comment is *string+omitempty (upstream apis.go), so an
        # absent key means "leave unchanged" and "" means "clear". Sending the key
        # unconditionally - as this tool used to - wiped the comment on every
        # update that did not restate it.
        app = app_context(ctx)
        config: dict[str, Any] = {
            "name": sensor_name,
            "rules": [_waf_rule_body(r) for r in rules],
        }
        if comment is not None:
            config["comment"] = comment
        payload: dict[str, Any] = {"config": config}
        negatives = [f"{r.name}/{p.value}" for r in rules for p in r.patterns if p.op == "!regex"]
        plan = authorise_write(
            app.settings,
            operation="nv_update_waf_sensor",
            toolset="policy_write",
            target=sensor_name,
            effect=(
                f"REPLACE every rule on WAF sensor {sensor_name!r} with {len(rules)} rule(s): "
                f"{_describe_waf_rules(rules)}. Any rule currently on the sensor and absent "
                f"from this list is deleted and stops detecting. If the sensor is bound to a "
                f"Protect-mode group these patterns start blocking traffic immediately. "
                + (
                    f"CAUTION: {len(negatives)} pattern(s) use '!regex' and fire on every "
                    f"request that does NOT match ({', '.join(negatives)}). "
                    if negatives
                    else ""
                )
                + f"Confirm the current rules with nv_get_waf_sensor({sensor_name!r}) first."
            ),
            payload=payload,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/waf/sensor/{sensor_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_update_waf_sensor",
            target=sensor_name,
            effect=f"WAF sensor {sensor_name} now carries {len(rules)} rule(s)",
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_waf_sensor",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_waf_sensor(
        ctx: Context,
        sensor_name: Annotated[str, Field(min_length=1, description="Sensor to delete.")],
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Delete a WAF sensor and every rule it carries.

        Deletion ends detection silently: any group the sensor was bound to keeps running
        with one fewer sensor and nothing reports the gap. Check nv_get_waf_sensor for the
        'groups' list before deleting - if it is non-empty you are removing live
        inspection from those groups. Predefined sensors cannot be deleted.

        Calls DELETE /v1/waf/sensor/{name}.
        """
        app = app_context(ctx)
        plan = authorise_write(
            app.settings,
            operation="nv_delete_waf_sensor",
            toolset="policy_write",
            target=sensor_name,
            effect=(
                f"Delete WAF sensor {sensor_name!r} and all of its rules. Every group it is "
                f"bound to loses that inspection immediately and silently. Run "
                f"nv_get_waf_sensor({sensor_name!r}) and read its 'groups' field before "
                f"confirming."
            ),
            payload=None,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("DELETE", f"/v1/waf/sensor/{sensor_name}")
        return WriteOutcome(
            status="applied",
            operation="nv_delete_waf_sensor",
            target=sensor_name,
            effect=f"WAF sensor {sensor_name} deleted",
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_set_waf_group",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_set_waf_group(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group to configure, e.g. 'nv.api.prod'. From nv_list_groups.",
            ),
        ],
        sensors: Annotated[
            list[WafSensorBindingInput],
            Field(
                description="The COMPLETE binding list after the change. This REPLACES the "
                "group's bindings; an empty list unbinds every sensor. Read the current "
                "bindings with nv_get_waf_group first.",
            ),
        ],
        status: Annotated[
            bool | None,
            Field(
                description="True enables WAF inspection for the group, False disables it "
                "without changing the bindings. Omit to leave the current setting alone - "
                "do not pass True unless you mean to turn inspection ON."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Bind WAF sensors to a group and enable or disable inspection.

        This is what makes a sensor live. Binding is a REPLACE: the list you send becomes
        the group's entire binding set, and an omitted sensor is unbound.

        Binding alone does not block. A bound sensor with action='deny' raises a threat
        event in Discover and Monitor mode and only denies requests once the group is in
        Protect mode, which is set separately with nv_set_group_policy_mode. Bind in
        Monitor first, watch nv_query_security_events with kind='threat' for false
        positives, and only then move the group to Protect.

        Calls PATCH /v1/waf/group/{name} with {"config": {"name":..., "status":..., "replace": [{"name","action"}]}}.
        """
        # VERIFIED (live controller 5.4): 'replace' takes objects of {name, action} and
        # sets the whole list. The sibling 'delete' key takes bare NAME STRINGS, not
        # objects - sending objects there returns code 6 "Request in wrong format".
        # This tool uses 'replace' only, so an empty list is the way to unbind.
        # RESTWafGroupConfig.Status is *bool+omitempty (upstream apis.go): absent means
        # "leave unchanged". Defaulting it to True and always sending it - as this tool
        # used to - silently re-enabled inspection on a group where it had been
        # deliberately turned off, which starts denying traffic if the group is in Protect.
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
        plan = authorise_write(
            app.settings,
            operation="nv_set_waf_group",
            toolset="policy_write",
            target=group_name,
            effect=(
                (
                    f"Set WAF inspection on group {group_name!r} to status={status}"
                    if status is not None
                    else f"Leave WAF inspection on group {group_name!r} as it is"
                )
                + f" and REPLACE "
                f"its sensor bindings with: {binding_text}. Any sensor currently bound and "
                f"absent from this list is unbound and stops inspecting. "
                + (
                    f"{len(denying)} sensor(s) bind with action='deny' ({', '.join(denying)}): "
                    f"these only raise threat events while the group is in Discover or Monitor "
                    f"mode, and will DENY matching requests if the group is moved to Protect. "
                    if denying
                    else ""
                )
                + f"Check the group's current mode with nv_get_group({group_name!r}) so you "
                f"know which of those two applies."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_group_name(group_name),
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/waf/group/{group_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_set_waf_group",
            target=group_name,
            effect=(
                f"WAF on group {group_name}: "
                + (f"status={status}, " if status is not None else "status unchanged, ")
                + f"bindings replaced with {binding_text}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )
