"""Admission control tools: cluster-wide webhook state and admission rules.

Every tool in this module is mutating and tagged ``admission``. Each follows the
same five-step body as ``policy_write`` (SPEC 7.4), in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

Admission control is the only subsystem in this server whose blast radius is the
whole cluster: a deny rule, or ``default_action="deny"`` in ``protect`` mode,
makes the Kubernetes API server reject workload creates and updates in EVERY
namespace. ``NV_ALLOWED_NAMESPACES`` cannot constrain it - there is no namespace
to pass to the guard - so the only controls are ``NV_TOOLSETS``,
``NV_READ_ONLY``, the confirm handshake, and the API key's NeuVector role.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import ValidationError_
from ..guard import authorise_write
from ..models import AdmissionCriterionInput, WriteOutcome

# All four tools are destructiveHint=True, including nv_create_admission_rule.
# Part C section C.0.3: classify by blast radius, not by HTTP verb. A new
# admission deny rule is live cluster-wide the instant the controller stores it,
# which is SPEC 6.2's traffic-affecting row, not its object-creation row.
MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)

#: Hard cap on criteria per admission rule. A rule with dozens of criteria is
#: unreviewable in a preview, and an unreviewable deny rule is how a cluster
#: stops accepting deployments.
MAX_ADMISSION_CRITERIA = 16


def _criterion_body(criterion: AdmissionCriterionInput) -> dict[str, Any]:
    """Render one ``RESTAdmRuleCriterion``, including nested sub_criteria.

    Only the four fields Appendix B marks required are sent (``name``, ``op``,
    ``value``, plus ``sub_criteria`` when non-empty). ``type``,
    ``template_kind``, ``path`` and ``value_type`` exist on the type but are
    controller-side annotations - do not send them.
    """
    body: dict[str, Any] = {
        "name": criterion.name,
        "op": criterion.op,
        "value": criterion.value,
    }
    if criterion.sub_criteria:
        body["sub_criteria"] = [_criterion_body(c) for c in criterion.sub_criteria]
    return body


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the admission toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("admission"):
        return

    @mcp.tool(
        name="nv_set_admission_state",
        annotations=MUTATING,
        tags={"admission", "write"},
    )
    async def nv_set_admission_state(
        ctx: Context,
        enable: Annotated[
            bool,
            Field(
                description="True activates the Kubernetes admission webhook cluster-wide; "
                "false deactivates it and makes every admission rule inert. False is the "
                "break-glass direction."
            ),
        ],
        mode: Annotated[
            Literal["monitor", "protect"] | None,
            Field(
                description="'monitor' logs what would have been denied and admits "
                "everything; 'protect' actually DENIES matching requests. Omit to leave the "
                "current mode alone. The controller refuses global settings while admission "
                "control is disabled (code 36), so enable it in 'monitor' first, verify, then "
                "switch to 'protect' in a second call."
            ),
        ] = None,
        default_action: Annotated[
            Literal["allow", "deny"] | None,
            Field(
                description="What happens to a request that no admission rule matches. "
                "'deny' means EVERY unmatched deployment in EVERY namespace is rejected while "
                "mode is 'protect' - that is a cluster-wide outage unless your exception rules "
                "are complete and you have verified them with nv_assess_admission_rule. Omit "
                "to leave the current setting alone."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change - and read the whole 'effect' "
                "before you send the token."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Enable, disable or reconfigure Kubernetes admission control for the whole cluster.

        MOST DANGEROUS TOOL IN THIS SERVER. With enable=true and mode='protect' the
        Kubernetes API server REJECTS every create and update that a deny rule matches,
        in EVERY namespace, including pod restarts and scale-ups of workloads already
        running and including NeuVector's own components. With default_action='deny' it
        also rejects everything no rule allows. There is no rollout and no per-namespace
        staging: the change is live as soon as the controller stores it, and recovering
        can require deleting the NeuVector ValidatingWebhookConfiguration from the
        cluster by hand.

        REQUIRED BEFORE YOU CALL THIS: run nv_assess_admission_rule for every deny rule
        you have and read its results - each entry with allowed=false is an object that
        will be blocked. Then read nv_get_admission_state to see where you are starting
        from. Enable in mode='monitor' first, confirm the audit events with
        nv_query_audit_events, and only then call again with mode='protect'. The
        controller refuses global settings while admission control is disabled (code 36),
        and returns code 30 on any non-Kubernetes platform.

        Calls PATCH /v1/admission/state with {"state": {"enable":..., "mode":..., "default_action":...}}.
        """
        app = app_context(ctx)

        state: dict[str, Any] = {"enable": enable}
        if mode is not None:
            state["mode"] = mode
        if default_action is not None:
            state["default_action"] = default_action
        payload: dict[str, Any] = {"state": state}

        if not enable:
            consequence = (
                "The webhook stops evaluating requests entirely: every admission rule "
                "becomes inert and nothing is blocked. This is the break-glass direction, "
                "and it also removes whatever protection the rules were providing."
            )
        elif mode == "protect" or default_action == "deny":
            consequence = (
                "DANGER - THIS CAN BLOCK EVERY DEPLOYMENT IN THE CLUSTER. With "
                "mode='protect' the Kubernetes API server REJECTS every create and update "
                "that a deny rule matches; with default_action='deny' it also REJECTS "
                "everything no rule allows. That applies to EVERY namespace, including "
                "pod restarts and scale-ups of workloads already running and including "
                "NeuVector's own components. There is no rollout and no per-namespace "
                "staging. Before you send the confirm token: run nv_assess_admission_rule "
                "for every deny rule you have and check that each allowed=false result is "
                "intended, and make sure you can remove the NeuVector "
                "ValidatingWebhookConfiguration from the cluster by hand if this goes "
                "wrong - this server cannot do that for you."
            )
        else:
            consequence = (
                "In mode 'monitor' matching requests are recorded as admission control "
                "events and still admitted, so nothing is blocked. Read the events with "
                "nv_query_audit_events, confirm they are what you expect, and only then "
                "switch to mode='protect' in a second call."
            )

        effect = (
            f"{'ENABLE' if enable else 'DISABLE'} Kubernetes admission control "
            f"CLUSTER-WIDE (enable={enable}"
            + (f", mode={mode}" if mode is not None else ", mode unchanged")
            + (
                f", default_action={default_action}"
                if default_action is not None
                else ", default_action unchanged"
            )
            + f"). {consequence}"
        )

        plan = authorise_write(
            app.settings,
            operation="nv_set_admission_state",
            toolset="admission",
            target="cluster admission control",
            effect=effect,
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", "/v1/admission/state", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_set_admission_state",
            target="cluster admission control",
            effect=(
                f"cluster admission control set to enable={enable}"
                + (f", mode={mode}" if mode is not None else "")
                + (f", default_action={default_action}" if default_action is not None else "")
                + ". Verify with nv_get_admission_state and watch nv_query_audit_events."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_create_admission_rule",
        annotations=MUTATING,
        tags={"admission", "write"},
    )
    async def nv_create_admission_rule(
        ctx: Context,
        rule_type: Annotated[
            Literal["deny", "exception"],
            Field(
                description="'deny' BLOCKS matching Kubernetes requests while admission "
                "control is enabled in protect mode. 'exception' exempts matching requests "
                "from deny rules. Run nv_assess_admission_rule with the same criteria first "
                "to see what a deny rule would have blocked."
            ),
        ],
        criteria: Annotated[
            list[AdmissionCriterionInput],
            Field(
                min_length=1,
                max_length=MAX_ADMISSION_CRITERIA,
                description="Match criteria for the rule. Each needs name, op and value; "
                "nested sub_criteria are optional. Get valid names and operators from an "
                "existing rule via nv_list_admission_rules - they are not enumerated in the "
                "schema reference.",
            ),
        ],
        category: Annotated[
            str,
            Field(
                description="Rule category the controller expects; leave at the default "
                "unless an existing rule from nv_list_admission_rules shows otherwise."
            ),
        ] = "Kubernetes",
        containers: Annotated[
            list[Literal["containers", "init_containers", "ephemeral_containers"]],
            Field(
                description="Which container classes the rule inspects. Adding "
                "'init_containers' makes a deny rule block pods whose init containers match, "
                "which is easy to overlook."
            ),
        ] = ["containers"],  # noqa: B006 - read-only, copied with list() before sending
        rule_mode: Annotated[
            Literal["", "monitor", "protect"],
            Field(
                description="Per-rule mode. Empty inherits the cluster mode from "
                "nv_get_admission_state; 'monitor' logs this rule's matches without blocking "
                "even when the cluster is in protect mode. Use 'monitor' to stage a new deny "
                "rule."
            ),
        ] = "",
        comment: Annotated[
            str,
            Field(
                description="Free-text comment stored on the rule. Say why it exists; it is "
                "the only provenance an operator gets later."
            ),
        ] = "",
        disable: Annotated[
            bool,
            Field(
                description="True stores the rule without enforcing it. Create a deny rule "
                "disabled first, verify with nv_assess_admission_rule, then enable it with "
                "nv_update_admission_rule."
            ),
        ] = False,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Create a Kubernetes admission control rule.

        A 'deny' rule takes effect the moment the controller stores it: while admission
        control is enabled and in protect mode, the Kubernetes API server REJECTS every
        matching create and update, in every namespace, with no rollout. An 'exception'
        rule exempts matching requests from deny rules, so removing or narrowing one
        later can start blocking deployments that used to work. Run
        nv_assess_admission_rule with the same rule_type and criteria FIRST and read its
        results: every entry with allowed=false is an object this rule would block. Stage
        risky rules with disable=true or rule_mode='monitor', verify, then enable.
        Criterion names and operators are not enumerated in this spec - copy exact values
        from an existing rule via nv_list_admission_rules.

        Calls POST /v1/admission/rule with {"config": {"category":..., "rule_type":..., "criteria":[...], "containers":[...], "rule_mode":..., "comment":..., "disable":..., "cfg_type": "user_created"}}.
        """
        app = app_context(ctx)

        if len(criteria) > MAX_ADMISSION_CRITERIA:
            raise ValidationError_(
                f"{len(criteria)} criteria exceeds the cap of {MAX_ADMISSION_CRITERIA}. A "
                "rule whose preview cannot be read in full is a rule nobody reviewed."
            )

        payload: dict[str, Any] = {
            "config": {
                "category": category,
                "rule_type": rule_type,
                "cfg_type": "user_created",
                "criteria": [_criterion_body(c) for c in criteria],
                "containers": list(containers),
                "rule_mode": rule_mode,
                "comment": comment,
                "disable": disable,
            }
        }

        criteria_text = "; ".join(f"{c.name} {c.op} {c.value}" for c in criteria)
        plan = authorise_write(
            app.settings,
            operation="nv_create_admission_rule",
            toolset="admission",
            target=f"new {rule_type} admission rule",
            effect=(
                f"Create a {rule_type.upper()} admission rule (category={category}, "
                f"containers={','.join(containers)}, "
                f"rule_mode={rule_mode or 'inherit cluster mode'}, disabled={disable}) "
                f"matching {len(criteria)} criterion(s): {criteria_text}. "
                + (
                    "BLAST RADIUS: a deny rule takes effect as soon as the controller "
                    "stores it - there is no rollout. While admission control is enabled "
                    "and in protect mode, every create and update of a matching pod, "
                    "deployment, job or cronjob in EVERY namespace is REJECTED by the "
                    "Kubernetes API server. Run nv_assess_admission_rule with rule_type="
                    "'deny' and these exact criteria first: each result with allowed=false "
                    "is an object this rule will block."
                    if rule_type == "deny"
                    else "An exception rule cannot itself block a deployment - it exempts "
                    "matching requests from deny rules. The risk is the opposite one: it "
                    "can silently exempt workloads from a deny rule you rely on, so check "
                    "with nv_assess_admission_rule which objects it would cover."
                )
                + (
                    " This rule is created DISABLED and enforces nothing until it is "
                    "enabled with nv_update_admission_rule."
                    if disable
                    else ""
                )
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("POST", "/v1/admission/rule", json=payload)
        body = response if isinstance(response, dict) else {}
        created = body.get("rule")
        new_id = created.get("id") if isinstance(created, dict) else None
        return WriteOutcome(
            status="applied",
            operation="nv_create_admission_rule",
            target=(
                f"admission rule {new_id}"
                if new_id is not None
                else f"new {rule_type} admission rule"
            ),
            effect=(
                f"{rule_type} admission rule created"
                + (f" with id {new_id}" if new_id is not None else "")
                + f" (disabled={disable}, rule_mode={rule_mode or 'inherit'}): {criteria_text}"
            ),
            payload=payload,
            controller_response=body,
        )

    @mcp.tool(
        name="nv_update_admission_rule",
        annotations=MUTATING,
        tags={"admission", "write"},
    )
    async def nv_update_admission_rule(
        ctx: Context,
        rule_id: Annotated[
            int,
            Field(
                ge=0,
                description="Id of the admission rule to overwrite. Get ids from "
                "nv_list_admission_rules. The id goes in the request BODY - this endpoint "
                "has no id in its path.",
            ),
        ],
        rule_type: Annotated[
            Literal["deny", "exception"],
            Field(
                description="'deny' BLOCKS matching Kubernetes requests; 'exception' exempts "
                "them from deny rules. Send the rule's existing type unless you intend to "
                "flip it - flipping a deny rule to exception silently stops it blocking "
                "anything."
            ),
        ],
        criteria: Annotated[
            list[AdmissionCriterionInput],
            Field(
                min_length=1,
                max_length=MAX_ADMISSION_CRITERIA,
                description="The COMPLETE new criteria set. This REPLACES the existing set - "
                "it is not merged, so any criterion you omit is removed. Read the current "
                "rule with nv_list_admission_rules and echo back what you intend to keep.",
            ),
        ],
        category: Annotated[
            str,
            Field(description="Rule category. Send the value the existing rule already has."),
        ] = "Kubernetes",
        containers: Annotated[
            list[Literal["containers", "init_containers", "ephemeral_containers"]],
            Field(
                description="Which container classes the rule inspects. This REPLACES the "
                "existing list."
            ),
        ] = ["containers"],  # noqa: B006 - read-only, copied with list() before sending
        rule_mode: Annotated[
            Literal["", "monitor", "protect"],
            Field(
                description="Per-rule mode. Empty inherits the cluster mode. Switching a rule "
                "from 'monitor' to '' or 'protect' is what makes an already-matching deny rule "
                "start blocking."
            ),
        ] = "",
        comment: Annotated[
            str,
            Field(
                description="Free-text comment stored on the rule. Not sending it clears the "
                "existing comment."
            ),
        ] = "",
        disable: Annotated[
            bool,
            Field(
                description="True stores the rule without enforcing it. Set true to switch a "
                "deny rule off without deleting it - safer than deletion, because deletion "
                "also removes the exception rules' reason for existing."
            ),
        ] = False,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Overwrite an existing Kubernetes admission control rule.

        The id travels in the request body, not the path. This is a whole-rule
        replacement: criteria, containers, mode, comment and disable are all set to what
        you send, so read the current rule with nv_list_admission_rules and echo back
        everything you intend to keep. Widening a deny rule's criteria starts REJECTING
        more deployments cluster-wide the moment the controller stores it; narrowing an
        exception rule starts rejecting the deployments it used to exempt. Run
        nv_assess_admission_rule with the new rule_type and criteria first and read its
        results. Rules with critical=true, or cfg_type 'federal' or 'ground', are not
        editable here and come back as code 4 or code 46.

        Calls PATCH /v1/admission/rule with {"config": {"id":..., "category":..., "rule_type":..., "criteria":[...], "containers":[...], "rule_mode":..., "comment":..., "disable":..., "cfg_type": "user_created"}}.
        """
        app = app_context(ctx)

        if len(criteria) > MAX_ADMISSION_CRITERIA:
            raise ValidationError_(
                f"{len(criteria)} criteria exceeds the cap of {MAX_ADMISSION_CRITERIA}. A "
                "rule whose preview cannot be read in full is a rule nobody reviewed."
            )

        payload: dict[str, Any] = {
            "config": {
                "id": rule_id,
                "category": category,
                "rule_type": rule_type,
                "cfg_type": "user_created",
                "criteria": [_criterion_body(c) for c in criteria],
                "containers": list(containers),
                "rule_mode": rule_mode,
                "comment": comment,
                "disable": disable,
            }
        }

        criteria_text = "; ".join(f"{c.name} {c.op} {c.value}" for c in criteria)
        plan = authorise_write(
            app.settings,
            operation="nv_update_admission_rule",
            toolset="admission",
            target=str(rule_id),
            effect=(
                f"OVERWRITE admission rule id {rule_id} as a {rule_type.upper()} rule "  # noqa: S608 - prose, not SQL
                f"(category={category}, containers={','.join(containers)}, "
                f"rule_mode={rule_mode or 'inherit cluster mode'}, disabled={disable}) "
                f"matching {len(criteria)} criterion(s): {criteria_text}. This is a "
                f"whole-rule replacement, not a merge: any criterion, container class or "
                f"comment not listed here is REMOVED. "
                + (
                    "BLAST RADIUS: while admission control is enabled and in protect mode, "
                    "this deny rule REJECTS every matching create and update in EVERY "
                    "namespace as soon as the controller stores it. Widening the criteria "
                    "rejects more; run nv_assess_admission_rule with rule_type='deny' and "
                    "these exact criteria first and check every allowed=false result."
                    if rule_type == "deny"
                    else "This is an exception rule: narrowing its criteria stops exempting "
                    "workloads that used to be exempt, so deployments that worked "
                    "yesterday can start being REJECTED by deny rules. Assess it with "
                    "nv_assess_admission_rule before confirming."
                )
                + (
                    " The rule is being set DISABLED, so it enforces nothing until it is "
                    "re-enabled."
                    if disable
                    else ""
                )
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", "/v1/admission/rule", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_update_admission_rule",
            target=str(rule_id),
            effect=(
                f"admission rule {rule_id} overwritten as {rule_type} "
                f"(disabled={disable}, rule_mode={rule_mode or 'inherit'}): {criteria_text}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_admission_rule",
        annotations=MUTATING,
        tags={"admission", "write"},
    )
    async def nv_delete_admission_rule(
        ctx: Context,
        rule_id: Annotated[
            int,
            Field(
                ge=0,
                description="Id of the admission rule to delete. Get ids from "
                "nv_list_admission_rules and read the rule's type first: deleting an "
                "'exception' rule can start BLOCKING deployments it used to exempt.",
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
        """Delete one Kubernetes admission control rule by id.

        Read the rule first with nv_list_admission_rules, because the two rule types fail
        in opposite directions. Deleting an 'exception' rule removes an exemption, so
        deployments that used to be admitted can start being REJECTED by the deny rules
        that exception was shielding them from - this is the surprising case. Deleting a
        'deny' rule removes a control, so objects it blocked are admitted from now on.
        Prefer nv_update_admission_rule with disable=true when you only want to switch a
        rule off: it is reversible and it leaves the rule's comment and criteria intact
        for whoever asks why. Rules with critical=true, or cfg_type 'federal' or
        'ground', cannot be deleted here and come back as code 4 or code 46.

        Calls DELETE /v1/admission/rule/{id}.
        """
        app = app_context(ctx)
        plan = authorise_write(
            app.settings,
            operation="nv_delete_admission_rule",
            toolset="admission",
            target=str(rule_id),
            effect=(
                f"Delete admission control rule id {rule_id}. If it is an EXCEPTION (allow) "
                f"rule, the deployments it exempted are once again evaluated by every deny "
                f"rule and may start being REJECTED by the Kubernetes API server - that is "
                f"the surprising direction. If it is a DENY rule, objects it blocked will be "
                f"admitted from now on and a control is gone. Call nv_list_admission_rules "
                f"first to see which of the two you are doing. Consider "
                f"nv_update_admission_rule with disable=true instead: reversible, and it "
                f"keeps the rule's criteria and comment. Rules with critical=true or "
                f"cfg_type 'federal'/'ground' cannot be deleted (controller code 4 or 46)."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("DELETE", f"/v1/admission/rule/{rule_id}")
        return WriteOutcome(
            status="applied",
            operation="nv_delete_admission_rule",
            target=str(rule_id),
            effect=(
                f"admission rule {rule_id} deleted. Verify the remaining rules with "
                f"nv_list_admission_rules and re-assess with nv_assess_admission_rule."
            ),
            payload={},
            controller_response=response if isinstance(response, dict) else {},
        )
