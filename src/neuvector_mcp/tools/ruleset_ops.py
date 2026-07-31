"""Single-rule updates and whole-ruleset deletes. Toolsets ``policy_write`` and ``admission``.

Every tool here follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3. That
ordering is why the two bulk deletes cannot count the rules they are about to
destroy: counting would be a controller call before the plan exists. The count
is therefore supplied by the caller (``expected_rule_count``) and echoed into
the plan as a caller assertion, never as a controller-verified fact.
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
from ..models import WriteOutcome

MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)

#: What each ``scope`` value selects, spelled out for the confirmation plan.
#: Wording follows the query-parameter descriptions in apis.yaml for
#: ``DELETE /v1/policy/rule`` and ``DELETE /v1/admission/rules``.
_SCOPE_MEANING: dict[str, str] = {
    "local": (
        "scope 'local' means THIS cluster's own rules; federated rules pushed by a "
        "federation primary are left alone"
    ),
    "fed": (
        "scope 'fed' means the FEDERATED rules, which a federation primary pushes to "
        "every member cluster - deleting them removes those rules from every member, "
        "not only from this one"
    ),
}


def _rule_config_body(
    rule_id: int,
    *,
    comment: str | None,
    from_group: str | None,
    to_group: str | None,
    ports: str | None,
    action: str | None,
    applications: list[str] | None,
    disable: bool | None,
) -> dict[str, Any]:
    """Render one ``RESTPolicyRuleConfig`` for a single-rule PATCH.

    Field names and, critically, the omission semantics come from apis.go
    ``RESTPolicyRuleConfig``, which carries the comment "Omit fields indicate
    that it's not modified" and declares every optional field as a pointer with
    ``omitempty`` (``Comment *string``, ``From *string``, ``To *string``,
    ``Ports *string``, ``Action *string``, ``Applications *[]string``,
    ``Disable *bool``). A Go pointer + omitempty field is absent from the wire
    body when nil, so an omitted key is what tells the controller "leave this
    alone". Sending ``null`` instead would not be an omission and sending a
    default would overwrite the operator's current value - which is why this
    body is built by explicit key, never from ``model_dump()``.

    ``id`` and ``cfg_type`` are the two non-pointer fields (apis.yaml lists both
    under ``required``), so they are always present.
    """
    body: dict[str, Any] = {"id": rule_id, "cfg_type": "user_created"}
    if comment is not None:
        body["comment"] = comment
    if from_group is not None:
        body["from"] = from_group
    if to_group is not None:
        body["to"] = to_group
    if ports is not None:
        body["ports"] = ports
    if action is not None:
        body["action"] = action
    if applications is not None:
        body["applications"] = list(applications)
    if disable is not None:
        body["disable"] = disable
    return body


def _describe_changes(config: dict[str, Any]) -> str:
    """One line per field the PATCH actually changes, for the confirmation plan."""
    skip = {"id", "cfg_type"}
    changed = [f"{k}={config[k]!r}" for k in config if k not in skip]
    return ", ".join(changed)


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the rule-set gap-closer tools to ``mcp``, gating each toolset separately."""
    if settings.toolset_enabled("policy_write"):
        _register_policy_write(mcp)
    if settings.toolset_enabled("admission"):
        _register_admission(mcp)


def _register_policy_write(mcp: FastMCP) -> None:
    """Tools tagged ``policy_write``: single-rule update and the whole-list delete."""

    @mcp.tool(
        name="nv_update_network_rule",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_update_network_rule(
        ctx: Context,
        rule_id: Annotated[
            int,
            Field(
                ge=0,
                description="Id of the rule to update. Get ids from nv_list_network_rules and "
                "read the current rule with nv_get_network_rule first.",
            ),
        ],
        from_group: Annotated[
            str | None,
            Field(
                description="New source group name (controller field 'from'). Omit to leave the "
                "current source unchanged. The group must already exist."
            ),
        ] = None,
        to_group: Annotated[
            str | None,
            Field(
                description="New destination group name (controller field 'to'). Omit to leave "
                "the current destination unchanged. The group must already exist."
            ),
        ] = None,
        action: Annotated[
            Literal["allow", "deny"] | None,
            Field(
                description="New verdict. 'allow' permits the connection; 'deny' blocks it in "
                "Protect mode and logs a violation in Monitor mode. Omit to leave unchanged - "
                "flipping allow to deny drops production traffic immediately in Protect mode."
            ),
        ] = None,
        ports: Annotated[
            str | None,
            Field(
                description="New free-style port list exactly as the controller stores it, e.g. "
                "'tcp/443,tcp/8080-8090', 'udp/53' or 'any'. Omit to leave unchanged. This "
                "REPLACES the whole port list, it does not add to it."
            ),
        ] = None,
        applications: Annotated[
            list[str] | None,
            Field(
                description="New layer-7 application list, e.g. ['HTTP']. Omit to leave "
                "unchanged. This REPLACES the whole list; pass [] to mean any application."
            ),
        ] = None,
        comment: Annotated[
            str | None,
            Field(
                description="New free-text comment. Omit to leave the existing comment alone. "
                "Say why the rule changed; it is the only provenance an operator gets later."
            ),
        ] = None,
        disable: Annotated[
            bool | None,
            Field(
                description="True stores the rule but stops enforcing it; false re-enables it. "
                "Omit to leave unchanged. Disabling an allow rule has the same effect on "
                "traffic as deleting it."
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
        """Update selected fields of one network policy rule, leaving the rest untouched.

        This is a PARTIAL update: only the arguments you supply are sent, and a field
        that is not sent is not modified. That is what distinguishes this tool from
        nv_apply_network_rule_changes, whose configure_rules entries OVERWRITE the whole
        rule at that id and reset anything you did not send. Use this tool to change one
        or two fields of one rule; use nv_apply_network_rule_changes when you need
        several rules changed atomically, or when order matters, because rule order is
        evaluation order and only the batch tool can insert, move and delete. Changing
        'action' from allow to deny, or setting disable=true, DROPS the traffic this rule
        was permitting the moment the source group is in Protect mode. Rule position is
        not changed here. Learned rules cannot be edited - the controller rejects those
        with code 4. Re-read the rule with nv_get_network_rule afterwards: the controller
        answers 200 even for fields it ignored.

        Calls PATCH /v1/policy/rule/{id} with {"config": {"id":..., "cfg_type": "user_created", ...only the fields you supplied}}.
        """
        app = app_context(ctx)

        config = _rule_config_body(
            rule_id,
            comment=comment,
            from_group=from_group,
            to_group=to_group,
            ports=ports,
            action=action,
            applications=applications,
            disable=disable,
        )
        # --- step 1 validation: local only, no network call ---------------------
        changes = _describe_changes(config)
        if not changes:
            raise ValidationError_(
                f"nv_update_network_rule was called for rule {rule_id} with no field to "
                "change. Supply at least one of from_group, to_group, action, ports, "
                "applications, comment or disable. Nothing was sent to the controller."
            )

        payload: dict[str, Any] = {"config": config}
        target = f"network policy rule {rule_id}"
        plan = authorise_write(
            app.settings,
            operation="nv_update_network_rule",
            toolset="policy_write",
            target=target,
            effect=(
                f"Update network policy rule {rule_id}: {changes}. Fields not listed here "
                f"are omitted from the request body and the controller leaves them "
                f"unchanged. Rules are evaluated top-down, first match wins, and this "
                f"rule keeps its current position. If this makes the rule stop allowing "
                f"traffic it allows today (action becomes 'deny', disable becomes true, or "
                f"a narrower from/to/ports/applications), that traffic falls through to the "
                f"rules below it and any group in Protect mode DROPS whatever no lower "
                f"rule allows. Read the current rule with nv_get_network_rule({rule_id}) "
                f"before confirming."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/policy/rule/{rule_id}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_update_network_rule",
            target=target,
            effect=(
                f"network policy rule {rule_id} updated: {changes}. Verify with "
                f"nv_get_network_rule({rule_id}) - a 200 does not prove the controller "
                f"kept every field."
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_all_network_rules",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_all_network_rules(
        ctx: Context,
        expected_rule_count: Annotated[
            int,
            Field(
                ge=0,
                description="How many rules you believe are in this scope, taken from "
                "nv_list_network_rules(scope=...) immediately before calling. It is echoed "
                "into the plan so the operator sees how many rules are about to die. It is "
                "NOT checked against the controller and does not limit the delete: the "
                "endpoint removes every rule in the scope whatever this number says.",
            ),
        ],
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="Which ruleset to wipe. 'local' deletes THIS cluster's own rules "
                "and leaves federated rules alone. 'fed' deletes the FEDERATED rules, which a "
                "federation primary pushes to every member cluster, so the deletion is felt on "
                "every member and not only here; only a federation primary may do it, and "
                "elsewhere the controller rejects it with code 46. Getting this wrong destroys "
                "the wrong ruleset, so read the list with nv_list_network_rules(scope=...) "
                "first and confirm you are looking at the rules you mean to delete."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete EVERY network policy rule in one scope. The most destructive call in this API.

        This empties the network rule list. It is not a filtered delete and it takes no
        rule ids: everything in the chosen scope goes. Groups in Protect mode then DROP
        the traffic the deleted rules were allowing, immediately and with no warning, so
        a running application loses connectivity the moment this returns. Traffic that
        was being denied stops being denied. The controller keeps no copy and there is no
        undo - the only recovery is re-creating every rule by hand, so export the list
        with nv_list_network_rules(scope=...) and keep it before you confirm. To remove a
        few rules use nv_delete_network_rule or nv_apply_network_rule_changes instead;
        reach for this one only when you genuinely intend to start the ruleset from
        nothing.

        Calls DELETE /v1/policy/rule with scope.
        """
        app = app_context(ctx)
        # expected_rule_count is bound into 'target' so the confirmation token covers
        # it: a caller who re-reads the list and gets a different number must take a
        # fresh plan rather than reusing the old token.
        target = (
            f"all network policy rules in scope {scope!r} "
            f"(caller asserts {expected_rule_count} rule(s))"
        )
        plan = authorise_write(
            app.settings,
            operation="nv_delete_all_network_rules",
            toolset="policy_write",
            target=target,
            effect=(
                f"Delete ALL {expected_rule_count} network policy rules in scope {scope!r} "
                f"- {_SCOPE_MEANING[scope]}. The count {expected_rule_count} is what YOU "
                f"asserted from nv_list_network_rules(scope={scope!r}); it is not verified "
                f"against the controller and it does not limit the delete, so if it is "
                f"wrong the number actually destroyed is different and is still every rule "
                f"in the scope. The rule list ends up EMPTY. Every group in Protect mode "
                f"then DROPS the traffic these rules were allowing, immediately and without "
                f"warning: running applications lose connectivity as soon as this call "
                f"returns. Traffic that these rules were denying stops being denied. The "
                f"controller keeps no copy and there is no undo - recovery means "
                f"re-creating every rule by hand, so export the current list with "
                f"nv_list_network_rules(scope={scope!r}) and keep it before confirming."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "DELETE", "/v1/policy/rule", params=build_query(extra={"scope": scope})
        )
        return WriteOutcome(
            status="applied",
            operation="nv_delete_all_network_rules",
            target=target,
            effect=(
                f"every network policy rule in scope {scope} deleted; the list is now empty "
                f"and groups in Protect mode are dropping whatever those rules allowed. "
                f"Confirm with nv_list_network_rules(scope={scope!r})."
            ),
            payload={},
            controller_response=response if isinstance(response, dict) else {},
        )


def _register_admission(mcp: FastMCP) -> None:
    """Tools tagged ``admission``: the whole admission-ruleset delete."""

    @mcp.tool(
        name="nv_delete_all_admission_rules",
        annotations=MUTATING,
        tags={"admission", "write"},
    )
    async def nv_delete_all_admission_rules(
        ctx: Context,
        expected_rule_count: Annotated[
            int,
            Field(
                ge=0,
                description="How many admission rules you believe are in this scope, taken "
                "from nv_list_admission_rules(scope=...) immediately before calling. It is "
                "echoed into the plan so the operator sees how many rules are about to die. "
                "It is NOT checked against the controller and does not limit the delete: the "
                "endpoint removes every rule in the scope whatever this number says.",
            ),
        ],
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="Which ruleset to wipe. 'local' deletes THIS cluster's own "
                "admission rules and leaves federated rules alone. 'fed' deletes the "
                "FEDERATED admission rules, which a federation primary pushes to every member "
                "cluster, so every member stops gating on them and not only this one; only a "
                "federation primary may do it. Getting this wrong destroys the wrong ruleset, "
                "so read the list with nv_list_admission_rules(scope=...) first and confirm "
                "you are looking at the rules you mean to delete."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete EVERY admission control rule in one scope, switching off deployment gating.

        This empties the admission rule list. It takes no rule ids and is not a filtered
        delete: everything in the chosen scope goes. With no rules left the cluster stops
        gating deployments entirely and immediately - the admission controller admits
        every pod, including the images with critical vulnerabilities, the unscanned
        images and the privileged containers it was denying a moment earlier. Exception
        (allow) rules go too, so this is not a loosening of policy, it is a switch-off.
        The admission state itself (nv_get_admission_state) is left enabled, which makes
        the gap easy to miss: the controller still reports admission control as on while
        nothing is being checked. There is no undo and the controller keeps no copy, so
        export the list with nv_list_admission_rules(scope=...) before you confirm. To
        remove one rule, use the single-rule delete instead.

        Calls DELETE /v1/admission/rules with scope.
        """
        app = app_context(ctx)
        # As with the network-rule wipe, expected_rule_count is bound into 'target'
        # so the confirmation token is invalidated when the asserted count changes.
        target = (
            f"all admission control rules in scope {scope!r} "
            f"(caller asserts {expected_rule_count} rule(s))"
        )
        plan = authorise_write(
            app.settings,
            operation="nv_delete_all_admission_rules",
            toolset="admission",
            target=target,
            effect=(
                f"Delete ALL {expected_rule_count} admission control rules in scope "
                f"{scope!r} - {_SCOPE_MEANING[scope]}. The count {expected_rule_count} is "
                f"what YOU asserted from nv_list_admission_rules(scope={scope!r}); it is "
                f"not verified against the controller and it does not limit the delete, so "
                f"if it is wrong the number actually destroyed is different and is still "
                f"every rule in the scope. The cluster STOPS GATING DEPLOYMENTS entirely "
                f"and immediately: with no rules left, admission control admits every pod, "
                f"including images with critical vulnerabilities, unscanned images and "
                f"privileged containers that were being denied a moment ago. Exception "
                f"(allow) rules are deleted along with deny rules, so this is not a "
                f"loosening of policy, it is a switch-off. Admission control still reports "
                f"itself as enabled in nv_get_admission_state, so nothing will look wrong "
                f"while nothing is being checked. There is no undo and the controller keeps "
                f"no copy - export the current list with "
                f"nv_list_admission_rules(scope={scope!r}) and keep it before confirming."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "DELETE", "/v1/admission/rules", params=build_query(extra={"scope": scope})
        )
        return WriteOutcome(
            status="applied",
            operation="nv_delete_all_admission_rules",
            target=target,
            effect=(
                f"every admission control rule in scope {scope} deleted; the cluster is no "
                f"longer gating deployments on any rule. Confirm with "
                f"nv_list_admission_rules(scope={scope!r}) and re-create the rules you "
                f"still need before the next deployment."
            ),
            payload={},
            controller_response=response if isinstance(response, dict) else {},
        )
