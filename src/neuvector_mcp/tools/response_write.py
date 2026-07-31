"""Response rules and their webhook destinations. Toolsets ``policy_write`` and ``system_write``.

Response rules and webhooks ship together on purpose. A response rule's
``webhooks`` field references webhook destinations **by name only**, so a rule
written without its destination is a dangling reference: the controller stores
the name, answers 200, and the notification silently never arrives. Deleting a
webhook breaks every rule that names it in exactly the same silent way. Anything
that creates a webhook-notifying rule must therefore be able to create the
webhook, and this module owns both halves.

Every mutating tool here follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

Webhook URLs and the two-payload rule
-------------------------------------
A webhook URL is an egress destination that frequently *is* the credential:
Slack and Teams incoming-webhook URLs carry their bearer token in the path
(``https://hooks.slack.com/services/T…/B…/<token>``). The three webhook tools
therefore obey the two-payload rule already used by ``tools/scan_ops.py`` and
``tools/iam_write.py``:

``wire_payload``
    the real body with the real URL. Handed to ``app.client.request(json=...)``
    and to nothing else.
``safe_payload``
    the same shape with the URL replaced by :func:`_redact_webhook_url`. Handed
    to the guard and placed in ``WriteOutcome.payload``.

The redaction here is deliberately *partial* rather than a bare ``"***"``. The
guard's confirmation plan exists so a human can review what is about to be sent,
and for an egress destination the security-relevant question is "where is this
data going" - a plan that hides the host answers nothing and invites a blind
confirm. So the safe form keeps scheme and host, which is what a reviewer needs,
and masks userinfo, path, query and fragment, which is where the secret lives.

Because the masked form would otherwise be identical for two different URLs on
the same host, it also carries a truncated SHA-256 of the **full** URL. That
keeps the confirmation token bound to the exact URL: previewing a plan for
``hooks.slack.com/services/A`` and then confirming with ``.../B`` fails with a
token mismatch. This is stricter than the scan_ops registry tools, where the
token deliberately does not cover the credential value.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..errors import ValidationError_
from ..guard import authorise_write
from ..models import (
    REDACTED,
    ResponseRuleInput,
    ResponseRuleOptions,
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

#: Hard cap on one batch of response-rule inserts. Same reasoning as
#: ``MAX_RULE_CHANGES`` in tools/policy_write.py: response rules are an ORDERED
#: list, so a batch that is wrong changes which rule reacts to every event the
#: inserted rules now shadow - and one of those reactions is quarantining a
#: running workload. Batches stay small enough for a human to read the preview
#: in full before confirming.
MAX_RESPONSE_RULE_CHANGES = 16

#: Schemes a webhook may target. The controller posts to this URL from inside the
#: cluster; anything that is not HTTP(S) is a caller mistake, not a destination.
_ALLOWED_WEBHOOK_SCHEMES = ("http", "https")


def _redact_webhook_url(url: str) -> str:
    """Reviewable, non-echoing form of a webhook URL.

    Keeps ``scheme://host[:port]`` so a reviewer can see where data would egress;
    masks userinfo, path, query and fragment, which is where Slack and Teams put
    the token. The appended digest is over the WHOLE original URL, so the
    confirmation token derived from this string still changes when any masked
    part changes.
    """
    digest = hashlib.sha256(url.encode()).hexdigest()[:12]
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host and parts.port:
        host = f"{host}:{parts.port}"
    if not parts.scheme or not host:
        return f"{REDACTED} (sha256:{digest})"
    return f"{parts.scheme}://{host}/{REDACTED} (sha256:{digest})"


def _redact_urls(obj: Any) -> Any:
    """Deep copy with every ``url`` value replaced by :func:`_redact_webhook_url`.

    Applied only to webhook request and response bodies. ``url`` is deliberately
    NOT in :data:`~neuvector_mcp.models.SECRET_FIELDS`, because a registry URL or
    a controller URL is not a secret and redacting those globally would break
    every other tool's payload preview.
    """
    if isinstance(obj, dict):
        return {
            key: (
                _redact_webhook_url(value)
                if key == "url" and isinstance(value, str)
                else _redact_urls(value)
            )
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_urls(item) for item in obj]
    return obj


def _condition_body(condition: Any) -> dict[str, str]:
    """Render one ``RESTCLUSEventCondition``: exactly ``type`` and ``value``.

    Field names from apis.go ``v1.EventCondition`` / apis.yaml
    ``RESTCLUSEventCondition``. Built explicitly rather than by ``model_dump()``
    so the wire shape is auditable field by field.
    """
    return {"type": condition.type, "value": condition.value}


def _response_rule_body(rule: ResponseRuleInput) -> dict[str, Any]:
    """Render one ``RESTResponseRule`` request object.

    Field names from apis.go ``RESTResponseRule``: id, event, comment, group,
    conditions, actions, webhooks, disable, cfg_type. ``id`` is omitted - it is a
    plain ``uint32`` with no ``omitempty``, so an absent id unmarshals to 0 on
    the controller, which is how it recognises a rule it must assign an id to.
    ``cfg_type`` is always ``user_created``; ``federal`` rules are authored on a
    federation primary and are not writable through this tool.
    """
    return {
        "event": rule.event,
        "comment": rule.comment,
        "group": rule.group,
        "conditions": [_condition_body(c) for c in rule.conditions],
        "actions": list(rule.actions),
        "webhooks": list(rule.webhooks),
        "disable": rule.disable,
        "cfg_type": "user_created",
    }


def _describe_response_rule(rule: ResponseRuleInput) -> str:
    """One preview line for an inserted rule."""
    conditions = ", ".join(f"{c.type}={c.value}" for c in rule.conditions) or "none"
    return (
        f"  + INSERT on {rule.event} for group={rule.group or 'ALL WORKLOADS'} "
        f"conditions=[{conditions}] "
        f"actions={','.join(rule.actions)} "
        f"webhooks={','.join(rule.webhooks) or 'none'}"
        f"{' [disabled]' if rule.disable else ''}"
    )


def _describe_after(after_rule_id: int | None) -> str:
    """Human reading of ``RESTResponseRuleInsert.after`` (semantics from apis.go)."""
    if after_rule_id is None:
        return "appended at the END of the rule list (no 'after' sent)"
    if after_rule_id == 0:
        return "placed FIRST in the rule list (after=0)"
    if after_rule_id > 0:
        return f"placed AFTER existing rule id {after_rule_id}"
    return f"placed BEFORE existing rule id {-after_rule_id}"


def _webhook_body(
    *, name: str, url: str, enable: bool, use_proxy: bool, webhook_type: str, cfg_type: str
) -> dict[str, Any]:
    """Render a ``RESTWebhook`` request object.

    Field names from apis.go ``RESTWebhook``: name, url, enable, use_proxy, type,
    cfg_type. Every one is a plain non-pointer field with no ``omitempty``, which
    is why the update tool has to send all of them - see its docstring.
    """
    return {
        "name": name,
        "url": url,
        "enable": enable,
        "use_proxy": use_proxy,
        "type": webhook_type,
        "cfg_type": cfg_type,
    }


def _validate_webhook_url(url: str) -> str:
    """Reject a URL the controller could not post to. Nothing is sent here."""
    candidate = url.strip()
    if candidate != url or not candidate:
        raise ValidationError_(
            "webhook url must not be empty or carry surrounding whitespace. "
            "Nothing was sent to the controller."
        )
    scheme = urlsplit(candidate).scheme.lower()
    if scheme not in _ALLOWED_WEBHOOK_SCHEMES:
        raise ValidationError_(
            f"webhook url must use http:// or https://, got {scheme or 'no scheme'!r}. "
            "The controller posts to this URL from inside the cluster. "
            "Nothing was sent to the controller."
        )
    if not urlsplit(candidate).hostname:
        raise ValidationError_("webhook url has no host. Nothing was sent to the controller.")
    return candidate


def _validate_webhook_names(webhooks: list[str]) -> None:
    """Reject blank or duplicated webhook references. Nothing is sent here."""
    if any(not name.strip() for name in webhooks):
        raise ValidationError_(
            "response rule 'webhooks' entries must be non-empty webhook NAMES, not URLs. "
            "List the configured names with nv_get_response_rule_options, or create one "
            "with nv_create_webhook. Nothing was sent to the controller."
        )
    if len(set(webhooks)) != len(webhooks):
        raise ValidationError_(
            "response rule 'webhooks' contains a duplicate name. "
            "Nothing was sent to the controller."
        )


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the response-rule and webhook tools to ``mcp``.

    Two toolsets are gated independently so a read tool never ships under a write
    toolset: the options lookup is ``policy_read``, the response-rule writes are
    ``policy_write``, and the webhook writes are ``system_write`` (a webhook is
    cluster-wide system configuration, not policy).
    """
    if settings.toolset_enabled("policy_read"):
        _register_read(mcp)
    if settings.toolset_enabled("policy_write"):
        _register_response_rule_writes(mcp)
    if settings.toolset_enabled("system_write"):
        _register_webhook_writes(mcp)


def _register_read(mcp: FastMCP) -> None:
    @mcp.tool(
        name="nv_get_response_rule_options",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_response_rule_options(ctx: Context) -> ResponseRuleOptions:
        """The vocabulary a response rule may use: event categories, actions and webhook names.

        Call this BEFORE writing a response rule. Event names, action names and
        condition types are controller-defined strings; an unrecognised one is stored
        without complaint and the rule then never fires, so guessing produces a rule
        that looks correct in a listing and does nothing. The 'webhooks' list is the
        complete set of names a rule's 'webhooks' field may reference - anything else
        is a dangling reference whose notification silently never arrives.

        Calls GET /v1/response/options.
        """
        app = app_context(ctx)
        body = await app.client.request("GET", "/v1/response/options")
        return ResponseRuleOptions.from_api(body if isinstance(body, dict) else {})


def _register_response_rule_writes(mcp: FastMCP) -> None:
    @mcp.tool(
        name="nv_apply_response_rule_changes",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_apply_response_rule_changes(
        ctx: Context,
        insert_rules: Annotated[
            list[ResponseRuleInput],
            Field(
                default_factory=list,
                description="New response rules, in the order they should appear. The controller "
                "assigns their ids. Insert a rule with a quarantine action disabled=true first, "
                "check with nv_list_response_rules which events it matches, then enable it.",
            ),
        ],
        insert_after_rule_id: Annotated[
            int | None,
            Field(
                description="Where the batch lands in the ordered rule list (controller field "
                "'insert.after'). Omit for LAST; 0 for FIRST; a positive existing rule id to go "
                "after that rule; the NEGATIVE of an existing rule id to go before it. Those "
                "four meanings are stated on RESTResponseRuleInsert.After in the upstream "
                "apis.go. Verify the resulting order with nv_list_response_rules afterwards."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the whole batch."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Insert one ordered batch of response rules.

        Response rules are an ORDERED list and one of their actions QUARANTINES a running
        workload, so a rule inserted too high reacts to events the rules below it were
        meant to handle and can take production containers off the network. Read the
        current list with nv_list_response_rules first, get valid event and action names
        from nv_get_response_rule_options, keep the batch small, and re-read the list
        immediately after applying to confirm the order you got is the order you wanted.
        Any rule naming a webhook needs that webhook to exist already (nv_create_webhook)
        or the notification silently never arrives. At most 16 rules per call.

        This route INSERTS ONLY. RESTResponseRuleActionData carries a single 'insert'
        field in both apis.go and apis.yaml for controller 5.6.0 - unlike network rules
        it has no 'move', 'rules' or 'delete' member - so reordering an existing rule is
        not expressible here, editing one goes through nv_update_response_rule, and
        removing one goes through nv_delete_response_rule.

        Calls PATCH /v1/response/rule with {"insert": {"after":..., "rules": [...]}}.
        """
        app = app_context(ctx)

        # --- step 1 validation: local only, no network call --------------------
        rules = list(insert_rules)
        if not rules:
            raise ValidationError_(
                "nv_apply_response_rule_changes needs at least one entry in insert_rules. "
                "Nothing was sent to the controller."
            )
        if len(rules) > MAX_RESPONSE_RULE_CHANGES:
            raise ValidationError_(
                f"batch of {len(rules)} response rules exceeds the hard cap of "
                f"{MAX_RESPONSE_RULE_CHANGES}. Split it into smaller batches and verify with "
                "nv_list_response_rules between them: a large batch that is wrong starts "
                "quarantining workloads before anyone reads the result. Nothing was sent "
                "to the controller."
            )
        for rule in rules:
            _validate_webhook_names(list(rule.webhooks))

        payload: dict[str, Any] = {"rules": [_response_rule_body(r) for r in rules]}
        if insert_after_rule_id is not None:
            payload["after"] = insert_after_rule_id
        wire_payload: dict[str, Any] = {"insert": payload}

        diff = "\n".join(_describe_response_rule(r) for r in rules)
        position = _describe_after(insert_after_rule_id)
        target = "response rules"
        effect = (
            f"Insert {len(rules)} response rule(s) as ONE batch, {position}:\n{diff}\n"
            "Rule order IS evaluation order. A response rule reacts automatically and with "
            "no human in the loop: depending on its actions it can suppress the log of an "
            "event, quarantine the workload that caused it, or post the event to a webhook. "
            "Webhook targets are referenced by NAME - if the name does not exist the rule is "
            "stored anyway and the notification silently never arrives. Re-read the list with "
            "nv_list_response_rules straight after applying."
        )

        plan = authorise_write(
            app.settings,
            operation="nv_apply_response_rule_changes",
            toolset="policy_write",
            target=target,
            effect=effect,
            payload=wire_payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", "/v1/response/rule", json=wire_payload)
        return WriteOutcome(
            status="applied",
            operation="nv_apply_response_rule_changes",
            target=target,
            effect=(
                f"inserted {len(rules)} response rule(s), {position}:\n{diff}\n"
                "Verify the resulting order and the assigned ids with nv_list_response_rules."
            ),
            payload=wire_payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_response_rule",
        annotations=MUTATING_IDEMPOTENT,
        tags={"policy_write", "write"},
    )
    async def nv_update_response_rule(
        ctx: Context,
        rule_id: Annotated[
            int,
            Field(ge=0, description="Id of the rule to change, from nv_list_response_rules."),
        ],
        event: Annotated[
            str | None,
            Field(
                description="New event category. Omit to leave it unchanged. Valid names come "
                "from nv_get_response_rule_options."
            ),
        ] = None,
        group: Annotated[
            str | None,
            Field(
                description="New group scope. Omit to leave it unchanged. An empty string "
                "widens the rule to EVERY workload in the cluster."
            ),
        ] = None,
        actions: Annotated[
            list[str] | None,
            Field(
                description="New action list. Omit to leave it unchanged. This REPLACES the "
                "current actions rather than adding to them."
            ),
        ] = None,
        webhooks: Annotated[
            list[str] | None,
            Field(
                description="New webhook NAME list. Omit to leave it unchanged. This REPLACES "
                "the current list. A name with no matching webhook is a dangling reference."
            ),
        ] = None,
        conditions: Annotated[
            list[dict[str, str]] | None,
            Field(
                description="New condition list as [{'type':..., 'value':...}]. Omit to leave "
                "it unchanged; pass [] to drop every condition, which WIDENS the rule to every "
                "event of its category."
            ),
        ] = None,
        comment: Annotated[
            str | None, Field(description="New comment. Omit to leave it unchanged.")
        ] = None,
        disable: Annotated[
            bool | None,
            Field(
                description="True stores the rule but stops it acting; False re-arms it. Omit "
                "to leave it unchanged."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Change fields of one existing response rule in place.

        Only the arguments you pass are sent. RESTResponseRuleConfig makes every editable
        field a POINTER with omitempty, so an ABSENT field means "not modified" while a
        field present as null would be a modification - which is why an omitted argument
        is dropped from the body entirely rather than sent as null. List-valued fields
        that you do pass REPLACE the stored list, so read the rule with
        nv_list_response_rules first and send the whole list you want to end up with.
        Widening a rule (clearing 'group', clearing 'conditions', adding a quarantine
        action) makes it react to events it previously ignored.

        The tool always sends cfg_type=user_created; federated response rules are
        authored on a federation primary and are not editable here.

        Calls PATCH /v1/response/rule/{id} with {"config": {...}}.
        """
        app = app_context(ctx)

        # --- step 1 validation: local only, no network call --------------------
        if webhooks is not None:
            _validate_webhook_names(list(webhooks))
        if conditions is not None:
            for entry in conditions:
                if not entry.get("type"):
                    raise ValidationError_(
                        "every condition needs a non-empty 'type'; valid types come from "
                        "nv_get_response_rule_options. Nothing was sent to the controller."
                    )
                unknown = set(entry) - {"type", "value"}
                if unknown:
                    raise ValidationError_(
                        f"condition has unknown key(s) {sorted(unknown)}; a condition is exactly "
                        "{'type': ..., 'value': ...} (RESTCLUSEventCondition). The controller "
                        "answers 200 and silently drops unknown fields, so this is rejected "
                        "here. Nothing was sent to the controller."
                    )

        # Field names and pointer/omitempty semantics from apis.go
        # RESTResponseRuleConfig. id and cfg_type are the only non-pointer members,
        # so they are always present; everything else is written only when given.
        config: dict[str, Any] = {"id": rule_id, "cfg_type": "user_created"}
        changes: list[str] = []
        if comment is not None:
            config["comment"] = comment
            changes.append(f"comment={comment!r}")
        if group is not None:
            config["group"] = group
            changes.append(f"group={group!r}" if group else "group=ALL WORKLOADS (cleared)")
        if event is not None:
            config["event"] = event
            changes.append(f"event={event!r}")
        if conditions is not None:
            config["conditions"] = [
                {"type": c.get("type", ""), "value": c.get("value", "")} for c in conditions
            ]
            changes.append(
                f"conditions REPLACED with {len(conditions)} entr"
                f"{'y' if len(conditions) == 1 else 'ies'}"
                + ("" if conditions else " (rule now matches EVERY event of its category)")
            )
        if actions is not None:
            config["actions"] = list(actions)
            changes.append(f"actions REPLACED with {actions}")
        if webhooks is not None:
            config["webhooks"] = list(webhooks)
            changes.append(f"webhooks REPLACED with {webhooks}")
        if disable is not None:
            config["disable"] = disable
            changes.append("rule DISABLED" if disable else "rule ENABLED")

        if not changes:
            raise ValidationError_(
                "nv_update_response_rule was given nothing to change. Pass at least one of "
                "event, group, actions, webhooks, conditions, comment or disable. Nothing "
                "was sent to the controller."
            )

        wire_payload: dict[str, Any] = {"config": config}
        target = f"response rule {rule_id}"
        effect = (
            f"Change response rule {rule_id}: " + "; ".join(changes) + ". "
            "Fields not listed are left untouched; list-valued fields listed here REPLACE "
            "the stored list. Re-read the rule with nv_list_response_rules afterwards."
        )

        plan = authorise_write(
            app.settings,
            operation="nv_update_response_rule",
            toolset="policy_write",
            target=target,
            effect=effect,
            payload=wire_payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH", f"/v1/response/rule/{rule_id}", json=wire_payload
        )
        return WriteOutcome(
            status="applied",
            operation="nv_update_response_rule",
            target=target,
            effect=f"response rule {rule_id} updated: " + "; ".join(changes),
            payload=wire_payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_response_rule",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_response_rule(
        ctx: Context,
        rule_id: Annotated[
            int,
            Field(ge=0, description="Id of the rule to delete, from nv_list_response_rules."),
        ],
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Delete one response rule.

        The automated reaction that rule performed stops happening immediately and there
        is no undo: read the rule with nv_list_response_rules and keep a copy of its
        event, group, conditions, actions and webhooks first, because re-creating it with
        nv_apply_response_rule_changes needs all of them and the new rule gets a new id
        at a new position in the ordered list. Deleting a rule that only SUPPRESSED logs
        makes those events start appearing again; deleting one that quarantined or
        notified removes a control nobody will notice is gone.

        Calls DELETE /v1/response/rule/{id}.
        """
        app = app_context(ctx)
        target = f"response rule {rule_id}"
        plan = authorise_write(
            app.settings,
            operation="nv_delete_response_rule",
            toolset="policy_write",
            target=target,
            effect=(
                f"Delete response rule {rule_id}. The automated reaction it performed - "
                "log suppression, quarantine or webhook notification - stops immediately "
                "and cannot be undone."
            ),
            payload=None,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request("DELETE", f"/v1/response/rule/{rule_id}")
        return WriteOutcome(
            status="applied",
            operation="nv_delete_response_rule",
            target=target,
            effect=f"response rule {rule_id} deleted",
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_all_response_rules",
        annotations=MUTATING,
        tags={"policy_write", "write"},
    )
    async def nv_delete_all_response_rules(
        ctx: Context,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' wipes this cluster's own response rules. 'fed' wipes the "
                "federated rules, which only a federation primary may change - elsewhere the "
                "controller rejects it."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete EVERY response rule in one scope. Destroys all automated response.

        HIGHEST-RISK TOOL IN THIS MODULE, and almost never the right one. This does not
        disable rules, it removes them, all of them, in one call, with no undo and no
        per-rule preview: after it returns, NOTHING is quarantined automatically, NO
        webhook fires on any security event, and every log a suppression rule was hiding
        starts flowing again. The cluster keeps detecting and keeps alerting, so nothing
        looks broken - the automated RESPONSE is simply gone, which is exactly the kind of
        failure nobody notices until an incident is not contained. Export the rules with
        nv_list_response_rules and keep the output before you even preview this, and
        prefer deleting rules one at a time with nv_delete_response_rule.

        Calls DELETE /v1/response/rule with scope.
        """
        app = app_context(ctx)
        target = f"all response rules (scope={scope})"
        plan = authorise_write(
            app.settings,
            operation="nv_delete_all_response_rules",
            toolset="policy_write",
            target=target,
            effect=(
                f"Delete EVERY response rule in scope {scope!r}. This silently disables all "
                "automated response: no quarantine, no webhook notification, and previously "
                "suppressed events start appearing again. Detection and alerting continue "
                "unchanged, so the loss is invisible until an incident goes uncontained. "
                "There is no undo - save nv_list_response_rules output first."
            ),
            payload=None,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "DELETE", "/v1/response/rule", params=build_query(extra={"scope": scope})
        )
        return WriteOutcome(
            status="applied",
            operation="nv_delete_all_response_rules",
            target=target,
            effect=(
                f"every response rule in scope {scope} deleted; no automated response remains. "
                "Confirm with nv_list_response_rules and rebuild what you still need."
            ),
            controller_response=response if isinstance(response, dict) else {},
        )


def _register_webhook_writes(mcp: FastMCP) -> None:
    @mcp.tool(
        name="nv_create_webhook",
        annotations=MUTATING_CREATE,
        tags={"system_write", "write"},
    )
    async def nv_create_webhook(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for the new webhook. This is the string a response rule's "
                "'webhooks' field references, so pick something a rule author will recognise.",
            ),
        ],
        url: Annotated[
            str,
            Field(
                min_length=1,
                description="Destination the controller POSTs events to. Must be http:// or "
                "https://. Treated as a credential: previews and results show only "
                "scheme://host plus a digest, never the path or query.",
            ),
        ],
        webhook_type: Annotated[
            Literal["Slack", "JSON", "Teams"],
            Field(
                description="Payload format (controller field 'type'). 'Slack' and 'Teams' "
                "emit that product's message format; 'JSON' posts the raw event."
            ),
        ] = "JSON",
        enable: Annotated[
            bool,
            Field(description="False stores the destination without ever posting to it."),
        ] = True,
        use_proxy: Annotated[
            bool,
            Field(
                description="Route the POST through the cluster's configured egress proxy. "
                "Needs a proxy configured in system settings."
            ),
        ] = False,
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Create a webhook destination that response rules can notify by name.

        This is the other half of a webhook-notifying response rule: a rule references a
        destination by NAME only, so create the webhook first and then name it in
        nv_apply_response_rule_changes, or the rule stores a dangling reference and the
        notification silently never arrives. Every security event matching such a rule is
        then POSTed to this URL, so it is an egress path out of the cluster - point it at
        a destination that is allowed to receive security event data.

        The URL is handled as a credential. Slack and Teams incoming-webhook URLs carry
        their token in the path, so the confirmation plan and the result show only
        scheme://host plus a SHA-256 prefix of the whole URL. The digest keeps the confirm
        token bound to the exact URL while never echoing the secret back.

        Calls POST /v1/system/config/webhook with {"config": {...}}.
        """
        app = app_context(ctx)

        # --- step 1 validation: local only, no network call --------------------
        clean_url = _validate_webhook_url(url)

        # Field names from apis.go RESTWebhook. cfg_type=user_created: this route
        # has no scope parameter, so it always creates a local webhook.
        wire_payload: dict[str, Any] = {
            "config": _webhook_body(
                name=name,
                url=clean_url,
                enable=enable,
                use_proxy=use_proxy,
                webhook_type=webhook_type,
                cfg_type="user_created",
            )
        }
        safe_payload = _redact_urls(wire_payload)
        effect = (
            f"Create webhook {name!r} of type {webhook_type} posting to "
            f"{_redact_webhook_url(clean_url)}"
            f"{'' if enable else ' (created disabled)'}. "
            "Every event matched by a response rule naming this webhook is sent to that "
            "destination, so this is an egress path for security event data out of the "
            "cluster. The URL is shown host-only on purpose; the digest covers the whole "
            "URL, so the confirm token stops a different path being substituted."
        )

        plan = authorise_write(
            app.settings,
            operation="nv_create_webhook",
            toolset="system_write",
            target=name,
            effect=effect,
            payload=safe_payload,
            confirm=confirm,
            namespace=None,  # cluster-wide: NV_ALLOWED_NAMESPACES cannot scope it
        )
        if plan is not None:
            return plan

        response = await app.client.request("POST", "/v1/system/config/webhook", json=wire_payload)
        return WriteOutcome(
            status="applied",
            operation="nv_create_webhook",
            target=name,
            effect=f"webhook {name} created ({webhook_type}, {_redact_webhook_url(clean_url)})",
            payload=safe_payload,
            controller_response=_redact_urls(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_webhook",
        annotations=MUTATING_IDEMPOTENT,
        tags={"system_write", "write"},
    )
    async def nv_update_webhook(
        ctx: Context,
        name: Annotated[
            str, Field(min_length=1, description="Name of the existing webhook to reconfigure.")
        ],
        url: Annotated[
            str,
            Field(
                min_length=1,
                description="Destination URL. REQUIRED even when unchanged - see the tool "
                "description; the controller overwrites the whole webhook object.",
            ),
        ],
        webhook_type: Annotated[
            Literal["Slack", "JSON", "Teams"],
            Field(description="Payload format. Required for the same reason as 'url'."),
        ] = "JSON",
        enable: Annotated[
            bool, Field(description="False keeps the destination but stops posting to it.")
        ] = True,
        use_proxy: Annotated[
            bool, Field(description="Route the POST through the configured egress proxy.")
        ] = False,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' edits this cluster's webhook. 'fed' edits the federated "
                "webhook, which only a federation primary may change."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Reconfigure an existing webhook destination. Sends the WHOLE object every time.

        There is no partial update here. RESTWebhook has no pointer or omitempty fields,
        so every one of name, url, enable, use_proxy, type and cfg_type goes on the wire
        and the stored webhook is OVERWRITTEN - anything you do not pass reverts to this
        tool's default, not to its current value. Read the webhook's current settings
        before calling and pass them all back. Changing the URL silently redirects every
        response rule that names this webhook, and those rules are not notified.

        The URL is handled as a credential: the confirmation plan shows only scheme://host
        plus a SHA-256 prefix of the whole URL, which is enough to review the destination
        without echoing a Slack or Teams token back.

        Calls PATCH /v1/system/config/webhook/{name} with scope and {"config": {...}}.
        """
        app = app_context(ctx)

        # --- step 1 validation: local only, no network call --------------------
        clean_url = _validate_webhook_url(url)

        # cfg_type mirrors the scope query parameter: apis.go names the two
        # constants CfgTypeUserCreated="user_created" and CfgTypeFederal="federal".
        cfg_type = "federal" if scope == "fed" else "user_created"
        wire_payload: dict[str, Any] = {
            "config": _webhook_body(
                name=name,
                url=clean_url,
                enable=enable,
                use_proxy=use_proxy,
                webhook_type=webhook_type,
                cfg_type=cfg_type,
            )
        }
        safe_payload = _redact_urls(wire_payload)
        effect = (
            f"Overwrite webhook {name!r} in scope {scope!r}: type={webhook_type}, "
            f"url={_redact_webhook_url(clean_url)}, enable={enable}, use_proxy={use_proxy}. "
            "The whole object is replaced, so any field not passed reverts to this tool's "
            "default rather than keeping its current value. Response rules referencing "
            f"{name!r} follow the new URL without being notified."
        )

        plan = authorise_write(
            app.settings,
            operation="nv_update_webhook",
            toolset="system_write",
            target=name,
            effect=effect,
            payload=safe_payload,
            confirm=confirm,
            namespace=None,  # cluster-wide: NV_ALLOWED_NAMESPACES cannot scope it
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH",
            f"/v1/system/config/webhook/{name}",
            params=build_query(extra={"scope": scope}),
            json=wire_payload,
        )
        return WriteOutcome(
            status="applied",
            operation="nv_update_webhook",
            target=name,
            effect=(
                f"webhook {name} in scope {scope} overwritten "
                f"({webhook_type}, {_redact_webhook_url(clean_url)}, enable={enable})"
            ),
            payload=safe_payload,
            controller_response=_redact_urls(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_webhook",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_delete_webhook(
        ctx: Context,
        name: Annotated[
            str, Field(min_length=1, description="Name of the webhook destination to delete.")
        ],
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' deletes this cluster's webhook. 'fed' deletes the "
                "federated one, which only a federation primary may change."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(description="Confirmation token from the plan returned by the first call."),
        ] = None,
    ) -> WriteOutcome:
        """Delete a webhook destination. Breaks every response rule that names it.

        Response rules reference a webhook by NAME, and nothing re-validates those
        references: rules naming this webhook keep existing, keep matching events, and
        their notification silently stops arriving. That is the failure this tool causes
        and it produces no error anywhere. Before deleting, list the rules with
        nv_list_response_rules and check the 'webhooks' field of each - update or delete
        the rules that name this webhook first, then delete the destination. The URL is
        not recoverable from this server afterwards, so save it elsewhere if you may need
        to recreate the destination.

        Calls DELETE /v1/system/config/webhook/{name} with scope.
        """
        app = app_context(ctx)
        plan = authorise_write(
            app.settings,
            operation="nv_delete_webhook",
            toolset="system_write",
            target=name,
            effect=(
                f"Delete webhook {name!r} in scope {scope!r}. Every response rule whose "
                f"'webhooks' field names {name!r} keeps matching events but its notification "
                "silently stops arriving - no rule is updated and no error is raised. Check "
                "nv_list_response_rules for references first."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,  # cluster-wide: NV_ALLOWED_NAMESPACES cannot scope it
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "DELETE",
            f"/v1/system/config/webhook/{name}",
            params=build_query(extra={"scope": scope}),
        )
        return WriteOutcome(
            status="applied",
            operation="nv_delete_webhook",
            target=name,
            effect=(
                f"webhook {name} deleted from scope {scope}; response rules still naming it "
                "no longer notify anything"
            ),
            controller_response=_redact_urls(response) if isinstance(response, dict) else {},
        )
