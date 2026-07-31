# TOOLS — Part C: `policy_write`, `admission` (12 mutating tools)

Companion to `SPEC.md` sections 3 (API conventions), 6 (safety model), 7.4 (the
five-step mutating tool body) and 12 (gate rules). Every contract below is in
`_TEMPLATE.md` format and is normative.

**This part contains the only tools in the server that can drop production
traffic or block a cluster's deployments.** Read `SPEC.md` §6 and §7.4 before
writing a line of code, and read `reference/src/neuvector_mcp/guard.py` and
`reference/tests/test_guard.py` — the guard is already written and already
tested; you call it, you never re-implement it.

## C.0.0 Invariants that apply to all 12 tools, without exception

| # | Invariant |
|---|---|
| **C1** | `readOnlyHint=False` on every tool. Both toolsets are write-kind (SPEC §5.1), so gate rule R3 fails any tool here that claims `readOnlyHint=True`. |
| **C2** | Exactly **two** tags: one toolset tag plus `"write"` — `{"policy_write", "write"}` or `{"admission", "write"}` (gate rule R4). Never both toolsets, never `"read"`. |
| **C3** | Every tool accepts `confirm: Annotated[str \| None, Field(description=...)] = None` as its **last** parameter (gate rule R5). |
| **C4** | Every tool returns `WriteOutcome` — the existing model in `models.py`. Do not subclass it, do not add fields to it, do not return `dict` (gate rule R7). |
| **C5** | Every tool body is the five steps of SPEC §7.4 **in order**: (1) build payload, (2) `authorise_write(...)`, (3) `if plan is not None: return plan`, (4) controller call, (5) `WriteOutcome(status="applied", ...)`. |
| **C6** | **No `await app.client.*` call may appear before step 3.** Not a read to enrich the preview, not a lookup to validate an id, nothing. `test_guard.py::test_first_call_returns_plan_and_sends_nothing` asserts `route.call_count == 0` and every tool here repeats that assertion under its own name. Local, non-network validation (argument shape, batch caps) belongs in step 1 and may raise. |
| **C7** | `register(mcp, settings)` returns immediately when the toolset is disabled, exactly as the reference does: `if not settings.toolset_enabled("<toolset>"): return`. This is what makes `NV_READ_ONLY=true` hide the tools rather than fail them at call time. |
| **C8** | The confirm token is `sha256(operation \| target \| canonical_json(payload))[:12]` (`guard.confirm_token`). It binds **operation, target and payload only** — it does **not** bind `effect`, and it does **not** bind query parameters. Any value that changes controller behaviour but is not in the payload **must be folded into `target`**. Exactly one tool in this part needs that: `nv_apply_network_rule_changes` (`scope`). |
| **C9** | The docstring's last line(s) are `Calls <METHOD> <path>[ with <payload>].` — machine-parsed by gate rule R6. One line per endpoint the tool may hit. |

## C.0.1 Endpoint verification record — done before this document was written

All 11 distinct endpoints were resolved against
`spec_endpoints.json["documented"]` (232 routes). Result: **11 documented, 0
undocumented, 0 invented, 0 BLOCKED on a missing endpoint.**

| Tool | Endpoint | In `spec_endpoints.json["documented"]` |
|---|---|---|
| `nv_create_group` | `POST /v1/group` | yes |
| `nv_update_group_criteria` | `PATCH /v1/group/{name}` | yes |
| `nv_delete_group` | `DELETE /v1/group/{name}` | yes |
| `nv_set_group_policy_mode` | `PATCH /v1/group/{name}` | yes |
| `nv_apply_network_rule_changes` | `PATCH /v1/policy/rule` | yes |
| `nv_delete_network_rule` | `DELETE /v1/policy/rule/{id}` | yes |
| `nv_update_process_profile` | `PATCH /v1/process_profile/{name}` | yes |
| `nv_update_file_monitor_profile` | `PATCH /v1/file_monitor/{name}` | yes |
| `nv_set_admission_state` | `PATCH /v1/admission/state` | yes |
| `nv_create_admission_rule` | `POST /v1/admission/rule` | yes |
| `nv_update_admission_rule` | `PATCH /v1/admission/rule` | yes |
| `nv_delete_admission_rule` | `DELETE /v1/admission/rule/{id}` | yes |

Note the two shapes a 30B model gets wrong most often:

* `PATCH /v1/admission/rule` has **no `{id}` path segment**. The rule id travels
  in the request body as `config.id`. `PATCH /v1/admission/rule/{id}` does not
  exist — sending it fails R6 and would 404.
* `PATCH /v1/policy/rule` (batch, no `{id}`) and `PATCH /v1/policy/rule/{id}`
  (single rule) are both documented and are different operations. This part uses
  **only the batch form**. Do not add a tool for the single form.

## C.0.2 Request-body verification record

Every field sent by every tool in this part is listed here with the Appendix B
type it comes from. Nothing else may be sent.

| Type | Envelope key | Verified fields used | Status |
|---|---|---|---|
| `RESTGroupConfigData` | `config` | — | documented |
| `RESTGroupConfig` | — | `name`*, `criteria`, `cfg_type`* | documented |
| `RESTCriteriaEntry` | — | `key`*, `value`*, `op`* | documented; `key`/`op` **not enumerated** — see `nv_create_group` Notes |
| `RESTPolicyRuleActionData` | *(none — fields are top level)* | `insert`, `move`, `rules`, `delete` | documented |
| `RESTPolicyRuleInsert` | — | `after`, `rules`* | documented; `after` **semantics undocumented** |
| `RESTPolicyRuleMove` | — | `after`, `id`* | documented; `after` **semantics undocumented** |
| `RESTPolicyRule` | — | `id`, `from`*, `to`*, `ports`*, `action`*, `applications`*, `comment`*, `disable`*, `cfg_type`* | documented |
| `RESTProcessProfileConfigData` | **`process_profile_config`** | — | documented — the key is **not** `config` |
| `RESTProcessProfileConfig` | — | `group`*, `alert_disabled`, `hash_enabled`, `process_change_list`, `process_delete_list` | documented |
| `RESTProcessProfileEntryConfig` | — | `name`*, `path`*, `action`*, `group`* | documented; all four required |
| `RESTFileMonitorConfigData` | `config` | — | documented |
| `RESTFileMonitorConfig` | — | `add_filters`, `update_filters`, `delete_filters` | documented |
| `RESTFileMonitorFilterConfig` | — | `filter`*, `recursive`*, `behavior`*, `applications`*, `group`* | documented; all five required, `behavior` **not enumerated** |
| `RESTAdmissionConfigData` | *(none — `state` is a field, not a wrapper)* | `state` | documented; `k8s_env` is required in Swagger but **must not be sent** — see `nv_set_admission_state` Notes |
| `RESTAdmissionState` | — | `enable`, `mode`, `default_action` | documented; `mode`/`default_action` **not enumerated on this type** |
| `RESTAdmissionRuleConfigData` | `config` | — | documented |
| `RESTAdmissionRuleConfig` | — | `id`*, `category`*, `comment`, `criteria`, `disable`, `cfg_type`*, `rule_type`*, `rule_mode`, `containers`* | documented; `actions` exists but is **not sent** |
| `RESTAdmRuleCriterion` | — | `name`*, `op`*, `value`*, `sub_criteria`, `type`, `template_kind`, `path`, `value_type` | documented; only the first four are sent |

**BLOCKED items in this part — four, all `BLOCKED (schema)` or
`BLOCKED (semantics)`, none blocking on a missing endpoint:**

1. **`BLOCKED (semantics)` — the sign and omission semantics of
   `RESTPolicyRuleInsert.after` and `RESTPolicyRuleMove.after`.** See
   `nv_apply_network_rule_changes` Notes. Consequence: the value is passed
   through verbatim and never synthesised.
2. **`BLOCKED (semantics)` — whether `RESTPolicyRuleActionData.rules` is a
   partial "configure these ids" list or a whole-list replacement.** See
   `nv_apply_network_rule_changes` Notes. Consequence: an `id` is mandatory on
   every configure entry, and the effect string states the ambiguity.
3. **`BLOCKED (schema)` — `RESTGroupConfig` has no `policy_mode` field**, yet the
   already-implemented `nv_set_group_policy_mode` sends one. See that tool's
   Notes. Consequence: **do not "fix" it** — rule N3 pins the reference file.
4. **`BLOCKED (schema)` — `RESTAdmissionConfigData.k8s_env` is marked required**
   but is a controller-reported fact, not a client-settable field. See
   `nv_set_admission_state` Notes. Consequence: it is not sent, and a `code=6`
   from a live controller is the signal to revisit.

Three enumerations are absent from Appendix B and are **narrowed deliberately** in
this part, with the narrowing recorded in the owning tool's Notes:
`RESTPolicyRule.action` → `Literal["allow", "deny"]`,
`RESTProcessProfileEntryConfig.action` → `Literal["allow", "deny"]`,
`RESTAdmissionState.default_action` → `Literal["allow", "deny"]`. If a live
controller rejects one of these with `code=6`, widen that argument to `str` and
record it — do not invent a third value.

## C.0.3 Destructive-operation classification (SPEC §6.2)

Every tool is placed in exactly one SPEC §6.2 class, and the class determines
`destructiveHint`. Two placements are deliberate departures from the obvious row
and are justified in the owning tool's Notes.

| Tool | SPEC §6.2 class | `destructiveHint` | `idempotentHint` | Annotation constant |
|---|---|---|---|---|
| `nv_create_group` | Object creation | `False` | `False` | `MUTATING_CREATE` |
| `nv_update_group_criteria` | Traffic-affecting | `True` | `False` | `MUTATING` |
| `nv_delete_group` | Data-destroying | `True` | `False` | `MUTATING` |
| `nv_set_group_policy_mode` | Reversible config change | `False` | `True` | `MUTATING_IDEMPOTENT` |
| `nv_apply_network_rule_changes` | Traffic-affecting **and** data-destroying | `True` | `False` | `MUTATING` |
| `nv_delete_network_rule` | Data-destroying **and** traffic-affecting | `True` | `False` | `MUTATING` |
| `nv_update_process_profile` | Traffic-affecting (process-killing) | `True` | `False` | `MUTATING` |
| `nv_update_file_monitor_profile` | Traffic-affecting (write-blocking) | `True` | `False` | `MUTATING` |
| `nv_set_admission_state` | Traffic-affecting — the widest blast radius in the server | `True` | `False` | `MUTATING` |
| `nv_create_admission_rule` | Traffic-affecting (**not** object creation — see Notes) | `True` | `False` | `MUTATING` |
| `nv_update_admission_rule` | Traffic-affecting | `True` | `False` | `MUTATING` |
| `nv_delete_admission_rule` | Data-destroying **and** traffic-affecting | `True` | `False` | `MUTATING` |

**Why `idempotentHint=False` almost everywhere.** The hint tells a client "repeat
me for free". That is only true of `nv_set_group_policy_mode`, where the
controller converges on a mode. Everywhere else a repeat is either an error
(`nv_create_group` → `code=13`; deleting an already-deleted rule → `code=7`) or a
second distinct change (`insert` mints new rule ids each time). When in doubt the
answer is `False`: a false `True` invites a client to retry a traffic-affecting
write it should have re-previewed.

**Why `nv_create_admission_rule` is `destructiveHint=True` while
`nv_create_group` is `False`.** SPEC §6.2 has a row for object creation
(`False`) and a row for traffic-affecting operations (`True`). A new group is
inert: it has no rules, no policy mode of its own, and changes nothing until
something references it — row 2, `False`. A new admission **deny** rule is the
opposite: the moment the controller stores it, the Kubernetes API server starts
rejecting matching requests cluster-wide, with no rollout and no per-namespace
staging. That is row 4, `True`. Classify by blast radius, not by HTTP verb.

---

## C.0.4 `src/neuvector_mcp/tools/policy_write.py` [Phase 7] — extend, do not rewrite

`reference/src/neuvector_mcp/tools/policy_write.py` is copied verbatim in Phase 0
and already contains the module docstring, the imports, `MUTATING`,
`MUTATING_IDEMPOTENT`, `register()`, and **two finished tools**
(`nv_set_group_policy_mode`, `nv_delete_group`). Phase 7 makes exactly four kinds
of edit:

1. Keep both existing tool bodies **byte-identical**. Do not reorder their
   arguments, do not reword their docstrings, do not "harmonise" their effect
   strings with the new ones. Rule N3.
2. Extend the existing model import to:

   ```python
   from ..models import (
       FileMonitorFilterInput,
       GroupCriterionInput,
       NetworkRuleInput,
       ProcessProfileEntryInput,
       WriteOutcome,
   )
   ```

   and add `from ..client import build_query` next to the other `..` imports
   (only `nv_apply_network_rule_changes` needs it, for `scope`).
3. Add these module-level definitions **after** `MUTATING_IDEMPOTENT` and
   **before** `register()`:

   ```python
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


   def _file_filter_body(item: FileMonitorFilterInput, group_name: str) -> dict[str, Any]:
       """Render one ``RESTFileMonitorFilterConfig``; all five fields are required."""
       return {
           "filter": item.filter,
           "recursive": item.recursive,
           "behavior": item.behavior,
           "applications": list(item.applications),
           "group": group_name,
       }
   ```

4. Append the six new tools **inside the existing `register()` function**, after
   `nv_delete_group`, in the order they appear in this document.

`server.py` already lists `"neuvector_mcp.tools.policy_write"` in `TOOL_MODULES`
(the module ships in Phase 0). Phase 7 adds no entry.

## C.0.5 `src/neuvector_mcp/tools/admission.py` [Phase 8] — new file

```python
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
from ..guard import authorise_write
from ..models import AdmissionCriterionInput, WriteOutcome

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
    ...
```

`admission.py` defines only `MUTATING`: all four of its tools are
`destructiveHint=True`, including `nv_create_admission_rule` (C.0.3). It does
**not** define `MUTATING_CREATE` or `MUTATING_IDEMPOTENT`, and it does **not**
import anything from `tools/policy_write.py` — a `tools/*` module importing
another `tools/*` module is a defect (SPEC §4.1). The duplicated `MUTATING`
constant is intentional.

`server.py` gains `"neuvector_mcp.tools.admission"` in `TOOL_MODULES` in Phase 8.

## C.0.6 Input models appended to `models.py` [Phase 7]

Append in this order, after Part B's classes. `AdmissionCriterionInput` already
exists from Phase 6 — **reference it, never redefine it.** All four are *input*
models: `extra="forbid"`, not frozen, no `from_api`.

```python
class GroupCriterionInput(BaseModel):
    """One group membership criterion. Mirrors RESTCriteriaEntry."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        min_length=1,
        description="Criterion key, i.e. the workload attribute to test. Controller field "
        "names, e.g. 'domain' (Kubernetes namespace), 'image', 'service', 'label', "
        "'node', 'container'. Copy an exact key from an existing group's criteria via "
        "nv_get_group rather than guessing; an unknown key is rejected with code 6.",
    )
    op: str = Field(
        min_length=1,
        description="Comparison operator the controller defines for group criteria, e.g. '=' "
        "or 'contains'. This is NOT the query-filter operator set used by list tools. "
        "Copy an exact operator from an existing group via nv_get_group.",
    )
    value: str = Field(description="Value to compare the key against. May be empty for operators that take none.")


class NetworkRuleInput(BaseModel):
    """One network policy rule to insert or reconfigure. Mirrors RESTPolicyRule."""

    model_config = ConfigDict(extra="forbid")

    from_group: str = Field(
        min_length=1,
        description="Source group name (controller field 'from'). The group must already "
        "exist; get names from nv_list_groups.",
    )
    to_group: str = Field(
        min_length=1,
        description="Destination group name (controller field 'to'). The group must already exist.",
    )
    action: Literal["allow", "deny"] = Field(
        description="'allow' permits the connection; 'deny' blocks it in Protect mode and "
        "logs a violation in Monitor mode."
    )
    ports: str = Field(
        default="any",
        description="Free-style port list exactly as the controller stores it, e.g. "
        "'tcp/443,tcp/8080-8090', 'udp/53' or 'any'. Copy the format from an existing "
        "rule via nv_list_network_rules.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Layer-7 application names the rule is scoped to, e.g. ['HTTP']. "
        "Empty means any application.",
    )
    comment: str = Field(
        default="",
        description="Free-text comment stored on the rule. Say why the rule exists; it is the "
        "only provenance an operator gets later.",
    )
    disable: bool = Field(
        default=False,
        description="True stores the rule but does not enforce it. Insert a risky rule disabled "
        "first, confirm it matches what you expect, then enable it.",
    )
    id: int | None = Field(
        default=None,
        ge=0,
        description="Existing rule id. REQUIRED for configure_rules, must be omitted for "
        "insert_rules (the controller assigns the id).",
    )


class ProcessProfileEntryInput(BaseModel):
    """One process profile entry to add, change or remove. Mirrors RESTProcessProfileEntryConfig."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        description="Process name as the enforcer reports it, e.g. 'nginx'. Match the exact "
        "spelling from nv_get_process_profile or from the 'process' incident that prompted "
        "this change.",
    )
    path: str = Field(
        min_length=1,
        description="Absolute executable path, e.g. '/usr/sbin/nginx'. Required by the "
        "controller; use '*' to mean any path only if an existing entry already does.",
    )
    action: Literal["allow", "deny"] = Field(
        description="'allow' permits the process; 'deny' blocks it. In Protect mode 'deny' "
        "kills the process immediately."
    )


class FileMonitorFilterInput(BaseModel):
    """One file-monitor filter to add, update or remove. Mirrors RESTFileMonitorFilterConfig."""

    model_config = ConfigDict(extra="forbid")

    filter: str = Field(
        min_length=1,
        description="Path or glob to watch, e.g. '/etc/nginx/*'. Copy the exact form from "
        "nv_get_file_monitor_profile.",
    )
    recursive: bool = Field(
        default=False, description="True watches subdirectories of the path as well."
    )
    behavior: str = Field(
        default="monitor",
        description="What the enforcer does on a hit: 'monitor' records a file incident and "
        "allows the write, 'block' denies the write in Protect mode. Values are not "
        "enumerated in the schema reference; copy an existing filter's value if unsure.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Processes the filter applies to. Empty means any process.",
    )
```

`group` is **not** a field on `ProcessProfileEntryInput` or
`FileMonitorFilterInput` even though the controller marks it required on both
config types. The tool fills it from its own `group_name` argument
(`_process_entry_body`, `_file_filter_body`), so a caller cannot write an entry
into a group other than the one the guard authorised. That is a safety property,
not a convenience — do not expose `group` as an argument.

---

# Toolset `policy_write` (write) — 8 tools

### `nv_create_group`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `POST /v1/group` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Object creation — a new group has no rules and no policy mode, so nothing is enforced until something references it. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Name for the new group. Must not begin 'nv.' — that prefix is reserved for groups NeuVector learns, and the controller rejects it with code 15. |
| `criteria` | `list[GroupCriterionInput]` (min_length=1) | — | Match criteria defining membership. A workload joins the group when it satisfies ALL of them. Copy exact keys and operators from an existing group via nv_get_group; at least one criterion is required or the group would match everything. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | JSON body `config.name` |
| `criteria` | JSON body `config.criteria` |
| — | JSON body `config.cfg_type` is always the literal `"user_created"` |

Appendix A documents **no** query parameters on `POST /v1/group` (`scope` is
documented on `GET /v1/group` only). Send none.

**Docstring (use verbatim)**

```
Create a custom group defined by membership criteria.

A group is the unit every policy attaches to: network rules, process profiles and
file-monitor profiles all reference groups, not workloads. Membership is
re-evaluated continuously, so every current and future workload matching the
criteria joins. Creating a group changes no enforcement on its own - it becomes
live only when a rule or a policy mode references it. Get exact criterion keys
and operators by reading an existing group with nv_get_group; a name beginning
'nv.' is reserved for learned groups and is rejected with code 15, and a
duplicate name is rejected with code 13.

Calls POST /v1/group with {"config": {"name":..., "criteria":[{"key","value","op"}], "cfg_type": "user_created"}}.
```

**Body (normative)**

```python
app = app_context(ctx)
payload: dict[str, Any] = {
    "config": {
        "name": group_name,
        "cfg_type": "user_created",
        "criteria": [
            {"key": c.key, "value": c.value, "op": c.op} for c in criteria
        ],
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
    effect=f"group {group_name} created with {len(criteria)} criterion(s): {criteria_text}",
    payload=payload,
    controller_response=response if isinstance(response, dict) else {},
)
```

**Exact effect f-string** — the preview string above, verbatim:

```python
f"Create user-created group {group_name!r} with {len(criteria)} criterion(s): "
f"{criteria_text}. Membership is re-evaluated continuously, so every current "
f"and future workload matching ALL of those criteria joins the group. No "
f"policy rule references the new group yet, so no traffic changes until one "
f"does."
```

**Output model** — `WriteOutcome`, already in `models.py`. No new output model.

**Fixture** — none. `POST /v1/group` returns `object` (Appendix A), which in
practice is an empty body; tests stub `json={}` inline. The error tests use
`tests/fixtures/error_duplicate_name.json` (**no envelope** — a bare `RESTError`
with `code: 13`).

**Tests** `tests/test_policy_write.py`:
`test_create_group_preview_sends_nothing` (assert `status ==
"confirmation_required"`, `len(confirm_token) == 12`, both criteria appear in
`effect`, and `route.call_count == 0`),
`test_create_group_confirmed_sends_config_body` (assert `route.call_count == 1`,
`route.calls.last.request.method == "POST"` and
`json.loads(route.calls.last.request.read()) == {"config": {"name":
"custom.payments", "cfg_type": "user_created", "criteria": [{"key": "domain",
"value": "payments", "op": "="}]}}`),
`test_create_group_duplicate_name_raises_conflict` (respond `400` with
`error_duplicate_name.json`, expect `ConflictError`).

**Criterion structure — exactly as Appendix B defines it**

`RESTGroupConfigData` → `config` → `RESTGroupConfig` → `criteria` →
`array<RESTCriteriaEntry>`, and `RESTCriteriaEntry` has exactly three fields, all
required:

| Field | Type | Req |
|---|---|---|
| `key` | string | * |
| `value` | string | * |
| `op` | string | * |

Send all three on every criterion, always, even when `value` is empty. There is
no fourth field: `RESTCriteriaEntry` has no `sub_criteria`, no `type` and no
`path` (that is `RESTAdmRuleCriterion`, a different type used only by admission
rules).

**Notes**

* **Criterion keys and operators are NOT enumerated in Appendix B.**
  `RESTCriteriaEntry.key` and `RESTCriteriaEntry.op` are declared as bare
  `string` with no `enum` and no description, and Appendix A documents no
  criterion vocabulary either. Consequence, and this is the instruction:
  **type both as `str` (never a `Literal`) and let the controller validate.**
  The `Field(description=...)` texts above name the keys and operators that
  appear in real NeuVector groups as *examples to copy*, and both descriptions
  tell the caller to read an exact value out of an existing group with
  `nv_get_group` rather than guess. An unknown key or operator comes back as
  `code=6` ("Request in wrong format"), which `errors.classify` maps to
  `ValidationError_` — an actionable message, which is the correct outcome for an
  un-enumerable field. Do not add a client-side allowlist; a stale allowlist
  would reject criteria the controller accepts.
* **Do not confuse group-criterion operators with query-filter operators.** SPEC
  §3.2 enumerates `eq neq in notin gt gte lt lte prefix` — those are the `f_<field>`
  operators for **list endpoints**, enforced client-side by
  `client.FILTER_OPS`. They are a different vocabulary from
  `RESTCriteriaEntry.op` and must not be reused or validated against here.
* `cfg_type` is required and is always `"user_created"`. The other three enum
  values are not the client's to send: `learned` belongs to the controller,
  `ground` to Kubernetes CRDs, `federal` to a federation primary (out of scope,
  SPEC §1.2).
* `namespace` for the guard comes from a `domain` criterion, because `domain` is
  the controller's field name for a Kubernetes namespace (`RESTGroup.domain`). A
  group with no `domain` criterion is cluster-wide, so `namespace=None` and
  `NV_ALLOWED_NAMESPACES` cannot constrain it — which is correct, since such a
  group can match workloads anywhere.
* Common controller codes: **13** duplicate name (a group with that name already
  exists — read it with `nv_get_group` instead of recreating);
  **15** invalid name (the `nv.` prefix, or characters the controller rejects);
  **6** invalid request (unknown criterion key or operator, or empty `criteria`);
  **25** object access denied (the API key's role cannot create groups in that
  namespace); **8** / **19** cluster write or lock failure (transient — the
  client retries these per SPEC §7.2).

---

### `nv_update_group_criteria`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `PATCH /v1/group/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting — changing criteria changes membership, and every rule attached to the group immediately applies to a different set of workloads. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group whose criteria to replace. Learned groups (names beginning 'nv.') have controller-owned criteria and are rejected with code 4. |
| `criteria` | `list[GroupCriterionInput]` (min_length=1) | — | The COMPLETE new criteria set. This REPLACES the existing set - it is not merged, so any criterion you omit is removed. Read the current set with nv_get_group and echo back everything you intend to keep. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` |
| `criteria` | JSON body `config.criteria` |
| — | JSON body `config.name` echoes `group_name`; `config.cfg_type` is always `"user_created"` |

Appendix A documents no query parameters on `PATCH /v1/group/{name}`.

**Docstring (use verbatim)**

```
Replace the membership criteria of one custom group.

This is a whole-set replacement, not a merge: criteria you do not send are
removed. Call nv_get_group first, then send the criteria you want to keep plus
your change. Membership changes take effect at once, so every network rule,
process profile and file-monitor profile attached to this group starts applying
to a different set of workloads - a workload that leaves the group loses its
allow rules, and if its new group is in Protect mode its traffic is dropped.
Learned groups ('nv.' prefix) have controller-owned criteria and are rejected
with code 4.

Calls PATCH /v1/group/{name} with {"config": {"name":..., "criteria":[{"key","value","op"}], "cfg_type": "user_created"}}.
```

**Body (normative)**

```python
app = app_context(ctx)
payload: dict[str, Any] = {
    "config": {
        "name": group_name,
        "cfg_type": "user_created",
        "criteria": [
            {"key": c.key, "value": c.value, "op": c.op} for c in criteria
        ],
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
    namespace=_namespace_from_group_name(group_name)
    or _namespace_from_criteria(criteria),
)
if plan is not None:
    return plan

response = await app.client.request("PATCH", f"/v1/group/{group_name}", json=payload)
return WriteOutcome(
    status="applied",
    operation="nv_update_group_criteria",
    target=group_name,
    effect=f"criteria of {group_name} replaced with {len(criteria)} criterion(s): {criteria_text}",
    payload=payload,
    controller_response=response if isinstance(response, dict) else {},
)
```

**Exact effect f-string** — the preview string above, verbatim.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path (`PATCH` returns an empty body, SPEC §3.3;
stub `json={}` inline). The error test uses
`tests/fixtures/error_op_not_allowed.json` (**no envelope** — bare `RESTError`
with `code: 4`).

**Tests** `tests/test_policy_write.py`:
`test_update_group_criteria_preview_sends_nothing`,
`test_update_group_criteria_confirmed_replaces_criteria` (assert the exact body
`{"config": {"name": "custom.payments", "cfg_type": "user_created", "criteria":
[{"key": "domain", "value": "payments", "op": "="}, {"key": "label", "value":
"tier=web", "op": "="}]}}` and `route.calls.last.request.method == "PATCH"`),
`test_update_group_criteria_learned_group_returns_permission_error` (respond
`403` with `error_op_not_allowed.json`, expect `PermissionError_` — this is the
module's `code=4` classification case),
`test_update_group_criteria_effect_says_replacement` (assert `"REPLACE"` and
`"REMOVED"` are in the preview `effect`, so a caller cannot read the plan and
still believe it is a merge).

**Notes**

* **No pre-read, therefore no true diff.** SPEC §7.4 and invariant C6 forbid a
  controller call before the guard returns, so the preview cannot show
  *removed* criteria — it can only state, loudly, that omission means removal.
  That is why the `effect` string spells out "whole-set replacement, not a merge"
  and why the argument description repeats it. Do **not** add a `nv_get_group`
  call to enrich the preview; it would break C6 and
  `test_update_group_criteria_preview_sends_nothing`.
* `PATCH /v1/group/{name}` is shared with the already-implemented
  `nv_set_group_policy_mode`. Two tools legitimately hit one endpoint with
  different payload keys. Keep them separate: a caller changing criteria must not
  be able to change the enforcement mode in the same unreviewed call, and the
  confirm token binds the payload, so merging them would let one preview cover
  both changes.
* `cfg_type` is required on `RESTGroupConfig` and is always `"user_created"` —
  same reasoning as `nv_create_group`.
* Guard namespace: prefer the namespace encoded in the group's own name
  (`nv.<service>.<namespace>`), and fall back to a `domain` criterion. For a
  learned group the call will fail at the controller with `code=4` anyway, but
  the namespace allowlist should still refuse it first, before any request goes
  out.
* Common controller codes: **7** object not found (no such group — check
  `nv_list_groups`); **4** operation not allowed (learned or reserved group, or a
  `ground` group owned by a Kubernetes CRD); **46** read-only rules (a `federal`
  group pushed by a federation primary cannot be edited on this cluster);
  **6** invalid request (unknown criterion key or operator); **16** object in use;
  **25** object access denied.

---

### `nv_delete_group`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `DELETE /v1/group/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Data-destroying — the group and every rule referencing it are removed. |

> **ALREADY IMPLEMENTED.** This tool exists in
> `reference/src/neuvector_mcp/tools/policy_write.py` and is copied verbatim in
> Phase 0. Rule N3 applies: **do not rewrite, reformat, rename, reorder or
> re-derive any part of it.** The contract below is a transcription of the
> shipped code so the rest of this document can reference it. If your file
> differs from this in any byte, your file is wrong.

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group to delete. |
| `confirm` | `str \| None` | `None` | Confirmation token from the preview call. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` |

**Docstring (already in the file — do not reword)**

```
Delete a custom group.

Rules that reference the group are removed with it. Learned groups
(names beginning 'nv.') cannot be deleted; the controller rejects those
with code 4 (Operation not allowed).

Calls DELETE /v1/group/{name}.
```

**Body (already in the file — reproduced for reference only)**

```python
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
```

**Exact effect f-string** (as shipped):

```python
f"Delete group {group_name!r} and every rule that references it."
```

**Output model** — `WriteOutcome`.

**Fixture** — none; `DELETE` returns an empty body. Error tests use
`tests/fixtures/error_op_not_allowed.json` (no envelope, `code: 4`).

**Tests** — `tests/test_guard.py` (verbatim from `reference/`, do not edit)
already covers this tool's registration and annotations in
`test_read_only_hides_mutating_toolsets` and `test_annotations_declare_mutation`,
but **not** its preview/apply pair. Add both in `tests/test_policy_write.py`:
`test_delete_group_preview_sends_nothing`,
`test_delete_group_confirmed_calls_delete` (assert `route.call_count == 1`,
`route.calls.last.request.method == "DELETE"`, and that the request body is empty
— there is no JSON body on this call).

**Notes**

* `payload=None`, so the token is
  `sha256("nv_delete_group|<group_name>|{}")[:12]` — `guard.confirm_token`
  canonicalises `None` to `{}`. A test that constructs the expected token must
  pass `None` or `{}`, not omit the argument.
* `namespace` is **not** passed to the guard here. That is the shipped behaviour
  and it means `NV_ALLOWED_NAMESPACES` does not constrain group deletion. Do not
  "improve" this in Phase 7 — N3 pins the file, and changing it would change the
  token for every existing preview.
* Common controller codes: **4** operation not allowed (learned or reserved
  group — the documented case, called out in the docstring); **7** object not
  found; **16** object in use; **46** read-only rules (federated group);
  **25** object access denied.

---

### `nv_set_group_policy_mode`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `PATCH /v1/group/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_IDEMPOTENT`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Reversible config change — the mode can be set back, so `destructiveHint=False` even though `Protect` starts blocking. |

> **ALREADY IMPLEMENTED.** Exists in
> `reference/src/neuvector_mcp/tools/policy_write.py`, copied verbatim in Phase
> 0. Rule N3: **match the existing code exactly.** Transcription follows.

> **SUPERSEDED TWICE — the transcription below is history, not the current tool.**
> 1. The endpoint is `PATCH /v1/service/config`, not `PATCH /v1/group/{name}`.
>    `RESTGroupConfig` genuinely has no `policy_mode`; the controller answered 200
>    and dropped it. Policy mode is a property of the *service*, so the tool now
>    strips the `nv.` prefix and sends `{"config": {"services": [<service>],
>    "policy_mode": ...}}`. See the note on Appendix B below, which called this
>    out as blocked and was resolved by measurement, not by guessing a key.
> 2. The controller applies the change *after* it acknowledges it — 0.33–0.59s
>    measured — so a `200` proves nothing and neither does a read taken straight
>    after one. The tool now reads the current mode with `GET /v1/service`, sends
>    one `PATCH`, and re-reads until the controller agrees before reporting
>    `applied`. The shared helpers live in `neuvector_mcp/modes.py` and are
>    documented under `nv_set_service_mode` in PART-D.
>
>    A revision between these two briefly stepped every change through `Monitor`,
>    believing a two-rung move was silently discarded. It is not; that was this
>    same asynchrony misread. See the retraction under `nv_set_service_mode`.
>
> `test_guard.py` has grown accordingly and the "add nothing, edit nothing" note
> further down no longer holds.

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group name, e.g. 'nv.api.prod'. |
| `mode` | `Literal["Discover", "Monitor", "Protect"]` | — | Discover learns behaviour, Monitor alerts, Protect blocks. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` |
| `mode` | JSON body `config.policy_mode` |

**Docstring (already in the file — do not reword)**

```
Change the policy mode of one group.

Moving a group to Protect starts BLOCKING traffic and process activity
that the learned policy does not allow. Preview first: call without
'confirm', read the returned plan, then call again with the token.

Calls PATCH /v1/group/{name} with {"config": {"name":..., "policy_mode":...}}.
```

**Body (already in the file — reproduced for reference only)**

```python
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
```

**Exact effect f-string** (as shipped — note the conditional suffix, which
`test_guard.py` asserts on):

```python
f"Set policy mode of group {group_name!r} to {mode}."
+ (
    " Traffic and process activity outside the learned policy will be "
    "blocked immediately."
    if mode == "Protect"
    else ""
)
```

**Output model** — `WriteOutcome`.

**Fixture** — none; stub `PATCH /v1/group/nv.api.prod` with `json={}`.

**Tests** — fully covered by `tests/test_guard.py` (verbatim from `reference/`):
`test_first_call_returns_plan_and_sends_nothing` (preview sends nothing,
`route.call_count == 0`), `test_confirmed_call_applies` (exact JSON body
`{"config": {"name": "nv.api.prod", "policy_mode": "Protect"}}`),
`test_token_is_bound_to_arguments` (**this is the `policy_write` module's
token-binding test** required by SPEC §10.2 — a token minted for
`mode="Monitor"` is rejected for `mode="Protect"`),
`test_read_only_hides_mutating_toolsets`,
`test_namespace_allowlist_blocks_outside_namespace`,
`test_annotations_declare_mutation`. **Add nothing for this tool and edit
nothing in `test_guard.py`.**

**Notes**

* **BLOCKED (schema): `RESTGroupConfig` in Appendix B has no `policy_mode`
  field.** Its three documented fields are `name`, `criteria` and `cfg_type`.
  The shipped tool nevertheless sends `config.policy_mode`, and the shipped test
  asserts that exact body. Resolution, and this is the instruction: **change
  nothing.** Rule N3 pins the reference; `policy_mode` *is* documented on
  `RESTGroup` and `RESTGroupDetail` (the response side) and on
  `RESTServiceConfig`, so the gap is an Appendix B omission on the request type,
  not a fabricated field. Record it here and move on. If a live controller
  returns `code=6` for this body, that is the signal to revisit the appendix —
  not a licence to guess a different key.
* `destructiveHint=False` while `Protect` blocks traffic looks wrong at a glance
  and is correct: SPEC §6.2 row 1 covers reversible config changes, and the mode
  is reversible with one call in the other direction. The danger is carried by
  the `effect` string, not by the annotation.
* `idempotentHint=True` is genuine here: the controller converges on the
  requested mode, so a repeat is a no-op. This is the only tool in Part C that
  can claim it.
* Common controller codes: **7** object not found; **4** operation not allowed
  (`cap_change_mode` false on the group — some reserved groups cannot change
  mode); **6** invalid request; **25** object access denied.

---

### `nv_apply_network_rule_changes`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `PATCH /v1/policy/rule` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting **and** data-destroying. Both rows apply, so `destructiveHint=True`. |

> **This is the highest-risk tool in the server.** It rewrites the ordered
> network policy rule list in one atomic batch. A wrong batch does not fail
> loudly — it silently stops matching production traffic, and every Protect-mode
> group then drops the connections no surviving rule allows. Treat every
> instruction in this section as load-bearing.

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `insert_rules` | `list[NetworkRuleInput]` | `[]` | New rules to insert, in the order they should appear. Omit 'id' on every entry - the controller assigns ids. Insert risky rules with disable=true first, verify with nv_list_network_rules, then enable them. |
| `insert_after_rule_id` | `int \| None` | `None` | Existing rule id that the inserted rules are positioned relative to (controller field 'insert.after'). Omit to let the controller choose the position. The controller's interpretation of this value is not documented - verify the resulting order with nv_list_network_rules immediately after applying. |
| `move_rule_id` | `int \| None` (ge=0) | `None` | Id of one existing rule to move. The controller accepts at most one move per batch. Moving a rule changes which connections the rules above it no longer see. |
| `move_after_rule_id` | `int \| None` | `None` | Existing rule id that move_rule_id is positioned relative to (controller field 'move.after'). Requires move_rule_id. Omit to let the controller choose. |
| `configure_rules` | `list[NetworkRuleInput]` | `[]` | Existing rules to overwrite in place. Every entry MUST carry the 'id' of the rule it replaces; the whole rule is overwritten, so send every field you want to keep. Read current values with nv_get_network_rule first. |
| `delete_rule_ids` | `list[int]` | `[]` | Ids of rules to delete. Learned rules cannot be deleted and are rejected with code 4. |
| `scope` | `Literal["local", "fed"]` | `"local"` | 'local' edits this cluster's rules. 'fed' edits federated rules, which only a federation primary may change - elsewhere the controller rejects them with code 46. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the whole batch as a diff. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `scope` | `scope=<value>` (via `build_query(extra={"scope": scope})`) **and** folded into the guard's `target` — see Notes |
| `insert_rules`, `insert_after_rule_id` | JSON body `insert` = `{"rules": [...], "after": <id>}` |
| `move_rule_id`, `move_after_rule_id` | JSON body `move` = `{"id": <id>, "after": <id>}` |
| `configure_rules` | JSON body `rules` = `[...]` |
| `delete_rule_ids` | JSON body `delete` = `[<id>, ...]` |

**Exact body shape from Appendix B**

`RESTPolicyRuleActionData` is **not** enveloped — its four fields are top level:

| Field | Type | Req | Cardinality that follows from the type |
|---|---|---|---|
| `insert` | `RESTPolicyRuleInsert` | | **one object**, so **one insert position per call** (many rules, one `after`) |
| `move` | `RESTPolicyRuleMove` | | **one object**, so **at most one move per call** |
| `rules` | `array<RESTPolicyRule>` | | many configure entries |
| `delete` | `array<integer(uint32)>` | | many ids |

`RESTPolicyRuleInsert` = `{"after": integer (optional), "rules": array<RESTPolicyRule> (required)}`.
`RESTPolicyRuleMove` = `{"after": integer (optional), "id": integer(uint32) (required)}`.
Each `RESTPolicyRule` sent uses only these documented fields: `id` (configure
only), `from`, `to`, `ports`, `action`, `applications`, `comment`, `disable`,
`cfg_type`. Never send `learned`, `priority`, `match_counter`,
`last_match_timestamp`, `created_timestamp` or `last_modified_timestamp` — they
are controller-owned even though they appear on the type.

Omit any of the four top-level keys that has nothing in it. Do not send
`"insert": null`, `"delete": []` or `"rules": []` — an empty array is a
different statement from an absent key, and given BLOCKED item 2 below, an empty
`rules` array is exactly the shape that might be read as "replace the rule list
with nothing".

**Docstring (use verbatim)**

```
Apply one atomic batch of network policy rule changes: insert, move, configure and delete.

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
```

**Body (normative)**

```python
from ..errors import ValidationError_

app = app_context(ctx)

inserts = list(insert_rules)
configures = list(configure_rules)
deletes = list(delete_rule_ids)
change_count = (
    len(inserts) + len(configures) + len(deletes) + (1 if move_rule_id is not None else 0)
)

# --- step 1 validation: local only, no network call (invariant C6) -----------
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

# --- the diff-style preview -------------------------------------------------
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
```

**Exact effect f-string** — the preview string above, verbatim. The diff is built
first and interpolated as `{diff}`; each change is one line, prefixed `+` for
insert, `~` for move and configure, `-` for delete, `=` for the position note. A
human reading the preview sees every rule that will exist, every rule that will
be overwritten and every id that will vanish, with no controller round-trip.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path; `PATCH /v1/policy/rule` returns an empty
body, so tests stub `json={}` inline. Error tests use
`tests/fixtures/error_op_not_allowed.json` (`code: 4`, learned rule) and
`tests/fixtures/error_read_only_rules.json` (**no envelope**, bare `RESTError`
with `code: 46`, for `scope="fed"`).

**Tests** `tests/test_policy_write.py`:

* `test_apply_network_rule_changes_preview_lists_every_change` — one insert, one
  move, one configure and two deletes; assert `route.call_count == 0`, and that
  the `effect` contains `"+ INSERT"`, `"~ MOVE rule id"`, `"~ CONFIGURE rule id"`
  and a `"- DELETE rule id"` line for **each** deleted id.
* `test_apply_network_rule_changes_confirmed_sends_batch_body` — assert
  `route.call_count == 1`, `route.calls.last.request.method == "PATCH"`, and the
  exact body:

  ```python
  assert json.loads(route.calls.last.request.read()) == {
      "insert": {
          "after": 10,
          "rules": [
              {
                  "from": "custom.web",
                  "to": "custom.db",
                  "ports": "tcp/5432",
                  "action": "allow",
                  "applications": ["PostgreSQL"],
                  "comment": "web to db",
                  "disable": False,
                  "cfg_type": "user_created",
              }
          ],
      },
      "rules": [
          {
              "id": 22,
              "from": "custom.web",
              "to": "custom.cache",
              "ports": "tcp/6379",
              "action": "deny",
              "applications": [],
              "comment": "",
              "disable": False,
              "cfg_type": "user_created",
          }
      ],
      "delete": [31, 32],
  }
  ```

  Note what the assertion proves: `move` is **absent** (not `null`) because no
  move was requested, and inserted rules carry **no** `id`.
* `test_apply_network_rule_changes_sends_scope_param` — assert
  `route.calls.last.request.url.params["scope"] == "fed"`.
* `test_apply_network_rule_changes_token_is_bound_to_scope` — mint a token with
  `confirm_token("nv_apply_network_rule_changes", "network policy rules
  (scope=local)", payload)` and assert it is **rejected** when the same batch is
  submitted with `scope="fed"`; assert `route.call_count == 0`. This is the test
  that proves the `scope`-into-`target` fold works, and it is the second
  token-binding test in the `policy_write` module.
* `test_apply_network_rule_changes_rejects_oversized_batch` — 17 delete ids;
  expect `ValidationError_`, assert `"hard cap"` in the message and
  `route.call_count == 0`.
* `test_apply_network_rule_changes_requires_id_on_configure` — one
  `configure_rules` entry without `id`; expect `ValidationError_` and
  `route.call_count == 0`.
* `test_apply_network_rule_changes_rejects_id_on_insert` — one `insert_rules`
  entry with `id=5`; expect `ValidationError_` and `route.call_count == 0`.
* `test_apply_network_rule_changes_rejects_empty_batch` — no arguments beyond
  `scope`; expect `ValidationError_` and `route.call_count == 0`.
* `test_apply_network_rule_changes_learned_rule_returns_permission_error` —
  respond `403` with `error_op_not_allowed.json`; expect `PermissionError_`.

**Notes**

* **Rule ordering semantics, stated once and relied on everywhere.** The
  controller stores network rules as an **ordered list**. Evaluation is
  **top-down, first match wins**: the first rule whose `from`, `to`, `ports` and
  `applications` all match a connection decides it, and no later rule is
  consulted. Three consequences the implementer must encode in the docstring and
  the effect string, because they are the actual failure modes:
  1. Inserting an `allow` rule **above** a `deny` rule silently disables that
     deny for the overlapping traffic. Inserting a `deny` **above** an `allow`
     does the reverse and is how production traffic dies.
  2. Moving a rule changes the verdict for every connection that used to be
     decided by a rule between its old and new position.
  3. Deleting an `allow` rule makes its traffic fall through; if nothing below
     matches and the source group is in `Protect` mode, the connection is
     dropped. In `Discover` or `Monitor` mode it is only logged — which is why
     the caller should check group modes with `nv_list_groups` before batching.
  Part B's `nv_list_network_rules` returns an absolute `order` field per rule for
  exactly this purpose; use it to name positions in the preview a human can
  match against the current list.
* **The `scope` query parameter.** Appendix A documents `scope` on
  `PATCH /v1/policy/rule` (and on `GET`/`DELETE /v1/policy/rule`). SPEC §3.2:
  `scope=local|fed`. `local` addresses this cluster's own rules; `fed` addresses
  rules pushed from a federation primary, which are read-only on a managed
  cluster and come back as `code=46`. Send it through
  `build_query(extra={"scope": scope})` — never hand-format the query string.
  **`scope` is not part of the payload, so the confirm token would not bind it**
  (invariant C8): a caller could preview a batch against `local` and apply the
  identical batch to `fed` with the same token. That is why `target` is
  `f"network policy rules (scope={scope})"` rather than a bare constant, and why
  `test_apply_network_rule_changes_token_is_bound_to_scope` exists. Federation
  itself is out of scope for this server (SPEC §1.2) — `scope="fed"` is exposed
  because the endpoint accepts it and refusing it client-side would be inventing
  a restriction, not because any tool here orchestrates a federation.
* **BLOCKED (semantics): the meaning of `after`.** Appendix B types
  `RESTPolicyRuleInsert.after` and `RESTPolicyRuleMove.after` as **signed**
  `integer`, while rule ids are `integer(uint32)` — so the field can carry
  values no rule id can, which strongly suggests a sign convention. Neither
  Appendix A nor Appendix B documents what the sign means, nor what omitting
  `after` does. Instruction: **pass the caller's value through verbatim and never
  synthesise, negate or default it.** Omit the key entirely when the argument is
  `None`. The argument descriptions and the preview line both state that the
  interpretation is unverified and that the caller must re-read the list to see
  where the rules landed. Do not encode a guessed convention in code or in a
  docstring; confirm it against a live controller and, if confirmed, record it in
  Appendix B first.
* **BLOCKED (semantics): what `rules` means.** Appendix B says
  `RESTPolicyRuleActionData.rules` is `array<RESTPolicyRule>` and says nothing
  about whether the array configures the listed ids or replaces the entire
  ordered list. Those two readings differ by "every rule you did not list is
  deleted". Three mitigations, all mandatory: (1) every `configure_rules` entry
  must carry an `id`, enforced client-side above; (2) the key is omitted
  entirely when `configure_rules` is empty, so a batch that only deletes can
  never be read as "replace the list with nothing"; (3) the effect string tells
  the caller that configure OVERWRITES the whole rule at that id and that they
  must re-read the list afterwards. Verify against a non-production cluster
  before using `configure_rules` at scale.
* **Batch cap.** `MAX_RULE_CHANGES = 16`, counted as
  `len(insert_rules) + len(configure_rules) + len(delete_rule_ids) + (1 if move_rule_id else 0)`,
  enforced in step 1 and therefore before the guard and before any request. The
  cap is not a controller limit — it is a review limit: a preview a human will
  not read in full is not a preview. At most **one** move per batch is not a
  choice either; `RESTPolicyRuleMove` is a single object, so the schema permits
  no more.
* **Atomicity and partial failure.** The controller applies the batch under a
  cluster lock. A `code=8` (write to cluster failed) or `code=19` (acquire
  cluster lock failed) leaves the outcome **unknown** to this server, and both
  are in `RETRYABLE_CODES`, so `client.py` will have already retried up to three
  times (SPEC §7.2). If the error still surfaces, the caller must re-read with
  `nv_list_network_rules` before retrying — say so in the error path by leaving
  the classified error to propagate; do not swallow it and do not report
  `status="applied"`.
* `namespace=None` for the guard: a rule spans two groups that may live in
  different namespaces, so there is no single namespace to check and
  `NV_ALLOWED_NAMESPACES` cannot constrain this tool. The controls that do apply
  are `NV_TOOLSETS`, `NV_READ_ONLY`, the confirm handshake and the API key's
  role. State this in the deployment README rather than faking a namespace.
* Never infer a rule's provenance from its id — Part B's
  `nv_list_network_rules` Notes make this a standing rule, since the id ranges
  that separate learned, user-created, ground and federated rules are not
  published. Read `cfg_type` and `learned` instead.
* Common controller codes: **6** invalid request (a group name that does not
  exist, a malformed `ports` string, an unknown `action`); **7** object not found
  (a referenced rule id is gone — re-read the list); **4** operation not allowed
  (editing or deleting a `learned` rule); **46** read-only rules (`federal` or
  `ground` rules, or `scope="fed"` on a managed cluster); **16** object in use;
  **25** object access denied; **8** / **19** cluster write or lock failure, see
  atomicity above.

---

### `nv_delete_network_rule`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `DELETE /v1/policy/rule/{id}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Data-destroying **and** traffic-affecting. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `rule_id` | `int` (ge=0) | — | Id of the network policy rule to delete. Get ids from nv_list_network_rules, and read the rule with nv_get_network_rule first to see what it allows or denies. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `rule_id` | path segment `{id}` |

Appendix A documents `scope` on `DELETE /v1/policy/rule` (the delete-all form,
which this server does not expose) but **not** on
`DELETE /v1/policy/rule/{id}`. Send no query parameters.

**Docstring (use verbatim)**

```
Delete one network policy rule by id.

Rules are an ordered list evaluated top-down, first match wins, so deleting one
makes its traffic fall through to the rules below it. Deleting an allow rule can
DROP production traffic the moment the source group is in Protect mode and
nothing below matches; deleting a deny rule can permit traffic that was being
blocked. Read the rule with nv_get_network_rule first to see which case you are
in. Learned rules cannot be deleted - the controller rejects those with code 4.
To remove several rules atomically, or to remove and reorder in one step, use
nv_apply_network_rule_changes instead.

Calls DELETE /v1/policy/rule/{id}.
```

**Body (normative)**

```python
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
```

**Exact effect f-string** — the preview string above, verbatim.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path. Error test uses
`tests/fixtures/error_object_not_found.json` (**no envelope**, bare `RESTError`
with `code: 7`).

**Tests** `tests/test_policy_write.py`:
`test_delete_network_rule_preview_sends_nothing` (assert `route.call_count == 0`
and that `str(rule_id)` and `"ALLOW"` both appear in `effect`),
`test_delete_network_rule_confirmed_calls_delete` (assert `route.call_count ==
1`, `route.calls.last.request.method == "DELETE"`,
`route.calls.last.request.url.path == "/v1/policy/rule/42"`, and that the request
carries no body),
`test_delete_network_rule_missing_raises_not_found` (respond `404` with
`error_object_not_found.json`, expect `NotFoundError` — the module's `code=7`
classification case).

**Notes**

* `payload=None` in the guard call, matching `nv_delete_group`: there is no
  request body, so the token is `sha256("nv_delete_network_rule|<id>|{}")[:12]`.
  The `WriteOutcome` on success sets `payload={}` explicitly — the default is
  already `{}`, but stating it keeps the applied record symmetric with the plan
  record.
* `target=str(rule_id)`, not `rule_id`. `WriteOutcome.target` and
  `confirm_token`'s `target` are both `str`; passing an `int` would raise a
  Pydantic validation error inside the guard.
* `idempotentHint=False`: a second delete of the same id returns `code=7`, so a
  repeat is not free. Consistency with `nv_delete_group` also matters here — a
  client should see the same annotation shape on every delete in this server.
* Prefer `nv_apply_network_rule_changes` for multi-rule removals: N separate
  deletes are N separate windows in which the rule list is in a state nobody
  designed. Say so in the docstring, as above.
* Common controller codes: **7** object not found (already deleted, or the id
  never existed); **4** operation not allowed (`learned` rule); **46** read-only
  rules (`federal` or `ground` rule); **16** object in use; **25** object access
  denied.

---

### `nv_update_process_profile`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `PATCH /v1/process_profile/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting — in `Protect` mode the enforcer acts on this profile against processes that are running right now. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group whose process profile to change, e.g. 'nv.api.prod'. Read the current profile with nv_get_process_profile and the group's enforcement mode with nv_get_group first. |
| `add_entries` | `list[ProcessProfileEntryInput]` | `[]` | Entries to add or change. An entry with the same name and path as an existing one replaces it, so this is how you flip an entry from allow to deny. |
| `delete_entries` | `list[ProcessProfileEntryInput]` | `[]` | Entries to remove. Removing an 'allow' entry means the process is no longer permitted - in Protect mode the enforcer kills it. |
| `alert_disabled` | `bool \| None` | `None` | True stops this profile raising alerts on a violation. Omit to leave the current setting alone. Disabling alerts hides process incidents you would otherwise see in nv_query_security_events. |
| `hash_enabled` | `bool \| None` | `None` | True makes the enforcer verify executable hashes as well as paths. Omit to leave the current setting alone. Enabling it can start blocking processes whose binaries were legitimately updated. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` **and** JSON body `process_profile_config.group` |
| `add_entries` | JSON body `process_profile_config.process_change_list` |
| `delete_entries` | JSON body `process_profile_config.process_delete_list` |
| `alert_disabled` | JSON body `process_profile_config.alert_disabled`, omitted when `None` |
| `hash_enabled` | JSON body `process_profile_config.hash_enabled`, omitted when `None` |

**Docstring (use verbatim)**

```
Add, change or remove allowed-process entries in one group's process profile.

BLAST RADIUS: the process profile is an allowlist the enforcer checks every
process against, and in Protect mode it acts immediately. A 'deny' entry, or
removing the 'allow' entry that covers a process running right now, KILLS that
process in EVERY container in the group - including sidecars, entrypoints and
health checks. In Discover or Monitor mode the same change only raises a
'process' incident. Read the current entries with nv_get_process_profile and the
group's mode with nv_get_group before you confirm. The request body's envelope
key is 'process_profile_config', not 'config'.

Calls PATCH /v1/process_profile/{name} with {"process_profile_config": {"group":..., "process_change_list":[...], "process_delete_list":[...]}}.
```

**Body (normative)**

```python
from ..errors import ValidationError_

app = app_context(ctx)

if not add_entries and not delete_entries and alert_disabled is None and hash_enabled is None:
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
    "; ".join(f"{e.action.upper()} {e.name} at {e.path}" for e in delete_entries)
    or "none"
)
flags_text = ", ".join(
    part
    for part in (
        None if alert_disabled is None else f"alert_disabled={alert_disabled}",
        None if hash_enabled is None else f"hash_enabled={hash_enabled}",
    )
    if part is not None
) or "unchanged"

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
```

**Exact effect f-string** — the preview string above, verbatim.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path. Error test uses
`tests/fixtures/error_object_not_found.json` (`code: 7`).

**Tests** `tests/test_policy_write.py`:
`test_update_process_profile_preview_sends_nothing` (assert `route.call_count ==
0`, `"KILLS"` in `effect`, and that each entry's name and path appear),
`test_update_process_profile_confirmed_sends_process_profile_config_body` —
assert `route.call_count == 1`, `route.calls.last.request.method == "PATCH"` and
the exact body:

```python
assert json.loads(route.calls.last.request.read()) == {
    "process_profile_config": {
        "group": "nv.api.prod",
        "process_change_list": [
            {
                "name": "curl",
                "path": "/usr/bin/curl",
                "action": "deny",
                "group": "nv.api.prod",
            }
        ],
    }
}
```

`test_update_process_profile_fills_group_on_every_entry` (assert each entry in
both lists carries `"group": group_name`, even though the caller never passed
it), `test_update_process_profile_omits_unset_flags` (call with
`alert_disabled=None, hash_enabled=None`; assert neither key is present in the
body), `test_update_process_profile_rejects_empty_change_set` (expect
`ValidationError_`, `route.call_count == 0`).

**Notes**

* **The envelope key is `process_profile_config`, not `config`.** Appendix B:
  `RESTProcessProfileConfigData` has exactly one field, `process_profile_config`,
  of type `RESTProcessProfileConfig`. This is the single most likely defect in
  Phase 7 — every neighbouring type in this part uses `config`
  (`RESTGroupConfigData`, `RESTFileMonitorConfigData`,
  `RESTAdmissionRuleConfigData`), and this one does not. The docstring says so on
  purpose, and `test_update_process_profile_confirmed_sends_process_profile_config_body`
  asserts it.
* **All four fields of `RESTProcessProfileEntryConfig` are required**: `name`,
  `path`, `action`, `group`. `_process_entry_body` sends all four on every entry
  in both lists, filling `group` from the tool's own `group_name`. A caller
  cannot address another group's profile.
* `RESTProcessProfileConfig` also has `alert_disabled` and `hash_enabled`, both
  optional. They are omitted when the argument is `None` so a caller updating
  entries cannot silently reset a flag they never mentioned — a `PATCH` that
  sends a field sets it, and `False` is not the same statement as absent.
* `action` is narrowed to `Literal["allow", "deny"]` on
  `ProcessProfileEntryInput`. Appendix B types
  `RESTProcessProfileEntryConfig.action` as bare `string` with no enum; the
  narrowing is deliberate (C.0.2) and Part B's read projection documents the same
  two values. If a live controller accepts a third value you need, widen to
  `str` and record it.
* Entries carry a `uuid` on the **read** side (`RESTProcessProfileEntry.uuid`,
  projected by Part B's `nv_get_process_profile`), but
  `RESTProcessProfileEntryConfig` has **no** `uuid` field. Do not send one. The
  controller matches config entries by `name` + `path` + `group`, which is why
  those three are required and why an add with an existing name and path is a
  replacement.
* Common controller codes: **7** object not found (no profile for that group —
  the group may not exist, or may never have been in Discover mode); **4**
  operation not allowed (`system_defined` entries, or a group whose profile the
  controller owns); **46** read-only rules (`federal` or `ground` profile);
  **6** invalid request (missing `path`, unknown `action`); **25** object access
  denied; **21** enforcer error (the controller accepted the change but an
  enforcer could not apply it — the profile is updated, the enforcement is not;
  re-read with `nv_get_process_profile`).

---

### `nv_update_file_monitor_profile`

| | |
|---|---|
| **Toolset** | `policy_write` (write) |
| **Endpoints** | `PATCH /v1/file_monitor/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting — `behavior="block"` in a `Protect`-mode group makes the enforcer deny file writes, which breaks running processes. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group whose file-monitor profile to change, e.g. 'nv.api.prod'. Read the current filters with nv_get_file_monitor_profile first. |
| `add_filters` | `list[FileMonitorFilterInput]` | `[]` | Filters to add. Each names a path or glob, whether it recurses, and the behaviour on a hit. |
| `update_filters` | `list[FileMonitorFilterInput]` | `[]` | Existing filters to change in place, matched by their 'filter' path. Send every field you want to keep - the filter is overwritten. |
| `delete_filters` | `list[FileMonitorFilterInput]` | `[]` | Filters to remove, matched by their 'filter' path. Removing a filter silently ends detection for that path. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` **and** the `group` field of every filter sent |
| `add_filters` | JSON body `config.add_filters` |
| `update_filters` | JSON body `config.update_filters` |
| `delete_filters` | JSON body `config.delete_filters` |

**Docstring (use verbatim)**

```
Add, change or remove watched paths in one group's file-monitor profile.

Each filter names a path or glob the enforcer watches and what to do on a hit:
'monitor' records a file incident and allows the write, 'block' denies it. BLAST
RADIUS: a 'block' filter in a Protect-mode group breaks every process in the
group that writes to a matching path - package managers, log rotation, config
reloads and anything that writes a pid or lock file. Deleting a filter has the
opposite failure mode: detection for that path stops silently and nothing tells
you. Read the current filters with nv_get_file_monitor_profile and the group's
mode with nv_get_group before you confirm.

Calls PATCH /v1/file_monitor/{name} with {"config": {"add_filters":[...], "update_filters":[...], "delete_filters":[...]}}.
```

**Body (normative)**

```python
from ..errors import ValidationError_

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
    config["update_filters"] = [
        _file_filter_body(f, group_name) for f in update_filters
    ]
if delete_filters:
    config["delete_filters"] = [
        _file_filter_body(f, group_name) for f in delete_filters
    ]
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

response = await app.client.request(
    "PATCH", f"/v1/file_monitor/{group_name}", json=payload
)
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
```

`_describe` is a closure inside the tool body, not a module-level helper, because
it exists only to build this one effect string. If `ruff` objects to a nested
`def`, hoist it next to `_file_filter_body` in the module — but do not export it.

**Exact effect f-string** — the preview string above, verbatim. The
`behavior="block"` branch is the load-bearing part: a reader must be able to see,
without any controller call, exactly which paths will start denying writes.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path. Error test uses
`tests/fixtures/error_object_not_found.json` (`code: 7`).

**Tests** `tests/test_policy_write.py`:
`test_update_file_monitor_profile_preview_sends_nothing` (assert
`route.call_count == 0` and that a `behavior="block"` filter's path appears
inside the `"BLAST RADIUS"` clause of `effect`),
`test_update_file_monitor_profile_confirmed_sends_config_body` — assert
`route.call_count == 1`, `route.calls.last.request.method == "PATCH"` and the
exact body:

```python
assert json.loads(route.calls.last.request.read()) == {
    "config": {
        "add_filters": [
            {
                "filter": "/etc/nginx/*",
                "recursive": True,
                "behavior": "block",
                "applications": ["nginx"],
                "group": "nv.api.prod",
            }
        ],
        "delete_filters": [
            {
                "filter": "/var/log/*",
                "recursive": False,
                "behavior": "monitor",
                "applications": [],
                "group": "nv.api.prod",
            }
        ],
    }
}
```

`test_update_file_monitor_profile_omits_empty_lists` (assert `"update_filters"`
is absent from the body when `update_filters` is empty),
`test_update_file_monitor_profile_rejects_empty_change_set` (expect
`ValidationError_`, `route.call_count == 0`).

**Notes**

* Envelope key here **is** `config` (`RESTFileMonitorConfigData.config`), unlike
  `nv_update_process_profile`. Both keys are verified in Appendix B; do not
  generalise from one to the other.
* **All five fields of `RESTFileMonitorFilterConfig` are required**: `filter`,
  `recursive`, `behavior`, `applications`, `group`. `_file_filter_body` sends all
  five on every filter in all three lists, including `delete_filters` — a delete
  entry is a full filter object, not a bare path, because the schema says so.
  `group` is filled from the tool's own `group_name`.
* `behavior` is **not enumerated** in Appendix B (`string`, no enum). Typed
  `str` with a default of `"monitor"`, and the description names `monitor` and
  `block` as the values Part B's read projection documents. Do not use a
  `Literal` here: a controller build that reports `behavior` as a boolean exists
  (see Part B's `nv_get_file_monitor_profile` Notes, where the read model is
  typed `bool | str`), and a `Literal` would make the write side reject a value
  the read side round-trips. The `blocking` check compares against the literal
  string `"block"`, which is safe: a non-matching value simply produces the
  "no filter in this change uses behavior='block'" branch rather than a false
  reassurance about a value that does block. If you find a controller that spells
  it differently, the fix is to widen the comparison, not to narrow the type.
* Empty lists are omitted from `config` rather than sent as `[]`, matching the
  treatment in `nv_apply_network_rule_changes`: an absent key is "leave alone",
  an empty array is a statement about a list.
* Common controller codes: **7** object not found (no file-monitor profile for
  that group); **4** operation not allowed (predefined filters the controller
  owns cannot be changed or deleted); **6** invalid request (a malformed glob, a
  `behavior` the controller does not accept); **46** read-only rules (`federal`
  or `ground` profile); **25** object access denied; **21** enforcer error (the
  profile changed but an enforcer could not apply it).

---

# Toolset `admission` (write) — 4 tools

All four are tagged `{"admission", "write"}`, all four use the module's single
`MUTATING` constant (`destructiveHint=True`), and all four pass
`namespace=None` to the guard because admission control is cluster-wide — there
is no namespace for `NV_ALLOWED_NAMESPACES` to check. Say so in the deployment
notes; do not fabricate a namespace to make the allowlist appear to apply.

Every tool in this toolset can return **`code=30`** (admission control is not
supported on a non-Kubernetes environment), **`code=31`** (NeuVector's Kubernetes
RBAC is misconfigured), **`code=32`** (the `neuvector-svc-admission-webhook`
service is misconfigured), **`code=33`** (the controller lacks UPDATE permission
on the service resource), **`code=34`** (the API server could not reach the
webhook — try a different client mode), **`code=35`** (the controller is
forbidden to read service details) and **`code=25`** (object access denied).
Those seven are listed once here rather than repeated four times; each tool's
Notes list only the codes that carry a *tool-specific* meaning.

### `nv_set_admission_state`

| | |
|---|---|
| **Toolset** | `admission` (write) |
| **Endpoints** | `PATCH /v1/admission/state` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting, and the widest blast radius of any tool in this server. |

> ## THE MOST DANGEROUS TOOL IN THIS SERVER
>
> Enabling admission control with `mode="protect"`, or with
> `default_action="deny"`, makes the Kubernetes API server **reject workload
> creates and updates across the entire cluster**. That includes namespaces
> nobody intended to protect, pod restarts and scale-ups of workloads that are
> already running, and NeuVector's own components. There is no rollout, no
> canary and no per-namespace staging: the change is live the moment the
> controller stores it. Recovering can require removing the
> ValidatingWebhookConfiguration from the cluster with `kubectl` — which this
> server cannot do for you, because it never talks to the Kubernetes API
> (SPEC §1.2).
>
> The docstring below **must** instruct the caller to run
> `nv_assess_admission_rule` first. That is not advice, it is the required
> workflow: assessment is the only way to see, before the fact, which running
> and pending objects the current deny rules would reject.

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `enable` | `bool` | — | True activates the Kubernetes admission webhook cluster-wide; false deactivates it and makes every admission rule inert. False is the break-glass direction. |
| `mode` | `Literal["monitor", "protect"] \| None` | `None` | 'monitor' logs what would have been denied and admits everything; 'protect' actually DENIES matching requests. Omit to leave the current mode alone. The controller refuses global settings while admission control is disabled (code 36), so enable it in 'monitor' first, verify, then switch to 'protect' in a second call. |
| `default_action` | `Literal["allow", "deny"] \| None` | `None` | What happens to a request that no admission rule matches. 'deny' means EVERY unmatched deployment in EVERY namespace is rejected while mode is 'protect' - that is a cluster-wide outage unless your exception rules are complete and you have verified them with nv_assess_admission_rule. Omit to leave the current setting alone. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change - and read the whole 'effect' before you send the token. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `enable` | JSON body `state.enable` |
| `mode` | JSON body `state.mode`, omitted when `None` |
| `default_action` | JSON body `state.default_action`, omitted when `None` |

Appendix A documents no query parameters on `PATCH /v1/admission/state`.

**Docstring (use verbatim)**

```
Enable, disable or reconfigure Kubernetes admission control for the whole cluster.

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
```

**Body (normative)**

```python
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
```

**Exact effect f-string** — the composed `effect` variable above, verbatim,
including all three `consequence` branches. The three branches are the point: a
reader must be able to tell from the preview alone whether this call blocks
deployments, merely logs them, or turns enforcement off.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path (`PATCH` returns an empty body). Error test
uses `tests/fixtures/error_admctrl_unsupported.json` (**no envelope**, bare
`RESTError` with `code: 30`).

**Tests** `tests/test_admission.py`:

* `test_set_admission_state_preview_sends_nothing` — assert `route.call_count ==
  0`, `status == "confirmation_required"`, `len(confirm_token) == 12`.
* `test_set_admission_state_preview_warns_about_blocking_all_deployments` — call
  with `enable=True, mode="protect", default_action="deny"`; assert
  `"BLOCK EVERY DEPLOYMENT IN THE CLUSTER"` and `"nv_assess_admission_rule"` are
  both in `effect`, and `route.call_count == 0`.
* `test_set_admission_state_monitor_preview_says_nothing_is_blocked` — call with
  `enable=True, mode="monitor"`; assert `"nothing is blocked"` in `effect` and
  that `"DANGER"` is **not** in it. This proves the branch is real and not
  boilerplate.
* `test_set_admission_state_disable_preview_says_break_glass` — call with
  `enable=False`; assert `"break-glass"` in `effect`.
* `test_set_admission_state_confirmed_sends_state_body` — assert
  `route.call_count == 1`, `route.calls.last.request.method == "PATCH"` and
  `json.loads(route.calls.last.request.read()) == {"state": {"enable": True,
  "mode": "protect", "default_action": "deny"}}`.
* `test_set_admission_state_omits_unset_fields` — call with `enable=True` only;
  assert the body is exactly `{"state": {"enable": True}}`, i.e. neither `mode`
  nor `default_action` nor `k8s_env` is present.
* `test_set_admission_state_token_is_bound_to_arguments` — **the `admission`
  module's token-binding test (SPEC §10.2).** Mint
  `confirm_token("nv_set_admission_state", "cluster admission control", {"state":
  {"enable": True, "mode": "monitor"}})` and submit it with `mode="protect"`;
  assert the call raises with `"confirm token mismatch"` and
  `route.call_count == 0`. Monitor-to-protect is precisely the substitution this
  handshake exists to stop.
* `test_set_admission_state_non_kubernetes_returns_validation_error` — respond
  `400` with `error_admctrl_unsupported.json`; expect `ValidationError_` (Appendix
  C `code=30` → `ValidationError_` in `errors._CODE_MAP`). This is the module's
  error-classification case.
* `test_admission_tools_hidden_when_read_only` — `build_server(make_settings(
  read_only=True, toolsets=DEFAULT_TOOLSETS))`, then assert none of
  `nv_set_admission_state`, `nv_create_admission_rule`,
  `nv_update_admission_rule`, `nv_delete_admission_rule` appears in
  `list_tools()`, while `nv_get_admission_state` (read, `policy_read`) still
  does.

**Notes**

* **BLOCKED (schema): `RESTAdmissionConfigData.k8s_env` is marked required (`*`)
  but must not be sent.** `k8s_env` is the controller telling the client "this is
  a Kubernetes cluster"; it is not a setting. The type is shared between the
  `GET` response and the `PATCH` request, which is where the spurious `required`
  comes from — the same Swagger artefact as `RESTAdmissionRuleConfig.id` on
  create. Defensive shape and instruction: send **only**
  `{"state": {...}}` with the two or three fields the caller set. Do not send
  `k8s_env`, `admission_options`, `admission_custom_criteria_options`,
  `admission_custom_criteria_templates` or `predefined_risky_roles` — the last
  four are option catalogues for building rules, they are large, and the client
  has no business echoing them. If a live controller rejects `{"state": {...}}`
  with `code=6` ("Request in wrong format"), **record it and stop**; do not
  retry with `k8s_env` guessed, and do not iterate shapes against a live
  cluster whose admission control you are configuring.
* `RESTAdmissionState`'s other fields — `adm_client_mode`, `adm_svc_type`,
  `adm_client_mode_options`, `ctrl_states` — are documented but not exposed.
  `adm_client_mode` is a plausible future argument (`code=34` explicitly
  suggests trying a different client mode), but adding it needs the valid values,
  which live in `adm_client_mode_options` and are not enumerated in Appendix B.
  Leaving it out is the honest choice; a caller who needs it can read the current
  value with `nv_get_admission_state`.
* **`mode` values are verified, `default_action` values are narrowed.**
  `RESTAdmissionState.mode` is a bare `string` on its own type, but Appendix B
  enumerates the same concept twice elsewhere:
  `RESTAdmCtrlRulesTestResults.global_mode` is `enum(monitor|protect|)` and
  `RESTAdmissionRule.rule_mode` is `enum(|monitor|protect)`. Those two make
  `Literal["monitor", "protect"]` a documented set, not a guess — note the
  lowercase spelling, which differs from group policy modes
  (`Discover`/`Monitor`/`Protect`, capitalised). `default_action` has no such
  corroboration; `Literal["allow", "deny"]` is the deliberate narrowing recorded
  in C.0.2. Widen to `str` only if a live controller rejects one of them.
* **`code=36` is a real ordering constraint, not a curiosity.** "Configuring
  NeuVector Admission Control global settings is not allowed when admission
  control is disabled." So a single call that sets `enable=false` *and* a new
  `mode` will fail, and setting `mode` while the webhook is currently disabled
  will fail too. That is why both the docstring and the `mode` description
  prescribe the two-call sequence: enable in `monitor`, verify, then switch to
  `protect`. Do not paper over it with a retry.
* `idempotentHint=False` is conservative on purpose. Re-sending the same state is
  in fact a no-op at the controller, but a client must not be told that
  re-issuing a cluster-wide enforcement change is free.
* `target` is the constant string `"cluster admission control"` — there is no
  object id. The token therefore binds only the operation and the payload, which
  is sufficient because every behaviour-changing input is in the payload (there
  are no query parameters on this route, unlike
  `nv_apply_network_rule_changes`).
* Tool-specific controller codes, on top of the seven listed for the toolset:
  **36** global settings while disabled (see above); **6** invalid request
  (unknown `mode` or `default_action`, or the `k8s_env` question above);
  **20** license failure (admission control is a licensed feature on some
  editions — the request is well-formed and still refused).

---

### `nv_create_admission_rule`

| | |
|---|---|
| **Toolset** | `admission` (write) |
| **Endpoints** | `POST /v1/admission/rule` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting — **not** object creation. See C.0.3 for the justification. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `rule_type` | `Literal["deny", "exception"]` | — | 'deny' BLOCKS matching Kubernetes requests while admission control is enabled in protect mode. 'exception' exempts matching requests from deny rules. Run nv_assess_admission_rule with the same criteria first to see what a deny rule would have blocked. |
| `criteria` | `list[AdmissionCriterionInput]` (min_length=1, max_length=16) | — | Match criteria for the rule. Each needs name, op and value; nested sub_criteria are optional. Get valid names and operators from an existing rule via nv_list_admission_rules - they are not enumerated in the schema reference. |
| `category` | `str` | `"Kubernetes"` | Rule category the controller expects; leave at the default unless an existing rule from nv_list_admission_rules shows otherwise. |
| `containers` | `list[Literal["containers", "init_containers", "ephemeral_containers"]]` | `["containers"]` | Which container classes the rule inspects. Adding 'init_containers' makes a deny rule block pods whose init containers match, which is easy to overlook. |
| `rule_mode` | `Literal["", "monitor", "protect"]` | `""` | Per-rule mode. Empty inherits the cluster mode from nv_get_admission_state; 'monitor' logs this rule's matches without blocking even when the cluster is in protect mode. Use 'monitor' to stage a new deny rule. |
| `comment` | `str` | `""` | Free-text comment stored on the rule. Say why it exists; it is the only provenance an operator gets later. |
| `disable` | `bool` | `False` | True stores the rule without enforcing it. Create a deny rule disabled first, verify with nv_assess_admission_rule, then enable it with nv_update_admission_rule. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| every argument except `confirm` | JSON body under `config` — see Body |
| — | `config.cfg_type` is always the literal `"user_created"`; `config.id` is **not** sent |

Appendix A documents no query parameters on `POST /v1/admission/rule`.

**Docstring (use verbatim)**

```
Create a Kubernetes admission control rule.

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
```

**Body (normative)**

```python
from ..errors import ValidationError_

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
    target=f"admission rule {new_id}" if new_id is not None else f"new {rule_type} admission rule",
    effect=(
        f"{rule_type} admission rule created"
        + (f" with id {new_id}" if new_id is not None else "")
        + f" (disabled={disable}, rule_mode={rule_mode or 'inherit'}): {criteria_text}"
    ),
    payload=payload,
    controller_response=body,
)
```

**Exact effect f-string** — the preview string above, verbatim, including the
`rule_type` branch and the trailing `disable` clause.

**Output model** — `WriteOutcome`. `AdmissionCriterionInput` is the **existing**
input model from Phase 6 (`models.py`), declared for
`nv_assess_admission_rule`. Import it; do not redefine it. Using the same model
for both tools is deliberate: a caller can assess a candidate rule and then
create it with the identical `criteria` argument, unchanged.

**Fixture** `tests/fixtures/admission_rule_created.json` — envelope key **`rule`**
(`RESTAdmissionRuleData.rule`, a `RESTAdmissionRule`). This is the only mutating
route in Part C with a non-empty success body, and the only reason it matters is
`id`: the controller assigns it, and the caller needs it for
`nv_update_admission_rule` and `nv_delete_admission_rule`. Give the fixture
`id`, `category`, `rule_type`, `rule_mode`, `disable`, `critical`, `cfg_type`,
`containers` and one `criteria` entry.

**Tests** `tests/test_admission.py`:
`test_create_admission_rule_preview_sends_nothing` (assert `route.call_count ==
0` and that every criterion appears in `effect`),
`test_create_admission_rule_deny_preview_warns_about_rejection` (assert
`"REJECTED by the"` and `"nv_assess_admission_rule"` in `effect` for
`rule_type="deny"`),
`test_create_admission_rule_exception_preview_warns_about_exemption` (assert
`"exempts matching requests"` in `effect` and `"BLAST RADIUS"` absent, for
`rule_type="exception"`),
`test_create_admission_rule_confirmed_sends_config_body` — assert
`route.call_count == 1`, `route.calls.last.request.method == "POST"` and the
exact body:

```python
assert json.loads(route.calls.last.request.read()) == {
    "config": {
        "category": "Kubernetes",
        "rule_type": "deny",
        "cfg_type": "user_created",
        "criteria": [{"name": "runAsRoot", "op": "=", "value": "true"}],
        "containers": ["containers"],
        "rule_mode": "monitor",
        "comment": "block root containers",
        "disable": False,
    }
}
```

Note what that asserts: **no `id` key**, and no `actions` key.

`test_create_admission_rule_returns_new_id` (respond with
`admission_rule_created.json`; assert `target == "admission rule 1001"` and
`controller_response["rule"]["id"] == 1001`),
`test_create_admission_rule_rejects_too_many_criteria` (17 criteria; expect
`ValidationError_`, `route.call_count == 0`).

**Notes**

* **`destructiveHint=True` even though this tool creates an object.** Justified
  in full in C.0.3: a new deny rule is live cluster-wide the instant it is
  stored, which is SPEC §6.2's traffic-affecting row, not its object-creation
  row. `nv_create_group` is the contrasting case and is correctly `False`.
* **`RESTAdmissionRuleConfig.id` is marked required but is not sent on create.**
  The type is shared with `PATCH /v1/admission/rule`, where the id is the whole
  point; on create the controller assigns it. Part B set exactly this precedent
  for `nv_assess_admission_rule`, which omits `id` for the same reason. Read the
  assigned id out of the response's `rule.id`.
* **`actions` is not sent.** `RESTAdmissionRuleConfig.actions` is
  `array<string>`, optional, with no enumeration anywhere in Appendix A or B.
  An un-enumerable optional field on the server's most dangerous rule type is
  not something to guess at — omit it. If a use case appears, enumerate the
  values in Appendix B first.
* **`critical` is not sent.** It exists on `RESTAdmissionRule` (the response) and
  **not** on `RESTAdmissionRuleConfig` (the request): it marks a
  controller-provided rule and is not the client's to set. A rule with
  `critical=true` is also the one you will not be able to update or delete —
  expect `code=4` or `code=46` there.
* Criterion names and operators are **not enumerated** in Appendix B
  (`RESTAdmRuleCriterion.name` and `.op` are bare `string`). Same instruction as
  `nv_create_group`'s criteria: keep them `str`, tell the caller to copy exact
  values from `nv_list_admission_rules`, and let the controller reject unknowns
  with `code=6`. `_criterion_body` sends only `name`, `op`, `value` and
  `sub_criteria` — never `type`, `template_kind`, `path` or `value_type`, which
  are controller-side annotations on the same type.
* `containers` defaults to `["containers"]` and not to all three classes. A deny
  rule that also inspects `init_containers` blocks pods whose init containers
  match, which callers routinely fail to anticipate; making it opt-in and saying
  so in the description is the safer default.
* Tool-specific controller codes, on top of the seven listed for the toolset:
  **36** configuring rules while admission control is disabled; **6** invalid
  request (unknown criterion name or operator, unknown `category`); **13**
  duplicate name (where the controller enforces uniqueness on a rule's identity);
  **20** license failure.

---

### `nv_update_admission_rule`

| | |
|---|---|
| **Toolset** | `admission` (write) |
| **Endpoints** | `PATCH /v1/admission/rule` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Traffic-affecting. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `rule_id` | `int` (ge=0) | — | Id of the admission rule to overwrite. Get ids from nv_list_admission_rules. The id goes in the request BODY - this endpoint has no id in its path. |
| `rule_type` | `Literal["deny", "exception"]` | — | 'deny' BLOCKS matching Kubernetes requests; 'exception' exempts them from deny rules. Send the rule's existing type unless you intend to flip it - flipping a deny rule to exception silently stops it blocking anything. |
| `criteria` | `list[AdmissionCriterionInput]` (min_length=1, max_length=16) | — | The COMPLETE new criteria set. This REPLACES the existing set - it is not merged, so any criterion you omit is removed. Read the current rule with nv_list_admission_rules and echo back what you intend to keep. |
| `category` | `str` | `"Kubernetes"` | Rule category. Send the value the existing rule already has. |
| `containers` | `list[Literal["containers", "init_containers", "ephemeral_containers"]]` | `["containers"]` | Which container classes the rule inspects. This REPLACES the existing list. |
| `rule_mode` | `Literal["", "monitor", "protect"]` | `""` | Per-rule mode. Empty inherits the cluster mode. Switching a rule from 'monitor' to '' or 'protect' is what makes an already-matching deny rule start blocking. |
| `comment` | `str` | `""` | Free-text comment stored on the rule. Not sending it clears the existing comment. |
| `disable` | `bool` | `False` | True stores the rule without enforcing it. Set true to switch a deny rule off without deleting it - safer than deletion, because deletion also removes the exception rules' reason for existing. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `rule_id` | JSON body `config.id` — **not** a path segment |
| every other argument except `confirm` | JSON body under `config` |
| — | `config.cfg_type` is always the literal `"user_created"` |

**Docstring (use verbatim)**

```
Overwrite an existing Kubernetes admission control rule.

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
```

**Body (normative)**

```python
from ..errors import ValidationError_

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
        f"OVERWRITE admission rule id {rule_id} as a {rule_type.upper()} rule "
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
```

**Exact effect f-string** — the preview string above, verbatim.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path (`PATCH` returns an empty body). Error
tests use `tests/fixtures/error_object_not_found.json` (`code: 7`) and
`tests/fixtures/error_read_only_rules.json` (`code: 46`).

**Tests** `tests/test_admission.py`:
`test_update_admission_rule_preview_sends_nothing` (assert `route.call_count ==
0`, `"OVERWRITE admission rule id"` and `"REMOVED"` in `effect`),
`test_update_admission_rule_confirmed_sends_id_in_body` — assert
`route.call_count == 1`, `route.calls.last.request.method == "PATCH"`,
`route.calls.last.request.url.path == "/v1/admission/rule"` (**no id in the
path** — this is the assertion that catches the most likely defect) and the exact
body:

```python
assert json.loads(route.calls.last.request.read()) == {
    "config": {
        "id": 1001,
        "category": "Kubernetes",
        "rule_type": "deny",
        "cfg_type": "user_created",
        "criteria": [{"name": "imageRegistry", "op": "containsAny", "value": "docker.io"}],
        "containers": ["containers", "init_containers"],
        "rule_mode": "",
        "comment": "no public registries",
        "disable": False,
    }
}
```

`test_update_admission_rule_missing_raises_not_found` (respond `404` with
`error_object_not_found.json`, expect `NotFoundError`),
`test_update_admission_rule_readonly_rule_returns_permission_error` (respond
`403` with `error_read_only_rules.json`, expect `PermissionError_` — Appendix C
`code=46` maps to `PermissionError_`).

**Notes**

* **The path has no `{id}`.** `PATCH /v1/admission/rule` is the documented route;
  `PATCH /v1/admission/rule/{id}` does not exist and would fail gate rule R6.
  The id is `config.id`, which is why `RESTAdmissionRuleConfig` marks `id`
  required. `test_update_admission_rule_confirmed_sends_id_in_body` asserts the
  URL path explicitly for this reason.
* **Whole-rule replacement, and no pre-read.** As with
  `nv_update_group_criteria`, invariant C6 forbids reading the current rule
  before the guard returns, so the preview states that omission means removal
  rather than showing a diff against the live rule. The argument descriptions
  repeat it. Do not add a read to enrich the preview.
* `comment` defaults to `""`, which **clears** an existing comment when the
  caller does not resend it. That is stated in the argument description. The
  alternative — omitting the key — is worse here: the field is optional on the
  type, so an omitted `comment` on a whole-rule overwrite has undefined merge
  behaviour, and a predictable clear is easier to reason about than an
  undocumented merge.
* `disable=True` is the recommended way to switch a deny rule off. Say so in the
  description: deleting the rule also removes the reason its exception rules
  exist, and someone will later delete those too.
* Tool-specific controller codes, on top of the seven listed for the toolset:
  **7** object not found (no rule with that id — re-read
  `nv_list_admission_rules`); **4** operation not allowed and **46** read-only
  rules (a `critical` rule, or `cfg_type` `federal` / `ground`); **36**
  configuring rules while admission control is disabled; **6** invalid request;
  **20** license failure.

---

### `nv_delete_admission_rule`

| | |
|---|---|
| **Toolset** | `admission` (write) |
| **Endpoints** | `DELETE /v1/admission/rule/{id}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING`) |
| **Returns** | `WriteOutcome` |
| **SPEC §6.2 class** | Data-destroying **and** traffic-affecting. |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `rule_id` | `int` (ge=0) | — | Id of the admission rule to delete. Get ids from nv_list_admission_rules and read the rule's type first: deleting an 'exception' rule can start BLOCKING deployments it used to exempt. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `rule_id` | path segment `{id}` |

Appendix A documents `scope` on `DELETE /v1/admission/rules` (the delete-all
form, which this server does not expose) but **not** on
`DELETE /v1/admission/rule/{id}`. Send no query parameters.

**Docstring (use verbatim)**

```
Delete one Kubernetes admission control rule by id.

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
```

**Body (normative)**

```python
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
```

**Exact effect f-string** — the preview string above, verbatim.

**Output model** — `WriteOutcome`.

**Fixture** — none for the happy path. Error tests use
`tests/fixtures/error_object_not_found.json` (`code: 7`) and
`tests/fixtures/error_op_not_allowed.json` (`code: 4`).

**Tests** `tests/test_admission.py`:
`test_delete_admission_rule_preview_sends_nothing` (assert `route.call_count ==
0` and that both `"EXCEPTION"` and `"DENY"` appear in `effect`, since the preview
cannot know which the rule is),
`test_delete_admission_rule_confirmed_calls_delete` (assert `route.call_count ==
1`, `route.calls.last.request.method == "DELETE"`,
`route.calls.last.request.url.path == "/v1/admission/rule/1001"`, and no request
body),
`test_delete_admission_rule_critical_rule_returns_permission_error` (respond
`403` with `error_op_not_allowed.json`, expect `PermissionError_`).

**Notes**

* `payload=None`, so the token is
  `sha256("nv_delete_admission_rule|<id>|{}")[:12]`. `target=str(rule_id)`, not
  the `int`.
* **The preview describes both directions on purpose.** Invariant C6 forbids a
  pre-read, so the tool genuinely does not know whether this is a deny rule or an
  exception rule. Stating both consequences is the honest preview; inferring the
  type from the id would be a fabrication (Part B's standing rule about id
  ranges applies here too).
* The docstring steers the caller to `nv_update_admission_rule(disable=True)`.
  That is deliberate: for admission control, "switch it off" and "delete it" have
  the same immediate effect and very different recoverability.
* Tool-specific controller codes, on top of the seven listed for the toolset:
  **7** object not found (already deleted); **4** operation not allowed and **46**
  read-only rules (`critical` rule, or `cfg_type` `federal` / `ground`);
  **16** object in use; **36** while admission control is disabled.

---

## C.9 Test files and fixture inventory

### C.9.1 Test files

| File | Phase | Tools covered |
|---|---|---|
| `tests/test_guard.py` | 0 | **verbatim from `reference/`, never edited.** Covers `nv_set_group_policy_mode` completely (preview, confirmed-body, token binding, namespace allowlist, read-only hiding, annotations) and `nv_delete_group` partially (registration and annotations only). |
| `tests/test_policy_write.py` | 7 | new file; the other 6 `policy_write` tools plus the preview/apply pair `test_guard.py` does not give `nv_delete_group` |
| `tests/test_admission.py` | 8 | new file; all 4 `admission` tools |

Gate rule R8 matches on the **literal quoted tool name**, so all 12 names must
appear as `"nv_..."` in one of those three files. `nv_set_group_policy_mode` and
`nv_delete_group` are already satisfied by `test_guard.py`; the other ten are
satisfied by the tests named in each tool's section.

**Per-tool coverage matrix (SPEC §10.2).** Every row must be green before the
phase gate passes.

| Tool | preview sends nothing | confirmed applies (exact body) | token binding |
|---|---|---|---|
| `nv_create_group` | `test_create_group_preview_sends_nothing` | `test_create_group_confirmed_sends_config_body` | — |
| `nv_update_group_criteria` | `test_update_group_criteria_preview_sends_nothing` | `test_update_group_criteria_confirmed_replaces_criteria` | — |
| `nv_delete_group` | `test_delete_group_preview_sends_nothing` | `test_delete_group_confirmed_calls_delete` | — |
| `nv_set_group_policy_mode` | `test_first_call_returns_plan_and_sends_nothing` (test_guard.py) | `test_confirmed_call_applies` (test_guard.py) | **`test_token_is_bound_to_arguments`** (test_guard.py) |
| `nv_apply_network_rule_changes` | `test_apply_network_rule_changes_preview_lists_every_change` | `test_apply_network_rule_changes_confirmed_sends_batch_body` | **`test_apply_network_rule_changes_token_is_bound_to_scope`** |
| `nv_delete_network_rule` | `test_delete_network_rule_preview_sends_nothing` | `test_delete_network_rule_confirmed_calls_delete` | — |
| `nv_update_process_profile` | `test_update_process_profile_preview_sends_nothing` | `test_update_process_profile_confirmed_sends_process_profile_config_body` | — |
| `nv_update_file_monitor_profile` | `test_update_file_monitor_profile_preview_sends_nothing` | `test_update_file_monitor_profile_confirmed_sends_config_body` | — |
| `nv_set_admission_state` | `test_set_admission_state_preview_sends_nothing` | `test_set_admission_state_confirmed_sends_state_body` | **`test_set_admission_state_token_is_bound_to_arguments`** |
| `nv_create_admission_rule` | `test_create_admission_rule_preview_sends_nothing` | `test_create_admission_rule_confirmed_sends_config_body` | — |
| `nv_update_admission_rule` | `test_update_admission_rule_preview_sends_nothing` | `test_update_admission_rule_confirmed_sends_id_in_body` | — |
| `nv_delete_admission_rule` | `test_delete_admission_rule_preview_sends_nothing` | `test_delete_admission_rule_confirmed_calls_delete` | — |

Token binding is required **≥1 per mutating module** (SPEC §10.2). `policy_write`
has two (one shipped, one new for the `scope` fold); `admission` has one.

Every "preview sends nothing" test asserts, without exception:

```python
assert route.call_count == 0, "the guard must not touch the controller"
```

Every "confirmed applies" test asserts `route.call_count == 1`, the HTTP method,
and `json.loads(route.calls.last.request.read()) == {...}` with the body spelled
out in full — never a subset match, never `in`.

**Read-only hiding** (once per mutating module): `test_guard.py`'s
`test_read_only_hides_mutating_toolsets` covers `policy_write` for the two
shipped tools; add `test_policy_write_tools_hidden_when_read_only` in
`tests/test_policy_write.py` naming the six new tools, and
`test_admission_tools_hidden_when_read_only` in `tests/test_admission.py` naming
all four.

**Error classification** (≥1 per module): `policy_write` uses
`test_update_group_criteria_learned_group_returns_permission_error` (`code=4`)
and `test_delete_network_rule_missing_raises_not_found` (`code=7`); `admission`
uses `test_set_admission_state_non_kubernetes_returns_validation_error`
(`code=30`) and
`test_update_admission_rule_readonly_rule_returns_permission_error` (`code=46`).

### C.9.2 Fixtures

Mutating routes in this part return an **empty body** on success (SPEC §3.3:
`PATCH` and `DELETE` return 200 with no body; `POST /v1/group` is documented as
bare `object` and behaves the same). Those tests stub `respond(200, json={})`
inline and need **no fixture file**. Only one success body carries information,
and four error bodies are shared.

| File | Envelope key | Used by |
|---|---|---|
| `tests/fixtures/admission_rule_created.json` | **`rule`** (`RESTAdmissionRuleData.rule`) | `nv_create_admission_rule` — the only Part C success body that matters, because it carries the assigned `id` |
| `tests/fixtures/error_duplicate_name.json` | *(none — bare `RESTError`)* | `nv_create_group` (`code: 13`) |
| `tests/fixtures/error_op_not_allowed.json` | *(none — bare `RESTError`)* | `nv_update_group_criteria`, `nv_delete_group`, `nv_apply_network_rule_changes`, `nv_delete_admission_rule` (`code: 4`) |
| `tests/fixtures/error_object_not_found.json` | *(none — bare `RESTError`)* | `nv_delete_network_rule`, `nv_update_process_profile`, `nv_update_file_monitor_profile`, `nv_update_admission_rule` (`code: 7`) |
| `tests/fixtures/error_read_only_rules.json` | *(none — bare `RESTError`)* | `nv_apply_network_rule_changes` with `scope="fed"`, `nv_update_admission_rule` (`code: 46`) |
| `tests/fixtures/error_admctrl_unsupported.json` | *(none — bare `RESTError`)* | every `admission` tool on a non-Kubernetes platform (`code: 30`) |

Each error fixture is a three-key `RESTError` body with the `code` and the exact
`error` string from Appendix C, e.g.

```json
{"code": 4, "error": "Operation not allowed", "message": "Learned group cannot be modified"}
```

`message` is free text and may be anything descriptive; `code` and `error` must
match Appendix C exactly, because `errors.classify` branches on `code` and the
assertions read the message it composes.

## C.10 Registration and gate checklist

`server.py` `TOOL_MODULES`: `"neuvector_mcp.tools.policy_write"` is already
present from Phase 0 (Phase 7 adds no entry, it only extends the module's
`register()`); Phase 8 appends `"neuvector_mcp.tools.admission"`.

| Gate rule | How Part C satisfies it |
|---|---|
| **R1** | All 12 names match `^nv_[a-z0-9_]+$`. |
| **R2** | Every docstring has a summary line, a guidance paragraph naming the blast radius, and a `Calls` line; all exceed 80 characters and 3 lines by a wide margin. |
| **R3** | `ToolAnnotations` on every tool with `readOnlyHint=False`; both toolsets are write-kind (SPEC §5.1), so the derivation agrees. Constants: `MUTATING`, `MUTATING_IDEMPOTENT`, `MUTATING_CREATE` in `policy_write.py`; `MUTATING` in `admission.py`. |
| **R4** | Exactly one toolset tag per tool: `policy_write` (8), `admission` (4), each plus `"write"`. |
| **R5** | All 12 accept `confirm: str \| None = None` as the last parameter. |
| **R6** | 11 distinct endpoints, all in `spec_endpoints.json["documented"]` (see C.0.1). No `UNDOCUMENTED_ALLOWLIST` entry, no `NV_ALLOW_UNDOCUMENTED` gating. |
| **R7** | All 12 return `WriteOutcome`. No `dict` returns. |
| **R8** | All 12 names appear in `tests/test_guard.py`, `tests/test_policy_write.py` or `tests/test_admission.py` per the C.9.1 matrix. |
| **R9** | Satisfied by construction: with all toolsets enabled these 12 mutating tools are registered. |

**New classes appended to `models.py`** [Phase 7], in this order:
`GroupCriterionInput`, `NetworkRuleInput`, `ProcessProfileEntryInput`,
`FileMonitorFilterInput`. Phase 8 appends **nothing** — `admission.py` reuses
`AdmissionCriterionInput` (Phase 6) and `WriteOutcome` (Phase 0). `Page`,
`WriteOutcome`, `AdmissionCriterionInput`, `PolicyMode` and `_BASE` already
exist; reference them, never redefine them.

**New module-level definitions in `policy_write.py`** [Phase 7]:
`MUTATING_CREATE`, `MAX_RULE_CHANGES`, `_namespace_from_group_name`,
`_namespace_from_criteria`, `_rule_body`, `_process_entry_body`,
`_file_filter_body`. **New module-level definitions in `admission.py`** [Phase
8]: `MUTATING`, `MAX_ADMISSION_CRITERIA`, `_criterion_body`, `register`.

**Final reminder.** The two tools already in
`reference/src/neuvector_mcp/tools/policy_write.py` (`nv_set_group_policy_mode`,
`nv_delete_group`) and the file `reference/tests/test_guard.py` are pinned by
rule N3. If `git diff` shows a change to any line of either, revert it — a
changed effect string changes a confirm token, and a changed token breaks the
one safety property this whole part exists to provide.
