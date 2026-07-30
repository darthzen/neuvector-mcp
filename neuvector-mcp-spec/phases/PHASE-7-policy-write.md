# PHASE 7 — `policy_write` toolset (6 new tools)

**This is the first phase that can break a production cluster. Read it fully
before writing a line.**

**Read only this file plus:**

* `SPEC.md` sections 6 (safety model), 7.4 (the five-step body), 12 (gate rules)
* `tools/PART-C-policy-write-admission.md` — sections **C.0.0** through **C.0.6**
  and the **`Toolset policy_write`** section
* `appendix/B-schema-reference.md`, `appendix/C-error-taxonomy.md`
* `reference/tests/test_guard.py` — the tests that already pin the handshake

## Goal

Extend `tools/policy_write.py` from 2 tools to 8. Add the input models Part C
section C.0.6 specifies to `models.py`.

## Tools

Already implemented in Phase 0 — **do not touch them**:
`nv_set_group_policy_mode`, `nv_delete_group`.

New in this phase:

| Tool | Endpoint | `destructiveHint` |
|---|---|---|
| `nv_create_group` | `POST /v1/group` | `False` |
| `nv_update_group_criteria` | `PATCH /v1/group/{name}` | `True` |
| `nv_apply_network_rule_changes` | `PATCH /v1/policy/rule` | `True` |
| `nv_delete_network_rule` | `DELETE /v1/policy/rule/{id}` | `True` |
| `nv_update_process_profile` | `PATCH /v1/process_profile/{name}` | `True` |
| `nv_update_file_monitor_profile` | `PATCH /v1/file_monitor/{name}` | `True` |

## Non-negotiable invariants

Every one of the six tools:

1. builds the payload,
2. calls `authorise_write(...)` **before any network call**,
3. returns the guard's `WriteOutcome` verbatim when it is not `None`,
4. only then calls the controller,
5. returns `WriteOutcome(status="applied", ...)`.

`readOnlyHint=False`, exactly one toolset tag (`policy_write`) plus `"write"`,
`confirm: str | None = None` as the **last** argument, return type `WriteOutcome`.

A tool that issues a request before step 3 fails
`test_*_preview_sends_nothing`, which asserts `route.call_count == 0`. That
assertion is the whole safety model in one line — do not weaken it.

## `nv_apply_network_rule_changes` — the highest-risk tool in the server

A malformed batch drops production traffic. Part C prescribes, and you must
implement:

* the exact `RESTPolicyRuleActionData` body shape,
* a **hard cap** on batch size,
* an `effect` string that enumerates **every** rule change as a diff, one line
  per rule, so a human reading the preview can see exactly what will happen,
* `id` mandatory on every configure entry,
* the `scope` query parameter folded into the guard's `target`, because the
  confirm token cannot bind query parameters. Part C explains this; the
  consequence is a required test,
  `test_apply_network_rule_changes_token_is_bound_to_scope`.

`after` positioning semantics on insert and move are marked `BLOCKED` in Part C:
pass the caller's value through **verbatim** and never synthesise one.

## Process and file-monitor profiles

In `Protect` mode a wrong process-profile entry terminates a running process.
State that in the docstring in those words. The `effect` string must name every
entry being added or removed, not just a count.

`RESTProcessProfileConfigData`'s envelope key is `process_profile_config`, not
`config`. Confirm in Appendix B before writing it.

## Error codes to document per tool

From Appendix C, in each docstring where relevant:

| Code | Situation |
|---|---|
| 4 | Deleting or renaming a learned group (`nv.*`) |
| 13 | Duplicate group name |
| 7 | Rule or profile id does not exist |
| 46 | Federated or learned rules cannot be modified |
| 16 | Group is in use by a rule |

## Test requirements

Part C section C.9 names 40 test functions across this phase and Phase 8. For this
phase, at minimum, per tool:

* `test_<tool>_preview_sends_nothing` — asserts `route.call_count == 0`
* `test_<tool>_confirmed_applies` — asserts the **exact** JSON body and
  `call_count == 1`

Plus, once for the module:

* `test_apply_network_rule_changes_token_is_bound_to_scope`
* `test_read_only_hides_policy_write_tools`
* an error-classification test for code 46

## Gate

```bash
make verify
```

`make spec` must report **45 tools introspected**, zero violations.

## Stop here
Report the tool count and gate result. Do not start Phase 8.
