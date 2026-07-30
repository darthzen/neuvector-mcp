# PHASE 8 — `admission` toolset (4 tools)

**The tool in this phase with the widest blast radius in the entire server is
`nv_set_admission_state`. Enabling admission control in deny mode can block every
deployment in the cluster.**

**Read only this file plus:**

* `SPEC.md` sections 6, 7.4, 12
* `tools/PART-C-policy-write-admission.md` — sections **C.0.0**, **C.0.3**,
  **C.0.5** and the **`Toolset admission`** section
* `appendix/B-schema-reference.md`, `appendix/C-error-taxonomy.md`

## Goal

New file `src/neuvector_mcp/tools/admission.py` with 4 mutating tools, registered
in `server.py`.

## Tools

| Tool | Endpoint | `destructiveHint` |
|---|---|---|
| `nv_set_admission_state` | `PATCH /v1/admission/state` | `True` |
| `nv_create_admission_rule` | `POST /v1/admission/rule` | `True` |
| `nv_update_admission_rule` | `PATCH /v1/admission/rule` | `True` |
| `nv_delete_admission_rule` | `DELETE /v1/admission/rule/{id}` | `True` |

`nv_create_admission_rule` is `destructiveHint=True` even though it creates rather
than deletes, because a new deny rule affects traffic immediately. Part C section
C.0.3 states the justification; keep it in a comment.

## `nv_set_admission_state`

Requirements Part C specifies and you must implement:

* Three branch-specific `effect` strings (enable, disable, mode change), each
  naming the concrete consequence.
* The docstring must direct the caller to run `nv_assess_admission_rule`
  (Phase 6) **first**, and must say in plain words that deny mode can block all
  deployments cluster-wide.
* `RESTAdmissionConfigData.k8s_env` is marked required in the schema but **must
  not be sent**. Part C marks this `BLOCKED`; follow its instruction exactly.

## Endpoint detail that catches people out

`PATCH /v1/admission/rule` has **no** `{id}` path segment. The rule id travels in
the body as `config.id`. Verify against Appendix A before writing it.

## Error codes

| Code | Situation |
|---|---|
| 30 | Admission control is unsupported on a non-Kubernetes platform |
| 36 | Configuring global settings while admission control is disabled |
| 31, 32, 33, 34, 35 | Kubernetes RBAC or webhook service misconfiguration — surface the controller's message verbatim; these are cluster problems, not caller errors |
| 7 | Rule id does not exist |

## Test requirements

Per tool: `test_<tool>_preview_sends_nothing` and `test_<tool>_confirmed_*`
asserting the exact body. Plus:

* `test_set_admission_state_token_is_bound_to_arguments`
* `test_set_admission_state_effect_warns_about_blocking_deployments` — assert the
  preview `effect` text contains the warning
* `test_admission_rule_patch_has_no_id_in_path`
* `test_read_only_hides_admission_tools`
* an error-classification test for code 30

## Gate

```bash
make verify
```

`make spec` must report **49 tools introspected**, zero violations.

## Stop here
Report the tool count and gate result. Do not start Phase 9.
