# PHASE 6 — `policy_read` toolset (10 tools)

**Read only this file plus:**

* `SPEC.md` sections 3, 7.3, 7.5, 7.6, 12
* `tools/PART-B-events-policy-read-iam-read.md` — section **B.0** and the
  **`Toolset policy_read`** section
* `appendix/B-schema-reference.md`, `appendix/C-error-taxonomy.md`

## Goal

New file `src/neuvector_mcp/tools/policy_read.py` with 10 read tools, registered
in `server.py`.

## Tools

| Tool | Endpoint |
|---|---|
| `nv_list_network_rules` | `GET /v1/policy/rule` |
| `nv_get_network_rule` | `GET /v1/policy/rule/{id}` |
| `nv_get_process_profile` | `GET /v1/process_profile/{name}` |
| `nv_get_file_monitor_profile` | `GET /v1/file_monitor/{name}` |
| `nv_list_response_rules` | `GET /v1/response/rule` |
| `nv_list_dlp_sensors` | `GET /v1/dlp/sensor` |
| `nv_list_waf_sensors` | `GET /v1/waf/sensor` |
| `nv_get_admission_state` | `GET /v1/admission/state` |
| `nv_list_admission_rules` | `GET /v1/admission/rules` |
| `nv_assess_admission_rule` | `POST /v1/assess/admission/rule` |

## Why a POST lives in a read toolset

`nv_assess_admission_rule` evaluates a candidate admission rule against the
cluster's current objects and reports what **would** match. It changes nothing.
It is therefore tagged `policy_read` with `readOnlyHint=True` and takes **no**
`confirm` argument — gate rule R5 forbids one on a read tool.

This matters operationally: it is the tool a caller must use before
`nv_set_admission_state` in Phase 8. Say so in its docstring.

## Rules specific to this phase

* **Rule ordering is semantic.** Network rules are evaluated in list order and id
  ranges distinguish learned, user-created and federated rules. Part B gives the
  ranges. The projection must expose enough for a caller to reason about
  precedence, and the docstring must explain it, because Phase 7's
  `nv_apply_network_rule_changes` depends on the caller understanding it.
* `scope` is documented on `/v1/waf/sensor` and `/v1/admission/rules` but **not**
  on `/v1/dlp/sensor`. Do not add a `scope` argument to `nv_list_dlp_sensors`.
  Part B records this asymmetry; it is upstream's, not a mistake.
* Several response types are absent from Appendix B (`RESTDlpSensor`,
  `RESTWafSensor`, `RESTFileMonitorFile`, `RESTNvAlerts`). Part B marks these
  `BLOCKED (schema)` and gives defensive projections with an `envelope_keys`
  diagnostic field. Implement them as written and leave the `BLOCKED` note as a
  code comment so a later operator knows to confirm against a live controller.
* Rules that cannot be modified return code 46 on write attempts. Mention that in
  `nv_list_network_rules`' docstring so a caller learns it before Phase 7.

## Test requirements

SPEC.md 10.2 plus:

* `test_list_network_rules_scope_parameter`
* `test_network_rule_projection_preserves_order`
* `test_list_dlp_sensors_has_no_scope_argument` — introspect the tool schema
* `test_assess_admission_rule_has_no_confirm_argument`
* `test_assess_admission_rule_is_read_only_hint`

## Gate

```bash
make verify
```

`make spec` must report **39 tools introspected**, zero violations.

## Stop here
Report the tool count and gate result. Do not start Phase 7.
