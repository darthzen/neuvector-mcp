# PHASE 2 — `inventory` toolset (8 new tools)

**Read only this file plus:**

* `SPEC.md` sections 3, 7.3, 7.5, 7.6, 12
* `tools/PART-A-inventory-vulnerability-compliance.md` — section **A.0** (module
  preamble) and the **`Toolset inventory`** section
* `appendix/B-schema-reference.md` — for any field you touch
* `appendix/D-api-conventions.md` — sections D.2 and D.3

Do not read other phases. Do not read the `vulnerability` or `compliance`
sections of Part A yet.

## Goal

Extend `tools/inventory.py` from 3 tools to 11, and append the new output models
to `models.py`.

## Tools

Already implemented in Phase 0 — **do not touch them**:
`nv_get_system_summary`, `nv_list_workloads`, `nv_get_workload`.

New in this phase:

| Tool | Endpoint |
|---|---|
| `nv_whoami` | `GET /v1/selfuser` (undocumented, gated) |
| `nv_list_hosts` | `GET /v1/host` |
| `nv_list_groups` | `GET /v1/group` |
| `nv_get_group` | `GET /v1/group/{name}` |
| `nv_list_services` | `GET /v1/service` |
| `nv_list_enforcers` | `GET /v1/enforcer` |
| `nv_list_namespaces` | `GET /v1/domain` |
| `nv_get_network_conversations` | `GET /v1/conversation` (undocumented, gated) |

Part A gives each one's arguments, query mapping, verbatim docstring, output
model with `from_api()`, fixture name and envelope key. Follow it exactly.

## Order of work

1. Append every new model class to `models.py`, in the order Part A lists them.
   Nothing above them changes.
2. Write the fixtures named in Part A section A.9. Field names come from Appendix
   B — do not invent any.
3. Add the eight tools to `tools/inventory.py`, inside the existing
   `register(mcp, settings)` function, after the three that are already there.
4. Extend `tests/test_inventory.py` with the tests Part A names.
5. Run the gate.

## Rules specific to this phase

* **Two tools are gated on undocumented routes.** `nv_whoami` and
  `nv_get_network_conversations` must check `app.settings.allow_undocumented` and
  behave exactly as Part A prescribes when it is false — `nv_whoami` degrades to
  the cached `AppContext.identity`; `nv_get_network_conversations` raises
  `GuardError`. Their `Calls` lines are already present in
  `UNDOCUMENTED_ALLOWLIST` in `scripts/verify_spec.py`; do not edit that list.
* Every list tool uses the over-fetch-by-one truncation pattern from SPEC.md 7.3.
  A list tool without it fails review even if its tests pass.
* `nv_list_groups` and `nv_get_group` return different models. A list entry is a
  brief; the detail carries criteria. Do not collapse them into one model.
* `tools/inventory.py` imports nothing from another `tools/*` module.

## Test requirements

Per SPEC.md 10.2, each new tool needs at minimum a happy-path test, and each list
tool additionally needs a query-construction test and a truncation test. Part A
names the specific test functions. Add one error-classification test for the
module if `test_inventory.py` does not already have one (it does —
`test_controller_error_is_classified`).

## Gate

```bash
make verify
```

`make spec` must report **13 tools introspected** with zero violations.

## Stop here

Report the tool count and the `make verify` result. Do not start Phase 3.
