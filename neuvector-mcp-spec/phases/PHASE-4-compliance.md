# PHASE 4 — `compliance` toolset (4 tools)

**Read only this file plus:**

* `SPEC.md` sections 3, 7.3, 7.5, 7.6, 12
* `tools/PART-A-inventory-vulnerability-compliance.md` — section **A.0** and the
  **`Toolset compliance`** section
* `appendix/B-schema-reference.md`, `appendix/D-api-conventions.md` D.3 and D.7

## Goal

New file `src/neuvector_mcp/tools/compliance.py` with 4 read tools, registered in
`server.py`.

## Tools

| Tool | Endpoint(s) |
|---|---|
| `nv_get_compliance_findings` | `GET /v1/workload/{id}/compliance`, `GET /v1/host/{id}/compliance` |
| `nv_get_bench_report` | `GET /v1/bench/host/{id}/kubernetes`, `GET /v1/bench/host/{id}/docker` |
| `nv_list_compliance_profiles` | `GET /v1/compliance/profile` |
| `nv_get_compliance_profile` | `GET /v1/compliance/profile/{name}` |

## Rules specific to this phase

* **Unwrapped responses.** `RESTComplianceData` and `RESTBenchReport` are returned
  without an envelope on some paths. Use the defensive pattern Part A prescribes
  (`raw.get("<key>") or raw`) and say so in a comment. Do not guess a key.
* Both multi-endpoint tools are discriminated by an argument (`scope`,
  `benchmark`). Validate locally and raise `ValidationError_` naming the bad value
  before any network call.
* Bench reports can be large and slow: `settings.long_request_timeout_s`, plus the
  same client-side cap and truncation reporting as scan reports.
* Compliance findings group naturally by outcome. Part A specifies the projection:
  return counts by level plus the failing checks, and offer a filter to include
  passing checks. Default to failures only — a caller asking about compliance
  wants what is wrong.

## Test requirements

SPEC.md 10.2 plus:

* `test_compliance_findings_scope_workload_and_host_hit_different_paths`
* `test_compliance_findings_defaults_to_failures_only`
* `test_bench_report_benchmark_argument_selects_path`
* `test_bench_report_invalid_benchmark_rejected_before_request` (assert
  `route.call_count == 0`)
* `test_unwrapped_body_projects_correctly`

## Gate

```bash
make verify
```

`make spec` must report **24 tools introspected**, zero violations.

## Stop here
Report the tool count and gate result. Do not start Phase 5.
