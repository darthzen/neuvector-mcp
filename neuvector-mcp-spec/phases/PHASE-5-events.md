# PHASE 5 — `events` toolset (5 tools)

**Read only this file plus:**

* `SPEC.md` sections 3, 7.3, 7.5, 7.6, 11, 12
* `tools/PART-B-events-policy-read-iam-read.md` — section **B.0** and the
  **`Toolset events`** section
* `appendix/B-schema-reference.md`, `appendix/D-api-conventions.md` D.2

## Goal

New file `src/neuvector_mcp/tools/events.py` with 5 read tools, registered in
`server.py`.

## Tools

| Tool | Endpoint(s) |
|---|---|
| `nv_query_security_events` | `GET /v1/log/threat`, `GET /v1/log/violation`, `GET /v1/log/incident` |
| `nv_get_threat_detail` | `GET /v1/log/threat/{id}` |
| `nv_query_audit_events` | `GET /v1/log/audit` |
| `nv_query_system_events` | `GET /v1/log/event` |
| `nv_get_system_alerts` | `GET /v1/system/alerts` |

## The hard part: the filter field names differ per event kind

This is the trap in this phase. The three security-event kinds use **different
JSON tags for the same concept**. Part B section `Toolset events` has the
authoritative mapping table. Reproduce it in a module-level constant so the tool
body cannot get it wrong:

* namespace: `client_workload_domain` (threat) vs `client_domain` (violation) vs
  `workload_domain` (incident)
* severity: `severity` (threat) vs `level` (violation and incident)

Verify each tag against Appendix B before you write it. A wrong tag produces an
empty result set with no error, which reads as "no threats" — the most dangerous
silent failure in a security tool.

## Other rules

* `build_query` renders **one value per field**, so a two-sided time window
  cannot be expressed server-side. Part B specifies the approach: filter one side
  server-side and trim the other client-side, reporting how many entries were
  dropped. Implement it exactly as written.
* Threat **list** responses have the packet payload stripped by the controller;
  `GET /v1/log/threat/{id}` includes it. `nv_get_threat_detail` must withhold the
  packet unless explicitly requested and clip it to
  `settings.max_response_chars // 2`.
* `Event.rest_body` is never projected. It records request bodies, which can
  contain passwords and tokens that were sent to the controller by other clients.
  This is a hard rule, not a preference.
* Default sort is newest first (`s_reported_at=desc` or the tag Part B names).

## Test requirements

SPEC.md 10.2 plus:

* `test_security_events_kind_selects_path_and_filter_tags` — one case per kind,
  asserting the exact `f_*` parameter names
* `test_security_events_time_window_trims_client_side`
* `test_threat_detail_omits_packet_by_default`
* `test_threat_detail_packet_is_clipped_when_requested`
* `test_system_events_never_project_rest_body` — plant a password in
  `rest_body` in the fixture and assert it is absent from the serialised result

## Gate

```bash
make verify
```

`make spec` must report **29 tools introspected**, zero violations.

## Stop here
Report the tool count and gate result. Do not start Phase 6.
