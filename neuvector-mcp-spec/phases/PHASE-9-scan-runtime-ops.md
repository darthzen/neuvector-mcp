# PHASE 9 — `scan_ops` and `runtime_ops` toolsets (11 tools)

**Read only this file plus:**

* `SPEC.md` sections 6, 7.4, 11, 12
* `tools/PART-D-scanops-runtimeops-iam-system.md` — the invariants section,
  **D.0**, and the **`Toolset scan_ops`** and **`Toolset runtime_ops`** sections
* `appendix/B-schema-reference.md`, `appendix/C-error-taxonomy.md`,
  `appendix/D-api-conventions.md` D.7

## Goal

Two new files: `src/neuvector_mcp/tools/scan_ops.py` (7 tools) and
`src/neuvector_mcp/tools/runtime_ops.py` (4 tools), both registered in
`server.py`.

## Tools

### `scan_ops`

| Tool | Endpoint(s) | `destructiveHint` |
|---|---|---|
| `nv_trigger_scan` | `POST /v1/scan/workload/{id}`, `POST /v1/scan/host/{id}`, `POST /v1/scan/registry/{name}/scan` | `False` |
| `nv_stop_registry_scan` | `DELETE /v1/scan/registry/{name}/scan` | `False` |
| `nv_scan_repository` | `POST /v1/scan/repository` | `False` |
| `nv_create_registry` | `POST /v2/scan/registry` | `False` |
| `nv_update_registry` | `PATCH /v2/scan/registry/{name}` | `False` |
| `nv_delete_registry` | `DELETE /v1/scan/registry/{name}` | `True` |
| `nv_trigger_bench_run` | `POST /v1/bench/host/{id}/kubernetes`, `.../docker` | `False` |

### `runtime_ops`

| Tool | Endpoint | `destructiveHint` |
|---|---|---|
| `nv_quarantine_workload` | `POST /v1/workload/request/{id}` | `True` |
| `nv_set_service_mode` | `PATCH /v1/service/config`, `/network`, `/profile` | `False` |
| `nv_start_packet_capture` | `POST /v1/sniffer` | `False` |
| `nv_stop_packet_capture` | `PATCH /v1/sniffer/stop/{id}` | `False` |

## Secret handling — the two-payload rule

Registry credentials pass through three of these tools. Part D section D.0
defines the normative mechanism and you must implement it exactly:

```
wire_payload  = the real body, with real credentials  -> client.request() ONLY
safe_payload  = redact_secrets(wire_payload)          -> the guard AND WriteOutcome.payload
confirm_token = sha256(op | target | canonical_json(safe_payload))[:12]
```

The token is computed over the **redacted** payload so that preview and execution
agree. The deliberate consequence, stated in Part D: changing only the secret does
not invalidate the token. That is accepted; document it in a comment so nobody
"fixes" it later and breaks the handshake.

`controller_response` is redacted for every tool in this phase.

## Asynchronous scans

`nv_trigger_scan` returns as soon as the controller accepts the request. It does
not wait and it must not poll. Its docstring tells the caller to read progress via
`nv_get_scan_status` (Phase 3). Use `settings.long_request_timeout_s` for the
request itself.

`nv_scan_repository` is the exception: it is synchronous, slow, and returns a full
report. Project and cap it exactly like `nv_get_scan_report`. Drop
`RESTScanRepoReport.envs` and `labels` — environment variables carry credentials.

## Packet capture

`GET /v1/sniffer/{id}/pcap` is **deliberately not exposed**. A binary pcap is not
a sane MCP result. `nv_start_packet_capture`'s docstring says so and tells the
operator to retrieve the capture out of band. Capture is privacy-sensitive; the
`effect` string must name the target workload and the filter.

## Quarantine

`nv_quarantine_workload` severs a running container's network. `destructiveHint=True`,
and the `effect` string says the container will lose network connectivity
immediately. The same endpoint un-quarantines; Part D names the exact field.

## Test requirements

Part D section D.1 names the functions. Minimum per tool: preview-sends-nothing
and confirmed-applies with the exact body. Plus:

* `test_scan_repository_password_not_logged`
* `test_create_registry_password_not_logged`
* `test_update_registry_password_not_logged`
* `test_preview_payload_shows_redacted_password`
* `test_read_only_hides_scan_ops_tools` and the same for `runtime_ops`

The secret-not-logged tests must use `capfd`, because structlog binds stderr with
`cache_logger_on_first_use=True` — `caplog` will not see the output. Part D
explains this.

## Gate

```bash
make verify
```

`make spec` must report **60 tools introspected**, zero violations.

## Stop here
Report the tool count and gate result. Do not start Phase 10.
