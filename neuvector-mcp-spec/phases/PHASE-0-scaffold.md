# PHASE 0 — Scaffold from the reference core

**Read only this file and the files it names. Do not read other phases.**

## Goal

Stand up the repository with the already-written, already-tested core. You write
**no new logic** in this phase. You copy, wire and prove.

## Why nothing is written from scratch here

Everything under `reference/` was implemented and executed in a sandbox: 11 tests
pass and all 9 gate rules pass. Re-deriving it introduces defects and wastes the
budget. Copy it byte for byte.

## Steps

### 1. Create the tree

```
neuvector-mcp/
├── pyproject.toml
├── Makefile
├── README.md
├── spec_endpoints.json
├── src/neuvector_mcp/
│   ├── __init__.py
│   ├── config.py
│   ├── errors.py
│   ├── client.py
│   ├── models.py
│   ├── context.py
│   ├── guard.py
│   ├── audit.py
│   ├── server.py
│   └── tools/
│       ├── __init__.py
│       ├── inventory.py
│       └── policy_write.py
├── tests/
│   ├── conftest.py
│   ├── fixtures/system_summary.json
│   ├── fixtures/workloads_v2.json
│   ├── test_inventory.py
│   └── test_guard.py
├── scripts/
│   ├── verify_spec.py
│   └── smoke_stdio.py
└── deploy/
    ├── Dockerfile
    ├── deployment.yaml
    └── fleet.yaml
```

### 2. Copy every file from `reference/` to the matching path

Verbatim. No reformatting, no renaming, no "cleanup". If your editor reflows
lines or strips trailing whitespace, fix it back.

The only file you may extend later is `server.py` (its `TOOL_MODULES` import and
loop) and `models.py` (append-only).

### 3. Install

```bash
python3 -m pip install -e '.[dev]'
```

### 4. Prove it

```bash
make test     # expect: 11 passed
make spec     # expect: 5 tools introspected, R1-R9 all ok
```

## Gate

Both commands above must succeed with exactly those outcomes:

* `make test` → `11 passed`
* `make spec` → `verify_spec: 5 tools introspected` and zero violations across
  R1–R9

If `make spec` reports a different tool count, a `register()` call is missing from
`server.py` or a copy is incomplete.

## What exists after this phase

| Module | Provides |
|---|---|
| `config.py` | `Settings`, `load_settings()`, `ALL_TOOLSETS`, `DEFAULT_TOOLSETS`, `MUTATING_TOOLSETS`, `READ_TOOLSETS` |
| `errors.py` | `classify()`, `is_retryable()`, the error code constants, the `ToolError` subclasses |
| `client.py` | `build_query()`, `NeuVectorClient` with auth, retry and envelope unwrapping |
| `models.py` | `Page`, `WorkloadBrief`, `WorkloadList`, `SystemSummary`, `WriteOutcome` |
| `context.py` | `AppContext`, `app_context(ctx)` |
| `guard.py` | `confirm_token()`, `authorise_write()` |
| `audit.py` | `configure_logging()`, `AuditMiddleware`, `redact()` |
| `server.py` | `build_server()`, `lifespan`, `main()`, the `INSTRUCTIONS` string |
| `tools/inventory.py` | `nv_get_system_summary`, `nv_list_workloads`, `nv_get_workload` |
| `tools/policy_write.py` | `nv_set_group_policy_mode`, `nv_delete_group` |

Five of the 72 tools are already done. The remaining phases add the other 67.

## Stop here

Do not start Phase 1. Report the two gate outcomes and wait.
