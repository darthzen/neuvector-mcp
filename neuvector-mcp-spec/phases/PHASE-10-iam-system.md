# PHASE 10 — `iam_read`, `iam_write`, `system_write` toolsets (12 tools)

**Read only this file plus:**

* `SPEC.md` sections 6, 7.3, 7.4, 11, 12
* `tools/PART-B-events-policy-read-iam-read.md` — the **`Toolset iam_read`** section
* `tools/PART-D-scanops-runtimeops-iam-system.md` — **D.0** and the
  **`Toolset iam_write`** and **`Toolset system_write`** sections
* `appendix/B-schema-reference.md`, `appendix/C-error-taxonomy.md`

## Goal

Two new files: `src/neuvector_mcp/tools/iam.py` (4 read + 5 write tools) and
`src/neuvector_mcp/tools/system.py` (3 write tools), both registered in
`server.py`.

`tools/iam.py` registers **two** toolsets from one module. Its `register()`
therefore has two independent `if settings.toolset_enabled(...)` guards, not one.
Read tools go under `iam_read`, write tools under `iam_write`. A read tool tagged
`iam_write` fails gate rule R3.

## Tools

### `iam_read` (4)

| Tool | Endpoint |
|---|---|
| `nv_list_users` | `GET /v1/user` |
| `nv_list_roles` | `GET /v1/user_role` |
| `nv_list_auth_servers` | `GET /v1/server` |
| `nv_list_api_keys` | `GET /v1/api_key` |

### `iam_write` (5)

| Tool | Endpoint | `destructiveHint` |
|---|---|---|
| `nv_create_user` | `POST /v1/user` | `False` |
| `nv_update_user_role` | `PATCH /v1/user/{fullname}/role/{role}` | `False` |
| `nv_delete_user` | `DELETE /v1/user/{fullname}` | `True` |
| `nv_create_api_key` | `POST /v1/api_key` | `False` |
| `nv_delete_api_key` | `DELETE /v1/api_key/{accesskey}` | `True` |

### `system_write` (3)

| Tool | Endpoint | `destructiveHint` |
|---|---|---|
| `nv_update_system_config` | `PATCH /v2/system/config` | `False` |
| `nv_set_namespace_tags` | `PATCH /v1/domain/{name}` | `False` |
| `nv_update_scan_config` | `PATCH /v1/scan/config` | `False` |

## Secret handling — three distinct rules

| Secret | Rule |
|---|---|
| `RESTUser.password` on create | Two-payload rule from Phase 9: real value on the wire, `"***"` in the preview payload and in `WriteOutcome.payload`, token computed over the redacted form. **Never** projected on read. |
| `RESTApikey.apikey_secret` on create | **Returned to the caller** — that is the point of the tool, and the controller shows it once. Never logged; the audit record notes only that a key was created. Never retrievable afterwards, so `nv_list_api_keys` cannot and must not return it. |
| Auth server bind passwords and client secrets | `nv_list_auth_servers` uses an **allowlist** projection: only the fields Part B names are read by value; every other key is reported by name only, with name-matches on `password`/`secret`/`token`/`credential`/`private`/`key` diverted to a `redacted_keys` list. An allowlist, not a denylist — a controller upgrade that adds a secret field must fail closed. |

## `nv_update_system_config` — the one sanctioned pre-guard read

This tool performs a **read-only, failure-tolerant** `GET /v2/system/config`
before calling the guard, so its `effect` string can name each field as
`old -> new`. Part D section D.0.8 bounds this exception:

* the GET is the only network call permitted before the guard,
* a failure of that GET must not fail the tool — fall back to naming the new
  values only,
* the PATCH still happens only after confirmation.

`test_update_system_config_preview_reads_current_config_only` asserts exactly one
GET and zero PATCHes on the preview call. That test is what keeps this exception
from becoming a loophole.

Enumerate the highest-risk sub-fields in the docstring: cluster-wide enforcement
defaults, syslog destination, webhooks, and network settings.

## `nv_update_user_role`

Part D justifies choosing `PATCH /v1/user/{fullname}/role/{role}` over
`PATCH /v1/user/{fullname}`: the role travels in a verified path, and it avoids
sharing a request body with `password` and `email`. Keep that reasoning as a
comment.

## Error codes

| Code | Situation |
|---|---|
| 13 | Duplicate user or role name |
| 14 | Password does not satisfy the password profile |
| 15 | Name format rejected |
| 4 | Modifying a built-in role or the last admin |
| 25 | Namespace outside the identity's scope |

## Test requirements

Part D section D.1 and Part B name the functions. Minimum:

* every write tool: preview-sends-nothing, confirmed-applies with exact body
* `test_create_user_password_not_logged` (uses `capfd`)
* `test_create_user_preview_shows_redacted_password`
* `test_create_api_key_secret_returned_but_not_logged`
* `test_list_users_never_projects_password` — plant a password in the fixture,
  assert it is absent from the serialised result
* `test_list_api_keys_never_returns_secret`
* `test_auth_server_secret_fields_are_redacted_by_allowlist`
* `test_update_system_config_preview_reads_current_config_only`
* `test_read_only_hides_iam_write_and_system_write_but_keeps_iam_read`

## Gate

```bash
make verify
```

`make spec` must report **72 tools introspected**, zero violations. That is the
complete tool surface.

Also confirm the default read-only surface:

```bash
NV_READ_ONLY=true python3 -c "
import asyncio, sys; sys.path[:0]=['src','tests']
from conftest import make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.server import build_server
async def m():
    s = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    print(len(await s.list_tools(run_middleware=False)))
asyncio.run(m())"
```

Expected output: `41`.

## Stop here
Report both counts and the gate result. Do not start Phase 11.
