# PHASE 1 — Harden the core

**Read only this file plus `SPEC.md` sections 3, 5 and 7.2, and
`appendix/C-error-taxonomy.md`. Do not read other phases.**

## Goal

Add the two test modules that pin down `config.py` and `client.py` behaviour, so
later phases cannot silently break them. **No production code changes.** If a
test fails, the test is wrong — the reference core is the specification.

## Files you create

* `tests/test_config.py`
* `tests/test_client.py`

## `tests/test_config.py` — required tests

Use `monkeypatch.setenv` / `delenv`. Never mutate `os.environ` directly.

| Test | Asserts |
|---|---|
| `test_defaults_are_read_only` | With only `NV_CONTROLLER_URL`, `NV_API_ACCESS_KEY`, `NV_API_SECRET_KEY` set, `load_settings()` yields `read_only=True`, `transport="stdio"`, `toolsets == DEFAULT_TOOLSETS`, `require_confirm_token=True`. |
| `test_controller_url_must_have_scheme` | `NV_CONTROLLER_URL=nv.example:10443` raises `ValidationError`. |
| `test_controller_url_trailing_slash_stripped` | `https://x:10443/` → `https://x:10443`. |
| `test_apikey_mode_requires_both_keys` | `NV_AUTH_MODE=apikey` with only the access key raises. |
| `test_password_mode_requires_username_and_password` | `NV_AUTH_MODE=password` with neither raises. |
| `test_file_indirection` | `NV_API_SECRET_KEY_FILE` pointing at a `tmp_path` file whose content is `"s3cret\n"` yields `api_secret_key == "s3cret"` (stripped). |
| `test_direct_env_beats_file` | Both `NV_API_SECRET_KEY` and `..._FILE` set → the direct value wins. |
| `test_unknown_toolset_rejected` | `NV_TOOLSETS=inventory,bogus` raises, and the message lists the valid values. |
| `test_read_only_conflicts_with_mutating_toolset` | `NV_READ_ONLY=true` + `NV_TOOLSETS=policy_write` raises, and the message names `policy_write`. |
| `test_read_only_false_allows_mutating_toolset` | The same config with `NV_READ_ONLY=false` succeeds. |
| `test_bool_parsing` | `1`, `true`, `TRUE`, `yes`, `on` are all true; `0`, `false`, `no`, `off`, `""` are all false. |
| `test_settings_are_frozen` | Assigning to `settings.read_only` raises. |
| `test_redacted_hides_secrets` | `settings.redacted()["api_secret_key"] == "***REDACTED***"`, and the real secret string appears nowhere in `repr(settings.redacted())`. |
| `test_toolsets_split_is_read_or_write_never_both` | `MUTATING_TOOLSETS & READ_TOOLSETS == set()` and their union is `set(ALL_TOOLSETS)`. |

## `tests/test_client.py` — required tests

Build the client directly rather than through the server:

```python
settings = make_settings(**overrides)
http = NeuVectorClient.build_http_client(settings)
client = NeuVectorClient(settings, http)
```

Close it in a fixture with `await http.aclose()`.

### `build_query` (pure, no mocking)

| Test | Asserts |
|---|---|
| `test_build_query_paging` | `start=0, limit=50` → `{"start": "0", "limit": "50"}`. |
| `test_build_query_implicit_eq` | `filters={"domain": "prod"}` → `{"f_domain": "prod"}`. |
| `test_build_query_explicit_operator` | `filters={"high": "gte,5"}` → `{"f_high": "gte,5"}`. |
| `test_build_query_rejects_unknown_operator` | `filters={"x": "like,y"}` raises `ValueError` naming the valid operators. Rationale: the controller silently degrades an unknown operator to `eq`, which returns wrong data quietly — see `appendix/D-api-conventions.md` D.2.2. |
| `test_build_query_sort` | `sort={"reported_at": "desc"}` → `{"s_reported_at": "desc"}`; `"sideways"` raises. |
| `test_build_query_extra_booleans_lowercased` | `extra={"brief": True}` → `{"brief": "true"}`. |

### Auth

| Test | Asserts |
|---|---|
| `test_apikey_header_format` | A GET carries `X-Auth-Apikey: <access>:<secret>` and **no** `X-Auth-Token`. |
| `test_apikey_login_probes_summary` | `await client.login()` in apikey mode issues exactly one `GET /v1/system/summary` and sets `identity["mode"] == "apikey"`. |
| `test_password_login_posts_auth_and_caches_token` | `POST /v1/auth` body is `{"password": {"username": ..., "password": ...}}`; the following request carries `X-Auth-Token: <token>` and no apikey header. |
| `test_password_login_without_token_raises_auth_error` | A 200 response with `{"token": {}}` raises `AuthError`. |
| `test_logout_deletes_auth_in_password_mode` | `DELETE /v1/auth` is called once; in apikey mode it is not called at all. |

### Retry and re-login

| Test | Asserts |
|---|---|
| `test_retries_transient_status` | Two 503s then a 200 → exactly 3 calls, and the result is the 200 body. |
| `test_retries_transient_code` | HTTP 500 with `{"code": 11}` (cluster timeout) is retried. |
| `test_does_not_retry_permanent_code` | HTTP 404 with `{"code": 7}` raises `NotFoundError` after exactly **1** call. |
| `test_gives_up_after_three_attempts` | Three 503s → 3 calls, then raises. |
| `test_relogin_once_on_401_password_mode` | 401 then 200: exactly one extra `POST /v1/auth`, the original request retried once, total 401-path calls = 2. |
| `test_no_relogin_loop` | Persistent 401 in password mode → at most one re-login, then raises `AuthError`. |
| `test_no_relogin_in_apikey_mode` | 401 in apikey mode raises immediately with no `POST /v1/auth`. |

Patch `asyncio.sleep` (`monkeypatch.setattr("neuvector_mcp.client.asyncio.sleep", ...)`)
so retry tests do not actually wait.

### Envelopes and errors

| Test | Asserts |
|---|---|
| `test_empty_body_is_success` | A 200 with no content returns `{}`. |
| `test_get_list_unwraps_envelope` | `{"groups": [...]}` with key `groups` returns the list. |
| `test_get_list_missing_key_returns_empty` | `{}` returns `[]`, not `None` and not a raise. |
| `test_get_object_unwraps_envelope` | `{"group": {...}}` returns the dict. |
| `test_non_json_body_is_classified` | A 500 with `text/html` content still raises an `UpstreamError` and does not blow up in `.json()`. |
| `test_classify_prefers_code_over_status` | HTTP 500 with `{"code": 7}` classifies as `NotFoundError`, proving `code` beats status (D.4). |
| `test_error_message_includes_code_and_controller_text` | The raised message contains `code=25` and the controller's `error` string. |

## Gate

```bash
make verify
```

All four stages must pass: `lint`, `types`, `test`, `spec`. Coverage must be at
or above 85%.

Expected test count after this phase: **11 reference tests + your new ones**
(roughly 45 total). `make spec` still reports 5 tools.

## Stop here

Report the `make verify` output. Do not start Phase 2.
