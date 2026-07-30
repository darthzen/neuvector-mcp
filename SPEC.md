# SPEC — NeuVector MCP Server

**Spec version:** 1.0.0
**Target NeuVector:** 5.6.x (API surface generated from `neuvector/neuvector` `main`)
**Implementer:** `qwen3-coder:30b` (or any coding model), driven phase by phase
**Definition of done:** `make verify` exits 0

---

## 0. Rules for the implementing model

These rules override any habit or preference. Violating one is a build failure,
not a style disagreement.

| # | Rule |
|---|---|
| **N1** | **Never invent a controller endpoint.** Every HTTP path you send must appear in `appendix/A-endpoint-inventory.md` section A.1, or in the `UNDOCUMENTED_ALLOWLIST` in `scripts/verify_spec.py`. If a phase asks for something you cannot find there, stop and write `BLOCKED: <what is missing>` in your output instead of guessing. |
| **N2** | **Never invent a response field.** Field names come from `appendix/B-schema-reference.md`. If a field you want is absent, it does not exist. |
| **N3** | **Copy the reference files verbatim.** Everything under `reference/` is already written, tested and passing. Do not rewrite, "improve", reformat or re-derive it. Phase 0 copies it; later phases only add new files and extend `server.py`'s registration list. |
| **N4** | **One phase at a time.** Read exactly one `phases/PHASE-N-*.md`, complete it, run its gate command, and stop. Do not read ahead. Do not start phase N+1 in the same pass. |
| **N5** | **Every new tool needs a test in the same phase.** A tool with no test fails gate rule R8. Write the test first if that helps. |
| **N6** | **No new dependencies.** The dependency set in `pyproject.toml` is fixed: `fastmcp`, `httpx`, `pydantic`, `structlog` at runtime; `pytest`, `pytest-asyncio`, `pytest-cov`, `respx`, `mypy`, `ruff` for development. Adding anything else fails review. |
| **N7** | **No network access in tests.** Every test runs against `respx`. A test that reaches a real host is a defect. |
| **N8** | **Never log a credential.** Argument *values* are never logged, only key names. See `reference/src/neuvector_mcp/audit.py`. |
| **N9** | **Follow the five-step mutating tool body exactly** (section 7.4). Do not call the controller before the guard returns. |
| **N10** | **Do not write to stdout.** On the `stdio` transport, stdout carries the MCP JSON-RPC framing. All diagnostics go to stderr. No `print()` in `src/`; `ruff` rule `T20` enforces this. |

---

## 1. What this server is

A Model Context Protocol server that exposes the **SUSE NeuVector container
security control plane** to MCP clients, so an operator or an agent can ask
questions like *"which prod workloads run images with critical CVEs and are still
in Discover mode"* and, with explicit confirmation, act on the answer.

### 1.1 In scope

* Read access across the whole controller API: inventory, vulnerability and scan
  data, compliance and CIS benchmark results, security events, and every policy
  object (network rules, process profiles, file monitors, DLP/WAF sensors,
  admission control, response rules).
* Mutating access to policy, admission control, scan operations, runtime
  enforcement actions, IAM and system configuration — each gated by a two-step
  confirmation handshake and disabled by default.
* Two transports from one codebase: `stdio` for local clients, authenticated
  streamable HTTP for in-cluster deployment.

### 1.2 Out of scope (do not implement)

* Federation (`/v1/fed/*`) — multi-cluster orchestration deserves its own server.
* Internal and debug routes (`/v1/debug/*`, `/v1/internal/*`) — unstable.
* IBM Security Advisor and CSP billing integrations.
* Any write path to the Kubernetes API. This server talks only to the NeuVector
  controller REST API.
* An LLM-facing "explain this CVE" feature. The server returns facts; the client
  model does the reasoning.

### 1.3 Why the shape is what it is

NeuVector's controller has **232 documented operations** over **396 response
types**. Three consequences drive the whole design:

1. **Tools are not endpoints.** One tool may front several sibling endpoints via
   a discriminator argument (`nv_get_scan_report(target=...)`), because a model
   picks correctly from one well-described tool more reliably than from four
   nearly-identical ones. Total tool count lands near 55, not 232.
2. **Responses must be projected.** A single `RESTWorkload` carries 40+ fields.
   Returning controller bodies verbatim exhausts a client's context after a
   handful of calls. Every tool returns a narrow Pydantic projection.
3. **Writes must be structurally hard.** The controller will happily switch a
   production namespace into `Protect` mode and start dropping traffic. The
   confirmation handshake in section 7.4 makes an accidental write impossible
   rather than merely unlikely.

---

## 2. Verified environment

Every version below was resolved and exercised in a live sandbox on
2026-07-29. The API surface in the appendices was generated from source, not
recalled.

| Component | Pinned version | How it was verified |
|---|---|---|
| Python | `>=3.12` (3.13 in the image) | openSUSE BCI `python:3.13` resolves to 3.13.13 |
| `fastmcp` | `3.4.5` | installed; `FastMCP.__init__`, `.tool()`, `.run()`, `list_tools()`, middleware and `StaticTokenVerifier` all introspected and exercised |
| `httpx` | `0.28.1` | installed |
| `pydantic` | `2.13.4` | installed |
| `structlog` | `26.1.0` | installed |
| `respx` | `0.23.1` | installed; used by the 11 passing reference tests |
| NeuVector API | 5.6.0 | `controller/api/apis.yaml` parsed: 232 operations, 396 definitions; `controller/rest/rest.go` parsed: 340 registered routes |

**FastMCP 3.x notes that matter**, because 2.x tutorials differ:

* `Transport` is `Literal["stdio", "http", "sse", "streamable-http"]`. Use
  `"stdio"` and `"http"`.
* `FastMCP(...)` accepts `lifespan`, `middleware`, `auth`, `mask_error_details`,
  `on_duplicate`, `version`, `instructions`.
* `@mcp.tool(name=..., annotations=..., tags=...)` — `annotations` takes
  `mcp.types.ToolAnnotations`.
* Server-side introspection is `await server.list_tools(run_middleware=False)`.
  There is no `get_tools()`.
* Lifespan value is reached from a tool as `ctx.request_context.lifespan_context`.
* Middleware hooks are `async def on_call_tool(self, context, call_next)`.
* HTTP auth uses `fastmcp.server.auth.providers.jwt.StaticTokenVerifier` or
  `JWTVerifier`.

---

## 3. Controller API conventions

Grounded in `controller/rest/rest.go` (`restParseQuery`) and
`controller/api/apis.go`. Full detail in `appendix/D-api-conventions.md`.

### 3.1 Authentication

| Mode | Header | Login required |
|---|---|---|
| API key (**default**) | `X-Auth-Apikey: <access_key>:<secret_key>` | No — stateless |
| Password | `X-Auth-Token: <token>` from `POST /v1/auth` | Yes |

The controller checks `X-Auth-Token` first and only falls back to
`X-Auth-Apikey`. **Never send both headers on one request.**

API keys carry an expiry (`expiration_timestamp`); an expired key returns
`code=3`. Password sessions expire on idle timeout; the client re-logs in exactly
once per 401 and never loops.

### 3.2 Query conventions — apply to every list endpoint

| Concern | Parameter | Notes |
|---|---|---|
| Paging offset | `start=<int>` | Negative values page **backwards**. Only send `>= 0`. |
| Page size | `limit=<int>` | `0` means controller default. |
| Filter | `f_<field>=<value>` | Implicit `eq`. |
| Filter with operator | `f_<field>=<op>,<value>` | `op` ∈ `eq neq in notin gt gte lt lte prefix`. Unknown ops are silently downgraded to `eq` by the controller — validate client-side instead. |
| Sort | `s_<field>=asc\|desc` | Any other value is ignored. |
| Verbosity | `brief`, `verbose`, `raw`, `with_cap` | Booleans. |
| Scope | `scope=local\|fed` | Policy, group, admission and system endpoints. |
| View | `view=pod\|pod_only` | Workload endpoints. |
| Accepted-only | `show=accepted` | Scan endpoints. |

`<field>` is the **JSON tag** of the response field, not a friendly name. At most
**8** filters and 8 sorts per request are honoured.

### 3.3 Response envelopes

Collections are wrapped under a key named after the resource:

```
GET /v1/group        -> {"groups":    [ ... ]}
GET /v1/group/{name} -> {"group":     { ... }}
GET /v2/workload     -> {"workloads": [ ... ]}
GET /v1/system/summary -> {"summary": { ... }}
```

`PATCH` and `DELETE` normally return `200` with an **empty body**. Treat an empty
body as success, not as an error.

### 3.4 Errors

```json
{"code": 7, "error": "Object not found", "message": "Group not found"}
```

`code` is a stable integer (upstream: *"Don't modify value or reorder"*); the HTTP
status is chosen per call site. **Branch on `code` first**, fall back to status
only when the body is missing or unparseable. Full table:
`appendix/C-error-taxonomy.md`.

---

## 4. Repository layout

Exactly this. No extra files, no missing ones.

```
neuvector-mcp/
├── pyproject.toml                 # from reference/, verbatim
├── Makefile                       # from reference/, verbatim
├── README.md
├── spec_endpoints.json            # from reference/, verbatim (generated allowlist)
├── src/neuvector_mcp/
│   ├── __init__.py                # __version__ only
│   ├── config.py         [P0]     # env -> Settings; no other module imports os.environ
│   ├── errors.py         [P0]     # controller code -> ToolError subclass
│   ├── client.py         [P0]     # httpx wrapper, auth, retry, build_query
│   ├── models.py         [P0+]    # output projections; every phase appends
│   ├── context.py        [P0]     # AppContext + app_context(ctx)
│   ├── guard.py          [P0]     # authorise_write / confirm_token
│   ├── audit.py          [P0]     # configure_logging + AuditMiddleware
│   ├── server.py         [P0+]    # assembly; every phase appends to TOOL_MODULES
│   └── tools/
│       ├── __init__.py
│       ├── inventory.py      [P2]
│       ├── vulnerability.py  [P3]
│       ├── compliance.py     [P4]
│       ├── events.py         [P5]
│       ├── policy_read.py    [P6]
│       ├── policy_write.py   [P7]
│       ├── admission.py      [P8]
│       ├── scan_ops.py       [P9]
│       ├── runtime_ops.py    [P9]
│       ├── iam.py            [P10]
│       └── system.py         [P10]
├── tests/
│   ├── conftest.py                # from reference/, verbatim
│   ├── fixtures/*.json            # one per controller response shape
│   ├── test_config.py    [P1]
│   ├── test_client.py    [P1]
│   ├── test_guard.py     [P0]     # from reference/, verbatim
│   └── test_<toolset>.py [P2..P10]
├── scripts/
│   ├── verify_spec.py             # from reference/, verbatim
│   └── smoke_stdio.py             # from reference/, verbatim
└── deploy/
    ├── Dockerfile                 # from reference/, verbatim (openSUSE BCI)
    ├── deployment.yaml            # from reference/, verbatim
    └── fleet.yaml                 # from reference/, verbatim
```

### 4.1 Dependency direction

```
config ──▶ (nothing)
errors ──▶ (fastmcp only)
models ──▶ (pydantic only)
client ──▶ config, errors
guard  ──▶ config, errors, models
audit  ──▶ config
context──▶ config, client
tools/*──▶ context, models, guard, client, errors, config
server ──▶ everything
```

A `tools/*` module importing another `tools/*` module is a defect. Shared helpers
go in `models.py` or a new `tools/_common.py`, never sideways.

---

## 5. Configuration

Every knob is an environment variable prefixed `NV_`. Each also accepts
`NV_<NAME>_FILE` pointing at a file whose contents are the value, so Kubernetes
Secrets can be mounted rather than injected.

| Variable | Default | Meaning |
|---|---|---|
| `NV_CONTROLLER_URL` | `https://127.0.0.1:10443` | Controller REST base URL. Must start `http://` or `https://`. |
| `NV_VERIFY_TLS` | `true` | Set `false` for the controller's default self-signed cert. |
| `NV_CA_BUNDLE` | — | Path to a CA bundle; takes precedence over `NV_VERIFY_TLS`. |
| `NV_REQUEST_TIMEOUT_S` | `30` | Normal calls. |
| `NV_LONG_REQUEST_TIMEOUT_S` | `300` | Scan, bench and repository-scan calls. |
| `NV_AUTH_MODE` | `apikey` | `apikey` or `password`. |
| `NV_API_ACCESS_KEY` / `NV_API_SECRET_KEY` | — | Required when `apikey`. |
| `NV_USERNAME` / `NV_PASSWORD` | — | Required when `password`. |
| `NV_TRANSPORT` | `stdio` | `stdio` or `http`. |
| `NV_HTTP_HOST` / `NV_HTTP_PORT` / `NV_HTTP_PATH` | `0.0.0.0` / `8080` / `/mcp` | HTTP transport binding. |
| `NV_HTTP_BEARER_TOKENS` | — | **Required for `http`.** `token:scope\|scope,token2:scope`. |
| `NV_READ_ONLY` | `true` | `true` refuses every mutation and hides mutating toolsets. |
| `NV_TOOLSETS` | the six read toolsets | Comma-separated; see 5.1. |
| `NV_REQUIRE_CONFIRM_TOKEN` | `true` | `false` removes the two-step handshake. Only for automation with its own approval gate. |
| `NV_ALLOWED_NAMESPACES` | — | When set, mutations outside these namespaces are refused. |
| `NV_ALLOW_UNDOCUMENTED` | `false` | Gates tools that use non-Swagger routes. |
| `NV_MAX_ITEMS` | `200` | Hard cap on any list tool's page size. |
| `NV_MAX_RESPONSE_CHARS` | `60000` | Truncation budget per tool result. |
| `NV_LOG_LEVEL` | `INFO` | |
| `NV_LOG_FORMAT` | `json` | `json` or `console`. |
| `NV_AUDIT_LOG_PATH` | — | Optional second sink for audit records. |

### 5.1 Toolsets

A toolset is either read-only or mutating; **never mixed**. `verify_spec.py`
derives each tool's `readOnlyHint` from its toolset, so a read tool tagged with a
mutating toolset fails rule R3.

| Toolset | Kind | Default | Contents |
|---|---|---|---|
| `inventory` | read | on | workloads, hosts, groups, services, enforcers, namespaces, network conversations |
| `vulnerability` | read | on | image/workload/host scan reports, registries, scanners, vulnerability profiles |
| `compliance` | read | on | workload/host compliance, CIS bench reports, compliance profiles |
| `events` | read | on | threats, violations, incidents, audits, system events, alerts |
| `policy_read` | read | on | network rules, process/file profiles, DLP/WAF sensors, response rules, admission state and rules, admission rule assessment |
| `iam_read` | read | on | users, roles, auth servers, API keys (metadata only) |
| `policy_write` | write | **off** | create/update/delete groups, network rules, process and file-monitor profiles |
| `admission` | write | **off** | admission control state and rules |
| `scan_ops` | write | **off** | trigger/stop scans, registry CRUD, repository scan, bench runs |
| `runtime_ops` | write | **off** | quarantine, service mode changes, packet capture |
| `iam_write` | write | **off** | user, role and API key mutations |
| `system_write` | write | **off** | system config, namespace tags, scan config |

`NV_READ_ONLY=true` together with any mutating toolset is a **startup error**,
not a silent downgrade. Fail loudly on contradictory configuration.

---

## 6. Safety model

Five independent layers. A mutation must clear all five.

```
 ┌─ 1. Transport auth ── HTTP requires a bearer token; stdio inherits process trust
 ├─ 2. Controller RBAC ─ the API key's NeuVector role is the real ceiling
 ├─ 3. NV_READ_ONLY ──── mutating toolsets are not registered at all
 ├─ 4. NV_TOOLSETS ───── unenabled toolsets are absent from tools/list
 └─ 5. Confirm token ─── per-operation, payload-bound, two-step handshake
```

Layer 2 is the one that actually protects the cluster: **provision the API key
with the least NeuVector role that satisfies the enabled toolsets.** Read-only
deployments use the `reader` role. The other four layers protect against model
error, not against a compromised credential.

### 6.1 Confirmation handshake

```
model → nv_set_group_policy_mode(group_name="nv.api.prod", mode="Protect")
server ← {status: "confirmation_required",
          effect: "Set policy mode of group 'nv.api.prod' to Protect. Traffic and
                   process activity outside the learned policy will be blocked
                   immediately.",
          payload: {config: {name: "nv.api.prod", policy_mode: "Protect"}},
          confirm_token: "a3f19c2b7e04",
          next_step: "... call again with confirm='a3f19c2b7e04'"}
          ← nothing was sent to the controller

model → nv_set_group_policy_mode(group_name="nv.api.prod", mode="Protect",
                                 confirm="a3f19c2b7e04")
server ← {status: "applied", ...}
```

The token is `sha256(operation | target | canonical_json(payload))[:12]`. Change
any argument and the token no longer matches, so a model cannot reuse a token
from a different operation. This is a **guard rail, not a security boundary** —
the model can compute it in principle; the point is that it cannot do so
*accidentally*.

### 6.2 Destructive-operation classification

| Class | `destructiveHint` | Examples |
|---|---|---|
| Reversible config change | `false` | set policy mode, update system config |
| Object creation | `false` | create group, create registry, create user |
| Data-destroying | `true` | delete group, delete rule, delete registry, delete user |
| Traffic-affecting | `true` | quarantine workload, set admission control to deny |

---

## 7. Implementation contracts

### 7.1 `config.py`

Copy `reference/src/neuvector_mcp/config.py` verbatim. Its contract:
`load_settings() -> Settings` reads the environment; `Settings` is frozen and
validates cross-field consistency. **No other module reads `os.environ`.**

### 7.2 `client.py`

Copy `reference/src/neuvector_mcp/client.py` verbatim. Public surface:

```python
def build_query(*, start=None, limit=None, filters=None, sort=None, extra=None) -> dict[str, str]
class NeuVectorClient:
    @classmethod
    def build_http_client(cls, settings: Settings) -> httpx.AsyncClient
    async def login(self) -> dict[str, Any]
    async def logout(self) -> None
    async def request(self, method, path, *, params=None, json=None,
                      timeout_s=None, authenticated=True) -> Any
    async def get_list(self, path, envelope_key, *, params=None) -> list[Any]
    async def get_object(self, path, envelope_key, *, params=None) -> dict[str, Any]
```

Behaviour that tests depend on:

* 3 attempts with 0.5s / 1.0s exponential backoff, **retrying only** transient
  failures (HTTP 502/503/504, or `code` ∈ {8, 9, 11, 19, 24, 55}).
* Exactly one re-login on HTTP 401 in `password` mode, then the original request
  is retried once. Never a second time.
* Non-retryable non-2xx raises immediately via `errors.classify`.
* An empty 2xx body returns `{}`.

### 7.3 Read tool body — the canonical shape

```python
@mcp.tool(name="nv_list_<things>", annotations=READ_ONLY, tags={"<toolset>", "read"})
async def nv_list_things(
    ctx: Context,
    <filter args with Annotated[..., Field(description=...)]>,
    start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
    limit: Annotated[int, Field(ge=1, le=1000, description="...")] = 50,
) -> ThingList:
    """<One-line summary of what this returns.>

    <Two or three lines of guidance: when to reach for this, what to call first
    to obtain the identifiers it needs, what the result is good for.>

    Calls GET /v1/<path> with <the filters it applies>.
    """
    app = app_context(ctx)
    effective_limit = min(limit, app.settings.max_items)
    filters = {...}                                    # only non-None args
    params = build_query(start=start, limit=effective_limit + 1, filters=filters)
    items = await app.client.get_list("/v1/<path>", "<envelope>", params=params)
    truncated = len(items) > effective_limit
    page_items = items[:effective_limit]
    return ThingList(
        page=Page(start=start, returned=len(page_items), truncated=truncated,
                  hint=... if truncated else None),
        things=[Thing.from_api(i) for i in page_items],
    )
```

The **over-fetch by one** is mandatory: NeuVector list endpoints do not return a
total count, so requesting `limit+1` is the only way to know whether more exist.

### 7.4 Mutating tool body — the five steps, in order

```python
@mcp.tool(name="nv_<verb>_<thing>", annotations=MUTATING, tags={"<toolset>", "write"})
async def nv_verb_thing(
    ctx: Context,
    <target and payload args>,
    confirm: Annotated[str | None, Field(description="Confirmation token ...")] = None,
) -> WriteOutcome:
    """<One line: what changes.>

    <Two or three lines: the blast radius, stated plainly. What breaks if this is
    wrong. Any controller precondition, with its error code.>

    Calls <METHOD> /v1/<path> with <payload shape>.
    """
    app = app_context(ctx)
    payload = {...}                                     # 1. build payload
    plan = authorise_write(                             # 2. guard
        app.settings, operation="nv_verb_thing", toolset="<toolset>",
        target=<identifier>, effect="<one sentence>", payload=payload,
        confirm=confirm, namespace=<namespace or None>,
    )
    if plan is not None:                                # 3. return plan verbatim
        return plan
    response = await app.client.request(<METHOD>, "/v1/<path>", json=payload)  # 4.
    return WriteOutcome(                                # 5. report
        status="applied", operation="nv_verb_thing", target=<identifier>,
        effect="<past tense>", payload=payload,
        controller_response=response if isinstance(response, dict) else {},
    )
```

Steps 1–3 must precede any network call. `test_guard.py::test_first_call_returns_plan_and_sends_nothing`
asserts `route.call_count == 0` on the preview call; that assertion is the gate.

### 7.5 Output models

* Live in `models.py`. Each phase **appends**; nothing is rewritten.
* `model_config = ConfigDict(extra="ignore", frozen=True)` on read projections.
  `WriteOutcome` is not frozen.
* Each model provides `@classmethod from_api(cls, raw: dict) -> Self` doing all
  projection and coercion. Tool bodies never index into raw dicts.
* Every field carries a `Field(description=...)`. The description is what a
  client model reads; an undescribed field is a defect.
* Never return `dict[str, Any]` from a tool. Rule R7 fails it.

### 7.6 Tool descriptions

The docstring **is** the tool description and is the single highest-leverage
artefact in this project. Required structure:

1. **Line 1** — what the tool returns or does, one sentence, no preamble.
2. **Body** — when to use it, what to call first for identifiers, what the caller
   must know to interpret the result. For mutations: the blast radius.
3. **Last line** — `Calls <METHOD> <path>[ with <payload>].` One line per
   endpoint the tool may hit. `verify_spec.py` R6 parses these and checks them
   against the endpoint allowlist, so the format is not decorative.

---

## 8. Tool catalogue

Complete contracts, argument by argument, are in `TOOLS.md`. Summary:

| Toolset | Tools | Count |
|---|---|---|
| `inventory` | `nv_get_system_summary`, `nv_whoami`, `nv_list_workloads`, `nv_get_workload`, `nv_list_hosts`, `nv_list_groups`, `nv_get_group`, `nv_list_services`, `nv_list_enforcers`, `nv_list_namespaces`, `nv_get_network_conversations` | 11 |
| `vulnerability` | `nv_list_image_scan_summaries`, `nv_get_scan_report`, `nv_get_scan_status`, `nv_list_scanners`, `nv_list_registries`, `nv_list_registry_images`, `nv_get_vulnerability_profile` | 7 |
| `compliance` | `nv_get_compliance_findings`, `nv_get_bench_report`, `nv_list_compliance_profiles`, `nv_get_compliance_profile` | 4 |
| `events` | `nv_query_security_events`, `nv_get_threat_detail`, `nv_query_audit_events`, `nv_query_system_events`, `nv_get_system_alerts` | 5 |
| `policy_read` | `nv_list_network_rules`, `nv_get_network_rule`, `nv_get_process_profile`, `nv_get_file_monitor_profile`, `nv_list_response_rules`, `nv_list_dlp_sensors`, `nv_list_waf_sensors`, `nv_get_admission_state`, `nv_list_admission_rules`, `nv_assess_admission_rule` | 10 |
| `iam_read` | `nv_list_users`, `nv_list_roles`, `nv_list_auth_servers`, `nv_list_api_keys` | 4 |
| `policy_write` | `nv_create_group`, `nv_update_group_criteria`, `nv_delete_group`, `nv_set_group_policy_mode`, `nv_apply_network_rule_changes`, `nv_delete_network_rule`, `nv_update_process_profile`, `nv_update_file_monitor_profile` | 8 |
| `admission` | `nv_set_admission_state`, `nv_create_admission_rule`, `nv_update_admission_rule`, `nv_delete_admission_rule` | 4 |
| `scan_ops` | `nv_trigger_scan`, `nv_stop_registry_scan`, `nv_scan_repository`, `nv_create_registry`, `nv_update_registry`, `nv_delete_registry`, `nv_trigger_bench_run` | 7 |
| `runtime_ops` | `nv_quarantine_workload`, `nv_set_service_mode`, `nv_start_packet_capture`, `nv_stop_packet_capture` | 4 |
| `iam_write` | `nv_create_user`, `nv_update_user_role`, `nv_delete_user`, `nv_create_api_key`, `nv_delete_api_key` | 5 |
| `system_write` | `nv_update_system_config`, `nv_set_namespace_tags`, `nv_update_scan_config` | 3 |
| | **total** | **72** |

Default (read-only) surface: **41 tools**.

---

## 9. Server instructions string

`server.py` sets `instructions=` on the `FastMCP` constructor. That text is the
only guidance a client model gets before it starts calling tools, so it earns the
same care as a tool description. The reference `INSTRUCTIONS` constant is
normative — copy it, and extend it only when a phase says to.

---

## 10. Test harness

### 10.1 Principles

* **Offline, always.** `respx` intercepts every request. No live host, no
  `--integration` marker, no conditional skips.
* **Fixtures are real shapes.** Each `tests/fixtures/<name>.json` matches the
  schema in Appendix B for the endpoint it stands in for. Invented field names
  make the tests worthless.
* **Assert the request, not just the response.** Every list-tool test asserts the
  outgoing query parameters. Getting `f_domain` wrong is the most likely defect
  and a response-only assertion cannot catch it.
* **In-process client.** `async with Client(build_server(settings)) as c` exercises
  the full MCP path: schema generation, validation, middleware, serialisation.

### 10.2 Required coverage per tool

| Test | Applies to | Asserts |
|---|---|---|
| happy path | every tool | projection is correct, envelope unwrapped |
| query construction | every list tool | exact `f_*` / `s_*` / `start` / `limit` / `extra` params |
| truncation | every list tool | `limit+1` over-fetch, `truncated=True`, hint text |
| not found | every get-by-id tool | empty envelope raises `NotFoundError` |
| error classification | ≥1 per module | `code=25` → permission error, `code=7` → not found |
| preview sends nothing | every mutating tool | `route.call_count == 0` |
| confirmed applies | every mutating tool | exact JSON body, `call_count == 1` |
| token binding | ≥1 per mutating module | a token for different args is rejected |
| read-only hiding | once per mutating module | tool absent from `list_tools()` |

### 10.3 Coverage gate

`fail_under = 85` on branch coverage. Not negotiable downward.

---

## 11. Observability

* One structured record per tool call: `tool`, `arg_keys` (**names only**),
  `confirmed`, `outcome`, `duration_ms`, and on failure `error_class` + truncated
  `error`.
* One record per controller login and one per connection failure.
* stderr only. JSON by default.
* Argument *values* are never logged. Registry passwords, user passwords and
  bearer tokens all pass through tool arguments.

---

## 12. Gate rules (`scripts/verify_spec.py`)

| Rule | Requirement |
|---|---|
| **R1** | Tool name matches `^nv_[a-z0-9_]+$`. |
| **R2** | Description has ≥3 lines and ≥80 characters. |
| **R3** | `ToolAnnotations` present; `readOnlyHint` agrees with the toolset kind. |
| **R4** | Exactly one toolset tag from `ALL_TOOLSETS`. |
| **R5** | Mutating tools accept `confirm`; read tools do not. |
| **R6** | Every `Calls <METHOD> <path>` line resolves to a documented route, or to an entry in `UNDOCUMENTED_ALLOWLIST` with a written justification. |
| **R7** | A structured output schema is declared (no bare `dict` returns). |
| **R8** | The tool's name appears in at least one test file. |
| **R9** | With all toolsets enabled, at least one mutating tool is registered. |

`make verify` = `lint` + `types` + `test` + `spec`. CI runs exactly that. Any
non-zero exit is a failed build.

---

## 13. Deployment

`stdio` for desktop clients, authenticated `http` in-cluster. Both from the same
image.

* **Base image: openSUSE BCI** (`registry.opensuse.org/opensuse/bci/python:3.13`),
  or `registry.suse.com/bci/python:3.13` for a SUSE-supported lifecycle. No other
  base is permitted.
* Two-stage build; no compilers in the runtime layer.
* uid/gid `10001`, `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities
  dropped, `automountServiceAccountToken: false`.
* `NetworkPolicy` allows egress to the controller port and DNS, nothing else.
* Liveness/readiness are **TCP probes**. The MCP endpoint requires a bearer
  token, so an HTTP probe would always fail.
* Controller credentials and client bearer tokens live in two separate Secrets.
  `deploy/fleet.yaml` excludes both from Fleet's diff so GitOps never reverts
  them.

### 13.1 NeuVector API key provisioning

1. NeuVector UI → **Settings → API Keys → Add**.
2. Role: `reader` for read-only deployments. For mutating toolsets, the narrowest
   role that covers them — `admin` only when `iam_write` or `system_write` is on.
3. Set an expiry and calendar the rotation. An expired key surfaces as `code=3`.
4. Store `apikey_name` as `NV_API_ACCESS_KEY` and `apikey_secret` as
   `NV_API_SECRET_KEY`. The secret is shown **once**.

---

## 14. Phase plan

Each phase is a self-contained work order in `phases/`. Read one, do it, run its
gate, stop.

| Phase | Deliverable | Gate |
|---|---|---|
| **0** | Copy the reference core; 11 tests green | `make test && make spec` |
| **1** | `test_config.py`, `test_client.py` — harden the core | `make verify` |
| **2** | `tools/inventory.py` — 11 tools | `make verify` |
| **3** | `tools/vulnerability.py` — 7 tools | `make verify` |
| **4** | `tools/compliance.py` — 4 tools | `make verify` |
| **5** | `tools/events.py` — 5 tools | `make verify` |
| **6** | `tools/policy_read.py` — 10 tools | `make verify` |
| **7** | `tools/policy_write.py` — 8 tools | `make verify` |
| **8** | `tools/admission.py` — 4 tools | `make verify` |
| **9** | `tools/scan_ops.py` + `tools/runtime_ops.py` — 11 tools | `make verify` |
| **10** | `tools/iam.py` + `tools/system.py` — 12 tools | `make verify` |
| **11** | Container, manifests, live smoke test, README | `make verify && make image` |

A phase is complete when its gate passes **and** the tool count in
`verify_spec.py` output matches the phase's target.

---

## 15. Appendices

| File | Contents |
|---|---|
| `appendix/A-endpoint-inventory.md` | All 232 documented operations with request/response schema names; plus the 112 registered-but-undocumented routes |
| `appendix/B-schema-reference.md` | Field-level reference for the 100+ request/response types this server touches |
| `appendix/C-error-taxonomy.md` | Controller error codes 1–55 with their exact strings |
| `appendix/D-api-conventions.md` | Auth, paging, filtering, sorting, envelopes, scope/view/show — with source citations |
| `TOOLS.md` | Every tool's arguments, return model, endpoint mapping and annotations |
| `reference/` | The working, tested core to copy in Phase 0 |
