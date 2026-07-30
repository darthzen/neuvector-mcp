# Appendix D — NeuVector controller API conventions

Every statement here was read out of the upstream source, not recalled. Source
paths are relative to `github.com/neuvector/neuvector` at `main`
(API version 5.6.0).

---

## D.1 Authentication

Source: `controller/api/apis.go` (header constants), `controller/rest/auth.go`
(`restReq2User`, lines ~611-700).

```go
const RESTTokenHeader   string = "X-Auth-Token"
const RESTAPIKeyHeader  string = "X-Auth-Apikey"
const RESTRancherTokenHeader string = "X-R-Sess"
const RESTNvPageHeader  string = "X-Nv-Page"
const RESTMaskedValue   string = "The value is masked"
```

### D.1.1 Resolution order

`restReq2User` resolves the caller in this order:

1. On Kubernetes + Rancher flavour, read `X-R-Sess` for Rancher SSO.
2. Read `X-Auth-Token`. If present with exactly one value, it is a session token.
3. **Only if `X-Auth-Token` is absent**, read `X-Auth-Apikey`.

**Therefore: never send both headers.** `X-Auth-Token` wins and the API key is
ignored, which produces confusing 401s when the token has expired.

### D.1.2 API key format

`X-Auth-Apikey: <access_key>:<secret_key>`

The value is split on `:` and must yield exactly two parts. `access_key` is the
key's `apikey_name`; `secret_key` is the `apikey_secret` returned once at
creation. The controller:

* looks the key up, hashes the supplied secret (salted format `…-<salt>-…`, with a
  legacy unsalted path that is transparently upgraded);
* checks `expiration_timestamp` against now and returns a timeout failure when
  past;
* derives the effective role map from `role` plus `role_domains`.

No login call is needed or possible — API key auth is stateless per request. To
fail fast on a bad key at startup, issue one cheap authenticated read
(`GET /v1/system/summary`).

### D.1.3 Password login

`POST /v1/auth` with `RESTAuthData`:

```json
{"password": {"username": "admin", "password": "…"}}
```

Response `RESTTokenData`:

```json
{"token": {"token": "<jwt>", "global_permissions": [...], "domain_permissions": {...},
           "fullname": "admin", ...},
 "password_days_until_expire": 89,
 "password_hours_until_expire": 3,
 "need_to_reset_password": false}
```

Notes:

* `password_days_until_expire` is negative when unknown (LDAP/SAML/OIDC logins).
* Both `days` and `hours` at `0` means the password has **already expired**.
* `RESTAuthData.Token` (capital T in the JSON tag: `"Token"`) is the SAML/OIDC
  path; unused by this server.
* `POST /v1/auth/{server}` authenticates against a named external auth server.
* `DELETE /v1/auth` logs out. `PATCH /v1/auth` refreshes.

---

## D.2 Query conventions

Source: `controller/rest/rest.go` `restParseQuery` (line 497), constants in
`controller/api/apis.go` lines 77-109.

```go
const FilterPrefix string = "f_"
const SortPrefix   string = "s_"
const PageStart    string = "start"
const PageLimit    string = "limit"
const BriefFlag    string = "brief"
const VerboseFlag  string = "verbose"
const RawFlag      string = "raw"
const WithCapFlag  string = "with_cap"
const OPeq  = "eq"    const OPneq = "neq"
const OPin  = "in"    const OPnotin = "notin"
const OPgt  = "gt"    const OPgte = "gte"
const OPlt  = "lt"    const OPlte = "lte"
const OPprefix = "prefix"
const SortAsc  = "asc"  const SortDesc = "desc"
```

### D.2.1 Paging

| Parameter | Parsing behaviour |
|---|---|
| `start` | `strconv.Atoi`. `>= 0` sets the offset. **A negative value sets `start = -value` and flips the query to backward paging.** Non-numeric values are silently ignored. |
| `limit` | `strconv.Atoi`, applied only when `>= 0`. `0` leaves the controller default in place. |

There is **no total-count field** in any list response. To detect "more exist",
request `limit + 1` and check whether you got `limit + 1` items back. This is why
every list tool in this project over-fetches by one.

### D.2.2 Filtering

`f_<json_tag>=<value>` — implicit `eq`.
`f_<json_tag>=<op>,<value>` — explicit operator.

Parsing detail that matters:

* The value is split on `,`. With one part, the operator is `eq`. With two or
  more, part 0 is the operator and part 1 is the value.
* **An unrecognised operator silently degrades to `eq`.** The controller does not
  reject it. Validate the operator client-side or you will get wrong answers
  quietly. `build_query` in `client.py` raises `ValueError` for this reason.
* A value containing a comma cannot be expressed — the split is unconditional.
* `<json_tag>` is the **JSON field name of the response type**, not a friendly
  alias. Look it up in Appendix B.

### D.2.3 Sorting

`s_<json_tag>=asc` or `s_<json_tag>=desc`. Any other value is dropped silently.

### D.2.4 Field limits

Both filters and sorts are capped at `MaxFilelds` (upstream spelling) per
request. Excess entries are **discarded silently**, not rejected. Keep filter
count small and deterministic.

### D.2.5 Flags and endpoint-specific pairs

`brief`, `verbose`, `raw`, `with_cap` are parsed with `strconv.ParseBool`.
Anything not matching a known key or prefix lands in a generic `pairs` map, which
individual handlers read:

| Key | Values | Used by |
|---|---|---|
| `scope` | `local`, `fed` | group, policy rule, response rule, admission rule, registry, system config |
| `view` | `pod`, `pod_only` | `/v1/workload`, `/v2/workload` (`controller/rest/workload.go`) |
| `show` | `accepted` | scan endpoints (`controller/rest/scanner.go`) |
| `section` | — | reserved |

---

## D.3 Response envelopes

Collections and single objects are wrapped in a key named for the resource. The
key is **not** always the obvious plural — `RESTRegistrySummaryListData` uses
`summarys`. Always confirm the key in Appendix B before writing `get_list`.

| Endpoint | Envelope key |
|---|---|
| `GET /v1/system/summary` | `summary` |
| `GET /v2/workload` | `workloads` |
| `GET /v2/workload/{id}` | `workload` |
| `GET /v1/host` | `hosts` |
| `GET /v1/group` | `groups` |
| `GET /v1/group/{name}` | `group` |
| `GET /v1/policy/rule` | `rules` |
| `GET /v1/scan/registry` | `summarys` |
| `GET /v1/log/threat` | `threats` |
| `GET /v1/log/violation` | `violations` |
| `GET /v1/log/incident` | `incidents` |
| `GET /v1/log/audit` | `audits` |
| `GET /v1/log/event` | `events` |

Some endpoints return the object **unwrapped** — `RESTComplianceData` and
`RESTBenchReport` among them. Where a projection cannot be certain, the
established pattern is `raw.get("<key>") or raw`.

### D.3.1 Empty bodies

`PATCH` and `DELETE` typically return `200` with **no body**. `client.request`
returns `{}` in that case. Treat it as success.

### D.3.2 Partial content

`controller/rest/rest.go` writes `http.StatusPartialContent` (206) in some
list paths. Accept any `2xx` as success.

---

## D.4 Errors

Source: `controller/api/apis.go` (`RESTError`, codes 1-55),
`controller/rest/rest.go` (`restErrMessage`).

```go
type RESTError struct {
    Code            int    `json:"code"`
    Error           string `json:"error"`
    Message         string `json:"message"`
    PwdProfileBasic *RESTPwdProfileBasic `json:"password_profile_basic,omitempty"`
    ImportTaskData  *RESTImportTaskData  `json:"import_task_data,omitempty"`
}
```

The numeric constants carry the upstream comment **"Don't modify value or
reorder"**, so `code` is a stable contract across releases. The HTTP status is
chosen independently at each call site, which is why classification must key on
`code` first. Full table: `appendix/C-error-taxonomy.md`.

Codes worth special handling:

| Code | Meaning | Handling |
|---|---|---|
| 3 | Authentication failed | Re-login once (password mode) then surface as `AuthError`. An expired API key lands here. |
| 4 | Operation not allowed | Structural refusal, e.g. deleting a learned group. Never retry. |
| 7 | Object not found | `NotFoundError`. |
| 12 | More search criteria required | The query was too broad; tell the caller to add filters. |
| 25 | Object access denied | The identity's role does not cover this namespace. |
| 46 | Read-only rule(s) cannot be updated | Federated or learned rules; not the caller's to change. |
| 8, 9, 11, 19, 24, 55 | Cluster write/read/timeout/lock/RPC/server | Transient. Bounded retry. |
| 30 | Admission control unsupported | Non-Kubernetes platform. Never retry. |
| 53 | Invalid or expired query id | Re-run the `POST` that creates the query id. |

---

## D.5 Two API versions

Several resources exist at both `/v1` and `/v2`. Where a `/v2` variant exists,
**use it** — it is the shape the current UI consumes.

| Resource | v1 | v2 | Use |
|---|---|---|---|
| Workloads | `GET /v1/workload`, `/v1/workload/{id}` | `GET /v2/workload`, `/v2/workload/{id}`, `POST /v2/workload` | v2 |
| System config | `GET/PATCH /v1/system/config` | `GET/PATCH /v2/system/config` | v2 |
| Registry | `POST /v1/scan/registry`, `PATCH /v1/scan/registry/{name}` | `POST /v2/scan/registry`, `PATCH /v2/scan/registry/{name}` | v2 for create/update, v1 for `DELETE` (no v2 delete exists) |

`POST /v2/workload` takes a `RESTAssetIDList` body — a bulk fetch by id list,
useful when a caller already holds ids and wants to avoid N round trips.

---

## D.6 Documented versus registered routes

`controller/api/apis.yaml` documents **232** operations. `controller/rest/rest.go`
registers **340**. The 112-route difference is listed in Appendix A section A.2;
most are marked `// Skip API document` upstream.

Policy for this project:

* Documented routes: use freely.
* Undocumented routes: allowed **only** when listed in `UNDOCUMENTED_ALLOWLIST`
  in `scripts/verify_spec.py`, with a written justification, and gated at runtime
  behind `NV_ALLOW_UNDOCUMENTED=true`.
* Everything else: forbidden. Gate rule R6 fails the build.

Undocumented routes that matter and are allowlisted:

| Route | Why it is worth the risk |
|---|---|
| `GET /v1/conversation`, `GET /v1/conversation/{from}/{to}` | The network conversation graph. There is no documented equivalent, and it is the only way to answer "who talks to whom". |
| `POST /v1/vulasset` + `GET /v1/vulasset` | Query-id-based paged vulnerability view. The only scalable way to page vulnerabilities across a large cluster. |
| `GET /v1/selfuser` | Identity of the configured credential. |
| `GET /v1/list/application`, `GET /v1/list/compliance`, `GET /v1/list/registry_type` | Enumerations needed to validate rule and registry inputs client-side. |
| `GET /v1/response/options`, `GET /v1/group/{name}/stats` | Response-rule action enumeration; group traffic counters. |

Undocumented routes deliberately **not** used: everything under `/v1/debug/*`,
`/v1/internal/*`, `/v1/fed/*`, `/v1/partner/*`, `/identity/token`, `/findings/v1/*`.

---

## D.7 Long-running operations

These calls can exceed the default 30s timeout. Use
`settings.long_request_timeout_s`:

| Call | Why |
|---|---|
| `POST /v1/scan/repository` | Synchronous image pull plus scan. |
| `POST /v1/scan/registry/{name}/scan` | Kicks off a registry sweep. |
| `POST /v1/bench/host/{id}/kubernetes` / `/docker` | Runs a CIS benchmark on the node. |
| `GET /v1/scan/image/{id}` on a large image | Reports can carry thousands of CVE entries. |

Scan triggers are **asynchronous**: the POST returns once accepted, and progress
is read from `GET /v1/scan/status`. Never poll inside a tool; return and let the
caller poll.

---

## D.8 Response size

The controller does not paginate vulnerability entries inside a scan report. One
`GET /v1/scan/image/{id}` on a large base image can return several megabytes.
Every tool that touches scan reports, threat packets or bench results must
project, filter and cap client-side against `settings.max_response_chars`, and
say in its result that truncation occurred.
