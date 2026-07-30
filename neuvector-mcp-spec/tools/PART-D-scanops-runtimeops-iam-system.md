# TOOLS — Part D: `scan_ops`, `runtime_ops`, `iam_write`, `system_write` (19 mutating tools)

Companion to `SPEC.md` sections 3 (API conventions), 6 (safety model), 7.4
(mutating tool body) and 12 (gate rules). Every contract below is in
`_TEMPLATE.md` format and is **normative**. This is the file Part B refers to as
"Part C, `iam_write`" — the `iam_write` half of `tools/iam.py` lives here.

Phases: `scan_ops` + `runtime_ops` = **Phase 9**; `iam_write` + `system_write` =
**Phase 10**.

**Read before writing any code:** `SPEC.md` §6.1 (confirmation handshake), §6.2
(destructive classification), §7.4 (the five steps), §7.5 (output models), §7.6
(docstring structure), and `reference/src/neuvector_mcp/tools/policy_write.py`
(the established style — copy its shape, not its content).

## Invariants for all 19 tools (no exceptions)

| # | Invariant |
|---|---|
| **D-I1** | `readOnlyHint=False`. |
| **D-I2** | Exactly **one** toolset tag from `{scan_ops, runtime_ops, iam_write, system_write}` plus the literal `"write"` — `tags={"scan_ops", "write"}` etc. (gate R4, R3). |
| **D-I3** | Accepts `confirm: Annotated[str \| None, Field(description=...)] = None` as the **last** parameter (gate R5). |
| **D-I4** | Returns `WriteOutcome` and nothing else (gate R7). Never `dict[str, Any]`, never a bespoke result model. |
| **D-I5** | Follows the five-step body of §7.4 in order. `authorise_write(...)` is called **before** any mutating network call, and `if plan is not None: return plan` returns the guard's object **verbatim** — never re-wrapped, never edited. |
| **D-I6** | The docstring's last lines are `Calls <METHOD> <path>[ with ...].`, one per endpoint the tool may hit, machine-parsed by gate R6 (`CALLS_RE` in `scripts/verify_spec.py`). |
| **D-I7** | Registered inside `register()` behind `if not settings.toolset_enabled("<toolset>"): return` (or a per-toolset `if` block in the shared `iam.py`), so a disabled toolset is absent from `tools/list`. |
| **D-I8** | No tool logs an argument value or a payload. Audit records are produced only by `AuditMiddleware` (`arg_keys`, names only). |

**Endpoint verification.** Every `Calls` target in this file was resolved
programmatically against `spec_endpoints.json` (232 documented / 112
undocumented) before the contract was written. Result: **25 `Calls` lines over 25
distinct endpoints, all documented, 0 undocumented, 0 invented, 0 tools BLOCKED on
a missing endpoint.** Full record: §D.2.

**Schema verification.** Every request-body field name below appears in
`appendix/B-schema-reference.md`. Four request types used by this part are
**absent** from Appendix B; each is marked `BLOCKED (schema)` in §D.0.7 and again
in the owning tool's Notes, with a defensive shape and a live-controller
confirmation step.

---

## D.0 Module preamble — read before writing any code

### D.0.1 Modules and registration

| Module | Phase | Toolsets registered | New file? |
|---|---|---|---|
| `src/neuvector_mcp/tools/scan_ops.py` | 9 | `scan_ops` | new |
| `src/neuvector_mcp/tools/runtime_ops.py` | 9 | `runtime_ops` | new |
| `src/neuvector_mcp/tools/iam.py` | 10 | `iam_read` (Part B) **and** `iam_write` (here) | extend |
| `src/neuvector_mcp/tools/system.py` | 10 | `system_write` | new |

`server.py` registers modules by extending the tuple in `build_server`:

```python
for module in (inventory, policy_write, ..., scan_ops, runtime_ops, iam, system):
    module.register(mcp, settings)
```

Add `scan_ops` and `runtime_ops` in Phase 9; `system` in Phase 10 (`iam` is
already there from Phase 10's read half — do not add it twice, `on_duplicate="error"`
will abort the server).

In `tools/iam.py`, the two halves are independent blocks inside the single
`register()`:

```python
def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the iam_read and iam_write toolsets to ``mcp`` when each is enabled."""
    if settings.toolset_enabled("iam_read"):
        ...  # Part B tools, unchanged
    if settings.toolset_enabled("iam_write"):
        ...  # the five tools in this part
```

Never a single combined `if`. Enabling `iam_read` must not register a write tool
and vice versa. A `tools/*` module never imports another `tools/*` module (SPEC 4.1).

### D.0.2 Module header — identical in all four modules

```python
"""<Toolset description>. Toolset ``<toolset>``.

Every tool here follows the five-step mutating body of SPEC 7.4, in this order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query          # only scan_ops and runtime_ops need this
from ..config import Settings
from ..context import app_context
from ..errors import GuardError, ValidationError_
from ..guard import authorise_write
from ..models import WriteOutcome, redact_secrets  # plus this module's helpers
```

### D.0.3 The four annotation constants

Declare these **verbatim** at module top in each of the four modules. Do not
invent a fifth combination, and do not import them across modules.

```python
#: Creates something, or starts an action, that did not exist before. Not
#: destructive; not idempotent (a second call creates or starts again).
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
#: Reversible configuration change. Re-applying the same arguments is a no-op.
MUTATING_UPDATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Destroys a stored object. A second call fails with controller code 7.
MUTATING_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
#: Traffic-affecting but converging: re-applying the same arguments is a no-op.
MUTATING_DESTRUCTIVE_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
)
```

`destructiveHint` per tool, classified against **SPEC 6.2**:

| Tool | SPEC 6.2 class | `destructiveHint` | Constant |
|---|---|---|---|
| `nv_trigger_scan` | object creation (starts a scan job) | `False` | `MUTATING_CREATE` |
| `nv_stop_registry_scan` | reversible config change (re-trigger resumes; nothing stored is lost) | `False` | `MUTATING_UPDATE` |
| `nv_scan_repository` | object creation (produces a report, stores nothing) | `False` | `MUTATING_CREATE` |
| `nv_create_registry` | object creation | `False` | `MUTATING_CREATE` |
| `nv_update_registry` | reversible config change | `False` | `MUTATING_UPDATE` |
| `nv_delete_registry` | **data-destroying** | `True` | `MUTATING_DESTRUCTIVE` |
| `nv_trigger_bench_run` | object creation (starts a bench job) | `False` | `MUTATING_CREATE` |
| `nv_quarantine_workload` | **traffic-affecting** | `True` | `MUTATING_DESTRUCTIVE_IDEMPOTENT` |
| `nv_set_service_mode` | reversible config change — 6.2 lists "set policy mode" here explicitly | `False` | `MUTATING_UPDATE` |
| `nv_start_packet_capture` | object creation | `False` | `MUTATING_CREATE` |
| `nv_stop_packet_capture` | reversible config change | `False` | `MUTATING_UPDATE` |
| `nv_create_user` | object creation | `False` | `MUTATING_CREATE` |
| `nv_update_user_role` | reversible config change (the user object survives) | `False` | `MUTATING_UPDATE` |
| `nv_delete_user` | **data-destroying** | `True` | `MUTATING_DESTRUCTIVE` |
| `nv_create_api_key` | object creation | `False` | `MUTATING_CREATE` |
| `nv_delete_api_key` | **data-destroying** | `True` | `MUTATING_DESTRUCTIVE` |
| `nv_update_system_config` | reversible config change — 6.2 lists "update system config" here explicitly | `False` | `MUTATING_UPDATE` |
| `nv_set_namespace_tags` | reversible config change | `False` | `MUTATING_UPDATE` |
| `nv_update_scan_config` | reversible config change | `False` | `MUTATING_UPDATE` |

Two classifications are deliberately **not** escalated, and the reason is
recorded so nobody "fixes" them later:

* `nv_set_service_mode` switching to `Protect` **is** traffic-affecting in
  effect, but SPEC 6.2 names "set policy mode" as a reversible config change and
  the reference `nv_set_group_policy_mode` already ships with
  `destructiveHint=False`. Consistency with the reference wins; the warning lives
  in the docstring and in the `effect` string, which is what the operator reads
  in the confirmation plan.
* `nv_update_user_role` can lock an operator out of the cluster, but it destroys
  no object. It stays `False`; the lock-out hazard is named in the docstring and
  in `effect`.

### D.0.4 Secret handling — normative, and the confirm-token consequence

Four kinds of secret pass through this part: **registry credentials**
(`nv_scan_repository`, `nv_create_registry`, `nv_update_registry`), **user
passwords** (`nv_create_user`), **API key secrets** (`nv_create_api_key`), and
**captured packet data** (`nv_start_packet_capture`, which never returns it).

Append to `models.py` (pure functions; `models.py` imports pydantic only):

```python
#: JSON field names whose VALUE is a credential. Exact-match, not substring:
#: every name here is a real field in appendix/B-schema-reference.md.
#:   password              RESTRegistryConfig, RESTUser, RESTJfrogXrayConfig, RESTProxyConfig
#:   auth_token            RESTRegistryConfig
#:   gitlab_private_token  RESTRegistryConfig
#:   secret_access_key     RESTAWSAccountKeyConfig
#:   json_key              RESTGCRKeyConfig
#:   personal_access_token RESTRemoteRepo_GitHubConfig
#:   apikey_secret         RESTApikey, RESTApikeyGenerated
SECRET_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "auth_token",
        "gitlab_private_token",
        "secret_access_key",
        "json_key",
        "personal_access_token",
        "apikey_secret",
    }
)

#: The single sentinel a preview payload shows in place of a credential.
REDACTED = "***"


def redact_secrets(obj: Any) -> Any:
    """Deep copy of ``obj`` with every :data:`SECRET_FIELDS` value replaced by '***'.

    Absent keys stay absent: this never introduces a field the controller was not
    going to receive, so the redacted copy has the same SHAPE as the wire copy and
    is therefore a stable basis for the confirmation token.
    """
    if isinstance(obj, dict):
        return {
            key: (REDACTED if key in SECRET_FIELDS else redact_secrets(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    return obj
```

**The two-payload rule.** Every tool that carries a secret builds exactly two
dicts and keeps them straight:

| Variable | Contains | Goes to |
|---|---|---|
| `wire_payload` | the real credential | **only** `app.client.request(..., json=wire_payload)` |
| `safe_payload = redact_secrets(wire_payload)` | `"***"` in every secret field | `authorise_write(payload=safe_payload)` **and** `WriteOutcome(payload=safe_payload)` — both the preview and the applied outcome |

**Exactly where each secret goes:**

| Concern | Rule |
|---|---|
| Preview `payload` | `safe_payload`. The credential is `"***"`. A model reading the plan can verify the username, registry, role and every other field, and cannot read the secret. |
| Applied `payload` | `safe_payload`, same redaction. `WriteOutcome.payload` is *never* the wire copy. |
| `controller_response` | `redact_secrets(response)` for **every** tool except `nv_create_api_key`, so a controller that echoes a config back cannot leak through the outcome. |
| Logs | `AuditMiddleware` records `arg_keys` only — names, never values (`reference/.../audit.py`, SPEC 11, rule N8). No tool in this part logs a payload, an effect containing a secret, or a controller body. This holds at `NV_LOG_LEVEL=DEBUG` too. |
| Returned to caller | Nothing, except `nv_create_api_key`, which returns `apikey_secret` in `controller_response` **because it is the only copy that will ever exist**. |
| Never fetched at all | pcap bytes. `GET /v1/sniffer/{id}/pcap` is documented but **not exposed** by this server. |

**Confirm token in the presence of a secret — exact rule.** `authorise_write`
computes `confirm_token(operation, target, payload)` =
`sha256(f"{operation}|{target}|{canonical_json(payload)}")[:12]` from the payload
it is handed (`reference/.../guard.py`). Because it is handed `safe_payload`:

```
token = sha256("nv_create_user|alice|" + json.dumps(
    {"user": {"email": "a@x.io", "fullname": "alice", "password": "***",
              "role": "admin", "username": "alice"}},
    sort_keys=True, separators=(",", ":"))).hexdigest()[:12]
```

Preview and execution therefore agree: `safe_payload` is a pure function of the
arguments, with the secret value factored out, so the token the preview returned
is exactly the token the confirmed call recomputes. Two consequences, both
deliberate and both to be stated in the tools' Notes:

1. **Changing only the secret value does not invalidate the token.** Changing the
   username, role, registry, or any non-secret field does. This is the accepted
   cost of not echoing credentials back to the model; SPEC 6.1 already states the
   token is *"a guard rail, not a security boundary"*.
2. The guard is never modified to accept two payloads. `guard.py` is copied
   verbatim (rule N3).

### D.0.5 Namespace enforcement when the target has no namespace in its name

`authorise_write(namespace=...)` takes **one** namespace and is the only place
`NV_ALLOWED_NAMESPACES` is enforced (SPEC 6, layer 5). Three shapes occur here:

| Shape | Tools | Rule |
|---|---|---|
| Namespace is derivable from the target name | `nv_set_service_mode` (service names are `<service>.<namespace>`), `nv_set_namespace_tags` (the target **is** the namespace) | derive it and pass it |
| Target is an opaque id | `nv_quarantine_workload`, `nv_start_packet_capture`, `nv_trigger_scan(target='workload')` | the tool takes an explicit `namespace` argument. **Required** for the two `runtime_ops` tools, optional for the scan. It is used for the guard check only and is **never sent to the controller**. |
| Cluster-wide, no namespace | `nv_update_system_config`, `nv_update_scan_config`, registry and IAM tools, host/registry scans, bench runs | pass `namespace=None`. `NV_ALLOWED_NAMESPACES` cannot scope a cluster-wide change; say so in Notes. |

For the one batch tool, add this pure helper to `models.py` and use it:

```python
def service_namespace(service_name: str) -> str:
    """Namespace of a NeuVector service name.

    NeuVector names a Kubernetes service group ``<service>.<namespace>`` (see
    ``RESTService.name`` and ``RESTService.domain`` in appendix B). Returns "" when
    the name carries no namespace suffix, e.g. a Docker-only service.
    """
    _, _, suffix = service_name.rpartition(".")
    return suffix if "." in service_name else ""
```

`nv_set_service_mode` then, **before** `authorise_write`:

```python
namespaces = sorted({service_namespace(s) for s in services} - {""})
allowed = app.settings.allowed_namespaces
if allowed:
    outside = sorted(n for n in namespaces if n not in allowed)
    if outside:
        raise GuardError(
            f"nv_set_service_mode targets namespaces {outside}, which are outside "
            f"NV_ALLOWED_NAMESPACES ({sorted(allowed)}). No request was sent."
        )
guard_namespace = namespaces[0] if len(namespaces) == 1 else None
```

This is a **narrowing** of the guard, never a replacement: the guard still runs,
and it still receives a namespace whenever the batch is single-namespace. The
pre-check exists only because `authorise_write` cannot express a set.

### D.0.6 Long-request timeout

`app.client.request` takes `timeout_s`. Four tools must pass
`app.settings.long_request_timeout_s` (`NV_LONG_REQUEST_TIMEOUT_S`, default 300s;
SPEC 5) because the controller holds the connection while scanners work:

| Tool | Why |
|---|---|
| `nv_trigger_scan(target='registry')` | a registry scan enumerates repositories and tags before returning, and consumes shared scanner capacity |
| `nv_scan_repository` | **synchronous** — the controller pulls, unpacks and scans the image on the call |
| `nv_trigger_bench_run` | the enforcer runs the CIS script on the node |
| `nv_update_system_config` when `scanner_autoscale_cfg` is present | the controller talks to the Kubernetes API |

Everything else uses the default `NV_REQUEST_TIMEOUT_S`. Passing the long timeout
where it is not needed hides a hung controller for five minutes; do not do it.

### D.0.7 Schema gaps — `BLOCKED (schema)` register

| Type | Used by | Status | Defensive shape and confirmation step |
|---|---|---|---|
| `RESTRegistryConfigDataV2` / `RESTRegistryConfigV2` | `nv_create_registry`, `nv_update_registry` | **BLOCKED (schema)** — absent from Appendix B | Send the **documented V1 body** shape: `{"config": {...}}` with `RESTRegistryConfig` field names (all verified in B, `POST /v1/scan/registry`). See the tools' Notes for the confirmation procedure. |
| `RESTUserRoleDomainsConfigData` | `nv_update_user_role` | **BLOCKED (schema)** — absent from Appendix B | `{"config": {"name": <fullname>, "role_domains": {<role>: [<namespace>, ...]}}}`. The global role travels in the **path**, which *is* verified, so a wrong body cannot mis-assign the global role. |
| `RESTDomainEntryConfigData` | `nv_set_namespace_tags` | **BLOCKED (schema)** — absent from Appendix B | `{"config": {"name": <namespace>, "tags": [...]}}`. `tags` is `array<string>` on `RESTDomain` (verified in B); the `config` wrapper and the `name` echo follow every other `REST*ConfigData` in B. |
| `POST /v1/sniffer` 200 body | `nv_start_packet_capture` | **BLOCKED (schema)** — Appendix A declares the 200 schema as bare `object` | Do not project it. Pass `redact_secrets(response)` through to `controller_response` and tell the caller the capture id appears there if the controller returns one. |
| `RESTScanConfigResp` | *(not used)* | absent from B | `nv_update_scan_config` therefore does **no** pre-read; its `effect` names new values only. |
| `RESTWorkloadConfigData` | *(not used)* | absent from B | Reason `nv_quarantine_workload` uses `POST /v1/workload/request/{id}` (`RESTWorkloadRequestData`, which **is** in B) rather than `PATCH /v1/workload/{id}`. |

Every `BLOCKED (schema)` item follows the same three rules: (a) the field names in
the defensive shape all come from a type that *is* in Appendix B, (b) the tool's
Notes name the gap and the verification step, (c) the docstring does not promise
behaviour the schema cannot support.

### D.0.8 The one permitted pre-guard network call

SPEC 7.4 says steps 1–3 precede any network call. **`nv_update_system_config` is
the single documented exception**, and it is bounded as follows:

1. The pre-guard call is `GET /v2/system/config` — read-only, idempotent, and on a
   *different route* from the mutation.
2. It exists only to put real old-vs-new values into the `effect` string, which is
   the operator's entire basis for approving a cluster-wide change. The `effect`
   is built in step 1, before `authorise_write`, so the read cannot be deferred.
3. It is **failure-tolerant**: wrap it in `try/except NeuVectorMCPError` and fall
   back to old values rendered as `?`. A controller hiccup must not block a
   preview.
4. It never affects the token: `effect` is not hashed (`guard.confirm_token`
   hashes operation, target and payload only). A config drift between preview and
   confirm therefore does not invalidate the token — say so in the docstring.
5. The gate assertion still holds and is tested explicitly: on the preview call
   the **PATCH** route has `call_count == 0` while the **GET** route has
   `call_count == 1` (`test_update_system_config_preview_reads_current_config_only`).

No other tool in this part may read before the guard.

### D.0.9 New `models.py` additions

Appended in this order, after Part B's additions. Nothing existing is rewritten
(`Page`, `WriteOutcome`, `PolicyMode`, `SeverityCounts`, `VulnerabilityFinding`,
`_BASE`, `_clip`, `normalise_severity`, `severity_rank` all already exist —
reference them, never redefine them).

Phase 9: `SECRET_FIELDS`, `REDACTED`, `redact_secrets`, `service_namespace`,
`RepositoryScanReport`.
Phase 10: `describe_change`.

```python
def describe_change(path: str, old: Any, new: Any) -> str:
    """One clause of a change summary: "<path> <old> -> <new>".

    ``old`` is rendered ``?`` when the current value could not be read. Values are
    rendered with ``repr`` so an empty string is visibly empty. Never pass a
    credential to this function; secrets are summarised as a field name only.
    """
    return f"{path} {'?' if old is _UNKNOWN else old!r} -> {new!r}"


#: Sentinel meaning "the current value could not be read".
_UNKNOWN = object()
```

Declare `_UNKNOWN` **above** `describe_change`; the ordering above is descriptive,
the file must be valid Python.

---

# Toolset `scan_ops` (write) — 7 tools

### `nv_trigger_scan`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `POST /v1/scan/workload/{id}`, `POST /v1/scan/host/{id}`, `POST /v1/scan/registry/{name}/scan` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `target` | `Literal["workload","host","registry"]` | required | What to scan: 'workload' rescans one container's image, 'host' rescans one node, 'registry' starts a full scan of every image a configured registry matches. |
| `target_id` | `str` (min_length=1) | required | Workload id from nv_list_workloads, host id from nv_list_hosts, or registry name from nv_list_registries, matching 'target'. |
| `namespace` | `str \| None` | `None` | Namespace the workload runs in, from nv_list_workloads. Used only to enforce NV_ALLOWED_NAMESPACES; it is never sent to the controller. Ignored for host and registry scans. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Path mapping** — no request body on any of the three routes (Appendix A
declares the request schema as `—`). `json=None`; `payload=None` into the guard.

| `target` | Path | Timeout |
|---|---|---|
| `workload` | `/v1/scan/workload/{target_id}` | `settings.request_timeout_s` (default) |
| `host` | `/v1/scan/host/{target_id}` | default |
| `registry` | `/v1/scan/registry/{target_id}/scan` | **`settings.long_request_timeout_s`** |

**Docstring (use verbatim)**

```
Start a vulnerability scan of one workload, one host, or a whole registry.

Asynchronous: the controller accepts the request and returns immediately, so an
'applied' outcome means "scan queued", not "scan finished". Poll progress with
nv_get_scan_status and read results with nv_get_scan_report. A registry scan is
the expensive one - it walks every repository and tag the registry filters
match, occupies shared scanner capacity for as long as that takes, and delays
every other scan in the cluster; scope the registry's filters before starting
one, and stop it with nv_stop_registry_scan if it was a mistake. Get ids from
nv_list_workloads, nv_list_hosts or nv_list_registries.

Calls POST /v1/scan/workload/{id} with target='workload'.
Calls POST /v1/scan/host/{id} with target='host'.
Calls POST /v1/scan/registry/{name}/scan with target='registry'.
```

**Body**

```python
app = app_context(ctx)
if target == "registry":
    path = f"/v1/scan/registry/{target_id}/scan"
    timeout_s: float | None = app.settings.long_request_timeout_s
    effect = (
        f"Start a full scan of registry {target_id!r}. Every matching repository and tag "
        "will be scanned; this occupies shared scanner capacity until it completes."
    )
else:
    path = f"/v1/scan/{target}/{target_id}"
    timeout_s = None
    effect = f"Queue a rescan of {target} {target_id!r}."

plan = authorise_write(
    app.settings,
    operation="nv_trigger_scan",
    toolset="scan_ops",
    target=f"{target} {target_id}",
    effect=effect,
    payload=None,
    confirm=confirm,
    namespace=namespace if target == "workload" else None,
)
if plan is not None:
    return plan

response = await app.client.request("POST", path, timeout_s=timeout_s)
return WriteOutcome(
    status="applied",
    operation="nv_trigger_scan",
    target=f"{target} {target_id}",
    effect=f"scan of {target} {target_id} queued; poll nv_get_scan_status",
    payload={},
    controller_response=response if isinstance(response, dict) else {},
)
```

**Fixture** — none. All three routes return an empty body; tests respond
`200, json={}`.

**Tests** `tests/test_scan_ops.py`: `test_trigger_scan_preview_sends_nothing`,
`test_trigger_scan_workload_confirmed_applies`,
`test_trigger_scan_host_confirmed_applies`,
`test_trigger_scan_registry_uses_long_timeout`,
`test_trigger_scan_token_bound_to_target`.

**Notes**
* `payload=None` (not `{}`) into the guard, matching `nv_delete_group` in the
  reference. The token then hashes `canonical_json(None) == "{}"`, and `target`
  is `f"{target} {target_id}"` so switching `target` from `workload` to `host`
  with the same id invalidates the token — that is what
  `test_trigger_scan_token_bound_to_target` asserts.
* `WriteOutcome.payload` is `{}`; these routes have no body. Do not synthesise one.
* Common controller codes: **7** target id or registry name unknown; **22**
  container not running, so there is nothing to scan; **4** the target cannot be
  scanned (platform container, or a registry scan already in progress); **20**
  scanning not covered by the licence; **21** the enforcer on that node failed;
  **27** registry scan failed. **Code 27 is absent from `errors._CODE_MAP`**, so
  it classifies by HTTP status and normally surfaces as `UpstreamError` with the
  controller's message preserved. Do not edit `errors.py` (rule N3).

---

### `nv_stop_registry_scan`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `DELETE /v1/scan/registry/{name}/scan` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `registry_name` | `str` (min_length=1) | required | Registry whose running scan to cancel, from nv_list_registries. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — none. `json=None`, `payload=None`.

**Docstring (use verbatim)**

```
Cancel the scan currently running against one registry.

Stops the scan in flight and frees the scanner capacity it was holding. Images
already scanned keep their results, so nothing is lost - the registry is simply
left partially scanned until the next scan, and nv_get_scan_status will show a
lower 'scanned' count than 'scheduled'. Use this when a registry scan with
overly broad filters is starving the rest of the cluster. Re-start it with
nv_trigger_scan(target='registry').

Calls DELETE /v1/scan/registry/{name}/scan.
```

**Body** — §7.4 shape. `target=registry_name`, `payload=None`, `namespace=None`,
`effect=f"Cancel the running scan of registry {registry_name!r}. Already-scanned images keep their results."`,
applied effect `f"scan of registry {registry_name} cancelled"`, default timeout.

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_scan_ops.py`:
`test_stop_registry_scan_preview_sends_nothing`,
`test_stop_registry_scan_confirmed_applies`.

**Notes**
* Not destructive under SPEC 6.2: no stored object is removed. Idempotent —
  cancelling a registry with no scan in progress converges to the same state,
  though the controller may report it as **code 4** (Operation not allowed)
  rather than succeeding.
* Common codes: **7** no such registry; **4** no scan in progress; **25** the API
  key's role cannot manage this registry.

---

### `nv_scan_repository`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `POST /v1/scan/repository` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` (the projected report travels in `controller_response`) |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `repository` | `str` (min_length=1) | required | Repository path without the tag, e.g. 'library/nginx' or 'myorg/api'. |
| `tag` | `str` (min_length=1) | required | Image tag to scan, e.g. '1.27.0'. Prefer an immutable tag or a digest-pinned tag; 'latest' makes the result unreproducible. |
| `registry` | `str` | `""` | Registry base URL, e.g. 'https://registry.example.com'. Leave empty for the scanner's default public registry. |
| `username` | `str \| None` | `None` | Registry username, when the repository is private. |
| `password` | `str \| None` | `None` | Registry password or token. It is sent to the controller, is never logged, and is shown as '***' in the returned payload. |
| `base_image` | `str` | `""` | Base image reference, e.g. 'alpine:3.20'. When set, findings inherited from the base image are marked, so you can tell your CVEs from your base image's. |
| `scan_layers` | `bool` | `False` | True also reports which layer introduced each finding. Slower and much larger. |
| `ignore_proxy` | `bool` | `False` | True bypasses the cluster's configured registry proxy for this one pull. |
| `summary_only` | `bool` | `False` | True returns only the severity counts and no CVE detail. Always try this first. |
| `min_severity` | `Literal["Critical","High","Medium","Low"] \| None` | `None` | Keep only vulnerabilities at or above this severity. |
| `fixable_only` | `bool` | `False` | True keeps only vulnerabilities that have a fixed version available. |
| `max_vulnerabilities` | `int` (ge=1, le=500) | `50` | Hard cap on CVEs returned, applied after filtering and after sorting worst-first. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `RESTScanRepoReqData` (Appendix B). Every field verified against
`RESTScanRepoReq` / `RESTScanMeta`:

```python
wire_payload: dict[str, Any] = {
    "request": {
        "metadata": {
            "source": "neuvector-mcp",
            "user": "",
            "job": "",
            "workspace": "",
            "function": "",
            "region": "",
        },
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "scan_layers": scan_layers,
        "base_image": base_image,
        "ignore_proxy": ignore_proxy,
    }
}
if username is not None:
    wire_payload["request"]["username"] = username
if password is not None:
    wire_payload["request"]["password"] = password
safe_payload = redact_secrets(wire_payload)
```

`metadata`, `registry`, `repository`, `tag`, `scan_layers` and `base_image` are
all marked required in Appendix B, so all six are always present — the five empty
`RESTScanMeta` strings are intentional, not placeholders to fill in. `username`
and `password` are optional and omitted when `None`, so an anonymous pull does not
send empty credentials.

**Docstring (use verbatim)**

```
Scan one image in a registry on demand and return its vulnerability report.

This is the CI-style ad-hoc scan: nothing is stored, no registry has to be
configured first, and the image does not have to be running anywhere. It is
SYNCHRONOUS and slow - the controller pulls, unpacks and scans the image while
your call waits, which can take minutes on a large image - so expect to wait up
to NV_LONG_REQUEST_TIMEOUT_S. The report can carry thousands of CVEs, so it is
projected and capped exactly like nv_get_scan_report: call with
summary_only=true first for the counts, then narrow with min_severity and
fixable_only. If credentials are needed, 'password' is sent to the controller
but never logged and never echoed back - the returned payload shows '***'.

Calls POST /v1/scan/repository with {"request": {...}}.
```

**Body**

```python
app = app_context(ctx)
wire_payload = {...}                                    # 1. above
safe_payload = redact_secrets(wire_payload)
image_ref = f"{registry.rstrip('/')}/{repository}:{tag}" if registry else f"{repository}:{tag}"

plan = authorise_write(                                 # 2. guard
    app.settings,
    operation="nv_scan_repository",
    toolset="scan_ops",
    target=image_ref,
    effect=(
        f"Scan image {image_ref} now. This consumes shared scanner capacity for the "
        "duration of the scan and stores nothing on the controller."
    ),
    payload=safe_payload,
    confirm=confirm,
    namespace=None,
)
if plan is not None:                                    # 3.
    return plan

body = await app.client.request(                        # 4.
    "POST",
    "/v1/scan/repository",
    json=wire_payload,
    timeout_s=app.settings.long_request_timeout_s,
)
raw = body.get("report") if isinstance(body, dict) else None
report = RepositoryScanReport.from_api(
    raw if isinstance(raw, dict) else {},
    image_ref=image_ref,
    summary_only=summary_only,
    min_severity=min_severity,
    fixable_only=fixable_only,
    max_vulnerabilities=min(max_vulnerabilities, app.settings.max_items),
)
return WriteOutcome(                                    # 5.
    status="applied",
    operation="nv_scan_repository",
    target=image_ref,
    effect=f"scanned {image_ref}: {report.counts.total} vulnerabilities found",
    payload=safe_payload,
    controller_response=report.model_dump(mode="json"),
)
```

**Output model** — the tool returns `WriteOutcome` (D-I4), so the projection is
serialised into `controller_response`. `RepositoryScanReport` exists to do the
capping; it is never a return annotation.

```python
class RepositoryScanReport(BaseModel):
    """Projected, capped result of ``nv_scan_repository``.

    Serialised into ``WriteOutcome.controller_response``. Reuses ``SeverityCounts``
    and ``VulnerabilityFinding`` from Phase 3 so an ad-hoc scan and a stored scan
    report read identically to a client model.
    """

    model_config = _BASE

    image_ref: str = Field(description="Image that was scanned, as registry/repository:tag.")
    verdict: str = Field(
        default="",
        description="Controller's pass/fail verdict against the vulnerability profile, when it "
        "returns one; empty when it does not.",
    )
    image_id: str = Field(default="", description="Image id the scanner resolved.")
    digest: str = Field(default="", description="Image digest; the reproducible identity of what was scanned.")
    size: int = Field(default=0, description="Image size in bytes.")
    base_os: str = Field(default="", description="Base OS the scanner detected.")
    created_at: str = Field(default="", description="Image creation timestamp.")
    cvedb_version: str = Field(default="", description="CVE database version used; results are only as fresh as this.")
    layer_count: int = Field(default=0, description="Layers reported; 0 unless scan_layers was true.")
    module_count: int = Field(default=0, description="Software modules the scanner inventoried.")
    counts: SeverityCounts = Field(description="Counts over the WHOLE report, before any filtering.")
    matched: int = Field(default=0, description="Vulnerabilities left after min_severity and fixable_only.")
    page: Page
    vulnerabilities: list[VulnerabilityFinding] = Field(
        default_factory=list, description="Worst-first, filtered and capped. Empty when summary_only."
    )

    @classmethod
    def from_api(
        cls,
        raw: dict[str, Any],
        *,
        image_ref: str,
        summary_only: bool = False,
        min_severity: str | None = None,
        fixable_only: bool = False,
        max_vulnerabilities: int = 50,
    ) -> "RepositoryScanReport":
        """Project a ``RESTScanRepoReport``.

        ``envs`` and ``labels`` are deliberately DROPPED: container environment
        variables routinely carry credentials, and this server must not surface a
        secret it was not asked for. Filtering, sorting and capping are identical
        to ``ScanReport.from_api``.
        """
        ...  # same filter/sort/cap sequence as ScanReport.from_api (Part A)
```

**Fixture** `tests/fixtures/scan_repo_report.json` — envelope key `report`
(`RESTScanRepoReportData`). At least 6 vulnerabilities spanning
Critical/High/Medium/Low, some with an empty `fixed_version`, a non-empty
`modules` array, and an `envs` entry that looks like a credential
(`"AWS_SECRET_ACCESS_KEY=AKIAnotreal"`) so
`test_scan_repository_drops_envs_and_labels` can assert it never appears in the
result.

**Tests** `tests/test_scan_ops.py`:
`test_scan_repository_preview_sends_nothing`,
`test_scan_repository_confirmed_applies_and_caps_report`,
`test_scan_repository_password_redacted_in_outcome`,
`test_scan_repository_password_not_logged`,
`test_scan_repository_drops_envs_and_labels`,
`test_scan_repository_summary_only_returns_no_cves`.

**Notes**
* **Secret rule.** `password` is the credential. Preview payload: `"***"`.
  Applied payload: `"***"`. Wire body: the real value, once. Logs: never — the
  audit record carries `arg_keys` including the *name* `password` and no value.
  Returned to caller: never. `test_scan_repository_password_not_logged` asserts
  the literal secret appears in neither stdout nor stderr; use `capfd` (not
  `capsys`) because structlog is configured with
  `cache_logger_on_first_use=True` and a bound stderr stream.
* Consequence of D.0.4: changing only `password` between preview and confirm does
  **not** invalidate the token. Changing `repository`, `tag`, `registry` or any
  other argument does.
* The whole report never reaches the client: it is capped by
  `min(max_vulnerabilities, NV_MAX_ITEMS)` before serialisation, and
  `NV_MAX_RESPONSE_CHARS` remains the outer budget. Never place the raw
  controller body in `controller_response` for this tool.
* Common codes: **26** Fail to scan repository — by far the most common, and it
  means bad credentials, an unreachable registry, or an unknown repository/tag;
  **6** wrong request format; **20** licence; **25** access denied. **Code 26 is
  absent from `errors._CODE_MAP`** and so classifies by HTTP status, normally as
  `UpstreamError`; the controller's `message` is preserved and is where the real
  cause is.
* The undocumented `POST /v1/scan/result/repository` route (Appendix A.2) is
  **not** used.

---

### `nv_create_registry`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `POST /v2/scan/registry` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `name` | `str` (min_length=1) | required | Name for this registry entry inside NeuVector. It is the id every other registry tool takes; it is not the registry's hostname. |
| `registry_type` | `str` (min_length=1) | required | Registry kind as the controller spells it, e.g. the value shown by nv_list_registries for an existing entry of the same kind. Pass it verbatim; the controller rejects an unknown kind with code 6. |
| `registry` | `str` (min_length=1) | required | Registry base URL, e.g. 'https://registry.example.com' or 'https://index.docker.io/'. |
| `filters` | `list[str]` | `[]` | Repository/tag patterns to include, e.g. ['myorg/*:release-*']. An empty list means EVERY repository in the registry, which on a large registry is a scanner-capacity incident waiting to happen. |
| `username` | `str \| None` | `None` | Registry username. Omit for an anonymous registry. |
| `password` | `str \| None` | `None` | Registry password. Stored by the controller, never logged here, and shown as '***' in the returned payload. |
| `auth_token` | `str \| None` | `None` | Bearer token, as an alternative to username and password. Same redaction as 'password'. |
| `auth_with_token` | `bool` | `False` | True tells the controller to authenticate with 'auth_token' rather than username and password. |
| `scan_layers` | `bool` | `False` | True records which layer introduced each finding. Slower, and the stored reports are much larger. |
| `rescan_after_db_update` | `bool` | `False` | True rescans every matched image whenever the CVE database updates. Convenient, and a recurring capacity cost. |
| `repo_limit` | `int \| None` | `None` | Maximum repositories to enumerate. Set this before pointing NeuVector at a large registry. |
| `tag_limit` | `int \| None` | `None` | Maximum tags per repository to enumerate. |
| `ignore_proxy` | `bool` | `False` | True bypasses the cluster's configured registry proxy for this registry. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `{"config": {...}}` with `RESTRegistryConfig` field names
(BLOCKED (schema) on the V2 variant; see Notes). Only non-`None` optional fields
are included, so a `PATCH`-shaped partial body is never sent on a create:

```python
config: dict[str, Any] = {
    "name": name,
    "registry_type": registry_type,
    "registry": registry,
    "filters": sorted(filters),          # order is not semantic -> sorted for a stable token
    "auth_with_token": auth_with_token,
    "scan_layers": scan_layers,
    "rescan_after_db_update": rescan_after_db_update,
    "ignore_proxy": ignore_proxy,
}
for key, value in (
    ("username", username),
    ("password", password),
    ("auth_token", auth_token),
    ("repo_limit", repo_limit),
    ("tag_limit", tag_limit),
):
    if value is not None:
        config[key] = value
wire_payload = {"config": config}
safe_payload = redact_secrets(wire_payload)
```

**Docstring (use verbatim)**

```
Register a container registry so NeuVector can scan the images in it.

Creating the entry does not scan anything - it stores the connection and the
repository filters; nv_trigger_scan(target='registry') starts the work. Set
'filters', 'repo_limit' and 'tag_limit' before you create the entry: an
unfiltered large registry will enumerate every repository and tag and starve
every other scan in the cluster. Credentials are stored by the controller and
are write-only from this server's point of view - 'password' and 'auth_token'
are sent once, never logged, and shown as '***' in the returned payload, and no
read tool can retrieve them afterwards. A duplicate name is rejected with code
13.

Calls POST /v2/scan/registry with {"config": {...}}.
```

**Body** — §7.4 shape with the two-payload rule of D.0.4. `target=name`,
`namespace=None`, default timeout,
`effect=f"Create registry entry {name!r} for {registry} with {len(filters)} filter(s). Credentials, if supplied, are stored by the controller."`,
applied effect `f"registry {name} created"`, and
`controller_response=redact_secrets(response) if isinstance(response, dict) else {}`.

**Fixture** — none; `POST /v2/scan/registry` returns an empty body. Respond
`200, json={}`.

**Tests** `tests/test_scan_ops.py`:
`test_create_registry_preview_sends_nothing`,
`test_create_registry_confirmed_applies`,
`test_create_registry_password_redacted_in_preview_payload`,
`test_create_registry_token_matches_between_preview_and_apply`,
`test_create_registry_password_not_logged`.

`test_create_registry_token_matches_between_preview_and_apply` is the test that
proves D.0.4 works: take the token from a preview whose `password` was real, call
again with the same arguments plus that token, and assert the call is applied and
that `json.loads(route.calls.last.request.read())["config"]["password"]` is the
**real** password while `result.structured_content["payload"]["config"]["password"]`
is `"***"`.

**Notes**
* **BLOCKED (schema): `RESTRegistryConfigDataV2` / `RESTRegistryConfigV2` are
  absent from Appendix B.** The endpoint `POST /v2/scan/registry` *is* documented
  (Appendix A.1, tag `Scan`). The defensive shape above is the documented V1 body
  for the same operation (`POST /v1/scan/registry` → `RESTRegistryConfigData` →
  `RESTRegistryConfig`), so **every field name is verified**; only the V2
  *wrapper* is unverified. Confirmation procedure before production use: create a
  throwaway entry against a live controller, then call `nv_list_registries` and
  confirm `name`, `registry_type`, `registry`, `filters`, `scan_layers` and
  `rescan_after_db_update` came back as sent. If the controller answers **code 6**,
  the V2 wrapper differs — record the observed shape in Appendix B before
  changing this tool, and do not fall back to `/v1` silently.
* `aws_key`, `gcr_key`, `jfrog_xray`, `gitlab_private_token` and `schedule` are
  **not exposed**. They are nested credential objects (`secret_access_key`,
  `json_key`, `password`, `gitlab_private_token`) whose V2 shape is unverified;
  configure them in the NeuVector UI. `redact_secrets` already covers all four
  names, so a later addition cannot leak by omission.
* `registry_type` deliberately has no `Literal`: Appendix B declares it a plain
  string with no enum, and the route that enumerates the valid values
  (`GET /v1/list/registry_type`) is undocumented and gated behind
  `NV_ALLOW_UNDOCUMENTED`. Inventing an enum here would fail rule N2.
* `filters` is **sorted** before it goes into the payload. Order is not semantic
  for repository patterns, and sorting makes the confirm token independent of the
  order the model happened to list them in.
* Common codes: **13** duplicate name; **15** invalid name; **6** wrong format or
  unknown `registry_type`; **25** access denied; **20** licence.

---

### `nv_update_registry`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `PATCH /v2/scan/registry/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Arguments** — `name` (`str`, min_length=1, required, *"Registry entry to change, from nv_list_registries."*) plus the same optional fields as `nv_create_registry`, **all defaulting to `None`**, plus `confirm`. `registry_type` is not settable: changing the kind of an existing entry is a delete-and-recreate.

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `name` | `str` (min_length=1) | required | Registry entry to change, from nv_list_registries. |
| `registry` | `str \| None` | `None` | New registry base URL. Omit to leave it unchanged. |
| `filters` | `list[str] \| None` | `None` | Replacement repository/tag patterns. This REPLACES the existing list, it does not add to it; pass the full set you want. |
| `username` | `str \| None` | `None` | New registry username. Omit to leave it unchanged. |
| `password` | `str \| None` | `None` | New registry password. Sent once, never logged, shown as '***' in the returned payload. Omit to leave the stored one unchanged. |
| `auth_token` | `str \| None` | `None` | New bearer token. Same redaction as 'password'. |
| `auth_with_token` | `bool \| None` | `None` | True switches to token authentication, false switches to username and password. |
| `scan_layers` | `bool \| None` | `None` | Toggle per-layer findings. |
| `rescan_after_db_update` | `bool \| None` | `None` | Toggle rescanning on every CVE database update. |
| `repo_limit` | `int \| None` | `None` | New repository enumeration limit. |
| `tag_limit` | `int \| None` | `None` | New per-repository tag limit. |
| `ignore_proxy` | `bool \| None` | `None` | Toggle bypassing the configured registry proxy. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `{"config": {"name": name, ...only the arguments that are not None}}`.
`filters` is sorted, as in `nv_create_registry`. If **no** optional argument was
supplied, raise before the guard:

```python
if not changes:
    raise ValidationError_(
        "nv_update_registry needs at least one field to change. No request was sent."
    )
```

**Docstring (use verbatim)**

```
Change the configuration of an existing registry entry.

Only the fields you pass are changed; everything else keeps its stored value.
Two exceptions worth knowing: 'filters' REPLACES the whole pattern list rather
than adding to it, and widening the filters is the usual cause of an
unexpectedly enormous next scan. New credentials are sent once, never logged,
and shown as '***' in the returned payload; omitting 'password' leaves the
stored credential untouched rather than clearing it. The registry kind cannot be
changed - delete the entry and create a new one instead.

Calls PATCH /v2/scan/registry/{name} with {"config": {...}}.
```

**Body** — §7.4 shape with the two-payload rule. `target=name`,
`namespace=None`, `effect` naming each field being set, e.g.
`f"Update registry {name!r}: change {', '.join(sorted(changed_field_names))}."`
— field **names** only, never values, because one of them may be `password`.

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_scan_ops.py`:
`test_update_registry_preview_sends_nothing`,
`test_update_registry_confirmed_applies`,
`test_update_registry_sends_only_changed_fields`,
`test_update_registry_no_fields_raises`,
`test_update_registry_password_not_logged`.

**Notes**
* Same **BLOCKED (schema)** status and the same confirmation procedure as
  `nv_create_registry` — `RESTRegistryConfigDataV2` is absent from Appendix B;
  the field names are the verified V1 `RESTRegistryConfig` names.
* Note the version asymmetry across the three registry tools: create and update
  use `/v2`, delete uses `/v1`. Appendix A.1 documents no `DELETE /v2/scan/registry/{name}`,
  so this is the controller's shape, not an oversight here.
* The `effect` string names changed **fields**, not values, precisely so a
  credential cannot reach the plan through the prose. `payload` already shows
  every non-secret new value.
* Common codes: **7** no such registry; **6** wrong format; **16** object in use
  (a scan is running — stop it with `nv_stop_registry_scan` first); **25** access
  denied.

---

### `nv_delete_registry`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `DELETE /v1/scan/registry/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING_DESTRUCTIVE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `name` | `str` (min_length=1) | required | Registry entry to delete, from nv_list_registries. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — none. `payload=None`.

**Docstring (use verbatim)**

```
Delete a registry entry and every scan result stored under it.

Data-destroying and not recoverable from this server: the stored credentials,
the repository filters and all scan reports for images in this registry go with
it, so nv_get_scan_report(target='registry_image') will stop answering for those
images. Admission control rules and vulnerability profiles that reason about
those images lose their evidence. A registry with a scan in progress is refused
with code 16 - stop the scan with nv_stop_registry_scan first.

Calls DELETE /v1/scan/registry/{name}.
```

**Body** — §7.4 shape. `target=name`, `payload=None`, `namespace=None`,
`effect=f"Delete registry {name!r}, its stored credentials, its filters and every scan report for its images."`,
applied effect `f"registry {name} deleted"`.

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_scan_ops.py`:
`test_delete_registry_preview_sends_nothing`,
`test_delete_registry_confirmed_applies`.

**Notes**
* Common codes: **7** no such registry; **16** object in use, i.e. a scan is
  running; **4** the entry is a federated or ground-configured registry that a
  local admin may not delete; **25** access denied.
* Deleting is the only way to change `registry_type`; say nothing else about
  recovery, because there is none.

---

### `nv_trigger_bench_run`

| | |
|---|---|
| **Toolset** | `scan_ops` (write) |
| **Endpoints** | `POST /v1/bench/host/{id}/kubernetes`, `POST /v1/bench/host/{id}/docker` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `host_id` | `str` (min_length=1) | required | Host (node) id from nv_list_hosts. |
| `benchmark` | `Literal["kubernetes","docker"]` | required | Which CIS benchmark to run: 'kubernetes' for the CIS Kubernetes Benchmark, 'docker' for the CIS Docker Benchmark. Run the one that matches what the node actually runs. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Path mapping** — no request body (Appendix A declares `—`). `json=None`,
`payload=None`, timeout `settings.long_request_timeout_s`.

| `benchmark` | Path |
|---|---|
| `kubernetes` | `/v1/bench/host/{host_id}/kubernetes` |
| `docker` | `/v1/bench/host/{host_id}/docker` |

**Docstring (use verbatim)**

```
Re-run a CIS benchmark on one node and refresh its stored report.

The enforcer on that node executes the benchmark scripts, which is CPU-noisy for
a short while but changes nothing on the host. Read the result afterwards with
nv_get_bench_report for the same host and benchmark - this call only triggers
the run, so a fresh report may take a moment to appear. Pick the benchmark that
matches the node: asking for 'docker' on a containerd node produces a report
full of failures that mean nothing.

Calls POST /v1/bench/host/{id}/kubernetes with benchmark='kubernetes'.
Calls POST /v1/bench/host/{id}/docker with benchmark='docker'.
```

**Body** — §7.4 shape. `target=f"{benchmark} benchmark on host {host_id}"`,
`payload=None`, `namespace=None` (a node is not namespaced — say so in Notes),
`effect=f"Re-run the CIS {benchmark} benchmark on node {host_id!r}. The enforcer executes the benchmark scripts; nothing on the host is modified."`,
applied effect `f"CIS {benchmark} benchmark started on {host_id}; read it with nv_get_bench_report"`.

**Fixture** — none; both routes return an empty body. Respond `200, json={}`.

**Tests** `tests/test_scan_ops.py`:
`test_trigger_bench_run_preview_sends_nothing`,
`test_trigger_bench_run_kubernetes_confirmed_applies`,
`test_trigger_bench_run_docker_confirmed_applies`,
`test_trigger_bench_run_token_bound_to_benchmark`.

**Notes**
* `namespace=None`: a host is cluster-scoped, so `NV_ALLOWED_NAMESPACES` cannot
  constrain this tool. `NV_READ_ONLY` and `NV_TOOLSETS` are the layers that apply.
* `benchmark` is part of `target`, so a token issued for `kubernetes` is rejected
  for `docker`.
* Common codes: **7** unknown host id; **23** CIS benchmark error (the script
  failed on the node); **21** enforcer error, usually a node whose enforcer is
  disconnected; **25** access denied.

---

# Toolset `runtime_ops` (write) — 4 tools

### `nv_quarantine_workload`

| | |
|---|---|
| **Toolset** | `runtime_ops` (write) |
| **Endpoints** | `POST /v1/workload/request/{id}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True` (`MUTATING_DESTRUCTIVE_IDEMPOTENT`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `workload_id` | `str` (min_length=1) | required | Workload (container) id from nv_list_workloads or nv_get_workload. |
| `namespace` | `str` (min_length=1) | required | Namespace the workload runs in, from nv_list_workloads. Used only to enforce NV_ALLOWED_NAMESPACES; it is not sent to the controller. Required so that a mis-typed id cannot escape the namespace allowlist. |
| `action` | `Literal["quarantine","unquarantine"]` | required | 'quarantine' cuts the container off the network; 'unquarantine' restores it. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `RESTWorkloadRequestData` (Appendix B). `RESTWorkloadRequest` has
exactly one field, `command`, and the un-quarantine path is the same endpoint with
the opposite command:

```python
wire_payload = {"request": {"command": action}}     # no secret; safe == wire
```

**Docstring (use verbatim)**

```
Cut a running container off the network, or restore it.

The highest blast radius of any tool in this server. Quarantine severs the
container's network connectivity while leaving the process running: every
inbound and outbound connection stops, so if the container serves live traffic
that traffic fails immediately and any dependent service fails with it. Nothing
is deleted and the container is not restarted - call again with
action='unquarantine' to restore it. Check the workload's 'state' with
nv_list_workloads first: a workload already showing 'quarantined' does not need
this, and a workload the platform will not let NeuVector quarantine is refused
with code 4. A stopped container is refused with code 22.

Calls POST /v1/workload/request/{id} with {"request": {"command": ...}}.
```

**Body**

```python
app = app_context(ctx)
wire_payload: dict[str, Any] = {"request": {"command": action}}

plan = authorise_write(
    app.settings,
    operation="nv_quarantine_workload",
    toolset="runtime_ops",
    target=workload_id,
    effect=(
        f"Sever all network connectivity of container {workload_id!r} in namespace "
        f"{namespace!r}. Live traffic to and from it will fail immediately."
        if action == "quarantine"
        else f"Restore network connectivity of container {workload_id!r} in namespace {namespace!r}."
    ),
    payload=wire_payload,
    confirm=confirm,
    namespace=namespace,
)
if plan is not None:
    return plan

response = await app.client.request(
    "POST", f"/v1/workload/request/{workload_id}", json=wire_payload
)
return WriteOutcome(
    status="applied",
    operation="nv_quarantine_workload",
    target=workload_id,
    effect=f"{action} applied to container {workload_id}",
    payload=wire_payload,
    controller_response=response if isinstance(response, dict) else {},
)
```

**Fixture** — none; the route returns an empty body. Respond `200, json={}`.

**Tests** `tests/test_runtime_ops.py`:
`test_quarantine_preview_sends_nothing`,
`test_quarantine_confirmed_applies`,
`test_unquarantine_confirmed_applies`,
`test_quarantine_token_bound_to_action`,
`test_quarantine_outside_allowed_namespace_refused` (asserts `GuardError` text
contains `outside NV_ALLOWED_NAMESPACES` and `route.call_count == 0`),
`test_runtime_ops_hidden_when_read_only`.

**Notes**
* **The field is `request.command`.** `RESTWorkloadRequest` in Appendix B declares
  exactly one property, `command` (string, optional), and both directions go
  through it — there is no separate un-quarantine endpoint and no `quarantine`
  boolean. **BLOCKED (partial):** Appendix B declares **no enum** for `command`,
  so the two literals `"quarantine"` and `"unquarantine"` are constrained
  client-side by the `Literal` on `action` and must be confirmed against a live
  controller: issue `action="quarantine"`, then read the workload back with
  `nv_list_workloads` and check `state == "quarantined"`. If the controller
  answers **code 6**, record the accepted command strings in Appendix B before
  changing this tool.
* `RESTUnquarReq` (`response_rule`, `group`) in Appendix B belongs to
  `RESTSystemRequest.unquarantine` (`POST /v1/system/request`), which is a
  *bulk* un-quarantine by response rule or group. It is **not** this endpoint's
  body and is not exposed by this server.
* `PATCH /v1/workload/{id}` with `RESTWorkloadConfigData` is the documented
  alternative, and is **not** used: `RESTWorkloadConfigData` is absent from
  Appendix B, so its field names cannot be verified (rule N2).
* `namespace` is required, not optional, and is never sent. It is the only way
  `NV_ALLOWED_NAMESPACES` can constrain an opaque container id (D.0.5).
* Idempotent: quarantining an already-quarantined container converges. Still
  `destructiveHint=True` — SPEC 6.2 classes quarantine as traffic-affecting, and
  it is the table's own example.
* Common codes: **7** unknown workload id; **22** container not running; **4** the
  workload cannot be quarantined (platform or system container, i.e.
  `cap_quarantine` is false on `RESTWorkloadSecurityV2`); **21** enforcer error;
  **25** access denied.

---

### `nv_set_service_mode`

| | |
|---|---|
| **Toolset** | `runtime_ops` (write) |
| **Endpoints** | `PATCH /v1/service/config`, `PATCH /v1/service/config/network`, `PATCH /v1/service/config/profile` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `services` | `list[str]` (min_length=1) | required | Service (group) names from nv_list_services, e.g. ['api.prod', 'web.prod']. All of them get the same settings in one controller call. |
| `scope` | `Literal["both","network","profile"]` | `"both"` | Which dimension to change: 'network' sets only network policy enforcement, 'profile' sets only process and file profile enforcement, 'both' sets them together. Use 'network' or 'profile' when you want to enforce one dimension while still learning the other. |
| `policy_mode` | `Literal["Discover","Monitor","Protect"] \| None` | `None` | Discover learns behaviour, Monitor alerts only, Protect BLOCKS. Omit to leave the mode unchanged. |
| `baseline_profile` | `str \| None` | `None` | Process baseline strictness, verbatim controller string; see 'baseline_profile' on an existing service via nv_list_services for the values in use. Only meaningful with scope='profile' or 'both'. |
| `not_scored` | `bool \| None` | `None` | True excludes these services from the cluster security score. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Endpoint and payload mapping** — all three routes take the **same** body type,
`RESTServiceBatchConfigData` (verified in Appendix A.1 and Appendix B):

| `scope` | Path | Applies to |
|---|---|---|
| `both` | `/v1/service/config` | network policy mode **and** process/file profile mode together |
| `network` | `/v1/service/config/network` | network policy enforcement only |
| `profile` | `/v1/service/config/profile` | process and file profile enforcement only, including `baseline_profile` |

```python
config: dict[str, Any] = {"services": sorted(services)}   # sorted: set semantics, stable token
for key, value in (
    ("policy_mode", policy_mode),
    ("baseline_profile", baseline_profile),
    ("not_scored", not_scored),
):
    if value is not None:
        config[key] = value
if len(config) == 1:
    raise ValidationError_(
        "nv_set_service_mode needs at least one of policy_mode, baseline_profile or "
        "not_scored. No request was sent."
    )
wire_payload = {"config": config}
path = {
    "both": "/v1/service/config",
    "network": "/v1/service/config/network",
    "profile": "/v1/service/config/profile",
}[scope]
```

`RESTServiceBatchConfig` has exactly four fields — `services`, `policy_mode`,
`baseline_profile`, `not_scored` — and every one of them is used above. There is
no `profile_mode` field on the request body: the *dimension* is chosen by the
path, not by the body. That is why `scope` exists.

**Docstring (use verbatim)**

```
Set the enforcement mode of one or more services in a single call.

Traffic-affecting: moving a service to Protect starts BLOCKING connections and
process activity that its learned policy does not allow, for every container in
that service at once, and a service whose learning was incomplete will break the
moment you do it. Preview first and read the service list in the plan. 'scope'
picks the dimension: 'network' enforces network policy only, 'profile' enforces
process and file profiles only, 'both' does the two together - a common safe
sequence is network first, profile once process learning has settled. Get names
from nv_list_services, and check each service's current policy_mode and
profile_mode there before changing them.

Calls PATCH /v1/service/config with scope='both'.
Calls PATCH /v1/service/config/network with scope='network'.
Calls PATCH /v1/service/config/profile with scope='profile'.
```

**Body** — §7.4 shape, with the namespace pre-check of D.0.5 **before**
`authorise_write`. `target=",".join(sorted(services))`, `namespace=guard_namespace`,

```python
effect = (
    f"Set {', '.join(f'{k}={v!r}' for k, v in sorted(config.items()) if k != 'services')} "
    f"on {len(services)} service(s): {', '.join(sorted(services))} (scope={scope})."
    + (
        " Traffic and process activity outside the learned policy will be blocked immediately."
        if policy_mode == "Protect"
        else ""
    )
)
```

The `Protect` sentence is copied from the reference `nv_set_group_policy_mode`
deliberately: `test_first_call_returns_plan_and_sends_nothing` in
`test_guard.py` already keys on `"blocked immediately"`, and the two tools should
read the same to an operator.

**Fixture** — none; all three routes return an empty body. Respond `200, json={}`.

**Tests** `tests/test_runtime_ops.py`:
`test_set_service_mode_preview_sends_nothing`,
`test_set_service_mode_confirmed_applies_to_batch_endpoint`,
`test_set_service_mode_network_scope_uses_network_endpoint`,
`test_set_service_mode_profile_scope_uses_profile_endpoint`,
`test_set_service_mode_sorts_services_for_stable_token`,
`test_set_service_mode_multi_namespace_refused_outside_allowlist`,
`test_set_service_mode_no_fields_raises`.

**Notes**
* Appendix A.1 documents all three routes with the **same** request and response
  schemas and gives no prose distinguishing them, so the dimension mapping above
  is a *design decision of this spec*, grounded in `RESTService` carrying two
  separate mode fields (`policy_mode` and `profile_mode`) while
  `RESTServiceBatchConfig` carries only one. Verify on first use: set
  `scope='network'` on a test service and confirm via `nv_list_services` that
  `policy_mode` moved and `profile_mode` did not. If the controller behaves
  otherwise, correct this table before shipping — do not change the argument
  names.
* `services` is **sorted** in the payload and in `target`, so the confirm token
  does not depend on the order the model listed them. `sorted()` also makes the
  `effect` string stable, which matters for the test assertions.
* Namespace enforcement (D.0.5): the tool refuses the whole batch if **any**
  service's namespace is outside `NV_ALLOWED_NAMESPACES`, and passes the single
  namespace to the guard only when the batch is single-namespace. A batch is
  never partially applied by this server; the controller applies the batch
  atomically or not at all.
* Common codes: **7** a service in the list does not exist — the controller
  rejects the whole batch, so verify names first; **6** invalid `policy_mode` or
  `baseline_profile`; **4** the service is federated or ground-configured and its
  mode may not be set locally; **20** Protect not covered by the licence; **8**
  write to cluster failed (retried automatically by `client.py`); **25** access
  denied.

---

### `nv_start_packet_capture`

| | |
|---|---|
| **Toolset** | `runtime_ops` (write) |
| **Endpoints** | `POST /v1/sniffer` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `workload_id` | `str` (min_length=1) | required | Workload (container) id whose traffic to capture, from nv_list_workloads. |
| `namespace` | `str` (min_length=1) | required | Namespace the workload runs in, from nv_list_workloads. Used only to enforce NV_ALLOWED_NAMESPACES; it is not sent to the controller. Required because a packet capture is privacy-sensitive and must not be startable outside the allowed namespaces by a mis-typed id. |
| `duration_s` | `int` (ge=1, le=3600) | `60` | Seconds to capture for. Keep it short: a capture on a busy container fills the enforcer's disk quickly. |
| `filter` | `str` | `""` | Berkeley Packet Filter expression, e.g. 'tcp port 443'. Strongly recommended - an unfiltered capture records every packet, including other tenants' payloads if the container proxies them. |
| `file_number` | `int` (ge=1, le=10) | `1` | Number of rotating capture files the enforcer keeps. More files means a longer window and more disk. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Query and payload mapping** — the target workload is a **query parameter**, not
a path segment or a body field (Appendix A.1: `POST /v1/sniffer` … query params
`f_workload`). The body is `RESTSnifferArgsData`, whose `RESTSnifferArgs` has
exactly three fields, all used:

```python
params = build_query(filters={"workload": workload_id})     # -> {"f_workload": <id>}
wire_payload = {
    "sniffer": {"file_number": file_number, "duration": duration_s, "filter": filter}
}
```

**Docstring (use verbatim)**

```
Start a packet capture on one running container.

Privacy-sensitive: this records the container's actual network traffic, payloads
included, onto the enforcer's disk. Anything the container carries in clear -
credentials, personal data, another tenant's requests - lands in that file, so
scope it with a BPF 'filter' and the shortest 'duration_s' that answers your
question, and treat the result as regulated data. The capture file is NOT
retrievable through this server: the controller serves it from
GET /v1/sniffer/{id}/pcap as a binary payload, which is unsuitable for an MCP
result, so this server does not expose it. Fetch the pcap out of band with the
NeuVector UI or a direct authenticated HTTP call, then analyse it there. Stop
the capture early with nv_stop_packet_capture.

Calls POST /v1/sniffer with f_workload and {"sniffer": {...}}.
```

**Body** — §7.4 shape. `target=workload_id`, `namespace=namespace`,
`payload=wire_payload` (no secret field, so `safe == wire`),

```python
effect = (
    f"Capture up to {duration_s}s of network traffic from container {workload_id!r} in "
    f"namespace {namespace!r} into {file_number} file(s) on the enforcer"
    + (f", filtered by {filter!r}." if filter else
       ". NO FILTER IS SET, so every packet including payloads will be recorded.")
)
```

then

```python
response = await app.client.request("POST", "/v1/sniffer", params=params, json=wire_payload)
return WriteOutcome(
    status="applied",
    operation="nv_start_packet_capture",
    target=workload_id,
    effect=f"packet capture started on container {workload_id}",
    payload=wire_payload,
    controller_response=redact_secrets(response) if isinstance(response, dict) else {},
)
```

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_runtime_ops.py`:
`test_start_packet_capture_preview_sends_nothing`,
`test_start_packet_capture_confirmed_applies_with_f_workload` (asserts
`route.calls.last.request.url.params["f_workload"] == "<id>"` **and** the exact
JSON body),
`test_start_packet_capture_unfiltered_effect_warns`,
`test_start_packet_capture_never_fetches_pcap` (registers a respx route for
`GET /v1/sniffer/{id}/pcap` and asserts `call_count == 0`).

**Notes**
* **Secret rule.** No request field is a credential, but the *artefact* is
  sensitive. Rules: nothing captured is ever read by this server; `GET /v1/sniffer/{id}/pcap`
  is documented in Appendix A.1 and deliberately **not** exposed, because a binary
  payload has no useful MCP representation and because streaming captured traffic
  through a model is exactly the wrong place to put it. `controller_response` is
  still passed through `redact_secrets` defensively. The `filter` argument is an
  argument value and therefore never logged (only the key name `filter` appears in
  the audit record).
* **BLOCKED (schema): the 200 body of `POST /v1/sniffer` is declared as bare
  `object`** in Appendix A.1, so the capture id's field name cannot be verified.
  Do not project it and do not invent a key. Pass the body through to
  `controller_response` and let the operator read the id from there. This server
  exposes no list-captures tool (`GET /v1/sniffer` is not in any toolset in SPEC 8),
  so if the controller returns nothing, the id must be obtained out of band before
  `nv_stop_packet_capture` can be used. Record the observed response shape in
  Appendix B when a live controller is available.
* `build_query(filters={"workload": workload_id})` is used rather than a
  hand-built dict, so the `f_` convention stays in one place (SPEC 3.2).
* `duration_s` maps to the controller's `duration`; the argument is named with the
  unit because a bare `duration` in a tool schema invites milliseconds.
* Common codes: **7** unknown workload id; **22** container not running; **4** the
  container cannot be sniffed (`cap_sniff` is false on `RESTWorkloadSecurityV2`);
  **21** enforcer error or no disk space; **25** access denied.

---

### `nv_stop_packet_capture`

| | |
|---|---|
| **Toolset** | `runtime_ops` (write) |
| **Endpoints** | `PATCH /v1/sniffer/stop/{id}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `capture_id` | `str` (min_length=1) | required | Capture id, as returned in controller_response by nv_start_packet_capture. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — none (Appendix A declares the request schema as `—`). `payload=None`.

**Docstring (use verbatim)**

```
Stop a running packet capture.

Stops the enforcer writing further packets and leaves the file it has already
written in place, so this reduces exposure rather than eliminating it - the
captured traffic still exists on the enforcer until it is removed out of band.
Do this as soon as you have what you need, and always for an unfiltered capture.
The capture id comes from the controller_response of nv_start_packet_capture;
this server exposes no way to list captures, so keep the id.

Calls PATCH /v1/sniffer/stop/{id}.
```

**Body** — §7.4 shape. `target=capture_id`, `payload=None`, `namespace=None`,
`effect=f"Stop packet capture {capture_id!r}. Packets already written stay on the enforcer."`,
applied effect `f"packet capture {capture_id} stopped"`.

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_runtime_ops.py`:
`test_stop_packet_capture_preview_sends_nothing`,
`test_stop_packet_capture_confirmed_applies`.

**Notes**
* `DELETE /v1/sniffer/{id}` — which deletes the capture *and* its pcap file — is
  documented in Appendix A.1 and is **not** exposed. It is the only genuinely
  data-destroying sniffer operation, it is outside the four tools SPEC 8 allocates
  to `runtime_ops`, and adding it would change the toolset's tool count and fail
  the phase gate. If capture cleanup is needed, add it in a later phase with
  `destructiveHint=True`; do not smuggle it into this tool.
* `namespace=None`: a capture id carries no namespace and the workload it belongs
  to is not knowable from the id alone. The namespace gate was applied at start
  time; note this asymmetry rather than pretending it applies here too.
* Common codes: **7** unknown capture id; **4** the capture already stopped;
  **21** enforcer error; **25** access denied.

---

# Toolset `iam_write` (write) — 5 tools

### `nv_create_user`

| | |
|---|---|
| **Toolset** | `iam_write` (write) |
| **Endpoints** | `POST /v1/user` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `username` | `str` (min_length=1) | required | Login name for the new local user. It also becomes the account's fullname, which is the id nv_update_user_role and nv_delete_user take. |
| `password` | `str` (min_length=1) | required | Initial password. It is sent to the controller once, is never logged, and is shown as '***' in the returned payload - this server cannot read it back afterwards. A password that fails the cluster's password profile is rejected with code 14. |
| `email` | `str` | `""` | Contact email for the account. |
| `role` | `str` (min_length=1) | required | Global role, e.g. a name from nv_list_roles. This is the account's ceiling everywhere except the namespaces named in role_domains. |
| `role_domains` | `dict[str, list[str]] \| None` | `None` | Namespace-scoped roles as role name -> list of namespaces, e.g. {'admin': ['staging']}. Use this instead of a broad global role wherever it will do. |
| `timeout_s` | `int \| None` | `None` | Idle session timeout in seconds. Omit for the cluster default. |
| `locale` | `str \| None` | `None` | UI locale for this account, e.g. 'en'. Omit for the cluster default. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `RESTUserData` (Appendix B); every field name from `RESTUser`:

```python
user: dict[str, Any] = {
    "fullname": username,      # local accounts: fullname == username; 'server' is left unset
    "username": username,
    "password": password,
    "email": email,
    "role": role,
}
if role_domains is not None:
    user["role_domains"] = {r: sorted(ns) for r, ns in role_domains.items()}
if timeout_s is not None:
    user["timeout"] = timeout_s
if locale is not None:
    user["locale"] = locale
wire_payload = {"user": user}
safe_payload = redact_secrets(wire_payload)      # -> user.password == "***"
```

`server` is deliberately **omitted**: an unset `server` is what makes the account
local, and remote accounts are created by the identity provider, not here.

**Docstring (use verbatim)**

```
Create a local user account with a role.

The new account can log in immediately with the password you supply, so scope
'role' to the least it needs and prefer 'role_domains' - a namespace-scoped role
- over a broad global one. The password is sent to the controller once and is
write-only from here: it is never logged, the returned payload shows '***', and
no read tool can retrieve it, so deliver it to the human out of band and have
them change it. A duplicate username is rejected with code 13 and a password
that fails the cluster's password profile with code 14. Verify the result with
nv_list_users, which reports the account's fullname - the id the other IAM tools
take.

Calls POST /v1/user with {"user": {...}}.
```

**Body**

```python
app = app_context(ctx)
wire_payload = {...}                                  # 1. above
safe_payload = redact_secrets(wire_payload)

plan = authorise_write(                               # 2. guard - on the REDACTED payload
    app.settings,
    operation="nv_create_user",
    toolset="iam_write",
    target=username,
    effect=(
        f"Create local user {username!r} with global role {role!r}"
        + (f" and namespace roles {sorted(role_domains or {})}." if role_domains else ".")
        + " The account can log in immediately."
    ),
    payload=safe_payload,
    confirm=confirm,
    namespace=None,
)
if plan is not None:                                  # 3.
    return plan

response = await app.client.request("POST", "/v1/user", json=wire_payload)   # 4. REAL payload
return WriteOutcome(                                  # 5.
    status="applied",
    operation="nv_create_user",
    target=username,
    effect=f"local user {username} created with role {role}",
    payload=safe_payload,                             # still redacted
    controller_response=redact_secrets(response) if isinstance(response, dict) else {},
)
```

**Confirm token — exact computation for this tool.** The guard is handed
`safe_payload`, so:

```
confirm_token("nv_create_user", username, safe_payload)
  = sha256("nv_create_user|" + username + "|" + json.dumps(safe_payload,
             sort_keys=True, separators=(",", ":"))).hexdigest()[:12]
```

with `safe_payload["user"]["password"] == "***"`. Preview and execution agree
because `safe_payload` does not depend on the password's value. Changing
`username`, `role`, `email`, `role_domains`, `timeout_s` or `locale` invalidates
the token; changing **only** `password` does not (D.0.4, accepted deliberately).

**Fixture** — none; `POST /v1/user` returns an empty body. Respond `200, json={}`.

**Tests** `tests/test_iam.py`:
`test_create_user_preview_sends_nothing`,
`test_create_user_preview_payload_masks_password` (asserts
`structured_content["payload"]["user"]["password"] == "***"` **and** that the real
password string appears nowhere in `json.dumps(structured_content)`),
`test_create_user_token_matches_between_preview_and_apply`,
`test_create_user_confirmed_sends_real_password` (asserts the outgoing body's
`user.password` is the real value while the returned `payload` still shows `"***"`),
`test_create_user_password_not_logged` (`capfd`; the literal password appears in
neither stdout nor stderr),
`test_iam_write_hidden_when_read_only`.

**Notes**
* **Secret rule, restated for this tool.** Redacted in the preview payload:
  `user.password` → `"***"`. Redacted in logs: everything — the audit record
  carries `arg_keys` (`["confirm", "email", "password", "role", "username"]`) and
  no values. Returned to the caller: nothing; the password is never echoed, in
  either the preview or the applied outcome.
* `fullname == username` for local accounts is the convention the `/v1/user/{fullname}`
  path depends on; `RESTUser` carries both fields and Appendix B does not state
  the relation, so the docstring tells the caller to confirm it with
  `nv_list_users` rather than asserting it.
* `role` has no `Literal`: roles are user-extensible (`POST /v1/user_role`) and
  Appendix B declares `RESTUser.role` a plain string. `nv_list_roles` is the
  enumeration.
* `POST /v1/user/{fullname}/password` (password change) is documented and **not**
  exposed: SPEC 8 allocates five tools to `iam_write` and a password-reset tool is
  not one of them.
* Common codes: **13** duplicate name; **14** weak password (the cluster's
  password profile refused it); **15** invalid name; **6** wrong format or unknown
  role; **4** the caller's own role may not grant the role being assigned;
  **25** access denied.

---

### `nv_update_user_role`

| | |
|---|---|
| **Toolset** | `iam_write` (write) |
| **Endpoints** | `PATCH /v1/user/{fullname}/role/{role}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Endpoint choice — both candidates verified, and why this one wins.** Appendix A.1
documents both:

| Candidate | Request schema | In Appendix B? |
|---|---|---|
| `PATCH /v1/user/{fullname}/role/{role}` | `RESTUserRoleDomainsConfigData` | **no** |
| `PATCH /v1/user/{fullname}` | `RESTUserConfigData` | **no** |

Neither body type is in Appendix B, so schema risk is identical and the tie is
broken on blast radius:

1. **The role travels in the path**, and the path *is* verified. Even if the
   defensive body shape is wrong, the controller still receives an unambiguous
   global-role assignment; with `PATCH /v1/user/{fullname}` the role is a body
   field, so a wrong body means a silently wrong or absent role change.
2. **It cannot touch anything else.** `RESTUserConfigData` is the general user
   update — the same body that carries `password`, `email` and `timeout` on
   `RESTUser`. A malformed partial body on that route risks clearing an unrelated
   field, including a credential. The role route has no such reach.
3. **Narrower RBAC surface** for the API key that drives this server.

Chosen: `PATCH /v1/user/{fullname}/role/{role}`.

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `fullname` | `str` (min_length=1) | required | Account id from nv_list_users. For a local account this is the username; for a remote one it also identifies the auth server. |
| `role` | `str` (min_length=1) | required | New global role, e.g. a name from nv_list_roles. This replaces the account's current global role outright. |
| `role_domains` | `dict[str, list[str]] \| None` | `None` | Namespace-scoped roles as role name -> list of namespaces, e.g. {'admin': ['staging']}. Passing this REPLACES the account's existing namespace roles; omit it to send none. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — defensive shape, `BLOCKED (schema)`:

```python
wire_payload = {
    "config": {
        "name": fullname,
        "role_domains": {r: sorted(ns) for r, ns in (role_domains or {}).items()},
    }
}
```

`role_domains` as `map<role, array<namespace>>` is verified twice in Appendix B —
`RESTUser.role_domains` ("map of roles on namespaces") and
`RESTApikey.role_domains` ("Object key is role and value is array of domains").
The `config` wrapper and the `name` echo follow every `REST*ConfigData` in
Appendix B (`RESTGroupConfigData`, `RESTRegistryConfigData`,
`RESTScanConfigData`, `RESTServiceBatchConfigData`). No secret field, so
`safe == wire`.

**Docstring (use verbatim)**

```
Change a user account's global role, and optionally its namespace roles.

This replaces the account's global role outright rather than adding to it, so a
downgrade takes effect immediately and the person loses whatever the old role
allowed. Two ways to hurt yourself: changing your own account's role can remove
your ability to change it back, and removing the last admin leaves nobody who
can administer the cluster - the controller refuses that second one with code 4,
but not the first. Read the account's current role with nv_list_users before
calling, and prefer role_domains, which scopes power to named namespaces, over a
broad global role.

Calls PATCH /v1/user/{fullname}/role/{role} with {"config": {...}}.
```

**Body** — §7.4 shape. `target=fullname`, `namespace=None`, default timeout,
path `f"/v1/user/{fullname}/role/{role}"`,
`effect=f"Set global role of account {fullname!r} to {role!r}" + (f", with namespace roles {sorted(role_domains or {})}" if role_domains else ", clearing any namespace roles") + ". The change takes effect on the account's next request."`

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_iam.py`:
`test_update_user_role_preview_sends_nothing`,
`test_update_user_role_confirmed_applies` (asserts the request path is
`/v1/user/alice/role/admin` and the exact JSON body),
`test_update_user_role_token_bound_to_role`.

**Notes**
* **BLOCKED (schema): `RESTUserRoleDomainsConfigData` is absent from Appendix B.**
  Confirmation procedure: call it against a live controller on a throwaway
  account, then read the account back with `nv_list_users` and confirm both
  `role` and `role_domains`. If the controller answers **code 6**, retry the same
  operation with the body reduced to `{"config": {"name": fullname}}` — the role
  is in the path either way — and record the accepted shape in Appendix B. Only
  if the role route turns out to be namespace-roles-only should
  `PATCH /v1/user/{fullname}` with `RESTUserConfigData` be reconsidered, and that
  is a spec change, not an implementation choice.
* `destructiveHint=False`: SPEC 6.2 classes this as a reversible config change —
  the user object survives and the previous role can be re-applied. The lock-out
  hazard lives in the docstring and in `effect`, which is what an operator
  actually reads in the plan.
* Idempotent: re-applying the same role converges.
* Common codes: **7** no such account; **4** operation not allowed — removing the
  last admin, or a role the caller's own role may not grant; **6** unknown role or
  wrong body format; **25** access denied.

---

### `nv_delete_user`

| | |
|---|---|
| **Toolset** | `iam_write` (write) |
| **Endpoints** | `DELETE /v1/user/{fullname}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING_DESTRUCTIVE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `fullname` | `str` (min_length=1) | required | Account id from nv_list_users. For a local account this is the username. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — none. `payload=None`.

**Docstring (use verbatim)**

```
Delete a user account.

Data-destroying: the account, its role assignments and its namespace roles go
away and the person can no longer log in. API keys are separate objects and are
NOT removed with the account - audit them with nv_list_api_keys and delete them
with nv_delete_api_key, or the account's automation keeps working after the
account is gone. Deleting the last admin, or your own account, is refused with
code 4 on some controllers and permitted on others, so read nv_list_users first
and be certain which account this is.

Calls DELETE /v1/user/{fullname}.
```

**Body** — §7.4 shape. `target=fullname`, `payload=None`, `namespace=None`,
`effect=f"Delete user account {fullname!r} and its role assignments. Any API keys the person created are NOT deleted."`,
applied effect `f"user {fullname} deleted"`.

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_iam.py`:
`test_delete_user_preview_sends_nothing`,
`test_delete_user_confirmed_applies`.

**Notes**
* The "API keys survive the account" warning is grounded in Appendix B:
  `RESTApikey.created_by_entity` records who created a key, and nothing in
  `RESTUser` references keys. They are independent objects on independent routes.
* Common codes: **7** no such account; **4** the default admin, the last admin, or
  the caller's own account; **25** access denied.

---

### `nv_create_api_key`

| | |
|---|---|
| **Toolset** | `iam_write` (write) |
| **Endpoints** | `POST /v1/api_key` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True` (`MUTATING_CREATE`) |
| **Returns** | `WriteOutcome` (**the secret is in `controller_response`**) |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `apikey_name` | `str` (min_length=1) | required | Name for the key. It is also the access key half of the credential and the id nv_delete_api_key takes. |
| `role` | `str` (min_length=1) | required | Global role the key carries, e.g. a name from nv_list_roles. This is the key's ceiling; a key with 'admin' can do anything to the cluster with no human in the loop. |
| `role_domains` | `dict[str, list[str]] \| None` | `None` | Namespace-scoped roles as role name -> list of namespaces. Prefer this to a broad global role for automation. |
| `expiration_type` | `str` (min_length=1) | required | How the key expires, as the controller spells it; see 'expiration_type' on an existing key via nv_list_api_keys for the accepted values. A non-expiring key is a permanent credential - justify it. |
| `expiration_hours` | `int \| None` | `None` | Lifetime in hours, when 'expiration_type' is hour-based. Set the shortest that works. |
| `description` | `str` | `""` | What this key is for and who owns it. Write it; in six months it is the only way to know whether the key is still needed. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `RESTApikeyCreationData` (Appendix B); every field from
`RESTApikeyCreation`. Note the request type has **no** `apikey_secret` field: the
controller generates the secret.

```python
apikey: dict[str, Any] = {
    "apikey_name": apikey_name,
    "role": role,
    "expiration_type": expiration_type,
    "description": description,
}
if expiration_hours is not None:
    apikey["expiration_hours"] = expiration_hours
if role_domains is not None:
    apikey["role_domains"] = {r: sorted(ns) for r, ns in role_domains.items()}
wire_payload = {"apikey": apikey}      # no secret in the REQUEST; safe == wire
```

**Docstring (use verbatim)**

```
Create an API key and return its secret - the only copy that will ever exist.

The secret half is generated by the controller, returned once in
controller_response.apikey.apikey_secret, and is not retrievable afterwards by
any route: nv_list_api_keys shows metadata only. Store it in a secret manager
the moment you get it; if you lose it, delete the key and make a new one. Scope
it hard - the key's role is its ceiling and nobody confirms its requests, so a
non-expiring admin key is a standing compromise waiting to happen. Prefer a
short 'expiration_hours' and namespace-scoped 'role_domains'. An expired key
surfaces to its holder as controller error code 3.

Calls POST /v1/api_key with {"apikey": {...}}.
```

**Body** — §7.4 shape. `target=apikey_name`, `payload=wire_payload`,
`namespace=None`,
`effect=f"Create API key {apikey_name!r} with global role {role!r} and expiration_type {expiration_type!r}. The secret is returned once and cannot be retrieved again."`,
applied effect `f"API key {apikey_name} created with role {role}; secret returned once"`, and — **uniquely in this part**:

```python
response = await app.client.request("POST", "/v1/api_key", json=wire_payload)
return WriteOutcome(
    status="applied",
    operation="nv_create_api_key",
    target=apikey_name,
    effect=f"API key {apikey_name} created with role {role}; secret returned once",
    payload=wire_payload,
    controller_response=response if isinstance(response, dict) else {},   # NOT redacted
)
```

**Fixture** `tests/fixtures/api_key_generated.json` — envelope key `apikey`
(`RESTApikeyGeneratedData` → `RESTApikeyGenerated`, fields `apikey_name` and
`apikey_secret`).

**Tests** `tests/test_iam.py`:
`test_create_api_key_preview_sends_nothing`,
`test_create_api_key_returns_secret_to_caller` (asserts
`structured_content["controller_response"]["apikey"]["apikey_secret"]` equals the
fixture's secret — this is the one place a secret is expected in a result),
`test_create_api_key_secret_not_logged` (`capfd`; the fixture's secret appears in
neither stdout nor stderr),
`test_create_api_key_confirmed_applies`.

**Notes**
* **Secret rule — this tool is the documented exception.** Redacted in the
  preview payload: nothing, because the request carries no secret. Redacted in
  logs: everything, as always — the audit record notes only that
  `nv_create_api_key` was called, with `arg_keys` and `confirmed=True`, and never
  the response body. Returned to the caller: **the secret, deliberately** — that
  is the entire point of the call, and `controller_response` is passed through
  **without** `redact_secrets` for this tool alone. Write the exception into the
  code as a comment, or a later "consistency" cleanup will break the tool.
* This is also why `apikey_secret` is in `SECRET_FIELDS`: every *other* tool's
  `controller_response` goes through `redact_secrets`, so if a future controller
  release echoes a key secret from an unrelated route it is masked by default.
  The exception is opt-in, per tool, and visible.
* `expiration_type` has no `Literal`: Appendix B declares it a plain string with
  no enum (`RESTApikeyCreation.expiration_type`). `nv_list_api_keys` is the
  enumeration. Inventing values would fail rule N2.
* Common codes: **13** duplicate key name; **15** invalid name; **6** wrong format
  or unknown role or `expiration_type`; **4** the caller's role may not grant the
  requested role; **25** access denied.

---

### `nv_delete_api_key`

| | |
|---|---|
| **Toolset** | `iam_write` (write) |
| **Endpoints** | `DELETE /v1/api_key/{accesskey}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True` (`MUTATING_DESTRUCTIVE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `access_key` | `str` (min_length=1) | required | The key's access key, which is its apikey_name from nv_list_api_keys. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — none. `payload=None`.

**Docstring (use verbatim)**

```
Revoke an API key immediately.

Data-destroying and instant: every client still using this key starts failing
authentication on its next request, which is the point when revoking a leaked
credential and a self-inflicted outage when the key belonged to a pipeline
someone forgot to tell you about. Check 'description' and 'created_by_entity' in
nv_list_api_keys first. There is no undo - the secret cannot be recreated, only
a new key issued. Note this is also how you revoke the key this MCP server
itself authenticates with, so make sure it is not that one.

Calls DELETE /v1/api_key/{accesskey}.
```

**Body** — §7.4 shape. `target=access_key`, `payload=None`, `namespace=None`,
`effect=f"Revoke API key {access_key!r}. Every client using it starts failing authentication immediately; the secret cannot be recovered."`,
applied effect `f"API key {access_key} revoked"`.

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_iam.py`:
`test_delete_api_key_preview_sends_nothing`,
`test_delete_api_key_confirmed_applies` (asserts the request path is
`/v1/api_key/<name>`).

**Notes**
* The path parameter is `{accesskey}` and its value is the key's `apikey_name`
  (`RESTApikey.apikey_name`) — the same string, two names, which is why the
  argument description says so explicitly.
* The **undocumented** `DELETE /v1/api_key/{name}` route (Appendix A.2) must
  **not** be used: it is not in `UNDOCUMENTED_ALLOWLIST`, so gate R6 fails it, and
  the documented route does the same job.
* Common codes: **7** no such key; **4** the key may not be deleted by the caller,
  e.g. it belongs to another entity; **25** access denied.

---

# Toolset `system_write` (write) — 3 tools

### `nv_update_system_config`

| | |
|---|---|
| **Toolset** | `system_write` (write) |
| **Endpoints** | `GET /v2/system/config` (pre-guard read, D.0.8), `PATCH /v2/system/config` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Highest-risk sub-fields of `RESTSystemConfigConfigDataV2`.** Enumerated from
Appendix B, worst first. "Exposed" says whether this tool can set it.

| # | Field (write path) | Why it is dangerous | Exposed |
|---|---|---|---|
| 1 | `net_config.disable_net_policy` | Disables **all** network policy enforcement cluster-wide. Every Protect group stops blocking. | yes |
| 2 | `atmo_config.mode_auto_m2p` (+ `mode_auto_m2p_duration`) | Automatic Monitor→Protect promotion. Groups start **blocking** later, with no further human action and no confirmation handshake. | yes |
| 3 | `config_v2.svc_cfg.new_service_policy_mode` | Enforcement mode every **new** service inherits. Set to Protect, a freshly deployed workload blocks traffic from its first packet. | yes |
| 4 | `net_config.net_service_policy_mode` | Cluster-wide mode for the network service. | yes |
| 5 | `net_config.net_service_status` | Enables/disables network service policy wholesale. | yes |
| 6 | `config_v2.auth_cfg.auth_order`, `auth_by_platform`, `rancher_ep` | Decides who can log in and in what order. A wrong order can lock every human out while leaving API keys working. | `auth_order`, `auth_by_platform` |
| 7 | `config_v2.syslog_cfg.syslog_ip`, `syslog_port`, `syslog_status`, `syslog_categories` | Redirects or silences the security event stream. Losing it destroys the audit trail; redirecting it exfiltrates one. | yes |
| 8 | `config_v2.webhooks[]` | **Full-list replacement**, not a merge. One wrong call silences all alerting or points events at an attacker's URL. | **no** |
| 9 | `config_v2.remote_repositories[]` | Full-list replacement; carries `github_configuration.personal_access_token`. | **no** |
| 10 | `config_v2.proxy_cfg.registry_http_proxy_cfg` / `registry_https_proxy_cfg` | Carry a proxy `password`. | status booleans only |
| 11 | `config_v2.tls_cfg.enable_tls_verification`, `cacerts` | Turning verification off makes every controller-initiated TLS connection trust anything. | `enable_tls_verification` |
| 12 | `net_config.strict_group_mode`, `detect_unmanaged_wl` | Change how workloads are grouped and whether unmanaged ones are policed; can silently widen or narrow every rule's scope. | yes |
| 13 | `config_v2.scanner_autoscale_cfg.strategy`, `min_pods`, `max_pods` | Scales scanner pods; talks to the Kubernetes API and costs money. | yes |
| 14 | `config_v2.misc_cfg.controller_debug` | Enables debug categories on the controller; noisy and can log sensitive internals. | yes |
| 15 | `config_v2.misc_cfg.unused_group_aging`, `cluster_name`, `xff_enabled`, `monitor_service_mesh`, `no_telemetry_report` | Lower risk, still cluster-wide. | yes |
| 16 | `fed_config` | Federation — **out of scope** (SPEC 1.2). | **no** |
| 17 | `config_v2.ibmsa_cfg` | IBM Security Advisor — **out of scope** (SPEC 1.2). | **no** |

**Arguments** — all optional, `None` meaning "leave unchanged", plus `confirm`.
Argument → JSON path is one-to-one; there is no free-form dict (SPEC 7.5).

| Name | Type | Default | JSON path | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|---|
| `new_service_policy_mode` | `Literal["Discover","Monitor","Protect"] \| None` | `None` | `config_v2.svc_cfg.new_service_policy_mode` | Enforcement mode every NEWLY discovered service starts in. Protect means a freshly deployed workload blocks traffic from its first packet. |
| `new_service_profile_baseline` | `str \| None` | `None` | `config_v2.svc_cfg.new_service_profile_baseline` | Process baseline strictness for new services, verbatim controller string; see 'baseline_profile' on an existing service via nv_list_services. |
| `net_service_status` | `bool \| None` | `None` | `net_config.net_service_status` | Enable or disable network service policy cluster-wide. |
| `net_service_policy_mode` | `Literal["Discover","Monitor","Protect"] \| None` | `None` | `net_config.net_service_policy_mode` | Cluster-wide network service policy mode. |
| `disable_net_policy` | `bool \| None` | `None` | `net_config.disable_net_policy` | True disables ALL network policy enforcement cluster-wide, so every Protect group stops blocking. |
| `detect_unmanaged_wl` | `bool \| None` | `None` | `net_config.detect_unmanaged_wl` | True reports workloads NeuVector does not manage. |
| `strict_group_mode` | `bool \| None` | `None` | `net_config.strict_group_mode` | True narrows how workloads are matched into groups, which changes the scope of every existing rule. |
| `mode_auto_d2m` | `bool \| None` | `None` | `atmo_config.mode_auto_d2m` | True promotes groups from Discover to Monitor automatically after mode_auto_d2m_duration. |
| `mode_auto_d2m_duration` | `int \| None` | `None` | `atmo_config.mode_auto_d2m_duration` | Seconds a group stays in Discover before automatic promotion to Monitor. |
| `mode_auto_m2p` | `bool \| None` | `None` | `atmo_config.mode_auto_m2p` | True promotes groups from Monitor to Protect automatically, so they START BLOCKING with no further human action. |
| `mode_auto_m2p_duration` | `int \| None` | `None` | `atmo_config.mode_auto_m2p_duration` | Seconds a group stays in Monitor before automatic promotion to Protect. |
| `syslog_status` | `bool \| None` | `None` | `config_v2.syslog_cfg.syslog_status` | Enable or disable syslog forwarding. Disabling it stops the external security event trail. |
| `syslog_ip` | `str \| None` | `None` | `config_v2.syslog_cfg.syslog_ip` | Syslog destination address. Changing it sends every security event somewhere new. |
| `syslog_port` | `int \| None` (ge=1, le=65535) | `None` | `config_v2.syslog_cfg.syslog_port` | Syslog destination port. |
| `syslog_level` | `str \| None` | `None` | `config_v2.syslog_cfg.syslog_level` | Minimum syslog severity, verbatim controller string. |
| `syslog_categories` | `list[str] \| None` | `None` | `config_v2.syslog_cfg.syslog_categories` | Event categories to forward. This REPLACES the current list; pass the full set you want. |
| `syslog_in_json` | `bool \| None` | `None` | `config_v2.syslog_cfg.syslog_in_json` | True forwards syslog records as JSON. |
| `auth_order` | `list[str] \| None` | `None` | `config_v2.auth_cfg.auth_order` | Authentication servers in the order they are tried. ORDER IS SIGNIFICANT and this REPLACES the list; a wrong order can lock every human out. Names from nv_list_auth_servers. |
| `auth_by_platform` | `bool \| None` | `None` | `config_v2.auth_cfg.auth_by_platform` | True delegates authentication to the platform, e.g. Rancher. |
| `enable_tls_verification` | `bool \| None` | `None` | `config_v2.tls_cfg.enable_tls_verification` | False makes controller-initiated TLS connections trust any certificate. |
| `registry_http_proxy_status` | `bool \| None` | `None` | `config_v2.proxy_cfg.registry_http_proxy_status` | Enable or disable the configured HTTP registry proxy. Proxy credentials cannot be set here. |
| `registry_https_proxy_status` | `bool \| None` | `None` | `config_v2.proxy_cfg.registry_https_proxy_status` | Enable or disable the configured HTTPS registry proxy. Proxy credentials cannot be set here. |
| `scanner_autoscale_strategy` | `Literal["","immediate","delayed"] \| None` | `None` | `config_v2.scanner_autoscale_cfg.strategy` | Scanner autoscaling strategy. Empty string disables autoscaling. |
| `scanner_min_pods` | `int \| None` (ge=0) | `None` | `config_v2.scanner_autoscale_cfg.min_pods` | Minimum scanner pods. |
| `scanner_max_pods` | `int \| None` (ge=0) | `None` | `config_v2.scanner_autoscale_cfg.max_pods` | Maximum scanner pods. Raising this raises cost. |
| `cluster_name` | `str \| None` | `None` | `config_v2.misc_cfg.cluster_name` | Cluster display name, used in events and syslog records. |
| `unused_group_aging` | `int \| None` (ge=0, le=255) | `None` | `config_v2.misc_cfg.unused_group_aging` | Hours before an unused group is aged out. |
| `controller_debug` | `list[str] \| None` | `None` | `config_v2.misc_cfg.controller_debug` | Controller debug categories to enable, from cpath, conn, mutex, scan, cluster, k8s_monitor. This REPLACES the list; pass [] to turn debugging off. |
| `monitor_service_mesh` | `bool \| None` | `None` | `config_v2.misc_cfg.monitor_service_mesh` | True monitors service-mesh sidecar traffic. |
| `xff_enabled` | `bool \| None` | `None` | `config_v2.misc_cfg.xff_enabled` | True trusts X-Forwarded-For when attributing traffic. |
| `no_telemetry_report` | `bool \| None` | `None` | `config_v2.misc_cfg.no_telemetry_report` | True stops telemetry reporting. |
| `confirm` | `str \| None` | `None` | — | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

`scanner_autoscale_strategy`'s `Literal` is the **only** enum in this tool taken
from Appendix B, where `RESTSystemConfigAutoscaleConfig.strategy` is declared
`string enum(|immediate|delayed)` — note the empty first alternative.
`controller_debug`'s six values are likewise the declared enum on
`RESTSystemConfigMiscCfgV2.controller_debug`; it stays `list[str]` because the
controller accepts any subset and validating the set client-side buys nothing.

**Read path → write path mapping**, for the old values in `effect`. The two
shapes differ and this table is the whole reason the pre-read is not trivial:

| Write path (`PATCH` body) | Read path (`GET` body) |
|---|---|
| `config_v2.svc_cfg.*` | `config.new_svc.*` |
| `config_v2.syslog_cfg.*` | `config.syslog.*` |
| `config_v2.auth_cfg.*` | `config.auth.*` |
| `config_v2.misc_cfg.*` | `config.misc.*` |
| `config_v2.proxy_cfg.*` | `config.proxy.*` |
| `config_v2.tls_cfg.*` | `config.tls_cfg.*` |
| `config_v2.scanner_autoscale_cfg.*` | `config.scanner_autoscale.*` |
| `net_config.net_service_status` | `config.net_svc.net_service_status` |
| `net_config.disable_net_policy` | `config.net_svc.disable_net_policy` |
| `net_config.detect_unmanaged_wl` | `config.net_svc.detect_unmanaged_wl` |
| `net_config.strict_group_mode` | `config.net_svc.strict_group_mode` |
| `net_config.net_service_policy_mode` | **no counterpart** — `RESTSystemConfigNetSvcV2` (read) declares `new_service_profile_baseline` where `RESTSysNetConfigConfig` (write) declares `net_service_policy_mode`. Old value is unknown; render `?`. |
| `atmo_config.*` | `config.mode_auto.*` |

**Docstring (use verbatim)**

```
Change cluster-wide system configuration, one named field at a time.

The widest-reaching tool in this server: these settings are the defaults and
kill switches behind every group and rule. disable_net_policy=true stops all
network enforcement cluster-wide; mode_auto_m2p=true makes groups start blocking
later with no human in the loop; new_service_policy_mode='Protect' makes every
newly deployed workload block from its first packet; changing syslog or
auth_order can destroy your audit trail or lock every human out. Only the fields
you pass are changed. The preview reads the current configuration first and the
'effect' string names every field with its old and new value - read it before
confirming; a '?' means the old value could not be read. Webhooks, remote
repositories, proxy credentials, federation and IBM Security Advisor settings are
deliberately not settable here.

Calls GET /v2/system/config.
Calls PATCH /v2/system/config with only the sub-objects you change.
```

**Body**

```python
app = app_context(ctx)

# --- 1. build payload: only the sub-objects that have at least one set field ---
svc_cfg = {...}; syslog_cfg = {...}; auth_cfg = {...}; misc_cfg = {...}
proxy_cfg = {...}; tls_cfg = {...}; autoscale_cfg = {...}
net_config = {...}; atmo_config = {...}
config_v2 = {k: v for k, v in (
    ("svc_cfg", svc_cfg), ("syslog_cfg", syslog_cfg), ("auth_cfg", auth_cfg),
    ("misc_cfg", misc_cfg), ("proxy_cfg", proxy_cfg), ("tls_cfg", tls_cfg),
    ("scanner_autoscale_cfg", autoscale_cfg),
) if v}
wire_payload = {k: v for k, v in (
    ("config_v2", config_v2), ("net_config", net_config), ("atmo_config", atmo_config),
) if v}
if not wire_payload:
    raise ValidationError_(
        "nv_update_system_config needs at least one field to change. No request was sent."
    )

# --- 1b. pre-guard read (D.0.8): old values for the effect string only ---
current: dict[str, Any] = {}
try:
    body = await app.client.request("GET", "/v2/system/config")
    current = body.get("config") or {} if isinstance(body, dict) else {}
except NeuVectorMCPError:
    current = {}                      # degrade to '?' rather than block the preview

changes = [
    describe_change(write_path, _lookup(current, read_path), new_value)
    for write_path, read_path, new_value in _changed_fields(wire_payload)
]
effect = _clip(
    "Change cluster-wide system configuration: " + "; ".join(changes) + ".", 1500
)[0]

# --- 2..5. standard five steps ---
plan = authorise_write(
    app.settings,
    operation="nv_update_system_config",
    toolset="system_write",
    target="cluster system configuration",
    effect=effect,
    payload=wire_payload,
    confirm=confirm,
    namespace=None,
)
if plan is not None:
    return plan

timeout_s = (
    app.settings.long_request_timeout_s
    if "scanner_autoscale_cfg" in config_v2
    else None
)
response = await app.client.request(
    "PATCH", "/v2/system/config", json=wire_payload, timeout_s=timeout_s
)
return WriteOutcome(
    status="applied",
    operation="nv_update_system_config",
    target="cluster system configuration",
    effect=effect,
    payload=wire_payload,
    controller_response=redact_secrets(response) if isinstance(response, dict) else {},
)
```

`_lookup(mapping, "a.b.c")` walks dotted read paths and returns the `_UNKNOWN`
sentinel when any segment is missing; `_changed_fields(payload)` yields
`(write_path, read_path, value)` for every leaf actually present, driven by a
module-level constant mapping the table above. Both are private helpers in
`tools/system.py`, not in `models.py`: they are specific to this one endpoint pair.

**Fixture** `tests/fixtures/system_config_v2.json` — envelope key `config`
(`RESTSystemConfigDataV2` → `RESTSystemConfigV2`). Populate `new_svc`, `syslog`,
`auth`, `misc`, `net_svc`, `mode_auto`, `scanner_autoscale` and `tls_cfg` so the
old-value lookups resolve, and deliberately **omit** one field the tests change,
so the `?` rendering is exercised.

**Tests** `tests/test_system.py`:
`test_update_system_config_preview_sends_nothing` (asserts the **PATCH** route
`call_count == 0`),
`test_update_system_config_preview_reads_current_config_only` (asserts the GET
route `call_count == 1` and the PATCH route `call_count == 0`),
`test_update_system_config_effect_names_old_and_new_values` (asserts the effect
contains `new_service_policy_mode 'Monitor' -> 'Protect'` and a `?` for the field
missing from the fixture),
`test_update_system_config_effect_degrades_when_read_fails` (GET responds 500;
preview still returns a plan, every old value is `?`),
`test_update_system_config_confirmed_applies` (asserts the exact nested JSON body
and that untouched sub-objects are **absent**, not empty),
`test_update_system_config_no_fields_raises`,
`test_system_write_hidden_when_read_only`.

**Notes**
* The pre-guard `GET` is the single exception permitted by D.0.8. It is read-only,
  on a different route, failure-tolerant, and does not feed the token — a config
  drift between preview and confirm therefore does not invalidate the token, which
  the docstring states.
* Sub-objects are **omitted** when empty, never sent as `{}`. Appendix B marks
  every sub-object on `RESTSystemConfigConfigDataV2` and its children optional, so
  an empty object is a request to set nothing and the controller's behaviour with
  one is unverified.
* `syslog_categories`, `auth_order` and `controller_debug` are **full-list
  replacements**. `auth_order` and `controller_debug` are **order-preserving** —
  never sort them, order is semantic for `auth_order` and the token must change
  when the order changes. Nothing in this tool is sorted.
* No secret is settable here by design (item 8–10 of the risk table), so `payload`
  needs no redaction. `redact_secrets` is still applied to `controller_response`,
  because `RESTSystemConfigV2` transitively contains `password` and
  `personal_access_token` and a controller that echoes its config back would
  otherwise leak them into a tool result.
* Common codes: **6** invalid value, the usual answer to a bad mode or a
  malformed syslog address; **4** the setting is ground- or federation-controlled
  and may not be changed locally; **28** Kubernetes API error, typically from
  `scanner_autoscale_cfg`; **8** write to cluster failed (retried by `client.py`);
  **20** licence; **25** access denied.
* `PATCH /v1/system/config` (`RESTSystemConfigConfigData`, the V1 body) is
  documented and **not** used: the V2 pair is the one whose request *and* response
  types are both in Appendix B.

---

### `nv_set_namespace_tags`

| | |
|---|---|
| **Toolset** | `system_write` (write) |
| **Endpoints** | `PATCH /v1/domain/{name}` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `namespace` | `str` (min_length=1) | required | Namespace to tag, from nv_list_namespaces. |
| `tags` | `list[str]` | required | Compliance tags to set on the namespace, e.g. ['PCI', 'GDPR']. This REPLACES the namespace's current tags rather than adding to them; pass the full set you want, and [] to clear them. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — defensive shape, `BLOCKED (schema)`:

```python
wire_payload = {"config": {"name": namespace, "tags": sorted(set(tags))}}
```

`tags` is `array<string>` on `RESTDomain` (verified in Appendix B). Deduplicated
and sorted: tags are a set, and normalising makes the confirm token independent of
the order the model listed them in.

**Docstring (use verbatim)**

```
Set the compliance tags on one namespace.

Tags drive which compliance checks and CIS benchmark items are reported for
everything in the namespace, so this changes what nv_get_compliance_findings and
nv_get_bench_report consider a finding - it does not change enforcement and
blocks no traffic. The list REPLACES the namespace's current tags, so read them
from nv_list_namespaces first or you will silently drop the ones you did not
mention. Per-namespace tagging must be enabled cluster-wide: nv_list_namespaces
reports that as 'tag_per_domain', and the controller answers code 4 when it is
off.

Calls PATCH /v1/domain/{name} with {"config": {"name":..., "tags":[...]}}.
```

**Body** — §7.4 shape. `target=namespace`, `namespace=namespace` (the target
**is** the namespace, so `NV_ALLOWED_NAMESPACES` applies directly),
`effect=f"Set the compliance tags of namespace {namespace!r} to {sorted(set(tags))}, replacing its current tags."`,
applied effect `f"tags of namespace {namespace} set to {sorted(set(tags))}"`.

**Fixture** — none; respond `200, json={}`. Tests that need current tags reuse
`tests/fixtures/domains.json` (envelope `domains`) from Part A.

**Tests** `tests/test_system.py`:
`test_set_namespace_tags_preview_sends_nothing`,
`test_set_namespace_tags_confirmed_applies`,
`test_set_namespace_tags_normalises_tag_order`,
`test_set_namespace_tags_outside_allowed_namespace_refused`.

**Notes**
* **BLOCKED (schema): `RESTDomainEntryConfigData` is absent from Appendix B.** The
  endpoint is documented (Appendix A.1, tag `Namespace`). Confirmation procedure:
  apply against a live controller, then call `nv_list_namespaces` and confirm
  `tags` came back as sent. If the controller answers **code 6**, try
  `{"config": {"tags": [...]}}` without the `name` echo and record the accepted
  shape in Appendix B.
* `PATCH /v1/domain` (no name, body `RESTDomainConfigData`, also absent from
  Appendix B) toggles `tag_per_domain` cluster-wide and is **not** exposed. If
  tagging is off, that is an operator action in the UI, not something this tool
  should silently enable.
* Common codes: **7** unknown namespace; **4** per-domain tagging disabled
  cluster-wide; **6** wrong body format; **25** access denied.

---

### `nv_update_scan_config`

| | |
|---|---|
| **Toolset** | `system_write` (write) |
| **Endpoints** | `PATCH /v1/scan/config` |
| **Annotations** | `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True` (`MUTATING_UPDATE`) |
| **Returns** | `WriteOutcome` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `auto_scan` | `bool \| None` | `None` | Global auto-scan switch. True makes the controller scan workloads and hosts automatically; it is overridden for either target by enable_auto_scan_workload or enable_auto_scan_host when those are set. |
| `enable_auto_scan_workload` | `bool \| None` | `None` | Auto-scan workloads specifically. Omit to leave it to the global auto_scan setting. |
| `enable_auto_scan_host` | `bool \| None` | `None` | Auto-scan hosts specifically. Omit to leave it to the global auto_scan setting. |
| `confirm` | `str \| None` | `None` | Confirmation token from the plan returned by the first call. Omit on the first call to preview the change. |

**Payload** — `RESTScanConfigData` (Appendix B), all three fields optional on
`RESTScanConfigConfig`; only the arguments that are not `None` are included:

```python
config = {k: v for k, v in (
    ("auto_scan", auto_scan),
    ("enable_auto_scan_workload", enable_auto_scan_workload),
    ("enable_auto_scan_host", enable_auto_scan_host),
) if v is not None}
if not config:
    raise ValidationError_(
        "nv_update_scan_config needs at least one field to change. No request was sent."
    )
wire_payload = {"config": config}
```

**Docstring (use verbatim)**

```
Turn cluster-wide automatic vulnerability scanning on or off.

Enabling auto-scan makes the controller scan every workload and host it does not
have a current report for, which on a large cluster is a scanning storm that
occupies the scanners for a long while and delays every registry scan and ad-hoc
scan behind it - enable it during a quiet window. Disabling it is the quieter
change but it silently stops new reports, so nv_get_scan_report keeps answering
with data that ages out. The two enable_auto_scan_* switches override the global
auto_scan for their target, so you can auto-scan workloads and leave hosts alone.
Only the fields you pass are changed.

Calls PATCH /v1/scan/config with {"config": {...}}.
```

**Body** — §7.4 shape. `target="cluster scan configuration"`, `namespace=None`,
default timeout,
`effect="Change cluster-wide scan configuration: " + ", ".join(f"{k}={v!r}" for k, v in sorted(config.items())) + ". Enabling auto-scan starts scanning every workload and host without a current report."`

**Fixture** — none; respond `200, json={}`.

**Tests** `tests/test_system.py`:
`test_update_scan_config_preview_sends_nothing`,
`test_update_scan_config_confirmed_applies`,
`test_update_scan_config_sends_only_provided_fields`,
`test_update_scan_config_no_fields_raises`.

**Notes**
* No pre-read: `GET /v1/scan/config` returns `RESTScanConfigResp`, which is
  **absent from Appendix B** (D.0.7), so old values cannot be projected safely and
  the `effect` names new values only. This is why `nv_update_scan_config` is not a
  second exception to D.0.8.
* The `auto_scan` / `enable_auto_scan_*` precedence in the docstring is quoted
  from Appendix B's own field descriptions on `RESTScanConfigConfig`, not inferred.
* `namespace=None`: cluster-wide, so `NV_ALLOWED_NAMESPACES` cannot scope it.
* Common codes: **6** wrong body format; **4** the setting is ground-controlled;
  **8** write to cluster failed (retried by `client.py`); **25** access denied.

---

## D.1 Test files, fixtures and function names

### D.1.1 Test files

| File | Phase | Tools covered |
|---|---|---|
| `tests/test_scan_ops.py` | 9 | all 7 `scan_ops` tools |
| `tests/test_runtime_ops.py` | 9 | all 4 `runtime_ops` tools |
| `tests/test_iam.py` | 10 | extends the Part B file with the 5 `iam_write` tools |
| `tests/test_system.py` | 10 | all 3 `system_write` tools |

Gate R8 matches on the **literal quoted tool name**, so each of the 19 names must
appear as `"nv_..."` in one of these files.

### D.1.2 Mandatory cases per tool (SPEC 10.2)

| Case | Applies to | Asserts |
|---|---|---|
| **preview sends nothing** | all 19 | `status == "confirmation_required"`, `len(confirm_token) == 12`, and `route.call_count == 0` on the **mutating** route |
| **confirmed applies** | all 19 | `status == "applied"`, `route.call_count == 1`, and the **exact** JSON body via `json.loads(route.calls.last.request.read())` |
| **token binding** | ≥1 per module | a token computed for different arguments is rejected with `"confirm token mismatch"` |
| **read-only hiding** | once per module | the tool is absent from `list_tools()` when `NV_READ_ONLY=true` |
| **error classification** | ≥1 per module | `code=25` → permission error, `code=7` → not found |
| **secret not logged** | every secret-bearing tool | the literal secret appears in neither stdout nor stderr |

Per-module read-only hiding tests: `test_scan_ops_hidden_when_read_only`,
`test_runtime_ops_hidden_when_read_only`, `test_iam_write_hidden_when_read_only`,
`test_system_write_hidden_when_read_only`. Each builds a server with
`make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS)` and asserts the write
tool names are absent while a read tool name is present, exactly as
`test_guard.py::test_read_only_hides_mutating_toolsets` does.

Per-module error-classification tests:
`test_scan_ops_error_codes_classify` (`code=27` → `UpstreamError` because 27 is
absent from `_CODE_MAP`; `code=7` → `NotFoundError`),
`test_runtime_ops_error_codes_classify` (`code=22` → `ConflictError`, `code=25` →
permission error),
`test_iam_write_error_codes_classify` (`code=13` → `ConflictError`, `code=14` →
`UpstreamError`/status fallback, `code=25` → permission error),
`test_system_write_error_codes_classify` (`code=6` → `ValidationError_`,
`code=25` → permission error).

### D.1.3 Secret-not-logged tests — the five of them

| Test | File | Secret |
|---|---|---|
| `test_scan_repository_password_not_logged` | `test_scan_ops.py` | registry password in the request body |
| `test_create_registry_password_not_logged` | `test_scan_ops.py` | registry password in the request body |
| `test_update_registry_password_not_logged` | `test_scan_ops.py` | replacement registry password |
| `test_create_user_password_not_logged` | `test_iam.py` | user password |
| `test_create_api_key_secret_not_logged` | `test_iam.py` | generated API key secret in the **response** |

All five follow one shape. Use `capfd`, **not** `capsys`: `configure_logging`
builds structlog with `PrintLoggerFactory(file=sys.stderr)` and
`cache_logger_on_first_use=True`, so the stream is bound once and only
file-descriptor-level capture sees it.

```python
SECRET = "n0t-a-real-p4ssword"

async def test_create_user_password_not_logged(client, nv_mock, capfd) -> None:
    route = nv_mock.post("/v1/user").respond(200, json={})
    args = {"username": "alice", "password": SECRET, "role": "admin"}
    plan = await client.call_tool("nv_create_user", args)
    token = plan.structured_content["confirm_token"]
    result = await client.call_tool("nv_create_user", {**args, "confirm": token})

    assert result.structured_content["payload"]["user"]["password"] == "***"
    assert SECRET not in json.dumps(result.structured_content)
    assert json.loads(route.calls.last.request.read())["user"]["password"] == SECRET
    out, err = capfd.readouterr()
    assert SECRET not in out and SECRET not in err
    assert "password" in out + err or True   # key NAMES may appear; values may not
```

### D.1.4 Fixtures

| File | Envelope key | Used by |
|---|---|---|
| `tests/fixtures/scan_repo_report.json` | `report` (`RESTScanRepoReportData`) | `nv_scan_repository` |
| `tests/fixtures/api_key_generated.json` | `apikey` (`RESTApikeyGeneratedData`) | `nv_create_api_key` |
| `tests/fixtures/system_config_v2.json` | `config` (`RESTSystemConfigDataV2`) | `nv_update_system_config` pre-read |
| *(reused)* `tests/fixtures/domains.json` | `domains` | `nv_set_namespace_tags` current-tags assertions |
| *(reused)* `tests/fixtures/services.json` | `services` | `nv_set_service_mode` name/namespace assertions |
| *(reused)* `tests/fixtures/registries.json` | `summarys` | registry-tool round-trip assertions |

**Three new fixtures only.** Sixteen of the nineteen tools hit routes whose
documented 200 schema is `object` — an empty body — so their tests respond
`200, json={}` inline. Do not invent fixture files for empty bodies; an invented
shape is worse than none (SPEC 10.1).

---

## D.2 Endpoint verification record

All 25 `Calls` targets in this document were extracted with `verify_spec.CALLS_RE`
and resolved with `verify_spec.path_matches` against `spec_endpoints.json` (232
documented, 112 undocumented). Result: **25 documented, 0 undocumented, 0
invented, 0 BLOCKED on a missing endpoint.**

| Endpoint | Tool |
|---|---|
| `POST /v1/scan/workload/{id}` | `nv_trigger_scan` |
| `POST /v1/scan/host/{id}` | `nv_trigger_scan` |
| `POST /v1/scan/registry/{name}/scan` | `nv_trigger_scan` |
| `DELETE /v1/scan/registry/{name}/scan` | `nv_stop_registry_scan` |
| `POST /v1/scan/repository` | `nv_scan_repository` |
| `POST /v2/scan/registry` | `nv_create_registry` |
| `PATCH /v2/scan/registry/{name}` | `nv_update_registry` |
| `DELETE /v1/scan/registry/{name}` | `nv_delete_registry` |
| `POST /v1/bench/host/{id}/kubernetes` | `nv_trigger_bench_run` |
| `POST /v1/bench/host/{id}/docker` | `nv_trigger_bench_run` |
| `POST /v1/workload/request/{id}` | `nv_quarantine_workload` |
| `PATCH /v1/service/config` | `nv_set_service_mode` |
| `PATCH /v1/service/config/network` | `nv_set_service_mode` |
| `PATCH /v1/service/config/profile` | `nv_set_service_mode` |
| `POST /v1/sniffer` | `nv_start_packet_capture` |
| `PATCH /v1/sniffer/stop/{id}` | `nv_stop_packet_capture` |
| `POST /v1/user` | `nv_create_user` |
| `PATCH /v1/user/{fullname}/role/{role}` | `nv_update_user_role` |
| `DELETE /v1/user/{fullname}` | `nv_delete_user` |
| `POST /v1/api_key` | `nv_create_api_key` |
| `DELETE /v1/api_key/{accesskey}` | `nv_delete_api_key` |
| `GET /v2/system/config` | `nv_update_system_config` (pre-guard read) |
| `PATCH /v2/system/config` | `nv_update_system_config` |
| `PATCH /v1/domain/{name}` | `nv_set_namespace_tags` |
| `PATCH /v1/scan/config` | `nv_update_scan_config` |

Documented routes deliberately **not** used, each with the reason stated in the
owning tool's Notes: `GET /v1/sniffer/{id}/pcap` (binary payload — fetch out of
band), `DELETE /v1/sniffer/{id}` (destroys a capture; outside `runtime_ops`'s four
tools), `PATCH /v1/workload/{id}` (`RESTWorkloadConfigData` absent from Appendix B),
`PATCH /v1/user/{fullname}` (general user update — wider blast radius than the
role route), `POST /v1/user/{fullname}/password` (outside `iam_write`'s five
tools), `PATCH /v1/system/config` (V1 body), `PATCH /v1/domain`
(`tag_per_domain` toggle), `POST /v1/scan/registry`, `PATCH /v1/scan/registry/{name}`
(V1 registry bodies), `POST /v1/system/config/webhook*` (outside `system_write`'s
three tools), `POST /v1/system/request` (bulk un-quarantine).

Undocumented routes referenced only to forbid them: `DELETE /v1/api_key/{name}`,
`POST /v1/scan/result/repository`, `GET /v1/list/registry_type`.

**Schema gaps: 4 `BLOCKED (schema)` + 1 `BLOCKED (partial)`** — `RESTRegistryConfigDataV2`
(2 tools), `RESTUserRoleDomainsConfigData`, `RESTDomainEntryConfigData`, the
`POST /v1/sniffer` 200 body, and the `RESTWorkloadRequest.command` value set.
Each has a defensive shape whose every field name comes from a type that *is* in
Appendix B, plus a written live-controller confirmation step. No tool is blocked
outright.

---

## D.3 Gate checklist

| Gate rule | How Part D satisfies it |
|---|---|
| **R1** | All 19 names match `^nv_[a-z0-9_]+$`. |
| **R2** | Every docstring has a summary line, a blast-radius paragraph and at least one `Calls` line; all exceed 80 characters and 3 lines. |
| **R3** | Every tool uses one of the four constants in D.0.3, all with `readOnlyHint=False`; all four toolsets are write-kind in `config.MUTATING_TOOLSETS`. |
| **R4** | Exactly one toolset tag per tool: `scan_ops` (7), `runtime_ops` (4), `iam_write` (5), `system_write` (3) = 19. |
| **R5** | Every tool declares `confirm: str \| None = None` as its last parameter. |
| **R6** | 25 `Calls` lines over 25 distinct endpoints, every one in `spec_endpoints.json["documented"]`; nothing needs `UNDOCUMENTED_ALLOWLIST` or `NV_ALLOW_UNDOCUMENTED`. |
| **R7** | Every tool returns `WriteOutcome`. `nv_scan_repository`'s projected report travels inside `WriteOutcome.controller_response`; it is not a second return type. |
| **R8** | Every name appears in `tests/test_scan_ops.py`, `tests/test_runtime_ops.py`, `tests/test_iam.py` or `tests/test_system.py` as listed per tool. |
| **R9** | Satisfied several times over: 19 mutating tools register when all toolsets are enabled. |

**New `models.py` classes and helpers** (append in this order; Phase 9 first):
`SECRET_FIELDS`, `REDACTED`, `redact_secrets`, `service_namespace`,
`RepositoryScanReport` [P9]; `_UNKNOWN`, `describe_change` [P10]. `Page`,
`WriteOutcome`, `PolicyMode`, `SeverityCounts`, `VulnerabilityFinding`, `_BASE`,
`_clip`, `normalise_severity` and `severity_rank` already exist — reference them,
never redefine them.

**Phase 9 target tool count:** 11 new (`scan_ops` 7 + `runtime_ops` 4).
**Phase 10 target tool count:** 12 new (`iam_read` 4 from Part B + `iam_write` 5 +
`system_write` 3), bringing the full surface to **72** and the default read-only
surface to **41** (SPEC 8).
