# neuvector-mcp
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdarthzen%2Fneuvector-mcp.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdarthzen%2Fneuvector-mcp?ref=badge_shield)


A Model Context Protocol server over the SUSE NeuVector container security
control plane. It exposes NeuVector's inventory, vulnerability, compliance,
event and policy surface as 72 typed MCP tools, so an operator or an agent can
ask questions like *"which prod workloads run images with critical CVEs and are
still in Discover mode"* and, behind an explicit two-step confirmation, act on
the answer. It ships as one SUSE BCI image that runs either over `stdio` for
a desktop MCP client or over authenticated HTTP in-cluster.

**Read-only by default.** Of the 72 tools, only the 41 read tools are registered
unless you deliberately turn a mutating toolset on.

---

## Contents

- [Quick start — stdio](#quick-start--stdio)
- [Quick start — in-cluster HTTP](#quick-start--in-cluster-http)
- [Configuration](#configuration)
- [Toolsets](#toolsets)
- [The confirmation handshake](#the-confirmation-handshake)
- [NeuVector API key provisioning](#neuvector-api-key-provisioning)
- [Verified vs unverified](#verified-vs-unverified)
- [Known issues](#known-issues)
- [Running the gate](#running-the-gate)

---

## Quick start — stdio

`stdio` inherits the trust boundary of the parent process, so it carries no
transport auth. Use it only for a local desktop client.

Four environment variables and one command:

```bash
export NV_CONTROLLER_URL=https://<controller-host>:10443
export NV_API_ACCESS_KEY=<apikey_name>
export NV_API_SECRET_KEY=<apikey_secret>
export NV_VERIFY_TLS=false      # the controller serves a self-signed cert by default

neuvector-mcp
```

`NV_TRANSPORT` defaults to `stdio` and `NV_READ_ONLY` defaults to `true`, so the
above gives you the 41 read tools and nothing else.

### Client configuration block

```json
{
  "mcpServers": {
    "neuvector": {
      "command": "neuvector-mcp",
      "env": {
        "NV_CONTROLLER_URL": "https://192.0.2.10:10443",
        "NV_API_ACCESS_KEY": "mcp-reader",
        "NV_API_SECRET_KEY": "…",
        "NV_VERIFY_TLS": "false"
      }
    }
  }
}
```

If you installed into a virtualenv rather than onto `PATH`, use the absolute
path to the `neuvector-mcp` console script as `command`. The server writes
nothing to stdout except MCP JSON-RPC framing; all diagnostics go to stderr.

### Verify the connection

```bash
python3 scripts/smoke_stdio.py
```

Reports the tool count, the system summary, and up to five workloads with their
policy mode and high-severity vulnerability count. Read tools only — it performs
no mutation regardless of `NV_READ_ONLY`.

---

## Quick start — in-cluster HTTP

HTTP is network-reachable, so it **must** be authenticated. The server refuses
to start on `NV_TRANSPORT=http` without at least one bearer token in
`NV_HTTP_BEARER_TOKENS`.

### 1. Build and push the image

```bash
make image                                   # podman build, SUSE BCI base
podman push localhost:5000/neuvector-mcp:1.0.3 <your-registry>/neuvector-mcp:1.0.3
```

Override the tag or registry with `make image REGISTRY=<host> TAG=<tag>`.

The base is `registry.suse.com/bci/python:3.13` (SLE-based, SUSE-supported
lifecycle). The openSUSE equivalent, `registry.opensuse.org/opensuse/bci/python`,
is the only other permitted base — but as of 2026-07 its `:3.13` manifest list
carries no `linux/amd64` image, so it cannot build on x86_64. Its `:3.12` tag
can. No base outside those two is permitted.

**No local container runtime?** The image builds fine in-cluster with a
throwaway rootless BuildKit pod. `kubectl cp` the build context (`pyproject.toml`,
`README.md`, `src/`, `deploy/Dockerfile`) to `/workspace/src`, mount a registry
credential as `/home/user/.docker/config.json`, then:

```bash
kubectl exec <pod> -- sh -c 'BUILDKITD_FLAGS=--oci-worker-no-process-sandbox \
  buildctl-daemonless.sh build --frontend dockerfile.v0 \
    --local context=/workspace/src --local dockerfile=/workspace/src/deploy \
    --opt platform=linux/amd64 \
    --output type=image,name=<registry>/neuvector-mcp:1.0.3,push=true'
```

`--oci-worker-no-process-sandbox` is required: without it every `RUN` step dies
with `error mounting "proc" to rootfs ... operation not permitted`, because a
rootless pod cannot nest the process sandbox's user namespace.

### 2. Fill in the three placeholder values

`deploy/deployment.yaml` ships with three `REPLACE_ME` values. Do not commit
real ones; manage the two Secrets with SOPS or External Secrets instead.

| Location | Replace with |
|---|---|
| `Secret/neuvector-mcp-controller` `access-key`, `secret-key` | The NeuVector API key pair — see [provisioning](#neuvector-api-key-provisioning) |
| `Secret/neuvector-mcp-clients` `bearer-tokens` | `openssl rand -hex 32`, formatted `<token>:nv:read` |
| `Deployment` `image` | Your registry path |

The bearer-token string is `token:scope|scope,token2:scope`. A token with no
scope suffix defaults to `nv:read`.

Check the `NetworkPolicy` egress selector against your cluster: it targets
`kubernetes.io/metadata.name: cattle-neuvector-system` on port 10443. If
NeuVector runs in another namespace, change the selector, not the port.

### 3. Apply

```bash
kubectl apply --dry-run=server -f deploy/deployment.yaml   # check first
kubectl apply -f deploy/deployment.yaml
```

The namespace is labelled `pod-security.kubernetes.io/enforce: restricted`, so
the server-side dry run is a real admission check rather than a formality. Note
that a dry run against a cluster where the `neuvector-mcp` namespace does not
yet exist will report `namespaces "neuvector-mcp" not found` for every
namespaced object — the dry-run Namespace is never persisted. Create the
namespace first if you want the dry run to exercise PodSecurity.

The namespace, PodSecurity `restricted` admission, and the image have all been
exercised for real on a k3s cluster — the pod is admitted and runs as uid 10001
with a read-only root filesystem.

`deploy/fleet.yaml` is a Fleet bundle for the same manifests. It excludes both
Secrets from Fleet's diff, so GitOps never reverts externally managed
credentials.

For MCP clients outside the cluster, apply `deploy/service-loadbalancer.yaml`
**instead of** the ClusterIP Service in `deployment.yaml` — both use the name
`neuvector-mcp`. It carries a MetalLB annotation for a fixed address; other
LoadBalancer implementations spell that differently, and omitting it lets the
controller pick. The `NetworkPolicy` needs no change: its ingress rule has no
`from` selector, so off-cluster sources on port 8080 are already admitted, and
the bearer token is what actually authorises them.

### 4. Point a client at it

```
POST https://<service>:8080/mcp
Authorization: Bearer <the token you generated>
```

---

## Configuration

Every knob is an environment variable prefixed `NV_`. Each also accepts
`NV_<NAME>_FILE` pointing at a file whose contents are the value, so Kubernetes
Secrets can be mounted rather than injected.

| Variable | Default | Meaning |
|---|---|---|
| `NV_CONTROLLER_URL` | `https://127.0.0.1:10443` | Controller REST base URL. Must start `http://` or `https://`. A trailing slash is stripped. |
| `NV_VERIFY_TLS` | `true` | Set `false` for the controller's default self-signed cert. |
| `NV_CA_BUNDLE` | — | Path to a CA bundle. Takes precedence over `NV_VERIFY_TLS`. |
| `NV_REQUEST_TIMEOUT_S` | `30` | Timeout for normal calls, in seconds. |
| `NV_LONG_REQUEST_TIMEOUT_S` | `300` | Timeout for scan, bench and repository-scan calls, in seconds. |
| `NV_AUTH_MODE` | `apikey` | `apikey` or `password`. |
| `NV_API_ACCESS_KEY` | — | Required when `NV_AUTH_MODE=apikey`. The API key's `apikey_name`. |
| `NV_API_SECRET_KEY` | — | Required when `NV_AUTH_MODE=apikey`. The API key's `apikey_secret`. |
| `NV_USERNAME` | — | Required when `NV_AUTH_MODE=password`. |
| `NV_PASSWORD` | — | Required when `NV_AUTH_MODE=password`. |
| `NV_TRANSPORT` | `stdio` | `stdio` or `http`. |
| `NV_HTTP_HOST` | `0.0.0.0` | HTTP transport bind address. |
| `NV_HTTP_PORT` | `8080` | HTTP transport bind port. |
| `NV_HTTP_PATH` | `/mcp` | HTTP transport request path. |
| `NV_HTTP_BEARER_TOKENS` | — | **Required for `http`.** `token:scope\|scope,token2:scope`. Startup fails without it on HTTP. |
| `NV_READ_ONLY` | `true` | `true` refuses every mutation and does not register mutating toolsets at all. |
| `NV_TOOLSETS` | the six read toolsets | Comma-separated list; see [Toolsets](#toolsets). |
| `NV_REQUIRE_CONFIRM_TOKEN` | `true` | `false` removes the two-step handshake. Only for automation that has its own approval gate. |
| `NV_ALLOWED_NAMESPACES` | — | When set, mutations targeting a namespace outside this list are refused. |
| `NV_ALLOW_UNDOCUMENTED` | `false` | Gates tools that use routes absent from the controller's Swagger. |
| `NV_MAX_ITEMS` | `200` | Hard cap on any list tool's page size. |
| `NV_MAX_RESPONSE_CHARS` | `60000` | Truncation budget per tool result. Truncated results set `truncated=true`. |
| `NV_LOG_LEVEL` | `INFO` | Standard Python log level name. |
| `NV_LOG_FORMAT` | `json` | `json` or `console`. |
| `NV_AUDIT_LOG_PATH` | — | Optional second sink for audit records. |

`NV_READ_ONLY=true` together with any mutating toolset is a **startup error**,
not a silent downgrade. Contradictory configuration fails loudly.

---

## Toolsets

There are 12 toolsets. A toolset is either read-only or mutating, never mixed —
the gate derives each tool's `readOnlyHint` from its toolset tag.

| Toolset | Kind | On by default | Tools | Contents |
|---|---|---|---|---|
| `inventory` | read | yes | 11 | workloads, hosts, groups, services, enforcers, namespaces, network conversations |
| `vulnerability` | read | yes | 7 | image/workload/host scan reports, registries, scanners, vulnerability profiles |
| `compliance` | read | yes | 4 | workload/host compliance, CIS bench reports, compliance profiles |
| `events` | read | yes | 5 | threats, violations, incidents, audits, system events, alerts |
| `policy_read` | read | yes | 10 | network rules, process/file profiles, DLP/WAF sensors, response rules, admission state and rules, admission rule assessment |
| `iam_read` | read | yes | 4 | users, roles, auth servers, API keys (metadata only) |
| `policy_write` | write | **no** | 8 | create/update/delete groups, network rules, process and file-monitor profiles |
| `admission` | write | **no** | 4 | admission control state and rules |
| `scan_ops` | write | **no** | 7 | trigger/stop scans, registry CRUD, repository scan, bench runs |
| `runtime_ops` | write | **no** | 4 | quarantine, service mode changes, packet capture |
| `iam_write` | write | **no** | 5 | user, role and API key mutations |
| `system_write` | write | **no** | 3 | system config, namespace tags, scan config |
| | | | **72** | |

**The default surface is 41 read tools. All 31 mutating tools are OFF by
default.** With `NV_TOOLSETS` and `NV_READ_ONLY` unset, `tools/list` returns
exactly the 41 read tools; the mutating ones are never registered, so they are
not merely refused, they are absent.

To enable a mutating toolset you must do two things:

```bash
export NV_READ_ONLY=false
export NV_TOOLSETS=inventory,vulnerability,compliance,events,policy_read,iam_read,policy_write
```

Naming a mutating toolset without also setting `NV_READ_ONLY=false` is a startup
error. Enable the narrowest set that does the job, and provision the API key's
NeuVector role to match — see the safety model below.

### Safety model

Five independent layers. A mutation must clear all five.

```
 1. Transport auth ── HTTP requires a bearer token; stdio inherits process trust
 2. Controller RBAC ─ the API key's NeuVector role is the real ceiling
 3. NV_READ_ONLY ──── mutating toolsets are not registered at all
 4. NV_TOOLSETS ───── unenabled toolsets are absent from tools/list
 5. Confirm token ─── per-operation, payload-bound, two-step handshake
```

Layer 2 is the one that actually protects the cluster. The other four protect
against model error, not against a compromised credential.

---

## The confirmation handshake

Every mutating tool takes an optional `confirm` argument. Call it once **without**
`confirm` and nothing is sent to the controller — you get back a plan describing
the exact effect, the exact request body, and a token. Call it again with
identical arguments plus that token to execute.

The token is `sha256(operation | target | canonical_json(payload))[:12]`. Change
any argument that feeds the payload and the token stops matching, so a token
issued for one change cannot be replayed against a different one. This is a
**guard rail, not a security boundary** — a model could compute it in principle;
the point is that it cannot do so *accidentally*.

`target` is usually the bare object name, but it is not required to be. Where an
argument reaches the controller in the **URL path** rather than the body, it is
in neither the payload nor the object name, and folding it into `target` is the
only thing that binds the token to it. `nv_update_user_role` is the case that
matters: its `role` travels in the path, so its target is
`"<fullname> role=<role>"`, not `"<fullname>"`. Without that, a token previewed
for `role="reader"` would also authorise `role="admin"` — the handshake would
fail to gate the single field the tool exists to change. The controller call and
the request body are untouched by this; only the hashed target differs. Keep this
in mind when adding any mutating tool with path parameters.

### Worked example

Call 1 — preview:

```json
{"name": "nv_set_group_policy_mode",
 "arguments": {"group_name": "nv.api.prod", "mode": "Protect"}}
```

Response. Nothing was sent to the controller:

```json
{
  "status": "confirmation_required",
  "operation": "nv_set_group_policy_mode",
  "target": "nv.api.prod",
  "effect": "Set policy mode of group 'nv.api.prod' to Protect. Traffic and process activity outside the learned policy will be blocked immediately.",
  "payload": {"config": {"name": "nv.api.prod", "policy_mode": "Protect"}},
  "confirm_token": "b670afec803f",
  "next_step": "Review 'effect' and 'payload'. To execute, call nv_set_group_policy_mode again with identical arguments plus confirm='b670afec803f'."
}
```

Call 2 — execute:

```json
{"name": "nv_set_group_policy_mode",
 "arguments": {"group_name": "nv.api.prod", "mode": "Protect",
               "confirm": "b670afec803f"}}
```

Response:

```json
{
  "status": "applied",
  "operation": "nv_set_group_policy_mode",
  "target": "nv.api.prod",
  "effect": "policy_mode of nv.api.prod set to Protect",
  "payload": {"config": {"name": "nv.api.prod", "policy_mode": "Protect"}}
}
```

Change `mode` to `Monitor` while keeping the old token and the guard raises a
mismatch error telling you to call again without `confirm` for a fresh plan.

---

## NeuVector API key provisioning

1. NeuVector UI → **Settings → API Keys → Add**.
2. Role: **`reader` suffices for read-only deployments** — that is, for the
   default 41-tool surface. For mutating toolsets, pick the narrowest role that
   covers them; use `admin` only when `iam_write` or `system_write` is enabled.
3. Set an expiry and calendar the rotation. An expired key surfaces as the
   controller error `code=3`.
4. Store `apikey_name` as `NV_API_ACCESS_KEY` and `apikey_secret` as
   `NV_API_SECRET_KEY`. **The secret is shown once.**

The API key's role is the real ceiling on what this server can do. A `reader`
key makes every mutating tool fail at the controller even if `NV_READ_ONLY` is
misconfigured.

---

## Verified vs unverified

Read this before you rely on any of it.

Every tool in this server was built from appendices **generated by parsing the
NeuVector source**. The majority of the surface is schema-backed: the request
paths come from a generated endpoint inventory, and the response field names
come from a generated field-level schema reference. The offline test suite
remains authoritative for CI, which has no cluster.

**A small subset has now been exercised against a live 5.4 controller** —
`nv_list_registries`, `nv_create_registry`, `nv_update_registry`,
`nv_trigger_scan`, `nv_delete_registry`, and the startup `login()` probe against
`GET /v1/system/summary`. Everything outside that list is still unvalidated
against a running controller. That first live run immediately found a defect the
table below had mis-predicted; see **What the live run changed**.

The items below are the exceptions. For each, the type that would have pinned
the shape was **absent** from the schema reference, so the implementation either
inferred an envelope key or wrote a defensive extraction. A real controller can
contradict any of them.

| Endpoint | Tool | What is unverified | Failure mode if wrong |
|---|---|---|---|
| `GET /v1/compliance/profile/{name}` | `nv_get_compliance_profile` | Envelope key `"profile"` inferred; no `RESTComplianceProfileData` in Appendix B | Degrades to `NotFoundError` |
| `GET /v1/server` | `nv_list_auth_servers` | `RESTServer` / `RESTServersData` absent; envelope key `"servers"` inferred | Degrades to an empty list |
| `GET /v1/conversation` | `nv_get_network_conversations` | No Appendix B type at all; best-effort projection | Fields may come back empty |
| `GET /v1/system/alerts` | `nv_get_system_alerts` | `RESTNvAlerts` absent; defensive extraction | Returns `envelope_keys` diagnostically instead of alerts |
| `GET /v1/file_monitor/{name}` | `nv_get_file_monitor_profile` | `RESTFileMonitorFile` absent; probes `filters` → `profile.filters` → first list-valued key | Wrong or empty filter list |
| `GET /v1/dlp/sensor` | `nv_list_dlp_sensors` | `RESTDlpSensor` absent; envelope key `"sensors"` inferred | Degrades to an empty list |
| `GET /v1/waf/sensor` | `nv_list_waf_sensors` | `RESTWafSensor` absent; envelope key `"sensors"` inferred | Degrades to an empty list |
| `GET /v1/scan/scanner` | `nv_list_scanners` | `RESTScannerData` absent; three-field best-effort projection | Missing or empty scanner fields |
| `PATCH /v1/user/{fullname}/role/{role}` | `nv_update_user_role` | `RESTUserRoleDomainsConfigData` absent; defensive body shape | Controller rejects the body, or applies a partial change |
| `PATCH /v1/domain/{name}` | `nv_set_namespace_tags` | `RESTDomainEntryConfigData` absent; defensive body shape | Controller rejects the body |
| `PATCH /v1/admission/state` | `nv_set_admission_state` | `RESTAdmissionConfigData.k8s_env` is marked **required** in the schema but is deliberately **not sent** | Controller rejects the body as incomplete |

Each row is a place where the implementation had to choose without evidence.
Treat the first run against a real controller as the actual verification step,
and when a field comes back empty, fix both the projection and its fixture so
the test would have caught it.

### What the live run changed

The two `RESTRegistryConfigV2` rows used to sit in that table, predicting that a
wrong wrapper would make the *"controller reject the body"*. The first live run
showed the real behaviour is worse, and silent:

**`POST /v2/scan/registry` nests every credential under `config.auth`.** Sent
flat — which is what the documented V1 shape does — the controller answers
**200** and stores the entry **with no credentials at all**. Nothing in the
response says so. The entry looks correct in `nv_list_registries` apart from an
empty `username`, and then every scan of a private repository fails. A flat
`auth_with_token: true` reads back as `False` the same way. `PATCH` behaves
identically, which is worse: a password rotation reports success and leaves the
stored credential untouched.

Both tools now send `{"config": {..., "auth": {...}}}`, pinned by
`test_create_registry_credentials_nest_under_auth` and
`test_update_registry_credentials_nest_under_auth`, and confirmed end to end
against a live controller. The lesson generalises to the rows still in the
table: *"the controller rejects the body"* is the optimistic failure mode. Silent
partial acceptance is the one to design for.

---

## Known issues

These are real defects and gaps, stated as such.

**1. Empty-string environment variables are treated as unset.**
`config._env()` returns the fallback when a variable is present but empty, so
`NV_READ_ONLY=""` yields `True` (the default) rather than `False`. This
contradicts the bool parsing PHASE-1 states. It is fail-safe — the server stays
read-only — and is pinned by a non-strict `xfail` in
`tests/test_config.py::test_bool_parsing_empty_string_is_false`.

**2. Credentials are redacted before the confirm token is computed.**
For registry and user mutations, the payload that feeds the token already has
the password or secret replaced. Consequence: changing **only** a credential
does not invalidate a previously issued token. This is deliberate — the
alternative is hashing a live credential — but it is worth knowing before you
rely on the token to detect payload drift.

**3. The offline test suite is authoritative for CI, which has no cluster.**
Fixtures are hand-written and therefore agree with the implementation by
construction — a fixture cannot catch a wrong wire shape, which is exactly how
the registry credential defect survived to the first live run. Only the handful
of tools listed in [Verified vs unverified](#verified-vs-unverified) have been
exercised against a real controller.

---

## Running the gate

`make verify` is the definition of done. CI runs exactly this.

```bash
make verify        # = lint + types + test + spec
```

| Target | What it runs |
|---|---|
| `make lint` | `ruff check` and `ruff format --check` over `src`, `tests`, `scripts` |
| `make types` | `mypy` in strict mode |
| `make test` | `pytest` with the branch-coverage gate |
| `make spec` | `scripts/verify_spec.py` — the nine rules below |
| `make image` | `podman build` on the SUSE BCI base |
| `make smoke` | `scripts/smoke_stdio.py` against a live controller |

Pass a specific interpreter with `PY=`, e.g. `make verify PY=.venv/bin/python`.

### The nine spec rules

`make spec` builds the server with **all** toolsets enabled, introspects the
assembled tool list, and checks:

| Rule | Requirement |
|---|---|
| **R1** | Tool name matches `^nv_[a-z0-9_]+$`. |
| **R2** | Description has at least 3 lines and at least 80 characters. |
| **R3** | `ToolAnnotations` are present, and `readOnlyHint` agrees with the toolset's kind. |
| **R4** | Exactly one toolset tag, drawn from the 12 valid toolsets. |
| **R5** | Every mutating tool accepts `confirm`; no read tool accepts it. |
| **R6** | Every `Calls <METHOD> <path>` line in a docstring resolves to a documented controller route, or to an entry in `UNDOCUMENTED_ALLOWLIST` carrying a written justification. |
| **R7** | A structured output schema is declared — no bare `dict` returns. |
| **R8** | The tool's name appears in at least one test file. |
| **R9** | With all toolsets enabled, at least one mutating tool is actually registered. |

Current state:

```
verify_spec: 72 tools introspected
  [ok  ] R1: 72 checked, 0 violation(s)
  [ok  ] R2: 72 checked, 0 violation(s)
  [ok  ] R3: 72 checked, 0 violation(s)
  [ok  ] R4: 72 checked, 0 violation(s)
  [ok  ] R5: 72 checked, 0 violation(s)
  [ok  ] R6: 72 checked, 0 violation(s)
  [ok  ] R7: 72 checked, 0 violation(s)
  [ok  ] R8: 72 checked, 0 violation(s)
  [ok  ] R9: 1 checked, 0 violation(s)
```

---

## Repository layout

```
src/neuvector_mcp/       config, client, guard, audit, models, server + 12 tool modules
tests/                   offline suite; every controller call is mocked with respx
scripts/verify_spec.py   the nine-rule gate
scripts/smoke_stdio.py   the only script that talks to a real controller
deploy/                  Dockerfile (SUSE BCI), deployment.yaml, fleet.yaml
neuvector-mcp-spec/      the normative spec package this server was built from
```

Full per-tool contracts are in `neuvector-mcp-spec/tools/`. The normative
specification is `SPEC.md`.
MCP server for the SUSE NeuVector container security platform. Built to the
specification in `spec/SPEC.md`; `make verify` is the definition of done.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdarthzen%2Fneuvector-mcp.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdarthzen%2Fneuvector-mcp?ref=badge_large)
