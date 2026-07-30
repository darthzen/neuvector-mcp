# PHASE 11 — Package, deploy, verify against a live controller

**Read only this file plus `SPEC.md` section 13 and the three files in
`reference/deploy/`.**

## Goal

Ship it: a container image on openSUSE BCI, Kubernetes manifests, a live smoke
test, and a README that lets someone else run this.

## 1. Container image

`deploy/Dockerfile` was copied verbatim in Phase 0. Build and inspect it.

```bash
make image
```

Then verify the properties that matter, and record the output of each:

```bash
podman run --rm --entrypoint /bin/sh localhost:5000/neuvector-mcp:1.0.0 -c 'id'
# expect uid=10001 gid=10001, NOT root

podman run --rm --entrypoint /bin/sh localhost:5000/neuvector-mcp:1.0.0 -c \
  'which gcc cc make 2>&1 || echo "no compilers - correct"'

podman image inspect localhost:5000/neuvector-mcp:1.0.0 \
  --format '{{.Labels}}{{"\n"}}{{.Config.Entrypoint}}'
```

**Base image policy: openSUSE or SUSE BCI only.** The Dockerfile uses
`registry.opensuse.org/opensuse/bci/python:3.13`. For a SUSE-supported lifecycle,
change both `FROM` lines to `registry.suse.com/bci/python:3.13` — same layout,
SLE-based. Any other base requires written justification and approval before you
change it.

## 2. Manifests

`deploy/deployment.yaml` was copied verbatim. Before it can be applied, three
values must be replaced. Do **not** commit real values.

| Location | Replace with |
|---|---|
| `Secret/neuvector-mcp-controller` `access-key`, `secret-key` | The NeuVector API key pair (SPEC.md 13.1) |
| `Secret/neuvector-mcp-clients` `bearer-tokens` | `openssl rand -hex 32`, formatted `<token>:nv:read` |
| `Deployment` `image` | Your registry path |

Then confirm the security posture actually holds:

```bash
kubectl apply --dry-run=server -f deploy/deployment.yaml
```

The namespace is labelled `pod-security.kubernetes.io/enforce: restricted`, so a
server-side dry run is a real check, not a formality. It must pass with
`runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities dropped and
`automountServiceAccountToken: false` intact.

Verify the `NetworkPolicy` matches your cluster: the egress rule targets
`kubernetes.io/metadata.name: cattle-neuvector-system` on port 10443. If NeuVector
runs in a different namespace, fix the selector, not the port.

## 3. Live smoke test

This is the only step that touches a real controller. It calls read tools only.

```bash
export NV_CONTROLLER_URL=https://<controller>:10443
export NV_API_ACCESS_KEY=... NV_API_SECRET_KEY=...
export NV_VERIFY_TLS=false          # the controller's default cert is self-signed
python3 scripts/smoke_stdio.py
```

Expected: the tool count, the system summary, and up to five workloads with their
policy mode and high-severity vulnerability count.

**This is where projection bugs surface.** Fixtures are hand-written; a live
controller is not. If a field comes back empty that the fixture populated, the
JSON tag in that `from_api()` is wrong. Fix the projection **and** the fixture, so
the test would have caught it.

Record any discrepancy you find. Each one is a real defect that got past 72 tool
contracts and a full test suite, which is worth knowing.

## 4. README

Write `README.md` covering, in this order:

1. What the server does, in three sentences.
2. Quick start over stdio — the four environment variables and one command.
3. The client configuration block for stdio.
4. In-cluster deployment — image build, the three Secret values, `kubectl apply`.
5. Toolsets table and how to enable mutating ones, with the read-only default
   stated plainly.
6. The confirmation handshake, with a worked two-call example.
7. `make verify` as the definition of done.
8. NeuVector API key provisioning, including the `reader` role recommendation and
   the expiry/rotation note.

No feature list padding. Someone should be able to run this from the README
alone.

## 5. Final gate

```bash
make verify
make image
```

Plus the live smoke test above.

## Definition of done for the whole project

| Check | Expected |
|---|---|
| `make verify` | exits 0 |
| `make spec` | 72 tools, zero violations across R1-R9 |
| Read-only default surface | 41 tools |
| Coverage | at or above 85% branch |
| `make image` | builds on openSUSE BCI, runs as uid 10001 |
| `kubectl apply --dry-run=server` | passes under PodSecurity `restricted` |
| `scripts/smoke_stdio.py` | returns real data from a live controller |

## Report

State each row of that table with its actual result, and list every projection
defect the live smoke test exposed.
