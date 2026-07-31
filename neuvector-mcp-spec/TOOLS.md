# TOOLS — index

> **Scope of this file.** The `tools/PART-*.md` contracts below specify the
> original **72**-tool build. The server now registers **125** tools: 8 WAF tools
> added in PR #38 and 45 security-ops write tools added on
> `feat/full-write-surface` have **no PART-file contract**. They were specified
> directly from upstream `controller/api/apis.go` and `apis.yaml` (NeuVector
> 5.6.0) instead, and their contracts live in their docstrings plus
> `tests/test_*.py`. They are listed in
> [Tools without a PART contract](#tools-without-a-part-contract) at the end of
> this file. Do not read the PART files expecting to find them.

Complete contracts for the original **72** tools live in four files under `tools/`. Each
tool entry gives: toolset, endpoints, annotations, return model, every argument
with its verbatim `Field(description=...)`, the argument-to-query-parameter
mapping, the verbatim docstring, the output model with its `from_api()` body, the
fixture name and envelope key, and implementation notes including the controller
error codes that tool commonly hits.

**Read only the section your current phase needs.** These files total ~11,000
lines; reading all four at once wastes context you will need for the code.

## By phase

| Phase | File | Section |
|---|---|---|
| 2 | `tools/PART-A-inventory-vulnerability-compliance.md` | `A.0` + `Toolset inventory` |
| 3 | `tools/PART-A-inventory-vulnerability-compliance.md` | `A.0` + `Toolset vulnerability` |
| 4 | `tools/PART-A-inventory-vulnerability-compliance.md` | `A.0` + `Toolset compliance` |
| 5 | `tools/PART-B-events-policy-read-iam-read.md` | `B.0` + `Toolset events` |
| 6 | `tools/PART-B-events-policy-read-iam-read.md` | `B.0` + `Toolset policy_read` |
| 7 | `tools/PART-C-policy-write-admission.md` | `C.0.0`–`C.0.6` + `Toolset policy_write` |
| 8 | `tools/PART-C-policy-write-admission.md` | `C.0.0`, `C.0.3`, `C.0.5` + `Toolset admission` |
| 9 | `tools/PART-D-scanops-runtimeops-iam-system.md` | invariants + `D.0` + `Toolset scan_ops`, `Toolset runtime_ops` |
| 10 | `tools/PART-B-events-policy-read-iam-read.md` `Toolset iam_read`, `tools/PART-D-scanops-runtimeops-iam-system.md` `D.0` + `Toolset iam_write`, `Toolset system_write` | |

## By toolset

Counts are `in PART files` + `added later` = `registered today`.

| Toolset | Kind | In PART files | Added later | Registered | File |
|---|---|---|---|---|---|
| `inventory` | read | 11 | 0 | 11 | Part A |
| `vulnerability` | read | 7 | 3 | 10 | Part A |
| `compliance` | read | 4 | 0 | 4 | Part A |
| `events` | read | 5 | 0 | 5 | Part B |
| `policy_read` | read | 10 | 9 | 19 | Part B |
| `iam_read` | read | 4 | 0 | 4 | Part B |
| `policy_write` | write | 8 | 15 | 23 | Part C |
| `admission` | write | 4 | 1 | 5 | Part C |
| `scan_ops` | write | 7 | 6 | 13 | Part D |
| `runtime_ops` | write | 4 | 1 | 5 | Part D |
| `iam_write` | write | 5 | 0 | 5 | Part D |
| `system_write` | write | 3 | 18 | 21 | Part D |

Originally **41 read / 31 write**. Today **53 read tools** (the default surface)
and **72 write tools** (all off by default).

## Alphabetical tool index

| Tool | Toolset | File |
|---|---|---|
| `nv_apply_network_rule_changes` | `policy_write` | Part C |
| `nv_assess_admission_rule` | `policy_read` | Part B |
| `nv_create_admission_rule` | `admission` | Part C |
| `nv_create_api_key` | `iam_write` | Part D |
| `nv_create_group` | `policy_write` | Part C |
| `nv_create_registry` | `scan_ops` | Part D |
| `nv_create_user` | `iam_write` | Part D |
| `nv_delete_admission_rule` | `admission` | Part C |
| `nv_delete_api_key` | `iam_write` | Part D |
| `nv_delete_group` | `policy_write` | Part C (implemented in Phase 0) |
| `nv_delete_network_rule` | `policy_write` | Part C |
| `nv_delete_registry` | `scan_ops` | Part D |
| `nv_delete_user` | `iam_write` | Part D |
| `nv_get_admission_state` | `policy_read` | Part B |
| `nv_get_bench_report` | `compliance` | Part A |
| `nv_get_compliance_findings` | `compliance` | Part A |
| `nv_get_compliance_profile` | `compliance` | Part A |
| `nv_get_file_monitor_profile` | `policy_read` | Part B |
| `nv_get_group` | `inventory` | Part A |
| `nv_get_network_conversations` | `inventory` | Part A |
| `nv_get_network_rule` | `policy_read` | Part B |
| `nv_get_process_profile` | `policy_read` | Part B |
| `nv_get_scan_report` | `vulnerability` | Part A |
| `nv_get_scan_status` | `vulnerability` | Part A |
| `nv_get_system_alerts` | `events` | Part B |
| `nv_get_system_summary` | `inventory` | Part A (implemented in Phase 0) |
| `nv_get_threat_detail` | `events` | Part B |
| `nv_get_vulnerability_profile` | `vulnerability` | Part A |
| `nv_get_workload` | `inventory` | Part A (implemented in Phase 0) |
| `nv_list_admission_rules` | `policy_read` | Part B |
| `nv_list_api_keys` | `iam_read` | Part B |
| `nv_list_auth_servers` | `iam_read` | Part B |
| `nv_list_compliance_profiles` | `compliance` | Part A |
| `nv_list_dlp_sensors` | `policy_read` | Part B |
| `nv_list_enforcers` | `inventory` | Part A |
| `nv_list_groups` | `inventory` | Part A |
| `nv_list_hosts` | `inventory` | Part A |
| `nv_list_image_scan_summaries` | `vulnerability` | Part A |
| `nv_list_namespaces` | `inventory` | Part A |
| `nv_list_network_rules` | `policy_read` | Part B |
| `nv_list_registries` | `vulnerability` | Part A |
| `nv_list_registry_images` | `vulnerability` | Part A |
| `nv_list_response_rules` | `policy_read` | Part B |
| `nv_list_roles` | `iam_read` | Part B |
| `nv_list_scanners` | `vulnerability` | Part A |
| `nv_list_services` | `inventory` | Part A |
| `nv_list_users` | `iam_read` | Part B |
| `nv_list_waf_sensors` | `policy_read` | Part B |
| `nv_list_workloads` | `inventory` | Part A (implemented in Phase 0) |
| `nv_quarantine_workload` | `runtime_ops` | Part D |
| `nv_query_audit_events` | `events` | Part B |
| `nv_query_security_events` | `events` | Part B |
| `nv_query_system_events` | `events` | Part B |
| `nv_scan_repository` | `scan_ops` | Part D |
| `nv_set_admission_state` | `admission` | Part C |
| `nv_set_group_policy_mode` | `policy_write` | Part C (implemented in Phase 0) |
| `nv_set_namespace_tags` | `system_write` | Part D |
| `nv_set_service_mode` | `runtime_ops` | Part D |
| `nv_start_packet_capture` | `runtime_ops` | Part D |
| `nv_stop_packet_capture` | `runtime_ops` | Part D |
| `nv_stop_registry_scan` | `scan_ops` | Part D |
| `nv_trigger_bench_run` | `scan_ops` | Part D |
| `nv_trigger_scan` | `scan_ops` | Part D |
| `nv_update_admission_rule` | `admission` | Part C |
| `nv_update_file_monitor_profile` | `policy_write` | Part C |
| `nv_update_group_criteria` | `policy_write` | Part C |
| `nv_update_process_profile` | `policy_write` | Part C |
| `nv_update_registry` | `scan_ops` | Part D |
| `nv_update_scan_config` | `system_write` | Part D |
| `nv_update_system_config` | `system_write` | Part D |
| `nv_update_user_role` | `iam_write` | Part D |
| `nv_whoami` | `inventory` | Part A |

## Endpoint coverage

As originally specified, the 72 tools referenced **84 distinct controller
endpoints** out of 232 documented, plus 2 allowlisted undocumented routes. The
125 tools registered today reference **151 distinct endpoints**: 148 documented
and 3 allowlisted undocumented (`GET /v1/conversation`,
`GET /v1/response/options`, `GET /v1/selfuser`). Every reference is
machine-verified against `spec_endpoints.json` by `scripts/verify_spec.py`
rule R6, so the endpoint set in this spec and the endpoint set the gate accepts
are identical by construction.

Endpoints deliberately left uncovered: federation, debug and internal routes,
IBM Security Advisor, CSP billing, and platform administration (users, roles,
LDAP/SAML/OIDC auth servers, sniffer, license).

**Reversed decision — file import/export.** This spec originally excluded the
file endpoints (`/v1/file/*`) on the grounds that they "move whole YAML
configurations and belong in a CLI rather than a conversational tool surface."
`feat/full-write-surface` reverses that: `nv_export_config` and
`nv_import_config` cover them, on the principle that the server implements the
API and the operator gates it by toolset. Three mitigations came with the
reversal, because the original objection was not baseless:

- `POST /v1/file/config` (multipart whole-cluster import) is still **not**
  implemented — it is the most destructive call in the API.
- `kind="all"` export refuses to return the document body, reporting size and a
  count of credential key names only. A full-cluster export embeds registry
  credentials and webhook URLs, and the line-based redactor cannot safely
  guarantee they are all masked.
- Narrow-kind exports return redacted YAML with the redactor's blind spots
  enumerated in the tool description and pinned by tests.

## Tools without a PART contract

These 53 tools are registered by the server but are **not** specified in the
`tools/PART-*.md` files. Their wire shapes were taken from upstream
`controller/api/apis.go` and `apis.yaml` at NeuVector **5.6.0**; where those two
disagreed `apis.go` won, because it is the struct that actually decodes the
request. The authoritative contract for each is its docstring plus its tests.

Endpoint coverage is still enforced: `make spec` rule R6 checks every
`Calls <METHOD> <path>` line against `spec_endpoints.json`, and R8 requires a
test naming each tool.

### `tools/policy_read.py` — WAF reads (PR #38)

Tests: `tests/test_policy_read.py`

| Tool | Toolset |
|---|---|
| `nv_get_waf_group` | `policy_read` |
| `nv_get_waf_sensor` | `policy_read` |
| `nv_list_waf_groups` | `policy_read` |
| `nv_list_waf_rules` | `policy_read` |

### `tools/policy_write.py` — WAF sensor and group writes (PR #38)

Tests: `tests/test_policy_write.py`

| Tool | Toolset |
|---|---|
| `nv_create_waf_sensor` | `policy_write` |
| `nv_delete_waf_sensor` | `policy_write` |
| `nv_set_waf_group` | `policy_write` |
| `nv_update_waf_sensor` | `policy_write` |

### `tools/dlp.py` — DLP sensors and group bindings

Tests: `tests/test_dlp.py`

| Tool | Toolset |
|---|---|
| `nv_create_dlp_sensor` | `policy_write` |
| `nv_delete_dlp_sensor` | `policy_write` |
| `nv_get_dlp_group` | `policy_read` |
| `nv_get_dlp_sensor` | `policy_read` |
| `nv_list_dlp_groups` | `policy_read` |
| `nv_set_dlp_group` | `policy_write` |
| `nv_update_dlp_sensor` | `policy_write` |

### `tools/response_write.py` — Response rules and webhook destinations

Tests: `tests/test_response_write.py`

| Tool | Toolset |
|---|---|
| `nv_apply_response_rule_changes` | `policy_write` |
| `nv_create_webhook` | `system_write` |
| `nv_delete_all_response_rules` | `policy_write` |
| `nv_delete_response_rule` | `policy_write` |
| `nv_delete_webhook` | `system_write` |
| `nv_get_response_rule_options` | `policy_read` |
| `nv_update_response_rule` | `policy_write` |
| `nv_update_webhook` | `system_write` |

### `tools/ruleset_ops.py` — Single-rule update and scope-wide rule deletion

Tests: `tests/test_ruleset_ops.py`

| Tool | Toolset |
|---|---|
| `nv_delete_all_admission_rules` | `admission` |
| `nv_delete_all_network_rules` | `policy_write` |
| `nv_update_network_rule` | `policy_write` |

### `tools/vulnerability_write.py` — Vulnerability profile / CVE suppression

Tests: `tests/test_vulnerability_write.py`

| Tool | Toolset |
|---|---|
| `nv_add_vulnerability_profile_entry` | `system_write` |
| `nv_delete_vulnerability_profile_entry` | `system_write` |
| `nv_update_vulnerability_profile` | `system_write` |
| `nv_update_vulnerability_profile_entry` | `system_write` |

### `tools/compliance_write.py` — Compliance profiles and custom node checks

Tests: `tests/test_compliance_write.py`

| Tool | Toolset |
|---|---|
| `nv_delete_compliance_check_tags` | `system_write` |
| `nv_set_compliance_check_tags` | `system_write` |
| `nv_set_custom_compliance_checks` | `system_write` |
| `nv_update_compliance_profile` | `system_write` |

### `tools/sigstore.py` — Image-signature trust (sigstore)

Tests: `tests/test_sigstore.py`

| Tool | Toolset |
|---|---|
| `nv_create_sigstore_root` | `scan_ops` |
| `nv_create_sigstore_verifier` | `scan_ops` |
| `nv_delete_sigstore_root` | `scan_ops` |
| `nv_delete_sigstore_verifier` | `scan_ops` |
| `nv_get_sigstore_root` | `vulnerability` |
| `nv_list_sigstore_roots` | `vulnerability` |
| `nv_list_sigstore_verifiers` | `vulnerability` |
| `nv_update_sigstore_root` | `scan_ops` |
| `nv_update_sigstore_verifier` | `scan_ops` |

### `tools/service_ops.py` — Service, workload, cluster request, namespace defaults

Tests: `tests/test_service_ops.py`

| Tool | Toolset |
|---|---|
| `nv_apply_system_request` | `system_write` |
| `nv_create_service` | `policy_write` |
| `nv_set_namespace_defaults` | `system_write` |
| `nv_update_workload_config` | `runtime_ops` |

### `tools/config_transfer.py` — Config export / import and remote repositories

Tests: `tests/test_config_transfer.py`

| Tool | Toolset |
|---|---|
| `nv_create_remote_repository` | `system_write` |
| `nv_delete_remote_repository` | `system_write` |
| `nv_export_config` | `system_write` |
| `nv_get_import_status` | `policy_read` |
| `nv_import_config` | `system_write` |
| `nv_update_remote_repository` | `system_write` |
