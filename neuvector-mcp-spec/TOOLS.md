# TOOLS — index

Complete contracts for all **72** tools live in four files under `tools/`. Each
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

| Toolset | Kind | Tools | File |
|---|---|---|---|
| `inventory` | read | 11 | Part A |
| `vulnerability` | read | 7 | Part A |
| `compliance` | read | 4 | Part A |
| `events` | read | 5 | Part B |
| `policy_read` | read | 10 | Part B |
| `iam_read` | read | 4 | Part B |
| `policy_write` | write | 8 | Part C |
| `admission` | write | 4 | Part C |
| `scan_ops` | write | 7 | Part D |
| `runtime_ops` | write | 4 | Part D |
| `iam_write` | write | 5 | Part D |
| `system_write` | write | 3 | Part D |

**41 read tools** (the default surface), **31 write tools** (all off by default).

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

The 72 tools reference **84 distinct controller endpoints** out of 232 documented,
plus 2 allowlisted undocumented routes. Every reference was machine-verified
against `spec_endpoints.json` using the same matcher `scripts/verify_spec.py`
rule R6 uses, so the endpoint set in this spec and the endpoint set the gate
accepts are identical by construction.

Endpoints deliberately left uncovered: federation, debug and internal routes, IBM
Security Advisor, CSP billing, and the file import/export endpoints
(`POST /v1/file/*`), which move whole YAML configurations and belong in a CLI
rather than a conversational tool surface.
