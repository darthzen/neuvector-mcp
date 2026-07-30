# Appendix B — NeuVector REST schema reference

Generated from `controller/api/apis.yaml` (Swagger `definitions`), transitively closed over
the response and request types this MCP server touches. `*` marks a required property.

Definitions included: **191** of 396 total.

### `Audit`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string |  |  |
| `level` | string | * |  |
| `reported_timestamp` | integer(int64) | * |  |
| `reported_at` | string(date-time) | * |  |
| `cluster_name` | string | * |  |
| `response_rule_id` | integer |  |  |
| `host_id` | string | * |  |
| `host_name` | string | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `workload_id` | string |  |  |
| `workload_name` | string |  |  |
| `workload_domain` | string |  |  |
| `workload_image` | string |  |  |
| `workload_service` | string |  |  |
| `image` | string |  |  |
| `image_id` | string |  |  |
| `registry` | string |  |  |
| `registry_name` | string |  |  |
| `repository` | string |  |  |
| `tag` | string |  |  |
| `base_os` | string | * |  |
| `high_vul_cnt` | integer | * |  |
| `medium_vul_cnt` | integer | * |  |
| `high_vuls` | array<string> |  |  |
| `medium_vuls` | array<string> |  |  |
| `cvedb_version` | string | * |  |
| `message` | string | * |  |
| `user` | string | * |  |
| `error` | string | * |  |
| `aggregation_from` | integer(int64) | * |  |
| `count` | integer | * |  |
| `items` | array<string> |  |  |
| `platform` | string | * |  |
| `platform_version` | string | * |  |
| `packages` | array<string> |  |  |
| `package_ver` | string |  |  |
| `fixed_ver` | string |  |  |
| `score` | number(float32) |  |  |
| `score_v3` | number(float32) |  |  |
| `vectors` | string |  |  |
| `vectors_v3` | string |  |  |
| `link` | string |  |  |
| `description` | string |  |  |
| `pub_date` | string |  |  |
| `last_mod_date` | string |  |  |
| `image_layer_digest` | string |  |  |
| `cmds` | string |  |  |

### `Event`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string |  |  |
| `level` | string | * |  |
| `reported_timestamp` | integer(int64) | * |  |
| `reported_at` | string(date-time) | * |  |
| `cluster_name` | string | * |  |
| `response_rule_id` | integer |  |  |
| `host_id` | string | * |  |
| `host_name` | string | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `controller_id` | string | * |  |
| `controller_name` | string | * |  |
| `workload_id` | string | * |  |
| `workload_name` | string | * |  |
| `workload_domain` | string | * |  |
| `workload_image` | string | * |  |
| `workload_service` | string | * |  |
| `category` | string | * |  |
| `user` | string | * |  |
| `user_roles` | map<string,string> | * | map key is domain(string type) |
| `user_addr` | string | * |  |
| `user_session` | string | * |  |
| `rest_method` | string |  |  |
| `rest_request` | string |  |  |
| `rest_body` | string |  |  |
| `enforcer_limit` | integer |  |  |
| `license_expire` | string |  |  |
| `message` | string | * |  |

### `Incident`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `level` | string | * |  |
| `reported_timestamp` | integer(int64) | * |  |
| `reported_at` | string(date-time) | * |  |
| `cluster_name` | string | * |  |
| `response_rule_id` | integer | * |  |
| `host_id` | string | * |  |
| `host_name` | string | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `id` | string | * |  |
| `workload_id` | string | * |  |
| `workload_name` | string | * |  |
| `workload_domain` | string | * |  |
| `workload_image` | string | * |  |
| `workload_service` | string | * |  |
| `remote_workload_id` | string | * |  |
| `remote_workload_name` | string | * |  |
| `remote_workload_domain` | string | * |  |
| `remote_workload_image` | string | * |  |
| `remote_workload_service` | string | * |  |
| `proc_name` | string | * |  |
| `proc_path` | string | * |  |
| `proc_cmd` | string | * |  |
| `proc_real_uid` | integer | * |  |
| `proc_effective_uid` | integer | * |  |
| `proc_real_user` | string | * |  |
| `proc_effective_user` | string | * |  |
| `file_path` | string | * |  |
| `file_name` | array<string> | * |  |
| `client_ip` | string | * |  |
| `server_ip` | string | * |  |
| `client_port` | integer(uint16) | * |  |
| `server_port` | integer(uint16) | * |  |
| `server_conn_port` | integer(uint16) | * |  |
| `ether_type` | integer(uint16) | * |  |
| `ip_proto` | integer(uint8) | * |  |
| `conn_ingress` | boolean | * |  |
| `proc_parent_name` | string | * |  |
| `proc_parent_path` | string | * |  |
| `action` | string | * |  |
| `group` | string | * |  |
| `rule_id` | string | * |  |
| `aggregation_from` | integer(int64) | * |  |
| `count` | integer | * |  |
| `message` | string | * |  |

### `RESTAWSAccountKey`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | * |  |
| `access_key_id` | string |  |  |
| `secret_access_key` | string |  |  |
| `region` | string | * |  |

### `RESTAWSAccountKeyConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string |  |  |
| `access_key_id` | string |  |  |
| `secret_access_key` | string |  |  |
| `region` | string |  |  |

### `RESTAdmCatOptions`

| Field | Type | Req | Description |
|---|---|---|---|
| `k8s_options` | [RESTAdmRuleOptions] |  |  |

### `RESTAdmCtrlRulesTestResult`

| Field | Type | Req | Description |
|---|---|---|---|
| `index` | integer | * |  |
| `name` | string | * |  |
| `kind` | string | * |  |
| `message` | string | * |  |
| `matched_rules` | array<[RESTAdmCtrlTestRuleInfo]> | * |  |
| `allowed` | boolean | * |  |

### `RESTAdmCtrlRulesTestResults`

| Field | Type | Req | Description |
|---|---|---|---|
| `props_unavailable` | array<string> |  |  |
| `global_mode` | string enum(monitor|protect|) |  |  |
| `results` | array<[RESTAdmCtrlRulesTestResult]> |  |  |

### `RESTAdmCtrlTestRuleInfo`

| Field | Type | Req | Description |
|---|---|---|---|
| `container_image` | string | * | the tested container image in the pod |
| `id` | integer(uint32) | * |  |
| `disabled` | boolean | * |  |
| `type` | string enum(allow|deny) | * |  |
| `mode` | string enum(monitor|protect|) | * | per-rule mode |
| `rule_details` | string | * |  |
| `rule_cfg_type` | string enum(federal|ground|user_created) | * |  |

### `RESTAdmRuleCriterion`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `op` | string | * |  |
| `value` | string | * |  |
| `sub_criteria` | array<[RESTAdmRuleCriterion]> |  |  |
| `type` | string |  |  |
| `template_kind` | string |  |  |
| `path` | string |  |  |
| `value_type` | string |  |  |

### `RESTAdmRuleOptions`

| Field | Type | Req | Description |
|---|---|---|---|
| `rule_options` | object | * |  |

### `RESTAdmRuleTypeOptions`

| Field | Type | Req | Description |
|---|---|---|---|
| `deny_options` | [RESTAdmCatOptions] | * |  |
| `exception_options` | [RESTAdmCatOptions] | * |  |
| `psp_collection` | array<[RESTAdmRuleCriterion]> |  |  |
| `pss_collections` | map<string,array<string>> |  | map key is domain(string type) |
| `sigstore_verifiers` | array<string> |  |  |

### `RESTAdminCriteriaTemplate`

| Field | Type | Req | Description |
|---|---|---|---|
| `kind` | string | * |  |
| `rawjson` | string | * |  |

### `RESTAdminCustomCriteriaOptions`

| Field | Type | Req | Description |
|---|---|---|---|
| `ops` | array<string> | * |  |
| `values` | array<string> |  |  |
| `valuetype` | string | * |  |

### `RESTAdmissionConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `state` | [RESTAdmissionState] |  |  |
| `admission_options` | [RESTAdmRuleTypeOptions] |  |  |
| `k8s_env` | boolean | * |  |
| `admission_custom_criteria_options` | [RESTAdminCustomCriteriaOptions] |  |  |
| `admission_custom_criteria_templates` | [RESTAdminCriteriaTemplate] |  |  |
| `predefined_risky_roles` | array<string> |  |  |

### `RESTAdmissionRule`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | integer(uint32) | * |  |
| `category` | string | * |  |
| `comment` | string | * |  |
| `criteria` | array<[RESTAdmRuleCriterion]> | * |  |
| `disable` | boolean | * |  |
| `critical` | boolean | * |  |
| `cfg_type` | string enum(user_created|ground|federal) | * |  |
| `rule_type` | string enum(exception|deny) | * |  |
| `rule_mode` | string enum(|monitor|protect) | * |  |
| `containers` | array<string enum(containers|init_containers|ephemeral_containers)> | * |  |

### `RESTAdmissionRuleConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | integer(uint32) | * |  |
| `category` | string | * |  |
| `comment` | string |  |  |
| `criteria` | array<[RESTAdmRuleCriterion]> |  |  |
| `disable` | boolean |  |  |
| `actions` | array<string> |  |  |
| `cfg_type` | string enum(user_created|ground|federal) | * |  |
| `rule_type` | string enum(exception|deny) | * |  |
| `rule_mode` | string enum(|monitor|protect) |  |  |
| `containers` | array<string enum(containers|init_containers|ephemeral_containers)> | * |  |

### `RESTAdmissionRuleConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTAdmissionRuleConfig] | * |  |

### `RESTAdmissionRuleData`

| Field | Type | Req | Description |
|---|---|---|---|
| `rule` | [RESTAdmissionRule] | * |  |

### `RESTAdmissionRulesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `rules` | array<[RESTAdmissionRule]> | * |  |

### `RESTAdmissionState`

| Field | Type | Req | Description |
|---|---|---|---|
| `enable` | boolean |  |  |
| `mode` | string |  |  |
| `default_action` | string |  |  |
| `adm_client_mode` | string |  |  |
| `adm_svc_type` | string |  |  |
| `adm_client_mode_options` | object |  |  |
| `ctrl_states` | object |  |  |

### `RESTAdmissionStats`

| Field | Type | Req | Description |
|---|---|---|---|
| `k8s_allowed_requests` | integer(int64) | * |  |
| `k8s_denied_requests` | integer(int64) | * |  |
| `k8s_erroneous_requests` | integer(int64) | * |  |
| `k8s_ignored_requests` | integer(int64) | * |  |
| `jenkins_allowed_requests` | integer(int64) | * |  |
| `jenkins_denied_requests` | integer(int64) | * |  |
| `jenkins_erroneous_requests` | integer(int64) | * |  |

### `RESTAdmissionStatsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `stats` | [RESTAdmissionStats] | * |  |

### `RESTAgent`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | * |  |
| `name` | string | * |  |
| `display_name` | string | * |  |
| `host_name` | string | * |  |
| `host_id` | string | * |  |
| `version` | string | * |  |
| `labels` | map<string,string> | * | map key is string type |
| `domain` | string | * |  |
| `pid_mode` | string | * |  |
| `network_mode` | string | * |  |
| `created_at` | string(date-time) | * |  |
| `started_at` | string(date-time) | * |  |
| `joined_at` | string(date-time) | * |  |
| `memory_limit` | integer(int64) | * |  |
| `cpus` | string | * |  |
| `cluster_ip` | string | * |  |
| `connection_state` | string | * |  |
| `disconnected_at` | string | * |  |

### `RESTAgentsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `enforcers` | array<[RESTAgent]> | * |  |

### `RESTApikey`

| Field | Type | Req | Description |
|---|---|---|---|
| `expiration_type` | string | * |  |
| `expiration_hours` | integer(uint32) |  |  |
| `apikey_name` | string | * |  |
| `apikey_secret` | string |  |  |
| `description` | string |  |  |
| `role` | string | * |  |
| `role_domains` | map<string,array<string>> |  | Object key is role and value is array of domains |
| `expiration_timestamp` | integer(int64) |  |  |
| `created_timestamp` | integer(int64) |  |  |
| `created_by_entity` | string |  |  |

### `RESTApikeyCreation`

| Field | Type | Req | Description |
|---|---|---|---|
| `expiration_type` | string | * |  |
| `expiration_hours` | integer(uint32) |  |  |
| `apikey_name` | string | * |  |
| `description` | string |  |  |
| `role` | string | * |  |
| `role_domains` | map<string,array<string>> |  | Object key is role and value is array of domains |

### `RESTApikeyCreationData`

| Field | Type | Req | Description |
|---|---|---|---|
| `apikey` | [RESTApikeyCreation] | * |  |

### `RESTApikeyGenerated`

| Field | Type | Req | Description |
|---|---|---|---|
| `apikey_name` | string | * |  |
| `apikey_secret` | string | * |  |

### `RESTApikeyGeneratedData`

| Field | Type | Req | Description |
|---|---|---|---|
| `apikey` | [RESTApikeyGenerated] | * |  |

### `RESTApikeysData`

| Field | Type | Req | Description |
|---|---|---|---|
| `apikeys` | array<[RESTApikey]> | * |  |
| `global_roles` | array<string> | * |  |
| `domain_roles` | array<string> | * |  |

### `RESTAuditsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `audits` | array<[Audit]> | * |  |

### `RESTAuthData`

| Field | Type | Req | Description |
|---|---|---|---|
| `client_ip` | string | * |  |
| `password` | [RESTAuthPassword] |  |  |
| `Token` | [RESTAuthToken] |  |  |

### `RESTAuthPassword`

| Field | Type | Req | Description |
|---|---|---|---|
| `username` | string | * |  |
| `password` | string(password) | * |  |
| `new_password` | string |  | need to specify when server responds the user needs to change password |

### `RESTAuthToken`

| Field | Type | Req | Description |
|---|---|---|---|
| `token` | string | * |  |
| `state` | string | * |  |
| `redirect_endpoint` | string | * |  |

### `RESTBenchItem`

| Field | Type | Req | Description |
|---|---|---|---|
| `catalog` | string | * |  |
| `type` | string | * |  |
| `level` | string | * |  |
| `test_number` | string | * |  |
| `profile` | string | * |  |
| `scored` | boolean | * |  |
| `automated` | boolean | * |  |
| `description` | string | * |  |
| `message` | array<string> | * |  |
| `remediation` | string | * |  |
| `group` | string | * |  |

### `RESTBenchReport`

| Field | Type | Req | Description |
|---|---|---|---|
| `run_timestamp` | integer(int64) | * |  |
| `run_at` | string(date-time) | * |  |
| `cis_version` | string | * |  |
| `items` | array<[RESTBenchItem]> | * |  |

### `RESTCLUSEventCondition`

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string |  |  |
| `value` | string |  |  |

### `RESTComplianceData`

| Field | Type | Req | Description |
|---|---|---|---|
| `run_timestamp` | integer(int64) | * |  |
| `run_at` | string(date-time) | * |  |
| `kubernetes_cis_category` | string | * |  |
| `kubernetes_cis_version` | string | * |  |
| `docker_cis_version` | string | * |  |
| `items` | array<[RESTBenchItem]> | * |  |

### `RESTComplianceProfile`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `disable_system` | boolean | * |  |
| `entries` | array<[RESTComplianceProfileEntry]> | * |  |
| `cfg_type` | string enum(user_created|ground) |  |  |

### `RESTComplianceProfileEntry`

| Field | Type | Req | Description |
|---|---|---|---|
| `test_number` | string | * |  |
| `tags` | array<string> | * |  |

### `RESTComplianceProfilesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `profiles` | array<[RESTComplianceProfile]> | * |  |

### `RESTCriteriaEntry`

| Field | Type | Req | Description |
|---|---|---|---|
| `key` | string | * |  |
| `value` | string | * |  |
| `op` | string | * |  |

### `RESTCustomCheck`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `script` | string | * |  |

### `RESTCustomCheckData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTCustomChecks] | * |  |

### `RESTCustomChecks`

| Field | Type | Req | Description |
|---|---|---|---|
| `group` | string | * |  |
| `enabled` | boolean |  |  |
| `writable` | boolean |  |  |
| `scripts` | array<[RESTCustomCheck]> | * |  |

### `RESTDomain`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `workloads` | integer | * |  |
| `running_workloads` | integer | * |  |
| `running_pods` | integer | * |  |
| `services` | integer | * |  |
| `tags` | array<string> | * |  |
| `labels` | map<string,string> | * | map key is string type |

### `RESTDomainsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `domains` | array<[RESTDomain]> | * |  |
| `tag_per_domain` | boolean | * |  |

### `RESTError`

| Field | Type | Req | Description |
|---|---|---|---|
| `code` | integer | * |  |
| `error` | string | * |  |
| `message` | string | * |  |
| `password_profile_basic` | [RESTPwdProfileBasic] |  |  |
| `import_task_data` | [RESTImportTaskData] |  |  |

### `RESTEventsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `events` | array<[Event]> | * |  |

### `RESTFedSystemConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `webhooks` | [RESTWebhook] | * |  |

### `RESTFedSystemConfigConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `webhooks` | array<[RESTWebhook]> |  |  |

### `RESTFileMonitorConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `add_filters` | array<[RESTFileMonitorFilterConfig]> |  |  |
| `delete_filters` | array<[RESTFileMonitorFilterConfig]> |  |  |
| `update_filters` | array<[RESTFileMonitorFilterConfig]> |  |  |

### `RESTFileMonitorConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTFileMonitorConfig] | * |  |

### `RESTFileMonitorFilterConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `filter` | string | * |  |
| `recursive` | boolean | * |  |
| `behavior` | string | * |  |
| `applications` | array<string> | * |  |
| `group` | string | * |  |

### `RESTGCRKey`

| Field | Type | Req | Description |
|---|---|---|---|
| `json_key` | string |  |  |

### `RESTGCRKeyConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `json_key` | string |  |  |

### `RESTGroup`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `learned` | boolean | * |  |
| `reserved` | boolean | * |  |
| `policy_mode` | string |  |  |
| `domain` | string | * |  |
| `creater_domains` | array<string> | * |  |
| `kind` | string | * |  |
| `platform_role` | string | * |  |
| `cap_change_mode` | boolean | * |  |
| `criteria` | array<[RESTCriteriaEntry]> | * |  |
| `members` | array<[RESTWorkloadBrief]> | * |  |
| `policy_rules` | array<integer(uint32)> | * |  |
| `response_rules` | array<integer(uint32)> | * |  |

### `RESTGroupConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `criteria` | array<[RESTCriteriaEntry]> |  |  |
| `cfg_type` | string enum(learned|user_created|ground|federal) | * |  |

### `RESTGroupConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTGroupConfig] | * |  |

### `RESTGroupData`

| Field | Type | Req | Description |
|---|---|---|---|
| `group` | [RESTGroupDetail] | * |  |

### `RESTGroupDetail`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `learned` | boolean | * |  |
| `reserved` | boolean | * |  |
| `policy_mode` | string |  |  |
| `domain` | string | * |  |
| `creater_domains` | array<string> | * |  |
| `kind` | string | * |  |
| `platform_role` | string | * |  |
| `cap_change_mode` | boolean | * |  |
| `cfg_type` | string enum(learned|user_created|ground|federal) | * |  |
| `monitor_metric` | boolean | * |  |
| `group_sess_cur` | integer(uint32) | * |  |
| `group_sess_rate` | integer(uint32) | * |  |
| `group_band_width` | integer(uint32) | * |  |
| `criteria` | array<[RESTCriteriaEntry]> | * |  |
| `members` | array<[RESTWorkloadBrief]> | * |  |
| `policy_rules` | array<[RESTPolicyRule]> | * |  |
| `response_rules` | array<[RESTResponseRule]> | * |  |

### `RESTGroupsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `groups` | array<[RESTGroup]> | * |  |

### `RESTHost`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `id` | string | * |  |
| `runtime` | string | * |  |
| `runtime_version` | string | * |  |
| `runtime_api_version` | string | * |  |
| `platform` | string | * |  |
| `os` | string | * |  |
| `kernel` | string | * |  |
| `cpus` | integer(int64) | * |  |
| `memory` | integer(int64) | * |  |
| `cgroup_version` | integer | * |  |
| `containers` | integer | * |  |
| `interfaces` | map<string,array<[RESTIPAddr]>> | * | map key is string type like "eth0" |
| `state` | string | * |  |
| `cap_docker_bench` | boolean | * |  |
| `cap_kube_bench` | boolean | * |  |
| `docker_bench_status` | string |  |  |
| `kube_bench_status` | string |  |  |
| `policy_mode` | string | * |  |
| `profile_mode` | string | * |  |
| `scan_summary` | [RESTScanBrief] | * |  |
| `storage_driver` | string | * |  |
| `labels` | map<string,string> | * | map key is string type |
| `annotations` | map<string,string> | * | map key is string type |

### `RESTHostsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `hosts` | array<[RESTHost]> | * |  |

### `RESTIPAddr`

| Field | Type | Req | Description |
|---|---|---|---|
| `ip` | string | * |  |
| `ip_prefix` | integer | * |  |
| `gateway` | string | * |  |

### `RESTIPPort`

| Field | Type | Req | Description |
|---|---|---|---|
| `ip` | string | * |  |
| `port` | integer(uint16) | * |  |

### `RESTImportTask`

| Field | Type | Req | Description |
|---|---|---|---|
| `tid` | string | * |  |
| `ctrler_id` | string | * |  |
| `last_update_time` | string(date-time) |  |  |
| `percentage` | integer | * |  |
| `triggered_by` | string |  |  |
| `status` | string |  |  |
| `temp_token` | string |  |  |
| `fail_to_decrypt_key_fields` | map<string,array<string>> |  | Object key is kv key and value is array of cloaked fields that cannot be decrypted |

### `RESTImportTaskData`

| Field | Type | Req | Description |
|---|---|---|---|
| `data` | [RESTImportTask] | * |  |

### `RESTIncidentsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `incidents` | array<[Incident]> | * |  |

### `RESTJfrogXray`

| Field | Type | Req | Description |
|---|---|---|---|
| `url` | string | * |  |
| `enable` | boolean | * |  |
| `username` | string | * |  |
| `password` | string(password) |  |  |

### `RESTJfrogXrayConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `url` | string |  |  |
| `enable` | boolean |  |  |
| `username` | string |  |  |
| `password` | string(password) |  |  |

### `RESTModuleCve`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `status` | string | * |  |

### `RESTPermitsAssigned`

| Field | Type | Req | Description |
|---|---|---|---|
| `permissions` | array<[RESTRolePermission]> |  | array of permissions |
| `domains` | array<string> |  | array of domains that have the same permissions |

### `RESTPolicyRule`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | integer(uint32) | * |  |
| `comment` | string | * |  |
| `from` | string | * | group name |
| `to` | string | * | group name |
| `ports` | string | * | free-style port list |
| `action` | string | * |  |
| `applications` | array<string> | * |  |
| `learned` | boolean | * |  |
| `disable` | boolean | * |  |
| `created_timestamp` | integer(int64) | * |  |
| `last_modified_timestamp` | integer(int64) | * |  |
| `cfg_type` | string enum(learned|user_created|ground|federal) | * |  |
| `priority` | integer(uint32) | * |  |
| `match_counter` | integer(uint64) | * |  |
| `last_match_timestamp` | integer(int64) | * |  |

### `RESTPolicyRuleActionData`

| Field | Type | Req | Description |
|---|---|---|---|
| `move` | [RESTPolicyRuleMove] |  |  |
| `insert` | [RESTPolicyRuleInsert] |  |  |
| `rules` | array<[RESTPolicyRule]> |  |  |
| `delete` | array<integer(uint32)> |  |  |

### `RESTPolicyRuleInsert`

| Field | Type | Req | Description |
|---|---|---|---|
| `after` | integer |  |  |
| `rules` | array<[RESTPolicyRule]> | * |  |

### `RESTPolicyRuleMove`

| Field | Type | Req | Description |
|---|---|---|---|
| `after` | integer |  |  |
| `id` | integer(uint32) | * |  |

### `RESTPolicyRulesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `rules` | array<[RESTPolicyRule]> | * |  |

### `RESTPolicyViolationsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `violations` | array<[Violation]> | * |  |

### `RESTProcessProfile`

| Field | Type | Req | Description |
|---|---|---|---|
| `group` | string | * |  |
| `alert_disabled` | boolean |  |  |
| `hash_enabled` | boolean |  |  |
| `mode` | string | * |  |
| `process_list` | array<[RESTProcessProfileEntry]> | * |  |

### `RESTProcessProfileConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `group` | string | * |  |
| `alert_disabled` | boolean |  |  |
| `hash_enabled` | boolean |  |  |
| `process_change_list` | array<[RESTProcessProfileEntryConfig]> |  |  |
| `process_delete_list` | array<[RESTProcessProfileEntryConfig]> |  |  |

### `RESTProcessProfileConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `process_profile_config` | [RESTProcessProfileConfig] | * |  |

### `RESTProcessProfileData`

| Field | Type | Req | Description |
|---|---|---|---|
| `process_profile` | [RESTProcessProfile] | * |  |

### `RESTProcessProfileEntry`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `path` | string |  |  |
| `user` | string |  |  |
| `uid` | integer(int32) |  |  |
| `action` | string | * |  |
| `cfg_type` | string enum(learned|user_created|ground|federal|system_defined) | * |  |
| `uuid` | string(uuid) | * |  |
| `group` | string |  |  |
| `created_timestamp` | integer(int64) | * |  |
| `last_modified_timestamp` | integer(int64) | * |  |

### `RESTProcessProfileEntryConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `path` | string | * |  |
| `action` | string | * |  |
| `group` | string | * |  |

### `RESTProxy`

Define proxy settings.

| Field | Type | Req | Description |
|---|---|---|---|
| `url` | string | * |  |
| `username` | string | * |  |
| `password` | string(password) |  |  |

### `RESTProxyConfig`

Define proxy settings, similar to RESTProxy, but allow users to perform partial update on RESTProxy. When both exist, this config will take precedence over RESTProxy.

| Field | Type | Req | Description |
|---|---|---|---|
| `url` | string | * |  |
| `username` | string | * |  |
| `password` | string(password) |  |  |

### `RESTPwdProfileBasic`

| Field | Type | Req | Description |
|---|---|---|---|
| `min_len` | integer | * |  |
| `min_uppercase_count` | integer | * |  |
| `min_lowercase_count` | integer | * |  |
| `min_digit_count` | integer | * |  |
| `min_special_count` | integer | * |  |

### `RESTRegistryConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `registry_type` | string | * |  |
| `registry` | string |  |  |
| `filters` | array<string> |  |  |
| `username` | string |  |  |
| `password` | string(password) |  |  |
| `auth_token` | string |  |  |
| `auth_with_token` | boolean |  |  |
| `rescan_after_db_update` | boolean |  |  |
| `scan_layers` | boolean |  |  |
| `repo_limit` | integer |  |  |
| `tag_limit` | integer |  |  |
| `schedule` | [RESTScanSchedule] |  |  |
| `aws_key` | [RESTAWSAccountKeyConfig] |  |  |
| `jfrog_xray` | [RESTJfrogXrayConfig] |  |  |
| `gcr_key` | [RESTGCRKeyConfig] |  |  |
| `jfrog_mode` | string |  |  |
| `jfrog_aql` | boolean |  |  |
| `gitlab_external_url` | string |  |  |
| `gitlab_private_token` | string |  |  |
| `ibm_cloud_token_url` | string |  |  |
| `ibm_cloud_account` | string |  |  |
| `ignore_proxy` | boolean |  |  |

### `RESTRegistryConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTRegistryConfig] | * |  |

### `RESTRegistryImageSummary`

| Field | Type | Req | Description |
|---|---|---|---|
| `domain` | string | * |  |
| `repository` | string | * |  |
| `tag` | string | * |  |
| `image_id` | string | * |  |
| `digest` | string | * |  |
| `size` | integer(int64) | * |  |
| `author` | string | * |  |
| `run_as_root` | boolean | * |  |
| `envs` | array<string> | * |  |
| `labels` | map<string,string> | * | map key is string type |
| `layers` | array<string> | * |  |
| `status` | string | * |  |
| `high` | integer | * |  |
| `medium` | integer | * |  |
| `result` | string | * |  |
| `scanned_timestamp` | integer(int64) | * |  |
| `scanned_at` | string(date-time) | * |  |
| `created_at` | string(date-time) | * |  |
| `base_os` | string | * |  |
| `scanner_version` | string | * |  |
| `cvedb_create_time` | string(date-time) |  |  |

### `RESTRegistryImageSummaryData`

| Field | Type | Req | Description |
|---|---|---|---|
| `images` | array<[RESTRegistryImageSummary]> | * |  |

### `RESTRegistrySummary`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `registry_type` | string | * |  |
| `registry` | string | * |  |
| `username` | string | * |  |
| `password` | string(password) |  |  |
| `auth_token` | string |  |  |
| `auth_with_token` | boolean | * |  |
| `filters` | array<string> | * |  |
| `rescan_after_db_update` | boolean | * |  |
| `scan_layers` | boolean | * |  |
| `repo_limit` | integer | * |  |
| `tag_limit` | integer | * |  |
| `schedule` | [RESTScanSchedule] | * |  |
| `aws_key` | [RESTAWSAccountKey] |  |  |
| `jfrog_xray` | [RESTJfrogXray] |  |  |
| `gcr_key` | [RESTGCRKey] |  |  |
| `jfrog_mode` | string | * |  |
| `gitlab_external_url` | string | * |  |
| `gitlab_private_token` | string |  |  |
| `ibm_cloud_token_url` | string | * |  |
| `ibm_cloud_account` | string | * |  |
| `status` | string | * |  |
| `error_message` | string | * |  |
| `error_detail` | string | * |  |
| `started_at` | string(date-time) | * |  |
| `scanned` | integer(uint32) | * |  |
| `scheduled` | integer(uint32) | * |  |
| `scanning` | integer(uint32) | * |  |
| `failed` | integer(uint32) | * |  |
| `cvedb_version` | string | * |  |
| `cvedb_create_time` | string(date-time) | * |  |
| `ignore_proxy` | boolean |  |  |

### `RESTRegistrySummaryListData`

| Field | Type | Req | Description |
|---|---|---|---|
| `summarys` | array<[RESTRegistrySummary]> | * |  |

### `RESTRemoteRepo_GitHubConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `repository_owner_username` | string | * |  |
| `repository_name` | string | * |  |
| `repository_branch_name` | string | * |  |
| `personal_access_token` | string | * |  |
| `personal_access_token_committer_name` | string | * |  |
| `personal_access_token_committer_email` | string | * |  |

### `RESTRemoteRepository`

| Field | Type | Req | Description |
|---|---|---|---|
| `nickname` | string | * |  |
| `provider` | string | * | currently only github is supported |
| `comment` | string |  |  |
| `enable` | boolean |  |  |
| `github_configuration` | [RESTRemoteRepo_GitHubConfig] | * |  |

### `RESTResponseRule`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | integer(uint32) | * |  |
| `event` | string | * |  |
| `comment` | string | * |  |
| `group` | string | * |  |
| `conditions` | array<[RESTCLUSEventCondition]> | * |  |
| `actions` | array<string> | * |  |
| `webhooks` | array<string> | * |  |
| `disable` | boolean | * |  |
| `cfg_type` | string enum(user_created|ground|federal) | * |  |

### `RESTResponseRuleActionData`

| Field | Type | Req | Description |
|---|---|---|---|
| `insert` | [RESTResponseRuleInsert] |  |  |

### `RESTResponseRuleInsert`

| Field | Type | Req | Description |
|---|---|---|---|
| `after` | integer |  |  |
| `rules` | array<[RESTResponseRule]> | * |  |

### `RESTResponseRulesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `rules` | array<[RESTResponseRule]> | * |  |

### `RESTRolePermission`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | * |  |
| `read` | boolean | * |  |
| `write` | boolean | * |  |

### `RESTScanBrief`

| Field | Type | Req | Description |
|---|---|---|---|
| `status` | string | * |  |
| `high` | integer | * |  |
| `medium` | integer | * |  |
| `result` | string | * |  |
| `scanned_timestamp` | integer(int64) | * |  |
| `scanned_at` | string(date-time) | * |  |
| `base_os` | string | * |  |
| `scanner_version` | string | * |  |
| `cvedb_create_time` | string(date-time) | * |  |

### `RESTScanConfigConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `auto_scan` | boolean |  | Global auto-scan setting. When true, auto-scan is adopted unless one of the detailed control flags (enable_auto_scan_workload or enable_auto_scan_host |
| `enable_auto_scan_workload` | boolean |  | Optional detailed control for workload auto-scan. If provided (non-nil), its value is adopted. |
| `enable_auto_scan_host` | boolean |  | Optional detailed control for host auto-scan. If provided (non-nil), its value is adopted. |

### `RESTScanConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTScanConfigConfig] | * |  |

### `RESTScanImageSummary`

| Field | Type | Req | Description |
|---|---|---|---|
| `image` | string | * |  |
| `image_id` | string | * |  |
| `author` | string | * |  |
| `status` | string | * |  |
| `high` | integer | * |  |
| `medium` | integer | * |  |
| `result` | string | * |  |
| `scanned_timestamp` | integer(int64) | * |  |
| `scanned_at` | string | * |  |
| `created_at` | string | * |  |
| `base_os` | string | * |  |
| `scanner_version` | string | * |  |
| `cvedb_create_time` | string | * |  |

### `RESTScanImageSummaryData`

| Field | Type | Req | Description |
|---|---|---|---|
| `images` | array<[RESTScanImageSummary]> | * |  |

### `RESTScanLayer`

| Field | Type | Req | Description |
|---|---|---|---|
| `digest` | string | * |  |
| `cmds` | string | * |  |
| `vulnerabilities` | array<[RESTVulnerability]> | * |  |
| `size` | integer(int64) | * |  |

### `RESTScanMeta`

| Field | Type | Req | Description |
|---|---|---|---|
| `source` | string | * |  |
| `user` | string | * |  |
| `job` | string | * |  |
| `workspace` | string | * |  |
| `function` | string | * |  |
| `region` | string | * |  |

### `RESTScanModule`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `file` | string |  |  |
| `version` | string | * |  |
| `source` | string | * |  |
| `cves` | array<[RESTModuleCve]> |  |  |
| `cpes` | array<string> |  |  |

### `RESTScanRepoReport`

| Field | Type | Req | Description |
|---|---|---|---|
| `verdict` | string |  |  |
| `image_id` | string | * |  |
| `registry` | string | * |  |
| `repository` | string | * |  |
| `tag` | string | * |  |
| `digest` | string | * |  |
| `size` | integer(int64) | * |  |
| `author` | string | * |  |
| `base_os` | string | * |  |
| `created_at` | string(date-time) | * |  |
| `cvedb_version` | string | * |  |
| `cvedb_create_time` | string(date-time) | * |  |
| `layers` | array<[RESTScanLayer]> | * |  |
| `vulnerabilities` | array<[RESTVulnerability]> | * |  |
| `modules` | array<[RESTScanModule]> | * |  |
| `envs` | array<string> | * |  |
| `labels` | map<string,string> | * | map key is string type |

### `RESTScanRepoReportData`

| Field | Type | Req | Description |
|---|---|---|---|
| `report` | [RESTScanRepoReport] | * |  |

### `RESTScanRepoReq`

| Field | Type | Req | Description |
|---|---|---|---|
| `metadata` | [RESTScanMeta] | * |  |
| `registry` | string | * |  |
| `username` | string |  |  |
| `password` | string(password) |  |  |
| `repository` | string | * |  |
| `tag` | string | * |  |
| `scan_layers` | boolean | * |  |
| `base_image` | string | * |  |
| `ignore_proxy` | boolean |  |  |

### `RESTScanRepoReqData`

| Field | Type | Req | Description |
|---|---|---|---|
| `request` | [RESTScanRepoReq] | * |  |

### `RESTScanReport`

| Field | Type | Req | Description |
|---|---|---|---|
| `vulnerabilities` | array<[RESTVulnerability]> | * |  |
| `modules` | array<[RESTScanModule]> |  |  |
| `checks` | array<[RESTBenchItem]> |  |  |
| `secrets` | array<[RESTScanSecret]> |  |  |
| `setid_perms` | array<[RESTScanSetIdPerm]> |  |  |
| `envs` | array<string> |  |  |
| `labels` | map<string,string> |  | map key is string type |
| `cmds` | array<string> |  |  |

### `RESTScanReportData`

| Field | Type | Req | Description |
|---|---|---|---|
| `report` | [RESTScanReport] | * |  |

### `RESTScanSchedule`

| Field | Type | Req | Description |
|---|---|---|---|
| `schedule` | string | * |  |
| `interval` | integer | * |  |

### `RESTScanSecret`

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string | * |  |
| `evidence` | string | * |  |
| `path` | string | * |  |
| `suggestion` | string | * |  |

### `RESTScanSetIdPerm`

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string | * |  |
| `evidence` | string | * |  |
| `path` | string | * |  |

### `RESTScanStatus`

| Field | Type | Req | Description |
|---|---|---|---|
| `scanned` | integer | * |  |
| `scheduled` | integer | * |  |
| `scanning` | integer | * |  |
| `failed` | integer | * |  |
| `cvedb_version` | string | * |  |
| `cvedb_create_time` | string(date-time) | * |  |

### `RESTScanStatusData`

| Field | Type | Req | Description |
|---|---|---|---|
| `status` | [RESTScanStatus] | * |  |

### `RESTService`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `comment` | string | * |  |
| `policy_mode` | string | * |  |
| `profile_mode` | string | * |  |
| `not_scored` | boolean | * |  |
| `domain` | string | * |  |
| `platform_role` | string | * |  |
| `members` | array<[RESTWorkloadBrief]> | * |  |
| `policy_rules` | array<[RESTPolicyRule]> | * |  |
| `response_rules` | array<[RESTResponseRule]> | * |  |
| `service_addr` | [RESTIPPort] |  |  |
| `ingress_exposure` | boolean | * |  |
| `egress_exposure` | boolean | * |  |
| `baseline_profile` | string | * |  |
| `cap_change_mode` | boolean |  |  |
| `cap_scorable` | boolean |  |  |

### `RESTServiceBatchConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `services` | array<string> |  |  |
| `policy_mode` | string |  |  |
| `baseline_profile` | string |  |  |
| `not_scored` | boolean |  |  |

### `RESTServiceBatchConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTServiceBatchConfig] | * |  |

### `RESTServiceConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `domain` | string | * |  |
| `comment` | string | * |  |
| `policy_mode` | string |  |  |
| `baseline_profile` | string |  |  |
| `not_scored` | boolean |  |  |

### `RESTServiceConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTServiceConfig] | * |  |

### `RESTServicesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `services` | array<[RESTService]> | * |  |

### `RESTSnifferArgs`

| Field | Type | Req | Description |
|---|---|---|---|
| `file_number` | integer(uint32) |  |  |
| `duration` | integer(uint32) |  |  |
| `filter` | string |  |  |

### `RESTSnifferArgsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `sniffer` | [RESTSnifferArgs] | * |  |

### `RESTSnifferData`

| Field | Type | Req | Description |
|---|---|---|---|
| `sniffer` | [RESTSnifferInfo] | * |  |

### `RESTSnifferInfo`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | * |  |
| `enforcer_id` | string | * |  |
| `container_id` | string | * |  |
| `file_number` | integer(uint32) | * |  |
| `size` | integer(int64) | * |  |
| `status` | string | * |  |
| `args` | string | * |  |
| `start_time` | integer(int64) | * |  |
| `stop_time` | integer(int64) | * |  |

### `RESTSysAtmoConfigConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `mode_auto_d2m` | boolean |  |  |
| `mode_auto_d2m_duration` | integer(int64) |  |  |
| `mode_auto_m2p` | boolean |  |  |
| `mode_auto_m2p_duration` | integer(int64) |  |  |

### `RESTSysNetConfigConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `net_service_status` | boolean |  |  |
| `net_service_policy_mode` | string |  |  |
| `disable_net_policy` | boolean |  |  |
| `detect_unmanaged_wl` | boolean |  |  |
| `strict_group_mode` | boolean |  |  |

### `RESTSystemConfigAuthCfgV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `auth_order` | array<string> |  |  |
| `auth_by_platform` | boolean |  |  |
| `rancher_ep` | string |  |  |

### `RESTSystemConfigAuthV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `auth_order` | array<string> | * |  |
| `auth_by_platform` | boolean | * |  |
| `rancher_ep` | string | * |  |

### `RESTSystemConfigAutoscale`

| Field | Type | Req | Description |
|---|---|---|---|
| `strategy` | string enum(|immediate|delayed) | * |  |
| `min_pods` | integer(uint32) | * |  |
| `max_pods` | integer(uint32) | * |  |

### `RESTSystemConfigAutoscaleConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `strategy` | string enum(|immediate|delayed) |  |  |
| `min_pods` | integer(uint32) |  |  |
| `max_pods` | integer(uint32) |  |  |

### `RESTSystemConfigConfigDataV2`

it leverages RESTSystemConfigConfigData in apis.go

| Field | Type | Req | Description |
|---|---|---|---|
| `config_v2` | [RESTSystemConfigConfigV2] |  |  |
| `fed_config` | [RESTFedSystemConfigConfig] |  |  |
| `net_config` | [RESTSysNetConfigConfig] |  |  |
| `atmo_config` | [RESTSysAtmoConfigConfig] |  |  |

### `RESTSystemConfigConfigV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `svc_cfg` | [RESTSystemConfigSvcCfgV2] |  |  |
| `syslog_cfg` | [RESTSystemConfigSyslogCfgV2] |  |  |
| `auth_cfg` | [RESTSystemConfigAuthCfgV2] |  |  |
| `proxy_cfg` | [RESTSystemConfigProxyCfgV2] |  |  |
| `webhooks` | array<[RESTWebhook]> |  |  |
| `ibmsa_cfg` | [RESTSystemConfigIBMSAVCfg2] |  |  |
| `scanner_autoscale_cfg` | [RESTSystemConfigAutoscaleConfig] |  |  |
| `remote_repositories` | array<[RESTRemoteRepository]> |  |  |
| `misc_cfg` | [RESTSystemConfigMiscCfgV2] |  |  |
| `tls_cfg` | [RESTSystemConfigTls] |  |  |

### `RESTSystemConfigDataV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTSystemConfigV2] |  |  |
| `fed_config` | [RESTFedSystemConfig] |  |  |

### `RESTSystemConfigIBMSAV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `ibmsa_ep_enabled` | boolean | * |  |
| `ibmsa_ep_start` | integer(uint32) | * |  |
| `ibmsa_ep_dashboard_url` | string | * |  |
| `ibmsa_ep_connected_at` | string | * |  |

### `RESTSystemConfigIBMSAVCfg2`

| Field | Type | Req | Description |
|---|---|---|---|
| `ibmsa_ep_enabled` | boolean |  |  |
| `ibmsa_ep_dashboard_url` | string |  |  |

### `RESTSystemConfigMiscCfgV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `unused_group_aging` | integer(uint8) |  |  |
| `cluster_name` | string |  |  |
| `controller_debug` | array<string enum(cpath|conn|mutex|scan|cluster|k8s_monitor)> |  |  |
| `monitor_service_mesh` | boolean |  |  |
| `xff_enabled` | boolean |  |  |
| `no_telemetry_report` | boolean |  |  |

### `RESTSystemConfigMiscV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `configured_internal_subnets` | array<string> |  |  |
| `unused_group_aging` | integer(uint8) | * |  |
| `cluster_name` | string | * |  |
| `controller_debug` | array<string enum(cpath|conn|mutex|scan|cluster|k8s_monitor)> | * |  |
| `csp_type` | string |  |  |
| `monitor_service_mesh` | boolean | * |  |
| `xff_enabled` | boolean | * |  |
| `no_telemetry_report` | boolean | * |  |
| `cfg_type` | string enum(user_created|ground|federal) | * |  |

### `RESTSystemConfigModeAutoV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `mode_auto_d2m` | boolean | * |  |
| `mode_auto_d2m_duration` | integer(int64) | * |  |
| `mode_auto_m2p` | boolean | * |  |
| `mode_auto_m2p_duration` | integer(int64) | * |  |

### `RESTSystemConfigNetSvcV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `net_service_status` | boolean | * |  |
| `new_service_profile_baseline` | string | * |  |
| `disable_net_policy` | boolean | * |  |
| `detect_unmanaged_wl` | boolean | * |  |
| `strict_group_mode` | boolean | * |  |

### `RESTSystemConfigNewSvcV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `new_service_policy_mode` | string | * |  |
| `new_service_profile_baseline` | string | * |  |

### `RESTSystemConfigProxyCfgV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `registry_http_proxy_status` | boolean |  |  |
| `registry_https_proxy_status` | boolean |  |  |
| `registry_http_proxy` | [RESTProxy] |  |  |
| `registry_https_proxy` | [RESTProxy] |  |  |
| `registry_http_proxy_cfg` | [RESTProxyConfig] |  |  |
| `registry_https_proxy_cfg` | [RESTProxyConfig] |  |  |

### `RESTSystemConfigProxyV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `registry_http_proxy_status` | boolean | * |  |
| `registry_https_proxy_status` | boolean | * |  |
| `registry_http_proxy` | [RESTProxy] | * |  |
| `registry_https_proxy` | [RESTProxy] | * |  |
| `registry_http_proxy_cfg` | [RESTProxyConfig] |  |  |
| `registry_https_proxy_cfg` | [RESTProxyConfig] |  |  |

### `RESTSystemConfigSvcCfgV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `new_service_policy_mode` | string |  |  |
| `new_service_profile_baseline` | string |  |  |

### `RESTSystemConfigSyslogCfgV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `syslog_ip` | string |  |  |
| `syslog_ip_proto` | integer(uint8) |  |  |
| `syslog_port` | integer(uint16) |  |  |
| `syslog_level` | string |  |  |
| `syslog_status` | boolean |  |  |
| `syslog_categories` | array<string> |  |  |
| `syslog_in_json` | boolean |  |  |
| `single_cve_per_syslog` | boolean |  |  |
| `syslog_cve_in_layers` | boolean |  |  |
| `syslog_server_cert` | string |  |  |
| `output_event_to_logs` | boolean |  |  |

### `RESTSystemConfigSyslogV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `syslog_ip` | string | * |  |
| `syslog_ip_proto` | integer(uint8) | * |  |
| `syslog_port` | integer(uint16) | * |  |
| `syslog_level` | string | * |  |
| `syslog_status` | boolean | * |  |
| `syslog_categories` | array<string> | * |  |
| `syslog_in_json` | boolean | * |  |
| `single_cve_per_syslog` | boolean | * |  |
| `syslog_cve_in_layers` | boolean | * |  |
| `syslog_server_cert` | string | * |  |
| `output_event_to_logs` | boolean | * |  |

### `RESTSystemConfigTls`

| Field | Type | Req | Description |
|---|---|---|---|
| `enable_tls_verification` | boolean |  |  |
| `cacerts` | array<string> |  |  |

### `RESTSystemConfigV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `new_svc` | [RESTSystemConfigNewSvcV2] | * |  |
| `syslog` | [RESTSystemConfigSyslogV2] | * |  |
| `auth` | [RESTSystemConfigAuthV2] | * |  |
| `misc` | [RESTSystemConfigMiscV2] | * |  |
| `webhooks` | array<[RESTWebhook]> | * |  |
| `proxy` | [RESTSystemConfigProxyV2] | * |  |
| `ibmsa` | [RESTSystemConfigIBMSAV2] | * |  |
| `net_svc` | [RESTSystemConfigNetSvcV2] | * |  |
| `mode_auto` | [RESTSystemConfigModeAutoV2] | * |  |
| `scanner_autoscale` | [RESTSystemConfigAutoscale] | * |  |
| `tls_cfg` | [RESTSystemConfigTls] |  |  |

### `RESTSystemRequest`

| Field | Type | Req | Description |
|---|---|---|---|
| `baseline_profile` | string |  |  |
| `policy_mode` | string |  |  |
| `unquarantine` | [RESTUnquarReq] |  |  |

### `RESTSystemRequestData`

| Field | Type | Req | Description |
|---|---|---|---|
| `request` | [RESTSystemRequest] | * |  |

### `RESTSystemSummary`

| Field | Type | Req | Description |
|---|---|---|---|
| `hosts` | integer | * |  |
| `controllers` | integer | * |  |
| `enforcers` | integer | * |  |
| `disconnected_enforcers` | integer | * |  |
| `workloads` | integer | * |  |
| `running_workloads` | integer | * |  |
| `running_pods` | integer | * |  |
| `services` | integer | * |  |
| `policy_rules` | integer | * |  |
| `scanners` | integer | * |  |
| `platform` | string | * |  |
| `kube_version` | string | * |  |
| `openshift_version` | string | * |  |
| `cvedb_version` | string | * |  |
| `cvedb_create_time` | string(date-time) | * |  |
| `component_versions` | array<string> | * |  |

### `RESTSystemSummaryData`

| Field | Type | Req | Description |
|---|---|---|---|
| `summary` | [RESTSystemSummary] | * |  |

### `RESTThreatsData`

| Field | Type | Req | Description |
|---|---|---|---|
| `threats` | array<[Threat]> | * |  |

### `RESTToken`

| Field | Type | Req | Description |
|---|---|---|---|
| `token` | string | * |  |
| `fullname` | string | * |  |
| `server` | string | * |  |
| `username` | string | * |  |
| `password` | string | * |  |
| `email` | string(email) | * |  |
| `role` | string | * |  |
| `global_permissions` | array<[RESTRolePermission]> |  | permissions on global domain. only for Rancher SSO |
| `timeout` | integer(uint32) | * |  |
| `locale` | string | * |  |
| `default_password` | boolean | * |  |
| `modify_password` | boolean | * |  |
| `role_domains` | map<string,array<string>> |  | Object key is role and value is array of domains |
| `domain_permissions` | array<[RESTRolePermission]> |  | permissions on namespaces. only for Rancher SSO |
| `extra_permissions` | array<[RESTRolePermission]> |  | extra permissions(other than 'role') on global domain. only for Rancher SSO |
| `extra_permissions_domains` | array<[RESTPermitsAssigned]> |  | list of extra permissions(other than specified in 'role_domains') on namespaces. only for Rancher SSO |
| `remote_role_permissions` | object |  | role/permissions on managed clusters in fed. only for Rancher SSO |
| `last_login_timestamp` | integer(int64) | * |  |
| `last_login_at` | string | * |  |
| `login_count` | integer(uint32) | * |  |

### `RESTTokenData`

| Field | Type | Req | Description |
|---|---|---|---|
| `token` | [RESTToken] | * |  |
| `password_days_until_expire` | integer | * |  |
| `password_hours_until_expire` | integer | * |  |
| `need_to_reset_password` | boolean |  | prompt the uer to login again & provide the new password to reset after login |

### `RESTUnquarReq`

| Field | Type | Req | Description |
|---|---|---|---|
| `response_rule` | integer(uint32) |  |  |
| `group` | string |  |  |

### `RESTUser`

| Field | Type | Req | Description |
|---|---|---|---|
| `fullname` | string | * |  |
| `server` | string | * |  |
| `username` | string | * |  |
| `password` | string(password) |  |  |
| `email` | string(email) | * |  |
| `role` | string | * | role on global domain |
| `extra_permissions` | array<[RESTRolePermission]> |  | extra permissions(other than 'role') extra permissions(other than 'Role') on global domain. only for Rancher SSO |
| `timeout` | integer(uint32) | * |  |
| `locale` | string | * |  |
| `default_password` | boolean | * | If the user is using default password |
| `modify_password` | boolean | * | If the password should be modified |
| `role_domains` | object |  | map of roles on namespaces |
| `extra_permissions_domains` | array<[RESTPermitsAssigned]> |  | list of extra permissions(other than 'role_domains') for namespaces on managed clusters in fed. only for Rancher SSO |
| `remote_role_permissions` | object |  | role/permissions on managed clusters in fed. only for Rancher SSO |
| `last_login_timestamp` | integer(int64) | * |  |
| `last_login_at` | string | * |  |
| `login_count` | integer(uint32) | * |  |
| `blocked_for_failed_login` | boolean | * |  |
| `blocked_for_password_expired` | boolean | * |  |
| `password_resettable` | boolean | * | whether the user's password can be reset by the current login user |

### `RESTUserData`

| Field | Type | Req | Description |
|---|---|---|---|
| `user` | [RESTUser] | * |  |

### `RESTUserRole`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `comment` | string | * |  |
| `reserved` | boolean | * |  |
| `permissions` | array<[RESTRolePermission]> | * |  |

### `RESTUserRoleConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `comment` | string | * |  |
| `permissions` | array<[RESTRolePermission]> | * |  |

### `RESTUserRoleConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTUserRoleConfig] | * |  |

### `RESTUserRolesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `roles` | array<[RESTUserRole]> | * |  |

### `RESTUsersData`

| Field | Type | Req | Description |
|---|---|---|---|
| `users` | array<[RESTUser]> | * |  |
| `global_roles` | array<string> | * |  |
| `domain_roles` | array<string> | * |  |
| `roles_not_for_domain` | array<string> |  |  |

### `RESTVulnerability`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `score` | number(float32) | * |  |
| `severity` | string | * |  |
| `vectors` | string | * |  |
| `description` | string | * |  |
| `file_name` | string | * |  |
| `package_name` | string | * |  |
| `package_version` | string | * |  |
| `fixed_version` | string | * |  |
| `link` | string | * |  |
| `score_v3` | number(float32) | * |  |
| `vectors_v3` | string | * |  |
| `published_timestamp` | integer(int64) | * |  |
| `last_modified_timestamp` | integer(int64) | * |  |
| `cpes` | array<string> |  |  |
| `cves` | array<string> |  |  |
| `feed_rating` | string | * |  |
| `in_base_image` | boolean | * |  |
| `tags` | array<string> |  |  |

### `RESTVulnerabilityProfile`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `entries` | array<[RESTVulnerabilityProfileEntry]> | * |  |
| `cfg_type` | string enum(user_created|ground) |  |  |

### `RESTVulnerabilityProfileConfig`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `entries` | array<[RESTVulnerabilityProfileEntry]> |  |  |

### `RESTVulnerabilityProfileConfigData`

| Field | Type | Req | Description |
|---|---|---|---|
| `config` | [RESTVulnerabilityProfileConfig] | * |  |

### `RESTVulnerabilityProfileData`

| Field | Type | Req | Description |
|---|---|---|---|
| `profile` | [RESTVulnerabilityProfile] | * |  |

### `RESTVulnerabilityProfileEntry`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | integer(uint32) | * |  |
| `name` | string | * |  |
| `comment` | string | * |  |
| `days` | integer(uint) | * |  |
| `domains` | array<string> | * |  |
| `images` | array<string> | * |  |

### `RESTVulnerabilityProfilesData`

| Field | Type | Req | Description |
|---|---|---|---|
| `profiles` | array<[RESTVulnerabilityProfile]> | * |  |

### `RESTWebhook`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string | * |  |
| `url` | string | * |  |
| `enable` | boolean | * |  |
| `use_proxy` | boolean | * |  |
| `type` | string enum(|Slack|JSON|Teams) | * |  |
| `cfg_type` | string enum(user_created|ground|federal) | * |  |

### `RESTWorkloadBrief`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | * |  |
| `name` | string | * |  |
| `display_name` | string | * |  |
| `pod_name` | string | * |  |
| `image` | string | * |  |
| `image_id` | string | * |  |
| `image_digest` | array<string> |  |  |
| `image_created_at` | string(date-time) | * |  |
| `image_reg_scanned` | boolean |  |  |
| `platform_role` | string | * |  |
| `domain` | string | * |  |
| `state` | string | * |  |
| `service` | string | * |  |
| `author` | string | * |  |
| `service_group` | string | * |  |
| `share_ns_with` | string |  |  |
| `cap_sniff` | boolean | * |  |
| `cap_quarantine` | boolean | * |  |
| `cap_change_mode` | boolean | * |  |
| `policy_mode` | string | * |  |
| `profile_mode` | string | * |  |
| `scan_summary` | [RESTScanBrief] | * |  |
| `children` | array<[RESTWorkloadBrief]> | * |  |
| `quarantine_reason` | string |  |  |
| `service_mesh` | boolean | * |  |
| `service_mesh_sidecar` | boolean | * |  |
| `privileged` | boolean | * |  |
| `run_as_root` | boolean | * |  |
| `baseline_profile` | string | * |  |

### `RESTWorkloadBriefV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `id` | string | * |  |
| `name` | string | * |  |
| `display_name` | string | * |  |
| `host_name` | string | * |  |
| `host_id` | string | * |  |
| `image` | string | * |  |
| `image_id` | string | * |  |
| `image_digest` | array<string> |  |  |
| `image_created_at` | string(date-time) | * |  |
| `image_reg_scanned` | boolean |  |  |
| `domain` | string | * |  |
| `state` | string | * |  |
| `service` | string | * |  |
| `author` | string | * |  |
| `service_group` | string | * |  |

### `RESTWorkloadDetailDataV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `workload` | [RESTWorkloadDetailV2] | * |  |

### `RESTWorkloadDetailMiscV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `groups` | array<string> | * |  |
| `app_ports` | map<string,string> | * | map key is string type |
| `children` | array<[RESTWorkloadDetailV2]> | * |  |

### `RESTWorkloadDetailV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `brief` | [RESTWorkloadBriefV2] | * |  |
| `security` | [RESTWorkloadSecurityV2] | * |  |
| `rt_attributes` | [RESTWorkloadRtAttribesV2] | * |  |
| `children` | array<[RESTWorkloadV2]> | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `platform_role` | string | * |  |
| `created_at` | string(date-time) | * |  |
| `started_at` | string(date-time) | * |  |
| `finished_at` | string(date-time) | * |  |
| `running` | boolean | * |  |
| `secured_at` | string(date-time) | * |  |
| `exit_code` | integer | * |  |
| `misc` | [RESTWorkloadDetailMiscV2] | * |  |

### `RESTWorkloadPorts`

| Field | Type | Req | Description |
|---|---|---|---|
| `ip_proto` | integer(uint8) | * |  |
| `port` | integer(uint16) | * |  |
| `host_ip` | string | * |  |
| `host_port` | integer(uint16) | * |  |

### `RESTWorkloadRequest`

| Field | Type | Req | Description |
|---|---|---|---|
| `command` | string |  |  |

### `RESTWorkloadRequestData`

| Field | Type | Req | Description |
|---|---|---|---|
| `request` | [RESTWorkloadRequest] | * |  |

### `RESTWorkloadRtAttribesV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `pod_name` | string | * |  |
| `share_ns_with` | string |  |  |
| `privileged` | boolean | * |  |
| `run_as_root` | boolean | * |  |
| `labels` | map<string,string> | * | map key is string type |
| `memory_limit` | integer(int64) | * |  |
| `cpus` | string | * |  |
| `service_account` | string | * |  |
| `network_mode` | string | * |  |
| `interfaces` | map<string,array<[RESTIPAddr]>> | * | map key is string type like "eth0" |
| `ports` | array<[RESTWorkloadPorts]> | * |  |
| `applications` | array<string> | * |  |

### `RESTWorkloadSecurityV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `cap_sniff` | boolean | * |  |
| `cap_quarantine` | boolean | * |  |
| `cap_change_mode` | boolean | * |  |
| `service_mesh` | boolean | * |  |
| `service_mesh_sidecar` | boolean | * |  |
| `policy_mode` | string | * |  |
| `profile_mode` | string | * |  |
| `baseline_profile` | string | * |  |
| `quarantine_reason` | string |  |  |
| `scan_summary` | [RESTScanBrief] | * |  |

### `RESTWorkloadV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `brief` | [RESTWorkloadBriefV2] | * |  |
| `security` | [RESTWorkloadSecurityV2] | * |  |
| `rt_attributes` | [RESTWorkloadRtAttribesV2] | * |  |
| `children` | array<[RESTWorkloadV2]> | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `platform_role` | string | * |  |
| `created_at` | string(date-time) | * |  |
| `started_at` | string(date-time) | * |  |
| `finished_at` | string(date-time) | * |  |
| `running` | boolean | * |  |
| `secured_at` | string(date-time) | * |  |
| `exit_code` | integer | * |  |

### `RESTWorkloadsDataV2`

| Field | Type | Req | Description |
|---|---|---|---|
| `workloads` | array<[RESTWorkloadV2]> | * |  |

### `Threat`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string |  |  |
| `level` | string | * |  |
| `reported_timestamp` | integer(int64) | * |  |
| `reported_at` | string | * |  |
| `cluster_name` | string | * |  |
| `response_rule_id` | integer |  |  |
| `host_id` | string | * |  |
| `host_name` | string | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `id` | string | * |  |
| `threat_id` | integer(uint32) | * |  |
| `client_workload_id` | string | * |  |
| `client_workload_name` | string | * |  |
| `client_workload_domain` | string |  |  |
| `client_workload_image` | string |  |  |
| `client_workload_service` | string |  |  |
| `server_workload_id` | string | * |  |
| `server_workload_name` | string | * |  |
| `server_workload_domain` | string |  |  |
| `server_workload_image` | string |  |  |
| `server_workload_service` | string |  |  |
| `severity` | string | * |  |
| `action` | string | * |  |
| `count` | integer(uint32) | * |  |
| `ether_type` | integer(uint16) | * |  |
| `client_port` | integer(uint16) | * |  |
| `server_port` | integer(uint16) | * |  |
| `server_conn_port` | integer(uint16) | * |  |
| `icmp_code` | integer(uint8) | * |  |
| `icmp_type` | integer(uint8) | * |  |
| `ip_proto` | integer(uint8) | * |  |
| `client_ip` | string | * |  |
| `server_ip` | string | * |  |
| `application` | string | * |  |
| `sensor` | string | * |  |
| `group` | string | * |  |
| `target` | string | * |  |
| `monitor` | boolean | * |  |
| `cap_len` | integer(uint16) |  |  |
| `packet` | string |  |  |
| `message` | string | * |  |

### `Violation`

| Field | Type | Req | Description |
|---|---|---|---|
| `name` | string |  |  |
| `level` | string | * |  |
| `reported_timestamp` | integer(int64) | * |  |
| `reported_at` | string(date-time) | * |  |
| `cluster_name` | string | * |  |
| `response_rule_id` | integer |  |  |
| `host_id` | string | * |  |
| `host_name` | string | * |  |
| `enforcer_id` | string | * |  |
| `enforcer_name` | string | * |  |
| `id` | string | * |  |
| `client_id` | string | * |  |
| `client_name` | string | * |  |
| `client_domain` | string |  |  |
| `client_image` | string |  |  |
| `client_service` | string |  |  |
| `server_id` | string | * |  |
| `server_name` | string | * |  |
| `server_domain` | string |  |  |
| `server_image` | string |  |  |
| `server_service` | string |  |  |
| `server_port` | integer(uint16) | * |  |
| `ip_proto` | integer(uint8) | * |  |
| `applications` | array<string> | * |  |
| `servers` | array<string> | * |  |
| `sessions` | integer(uint32) | * |  |
| `policy_action` | string | * |  |
| `policy_id` | integer(uint32) | * |  |
| `client_ip` | string | * |  |
| `server_ip` | string | * |  |
| `fqdn` | string | * |  |

