# Appendix A — NeuVector Controller REST API inventory (v5.6.0)

Generated from `controller/api/apis.yaml` @ neuvector/neuvector main.

## A.1 Documented endpoints (Swagger)

| Tag | Method | Path | Request body schema | 200 response schema | Query params (documented) |
|---|---|---|---|---|---|
| Admission | GET | `/v1/admission/options` | — | RESTAdmissionConfigData | — |
| Admission | PATCH | `/v1/admission/rule` | RESTAdmissionRuleConfigData | object | — |
| Admission | POST | `/v1/admission/rule` | RESTAdmissionRuleConfigData | RESTAdmissionRuleData | — |
| Admission | POST | `/v1/admission/rule/promote` | RESTAdmCtrlPromoteRequestData | object | — |
| Admission | DELETE | `/v1/admission/rule/{id}` | — | object | — |
| Admission | GET | `/v1/admission/rule/{id}` | — | RESTAdmissionRuleData | — |
| Admission | DELETE | `/v1/admission/rules` | — | object | scope |
| Admission | GET | `/v1/admission/rules` | — | RESTAdmissionRulesData | scope |
| Admission | GET | `/v1/admission/state` | — | RESTAdmissionConfigData | — |
| Admission | PATCH | `/v1/admission/state` | RESTAdmissionConfigData | object | — |
| Admission | GET | `/v1/admission/stats` | — | RESTAdmissionStatsData | — |
| Admission | POST | `/v1/assess/admission/rule` | string | RESTAdmCtrlRulesTestResults | — |
| Apikey | GET | `/v1/api_key` | — | RESTApikeysData | — |
| Apikey | POST | `/v1/api_key` | RESTApikeyCreationData | RESTApikeyGeneratedData | — |
| Apikey | DELETE | `/v1/api_key/{accesskey}` | — | object | — |
| Apikey | GET | `/v1/api_key/{accesskey}` | — | RESTApikeyData | — |
| Authentication | DELETE | `/v1/auth` | — | object | — |
| Authentication | PATCH | `/v1/auth` | — | object | — |
| Authentication | POST | `/v1/auth` | RESTAuthData | RESTTokenData | — |
| Authentication | POST | `/v1/auth/{server}` | RESTAuthData | object | — |
| Compliance | GET | `/v1/bench/host/{id}/docker` | — | RESTBenchReport | — |
| Compliance | POST | `/v1/bench/host/{id}/docker` | — | object | — |
| Compliance | GET | `/v1/bench/host/{id}/kubernetes` | — | RESTBenchReport | — |
| Compliance | POST | `/v1/bench/host/{id}/kubernetes` | — | object | — |
| Compliance | GET | `/v1/compliance/profile` | — | RESTComplianceProfilesData | — |
| Compliance | GET | `/v1/compliance/profile/{name}` | — | RESTComplianceProfileData | — |
| Compliance | PATCH | `/v1/compliance/profile/{name}` | RESTComplianceProfileConfigData | object | — |
| Compliance | DELETE | `/v1/compliance/profile/{name}/entry/{check}` | — | object | — |
| Compliance | PATCH | `/v1/compliance/profile/{name}/entry/{check}` | RESTComplianceProfileEntryConfigData | object | — |
| Compliance | GET | `/v1/custom_check` | — | RESTCustomCheckListData | — |
| Compliance | GET | `/v1/custom_check/{group}` | — | RESTCustomCheckData | — |
| Compliance | PATCH | `/v1/custom_check/{group}` | RESTCustomCheckConfigData | object | — |
| Container | GET | `/v1/workload` | — | RESTWorkloadsData | — |
| Container | POST | `/v1/workload/request/{id}` | RESTWorkloadRequestData | object | — |
| Container | GET | `/v1/workload/{id}` | — | RESTWorkloadDetailData | — |
| Container | PATCH | `/v1/workload/{id}` | RESTWorkloadConfigData | object | — |
| Container | GET | `/v1/workload/{id}/compliance` | — | RESTComplianceData | — |
| Container | GET | `/v1/workload/{id}/config` | — | RESTWorkloadConfigData | — |
| Container | GET | `/v1/workload/{id}/process` | — | RESTProcessList | — |
| Container | GET | `/v1/workload/{id}/process_history` | — | RESTProcessProfileEntry | — |
| Container | GET | `/v1/workload/{id}/stats` | — | RESTWorkloadStatsData | — |
| Container | GET | `/v2/workload` | — | RESTWorkloadsDataV2 | — |
| Container | POST | `/v2/workload` | RESTAssetIDList | RESTWorkloadsDataV2 | — |
| Container | GET | `/v2/workload/{id}` | — | RESTWorkloadDetailDataV2 | — |
| Controller | GET | `/v1/controller` | — | RESTController | — |
| Controller | GET | `/v1/controller/{id}` | — | RESTControllerData | — |
| Controller | PATCH | `/v1/controller/{id}` | RESTControllerConfigData | object | — |
| Controller | GET | `/v1/controller/{id}/config` | — | RESTControllerConfigData | — |
| Controller | GET | `/v1/controller/{id}/stats` | — | RESTWorkloadStatsData | — |
| DLP | GET | `/v1/dlp/group` | — | RESTDlpGroupsData | — |
| DLP | GET | `/v1/dlp/group/{name}` | — | RESTDlpGroupData | — |
| DLP | PATCH | `/v1/dlp/group/{name}` | RESTDlpGroupConfigData | object | — |
| DLP | GET | `/v1/dlp/rule` | — | RESTDlpRulesData | — |
| DLP | GET | `/v1/dlp/rule/{name}` | — | RESTDlpRuleData | — |
| DLP | GET | `/v1/dlp/sensor` | — | RESTDlpSensorsData | — |
| DLP | POST | `/v1/dlp/sensor` | RESTDlpSensorConfigData | object | — |
| DLP | DELETE | `/v1/dlp/sensor/{name}` | — | object | — |
| DLP | GET | `/v1/dlp/sensor/{name}` | — | RESTDlpSensorData | — |
| DLP | PATCH | `/v1/dlp/sensor/{name}` | RESTDlpSensorConfigData | object | — |
| EULA | GET | `/v1/eula` | — | RESTEULAData | — |
| EULA | POST | `/v1/eula` | RESTEULAData | object | — |
| Enforcer | GET | `/v1/enforcer` | — | RESTAgentsData | — |
| Enforcer | GET | `/v1/enforcer/{id}` | — | RESTAgentData | — |
| Enforcer | PATCH | `/v1/enforcer/{id}` | RESTAgentConfigData | object | — |
| Enforcer | GET | `/v1/enforcer/{id}/config` | — | RESTAgentConfigData | — |
| Enforcer | GET | `/v1/enforcer/{id}/stats` | — | RESTAgentStatsData | — |
| Federation | GET | `/v1/fed/healthcheck` | — | object | — |
| File | POST | `/v1/csp/file/support` | — | object | — |
| File | POST | `/v1/file/admission` | RESTAdmCtrlRulesExport | RESTRemoteExportData | scope |
| File | POST | `/v1/file/admission/config` | string | object | scope |
| File | POST | `/v1/file/compliance/profile` | RESTCompProfilesExport | RESTRemoteExportData | — |
| File | GET | `/v1/file/config` | — | object | — |
| File | POST | `/v1/file/config` | — | object | scope |
| File | POST | `/v1/file/dlp` | RESTDlpSensorExport | RESTRemoteExportData | scope |
| File | POST | `/v1/file/dlp/config` | string | object | scope |
| File | POST | `/v1/file/fed_config` | RESTFedConfigExport | RESTRemoteExportData | — |
| File | GET | `/v1/file/group` | RESTGroupExport | object | — |
| File | POST | `/v1/file/group` | RESTGroupExport | RESTRemoteExportData | scope |
| File | GET | `/v1/file/group/config` | — | RESTImportTaskData | — |
| File | POST | `/v1/file/group/config` | string | object | scope |
| File | POST | `/v1/file/response/rule` | RESTResponseRulesExport | RESTRemoteExportData | scope |
| File | POST | `/v1/file/response/rule/config` | string | object | scope |
| File | POST | `/v1/file/vulnerability/profile` | RESTVulnProfilesExport | RESTRemoteExportData | — |
| File | POST | `/v1/file/waf` | RESTWafSensorExport | RESTRemoteExportData | scope |
| File | POST | `/v1/file/waf/config` | string | object | scope |
| File Monitor | GET | `/v1/file_monitor` | — | RESTFileMonitorFileData | scope |
| File Monitor | GET | `/v1/file_monitor/{name}` | — | RESTFileMonitorFile | — |
| File Monitor | PATCH | `/v1/file_monitor/{name}` | RESTFileMonitorConfigData | object | — |
| Group | GET | `/v1/group` | — | RESTGroupsData | scope |
| Group | POST | `/v1/group` | RESTGroupConfigData | object | — |
| Group | DELETE | `/v1/group/{name}` | — | object | — |
| Group | GET | `/v1/group/{name}` | — | RESTGroupData | — |
| Group | PATCH | `/v1/group/{name}` | RESTGroupConfigData | object | — |
| Host | GET | `/v1/host` | — | RESTHostsData | — |
| Host | GET | `/v1/host/{id}` | — | RESTHostData | — |
| Host | GET | `/v1/host/{id}/compliance` | — | RESTComplianceData | — |
| Log | GET | `/v1/log/activity` | — | RESTEventsData | — |
| Log | GET | `/v1/log/audit` | — | RESTAuditsData | — |
| Log | GET | `/v1/log/event` | — | RESTEventsData | — |
| Log | GET | `/v1/log/incident` | — | RESTIncidentsData | — |
| Log | GET | `/v1/log/security` | — | RESTSecurityData | — |
| Log | GET | `/v1/log/threat` | — | RESTThreatsData | — |
| Log | GET | `/v1/log/threat/{id}` | — | RESTThreatData | — |
| Log | GET | `/v1/log/violation` | — | RESTPolicyViolationsData | — |
| Log | GET | `/v1/log/violation/workload` | — | RESTPolicyViolationsWLData | — |
| Namespace | GET | `/v1/domain` | — | RESTDomainsData | — |
| Namespace | PATCH | `/v1/domain` | RESTDomainConfigData | object | — |
| Namespace | PATCH | `/v1/domain/{name}` | RESTDomainEntryConfigData | object | — |
| Policy | DELETE | `/v1/policy/rule` | — | object | scope |
| Policy | GET | `/v1/policy/rule` | — | RESTPolicyRulesData | scope |
| Policy | PATCH | `/v1/policy/rule` | RESTPolicyRuleActionData | object | scope |
| Policy | DELETE | `/v1/policy/rule/{id}` | — | object | — |
| Policy | GET | `/v1/policy/rule/{id}` | — | RESTPolicyRuleData | — |
| Policy | PATCH | `/v1/policy/rule/{id}` | RESTPolicyRuleConfigData | object | — |
| Policy | POST | `/v1/policy/rules/promote` | RESTPolicyPromoteRequestData | object | — |
| Process | GET | `/v1/process_profile` | — | RESTProcessProfilesData | scope |
| Process | GET | `/v1/process_profile/{name}` | — | RESTProcessProfileData | — |
| Process | PATCH | `/v1/process_profile/{name}` | RESTProcessProfileConfigData | object | — |
| Process | GET | `/v1/process_rules/{uuid}` | — | RESTProcessRulesResp | — |
| Remote Export Repository | DELETE | `/v1/system/config/remote_repository/{alias}` | — | object | — |
| Remote Repository | POST | `/v1/system/config/remote_repository` | RESTRemoteRepository | object | — |
| Remote Repository | PATCH | `/v1/system/config/remote_repository/{alias}` | RESTRemoteRepositoryConfigData | object | — |
| Response Rule | DELETE | `/v1/response/rule` | — | object | scope |
| Response Rule | GET | `/v1/response/rule` | — | RESTResponseRulesData | scope |
| Response Rule | PATCH | `/v1/response/rule` | RESTResponseRuleActionData | object | — |
| Response Rule | DELETE | `/v1/response/rule/{id}` | — | object | — |
| Response Rule | GET | `/v1/response/rule/{id}` | — | RESTResponseRuleData | — |
| Response Rule | PATCH | `/v1/response/rule/{id}` | RESTResponseRuleConfigData | object | — |
| Response Rule | GET | `/v1/response/workload_rules/{id}` | — | RESTResponseRulesData | — |
| Scan | GET | `/v1/scan/cache_data/{id}` | — | RESTScanCacheData | — |
| Scan | GET | `/v1/scan/cache_stat/{id}` | — | RESTScanCacheStat | — |
| Scan | GET | `/v1/scan/config` | — | RESTScanConfigResp | — |
| Scan | PATCH | `/v1/scan/config` | RESTScanConfigData | object | — |
| Scan | GET | `/v1/scan/host/{id}` | — | RESTScanReportData | — |
| Scan | POST | `/v1/scan/host/{id}` | — | object | — |
| Scan | POST | `/v1/scan/hosts/scan_report` | RESTAssetsScanReportQuery | RESTAssetScanReportData | — |
| Scan | GET | `/v1/scan/image` | — | RESTScanImageSummaryData | — |
| Scan | GET | `/v1/scan/image/{id}` | — | RESTScanReportData | — |
| Scan | GET | `/v1/scan/platform` | — | RESTScanPlatformSummaryData | — |
| Scan | GET | `/v1/scan/platform/platform` | — | RESTScanReportData | — |
| Scan | POST | `/v1/scan/platform/platform` | — | object | — |
| Scan | GET | `/v1/scan/registry` | — | RESTRegistrySummaryListData | scope |
| Scan | POST | `/v1/scan/registry` | RESTRegistryConfigData | object | — |
| Scan | DELETE | `/v1/scan/registry/{name}` | — | object | — |
| Scan | GET | `/v1/scan/registry/{name}` | — | RESTRegistrySummaryData | — |
| Scan | PATCH | `/v1/scan/registry/{name}` | RESTRegistryConfigData | object | — |
| Scan | GET | `/v1/scan/registry/{name}/image/{id}` | — | RESTScanReportData | — |
| Scan | GET | `/v1/scan/registry/{name}/images` | — | RESTRegistryImageSummaryData | — |
| Scan | GET | `/v1/scan/registry/{name}/layers/{id}` | — | RESTScanLayersReportData | — |
| Scan | DELETE | `/v1/scan/registry/{name}/scan` | — | object | — |
| Scan | POST | `/v1/scan/registry/{name}/scan` | — | object | — |
| Scan | POST | `/v1/scan/repository` | RESTScanRepoReqData | RESTScanRepoReportData | — |
| Scan | GET | `/v1/scan/scanner` | — | RESTScannerData | — |
| Scan | GET | `/v1/scan/sigstore/root_of_trust` | — | REST_SigstoreRootOfTrustCollection | — |
| Scan | POST | `/v1/scan/sigstore/root_of_trust` | REST_SigstoreRootOfTrust_POST | object | — |
| Scan | DELETE | `/v1/scan/sigstore/root_of_trust/{root_name}` | — | object | — |
| Scan | GET | `/v1/scan/sigstore/root_of_trust/{root_name}` | — | REST_SigstoreRootOfTrust_GET | — |
| Scan | PATCH | `/v1/scan/sigstore/root_of_trust/{root_name}` | REST_SigstoreRootOfTrust_PATCH | object | — |
| Scan | GET | `/v1/scan/sigstore/root_of_trust/{root_name}/verifier` | — | REST_SigstoreVerifierCollection | — |
| Scan | POST | `/v1/scan/sigstore/root_of_trust/{root_name}/verifier` | REST_SigstoreVerifier | object | — |
| Scan | DELETE | `/v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name}` | — | object | — |
| Scan | GET | `/v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name}` | — | REST_SigstoreVerifier | — |
| Scan | PATCH | `/v1/scan/sigstore/root_of_trust/{root_name}/verifier/{verifier_name}` | REST_SigstoreVerifier_PATCH | object | — |
| Scan | GET | `/v1/scan/status` | — | RESTScanStatusData | — |
| Scan | GET | `/v1/scan/workload/{id}` | — | RESTScanReportData | — |
| Scan | POST | `/v1/scan/workload/{id}` | — | object | — |
| Scan | POST | `/v1/scan/workloads/scan_report` | RESTAssetsScanReportQuery | RESTAssetScanReportData | — |
| Scan | POST | `/v2/scan/registry` | RESTRegistryConfigDataV2 | object | — |
| Scan | PATCH | `/v2/scan/registry/{name}` | RESTRegistryConfigDataV2 | object | — |
| Server | GET | `/v1/server` | — | RESTServersData | — |
| Server | POST | `/v1/server` | RESTServerConfigData | object | — |
| Server | DELETE | `/v1/server/{name}` | — | object | — |
| Server | GET | `/v1/server/{name}` | — | RESTServerData | — |
| Server | PATCH | `/v1/server/{name}` | RESTServerConfigData | object | — |
| Server | PATCH | `/v1/server/{name}/role/{role}` | RESTServerRoleGroupsConfigData | object | — |
| Server | GET | `/v1/server/{name}/user` | — | RESTUsersData | — |
| Service | GET | `/v1/service` | — | RESTServicesData | — |
| Service | POST | `/v1/service` | RESTServiceConfigData | object | — |
| Service | PATCH | `/v1/service/config` | RESTServiceBatchConfigData | object | — |
| Service | PATCH | `/v1/service/config/network` | RESTServiceBatchConfigData | object | — |
| Service | PATCH | `/v1/service/config/profile` | RESTServiceBatchConfigData | object | — |
| Service | GET | `/v1/service/{name}` | — | RESTServiceData | — |
| Sniffer | GET | `/v1/sniffer` | — | RESTSniffersData | f_workload |
| Sniffer | POST | `/v1/sniffer` | RESTSnifferArgsData | object | f_workload |
| Sniffer | PATCH | `/v1/sniffer/stop/{id}` | — | object | — |
| Sniffer | DELETE | `/v1/sniffer/{id}` | — | object | — |
| Sniffer | GET | `/v1/sniffer/{id}` | — | RESTSnifferData | — |
| Sniffer | GET | `/v1/sniffer/{id}/pcap` | — | object | — |
| System | GET | `/v1/system/alerts` | — | RESTNvAlerts | — |
| System | GET | `/v1/system/config` | — | RESTSystemConfigData | scope |
| System | PATCH | `/v1/system/config` | RESTSystemConfigConfigData | object | — |
| System | POST | `/v1/system/config/webhook` | RESTSystemWebhookConfigData | object | — |
| System | DELETE | `/v1/system/config/webhook/{name}` | — | object | scope |
| System | PATCH | `/v1/system/config/webhook/{name}` | RESTSystemWebhookConfigData | object | scope |
| System | POST | `/v1/system/request` | RESTSystemRequestData | object | — |
| System | GET | `/v1/system/score/metrics` | — | RESTScoreMetricsData | — |
| System | GET | `/v1/system/summary` | — | RESTSystemSummaryData | — |
| System | GET | `/v2/system/config` | — | RESTSystemConfigDataV2 | scope |
| System | PATCH | `/v2/system/config` | RESTSystemConfigConfigDataV2 | object | — |
| User | GET | `/v1/password_profile` | — | RESTPwdProfilesData | — |
| User | GET | `/v1/password_profile/{name}` | — | RESTPwdProfileData | — |
| User | PATCH | `/v1/password_profile/{name}` | RESTPwdProfileConfigData | object | — |
| User | GET | `/v1/user` | — | RESTUsersData | — |
| User | POST | `/v1/user` | RESTUserData | object | — |
| User | DELETE | `/v1/user/{fullname}` | — | object | — |
| User | GET | `/v1/user/{fullname}` | — | RESTUserData | — |
| User | PATCH | `/v1/user/{fullname}` | RESTUserConfigData | object | — |
| User | POST | `/v1/user/{fullname}/password` | RESTUserPwdConfigData | object | — |
| User | PATCH | `/v1/user/{fullname}/role/{role}` | RESTUserRoleDomainsConfigData | object | — |
| User | GET | `/v1/user_role` | — | RESTUserRolesData | — |
| User | POST | `/v1/user_role` | RESTUserRoleConfigData | object | — |
| User | DELETE | `/v1/user_role/{name}` | — | object | — |
| User | GET | `/v1/user_role/{name}` | — | RESTUserRoleData | — |
| User | PATCH | `/v1/user_role/{name}` | RESTUserRoleConfigData | object | — |
| Vulnerability | GET | `/v1/vulnerability/profile` | — | RESTVulnerabilityProfilesData | — |
| Vulnerability | GET | `/v1/vulnerability/profile/{name}` | — | RESTVulnerabilityProfileData | — |
| Vulnerability | PATCH | `/v1/vulnerability/profile/{name}` | RESTVulnerabilityProfileConfigData | object | — |
| Vulnerability | POST | `/v1/vulnerability/profile/{name}/entry` | RESTVulnerabilityProfileEntryConfigData | RESTVulnerabilityProfileEntryConfigData | — |
| Vulnerability | DELETE | `/v1/vulnerability/profile/{name}/entry/{id}` | — | object | — |
| Vulnerability | PATCH | `/v1/vulnerability/profile/{name}/entry/{id}` | RESTVulnerabilityProfileEntryConfigData | object | — |
| WAF Rule | GET | `/v1/waf/group` | — | RESTWafGroupsData | scope |
| WAF Rule | GET | `/v1/waf/group/{name}` | — | RESTWafGroupData | — |
| WAF Rule | PATCH | `/v1/waf/group/{name}` | RESTWafGroupConfigData | object | — |
| WAF Rule | GET | `/v1/waf/rule` | — | RESTWafRulesData | — |
| WAF Rule | GET | `/v1/waf/rule/{name}` | — | RESTWafRuleData | — |
| WAF Rule | GET | `/v1/waf/sensor` | — | RESTWafSensorsData | scope |
| WAF Rule | POST | `/v1/waf/sensor` | RESTDlpSensorConfigData | object | — |
| WAF Rule | DELETE | `/v1/waf/sensor/{name}` | — | object | — |
| WAF Rule | GET | `/v1/waf/sensor/{name}` | — | RESTWafSensorData | — |
| WAF Rule | PATCH | `/v1/waf/sensor/{name}` | RESTWafSensorConfigData | object | — |
| compliance profile. The payload body is the content of the compliance profile yaml file. | POST | `/v1/file/compliance/profile/config` | string | object | — |
| compliance profile. The payload body is the content of the vulnerability profile yaml file. | POST | `/v1/file/vulnerability/profile/config` | string | object | — |

**Total documented operations: 232**

## A.2 Routes registered in the controller but ABSENT from Swagger

These are real, reachable endpoints (source: `controller/rest/rest.go`). Many are marked
"Skip API document" upstream. Treat them as **unstable**: allowed only where this spec
explicitly names them, and always behind `NV_ALLOW_UNDOCUMENTED=true`.

| Method | Path |
|---|---|
| POST | `/findings/v1/{accountID}/providers/{providerID}/occurrences` |
| POST | `/identity/token` |
| DELETE | `/v1/api_key/{name}` |
| GET | `/v1/api_key/{name}` |
| POST | `/v1/assetvul` |
| GET | `/v1/compliance/asset` |
| GET | `/v1/compliance/available_filter` |
| GET | `/v1/controller/{id}/counter` |
| GET | `/v1/controller/{id}/logs` |
| POST | `/v1/controller/{id}/profiling` |
| DELETE | `/v1/conversation` |
| GET | `/v1/conversation` |
| DELETE | `/v1/conversation/{from}/{to}` |
| GET | `/v1/conversation/{from}/{to}` |
| GET | `/v1/conversation_endpoint` |
| DELETE | `/v1/conversation_endpoint/{id}` |
| PATCH | `/v1/conversation_endpoint/{id}` |
| POST | `/v1/debug/admission/test` |
| GET | `/v1/debug/admission_stats` |
| GET | `/v1/debug/controller/sync` |
| POST | `/v1/debug/controller/sync/{id}` |
| GET | `/v1/debug/dlp/mac` |
| GET | `/v1/debug/dlp/rule` |
| GET | `/v1/debug/dlp/wlrule` |
| GET | `/v1/debug/internal_subnets` |
| GET | `/v1/debug/ip2workload` |
| GET | `/v1/debug/policy/rule` |
| GET | `/v1/debug/registry/image/{name}` |
| POST | `/v1/debug/server/test` |
| GET | `/v1/debug/system/stats` |
| GET | `/v1/debug/workload/intercept` |
| POST | `/v1/dlp/rule` |
| DELETE | `/v1/dlp/rule/{name}` |
| PATCH | `/v1/dlp/rule/{name}` |
| GET | `/v1/enforcer/{id}/counter` |
| GET | `/v1/enforcer/{id}/logs` |
| GET | `/v1/enforcer/{id}/probe_containers` |
| GET | `/v1/enforcer/{id}/probe_processes` |
| GET | `/v1/enforcer/{id}/probe_summary` |
| POST | `/v1/enforcer/{id}/profiling` |
| DELETE | `/v1/fed/cluster/{id}` |
| DELETE | `/v1/fed/cluster/{id}/*request` |
| GET | `/v1/fed/cluster/{id}/*request` |
| PATCH | `/v1/fed/cluster/{id}/*request` |
| POST | `/v1/fed/cluster/{id}/*request` |
| POST | `/v1/fed/command_internal` |
| PATCH | `/v1/fed/config` |
| POST | `/v1/fed/csp_support_internal` |
| POST | `/v1/fed/demote` |
| POST | `/v1/fed/deploy` |
| POST | `/v1/fed/join` |
| POST | `/v1/fed/join_internal` |
| GET | `/v1/fed/join_token` |
| POST | `/v1/fed/joint_test_internal` |
| POST | `/v1/fed/leave` |
| POST | `/v1/fed/leave_internal` |
| GET | `/v1/fed/member` |
| POST | `/v1/fed/ping_internal` |
| POST | `/v1/fed/poll_internal` |
| POST | `/v1/fed/promote` |
| POST | `/v1/fed/remove_internal` |
| POST | `/v1/fed/scan_data_internal` |
| GET | `/v1/fed/tokens` |
| GET | `/v1/fed/view/{id}` |
| DELETE | `/v1/fed_auth` |
| POST | `/v1/fed_auth` |
| GET | `/v1/file_monitor_file` |
| GET | `/v1/group/{name}/stats` |
| GET | `/v1/host/{id}/process_profile` |
| POST | `/v1/internal/alert` |
| GET | `/v1/internal/system` |
| GET | `/v1/list/application` |
| GET | `/v1/list/compliance` |
| GET | `/v1/list/registry_type` |
| GET | `/v1/meter` |
| GET | `/v1/partner/ibm_sa/{id}/setup` |
| DELETE | `/v1/partner/ibm_sa/{id}/setup/{accountID}/{providerID}` |
| POST | `/v1/partner/ibm_sa/{id}/setup/{action}` |
| GET | `/v1/partner/ibm_sa/{id}/setup/{info}` |
| GET | `/v1/partner/ibm_sa_config` |
| GET | `/v1/partner/ibm_sa_ep` |
| POST | `/v1/password_profile` |
| DELETE | `/v1/password_profile/{name}` |
| GET | `/v1/response/options` |
| GET | `/v1/scan/asset` |
| GET | `/v1/scan/asset/images` |
| POST | `/v1/scan/asset/images` |
| DELETE | `/v1/scan/registry/{name}/test` |
| POST | `/v1/scan/registry/{name}/test` |
| POST | `/v1/scan/result/repository` |
| GET | `/v1/selfapikey` |
| GET | `/v1/selfuser` |
| PATCH | `/v1/server/{name}/group/{group}` |
| PATCH | `/v1/server/{name}/groups` |
| DELETE | `/v1/session` |
| GET | `/v1/session` |
| GET | `/v1/session/summary` |
| DELETE | `/v1/system/config/remote_repository/{nickname}` |
| PATCH | `/v1/system/config/remote_repository/{nickname}` |
| POST | `/v1/system/score/metrics` |
| GET | `/v1/system/usage` |
| GET | `/v1/token_auth_server` |
| GET | `/v1/token_auth_server/{server}` |
| POST | `/v1/token_auth_server/{server}` |
| GET | `/v1/token_auth_server/{server}/slo` |
| GET | `/v1/user_role_permission/options` |
| GET | `/v1/vulasset` |
| POST | `/v1/vulasset` |
| GET | `/v1/workload/{id}/file_profile` |
| GET | `/v1/workload/{id}/logs` |
| GET | `/v1/workload/{id}/process_profile` |
| POST | `/v2/scan/registry/{name}/test` |

**Total undocumented routes: 112**

