# Appendix C — NeuVector controller error taxonomy

Source: `controller/api/apis.go` (numeric constants) and `controller/rest/rest.go`
(`restErrMessage` table). The controller returns errors as a `RESTError` JSON body:

```json
{"code": 7, "error": "Object not found", "message": "Group not found"}
```

`code` is stable across releases (upstream comment: "Don't modify value or reorder").
The HTTP status is chosen per call site, so **branch on `code`, not on the status**.

| `code` | Constant | `error` string |
|---|---|---|
| 1 | `RESTErrNotFound` | URL not found |
| 2 | `RESTErrMethodNotAllowed` | Method not allowed |
| 3 | `RESTErrUnauthorized` | Authentication failed |
| 4 | `RESTErrOpNotAllowed` | Operation not allowed |
| 5 | `RESTErrTooManyLoginUser` | Too many login users |
| 6 | `RESTErrInvalidRequest` | Request in wrong format |
| 7 | `RESTErrObjectNotFound` | Object not found |
| 8 | `RESTErrFailWriteCluster` | Write to cluster failed |
| 9 | `RESTErrFailReadCluster` | Read from cluster failed |
| 10 | `RESTErrClusterWrongData` | Data read from cluster in wrong format |
| 11 | `RESTErrClusterTimeout` | Request to cluster timeout |
| 12 | `RESTErrNotEnoughFilter` | More search criteria required |
| 13 | `RESTErrDuplicateName` | Duplicate name |
| 14 | `RESTErrWeakPassword` | Password is weak |
| 15 | `RESTErrInvalidName` | Name in wrong format |
| 16 | `RESTErrObjectInuse` | Object in use |
| 17 | `RESTErrFailExport` | Failed to export |
| 18 | `RESTErrFailImport` | Failed to import |
| 19 | `RESTErrFailLockCluster` | Acquire cluster lock failed |
| 20 | `RESTErrLicenseFail` | Request not supported by license |
| 21 | `RESTErrAgentError` | Enforcer error |
| 22 | `RESTErrWorkloadNotRunning` | Container not running |
| 23 | `RESTErrCISBenchError` | CIS benchmark error |
| 24 | `RESTErrClusterRPCError` | Cluster RPC error |
| 25 | `RESTErrObjectAccessDenied` | Object access denied |
| 26 | `RESTErrFailRepoScan` | Fail to scan repository |
| 27 | `RESTErrFailRegistryScan` | Fail to scan registry |
| 28 | `RESTErrFailKubernetesApi` | Kubernetes API error |
| 29 | `RESTErrProxyError` | _(no message in table)_ |
| 30 | `RESTErrAdmCtrlUnSupported` | Admission control is not supported on non-Kubernetes environment |
| 31 | `RESTErrK8sNvRBAC` | Kubernetes RBAC settings required for NeuVector is not configured correctly |
| 32 | `RESTErrWebhookSvcForAdmCtrl` | The neuvector-svc-admission-webhook service required for NeuVector Admission Control is not configured correctly |
| 33 | `RESTErrNoUpdatePermission` | NeuVector controller doesn't have UPDATE permission for service resource |
| 34 | `RESTErrK8sApiSrvToWebhook` | Failed to receive a request from Kube-apiserver. Please try different client mode |
| 35 | `RESTErrNvPermission` | NeuVector controller is forbidden to get service details. Please check the clusterrole/clusterrolebinding required for NeuVector default service account |
| 36 | `RESTErrWebhookIsDisabled` | Configuring NeuVector Admission Control global settings is not allowed when admission control is disabled |
| 37 | `RESTErrRemoteUnauthorized` | Authentication to the remote cluster failed |
| 38 | `RESTErrRemoterRequestFail` | Request to the remote cluster failed |
| 39 | `RESTErrFedOperationFailed` | Federation operation failed |
| 40 | `RESTErrFedJointUnreachable` | Managed cluster is unreachable from primary cluster |
| 41 | `RESTErrFedDuplicateName` | Another cluster with the same name already exists in the federation |
| 42 | `RESTErrMasterUpgradeRequired` | Version of primary cluster is too old |
| 43 | `RESTErrJointUpgradeRequired` | Version of managed cluster is too old |
| 44 | `RESTErrIBMSATestFailed` | Failed to call IBM Security Advisor Findings endpoint |
| 45 | `RESTErrIBMSABadDashboardURL` | Invalid dashboard URL |
| 46 | `RESTErrReadOnlyRules` | Read-only rule(s) cannot be updated by current login user |
| 47 | `RESTErrUserLoginBlocked` | Temporarily blocked because of too many login failures |
| 48 | `RESTErrPasswordExpired` | Password expired |
| 49 | `RESTErrPromoteFail` | Failed to promote rules |
| 50 | `RESTErrPlatformAuthDisabled` | Platform authentication is disabled |
| 51 | `RESTErrRancherUnauthorized` | Rancher authentication failed |
| 52 | `RESTErrRemoteExportFail` | Failed to export to remote repository |
| 53 | `RESTErrInvalidQueryID` | Invalid or expired query id |
| 54 | `RESTErrPollJobNotFoundError` | Job not found in the Job Queue |
| 55 | `RESTErrServerError` | Server Error |
