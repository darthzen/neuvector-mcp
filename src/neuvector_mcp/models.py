"""Output models: narrow projections of NeuVector responses.

Rule: a tool NEVER returns the controller body verbatim. Controller objects carry
dozens of fields (a single ``RESTWorkload`` exceeds 40), and returning them all
burns the client's context for no benefit. Each tool declares a projection model
holding only the fields an operator or an agent reasons about, plus enough
identifiers to make a follow-up call.

Every model sets ``extra="ignore"`` so a controller upgrade that adds fields does
not break the server.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

_BASE = ConfigDict(extra="ignore", frozen=True)

PolicyMode = Literal["Discover", "Monitor", "Protect", ""]
Severity = Literal["Critical", "High", "Medium", "Low", "Info", ""]


class Page(BaseModel):
    """Paging envelope returned by every list tool."""

    model_config = _BASE

    start: int = Field(description="Zero-based offset of the first item returned.")
    returned: int = Field(description="Number of items in this page.")
    truncated: bool = Field(
        description="True when the controller had more items than were returned. "
        "Increase 'start' by 'returned' to fetch the next page."
    )
    hint: str | None = Field(
        default=None,
        description="Present when truncated: how to narrow or continue the query.",
    )


class WorkloadBrief(BaseModel):
    """One running container or pod."""

    model_config = _BASE

    id: str = Field(description="Workload id; pass to nv_get_workload.")
    name: str = Field(description="Container or pod name.")
    namespace: str = Field(default="", description="Kubernetes namespace.")
    service: str = Field(default="", description="NeuVector service (group) name.")
    image: str = Field(default="", description="Image reference as reported by the runtime.")
    state: str = Field(
        default="", description="exit | unmanaged | discover | monitor | protect | quarantined."
    )
    policy_mode: PolicyMode = Field(default="", description="Effective policy mode.")
    high_vuls: int = Field(default=0, description="High-severity vulnerability count.")
    med_vuls: int = Field(default=0, description="Medium-severity vulnerability count.")
    host_name: str = Field(default="", description="Node the workload runs on.")
    running: bool = Field(default=False, description="True when the container is running.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> WorkloadBrief:
        """Project a ``RESTWorkload``/``RESTWorkloadV2`` brief section."""
        brief = raw.get("workload_brief") or raw
        scan = brief.get("scan_summary") or {}
        return cls(
            id=str(brief.get("id", "")),
            name=str(brief.get("name", "")),
            namespace=str(brief.get("domain", "") or ""),
            service=str(brief.get("service", "") or ""),
            image=str(brief.get("image", "") or ""),
            state=str(brief.get("state", "") or ""),
            policy_mode=str(brief.get("policy_mode", "") or ""),  # type: ignore[arg-type]
            high_vuls=int(brief.get("high") or scan.get("high") or 0),
            med_vuls=int(brief.get("medium") or scan.get("medium") or 0),
            host_name=str(brief.get("host_name", "") or ""),
            running=bool(brief.get("running", False)),
        )


class WorkloadList(BaseModel):
    """Result of ``nv_list_workloads``."""

    model_config = _BASE

    page: Page
    workloads: list[WorkloadBrief]


class SystemSummary(BaseModel):
    """Result of ``nv_get_system_summary``."""

    model_config = _BASE

    hosts: int = Field(default=0, description="Nodes known to the cluster.")
    running_pods: int = Field(default=0, description="Running pods.")
    running_workloads: int = Field(default=0, description="Running containers.")
    services: int = Field(default=0, description="NeuVector services.")
    policy_rules: int = Field(default=0, description="Network policy rules.")
    enforcers: int = Field(default=0, description="Connected enforcers.")
    controllers: int = Field(default=0, description="Connected controllers.")
    domains: int = Field(default=0, description="Namespaces.")
    cvedb_version: str = Field(default="", description="Vulnerability database version.")
    platform: str = Field(default="", description="Detected platform, e.g. Kubernetes.")
    kube_version: str = Field(default="", description="Kubernetes version.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> SystemSummary:
        s = raw.get("summary") or raw
        return cls(
            hosts=int(s.get("hosts") or 0),
            running_pods=int(s.get("running_pods") or 0),
            running_workloads=int(s.get("running_workloads") or 0),
            services=int(s.get("services") or 0),
            policy_rules=int(s.get("policy_rules") or 0),
            enforcers=int(s.get("enforcers") or 0),
            controllers=int(s.get("controllers") or 0),
            domains=int(s.get("domains") or 0),
            cvedb_version=str(s.get("cvedb_version") or ""),
            platform=str(s.get("platform") or ""),
            kube_version=str(s.get("kube_version") or ""),
        )


class WriteOutcome(BaseModel):
    """The single return type of every mutating tool.

    Two states, distinguished by ``status``:

    * ``confirmation_required`` - nothing was sent to the controller. The caller
      must re-invoke the same tool with ``confirm=<confirm_token>``.
    * ``applied`` - the controller accepted the change.
    """

    model_config = ConfigDict(extra="ignore")

    status: Literal["confirmation_required", "applied"] = Field(
        description="'confirmation_required' means NOTHING changed yet."
    )
    operation: str = Field(description="Tool that produced this outcome.")
    target: str = Field(description="Object the operation acts on.")
    effect: str = Field(description="What will change, or what did change, in one sentence.")
    payload: dict[str, Any] = Field(
        default_factory=dict, description="Exact body that will be, or was, sent to the controller."
    )
    confirm_token: str | None = Field(
        default=None,
        description="Present only when status is confirmation_required. Echo it back as 'confirm'.",
    )
    next_step: str | None = Field(
        default=None, description="Present only when status is confirmation_required."
    )
    controller_response: dict[str, Any] = Field(
        default_factory=dict,
        description="Controller body on success; usually empty for PATCH and DELETE.",
    )


# --- appended by the phase build (models-fragments) ---


# ----- 00-helpers-events.py -----
EventKind = Literal["threat", "violation", "incident"]


def _clip(text: str, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to ``limit`` characters. Returns (text, was_truncated)."""
    if limit <= 0:
        return "", bool(text)
    if len(text) <= limit:
        return text, False
    return text[:limit], True


# ----- 00-helpers-vulnerability.py -----
#: Ranking used to sort and threshold vulnerability severities. Controller
#: ``severity`` strings are free-form (Appendix B declares no enum), so unknown
#: values rank 0 and normalise to "".
SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "": 0,
}


def normalise_severity(value: Any) -> Severity:
    """Map any controller severity string onto the ``Severity`` literal."""
    text = str(value or "").strip().lower()
    for canonical in ("Critical", "High", "Medium", "Low", "Info"):
        if text == canonical.lower():
            return canonical
    return ""


def severity_rank(value: Any) -> int:
    """Numeric rank of a controller severity string; unknown values rank 0."""
    return SEVERITY_RANK.get(str(value or "").strip().lower(), 0)


def count_by_level(items: list[dict[str, Any]]) -> dict[str, int]:
    """Count CIS/compliance check ``level`` values, e.g. {"PASS": 40, "WARN": 7}.

    ``level`` is a free-form string in Appendix B (``RESTBenchItem.level``); keys
    are the controller's own values, upper-cased, with "" for a missing level.
    """
    counts: dict[str, int] = {}
    for item in items:
        key = str(item.get("level", "") or "").upper()
        counts[key] = counts.get(key, 0) + 1
    return counts


# ----- 00-helpers-runtime_ops.py -----
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


def service_namespace(service_name: str) -> str:
    """Namespace of a NeuVector service name.

    NeuVector names a Kubernetes service group ``<service>.<namespace>`` (see
    ``RESTService.name`` and ``RESTService.domain`` in appendix B). Returns "" when
    the name carries no namespace suffix, e.g. a Docker-only service.
    """
    _, _, suffix = service_name.rpartition(".")
    return suffix if "." in service_name else ""


# ----- 00-helpers-system.py -----
#: Sentinel meaning "the current value could not be read".
_UNKNOWN = object()


def describe_change(path: str, old: Any, new: Any) -> str:
    """One clause of a change summary: "<path> <old> -> <new>".

    ``old`` is rendered ``?`` when the current value could not be read. Values are
    rendered with ``repr`` so an empty string is visibly empty. Never pass a
    credential to this function; secrets are summarised as a field name only.
    """
    return f"{path} {'?' if old is _UNKNOWN else old!r} -> {new!r}"


# ----- 10-inventory.py -----
class Identity(BaseModel):
    """Result of ``nv_whoami``: who this server is to the controller."""

    model_config = _BASE

    source: Literal["controller", "cached"] = Field(
        description="'controller' means GET /v1/selfuser answered; 'cached' means the "
        "identity established at startup is being reported instead."
    )
    auth_mode: str = Field(
        default="", description="How this server authenticates: apikey or password."
    )
    username: str = Field(default="", description="Login name or API access key.")
    fullname: str = Field(
        default="", description="Fully qualified user name including server prefix."
    )
    server: str = Field(default="", description="Authentication server; empty for local users.")
    email: str = Field(default="", description="Registered email address, when set.")
    role: str = Field(
        default="",
        description="Role on the global domain, e.g. admin, reader, ciops. Empty means "
        "namespace-scoped access only.",
    )
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Namespace-scoped roles: role name -> namespaces it applies to.",
    )
    global_permissions: list[str] = Field(
        default_factory=list,
        description="Permission ids on the global domain. ['unknown (api key)'] when the "
        "controller does not report them for API-key auth.",
    )
    last_login_at: str = Field(default="", description="RFC3339 timestamp of the last login.")
    note: str = Field(
        default="",
        description="Why 'source' is what it is. Read this before concluding anything about "
        "permissions from a cached answer.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> Identity:
        """Project the ``RESTUser`` object returned under 'user' by GET /v1/selfuser."""
        user = raw.get("user") or raw
        domains: dict[str, list[str]] = {}
        for role, values in (user.get("role_domains") or {}).items():
            domains[str(role)] = [str(v) for v in (values or [])]
        return cls(
            source="controller",
            auth_mode="",
            username=str(user.get("username", "") or ""),
            fullname=str(user.get("fullname", "") or ""),
            server=str(user.get("server", "") or ""),
            email=str(user.get("email", "") or ""),
            role=str(user.get("role", "") or ""),
            role_domains=domains,
            global_permissions=[
                str(p.get("id", "") or "")
                for p in (user.get("global_permissions") or raw.get("global_permissions") or [])
                if isinstance(p, dict)
            ],
            last_login_at=str(user.get("last_login_at", "") or ""),
            note="",
        )

    @classmethod
    def from_cached(cls, identity: dict[str, Any], *, note: str) -> Identity:
        """Build from the ``AppContext.identity`` dict produced by ``client.login()``."""
        return cls(
            source="cached",
            auth_mode=str(identity.get("mode", "") or ""),
            username=str(identity.get("username", "") or ""),
            global_permissions=[str(p) for p in (identity.get("global_permissions") or [])],
            note=note,
        )


class HostBrief(BaseModel):
    """One cluster node."""

    model_config = _BASE

    id: str = Field(description="Host id; pass to nv_get_bench_report and nv_get_scan_report.")
    name: str = Field(default="", description="Node name.")
    state: str = Field(default="", description="Node state as reported by the controller.")
    policy_mode: PolicyMode = Field(default="", description="Effective policy mode of the node.")
    platform: str = Field(default="", description="Platform, e.g. Kubernetes.")
    os: str = Field(default="", description="Operating system string.")
    kernel: str = Field(default="", description="Kernel version.")
    runtime: str = Field(default="", description="Container runtime, e.g. containerd.")
    cpus: int = Field(default=0, description="CPU count.")
    memory_bytes: int = Field(default=0, description="Physical memory in bytes.")
    containers: int = Field(default=0, description="Containers currently on this node.")
    high_vuls: int = Field(default=0, description="High-severity vulnerabilities in the host scan.")
    med_vuls: int = Field(
        default=0, description="Medium-severity vulnerabilities in the host scan."
    )
    scan_status: str = Field(
        default="", description="Host scan status, e.g. finished or unscanned."
    )
    cap_kube_bench: bool = Field(
        default=False,
        description="True when nv_get_bench_report(benchmark='kubernetes') is possible.",
    )
    cap_docker_bench: bool = Field(
        default=False, description="True when nv_get_bench_report(benchmark='docker') is possible."
    )
    kube_bench_status: str = Field(default="", description="Last Kubernetes CIS run status.")
    docker_bench_status: str = Field(default="", description="Last Docker CIS run status.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> HostBrief:
        """Project a ``RESTHost``."""
        scan = raw.get("scan_summary") or {}
        return cls(
            id=str(raw.get("id", "")),
            name=str(raw.get("name", "") or ""),
            state=str(raw.get("state", "") or ""),
            policy_mode=str(raw.get("policy_mode", "") or ""),  # type: ignore[arg-type]
            platform=str(raw.get("platform", "") or ""),
            os=str(raw.get("os", "") or ""),
            kernel=str(raw.get("kernel", "") or ""),
            runtime=str(raw.get("runtime", "") or ""),
            cpus=int(raw.get("cpus") or 0),
            memory_bytes=int(raw.get("memory") or 0),
            containers=int(raw.get("containers") or 0),
            high_vuls=int(scan.get("high") or 0),
            med_vuls=int(scan.get("medium") or 0),
            scan_status=str(scan.get("status", "") or ""),
            cap_kube_bench=bool(raw.get("cap_kube_bench", False)),
            cap_docker_bench=bool(raw.get("cap_docker_bench", False)),
            kube_bench_status=str(raw.get("kube_bench_status", "") or ""),
            docker_bench_status=str(raw.get("docker_bench_status", "") or ""),
        )


class HostList(BaseModel):
    """Result of ``nv_list_hosts``."""

    model_config = _BASE

    page: Page
    hosts: list[HostBrief]


class GroupBrief(BaseModel):
    """One security group."""

    model_config = _BASE

    name: str = Field(description="Group name; pass to nv_get_group.")
    namespace: str = Field(
        default="", description="Kubernetes namespace (controller field 'domain')."
    )
    policy_mode: PolicyMode = Field(default="", description="Policy mode applied to members.")
    kind: str = Field(default="", description="Group kind, e.g. container, node or address.")
    learned: bool = Field(
        default=False, description="True when NeuVector created this group itself."
    )
    reserved: bool = Field(
        default=False, description="True for built-in groups that cannot be deleted."
    )
    platform_role: str = Field(default="", description="Platform role, e.g. system, when set.")
    member_count: int = Field(default=0, description="Number of workloads currently in the group.")
    policy_rule_count: int = Field(default=0, description="Network rules referencing this group.")
    response_rule_count: int = Field(
        default=0, description="Response rules referencing this group."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> GroupBrief:
        """Project a ``RESTGroup``."""
        return cls(
            name=str(raw.get("name", "")),
            namespace=str(raw.get("domain", "") or ""),
            policy_mode=str(raw.get("policy_mode", "") or ""),  # type: ignore[arg-type]
            kind=str(raw.get("kind", "") or ""),
            learned=bool(raw.get("learned", False)),
            reserved=bool(raw.get("reserved", False)),
            platform_role=str(raw.get("platform_role", "") or ""),
            member_count=len(raw.get("members") or []),
            policy_rule_count=len(raw.get("policy_rules") or []),
            response_rule_count=len(raw.get("response_rules") or []),
        )


class GroupList(BaseModel):
    """Result of ``nv_list_groups``."""

    model_config = _BASE

    page: Page
    groups: list[GroupBrief]


class GroupCriterion(BaseModel):
    """One membership criterion of a group."""

    model_config = _BASE

    key: str = Field(default="", description="Attribute matched, e.g. domain, image or label.")
    value: str = Field(default="", description="Value the attribute is compared with.")
    op: str = Field(default="", description="Comparison operator, e.g. = or contains.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> GroupCriterion:
        """Project a ``RESTCriteriaEntry``."""
        return cls(
            key=str(raw.get("key", "") or ""),
            value=str(raw.get("value", "") or ""),
            op=str(raw.get("op", "") or ""),
        )


class GroupDetail(BaseModel):
    """Result of ``nv_get_group``."""

    model_config = _BASE

    name: str = Field(description="Group name.")
    namespace: str = Field(
        default="", description="Kubernetes namespace (controller field 'domain')."
    )
    policy_mode: PolicyMode = Field(default="", description="Policy mode applied to members.")
    kind: str = Field(default="", description="Group kind, e.g. container, node or address.")
    learned: bool = Field(
        default=False, description="True when NeuVector created this group itself."
    )
    reserved: bool = Field(
        default=False, description="True for built-in groups that cannot be modified."
    )
    cfg_type: str = Field(
        default="",
        description="learned | user_created | ground | federal. 'ground' groups come from CRDs and "
        "are overwritten by the CRD controller.",
    )
    platform_role: str = Field(default="", description="Platform role, e.g. system, when set.")
    cap_change_mode: bool = Field(
        default=False, description="True when this group's policy mode may be changed."
    )
    criteria: list[GroupCriterion] = Field(
        default_factory=list,
        description="Membership criteria; all must match for a workload to join.",
    )
    member_count: int = Field(default=0, description="True number of members, before max_members.")
    members: list[WorkloadBrief] = Field(
        default_factory=list, description="Member workloads, capped by max_members."
    )
    policy_rule_ids: list[int] = Field(
        default_factory=list, description="Network rule ids referencing this group."
    )
    response_rule_ids: list[int] = Field(
        default_factory=list, description="Response rule ids referencing this group."
    )
    page: Page

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_members: int = 20) -> GroupDetail:
        """Project a ``RESTGroupDetail``, capping the member list."""
        members = list(raw.get("members") or [])
        shown = members[:max_members]
        return cls(
            name=str(raw.get("name", "")),
            namespace=str(raw.get("domain", "") or ""),
            policy_mode=str(raw.get("policy_mode", "") or ""),  # type: ignore[arg-type]
            kind=str(raw.get("kind", "") or ""),
            learned=bool(raw.get("learned", False)),
            reserved=bool(raw.get("reserved", False)),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            platform_role=str(raw.get("platform_role", "") or ""),
            cap_change_mode=bool(raw.get("cap_change_mode", False)),
            criteria=[GroupCriterion.from_api(c) for c in (raw.get("criteria") or [])],
            member_count=len(members),
            members=[WorkloadBrief.from_api(m) for m in shown],
            policy_rule_ids=[
                int(r.get("id") or 0)
                for r in (raw.get("policy_rules") or [])
                if isinstance(r, dict)
            ],
            response_rule_ids=[
                int(r.get("id") or 0)
                for r in (raw.get("response_rules") or [])
                if isinstance(r, dict)
            ],
            page=Page(
                start=0,
                returned=len(shown),
                truncated=len(members) > len(shown),
                hint=(
                    f"{len(members)} members exist; {len(shown)} shown. Raise max_members, or use "
                    "nv_list_workloads with a namespace filter."
                    if len(members) > len(shown)
                    else None
                ),
            ),
        )


class ServiceBrief(BaseModel):
    """One NeuVector service."""

    model_config = _BASE

    name: str = Field(description="Service name; pass to nv_set_service_mode.")
    namespace: str = Field(
        default="", description="Kubernetes namespace (controller field 'domain')."
    )
    policy_mode: PolicyMode = Field(default="", description="Network policy mode.")
    profile_mode: PolicyMode = Field(default="", description="Process and file profile mode.")
    platform_role: str = Field(default="", description="Platform role, e.g. system, when set.")
    baseline_profile: str = Field(default="", description="Process baseline: basic or zero-drift.")
    member_count: int = Field(default=0, description="Workloads in this service.")
    policy_rule_count: int = Field(default=0, description="Network rules bound to this service.")
    ingress_exposure: bool = Field(
        default=False, description="True when something outside the cluster can reach this service."
    )
    egress_exposure: bool = Field(
        default=False, description="True when this service reaches outside the cluster."
    )
    not_scored: bool = Field(
        default=False, description="True when this service is excluded from the security score."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ServiceBrief:
        """Project a ``RESTService``."""
        return cls(
            name=str(raw.get("name", "")),
            namespace=str(raw.get("domain", "") or ""),
            policy_mode=str(raw.get("policy_mode", "") or ""),  # type: ignore[arg-type]
            profile_mode=str(raw.get("profile_mode", "") or ""),  # type: ignore[arg-type]
            platform_role=str(raw.get("platform_role", "") or ""),
            baseline_profile=str(raw.get("baseline_profile", "") or ""),
            member_count=len(raw.get("members") or []),
            policy_rule_count=len(raw.get("policy_rules") or []),
            ingress_exposure=bool(raw.get("ingress_exposure", False)),
            egress_exposure=bool(raw.get("egress_exposure", False)),
            not_scored=bool(raw.get("not_scored", False)),
        )


class ServiceList(BaseModel):
    """Result of ``nv_list_services``."""

    model_config = _BASE

    page: Page
    services: list[ServiceBrief]


class EnforcerBrief(BaseModel):
    """One enforcer instance."""

    model_config = _BASE

    id: str = Field(description="Enforcer id.")
    name: str = Field(default="", description="Enforcer container name.")
    display_name: str = Field(default="", description="Name shown in the NeuVector console.")
    host_name: str = Field(default="", description="Node this enforcer runs on.")
    host_id: str = Field(default="", description="Host id of that node.")
    version: str = Field(default="", description="Enforcer build version.")
    namespace: str = Field(
        default="", description="Namespace of the enforcer pod (controller field 'domain')."
    )
    cluster_ip: str = Field(default="", description="Address the controller reaches it on.")
    connection_state: str = Field(
        default="",
        description="connected | disconnected. Anything but connected means no enforcement.",
    )
    joined_at: str = Field(default="", description="When this enforcer joined the cluster.")
    disconnected_at: str = Field(
        default="", description="When it last disconnected, when applicable."
    )
    cpus: str = Field(default="", description="CPU allocation as the controller reports it.")
    memory_limit: int = Field(default=0, description="Memory limit in bytes; 0 means unlimited.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> EnforcerBrief:
        """Project a ``RESTAgent``."""
        return cls(
            id=str(raw.get("id", "")),
            name=str(raw.get("name", "") or ""),
            display_name=str(raw.get("display_name", "") or ""),
            host_name=str(raw.get("host_name", "") or ""),
            host_id=str(raw.get("host_id", "") or ""),
            version=str(raw.get("version", "") or ""),
            namespace=str(raw.get("domain", "") or ""),
            cluster_ip=str(raw.get("cluster_ip", "") or ""),
            connection_state=str(raw.get("connection_state", "") or ""),
            joined_at=str(raw.get("joined_at", "") or ""),
            disconnected_at=str(raw.get("disconnected_at", "") or ""),
            cpus=str(raw.get("cpus", "") or ""),
            memory_limit=int(raw.get("memory_limit") or 0),
        )


class EnforcerList(BaseModel):
    """Result of ``nv_list_enforcers``."""

    model_config = _BASE

    page: Page
    enforcers: list[EnforcerBrief]


class NamespaceBrief(BaseModel):
    """One Kubernetes namespace, as the controller sees it."""

    model_config = _BASE

    name: str = Field(description="Namespace name; pass as 'namespace' to other tools.")
    workloads: int = Field(
        default=0, description="Containers known in this namespace, running or not."
    )
    running_workloads: int = Field(default=0, description="Running containers.")
    running_pods: int = Field(default=0, description="Running pods.")
    services: int = Field(default=0, description="NeuVector services in this namespace.")
    tags: list[str] = Field(
        default_factory=list,
        description="Compliance standards tagged on this namespace, e.g. PCI or GDPR.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> NamespaceBrief:
        """Project a ``RESTDomain``."""
        return cls(
            name=str(raw.get("name", "")),
            workloads=int(raw.get("workloads") or 0),
            running_workloads=int(raw.get("running_workloads") or 0),
            running_pods=int(raw.get("running_pods") or 0),
            services=int(raw.get("services") or 0),
            tags=[str(t) for t in (raw.get("tags") or [])],
        )


class NamespaceList(BaseModel):
    """Result of ``nv_list_namespaces``."""

    model_config = _BASE

    page: Page
    namespaces: list[NamespaceBrief]


class Conversation(BaseModel):
    """One observed group-to-group conversation. Best-effort projection."""

    model_config = _BASE

    from_group: str = Field(default="", description="Source group name.")
    to_group: str = Field(default="", description="Destination group name.")
    bytes: int = Field(default=0, description="Bytes observed on this pair.")
    sessions: int = Field(default=0, description="Sessions observed on this pair.")
    policy_action: str = Field(
        default="",
        description="What policy did or would do: allow, deny, violate or open. 'violate' means a "
        "Protect-mode group would have dropped this traffic.",
    )
    applications: list[str] = Field(
        default_factory=list, description="Application protocols detected, e.g. HTTP or Redis."
    )
    ports: list[str] = Field(default_factory=list, description="Ports observed, as reported.")
    severity: str = Field(default="", description="Severity the controller assigned, when any.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> Conversation:
        """Best-effort projection: GET /v1/conversation has no Appendix B schema.

        Every key is read with a default, so an unexpected controller shape yields
        empty fields instead of a validation error.
        """
        return cls(
            from_group=str(raw.get("from", "") or ""),
            to_group=str(raw.get("to", "") or ""),
            bytes=int(raw.get("bytes") or 0),
            sessions=int(raw.get("sessions") or 0),
            policy_action=str(raw.get("policy_action", "") or ""),
            applications=[str(a) for a in (raw.get("applications") or [])],
            ports=[str(p) for p in (raw.get("ports") or [])],
            severity=str(raw.get("severity", "") or ""),
        )


class ConversationList(BaseModel):
    """Result of ``nv_get_network_conversations``."""

    model_config = _BASE

    page: Page
    conversations: list[Conversation]


# ----- 20-vulnerability.py -----
class ImageScanSummary(BaseModel):
    """Scan summary for one image."""

    model_config = _BASE

    image: str = Field(description="Image reference as the controller recorded it.")
    image_id: str = Field(
        default="", description="Image id; pass to nv_get_scan_report with target='image'."
    )
    status: str = Field(
        default="", description="Scan status, e.g. finished, scanning or unscanned."
    )
    result: str = Field(default="", description="Scanner result string; non-empty on failure.")
    high_vuls: int = Field(default=0, description="High-severity vulnerability count.")
    med_vuls: int = Field(default=0, description="Medium-severity vulnerability count.")
    base_os: str = Field(default="", description="Base OS the scanner detected.")
    author: str = Field(default="", description="Image author, when the image records one.")
    scanned_at: str = Field(default="", description="When this image was last scanned.")
    scanner_version: str = Field(default="", description="Scanner build that produced the result.")
    cvedb_create_time: str = Field(
        default="",
        description="Vulnerability database timestamp used; old means the result is stale.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ImageScanSummary:
        """Project a ``RESTScanImageSummary``."""
        return cls(
            image=str(raw.get("image", "") or ""),
            image_id=str(raw.get("image_id", "") or ""),
            status=str(raw.get("status", "") or ""),
            result=str(raw.get("result", "") or ""),
            high_vuls=int(raw.get("high") or 0),
            med_vuls=int(raw.get("medium") or 0),
            base_os=str(raw.get("base_os", "") or ""),
            author=str(raw.get("author", "") or ""),
            scanned_at=str(raw.get("scanned_at", "") or ""),
            scanner_version=str(raw.get("scanner_version", "") or ""),
            cvedb_create_time=str(raw.get("cvedb_create_time", "") or ""),
        )


class ImageScanSummaryList(BaseModel):
    """Result of ``nv_list_image_scan_summaries``."""

    model_config = _BASE

    page: Page
    images: list[ImageScanSummary]


class VulnerabilityFinding(BaseModel):
    """One CVE in a scan report."""

    model_config = _BASE

    name: str = Field(description="CVE id, e.g. CVE-2026-1234.")
    severity: Severity = Field(
        default="", description="Severity as the vulnerability feed rates it."
    )
    score: float = Field(default=0.0, description="CVSS v2 base score.")
    score_v3: float = Field(default=0.0, description="CVSS v3 base score; prefer this one.")
    package_name: str = Field(default="", description="Affected package.")
    package_version: str = Field(default="", description="Installed version.")
    fixed_version: str = Field(
        default="", description="Version that fixes it; empty means no fix is available yet."
    )
    feed_rating: str = Field(
        default="", description="Rating from the vendor feed, when it differs."
    )
    in_base_image: bool = Field(
        default=False,
        description="True when the package came from the base image, so the fix belongs to whoever "
        "owns the base image.",
    )
    link: str = Field(default="", description="Advisory URL.")
    published_timestamp: int = Field(default=0, description="Unix time the CVE was published.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> VulnerabilityFinding:
        """Project a ``RESTVulnerability``, dropping 'description' and CVSS vectors."""
        return cls(
            name=str(raw.get("name", "") or ""),
            severity=normalise_severity(raw.get("severity")),
            score=float(raw.get("score") or 0.0),
            score_v3=float(raw.get("score_v3") or 0.0),
            package_name=str(raw.get("package_name", "") or ""),
            package_version=str(raw.get("package_version", "") or ""),
            fixed_version=str(raw.get("fixed_version", "") or ""),
            feed_rating=str(raw.get("feed_rating", "") or ""),
            in_base_image=bool(raw.get("in_base_image", False)),
            link=str(raw.get("link", "") or ""),
            published_timestamp=int(raw.get("published_timestamp") or 0),
        )


class SeverityCounts(BaseModel):
    """Vulnerability counts by severity for a whole report."""

    model_config = _BASE

    critical: int = Field(default=0, description="Critical-severity vulnerabilities.")
    high: int = Field(default=0, description="High-severity vulnerabilities.")
    medium: int = Field(default=0, description="Medium-severity vulnerabilities.")
    low: int = Field(default=0, description="Low-severity vulnerabilities.")
    unrated: int = Field(default=0, description="Vulnerabilities the feed did not rate.")
    total: int = Field(default=0, description="All vulnerabilities in the report.")
    fixable: int = Field(
        default=0,
        description="Vulnerabilities with a fixed version available; the actionable subset.",
    )

    @classmethod
    def from_api(cls, vulnerabilities: list[dict[str, Any]]) -> SeverityCounts:
        """Count a raw ``RESTVulnerability`` array. The controller returns no totals."""
        buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "": 0}
        fixable = 0
        for vuln in vulnerabilities:
            key = normalise_severity(vuln.get("severity"))
            buckets[key if key in buckets else ""] += 1
            if str(vuln.get("fixed_version", "") or ""):
                fixable += 1
        return cls(
            critical=buckets["Critical"],
            high=buckets["High"],
            medium=buckets["Medium"],
            low=buckets["Low"],
            unrated=buckets[""],
            total=len(vulnerabilities),
            fixable=fixable,
        )


class ScanReport(BaseModel):
    """Result of ``nv_get_scan_report``."""

    model_config = _BASE

    target: Literal["image", "workload", "host", "registry_image"] = Field(
        description="What this report is about."
    )
    target_id: str = Field(description="Id that was requested.")
    registry: str = Field(
        default="", description="Registry name; empty unless target='registry_image'."
    )
    counts: SeverityCounts = Field(
        description="Counts over the WHOLE report, before any filtering."
    )
    matched: int = Field(
        default=0, description="Vulnerabilities left after min_severity and fixable_only."
    )
    check_count: int = Field(default=0, description="Compliance checks embedded in this report.")
    module_count: int = Field(default=0, description="Software modules the scanner inventoried.")
    secret_count: int = Field(default=0, description="Secrets the scanner found in the filesystem.")
    setid_perm_count: int = Field(
        default=0, description="setuid/setgid binaries the scanner found."
    )
    page: Page
    vulnerabilities: list[VulnerabilityFinding] = Field(
        default_factory=list,
        description="Worst-first, filtered and capped. Empty when summary_only.",
    )

    @classmethod
    def from_api(
        cls,
        raw: dict[str, Any],
        *,
        target: str,
        target_id: str,
        registry: str = "",
        summary_only: bool = False,
        min_severity: str | None = None,
        fixable_only: bool = False,
        max_vulnerabilities: int = 50,
    ) -> ScanReport:
        """Project a ``RESTScanReport``: count everything, then filter, sort and cap."""
        all_vulns = [v for v in (raw.get("vulnerabilities") or []) if isinstance(v, dict)]
        counts = SeverityCounts.from_api(all_vulns)

        floor = severity_rank(min_severity) if min_severity else -1
        selected = [
            v
            for v in all_vulns
            if severity_rank(v.get("severity")) >= floor
            and (not fixable_only or str(v.get("fixed_version", "") or ""))
        ]
        selected.sort(
            key=lambda v: (
                -severity_rank(v.get("severity")),
                -float(v.get("score_v3") or 0.0),
                -float(v.get("score") or 0.0),
                str(v.get("name", "") or ""),
            )
        )
        shown = [] if summary_only else selected[:max_vulnerabilities]
        truncated = len(selected) > len(shown)
        return cls(
            target=target,  # type: ignore[arg-type]
            target_id=target_id,
            registry=registry,
            counts=counts,
            matched=len(selected),
            check_count=len(raw.get("checks") or []),
            module_count=len(raw.get("modules") or []),
            secret_count=len(raw.get("secrets") or []),
            setid_perm_count=len(raw.get("setid_perms") or []),
            page=Page(
                start=0,
                returned=len(shown),
                truncated=truncated,
                hint=(
                    (
                        f"{len(selected)} vulnerabilities matched; {len(shown)} returned. "
                        "Raise max_severity coverage with min_severity, set fixable_only=true, "
                        "or raise max_vulnerabilities."
                    )
                    if truncated
                    else None
                ),
            ),
            vulnerabilities=[VulnerabilityFinding.from_api(v) for v in shown],
        )


class ScanStatus(BaseModel):
    """Result of ``nv_get_scan_status``."""

    model_config = _BASE

    scanned: int = Field(default=0, description="Assets scanned successfully.")
    scheduled: int = Field(default=0, description="Assets queued for scanning.")
    scanning: int = Field(default=0, description="Assets being scanned right now.")
    failed: int = Field(default=0, description="Assets whose scan failed; these have no data.")
    cvedb_version: str = Field(default="", description="Vulnerability database version.")
    cvedb_create_time: str = Field(
        default="", description="When that database was built. Old means every count is stale."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ScanStatus:
        """Project a ``RESTScanStatus``, accepting the wrapped or unwrapped body."""
        s = raw.get("status") or raw
        return cls(
            scanned=int(s.get("scanned") or 0),
            scheduled=int(s.get("scheduled") or 0),
            scanning=int(s.get("scanning") or 0),
            failed=int(s.get("failed") or 0),
            cvedb_version=str(s.get("cvedb_version", "") or ""),
            cvedb_create_time=str(s.get("cvedb_create_time", "") or ""),
        )


class ScannerBrief(BaseModel):
    """One scanner instance. Best-effort projection."""

    model_config = _BASE

    id: str = Field(default="", description="Scanner id.")
    cvedb_version: str = Field(default="", description="Vulnerability database version it carries.")
    cvedb_create_time: str = Field(default="", description="When that database was built.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ScannerBrief:
        """Best-effort projection: ``RESTScannerData`` has no Appendix B entry.

        Only keys whose names are corroborated elsewhere in Appendix B are read
        (``cvedb_version`` and ``cvedb_create_time`` from ``RESTScanStatus``), each
        with a default, so an unexpected shape yields empty fields, never an error.
        """
        return cls(
            id=str(raw.get("id", "") or ""),
            cvedb_version=str(raw.get("cvedb_version", "") or ""),
            cvedb_create_time=str(raw.get("cvedb_create_time", "") or ""),
        )


class ScannerList(BaseModel):
    """Result of ``nv_list_scanners``."""

    model_config = _BASE

    page: Page
    scanners: list[ScannerBrief]


class RegistrySummary(BaseModel):
    """One configured registry. Credential fields are deliberately absent."""

    model_config = _BASE

    name: str = Field(description="Registry name; pass to nv_list_registry_images.")
    registry_type: str = Field(
        default="", description="Registry type, e.g. Docker Registry or Amazon ECR."
    )
    registry: str = Field(default="", description="Registry URL.")
    username: str = Field(
        default="", description="Configured username; empty for anonymous access."
    )
    filters: list[str] = Field(
        default_factory=list, description="Repository/tag patterns this registry scans."
    )
    status: str = Field(default="", description="Scan status, e.g. idle or scanning.")
    error_message: str = Field(
        default="", description="Non-empty when the last scan failed; its images have no data."
    )
    scanned: int = Field(default=0, description="Images scanned successfully.")
    scheduled: int = Field(default=0, description="Images queued.")
    scanning: int = Field(default=0, description="Images being scanned now.")
    failed: int = Field(default=0, description="Images whose scan failed.")
    scan_layers: bool = Field(default=False, description="True when per-layer scanning is enabled.")
    rescan_after_db_update: bool = Field(
        default=False, description="True when images are rescanned after a database update."
    )
    repo_limit: int = Field(
        default=0, description="Maximum repositories scanned; 0 means no limit."
    )
    tag_limit: int = Field(default=0, description="Maximum tags per repository; 0 means no limit.")
    started_at: str = Field(default="", description="When the current or last scan started.")
    cvedb_version: str = Field(default="", description="Vulnerability database version used.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> RegistrySummary:
        """Project a ``RESTRegistrySummary``, dropping every credential field."""
        return cls(
            name=str(raw.get("name", "")),
            registry_type=str(raw.get("registry_type", "") or ""),
            registry=str(raw.get("registry", "") or ""),
            username=str(raw.get("username", "") or ""),
            filters=[str(f) for f in (raw.get("filters") or [])],
            status=str(raw.get("status", "") or ""),
            error_message=str(raw.get("error_message", "") or ""),
            scanned=int(raw.get("scanned") or 0),
            scheduled=int(raw.get("scheduled") or 0),
            scanning=int(raw.get("scanning") or 0),
            failed=int(raw.get("failed") or 0),
            scan_layers=bool(raw.get("scan_layers", False)),
            rescan_after_db_update=bool(raw.get("rescan_after_db_update", False)),
            repo_limit=int(raw.get("repo_limit") or 0),
            tag_limit=int(raw.get("tag_limit") or 0),
            started_at=str(raw.get("started_at", "") or ""),
            cvedb_version=str(raw.get("cvedb_version", "") or ""),
        )


class RegistryList(BaseModel):
    """Result of ``nv_list_registries``."""

    model_config = _BASE

    page: Page
    registries: list[RegistrySummary]


class RegistryImageSummary(BaseModel):
    """One image in a registry."""

    model_config = _BASE

    repository: str = Field(description="Repository path within the registry.")
    tag: str = Field(default="", description="Image tag.")
    image_id: str = Field(
        default="",
        description="Image id; pass to nv_get_scan_report with target='registry_image'.",
    )
    digest: str = Field(default="", description="Image digest.")
    namespace: str = Field(
        default="", description="Registry namespace or project (controller field 'domain')."
    )
    status: str = Field(default="", description="Scan status, e.g. finished.")
    result: str = Field(default="", description="Scanner result string; non-empty on failure.")
    high_vuls: int = Field(default=0, description="High-severity vulnerability count.")
    med_vuls: int = Field(default=0, description="Medium-severity vulnerability count.")
    base_os: str = Field(default="", description="Base OS the scanner detected.")
    size_bytes: int = Field(default=0, description="Image size in bytes.")
    run_as_root: bool = Field(
        default=False, description="True when the image's default user is root."
    )
    scanned_at: str = Field(default="", description="When this image was last scanned.")
    created_at: str = Field(default="", description="When the image was built.")
    scanner_version: str = Field(default="", description="Scanner build that produced the result.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> RegistryImageSummary:
        """Project a ``RESTRegistryImageSummary``."""
        return cls(
            repository=str(raw.get("repository", "") or ""),
            tag=str(raw.get("tag", "") or ""),
            image_id=str(raw.get("image_id", "") or ""),
            digest=str(raw.get("digest", "") or ""),
            namespace=str(raw.get("domain", "") or ""),
            status=str(raw.get("status", "") or ""),
            result=str(raw.get("result", "") or ""),
            high_vuls=int(raw.get("high") or 0),
            med_vuls=int(raw.get("medium") or 0),
            base_os=str(raw.get("base_os", "") or ""),
            size_bytes=int(raw.get("size") or 0),
            run_as_root=bool(raw.get("run_as_root", False)),
            scanned_at=str(raw.get("scanned_at", "") or ""),
            created_at=str(raw.get("created_at", "") or ""),
            scanner_version=str(raw.get("scanner_version", "") or ""),
        )


class RegistryImageList(BaseModel):
    """Result of ``nv_list_registry_images``."""

    model_config = _BASE

    page: Page
    registry: str = Field(description="Registry these images came from.")
    images: list[RegistryImageSummary]


class VulnerabilityProfileEntry(BaseModel):
    """One vulnerability exception."""

    model_config = _BASE

    id: int = Field(default=0, description="Entry id, unique within the profile.")
    name: str = Field(default="", description="CVE id this entry suppresses, or 'any'.")
    comment: str = Field(default="", description="Why the exception exists.")
    days: int = Field(
        default=0,
        description="Grace period in days for a CVE with no fix available. 0 means the exception "
        "always applies.",
    )
    namespaces: list[str] = Field(
        default_factory=list,
        description="Namespaces the exception is limited to (controller field 'domains'); empty means "
        "cluster-wide.",
    )
    images: list[str] = Field(
        default_factory=list,
        description="Image patterns the exception is limited to; empty means every image.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> VulnerabilityProfileEntry:
        """Project a ``RESTVulnerabilityProfileEntry``."""
        return cls(
            id=int(raw.get("id") or 0),
            name=str(raw.get("name", "") or ""),
            comment=str(raw.get("comment", "") or ""),
            days=int(raw.get("days") or 0),
            namespaces=[str(d) for d in (raw.get("domains") or [])],
            images=[str(i) for i in (raw.get("images") or [])],
        )


class VulnerabilityProfile(BaseModel):
    """Result of ``nv_get_vulnerability_profile``."""

    model_config = _BASE

    name: str = Field(description="Profile name.")
    cfg_type: str = Field(
        default="",
        description="user_created | ground. 'ground' profiles come from a CRD and are overwritten by "
        "the CRD controller.",
    )
    entry_count: int = Field(default=0, description="True number of entries, before max_entries.")
    page: Page
    entries: list[VulnerabilityProfileEntry] = Field(
        default_factory=list, description="Exception entries, capped by max_entries."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_entries: int = 100) -> VulnerabilityProfile:
        """Project a ``RESTVulnerabilityProfile``, capping the entry list."""
        entries = [e for e in (raw.get("entries") or []) if isinstance(e, dict)]
        shown = entries[:max_entries]
        return cls(
            name=str(raw.get("name", "")),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            entry_count=len(entries),
            page=Page(
                start=0,
                returned=len(shown),
                truncated=len(entries) > len(shown),
                hint=(
                    f"{len(entries)} entries exist; {len(shown)} shown. Raise max_entries."
                    if len(entries) > len(shown)
                    else None
                ),
            ),
            entries=[VulnerabilityProfileEntry.from_api(e) for e in shown],
        )


# ----- 30-compliance.py -----
class ComplianceCheck(BaseModel):
    """One CIS or compliance check result."""

    model_config = _BASE

    test_number: str = Field(description="Check id, e.g. K.1.2.3 or D.5.4.")
    level: str = Field(
        default="", description="Outcome as the controller words it, e.g. PASS, WARN, INFO or NOTE."
    )
    catalog: str = Field(
        default="", description="Catalogue this check belongs to, e.g. kubernetes or docker."
    )
    type: str = Field(
        default="", description="What the check applies to, e.g. host, container or image."
    )
    profile: str = Field(default="", description="CIS profile, e.g. Level 1 or Level 2.")
    scored: bool = Field(
        default=False, description="True when the check counts toward the CIS score."
    )
    automated: bool = Field(
        default=False, description="False means the check needs a human to verify it."
    )
    description: str = Field(default="", description="What the check tests.")
    message: list[str] = Field(
        default_factory=list, description="Evidence the enforcer collected, one line per entry."
    )
    remediation: str = Field(default="", description="How to fix it, from the CIS benchmark text.")
    group: str = Field(
        default="", description="Group this check was reported for, when applicable."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ComplianceCheck:
        """Project a ``RESTBenchItem``."""
        return cls(
            test_number=str(raw.get("test_number", "") or ""),
            level=str(raw.get("level", "") or ""),
            catalog=str(raw.get("catalog", "") or ""),
            type=str(raw.get("type", "") or ""),
            profile=str(raw.get("profile", "") or ""),
            scored=bool(raw.get("scored", False)),
            automated=bool(raw.get("automated", False)),
            description=str(raw.get("description", "") or ""),
            message=[str(m) for m in (raw.get("message") or [])],
            remediation=str(raw.get("remediation", "") or ""),
            group=str(raw.get("group", "") or ""),
        )


class ComplianceFindings(BaseModel):
    """Result of ``nv_get_compliance_findings``."""

    model_config = _BASE

    scope: Literal["workload", "host"] = Field(description="What target_id referred to.")
    target_id: str = Field(description="Id that was requested.")
    run_at: str = Field(default="", description="When these checks were last run.")
    run_timestamp: int = Field(default=0, description="Unix time of that run.")
    kubernetes_cis_version: str = Field(
        default="", description="Kubernetes CIS benchmark version used."
    )
    kubernetes_cis_category: str = Field(
        default="", description="Node category tested, e.g. master or worker."
    )
    docker_cis_version: str = Field(default="", description="Docker CIS benchmark version used.")
    level_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Checks per level over the WHOLE report, before filtering, e.g. "
        "{'PASS': 40, 'WARN': 7}.",
    )
    matched: int = Field(default=0, description="Checks left after level and catalog filtering.")
    page: Page = Field(description="Client-side cap envelope; start is always 0.")
    checks: list[ComplianceCheck] = Field(
        default_factory=list, description="Filtered checks, capped by max_checks."
    )

    @classmethod
    def from_api(
        cls,
        raw: dict[str, Any],
        *,
        scope: str,
        target_id: str,
        level: str | None = None,
        catalog: str | None = None,
        max_checks: int = 50,
    ) -> ComplianceFindings:
        """Project a ``RESTComplianceData``: count everything, then filter and cap."""
        body = raw.get("report") or raw
        items = [i for i in (body.get("items") or []) if isinstance(i, dict)]
        selected = [
            i
            for i in items
            if (level is None or str(i.get("level", "") or "").upper() == level.upper())
            and (catalog is None or str(i.get("catalog", "") or "").lower() == catalog.lower())
        ]
        shown = selected[:max_checks]
        return cls(
            scope=scope,  # type: ignore[arg-type]
            target_id=target_id,
            run_at=str(body.get("run_at", "") or ""),
            run_timestamp=int(body.get("run_timestamp") or 0),
            kubernetes_cis_version=str(body.get("kubernetes_cis_version", "") or ""),
            kubernetes_cis_category=str(body.get("kubernetes_cis_category", "") or ""),
            docker_cis_version=str(body.get("docker_cis_version", "") or ""),
            level_counts=count_by_level(items),
            matched=len(selected),
            page=Page(
                start=0,
                returned=len(shown),
                truncated=len(selected) > len(shown),
                hint=(
                    f"{len(selected)} checks matched; {len(shown)} returned. Filter with "
                    "level or catalog, or raise max_checks."
                    if len(selected) > len(shown)
                    else None
                ),
            ),
            checks=[ComplianceCheck.from_api(i) for i in shown],
        )


class BenchReport(BaseModel):
    """Result of ``nv_get_bench_report``."""

    model_config = _BASE

    host_id: str = Field(description="Node this report is about.")
    benchmark: Literal["kubernetes", "docker"] = Field(description="Which benchmark was read.")
    run_at: str = Field(default="", description="When the benchmark last ran.")
    run_timestamp: int = Field(default=0, description="Unix time of that run.")
    cis_version: str = Field(default="", description="CIS benchmark version used.")
    level_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Checks per level over the WHOLE report, before filtering.",
    )
    matched: int = Field(default=0, description="Checks left after level filtering.")
    page: Page = Field(description="Client-side cap envelope; start is always 0.")
    items: list[ComplianceCheck] = Field(
        default_factory=list, description="Filtered checks, capped by max_items."
    )

    @classmethod
    def from_api(
        cls,
        raw: dict[str, Any],
        *,
        host_id: str,
        benchmark: str,
        level: str | None = None,
        max_items: int = 50,
    ) -> BenchReport:
        """Project a ``RESTBenchReport``: count everything, then filter and cap."""
        body = raw.get("report") or raw
        items = [i for i in (body.get("items") or []) if isinstance(i, dict)]
        selected = [
            i
            for i in items
            if level is None or str(i.get("level", "") or "").upper() == level.upper()
        ]
        shown = selected[:max_items]
        return cls(
            host_id=host_id,
            benchmark=benchmark,  # type: ignore[arg-type]
            run_at=str(body.get("run_at", "") or ""),
            run_timestamp=int(body.get("run_timestamp") or 0),
            cis_version=str(body.get("cis_version", "") or ""),
            level_counts=count_by_level(items),
            matched=len(selected),
            page=Page(
                start=0,
                returned=len(shown),
                truncated=len(selected) > len(shown),
                hint=(
                    f"{len(selected)} checks matched; {len(shown)} returned. Filter with "
                    "level, or raise max_items."
                    if len(selected) > len(shown)
                    else None
                ),
            ),
            items=[ComplianceCheck.from_api(i) for i in shown],
        )


class ComplianceProfileBrief(BaseModel):
    """One compliance profile, without its entries."""

    model_config = _BASE

    name: str = Field(description="Profile name; pass to nv_get_compliance_profile.")
    disable_system: bool = Field(
        default=False, description="True when NeuVector's built-in checks are disabled."
    )
    cfg_type: str = Field(
        default="",
        description="user_created | ground. 'ground' profiles come from a CRD and are overwritten by "
        "the CRD controller.",
    )
    entry_count: int = Field(default=0, description="Per-check tag overrides in this profile.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ComplianceProfileBrief:
        """Project a ``RESTComplianceProfile``, dropping its entries."""
        return cls(
            name=str(raw.get("name", "")),
            disable_system=bool(raw.get("disable_system", False)),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            entry_count=len(raw.get("entries") or []),
        )


class ComplianceProfileList(BaseModel):
    """Result of ``nv_list_compliance_profiles``."""

    model_config = _BASE

    page: Page = Field(description="Server-side paging envelope for this page of profiles.")
    profiles: list[ComplianceProfileBrief] = Field(description="Compliance profiles in this page.")


class ComplianceProfileEntry(BaseModel):
    """One per-check tag override."""

    model_config = _BASE

    test_number: str = Field(description="Check id this override applies to, e.g. K.1.2.3.")
    tags: list[str] = Field(
        default_factory=list,
        description="Compliance standards the check counts towards, e.g. PCI, GDPR, HIPAA.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ComplianceProfileEntry:
        """Project a ``RESTComplianceProfileEntry``."""
        return cls(
            test_number=str(raw.get("test_number", "") or ""),
            tags=[str(t) for t in (raw.get("tags") or [])],
        )


class ComplianceProfile(BaseModel):
    """Result of ``nv_get_compliance_profile``."""

    model_config = _BASE

    name: str = Field(description="Profile name.")
    disable_system: bool = Field(
        default=False, description="True when NeuVector's built-in checks are disabled."
    )
    cfg_type: str = Field(
        default="", description="user_created | ground. 'ground' profiles come from a CRD."
    )
    entry_count: int = Field(default=0, description="True number of entries, before max_entries.")
    page: Page = Field(description="Client-side cap envelope; start is always 0.")
    entries: list[ComplianceProfileEntry] = Field(
        default_factory=list, description="Per-check overrides, capped by max_entries."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_entries: int = 100) -> ComplianceProfile:
        """Project a ``RESTComplianceProfile``, capping the entry list."""
        entries = [e for e in (raw.get("entries") or []) if isinstance(e, dict)]
        shown = entries[:max_entries]
        return cls(
            name=str(raw.get("name", "")),
            disable_system=bool(raw.get("disable_system", False)),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            entry_count=len(entries),
            page=Page(
                start=0,
                returned=len(shown),
                truncated=len(entries) > len(shown),
                hint=(
                    f"{len(entries)} entries exist; {len(shown)} shown. Raise max_entries."
                    if len(entries) > len(shown)
                    else None
                ),
            ),
            entries=[ComplianceProfileEntry.from_api(e) for e in shown],
        )


# ----- 40-events.py -----
class SecurityEvent(BaseModel):
    """One threat, network-policy violation or runtime incident, normalised.

    The three controller types name the same concepts differently, so this
    projection maps them onto one vocabulary. Fields that a given kind does not
    carry stay at their default.
    """

    model_config = _BASE

    kind: EventKind = Field(description="Which log this came from.")
    id: str = Field(
        default="", description="Event id. For kind='threat' pass to nv_get_threat_detail."
    )
    name: str = Field(
        default="", description="Controller event name, e.g. the rule or signature name."
    )
    severity: str = Field(
        default="",
        description="Threat 'severity', or 'level' for violations and incidents.",
    )
    level: str = Field(default="", description="Controller log level, verbatim.")
    reported_timestamp: int = Field(
        default=0, description="Unix epoch seconds the enforcer reported the event."
    )
    reported_at: str = Field(
        default="", description="Human-readable report time from the controller."
    )
    action: str = Field(
        default="",
        description="What the enforcer did: threat 'action', violation 'policy_action', "
        "incident 'action'.",
    )
    client_id: str = Field(
        default="", description="Subject/client workload id, or '' when the peer is external."
    )
    client_name: str = Field(default="", description="Subject/client workload name.")
    client_namespace: str = Field(default="", description="Subject/client Kubernetes namespace.")
    client_ip: str = Field(default="", description="Source IP.")
    server_id: str = Field(default="", description="Peer/server workload id, or '' when external.")
    server_name: str = Field(default="", description="Peer/server workload name.")
    server_namespace: str = Field(default="", description="Peer/server Kubernetes namespace.")
    server_ip: str = Field(default="", description="Destination IP.")
    server_port: int = Field(default=0, description="Destination port.")
    ip_proto: int = Field(default=0, description="IP protocol number, 6=TCP 17=UDP 1=ICMP.")
    applications: str = Field(
        default="",
        description="Comma-joined application protocols the enforcer identified.",
    )
    group: str = Field(default="", description="NeuVector group the event was attributed to.")
    matched_rule_id: str = Field(
        default="",
        description="Rule that matched: incident 'rule_id', or violation 'policy_id'. "
        "Empty for threats, which carry 'threat_id' instead.",
    )
    threat_id: int = Field(default=0, description="Threat signature id; kind='threat' only.")
    count: int = Field(
        default=0,
        description="Aggregated occurrence count; for violations this is the session count.",
    )
    proc_name: str = Field(default="", description="Process name; kind='incident' only.")
    proc_path: str = Field(default="", description="Process path; kind='incident' only.")
    file_path: str = Field(default="", description="File path; kind='incident' only.")
    sensor: str = Field(default="", description="DLP/WAF sensor that fired; kind='threat' only.")
    host_name: str = Field(default="", description="Node that reported the event.")
    message: str = Field(
        default="",
        description="Controller message, clipped to 2000 characters. Violations carry no message.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, kind: EventKind) -> SecurityEvent:
        """Project a ``Threat``, ``Violation`` or ``Incident`` onto one shape.

        Note the non-template signature: the discriminator is required because
        the source field names differ per kind.
        """
        common: dict[str, Any] = {
            "kind": kind,
            "id": str(raw.get("id", "") or ""),
            "name": str(raw.get("name", "") or ""),
            "level": str(raw.get("level", "") or ""),
            "reported_timestamp": int(raw.get("reported_timestamp") or 0),
            "reported_at": str(raw.get("reported_at", "") or ""),
            "client_ip": str(raw.get("client_ip", "") or ""),
            "server_ip": str(raw.get("server_ip", "") or ""),
            "server_port": int(raw.get("server_port") or 0),
            "ip_proto": int(raw.get("ip_proto") or 0),
            "host_name": str(raw.get("host_name", "") or ""),
            "message": _clip(str(raw.get("message", "") or ""), 2000)[0],
        }
        if kind == "threat":
            return cls(
                **common,
                severity=str(raw.get("severity", "") or ""),
                action=str(raw.get("action", "") or ""),
                client_id=str(raw.get("client_workload_id", "") or ""),
                client_name=str(raw.get("client_workload_name", "") or ""),
                client_namespace=str(raw.get("client_workload_domain", "") or ""),
                server_id=str(raw.get("server_workload_id", "") or ""),
                server_name=str(raw.get("server_workload_name", "") or ""),
                server_namespace=str(raw.get("server_workload_domain", "") or ""),
                applications=str(raw.get("application", "") or ""),
                group=str(raw.get("group", "") or ""),
                threat_id=int(raw.get("threat_id") or 0),
                count=int(raw.get("count") or 0),
                sensor=str(raw.get("sensor", "") or ""),
            )
        if kind == "violation":
            policy_id = raw.get("policy_id")
            return cls(
                **common,
                severity=str(raw.get("level", "") or ""),
                action=str(raw.get("policy_action", "") or ""),
                client_id=str(raw.get("client_id", "") or ""),
                client_name=str(raw.get("client_name", "") or ""),
                client_namespace=str(raw.get("client_domain", "") or ""),
                server_id=str(raw.get("server_id", "") or ""),
                server_name=str(raw.get("server_name", "") or ""),
                server_namespace=str(raw.get("server_domain", "") or ""),
                applications=", ".join(str(a) for a in (raw.get("applications") or [])),
                matched_rule_id="" if policy_id is None else str(policy_id),
                count=int(raw.get("sessions") or 0),
            )
        return cls(
            **common,
            severity=str(raw.get("level", "") or ""),
            action=str(raw.get("action", "") or ""),
            client_id=str(raw.get("workload_id", "") or ""),
            client_name=str(raw.get("workload_name", "") or ""),
            client_namespace=str(raw.get("workload_domain", "") or ""),
            server_id=str(raw.get("remote_workload_id", "") or ""),
            server_name=str(raw.get("remote_workload_name", "") or ""),
            server_namespace=str(raw.get("remote_workload_domain", "") or ""),
            group=str(raw.get("group", "") or ""),
            matched_rule_id=str(raw.get("rule_id", "") or ""),
            count=int(raw.get("count") or 0),
            proc_name=str(raw.get("proc_name", "") or ""),
            proc_path=str(raw.get("proc_path", "") or ""),
            file_path=str(raw.get("file_path", "") or ""),
        )


class SecurityEventList(BaseModel):
    """Result of ``nv_query_security_events``."""

    model_config = _BASE

    page: Page = Field(description="Paging envelope; 'truncated' means more events exist.")
    kind: EventKind = Field(description="Which log was queried.")
    dropped_outside_window: int = Field(
        default=0,
        description="Items the controller returned that fell outside until_timestamp and were "
        "removed after paging. Non-zero means this page holds fewer than 'limit' items even "
        "though more matching events may exist.",
    )
    events: list[SecurityEvent] = Field(description="The events, newest first by default.")


class ThreatDetail(BaseModel):
    """Result of ``nv_get_threat_detail``: one threat plus its packet capture."""

    model_config = _BASE

    event: SecurityEvent = Field(description="The threat, projected like a list entry.")
    target: str = Field(default="", description="Which side the enforcer treated as the target.")
    monitor: bool = Field(
        default=False,
        description="True when the enforcer only logged the threat instead of blocking it.",
    )
    cap_len: int = Field(
        default=0, description="Captured packet length in bytes as reported by the enforcer."
    )
    packet: str = Field(
        default="",
        description="Captured packet as encoded by the controller, clipped to the budget. "
        "Empty when include_packet was False or nothing was captured.",
    )
    packet_chars: int = Field(
        default=0, description="Length of the packet field the controller sent, before clipping."
    )
    packet_truncated: bool = Field(
        default=False,
        description="True when the packet was clipped or withheld. The withheld bytes cannot be "
        "recovered through this server; use the NeuVector UI or a packet capture instead.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, packet_budget: int) -> ThreatDetail:
        """Project a ``Threat`` object, clipping ``packet`` to ``packet_budget`` chars."""
        full = str(raw.get("packet", "") or "")
        clipped, was_clipped = _clip(full, packet_budget)
        return cls(
            event=SecurityEvent.from_api(raw, kind="threat"),
            target=str(raw.get("target", "") or ""),
            monitor=bool(raw.get("monitor", False)),
            cap_len=int(raw.get("cap_len") or 0),
            packet=clipped,
            packet_chars=len(full),
            packet_truncated=was_clipped,
        )


class AuditEvent(BaseModel):
    """One entry from the audit log."""

    model_config = _BASE

    name: str = Field(
        default="", description="Audit event name, e.g. the scan or compliance event type."
    )
    level: str = Field(default="", description="Controller log level, verbatim.")
    reported_timestamp: int = Field(
        default=0, description="Unix epoch seconds the event was reported."
    )
    reported_at: str = Field(default="", description="Human-readable report time.")
    cluster_name: str = Field(default="", description="Cluster that produced the event.")
    host_name: str = Field(default="", description="Node the event refers to.")
    workload_id: str = Field(default="", description="Workload id; pass to nv_get_workload.")
    workload_name: str = Field(default="", description="Workload name.")
    workload_namespace: str = Field(
        default="", description="Kubernetes namespace (controller field 'workload_domain')."
    )
    workload_image: str = Field(default="", description="Image the workload runs.")
    workload_service: str = Field(default="", description="NeuVector service (group) name.")
    image: str = Field(
        default="",
        description="Scanned image reference, for registry and repository scan events.",
    )
    registry_name: str = Field(
        default="", description="Registry configuration name, when the event concerns a registry."
    )
    repository: str = Field(default="", description="Repository within the registry.")
    tag: str = Field(default="", description="Image tag.")
    base_os: str = Field(default="", description="Base OS the scanner identified.")
    high_vul_cnt: int = Field(
        default=0, description="High-severity vulnerability count at report time."
    )
    medium_vul_cnt: int = Field(
        default=0, description="Medium-severity vulnerability count at report time."
    )
    cvedb_version: str = Field(default="", description="Vulnerability database version used.")
    user: str = Field(default="", description="User the controller attributed the event to.")
    count: int = Field(default=0, description="Aggregated occurrence count.")
    message: str = Field(default="", description="Controller message, clipped to 2000 characters.")
    error: str = Field(
        default="", description="Controller error text when the audited operation failed."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> AuditEvent:
        """Project an ``Audit``. Vulnerability id arrays are deliberately dropped."""
        return cls(
            name=str(raw.get("name", "") or ""),
            level=str(raw.get("level", "") or ""),
            reported_timestamp=int(raw.get("reported_timestamp") or 0),
            reported_at=str(raw.get("reported_at", "") or ""),
            cluster_name=str(raw.get("cluster_name", "") or ""),
            host_name=str(raw.get("host_name", "") or ""),
            workload_id=str(raw.get("workload_id", "") or ""),
            workload_name=str(raw.get("workload_name", "") or ""),
            workload_namespace=str(raw.get("workload_domain", "") or ""),
            workload_image=str(raw.get("workload_image", "") or ""),
            workload_service=str(raw.get("workload_service", "") or ""),
            image=str(raw.get("image", "") or ""),
            registry_name=str(raw.get("registry_name", "") or ""),
            repository=str(raw.get("repository", "") or ""),
            tag=str(raw.get("tag", "") or ""),
            base_os=str(raw.get("base_os", "") or ""),
            high_vul_cnt=int(raw.get("high_vul_cnt") or 0),
            medium_vul_cnt=int(raw.get("medium_vul_cnt") or 0),
            cvedb_version=str(raw.get("cvedb_version") or ""),
            user=str(raw.get("user", "") or ""),
            count=int(raw.get("count") or 0),
            message=_clip(str(raw.get("message", "") or ""), 2000)[0],
            error=str(raw.get("error", "") or ""),
        )


class AuditEventList(BaseModel):
    """Result of ``nv_query_audit_events``."""

    model_config = _BASE

    page: Page = Field(description="Paging envelope; 'truncated' means more audit events exist.")
    dropped_outside_window: int = Field(
        default=0,
        description="Items removed after paging because they fell outside until_timestamp.",
    )
    audits: list[AuditEvent] = Field(description="The audit entries, newest first by default.")


class SystemEvent(BaseModel):
    """One controller, enforcer or REST-API event."""

    model_config = _BASE

    name: str = Field(default="", description="System event name.")
    category: str = Field(default="", description="Event category as the controller reports it.")
    level: str = Field(default="", description="Controller log level, verbatim.")
    reported_timestamp: int = Field(
        default=0, description="Unix epoch seconds the event was reported."
    )
    reported_at: str = Field(default="", description="Human-readable report time.")
    cluster_name: str = Field(default="", description="Cluster that produced the event.")
    host_name: str = Field(default="", description="Node the event refers to.")
    controller_name: str = Field(default="", description="Controller that produced the event.")
    enforcer_name: str = Field(default="", description="Enforcer the event refers to.")
    workload_id: str = Field(
        default="", description="Workload id, when the event is workload-scoped."
    )
    workload_name: str = Field(default="", description="Workload name.")
    workload_namespace: str = Field(
        default="", description="Kubernetes namespace (controller field 'workload_domain')."
    )
    user: str = Field(default="", description="User the controller attributed the event to.")
    user_addr: str = Field(default="", description="Client address the request came from.")
    rest_method: str = Field(default="", description="HTTP method, for REST-activity events.")
    rest_request: str = Field(default="", description="Request path, for REST-activity events.")
    enforcer_limit: int = Field(
        default=0, description="Licensed enforcer limit, on limit-related events."
    )
    license_expire: str = Field(
        default="", description="Licence expiry, on licence-related events."
    )
    message: str = Field(default="", description="Controller message, clipped to 2000 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> SystemEvent:
        """Project an ``Event``. 'rest_body' is dropped on purpose - see Notes."""
        return cls(
            name=str(raw.get("name", "") or ""),
            category=str(raw.get("category", "") or ""),
            level=str(raw.get("level", "") or ""),
            reported_timestamp=int(raw.get("reported_timestamp") or 0),
            reported_at=str(raw.get("reported_at", "") or ""),
            cluster_name=str(raw.get("cluster_name", "") or ""),
            host_name=str(raw.get("host_name", "") or ""),
            controller_name=str(raw.get("controller_name", "") or ""),
            enforcer_name=str(raw.get("enforcer_name", "") or ""),
            workload_id=str(raw.get("workload_id", "") or ""),
            workload_name=str(raw.get("workload_name", "") or ""),
            workload_namespace=str(raw.get("workload_domain", "") or ""),
            user=str(raw.get("user", "") or ""),
            user_addr=str(raw.get("user_addr", "") or ""),
            rest_method=str(raw.get("rest_method", "") or ""),
            rest_request=str(raw.get("rest_request", "") or ""),
            enforcer_limit=int(raw.get("enforcer_limit") or 0),
            license_expire=str(raw.get("license_expire", "") or ""),
            message=_clip(str(raw.get("message", "") or ""), 2000)[0],
        )


class SystemEventList(BaseModel):
    """Result of ``nv_query_system_events``."""

    model_config = _BASE

    page: Page = Field(description="Paging envelope; 'truncated' means more system events exist.")
    dropped_outside_window: int = Field(
        default=0,
        description="Items removed after paging because they fell outside until_timestamp.",
    )
    events: list[SystemEvent] = Field(description="The system events, newest first by default.")


class SystemAlerts(BaseModel):
    """Result of ``nv_get_system_alerts``.

    ``RESTNvAlerts`` is absent from Appendix B, so this model asserts no field
    names inside an alert. It reports alert text as strings and echoes the
    top-level keys the controller used, so the shape can be confirmed against a
    live controller without another code change.
    """

    model_config = _BASE

    alerts: list[str] = Field(
        default_factory=list,
        description="Alert text, one entry per alert, clipped to 1000 characters each.",
    )
    count: int = Field(default=0, description="Number of alerts returned.")
    envelope_keys: list[str] = Field(
        default_factory=list,
        description="Top-level keys the controller returned. Diagnostic: the alert envelope key "
        "is not documented, so this reveals the real shape.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> SystemAlerts:
        """Extract alert text defensively.

        Preference order: the ``alerts`` key (§3.3 naming convention), else the
        first list-valued top-level key. List entries may be strings or objects;
        objects are reduced to their ``message`` or ``name`` value if present,
        else to an empty string.
        """
        raw_list: list[Any] = []
        candidate = raw.get("alerts")
        if isinstance(candidate, list):
            raw_list = candidate
        else:
            for value in raw.values():
                if isinstance(value, list):
                    raw_list = value
                    break
        texts: list[str] = []
        for item in raw_list:
            if isinstance(item, str):
                text = item
            elif isinstance(item, dict):
                text = str(item.get("message") or item.get("name") or "")
            else:
                text = ""
            if text:
                texts.append(_clip(text, 1000)[0])
        return cls(alerts=texts, count=len(texts), envelope_keys=sorted(raw.keys()))


# ----- 50-policy_read.py -----
class NetworkRule(BaseModel):
    """One network policy rule."""

    model_config = _BASE

    id: int = Field(description="Rule id; pass to nv_get_network_rule or nv_delete_network_rule.")
    order: int = Field(
        default=0,
        description="Zero-based position in the controller's evaluation order, counted from the "
        "start of the whole list, not of this page. Lower wins.",
    )
    from_group: str = Field(default="", description="Source group name (controller field 'from').")
    to_group: str = Field(default="", description="Destination group name (controller field 'to').")
    ports: str = Field(
        default="",
        description="Free-form port list the rule matches, e.g. 'tcp/443,udp/53'.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Application protocols the rule matches; empty means any.",
    )
    action: str = Field(default="", description="allow or deny.")
    learned: bool = Field(
        default=False,
        description="True when NeuVector inferred this rule in Discover mode.",
    )
    disable: bool = Field(
        default=False, description="True when the rule is present but not enforced."
    )
    cfg_type: str = Field(
        default="",
        description="Provenance: learned | user_created | ground (Kubernetes CRD) | federal "
        "(pushed by a federation primary). Federal and ground rules are read-only here.",
    )
    priority: int = Field(
        default=0, description="Controller ordering weight; lower is evaluated earlier."
    )
    match_counter: int = Field(
        default=0,
        description="How many times the rule has matched since it was created.",
    )
    last_match_timestamp: int = Field(
        default=0, description="Unix epoch seconds of the last match, 0 if never."
    )
    created_timestamp: int = Field(
        default=0, description="Unix epoch seconds the rule was created."
    )
    last_modified_timestamp: int = Field(
        default=0, description="Unix epoch seconds the rule was last changed."
    )
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, order: int = 0) -> NetworkRule:
        """Project a ``RESTPolicyRule``.

        ``from`` and ``to`` are Python keywords, so they are read by string key
        and exposed as ``from_group`` / ``to_group``.
        """
        return cls(
            id=int(raw.get("id") or 0),
            order=order,
            from_group=str(raw.get("from", "") or ""),
            to_group=str(raw.get("to", "") or ""),
            ports=str(raw.get("ports", "") or ""),
            applications=[str(a) for a in (raw.get("applications") or [])],
            action=str(raw.get("action", "") or ""),
            learned=bool(raw.get("learned", False)),
            disable=bool(raw.get("disable", False)),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            priority=int(raw.get("priority") or 0),
            match_counter=int(raw.get("match_counter") or 0),
            last_match_timestamp=int(raw.get("last_match_timestamp") or 0),
            created_timestamp=int(raw.get("created_timestamp") or 0),
            last_modified_timestamp=int(raw.get("last_modified_timestamp") or 0),
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
        )


class NetworkRuleList(BaseModel):
    """Result of ``nv_list_network_rules``."""

    model_config = _BASE

    page: Page
    scope: str = Field(default="local", description="Scope the rules were read from: local or fed.")
    rules: list[NetworkRule]


class ProcessProfileEntry(BaseModel):
    """One allowed (or explicitly denied) process in a group's profile."""

    model_config = _BASE

    name: str = Field(description="Process name as the enforcer sees it.")
    path: str = Field(default="", description="Absolute executable path; empty means any path.")
    user: str = Field(
        default="",
        description="User the process is expected to run as; empty means any.",
    )
    uid: int = Field(default=0, description="Expected uid; 0 when unset rather than meaning root.")
    action: str = Field(default="", description="allow or deny.")
    cfg_type: str = Field(
        default="",
        description="Provenance: learned | user_created | ground | federal | system_defined.",
    )
    uuid: str = Field(
        default="",
        description="Entry uuid; the handle for updates through nv_update_process_profile.",
    )
    group: str = Field(
        default="",
        description="Group the entry belongs to, set when inherited from another group.",
    )
    created_timestamp: int = Field(
        default=0, description="Unix epoch seconds the entry was created."
    )
    last_modified_timestamp: int = Field(
        default=0, description="Unix epoch seconds the entry was last changed."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ProcessProfileEntry:
        """Project a ``RESTProcessProfileEntry``."""
        return cls(
            name=str(raw.get("name", "") or ""),
            path=str(raw.get("path", "") or ""),
            user=str(raw.get("user", "") or ""),
            uid=int(raw.get("uid") or 0),
            action=str(raw.get("action", "") or ""),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            uuid=str(raw.get("uuid", "") or ""),
            group=str(raw.get("group", "") or ""),
            created_timestamp=int(raw.get("created_timestamp") or 0),
            last_modified_timestamp=int(raw.get("last_modified_timestamp") or 0),
        )


class ProcessProfile(BaseModel):
    """Result of ``nv_get_process_profile``."""

    model_config = _BASE

    group: str = Field(description="Group this profile belongs to.")
    mode: PolicyMode = Field(
        default="", description="Enforcement mode: Discover, Monitor or Protect."
    )
    alert_disabled: bool = Field(
        default=False, description="True when profile violations do not raise alerts."
    )
    hash_enabled: bool = Field(
        default=False,
        description="True when executable hashes are verified as well as paths.",
    )
    entries_total: int = Field(
        default=0, description="Entries the controller returned, before the max_entries cap."
    )
    entries_truncated: bool = Field(
        default=False,
        description="True when entries were dropped by max_entries. Raise max_entries to see "
        "the rest.",
    )
    entries: list[ProcessProfileEntry]

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_entries: int = 100) -> ProcessProfile:
        """Project a ``RESTProcessProfile``, capping ``process_list`` client-side."""
        items = list(raw.get("process_list") or [])
        kept = items[:max_entries]
        return cls(
            group=str(raw.get("group", "") or ""),
            mode=str(raw.get("mode", "") or ""),  # type: ignore[arg-type]
            alert_disabled=bool(raw.get("alert_disabled", False)),
            hash_enabled=bool(raw.get("hash_enabled", False)),
            entries_total=len(items),
            entries_truncated=len(items) > len(kept),
            entries=[ProcessProfileEntry.from_api(i) for i in kept],
        )


class FileMonitorFilter(BaseModel):
    """One watched path pattern."""

    model_config = _BASE

    filter: str = Field(default="", description="Path or glob being watched.")
    recursive: bool = Field(default=False, description="True when subdirectories are watched too.")
    behavior: bool | str = Field(
        default="",
        description="What the enforcer does on a hit, verbatim as the controller reports it "
        "(monitor or block).",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Processes the filter is scoped to; empty means any process.",
    )
    group: str = Field(default="", description="Group the filter was inherited from, when set.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> FileMonitorFilter:
        """Project one filter entry. Names shared with ``RESTFileMonitorFilterConfig``."""
        return cls(
            filter=str(raw.get("filter", "") or ""),
            recursive=bool(raw.get("recursive", False)),
            behavior=str(raw.get("behavior", "") or ""),
            applications=[str(a) for a in (raw.get("applications") or [])],
            group=str(raw.get("group", "") or ""),
        )


class FileMonitorProfile(BaseModel):
    """Result of ``nv_get_file_monitor_profile``.

    ``RESTFileMonitorFile`` is absent from Appendix B, so the only field names
    read are the five that Appendix B documents on
    ``RESTFileMonitorFilterConfig``, all through ``.get()`` with defaults.
    """

    model_config = _BASE

    group: str = Field(description="Group this profile belongs to, echoed from the request.")
    filters_total: int = Field(
        default=0, description="Filters the controller returned, before the cap."
    )
    filters_truncated: bool = Field(
        default=False, description="True when filters were dropped by max_filters."
    )
    envelope_keys: list[str] = Field(
        default_factory=list,
        description="Top-level keys the controller returned. Diagnostic: this response shape is "
        "not documented in the schema reference.",
    )
    filters: list[FileMonitorFilter]

    @classmethod
    def from_api(
        cls, raw: dict[str, Any], *, group_name: str, max_filters: int = 100
    ) -> FileMonitorProfile:
        """Locate the filter list defensively, then project up to ``max_filters``.

        Preference order for the list: ``filters``, then ``profile.filters``,
        then the first list-valued top-level key.
        """
        items: list[Any] = []
        if isinstance(raw.get("filters"), list):
            items = list(raw["filters"])
        elif isinstance(raw.get("profile"), dict) and isinstance(
            raw["profile"].get("filters"), list
        ):
            items = list(raw["profile"]["filters"])
        else:
            for value in raw.values():
                if isinstance(value, list):
                    items = list(value)
                    break
        kept = [i for i in items[:max_filters] if isinstance(i, dict)]
        return cls(
            group=group_name,
            filters_total=len(items),
            filters_truncated=len(items) > max_filters,
            envelope_keys=sorted(raw.keys()),
            filters=[FileMonitorFilter.from_api(i) for i in kept],
        )


class ResponseRule(BaseModel):
    """One response rule."""

    model_config = _BASE

    id: int = Field(description="Rule id.")
    order: int = Field(default=0, description="Zero-based absolute position in evaluation order.")
    event: str = Field(default="", description="Event type that triggers the rule.")
    group: str = Field(
        default="", description="Group the rule is scoped to; empty means cluster-wide."
    )
    actions: list[str] = Field(
        default_factory=list,
        description="What the controller does when the rule matches, e.g. suppress log, "
        "quarantine, webhook.",
    )
    webhooks: list[str] = Field(
        default_factory=list,
        description="Names of configured webhook targets to notify. Names only, never URLs.",
    )
    conditions: list[str] = Field(
        default_factory=list,
        description="Extra match conditions rendered as 'type=value' strings.",
    )
    disable: bool = Field(default=False, description="True when the rule is present but inactive.")
    cfg_type: str = Field(default="", description="Provenance: user_created | ground | federal.")
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, order: int = 0) -> ResponseRule:
        """Project a ``RESTResponseRule``; conditions flatten ``RESTCLUSEventCondition``."""
        conditions = [
            f"{c.get('type', '') or ''!s}={c.get('value', '') or ''!s}"
            for c in (raw.get("conditions") or [])
            if isinstance(c, dict)
        ]
        return cls(
            id=int(raw.get("id") or 0),
            order=order,
            event=str(raw.get("event", "") or ""),
            group=str(raw.get("group", "") or ""),
            actions=[str(a) for a in (raw.get("actions") or [])],
            webhooks=[str(w) for w in (raw.get("webhooks") or [])],
            conditions=conditions,
            disable=bool(raw.get("disable", False)),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
        )


class ResponseRuleList(BaseModel):
    """Result of ``nv_list_response_rules``."""

    model_config = _BASE

    page: Page
    scope: str = Field(default="local", description="Scope the rules were read from: local or fed.")
    rules: list[ResponseRule]


class SensorBrief(BaseModel):
    """One DLP or WAF sensor, name-level only.

    Appendix B contains neither ``RESTDlpSensor`` nor ``RESTWafSensor``, so this
    projection asserts only ``name`` and ``comment`` and derives every other
    value with ``.get()`` defaults.
    """

    model_config = _BASE

    name: str = Field(
        default="", description="Sensor name; matches the 'sensor' field on threat events."
    )
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")
    rule_count: int = Field(
        default=0,
        description="Number of pattern rules the sensor carries, 0 when the controller did not "
        "report a rule list. Rule bodies are never returned.",
    )
    predefined: bool = Field(
        default=False,
        description="True when the sensor ships with NeuVector rather than being user-defined.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> SensorBrief:
        """Project a sensor entry defensively; unknown keys are ignored."""
        return cls(
            name=str(raw.get("name", "") or ""),
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
            rule_count=len(raw.get("rules") or []),
            predefined=bool(raw.get("predefined", False)),
        )


class DlpSensorList(BaseModel):
    """Result of ``nv_list_dlp_sensors``."""

    model_config = _BASE

    page: Page
    sensors: list[SensorBrief]


class WafSensorList(BaseModel):
    """Result of ``nv_list_waf_sensors``."""

    model_config = _BASE

    page: Page
    scope: str = Field(
        default="local", description="Scope the sensors were read from: local or fed."
    )
    sensors: list[SensorBrief]


class AdmissionState(BaseModel):
    """Result of ``nv_get_admission_state``."""

    model_config = _BASE

    enable: bool = Field(default=False, description="True when the admission webhook is active.")
    mode: str = Field(
        default="",
        description="monitor logs would-be denials, protect actually denies requests.",
    )
    default_action: str = Field(
        default="", description="What happens to a request that no rule matches."
    )
    adm_client_mode: str = Field(
        default="", description="How the controller reaches the Kubernetes API server."
    )
    adm_svc_type: str = Field(default="", description="Service type backing the admission webhook.")
    k8s_env: bool = Field(
        default=False,
        description="True when the controller detected Kubernetes. False means admission control "
        "is unavailable and mutations return controller code 30.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> AdmissionState:
        """Project ``RESTAdmissionConfigData``: top-level ``k8s_env`` plus ``state``."""
        state = raw.get("state") or {}
        return cls(
            enable=bool(state.get("enable", False)),
            mode=str(state.get("mode", "") or ""),
            default_action=str(state.get("default_action", "") or ""),
            adm_client_mode=str(state.get("adm_client_mode", "") or ""),
            adm_svc_type=str(state.get("adm_svc_type", "") or ""),
            k8s_env=bool(raw.get("k8s_env", False)),
        )


def _flatten_criterion(raw: dict[str, Any]) -> str:
    """Render a ``RESTAdmRuleCriterion`` as 'name op value', with sub-criteria inline."""
    name = str(raw.get("name", "") or "")
    op = str(raw.get("op", "") or "")
    value = str(raw.get("value", "") or "")
    base = f"{name} {op} {value}".strip()
    subs = [_flatten_criterion(s) for s in (raw.get("sub_criteria") or []) if isinstance(s, dict)]
    return f"{base} (sub: {'; '.join(subs)})" if subs else base


class AdmissionRule(BaseModel):
    """One admission control rule."""

    model_config = _BASE

    id: int = Field(
        description="Rule id; pass to nv_update_admission_rule or nv_delete_admission_rule."
    )
    category: str = Field(default="", description="Rule category as the controller reports it.")
    rule_type: str = Field(
        default="", description="deny blocks matching deployments, exception allows them."
    )
    rule_mode: str = Field(
        default="",
        description="Per-rule override of the global admission mode: monitor, protect, or empty "
        "to inherit.",
    )
    cfg_type: str = Field(default="", description="Provenance: user_created | ground | federal.")
    disable: bool = Field(
        default=False, description="True when the rule is present but not evaluated."
    )
    critical: bool = Field(
        default=False,
        description="True for built-in rules NeuVector always evaluates; these cannot be deleted.",
    )
    containers: list[str] = Field(
        default_factory=list,
        description="Which container classes the rule inspects: containers, init_containers, "
        "ephemeral_containers.",
    )
    criteria: list[str] = Field(
        default_factory=list,
        description="Match criteria flattened to 'name op value' strings.",
    )
    criteria_total: int = Field(
        default=0, description="Criteria the controller returned, before the cap."
    )
    criteria_truncated: bool = Field(
        default=False, description="True when criteria were dropped by max_criteria."
    )
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_criteria: int = 10) -> AdmissionRule:
        """Project a ``RESTAdmissionRule``."""
        items = [c for c in (raw.get("criteria") or []) if isinstance(c, dict)]
        kept = items[:max_criteria]
        return cls(
            id=int(raw.get("id") or 0),
            category=str(raw.get("category", "") or ""),
            rule_type=str(raw.get("rule_type", "") or ""),
            rule_mode=str(raw.get("rule_mode", "") or ""),
            cfg_type=str(raw.get("cfg_type", "") or ""),
            disable=bool(raw.get("disable", False)),
            critical=bool(raw.get("critical", False)),
            containers=[str(c) for c in (raw.get("containers") or [])],
            criteria=[_flatten_criterion(c) for c in kept],
            criteria_total=len(items),
            criteria_truncated=len(items) > len(kept),
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
        )


class AdmissionRuleList(BaseModel):
    """Result of ``nv_list_admission_rules``."""

    model_config = _BASE

    page: Page
    scope: str = Field(default="local", description="Scope the rules were read from: local or fed.")
    rules: list[AdmissionRule]


class AdmissionCriterionInput(BaseModel):
    """One criterion of the candidate rule. Mirrors RESTAdmRuleCriterion.

    This is the only INPUT model in Part B, so it is the one model here that
    does not use ``_BASE``: unknown keys are rejected rather than ignored, and
    it carries no ``from_api`` because nothing projects a controller body into
    it.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Criterion name, e.g. 'image' or 'runAsRoot'.")
    op: str = Field(
        description="Comparison operator the controller defines for this criterion name."
    )
    value: str = Field(default="", description="Value to compare against.")
    sub_criteria: list[AdmissionCriterionInput] = Field(
        default_factory=list, description="Nested criteria, for names that take them."
    )


AdmissionCriterionInput.model_rebuild()


class AdmissionMatchedRule(BaseModel):
    """An existing admission rule that also matched the assessed object."""

    model_config = _BASE

    id: int = Field(default=0, description="Existing rule id.")
    type: str = Field(default="", description="allow or deny.")
    mode: str = Field(
        default="", description="Per-rule mode: monitor or protect, empty to inherit."
    )
    disabled: bool = Field(default=False, description="True when that rule is currently disabled.")
    rule_cfg_type: str = Field(
        default="", description="Provenance: federal | ground | user_created."
    )
    container_image: str = Field(
        default="", description="Container image in the pod that this rule matched."
    )
    rule_details: str = Field(
        default="",
        description="Controller explanation of the match, clipped to 1000 characters.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> AdmissionMatchedRule:
        """Project a ``RESTAdmCtrlTestRuleInfo``."""
        return cls(
            id=int(raw.get("id") or 0),
            type=str(raw.get("type", "") or ""),
            mode=str(raw.get("mode", "") or ""),
            disabled=bool(raw.get("disabled", False)),
            rule_cfg_type=str(raw.get("rule_cfg_type", "") or ""),
            container_image=str(raw.get("container_image", "") or ""),
            rule_details=_clip(str(raw.get("rule_details", "") or ""), 1000)[0],
        )


class AdmissionAssessmentResult(BaseModel):
    """The verdict for one cluster object."""

    model_config = _BASE

    index: int = Field(
        default=0, description="Controller's index for this object within the assessment."
    )
    name: str = Field(default="", description="Object name.")
    kind: str = Field(default="", description="Kubernetes kind of the object, e.g. Deployment.")
    allowed: bool = Field(
        default=False, description="False when the webhook would deny this object."
    )
    message: str = Field(
        default="", description="Controller explanation, clipped to 1000 characters."
    )
    matched_rules: list[AdmissionMatchedRule] = Field(
        default_factory=list, description="Existing rules that also matched this object."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> AdmissionAssessmentResult:
        """Project a ``RESTAdmCtrlRulesTestResult``."""
        return cls(
            index=int(raw.get("index") or 0),
            name=str(raw.get("name", "") or ""),
            kind=str(raw.get("kind", "") or ""),
            allowed=bool(raw.get("allowed", False)),
            message=_clip(str(raw.get("message", "") or ""), 1000)[0],
            matched_rules=[
                AdmissionMatchedRule.from_api(m)
                for m in (raw.get("matched_rules") or [])
                if isinstance(m, dict)
            ],
        )


class AdmissionAssessment(BaseModel):
    """Result of ``nv_assess_admission_rule``. Nothing was changed to produce it."""

    model_config = _BASE

    global_mode: str = Field(
        default="",
        description="Cluster admission mode at assessment time: monitor, protect, or empty when "
        "disabled.",
    )
    props_unavailable: list[str] = Field(
        default_factory=list,
        description="Criterion properties the controller could not evaluate; results ignore them.",
    )
    results_total: int = Field(
        default=0, description="Objects the controller assessed, before the cap."
    )
    results_truncated: bool = Field(
        default=False, description="True when results were dropped by max_results."
    )
    denied_count: int = Field(default=0, description="Returned results whose verdict was deny.")
    results: list[AdmissionAssessmentResult]

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_results: int = 50) -> AdmissionAssessment:
        """Project a ``RESTAdmCtrlRulesTestResults`` body."""
        items = [r for r in (raw.get("results") or []) if isinstance(r, dict)]
        kept = [AdmissionAssessmentResult.from_api(r) for r in items[:max_results]]
        return cls(
            global_mode=str(raw.get("global_mode", "") or ""),
            props_unavailable=[str(p) for p in (raw.get("props_unavailable") or [])],
            results_total=len(items),
            results_truncated=len(items) > len(kept),
            denied_count=sum(1 for r in kept if not r.allowed),
            results=kept,
        )


# ----- 60-iam_read.py -----
class UserBrief(BaseModel):
    """One user account. Password material is structurally absent."""

    model_config = _BASE

    fullname: str = Field(
        description="Fully qualified user name; the id for nv_update_user_role and nv_delete_user."
    )
    username: str = Field(default="", description="Login name.")
    email: str = Field(default="", description="Email address on the account.")
    auth_server: str = Field(
        default="",
        description="Authentication server the user comes from; empty means a local account.",
    )
    role: str = Field(
        default="",
        description="Global role, e.g. admin, reader. Empty means namespace-scoped only.",
    )
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Namespace-scoped roles as role -> list of namespaces.",
    )
    timeout: int = Field(default=0, description="Session idle timeout in seconds.")
    locale: str = Field(default="", description="UI locale.")
    last_login_at: str = Field(default="", description="Human-readable last login time.")
    last_login_timestamp: int = Field(
        default=0, description="Unix epoch seconds of the last login, 0 if never."
    )
    login_count: int = Field(default=0, description="Successful logins recorded for this account.")
    default_password: bool = Field(
        default=True,
        description="True when the account still uses its default password. Treat as a finding. "
        "Defaults to True so a missing field never reads as safe.",
    )
    blocked_for_failed_login: bool = Field(
        default=False, description="True when locked out by failed logins."
    )
    blocked_for_password_expired: bool = Field(
        default=False, description="True when the password has expired."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> UserBrief:
        """Project a ``RESTUser``.

        ``password`` is NEVER read. See the tool notes: omission is a
        requirement, not an optimisation.
        """
        domains = raw.get("role_domains") or {}
        role_domains = (
            {
                str(role): [str(d) for d in (namespaces or [])]
                for role, namespaces in domains.items()
            }
            if isinstance(domains, dict)
            else {}
        )
        return cls(
            fullname=str(raw.get("fullname", "") or ""),
            username=str(raw.get("username", "") or ""),
            email=str(raw.get("email", "") or ""),
            auth_server=str(raw.get("server", "") or ""),
            role=str(raw.get("role", "") or ""),
            role_domains=role_domains,
            timeout=int(raw.get("timeout") or 0),
            locale=str(raw.get("locale", "") or ""),
            last_login_at=str(raw.get("last_login_at", "") or ""),
            last_login_timestamp=int(raw.get("last_login_timestamp") or 0),
            login_count=int(raw.get("login_count") or 0),
            default_password=bool(raw.get("default_password", True)),
            blocked_for_failed_login=bool(raw.get("blocked_for_failed_login", False)),
            blocked_for_password_expired=bool(raw.get("blocked_for_password_expired", False)),
        )


class UserList(BaseModel):
    """Result of ``nv_list_users``."""

    model_config = _BASE

    page: Page
    users: list[UserBrief]


class RolePermission(BaseModel):
    """One permission grant inside a role."""

    model_config = _BASE

    id: str = Field(description="Controller permission id, e.g. 'rt_policy' or 'admctrl'.")
    read: bool = Field(default=False, description="True when the role can read this area.")
    write: bool = Field(default=False, description="True when the role can change this area.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> RolePermission:
        """Project a ``RESTRolePermission``."""
        return cls(
            id=str(raw.get("id", "") or ""),
            read=bool(raw.get("read", False)),
            write=bool(raw.get("write", False)),
        )


class RoleBrief(BaseModel):
    """One role definition."""

    model_config = _BASE

    name: str = Field(description="Role name as referenced by users and API keys.")
    reserved: bool = Field(
        default=False,
        description="True for built-in roles, which cannot be modified or deleted.",
    )
    write_permission_count: int = Field(
        default=0,
        description="How many permission areas this role can change. 0 means read-only.",
    )
    permissions: list[RolePermission] = Field(
        default_factory=list, description="Permission grants making up the role."
    )
    comment: str = Field(default="", description="Role description, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> RoleBrief:
        """Project a ``RESTUserRole``."""
        perms = [
            RolePermission.from_api(p)
            for p in (raw.get("permissions") or [])
            if isinstance(p, dict)
        ]
        return cls(
            name=str(raw.get("name", "") or ""),
            reserved=bool(raw.get("reserved", False)),
            write_permission_count=sum(1 for p in perms if p.write),
            permissions=perms,
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
        )


class RoleList(BaseModel):
    """Result of ``nv_list_roles``."""

    model_config = _BASE

    page: Page
    roles: list[RoleBrief]


#: Only these top-level keys of a server entry may be projected, and only 'name'
#: as a value. Everything else is reported as a key name or dropped. An
#: allowlist is used deliberately: a denylist would leak any secret field that a
#: future controller release adds.
_AUTH_SERVER_VALUE_ALLOWLIST: frozenset[str] = frozenset({"name"})

#: Key-name substrings that must never appear even in the reported key list.
_SECRET_KEY_MARKERS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "credential",
    "private",
    "key",
)


class AuthServerBrief(BaseModel):
    """One authentication server, reduced to non-sensitive facts.

    Appendix B contains no ``RESTServer`` / ``RESTServersData`` definition, so
    the set of secret-bearing fields cannot be enumerated from the schema. This
    model therefore projects VALUES for allowlisted keys only ('name') and
    reports every other key by NAME, with secret-looking names filtered out.
    """

    model_config = _BASE

    name: str = Field(description="Server name; matches the 'server' field on a user account.")
    config_blocks: list[str] = Field(
        default_factory=list,
        description="Configuration block key names present on this server, e.g. the protocol "
        "block that identifies it as LDAP, SAML or OIDC. Names only, never values.",
    )
    redacted_keys: list[str] = Field(
        default_factory=list,
        description="Key names withheld because they matched a secret marker (password, secret, "
        "token, credential, private, key). Their values are never read.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> AuthServerBrief:
        """Project one server entry through the value allowlist."""
        blocks: list[str] = []
        redacted: list[str] = []
        for key in raw:
            if key in _AUTH_SERVER_VALUE_ALLOWLIST:
                continue
            lowered = key.lower()
            if any(marker in lowered for marker in _SECRET_KEY_MARKERS):
                redacted.append(key)
            else:
                blocks.append(key)
        return cls(
            name=str(raw.get("name", "") or ""),
            config_blocks=sorted(blocks),
            redacted_keys=sorted(redacted),
        )


class AuthServerList(BaseModel):
    """Result of ``nv_list_auth_servers``."""

    model_config = _BASE

    page: Page
    servers: list[AuthServerBrief]


class ApiKeyBrief(BaseModel):
    """One API key's metadata. The secret is structurally absent."""

    model_config = _BASE

    apikey_name: str = Field(
        description="Key name, i.e. the access key; the id for nv_delete_api_key."
    )
    role: str = Field(default="", description="Global role the key carries.")
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Namespace-scoped roles as role -> list of namespaces.",
    )
    expiration_type: str = Field(
        default="",
        description="How expiry is expressed, e.g. hours or never, verbatim from the controller.",
    )
    expiration_hours: int = Field(
        default=0, description="Configured lifetime in hours, 0 when not hour-based."
    )
    expiration_timestamp: int = Field(
        default=0,
        description="Unix epoch seconds the key expires, 0 when it does not expire.",
    )
    created_timestamp: int = Field(default=0, description="Unix epoch seconds the key was created.")
    created_by_entity: str = Field(default="", description="Who or what created the key.")
    description: str = Field(
        default="", description="Operator description, clipped to 500 characters."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ApiKeyBrief:
        """Project a ``RESTApikey``.

        ``apikey_secret`` is NEVER read. The controller returns it only from the
        creation call; there is no recovery path and this tool must not imply one.
        """
        domains = raw.get("role_domains") or {}
        role_domains = (
            {
                str(role): [str(d) for d in (namespaces or [])]
                for role, namespaces in domains.items()
            }
            if isinstance(domains, dict)
            else {}
        )
        return cls(
            apikey_name=str(raw.get("apikey_name", "") or ""),
            role=str(raw.get("role", "") or ""),
            role_domains=role_domains,
            expiration_type=str(raw.get("expiration_type", "") or ""),
            expiration_hours=int(raw.get("expiration_hours") or 0),
            expiration_timestamp=int(raw.get("expiration_timestamp") or 0),
            created_timestamp=int(raw.get("created_timestamp") or 0),
            created_by_entity=str(raw.get("created_by_entity", "") or ""),
            description=_clip(str(raw.get("description", "") or ""), 500)[0],
        )


class ApiKeyList(BaseModel):
    """Result of ``nv_list_api_keys``."""

    model_config = _BASE

    page: Page
    api_keys: list[ApiKeyBrief]


# ----- 70-policy_write.py -----
class GroupCriterionInput(BaseModel):
    """One group membership criterion. Mirrors RESTCriteriaEntry."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        min_length=1,
        description="Criterion key, i.e. the workload attribute to test. Controller field "
        "names, e.g. 'domain' (Kubernetes namespace), 'image', 'service', 'label', "
        "'node', 'container'. Copy an exact key from an existing group's criteria via "
        "nv_get_group rather than guessing; an unknown key is rejected with code 6.",
    )
    op: str = Field(
        min_length=1,
        description="Comparison operator the controller defines for group criteria, e.g. '=' "
        "or 'contains'. This is NOT the query-filter operator set used by list tools. "
        "Copy an exact operator from an existing group via nv_get_group.",
    )
    value: str = Field(
        description="Value to compare the key against. May be empty for operators that take none."
    )


class NetworkRuleInput(BaseModel):
    """One network policy rule to insert or reconfigure. Mirrors RESTPolicyRule."""

    model_config = ConfigDict(extra="forbid")

    from_group: str = Field(
        min_length=1,
        description="Source group name (controller field 'from'). The group must already "
        "exist; get names from nv_list_groups.",
    )
    to_group: str = Field(
        min_length=1,
        description="Destination group name (controller field 'to'). The group must already exist.",
    )
    action: Literal["allow", "deny"] = Field(
        description="'allow' permits the connection; 'deny' blocks it in Protect mode and "
        "logs a violation in Monitor mode."
    )
    ports: str = Field(
        default="any",
        description="Free-style port list exactly as the controller stores it, e.g. "
        "'tcp/443,tcp/8080-8090', 'udp/53' or 'any'. Copy the format from an existing "
        "rule via nv_list_network_rules.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Layer-7 application names the rule is scoped to, e.g. ['HTTP']. "
        "Empty means any application.",
    )
    comment: str = Field(
        default="",
        description="Free-text comment stored on the rule. Say why the rule exists; it is the "
        "only provenance an operator gets later.",
    )
    disable: bool = Field(
        default=False,
        description="True stores the rule but does not enforce it. Insert a risky rule disabled "
        "first, confirm it matches what you expect, then enable it.",
    )
    id: int | None = Field(
        default=None,
        ge=0,
        description="Existing rule id. REQUIRED for configure_rules, must be omitted for "
        "insert_rules (the controller assigns the id).",
    )


class ProcessProfileEntryInput(BaseModel):
    """One process profile entry to add, change or remove. Mirrors RESTProcessProfileEntryConfig."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        description="Process name as the enforcer reports it, e.g. 'nginx'. Match the exact "
        "spelling from nv_get_process_profile or from the 'process' incident that prompted "
        "this change.",
    )
    path: str = Field(
        min_length=1,
        description="Absolute executable path, e.g. '/usr/sbin/nginx'. Required by the "
        "controller; use '*' to mean any path only if an existing entry already does.",
    )
    action: Literal["allow", "deny"] = Field(
        description="'allow' permits the process; 'deny' blocks it. In Protect mode 'deny' "
        "kills the process immediately."
    )


class FileMonitorFilterInput(BaseModel):
    """One file-monitor filter to add, update or remove. Mirrors RESTFileMonitorFilterConfig."""

    model_config = ConfigDict(extra="forbid")

    filter: str = Field(
        min_length=1,
        description="Path or glob to watch, e.g. '/etc/nginx/*'. Copy the exact form from "
        "nv_get_file_monitor_profile.",
    )
    recursive: bool = Field(
        default=False, description="True watches subdirectories of the path as well."
    )
    behavior: str = Field(
        default="monitor",
        description="What the enforcer does on a hit: 'monitor' records a file incident and "
        "allows the write, 'block' denies the write in Protect mode. Values are not "
        "enumerated in the schema reference; copy an existing filter's value if unsure.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Processes the filter applies to. Empty means any process.",
    )


# ----- 90-scan_ops.py -----
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
    digest: str = Field(
        default="",
        description="Image digest; the reproducible identity of what was scanned.",
    )
    size: int = Field(default=0, description="Image size in bytes.")
    base_os: str = Field(default="", description="Base OS the scanner detected.")
    created_at: str = Field(default="", description="Image creation timestamp.")
    cvedb_version: str = Field(
        default="",
        description="CVE database version used; results are only as fresh as this.",
    )
    layer_count: int = Field(
        default=0, description="Layers reported; 0 unless scan_layers was true."
    )
    module_count: int = Field(default=0, description="Software modules the scanner inventoried.")
    counts: SeverityCounts = Field(
        description="Counts over the WHOLE report, before any filtering."
    )
    matched: int = Field(
        default=0, description="Vulnerabilities left after min_severity and fixable_only."
    )
    page: Page = Field(description="Paging envelope for the capped vulnerability list.")
    vulnerabilities: list[VulnerabilityFinding] = Field(
        default_factory=list,
        description="Worst-first, filtered and capped. Empty when summary_only.",
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
    ) -> RepositoryScanReport:
        """Project a ``RESTScanRepoReport``.

        ``envs`` and ``labels`` are deliberately DROPPED: container environment
        variables routinely carry credentials, and this server must not surface a
        secret it was not asked for. Filtering, sorting and capping are identical
        to ``ScanReport.from_api``.
        """
        all_vulns = [v for v in (raw.get("vulnerabilities") or []) if isinstance(v, dict)]
        counts = SeverityCounts.from_api(all_vulns)

        floor = severity_rank(min_severity) if min_severity else -1
        selected = [
            v
            for v in all_vulns
            if severity_rank(v.get("severity")) >= floor
            and (not fixable_only or str(v.get("fixed_version", "") or ""))
        ]
        selected.sort(
            key=lambda v: (
                -severity_rank(v.get("severity")),
                -float(v.get("score_v3") or 0.0),
                -float(v.get("score") or 0.0),
                str(v.get("name", "") or ""),
            )
        )
        shown = [] if summary_only else selected[:max_vulnerabilities]
        truncated = len(selected) > len(shown)
        return cls(
            image_ref=image_ref,
            verdict=str(raw.get("verdict", "") or ""),
            image_id=str(raw.get("image_id", "") or ""),
            digest=str(raw.get("digest", "") or ""),
            size=int(raw.get("size") or 0),
            base_os=str(raw.get("base_os", "") or ""),
            created_at=str(raw.get("created_at", "") or ""),
            cvedb_version=str(raw.get("cvedb_version", "") or ""),
            layer_count=len(raw.get("layers") or []),
            module_count=len(raw.get("modules") or []),
            counts=counts,
            matched=len(selected),
            page=Page(
                start=0,
                returned=len(shown),
                truncated=truncated,
                hint=(
                    (
                        f"{len(selected)} vulnerabilities matched; {len(shown)} returned. "
                        "Narrow with min_severity, set fixable_only=true, or raise "
                        "max_vulnerabilities."
                    )
                    if truncated
                    else None
                ),
            ),
            vulnerabilities=[VulnerabilityFinding.from_api(v) for v in shown],
        )
