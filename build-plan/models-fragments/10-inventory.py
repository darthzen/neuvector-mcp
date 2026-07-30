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
    fullname: str = Field(default="", description="Fully qualified user name including server prefix.")
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
    def from_api(cls, raw: dict[str, Any]) -> "Identity":
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
    def from_cached(cls, identity: dict[str, Any], *, note: str) -> "Identity":
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
    med_vuls: int = Field(default=0, description="Medium-severity vulnerabilities in the host scan.")
    scan_status: str = Field(default="", description="Host scan status, e.g. finished or unscanned.")
    cap_kube_bench: bool = Field(
        default=False, description="True when nv_get_bench_report(benchmark='kubernetes') is possible."
    )
    cap_docker_bench: bool = Field(
        default=False, description="True when nv_get_bench_report(benchmark='docker') is possible."
    )
    kube_bench_status: str = Field(default="", description="Last Kubernetes CIS run status.")
    docker_bench_status: str = Field(default="", description="Last Docker CIS run status.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "HostBrief":
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
    namespace: str = Field(default="", description="Kubernetes namespace (controller field 'domain').")
    policy_mode: PolicyMode = Field(default="", description="Policy mode applied to members.")
    kind: str = Field(default="", description="Group kind, e.g. container, node or address.")
    learned: bool = Field(default=False, description="True when NeuVector created this group itself.")
    reserved: bool = Field(default=False, description="True for built-in groups that cannot be deleted.")
    platform_role: str = Field(default="", description="Platform role, e.g. system, when set.")
    member_count: int = Field(default=0, description="Number of workloads currently in the group.")
    policy_rule_count: int = Field(default=0, description="Network rules referencing this group.")
    response_rule_count: int = Field(default=0, description="Response rules referencing this group.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "GroupBrief":
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
    def from_api(cls, raw: dict[str, Any]) -> "GroupCriterion":
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
    namespace: str = Field(default="", description="Kubernetes namespace (controller field 'domain').")
    policy_mode: PolicyMode = Field(default="", description="Policy mode applied to members.")
    kind: str = Field(default="", description="Group kind, e.g. container, node or address.")
    learned: bool = Field(default=False, description="True when NeuVector created this group itself.")
    reserved: bool = Field(default=False, description="True for built-in groups that cannot be modified.")
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
        default_factory=list, description="Membership criteria; all must match for a workload to join."
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
    def from_api(cls, raw: dict[str, Any], *, max_members: int = 20) -> "GroupDetail":
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
                int(r.get("id") or 0) for r in (raw.get("policy_rules") or []) if isinstance(r, dict)
            ],
            response_rule_ids=[
                int(r.get("id") or 0) for r in (raw.get("response_rules") or []) if isinstance(r, dict)
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
    namespace: str = Field(default="", description="Kubernetes namespace (controller field 'domain').")
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
    def from_api(cls, raw: dict[str, Any]) -> "ServiceBrief":
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
    namespace: str = Field(default="", description="Namespace of the enforcer pod (controller field 'domain').")
    cluster_ip: str = Field(default="", description="Address the controller reaches it on.")
    connection_state: str = Field(
        default="", description="connected | disconnected. Anything but connected means no enforcement."
    )
    joined_at: str = Field(default="", description="When this enforcer joined the cluster.")
    disconnected_at: str = Field(default="", description="When it last disconnected, when applicable.")
    cpus: str = Field(default="", description="CPU allocation as the controller reports it.")
    memory_limit: int = Field(default=0, description="Memory limit in bytes; 0 means unlimited.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "EnforcerBrief":
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
    workloads: int = Field(default=0, description="Containers known in this namespace, running or not.")
    running_workloads: int = Field(default=0, description="Running containers.")
    running_pods: int = Field(default=0, description="Running pods.")
    services: int = Field(default=0, description="NeuVector services in this namespace.")
    tags: list[str] = Field(
        default_factory=list,
        description="Compliance standards tagged on this namespace, e.g. PCI or GDPR.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "NamespaceBrief":
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
    def from_api(cls, raw: dict[str, Any]) -> "Conversation":
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
