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
