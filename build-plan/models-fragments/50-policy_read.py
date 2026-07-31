class NetworkRule(BaseModel):
    """One network policy rule."""

    model_config = _BASE

    id: int = Field(
        description="Rule id; pass to nv_get_network_rule or nv_delete_network_rule."
    )
    order: int = Field(
        default=0,
        description="Zero-based position in the controller's evaluation order, counted from the "
        "start of the whole list, not of this page. Lower wins.",
    )
    from_group: str = Field(default="", description="Source group name (controller field 'from').")
    to_group: str = Field(
        default="", description="Destination group name (controller field 'to')."
    )
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
    scope: str = Field(
        default="local", description="Scope the rules were read from: local or fed."
    )
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
    recursive: bool = Field(
        default=False, description="True when subdirectories are watched too."
    )
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
    order: int = Field(
        default=0, description="Zero-based absolute position in evaluation order."
    )
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
    disable: bool = Field(
        default=False, description="True when the rule is present but inactive."
    )
    cfg_type: str = Field(
        default="", description="Provenance: user_created | ground | federal."
    )
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
    scope: str = Field(
        default="local", description="Scope the rules were read from: local or fed."
    )
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
    adm_svc_type: str = Field(
        default="", description="Service type backing the admission webhook."
    )
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
    cfg_type: str = Field(
        default="", description="Provenance: user_created | ground | federal."
    )
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
    scope: str = Field(
        default="local", description="Scope the rules were read from: local or fed."
    )
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
    disabled: bool = Field(
        default=False, description="True when that rule is currently disabled."
    )
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
    kind: str = Field(
        default="", description="Kubernetes kind of the object, e.g. Deployment."
    )
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
    denied_count: int = Field(
        default=0, description="Returned results whose verdict was deny."
    )
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
