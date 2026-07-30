class ComplianceCheck(BaseModel):
    """One CIS or compliance check result."""

    model_config = _BASE

    test_number: str = Field(description="Check id, e.g. K.1.2.3 or D.5.4.")
    level: str = Field(
        default="", description="Outcome as the controller words it, e.g. PASS, WARN, INFO or NOTE."
    )
    catalog: str = Field(default="", description="Catalogue this check belongs to, e.g. kubernetes or docker.")
    type: str = Field(default="", description="What the check applies to, e.g. host, container or image.")
    profile: str = Field(default="", description="CIS profile, e.g. Level 1 or Level 2.")
    scored: bool = Field(default=False, description="True when the check counts toward the CIS score.")
    automated: bool = Field(
        default=False, description="False means the check needs a human to verify it."
    )
    description: str = Field(default="", description="What the check tests.")
    message: list[str] = Field(
        default_factory=list, description="Evidence the enforcer collected, one line per entry."
    )
    remediation: str = Field(default="", description="How to fix it, from the CIS benchmark text.")
    group: str = Field(default="", description="Group this check was reported for, when applicable.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "ComplianceCheck":
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
    kubernetes_cis_version: str = Field(default="", description="Kubernetes CIS benchmark version used.")
    kubernetes_cis_category: str = Field(default="", description="Node category tested, e.g. master or worker.")
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
    ) -> "ComplianceFindings":
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
    ) -> "BenchReport":
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
    def from_api(cls, raw: dict[str, Any]) -> "ComplianceProfileBrief":
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
    profiles: list[ComplianceProfileBrief] = Field(
        description="Compliance profiles in this page."
    )


class ComplianceProfileEntry(BaseModel):
    """One per-check tag override."""

    model_config = _BASE

    test_number: str = Field(description="Check id this override applies to, e.g. K.1.2.3.")
    tags: list[str] = Field(
        default_factory=list,
        description="Compliance standards the check counts towards, e.g. PCI, GDPR, HIPAA.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "ComplianceProfileEntry":
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
    def from_api(cls, raw: dict[str, Any], *, max_entries: int = 100) -> "ComplianceProfile":
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
