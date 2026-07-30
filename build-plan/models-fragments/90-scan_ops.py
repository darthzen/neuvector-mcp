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
    module_count: int = Field(
        default=0, description="Software modules the scanner inventoried."
    )
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
    ) -> "RepositoryScanReport":
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
