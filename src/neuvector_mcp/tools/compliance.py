"""Compliance tools: CIS benchmark results, compliance findings and profiles.

Every tool in this module is read-only and tagged ``compliance``.

Registration contract (identical in every tools/*.py module):

    def register(mcp: FastMCP, settings: Settings) -> None: ...

``register`` adds tools only when their toolset is enabled, so a disabled
toolset is absent from ``tools/list`` rather than present-and-failing.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..models import (
    BenchReport,
    ComplianceFindings,
    ComplianceProfile,
    ComplianceProfileBrief,
    ComplianceProfileList,
    Page,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

#: Path suffix per ``scope`` for nv_get_compliance_findings. Validated locally so a
#: bad discriminator never reaches the controller (PHASE-4).
_COMPLIANCE_SCOPES: frozenset[str] = frozenset({"workload", "host"})

#: Benchmarks nv_get_bench_report may request. Same local-validation rule.
_BENCHMARKS: frozenset[str] = frozenset({"kubernetes", "docker"})


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the compliance toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("compliance"):
        return

    @mcp.tool(
        name="nv_get_compliance_findings",
        annotations=READ_ONLY,
        tags={"compliance", "read"},
    )
    async def nv_get_compliance_findings(
        ctx: Context,
        scope: Annotated[
            Literal["workload", "host"],
            Field(description="Whether target_id is a workload id or a host id."),
        ],
        target_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Workload id from nv_list_workloads, or host id from nv_list_hosts.",
            ),
        ],
        level: Annotated[
            str | None,
            Field(
                description="Keep only checks whose 'level' equals this value, compared "
                "case-insensitively. The controller emits values such as PASS, WARN, INFO, "
                "NOTE and ERROR; no enum is documented."
            ),
        ] = None,
        catalog: Annotated[
            str | None,
            Field(
                description="Keep only checks from one catalogue, compared case-insensitively, "
                "e.g. docker, kubernetes, image or custom."
            ),
        ] = None,
        max_checks: Annotated[
            int,
            Field(
                ge=0, le=500, description="Maximum checks to return. 0 returns level_counts only."
            ),
        ] = 50,
    ) -> ComplianceFindings:
        """CIS and compliance check results for one workload or one node.

        level_counts is the answer to "is this thing compliant"; the checks list is the
        evidence, and it is long, so filter with level='WARN' to see only failures
        before raising max_checks. A workload report covers image and container checks,
        a host report covers node and runtime checks, so both are usually needed for a
        full picture. Ids come from nv_list_workloads and nv_list_hosts.

        Calls GET /v1/workload/{id}/compliance with scope='workload'.
        Calls GET /v1/host/{id}/compliance with scope='host'.
        """
        from ..errors import NotFoundError, ValidationError_

        if scope not in _COMPLIANCE_SCOPES:
            # Discriminator is checked before any network call (PHASE-4).
            raise ValidationError_(f"scope must be 'workload' or 'host', got {scope!r}")
        app = app_context(ctx)
        path = (
            f"/v1/workload/{target_id}/compliance"
            if scope == "workload"
            else f"/v1/host/{target_id}/compliance"
        )
        # Bench data may be fetched from the enforcer over RPC: long timeout (SPEC 5).
        raw = await app.client.request("GET", path, timeout_s=app.settings.long_request_timeout_s)
        if not isinstance(raw, dict) or not raw:
            raise NotFoundError(f"no compliance report for {scope} {target_id!r}")
        return ComplianceFindings.from_api(
            raw,
            scope=scope,
            target_id=target_id,
            level=level,
            catalog=catalog,
            max_checks=min(max_checks, app.settings.max_items),
        )

    @mcp.tool(
        name="nv_get_bench_report",
        annotations=READ_ONLY,
        tags={"compliance", "read"},
    )
    async def nv_get_bench_report(
        ctx: Context,
        host_id: Annotated[str, Field(min_length=1, description="Host id from nv_list_hosts.")],
        benchmark: Annotated[
            Literal["kubernetes", "docker"],
            Field(
                description="Which CIS benchmark to read. Check cap_kube_bench or "
                "cap_docker_bench on the host first; a node that reports False cannot "
                "produce that report."
            ),
        ] = "kubernetes",
        level: Annotated[
            str | None,
            Field(
                description="Keep only checks whose 'level' equals this value, compared "
                "case-insensitively. The controller emits values such as PASS, WARN, INFO "
                "and NOTE; no enum is documented."
            ),
        ] = None,
        max_items: Annotated[
            int,
            Field(
                ge=0, le=500, description="Maximum checks to return. 0 returns level_counts only."
            ),
        ] = 50,
    ) -> BenchReport:
        """CIS benchmark report for one node, Kubernetes or Docker.

        Read level_counts first: it says how many checks failed without pulling the
        whole benchmark, which runs to hundreds of items. Filter level='WARN' for the
        failures. This reads the last stored run; it does not start a new one, so
        run_at may be old or the report may be empty if the node has never been
        benchmarked. Host ids come from nv_list_hosts.

        Calls GET /v1/bench/host/{id}/kubernetes with benchmark='kubernetes'.
        Calls GET /v1/bench/host/{id}/docker with benchmark='docker'.
        """
        from ..errors import NotFoundError, ValidationError_

        if benchmark not in _BENCHMARKS:
            # Discriminator is checked before any network call (PHASE-4).
            raise ValidationError_(f"benchmark must be 'kubernetes' or 'docker', got {benchmark!r}")
        app = app_context(ctx)
        path = f"/v1/bench/host/{host_id}/{benchmark}"
        # Read only. POST on these same paths starts a new run (Phase 9, scan_ops).
        raw = await app.client.request("GET", path, timeout_s=app.settings.long_request_timeout_s)
        if not isinstance(raw, dict) or not raw:
            raise NotFoundError(f"no {benchmark} benchmark report for host {host_id!r}")
        return BenchReport.from_api(
            raw,
            host_id=host_id,
            benchmark=benchmark,
            level=level,
            # settings.max_items is the hard ceiling; it is NOT the max_items argument.
            max_items=min(max_items, app.settings.max_items),
        )

    @mcp.tool(
        name="nv_list_compliance_profiles",
        annotations=READ_ONLY,
        tags={"compliance", "read"},
    )
    async def nv_list_compliance_profiles(
        ctx: Context,
        start: Annotated[int, Field(ge=0, description="Zero-based paging offset.")] = 0,
        limit: Annotated[int, Field(ge=1, le=1000, description="Maximum profiles to return.")] = 50,
    ) -> ComplianceProfileList:
        """List compliance profiles, which decide how CIS checks are tagged and scored.

        There is normally exactly one profile, named 'default'. Use this to confirm the
        name before calling nv_get_compliance_profile, and to see whether
        disable_system is set, because that turns off NeuVector's own built-in checks
        and changes what nv_get_compliance_findings reports.

        Calls GET /v1/compliance/profile.
        """
        app = app_context(ctx)
        effective_limit = min(limit, app.settings.max_items)

        params = build_query(
            start=start,
            limit=effective_limit + 1,  # over-fetch by one to detect truncation
        )
        items = await app.client.get_list("/v1/compliance/profile", "profiles", params=params)
        truncated = len(items) > effective_limit
        page_items = items[:effective_limit]
        return ComplianceProfileList(
            page=Page(
                start=start,
                returned=len(page_items),
                truncated=truncated,
                hint=(
                    f"More profiles exist. Call again with start={start + len(page_items)}."
                    if truncated
                    else None
                ),
            ),
            profiles=[ComplianceProfileBrief.from_api(item) for item in page_items],
        )

    @mcp.tool(
        name="nv_get_compliance_profile",
        annotations=READ_ONLY,
        tags={"compliance", "read"},
    )
    async def nv_get_compliance_profile(
        ctx: Context,
        profile_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Profile name from nv_list_compliance_profiles. Almost always "
                "'default'.",
            ),
        ] = "default",
        max_entries: Annotated[
            int,
            Field(
                ge=0,
                le=500,
                description="Maximum per-check overrides to return. 0 returns the count only.",
            ),
        ] = 100,
    ) -> ComplianceProfile:
        """One compliance profile with its per-check tag overrides.

        Each entry re-tags a single CIS check with the standards it should count
        towards, e.g. PCI or GDPR, which is what makes a check show up in one
        compliance report and not another. Read this when a check appears under an
        unexpected standard, or when disable_system is set and built-in checks have
        gone missing.

        Calls GET /v1/compliance/profile/{name}.
        """
        app = app_context(ctx)
        # Envelope key "profile" is convention-derived: Appendix B has no
        # RESTComplianceProfileData. A different wrapper yields {} -> NotFoundError,
        # which is preferable to returning wrong data.
        raw = await app.client.get_object(f"/v1/compliance/profile/{profile_name}", "profile")
        if not raw:
            from ..errors import NotFoundError

            raise NotFoundError(f"no compliance profile named {profile_name!r}")
        return ComplianceProfile.from_api(raw, max_entries=min(max_entries, app.settings.max_items))
