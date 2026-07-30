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
    state: str = Field(default="", description="exit | unmanaged | discover | monitor | protect | quarantined.")
    policy_mode: PolicyMode = Field(default="", description="Effective policy mode.")
    high_vuls: int = Field(default=0, description="High-severity vulnerability count.")
    med_vuls: int = Field(default=0, description="Medium-severity vulnerability count.")
    host_name: str = Field(default="", description="Node the workload runs on.")
    running: bool = Field(default=False, description="True when the container is running.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "WorkloadBrief":
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
    def from_api(cls, raw: dict[str, Any]) -> "SystemSummary":
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
