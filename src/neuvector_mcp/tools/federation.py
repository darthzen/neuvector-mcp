"""Read-only federation status and selected member queries."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import PermissionError_, ValidationError_
from ..models import AdmissionState, GroupBrief, HostBrief, ScanStatus, SecurityEvent, WorkloadBrief

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)


def _cluster(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    return {key: raw[key] for key in ("id", "name", "status", "rest_version") if key in raw}


def register(mcp: FastMCP, settings: Settings) -> None:
    """Register federation reads when enabled explicitly."""
    if not settings.toolset_enabled("federation_read"):
        return

    @mcp.tool(
        name="nv_get_federation_status", annotations=READ_ONLY, tags={"federation_read", "read"}
    )
    async def nv_get_federation_status(ctx: Context) -> dict[str, Any]:
        """Get federation role and member names, status and REST versions.

        Credentials and connection details are excluded.

        Calls GET /v1/fed/member.
        """
        raw = await app_context(ctx).client.request("GET", "/v1/fed/member")
        return {
            "fed_role": raw.get("fed_role", ""),
            "master_cluster": _cluster(raw.get("master_cluster")),
            "joint_clusters": [_cluster(x) for x in (raw.get("joint_clusters") or [])],
        }

    @mcp.tool(
        name="nv_query_federation_member", annotations=READ_ONLY, tags={"federation_read", "read"}
    )
    async def nv_query_federation_member(
        ctx: Context,
        cluster: Annotated[
            str, Field(min_length=1, description="Exact joint cluster name from federation status.")
        ],
        resource: Literal[
            "groups",
            "hosts",
            "workloads",
            "scan_status",
            "threats",
            "violations",
            "incidents",
            "admission_state",
        ],
        start: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 50,
    ) -> dict[str, Any]:
        """Read a fixed selection of resources from a joint cluster through the master.

        Requires a federation master and fedAdmin, fedReader or equivalent federation
        read permission. Cluster names are resolved against the current member list;
        unknown or ambiguous names are rejected. Only GET requests can be forwarded.

        Calls GET /v1/fed/member.
        Calls GET /v1/fed/cluster/{id}/{request}.
        """
        app = app_context(ctx)
        membership = await app.client.request("GET", "/v1/fed/member")
        if membership.get("fed_role") != "master":
            raise ValidationError_("Federation member reads require a master controller.")
        matches = [
            x
            for x in (membership.get("joint_clusters") or [])
            if isinstance(x, dict) and x.get("name") == cluster
        ]
        if len(matches) != 1:
            raise ValidationError_(
                "Cluster name is unknown or ambiguous; inspect federation status."
            )
        cluster_id = matches[0].get("id")
        if not isinstance(cluster_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", cluster_id):
            raise ValidationError_("The controller returned an invalid member id.")
        routes = {
            "groups": ("/v1/group", "groups"),
            "hosts": ("/v1/host", "hosts"),
            "workloads": ("/v2/workload", "workloads"),
            "scan_status": ("/v1/scan/status", ""),
            "threats": ("/v1/log/threat", "threats"),
            "violations": ("/v1/log/violation", "violations"),
            "incidents": ("/v1/log/incident", "incidents"),
            "admission_state": ("/v1/admission/state", ""),
        }
        path, envelope = routes[resource]
        cap = min(limit, app.settings.max_items)
        params = {"start": str(start), "limit": str(cap + 1)} if envelope else {}
        try:
            body = await app.client.request(
                "GET", f"/v1/fed/cluster/{cluster_id}{path}", params=params
            )
        except PermissionError_ as exc:
            raise PermissionError_(
                "Federation proxy access denied: fedAdmin, fedReader or equivalent federation read permission is required."
            ) from exc
        if resource == "scan_status":
            return {"cluster": cluster, "result": ScanStatus.from_api(body).model_dump()}
        if resource == "admission_state":
            return {"cluster": cluster, "result": AdmissionState.from_api(body).model_dump()}
        items = body.get(envelope) or []
        items = [item for item in items if isinstance(item, dict)]
        results: list[dict[str, Any]] = []
        for item in items[:cap]:
            result: GroupBrief | HostBrief | WorkloadBrief | SecurityEvent
            if resource == "groups":
                result = GroupBrief.from_api(item)
            elif resource == "hosts":
                result = HostBrief.from_api(item)
            elif resource == "workloads":
                result = WorkloadBrief.from_api(item)
            else:
                kind: Literal["threat", "violation", "incident"] = (
                    "threat"
                    if resource == "threats"
                    else "violation"
                    if resource == "violations"
                    else "incident"
                )
                result = SecurityEvent.from_api(item, kind=kind)
            results.append(result.model_dump())
        return {
            "cluster": cluster,
            "start": start,
            "truncated": len(items) > cap,
            "results": results,
        }
