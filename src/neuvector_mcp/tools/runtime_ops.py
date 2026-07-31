"""Runtime response actions on live workloads and services. Toolset ``runtime_ops``.

Every tool here follows the five-step mutating body of SPEC 7.4, in this order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

These four tools act on running containers, not on stored configuration. Two of
them are traffic-affecting the moment the controller accepts them: quarantine
severs a container's network, and a move to Protect starts blocking anything the
learned policy does not already allow. The docstrings say so in those words
because the docstring is what the model reads before it decides.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..errors import GuardError, ValidationError_
from ..guard import authorise_write
from ..models import WriteOutcome, redact_secrets, service_namespace

#: Creates something, or starts an action, that did not exist before. Not
#: destructive; not idempotent (a second call creates or starts again).
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
#: Reversible configuration change. Re-applying the same arguments is a no-op.
MUTATING_UPDATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Destroys a stored object. A second call fails with controller code 7.
MUTATING_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
#: Traffic-affecting but converging: re-applying the same arguments is a no-op.
MUTATING_DESTRUCTIVE_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
)

#: ``scope`` -> controller route. All three take the same body type,
#: ``RESTServiceBatchConfigData``; the dimension is chosen by the path, which is
#: why there is no ``profile_mode`` field on the request body.
_SERVICE_MODE_PATHS: dict[str, str] = {
    "both": "/v1/service/config",
    "network": "/v1/service/config/network",
    "profile": "/v1/service/config/profile",
}


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the runtime_ops toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("runtime_ops"):
        return

    @mcp.tool(
        name="nv_quarantine_workload",
        annotations=MUTATING_DESTRUCTIVE_IDEMPOTENT,
        tags={"runtime_ops", "write"},
    )
    async def nv_quarantine_workload(
        ctx: Context,
        workload_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Workload (container) id from nv_list_workloads or nv_get_workload.",
            ),
        ],
        namespace: Annotated[
            str,
            Field(
                min_length=1,
                description="Namespace the workload runs in, from nv_list_workloads. Used only "
                "to enforce NV_ALLOWED_NAMESPACES; it is not sent to the controller. Required so "
                "that a mis-typed id cannot escape the namespace allowlist.",
            ),
        ],
        action: Annotated[
            Literal["quarantine", "unquarantine"],
            Field(
                description="'quarantine' cuts the container off the network; 'unquarantine' "
                "restores it."
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Cut a running container off the network, or restore it.

        The highest blast radius of any tool in this server. Quarantine severs the
        container's network connectivity while leaving the process running: every
        inbound and outbound connection stops, so if the container serves live traffic
        that traffic fails immediately and any dependent service fails with it. Nothing
        is deleted and the container is not restarted - call again with
        action='unquarantine' to restore it. Check the workload's 'state' with
        nv_list_workloads first: a workload already showing 'quarantined' does not need
        this, and a workload the platform will not let NeuVector quarantine is refused
        with code 4. A stopped container is refused with code 22.

        Calls POST /v1/workload/request/{id} with {"request": {"command": ...}}.
        """
        app = app_context(ctx)
        wire_payload: dict[str, Any] = {"request": {"command": action}}

        plan = authorise_write(
            app.settings,
            operation="nv_quarantine_workload",
            toolset="runtime_ops",
            target=workload_id,
            effect=(
                f"Sever all network connectivity of container {workload_id!r} in namespace "
                f"{namespace!r}. Live traffic to and from it will fail immediately."
                if action == "quarantine"
                else (
                    f"Restore network connectivity of container {workload_id!r} in namespace "
                    f"{namespace!r}."
                )
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=namespace,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "POST", f"/v1/workload/request/{workload_id}", json=wire_payload
        )
        return WriteOutcome(
            status="applied",
            operation="nv_quarantine_workload",
            target=workload_id,
            effect=f"{action} applied to container {workload_id}",
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_set_service_mode",
        annotations=MUTATING_UPDATE,
        tags={"runtime_ops", "write"},
    )
    async def nv_set_service_mode(
        ctx: Context,
        services: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Service (group) names from nv_list_services, e.g. "
                "['api.prod', 'web.prod']. All of them get the same settings in one "
                "controller call.",
            ),
        ],
        scope: Annotated[
            Literal["both", "network", "profile"],
            Field(
                description="Which dimension to change: 'network' sets only network policy "
                "enforcement, 'profile' sets only process and file profile enforcement, 'both' "
                "sets them together. Use 'network' or 'profile' when you want to enforce one "
                "dimension while still learning the other."
            ),
        ] = "both",
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(
                description="Discover learns behaviour, Monitor alerts only, Protect BLOCKS. "
                "Omit to leave the mode unchanged."
            ),
        ] = None,
        baseline_profile: Annotated[
            str | None,
            Field(
                description="Process baseline strictness, verbatim controller string; see "
                "'baseline_profile' on an existing service via nv_list_services for the values "
                "in use. Only meaningful with scope='profile' or 'both'."
            ),
        ] = None,
        not_scored: Annotated[
            bool | None,
            Field(description="True excludes these services from the cluster security score."),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Set the enforcement mode of one or more services in a single call.

        Traffic-affecting: moving a service to Protect starts BLOCKING connections and
        process activity that its learned policy does not allow, for every container in
        that service at once, and a service whose learning was incomplete will break the
        moment you do it. Preview first and read the service list in the plan. 'scope'
        picks the dimension: 'network' enforces network policy only, 'profile' enforces
        process and file profiles only, 'both' does the two together - a common safe
        sequence is network first, profile once process learning has settled. Get names
        from nv_list_services, and check each service's current policy_mode and
        profile_mode there before changing them.

        Calls PATCH /v1/service/config with scope='both'.
        Calls PATCH /v1/service/config/network with scope='network'.
        Calls PATCH /v1/service/config/profile with scope='profile'.
        """
        app = app_context(ctx)
        # sorted(): the batch has set semantics, and a stable order keeps the
        # confirm token independent of the order the caller listed the services in.
        config: dict[str, Any] = {"services": sorted(services)}
        for key, value in (
            ("policy_mode", policy_mode),
            ("baseline_profile", baseline_profile),
            ("not_scored", not_scored),
        ):
            if value is not None:
                config[key] = value
        if len(config) == 1:
            raise ValidationError_(
                "nv_set_service_mode needs at least one of policy_mode, baseline_profile or "
                "not_scored. No request was sent."
            )
        wire_payload: dict[str, Any] = {"config": config}
        path = _SERVICE_MODE_PATHS[scope]

        # D.0.5: authorise_write() takes one namespace and this batch may span
        # several, so narrow first - refuse the whole batch if any service sits
        # outside the allowlist, then let the guard run as usual.
        namespaces = sorted({service_namespace(name) for name in services} - {""})
        allowed = app.settings.allowed_namespaces
        if allowed:
            outside = sorted(name for name in namespaces if name not in allowed)
            if outside:
                raise GuardError(
                    f"nv_set_service_mode targets namespaces {outside}, which are outside "
                    f"NV_ALLOWED_NAMESPACES ({sorted(allowed)}). No request was sent."
                )
        guard_namespace = namespaces[0] if len(namespaces) == 1 else None

        target = ",".join(sorted(services))
        effect = (
            f"Set {', '.join(f'{k}={v!r}' for k, v in sorted(config.items()) if k != 'services')} "
            f"on {len(services)} service(s): {', '.join(sorted(services))} (scope={scope})."
            + (
                " Traffic and process activity outside the learned policy will be blocked "
                "immediately."
                if policy_mode == "Protect"
                else ""
            )
        )

        plan = authorise_write(
            app.settings,
            operation="nv_set_service_mode",
            toolset="runtime_ops",
            target=target,
            effect=effect,
            payload=wire_payload,
            confirm=confirm,
            namespace=guard_namespace,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", path, json=wire_payload)
        return WriteOutcome(
            status="applied",
            operation="nv_set_service_mode",
            target=target,
            effect=f"settings applied to {len(services)} service(s) with scope={scope}",
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_start_packet_capture",
        annotations=MUTATING_CREATE,
        tags={"runtime_ops", "write"},
    )
    async def nv_start_packet_capture(
        ctx: Context,
        workload_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Workload (container) id whose traffic to capture, from "
                "nv_list_workloads.",
            ),
        ],
        namespace: Annotated[
            str,
            Field(
                min_length=1,
                description="Namespace the workload runs in, from nv_list_workloads. Used only "
                "to enforce NV_ALLOWED_NAMESPACES; it is not sent to the controller. Required "
                "because a packet capture is privacy-sensitive and must not be startable "
                "outside the allowed namespaces by a mis-typed id.",
            ),
        ],
        duration_s: Annotated[
            int,
            Field(
                ge=1,
                le=3600,
                description="Seconds to capture for. Keep it short: a capture on a busy "
                "container fills the enforcer's disk quickly.",
            ),
        ] = 60,
        filter: Annotated[  # noqa: A002 - controller field name; see RESTSnifferArgs.filter
            str,
            Field(
                description="Berkeley Packet Filter expression, e.g. 'tcp port 443'. Strongly "
                "recommended - an unfiltered capture records every packet, including other "
                "tenants' payloads if the container proxies them."
            ),
        ] = "",
        file_number: Annotated[
            int,
            Field(
                ge=1,
                le=10,
                description="Number of rotating capture files the enforcer keeps. More files "
                "means a longer window and more disk.",
            ),
        ] = 1,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Start a packet capture on one running container.

        Privacy-sensitive: this records the container's actual network traffic, payloads
        included, onto the enforcer's disk. Anything the container carries in clear -
        credentials, personal data, another tenant's requests - lands in that file, so
        scope it with a BPF 'filter' and the shortest 'duration_s' that answers your
        question, and treat the result as regulated data. The capture file is NOT
        retrievable through this server: the controller serves it from
        GET /v1/sniffer/{id}/pcap as a binary payload, which is unsuitable for an MCP
        result, so this server does not expose it. Fetch the pcap out of band with the
        NeuVector UI or a direct authenticated HTTP call, then analyse it there. Stop
        the capture early with nv_stop_packet_capture.

        Calls POST /v1/sniffer with f_workload and {"sniffer": {...}}.
        """
        app = app_context(ctx)
        params = build_query(filters={"workload": workload_id})
        wire_payload: dict[str, Any] = {
            "sniffer": {"file_number": file_number, "duration": duration_s, "filter": filter}
        }

        plan = authorise_write(
            app.settings,
            operation="nv_start_packet_capture",
            toolset="runtime_ops",
            target=workload_id,
            effect=(
                f"Capture up to {duration_s}s of network traffic from container {workload_id!r} "
                f"in namespace {namespace!r} into {file_number} file(s) on the enforcer"
                + (
                    f", filtered by {filter!r}."
                    if filter
                    else ". NO FILTER IS SET, so every packet including payloads will be recorded."
                )
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=namespace,
        )
        if plan is not None:
            return plan

        response = await app.client.request("POST", "/v1/sniffer", params=params, json=wire_payload)
        return WriteOutcome(
            status="applied",
            operation="nv_start_packet_capture",
            target=workload_id,
            effect=f"packet capture started on container {workload_id}",
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_stop_packet_capture",
        annotations=MUTATING_UPDATE,
        tags={"runtime_ops", "write"},
    )
    async def nv_stop_packet_capture(
        ctx: Context,
        capture_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Capture id, as returned in controller_response by "
                "nv_start_packet_capture.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Stop a running packet capture.

        Stops the enforcer writing further packets and leaves the file it has already
        written in place, so this reduces exposure rather than eliminating it - the
        captured traffic still exists on the enforcer until it is removed out of band.
        Do this as soon as you have what you need, and always for an unfiltered capture.
        The capture id comes from the controller_response of nv_start_packet_capture;
        this server exposes no way to list captures, so keep the id.

        Calls PATCH /v1/sniffer/stop/{id}.
        """
        app = app_context(ctx)
        # namespace=None: a capture id carries no namespace and the workload it
        # belongs to is not knowable from the id alone. NV_ALLOWED_NAMESPACES was
        # applied when the capture was started; it cannot be re-applied here.
        plan = authorise_write(
            app.settings,
            operation="nv_stop_packet_capture",
            toolset="runtime_ops",
            target=capture_id,
            effect=(
                f"Stop packet capture {capture_id!r}. Packets already written stay on the enforcer."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/sniffer/stop/{capture_id}")
        return WriteOutcome(
            status="applied",
            operation="nv_stop_packet_capture",
            target=capture_id,
            effect=f"packet capture {capture_id} stopped",
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )
