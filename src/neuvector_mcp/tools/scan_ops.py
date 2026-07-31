"""Vulnerability-scan, registry and CIS-benchmark operations. Toolset ``scan_ops``.

Every tool here follows the five-step mutating body of SPEC 7.4, in this order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

Three tools carry registry credentials (``nv_scan_repository``,
``nv_create_registry``, ``nv_update_registry``) and obey the two-payload rule of
Part D section D.0.4:

``wire_payload``
    the real body, with the real credential. Handed to
    ``app.client.request(json=...)`` and to nothing else.
``safe_payload = redact_secrets(wire_payload)``
    the same shape with every credential replaced by ``"***"``. Handed to the
    guard and placed in ``WriteOutcome.payload``.

The confirmation token is therefore computed over the *redacted* payload, so a
preview and its confirmed re-invocation agree. The deliberate consequence:
changing **only** the credential value between preview and confirm does not
invalidate the token. That is accepted (SPEC 6.1 calls the token "a guard rail,
not a security boundary") and is the price of never echoing a secret back to the
model. Do not "fix" it by hashing the wire payload - that breaks the handshake.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import ValidationError_
from ..guard import authorise_write
from ..models import RepositoryScanReport, WriteOutcome, redact_secrets

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


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the scan_ops toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("scan_ops"):
        return

    @mcp.tool(
        name="nv_trigger_scan",
        annotations=MUTATING_CREATE,
        tags={"scan_ops", "write"},
    )
    async def nv_trigger_scan(
        ctx: Context,
        target: Annotated[
            Literal["workload", "host", "registry"],
            Field(
                description="What to scan: 'workload' rescans one container's image, 'host' "
                "rescans one node, 'registry' starts a full scan of every image a configured "
                "registry matches."
            ),
        ],
        target_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Workload id from nv_list_workloads, host id from nv_list_hosts, or "
                "registry name from nv_list_registries, matching 'target'.",
            ),
        ],
        namespace: Annotated[
            str | None,
            Field(
                description="Namespace the workload runs in, from nv_list_workloads. Used only to "
                "enforce NV_ALLOWED_NAMESPACES; it is never sent to the controller. Ignored for "
                "host and registry scans."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Start a vulnerability scan of one workload, one host, or a whole registry.

        Asynchronous: the controller accepts the request and returns immediately, so an
        'applied' outcome means "scan queued", not "scan finished". Poll progress with
        nv_get_scan_status and read results with nv_get_scan_report. A registry scan is
        the expensive one - it walks every repository and tag the registry filters
        match, occupies shared scanner capacity for as long as that takes, and delays
        every other scan in the cluster; scope the registry's filters before starting
        one, and stop it with nv_stop_registry_scan if it was a mistake. Get ids from
        nv_list_workloads, nv_list_hosts or nv_list_registries.

        Calls POST /v1/scan/workload/{id} with target='workload'.
        Calls POST /v1/scan/host/{id} with target='host'.
        Calls POST /v1/scan/registry/{name}/scan with target='registry'.
        """
        app = app_context(ctx)
        # 1. build the payload: none of the three routes takes a request body.
        if target == "registry":
            path = f"/v1/scan/registry/{target_id}/scan"
            timeout_s: float | None = app.settings.long_request_timeout_s
            effect = (
                f"Start a full scan of registry {target_id!r}. Every matching repository and tag "
                "will be scanned; this occupies shared scanner capacity until it completes."
            )
        else:
            path = f"/v1/scan/{target}/{target_id}"
            timeout_s = None
            effect = f"Queue a rescan of {target} {target_id!r}."

        plan = authorise_write(  # 2. guard
            app.settings,
            operation="nv_trigger_scan",
            toolset="scan_ops",
            target=f"{target} {target_id}",
            effect=effect,
            payload=None,
            confirm=confirm,
            namespace=namespace if target == "workload" else None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request("POST", path, timeout_s=timeout_s)  # 4.
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_trigger_scan",
            target=f"{target} {target_id}",
            effect=f"scan of {target} {target_id} queued; poll nv_get_scan_status",
            payload={},
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_stop_registry_scan",
        annotations=MUTATING_UPDATE,
        tags={"scan_ops", "write"},
    )
    async def nv_stop_registry_scan(
        ctx: Context,
        registry_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Registry whose running scan to cancel, from nv_list_registries.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Cancel the scan currently running against one registry.

        Stops the scan in flight and frees the scanner capacity it was holding. Images
        already scanned keep their results, so nothing is lost - the registry is simply
        left partially scanned until the next scan, and nv_get_scan_status will show a
        lower 'scanned' count than 'scheduled'. Use this when a registry scan with
        overly broad filters is starving the rest of the cluster. Re-start it with
        nv_trigger_scan(target='registry').

        Calls DELETE /v1/scan/registry/{name}/scan.
        """
        app = app_context(ctx)
        # 1. no request body on this route.
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_stop_registry_scan",
            toolset="scan_ops",
            target=registry_name,
            effect=(
                f"Cancel the running scan of registry {registry_name!r}. Already-scanned images "
                "keep their results."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "DELETE", f"/v1/scan/registry/{registry_name}/scan"
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_stop_registry_scan",
            target=registry_name,
            effect=f"scan of registry {registry_name} cancelled",
            payload={},
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_scan_repository",
        annotations=MUTATING_CREATE,
        tags={"scan_ops", "write"},
    )
    async def nv_scan_repository(
        ctx: Context,
        repository: Annotated[
            str,
            Field(
                min_length=1,
                description="Repository path without the tag, e.g. 'library/nginx' or 'myorg/api'.",
            ),
        ],
        tag: Annotated[
            str,
            Field(
                min_length=1,
                description="Image tag to scan, e.g. '1.27.0'. Prefer an immutable tag or a "
                "digest-pinned tag; 'latest' makes the result unreproducible.",
            ),
        ],
        registry: Annotated[
            str,
            Field(
                description="Registry base URL, e.g. 'https://registry.example.com'. Leave empty "
                "for the scanner's default public registry."
            ),
        ] = "",
        username: Annotated[
            str | None,
            Field(description="Registry username, when the repository is private."),
        ] = None,
        password: Annotated[
            str | None,
            Field(
                description="Registry password or token. It is sent to the controller, is never "
                "logged, and is shown as '***' in the returned payload."
            ),
        ] = None,
        base_image: Annotated[
            str,
            Field(
                description="Base image reference, e.g. 'alpine:3.20'. When set, findings "
                "inherited from the base image are marked, so you can tell your CVEs from your "
                "base image's."
            ),
        ] = "",
        scan_layers: Annotated[
            bool,
            Field(
                description="True also reports which layer introduced each finding. Slower and "
                "much larger."
            ),
        ] = False,
        ignore_proxy: Annotated[
            bool,
            Field(
                description="True bypasses the cluster's configured registry proxy for this one "
                "pull."
            ),
        ] = False,
        summary_only: Annotated[
            bool,
            Field(
                description="True returns only the severity counts and no CVE detail. Always try "
                "this first."
            ),
        ] = False,
        min_severity: Annotated[
            Literal["Critical", "High", "Medium", "Low"] | None,
            Field(description="Keep only vulnerabilities at or above this severity."),
        ] = None,
        fixable_only: Annotated[
            bool,
            Field(
                description="True keeps only vulnerabilities that have a fixed version available."
            ),
        ] = False,
        max_vulnerabilities: Annotated[
            int,
            Field(
                ge=1,
                le=500,
                description="Hard cap on CVEs returned, applied after filtering and after sorting "
                "worst-first.",
            ),
        ] = 50,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Scan one image in a registry on demand and return its vulnerability report.

        This is the CI-style ad-hoc scan: nothing is stored, no registry has to be
        configured first, and the image does not have to be running anywhere. It is
        SYNCHRONOUS and slow - the controller pulls, unpacks and scans the image while
        your call waits, which can take minutes on a large image - so expect to wait up
        to NV_LONG_REQUEST_TIMEOUT_S. The report can carry thousands of CVEs, so it is
        projected and capped exactly like nv_get_scan_report: call with
        summary_only=true first for the counts, then narrow with min_severity and
        fixable_only. If credentials are needed, 'password' is sent to the controller
        but never logged and never echoed back - the returned payload shows '***'.

        Calls POST /v1/scan/repository with {"request": {...}}.
        """
        app = app_context(ctx)
        # 1. build the payload. RESTScanRepoReqData -> RESTScanRepoReq -> RESTScanMeta.
        #    The five empty RESTScanMeta strings are required fields, not placeholders.
        wire_payload: dict[str, Any] = {
            "request": {
                "metadata": {
                    "source": "neuvector-mcp",
                    "user": "",
                    "job": "",
                    "workspace": "",
                    "function": "",
                    "region": "",
                },
                "registry": registry,
                "repository": repository,
                "tag": tag,
                "scan_layers": scan_layers,
                "base_image": base_image,
                "ignore_proxy": ignore_proxy,
            }
        }
        if username is not None:
            wire_payload["request"]["username"] = username
        if password is not None:
            wire_payload["request"]["password"] = password
        safe_payload = redact_secrets(wire_payload)
        image_ref = (
            f"{registry.rstrip('/')}/{repository}:{tag}" if registry else f"{repository}:{tag}"
        )

        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_scan_repository",
            toolset="scan_ops",
            target=image_ref,
            effect=(
                f"Scan image {image_ref} now. This consumes shared scanner capacity for the "
                "duration of the scan and stores nothing on the controller."
            ),
            payload=safe_payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        body = await app.client.request(  # 4. synchronous scan: long timeout
            "POST",
            "/v1/scan/repository",
            json=wire_payload,
            timeout_s=app.settings.long_request_timeout_s,
        )
        raw = body.get("report") if isinstance(body, dict) else None
        report = RepositoryScanReport.from_api(
            raw if isinstance(raw, dict) else {},
            image_ref=image_ref,
            summary_only=summary_only,
            min_severity=min_severity,
            fixable_only=fixable_only,
            max_vulnerabilities=min(max_vulnerabilities, app.settings.max_items),
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_scan_repository",
            target=image_ref,
            effect=f"scanned {image_ref}: {report.counts.total} vulnerabilities found",
            payload=safe_payload,
            controller_response=report.model_dump(mode="json"),
        )

    @mcp.tool(
        name="nv_create_registry",
        annotations=MUTATING_CREATE,
        tags={"scan_ops", "write"},
    )
    async def nv_create_registry(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name for this registry entry inside NeuVector. It is the id every "
                "other registry tool takes; it is not the registry's hostname.",
            ),
        ],
        registry_type: Annotated[
            str,
            Field(
                min_length=1,
                description="Registry kind as the controller spells it, e.g. the value shown by "
                "nv_list_registries for an existing entry of the same kind. Pass it verbatim; the "
                "controller rejects an unknown kind with code 6.",
            ),
        ],
        registry: Annotated[
            str,
            Field(
                min_length=1,
                description="Registry base URL, e.g. 'https://registry.example.com' or "
                "'https://index.docker.io/'.",
            ),
        ],
        filters: Annotated[
            list[str],
            Field(
                description="Repository/tag patterns to include, e.g. ['myorg/*:release-*']. An "
                "empty list means EVERY repository in the registry, which on a large registry is "
                "a scanner-capacity incident waiting to happen."
            ),
        ] = [],  # noqa: B006 - never mutated; sorted into a fresh list before sending
        username: Annotated[
            str | None,
            Field(description="Registry username. Omit for an anonymous registry."),
        ] = None,
        password: Annotated[
            str | None,
            Field(
                description="Registry password. Stored by the controller, never logged here, and "
                "shown as '***' in the returned payload."
            ),
        ] = None,
        auth_token: Annotated[
            str | None,
            Field(
                description="Bearer token, as an alternative to username and password. Same "
                "redaction as 'password'."
            ),
        ] = None,
        auth_with_token: Annotated[
            bool,
            Field(
                description="True tells the controller to authenticate with 'auth_token' rather "
                "than username and password."
            ),
        ] = False,
        scan_layers: Annotated[
            bool,
            Field(
                description="True records which layer introduced each finding. Slower, and the "
                "stored reports are much larger."
            ),
        ] = False,
        rescan_after_db_update: Annotated[
            bool,
            Field(
                description="True rescans every matched image whenever the CVE database updates. "
                "Convenient, and a recurring capacity cost."
            ),
        ] = False,
        repo_limit: Annotated[
            int | None,
            Field(
                description="Maximum repositories to enumerate. Set this before pointing "
                "NeuVector at a large registry."
            ),
        ] = None,
        tag_limit: Annotated[
            int | None,
            Field(description="Maximum tags per repository to enumerate."),
        ] = None,
        ignore_proxy: Annotated[
            bool,
            Field(
                description="True bypasses the cluster's configured registry proxy for this "
                "registry."
            ),
        ] = False,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Register a container registry so NeuVector can scan the images in it.

        Creating the entry does not scan anything - it stores the connection and the
        repository filters; nv_trigger_scan(target='registry') starts the work. Set
        'filters', 'repo_limit' and 'tag_limit' before you create the entry: an
        unfiltered large registry will enumerate every repository and tag and starve
        every other scan in the cluster. Credentials are stored by the controller and
        are write-only from this server's point of view - 'password' and 'auth_token'
        are sent once, never logged, and shown as '***' in the returned payload, and no
        read tool can retrieve them afterwards. A duplicate name is rejected with code
        13. Credentials are nested under config.auth - sent flat the controller answers
        200 and stores the entry with no credentials at all.

        Calls POST /v2/scan/registry with {"config": {..., "auth": {...}}}.
        """
        app = app_context(ctx)
        # 1. build the payload. The V2 endpoint nests every credential field under
        #    "auth"; sent flat they are SILENTLY DROPPED - the controller answers 200
        #    and stores an entry with no credentials, which then fails every scan of a
        #    private repository. Verified against a live 5.4 controller: flat username
        #    reads back as "", nested it reads back correctly, and a flat
        #    auth_with_token=true reads back False. Non-credential fields stay flat;
        #    those were confirmed to persist as-is.
        config: dict[str, Any] = {
            "name": name,
            "registry_type": registry_type,
            "registry": registry,
            # order is not semantic for repository patterns -> sorted for a stable token
            "filters": sorted(filters),
            "scan_layers": scan_layers,
            "rescan_after_db_update": rescan_after_db_update,
            "ignore_proxy": ignore_proxy,
        }
        for key, value in (
            ("repo_limit", repo_limit),
            ("tag_limit", tag_limit),
        ):
            if value is not None:
                config[key] = value
        auth: dict[str, Any] = {"auth_with_token": auth_with_token}
        for cred_key, cred_value in (
            ("username", username),
            ("password", password),
            ("auth_token", auth_token),
        ):
            if cred_value is not None:
                auth[cred_key] = cred_value
        config["auth"] = auth
        wire_payload = {"config": config}
        safe_payload = redact_secrets(wire_payload)

        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_create_registry",
            toolset="scan_ops",
            target=name,
            effect=(
                f"Create registry entry {name!r} for {registry} with {len(filters)} filter(s). "
                "Credentials, if supplied, are stored by the controller."
            ),
            payload=safe_payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4. wire_payload: the only place it goes
            "POST", "/v2/scan/registry", json=wire_payload
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_create_registry",
            target=name,
            effect=f"registry {name} created",
            payload=safe_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_registry",
        annotations=MUTATING_UPDATE,
        tags={"scan_ops", "write"},
    )
    async def nv_update_registry(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Registry entry to change, from nv_list_registries.",
            ),
        ],
        registry: Annotated[
            str | None,
            Field(description="New registry base URL. Omit to leave it unchanged."),
        ] = None,
        filters: Annotated[
            list[str] | None,
            Field(
                description="Replacement repository/tag patterns. This REPLACES the existing "
                "list, it does not add to it; pass the full set you want."
            ),
        ] = None,
        username: Annotated[
            str | None,
            Field(description="New registry username. Omit to leave it unchanged."),
        ] = None,
        password: Annotated[
            str | None,
            Field(
                description="New registry password. Sent once, never logged, shown as '***' in "
                "the returned payload. Omit to leave the stored one unchanged."
            ),
        ] = None,
        auth_token: Annotated[
            str | None,
            Field(description="New bearer token. Same redaction as 'password'."),
        ] = None,
        auth_with_token: Annotated[
            bool | None,
            Field(
                description="True switches to token authentication, false switches to username "
                "and password."
            ),
        ] = None,
        scan_layers: Annotated[
            bool | None,
            Field(description="Toggle per-layer findings."),
        ] = None,
        rescan_after_db_update: Annotated[
            bool | None,
            Field(description="Toggle rescanning on every CVE database update."),
        ] = None,
        repo_limit: Annotated[
            int | None,
            Field(description="New repository enumeration limit."),
        ] = None,
        tag_limit: Annotated[
            int | None,
            Field(description="New per-repository tag limit."),
        ] = None,
        ignore_proxy: Annotated[
            bool | None,
            Field(description="Toggle bypassing the configured registry proxy."),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Change the configuration of an existing registry entry.

        Only the fields you pass are changed; everything else keeps its stored value.
        Two exceptions worth knowing: 'filters' REPLACES the whole pattern list rather
        than adding to it, and widening the filters is the usual cause of an
        unexpectedly enormous next scan. New credentials are sent once, never logged,
        and shown as '***' in the returned payload; omitting 'password' leaves the
        stored credential untouched rather than clearing it. The registry kind cannot be
        changed - delete the entry and create a new one instead. Credentials are nested
        under config.auth - sent flat the controller answers 200 and changes nothing.

        Calls PATCH /v2/scan/registry/{name} with {"config": {..., "auth": {...}}}.
        """
        app = app_context(ctx)
        # 1. build the payload from the arguments that were actually supplied.
        #    Credentials nest under "auth" for the same reason as nv_create_registry:
        #    sent flat the V2 route drops them silently, so a password change would
        #    report success and leave the stored credential untouched.
        changes: dict[str, Any] = {}
        for key, value in (
            ("registry", registry),
            ("scan_layers", scan_layers),
            ("rescan_after_db_update", rescan_after_db_update),
            ("repo_limit", repo_limit),
            ("tag_limit", tag_limit),
            ("ignore_proxy", ignore_proxy),
        ):
            if value is not None:
                changes[key] = value
        auth: dict[str, Any] = {}
        for key, value in (
            ("username", username),
            ("password", password),
            ("auth_token", auth_token),
            ("auth_with_token", auth_with_token),
        ):
            if value is not None:
                auth[key] = value
        if filters is not None:
            changes["filters"] = sorted(filters)
        if not changes and not auth:
            raise ValidationError_(
                "nv_update_registry needs at least one field to change. No request was sent."
            )
        # Name the fields the CALLER passed, not the wire shape: nesting credentials
        # under "auth" must not turn "change password, scan_layers" into "change auth,
        # scan_layers" and hide which credential is being replaced.
        changed_fields = sorted([*changes, *auth])
        if auth:
            changes["auth"] = auth
        wire_payload = {"config": {"name": name, **changes}}
        safe_payload = redact_secrets(wire_payload)

        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_update_registry",
            toolset="scan_ops",
            # field NAMES only: one of them may be 'password', and a value must never
            # reach the plan through the prose.
            effect=f"Update registry {name!r}: change {', '.join(changed_fields)}.",
            target=name,
            payload=safe_payload,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4.
            "PATCH", f"/v2/scan/registry/{name}", json=wire_payload
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_update_registry",
            target=name,
            effect=f"registry {name} updated: {', '.join(sorted(changes))}",
            payload=safe_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_registry",
        annotations=MUTATING_DESTRUCTIVE,
        tags={"scan_ops", "write"},
    )
    async def nv_delete_registry(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Registry entry to delete, from nv_list_registries.",
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Delete a registry entry and every scan result stored under it.

        Data-destroying and not recoverable from this server: the stored credentials,
        the repository filters and all scan reports for images in this registry go with
        it, so nv_get_scan_report(target='registry_image') will stop answering for those
        images. Admission control rules and vulnerability profiles that reason about
        those images lose their evidence. A registry with a scan in progress is refused
        with code 16 - stop the scan with nv_stop_registry_scan first.

        Calls DELETE /v1/scan/registry/{name}.
        """
        app = app_context(ctx)
        # 1. no request body on this route.
        plan = authorise_write(  # 2.
            app.settings,
            operation="nv_delete_registry",
            toolset="scan_ops",
            target=name,
            effect=(
                f"Delete registry {name!r}, its stored credentials, its filters and every scan "
                "report for its images."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request("DELETE", f"/v1/scan/registry/{name}")  # 4.
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_delete_registry",
            target=name,
            effect=f"registry {name} deleted",
            payload={},
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_trigger_bench_run",
        annotations=MUTATING_CREATE,
        tags={"scan_ops", "write"},
    )
    async def nv_trigger_bench_run(
        ctx: Context,
        host_id: Annotated[
            str,
            Field(min_length=1, description="Host (node) id from nv_list_hosts."),
        ],
        benchmark: Annotated[
            Literal["kubernetes", "docker"],
            Field(
                description="Which CIS benchmark to run: 'kubernetes' for the CIS Kubernetes "
                "Benchmark, 'docker' for the CIS Docker Benchmark. Run the one that matches what "
                "the node actually runs."
            ),
        ],
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. Omit on "
                "the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Re-run a CIS benchmark on one node and refresh its stored report.

        The enforcer on that node executes the benchmark scripts, which is CPU-noisy for
        a short while but changes nothing on the host. Read the result afterwards with
        nv_get_bench_report for the same host and benchmark - this call only triggers
        the run, so a fresh report may take a moment to appear. Pick the benchmark that
        matches the node: asking for 'docker' on a containerd node produces a report
        full of failures that mean nothing.

        Calls POST /v1/bench/host/{id}/kubernetes with benchmark='kubernetes'.
        Calls POST /v1/bench/host/{id}/docker with benchmark='docker'.
        """
        app = app_context(ctx)
        # 1. no request body on either route.
        target = f"{benchmark} benchmark on host {host_id}"
        plan = authorise_write(  # 2. namespace=None: a node is cluster-scoped.
            app.settings,
            operation="nv_trigger_bench_run",
            toolset="scan_ops",
            target=target,
            effect=(
                f"Re-run the CIS {benchmark} benchmark on node {host_id!r}. The enforcer executes "
                "the benchmark scripts; nothing on the host is modified."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        if plan is not None:  # 3.
            return plan

        response = await app.client.request(  # 4. the enforcer runs the script: long timeout
            "POST",
            f"/v1/bench/host/{host_id}/{benchmark}",
            timeout_s=app.settings.long_request_timeout_s,
        )
        return WriteOutcome(  # 5.
            status="applied",
            operation="nv_trigger_bench_run",
            target=target,
            effect=(
                f"CIS {benchmark} benchmark started on {host_id}; read it with nv_get_bench_report"
            ),
            payload={},
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )
