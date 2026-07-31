"""Service creation, live-workload config, cluster requests and namespace defaults.

Toolsets ``policy_write``, ``runtime_ops`` and ``system_write``. Each is gated
separately in :func:`register` so a tool never ships under another's tag.

Every tool here follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3. No tool
here reads the controller before building its payload, so any "current value" a
plan mentions is a CALLER ASSERTION and never a controller-verified fact - which
is exactly why ``nv_update_workload_config`` makes the caller state the
quarantine flag rather than reading it.

Three schema findings shape this module:

* ``profile_mode`` is declared on apis.go ``RESTServiceConfig`` and apis.go
  ``RESTSystemRequest``, but on NEITHER the 5.6.0 apis.yaml NOR Appendix B. Two
  independent 5.6.0-era sources disagree with apis.go, so the field is not
  exposed by either tool: sending it risks a field the controller answers 200 to
  and drops. Profile enforcement is set with ``nv_set_service_mode(scope=
  'profile')``, which selects the dimension by route rather than by field.
* apis.go ``RESTWorkloadConfig.Quarantine`` is a plain ``bool`` with no
  ``omitempty``, and apis.yaml lists ``quarantine`` under ``required``. PATCH
  /v1/workload/{id} therefore has NO way to express "leave quarantine alone" -
  an omitted key decodes as ``false``. Every call to that route asserts a
  quarantine state whether the caller meant to or not.
* apis.go ``RESTDomainConfig`` carries exactly one field, ``tag_per_domain``, so
  PATCH /v1/domain is a single cluster-wide switch and nothing else.
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
from ..models import WriteOutcome, redact_secrets

#: Creates something that did not exist before. Not destructive; not idempotent
#: (a second call is rejected as a duplicate).
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
#: Reversible configuration change. Re-applying the same arguments is a no-op.
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Traffic-affecting or state-destroying. Treat as irreversible.
MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)


def _optional(*pairs: tuple[str, Any]) -> dict[str, Any]:
    """Keep only the pairs whose value is not ``None``.

    Every field passed through here is a Go pointer with ``omitempty`` in
    apis.go, so absence from the wire body is what tells the controller "not
    modified". ``None`` must therefore become an ABSENT KEY, never a JSON
    ``null`` and never a default value - a default would silently overwrite
    whatever the operator has configured today.
    """
    return {key: value for key, value in pairs if value is not None}


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the service, workload, cluster-request and namespace write tools.

    Each toolset is gated independently: enabling ``system_write`` must not drag
    in the ``runtime_ops`` tool, and vice versa.
    """
    if settings.toolset_enabled("policy_write"):
        _register_policy_write(mcp)
    if settings.toolset_enabled("runtime_ops"):
        _register_runtime_ops(mcp)
    if settings.toolset_enabled("system_write"):
        _register_system_write(mcp)


def _register_policy_write(mcp: FastMCP) -> None:
    """Tools tagged ``policy_write``: creating a service entry."""

    @mcp.tool(
        name="nv_create_service",
        annotations=MUTATING_CREATE,
        tags={"policy_write", "write"},
    )
    async def nv_create_service(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                description="Bare service name, without the namespace suffix. NeuVector "
                "displays a service as '<name>.<domain>' and derives its learned group "
                "'nv.<name>.<domain>' from the two, so pass the service name here and the "
                "namespace in 'domain'. Check nv_list_services first - a duplicate is "
                "rejected by the controller.",
            ),
        ],
        domain: Annotated[
            str,
            Field(
                min_length=1,
                description="Namespace the service belongs to (controller field 'domain'). "
                "This is the namespace NV_ALLOWED_NAMESPACES is checked against.",
            ),
        ],
        comment: Annotated[
            str,
            Field(description="Why this service exists. Shown in the NeuVector UI."),
        ] = "",
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(
                description="Initial enforcement mode. Discover learns behaviour, Monitor "
                "alerts only, Protect BLOCKS. Omit to let the controller apply the cluster "
                "default from 'new_service_policy_mode'. Creating a service directly in "
                "Protect means it enforces a policy it has never learned anything for."
            ),
        ] = None,
        baseline_profile: Annotated[
            str | None,
            Field(
                description="Process baseline strictness, verbatim controller string (e.g. "
                "'zero-drift'). Omit to take the cluster default. Read the values actually "
                "in use from 'baseline_profile' on an existing service via nv_list_services."
            ),
        ] = None,
        not_scored: Annotated[
            bool | None,
            Field(
                description="True excludes this service from the cluster security score. "
                "Omit to take the controller default."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Create a service entry, optionally with its initial enforcement mode.

        A service is what NeuVector attaches enforcement to: creating one also creates
        its learned group 'nv.<name>.<domain>'. Unlike a group, a service DOES carry a
        policy mode, and this route accepts it at creation time - RESTServiceConfig
        declares 'policy_mode' in apis.go, apis.yaml and Appendix B alike. Creating a
        service in Protect mode means it starts enforcing a policy it has learned nothing
        for, so every connection and process is unknown and gets BLOCKED; create in
        Discover, let it learn, then move it with nv_set_service_mode.

        'profile_mode' is deliberately not offered: apis.go declares it on
        RESTServiceConfig but the 5.6.0 apis.yaml and Appendix B do not, so it would be a
        field the controller can accept with 200 and drop. Set it afterwards with
        nv_set_service_mode(scope='profile'), which selects the dimension by route.

        Calls POST /v1/service with {"config": {"name":..., "domain":..., "comment":..., "policy_mode":...}}.
        """
        app = app_context(ctx)

        # --- 1. build payload -------------------------------------------------
        # Field names from apis.go RESTServiceConfig; apis.yaml and Appendix B
        # agree on every field used here and mark name/domain/comment required.
        # comment is a *string WITHOUT omitempty, so it is always present on the
        # wire; the other three are pointers with omitempty and are omitted when
        # the caller did not supply them.
        config: dict[str, Any] = {"name": name, "domain": domain, "comment": comment}
        config.update(
            _optional(
                ("policy_mode", policy_mode),
                ("baseline_profile", baseline_profile),
                ("not_scored", not_scored),
            )
        )
        wire_payload: dict[str, Any] = {"config": config}

        settings_text = (
            ", ".join(
                f"{key}={config[key]!r}"
                for key in ("policy_mode", "baseline_profile", "not_scored")
                if key in config
            )
            or "no mode or baseline given, so the controller applies its cluster defaults"
        )

        # --- 2. guard: 'domain' IS the namespace, so the allowlist applies ----
        plan = authorise_write(
            app.settings,
            operation="nv_create_service",
            toolset="policy_write",
            target=f"{name}.{domain}",
            effect=(
                f"Create service {name!r} in namespace {domain!r}, along with its learned "
                f"group 'nv.{name}.{domain}'. Settings: {settings_text}. "
                + (
                    "CREATED DIRECTLY IN PROTECT: the service enforces a policy it has "
                    "learned nothing for, so every connection and every process it makes "
                    "is unknown and will be BLOCKED from the moment a container joins it. "
                    "Create in Discover instead, then move it with nv_set_service_mode "
                    "once learning has settled."
                    if policy_mode == "Protect"
                    else ""
                )
                + "Creating the service changes nothing for containers that are already "
                "running until they are matched into its group."
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=domain,
        )
        # --- 3. return the plan verbatim -------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call ----------------------------------------------
        response = await app.client.request("POST", "/v1/service", json=wire_payload)
        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_create_service",
            target=f"{name}.{domain}",
            effect=(
                f"service {name} created in namespace {domain} ({settings_text}); "
                f"verify with nv_list_services that the mode you asked for is the mode "
                f"it has"
            ),
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )


def _register_runtime_ops(mcp: FastMCP) -> None:
    """Tools tagged ``runtime_ops``: per-container datapath configuration."""

    @mcp.tool(
        name="nv_update_workload_config",
        annotations=MUTATING,
        tags={"runtime_ops", "write"},
    )
    async def nv_update_workload_config(
        ctx: Context,
        workload_id: Annotated[
            str,
            Field(
                min_length=1,
                description="Workload (container) id from nv_list_workloads or nv_get_workload. "
                "Never guess it: this tool reconfigures the datapath of a LIVE container.",
            ),
        ],
        namespace: Annotated[
            str,
            Field(
                min_length=1,
                description="Namespace the container runs in, from nv_list_workloads. Used only "
                "to enforce NV_ALLOWED_NAMESPACES; it is not sent to the controller. Required so "
                "that a mis-typed id cannot escape the namespace allowlist.",
            ),
        ],
        quarantine: Annotated[
            bool,
            Field(
                description="The quarantine state this call ASSERTS. It is not optional on the "
                "wire: apis.go RESTWorkloadConfig.Quarantine is a plain bool with no omitempty "
                "and apis.yaml marks it required, so this route always sets quarantine and an "
                "omitted key would mean False. Read the container's current state with "
                "nv_get_workload and pass THE SAME VALUE, or you silently release a quarantined "
                "container (or cut off a healthy one). To CHANGE quarantine state use "
                "nv_quarantine_workload, which is the purpose-built tool for it."
            ),
        ],
        wire: Annotated[
            str | None,
            Field(
                description="Datapath mode for this container, e.g. 'default' (the only value "
                "given as an example anywhere in apis.yaml). The accepted set is enumerated in "
                "NO schema - not apis.go, not apis.yaml, not Appendix B - so an unrecognised "
                "value may be accepted with 200 and dropped, or may change how the enforcer "
                "sits in the container's traffic path. Copy the value from another container "
                "that is already in the mode you want. Required by this tool: changing only "
                "'quarantine' is what nv_quarantine_workload is for."
            ),
        ] = None,
        quarantine_reason: Annotated[
            str | None,
            Field(
                description="Reason recorded alongside a quarantine. The controller field is "
                "omitempty, so omitting it CLEARS any reason already recorded - echo the "
                "current one back from nv_get_workload if you are asserting quarantine=true "
                "and want to keep it."
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Change the datapath (wire) configuration of one LIVE running container.

        HIGH RISK. This reconfigures how the enforcer sits in a running container's
        traffic path, immediately and without restarting it. A wire mode the enforcer
        does not expect can drop or stop inspecting that container's traffic, and the
        accepted values are enumerated in no schema this server has, so copy the value
        from a container already in the mode you want rather than inventing one.

        THIS ROUTE CANNOT LEAVE QUARANTINE ALONE. apis.go RESTWorkloadConfig declares
        'quarantine' as a plain bool with no omitempty and apis.yaml lists it as
        required, so every PATCH here asserts a quarantine state; an omitted key means
        false. That is why 'quarantine' is a required argument: read the container's
        current state with nv_get_workload and echo it back unchanged, or a wire-mode
        change will silently release a container that incident response quarantined.
        This server does not verify that value against the controller - it is your
        assertion and it appears in the plan as one.

        USE nv_quarantine_workload TO QUARANTINE OR RELEASE. That tool posts a
        purpose-built request, states the connectivity consequence in its plan, and is
        the only path this server intends for quarantine. This tool exists for the wire
        mode, and refuses to run without one so the two do not become redundant.

        Calls PATCH /v1/workload/{id} with {"config": {"wire":..., "quarantine":...}}.
        """
        app = app_context(ctx)

        # --- step 1 validation: local only, no network call -------------------
        if wire is None:
            raise ValidationError_(
                "nv_update_workload_config needs a 'wire' value. Without one this call "
                "would only assert the quarantine flag, which duplicates "
                "nv_quarantine_workload - use that tool to quarantine or release a "
                "container. No request was sent to the controller."
            )

        # --- 1. build payload -------------------------------------------------
        # Field names from apis.go RESTWorkloadConfig (wire, quarantine,
        # quarantine_reason), confirmed against the apis.yaml definition of the
        # same type. 'quarantine' is always present because it is not omitempty;
        # 'wire' and 'quarantine_reason' are omitempty and are written only when
        # supplied. apis.go also declares a pointer-valued RESTWorkloadConfigCfg
        # with the same field names, but apis.yaml binds PATCH /v1/workload/{id}
        # to RESTWorkloadConfigData, which wraps the NON-pointer type - hence no
        # "leave unchanged" for quarantine.
        config: dict[str, Any] = {"quarantine": quarantine, "wire": wire}
        config.update(_optional(("quarantine_reason", quarantine_reason)))
        wire_payload: dict[str, Any] = {"config": config}

        # --- 2. guard ---------------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_update_workload_config",
            toolset="runtime_ops",
            target=workload_id,
            effect=(
                f"Set the datapath wire mode of LIVE container {workload_id!r} in namespace "
                f"{namespace!r} to {wire!r}, taking effect immediately and without a restart. "
                f"An unexpected wire mode can drop that container's traffic or stop it being "
                f"inspected, and the accepted values appear in no schema. "
                f"THIS ALSO ASSERTS quarantine={quarantine}: the controller's request type "
                f"has no 'leave unchanged' for that flag, so this call SETS it. You stated "
                f"the container is currently quarantine={quarantine}; this server did not "
                f"verify that against the controller. If the container is actually "
                f"quarantined and you send quarantine=false, it is RELEASED back onto the "
                f"network here, silently. Check nv_get_workload({workload_id!r}) before "
                f"confirming, and use nv_quarantine_workload when changing quarantine is "
                f"what you actually want."
                + (
                    ""
                    if quarantine_reason is not None
                    else " No quarantine_reason is being sent, which CLEARS any reason "
                    "currently recorded."
                )
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=namespace,
        )
        # --- 3. return the plan verbatim -------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call ----------------------------------------------
        response = await app.client.request(
            "PATCH", f"/v1/workload/{workload_id}", json=wire_payload
        )
        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_update_workload_config",
            target=workload_id,
            effect=(
                f"container {workload_id} set to wire={wire!r} with quarantine={quarantine}; "
                f"re-read nv_get_workload({workload_id!r}) to confirm both"
            ),
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )


def _register_system_write(mcp: FastMCP) -> None:
    """Tools tagged ``system_write``: cluster-wide requests and namespace defaults."""

    @mcp.tool(
        name="nv_apply_system_request",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_apply_system_request(
        ctx: Context,
        policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(
                description="Enforcement mode to apply to EVERY service in EVERY namespace. "
                "Discover learns, Monitor alerts only, Protect BLOCKS. Omit to leave modes "
                "alone. For one or a few services use nv_set_service_mode instead - it takes "
                "an explicit service list and can be constrained by NV_ALLOWED_NAMESPACES."
            ),
        ] = None,
        baseline_profile: Annotated[
            str | None,
            Field(
                description="Process baseline strictness to apply cluster-wide, verbatim "
                "controller string (e.g. 'zero-drift'). Omit to leave it alone. Tightening the "
                "baseline everywhere makes previously tolerated process activity a violation "
                "in every namespace at once."
            ),
        ] = None,
        unquarantine: Annotated[
            bool,
            Field(
                description="True issues a bulk unquarantine. With neither filter below it "
                "releases EVERY quarantined container in the cluster back onto the network, "
                "discarding isolation that incident response put in place. Always narrow it "
                "with unquarantine_group or unquarantine_response_rule_id, or release one "
                "container at a time with nv_quarantine_workload(action='unquarantine')."
            ),
        ] = False,
        unquarantine_group: Annotated[
            str | None,
            Field(
                description="Restrict the bulk unquarantine to containers in this group "
                "(controller field 'unquarantine.group'). Requires unquarantine=true."
            ),
        ] = None,
        unquarantine_response_rule_id: Annotated[
            int | None,
            Field(
                ge=0,
                description="Restrict the bulk unquarantine to containers quarantined by this "
                "response rule id (controller field 'unquarantine.response_rule'). Get ids from "
                "nv_list_response_rules. Requires unquarantine=true.",
            ),
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Apply a CLUSTER-WIDE system request: enforcement mode, baseline, or bulk unquarantine.

        THIS APPLIES TO THE WHOLE CLUSTER - every service in every namespace, in one
        call, with no service scoping of any kind. It is almost never the tool you want.
        The scoped alternative is nv_set_service_mode, which takes an explicit list of
        services and changes only those; reach for this tool only when moving the entire
        cluster is the deliberate intent.

        NV_ALLOWED_NAMESPACES CANNOT CONSTRAIN THIS TOOL. The request body carries no
        namespace, so the write guard has none to check and the namespace allowlist is
        not applied. A server configured with NV_ALLOWED_NAMESPACES still changes every
        namespace here, including ones outside the allowlist. An operator who believes
        namespace allow-listing bounds this blast radius is mistaken.

        Setting policy_mode='Protect' cluster-wide starts BLOCKING every connection and
        every process that the learned policy does not already allow, across every
        namespace, the moment this call returns - which will break running applications
        whose behaviour was never observed during Discover. 'unquarantine' is a bulk
        release: unfiltered, it restores network connectivity to every quarantined
        container at once.

        'profile_mode' is not offered: apis.go declares it on RESTSystemRequest but the
        5.6.0 apis.yaml and Appendix B do not, so it would be a field the controller can
        accept with 200 and drop. Use nv_set_service_mode(scope='profile').

        Calls POST /v1/system/request with {"request": {"policy_mode":..., "baseline_profile":..., "unquarantine": {...}}}.
        """
        app = app_context(ctx)

        # --- step 1 validation: local only, no network call -------------------
        if not unquarantine and (
            unquarantine_group is not None or unquarantine_response_rule_id is not None
        ):
            raise ValidationError_(
                "unquarantine_group / unquarantine_response_rule_id were given but "
                "unquarantine is false, so nothing would be released. Set unquarantine=true "
                "to mean it. No request was sent to the controller."
            )
        if policy_mode is None and baseline_profile is None and not unquarantine:
            raise ValidationError_(
                "nv_apply_system_request needs at least one of policy_mode, "
                "baseline_profile or unquarantine. No request was sent to the controller."
            )

        # --- 1. build payload -------------------------------------------------
        # Field names from apis.go RESTSystemRequest / RESTUnquarReq; apis.yaml
        # and Appendix B agree on all of them. Every field is a pointer with
        # omitempty, so an unsupplied one must be an ABSENT KEY.
        request: dict[str, Any] = _optional(
            ("policy_mode", policy_mode),
            ("baseline_profile", baseline_profile),
        )
        if unquarantine:
            request["unquarantine"] = _optional(
                ("group", unquarantine_group),
                ("response_rule", unquarantine_response_rule_id),
            )
        wire_payload: dict[str, Any] = {"request": request}

        changes: list[str] = []
        if policy_mode is not None:
            changes.append(f"policy_mode={policy_mode!r} on every service in every namespace")
        if baseline_profile is not None:
            changes.append(
                f"baseline_profile={baseline_profile!r} on every service in every namespace"
            )
        if unquarantine:
            scope_text = ", ".join(
                part
                for part in (
                    None if unquarantine_group is None else f"group={unquarantine_group!r}",
                    None
                    if unquarantine_response_rule_id is None
                    else f"response_rule={unquarantine_response_rule_id}",
                )
                if part is not None
            )
            changes.append(
                f"bulk unquarantine restricted to {scope_text}"
                if scope_text
                else "bulk unquarantine of EVERY quarantined container in the cluster"
            )

        effect = (
            "CLUSTER-WIDE CHANGE, no service or namespace scoping: "
            + "; ".join(changes)
            + ". "
            + (
                "Setting policy_mode=Protect cluster-wide starts BLOCKING every connection "
                "and every process that the learned policy does not already allow, in every "
                "namespace, the moment this call returns - any application whose behaviour "
                "was never observed during Discover WILL break, immediately, with no "
                "rollback beyond setting the mode back. "
                if policy_mode == "Protect"
                else ""
            )
            + (
                "The unquarantine releases quarantined containers back onto the network, "
                "discarding isolation that incident response put in place. "
                if unquarantine
                else ""
            )
            + "NV_ALLOWED_NAMESPACES DOES NOT CONSTRAIN THIS CALL: the request carries no "
            "namespace, so the guard has none to check and the change lands in every "
            "namespace, including any outside the allowlist. The scoped alternative is "
            "nv_set_service_mode, which takes an explicit service list."
        )

        # --- 2. guard. namespace=None: the request has no namespace to pass, so
        # the NV_ALLOWED_NAMESPACES check in authorise_write cannot fire here.
        # This is a real gap and the effect text above says so out loud.
        plan = authorise_write(
            app.settings,
            operation="nv_apply_system_request",
            toolset="system_write",
            target="entire cluster (all services, all namespaces)",
            effect=effect,
            payload=wire_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim -------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call ----------------------------------------------
        response = await app.client.request("POST", "/v1/system/request", json=wire_payload)
        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_apply_system_request",
            target="entire cluster (all services, all namespaces)",
            effect=(
                "cluster-wide system request applied: "
                + "; ".join(changes)
                + ". Verify with nv_list_services that every service has the mode you "
                "intended, and with nv_list_workloads that no container was released "
                "that should still be quarantined."
            ),
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_set_namespace_defaults",
        annotations=MUTATING_IDEMPOTENT,
        tags={"system_write", "write"},
    )
    async def nv_set_namespace_defaults(
        ctx: Context,
        tag_per_domain: Annotated[
            bool,
            Field(
                description="True lets each namespace carry its own compliance tags, which is "
                "what nv_set_namespace_tags writes. False turns the whole feature off "
                "cluster-wide: every namespace's tags stop driving compliance and CIS "
                "reporting at once, and nv_set_namespace_tags starts failing with code 4. "
                "Read the current value from 'tag_per_domain' in nv_list_namespaces first."
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
        """Turn per-namespace compliance tagging on or off for the WHOLE cluster.

        This is the cluster-wide sibling of nv_set_namespace_tags, and the two are easy
        to confuse. nv_set_namespace_tags calls PATCH /v1/domain/{name} and sets the tags
        of ONE named namespace. This tool calls PATCH /v1/domain - no name in the path -
        and flips the single switch that decides whether per-namespace tags are honoured
        AT ALL, for every namespace at once. If you meant to tag one namespace, you want
        nv_set_namespace_tags.

        Turning it off does not delete anybody's tags, but it does stop all of them
        taking effect, so nv_get_compliance_findings and nv_get_bench_report immediately
        report a different set of findings for every namespace in the cluster and
        nv_set_namespace_tags starts being rejected with code 4. Turning it on has the
        mirror effect: tags already stored on namespaces start counting again. No traffic
        is blocked either way - this changes reporting, not enforcement.

        apis.go RESTDomainConfig carries exactly one field, so 'tag_per_domain' is the
        only thing this route can change.

        Calls PATCH /v1/domain with {"config": {"tag_per_domain":...}}.
        """
        app = app_context(ctx)

        # --- 1. build payload -------------------------------------------------
        # Field name from apis.go RESTDomainConfig (*bool, omitempty), which
        # apis.yaml RESTDomainConfig confirms as its only property. Sending it
        # explicitly is the point of the tool, so it is always present.
        wire_payload: dict[str, Any] = {"config": {"tag_per_domain": tag_per_domain}}

        # --- 2. guard. namespace=None: PATCH /v1/domain names no namespace, so
        # NV_ALLOWED_NAMESPACES cannot scope it - it is every namespace at once.
        plan = authorise_write(
            app.settings,
            operation="nv_set_namespace_defaults",
            toolset="system_write",
            target="all namespaces (cluster-wide tag_per_domain)",
            effect=(
                f"Set tag_per_domain={tag_per_domain} for EVERY namespace in the cluster. "
                + (
                    "Per-namespace compliance tags start being honoured again, so the "
                    "findings reported by nv_get_compliance_findings and "
                    "nv_get_bench_report change for every namespace that has tags stored."
                    if tag_per_domain
                    else "Per-namespace compliance tags stop being honoured everywhere at "
                    "once: stored tags are not deleted but none of them apply, the "
                    "findings reported by nv_get_compliance_findings and "
                    "nv_get_bench_report change for every namespace, and "
                    "nv_set_namespace_tags starts failing with code 4."
                )
                + " This changes compliance reporting only; it blocks no traffic. To tag a "
                "single namespace use nv_set_namespace_tags (PATCH /v1/domain/{name}) "
                "instead - this route takes no namespace name and applies to all of them."
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- 3. return the plan verbatim -------------------------------------
        if plan is not None:
            return plan

        # --- 4. controller call ----------------------------------------------
        response = await app.client.request("PATCH", "/v1/domain", json=wire_payload)
        # --- 5. outcome -------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_set_namespace_defaults",
            target="all namespaces (cluster-wide tag_per_domain)",
            effect=(
                f"tag_per_domain set to {tag_per_domain} for every namespace; confirm with "
                f"nv_list_namespaces"
            ),
            payload=wire_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )
