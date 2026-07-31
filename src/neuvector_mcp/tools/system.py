"""Cluster-wide system, namespace-tag and scan configuration. Toolset ``system_write``.

Every tool here follows the five-step mutating body of SPEC 7.4, in this order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

``nv_update_system_config`` carries the one exception permitted by Part D section
D.0.8: a read-only, failure-tolerant ``GET /v2/system/config`` runs before the
guard so the confirmation plan can name each field as ``old -> new``. That GET
never mutates anything, sits on a different route from the PATCH, and never feeds
the confirm token.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import NeuVectorMCPError, ValidationError_
from ..guard import authorise_write
from ..models import _UNKNOWN, WriteOutcome, _clip, describe_change, redact_secrets

#: Reversible configuration change. Re-applying the same arguments is a no-op.
MUTATING_UPDATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

#: Longest ``effect`` string a plan may carry, in characters.
_EFFECT_LIMIT = 1500

#: Write path in the ``PATCH /v2/system/config`` body -> read path inside the
#: ``config`` object of ``GET /v2/system/config``. The two shapes differ field by
#: field (Part D, "Read path -> write path mapping"), so this table is the only
#: sanctioned translation. ``None`` means the read side has no counterpart and the
#: old value is rendered ``?``.
_READ_PATHS: dict[str, str | None] = {
    # config_v2.svc_cfg.* -> config.new_svc.*
    "config_v2.svc_cfg.new_service_policy_mode": "new_svc.new_service_policy_mode",
    "config_v2.svc_cfg.new_service_profile_baseline": "new_svc.new_service_profile_baseline",
    # config_v2.syslog_cfg.* -> config.syslog.*
    "config_v2.syslog_cfg.syslog_status": "syslog.syslog_status",
    "config_v2.syslog_cfg.syslog_ip": "syslog.syslog_ip",
    "config_v2.syslog_cfg.syslog_port": "syslog.syslog_port",
    "config_v2.syslog_cfg.syslog_level": "syslog.syslog_level",
    "config_v2.syslog_cfg.syslog_categories": "syslog.syslog_categories",
    "config_v2.syslog_cfg.syslog_in_json": "syslog.syslog_in_json",
    # config_v2.auth_cfg.* -> config.auth.*
    "config_v2.auth_cfg.auth_order": "auth.auth_order",
    "config_v2.auth_cfg.auth_by_platform": "auth.auth_by_platform",
    # config_v2.tls_cfg.* -> config.tls_cfg.*
    "config_v2.tls_cfg.enable_tls_verification": "tls_cfg.enable_tls_verification",
    # config_v2.proxy_cfg.* -> config.proxy.*
    "config_v2.proxy_cfg.registry_http_proxy_status": "proxy.registry_http_proxy_status",
    "config_v2.proxy_cfg.registry_https_proxy_status": "proxy.registry_https_proxy_status",
    # config_v2.scanner_autoscale_cfg.* -> config.scanner_autoscale.*
    "config_v2.scanner_autoscale_cfg.strategy": "scanner_autoscale.strategy",
    "config_v2.scanner_autoscale_cfg.min_pods": "scanner_autoscale.min_pods",
    "config_v2.scanner_autoscale_cfg.max_pods": "scanner_autoscale.max_pods",
    # config_v2.misc_cfg.* -> config.misc.*
    "config_v2.misc_cfg.cluster_name": "misc.cluster_name",
    "config_v2.misc_cfg.unused_group_aging": "misc.unused_group_aging",
    "config_v2.misc_cfg.controller_debug": "misc.controller_debug",
    "config_v2.misc_cfg.monitor_service_mesh": "misc.monitor_service_mesh",
    "config_v2.misc_cfg.xff_enabled": "misc.xff_enabled",
    "config_v2.misc_cfg.no_telemetry_report": "misc.no_telemetry_report",
    # net_config.* -> config.net_svc.*
    "net_config.net_service_status": "net_svc.net_service_status",
    "net_config.disable_net_policy": "net_svc.disable_net_policy",
    "net_config.detect_unmanaged_wl": "net_svc.detect_unmanaged_wl",
    "net_config.strict_group_mode": "net_svc.strict_group_mode",
    # RESTSystemConfigNetSvcV2 (read) declares new_service_profile_baseline where
    # RESTSysNetConfigConfig (write) declares net_service_policy_mode: no counterpart.
    "net_config.net_service_policy_mode": None,
    # atmo_config.* -> config.mode_auto.*
    "atmo_config.mode_auto_d2m": "mode_auto.mode_auto_d2m",
    "atmo_config.mode_auto_d2m_duration": "mode_auto.mode_auto_d2m_duration",
    "atmo_config.mode_auto_m2p": "mode_auto.mode_auto_m2p",
    "atmo_config.mode_auto_m2p_duration": "mode_auto.mode_auto_m2p_duration",
}


def _set_fields(*pairs: tuple[str, Any]) -> dict[str, Any]:
    """Sub-object holding only the arguments the caller actually set.

    The test is ``is not None``, never truthiness, so ``False``, ``0``, ``""`` and
    ``[]`` are real values that reach the controller while an omitted argument is
    absent from the body entirely. This is what makes every tool in this module a
    partial PATCH: a field nobody named is never sent, so it cannot be reset.
    """
    return {key: value for key, value in pairs if value is not None}


def _lookup(mapping: Mapping[str, Any], path: str | None) -> Any:
    """Value at a dotted ``path`` inside ``mapping``.

    Returns the :data:`~neuvector_mcp.models._UNKNOWN` sentinel when ``path`` is
    ``None`` or any segment is missing, which
    :func:`~neuvector_mcp.models.describe_change` renders as ``?``.
    """
    if path is None:
        return _UNKNOWN
    current: Any = mapping
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return _UNKNOWN
        current = current[segment]
    return current


def _changed_fields(
    payload: Mapping[str, Any], prefix: str = ""
) -> Iterator[tuple[str, str | None, Any]]:
    """Yield ``(write_path, read_path, new_value)`` for every leaf present in ``payload``.

    Walks the body the tool is about to send, so a field that was never set is
    never described. Insertion order is preserved: nothing here is sorted, because
    ``auth_order`` and ``controller_debug`` are order-significant lists.
    """
    for key, value in payload.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from _changed_fields(value, f"{path}.")
        else:
            yield path, _READ_PATHS.get(path), value


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the system_write toolset to ``mcp`` when it is enabled."""
    if not settings.toolset_enabled("system_write"):
        return

    @mcp.tool(
        name="nv_update_system_config",
        annotations=MUTATING_UPDATE,
        tags={"system_write", "write"},
    )
    # One argument per JSON path, by design: SPEC 7.5 forbids a free-form dict here.
    async def nv_update_system_config(
        ctx: Context,
        new_service_policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(
                description="Enforcement mode every NEWLY discovered service starts in. "
                "Protect means a freshly deployed workload blocks traffic from its first packet."
            ),
        ] = None,
        new_service_profile_baseline: Annotated[
            str | None,
            Field(
                description="Process baseline strictness for new services, verbatim controller "
                "string; see 'baseline_profile' on an existing service via nv_list_services."
            ),
        ] = None,
        net_service_status: Annotated[
            bool | None,
            Field(description="Enable or disable network service policy cluster-wide."),
        ] = None,
        net_service_policy_mode: Annotated[
            Literal["Discover", "Monitor", "Protect"] | None,
            Field(description="Cluster-wide network service policy mode."),
        ] = None,
        disable_net_policy: Annotated[
            bool | None,
            Field(
                description="True disables ALL network policy enforcement cluster-wide, so every "
                "Protect group stops blocking."
            ),
        ] = None,
        detect_unmanaged_wl: Annotated[
            bool | None,
            Field(description="True reports workloads NeuVector does not manage."),
        ] = None,
        strict_group_mode: Annotated[
            bool | None,
            Field(
                description="True narrows how workloads are matched into groups, which changes "
                "the scope of every existing rule."
            ),
        ] = None,
        mode_auto_d2m: Annotated[
            bool | None,
            Field(
                description="True promotes groups from Discover to Monitor automatically after "
                "mode_auto_d2m_duration."
            ),
        ] = None,
        mode_auto_d2m_duration: Annotated[
            int | None,
            Field(
                description="Seconds a group stays in Discover before automatic promotion to "
                "Monitor."
            ),
        ] = None,
        mode_auto_m2p: Annotated[
            bool | None,
            Field(
                description="True promotes groups from Monitor to Protect automatically, so they "
                "START BLOCKING with no further human action."
            ),
        ] = None,
        mode_auto_m2p_duration: Annotated[
            int | None,
            Field(
                description="Seconds a group stays in Monitor before automatic promotion to "
                "Protect."
            ),
        ] = None,
        syslog_status: Annotated[
            bool | None,
            Field(
                description="Enable or disable syslog forwarding. Disabling it stops the external "
                "security event trail."
            ),
        ] = None,
        syslog_ip: Annotated[
            str | None,
            Field(
                description="Syslog destination address. Changing it sends every security event "
                "somewhere new."
            ),
        ] = None,
        syslog_port: Annotated[
            int | None,
            Field(ge=1, le=65535, description="Syslog destination port."),
        ] = None,
        syslog_level: Annotated[
            str | None,
            Field(description="Minimum syslog severity, verbatim controller string."),
        ] = None,
        syslog_categories: Annotated[
            list[str] | None,
            Field(
                description="Event categories to forward. This REPLACES the current list; pass "
                "the full set you want."
            ),
        ] = None,
        syslog_in_json: Annotated[
            bool | None,
            Field(description="True forwards syslog records as JSON."),
        ] = None,
        auth_order: Annotated[
            list[str] | None,
            Field(
                description="Authentication servers in the order they are tried. ORDER IS "
                "SIGNIFICANT and this REPLACES the list; a wrong order can lock every human out. "
                "Names from nv_list_auth_servers."
            ),
        ] = None,
        auth_by_platform: Annotated[
            bool | None,
            Field(description="True delegates authentication to the platform, e.g. Rancher."),
        ] = None,
        enable_tls_verification: Annotated[
            bool | None,
            Field(
                description="False makes controller-initiated TLS connections trust any "
                "certificate."
            ),
        ] = None,
        registry_http_proxy_status: Annotated[
            bool | None,
            Field(
                description="Enable or disable the configured HTTP registry proxy. Proxy "
                "credentials cannot be set here."
            ),
        ] = None,
        registry_https_proxy_status: Annotated[
            bool | None,
            Field(
                description="Enable or disable the configured HTTPS registry proxy. Proxy "
                "credentials cannot be set here."
            ),
        ] = None,
        scanner_autoscale_strategy: Annotated[
            Literal["", "immediate", "delayed"] | None,
            Field(description="Scanner autoscaling strategy. Empty string disables autoscaling."),
        ] = None,
        scanner_min_pods: Annotated[
            int | None, Field(ge=0, description="Minimum scanner pods.")
        ] = None,
        scanner_max_pods: Annotated[
            int | None, Field(ge=0, description="Maximum scanner pods. Raising this raises cost.")
        ] = None,
        cluster_name: Annotated[
            str | None,
            Field(description="Cluster display name, used in events and syslog records."),
        ] = None,
        unused_group_aging: Annotated[
            int | None,
            Field(ge=0, le=255, description="Hours before an unused group is aged out."),
        ] = None,
        controller_debug: Annotated[
            list[str] | None,
            Field(
                description="Controller debug categories to enable, from cpath, conn, mutex, "
                "scan, cluster, k8s_monitor. This REPLACES the list; pass [] to turn debugging off."
            ),
        ] = None,
        monitor_service_mesh: Annotated[
            bool | None,
            Field(description="True monitors service-mesh sidecar traffic."),
        ] = None,
        xff_enabled: Annotated[
            bool | None,
            Field(description="True trusts X-Forwarded-For when attributing traffic."),
        ] = None,
        no_telemetry_report: Annotated[
            bool | None, Field(description="True stops telemetry reporting.")
        ] = None,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Change cluster-wide system configuration, one named field at a time.

        The widest-reaching tool in this server: these settings are the defaults and
        kill switches behind every group and rule. disable_net_policy=true stops all
        network enforcement cluster-wide; mode_auto_m2p=true makes groups start blocking
        later with no human in the loop; new_service_policy_mode='Protect' makes every
        newly deployed workload block from its first packet; changing syslog or
        auth_order can destroy your audit trail or lock every human out. Only the fields
        you pass are changed. The preview reads the current configuration first and the
        'effect' string names every field with its old and new value - read it before
        confirming; a '?' means the old value could not be read. Webhooks, remote
        repositories, proxy credentials, federation and IBM Security Advisor settings are
        deliberately not settable here.

        Calls GET /v2/system/config.
        Calls PATCH /v2/system/config with only the sub-objects you change.
        """
        app = app_context(ctx)

        # --- 1. build payload: only the sub-objects that have at least one set field ---
        svc_cfg = _set_fields(
            ("new_service_policy_mode", new_service_policy_mode),
            ("new_service_profile_baseline", new_service_profile_baseline),
        )
        syslog_cfg = _set_fields(
            ("syslog_status", syslog_status),
            ("syslog_ip", syslog_ip),
            ("syslog_port", syslog_port),
            ("syslog_level", syslog_level),
            ("syslog_categories", syslog_categories),
            ("syslog_in_json", syslog_in_json),
        )
        auth_cfg = _set_fields(
            ("auth_order", auth_order),
            ("auth_by_platform", auth_by_platform),
        )
        misc_cfg = _set_fields(
            ("cluster_name", cluster_name),
            ("unused_group_aging", unused_group_aging),
            ("controller_debug", controller_debug),
            ("monitor_service_mesh", monitor_service_mesh),
            ("xff_enabled", xff_enabled),
            ("no_telemetry_report", no_telemetry_report),
        )
        proxy_cfg = _set_fields(
            ("registry_http_proxy_status", registry_http_proxy_status),
            ("registry_https_proxy_status", registry_https_proxy_status),
        )
        tls_cfg = _set_fields(("enable_tls_verification", enable_tls_verification))
        autoscale_cfg = _set_fields(
            ("strategy", scanner_autoscale_strategy),
            ("min_pods", scanner_min_pods),
            ("max_pods", scanner_max_pods),
        )
        net_config = _set_fields(
            ("net_service_status", net_service_status),
            ("net_service_policy_mode", net_service_policy_mode),
            ("disable_net_policy", disable_net_policy),
            ("detect_unmanaged_wl", detect_unmanaged_wl),
            ("strict_group_mode", strict_group_mode),
        )
        atmo_config = _set_fields(
            ("mode_auto_d2m", mode_auto_d2m),
            ("mode_auto_d2m_duration", mode_auto_d2m_duration),
            ("mode_auto_m2p", mode_auto_m2p),
            ("mode_auto_m2p_duration", mode_auto_m2p_duration),
        )
        # An empty sub-object is a request to set nothing and the controller's
        # behaviour with one is unverified, so it is omitted rather than sent as {}.
        config_v2 = {
            key: value
            for key, value in (
                ("svc_cfg", svc_cfg),
                ("syslog_cfg", syslog_cfg),
                ("auth_cfg", auth_cfg),
                ("misc_cfg", misc_cfg),
                ("proxy_cfg", proxy_cfg),
                ("tls_cfg", tls_cfg),
                ("scanner_autoscale_cfg", autoscale_cfg),
            )
            if value
        }
        wire_payload: dict[str, Any] = {
            key: value
            for key, value in (
                ("config_v2", config_v2),
                ("net_config", net_config),
                ("atmo_config", atmo_config),
            )
            if value
        }
        if not wire_payload:
            raise ValidationError_(
                "nv_update_system_config needs at least one field to change. No request was sent."
            )

        # --- 1b. pre-guard read (D.0.8): old values for the effect string only ---
        # Read-only, on a different route from the mutation, failure-tolerant, and it
        # never feeds the confirm token. This is the ONLY network call in this server
        # that precedes the guard.
        current: dict[str, Any] = {}
        try:
            body = await app.client.request("GET", "/v2/system/config")
            if isinstance(body, dict):
                config = body.get("config")
                current = config if isinstance(config, dict) else {}
        except NeuVectorMCPError:
            current = {}  # degrade to '?' rather than block the preview

        changes = [
            describe_change(write_path, _lookup(current, read_path), new_value)
            for write_path, read_path, new_value in _changed_fields(wire_payload)
        ]
        effect = _clip(
            "Change cluster-wide system configuration: " + "; ".join(changes) + ".",
            _EFFECT_LIMIT,
        )[0]

        # --- 2. guard ---
        plan = authorise_write(
            app.settings,
            operation="nv_update_system_config",
            toolset="system_write",
            target="cluster system configuration",
            effect=effect,
            payload=wire_payload,
            confirm=confirm,
            namespace=None,  # cluster-wide: NV_ALLOWED_NAMESPACES cannot scope it
        )
        # --- 3. return the plan verbatim ---
        if plan is not None:
            return plan

        # --- 4. controller call ---
        timeout_s = (
            app.settings.long_request_timeout_s if "scanner_autoscale_cfg" in config_v2 else None
        )
        response = await app.client.request(
            "PATCH", "/v2/system/config", json=wire_payload, timeout_s=timeout_s
        )
        # --- 5. outcome ---
        return WriteOutcome(
            status="applied",
            operation="nv_update_system_config",
            target="cluster system configuration",
            effect=effect,
            payload=wire_payload,
            controller_response=(redact_secrets(response) if isinstance(response, dict) else {}),
        )

    @mcp.tool(
        name="nv_set_namespace_tags",
        annotations=MUTATING_UPDATE,
        tags={"system_write", "write"},
    )
    async def nv_set_namespace_tags(
        ctx: Context,
        namespace: Annotated[
            str,
            Field(min_length=1, description="Namespace to tag, from nv_list_namespaces."),
        ],
        tags: Annotated[
            list[str],
            Field(
                description="Compliance tags to set on the namespace, e.g. ['PCI', 'GDPR']. "
                "This REPLACES the namespace's current tags rather than adding to them; pass "
                "the full set you want, and [] to clear them."
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
        """Set the compliance tags on one namespace.

        Tags drive which compliance checks and CIS benchmark items are reported for
        everything in the namespace, so this changes what nv_get_compliance_findings and
        nv_get_bench_report consider a finding - it does not change enforcement and
        blocks no traffic. The list REPLACES the namespace's current tags, so read them
        from nv_list_namespaces first or you will silently drop the ones you did not
        mention. Per-namespace tagging must be enabled cluster-wide: nv_list_namespaces
        reports that as 'tag_per_domain', and the controller answers code 4 when it is
        off.

        Calls PATCH /v1/domain/{name} with {"config": {"name":..., "tags":[...]}}.
        """
        app = app_context(ctx)

        # --- 1. build payload ---
        # BLOCKED (schema): RESTDomainEntryConfigData is absent from Appendix B. The
        # shape below uses only field names verified on RESTDomain plus the "config"
        # wrapper every other REST*ConfigData in Appendix B uses. Tags are a set, so
        # deduplicating and sorting makes the confirm token independent of the order
        # the caller listed them in.
        normalised = sorted(set(tags))
        wire_payload: dict[str, Any] = {"config": {"name": namespace, "tags": normalised}}

        # --- 2. guard: the target IS the namespace, so the allowlist applies directly ---
        plan = authorise_write(
            app.settings,
            operation="nv_set_namespace_tags",
            toolset="system_write",
            target=namespace,
            effect=(
                f"Set the compliance tags of namespace {namespace!r} to {normalised}, "
                "replacing its current tags."
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=namespace,
        )
        # --- 3. return the plan verbatim ---
        if plan is not None:
            return plan

        # --- 4. controller call ---
        response = await app.client.request("PATCH", f"/v1/domain/{namespace}", json=wire_payload)
        # --- 5. outcome ---
        return WriteOutcome(
            status="applied",
            operation="nv_set_namespace_tags",
            target=namespace,
            effect=f"tags of namespace {namespace} set to {normalised}",
            payload=wire_payload,
            controller_response=(redact_secrets(response) if isinstance(response, dict) else {}),
        )

    @mcp.tool(
        name="nv_update_scan_config",
        annotations=MUTATING_UPDATE,
        tags={"system_write", "write"},
    )
    async def nv_update_scan_config(
        ctx: Context,
        auto_scan: Annotated[
            bool | None,
            Field(
                description="Global auto-scan switch. True makes the controller scan workloads "
                "and hosts automatically; it is overridden for either target by "
                "enable_auto_scan_workload or enable_auto_scan_host when those are set."
            ),
        ] = None,
        enable_auto_scan_workload: Annotated[
            bool | None,
            Field(
                description="Auto-scan workloads specifically. Omit to leave it to the global "
                "auto_scan setting."
            ),
        ] = None,
        enable_auto_scan_host: Annotated[
            bool | None,
            Field(
                description="Auto-scan hosts specifically. Omit to leave it to the global "
                "auto_scan setting."
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
        """Turn cluster-wide automatic vulnerability scanning on or off.

        Enabling auto-scan makes the controller scan every workload and host it does not
        have a current report for, which on a large cluster is a scanning storm that
        occupies the scanners for a long while and delays every registry scan and ad-hoc
        scan behind it - enable it during a quiet window. Disabling it is the quieter
        change but it silently stops new reports, so nv_get_scan_report keeps answering
        with data that ages out. The two enable_auto_scan_* switches override the global
        auto_scan for their target, so you can auto-scan workloads and leave hosts alone.
        Only the fields you pass are changed.

        Calls PATCH /v1/scan/config with {"config": {...}}.
        """
        app = app_context(ctx)

        # --- 1. build payload: RESTScanConfigData, all three fields optional ---
        config = _set_fields(
            ("auto_scan", auto_scan),
            ("enable_auto_scan_workload", enable_auto_scan_workload),
            ("enable_auto_scan_host", enable_auto_scan_host),
        )
        if not config:
            raise ValidationError_(
                "nv_update_scan_config needs at least one field to change. No request was sent."
            )
        wire_payload: dict[str, Any] = {"config": config}

        # --- 2. guard. No pre-read: GET /v1/scan/config returns RESTScanConfigResp,
        # which is absent from Appendix B, so old values cannot be projected safely.
        plan = authorise_write(
            app.settings,
            operation="nv_update_scan_config",
            toolset="system_write",
            target="cluster scan configuration",
            effect=(
                "Change cluster-wide scan configuration: "
                + ", ".join(f"{key}={value!r}" for key, value in sorted(config.items()))
                + ". Enabling auto-scan starts scanning every workload and host without "
                "a current report."
            ),
            payload=wire_payload,
            confirm=confirm,
            namespace=None,  # cluster-wide: NV_ALLOWED_NAMESPACES cannot scope it
        )
        # --- 3. return the plan verbatim ---
        if plan is not None:
            return plan

        # --- 4. controller call ---
        response = await app.client.request("PATCH", "/v1/scan/config", json=wire_payload)
        # --- 5. outcome ---
        return WriteOutcome(
            status="applied",
            operation="nv_update_scan_config",
            target="cluster scan configuration",
            effect=(
                "cluster scan configuration set to "
                + ", ".join(f"{key}={value!r}" for key, value in sorted(config.items()))
            ),
            payload=wire_payload,
            controller_response=(redact_secrets(response) if isinstance(response, dict) else {}),
        )
