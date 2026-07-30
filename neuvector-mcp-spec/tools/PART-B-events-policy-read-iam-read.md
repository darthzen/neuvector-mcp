# TOOLS — Part B: `events`, `policy_read`, `iam_read` (19 read tools)

Companion to `SPEC.md` sections 3, 7 and 8. Every contract below is in
`_TEMPLATE.md` format and is normative. Read `SPEC.md` §7.3 (read tool body),
§7.5 (output models) and §7.6 (docstring structure) before implementing.

**Endpoint verification.** Every `Calls <METHOD> <path>` line in this file was
checked against `spec_endpoints.json["documented"]` before being written. All 21
distinct endpoints used by these 19 tools are **documented** (none needs
`UNDOCUMENTED_ALLOWLIST`, none needs `NV_ALLOW_UNDOCUMENTED`).

**Field verification.** Every field name read in a `from_api()` body comes from
`appendix/B-schema-reference.md`. Where Appendix B does **not** contain the
response type, the tool's **Notes** say so explicitly, the projection is reduced
to the minimum, and every read uses `.get(...)` with a default. Types missing
from Appendix B, referenced by this part:

| Type | Endpoint | Consequence |
|---|---|---|
| `RESTThreatData` | `GET /v1/log/threat/{id}` | envelope key `threat` inferred from §3.3; the wrapped `Threat` type **is** in B, so item fields are verified. |
| `RESTNvAlerts` | `GET /v1/system/alerts` | **BLOCKED (partial)** — see `nv_get_system_alerts` Notes. No field name is asserted. |
| `RESTPolicyRuleData` | `GET /v1/policy/rule/{id}` | envelope key `rule` inferred from §3.3 and from `RESTAdmissionRuleData` (`rule`), which B does document. Item fields come from `RESTPolicyRule`, which is in B. |
| `RESTFileMonitorFile` | `GET /v1/file_monitor/{name}` | **BLOCKED (partial)** — see `nv_get_file_monitor_profile` Notes. |
| `RESTDlpSensorsData` / `RESTDlpSensor` | `GET /v1/dlp/sensor` | **BLOCKED (partial)** — see `nv_list_dlp_sensors` Notes. |
| `RESTWafSensorsData` / `RESTWafSensor` | `GET /v1/waf/sensor` | **BLOCKED (partial)** — see `nv_list_waf_sensors` Notes. |
| `RESTServersData` / `RESTServer` | `GET /v1/server` | **BLOCKED (partial)** — see `nv_list_auth_servers` Notes. Drives an allowlist-only projection. |

**Envelope-suffix rule used throughout.** A 200 schema whose name ends in `Data`
is a wrapper: read the resource key (§3.3). A 200 schema whose name does **not**
end in `Data` (`RESTFileMonitorFile`, `RESTNvAlerts`,
`RESTAdmCtrlRulesTestResults`, `RESTAdmissionConfigData` is a `Data` name but its
own fields are top level) is the body itself: call
`app.client.request("GET", path)` and project the returned dict directly.

**Uniform annotations.** Every tool in this part:

```python
READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
```

tagged `{"<toolset>", "read"}` — exactly one toolset tag plus `"read"` — and
**no `confirm` argument** (gate rule R5).

---

## B.0 Module scaffolding

### B.0.1 `src/neuvector_mcp/tools/events.py` [Phase 5]

```python
"""Security event tools: threats, violations, incidents, audits, system events, alerts.

Every tool in this module is read-only and tagged ``events``.

Registration contract (identical in every tools/*.py module):

    def register(mcp: FastMCP, settings: Settings) -> None: ...
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..errors import NotFoundError
from ..models import (
    AuditEvent,
    AuditEventList,
    Page,
    SecurityEvent,
    SecurityEventList,
    SystemAlerts,
    SystemEvent,
    SystemEventList,
    ThreatDetail,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

#: (path, envelope key) per kind. Paths verified against spec_endpoints.json;
#: envelope keys verified against RESTThreatsData / RESTPolicyViolationsData /
#: RESTIncidentsData in appendix B.
_KIND_ENDPOINT: dict[str, tuple[str, str]] = {
    "threat": ("/v1/log/threat", "threats"),
    "violation": ("/v1/log/violation", "violations"),
    "incident": ("/v1/log/incident", "incidents"),
}

#: Severity lives in a DIFFERENT json tag per type: Threat has both 'level' and
#: 'severity'; Violation and Incident have only 'level'.
_SEVERITY_FIELD: dict[str, str] = {
    "threat": "severity",
    "violation": "level",
    "incident": "level",
}

#: Namespace json tag per (kind, side). All names from appendix B.
_DOMAIN_FIELD: dict[tuple[str, str], str] = {
    ("threat", "client"): "client_workload_domain",
    ("threat", "server"): "server_workload_domain",
    ("violation", "client"): "client_domain",
    ("violation", "server"): "server_domain",
    ("incident", "client"): "workload_domain",
    ("incident", "server"): "remote_workload_domain",
}

#: Workload-id json tag per (kind, side). All names from appendix B.
_WORKLOAD_ID_FIELD: dict[tuple[str, str], str] = {
    ("threat", "client"): "client_workload_id",
    ("threat", "server"): "server_workload_id",
    ("violation", "client"): "client_id",
    ("violation", "server"): "server_id",
    ("incident", "client"): "workload_id",
    ("incident", "server"): "remote_workload_id",
}


def _reported_time_filter(
    since_timestamp: int | None, until_timestamp: int | None
) -> tuple[dict[str, str], int | None]:
    """Split a time window into a server-side filter plus a residual client bound.

    ``build_query`` renders exactly one value per field, so ONE request cannot
    carry both ``gte`` and ``lte`` on ``reported_timestamp``. Rule:

    * ``since`` only  -> ``f_reported_timestamp=gte,<since>``, no residual
    * ``until`` only  -> ``f_reported_timestamp=lte,<until>``, no residual
    * both            -> ``f_reported_timestamp=gte,<since>`` and ``until`` is
      returned as the residual bound, applied client-side after paging.

    Returns:
        ``(filters_fragment, residual_until)``.
    """
    if since_timestamp is not None:
        return {"reported_timestamp": f"gte,{since_timestamp}"}, until_timestamp
    if until_timestamp is not None:
        return {"reported_timestamp": f"lte,{until_timestamp}"}, None
    return {}, None


def _trim_window(items: list[dict], residual_until: int | None) -> tuple[list[dict], int]:
    """Drop items newer than ``residual_until``. Returns ``(kept, dropped_count)``."""
    if residual_until is None:
        return items, 0
    kept = [i for i in items if int(i.get("reported_timestamp") or 0) <= residual_until]
    return kept, len(items) - len(kept)
```

`_reported_time_filter` and `_trim_window` are module-private and used by
`nv_query_security_events`, `nv_query_audit_events` and `nv_query_system_events`.
They must not be imported by another `tools/*` module (SPEC §4.1).

### B.0.2 `src/neuvector_mcp/tools/policy_read.py` [Phase 6]

Same header shape as B.0.1 — same `from __future__`, same `Annotated`/`Literal`,
`Any`, `fastmcp`, `ToolAnnotations`, `Field` imports, the same `READ_ONLY`
constant, `from ..client import build_query`, `from ..config import Settings`,
`from ..context import app_context`, `from ..errors import NotFoundError` — with
docstring `"""Read-only policy tools ... tagged ``policy_read``."""`,
`if not settings.toolset_enabled("policy_read"): return`, and these models:

```python
from ..models import (
    AdmissionAssessment,
    AdmissionCriterionInput,
    AdmissionRule,
    AdmissionRuleList,
    AdmissionState,
    DlpSensorList,
    FileMonitorProfile,
    NetworkRule,
    NetworkRuleList,
    Page,
    ProcessProfile,
    ResponseRule,
    ResponseRuleList,
    WafSensorList,
)
```

### B.0.3 `src/neuvector_mcp/tools/iam.py` [Phase 10]

`tools/iam.py` holds both `iam_read` (this part) and `iam_write` (Part C). The
read tools are registered under `if settings.toolset_enabled("iam_read"):` and
the write tools under a separate `if settings.toolset_enabled("iam_write"):`
block, so enabling one never registers the other. Same header imports as B.0.2
(no `NotFoundError` is needed — every `iam_read` tool is a list tool). Models for
the read half:

```python
from ..models import (
    ApiKeyBrief,
    ApiKeyList,
    AuthServerBrief,
    AuthServerList,
    Page,
    RoleBrief,
    RoleList,
    RolePermission,
    UserBrief,
    UserList,
)
```

---

# Toolset `events` (read) — 5 tools

### `nv_query_security_events`

| | |
|---|---|
| **Toolset** | `events` (read) |
| **Endpoints** | `GET /v1/log/threat`, `GET /v1/log/violation`, `GET /v1/log/incident` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `SecurityEventList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `kind` | `Literal["threat", "violation", "incident"]` | — | Which log to read. 'threat' is network IDS/IPS and DLP/WAF detections, 'violation' is network traffic outside the learned or declared network policy, 'incident' is process, file and privilege-escalation activity outside the process profile. |
| `namespace` | `str \| None` | `None` | Filter to one Kubernetes namespace. Applied to the side selected by 'side'. |
| `severity` | `str \| None` | `None` | Filter by severity. For kind='threat' this filters the 'severity' field (Critical, High, Medium, Low, Info). For kind='violation' and kind='incident' it filters 'level' instead, whose vocabulary the controller does not publish; an unrecognised value returns an empty page rather than an error. |
| `workload_id` | `str \| None` | `None` | Filter to one workload id, on the side selected by 'side'. Get ids from nv_list_workloads. |
| `side` | `Literal["client", "server"]` | `"client"` | Which endpoint of the event the 'namespace' and 'workload_id' filters apply to. Controller filters are ANDed, so one call can constrain one side only; query twice to cover both. For kind='incident', 'client' means the subject workload and 'server' means the remote peer. |
| `since_timestamp` | `int \| None` (ge=0) | `None` | Lower bound on 'reported_timestamp', Unix epoch seconds, inclusive. |
| `until_timestamp` | `int \| None` (ge=0) | `None` | Upper bound on 'reported_timestamp', Unix epoch seconds, inclusive. When both bounds are given the controller applies the lower bound and the server trims the upper bound after paging; see 'dropped_outside_window' in the result. |
| `newest_first` | `bool` | `True` | Sort by 'reported_timestamp' descending. The controller ignores an unsupported sort silently, so treat ordering as best effort. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum events to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

`<kind>` selects both the path and the json tags. The controller filters
generically on the **json tag of the response field** (§3.2), and the three log
types name the same concepts differently — this table is the whole point of the
tool:

| Argument | `kind="threat"` | `kind="violation"` | `kind="incident"` |
|---|---|---|---|
| path | `/v1/log/threat` | `/v1/log/violation` | `/v1/log/incident` |
| envelope | `threats` | `violations` | `incidents` |
| `namespace`, `side="client"` | `f_client_workload_domain` | `f_client_domain` | `f_workload_domain` |
| `namespace`, `side="server"` | `f_server_workload_domain` | `f_server_domain` | `f_remote_workload_domain` |
| `workload_id`, `side="client"` | `f_client_workload_id` | `f_client_id` | `f_workload_id` |
| `workload_id`, `side="server"` | `f_server_workload_id` | `f_server_id` | `f_remote_workload_id` |
| `severity` | `f_severity` | `f_level` | `f_level` |
| `since_timestamp` | `f_reported_timestamp=gte,<v>` | same | same |
| `until_timestamp` (alone) | `f_reported_timestamp=lte,<v>` | same | same |
| `newest_first` | `s_reported_timestamp=desc` | same | same |
| `start` | `start` | same | same |
| `limit` | `limit + 1` (over-fetch to detect truncation) | same | same |

At most 8 filters per request are honoured (§3.2); this tool can send at most 4,
so the cap is never reached.

**Docstring (use verbatim)**

```
Query one of NeuVector's three runtime security event logs.

Pick 'kind' first: threat = network IDS/IPS, DLP and WAF detections;
violation = connections outside the learned or declared network policy;
incident = process, file and escalation activity outside the process profile.
Each log names the same concepts with different fields, so the namespace and
workload filters are translated per kind; 'side' chooses which end of the event
they constrain because controller filters are ANDed. Get workload ids from
nv_list_workloads. For a threat's captured packet call nv_get_threat_detail —
the list form has the packet stripped by the controller.

Calls GET /v1/log/threat with f_client_workload_domain, f_client_workload_id, f_severity, f_reported_timestamp.
Calls GET /v1/log/violation with f_client_domain, f_client_id, f_level, f_reported_timestamp.
Calls GET /v1/log/incident with f_workload_domain, f_workload_id, f_level, f_reported_timestamp.
```

**Body (normative)**

```python
app = app_context(ctx)
effective_limit = min(limit, app.settings.max_items)
path, envelope = _KIND_ENDPOINT[kind]

filters: dict[str, str] = {}
if namespace:
    filters[_DOMAIN_FIELD[(kind, side)]] = namespace
if workload_id:
    filters[_WORKLOAD_ID_FIELD[(kind, side)]] = workload_id
if severity:
    filters[_SEVERITY_FIELD[kind]] = severity
time_filters, residual_until = _reported_time_filter(since_timestamp, until_timestamp)
filters.update(time_filters)

params = build_query(
    start=start,
    limit=effective_limit + 1,  # over-fetch by one to detect truncation
    filters=filters,
    sort={"reported_timestamp": "desc"} if newest_first else None,
)
items = await app.client.get_list(path, envelope, params=params)
truncated = len(items) > effective_limit
page_items = items[:effective_limit]
kept, dropped = _trim_window(page_items, residual_until)
return SecurityEventList(
    page=Page(
        start=start,
        returned=len(kept),
        truncated=truncated,
        hint=(
            f"More {kind} events exist. Call again with start={start + len(page_items)}, "
            "or narrow with namespace/workload_id/severity/since_timestamp."
            if truncated
            else None
        ),
    ),
    kind=kind,
    dropped_outside_window=dropped,
    events=[SecurityEvent.from_api(i, kind=kind) for i in kept],
)
```

**Output model**

```python
EventKind = Literal["threat", "violation", "incident"]


def _clip(text: str, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to ``limit`` characters. Returns (text, was_truncated)."""
    if limit <= 0:
        return "", bool(text)
    if len(text) <= limit:
        return text, False
    return text[:limit], True


class SecurityEvent(BaseModel):
    """One threat, network-policy violation or runtime incident, normalised.

    The three controller types name the same concepts differently, so this
    projection maps them onto one vocabulary. Fields that a given kind does not
    carry stay at their default.
    """

    model_config = _BASE

    kind: EventKind = Field(description="Which log this came from.")
    id: str = Field(default="", description="Event id. For kind='threat' pass to nv_get_threat_detail.")
    name: str = Field(default="", description="Controller event name, e.g. the rule or signature name.")
    severity: str = Field(
        default="",
        description="Threat 'severity', or 'level' for violations and incidents.",
    )
    level: str = Field(default="", description="Controller log level, verbatim.")
    reported_timestamp: int = Field(default=0, description="Unix epoch seconds the enforcer reported the event.")
    reported_at: str = Field(default="", description="Human-readable report time from the controller.")
    action: str = Field(
        default="",
        description="What the enforcer did: threat 'action', violation 'policy_action', incident 'action'.",
    )
    client_id: str = Field(default="", description="Subject/client workload id, or '' when the peer is external.")
    client_name: str = Field(default="", description="Subject/client workload name.")
    client_namespace: str = Field(default="", description="Subject/client Kubernetes namespace.")
    client_ip: str = Field(default="", description="Source IP.")
    server_id: str = Field(default="", description="Peer/server workload id, or '' when external.")
    server_name: str = Field(default="", description="Peer/server workload name.")
    server_namespace: str = Field(default="", description="Peer/server Kubernetes namespace.")
    server_ip: str = Field(default="", description="Destination IP.")
    server_port: int = Field(default=0, description="Destination port.")
    ip_proto: int = Field(default=0, description="IP protocol number, 6=TCP 17=UDP 1=ICMP.")
    applications: str = Field(
        default="",
        description="Comma-joined application protocols the enforcer identified.",
    )
    group: str = Field(default="", description="NeuVector group the event was attributed to.")
    matched_rule_id: str = Field(
        default="",
        description="Rule that matched: incident 'rule_id', or violation 'policy_id'. "
        "Empty for threats, which carry 'threat_id' instead.",
    )
    threat_id: int = Field(default=0, description="Threat signature id; kind='threat' only.")
    count: int = Field(
        default=0,
        description="Aggregated occurrence count; for violations this is the session count.",
    )
    proc_name: str = Field(default="", description="Process name; kind='incident' only.")
    proc_path: str = Field(default="", description="Process path; kind='incident' only.")
    file_path: str = Field(default="", description="File path; kind='incident' only.")
    sensor: str = Field(default="", description="DLP/WAF sensor that fired; kind='threat' only.")
    host_name: str = Field(default="", description="Node that reported the event.")
    message: str = Field(
        default="",
        description="Controller message, clipped to 2000 characters. Violations carry no message.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, kind: EventKind) -> "SecurityEvent":
        """Project a ``Threat``, ``Violation`` or ``Incident`` onto one shape.

        Note the non-template signature: the discriminator is required because
        the source field names differ per kind.
        """
        common = dict(
            kind=kind,
            id=str(raw.get("id", "") or ""),
            name=str(raw.get("name", "") or ""),
            level=str(raw.get("level", "") or ""),
            reported_timestamp=int(raw.get("reported_timestamp") or 0),
            reported_at=str(raw.get("reported_at", "") or ""),
            client_ip=str(raw.get("client_ip", "") or ""),
            server_ip=str(raw.get("server_ip", "") or ""),
            server_port=int(raw.get("server_port") or 0),
            ip_proto=int(raw.get("ip_proto") or 0),
            host_name=str(raw.get("host_name", "") or ""),
            message=_clip(str(raw.get("message", "") or ""), 2000)[0],
        )
        if kind == "threat":
            return cls(
                **common,
                severity=str(raw.get("severity", "") or ""),
                action=str(raw.get("action", "") or ""),
                client_id=str(raw.get("client_workload_id", "") or ""),
                client_name=str(raw.get("client_workload_name", "") or ""),
                client_namespace=str(raw.get("client_workload_domain", "") or ""),
                server_id=str(raw.get("server_workload_id", "") or ""),
                server_name=str(raw.get("server_workload_name", "") or ""),
                server_namespace=str(raw.get("server_workload_domain", "") or ""),
                applications=str(raw.get("application", "") or ""),
                group=str(raw.get("group", "") or ""),
                threat_id=int(raw.get("threat_id") or 0),
                count=int(raw.get("count") or 0),
                sensor=str(raw.get("sensor", "") or ""),
            )
        if kind == "violation":
            policy_id = raw.get("policy_id")
            return cls(
                **common,
                severity=str(raw.get("level", "") or ""),
                action=str(raw.get("policy_action", "") or ""),
                client_id=str(raw.get("client_id", "") or ""),
                client_name=str(raw.get("client_name", "") or ""),
                client_namespace=str(raw.get("client_domain", "") or ""),
                server_id=str(raw.get("server_id", "") or ""),
                server_name=str(raw.get("server_name", "") or ""),
                server_namespace=str(raw.get("server_domain", "") or ""),
                applications=", ".join(str(a) for a in (raw.get("applications") or [])),
                matched_rule_id="" if policy_id is None else str(policy_id),
                count=int(raw.get("sessions") or 0),
            )
        return cls(
            **common,
            severity=str(raw.get("level", "") or ""),
            action=str(raw.get("action", "") or ""),
            client_id=str(raw.get("workload_id", "") or ""),
            client_name=str(raw.get("workload_name", "") or ""),
            client_namespace=str(raw.get("workload_domain", "") or ""),
            server_id=str(raw.get("remote_workload_id", "") or ""),
            server_name=str(raw.get("remote_workload_name", "") or ""),
            server_namespace=str(raw.get("remote_workload_domain", "") or ""),
            group=str(raw.get("group", "") or ""),
            matched_rule_id=str(raw.get("rule_id", "") or ""),
            count=int(raw.get("count") or 0),
            proc_name=str(raw.get("proc_name", "") or ""),
            proc_path=str(raw.get("proc_path", "") or ""),
            file_path=str(raw.get("file_path", "") or ""),
        )


class SecurityEventList(BaseModel):
    """Result of ``nv_query_security_events``."""

    model_config = _BASE

    page: Page
    kind: EventKind = Field(description="Which log was queried.")
    dropped_outside_window: int = Field(
        default=0,
        description="Items the controller returned that fell outside until_timestamp and were "
        "removed after paging. Non-zero means this page holds fewer than 'limit' items even "
        "though more matching events may exist.",
    )
    events: list[SecurityEvent]
```

**Fixtures**
`tests/fixtures/log_threat.json` — envelope key `threats`;
`tests/fixtures/log_violation.json` — envelope key `violations`;
`tests/fixtures/log_incident.json` — envelope key `incidents`.
Each holds 3 items so a `limit=2` call proves the over-fetch and `truncated=True`.

**Tests** `tests/test_events.py`: `test_query_threats_projects_and_pages`,
`test_query_violations_uses_level_and_client_domain`,
`test_query_incidents_uses_workload_domain`,
`test_side_server_switches_filter_field`,
`test_both_time_bounds_send_gte_and_trim_client_side`.
Each asserts the exact `f_*` / `s_*` / `start` / `limit` params (§10.1).

**Notes**
* Fields verified in Appendix B: `Threat`, `Violation`, `Incident`, and the
  envelopes `RESTThreatsData` (`threats`), `RESTPolicyViolationsData`
  (`violations`), `RESTIncidentsData` (`incidents`).
* `Violation` has **no** `severity` and **no** `message` field. Do not read
  either — `severity` maps to `level` and `message` stays `""`.
* `Threat` carries both `level` and `severity`; only `severity` is the
  Critical/High/Medium/Low/Info axis.
* **Threat list responses have the captured packet stripped by the controller.**
  `Threat.packet` and `Threat.cap_len` exist in the schema but the list route
  does not populate the payload. Never advertise packet bytes from this tool;
  route callers to `nv_get_threat_detail`.
* `from_api` takes a keyword-only `kind`, deviating from the template's
  `from_api(cls, raw)` signature. This is deliberate and is the only such
  deviation in Part B.
* Common controller errors: `code=25` object access denied when the API key's
  role lacks the namespace; `code=12` more search criteria required if the
  controller refuses an unfiltered scan — surface it, do not retry.

---

### `nv_get_threat_detail`

| | |
|---|---|
| **Toolset** | `events` (read) |
| **Endpoints** | `GET /v1/log/threat/{id}` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `ThreatDetail` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `threat_id` | `str` (min_length=1) | — | Event id from nv_query_security_events with kind='threat' (the 'id' field, not 'threat_id'). |
| `include_packet` | `bool` | `False` | True returns the captured packet as the controller encoded it, clipped to half of NV_MAX_RESPONSE_CHARS. Leave False unless you are inspecting payload bytes; captures routinely exceed the whole response budget. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `threat_id` | path segment `{id}` |
| `include_packet` | none — applied by the projection, not by the controller |

**Docstring (use verbatim)**

```
One threat event including its captured packet.

Unlike the list form, this route returns the packet the enforcer captured, which
can be tens of kilobytes and will exhaust a client's context if returned whole.
The packet is therefore omitted unless include_packet=True and is always clipped
to half of NV_MAX_RESPONSE_CHARS, with packet_truncated reporting the clip. Get
the id from nv_query_security_events with kind='threat'.

Calls GET /v1/log/threat/{id}.
```

**Body (normative)**

```python
app = app_context(ctx)
raw = await app.client.get_object(f"/v1/log/threat/{threat_id}", "threat")
if not raw:
    raise NotFoundError(f"no threat event with id {threat_id!r}")
budget = max(0, app.settings.max_response_chars // 2) if include_packet else 0
return ThreatDetail.from_api(raw, packet_budget=budget)
```

**Output model**

```python
class ThreatDetail(BaseModel):
    """Result of ``nv_get_threat_detail``: one threat plus its packet capture."""

    model_config = _BASE

    event: SecurityEvent = Field(description="The threat, projected like a list entry.")
    target: str = Field(default="", description="Which side the enforcer treated as the target.")
    monitor: bool = Field(
        default=False,
        description="True when the enforcer only logged the threat instead of blocking it.",
    )
    cap_len: int = Field(default=0, description="Captured packet length in bytes as reported by the enforcer.")
    packet: str = Field(
        default="",
        description="Captured packet as encoded by the controller, clipped to the budget. "
        "Empty when include_packet was False or nothing was captured.",
    )
    packet_chars: int = Field(default=0, description="Length of the packet field the controller sent, before clipping.")
    packet_truncated: bool = Field(
        default=False,
        description="True when the packet was clipped or withheld. The withheld bytes cannot be "
        "recovered through this server; use the NeuVector UI or a packet capture instead.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, packet_budget: int) -> "ThreatDetail":
        """Project a ``Threat`` object, clipping ``packet`` to ``packet_budget`` chars."""
        full = str(raw.get("packet", "") or "")
        clipped, was_clipped = _clip(full, packet_budget)
        return cls(
            event=SecurityEvent.from_api(raw, kind="threat"),
            target=str(raw.get("target", "") or ""),
            monitor=bool(raw.get("monitor", False)),
            cap_len=int(raw.get("cap_len") or 0),
            packet=clipped,
            packet_chars=len(full),
            packet_truncated=was_clipped,
        )
```

**Fixture** `tests/fixtures/log_threat_detail.json` — envelope key `threat`.
Give its `packet` at least 200 characters so a clipping test is meaningful.

**Tests** `tests/test_events.py`: `test_threat_detail_omits_packet_by_default`,
`test_threat_detail_clips_packet_to_budget` (set
`make_settings(max_response_chars=100)` and assert
`len(result.data.packet) == 50` and `packet_truncated is True`),
`test_threat_detail_missing_raises` (empty envelope → `NotFoundError`).

**Notes**
* `RESTThreatData` is **absent from Appendix B**; the envelope key `threat` is
  inferred from §3.3 and from the documented `RESTAdmissionRuleData` → `rule`
  precedent. The wrapped item is a `Threat`, which **is** in Appendix B, so
  every field name read here is verified.
* **Security/size rule, mandatory:** the packet may contain credentials or
  personal data in cleartext. It is withheld by default, never logged (SPEC N8
  already forbids logging argument values; do not log response bodies either),
  and clipped to `max_response_chars // 2` so the rest of the projection always
  fits inside the budget.
* Empty envelope means "no such event", not an empty event: raise
  `NotFoundError`. The controller may also answer `code=7`, which
  `errors.classify` already maps to `NotFoundError`.

---

### `nv_query_audit_events`

| | |
|---|---|
| **Toolset** | `events` (read) |
| **Endpoints** | `GET /v1/log/audit` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `AuditEventList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `namespace` | `str \| None` | `None` | Filter to one Kubernetes namespace (controller field 'workload_domain'). |
| `workload_id` | `str \| None` | `None` | Filter to one workload id from nv_list_workloads. |
| `level` | `str \| None` | `None` | Filter by controller log level, verbatim. |
| `name` | `str \| None` | `None` | Filter by audit event name, e.g. the scan or compliance event type. |
| `since_timestamp` | `int \| None` (ge=0) | `None` | Lower bound on 'reported_timestamp', Unix epoch seconds, inclusive. |
| `until_timestamp` | `int \| None` (ge=0) | `None` | Upper bound on 'reported_timestamp', Unix epoch seconds, inclusive. Applied after paging when a lower bound is also given. |
| `newest_first` | `bool` | `True` | Sort by 'reported_timestamp' descending. Best effort. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum audit events to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `namespace` | `f_workload_domain=<value>` |
| `workload_id` | `f_workload_id=<value>` |
| `level` | `f_level=<value>` |
| `name` | `f_name=<value>` |
| `since_timestamp` / `until_timestamp` | `f_reported_timestamp` per `_reported_time_filter` |
| `newest_first` | `s_reported_timestamp=desc` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Audit log: scan results, compliance findings and admission decisions per asset.

Reach for this to answer "what did NeuVector conclude about this image or
workload and when", including vulnerability counts at the time of the scan.
This is not the API-activity log — that is nv_query_system_events. Filters are
ANDed and use the controller's json tags, so namespace is 'workload_domain'.

Calls GET /v1/log/audit with f_workload_domain, f_workload_id, f_level, f_name, f_reported_timestamp.
```

**Body (normative)** — identical shape to §7.3 with envelope `audits`, the
`_reported_time_filter` / `_trim_window` pair as in `nv_query_security_events`,
`hint` text `f"More audit events exist. Call again with start={start + len(page_items)}, or narrow with namespace/level/since_timestamp."`.

**Output model**

```python
class AuditEvent(BaseModel):
    """One entry from the audit log."""

    model_config = _BASE

    name: str = Field(default="", description="Audit event name, e.g. the scan or compliance event type.")
    level: str = Field(default="", description="Controller log level, verbatim.")
    reported_timestamp: int = Field(default=0, description="Unix epoch seconds the event was reported.")
    reported_at: str = Field(default="", description="Human-readable report time.")
    cluster_name: str = Field(default="", description="Cluster that produced the event.")
    host_name: str = Field(default="", description="Node the event refers to.")
    workload_id: str = Field(default="", description="Workload id; pass to nv_get_workload.")
    workload_name: str = Field(default="", description="Workload name.")
    workload_namespace: str = Field(default="", description="Kubernetes namespace (controller field 'workload_domain').")
    workload_image: str = Field(default="", description="Image the workload runs.")
    workload_service: str = Field(default="", description="NeuVector service (group) name.")
    image: str = Field(default="", description="Scanned image reference, for registry and repository scan events.")
    registry_name: str = Field(default="", description="Registry configuration name, when the event concerns a registry.")
    repository: str = Field(default="", description="Repository within the registry.")
    tag: str = Field(default="", description="Image tag.")
    base_os: str = Field(default="", description="Base OS the scanner identified.")
    high_vul_cnt: int = Field(default=0, description="High-severity vulnerability count at report time.")
    medium_vul_cnt: int = Field(default=0, description="Medium-severity vulnerability count at report time.")
    cvedb_version: str = Field(default="", description="Vulnerability database version used.")
    user: str = Field(default="", description="User the controller attributed the event to.")
    count: int = Field(default=0, description="Aggregated occurrence count.")
    message: str = Field(default="", description="Controller message, clipped to 2000 characters.")
    error: str = Field(default="", description="Controller error text when the audited operation failed.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "AuditEvent":
        """Project an ``Audit``. Vulnerability id arrays are deliberately dropped."""
        return cls(
            name=str(raw.get("name", "") or ""),
            level=str(raw.get("level", "") or ""),
            reported_timestamp=int(raw.get("reported_timestamp") or 0),
            reported_at=str(raw.get("reported_at", "") or ""),
            cluster_name=str(raw.get("cluster_name", "") or ""),
            host_name=str(raw.get("host_name", "") or ""),
            workload_id=str(raw.get("workload_id", "") or ""),
            workload_name=str(raw.get("workload_name", "") or ""),
            workload_namespace=str(raw.get("workload_domain", "") or ""),
            workload_image=str(raw.get("workload_image", "") or ""),
            workload_service=str(raw.get("workload_service", "") or ""),
            image=str(raw.get("image", "") or ""),
            registry_name=str(raw.get("registry_name", "") or ""),
            repository=str(raw.get("repository", "") or ""),
            tag=str(raw.get("tag", "") or ""),
            base_os=str(raw.get("base_os", "") or ""),
            high_vul_cnt=int(raw.get("high_vul_cnt") or 0),
            medium_vul_cnt=int(raw.get("medium_vul_cnt") or 0),
            cvedb_version=str(raw.get("cvedb_version") or ""),
            user=str(raw.get("user", "") or ""),
            count=int(raw.get("count") or 0),
            message=_clip(str(raw.get("message", "") or ""), 2000)[0],
            error=str(raw.get("error", "") or ""),
        )


class AuditEventList(BaseModel):
    """Result of ``nv_query_audit_events``."""

    model_config = _BASE

    page: Page
    dropped_outside_window: int = Field(
        default=0, description="Items removed after paging because they fell outside until_timestamp."
    )
    audits: list[AuditEvent]
```

**Fixture** `tests/fixtures/log_audit.json` — envelope key `audits`.

**Tests** `tests/test_events.py`: `test_query_audit_events_query_and_projection`,
`test_query_audit_events_truncates`.

**Notes**
* `Audit` and `RESTAuditsData` (`audits`) are both in Appendix B; every field
  above is verified.
* `high_vuls`, `medium_vuls`, `packages`, `items`, `cmds` and the CVSS scoring
  fields exist on `Audit` but are **not** projected: an audit entry can carry
  hundreds of CVE ids and would blow the response budget. Callers who need CVE
  detail use the `vulnerability` toolset.
* Do not confuse `f_name` (audit event type) with `f_workload_name`.

---

### `nv_query_system_events`

| | |
|---|---|
| **Toolset** | `events` (read) |
| **Endpoints** | `GET /v1/log/event` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `SystemEventList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `namespace` | `str \| None` | `None` | Filter to one Kubernetes namespace (controller field 'workload_domain'). |
| `category` | `str \| None` | `None` | Filter by event category, verbatim as the controller reports it. |
| `level` | `str \| None` | `None` | Filter by controller log level, verbatim. |
| `user` | `str \| None` | `None` | Filter to events attributed to one user, for auditing who changed what. |
| `name` | `str \| None` | `None` | Filter by system event name. |
| `since_timestamp` | `int \| None` (ge=0) | `None` | Lower bound on 'reported_timestamp', Unix epoch seconds, inclusive. |
| `until_timestamp` | `int \| None` (ge=0) | `None` | Upper bound on 'reported_timestamp', Unix epoch seconds, inclusive. Applied after paging when a lower bound is also given. |
| `newest_first` | `bool` | `True` | Sort by 'reported_timestamp' descending. Best effort. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum system events to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `namespace` | `f_workload_domain=<value>` |
| `category` | `f_category=<value>` |
| `level` | `f_level=<value>` |
| `user` | `f_user=<value>` |
| `name` | `f_name=<value>` |
| `since_timestamp` / `until_timestamp` | `f_reported_timestamp` per `_reported_time_filter` |
| `newest_first` | `s_reported_timestamp=desc` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
System event log: controller and enforcer lifecycle plus REST API activity.

Use this to see who changed configuration and when, whether an enforcer
disconnected, or whether the licence or enforcer limit fired. Filter by 'user'
for an accountability trail. For per-asset scan and compliance conclusions use
nv_query_audit_events instead; for runtime detections use
nv_query_security_events.

Calls GET /v1/log/event with f_workload_domain, f_category, f_level, f_user, f_name, f_reported_timestamp.
```

**Body (normative)** — §7.3 shape, envelope `events`, hint
`f"More system events exist. Call again with start={start + len(page_items)}, or narrow with category/level/user/since_timestamp."`.

**Output model**

```python
class SystemEvent(BaseModel):
    """One controller, enforcer or REST-API event."""

    model_config = _BASE

    name: str = Field(default="", description="System event name.")
    category: str = Field(default="", description="Event category as the controller reports it.")
    level: str = Field(default="", description="Controller log level, verbatim.")
    reported_timestamp: int = Field(default=0, description="Unix epoch seconds the event was reported.")
    reported_at: str = Field(default="", description="Human-readable report time.")
    cluster_name: str = Field(default="", description="Cluster that produced the event.")
    host_name: str = Field(default="", description="Node the event refers to.")
    controller_name: str = Field(default="", description="Controller that produced the event.")
    enforcer_name: str = Field(default="", description="Enforcer the event refers to.")
    workload_id: str = Field(default="", description="Workload id, when the event is workload-scoped.")
    workload_name: str = Field(default="", description="Workload name.")
    workload_namespace: str = Field(default="", description="Kubernetes namespace (controller field 'workload_domain').")
    user: str = Field(default="", description="User the controller attributed the event to.")
    user_addr: str = Field(default="", description="Client address the request came from.")
    rest_method: str = Field(default="", description="HTTP method, for REST-activity events.")
    rest_request: str = Field(default="", description="Request path, for REST-activity events.")
    enforcer_limit: int = Field(default=0, description="Licensed enforcer limit, on limit-related events.")
    license_expire: str = Field(default="", description="Licence expiry, on licence-related events.")
    message: str = Field(default="", description="Controller message, clipped to 2000 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "SystemEvent":
        """Project an ``Event``. 'rest_body' is dropped on purpose - see Notes."""
        return cls(
            name=str(raw.get("name", "") or ""),
            category=str(raw.get("category", "") or ""),
            level=str(raw.get("level", "") or ""),
            reported_timestamp=int(raw.get("reported_timestamp") or 0),
            reported_at=str(raw.get("reported_at", "") or ""),
            cluster_name=str(raw.get("cluster_name", "") or ""),
            host_name=str(raw.get("host_name", "") or ""),
            controller_name=str(raw.get("controller_name", "") or ""),
            enforcer_name=str(raw.get("enforcer_name", "") or ""),
            workload_id=str(raw.get("workload_id", "") or ""),
            workload_name=str(raw.get("workload_name", "") or ""),
            workload_namespace=str(raw.get("workload_domain", "") or ""),
            user=str(raw.get("user", "") or ""),
            user_addr=str(raw.get("user_addr", "") or ""),
            rest_method=str(raw.get("rest_method", "") or ""),
            rest_request=str(raw.get("rest_request", "") or ""),
            enforcer_limit=int(raw.get("enforcer_limit") or 0),
            license_expire=str(raw.get("license_expire", "") or ""),
            message=_clip(str(raw.get("message", "") or ""), 2000)[0],
        )


class SystemEventList(BaseModel):
    """Result of ``nv_query_system_events``."""

    model_config = _BASE

    page: Page
    dropped_outside_window: int = Field(
        default=0, description="Items removed after paging because they fell outside until_timestamp."
    )
    events: list[SystemEvent]
```

**Fixture** `tests/fixtures/log_event.json` — envelope key `events`.

**Tests** `tests/test_events.py`: `test_query_system_events_filters_by_user`,
`test_system_event_projection_drops_rest_body`.

**Notes**
* `Event` and `RESTEventsData` (`events`) are in Appendix B; every field above is
  verified. `user_session` and `user_roles` exist but are not projected.
* **`rest_body` is never projected.** `Event.rest_body` is the raw body of a
  recorded REST call and can contain registry passwords, user passwords and
  bearer tokens. Omitting it is a hard requirement, consistent with SPEC N8.
  Do not add it later "for debugging".
* `GET /v1/log/activity` also returns `RESTEventsData` and is documented, but no
  tool in this spec uses it. Do not add it here.

---

### `nv_get_system_alerts`

| | |
|---|---|
| **Toolset** | `events` (read) |
| **Endpoints** | `GET /v1/system/alerts` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `SystemAlerts` |

**Arguments** — none beyond `ctx`.

**Query mapping** — none. Appendix A documents no query parameters for this
route; send none.

**Docstring (use verbatim)**

```
Standing NeuVector platform alerts, such as licence and configuration warnings.

Call this early in a health check: these are the conditions the controller
itself considers wrong, independent of any workload. Alert text is returned
verbatim as strings because the controller's alert schema is not published; use
nv_query_system_events for the timestamped history behind an alert.

Calls GET /v1/system/alerts.
```

**Body (normative)**

```python
app = app_context(ctx)
raw = await app.client.request("GET", "/v1/system/alerts")
return SystemAlerts.from_api(raw if isinstance(raw, dict) else {})
```

**Output model**

```python
class SystemAlerts(BaseModel):
    """Result of ``nv_get_system_alerts``.

    ``RESTNvAlerts`` is absent from Appendix B, so this model asserts no field
    names inside an alert. It reports alert text as strings and echoes the
    top-level keys the controller used, so the shape can be confirmed against a
    live controller without another code change.
    """

    model_config = _BASE

    alerts: list[str] = Field(
        default_factory=list,
        description="Alert text, one entry per alert, clipped to 1000 characters each.",
    )
    count: int = Field(default=0, description="Number of alerts returned.")
    envelope_keys: list[str] = Field(
        default_factory=list,
        description="Top-level keys the controller returned. Diagnostic: the alert envelope key "
        "is not documented, so this reveals the real shape.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "SystemAlerts":
        """Extract alert text defensively.

        Preference order: the ``alerts`` key (§3.3 naming convention), else the
        first list-valued top-level key. List entries may be strings or objects;
        objects are reduced to their ``message`` or ``name`` value if present,
        else to an empty string.
        """
        raw_list: list[Any] = []
        candidate = raw.get("alerts")
        if isinstance(candidate, list):
            raw_list = candidate
        else:
            for value in raw.values():
                if isinstance(value, list):
                    raw_list = value
                    break
        texts: list[str] = []
        for item in raw_list:
            if isinstance(item, str):
                text = item
            elif isinstance(item, dict):
                text = str(item.get("message") or item.get("name") or "")
            else:
                text = ""
            if text:
                texts.append(_clip(text, 1000)[0])
        return cls(alerts=texts, count=len(texts), envelope_keys=sorted(raw.keys()))
```

**Fixture** `tests/fixtures/system_alerts.json` — envelope key `alerts`
(**inferred**, see Notes). Write it as `{"alerts": ["...", "..."]}` and add a
second test that feeds `{"nv_alerts": [{"message": "..."}]}` inline to prove the
fallback path.

**Tests** `tests/test_events.py`: `test_system_alerts_reads_alerts_key`,
`test_system_alerts_falls_back_to_first_list_key`.

**Notes**
* **BLOCKED (partial): `RESTNvAlerts` is absent from `appendix/B-schema-reference.md`.**
  The endpoint itself is verified documented (`GET /v1/system/alerts`), so the
  tool ships, but neither the envelope key nor any item field name can be
  verified. Consequences, all mandatory: no field name is asserted; extraction
  is the defensive routine above; `envelope_keys` is returned so the real shape
  is observable. Do **not** replace this with a typed model until a live
  controller response is captured and Appendix B is updated.
* `RESTNvAlerts` does not end in `Data`, so the body is the object itself, not a
  wrapper around a resource key — hence `client.request`, not `get_list`.

---

# Toolset `policy_read` (read) — 10 tools

### `nv_list_network_rules`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/policy/rule` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `NetworkRuleList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `scope` | `Literal["local", "fed"]` | `"local"` | 'local' returns this cluster's rules, 'fed' returns rules pushed from a federation primary. Federated rules cannot be edited on this cluster. |
| `from_group` | `str \| None` | `None` | Return only rules whose source is this group name (controller field 'from'). Get names from nv_list_groups. |
| `to_group` | `str \| None` | `None` | Return only rules whose destination is this group name (controller field 'to'). |
| `action` | `Literal["allow", "deny"] \| None` | `None` | Return only rules with this action. |
| `cfg_type` | `Literal["learned", "user_created", "ground", "federal"] \| None` | `None` | Return only rules of this provenance: 'learned' was inferred in Discover mode, 'user_created' was added through the API or UI, 'ground' came from a Kubernetes CRD, 'federal' was pushed by a federation primary. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset into the ordered rule list. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum rules to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `scope` | `scope=<value>` (via `extra`) |
| `from_group` | `f_from=<value>` |
| `to_group` | `f_to=<value>` |
| `action` | `f_action=<value>` |
| `cfg_type` | `f_cfg_type=<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Network policy rules in controller evaluation order.

Rules are evaluated top-down in the order returned and the first match wins, so
list position is semantically load-bearing: paging with 'start' preserves that
order, and a rule's effect depends on everything above it. Read 'order' for the
position within this page and 'priority' for the controller's own ordering
weight. Provenance comes from 'cfg_type' and 'learned', never from the id value.
Filters are ANDed, so a from_group + to_group query returns only rules matching
both endpoints.

Calls GET /v1/policy/rule with scope, f_from, f_to, f_action and f_cfg_type.
```

**Body (normative)** — §7.3 shape, envelope `rules`,
`extra={"scope": scope}`, hint
`f"More rules exist. Call again with start={start + len(page_items)} to continue in evaluation order."`.
`order` is assigned while projecting so evaluation position survives paging:

```python
rules=[
    NetworkRule.from_api(item, order=start + offset)
    for offset, item in enumerate(page_items)
],
```

**Output model**

```python
class NetworkRule(BaseModel):
    """One network policy rule."""

    model_config = _BASE

    id: int = Field(description="Rule id; pass to nv_get_network_rule or nv_delete_network_rule.")
    order: int = Field(
        default=0,
        description="Zero-based position in the controller's evaluation order, counted from the "
        "start of the whole list, not of this page. Lower wins.",
    )
    from_group: str = Field(default="", description="Source group name (controller field 'from').")
    to_group: str = Field(default="", description="Destination group name (controller field 'to').")
    ports: str = Field(default="", description="Free-form port list the rule matches, e.g. 'tcp/443,udp/53'.")
    applications: list[str] = Field(
        default_factory=list, description="Application protocols the rule matches; empty means any."
    )
    action: str = Field(default="", description="allow or deny.")
    learned: bool = Field(default=False, description="True when NeuVector inferred this rule in Discover mode.")
    disable: bool = Field(default=False, description="True when the rule is present but not enforced.")
    cfg_type: str = Field(
        default="",
        description="Provenance: learned | user_created | ground (Kubernetes CRD) | federal "
        "(pushed by a federation primary). Federal and ground rules are read-only here.",
    )
    priority: int = Field(default=0, description="Controller ordering weight; lower is evaluated earlier.")
    match_counter: int = Field(default=0, description="How many times the rule has matched since it was created.")
    last_match_timestamp: int = Field(default=0, description="Unix epoch seconds of the last match, 0 if never.")
    created_timestamp: int = Field(default=0, description="Unix epoch seconds the rule was created.")
    last_modified_timestamp: int = Field(default=0, description="Unix epoch seconds the rule was last changed.")
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, order: int = 0) -> "NetworkRule":
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
    scope: str = Field(default="local", description="Scope the rules were read from: local or fed.")
    rules: list[NetworkRule]
```

**Fixture** `tests/fixtures/policy_rules.json` — envelope key `rules`. Include
one `learned` rule and one `user_created` rule so the provenance assertions bite.

**Tests** `tests/test_policy_read.py`:
`test_list_network_rules_sends_scope_and_filters`,
`test_list_network_rules_order_is_absolute_across_pages` (call with `start=2`
and assert `rules[0].order == 2`), `test_list_network_rules_truncates`.

**Notes**
* `RESTPolicyRule` and `RESTPolicyRulesData` (`rules`) are in Appendix B; every
  field above is verified.
* **Ordering, stated for the implementer:** the controller returns the rule list
  in evaluation order; evaluation is top-down and first-match-wins. `priority`
  is the controller's own ordering weight and `order` is the absolute list
  position this server computes. Reordering is a `policy_write` concern
  (`PATCH /v1/policy/rule` with `RESTPolicyRuleActionData.move`), not this tool.
* **BLOCKED (partial): the numeric id ranges that separate learned,
  user-created, ground and federated rules are not published in Appendix A or B.**
  Therefore: never infer provenance from an id threshold, and do not document
  one. Use `cfg_type` (`learned | user_created | ground | federal`) and the
  `learned` boolean, both of which are in Appendix B. If a future appendix adds
  the ranges, they belong in the `cfg_type` description, not in code.
* `scope=fed` on a cluster that is not in a federation returns an empty list,
  not an error.

---

### `nv_get_network_rule`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/policy/rule/{id}` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `NetworkRule` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `rule_id` | `int` (ge=0) | — | Rule id from nv_list_network_rules. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `rule_id` | path segment `{id}` |

**Docstring (use verbatim)**

```
One network policy rule by id, including its match counters.

Use this to confirm a rule's exact source, destination, ports and provenance
before changing or deleting it. It cannot tell you the rule's evaluation
position: that comes from the ordered list, so call nv_list_network_rules when
position matters.

Calls GET /v1/policy/rule/{id}.
```

**Body (normative)**

```python
app = app_context(ctx)
raw = await app.client.get_object(f"/v1/policy/rule/{rule_id}", "rule")
if not raw:
    raise NotFoundError(f"no network rule with id {rule_id}")
return NetworkRule.from_api(raw)
```

**Fixture** `tests/fixtures/policy_rule.json` — envelope key `rule`.

**Tests** `tests/test_policy_read.py`: `test_get_network_rule_projects`,
`test_get_network_rule_missing_raises`,
`test_get_network_rule_access_denied_is_classified` (`code=25`).

**Notes**
* `RESTPolicyRuleData` is **absent from Appendix B**; the envelope key `rule` is
  inferred from §3.3 and matches the documented `RESTAdmissionRuleData` → `rule`.
  The wrapped item is a `RESTPolicyRule`, which **is** in B, so all projected
  field names are verified.
* `order` stays `0` here because a single-rule fetch carries no position. Say so
  in the docstring — already done — and do not fake a value.
* Reuses `NetworkRule`; do not define a second model.

---

### `nv_get_process_profile`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/process_profile/{name}` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `ProcessProfile` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group whose process profile to read, e.g. 'nv.api.prod'. Get names from nv_list_groups. |
| `max_entries` | `int` (ge=1, le=1000) | `100` | Maximum process entries to return. A learned profile can hold hundreds; entries beyond this are dropped and entries_truncated is set. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` |
| `max_entries` | none — applied by the projection, not by the controller |

**Docstring (use verbatim)**

```
Allowed-process profile for one group, with its enforcement mode.

This is the allowlist NeuVector compares running processes against; anything
outside it produces a 'process' incident, visible through
nv_query_security_events with kind='incident'. 'mode' decides whether a
violation is only logged (Discover, Monitor) or blocked (Protect). The
controller returns the whole profile in one body, so entries are capped
client-side by max_entries rather than paged.

Calls GET /v1/process_profile/{name}.
```

**Body (normative)**

```python
app = app_context(ctx)
raw = await app.client.get_object(f"/v1/process_profile/{group_name}", "process_profile")
if not raw:
    raise NotFoundError(f"no process profile for group {group_name!r}")
return ProcessProfile.from_api(raw, max_entries=max_entries)
```

**Output model**

```python
class ProcessProfileEntry(BaseModel):
    """One allowed (or explicitly denied) process in a group's profile."""

    model_config = _BASE

    name: str = Field(description="Process name as the enforcer sees it.")
    path: str = Field(default="", description="Absolute executable path; empty means any path.")
    user: str = Field(default="", description="User the process is expected to run as; empty means any.")
    uid: int = Field(default=0, description="Expected uid; 0 when unset rather than meaning root.")
    action: str = Field(default="", description="allow or deny.")
    cfg_type: str = Field(
        default="",
        description="Provenance: learned | user_created | ground | federal | system_defined.",
    )
    uuid: str = Field(default="", description="Entry uuid; the handle for updates through nv_update_process_profile.")
    group: str = Field(default="", description="Group the entry belongs to, set when inherited from another group.")
    created_timestamp: int = Field(default=0, description="Unix epoch seconds the entry was created.")
    last_modified_timestamp: int = Field(default=0, description="Unix epoch seconds the entry was last changed.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "ProcessProfileEntry":
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
    mode: PolicyMode = Field(default="", description="Enforcement mode: Discover, Monitor or Protect.")
    alert_disabled: bool = Field(default=False, description="True when profile violations do not raise alerts.")
    hash_enabled: bool = Field(default=False, description="True when executable hashes are verified as well as paths.")
    entries_total: int = Field(default=0, description="Entries the controller returned, before the max_entries cap.")
    entries_truncated: bool = Field(
        default=False,
        description="True when entries were dropped by max_entries. Raise max_entries to see the rest.",
    )
    entries: list[ProcessProfileEntry]

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_entries: int = 100) -> "ProcessProfile":
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
```

**Fixture** `tests/fixtures/process_profile.json` — envelope key
`process_profile`. Give it 3 entries so a `max_entries=2` test proves the cap.

**Tests** `tests/test_policy_read.py`: `test_get_process_profile_projects_entries`,
`test_get_process_profile_caps_entries`,
`test_get_process_profile_missing_raises`.

**Notes**
* `RESTProcessProfileData` (envelope key `process_profile`), `RESTProcessProfile`
  and `RESTProcessProfileEntry` are all in Appendix B; every field is verified.
* The §7.3 over-fetch-by-one pattern **does not apply**: this is a single-object
  route with no `start`/`limit`, so the whole profile arrives in one body and the
  cap is client-side. `entries_total` reports the pre-cap count, which
  over-fetching would have provided on a list route.
* `mode` reuses the existing `PolicyMode` alias from `models.py`. Do not redefine
  it.
* `GET /v1/process_profile` (the list form, with `scope`) is documented but no
  tool in this spec uses it; adding one is out of scope for Part B.

---

### `nv_get_file_monitor_profile`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/file_monitor/{name}` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `FileMonitorProfile` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `group_name` | `str` (min_length=1) | — | Group whose file-monitor profile to read, e.g. 'nv.api.prod'. Get names from nv_list_groups. |
| `max_filters` | `int` (ge=1, le=1000) | `100` | Maximum file filters to return. Filters beyond this are dropped and filters_truncated is set. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `group_name` | path segment `{name}` |
| `max_filters` | none — applied by the projection, not by the controller |

**Docstring (use verbatim)**

```
File-monitor filters for one group: which paths NeuVector watches and how.

Each filter names a path or glob, whether it recurses, and the behaviour on a
hit (monitor or block). Matches surface as file incidents through
nv_query_security_events with kind='incident'; the file_path field there
corresponds to a filter here.

Calls GET /v1/file_monitor/{name}.
```

**Body (normative)**

```python
app = app_context(ctx)
body = await app.client.request("GET", f"/v1/file_monitor/{group_name}")
raw = body if isinstance(body, dict) else {}
if not raw:
    raise NotFoundError(f"no file monitor profile for group {group_name!r}")
return FileMonitorProfile.from_api(raw, group_name=group_name, max_filters=max_filters)
```

**Output model**

```python
class FileMonitorFilter(BaseModel):
    """One watched path pattern."""

    model_config = _BASE

    filter: str = Field(default="", description="Path or glob being watched.")
    recursive: bool = Field(default=False, description="True when subdirectories are watched too.")
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
    def from_api(cls, raw: dict[str, Any]) -> "FileMonitorFilter":
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
    filters_total: int = Field(default=0, description="Filters the controller returned, before the cap.")
    filters_truncated: bool = Field(default=False, description="True when filters were dropped by max_filters.")
    envelope_keys: list[str] = Field(
        default_factory=list,
        description="Top-level keys the controller returned. Diagnostic: this response shape is "
        "not documented in the schema reference.",
    )
    filters: list[FileMonitorFilter]

    @classmethod
    def from_api(
        cls, raw: dict[str, Any], *, group_name: str, max_filters: int = 100
    ) -> "FileMonitorProfile":
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
```

**Fixture** `tests/fixtures/file_monitor_profile.json` — envelope key `filters`
(**inferred**, see Notes). Add a second inline case
`{"profile": {"filters": [...]}}` to exercise the nested branch.

**Tests** `tests/test_policy_read.py`:
`test_get_file_monitor_profile_reads_filters_key`,
`test_get_file_monitor_profile_reads_nested_profile_key`,
`test_get_file_monitor_profile_missing_raises`.

**Notes**
* **BLOCKED (partial): `RESTFileMonitorFile` and `RESTFileMonitorFileData` are
  absent from `appendix/B-schema-reference.md`.** The endpoint is verified
  documented, so the tool ships, but the response envelope is unknown.
  Consequences: no envelope key is assumed (three candidates are tried in a
  fixed order), `envelope_keys` is returned for diagnosis, and the only item
  field names used — `filter`, `recursive`, `behavior`, `applications`, `group`
  — are exactly those Appendix B documents on `RESTFileMonitorFilterConfig`, the
  *request*-side counterpart. Every read uses `.get()` with a default.
* `behavior` is typed `bool | str` because the config-side schema types it
  `string` while some controller builds report a boolean; both serialise
  cleanly. Do not coerce to `bool`.
* `RESTFileMonitorFile` does not end in `Data`, which is why the body is fetched
  with `client.request` and probed, rather than with `get_object`.
* The group-scoped list route `GET /v1/file_monitor` (with `scope`) exists but is
  not used by any tool in this spec.

---

### `nv_list_response_rules`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/response/rule` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `ResponseRuleList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `scope` | `Literal["local", "fed"]` | `"local"` | 'local' returns this cluster's response rules, 'fed' returns rules pushed from a federation primary. |
| `event` | `str \| None` | `None` | Return only rules that react to this event type, verbatim as the controller names it. |
| `group` | `str \| None` | `None` | Return only rules scoped to this group name. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset into the ordered rule list. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum response rules to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `scope` | `scope=<value>` (via `extra`) |
| `event` | `f_event=<value>` |
| `group` | `f_group=<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Response rules: the automated reactions NeuVector takes when an event fires.

Read this to explain why a workload was quarantined or suppressed, or why a
webhook fired. Like network rules these are evaluated in the order returned, so
'order' matters. 'actions' names what happens and 'webhooks' names the
configured webhook targets by name only.

Calls GET /v1/response/rule with scope, f_event and f_group.
```

**Body (normative)** — §7.3 shape, envelope `rules`, `extra={"scope": scope}`,
absolute `order` assigned exactly as in `nv_list_network_rules`, hint
`f"More response rules exist. Call again with start={start + len(page_items)}."`.

**Output model**

```python
class ResponseRule(BaseModel):
    """One response rule."""

    model_config = _BASE

    id: int = Field(description="Rule id.")
    order: int = Field(default=0, description="Zero-based absolute position in evaluation order.")
    event: str = Field(default="", description="Event type that triggers the rule.")
    group: str = Field(default="", description="Group the rule is scoped to; empty means cluster-wide.")
    actions: list[str] = Field(
        default_factory=list,
        description="What the controller does when the rule matches, e.g. suppress log, quarantine, webhook.",
    )
    webhooks: list[str] = Field(
        default_factory=list, description="Names of configured webhook targets to notify. Names only, never URLs."
    )
    conditions: list[str] = Field(
        default_factory=list,
        description="Extra match conditions rendered as 'type=value' strings.",
    )
    disable: bool = Field(default=False, description="True when the rule is present but inactive.")
    cfg_type: str = Field(default="", description="Provenance: user_created | ground | federal.")
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, order: int = 0) -> "ResponseRule":
        """Project a ``RESTResponseRule``; conditions flatten ``RESTCLUSEventCondition``."""
        conditions = [
            f"{str(c.get('type', '') or '')}={str(c.get('value', '') or '')}"
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
    scope: str = Field(default="local", description="Scope the rules were read from: local or fed.")
    rules: list[ResponseRule]
```

**Fixture** `tests/fixtures/response_rules.json` — envelope key `rules`.

**Tests** `tests/test_policy_read.py`:
`test_list_response_rules_sends_scope_and_filters`,
`test_response_rule_conditions_are_flattened`.

**Notes**
* `RESTResponseRule`, `RESTResponseRulesData` (`rules`) and
  `RESTCLUSEventCondition` (`type`, `value`) are all in Appendix B; every field
  is verified.
* Only webhook **names** appear. Webhook URLs live in the system config and are
  not part of this projection; do not join them in.
* `GET /v1/response/options` would enumerate valid action names but is an
  undocumented route and is not used here.

---

### `nv_list_dlp_sensors`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/dlp/sensor` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `DlpSensorList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `name_prefix` | `str \| None` | `None` | Return only sensors whose name starts with this prefix. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum sensors to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `name_prefix` | `f_name=prefix,<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

Appendix A documents **no** `scope` parameter on `GET /v1/dlp/sensor` (unlike
`GET /v1/waf/sensor`). Do not send one.

**Docstring (use verbatim)**

```
Data-loss-prevention sensors configured on this cluster.

A sensor is a named bundle of patterns; groups opt into sensors, and a match
raises a threat event visible through nv_query_security_events with
kind='threat', where the 'sensor' field carries the name returned here. Pattern
bodies are not returned: they are large and frequently contain the regexes that
describe protected data.

Calls GET /v1/dlp/sensor with f_name.
```

**Body (normative)** — §7.3 shape, envelope `sensors` (**inferred**, see Notes),
hint `f"More DLP sensors exist. Call again with start={start + len(page_items)}."`.

**Output model**

```python
class SensorBrief(BaseModel):
    """One DLP or WAF sensor, name-level only.

    Appendix B contains neither ``RESTDlpSensor`` nor ``RESTWafSensor``, so this
    projection asserts only ``name`` and ``comment`` and derives every other
    value with ``.get()`` defaults.
    """

    model_config = _BASE

    name: str = Field(default="", description="Sensor name; matches the 'sensor' field on threat events.")
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")
    rule_count: int = Field(
        default=0,
        description="Number of pattern rules the sensor carries, 0 when the controller did not "
        "report a rule list. Rule bodies are never returned.",
    )
    predefined: bool = Field(
        default=False, description="True when the sensor ships with NeuVector rather than being user-defined."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "SensorBrief":
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
    scope: str = Field(default="local", description="Scope the sensors were read from: local or fed.")
    sensors: list[SensorBrief]
```

**Fixture** `tests/fixtures/dlp_sensors.json` — envelope key `sensors`
(**inferred**).

**Tests** `tests/test_policy_read.py`: `test_list_dlp_sensors_projects_names`,
`test_list_dlp_sensors_sends_no_scope_param` (assert `"scope" not in params`).

**Notes**
* **BLOCKED (partial): `RESTDlpSensorsData` and `RESTDlpSensor` are absent from
  `appendix/B-schema-reference.md`.** The endpoint is verified documented, so the
  tool ships. Consequences: the envelope key `sensors` is inferred from §3.3 and
  must be confirmed against a live controller; the only field names read are
  `name`, `comment`, `rules` (for a length only) and `predefined`, each through
  `.get()` with a default, so a wrong guess degrades to a default instead of an
  error. Do not add fields until Appendix B documents the type.
* `SensorBrief` is shared with `nv_list_waf_sensors`. Define it once.
* **Rule bodies are deliberately withheld.** A DLP pattern set describes exactly
  what an organisation treats as sensitive; returning it expands the blast radius
  of a leaked transcript for no operational gain. `GET /v1/dlp/rule` exists and
  is documented, but no tool in this spec exposes it.

---

### `nv_list_waf_sensors`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/waf/sensor` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `WafSensorList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `scope` | `Literal["local", "fed"]` | `"local"` | 'local' returns this cluster's sensors, 'fed' returns sensors pushed from a federation primary. |
| `name_prefix` | `str \| None` | `None` | Return only sensors whose name starts with this prefix. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum sensors to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `scope` | `scope=<value>` (via `extra`) — documented for this route |
| `name_prefix` | `f_name=prefix,<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Web-application-firewall sensors configured on this cluster.

A WAF sensor is a named bundle of request patterns that groups opt into; a match
raises a threat event visible through nv_query_security_events with
kind='threat'. Pattern bodies are not returned. Unlike the DLP sensor route this
one accepts a scope, so federated sensors can be listed separately.

Calls GET /v1/waf/sensor with scope and f_name.
```

**Body (normative)** — §7.3 shape, envelope `sensors` (**inferred**),
`extra={"scope": scope}`, returns `WafSensorList(page=..., scope=scope, sensors=[SensorBrief.from_api(i) ...])`,
hint `f"More WAF sensors exist. Call again with start={start + len(page_items)}."`.

**Fixture** `tests/fixtures/waf_sensors.json` — envelope key `sensors`
(**inferred**).

**Tests** `tests/test_policy_read.py`:
`test_list_waf_sensors_sends_scope`, `test_list_waf_sensors_truncates`.

**Notes**
* **BLOCKED (partial): `RESTWafSensorsData` and `RESTWafSensor` are absent from
  `appendix/B-schema-reference.md`.** Same consequences as
  `nv_list_dlp_sensors`: inferred envelope key, minimal projection, `.get()`
  defaults throughout, shared `SensorBrief` model.
* Appendix A shows `POST /v1/waf/sensor` taking `RESTDlpSensorConfigData`, i.e.
  DLP and WAF sensors share a config shape upstream. That is a hint the response
  shapes match too, which is why one `SensorBrief` serves both — but it remains
  a hint, not a verified schema.

---

### `nv_get_admission_state`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/admission/state` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `AdmissionState` |

**Arguments** — none beyond `ctx`.

**Query mapping** — none. Appendix A documents no query parameters for this
route.

**Docstring (use verbatim)**

```
Whether Kubernetes admission control is enabled, and in which mode.

Check this before reading or reasoning about admission rules: when 'enable' is
false the rules exist but nothing is enforced, and in mode 'monitor' denials are
only logged. 'default_action' is what happens to a request no rule matches.
'k8s_env' false means the cluster is not Kubernetes and admission control cannot
work at all.

Calls GET /v1/admission/state.
```

**Body (normative)**

```python
app = app_context(ctx)
raw = await app.client.request("GET", "/v1/admission/state")
return AdmissionState.from_api(raw if isinstance(raw, dict) else {})
```

**Output model**

```python
class AdmissionState(BaseModel):
    """Result of ``nv_get_admission_state``."""

    model_config = _BASE

    enable: bool = Field(default=False, description="True when the admission webhook is active.")
    mode: str = Field(
        default="",
        description="monitor logs would-be denials, protect actually denies requests.",
    )
    default_action: str = Field(default="", description="What happens to a request that no rule matches.")
    adm_client_mode: str = Field(default="", description="How the controller reaches the Kubernetes API server.")
    adm_svc_type: str = Field(default="", description="Service type backing the admission webhook.")
    k8s_env: bool = Field(
        default=False,
        description="True when the controller detected Kubernetes. False means admission control "
        "is unavailable and mutations return controller code 30.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "AdmissionState":
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
```

**Fixture** `tests/fixtures/admission_state.json` — top-level keys `state` and
`k8s_env` (no resource-name envelope; `state` is a field of
`RESTAdmissionConfigData`, not a wrapper).

**Tests** `tests/test_policy_read.py`:
`test_get_admission_state_projects_state_and_k8s_env`,
`test_get_admission_state_handles_missing_state` (body `{}` → all defaults, no
exception).

**Notes**
* `RESTAdmissionConfigData` and `RESTAdmissionState` are both in Appendix B;
  every field is verified.
* `ctrl_states`, `adm_client_mode_options`, `admission_options`,
  `admission_custom_criteria_options`, `admission_custom_criteria_templates` and
  `predefined_risky_roles` exist on `RESTAdmissionConfigData` but are **not**
  projected: they are option catalogues for building rules, not state, and they
  are large.
* An empty body must yield defaults rather than `NotFoundError` — the state
  always exists conceptually, even before admission control is configured.

---

### `nv_list_admission_rules`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `GET /v1/admission/rules` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `AdmissionRuleList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `scope` | `Literal["local", "fed"]` | `"local"` | 'local' returns this cluster's rules, 'fed' returns rules pushed from a federation primary. |
| `rule_type` | `Literal["deny", "exception"] \| None` | `None` | 'deny' rules block matching deployments, 'exception' rules allow them through. |
| `cfg_type` | `Literal["user_created", "ground", "federal"] \| None` | `None` | Provenance: 'user_created' added through the API or UI, 'ground' from a Kubernetes CRD, 'federal' pushed by a federation primary. |
| `category` | `str \| None` | `None` | Filter by rule category, verbatim as the controller reports it. |
| `max_criteria` | `int` (ge=1, le=50) | `10` | Maximum criteria to return per rule. A rule can carry deeply nested criteria; extras are dropped and criteria_truncated is set on that rule. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum rules to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `scope` | `scope=<value>` (via `extra`) |
| `rule_type` | `f_rule_type=<value>` |
| `cfg_type` | `f_cfg_type=<value>` |
| `category` | `f_category=<value>` |
| `max_criteria` | none — applied by the projection |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Admission control rules: what NeuVector blocks or exempts at deploy time.

Read nv_get_admission_state first — these rules do nothing while admission
control is disabled or in monitor mode. Criteria are flattened to
'name op value' strings, nested sub-criteria included as 'name op value
(sub: ...)'. To find out what a candidate rule would match without changing
anything, use nv_assess_admission_rule.

Calls GET /v1/admission/rules with scope, f_rule_type, f_cfg_type and f_category.
```

**Body (normative)** — §7.3 shape, envelope `rules`, `extra={"scope": scope}`,
`rules=[AdmissionRule.from_api(i, max_criteria=max_criteria) for i in page_items]`,
hint `f"More admission rules exist. Call again with start={start + len(page_items)}, or narrow with rule_type/cfg_type."`.

**Output model**

```python
def _flatten_criterion(raw: dict[str, Any]) -> str:
    """Render a ``RESTAdmRuleCriterion`` as 'name op value', with sub-criteria inline."""
    base = f"{str(raw.get('name', '') or '')} {str(raw.get('op', '') or '')} {str(raw.get('value', '') or '')}".strip()
    subs = [
        _flatten_criterion(s) for s in (raw.get("sub_criteria") or []) if isinstance(s, dict)
    ]
    return f"{base} (sub: {'; '.join(subs)})" if subs else base


class AdmissionRule(BaseModel):
    """One admission control rule."""

    model_config = _BASE

    id: int = Field(description="Rule id; pass to nv_update_admission_rule or nv_delete_admission_rule.")
    category: str = Field(default="", description="Rule category as the controller reports it.")
    rule_type: str = Field(default="", description="deny blocks matching deployments, exception allows them.")
    rule_mode: str = Field(
        default="",
        description="Per-rule override of the global admission mode: monitor, protect, or empty to inherit.",
    )
    cfg_type: str = Field(default="", description="Provenance: user_created | ground | federal.")
    disable: bool = Field(default=False, description="True when the rule is present but not evaluated.")
    critical: bool = Field(
        default=False, description="True for built-in rules NeuVector always evaluates; these cannot be deleted."
    )
    containers: list[str] = Field(
        default_factory=list,
        description="Which container classes the rule inspects: containers, init_containers, ephemeral_containers.",
    )
    criteria: list[str] = Field(
        default_factory=list, description="Match criteria flattened to 'name op value' strings."
    )
    criteria_total: int = Field(default=0, description="Criteria the controller returned, before the cap.")
    criteria_truncated: bool = Field(default=False, description="True when criteria were dropped by max_criteria.")
    comment: str = Field(default="", description="Operator comment, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_criteria: int = 10) -> "AdmissionRule":
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
    scope: str = Field(default="local", description="Scope the rules were read from: local or fed.")
    rules: list[AdmissionRule]
```

**Fixture** `tests/fixtures/admission_rules.json` — envelope key `rules`.
Include one rule with `sub_criteria` so the flattening branch is covered.

**Tests** `tests/test_policy_read.py`:
`test_list_admission_rules_sends_scope_and_filters`,
`test_admission_criteria_flatten_sub_criteria`,
`test_list_admission_rules_caps_criteria`.

**Notes**
* `RESTAdmissionRule`, `RESTAdmissionRulesData` (`rules`) and
  `RESTAdmRuleCriterion` (`name`, `op`, `value`, `sub_criteria`) are all in
  Appendix B; every field is verified. `type`, `template_kind`, `path` and
  `value_type` also exist on the criterion but are not projected.
* On a non-Kubernetes platform the controller answers `code=30`
  ("Admission control is not supported on non-Kubernetes environment"). Surface
  it; do not retry.
* `_flatten_criterion` recurses. `sub_criteria` nesting is shallow in practice,
  but keep the recursion — do not flatten one level and drop the rest silently.

---

### `nv_assess_admission_rule`

| | |
|---|---|
| **Toolset** | `policy_read` (read) |
| **Endpoints** | `POST /v1/assess/admission/rule` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `AdmissionAssessment` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `rule_type` | `Literal["deny", "exception"]` | — | 'deny' evaluates a candidate blocking rule, 'exception' evaluates a candidate allow rule. |
| `criteria` | `list[AdmissionCriterionInput]` (min_length=1) | — | Match criteria of the candidate rule. Each needs name, op and value; nested sub_criteria are optional. Get valid names from an existing rule via nv_list_admission_rules. |
| `category` | `str` | `"Kubernetes"` | Rule category the controller expects; leave at the default unless an existing rule shows otherwise. |
| `containers` | `list[Literal["containers", "init_containers", "ephemeral_containers"]]` | `["containers"]` | Which container classes the candidate rule would inspect. |
| `rule_mode` | `Literal["", "monitor", "protect"]` | `""` | Per-rule mode of the candidate rule; empty inherits the global admission mode. |
| `comment` | `str` | `""` | Free-text comment carried on the candidate rule. |
| `max_results` | `int` (ge=1, le=200) | `50` | Maximum matched objects to return. The controller evaluates every current cluster object, so a broad rule can match hundreds. |

`AdmissionCriterionInput` is an **input** model. It is declared in `models.py`
immediately before the assessment output models (tool bodies import it from
there, per SPEC §4.1) and is the only input model in Part B:

```python
class AdmissionCriterionInput(BaseModel):
    """One criterion of the candidate rule. Mirrors RESTAdmRuleCriterion."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Criterion name, e.g. 'image' or 'runAsRoot'.")
    op: str = Field(description="Comparison operator the controller defines for this criterion name.")
    value: str = Field(default="", description="Value to compare against.")
    sub_criteria: list["AdmissionCriterionInput"] = Field(
        default_factory=list, description="Nested criteria, for names that take them."
    )
```

**Query mapping**

| Argument | Controller parameter |
|---|---|
| all rule arguments | JSON request body `{"config": {...}}` — see Body |
| `max_results` | none — applied by the projection |

**Docstring (use verbatim)**

```
Evaluate a candidate admission rule against the cluster and report what it would match.

This is a dry run: it creates nothing, changes nothing and does not touch the
admission configuration. Use it before nv_create_admission_rule to see which
running or pending objects a candidate deny rule would have blocked, and which
existing rules already match them. 'allowed' per result is the verdict the
webhook would return. A broad criterion set matches a lot, so raise max_results
deliberately.

Calls POST /v1/assess/admission/rule with {"config": {rule_type, category, criteria, containers, rule_mode, comment}}.
```

**Body (normative)**

```python
app = app_context(ctx)
payload: dict[str, Any] = {
    "config": {
        "category": category,
        "rule_type": rule_type,
        "cfg_type": "user_created",
        "criteria": [c.model_dump(exclude_defaults=False) for c in criteria],
        "containers": list(containers),
        "rule_mode": rule_mode,
        "comment": comment,
        "disable": False,
    }
}
raw = await app.client.request("POST", "/v1/assess/admission/rule", json=payload)
return AdmissionAssessment.from_api(
    raw if isinstance(raw, dict) else {}, max_results=max_results
)
```

There is **no** `authorise_write` call and **no** `confirm` argument: see Notes.

**Output model**

```python
class AdmissionMatchedRule(BaseModel):
    """An existing admission rule that also matched the assessed object."""

    model_config = _BASE

    id: int = Field(default=0, description="Existing rule id.")
    type: str = Field(default="", description="allow or deny.")
    mode: str = Field(default="", description="Per-rule mode: monitor or protect, empty to inherit.")
    disabled: bool = Field(default=False, description="True when that rule is currently disabled.")
    rule_cfg_type: str = Field(default="", description="Provenance: federal | ground | user_created.")
    container_image: str = Field(default="", description="Container image in the pod that this rule matched.")
    rule_details: str = Field(default="", description="Controller explanation of the match, clipped to 1000 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "AdmissionMatchedRule":
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

    index: int = Field(default=0, description="Controller's index for this object within the assessment.")
    name: str = Field(default="", description="Object name.")
    kind: str = Field(default="", description="Kubernetes kind of the object, e.g. Deployment.")
    allowed: bool = Field(default=False, description="False when the webhook would deny this object.")
    message: str = Field(default="", description="Controller explanation, clipped to 1000 characters.")
    matched_rules: list[AdmissionMatchedRule] = Field(
        default_factory=list, description="Existing rules that also matched this object."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "AdmissionAssessmentResult":
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
        description="Cluster admission mode at assessment time: monitor, protect, or empty when disabled.",
    )
    props_unavailable: list[str] = Field(
        default_factory=list,
        description="Criterion properties the controller could not evaluate; results ignore them.",
    )
    results_total: int = Field(default=0, description="Objects the controller assessed, before the cap.")
    results_truncated: bool = Field(default=False, description="True when results were dropped by max_results.")
    denied_count: int = Field(default=0, description="Returned results whose verdict was deny.")
    results: list[AdmissionAssessmentResult]

    @classmethod
    def from_api(cls, raw: dict[str, Any], *, max_results: int = 50) -> "AdmissionAssessment":
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
```

**Fixture** `tests/fixtures/admission_assessment.json` — **no resource
envelope**: top-level keys `global_mode`, `props_unavailable`, `results`
(`RESTAdmCtrlRulesTestResults` does not end in `Data`). Include one denied result
with a `matched_rules` entry.

**Tests** `tests/test_policy_read.py`:
`test_assess_admission_rule_sends_config_body` (assert the exact JSON body and
`route.calls.last.request.method == "POST"`),
`test_assess_admission_rule_counts_denials`,
`test_assess_admission_rule_caps_results`,
`test_assess_admission_rule_has_no_confirm_argument` (assert `confirm` is absent
from the tool's input schema).

**Notes**
* **Why a POST is classified `policy_read` with `readOnlyHint=True` and no
  `confirm`.** Four independent reasons, all required for the classification to
  hold: (1) the route is an *assessment* — it evaluates a candidate rule against
  current cluster objects and returns verdicts; nothing is created, updated or
  deleted, and the admission configuration is untouched. (2) It is idempotent:
  the same body returns the same verdicts against unchanged cluster state, hence
  `idempotentHint=True`. (3) Its response type,
  `RESTAdmCtrlRulesTestResults`, contains only results — there is no object id or
  created resource anywhere in the schema. (4) Semantically it is the *safety
  tool* for admission changes; putting it behind the confirmation handshake would
  push callers toward guessing instead of assessing. The MCP annotation
  `readOnlyHint` describes environment mutation, not HTTP verb, so a
  non-mutating POST is correctly read-only. Consequences the implementer must
  respect: the tool is tagged `{"policy_read", "read"}`, takes **no** `confirm`
  argument (gate rule R5 would fail if it did), never calls
  `authorise_write`, and remains available when `NV_READ_ONLY=true`.
* **Request-body discrepancy — read before implementing.** Appendix A declares
  the request body of `POST /v1/assess/admission/rule` as bare `string`, which
  is a Swagger imprecision, not a real contract. Appendix B does document
  `RESTAdmissionRuleConfigData` = `{"config": RESTAdmissionRuleConfig}` with the
  fields used above (`id`, `category`, `comment`, `criteria`, `disable`,
  `actions`, `cfg_type`, `rule_type`, `rule_mode`, `containers`), and
  `PATCH`/`POST /v1/admission/rule` use exactly that shape. Therefore send
  `{"config": {...}}` as above and do **not** invent extra keys. `id` is omitted
  because the candidate rule has none. If a live controller rejects this with
  `code=6` ("Request in wrong format"), that is the signal to revisit — record
  it, do not silently retry with a different shape.
* Response field names verified in Appendix B:
  `RESTAdmCtrlRulesTestResults` (`props_unavailable`, `global_mode`, `results`),
  `RESTAdmCtrlRulesTestResult` (`index`, `name`, `kind`, `message`,
  `matched_rules`, `allowed`), `RESTAdmCtrlTestRuleInfo` (`container_image`,
  `id`, `disabled`, `type`, `mode`, `rule_details`, `rule_cfg_type`).
* `message` and `rule_details` are clipped to 1000 characters each so a
  200-result assessment cannot exceed `NV_MAX_RESPONSE_CHARS`; `max_results`
  defaults to 50 for the same reason.
* Expect `code=30` on non-Kubernetes platforms and `code=25` when the key's role
  cannot read admission configuration.

---

# Toolset `iam_read` (read) — 4 tools

### `nv_list_users`

| | |
|---|---|
| **Toolset** | `iam_read` (read) |
| **Endpoints** | `GET /v1/user` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `UserList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `role` | `str \| None` | `None` | Return only users holding this global role, e.g. 'admin' or 'reader'. Get names from nv_list_roles. |
| `auth_server` | `str \| None` | `None` | Return only users from this authentication server (controller field 'server'); empty on a user means local. |
| `name_prefix` | `str \| None` | `None` | Return only users whose full name starts with this prefix. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum users to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `role` | `f_role=<value>` |
| `auth_server` | `f_server=<value>` |
| `name_prefix` | `f_fullname=prefix,<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
NeuVector user accounts with their roles and login state.

Use this to audit who can change policy, spot accounts still on a default
password, and find accounts blocked by failed logins or password expiry.
Password material is never returned. Namespace-scoped roles appear in
role_domains as role -> namespaces.

Calls GET /v1/user with f_role, f_server and f_fullname.
```

**Body (normative)** — §7.3 shape, envelope `users`, hint
`f"More users exist. Call again with start={start + len(page_items)}, or narrow with role/auth_server."`.

**Output model**

```python
class UserBrief(BaseModel):
    """One user account. Password material is structurally absent."""

    model_config = _BASE

    fullname: str = Field(description="Fully qualified user name; the id for nv_update_user_role and nv_delete_user.")
    username: str = Field(default="", description="Login name.")
    email: str = Field(default="", description="Email address on the account.")
    auth_server: str = Field(
        default="", description="Authentication server the user comes from; empty means a local account."
    )
    role: str = Field(default="", description="Global role, e.g. admin, reader. Empty means namespace-scoped only.")
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict, description="Namespace-scoped roles as role -> list of namespaces."
    )
    timeout: int = Field(default=0, description="Session idle timeout in seconds.")
    locale: str = Field(default="", description="UI locale.")
    last_login_at: str = Field(default="", description="Human-readable last login time.")
    last_login_timestamp: int = Field(default=0, description="Unix epoch seconds of the last login, 0 if never.")
    login_count: int = Field(default=0, description="Successful logins recorded for this account.")
    default_password: bool = Field(
        default=True,
        description="True when the account still uses its default password. Treat as a finding. "
        "Defaults to True so a missing field never reads as safe.",
    )
    blocked_for_failed_login: bool = Field(default=False, description="True when locked out by failed logins.")
    blocked_for_password_expired: bool = Field(default=False, description="True when the password has expired.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "UserBrief":
        """Project a ``RESTUser``.

        ``password`` is NEVER read. See the tool notes: omission is a
        requirement, not an optimisation.
        """
        domains = raw.get("role_domains") or {}
        role_domains = {
            str(role): [str(d) for d in (namespaces or [])]
            for role, namespaces in domains.items()
        } if isinstance(domains, dict) else {}
        return cls(
            fullname=str(raw.get("fullname", "") or ""),
            username=str(raw.get("username", "") or ""),
            email=str(raw.get("email", "") or ""),
            auth_server=str(raw.get("server", "") or ""),
            role=str(raw.get("role", "") or ""),
            role_domains=role_domains,
            timeout=int(raw.get("timeout") or 0),
            locale=str(raw.get("locale", "") or ""),
            last_login_at=str(raw.get("last_login_at", "") or ""),
            last_login_timestamp=int(raw.get("last_login_timestamp") or 0),
            login_count=int(raw.get("login_count") or 0),
            default_password=bool(raw.get("default_password", True)),
            blocked_for_failed_login=bool(raw.get("blocked_for_failed_login", False)),
            blocked_for_password_expired=bool(raw.get("blocked_for_password_expired", False)),
        )


class UserList(BaseModel):
    """Result of ``nv_list_users``."""

    model_config = _BASE

    page: Page
    users: list[UserBrief]
```

**Fixture** `tests/fixtures/users.json` — envelope key `users`. Include a
`"password"` key on one entry **and** assert it does not appear in the result, so
the redaction is regression-tested rather than assumed.

**Tests** `tests/test_iam.py`: `test_list_users_query_and_projection`,
`test_list_users_never_returns_password`,
`test_list_users_defaults_default_password_true`.

**Notes**
* `RESTUser` and `RESTUsersData` (`users`) are in Appendix B; every field above
  is verified.
* **Redaction rule (mandatory): `password` is never projected.** `RESTUser`
  declares `password` as `string(password)`. The projection has no such field,
  so `extra="ignore"` drops it even if the controller sends it. Never add it,
  and never log a raw user body (SPEC N8, §11).
* `modify_password`, `password_resettable`, `extra_permissions`,
  `extra_permissions_domains` and `remote_role_permissions` exist on `RESTUser`
  but are not projected: the first two are UI hints and the last three are
  Rancher-SSO-only structures.
* `default_password` defaults to **True** on a missing field. A missing security
  signal must not read as "safe".
* `RESTUsersData.global_roles` and `.domain_roles` are envelope-level catalogues,
  not per-user data; `nv_list_roles` covers that ground.

---

### `nv_list_roles`

| | |
|---|---|
| **Toolset** | `iam_read` (read) |
| **Endpoints** | `GET /v1/user_role` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `RoleList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `name_prefix` | `str \| None` | `None` | Return only roles whose name starts with this prefix. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum roles to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `name_prefix` | `f_name=prefix,<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Roles and the read/write permissions each one grants.

Pair this with nv_list_users to answer "who can actually change policy": a
user's role name means nothing until you see its permission set. 'reserved'
marks built-in roles, which cannot be edited or deleted. Each permission entry
is a controller permission id with independent read and write flags.

Calls GET /v1/user_role with f_name.
```

**Body (normative)** — §7.3 shape, envelope `roles`, hint
`f"More roles exist. Call again with start={start + len(page_items)}."`.

**Output model**

```python
class RolePermission(BaseModel):
    """One permission grant inside a role."""

    model_config = _BASE

    id: str = Field(description="Controller permission id, e.g. 'rt_policy' or 'admctrl'.")
    read: bool = Field(default=False, description="True when the role can read this area.")
    write: bool = Field(default=False, description="True when the role can change this area.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "RolePermission":
        """Project a ``RESTRolePermission``."""
        return cls(
            id=str(raw.get("id", "") or ""),
            read=bool(raw.get("read", False)),
            write=bool(raw.get("write", False)),
        )


class RoleBrief(BaseModel):
    """One role definition."""

    model_config = _BASE

    name: str = Field(description="Role name as referenced by users and API keys.")
    reserved: bool = Field(
        default=False, description="True for built-in roles, which cannot be modified or deleted."
    )
    write_permission_count: int = Field(
        default=0, description="How many permission areas this role can change. 0 means read-only."
    )
    permissions: list[RolePermission] = Field(
        default_factory=list, description="Permission grants making up the role."
    )
    comment: str = Field(default="", description="Role description, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "RoleBrief":
        """Project a ``RESTUserRole``."""
        perms = [
            RolePermission.from_api(p) for p in (raw.get("permissions") or []) if isinstance(p, dict)
        ]
        return cls(
            name=str(raw.get("name", "") or ""),
            reserved=bool(raw.get("reserved", False)),
            write_permission_count=sum(1 for p in perms if p.write),
            permissions=perms,
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
        )


class RoleList(BaseModel):
    """Result of ``nv_list_roles``."""

    model_config = _BASE

    page: Page
    roles: list[RoleBrief]
```

**Fixture** `tests/fixtures/user_roles.json` — envelope key `roles`.

**Tests** `tests/test_iam.py`: `test_list_roles_projects_permissions`,
`test_role_write_permission_count`.

**Notes**
* `RESTUserRole`, `RESTUserRolesData` (`roles`) and `RESTRolePermission`
  (`id`, `read`, `write`) are in Appendix B; every field is verified.
* The permission-id vocabulary is not in Appendix A or B (the enumerating route
  `GET /v1/user_role_permission/options` is undocumented and unused here), so
  the `id` description gives examples without claiming to be exhaustive.
* `write_permission_count` is derived, not a controller field. It exists so a
  client model can answer "is this role read-only" without walking the list.

---

### `nv_list_auth_servers`

| | |
|---|---|
| **Toolset** | `iam_read` (read) |
| **Endpoints** | `GET /v1/server` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `AuthServerList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `name_prefix` | `str \| None` | `None` | Return only servers whose name starts with this prefix. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum servers to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `name_prefix` | `f_name=prefix,<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
Configured external authentication servers, by name and kind only.

Use this to see whether LDAP, SAML or OIDC login is configured and under what
name, then pair it with nv_list_users (auth_server filter) to see who logs in
through it. Configuration values are deliberately NOT returned: these objects
carry bind passwords and client secrets, so this tool reports only the server
name and which configuration blocks are present.

Calls GET /v1/server with f_name.
```

**Body (normative)** — §7.3 shape, envelope `servers` (**inferred**, see Notes),
hint `f"More authentication servers exist. Call again with start={start + len(page_items)}."`.

**Output model**

```python
#: Only these top-level keys of a server entry may be projected, and only 'name'
#: as a value. Everything else is reported as a key name or dropped. An
#: allowlist is used deliberately: a denylist would leak any secret field that a
#: future controller release adds.
_AUTH_SERVER_VALUE_ALLOWLIST: frozenset[str] = frozenset({"name"})

#: Key-name substrings that must never appear even in the reported key list.
_SECRET_KEY_MARKERS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "credential",
    "private",
    "key",
)


class AuthServerBrief(BaseModel):
    """One authentication server, reduced to non-sensitive facts.

    Appendix B contains no ``RESTServer`` / ``RESTServersData`` definition, so
    the set of secret-bearing fields cannot be enumerated from the schema. This
    model therefore projects VALUES for allowlisted keys only ('name') and
    reports every other key by NAME, with secret-looking names filtered out.
    """

    model_config = _BASE

    name: str = Field(description="Server name; matches the 'server' field on a user account.")
    config_blocks: list[str] = Field(
        default_factory=list,
        description="Configuration block key names present on this server, e.g. the protocol "
        "block that identifies it as LDAP, SAML or OIDC. Names only, never values.",
    )
    redacted_keys: list[str] = Field(
        default_factory=list,
        description="Key names withheld because they matched a secret marker (password, secret, "
        "token, credential, private, key). Their values are never read.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "AuthServerBrief":
        """Project one server entry through the value allowlist."""
        blocks: list[str] = []
        redacted: list[str] = []
        for key in raw:
            if key in _AUTH_SERVER_VALUE_ALLOWLIST:
                continue
            lowered = key.lower()
            if any(marker in lowered for marker in _SECRET_KEY_MARKERS):
                redacted.append(key)
            else:
                blocks.append(key)
        return cls(
            name=str(raw.get("name", "") or ""),
            config_blocks=sorted(blocks),
            redacted_keys=sorted(redacted),
        )


class AuthServerList(BaseModel):
    """Result of ``nv_list_auth_servers``."""

    model_config = _BASE

    page: Page
    servers: list[AuthServerBrief]
```

**Fixture** `tests/fixtures/auth_servers.json` — envelope key `servers`
(**inferred**). Build one entry containing a nested block plus a
`"bind_password"` key and assert: `bind_password` appears in `redacted_keys`,
its value appears nowhere in the serialised result, and no nested value is
present.

**Tests** `tests/test_iam.py`: `test_list_auth_servers_projects_names_only`,
`test_list_auth_servers_redacts_secret_key_names`,
`test_list_auth_servers_result_contains_no_config_values` (serialise the result
to JSON and assert the fixture's secret string is absent).

**Notes**
* **BLOCKED (partial): the task asks for the secret-bearing fields to be
  identified from Appendix B and listed explicitly, but
  `appendix/B-schema-reference.md` contains no `RESTServersData`, no
  `RESTServer`, and no LDAP/SAML/OIDC sub-type.** Grepping B for `RESTServer`,
  `ldap`, `saml`, `oidc`, `bind_password` and `client_secret` returns nothing.
  The field-level list therefore cannot be produced from the appendices without
  inventing names, which SPEC rule N2 forbids.
* **Mitigation, which is stricter than a field list:** the projection is an
  **allowlist**, not a denylist. Exactly one key's value is ever read (`name`).
  Every other key contributes its *name* only, and names matching
  `_SECRET_KEY_MARKERS` are diverted to `redacted_keys`. A secret field that a
  future controller release adds is thus withheld by default rather than leaked
  by omission from a denylist.
* Named for the record, so a later reviewer can confirm the mitigation covers
  them: the fields an LDAP/SAML/OIDC server object is *expected* to carry
  include a bind password, a client secret and signing material. None of these
  names is asserted anywhere in code — they are matched generically by
  `_SECRET_KEY_MARKERS`. When Appendix B gains `RESTServer`, replace this
  model with a typed projection and keep the allowlist discipline.
* `RESTServersData` is a `Data` name, so the body is a wrapper; the key
  `servers` is inferred from §3.3 and must be confirmed against a live
  controller. A wrong key degrades to an empty list (`get_list` returns `[]`),
  never to an exception.
* `GET /v1/server/{name}` and `GET /v1/server/{name}/user` are documented but
  intentionally **not** exposed: a single-server fetch returns the full
  configuration body, which is exactly what this tool exists to avoid.

---

### `nv_list_api_keys`

| | |
|---|---|
| **Toolset** | `iam_read` (read) |
| **Endpoints** | `GET /v1/api_key` |
| **Annotations** | `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True` |
| **Returns** | `ApiKeyList` |

**Arguments**

| Name | Type | Default | Description (verbatim into `Field(description=...)`) |
|---|---|---|---|
| `role` | `str \| None` | `None` | Return only keys holding this global role. Get names from nv_list_roles. |
| `name_prefix` | `str \| None` | `None` | Return only keys whose name starts with this prefix. |
| `start` | `int` (ge=0) | `0` | Zero-based paging offset. |
| `limit` | `int` (ge=1, le=1000) | `50` | Maximum keys to return. Capped by NV_MAX_ITEMS. |

**Query mapping**

| Argument | Controller parameter |
|---|---|
| `role` | `f_role=<value>` |
| `name_prefix` | `f_apikey_name=prefix,<value>` |
| `start` | `start` |
| `limit` | `limit + 1` (over-fetch to detect truncation) |

**Docstring (use verbatim)**

```
API key metadata: name, role, creator and expiry. Never the secret.

Use this to audit non-human access — which keys exist, how much they can do, and
which have expired or never expire. The secret half of a key is shown once at
creation and is not retrievable afterwards, so it is absent here by design: an
expiring key must be replaced, not recovered. An expired key surfaces to its
holder as controller error code 3.

Calls GET /v1/api_key with f_role and f_apikey_name.
```

**Body (normative)** — §7.3 shape, envelope `apikeys`, hint
`f"More API keys exist. Call again with start={start + len(page_items)}."`.

**Output model**

```python
class ApiKeyBrief(BaseModel):
    """One API key's metadata. The secret is structurally absent."""

    model_config = _BASE

    apikey_name: str = Field(description="Key name, i.e. the access key; the id for nv_delete_api_key.")
    role: str = Field(default="", description="Global role the key carries.")
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict, description="Namespace-scoped roles as role -> list of namespaces."
    )
    expiration_type: str = Field(
        default="", description="How expiry is expressed, e.g. hours or never, verbatim from the controller."
    )
    expiration_hours: int = Field(default=0, description="Configured lifetime in hours, 0 when not hour-based.")
    expiration_timestamp: int = Field(
        default=0, description="Unix epoch seconds the key expires, 0 when it does not expire."
    )
    created_timestamp: int = Field(default=0, description="Unix epoch seconds the key was created.")
    created_by_entity: str = Field(default="", description="Who or what created the key.")
    description: str = Field(default="", description="Operator description, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "ApiKeyBrief":
        """Project a ``RESTApikey``.

        ``apikey_secret`` is NEVER read. The controller returns it only from the
        creation call; there is no recovery path and this tool must not imply one.
        """
        domains = raw.get("role_domains") or {}
        role_domains = {
            str(role): [str(d) for d in (namespaces or [])]
            for role, namespaces in domains.items()
        } if isinstance(domains, dict) else {}
        return cls(
            apikey_name=str(raw.get("apikey_name", "") or ""),
            role=str(raw.get("role", "") or ""),
            role_domains=role_domains,
            expiration_type=str(raw.get("expiration_type", "") or ""),
            expiration_hours=int(raw.get("expiration_hours") or 0),
            expiration_timestamp=int(raw.get("expiration_timestamp") or 0),
            created_timestamp=int(raw.get("created_timestamp") or 0),
            created_by_entity=str(raw.get("created_by_entity", "") or ""),
            description=_clip(str(raw.get("description", "") or ""), 500)[0],
        )


class ApiKeyList(BaseModel):
    """Result of ``nv_list_api_keys``."""

    model_config = _BASE

    page: Page
    api_keys: list[ApiKeyBrief]
```

**Fixture** `tests/fixtures/api_keys.json` — envelope key `apikeys`. Put an
`"apikey_secret"` value on one entry and assert it appears nowhere in the
serialised result.

**Tests** `tests/test_iam.py`: `test_list_api_keys_query_and_projection`,
`test_list_api_keys_never_returns_secret`,
`test_list_api_keys_truncates`.

**Notes**
* `RESTApikey` and `RESTApikeysData` (`apikeys`) are in Appendix B; every field
  above is verified. Note the envelope key is `apikeys` while the result field
  is `api_keys` — the mismatch is intentional (snake-case output naming) and the
  test asserts the request/response wiring.
* **Redaction rule (mandatory): `apikey_secret` is never projected.**
  `RESTApikey` declares it, and `RESTApikeyGenerated` returns it once at
  creation. There is no retrieval path afterwards. The projection omits the
  field, `extra="ignore"` drops it if sent, and the docstring states the
  non-recovery explicitly so a client model does not go hunting for another
  route. `nv_create_api_key` (Part C, `iam_write`) is the only tool that ever
  sees a secret.
* `RESTApikeysData.global_roles` and `.domain_roles` are envelope-level
  catalogues and are not projected; use `nv_list_roles`.
* The undocumented `GET /v1/api_key/{name}` and `GET /v1/selfapikey` routes are
  **not** used by this tool.

---

## B.1 Registration and gate checklist

Add to `server.py`'s `TOOL_MODULES` in phase order: `tools.events` [P5],
`tools.policy_read` [P6], `tools.iam` [P10].

| Gate rule | How Part B satisfies it |
|---|---|
| R1 | All 19 names match `^nv_[a-z0-9_]+$`. |
| R2 | Every docstring has a summary line, a guidance paragraph and at least one `Calls` line; all exceed 80 characters. |
| R3 | Every tool uses the shared `READ_ONLY` annotations with `readOnlyHint=True`, and all three toolsets are read-kind. |
| R4 | Exactly one toolset tag per tool: `events` (5), `policy_read` (10), `iam_read` (4). |
| R5 | No tool in Part B declares `confirm` — including `nv_assess_admission_rule`. |
| R6 | 21 distinct endpoints, all present in `spec_endpoints.json["documented"]`; none needs `UNDOCUMENTED_ALLOWLIST`. |
| R7 | Every tool returns a Pydantic model; no `dict[str, Any]` returns. |
| R8 | Every tool name appears in `tests/test_events.py`, `tests/test_policy_read.py` or `tests/test_iam.py` as listed per tool. |
| R9 | Unaffected — Part B adds no mutating tools. |

**New classes appended to `models.py`** (in this order; `_clip` must precede its
users): `_clip`, `EventKind`, `SecurityEvent`, `SecurityEventList`,
`ThreatDetail`, `AuditEvent`, `AuditEventList`, `SystemEvent`,
`SystemEventList`, `SystemAlerts` [P5]; `NetworkRule`, `NetworkRuleList`,
`ProcessProfileEntry`, `ProcessProfile`, `FileMonitorFilter`,
`FileMonitorProfile`, `ResponseRule`, `ResponseRuleList`, `SensorBrief`,
`DlpSensorList`, `WafSensorList`, `AdmissionState`, `_flatten_criterion`,
`AdmissionRule`, `AdmissionRuleList`, `AdmissionCriterionInput`,
`AdmissionMatchedRule`, `AdmissionAssessmentResult`, `AdmissionAssessment` [P6];
`UserBrief`, `UserList`, `RolePermission`, `RoleBrief`, `RoleList`,
`_AUTH_SERVER_VALUE_ALLOWLIST`, `_SECRET_KEY_MARKERS`, `AuthServerBrief`,
`AuthServerList`, `ApiKeyBrief`, `ApiKeyList` [P10]. `Page`, `WorkloadBrief`,
`SystemSummary`, `WriteOutcome`, `PolicyMode`, `Severity` and `_BASE` already
exist — reference them, never redefine them.

**New fixture files** (21 total, envelope key in parentheses):
`log_threat.json` (`threats`), `log_violation.json` (`violations`),
`log_incident.json` (`incidents`), `log_threat_detail.json` (`threat`),
`log_audit.json` (`audits`), `log_event.json` (`events`),
`system_alerts.json` (`alerts`, inferred), `policy_rules.json` (`rules`),
`policy_rule.json` (`rule`), `process_profile.json` (`process_profile`),
`file_monitor_profile.json` (`filters`, inferred),
`response_rules.json` (`rules`), `dlp_sensors.json` (`sensors`, inferred),
`waf_sensors.json` (`sensors`, inferred),
`admission_state.json` (no envelope: `state` + `k8s_env`),
`admission_rules.json` (`rules`),
`admission_assessment.json` (no envelope: `results` + `global_mode`),
`users.json` (`users`), `user_roles.json` (`roles`),
`auth_servers.json` (`servers`, inferred), `api_keys.json` (`apikeys`).
