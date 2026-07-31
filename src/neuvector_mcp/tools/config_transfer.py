"""Configuration export/import and remote repositories. Toolsets ``system_write`` + ``policy_read``.

Every tool here follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Three things in this module differ from every other write module, and each is a
deliberate decision rather than an oversight.

**The responses are YAML, not JSON.** ``NeuVectorClient.request`` parses a
response as JSON and falls back to ``_safe_json``, which returns
``response.text[:500]`` for anything it cannot parse. Routing an export through
it would therefore return the first 500 characters of a YAML document while
reporting success - the same failure class as the 1.0.3 policy-mode bug. Exports
go through ``client.request_text`` instead, which returns the whole body.

**A whole export does not belong in a context window.** A cluster export is
routinely megabytes. ``nv_export_config`` caps what it returns at
``max_characters`` and sets ``controller_response["truncated"]`` when it clipped;
it never truncates silently. ``kind="all"`` never returns its document at all -
see :data:`_ALL_WITHHELD_REASON`.

**Redaction is line-wise and therefore incomplete.** ``redact_secrets`` in
``models.py`` walks parsed structures, but an export is an opaque string and
this project has no YAML parser (``pyproject.toml`` depends on fastmcp, httpx,
pydantic and structlog, and nothing else). :func:`redact_yaml_secrets` therefore
matches the :data:`~neuvector_mcp.models.SECRET_FIELDS` key names at the start of
a YAML mapping line and blanks the value, following block scalars. What that
does NOT catch is enumerated on :func:`redact_yaml_secrets` and repeated in the
tool docstring, because a redaction whose limits are not stated is worse than no
redaction at all.
"""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..client import build_query
from ..config import Settings
from ..context import app_context
from ..errors import ValidationError_
from ..guard import authorise_write
from ..models import (
    REDACTED,
    SECRET_FIELDS,
    ImportTaskStatus,
    WriteOutcome,
    _clip,
    redact_secrets,
)

#: Reads a whole configuration out of the controller. Not destructive, and
#: repeating it changes nothing - but it is gated like a write because the
#: document it returns can contain credentials.
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
#: Creates a stored object that did not exist before.
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
#: Overwrites or destroys stored configuration.
MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
#: Pure read.
READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

# --- YAML redaction -----------------------------------------------------------

#: What a redacted value is replaced with. Quoted so the document still parses.
REDACTED_YAML = f"'{REDACTED}'"

#: A YAML block-mapping key at the start of a line, optionally the first key of a
#: sequence item ("- name: x"). YAML requires whitespace after the colon in block
#: context, so "key:value" is not a mapping and is deliberately not matched.
_YAML_KEY_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?:-[ \t]+)?(?P<key>[A-Za-z0-9_.\-]+)[ \t]*:(?P<rest>[ \t].*|)$"
)


def redact_yaml_secrets(document: str) -> tuple[str, dict[str, int]]:
    """Blank the value of every :data:`SECRET_FIELDS` key in a YAML document.

    This is a LINE filter, not a parser. It replaces the value on any line whose
    key is exactly one of the known credential field names, and when that value
    opens a block scalar (``|`` or ``>``) it drops the indented block that
    follows, so a multi-line ``json_key`` does not survive its own header.

    What it CATCHES: ``password``, ``auth_token``, ``gitlab_private_token``,
    ``secret_access_key``, ``json_key``, ``personal_access_token`` and
    ``apikey_secret`` written as ordinary block-mapping keys, at any indentation,
    including as the first key of a sequence item, with plain, quoted or block
    scalar values.

    What it does NOT catch, and callers must be told so:

    * flow style - ``{password: hunter2}`` or ``[{password: hunter2}]`` on one
      line is a single line with a non-matching shape and passes through intact;
    * a secret stored under any key name NOT in :data:`SECRET_FIELDS`, which
      includes every credential a future controller version adds;
    * a credential embedded in the VALUE of an innocuous key - the webhook URLs
      in a system export are the live example: ``url: https://hooks.example/T00/B00/<token>``
      is a secret under the key ``url`` and is returned verbatim;
    * a secret inside a free-text ``comment`` or ``description``;
    * anything the controller emitted already encrypted or base64-wrapped, which
      is neither redacted nor recognisable.

    Args:
        document: The YAML text exactly as the controller returned it.

    Returns:
        ``(redacted_document, {key_name: times_blanked})``. The counts are
        reported to the caller so "0 secrets found" is distinguishable from
        "redaction did not run".
    """
    lines = document.splitlines()
    out: list[str] = []
    hits: dict[str, int] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        match = _YAML_KEY_RE.match(line)
        if match is None or match["key"] not in SECRET_FIELDS:
            out.append(line)
            continue
        key = match["key"]
        hits[key] = hits.get(key, 0) + 1
        prefix = line[: match.start("key")]
        out.append(f"{prefix}{key}: {REDACTED_YAML}")
        if match["rest"].strip()[:1] in ("|", ">"):
            # A block scalar owns every following line that is blank or indented
            # deeper than the key itself.
            key_column = len(prefix)
            while index < len(lines):
                following = lines[index]
                if following.strip() and len(following) - len(following.lstrip()) <= key_column:
                    break
                index += 1
    text = "\n".join(out)
    return (text + "\n" if document.endswith("\n") and text else text), hits


# --- export ------------------------------------------------------------------

#: One export kind: the route, whether the endpoint takes ``scope``, and the
#: selector field name in its request body. Routes and body types come from
#: apis.yaml 5.6.0; the body field names come from apis.go, which is authoritative.
#:
#: ``all`` is a GET and not a POST. apis.yaml declares ``GET /v1/file/config``
#: "Download a configure file" and ``POST /v1/file/config`` "Upload configure
#: file" (consumes multipart/form-data, formData file "configuration"). POSTing
#: to that path is therefore a whole-cluster IMPORT, not an export; using it to
#: export would overwrite the cluster.
_EXPORT_KINDS: dict[str, dict[str, Any]] = {
    "all": {
        "method": "GET",
        "path": "/v1/file/config",
        "scope": False,
        "selector": None,  # no request body at all
        "what": "the ENTIRE cluster configuration",
    },
    "group": {
        "method": "POST",
        "path": "/v1/file/group",
        "scope": True,
        "selector": "groups",  # apis.go RESTGroupExport.Groups
        "what": "group definitions with their process, file and network policy",
    },
    "admission": {
        "method": "POST",
        "path": "/v1/file/admission",
        "scope": True,
        "selector": "ids",  # apis.go RESTAdmCtrlRulesExport.IDs
        "what": "admission control rules, and the admission state when include_state is true",
    },
    "dlp": {
        "method": "POST",
        "path": "/v1/file/dlp",
        "scope": True,
        "selector": "names",  # apis.go RESTDlpSensorExport.Names
        "what": "DLP sensors and their rules",
    },
    "waf": {
        "method": "POST",
        "path": "/v1/file/waf",
        "scope": True,
        "selector": "names",  # apis.go RESTWafSensorExport.Names
        "what": "WAF sensors and their rules",
    },
    "response_rule": {
        "method": "POST",
        "path": "/v1/file/response/rule",
        "scope": True,
        "selector": "ids",  # apis.go RESTResponseRulesExport.IDs
        "what": "non-group-dependent response rules",
    },
    "compliance_profile": {
        "method": "POST",
        "path": "/v1/file/compliance/profile",
        "scope": False,
        "selector": "names",  # apis.go RESTCompProfilesExport.Names
        "what": "compliance profiles",
    },
    "vulnerability_profile": {
        "method": "POST",
        "path": "/v1/file/vulnerability/profile",
        "scope": False,
        "selector": "names",  # apis.go RESTVulnProfilesExport.Names
        "what": "vulnerability profiles and their exception entries",
    },
}

ExportKind = Literal[
    "all",
    "group",
    "admission",
    "dlp",
    "waf",
    "response_rule",
    "compliance_profile",
    "vulnerability_profile",
]

#: Why kind="all" reports its document instead of returning it.
_ALL_WITHHELD_REASON = (
    "kind='all' exports the whole cluster configuration, which contains registry "
    "credentials, LDAP/SAML server secrets, remote-repository access tokens and "
    "webhook URLs with tokens embedded in the URL itself. The line-wise redactor "
    "cannot be trusted on a document of that shape - a token inside a webhook URL "
    "sits under the key 'url' and no key-name filter will find it - so the document "
    "is NOT returned. Its size and the credential keys detected in it are reported "
    "instead. Export a narrower kind if you need the text, or take the full backup "
    "through the NeuVector console where it does not pass through a language model."
)

#: Import kinds, keyed the same way as the exports. There is deliberately no
#: "all": POST /v1/file/config is multipart/form-data (apis.yaml) and would
#: replace the entire cluster configuration in one call.
_IMPORT_KINDS: dict[str, dict[str, Any]] = {
    "group": {
        "path": "/v1/file/group/config",
        "scope": True,
        "replaces": "every group definition and the process, file and network policy attached to it",
    },
    "admission": {
        "path": "/v1/file/admission/config",
        "scope": True,
        "replaces": "the admission control rules, and the admission state when the file carries one",
    },
    "dlp": {
        "path": "/v1/file/dlp/config",
        "scope": True,
        "replaces": "the DLP sensors and their rules",
    },
    "waf": {
        "path": "/v1/file/waf/config",
        "scope": True,
        "replaces": "the WAF sensors and their rules",
    },
    "response_rule": {
        "path": "/v1/file/response/rule/config",
        "scope": True,
        "replaces": "the non-group-dependent response rules",
    },
    "compliance_profile": {
        "path": "/v1/file/compliance/profile/config",
        "scope": False,
        "replaces": "the compliance profiles",
    },
    "vulnerability_profile": {
        "path": "/v1/file/vulnerability/profile/config",
        "scope": False,
        "replaces": "the vulnerability profiles and their exception entries",
    },
}

ImportKind = Literal[
    "group",
    "admission",
    "dlp",
    "waf",
    "response_rule",
    "compliance_profile",
    "vulnerability_profile",
]

#: Wording of each scope value, for the confirmation plan. Follows the
#: ``scope`` query-parameter descriptions in apis.yaml for the /v1/file routes.
_SCOPE_MEANING: dict[str, str] = {
    "local": (
        "scope 'local' means THIS cluster's own configuration; federated objects pushed "
        "by a federation primary are not touched"
    ),
    "fed": (
        "scope 'fed' means the FEDERATED configuration, which a federation primary pushes "
        "to every member cluster - so the change is felt on every member, not only here"
    ),
}


def _export_body(
    kind: str,
    *,
    names: list[str] | None,
    ids: list[int] | None,
    use_name_referral: bool,
    include_state: bool,
) -> dict[str, Any] | None:
    """Render the request body for one export kind, field by field.

    Every field name comes from the apis.go export struct named in
    :data:`_EXPORT_KINDS`. None of those structs declares a pointer field except
    ``RemoteExportOptions`` (``omitempty``, and unsupported here), so every field
    written below is one the controller always expects to see.

    Returns ``None`` for ``kind="all"``, which is a GET with no body.
    """
    selector = _EXPORT_KINDS[kind]["selector"]
    if selector is None:
        return None
    if kind == "group":
        # apis.go RESTGroupExport: UseNameReferral and Groups are non-pointer, so
        # both are always sent. PolicyMode/ProfileMode are omitempty overrides
        # that REWRITE the mode recorded in the exported document; this tool
        # never sends them, so an export always records the modes as they are.
        return {"use_name_referral": use_name_referral, "groups": list(names or [])}
    if kind == "admission":
        # apis.go RESTAdmCtrlRulesExport: ExportConfig and IDs are both non-pointer.
        return {"export_config": include_state, "ids": list(ids or [])}
    if selector == "ids":
        return {"ids": list(ids or [])}
    return {"names": list(names or [])}


def _github_config(
    *,
    repository_owner: str | None,
    repository_name: str | None,
    branch: str | None,
    personal_access_token: str | None,
    committer_name: str | None,
    committer_email: str | None,
) -> dict[str, Any]:
    """Render a ``github_configuration`` object, omitting every unsupplied field.

    Field names come from apis.go ``RESTRemoteRepo_GitHubConfig`` /
    ``RESTRemoteRepository_GitHubConfigConfig``. One name is NOT what apis.yaml
    and appendix B say: both document the last field as
    ``personal_access_token_committer_email``, while apis.go - the struct the
    controller actually unmarshals into - tags it ``personal_access_token_email``.
    The house rule is that apis.go wins, and it must: sending the yaml's name
    would leave the field silently unset behind a 200, which is precisely how
    nv_set_group_policy_mode shipped broken.

    In the PATCH struct every field is a pointer, so an omitted key means "not
    supplied". In the POST struct every field is a plain string and all six are
    required, so the create tool supplies all six.
    """
    config: dict[str, Any] = {}
    if repository_owner is not None:
        config["repository_owner_username"] = repository_owner
    if repository_name is not None:
        config["repository_name"] = repository_name
    if branch is not None:
        config["repository_branch_name"] = branch
    if personal_access_token is not None:
        config["personal_access_token"] = personal_access_token
    if committer_name is not None:
        config["personal_access_token_committer_name"] = committer_name
    if committer_email is not None:
        config["personal_access_token_email"] = committer_email
    return config


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the config-transfer tools to ``mcp``, gating each toolset separately."""
    if settings.toolset_enabled("system_write"):
        _register_system_write(mcp)
    if settings.toolset_enabled("policy_read"):
        _register_policy_read(mcp)


def _register_policy_read(mcp: FastMCP) -> None:
    """The one non-mutating tool here: polling an import that is already running.

    It is tagged ``policy_read`` rather than ``system_write`` because a toolset is
    never mixed - a read tool must not ship under a write toolset - and because a
    poll that required a confirmation handshake would be unusable.
    """

    @mcp.tool(
        name="nv_get_import_status",
        annotations=READ_ONLY,
        tags={"policy_read", "read"},
    )
    async def nv_get_import_status(ctx: Context) -> ImportTaskStatus:
        """Report progress of the most recent configuration import on this controller.

        nv_import_config is ASYNCHRONOUS: it returns as soon as the controller has
        accepted the file, long before the file has been applied, so a successful
        import call is not a finished import. Poll this until percentage reaches 100,
        then read the imported objects back - nv_list_groups, nv_list_admission_rules,
        nv_list_waf_sensors and so on - because a finished task is still not proof
        that every rule in the file was accepted. There is ONE task record per
        controller and it is not per-kind: this reports whichever import ran last,
        whatever kind it was, so read task_id and triggered_by before assuming it is
        yours. A non-empty fail_to_decrypt_key_fields means the import PARTIALLY
        failed and the listed credential fields were not restored.

        Calls GET /v1/file/group/config (no request body).
        """
        app = app_context(ctx)
        raw = await app.client.request("GET", "/v1/file/group/config")
        return ImportTaskStatus.from_api(raw if isinstance(raw, dict) else {})


def _register_system_write(mcp: FastMCP) -> None:
    """Tools tagged ``system_write``: export, import, and the remote repositories."""

    @mcp.tool(
        name="nv_export_config",
        annotations=MUTATING_IDEMPOTENT,
        tags={"system_write", "write"},
    )
    async def nv_export_config(
        ctx: Context,
        kind: Annotated[
            ExportKind,
            Field(
                description="Which configuration to export, and therefore which route is "
                "called. 'group' exports group definitions with their process, file and "
                "network policy; 'admission' the admission rules; 'dlp' and 'waf' the "
                "sensors; 'response_rule' the non-group-dependent response rules; "
                "'compliance_profile' and 'vulnerability_profile' those profiles. 'all' "
                "exports the ENTIRE cluster configuration and does NOT return the document "
                "- it reports its size and the credential fields found in it, because a "
                "full export carries registry passwords, directory-server secrets and "
                "webhook URLs with tokens inside the URL."
            ),
        ],
        names: Annotated[
            list[str] | None,
            Field(
                description="Objects to export BY NAME, for kind 'group', 'dlp', 'waf', "
                "'compliance_profile' and 'vulnerability_profile'. An empty list or omitted "
                "means the controller decides what a nameless request covers, which for "
                "these endpoints is the whole set; that behaviour is documented nowhere and "
                "was NOT verified against a controller, so name what you want when you know "
                "it. Ignored for kinds that select by id."
            ),
        ] = None,
        ids: Annotated[
            list[int] | None,
            Field(
                description="Objects to export BY ID, for kind 'admission' and "
                "'response_rule' (both select with a numeric id list). Get ids from "
                "nv_list_admission_rules or nv_list_response_rules. Empty or omitted means "
                "the whole set, with the same caveat as 'names'. Ignored for kinds that "
                "select by name."
            ),
        ] = None,
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' exports THIS cluster's own configuration; 'fed' exports "
                "the FEDERATED configuration a federation primary pushes to its members. Only "
                "kinds 'group', 'admission', 'dlp', 'waf' and 'response_rule' accept it - "
                "passing 'fed' for any other kind is rejected before anything is sent."
            ),
        ] = "local",
        use_name_referral: Annotated[
            bool,
            Field(
                description="kind='group' only (apis.go RESTGroupExport.use_name_referral). "
                "True writes references to other groups by name instead of inlining their "
                "definitions, which keeps a group export small and self-consistent but makes "
                "it depend on those groups existing at import time."
            ),
        ] = False,
        include_state: Annotated[
            bool,
            Field(
                description="kind='admission' only (apis.go RESTAdmCtrlRulesExport."
                "export_config). True also exports the admission control STATE - whether "
                "admission control is enabled at all, and its default action. Importing such "
                "a file can therefore switch deployment gating on or off, not just change "
                "rules."
            ),
        ] = True,
        max_characters: Annotated[
            int,
            Field(
                ge=1000,
                le=200000,
                description="Hard cap on how much of the document is returned. An exported "
                "configuration is routinely megabytes and every character returned here is "
                "spent from the reading model's context window. When the document is longer "
                "the result is clipped and controller_response.truncated is set to true - it "
                "is never clipped silently. Raise it, or narrow the export with names/ids.",
            ),
        ] = 20000,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the export."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Export one part of the NeuVector configuration as a YAML document.

        The document this returns is what nv_import_config consumes, so ALWAYS run this
        for the matching kind and keep the output before importing anything - an import
        replaces a whole ruleset and the controller keeps no copy. Exporting changes
        nothing on the cluster, but it is gated like a write because a configuration
        document can carry credentials: values under the known credential key names are
        blanked line-wise before the document is returned, which catches an ordinary
        'password:' or 'personal_access_token:' key at any depth but CANNOT catch a
        secret embedded in a URL, a secret under a key name this server does not know,
        or flow-style YAML on one line. Treat any exported document as sensitive
        regardless. kind='all' is not returned at all, only described. The result is
        capped at max_characters and sets controller_response.truncated when it clipped.

        Calls GET /v1/file/config (kind='all'; the document is described, never returned).
        Calls POST /v1/file/group with {"groups": [...], "use_name_referral": ...} and scope.
        Calls POST /v1/file/admission with {"ids": [...], "export_config": ...} and scope.
        Calls POST /v1/file/dlp with {"names": [...]} and scope.
        Calls POST /v1/file/waf with {"names": [...]} and scope.
        Calls POST /v1/file/response/rule with {"ids": [...]} and scope.
        Calls POST /v1/file/compliance/profile with {"names": [...]}.
        Calls POST /v1/file/vulnerability/profile with {"names": [...]}.
        """
        app = app_context(ctx)
        spec = _EXPORT_KINDS[kind]

        # --- step 1: build the payload; validation first, no network call -------
        if scope == "fed" and not spec["scope"]:
            raise ValidationError_(
                f"nv_export_config(kind={kind!r}) does not accept scope='fed': apis.yaml "
                f"declares no scope parameter on {spec['method']} {spec['path']}. Only kinds "
                "group, admission, dlp, waf and response_rule are federation-scoped. Nothing "
                "was sent to the controller."
            )
        body = _export_body(
            kind,
            names=names,
            ids=ids,
            use_name_referral=use_name_referral,
            include_state=include_state,
        )
        params = build_query(extra={"scope": scope}) if spec["scope"] else {}

        selection = "everything in scope"
        if spec["selector"] == "names" and names:
            selection = f"{len(names)} named object(s): {', '.join(sorted(names))}"
        elif spec["selector"] == "ids" and ids:
            selection = f"{len(ids)} object(s) by id: {', '.join(str(i) for i in sorted(ids))}"

        route = f"{spec['method']} {spec['path']}"
        scope_text = f" with scope={scope!r}" if spec["scope"] else " (this route has no scope)"
        target = f"{kind} configuration export via {route}{scope_text}"
        payload: dict[str, Any] = {
            "route": route,
            "scope": scope if spec["scope"] else "",
            "body": body if body is not None else {},
        }

        # --- step 2: the guard --------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_export_config",
            toolset="system_write",
            target=target,
            effect=(
                f"Read {spec['what']} out of the controller as a YAML document by calling "
                f"{route}{scope_text}, exporting {selection}. Nothing on the cluster is "
                f"changed. The risk is disclosure, not damage: the document is placed in "
                f"this conversation, so whatever it contains is read by the model and kept "
                f"in the transcript. Values under the known credential key names "
                f"({', '.join(sorted(SECRET_FIELDS))}) are blanked line-wise first, but that "
                f"filter cannot see a token embedded in a URL, a credential under a key name "
                f"it does not know, or flow-style YAML."
                + (
                    f" Because kind='all', the document is NOT returned: {_ALL_WITHHELD_REASON}"
                    if kind == "all"
                    else f" At most {max_characters} characters are returned; anything longer "
                    f"is clipped and reported as truncated."
                )
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        # --- step 3: hand the plan back untouched -------------------------------
        if plan is not None:
            return plan

        # --- step 4: the controller call ---------------------------------------
        document = await app.client.request_text(
            spec["method"],
            spec["path"],
            params=params or None,
            json=body,
            timeout_s=app.settings.long_request_timeout_s,
        )
        redacted, secret_hits = redact_yaml_secrets(document)

        result: dict[str, Any] = {
            "kind": kind,
            "route": route,
            "scope": scope if spec["scope"] else "",
            "document_characters": len(document),
            "document_lines": document.count("\n") + (1 if document else 0),
            "credential_keys_found": dict(sorted(secret_hits.items())),
            "redaction": (
                "line-wise on the known credential key names; a secret inside a URL or "
                "under an unknown key name is NOT redacted"
            ),
        }
        if kind == "all":
            # --- step 5 for kind='all': describe, never disclose -----------------
            result.update(
                {
                    "yaml": "",
                    "truncated": True,
                    "withheld": True,
                    "withheld_reason": _ALL_WITHHELD_REASON,
                    "returned_characters": 0,
                    "hint": (
                        "Re-run with a narrower kind (group, admission, dlp, waf, "
                        "response_rule, compliance_profile, vulnerability_profile) to see "
                        "actual YAML."
                    ),
                }
            )
        else:
            shown, clipped = _clip(redacted, max_characters)
            result.update(
                {
                    "yaml": shown,
                    "truncated": clipped,
                    "withheld": False,
                    "returned_characters": len(shown),
                    "hint": (
                        f"{len(redacted)} characters after redaction, {len(shown)} returned. "
                        f"Raise max_characters, or narrow the export with names/ids. A "
                        f"truncated document is NOT importable."
                        if clipped
                        else None
                    ),
                }
            )

        return WriteOutcome(
            status="applied",
            operation="nv_export_config",
            target=target,
            effect=(
                f"exported {kind} configuration from {route}: {len(document)} characters, "
                f"{len(secret_hits)} distinct credential key name(s) blanked"
                + (
                    "; the document itself was withheld, see controller_response.withheld_reason"
                    if kind == "all"
                    else (
                        f"; {result['returned_characters']} characters returned"
                        + (" (TRUNCATED, not importable)" if result["truncated"] else "")
                    )
                )
            ),
            payload=payload,
            controller_response=result,
        )

    @mcp.tool(
        name="nv_import_config",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_import_config(
        ctx: Context,
        kind: Annotated[
            ImportKind,
            Field(
                description="Which ruleset the file REPLACES, and therefore which route is "
                "called. It must match what the file contains; a file exported with "
                "nv_export_config(kind=X) is imported with nv_import_config(kind=X). There "
                "is deliberately no 'all': the whole-cluster import "
                "(POST /v1/file/config) is a multipart upload and is not exposed here."
            ),
        ],
        yaml_document: Annotated[
            str,
            Field(
                min_length=1,
                description="The ENTIRE contents of the YAML file, sent verbatim as the "
                "request body. This is normally the 'yaml' value from a previous "
                "nv_export_config on the same kind. A document that nv_export_config "
                "reported as truncated is NOT importable and must never be passed here - it "
                "is a partial file and the controller will apply whatever prefix of it "
                "parses. Never pass a document you have not read.",
            ),
        ],
        scope: Annotated[
            Literal["local", "fed"],
            Field(
                description="'local' replaces THIS cluster's own configuration; 'fed' "
                "replaces the FEDERATED configuration a federation primary pushes to every "
                "member cluster, so every member is overwritten and not only this one. Only "
                "kinds 'group', 'admission', 'dlp', 'waf' and 'response_rule' accept it - "
                "passing 'fed' for any other kind is rejected before anything is sent."
            ),
        ] = "local",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the import. The token is bound to the "
                "SHA-256 of the document, so editing the file after previewing invalidates "
                "it and forces a fresh plan."
            ),
        ] = None,
    ) -> WriteOutcome:
        """REPLACE a whole ruleset with the contents of a YAML configuration file.

        This is the most destructive capability in this server. The chosen ruleset is
        not merged with the file, it is REPLACED by it: anything in the cluster that the
        file does not contain is gone, and anything the file contains overwrites what is
        there. There is no undo and the controller keeps no copy, so run
        nv_export_config for the same kind FIRST and keep the output where you can find
        it again. Groups in Protect mode start enforcing the file's network and process
        policy the moment it applies, so traffic that is allowed today can be dropped
        seconds later; importing admission rules can switch deployment gating off if the
        file carries an admission state. The import is ASYNCHRONOUS - a successful
        return means the controller accepted the file, not that it applied it - so poll
        nv_get_import_status until percentage reaches 100 and then read the objects back
        with nv_list_groups, nv_list_admission_rules or nv_list_waf_sensors, because a
        finished task is still not proof that every rule was accepted.

        Calls POST /v1/file/group/config with the YAML file as the body, and scope.
        Calls POST /v1/file/admission/config with the YAML file as the body, and scope.
        Calls POST /v1/file/dlp/config with the YAML file as the body, and scope.
        Calls POST /v1/file/waf/config with the YAML file as the body, and scope.
        Calls POST /v1/file/response/rule/config with the YAML file as the body, and scope.
        Calls POST /v1/file/compliance/profile/config with the YAML file as the body.
        Calls POST /v1/file/vulnerability/profile/config with the YAML file as the body.
        """
        app = app_context(ctx)
        spec = _IMPORT_KINDS[kind]

        # --- step 1: build the payload; validation first, no network call -------
        if not yaml_document.strip():
            raise ValidationError_(
                "nv_import_config was called with an empty yaml_document. Importing an empty "
                "file would ask the controller to replace a ruleset with nothing. Pass the "
                "document from nv_export_config. Nothing was sent to the controller."
            )
        if scope == "fed" and not spec["scope"]:
            raise ValidationError_(
                f"nv_import_config(kind={kind!r}) does not accept scope='fed': apis.yaml "
                f"declares no scope parameter on POST {spec['path']}. Only kinds group, "
                "admission, dlp, waf and response_rule are federation-scoped. Nothing was "
                "sent to the controller."
            )
        if REDACTED_YAML in yaml_document or f": {REDACTED}" in yaml_document:
            raise ValidationError_(
                "nv_import_config was given a document that still contains the redaction "
                f"sentinel {REDACTED!r}. That document came out of nv_export_config with its "
                "credentials blanked; importing it would store '***' as a live credential. "
                "Replace every sentinel with the real value first. Nothing was sent to the "
                "controller."
            )

        params = build_query(extra={"scope": scope}) if spec["scope"] else {}
        digest = hashlib.sha256(yaml_document.encode("utf-8")).hexdigest()
        head, head_clipped = _clip(yaml_document, 400)

        # The request body is a raw YAML document, not JSON, so 'payload' DESCRIBES
        # the body instead of being it: putting a megabyte of YAML into the plan
        # would flood the caller's context with text it just sent. Binding the
        # token to the sha256 is stricter than echoing the text would be - any
        # edit between preview and confirm invalidates it.
        payload: dict[str, Any] = {
            "route": f"POST {spec['path']}",
            "scope": scope if spec["scope"] else "",
            "content_type": "text/plain; charset=utf-8",
            "body_is": "the yaml_document verbatim, not a JSON object",
            "document_characters": len(yaml_document),
            "document_sha256": digest,
            "document_head": head + ("..." if head_clipped else ""),
        }
        scope_text = (
            f" with scope={scope!r} - {_SCOPE_MEANING[scope]}"
            if spec["scope"]
            else " (this route has no scope; it is always this cluster's own configuration)"
        )
        target = f"{kind} configuration on this cluster (sha256 {digest[:12]})"

        # --- step 2: the guard --------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_import_config",
            toolset="system_write",
            target=target,
            effect=(
                f"REPLACE {spec['replaces']} with the contents of a "
                f"{len(yaml_document)}-character YAML file, by POSTing that file as the "
                f"request body to {spec['path']}{scope_text}. This is a wholesale "
                f"replacement, not a merge: anything currently on the cluster that the file "
                f"does not contain is REMOVED, and anything the file contains overwrites "
                f"what is there. There is NO UNDO and the controller keeps no copy - export "
                f"the current state with nv_export_config(kind={kind!r}) and keep it before "
                f"confirming. Groups in Protect mode begin enforcing the file's policy as "
                f"soon as it applies, so traffic allowed today can be dropped immediately, "
                f"and an admission file carrying a state can switch deployment gating off. "
                f"The import runs ASYNCHRONOUSLY: this call returns when the controller has "
                f"accepted the file, not when it has applied it, so poll nv_get_import_status "
                f"afterwards and then read the objects back. The confirmation token is bound "
                f"to sha256 {digest} - editing the document invalidates it."
            ),
            payload=payload,
            confirm=confirm,
            namespace=None,
        )
        # --- step 3: hand the plan back untouched -------------------------------
        if plan is not None:
            return plan

        # --- step 4: the controller call ---------------------------------------
        response = await app.client.send_document(
            "POST",
            spec["path"],
            document=yaml_document,
            params=params or None,
            timeout_s=app.settings.long_request_timeout_s,
        )
        task = ImportTaskStatus.from_api(response if isinstance(response, dict) else {})

        # --- step 5 ------------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_import_config",
            target=target,
            effect=(
                f"the controller ACCEPTED a {len(yaml_document)}-character {kind} "
                f"configuration file. It has not necessarily finished applying it: the "
                f"import is asynchronous and reported {task.percentage}% complete with "
                f"status {task.status or 'unreported'!r}. Poll nv_get_import_status until "
                f"percentage is 100, then read the objects back - the previous {kind} "
                f"configuration is gone either way."
            ),
            payload=payload,
            controller_response={
                "import_task": task.model_dump(),
                "note": (
                    "Projected from RESTImportTaskData. temp_token is withheld: it is a "
                    "bearer token for resuming a transactional import. An empty task_id "
                    "means the controller answered without a task record, which does NOT "
                    "mean the import failed - poll nv_get_import_status."
                ),
            },
        )

    @mcp.tool(
        name="nv_create_remote_repository",
        annotations=MUTATING_CREATE,
        tags={"system_write", "write"},
    )
    async def nv_create_remote_repository(
        ctx: Context,
        nickname: Annotated[
            str,
            Field(
                min_length=1,
                description="Alias this repository is referred to by, e.g. 'backup'. It is "
                "the identity used in the URL of every later update or delete. Reusing an "
                "existing nickname is rejected by the controller with code 13.",
            ),
        ],
        repository_owner: Annotated[
            str,
            Field(
                min_length=1,
                description="GitHub account or organisation that owns the repository "
                "(controller field 'repository_owner_username').",
            ),
        ],
        repository_name: Annotated[
            str, Field(min_length=1, description="Repository name, without the owner prefix.")
        ],
        branch: Annotated[
            str,
            Field(
                min_length=1,
                description="Branch NeuVector commits to, e.g. 'main' (controller field "
                "'repository_branch_name'). Point this at a branch you are willing to have "
                "written to - exports are committed here.",
            ),
        ],
        personal_access_token: Annotated[
            str,
            Field(
                min_length=1,
                description="GitHub personal access token with write access to that branch. "
                "It is STORED ON THE CONTROLLER and used to push commits. It is never echoed "
                "back: the plan and the result show '***' in its place, so read the value "
                "back from your secret store rather than from this tool. Anyone who can read "
                "the controller's configuration can use this token.",
            ),
        ],
        committer_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Name recorded as the git committer on every pushed commit "
                "(controller field 'personal_access_token_committer_name').",
            ),
        ],
        committer_email: Annotated[
            str,
            Field(
                min_length=1,
                description="Email recorded as the git committer. NOTE: apis.go tags this "
                "field 'personal_access_token_email' while apis.yaml documents it as "
                "'personal_access_token_committer_email'; this server sends the apis.go name, "
                "because that is the one the controller unmarshals.",
            ),
        ],
        comment: Annotated[
            str,
            Field(
                description="Free-text note stored with the entry. Say who owns the token and "
                "when it expires; nothing else records that."
            ),
        ] = "",
        enable: Annotated[
            bool,
            Field(
                description="False stores the entry without using it. Create it disabled when "
                "you want to verify the values before the controller pushes anything."
            ),
        ] = True,
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Register a GitHub repository the controller can commit exported configuration to.

        This STORES A GIT CREDENTIAL on the controller: a personal access token with
        write access to the named branch, held so NeuVector can push commits without a
        human present. Anyone who can read the controller's configuration - including
        anyone who can run a full configuration export - can obtain it, so scope the
        token to that one repository, give it the least access that lets it commit, and
        record its expiry in 'comment' because nothing else will. GitHub is the only
        provider this tool configures; apis.yaml states it is the only one supported, and
        provider is sent as 'github'. The token is never echoed back: the plan and the
        result show '***'. Verify the entry took effect by listing the system
        configuration, not by trusting the 200.

        Calls POST /v1/system/config/remote_repository with {"nickname":..., "provider": "github", "github_configuration": {...}}.
        """
        app = app_context(ctx)

        # --- step 1: build the payload -----------------------------------------
        # apis.go RESTRemoteRepository: nickname, provider, comment and enable are
        # plain (non-pointer) fields, so all four are always sent.
        # azure_devops_configuration is a pointer and is OMITTED rather than sent
        # as null - apis.yaml's RESTRemoteRepository schema does not list it, and
        # this tool configures github only.
        wire_payload: dict[str, Any] = {
            "nickname": nickname,
            "provider": "github",
            "comment": comment,
            "enable": enable,
            "github_configuration": _github_config(
                repository_owner=repository_owner,
                repository_name=repository_name,
                branch=branch,
                personal_access_token=personal_access_token,
                committer_name=committer_name,
                committer_email=committer_email,
            ),
        }
        # The two-payload rule: the real token goes to the controller and nowhere
        # else; the guard and the result see only the redacted copy. This works
        # because 'personal_access_token' is already in models.SECRET_FIELDS.
        safe_payload = redact_secrets(wire_payload)

        target = f"remote repository {nickname!r}"
        # --- step 2: the guard --------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_create_remote_repository",
            toolset="system_write",
            target=target,
            effect=(
                f"Store a new remote repository {nickname!r} pointing at GitHub "
                f"{repository_owner}/{repository_name} branch {branch!r}, "
                f"{'enabled' if enable else 'disabled'}. This WRITES A GIT PERSONAL ACCESS "
                f"TOKEN into the controller's configuration, where it is kept so NeuVector "
                f"can push commits unattended; it is shown as '***' here and is never "
                f"returned by this server, but it is readable by anyone who can read the "
                f"controller's configuration or run a full configuration export. Commits "
                f"pushed with it are attributed to {committer_name} <{committer_email}>. "
                f"Nothing is pushed by creating the entry."
            ),
            payload=safe_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- step 3 -------------------------------------------------------------
        if plan is not None:
            return plan

        # --- step 4: wire_payload goes here and nowhere else ---------------------
        response = await app.client.request(
            "POST", "/v1/system/config/remote_repository", json=wire_payload
        )
        # --- step 5 -------------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_create_remote_repository",
            target=target,
            effect=(
                f"remote repository {nickname} created for "
                f"{repository_owner}/{repository_name} on branch {branch}; the access token "
                f"is now stored on the controller."
            ),
            payload=safe_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_update_remote_repository",
        annotations=MUTATING_IDEMPOTENT,
        tags={"system_write", "write"},
    )
    async def nv_update_remote_repository(
        ctx: Context,
        alias: Annotated[
            str,
            Field(
                min_length=1,
                description="Nickname of the repository entry to update. It appears in the "
                "URL and is also sent in the body, because apis.go RESTRemoteRepositoryConfig "
                "declares nickname as a required non-pointer field.",
            ),
        ],
        comment: Annotated[
            str | None,
            Field(description="New comment. Omit to leave the existing comment unchanged."),
        ] = None,
        enable: Annotated[
            bool | None,
            Field(
                description="True lets the controller use this repository again; false stops "
                "it pushing without deleting the stored token. Omit to leave unchanged."
            ),
        ] = None,
        repository_owner: Annotated[
            str | None,
            Field(
                description="New GitHub account or organisation. Omit to leave unchanged. See "
                "the tool description before sending any github field on its own."
            ),
        ] = None,
        repository_name: Annotated[
            str | None, Field(description="New repository name. Omit to leave unchanged.")
        ] = None,
        branch: Annotated[
            str | None, Field(description="New branch name. Omit to leave unchanged.")
        ] = None,
        personal_access_token: Annotated[
            str | None,
            Field(
                description="Replacement GitHub personal access token. Omit to keep the "
                "stored one. Supply this to rotate an expiring or leaked token. It is never "
                "echoed back - the plan and the result show '***'."
            ),
        ] = None,
        committer_name: Annotated[
            str | None, Field(description="New git committer name. Omit to leave unchanged.")
        ] = None,
        committer_email: Annotated[
            str | None,
            Field(
                description="New git committer email, sent as apis.go's "
                "'personal_access_token_email'. Omit to leave unchanged."
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
        """Update a stored remote repository, most often to rotate its access token.

        Only the arguments you supply are sent; apis.go RESTRemoteRepositoryConfig
        declares every optional field as a pointer, so an omitted key means "not
        modified". WARNING about the nested github_configuration: whether the controller
        MERGES a partial github_configuration into the stored one or REPLACES it
        wholesale is not stated in apis.yaml, apis.go or appendix B, and could not be
        verified offline. If you change any github field, supply every github field you
        want kept - repository_owner, repository_name, branch, personal_access_token,
        committer_name and committer_email - so the outcome is the same either way.
        apis.go's IsValid() additionally rejects a github field that is present but
        empty, so never pass "" to mean "clear this". Read the entry back after
        confirming; a 200 does not prove the controller kept every field.

        Calls PATCH /v1/system/config/remote_repository/{alias} with {"config": {...only the fields you supplied}}.
        """
        app = app_context(ctx)

        # --- step 1: build the payload -----------------------------------------
        github = _github_config(
            repository_owner=repository_owner,
            repository_name=repository_name,
            branch=branch,
            personal_access_token=personal_access_token,
            committer_name=committer_name,
            committer_email=committer_email,
        )
        # apis.go RESTRemoteRepositoryConfig: Nickname is non-pointer (always sent);
        # Comment, Enable and GitHubConfiguration are pointers, so an omitted key is
        # what tells the controller to leave that setting alone. Never send null.
        config: dict[str, Any] = {"nickname": alias}
        if comment is not None:
            config["comment"] = comment
        if enable is not None:
            config["enable"] = enable
        if github:
            config["github_configuration"] = github

        changed = [key for key in config if key != "nickname"]
        if not changed:
            raise ValidationError_(
                f"nv_update_remote_repository was called for {alias!r} with no field to "
                "change. Supply at least one of comment, enable, repository_owner, "
                "repository_name, branch, personal_access_token, committer_name or "
                "committer_email. Nothing was sent to the controller."
            )

        wire_payload: dict[str, Any] = {"config": config}
        safe_payload = redact_secrets(wire_payload)
        summary = ", ".join(
            sorted(k for k in safe_payload["config"] if k != "nickname")
            + (sorted(github) if github else [])
        )

        target = f"remote repository {alias!r}"
        # --- step 2: the guard --------------------------------------------------
        plan = authorise_write(
            app.settings,
            operation="nv_update_remote_repository",
            toolset="system_write",
            target=target,
            effect=(
                f"Update remote repository {alias!r}, sending only: {summary}. Fields not "
                f"listed are omitted from the body and the controller leaves them alone."
                + (
                    " A github_configuration is included: whether the controller merges it "
                    "into the stored configuration or replaces it wholesale is NOT documented "
                    "and was not verified, so any github field you did not supply may end up "
                    "cleared. Supply all six, or read the entry back immediately after."
                    if github
                    else ""
                )
                + (
                    " The stored access token is being REPLACED; the old one stops being "
                    "used and pushes will fail if the new one lacks write access to the "
                    "branch. It is shown as '***' here and never returned."
                    if personal_access_token is not None
                    else ""
                )
                + (
                    " Setting enable=false stops the controller pushing to this repository "
                    "but does NOT delete the stored token."
                    if enable is False
                    else ""
                )
            ),
            payload=safe_payload,
            confirm=confirm,
            namespace=None,
        )
        # --- step 3 -------------------------------------------------------------
        if plan is not None:
            return plan

        # --- step 4 -------------------------------------------------------------
        response = await app.client.request(
            "PATCH", f"/v1/system/config/remote_repository/{alias}", json=wire_payload
        )
        # --- step 5 -------------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_update_remote_repository",
            target=target,
            effect=(
                f"remote repository {alias} updated: {summary}. A 200 does not prove the "
                f"controller kept every field - read the entry back before relying on it."
            ),
            payload=safe_payload,
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_remote_repository",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_delete_remote_repository(
        ctx: Context,
        alias: Annotated[
            str,
            Field(
                min_length=1,
                description="Nickname of the repository entry to delete. Deleting an entry "
                "that does not exist is rejected by the controller with code 7.",
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
        """Delete a stored remote repository entry and the access token held with it.

        The entry and its personal access token are removed from the controller. Any
        scheduled or manual export configured to publish to this alias stops working
        immediately and the controller keeps no copy of the token, so re-creating the
        entry means obtaining a fresh token from GitHub - the old value is not
        recoverable from NeuVector. Nothing already committed to the git repository is
        touched: the history stays where it is, only NeuVector's ability to write to it
        goes. If your intent is to pause publishing rather than to decommission the
        integration, use nv_update_remote_repository(enable=false) instead, which keeps
        the token. Revoke the token in GitHub as well; deleting it here does not.

        Calls DELETE /v1/system/config/remote_repository/{alias} (no request body).
        """
        app = app_context(ctx)

        target = f"remote repository {alias!r}"
        # --- steps 1 and 2: no body; straight to the guard ----------------------
        plan = authorise_write(
            app.settings,
            operation="nv_delete_remote_repository",
            toolset="system_write",
            target=target,
            effect=(
                f"Delete the remote repository entry {alias!r} and the git personal access "
                f"token stored with it. Every export configured to publish to this alias "
                f"stops working immediately. The controller keeps no copy of the token, so "
                f"this is not undoable from NeuVector - re-creating the entry needs a fresh "
                f"token from GitHub. Nothing already committed to the git repository is "
                f"removed. To pause publishing without losing the token, use "
                f"nv_update_remote_repository({alias!r}, enable=false) instead. Deleting the "
                f"entry does NOT revoke the token in GitHub; revoke it there separately."
            ),
            payload=None,
            confirm=confirm,
            namespace=None,
        )
        # --- step 3 -------------------------------------------------------------
        if plan is not None:
            return plan

        # --- step 4 -------------------------------------------------------------
        response = await app.client.request(
            "DELETE", f"/v1/system/config/remote_repository/{alias}"
        )
        # --- step 5 -------------------------------------------------------------
        return WriteOutcome(
            status="applied",
            operation="nv_delete_remote_repository",
            target=target,
            effect=(
                f"remote repository {alias} deleted along with its stored access token; "
                f"exports publishing to this alias will now fail. Revoke the token in GitHub "
                f"as well."
            ),
            payload={},
            controller_response=redact_secrets(response) if isinstance(response, dict) else {},
        )
