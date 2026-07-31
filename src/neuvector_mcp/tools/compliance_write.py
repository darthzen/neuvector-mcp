"""Mutating compliance-profile and custom-check tools. Toolset ``system_write``.

Every tool here follows the same five-step body, in this exact order:

1. build the controller payload
2. call :func:`~neuvector_mcp.guard.authorise_write`
3. return the plan verbatim if the guard returned one
4. perform the controller call
5. return a :class:`~neuvector_mcp.models.WriteOutcome` with status="applied"

Do not reorder those steps and do not call the controller before step 3.

``nv_set_custom_compliance_checks`` is the highest-privilege tool in this
server. Its payload is a set of shell scripts that the NeuVector enforcer
executes on every node running the target group, which is remote code execution
on those nodes by design. It uses the same two-step confirm handshake as every
other mutating tool - the weight is carried by the plan text, which names the
group, the scripts and the fact that they will run, and by ``payload``, which
shows every script body in full and uncapped so a human can read it before
approving.

The read side of these objects lives in ``tools/compliance.py``
(``nv_list_compliance_profiles``, ``nv_get_compliance_profile``); this module
adds no read tools.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..config import Settings
from ..context import app_context
from ..errors import ValidationError_
from ..guard import authorise_write
from ..models import (
    ComplianceProfileEntryInput,
    CustomComplianceScriptInput,
    WriteOutcome,
)

MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
MUTATING_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
MUTATING_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)

#: Compliance standards a profile entry may be tagged with. Taken verbatim from
#: the ``ComplianceTemplate*`` constants in apis.go (5.6.0). ``ComplianceTemplateAll``
#: ("all") is deliberately excluded: it is a report-side filter meaning "every
#: standard", not a tag the controller stores on an entry. A misspelled tag is
#: accepted by the controller and then matches no report, so it is rejected here
#: rather than silently doing nothing.
COMPLIANCE_TAGS: frozenset[str] = frozenset({"PCI", "PCIv4", "GDPR", "HIPAA", "NIST", "DISA"})

#: Hard cap on entries listed by name in a confirmation plan. The count is always
#: exact; only the enumeration is capped, and the plan says so when it is.
MAX_ENTRIES_IN_PLAN = 25

#: Hard cap on scripts changed in one call to ``nv_set_custom_compliance_checks``.
#: These scripts execute on nodes, so a batch stays small enough that a human can
#: actually read every line of the preview before confirming. Same reasoning as
#: ``MAX_RULE_CHANGES`` in policy_write.py.
MAX_CUSTOM_SCRIPTS = 16


def _namespace_from_group_name(group_name: str) -> str | None:
    """Namespace a learned group belongs to, for NV_ALLOWED_NAMESPACES.

    Learned groups are named ``nv.<service>.<namespace>``; anything else is a
    custom group (or the built-in ``nodes`` group) whose namespace cannot be
    derived from its name. Mirrors the identical helper in policy_write.py -
    each tool module keeps its own copy rather than importing across modules.
    """
    return group_name.split(".")[-1] if group_name.startswith("nv.") else None


def _validate_tags(tags: list[str], where: str) -> None:
    """Reject tags the controller has no report for. Nothing is sent when this raises."""
    unknown = [t for t in tags if t not in COMPLIANCE_TAGS]
    if unknown:
        raise ValidationError_(
            f"unknown compliance tag(s) {unknown} in {where}. Valid tags are "
            f"{sorted(COMPLIANCE_TAGS)}. A tag outside that set is stored but matches "
            "no compliance report, so the check would silently count towards nothing. "
            "Nothing was sent to the controller."
        )


def _compliance_entry_body(entry: ComplianceProfileEntryInput) -> dict[str, Any]:
    """Render one ``RESTComplianceProfileEntry`` request object.

    Field names from apis.go ``RESTComplianceProfileEntry``: the check id is
    ``test_number``, NOT ``name``. Both fields are required and neither carries
    ``omitempty``, so both are always written. Built explicitly rather than by
    ``model_dump()`` so the wire shape is auditable field by field.
    """
    return {"test_number": entry.test_number, "tags": list(entry.tags)}


def _custom_check_body(script: CustomComplianceScriptInput) -> dict[str, Any]:
    """Render one ``RESTCustomCheck`` request object.

    Field names from apis.go ``RESTCustomCheck`` (name/script/configurable).
    apis.yaml documents only name and script; apis.go wins, and ``configurable``
    has no ``omitempty``, so it is always written.
    """
    return {
        "name": script.name,
        "script": script.script,
        "configurable": script.configurable,
    }


def _custom_checks_body(
    group_name: str, enabled: bool, scripts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Render one ``RESTCustomChecks`` sub-object of ``RESTCustomCheckConfig``.

    Field names from apis.go ``RESTCustomChecks``. ``writable`` is omitted on
    purpose: it is a server-reported flag saying whether the set may be written
    at all, not an instruction the caller gets to send.
    """
    return {"group": group_name, "enabled": enabled, "scripts": scripts}


def _describe_scripts(scripts: list[CustomComplianceScriptInput]) -> str:
    """Name every script with its size, so an oversized body is visible in the plan."""
    if not scripts:
        return "none"
    return "; ".join(
        f"{s.name} ({len(s.script.splitlines())} lines, {len(s.script.encode())} bytes)"
        for s in scripts
    )


def _describe_entries(entries: list[ComplianceProfileEntryInput]) -> str:
    """List check ids in a plan, capped, and say so explicitly when capped."""
    if not entries:
        return "none"
    shown = entries[:MAX_ENTRIES_IN_PLAN]
    text = ", ".join(f"{e.test_number}=[{','.join(e.tags) or 'no tags'}]" for e in shown)
    if len(entries) > len(shown):
        text += (
            f" ... plus {len(entries) - len(shown)} further entries not listed here "
            f"(this listing is capped at {MAX_ENTRIES_IN_PLAN}; the full list is in 'payload')"
        )
    return text


def register(mcp: FastMCP, settings: Settings) -> None:
    """Attach the compliance write tools to ``mcp`` when system_write is enabled."""
    if not settings.toolset_enabled("system_write"):
        return

    @mcp.tool(
        name="nv_update_compliance_profile",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_update_compliance_profile(
        ctx: Context,
        profile_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Profile to change, from nv_list_compliance_profiles. Almost "
                "always 'default'.",
            ),
        ] = "default",
        disable_system: Annotated[
            bool | None,
            Field(
                description="True turns OFF NeuVector's own built-in compliance checks for "
                "the whole cluster; false turns them back on. Omit to leave it unchanged."
            ),
        ] = None,
        entries: Annotated[
            list[ComplianceProfileEntryInput] | None,
            Field(
                description="The COMPLETE new list of per-check tag overrides. This REPLACES "
                "the existing list; any override you do not resend is dropped. Omit to leave "
                "the list untouched. Get the current list from nv_get_compliance_profile."
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
        """Replace a compliance profile's check-tag overrides, and toggle the built-in checks.

        'entries' REPLACES the whole override list - it is never merged. A short list
        silently drops every override you did not resend, which changes which CIS checks
        count towards PCI, PCIv4, GDPR, HIPAA, NIST and DISA in every compliance report,
        with nothing in the reports to say why. This tool does NOT read the profile for
        you: call nv_get_compliance_profile first and resend the entries you want to keep.
        disable_system=true switches off NeuVector's built-in checks entirely. Valid check
        ids come from GET /v1/list/compliance.

        Calls PATCH /v1/compliance/profile/{name} with {"config": {"name":..., "disable_system":..., "entries":[...]}}.
        """
        app = app_context(ctx)

        if disable_system is None and entries is None:
            raise ValidationError_(
                "nv_update_compliance_profile needs at least one of disable_system or "
                "entries; a call that changes nothing is rejected. Nothing was sent to "
                "the controller."
            )
        for entry in entries or []:
            _validate_tags(entry.tags, f"entry {entry.test_number!r}")

        # Wire shape from apis.go RESTComplianceProfileConfigData ->
        # RESTComplianceProfileConfig. disable_system and entries are pointers with
        # `omitempty`, so an unset one is OMITTED rather than sent as null - sending
        # null would be indistinguishable from "no change" only by luck.
        #
        # cfg_type is deliberately NOT sent. apis.go declares it on the config struct
        # but apis.yaml (5.6.0, verified against live) does not, and its only valid
        # values are "user_created"/"ground" - "ground" marking a CRD-owned profile.
        # There is no caller-meaningful choice here and no source says what the
        # controller does with an empty one, so the field is left out entirely.
        config: dict[str, Any] = {"name": profile_name}
        if disable_system is not None:
            config["disable_system"] = disable_system
        if entries is not None:
            config["entries"] = [_compliance_entry_body(e) for e in entries]
        payload: dict[str, Any] = {"config": config}

        if entries is None:
            entries_effect = "The per-check tag override list is NOT touched by this call."
        else:
            entries_effect = (
                f"REPLACE the entire per-check tag override list. The profile will have "
                f"EXACTLY {len(entries)} entry/entries afterwards, and every override not "
                f"in this list is DROPPED: {_describe_entries(entries)}. "
            )
        if disable_system is None:
            system_effect = "disable_system is left unchanged."
        elif disable_system:
            system_effect = (
                "disable_system=true turns OFF NeuVector's built-in compliance checks, so "
                "they stop appearing in nv_get_compliance_findings and stop counting in "
                "every compliance report."
            )
        else:
            system_effect = "disable_system=false turns NeuVector's built-in checks back on."

        plan = authorise_write(
            app.settings,
            operation="nv_update_compliance_profile",
            toolset="system_write",
            target=profile_name,
            effect=(
                f"Update compliance profile {profile_name!r}, which applies cluster-wide. "
                f"{entries_effect} {system_effect} "
                f"Compare against nv_get_compliance_profile({profile_name!r}) before confirming."
            ),
            payload=payload,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH", f"/v1/compliance/profile/{profile_name}", json=payload
        )
        return WriteOutcome(
            status="applied",
            operation="nv_update_compliance_profile",
            target=profile_name,
            effect=(
                f"compliance profile {profile_name} updated: "
                + (
                    f"entry list replaced, now exactly {len(entries)} entries"
                    if entries is not None
                    else "entry list unchanged"
                )
                + (
                    f"; disable_system={str(disable_system).lower()}"
                    if disable_system is not None
                    else "; disable_system unchanged"
                )
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_set_compliance_check_tags",
        annotations=MUTATING_IDEMPOTENT,
        tags={"system_write", "write"},
    )
    async def nv_set_compliance_check_tags(
        ctx: Context,
        check: Annotated[
            str,
            Field(
                min_length=1,
                description="Check id to re-tag, e.g. 'K.1.2.3' or 'D.1.1.1'. Ids come from "
                "GET /v1/list/compliance, or from the entries of nv_get_compliance_profile.",
            ),
        ],
        tags: Annotated[
            list[str],
            Field(
                description="The COMPLETE new tag list for this check. Valid values: PCI, "
                "PCIv4, GDPR, HIPAA, NIST, DISA. An empty list means the check counts "
                "towards no standard at all.",
            ),
        ],
        profile_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Profile holding the override, from nv_list_compliance_profiles. "
                "Almost always 'default'.",
            ),
        ] = "default",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Re-tag one CIS check with the compliance standards it should count towards.

        Tags decide which compliance report a check appears in: a check tagged only PCI
        counts towards PCI and nothing else. This REPLACES that check's whole tag list, so
        re-tagging a check ['PCI'] silently stops it counting towards GDPR, HIPAA, NIST,
        PCIv4 and DISA, and an empty list removes it from every report. Auditors read
        those reports, so a wrong tag here is a wrong audit answer. Check ids come from
        GET /v1/list/compliance; current tags come from nv_get_compliance_profile.

        Calls PATCH /v1/compliance/profile/{name}/entry/{check} with {"config": {"test_number":..., "tags":[...]}}.
        """
        app = app_context(ctx)
        _validate_tags(tags, f"check {check!r}")

        # Wire shape from apis.go RESTComplianceProfileEntryConfigData, whose Config is a
        # plain RESTComplianceProfileEntry: {"config": {"test_number":..., "tags":[...]}}.
        # The check id is repeated in the body because the entry struct requires it; the
        # path segment alone is not enough.
        payload: dict[str, Any] = {"config": {"test_number": check, "tags": list(tags)}}

        plan = authorise_write(
            app.settings,
            operation="nv_set_compliance_check_tags",
            toolset="system_write",
            target=f"{profile_name}/{check}",
            effect=(
                f"Set the compliance tags of check {check!r} in profile {profile_name!r} to "
                f"EXACTLY {list(tags) or 'an empty list'}, replacing whatever it has now. "
                + (
                    f"The check will count towards {', '.join(tags)} and no other standard."
                    if tags
                    else "The check will count towards NO compliance standard and will "
                    "disappear from every compliance report."
                )
                + " This applies cluster-wide. Read the current tags with "
                f"nv_get_compliance_profile({profile_name!r}) before confirming."
            ),
            payload=payload,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "PATCH", f"/v1/compliance/profile/{profile_name}/entry/{check}", json=payload
        )
        return WriteOutcome(
            status="applied",
            operation="nv_set_compliance_check_tags",
            target=f"{profile_name}/{check}",
            effect=(
                f"check {check} in profile {profile_name} now tagged "
                f"{', '.join(tags) if tags else '(no standards)'}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_delete_compliance_check_tags",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_delete_compliance_check_tags(
        ctx: Context,
        check: Annotated[
            str,
            Field(
                min_length=1,
                description="Check id whose override to remove, e.g. 'K.1.2.3'. Ids come from "
                "GET /v1/list/compliance, or from the entries of nv_get_compliance_profile.",
            ),
        ],
        profile_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Profile holding the override, from nv_list_compliance_profiles. "
                "Almost always 'default'.",
            ),
        ] = "default",
        confirm: Annotated[
            str | None,
            Field(
                description="Confirmation token from the plan returned by the first call. "
                "Omit on the first call to preview the change."
            ),
        ] = None,
    ) -> WriteOutcome:
        """Remove one check's tag overrides, reverting it to NeuVector's shipped tagging.

        This does not delete the CIS check itself; it deletes the profile entry that was
        re-tagging it, so the check goes back to whatever standards NeuVector ships it
        under. Compliance reports change silently as a result: a check you had added to
        PCI stops counting towards PCI, and nothing in the report explains the drop. The
        controller answers 200 whether or not an entry existed, so confirm the entry is
        really there with nv_get_compliance_profile before and after.

        Calls DELETE /v1/compliance/profile/{name}/entry/{check}.
        """
        app = app_context(ctx)
        target = f"{profile_name}/{check}"
        plan = authorise_write(
            app.settings,
            operation="nv_delete_compliance_check_tags",
            toolset="system_write",
            target=target,
            effect=(
                f"Delete the tag override for check {check!r} from compliance profile "
                f"{profile_name!r}. The check reverts to NeuVector's built-in tagging, so "
                "the standards it counts towards change cluster-wide and every compliance "
                "report shifts with it. This is not reversible from the deleted state - to "
                "restore it you must know the old tags, so read them with "
                f"nv_get_compliance_profile({profile_name!r}) first."
            ),
            payload=None,
            confirm=confirm,
        )
        if plan is not None:
            return plan

        response = await app.client.request(
            "DELETE", f"/v1/compliance/profile/{profile_name}/entry/{check}"
        )
        return WriteOutcome(
            status="applied",
            operation="nv_delete_compliance_check_tags",
            target=target,
            effect=f"tag override for check {check} removed from profile {profile_name}",
            controller_response=response if isinstance(response, dict) else {},
        )

    @mcp.tool(
        name="nv_set_custom_compliance_checks",
        annotations=MUTATING,
        tags={"system_write", "write"},
    )
    async def nv_set_custom_compliance_checks(
        ctx: Context,
        group_name: Annotated[
            str,
            Field(
                min_length=1,
                description="Group whose custom check scripts to change, from nv_list_groups. "
                "The scripts run on every node hosting a workload in this group. 'nodes' is "
                "the built-in group covering every node in the cluster.",
            ),
        ],
        add_scripts: Annotated[
            list[CustomComplianceScriptInput],
            Field(
                default_factory=list,
                description="Scripts to add. Each 'script' is a shell script that the "
                "enforcer EXECUTES on the node. Do not send anything you have not read "
                "line by line.",
            ),
        ],
        update_scripts: Annotated[
            list[CustomComplianceScriptInput],
            Field(
                default_factory=list,
                description="Existing scripts to overwrite, matched by name. The new body "
                "replaces the old one wholesale and is executed on the node just the same.",
            ),
        ],
        delete_script_names: Annotated[
            list[str],
            Field(
                default_factory=list,
                description="Names of scripts to remove. Removing a script silently ends the "
                "check it performed; nothing in later reports says it stopped running.",
            ),
        ],
        enabled: Annotated[
            bool,
            Field(
                description="Whether custom checks run for this group at all. True means the "
                "scripts in this group execute on the next compliance scan. False leaves them "
                "stored but not executed."
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
        """REMOTE CODE EXECUTION: ships shell scripts that NeuVector EXECUTES on your nodes.

        Every script sent here is run by the NeuVector enforcer on each node hosting a
        workload in the target group, on every compliance scan. The enforcer normally runs
        as a privileged DaemonSet, so this is equivalent to shell access on those nodes and
        is the highest-privilege operation this server exposes. Read every line of
        'payload' in the returned plan before confirming; the script bodies are shown in
        full and uncapped precisely so that review is possible.

        Scripts are matched by name: add_scripts creates, update_scripts overwrites in
        place, delete_script_names removes. This tool does NOT read the current set for
        you - read it from GET /v1/custom_check/{group} first, or you may overwrite a
        script someone else relies on.

        Calls PATCH /v1/custom_check/{group} with {"config": {"add":..., "update":..., "delete":...}}.
        """
        app = app_context(ctx)

        if not add_scripts and not update_scripts and not delete_script_names:
            raise ValidationError_(
                "nv_set_custom_compliance_checks needs at least one of add_scripts, "
                "update_scripts or delete_script_names. Nothing was sent to the controller."
            )
        total = len(add_scripts) + len(update_scripts) + len(delete_script_names)
        if total > MAX_CUSTOM_SCRIPTS:
            raise ValidationError_(
                f"{total} script changes in one call exceeds the limit of "
                f"{MAX_CUSTOM_SCRIPTS}. These scripts execute on your nodes, so a batch "
                "must stay small enough for a human to read every line of the preview. "
                "Split the change. Nothing was sent to the controller."
            )
        for script in list(add_scripts) + list(update_scripts):
            if not script.script.strip():
                raise ValidationError_(
                    f"script {script.name!r} has an empty body. An empty custom check "
                    "silently reports nothing rather than failing. Nothing was sent to "
                    "the controller."
                )

        # Wire shape from apis.go RESTCustomCheckConfigData -> RESTCustomCheckConfig,
        # which is add/delete/update (Go field Del carries json tag "delete") - NOT a
        # flat replacement of the script set. Each of the three is a *RESTCustomChecks
        # pointer; an unused one is OMITTED rather than sent as null.
        config: dict[str, Any] = {}
        if add_scripts:
            config["add"] = _custom_checks_body(
                group_name, enabled, [_custom_check_body(s) for s in add_scripts]
            )
        if update_scripts:
            config["update"] = _custom_checks_body(
                group_name, enabled, [_custom_check_body(s) for s in update_scripts]
            )
        if delete_script_names:
            # RESTCustomCheck has no omitempty on script/configurable, so a delete entry
            # still carries both; only the name identifies the script being removed.
            config["delete"] = _custom_checks_body(
                group_name,
                enabled,
                [{"name": n, "script": "", "configurable": False} for n in delete_script_names],
            )
        payload: dict[str, Any] = {"config": config}

        executing = list(add_scripts) + list(update_scripts)
        plan = authorise_write(
            app.settings,
            operation="nv_set_custom_compliance_checks",
            toolset="system_write",
            target=group_name,
            effect=(
                f"REMOTE CODE EXECUTION on every node running group {group_name!r}. "
                f"This writes {len(executing)} shell script(s) into the custom compliance "
                f"check set of {group_name!r}, and the NeuVector enforcer WILL EXECUTE them "
                f"on each of those nodes on every compliance scan; the enforcer normally "
                f"runs as a privileged DaemonSet, so treat this as shell access to those "
                f"nodes. Adding {len(add_scripts)}: {_describe_scripts(list(add_scripts))}. "
                f"Overwriting {len(update_scripts)}: {_describe_scripts(list(update_scripts))}. "
                f"Deleting {len(delete_script_names)}: "
                f"{', '.join(delete_script_names) or 'none'} - a deleted check stops running "
                f"silently. Custom checks for this group will be set enabled="
                f"{str(enabled).lower()}"
                + (
                    "; the scripts run on the next scan. "
                    if enabled
                    else "; the scripts are stored but not executed until enabled. "
                )
                + "The COMPLETE, UNTRUNCATED body of every script is in 'payload' below. "
                "Read all of it before confirming - whatever is in there runs on your nodes."
            ),
            payload=payload,
            confirm=confirm,
            namespace=_namespace_from_group_name(group_name),
        )
        if plan is not None:
            return plan

        response = await app.client.request("PATCH", f"/v1/custom_check/{group_name}", json=payload)
        return WriteOutcome(
            status="applied",
            operation="nv_set_custom_compliance_checks",
            target=group_name,
            effect=(
                f"custom compliance checks of group {group_name} updated: "
                f"{len(add_scripts)} added, {len(update_scripts)} overwritten, "
                f"{len(delete_script_names)} deleted, enabled={str(enabled).lower()}. "
                f"{len(executing)} script(s) now execute on every node running {group_name}"
            ),
            payload=payload,
            controller_response=response if isinstance(response, dict) else {},
        )
