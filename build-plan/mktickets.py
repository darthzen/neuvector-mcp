#!/usr/bin/env python3
"""Author the NeuVector MCP build queue as GitHub Issues via agent-build-tools.

Every ticket is emitted through `agent-tools.py new` so the toolkit parses back
exactly what it wrote. Bodies follow build-plan/tools/ISSUE_TEMPLATE.md.
"""
import os
import subprocess
import sys

REPO = "/Users/rashford/Developer/neuvector-mcp"
TOOLS = os.path.join(REPO, "build-plan/tools/agent-tools.py")
BODIES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bodies")
DRY = "--dry-run" in sys.argv

GATE = "make verify PY=.venv/bin/python"


def count_check(n):
    return f'make spec PY=.venv/bin/python | grep -q "{n} tools introspected"'


READING_PREAMBLE = """Read, in this order, and read nothing else — context exhaustion followed by
invention is the failure mode this spec is shaped to prevent:

{reading}
"""

DOD = """## Definition of done
`make verify` exits 0, the tool count is exactly as stated, the change is limited
to the files listed above, and the commit is `[{tid}] <title>` closing this issue.
"""


def body(tid, context, reading, deps, create, modify, steps, acceptance,
         guardrails, extra=""):
    dep_lines = "\n".join(f"- {d} (must be closed first)" for d in deps) or "- none"
    c = "\n".join(f"- `{f}`" for f in create) or "- (none)"
    m = "\n".join(f"- `{f}`" for f in modify) or "- (none)"
    acc = "\n".join(f"- [ ] {a}" for a in acceptance)
    steps_md = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
    g = "\n".join(f"- {x}" for x in guardrails)
    return f"""## Context
{context}

{READING_PREAMBLE.format(reading=reading)}
## Dependencies
{dep_lines}

## Files
Create:
{c}
Modify:
{m}
Do NOT touch anything else.

## Steps
{steps_md}
{extra}
## Acceptance
Runnable checks. The task is done only when all pass.
{acc}

## Out of scope / guardrails
{g}

{DOD.format(tid=tid)}"""


# --------------------------------------------------------------------------
# Shared reading blocks and guardrails
# --------------------------------------------------------------------------
PHASE = "neuvector-mcp-spec/phases"
PARTA = "neuvector-mcp-spec/tools/PART-A-inventory-vulnerability-compliance.md"
PARTB = "neuvector-mcp-spec/tools/PART-B-events-policy-read-iam-read.md"
PARTC = "neuvector-mcp-spec/tools/PART-C-policy-write-admission.md"
PARTD = "neuvector-mcp-spec/tools/PART-D-scanops-runtimeops-iam-system.md"
APPB = "neuvector-mcp-spec/appendix/B-schema-reference.md"
APPC = "neuvector-mcp-spec/appendix/C-error-taxonomy.md"
APPD = "neuvector-mcp-spec/appendix/D-api-conventions.md"

READ_GUARDS = [
    "Do not read any other PHASE-*.md file. Do not start the next ticket.",
    "Do not refactor, reformat or 'improve' any module that already passes the gate — "
    "every rewrite of passing code is a new chance to break it.",
    "Do not invent an endpoint, a JSON tag or a field name. If it is not in the "
    "appendices, stop and report BLOCKED with the exact thing you could not find.",
    "Do not edit `scripts/verify_spec.py`, `spec_endpoints.json`, `pyproject.toml` "
    "or anything under `neuvector-mcp-spec/`.",
]

READ_TOOL_GUARDS = READ_GUARDS + [
    "`models.py` is append-only — add new classes at the end in the order the Part "
    "file lists them; never redefine `Page`, `WorkloadBrief`, `SystemSummary`, "
    "`WriteOutcome`, `PolicyMode`, `Severity` or `_BASE`.",
    "Every list tool uses the over-fetch-by-one truncation pattern from SPEC.md 7.3. "
    "A list tool without it is a defect even if its tests pass.",
]

WRITE_TOOL_GUARDS = READ_GUARDS + [
    "`models.py` is append-only. Never edit `tests/test_guard.py` — it is verbatim "
    "from `reference/` and pins the handshake.",
    "Every mutating tool: build payload -> `authorise_write(...)` BEFORE any network "
    "call -> return the guard's `WriteOutcome` verbatim when it is not None -> only "
    "then call the controller. A request issued before the guard fails "
    "`test_*_preview_sends_nothing`, which asserts `route.call_count == 0`.",
    "`readOnlyHint=False`, exactly one toolset tag plus `\"write\"`, and "
    "`confirm: str | None = None` as the LAST argument. Return type `WriteOutcome`.",
]

TESTS_NOTE = (
    "Gate rule R8 matches the literal quoted tool name, so every tool name added "
    "here must appear as `\"nv_...\"` inside a test file. Coverage gates at 85% "
    "branch, so tests and tools must land in the same commit."
)

# --------------------------------------------------------------------------
# The queue
# --------------------------------------------------------------------------
T = []


def add(**kw):
    T.append(kw)


REF_FILES = [
    "pyproject.toml", "Makefile", "README.md", "spec_endpoints.json",
    "src/neuvector_mcp/__init__.py", "src/neuvector_mcp/config.py",
    "src/neuvector_mcp/errors.py", "src/neuvector_mcp/client.py",
    "src/neuvector_mcp/models.py", "src/neuvector_mcp/context.py",
    "src/neuvector_mcp/guard.py", "src/neuvector_mcp/audit.py",
    "src/neuvector_mcp/server.py", "src/neuvector_mcp/tools/__init__.py",
    "src/neuvector_mcp/tools/inventory.py", "src/neuvector_mcp/tools/policy_write.py",
    "tests/conftest.py", "tests/fixtures/system_summary.json",
    "tests/fixtures/workloads_v2.json", "tests/test_inventory.py",
    "tests/test_guard.py", "scripts/verify_spec.py", "scripts/smoke_stdio.py",
    "deploy/Dockerfile", "deploy/deployment.yaml", "deploy/fleet.yaml",
]

# ---- M0 -------------------------------------------------------------------
add(
    tid="T-001", milestone="M0", area="scaffold", assignee="agent", depends=[],
    title="Scaffold the repository from the tested reference core",
    create=REF_FILES, modify=[".gitignore"],
    context=(
        "Stand up the build tree by copying the already-written, already-tested core "
        "out of `neuvector-mcp-spec/reference/`. **No new logic is written in this "
        "ticket** — 11 tests and all 9 gate rules already pass on that code in a "
        "sandbox; re-deriving it introduces defects. Five of the 72 tools ship here."
    ),
    reading=(
        f"1. `SPEC.md` §0 (rules) and §4 (repository layout)\n"
        f"2. `{PHASE}/PHASE-0-scaffold.md`"
    ),
    steps=[
        "Create the tree exactly as PHASE-0 section 1 draws it.",
        "Copy every file from `neuvector-mcp-spec/reference/` to its matching path at "
        "the repository root — **verbatim**. No reformatting, no renaming, no cleanup. "
        "`reference/src/...` -> `src/...`, `reference/tests/...` -> `tests/...`, "
        "`reference/scripts/...` -> `scripts/...`, `reference/deploy/...` -> `deploy/...`, "
        "and `reference/pyproject.toml`, `reference/Makefile`, `reference/README.md`, "
        "`reference/spec_endpoints.json` to the root.",
        "Note that this replaces the root `README.md` (currently a copy of the spec "
        "package README) with the reference core README. The spec package keeps its own "
        "copy at `neuvector-mcp-spec/README.md`; T-034 writes the final user-facing one.",
        "Append `.venv/` and `__pycache__/` to `.gitignore`.",
        "Create the virtualenv and install: `python3 -m venv .venv` then "
        "`make install PY=.venv/bin/python`.",
        "Run the two gate commands and report their exact output.",
    ],
    acceptance=[
        "`python3 -m venv .venv`",
        "`make install PY=.venv/bin/python`",
        '`make test PY=.venv/bin/python | grep -q "11 passed"`',
        f"`{count_check(5)}`",
    ],
    guardrails=READ_GUARDS + [
        "Write no new logic. If a copied file needs a change to pass, the copy is "
        "incomplete — fix the copy, not the code.",
        "Do NOT change the pinned dependency versions in `pyproject.toml`. If a wheel "
        "is unavailable for the interpreter, report BLOCKED with the pip output.",
        "If `make spec` reports a tool count other than 5, a `register()` call is "
        "missing from `server.py` or a copy is incomplete.",
    ],
)

# ---- M1 -------------------------------------------------------------------
add(
    tid="T-002", milestone="M1", area="core", assignee="agent", depends=["T-001"],
    title="Pin configuration behaviour in tests/test_config.py",
    create=["tests/test_config.py"], modify=[],
    context=(
        "Add the test module that pins `config.py` behaviour so later phases cannot "
        "silently break it. **No production code changes.** If a test fails, the test "
        "is wrong — the reference core is the specification."
    ),
    reading=(
        f"1. `SPEC.md` §3, §5 and §7.2\n"
        f"2. `{PHASE}/PHASE-1-harden-core.md` — the `tests/test_config.py` table\n"
        f"3. `src/neuvector_mcp/config.py`"
    ),
    steps=[
        "Write all 14 tests named in the PHASE-1 `test_config.py` table, with exactly "
        "those function names: `test_defaults_are_read_only`, "
        "`test_controller_url_must_have_scheme`, "
        "`test_controller_url_trailing_slash_stripped`, "
        "`test_apikey_mode_requires_both_keys`, "
        "`test_password_mode_requires_username_and_password`, `test_file_indirection`, "
        "`test_direct_env_beats_file`, `test_unknown_toolset_rejected`, "
        "`test_read_only_conflicts_with_mutating_toolset`, "
        "`test_read_only_false_allows_mutating_toolset`, `test_bool_parsing`, "
        "`test_settings_are_frozen`, `test_redacted_hides_secrets`, "
        "`test_toolsets_split_is_read_or_write_never_both`.",
        "Use `monkeypatch.setenv` / `monkeypatch.delenv`. Never mutate `os.environ` "
        "directly — a leaked env var makes a later phase fail for no visible reason.",
        "Assert each row's stated outcome exactly, including that error messages name "
        "the offending value (`bogus`, `policy_write`).",
    ],
    acceptance=[
        "`.venv/bin/python -m pytest tests/test_config.py -q`",
        f"`{GATE}`",
        f"`{count_check(5)}`",
    ],
    guardrails=READ_GUARDS + [
        "No production code changes at all — `src/` is untouched by this ticket.",
    ],
)

add(
    tid="T-003", milestone="M1", area="core", assignee="agent", depends=["T-002"],
    title="Pin client build_query and authentication in tests/test_client.py",
    create=["tests/test_client.py"], modify=[],
    context=(
        "First half of the `client.py` contract: the pure `build_query` renderer and "
        "the two authentication modes. **No production code changes.**"
    ),
    reading=(
        f"1. `SPEC.md` §3 and §7.2\n"
        f"2. `{PHASE}/PHASE-1-harden-core.md` — `test_client.py`, the `build_query` and "
        f"`Auth` tables\n"
        f"3. `{APPD}` section D.2\n"
        f"4. `src/neuvector_mcp/client.py`"
    ),
    steps=[
        "Build the client directly rather than through the server: "
        "`settings = make_settings(**overrides)`; "
        "`http = NeuVectorClient.build_http_client(settings)`; "
        "`client = NeuVectorClient(settings, http)`. Close it in a fixture with "
        "`await http.aclose()`.",
        "Write the six `build_query` tests: `test_build_query_paging`, "
        "`test_build_query_implicit_eq`, `test_build_query_explicit_operator`, "
        "`test_build_query_rejects_unknown_operator`, `test_build_query_sort`, "
        "`test_build_query_extra_booleans_lowercased`.",
        "Write the five auth tests: `test_apikey_header_format`, "
        "`test_apikey_login_probes_summary`, "
        "`test_password_login_posts_auth_and_caches_token`, "
        "`test_password_login_without_token_raises_auth_error`, "
        "`test_logout_deletes_auth_in_password_mode`.",
        "Assert the exact header names and the exact `POST /v1/auth` body shape "
        "`{\"password\": {\"username\": ..., \"password\": ...}}` — an unknown query "
        "operator degrades to `eq` on the controller and returns wrong data silently, "
        "which is why `test_build_query_rejects_unknown_operator` must raise.",
    ],
    acceptance=[
        "`.venv/bin/python -m pytest tests/test_client.py -q`",
        f"`{GATE}`",
        f"`{count_check(5)}`",
    ],
    guardrails=READ_GUARDS + [
        "No production code changes at all.",
        "Leave retry, re-login and envelope tests to T-004 — do not write them here.",
    ],
)

add(
    tid="T-004", milestone="M1", area="core", assignee="agent", depends=["T-003"],
    title="Pin client retry, re-login, envelopes and error classification",
    create=[], modify=["tests/test_client.py"],
    context=(
        "Second half of the `client.py` contract: transient retry, the single re-login "
        "on 401, envelope unwrapping and error classification. **No production code "
        "changes.** This closes M1."
    ),
    reading=(
        f"1. `SPEC.md` §3 and §7.2\n"
        f"2. `{PHASE}/PHASE-1-harden-core.md` — the `Retry and re-login` and "
        f"`Envelopes and errors` tables\n"
        f"3. `{APPC}`\n"
        f"4. `{APPD}` section D.4"
    ),
    steps=[
        "Append the seven retry / re-login tests: `test_retries_transient_status`, "
        "`test_retries_transient_code`, `test_does_not_retry_permanent_code`, "
        "`test_gives_up_after_three_attempts`, "
        "`test_relogin_once_on_401_password_mode`, `test_no_relogin_loop`, "
        "`test_no_relogin_in_apikey_mode`.",
        "Patch the sleep so retry tests do not actually wait: "
        "`monkeypatch.setattr(\"neuvector_mcp.client.asyncio.sleep\", ...)`.",
        "Append the seven envelope / error tests: `test_empty_body_is_success`, "
        "`test_get_list_unwraps_envelope`, `test_get_list_missing_key_returns_empty`, "
        "`test_get_object_unwraps_envelope`, `test_non_json_body_is_classified`, "
        "`test_classify_prefers_code_over_status`, "
        "`test_error_message_includes_code_and_controller_text`.",
        "Assert exact call counts, not 'at least'. `test_does_not_retry_permanent_code` "
        "must assert exactly 1 call; `test_gives_up_after_three_attempts` exactly 3.",
        "Report the full `make verify` output including the coverage figure — it must "
        "be at or above 85%.",
    ],
    acceptance=[
        "`.venv/bin/python -m pytest tests/test_client.py -q`",
        f"`{GATE}`",
        f"`{count_check(5)}`",
    ],
    guardrails=READ_GUARDS + [
        "No production code changes at all.",
    ],
)


# ---- read-tool ticket helper ---------------------------------------------
def read_tools_ticket(tid, milestone, area, depends, title, tools, count,
                      part, part_section, module, testfile, fixtures,
                      new_module, context, hard, extra_reading="", extra_guards=()):
    tool_list = "\n".join(f"   - `{n}` — `{ep}`" for n, ep in tools)
    create, modify = [], ["src/neuvector_mcp/models.py"]
    (create if new_module else modify).append(module)
    (create if new_module else modify).append(testfile)
    if new_module:
        modify.append("src/neuvector_mcp/server.py")
    create += [f"tests/fixtures/{f}" for f in fixtures]
    steps = [
        "Append the new output models to the end of `models.py`, in the order the Part "
        "file lists them. Nothing above them changes.",
        "Write the fixtures named above. Every field name comes from "
        f"`{APPB}` — do not invent one. Every list fixture must hold more items than "
        "the smallest `limit` its test uses, so the over-fetch-by-one truncation path "
        "is actually exercised.",
        ("Create " if new_module else "Extend ") + f"`{module}` with these tools, each "
        "one exactly as the Part file specifies its arguments, query mapping, verbatim "
        "docstring, output model `from_api()` and envelope key:\n" + tool_list,
    ]
    if new_module:
        steps.append("Register the module in `server.py`'s `TOOL_MODULES` list.")
    steps += [
        f"{'Create' if new_module else 'Extend'} `{testfile}` with the test functions "
        f"the Part file names per tool. {TESTS_NOTE}",
        "Run the gate and report the exact tool count from `make spec`.",
    ]
    reading = (
        f"1. `SPEC.md` §3, §7.3, §7.5, §7.6, §12\n"
        f"2. `{PHASE}/{milestone_phase(milestone)}`\n"
        f"3. `{part}` — section {part_section}\n"
        f"4. `{APPB}` for every field you touch{extra_reading}"
    )
    add(tid=tid, milestone=milestone, area=area, assignee="agent", depends=depends,
        title=title, create=create, modify=modify, context=context, reading=reading,
        steps=steps,
        acceptance=[f"`{GATE}`", f"`{count_check(count)}`"],
        guardrails=list(READ_TOOL_GUARDS) + list(extra_guards),
        extra=("\n## The hard part\n" + hard + "\n") if hard else "")


PHASE_FILES = {
    "M0": "PHASE-0-scaffold.md", "M1": "PHASE-1-harden-core.md",
    "M2": "PHASE-2-inventory.md", "M3": "PHASE-3-vulnerability.md",
    "M4": "PHASE-4-compliance.md", "M5": "PHASE-5-events.md",
    "M6": "PHASE-6-policy-read.md", "M7": "PHASE-7-policy-write.md",
    "M8": "PHASE-8-admission.md", "M9": "PHASE-9-scan-runtime-ops.md",
    "M10": "PHASE-10-iam-system.md", "M11": "PHASE-11-package-deploy.md",
}


def milestone_phase(m):
    return PHASE_FILES[m]


# ---- M2 inventory ---------------------------------------------------------
read_tools_ticket(
    "T-005", "M2", "inventory", ["T-004"],
    "inventory: nv_whoami, nv_list_hosts, nv_list_groups, nv_get_group",
    [("nv_whoami", "GET /v1/selfuser (undocumented, gated)"),
     ("nv_list_hosts", "GET /v1/host"),
     ("nv_list_groups", "GET /v1/group"),
     ("nv_get_group", "GET /v1/group/{name}")],
    9, PARTA, "**A.0** (module preamble) and the first four tools of the "
    "**`Toolset inventory`** section",
    "src/neuvector_mcp/tools/inventory.py", "tests/test_inventory.py",
    ["selfuser.json", "hosts.json", "groups.json", "group_detail.json"],
    new_module=False,
    context=(
        "First four of the eight new `inventory` tools. `tools/inventory.py` already "
        "holds `nv_get_system_summary`, `nv_list_workloads` and `nv_get_workload` from "
        "T-001 — **do not touch them**; add after them inside the existing "
        "`register(mcp, settings)`."
    ),
    extra_reading=f"\n5. `{APPD}` sections D.2 and D.3",
    hard=(
        "`nv_whoami` runs on an **undocumented** route. It must check "
        "`app.settings.allow_undocumented` and, when that is false, degrade to the "
        "cached `AppContext.identity` rather than calling the controller. Its `Calls` "
        "line is already in `UNDOCUMENTED_ALLOWLIST` in `scripts/verify_spec.py` — do "
        "not edit that list.\n\n"
        "`nv_list_groups` and `nv_get_group` return **different** models: a list entry "
        "is a brief, the detail carries criteria. Do not collapse them into one model."
    ),
    extra_guards=["`tools/inventory.py` imports nothing from another `tools/*` module."],
)

read_tools_ticket(
    "T-006", "M2", "inventory", ["T-005"],
    "inventory: nv_list_services, nv_list_enforcers, nv_list_namespaces, nv_get_network_conversations",
    [("nv_list_services", "GET /v1/service"),
     ("nv_list_enforcers", "GET /v1/enforcer"),
     ("nv_list_namespaces", "GET /v1/domain"),
     ("nv_get_network_conversations", "GET /v1/conversation (undocumented, gated)")],
    13, PARTA, "**A.0** and the last four tools of the **`Toolset inventory`** section",
    "src/neuvector_mcp/tools/inventory.py", "tests/test_inventory.py",
    ["services.json", "enforcers.json", "domains.json", "conversations.json"],
    new_module=False,
    context=(
        "The remaining four `inventory` tools. This closes M2 at 13 tools — the "
        "`inventory` toolset is complete after this ticket."
    ),
    extra_reading=f"\n5. `{APPD}` sections D.2 and D.3",
    hard=(
        "`nv_get_network_conversations` runs on an **undocumented** route and, unlike "
        "`nv_whoami`, has no safe degradation: when `app.settings.allow_undocumented` "
        "is false it must raise `GuardError`. Its `Calls` line is already in "
        "`UNDOCUMENTED_ALLOWLIST` — do not edit that list.\n\n"
        "`tests/fixtures/conversations.json` is marked *normative* in Part A: the "
        "envelope key is unverifiable upstream, so the fixture defines the shape. "
        "Leave the Part A note about confirming it against a live controller as a code "
        "comment."
    ),
    extra_guards=["`tools/inventory.py` imports nothing from another `tools/*` module."],
)

# ---- M3 vulnerability -----------------------------------------------------
read_tools_ticket(
    "T-007", "M3", "vulnerability", ["T-006"],
    "vulnerability module: nv_list_image_scan_summaries, nv_get_scan_status, nv_list_scanners",
    [("nv_list_image_scan_summaries", "GET /v1/scan/image"),
     ("nv_get_scan_status", "GET /v1/scan/status"),
     ("nv_list_scanners", "GET /v1/scan/scanner")],
    16, PARTA, "**A.0** and the `nv_list_image_scan_summaries`, `nv_get_scan_status` "
    "and `nv_list_scanners` entries of the **`Toolset vulnerability`** section",
    "src/neuvector_mcp/tools/vulnerability.py", "tests/test_vulnerability.py",
    ["scan_image_summaries.json", "scan_status.json", "scanners.json"],
    new_module=True,
    context=(
        "Stand up the `vulnerability` toolset module with its three simplest tools, so "
        "the module, its registration and its test file exist before the harder "
        "registry and scan-report tools land."
    ),
    extra_reading=f"\n5. `{APPD}` sections D.7 and D.8",
    hard=(
        "`tests/fixtures/scanners.json` is *convention-derived* and therefore normative "
        "— Appendix B does not pin the envelope key for `GET /v1/scan/scanner`. Use the "
        "key Part A states and leave its note as a code comment."
    ),
)

read_tools_ticket(
    "T-008", "M3", "vulnerability", ["T-007"],
    "vulnerability: nv_list_registries, nv_list_registry_images, nv_get_vulnerability_profile",
    [("nv_list_registries", "GET /v1/scan/registry"),
     ("nv_list_registry_images", "GET /v1/scan/registry/{name}/images"),
     ("nv_get_vulnerability_profile", "GET /v1/vulnerability/profile/{name}")],
    19, PARTA, "**A.0** and the `nv_list_registries`, `nv_list_registry_images` and "
    "`nv_get_vulnerability_profile` entries of the **`Toolset vulnerability`** section",
    "src/neuvector_mcp/tools/vulnerability.py", "tests/test_vulnerability.py",
    ["registries.json", "registry_images.json", "vulnerability_profile.json"],
    new_module=False,
    context="The registry-facing read tools plus the vulnerability profile getter.",
    extra_reading=f"\n5. `{APPD}` sections D.7 and D.8",
    hard=(
        "`GET /v1/scan/registry` uses envelope key **`summarys`** — upstream's "
        "misspelling, not a typo in this spec. Confirm it in Appendix B before writing "
        "it. Getting an envelope key wrong returns an empty list **silently**, which is "
        "the worst failure mode in this project.\n\n"
        "Registry summaries carry credentials. Put a `password` and an `auth_token` "
        "value in `registries.json` and assert they do **not** appear in the projected "
        "result — `test_list_registries_uses_summarys_envelope` plus the credential "
        "assertion Part A names.\n\n"
        "`nv_list_registries` and `nv_list_groups` both accept `scope`: reuse the same "
        "argument shape and the same description wording."
    ),
)

read_tools_ticket(
    "T-009", "M3", "vulnerability", ["T-008"],
    "vulnerability: nv_get_scan_report with client-side severity filter and cap",
    [("nv_get_scan_report", "GET /v1/scan/image/{id}, GET /v1/scan/workload/{id}, "
      "GET /v1/scan/host/{id}, GET /v1/scan/registry/{name}/image/{id}")],
    20, PARTA, "**A.0** and the `nv_get_scan_report` entry of the "
    "**`Toolset vulnerability`** section",
    "src/neuvector_mcp/tools/vulnerability.py", "tests/test_vulnerability.py",
    ["scan_report.json"],
    new_module=False,
    context=(
        "One tool, on its own ticket, because it is the single most likely tool in the "
        "server to blow a client's context window. This closes M3 at 20 tools."
    ),
    extra_reading=f"\n5. `{APPD}` sections D.7 and D.8",
    hard=(
        "A scan report on a large base image carries thousands of CVE entries and the "
        "controller does **not** paginate inside a report (D.8). Implement all four "
        "parts of the mechanism Part A prescribes:\n\n"
        "1. a summary-counts-only mode that returns severity totals and no entries;\n"
        "2. severity filtering applied **client-side**, after the fetch;\n"
        "3. a `max_vulnerabilities` cap applied **after** sorting by severity, so the "
        "most serious findings survive truncation;\n"
        "4. `truncated=True` plus a hint naming what was dropped and how to narrow.\n\n"
        "A report tool that returns every entry unfiltered is a defect even when its "
        "test passes.\n\n"
        "One tool over four endpoints, discriminated by `target`. Validate the argument "
        "combination locally **before any call**: `target=\"registry_image\"` requires "
        "`registry_name`, the others require only `target_id`. Raise `ValidationError_` "
        "naming the missing argument. Use `settings.long_request_timeout_s` for the "
        "fetch (D.7).\n\n"
        "Required tests: `test_get_scan_report_summary_only_omits_entries`, "
        "`test_get_scan_report_severity_filter_applied_client_side`, "
        "`test_get_scan_report_cap_keeps_highest_severity_first`, "
        "`test_get_scan_report_registry_target_requires_registry_name`. Build "
        "`scan_report.json` with at least 12 vulnerability entries spanning "
        "Critical/High/Medium/Low so the cap and the sort are actually exercised."
    ),
)

# ---- M4 compliance --------------------------------------------------------
read_tools_ticket(
    "T-010", "M4", "compliance", ["T-009"],
    "compliance module: nv_list_compliance_profiles, nv_get_compliance_profile",
    [("nv_list_compliance_profiles", "GET /v1/compliance/profile"),
     ("nv_get_compliance_profile", "GET /v1/compliance/profile/{name}")],
    22, PARTA, "**A.0** and the two compliance-profile entries of the "
    "**`Toolset compliance`** section",
    "src/neuvector_mcp/tools/compliance.py", "tests/test_compliance.py",
    ["compliance_profiles.json", "compliance_profile.json"],
    new_module=True,
    context=(
        "Stand up the `compliance` toolset module with the two profile tools, ahead of "
        "the two large multi-endpoint report tools in T-011."
    ),
    extra_reading=f"\n5. `{APPD}` sections D.3 and D.7",
    hard=(
        "`tests/fixtures/compliance_profile.json` is *convention-derived*: the envelope "
        "key is best-effort, so the fixture pins it. Leave Part A's note as a code "
        "comment so a later operator knows to confirm it against a live controller."
    ),
)

read_tools_ticket(
    "T-011", "M4", "compliance", ["T-010"],
    "compliance: nv_get_compliance_findings and nv_get_bench_report",
    [("nv_get_compliance_findings", "GET /v1/workload/{id}/compliance, "
      "GET /v1/host/{id}/compliance"),
     ("nv_get_bench_report", "GET /v1/bench/host/{id}/kubernetes, "
      "GET /v1/bench/host/{id}/docker")],
    24, PARTA, "**A.0** and the `nv_get_compliance_findings` and `nv_get_bench_report` "
    "entries of the **`Toolset compliance`** section",
    "src/neuvector_mcp/tools/compliance.py", "tests/test_compliance.py",
    ["compliance_workload.json", "compliance_host.json", "bench_kubernetes.json",
     "bench_docker.json"],
    new_module=False,
    context="The two multi-endpoint compliance report tools. This closes M4 at 24 tools.",
    extra_reading=f"\n5. `{APPD}` sections D.3 and D.7",
    hard=(
        "**Unwrapped responses.** `RESTComplianceData` and `RESTBenchReport` come back "
        "without an envelope on some paths. Use the defensive "
        "`raw.get(\"<key>\") or raw` pattern Part A prescribes and say so in a comment. "
        "Do not guess a key. All four fixtures here are unwrapped — the body *is* the "
        "object.\n\n"
        "Both tools are discriminated by an argument (`scope`, `benchmark`). Validate "
        "locally and raise `ValidationError_` naming the bad value **before any network "
        "call** — `test_bench_report_invalid_benchmark_rejected_before_request` asserts "
        "`route.call_count == 0`.\n\n"
        "Bench reports are large and slow: use `settings.long_request_timeout_s` plus "
        "the same client-side cap and truncation reporting as `nv_get_scan_report`.\n\n"
        "Compliance findings **default to failures only** — a caller asking about "
        "compliance wants what is wrong. Return counts by level plus the failing "
        "checks, and offer a filter to include passing checks.\n\n"
        "Required tests: "
        "`test_compliance_findings_scope_workload_and_host_hit_different_paths`, "
        "`test_compliance_findings_defaults_to_failures_only`, "
        "`test_bench_report_benchmark_argument_selects_path`, "
        "`test_bench_report_invalid_benchmark_rejected_before_request`, "
        "`test_unwrapped_body_projects_correctly`."
    ),
)

# ---- M5 events ------------------------------------------------------------
read_tools_ticket(
    "T-012", "M5", "events", ["T-011"],
    "events module: nv_query_security_events and nv_get_threat_detail",
    [("nv_query_security_events", "GET /v1/log/threat, GET /v1/log/violation, "
      "GET /v1/log/incident"),
     ("nv_get_threat_detail", "GET /v1/log/threat/{id}")],
    26, PARTB, "**B.0** and the `nv_query_security_events` and `nv_get_threat_detail` "
    "entries of the **`Toolset events`** section",
    "src/neuvector_mcp/tools/events.py", "tests/test_events.py",
    ["log_threat.json", "log_violation.json", "log_incident.json",
     "log_threat_detail.json"],
    new_module=True,
    context=(
        "Stand up the `events` toolset module with the security-event query tool and "
        "the threat detail getter — the two tools that carry this phase's traps."
    ),
    extra_reading=f"\n5. `{APPD}` section D.2\n6. `SPEC.md` §11",
    hard=(
        "**The filter field names differ per event kind.** The three security-event "
        "kinds use different JSON tags for the same concept:\n\n"
        "- namespace: `client_workload_domain` (threat) vs `client_domain` (violation) "
        "vs `workload_domain` (incident)\n"
        "- severity: `severity` (threat) vs `level` (violation and incident)\n\n"
        "Reproduce Part B's authoritative mapping table as a module-level constant so "
        "the tool body cannot get it wrong, and verify every tag against Appendix B "
        "first. A wrong tag produces an empty result set with **no error**, which reads "
        "as \"no threats\" — the most dangerous silent failure in a security tool.\n\n"
        "`build_query` renders one value per field, so a two-sided time window cannot "
        "be expressed server-side. Filter one side server-side, trim the other "
        "client-side, and report how many entries were dropped "
        "(`dropped_outside_window`).\n\n"
        "Threat **list** responses have the packet payload stripped by the controller; "
        "`GET /v1/log/threat/{id}` includes it. `nv_get_threat_detail` must withhold "
        "the packet unless explicitly requested and clip it to "
        "`settings.max_response_chars // 2`.\n\n"
        "Default sort is newest first. Each of the three list fixtures holds 3 items so "
        "a `limit=2` call proves the over-fetch and `truncated=True`.\n\n"
        "Required tests: `test_query_threats_projects_and_pages`, "
        "`test_query_violations_uses_level_and_client_domain`, "
        "`test_query_incidents_uses_workload_domain`, "
        "`test_side_server_switches_filter_field`, "
        "`test_both_time_bounds_send_gte_and_trim_client_side`, "
        "`test_threat_detail_omits_packet_by_default`, "
        "`test_threat_detail_packet_is_clipped_when_requested`."
    ),
)

read_tools_ticket(
    "T-013", "M5", "events", ["T-012"],
    "events: nv_query_audit_events, nv_query_system_events, nv_get_system_alerts",
    [("nv_query_audit_events", "GET /v1/log/audit"),
     ("nv_query_system_events", "GET /v1/log/event"),
     ("nv_get_system_alerts", "GET /v1/system/alerts")],
    29, PARTB, "**B.0** and the `nv_query_audit_events`, `nv_query_system_events` and "
    "`nv_get_system_alerts` entries of the **`Toolset events`** section",
    "src/neuvector_mcp/tools/events.py", "tests/test_events.py",
    ["log_audit.json", "log_event.json", "system_alerts.json"],
    new_module=False,
    context="The remaining three `events` tools. This closes M5 at 29 tools.",
    extra_reading=f"\n5. `{APPD}` section D.2\n6. `SPEC.md` §11",
    hard=(
        "**`Event.rest_body` is never projected.** It records request bodies, which can "
        "contain passwords and tokens other clients sent to the controller. This is a "
        "hard rule, not a preference. Plant a password inside `rest_body` in "
        "`log_event.json` and assert it is absent from the serialised result — "
        "`test_system_events_never_project_rest_body`.\n\n"
        "`system_alerts.json`'s envelope key is *inferred* — leave Part B's note as a "
        "code comment.\n\n"
        "Other required tests: `test_query_audit_events_query_and_projection`, "
        "`test_query_system_events_filters_by_user`, "
        "`test_system_alerts_reads_alerts_key`."
    ),
)

# ---- M6 policy_read -------------------------------------------------------
read_tools_ticket(
    "T-014", "M6", "policy-read", ["T-013"],
    "policy_read module: network rules and the process / file-monitor profiles",
    [("nv_list_network_rules", "GET /v1/policy/rule"),
     ("nv_get_network_rule", "GET /v1/policy/rule/{id}"),
     ("nv_get_process_profile", "GET /v1/process_profile/{name}"),
     ("nv_get_file_monitor_profile", "GET /v1/file_monitor/{name}")],
    33, PARTB, "**B.0** and the `nv_list_network_rules`, `nv_get_network_rule`, "
    "`nv_get_process_profile` and `nv_get_file_monitor_profile` entries of the "
    "**`Toolset policy_read`** section",
    "src/neuvector_mcp/tools/policy_read.py", "tests/test_policy_read.py",
    ["policy_rules.json", "policy_rule.json", "process_profile.json",
     "file_monitor_profile.json"],
    new_module=True,
    context=(
        "Stand up the `policy_read` toolset module with the four tools M7's write "
        "counterparts depend on. A caller must be able to reason about rule precedence "
        "from these projections before `nv_apply_network_rule_changes` exists."
    ),
    extra_reading=f"\n5. `{APPC}`",
    hard=(
        "**Rule ordering is semantic.** Network rules are evaluated in list order, and "
        "id ranges distinguish learned, user-created and federated rules — Part B gives "
        "the ranges. The projection must expose enough for a caller to reason about "
        "precedence, and the docstring must explain it, because M7's "
        "`nv_apply_network_rule_changes` depends on the caller understanding it. "
        "`test_network_rule_projection_preserves_order` pins this.\n\n"
        "Rules that cannot be modified return **code 46** on write attempts. Say so in "
        "`nv_list_network_rules`' docstring so a caller learns it before M7.\n\n"
        "`RESTFileMonitorFile` is absent from Appendix B — Part B marks it "
        "`BLOCKED (schema)` and gives a defensive projection with an `envelope_keys` "
        "diagnostic field. Implement it as written and leave the `BLOCKED` note as a "
        "code comment. `file_monitor_profile.json`'s envelope key is inferred.\n\n"
        "Required tests include `test_list_network_rules_scope_parameter`, "
        "`test_network_rule_projection_preserves_order`, "
        "`test_get_network_rule_projects`, `test_get_process_profile_projects_entries`."
    ),
)

read_tools_ticket(
    "T-015", "M6", "policy-read", ["T-014"],
    "policy_read: nv_list_response_rules, nv_list_dlp_sensors, nv_list_waf_sensors",
    [("nv_list_response_rules", "GET /v1/response/rule"),
     ("nv_list_dlp_sensors", "GET /v1/dlp/sensor"),
     ("nv_list_waf_sensors", "GET /v1/waf/sensor")],
    36, PARTB, "**B.0** and the `nv_list_response_rules`, `nv_list_dlp_sensors` and "
    "`nv_list_waf_sensors` entries of the **`Toolset policy_read`** section",
    "src/neuvector_mcp/tools/policy_read.py", "tests/test_policy_read.py",
    ["response_rules.json", "dlp_sensors.json", "waf_sensors.json"],
    new_module=False,
    context="The response-rule and sensor listing tools.",
    extra_reading=f"\n5. `{APPC}`",
    hard=(
        "**`scope` is documented on `/v1/waf/sensor` but NOT on `/v1/dlp/sensor`.** Do "
        "not add a `scope` argument to `nv_list_dlp_sensors`. Part B records this "
        "asymmetry; it is upstream's, not a mistake. "
        "`test_list_dlp_sensors_has_no_scope_argument` introspects the tool schema to "
        "prove it.\n\n"
        "`RESTDlpSensor` and `RESTWafSensor` are absent from Appendix B — Part B marks "
        "both `BLOCKED (schema)` and gives defensive projections with an "
        "`envelope_keys` diagnostic field. Implement them as written and leave the "
        "`BLOCKED` notes as code comments. Both sensor fixtures' envelope keys are "
        "inferred.\n\n"
        "Required tests include `test_list_dlp_sensors_projects_names` and "
        "`test_list_dlp_sensors_has_no_scope_argument`."
    ),
)

read_tools_ticket(
    "T-016", "M6", "policy-read", ["T-015"],
    "policy_read: nv_get_admission_state, nv_list_admission_rules, nv_assess_admission_rule",
    [("nv_get_admission_state", "GET /v1/admission/state"),
     ("nv_list_admission_rules", "GET /v1/admission/rules"),
     ("nv_assess_admission_rule", "POST /v1/assess/admission/rule")],
    39, PARTB, "**B.0** and the `nv_get_admission_state`, `nv_list_admission_rules` and "
    "`nv_assess_admission_rule` entries of the **`Toolset policy_read`** section",
    "src/neuvector_mcp/tools/policy_read.py", "tests/test_policy_read.py",
    ["admission_state.json", "admission_rules.json", "admission_assessment.json"],
    new_module=False,
    context=(
        "The admission-control read surface, including the dry-run assessor. This "
        "closes M6 at 39 tools."
    ),
    extra_reading=f"\n5. `{APPC}`",
    hard=(
        "**Why a POST lives in a read toolset.** `nv_assess_admission_rule` evaluates a "
        "candidate admission rule against the cluster's current objects and reports "
        "what *would* match. It changes nothing. It is therefore tagged `policy_read` "
        "with `readOnlyHint=True` and takes **no** `confirm` argument — gate rule R5 "
        "forbids one on a read tool. Two tests pin this: "
        "`test_assess_admission_rule_has_no_confirm_argument` and "
        "`test_assess_admission_rule_is_read_only_hint`.\n\n"
        "Operationally this is the tool a caller must run **before** "
        "`nv_set_admission_state` in M8. Say so in its docstring.\n\n"
        "`RESTNvAlerts` and the assessment result types are partly absent from Appendix "
        "B — follow Part B's defensive projections and keep the `BLOCKED` notes as "
        "comments. `admission_state.json` and `admission_assessment.json` have **no** "
        "envelope: their top-level keys are the payload."
    ),
)


# ---- write-tool ticket helper --------------------------------------------
def write_tools_ticket(tid, milestone, area, depends, title, tools, count,
                       part, part_section, module, testfile, fixtures,
                       new_module, context, hard, extra_reading="",
                       extra_guards=(), models=True):
    tool_list = "\n".join(f"   - `{n}` — `{ep}` — `destructiveHint={d}`"
                          for n, ep, d in tools)
    create, modify = [], (["src/neuvector_mcp/models.py"] if models else [])
    (create if new_module else modify).append(module)
    (create if new_module else modify).append(testfile)
    if new_module:
        modify.append("src/neuvector_mcp/server.py")
    create += [f"tests/fixtures/{f}" for f in fixtures]
    steps = []
    if models:
        steps.append(
            "Append the input models Part C/D specifies to the end of `models.py`, in "
            "the order the Part file lists them. Nothing above them changes.")
    if fixtures:
        steps.append(
            "Write the fixtures named above; every field name comes from "
            f"`{APPB}`. Most write endpoints return an empty body — stub those routes "
            "with `json={}` rather than inventing a fixture.")
    steps.append(
        ("Create " if new_module else "Extend ") + f"`{module}` with these tools, each "
        "one following the five-step mutating-tool body from SPEC.md 7.4 exactly:\n"
        + tool_list)
    if new_module:
        steps.append("Register the module in `server.py`'s `TOOL_MODULES` list.")
    steps += [
        f"{'Create' if new_module else 'Extend'} `{testfile}` with, at minimum per "
        "tool, `test_<tool>_preview_sends_nothing` (asserting "
        "`route.call_count == 0`) and `test_<tool>_confirmed_applies` (asserting the "
        f"**exact** JSON body and `call_count == 1`). {TESTS_NOTE}",
        "Run the gate and report the exact tool count from `make spec`.",
    ]
    reading = (
        f"1. `SPEC.md` §6 (safety model), §7.4 (the five-step body), §12 (gate rules)\n"
        f"2. `{PHASE}/{milestone_phase(milestone)}`\n"
        f"3. `{part}` — section {part_section}\n"
        f"4. `{APPB}` and `{APPC}`\n"
        f"5. `tests/test_guard.py` — the tests that already pin the handshake{extra_reading}"
    )
    add(tid=tid, milestone=milestone, area=area, assignee="agent", depends=depends,
        title=title, create=create, modify=modify, context=context, reading=reading,
        steps=steps,
        acceptance=[f"`{GATE}`", f"`{count_check(count)}`"],
        guardrails=list(WRITE_TOOL_GUARDS) + list(extra_guards),
        extra=("\n## The hard part\n" + hard + "\n") if hard else "")


# ---- M7 policy_write ------------------------------------------------------
write_tools_ticket(
    "T-017", "M7", "policy-write", ["T-016"],
    "policy_write: nv_create_group and nv_update_group_criteria",
    [("nv_create_group", "POST /v1/group", "False"),
     ("nv_update_group_criteria", "PATCH /v1/group/{name}", "True")],
    41, PARTC, "**C.0.0** through **C.0.6** and the `nv_create_group` and "
    "`nv_update_group_criteria` entries of the **`Toolset policy_write`** section",
    "src/neuvector_mcp/tools/policy_write.py", "tests/test_policy_write.py", [],
    new_module=False,
    context=(
        "**This is the first milestone that can break a production cluster.** "
        "`tools/policy_write.py` already holds `nv_set_group_policy_mode` and "
        "`nv_delete_group` from T-001 — **do not touch them**. Add the two group "
        "mutation tools after them, and create the new `tests/test_policy_write.py`."
    ),
    hard=(
        "Add the preview/apply pair for `nv_delete_group` that `tests/test_guard.py` "
        "does not give it — Part C section C.9 lists it under this file.\n\n"
        "Document these controller error codes in the docstrings where relevant "
        "(Appendix C): **4** deleting or renaming a learned group (`nv.*`), **13** "
        "duplicate group name, **16** group is in use by a rule.\n\n"
        "Also add `test_read_only_hides_policy_write_tools` once for the module."
    ),
)

write_tools_ticket(
    "T-018", "M7", "policy-write", ["T-017"],
    "policy_write: nv_apply_network_rule_changes and nv_delete_network_rule",
    [("nv_apply_network_rule_changes", "PATCH /v1/policy/rule", "True"),
     ("nv_delete_network_rule", "DELETE /v1/policy/rule/{id}", "True")],
    43, PARTC, "**C.0.0** through **C.0.6** and the `nv_apply_network_rule_changes` and "
    "`nv_delete_network_rule` entries of the **`Toolset policy_write`** section",
    "src/neuvector_mcp/tools/policy_write.py", "tests/test_policy_write.py", [],
    new_module=False,
    context=(
        "`nv_apply_network_rule_changes` is the highest-risk tool in the server: a "
        "malformed batch drops production traffic. It gets its own ticket with "
        "`nv_delete_network_rule`, which shares its error taxonomy."
    ),
    hard=(
        "Implement everything Part C prescribes for `nv_apply_network_rule_changes`:\n\n"
        "- the exact `RESTPolicyRuleActionData` body shape;\n"
        "- a **hard cap** on batch size;\n"
        "- an `effect` string that enumerates **every** rule change as a diff, one line "
        "per rule, so a human reading the preview sees exactly what will happen;\n"
        "- `id` mandatory on every configure entry;\n"
        "- the `scope` query parameter folded into the guard's `target`, because the "
        "confirm token cannot bind query parameters. This is why "
        "`test_apply_network_rule_changes_token_is_bound_to_scope` is required.\n\n"
        "`after` positioning semantics on insert and move are marked **BLOCKED** in "
        "Part C: pass the caller's value through **verbatim** and never synthesise one.\n\n"
        "Error codes to document (Appendix C): **7** rule id does not exist, **46** "
        "federated or learned rules cannot be modified. Add an error-classification "
        "test for code 46."
    ),
)

write_tools_ticket(
    "T-019", "M7", "policy-write", ["T-018"],
    "policy_write: nv_update_process_profile and nv_update_file_monitor_profile",
    [("nv_update_process_profile", "PATCH /v1/process_profile/{name}", "True"),
     ("nv_update_file_monitor_profile", "PATCH /v1/file_monitor/{name}", "True")],
    45, PARTC, "**C.0.0** through **C.0.6** and the `nv_update_process_profile` and "
    "`nv_update_file_monitor_profile` entries of the **`Toolset policy_write`** section",
    "src/neuvector_mcp/tools/policy_write.py", "tests/test_policy_write.py", [],
    new_module=False,
    context="The two profile mutation tools. This closes M7 at 45 tools.",
    hard=(
        "**In `Protect` mode a wrong process-profile entry terminates a running "
        "process.** State that in the docstring in those words. The `effect` string "
        "must name every entry being added or removed, not just a count.\n\n"
        "`RESTProcessProfileConfigData`'s envelope key is **`process_profile_config`**, "
        "not `config`. Confirm it in Appendix B before writing it.\n\n"
        "Error code **7** (profile id does not exist) belongs in both docstrings."
    ),
)

# ---- M8 admission ---------------------------------------------------------
write_tools_ticket(
    "T-020", "M8", "admission", ["T-019"],
    "admission module: create, update and delete admission rules",
    [("nv_create_admission_rule", "POST /v1/admission/rule", "True"),
     ("nv_update_admission_rule", "PATCH /v1/admission/rule", "True"),
     ("nv_delete_admission_rule", "DELETE /v1/admission/rule/{id}", "True")],
    48, PARTC, "**C.0.0**, **C.0.3**, **C.0.5** and the three rule entries of the "
    "**`Toolset admission`** section",
    "src/neuvector_mcp/tools/admission.py", "tests/test_admission.py",
    ["admission_rule_created.json"],
    new_module=True,
    context=(
        "Stand up the `admission` toolset module with its three rule-CRUD tools. "
        "`nv_set_admission_state` — the widest blast radius in the server — is held "
        "back to T-021."
    ),
    hard=(
        "**`PATCH /v1/admission/rule` has NO `{id}` path segment.** The rule id travels "
        "in the body as `config.id`. Verify against Appendix A before writing it; "
        "`test_admission_rule_patch_has_no_id_in_path` pins it.\n\n"
        "`nv_create_admission_rule` is `destructiveHint=True` even though it creates "
        "rather than deletes, because a new deny rule affects traffic immediately. "
        "Part C section C.0.3 states the justification — keep it in a comment.\n\n"
        "`admission_rule_created.json` uses envelope key **`rule`**.\n\n"
        "Error codes (Appendix C): **7** rule id does not exist; **31, 32, 33, 34, 35** "
        "Kubernetes RBAC or webhook misconfiguration — surface the controller's message "
        "verbatim, these are cluster problems, not caller errors.\n\n"
        "Also add `test_admission_tools_hidden_when_read_only`."
    ),
)

write_tools_ticket(
    "T-021", "M8", "admission", ["T-020"],
    "admission: nv_set_admission_state",
    [("nv_set_admission_state", "PATCH /v1/admission/state", "True")],
    49, PARTC, "**C.0.0**, **C.0.3**, **C.0.5** and the `nv_set_admission_state` entry "
    "of the **`Toolset admission`** section",
    "src/neuvector_mcp/tools/admission.py", "tests/test_admission.py", [],
    new_module=False, models=False,
    context=(
        "One tool, on its own ticket: **enabling admission control in deny mode can "
        "block every deployment in the cluster.** This closes M8 at 49 tools."
    ),
    hard=(
        "Requirements Part C specifies and you must implement:\n\n"
        "- **three** branch-specific `effect` strings (enable, disable, mode change), "
        "each naming the concrete consequence;\n"
        "- a docstring that directs the caller to run `nv_assess_admission_rule` "
        "(T-016) **first**, and says in plain words that deny mode can block all "
        "deployments cluster-wide;\n"
        "- `RESTAdmissionConfigData.k8s_env` is marked required in the schema but "
        "**must not be sent**. Part C marks this `BLOCKED` — follow its instruction "
        "exactly.\n\n"
        "Error codes (Appendix C): **30** admission control unsupported on a "
        "non-Kubernetes platform, **36** configuring global settings while admission "
        "control is disabled. Add an error-classification test for code 30.\n\n"
        "Required tests: `test_set_admission_state_token_is_bound_to_arguments` and "
        "`test_set_admission_state_effect_warns_about_blocking_deployments`, which "
        "asserts the preview `effect` text actually contains the warning."
    ),
)

# ---- M9 scan_ops / runtime_ops --------------------------------------------
SECRET_RULE = (
    "**The two-payload rule (Part D section D.0) — implement it exactly:**\n\n"
    "```\n"
    "wire_payload  = the real body, with real credentials  -> client.request() ONLY\n"
    "safe_payload  = redact_secrets(wire_payload)          -> the guard AND WriteOutcome.payload\n"
    "confirm_token = sha256(op | target | canonical_json(safe_payload))[:12]\n"
    "```\n\n"
    "The token is computed over the **redacted** payload so preview and execution "
    "agree. The deliberate consequence, stated in Part D: changing only the secret does "
    "not invalidate the token. That is accepted — document it in a comment so nobody "
    "\"fixes\" it later and breaks the handshake. `controller_response` is redacted for "
    "every tool in this milestone.\n\n"
    "The secret-not-logged tests must use `capfd`, **not** `caplog`: structlog binds "
    "stderr with `cache_logger_on_first_use=True`, so `caplog` will not see the output. "
    "Part D explains this."
)

write_tools_ticket(
    "T-022", "M9", "scan-ops", ["T-021"],
    "scan_ops module and the two-payload secret rule: registry create, update, delete",
    [("nv_create_registry", "POST /v2/scan/registry", "False"),
     ("nv_update_registry", "PATCH /v2/scan/registry/{name}", "False"),
     ("nv_delete_registry", "DELETE /v1/scan/registry/{name}", "True")],
    52, PARTD, "the invariants section, **D.0**, and the registry entries of the "
    "**`Toolset scan_ops`** section",
    "src/neuvector_mcp/tools/scan_ops.py", "tests/test_scan_ops.py", [],
    new_module=True,
    context=(
        "Stand up the `scan_ops` toolset module with the three tools that carry "
        "registry credentials, so the two-payload secret mechanism lands before "
        "anything else in this milestone depends on it."
    ),
    extra_reading=f"\n6. `{APPD}` section D.7\n7. `SPEC.md` §11",
    hard=(
        SECRET_RULE + "\n\nRequired secret tests: "
        "`test_create_registry_password_not_logged`, "
        "`test_update_registry_password_not_logged`, "
        "`test_preview_payload_shows_redacted_password`, and "
        "`test_read_only_hides_scan_ops_tools`."
    ),
)

write_tools_ticket(
    "T-023", "M9", "scan-ops", ["T-022"],
    "scan_ops: nv_trigger_scan, nv_stop_registry_scan, nv_trigger_bench_run",
    [("nv_trigger_scan", "POST /v1/scan/workload/{id}, POST /v1/scan/host/{id}, "
      "POST /v1/scan/registry/{name}/scan", "False"),
     ("nv_stop_registry_scan", "DELETE /v1/scan/registry/{name}/scan", "False"),
     ("nv_trigger_bench_run", "POST /v1/bench/host/{id}/kubernetes, .../docker", "False")],
    55, PARTD, "**D.0** and the `nv_trigger_scan`, `nv_stop_registry_scan` and "
    "`nv_trigger_bench_run` entries of the **`Toolset scan_ops`** section",
    "src/neuvector_mcp/tools/scan_ops.py", "tests/test_scan_ops.py", [],
    new_module=False,
    context="The asynchronous scan and benchmark trigger tools.",
    extra_reading=f"\n6. `{APPD}` section D.7",
    hard=(
        "**`nv_trigger_scan` returns as soon as the controller accepts the request. It "
        "does not wait and it must not poll.** Its docstring tells the caller to read "
        "progress via `nv_get_scan_status` (T-007). Use "
        "`settings.long_request_timeout_s` for the request itself.\n\n"
        "All three routes return an empty body — respond `200, json={}` in tests rather "
        "than inventing a fixture.\n\n"
        "`nv_trigger_scan` is one tool over three endpoints and `nv_trigger_bench_run` "
        "one over two: validate the discriminating argument locally and raise "
        "`ValidationError_` before any network call."
    ),
)

write_tools_ticket(
    "T-024", "M9", "scan-ops", ["T-023"],
    "scan_ops: nv_scan_repository",
    [("nv_scan_repository", "POST /v1/scan/repository", "False")],
    56, PARTD, "**D.0** and the `nv_scan_repository` entry of the "
    "**`Toolset scan_ops`** section",
    "src/neuvector_mcp/tools/scan_ops.py", "tests/test_scan_ops.py",
    ["scan_repo_report.json"],
    new_module=False,
    context=(
        "One tool, on its own ticket: it is the only synchronous scan, it returns a "
        "full report, and it takes registry credentials."
    ),
    extra_reading=f"\n6. `{APPD}` sections D.7 and D.8",
    hard=(
        "`nv_scan_repository` is the exception to the async rule: it is synchronous, "
        "slow, and returns a full report. Project and cap it **exactly** like "
        "`nv_get_scan_report` (T-009) — summary-only mode, client-side severity filter, "
        "cap applied after sorting by severity, `truncated=True` with a hint.\n\n"
        "**Drop `RESTScanRepoReport.envs` and `labels` — environment variables carry "
        "credentials.**\n\n"
        "`scan_repo_report.json` uses envelope key `report`.\n\n"
        "The two-payload rule applies: `test_scan_repository_password_not_logged` uses "
        "`capfd`, not `caplog`."
    ),
)

write_tools_ticket(
    "T-025", "M9", "runtime-ops", ["T-024"],
    "runtime_ops module: nv_quarantine_workload and nv_set_service_mode",
    [("nv_quarantine_workload", "POST /v1/workload/request/{id}", "True"),
     ("nv_set_service_mode", "PATCH /v1/service/config, /network, /profile", "False")],
    58, PARTD, "**D.0** and the `nv_quarantine_workload` and `nv_set_service_mode` "
    "entries of the **`Toolset runtime_ops`** section",
    "src/neuvector_mcp/tools/runtime_ops.py", "tests/test_runtime_ops.py", [],
    new_module=True,
    context=(
        "Stand up the `runtime_ops` toolset module with the two tools that change how "
        "running workloads behave."
    ),
    extra_reading=f"\n6. `{APPD}` section D.7",
    hard=(
        "**`nv_quarantine_workload` severs a running container's network.** "
        "`destructiveHint=True`, and the `effect` string must say the container will "
        "lose network connectivity **immediately**. The same endpoint un-quarantines — "
        "Part D names the exact field; use it, do not invent a second tool.\n\n"
        "`nv_set_service_mode` covers three routes; validate the discriminating "
        "argument locally and raise `ValidationError_` before any network call.\n\n"
        "All routes return an empty body — respond `200, json={}`. Add "
        "`test_read_only_hides_runtime_ops_tools`."
    ),
)

write_tools_ticket(
    "T-026", "M9", "runtime-ops", ["T-025"],
    "runtime_ops: nv_start_packet_capture and nv_stop_packet_capture",
    [("nv_start_packet_capture", "POST /v1/sniffer", "False"),
     ("nv_stop_packet_capture", "PATCH /v1/sniffer/stop/{id}", "False")],
    60, PARTD, "**D.0** and the two packet-capture entries of the "
    "**`Toolset runtime_ops`** section",
    "src/neuvector_mcp/tools/runtime_ops.py", "tests/test_runtime_ops.py", [],
    new_module=False, models=False,
    context="The packet-capture pair. This closes M9 at 60 tools.",
    extra_reading=f"\n6. `{APPD}` section D.7",
    hard=(
        "**`GET /v1/sniffer/{id}/pcap` is deliberately NOT exposed.** A binary pcap is "
        "not a sane MCP result. `nv_start_packet_capture`'s docstring says so and tells "
        "the operator to retrieve the capture out of band. Do not add a third tool for "
        "it.\n\n"
        "Capture is privacy-sensitive: the `effect` string must name the target "
        "workload **and** the filter.\n\n"
        "Both routes return an empty body — respond `200, json={}`."
    ),
)

# ---- M10 iam / system -----------------------------------------------------
read_tools_ticket(
    "T-027", "M10", "iam", ["T-026"],
    "iam_read: nv_list_users, nv_list_roles, nv_list_auth_servers, nv_list_api_keys",
    [("nv_list_users", "GET /v1/user"),
     ("nv_list_roles", "GET /v1/user_role"),
     ("nv_list_auth_servers", "GET /v1/server"),
     ("nv_list_api_keys", "GET /v1/api_key")],
    64, PARTB, "the **`Toolset iam_read`** section",
    "src/neuvector_mcp/tools/iam.py", "tests/test_iam.py",
    ["users.json", "user_roles.json", "auth_servers.json", "api_keys.json"],
    new_module=True,
    context=(
        "Create `tools/iam.py` with its four read tools. The module will register "
        "**two** toolsets before M10 closes, so its `register()` needs two independent "
        "`if settings.toolset_enabled(...)` guards — add the `iam_read` guard now and "
        "the `iam_write` guard in T-028. A read tool tagged `iam_write` fails gate rule "
        "R3."
    ),
    extra_reading=f"\n5. `{APPC}`\n6. `SPEC.md` §6 and §11",
    hard=(
        "**Three secrets must never leak through these read tools:**\n\n"
        "- `nv_list_users` never projects `password`. Plant one in `users.json` and "
        "assert it is absent from the serialised result "
        "(`test_list_users_never_projects_password`).\n"
        "- `nv_list_api_keys` cannot and must not return `apikey_secret` — the "
        "controller shows it once, at creation, and never again "
        "(`test_list_api_keys_never_returns_secret`).\n"
        "- `nv_list_auth_servers` uses an **allowlist** projection: only the fields "
        "Part B names are read by value; every other key is reported **by name only**, "
        "with name-matches on `password`/`secret`/`token`/`credential`/`private`/`key` "
        "diverted to a `redacted_keys` list. An allowlist, not a denylist — a "
        "controller upgrade that adds a secret field must fail closed "
        "(`test_auth_server_secret_fields_are_redacted_by_allowlist`).\n\n"
        "`auth_servers.json`'s envelope key is inferred; `api_keys.json` uses "
        "`apikeys`."
    ),
)

write_tools_ticket(
    "T-028", "M10", "iam", ["T-027"],
    "iam_write: nv_create_user, nv_update_user_role, nv_delete_user",
    [("nv_create_user", "POST /v1/user", "False"),
     ("nv_update_user_role", "PATCH /v1/user/{fullname}/role/{role}", "False"),
     ("nv_delete_user", "DELETE /v1/user/{fullname}", "True")],
    67, PARTD, "**D.0** and the user entries of the **`Toolset iam_write`** section",
    "src/neuvector_mcp/tools/iam.py", "tests/test_iam.py", [],
    new_module=False,
    context=(
        "Add the `iam_write` toolset to `tools/iam.py`. Its `register()` gets a "
        "**second, independent** `if settings.toolset_enabled(\"iam_write\")` guard — "
        "not a widened version of the `iam_read` one."
    ),
    extra_reading=f"\n6. `{PARTB}` — the `Toolset iam_read` section, for the shared "
                  f"projections\n7. `SPEC.md` §11",
    hard=(
        "`RESTUser.password` on create follows the **two-payload rule** from T-022: "
        "real value on the wire, `\"***\"` in the preview payload and in "
        "`WriteOutcome.payload`, token computed over the redacted form. Required tests: "
        "`test_create_user_password_not_logged` (uses `capfd`, not `caplog`) and "
        "`test_create_user_preview_shows_redacted_password`.\n\n"
        "**`nv_update_user_role` uses `PATCH /v1/user/{fullname}/role/{role}`, not "
        "`PATCH /v1/user/{fullname}`.** Part D justifies it: the role travels in a "
        "verified path, and it avoids sharing a request body with `password` and "
        "`email`. Keep that reasoning as a comment.\n\n"
        "Error codes (Appendix C): **13** duplicate user or role name, **14** password "
        "does not satisfy the password profile, **15** name format rejected, **4** "
        "modifying a built-in role or the last admin, **25** namespace outside the "
        "identity's scope."
    ),
)

write_tools_ticket(
    "T-029", "M10", "iam", ["T-028"],
    "iam_write: nv_create_api_key and nv_delete_api_key",
    [("nv_create_api_key", "POST /v1/api_key", "False"),
     ("nv_delete_api_key", "DELETE /v1/api_key/{accesskey}", "True")],
    69, PARTD, "**D.0** and the API-key entries of the **`Toolset iam_write`** section",
    "src/neuvector_mcp/tools/iam.py", "tests/test_iam.py",
    ["api_key_generated.json"],
    new_module=False,
    context=(
        "The API-key pair, on its own ticket because `nv_create_api_key` is the one "
        "tool in the server that deliberately returns a secret to the caller."
    ),
    extra_reading="\n6. `SPEC.md` §11",
    hard=(
        "**`RESTApikey.apikey_secret` is returned to the caller** — that is the point "
        "of the tool, and the controller shows it once. It is never logged; the audit "
        "record notes only that a key was created. It is never retrievable afterwards, "
        "which is why `nv_list_api_keys` (T-027) cannot and must not return it.\n\n"
        "Required test: `test_create_api_key_secret_returned_but_not_logged` — assert "
        "the secret IS in the tool result and is NOT in `capfd`'s captured stderr.\n\n"
        "`api_key_generated.json` uses envelope key `apikey`."
    ),
)

write_tools_ticket(
    "T-030", "M10", "system", ["T-029"],
    "system_write module: nv_update_system_config, nv_set_namespace_tags, nv_update_scan_config",
    [("nv_update_system_config", "PATCH /v2/system/config", "False"),
     ("nv_set_namespace_tags", "PATCH /v1/domain/{name}", "False"),
     ("nv_update_scan_config", "PATCH /v1/scan/config", "False")],
    72, PARTD, "**D.0**, **D.0.8** and the **`Toolset system_write`** section",
    "src/neuvector_mcp/tools/system.py", "tests/test_system.py",
    ["system_config_v2.json"],
    new_module=True,
    context=(
        "The final three tools. After this ticket the tool surface is **complete at "
        "72**, and the default read-only surface must be exactly **41**."
    ),
    extra_reading="\n6. `SPEC.md` §7.3 and §11",
    hard=(
        "**`nv_update_system_config` is the one sanctioned pre-guard read.** It performs "
        "a read-only, failure-tolerant `GET /v2/system/config` before calling the "
        "guard, so its `effect` string can name each field as `old -> new`. Part D "
        "section D.0.8 bounds the exception:\n\n"
        "- the GET is the **only** network call permitted before the guard;\n"
        "- a failure of that GET must **not** fail the tool — fall back to naming the "
        "new values only;\n"
        "- the PATCH still happens only after confirmation.\n\n"
        "`test_update_system_config_preview_reads_current_config_only` asserts exactly "
        "one GET and **zero** PATCHes on the preview call. That test is what keeps this "
        "exception from becoming a loophole.\n\n"
        "Enumerate the highest-risk sub-fields in the docstring: cluster-wide "
        "enforcement defaults, syslog destination, webhooks, and network settings.\n\n"
        "`system_config_v2.json` uses envelope key `config`. Error code **25** covers a "
        "namespace outside the identity's scope.\n\n"
        "Also add `test_read_only_hides_iam_write_and_system_write_but_keeps_iam_read`."
    ),
)
# the read-only surface check is an extra acceptance line on T-030
T[-1]["acceptance"] = [
    f"`{GATE}`",
    f"`{count_check(72)}`",
    "`bash build-plan/check_readonly_surface.sh`",
]
T[-1]["create"] = T[-1]["create"] + ["build-plan/check_readonly_surface.sh"]
T[-1]["steps"] = T[-1]["steps"][:-1] + [
    "Write `build-plan/check_readonly_surface.sh`: a script that runs the read-only "
    "surface snippet from PHASE-10's Gate section under `.venv/bin/python` and exits "
    "non-zero unless it prints exactly `41`.",
    "Run the gate and report BOTH counts: 72 tools from `make spec` and 41 from the "
    "read-only surface check.",
]

# ---- M11 package and deploy ----------------------------------------------
add(
    tid="T-031", milestone="M11", area="deploy", assignee="agent", depends=["T-030"],
    title="Build and inspect the container image on openSUSE BCI",
    create=[], modify=[],
    context=(
        "Build the image from the `deploy/Dockerfile` copied verbatim in T-001 and "
        "prove the security properties that matter: non-root uid, no compilers in the "
        "final layer, correct labels and entrypoint."
    ),
    reading=(
        f"1. `SPEC.md` §13\n"
        f"2. `{PHASE}/PHASE-11-package-deploy.md` section 1\n"
        f"3. `deploy/Dockerfile`"
    ),
    steps=[
        "Run `make image` and record the output.",
        "Run each inspection command PHASE-11 section 1 lists and record its output: "
        "`id` must report uid=10001 gid=10001 and NOT root; `which gcc cc make` must "
        "find nothing; `podman image inspect` must show the labels and entrypoint.",
        "Report all four outputs in the issue before closing it.",
    ],
    acceptance=[
        "`make image`",
        "`bash -c 'podman run --rm --entrypoint /bin/sh localhost:5000/neuvector-mcp:1.0.0 -c id | grep -q \"uid=10001\"'`",
        f"`{GATE}`",
    ],
    guardrails=READ_GUARDS + [
        "**Base image policy: openSUSE or SUSE BCI only.** The Dockerfile uses "
        "`registry.opensuse.org/opensuse/bci/python:3.13`. Switching both `FROM` lines "
        "to `registry.suse.com/bci/python:3.13` for a SUSE-supported lifecycle is "
        "allowed. **Any other base requires written justification and approval "
        "first** — do not change it on your own initiative.",
        "Requires `podman` on PATH. If it is missing, report BLOCKED rather than "
        "substituting another builder.",
    ],
)

add(
    tid="T-032", milestone="M11", area="deploy", assignee="human", depends=["T-031"],
    title="Fill in deployment secrets and dry-run the manifests under PodSecurity restricted",
    create=[], modify=["deploy/deployment.yaml"],
    context=(
        "Three values in `deploy/deployment.yaml` must be replaced with real ones "
        "before it can be applied, and the security posture must be proven against a "
        "real API server. **Human ticket: needs a NeuVector API key pair, a generated "
        "bearer token and a reachable cluster.**"
    ),
    reading=(
        f"1. `SPEC.md` §13\n"
        f"2. `{PHASE}/PHASE-11-package-deploy.md` section 2\n"
        f"3. `deploy/deployment.yaml`"
    ),
    steps=[
        "Replace `Secret/neuvector-mcp-controller` `access-key` and `secret-key` with "
        "the NeuVector API key pair (SPEC.md 13.1).",
        "Replace `Secret/neuvector-mcp-clients` `bearer-tokens` with "
        "`openssl rand -hex 32`, formatted `<token>:nv:read`.",
        "Replace the `Deployment` `image` with your registry path.",
        "Run `kubectl apply --dry-run=server -f deploy/deployment.yaml`. The namespace "
        "is labelled `pod-security.kubernetes.io/enforce: restricted`, so this is a "
        "real check: it must pass with `runAsNonRoot`, `readOnlyRootFilesystem`, all "
        "capabilities dropped and `automountServiceAccountToken: false` intact.",
        "Verify the `NetworkPolicy` matches your cluster: the egress rule targets "
        "`kubernetes.io/metadata.name: cattle-neuvector-system` on port 10443. If "
        "NeuVector runs in a different namespace, fix the **selector**, not the port.",
    ],
    acceptance=[
        "`kubectl apply --dry-run=server -f deploy/deployment.yaml`",
        "Dry run passes with runAsNonRoot, readOnlyRootFilesystem, all capabilities "
        "dropped and automountServiceAccountToken: false intact (human check)",
        "NetworkPolicy egress selector matches the cluster's NeuVector namespace "
        "(human check)",
    ],
    guardrails=READ_GUARDS + [
        "**Do not commit real values.** Replace them locally to run the dry-run, then "
        "revert the file to its placeholder form before committing.",
        "Do not weaken the PodSecurity settings to make the dry-run pass.",
    ],
)

add(
    tid="T-033", milestone="M11", area="deploy", assignee="human", depends=["T-031"],
    title="Live smoke test against a NeuVector controller and fix the projection defects it exposes",
    create=[], modify=[],
    context=(
        "The only step that touches a real controller. It calls read tools only. "
        "**This is where projection bugs surface**: fixtures are hand-written, a live "
        "controller is not. **Human ticket: needs a controller URL and an API key "
        "pair.**"
    ),
    reading=(
        f"1. `SPEC.md` §13\n"
        f"2. `{PHASE}/PHASE-11-package-deploy.md` section 3\n"
        f"3. `scripts/smoke_stdio.py`"
    ),
    steps=[
        "Export `NV_CONTROLLER_URL`, `NV_API_ACCESS_KEY`, `NV_API_SECRET_KEY` and "
        "`NV_VERIFY_TLS=false` (the controller's default certificate is self-signed).",
        "Run `.venv/bin/python scripts/smoke_stdio.py`. Expect the tool count, the "
        "system summary, and up to five workloads with their policy mode and "
        "high-severity vulnerability count.",
        "For every field that comes back empty which the fixture populated, the JSON "
        "tag in that `from_api()` is wrong. Fix **both** the projection and the "
        "fixture, so the test would have caught it.",
        "Record every discrepancy in the issue. Each one is a real defect that got past "
        "72 tool contracts and a full test suite, which is worth knowing.",
    ],
    acceptance=[
        f"`{GATE}`",
        f"`{count_check(72)}`",
        "`scripts/smoke_stdio.py` returns real data from the live controller "
        "(human check)",
        "Every projection discrepancy is recorded in this issue and fixed in both the "
        "projection and its fixture (human check)",
    ],
    guardrails=READ_GUARDS + [
        "Read tools only. Do not run a mutating tool against a live controller from "
        "this ticket.",
        "Do not commit credentials, and do not add the controller URL to any file.",
    ],
)

add(
    tid="T-034", milestone="M11", area="deploy", assignee="agent", depends=["T-031"],
    title="Write the user-facing README",
    create=[], modify=["README.md"],
    context=(
        "Replace the reference-core README copied in T-001 with one that lets someone "
        "else run this server from the README alone."
    ),
    reading=(
        f"1. `SPEC.md` §13\n"
        f"2. `{PHASE}/PHASE-11-package-deploy.md` section 4\n"
        f"3. `src/neuvector_mcp/config.py` for the environment variables\n"
        f"4. `src/neuvector_mcp/server.py` for the INSTRUCTIONS string"
    ),
    steps=[
        "Write `README.md` covering, in this order: (1) what the server does, in three "
        "sentences; (2) quick start over stdio — the four environment variables and one "
        "command; (3) the client configuration block for stdio; (4) in-cluster "
        "deployment — image build, the three Secret values, `kubectl apply`; "
        "(5) the toolsets table and how to enable mutating ones, with the read-only "
        "default stated plainly; (6) the confirmation handshake, with a worked two-call "
        "example; (7) `make verify` as the definition of done; (8) NeuVector API key "
        "provisioning, including the `reader` role recommendation and the "
        "expiry/rotation note.",
        "Take the toolset names and the read-only default from `config.py` — do not "
        "recall them.",
        "State the final acceptance table with its actual results: 72 tools, 41 "
        "read-only, coverage at or above 85%.",
    ],
    acceptance=[
        f"`{GATE}`",
        "README covers all eight sections in the order listed, with no feature-list "
        "padding (human check)",
    ],
    guardrails=READ_GUARDS + [
        "No feature list padding. Someone should be able to run this from the README "
        "alone.",
        "Do not document a toolset, environment variable or tool that does not exist "
        "in the code.",
    ],
)


# --------------------------------------------------------------------------
def main():
    os.makedirs(BODIES, exist_ok=True)
    for t in T:
        md = body(t["tid"], t["context"], t["reading"], t["depends"], t["create"],
                  t["modify"], t["steps"], t["acceptance"], t["guardrails"],
                  t.get("extra", ""))
        path = os.path.join(BODIES, f"{t['tid']}.md")
        with open(path, "w") as fh:
            fh.write(md)
        cmd = [sys.executable, TOOLS, "new", t["title"],
               "--id", t["tid"], "--milestone", t["milestone"],
               "--assignee", t["assignee"], "--area", t["area"],
               "--body-file", path]
        if t["depends"]:
            cmd += ["--depends", ",".join(t["depends"])]
        if t["create"]:
            cmd += ["--create", ",".join(t["create"])]
        if t["modify"]:
            cmd += ["--modify", ",".join(t["modify"])]
        if DRY:
            print(f"{t['tid']:6} {t['milestone']:4} {t['assignee']:6} {t['title']}")
            continue
        r = subprocess.run(cmd, cwd=REPO, text=True, capture_output=True)
        print((r.stdout or "").strip() or (r.stderr or "").strip())
        if r.returncode != 0:
            sys.exit(f"failed at {t['tid']}")


if __name__ == "__main__":
    main()
