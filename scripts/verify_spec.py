#!/usr/bin/env python3
"""Machine-checkable spec compliance gate.

Run with every toolset enabled, introspect the assembled server, and fail the
build when any rule in SPEC.md section 12 is violated. This is the objective
definition of "the implementation matches the spec"; passing tests alone is not
sufficient.

Usage:
    python scripts/verify_spec.py            # check, human-readable report
    python scripts/verify_spec.py --json     # machine-readable report

Exit codes:
    0  every rule satisfied
    1  at least one violation
    2  the server could not be built or introspected
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TESTS = ROOT / "tests"
ENDPOINTS_FILE = ROOT / "spec_endpoints.json"

sys.path.insert(0, str(SRC))
sys.path.insert(0, str(TESTS))

TOOL_NAME_RE = re.compile(r"^nv_[a-z0-9_]+$")
CALLS_RE = re.compile(
    r"Calls (GET|POST|PATCH|DELETE) (/v[12]/[A-Za-z0-9_/{}.\-]+)(?: with | \(|\.|,|$)"
)

#: Undocumented controller routes this project is permitted to use, each with a
#: written justification. Anything outside this list fails rule R6.
UNDOCUMENTED_ALLOWLIST: dict[str, str] = {
    "GET /v1/conversation": "network graph; no documented equivalent exists",
    "GET /v1/conversation/{from}/{to}": "per-pair conversation detail",
    "GET /v1/vulasset": "paged vulnerability asset query; the only scalable vuln view",
    "POST /v1/vulasset": "creates the query id consumed by GET /v1/vulasset",
    "GET /v1/selfuser": "identity of the configured credential, used by nv_whoami",
    "GET /v1/list/application": "enumerates protocol names valid in network rules",
    "GET /v1/list/compliance": "enumerates compliance check ids",
    "GET /v1/list/registry_type": "enumerates registry types valid in nv_create_registry",
    "GET /v1/response/options": "enumerates valid response-rule actions",
    "GET /v1/group/{name}/stats": "group traffic counters",
}


class Report:
    def __init__(self) -> None:
        self.violations: list[dict[str, str]] = []
        self.checked: dict[str, int] = {}

    def fail(self, rule: str, subject: str, detail: str) -> None:
        self.violations.append({"rule": rule, "subject": subject, "detail": detail})

    def count(self, rule: str) -> None:
        self.checked[rule] = self.checked.get(rule, 0) + 1


async def collect_tools() -> list[object]:
    from conftest import make_settings  # type: ignore[import-not-found]

    from neuvector_mcp.config import ALL_TOOLSETS
    from neuvector_mcp.server import build_server

    server = build_server(make_settings(read_only=False, toolsets=ALL_TOOLSETS))
    return list(await server.list_tools(run_middleware=False))


def load_endpoints() -> tuple[set[str], set[str]]:
    data = json.loads(ENDPOINTS_FILE.read_text())
    return set(data["documented"]), set(data["undocumented"])


def normalise(call: str) -> str:
    """Reduce a concrete path to its templated form: /v1/group/foo -> /v1/group/{name}."""
    method, _, path = call.partition(" ")
    parts = path.strip("/").split("/")
    return f"{method} /" + "/".join(parts)


def path_matches(call: str, known: set[str]) -> bool:
    """True when ``call`` matches a known route, allowing {placeholder} segments."""
    method, _, path = call.partition(" ")
    call_parts = path.strip("/").split("/")
    for route in known:
        r_method, _, r_path = route.partition(" ")
        if r_method != method:
            continue
        r_parts = r_path.strip("/").split("/")
        if len(r_parts) != len(call_parts):
            continue
        if all(
            rp == cp or rp.startswith("{") or cp.startswith("{")
            for rp, cp in zip(r_parts, call_parts)
        ):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = Report()
    try:
        tools = asyncio.run(collect_tools())
        documented, undocumented = load_endpoints()
        from neuvector_mcp.config import ALL_TOOLSETS, MUTATING_TOOLSETS
    except Exception as exc:  # pragma: no cover
        print(f"FATAL: could not introspect server: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    test_text = "\n".join(p.read_text() for p in TESTS.rglob("test_*.py"))

    for tool in tools:
        name = tool.name
        doc = (tool.description or "").strip()
        tags = set(tool.tags or ())
        ann = tool.annotations
        params = set((tool.parameters or {}).get("properties", {}).keys())

        # R1 naming
        report.count("R1")
        if not TOOL_NAME_RE.match(name):
            report.fail("R1", name, "tool name must match ^nv_[a-z0-9_]+$")

        # R2 description
        report.count("R2")
        if len(doc.splitlines()) < 3 or len(doc) < 80:
            report.fail(
                "R2", name, "description needs a summary line, guidance, and a 'Calls ...' line"
            )

        # R3 annotations present and consistent
        report.count("R3")
        if ann is None:
            report.fail("R3", name, "missing ToolAnnotations")
        else:
            mutating_tags = MUTATING_TOOLSETS.intersection(tags)
            if mutating_tags and ann.readOnlyHint is not False:
                report.fail("R3", name, f"toolset {sorted(mutating_tags)} requires readOnlyHint=False")
            if not mutating_tags and ann.readOnlyHint is not True:
                report.fail("R3", name, "read tool requires readOnlyHint=True")

        # R4 toolset tag
        report.count("R4")
        toolset_tags = tags.intersection(ALL_TOOLSETS)
        if len(toolset_tags) != 1:
            report.fail(
                "R4", name, f"needs exactly one toolset tag from {sorted(ALL_TOOLSETS)}, has {sorted(tags)}"
            )

        # R5 confirm parameter on mutating tools
        report.count("R5")
        if MUTATING_TOOLSETS.intersection(tags) and "confirm" not in params:
            report.fail("R5", name, "mutating tool must accept a 'confirm' parameter")
        if not MUTATING_TOOLSETS.intersection(tags) and "confirm" in params:
            report.fail("R5", name, "read-only tool must not accept 'confirm'")

        # R6 endpoint allowlist
        report.count("R6")
        calls = CALLS_RE.findall(doc)
        if not calls:
            report.fail("R6", name, "description must name each endpoint as 'Calls <METHOD> <path>'")
        for method, path in calls:
            call = f"{method} {path.rstrip('.')}"
            if path_matches(call, documented):
                continue
            if call in UNDOCUMENTED_ALLOWLIST or path_matches(call, set(UNDOCUMENTED_ALLOWLIST)):
                continue
            if path_matches(call, undocumented):
                report.fail("R6", name, f"{call} is undocumented and not in UNDOCUMENTED_ALLOWLIST")
            else:
                report.fail("R6", name, f"{call} is not a NeuVector controller route")

        # R7 output schema declared
        report.count("R7")
        if not tool.output_schema:
            report.fail("R7", name, "tool must declare a structured output model")

        # R8 test coverage
        report.count("R8")
        if f'"{name}"' not in test_text and f"'{name}'" not in test_text:
            report.fail("R8", name, "no test references this tool name")

    # R9 aggregate: at least one mutating and one read tool exist
    report.count("R9")
    if not any(MUTATING_TOOLSETS.intersection(set(t.tags or ())) for t in tools):
        report.fail("R9", "<server>", "no mutating tools registered with all toolsets enabled")

    if args.json:
        print(json.dumps({"tools": len(tools), "checked": report.checked, "violations": report.violations}, indent=1))
    else:
        print(f"verify_spec: {len(tools)} tools introspected")
        for rule in sorted(report.checked):
            bad = sum(1 for v in report.violations if v["rule"] == rule)
            status = "ok  " if bad == 0 else "FAIL"
            print(f"  [{status}] {rule}: {report.checked[rule]} checked, {bad} violation(s)")
        for v in report.violations:
            print(f"    {v['rule']} {v['subject']}: {v['detail']}")
    return 1 if report.violations else 0


if __name__ == "__main__":
    sys.exit(main())
