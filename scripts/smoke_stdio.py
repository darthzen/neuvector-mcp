#!/usr/bin/env python3
"""Live smoke test: connect to a real controller over stdio and exercise reads.

This is the only script that talks to a real NeuVector controller. It performs no
mutations regardless of NV_READ_ONLY, because it only calls read tools.

Usage:
    export NV_CONTROLLER_URL=https://192.168.7.149:10443
    export NV_API_ACCESS_KEY=... NV_API_SECRET_KEY=... NV_VERIFY_TLS=false
    python scripts/smoke_stdio.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastmcp import Client

from neuvector_mcp.config import load_settings
from neuvector_mcp.server import build_server


async def main() -> int:
    settings = load_settings()
    server = build_server(settings)
    async with Client(server) as client:
        tools = await client.list_tools()
        print(f"connected to {settings.controller_url}")
        print(f"{len(tools)} tools: {', '.join(sorted(t.name for t in tools))}")

        summary = await client.call_tool("nv_get_system_summary", {})
        print("summary:", summary.structured_content)

        workloads = await client.call_tool("nv_list_workloads", {"limit": 5})
        for w in workloads.data.workloads:
            print(f"  {w.namespace}/{w.name} mode={w.policy_mode} high={w.high_vuls}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
