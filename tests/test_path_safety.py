"""Path-safety contract: a caller-supplied name may not choose the endpoint.

Every tool builds its controller path by interpolating an argument into an
f-string, e.g. ``f"/v1/group/{group_name}"``. Unvalidated, that argument is an
endpoint selector rather than an object name, because ``httpx`` resolves ``..``
against the base URL before the request goes out::

    group_name="../../v1/system/config"
    -> DELETE https://controller:10443/v1/system/config

That escapes three of this server's four safety controls at once: ``NV_READ_ONLY``
and ``NV_TOOLSETS`` gate which *tools* are registered rather than which
*endpoints* are reachable, ``NV_ALLOWED_NAMESPACES`` never sees the real target,
and the confirmation token is derived from the same unvalidated string, so the
handshake authorises the escape.

These tests pin the refusal, pin that nothing reaches the controller when it
fires, and pin that legitimate names still pass through byte-for-byte.
"""

from __future__ import annotations

from typing import Any

import pytest
import respx
from fastmcp import Client

from conftest import CONTROLLER, fixture, make_settings
from neuvector_mcp.client import validate_path
from neuvector_mcp.errors import NeuVectorMCPError, ValidationError_
from neuvector_mcp.server import build_server

# Names the controller genuinely uses. None of these may be rejected: dots in a
# learned group name, a colon in an image digest, a slash in a repository path,
# and the percent that survives an already-encoded segment.
LEGITIMATE = [
    "/v1/system/summary",
    "/v1/group/nv.api.prod",
    "/v1/group/custom-group_1",
    "/v1/scan/image/sha256:aaa111",
    "/v1/scan/registry/harbor/image/library/api:1.4.2",
    "/v1/user/admin@example.com/role/reader",
    "/v2/scan/registry/my-registry",
    "/v1/compliance/profile/default/entry/D.1.1.1",
    "/v1/group/a%20name",
]

# Every one of these changes which endpoint the request lands on.
MALICIOUS = [
    "/v1/group/../../v1/system/config",
    "/v1/group/../api_key/mcp-writer",
    "/v1/compliance/profile/../../../v1/user",
    "/v1/group/%2e%2e/%2e%2e/v1/system/config",
    "/v1/group/..%2f..%2fv1%2fsystem%2fconfig",
    "/v1/group/./config",
    "/v1/group/name?f_domain=prod",
    "/v1/group/name#fragment",
    "/v1/group/name with space",
    "/v1/group/back\\slash",
    "/v1/group/nul\x00byte",
    "/etc/passwd",
    "/v3/group/name",
    "v1/group/name",
]


# --- unit ---------------------------------------------------------------------


@pytest.mark.parametrize("path", LEGITIMATE)
def test_legitimate_paths_pass_through_unchanged(path: str) -> None:
    assert validate_path(path) == path


@pytest.mark.parametrize("path", MALICIOUS)
def test_traversal_and_delimiter_injection_are_refused(path: str) -> None:
    with pytest.raises(ValidationError_):
        validate_path(path)


def test_refusal_is_a_tool_error_so_the_model_sees_it() -> None:
    """ValidationError_ is a ToolError subclass; a raw exception would 500."""
    assert issubclass(ValidationError_, NeuVectorMCPError)


# --- integration: nothing reaches the controller ------------------------------


async def test_read_only_server_cannot_walk_out_to_another_get_endpoint(
    nv_mock: respx.MockRouter,
) -> None:
    """A read-only server with one read toolset stays inside that toolset's routes.

    Before validation this reached GET /v1/user, because read_only and toolsets
    gate registration and not reachability.
    """
    users = nv_mock.get("/v1/user").respond(200, json={"users": []})
    server = build_server(make_settings(read_only=True, toolsets=("compliance",)))
    async with Client(server) as c:
        with pytest.raises(Exception, match="traversal"):
            await c.call_tool("nv_get_compliance_profile", {"profile_name": "../../../v1/user"})
    assert not users.called, "traversal still reached /v1/user"


async def test_traversing_delete_sends_nothing(client: Any, nv_mock: respx.MockRouter) -> None:
    """The escape is refused even once the confirmation handshake has authorised it."""
    everything = nv_mock.route(method="DELETE").respond(200, json={})
    evil = "../api_key/mcp-writer"

    plan = await client.call_tool("nv_delete_group", {"group_name": evil})
    assert plan.data.status == "confirmation_required"
    assert not everything.called, "the preview call must never send a request"

    with pytest.raises(Exception, match="traversal"):
        await client.call_tool(
            "nv_delete_group", {"group_name": evil, "confirm": plan.data.confirm_token}
        )
    assert not everything.called, "confirmed traversal still reached the controller"


async def test_query_injection_through_a_name_sends_nothing(
    client: Any, nv_mock: respx.MockRouter
) -> None:
    everything = nv_mock.route().respond(200, json={})
    with pytest.raises(Exception, match="URL delimiter"):
        await client.call_tool("nv_get_process_profile", {"group_name": "nv.api.prod?scope=fed"})
    assert not everything.called


# --- integration: legitimate calls are untouched ------------------------------


async def test_a_real_group_name_still_reaches_the_real_route(
    client: Any, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get("/v1/process_profile/nv.api.prod").respond(
        200, json=fixture("process_profile")
    )
    await client.call_tool("nv_get_process_profile", {"group_name": "nv.api.prod"})
    assert route.called
    assert str(route.calls[0].request.url) == f"{CONTROLLER}/v1/process_profile/nv.api.prod"
