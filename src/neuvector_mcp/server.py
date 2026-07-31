"""Server assembly. The only module that knows about every other module.

Nothing here talks to the controller directly; it wires configuration, lifespan,
middleware, auth and toolset registration, then hands control to FastMCP.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import structlog
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from .audit import AuditMiddleware, configure_logging
from .client import NeuVectorClient
from .config import Settings, load_settings
from .context import AppContext
from .tools import (
    admission,
    compliance,
    events,
    iam_read,
    iam_write,
    inventory,
    policy_read,
    policy_write,
    runtime_ops,
    scan_ops,
    system,
    vulnerability,
)

log = structlog.get_logger(__name__)

SERVER_NAME = "neuvector"
SERVER_VERSION = "1.0.3"

#: Every toolset module, in registration order. Each exposes
#: ``register(mcp, settings)`` and is responsible for checking whether its own
#: toolset is enabled, so registration order carries no meaning beyond the order
#: tools appear in ``tools/list``.
TOOL_MODULES = (
    inventory,
    vulnerability,
    compliance,
    events,
    policy_read,
    iam_read,
    policy_write,
    admission,
    scan_ops,
    runtime_ops,
    iam_write,
    system,
)

INSTRUCTIONS = """\
NeuVector container security control plane.

Read before acting:
- Resolve objects before operating on them. Workload ids come from
  nv_list_workloads; group names from nv_list_groups; registry names from
  nv_list_registries. Never guess an id.
- Every mutating tool is a two-step handshake. Call it once WITHOUT 'confirm' to
  get a plan describing the exact effect plus a confirm token, then call again
  with that token. A plan is not a change; nothing was sent to the controller.
- Policy mode meanings: Discover learns and allows, Monitor alerts only, Protect
  blocks. Moving a group to Protect can break a running application.
- Vulnerability and event queries can return very large result sets. Filter by
  namespace, severity or time window first, then page with 'start'.
- When a tool reports truncated=true, either narrow the filter or page; do not
  assume the returned set is complete.
"""


@contextlib.asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Open the controller connection, verify credentials, hold it for the process."""
    settings: Settings = server._nv_settings  # type: ignore[attr-defined]
    http = NeuVectorClient.build_http_client(settings)
    client = NeuVectorClient(settings, http)
    try:
        identity = await client.login()
        log.info(
            "nv.connected",
            controller=settings.controller_url,
            auth_mode=settings.auth_mode,
            read_only=settings.read_only,
            toolsets=list(settings.toolsets),
        )
        yield AppContext(settings=settings, client=client, identity=identity)
    finally:
        await client.logout()
        await http.aclose()


def _auth_provider(settings: Settings) -> AuthProvider | None:
    """Return the HTTP auth provider, or ``None`` for stdio.

    stdio inherits the trust boundary of the parent process, so it carries no
    auth. HTTP is network-reachable and therefore MUST be authenticated: the
    server refuses to start on HTTP without at least one bearer token.
    """
    if settings.transport != "http":
        return None
    if not settings.http_bearer_tokens:
        from .errors import ConfigError

        raise ConfigError(
            "NV_TRANSPORT=http requires NV_HTTP_BEARER_TOKENS "
            "(format: 'token1:nv:read|nv:write,token2:nv:read'). "
            "Refusing to expose an unauthenticated control plane."
        )
    return StaticTokenVerifier(
        tokens={
            token: {"client_id": f"nv-mcp-{i}", "scopes": scopes}
            for i, (token, scopes) in enumerate(settings.http_bearer_tokens.items())
        }
    )


def build_server(settings: Settings | None = None) -> FastMCP:
    """Construct the fully wired :class:`FastMCP` server.

    Args:
        settings: Injected settings. Tests pass a constructed
            :class:`~neuvector_mcp.config.Settings`; production passes ``None``
            so the environment is read.

    Returns:
        A server ready for ``.run()`` or for in-process testing with
        ``fastmcp.Client(server)``.
    """
    settings = settings or load_settings()
    configure_logging(settings)

    mcp = FastMCP(
        name=SERVER_NAME,
        version=SERVER_VERSION,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
        auth=_auth_provider(settings),
        middleware=[AuditMiddleware(settings)],
        mask_error_details=False,
        on_duplicate="error",
    )
    mcp._nv_settings = settings  # type: ignore[attr-defined]

    for module in TOOL_MODULES:
        module.register(mcp, settings)

    return mcp


def main() -> None:
    """Console entry point."""
    settings = load_settings()
    mcp = build_server(settings)
    if settings.transport == "http":
        mcp.run(
            transport="http",
            host=settings.http_host,
            port=settings.http_port,
            path=settings.http_path,
            show_banner=False,
        )
    else:
        mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":  # pragma: no cover
    main()
