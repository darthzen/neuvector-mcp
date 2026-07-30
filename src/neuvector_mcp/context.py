"""The lifespan context every tool reaches through ``ctx.request_context``.

One instance exists per process. Tools obtain it with :func:`app_context`, which
is the ONLY sanctioned way to reach the client or the settings from a tool body.
Do not create module-level globals for either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastmcp import Context

from .client import NeuVectorClient
from .config import Settings


@dataclass(slots=True)
class AppContext:
    """Process-wide dependencies handed to tools."""

    settings: Settings
    client: NeuVectorClient
    identity: dict[str, Any] = field(default_factory=dict)


def app_context(ctx: Context) -> AppContext:
    """Return the :class:`AppContext` for the in-flight request.

    Args:
        ctx: The FastMCP context injected into every tool function.

    Returns:
        The process-wide :class:`AppContext`.
    """
    value = ctx.request_context.lifespan_context
    if not isinstance(value, AppContext):  # pragma: no cover - defensive
        raise RuntimeError(
            "lifespan context is not an AppContext; server.py wired the lifespan wrong"
        )
    return value
