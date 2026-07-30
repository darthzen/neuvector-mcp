"""Structured logging and the tool-call audit middleware.

Two responsibilities:

* :func:`configure_logging` sets up structlog once, at process start.
* :class:`AuditMiddleware` emits one record per ``tools/call`` with the tool
  name, argument keys (never values), outcome, duration and error class.

Argument *values* are never logged: a caller may pass a registry password or a
user password through a mutating tool. Only key names are recorded.
"""

from __future__ import annotations

import logging
import sys
import time
from typing import Any

import structlog
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .config import Settings

_SENSITIVE_KEYS = {"password", "secret", "token", "confirm", "api_secret_key"}


def configure_logging(settings: Settings) -> None:
    """Configure structlog for the process. Idempotent.

    stdio transport is a hard constraint: **all** logs go to stderr, because
    stdout carries the MCP JSON-RPC framing. Writing a single byte of log output
    to stdout corrupts the session.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, settings.log_level, logging.INFO),
        force=True,
    )
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=False))
    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level, logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


class AuditMiddleware(Middleware):
    """Emit one audit record per tool call."""

    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._log = structlog.get_logger("neuvector_mcp.audit")

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        params = getattr(context, "message", None)
        tool_name = getattr(params, "name", "<unknown>")
        raw_args = getattr(params, "arguments", None) or {}
        arg_keys = sorted(raw_args.keys()) if isinstance(raw_args, dict) else []
        confirmed = bool(isinstance(raw_args, dict) and raw_args.get("confirm"))
        started = time.monotonic()
        try:
            result = await call_next(context)
        except Exception as exc:
            self._log.warning(
                "tool.call",
                tool=tool_name,
                arg_keys=arg_keys,
                confirmed=confirmed,
                outcome="error",
                error_class=type(exc).__name__,
                error=str(exc)[:400],
                duration_ms=round((time.monotonic() - started) * 1000, 1),
            )
            raise
        self._log.info(
            "tool.call",
            tool=tool_name,
            arg_keys=arg_keys,
            confirmed=confirmed,
            outcome="ok",
            duration_ms=round((time.monotonic() - started) * 1000, 1),
        )
        return result


def redact(mapping: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``mapping`` with sensitive values replaced."""
    return {
        k: ("***REDACTED***" if any(s in k.lower() for s in _SENSITIVE_KEYS) else v)
        for k, v in mapping.items()
    }
