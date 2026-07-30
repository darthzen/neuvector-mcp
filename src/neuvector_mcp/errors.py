"""Error taxonomy: NeuVector controller errors -> MCP tool errors.

The controller returns errors as a ``RESTError`` JSON body::

    {"code": 7, "error": "Object not found", "message": "Group not found"}

``code`` is a stable integer (upstream: "Don't modify value or reorder"), while
the HTTP status is chosen per call site. Always branch on ``code`` first and fall
back to the HTTP status only when the body is absent or unparseable.

Every exception raised out of a tool function MUST be a :class:`ToolError`
subclass so FastMCP reports a clean, actionable message to the model instead of
leaking a traceback.
"""

from __future__ import annotations

from typing import Any

from fastmcp.exceptions import ToolError

# --- NeuVector RESTError codes (controller/api/apis.go) ----------------------
ERR_NOT_FOUND = 1
ERR_METHOD_NOT_ALLOWED = 2
ERR_UNAUTHORIZED = 3
ERR_OP_NOT_ALLOWED = 4
ERR_TOO_MANY_LOGIN_USER = 5
ERR_INVALID_REQUEST = 6
ERR_OBJECT_NOT_FOUND = 7
ERR_FAIL_WRITE_CLUSTER = 8
ERR_FAIL_READ_CLUSTER = 9
ERR_CLUSTER_WRONG_DATA = 10
ERR_CLUSTER_TIMEOUT = 11
ERR_NOT_ENOUGH_FILTER = 12
ERR_DUPLICATE_NAME = 13
ERR_WEAK_PASSWORD = 14
ERR_INVALID_NAME = 15
ERR_OBJECT_INUSE = 16
ERR_FAIL_EXPORT = 17
ERR_FAIL_IMPORT = 18
ERR_FAIL_LOCK_CLUSTER = 19
ERR_LICENSE_FAIL = 20
ERR_AGENT_ERROR = 21
ERR_WORKLOAD_NOT_RUNNING = 22
ERR_CIS_BENCH_ERROR = 23
ERR_CLUSTER_RPC_ERROR = 24
ERR_OBJECT_ACCESS_DENIED = 25
ERR_FAIL_REPO_SCAN = 26
ERR_FAIL_REGISTRY_SCAN = 27
ERR_FAIL_KUBERNETES_API = 28
ERR_ADMCTRL_UNSUPPORTED = 30
ERR_READ_ONLY_RULES = 46
ERR_USER_LOGIN_BLOCKED = 47
ERR_PASSWORD_EXPIRED = 48
ERR_PROMOTE_FAIL = 49
ERR_INVALID_QUERY_ID = 53
ERR_SERVER_ERROR = 55

#: Codes that mean "the caller's session is no longer usable".
AUTH_FAILURE_CODES: frozenset[int] = frozenset(
    {ERR_UNAUTHORIZED, ERR_USER_LOGIN_BLOCKED, ERR_PASSWORD_EXPIRED}
)

#: Codes that mean "transient; a retry may succeed".
RETRYABLE_CODES: frozenset[int] = frozenset(
    {
        ERR_FAIL_WRITE_CLUSTER,
        ERR_FAIL_READ_CLUSTER,
        ERR_CLUSTER_TIMEOUT,
        ERR_FAIL_LOCK_CLUSTER,
        ERR_CLUSTER_RPC_ERROR,
        ERR_SERVER_ERROR,
    }
)


class NeuVectorMCPError(ToolError):
    """Base class for every error this server surfaces to an MCP client."""


class ConfigError(NeuVectorMCPError):
    """The server is misconfigured; no request was attempted."""


class AuthError(NeuVectorMCPError):
    """Authentication or re-authentication against the controller failed."""


class PermissionError_(NeuVectorMCPError):
    """The controller identity lacks permission for this object or operation."""


class NotFoundError(NeuVectorMCPError):
    """The requested object does not exist."""


class ValidationError_(NeuVectorMCPError):
    """The controller rejected the request payload."""


class ConflictError(NeuVectorMCPError):
    """The object already exists, or is in use and cannot be changed."""


class UpstreamError(NeuVectorMCPError):
    """The controller failed for a reason the caller cannot fix."""


class GuardError(NeuVectorMCPError):
    """This server's own safety guard refused the call before it was sent."""


class TooLargeError(NeuVectorMCPError):
    """The result set is too large; the caller must narrow the query."""


#: Ordered mapping from controller ``code`` to the exception class to raise.
_CODE_MAP: dict[int, type[NeuVectorMCPError]] = {
    ERR_NOT_FOUND: NotFoundError,
    ERR_METHOD_NOT_ALLOWED: UpstreamError,
    ERR_UNAUTHORIZED: AuthError,
    ERR_OP_NOT_ALLOWED: PermissionError_,
    ERR_TOO_MANY_LOGIN_USER: UpstreamError,
    ERR_INVALID_REQUEST: ValidationError_,
    ERR_OBJECT_NOT_FOUND: NotFoundError,
    ERR_NOT_ENOUGH_FILTER: ValidationError_,
    ERR_DUPLICATE_NAME: ConflictError,
    ERR_INVALID_NAME: ValidationError_,
    ERR_OBJECT_INUSE: ConflictError,
    ERR_LICENSE_FAIL: PermissionError_,
    ERR_OBJECT_ACCESS_DENIED: PermissionError_,
    ERR_READ_ONLY_RULES: PermissionError_,
    ERR_USER_LOGIN_BLOCKED: AuthError,
    ERR_PASSWORD_EXPIRED: AuthError,
    ERR_INVALID_QUERY_ID: ValidationError_,
    ERR_ADMCTRL_UNSUPPORTED: ValidationError_,
    ERR_WORKLOAD_NOT_RUNNING: ConflictError,
}

#: Fallback mapping used when the body carries no usable ``code``.
_STATUS_MAP: dict[int, type[NeuVectorMCPError]] = {
    400: ValidationError_,
    401: AuthError,
    403: PermissionError_,
    404: NotFoundError,
    405: UpstreamError,
    408: UpstreamError,
    409: ConflictError,
    413: TooLargeError,
    429: UpstreamError,
}


def classify(status_code: int, body: Any) -> NeuVectorMCPError:
    """Turn a non-2xx controller response into the right exception instance.

    Args:
        status_code: HTTP status returned by the controller.
        body: Parsed JSON body, or ``None``/``str`` when the body was not JSON.

    Returns:
        An unraised :class:`NeuVectorMCPError` subclass instance whose message is
        safe to hand to a model: it names the controller code, the controller's
        own ``error`` string, and its ``message`` detail when present.
    """
    code: int | None = None
    err_str = ""
    detail = ""
    if isinstance(body, dict):
        raw_code = body.get("code")
        if isinstance(raw_code, int):
            code = raw_code
        err_str = str(body.get("error") or "")
        detail = str(body.get("message") or "")

    cls = _CODE_MAP.get(code) if code is not None else None
    if cls is None:
        cls = _STATUS_MAP.get(status_code, UpstreamError)

    parts = [f"NeuVector controller returned HTTP {status_code}"]
    if code is not None:
        parts.append(f"code={code}")
    if err_str:
        parts.append(err_str)
    if detail and detail != err_str:
        parts.append(detail)
    return cls(": ".join(parts[:2]) + (" - " + " / ".join(parts[2:]) if parts[2:] else ""))


def is_retryable(status_code: int, body: Any) -> bool:
    """True when the failure is transient and a bounded retry is appropriate."""
    if status_code in (502, 503, 504):
        return True
    if isinstance(body, dict):
        code = body.get("code")
        if isinstance(code, int) and code in RETRYABLE_CODES:
            return True
    return False
