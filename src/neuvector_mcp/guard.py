"""Write guard: the only place a mutating call may be authorised.

Every mutating tool calls :func:`authorise_write` before it touches the client.
The guard enforces four independent conditions, in this order:

1. ``NV_READ_ONLY`` must be false.
2. The tool's toolset must be enabled in ``NV_TOOLSETS``.
3. When ``NV_ALLOWED_NAMESPACES`` is non-empty, the target namespace must be in it.
4. When ``NV_REQUIRE_CONFIRM_TOKEN`` is true, the caller must echo back a
   deterministic confirmation token derived from the exact operation.

Condition 4 makes accidental writes structurally impossible: the model cannot
guess the token, so it must first call the tool without one, read the returned
plan, and call again with the token. That two-step handshake is the audit trail.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .config import Settings
from .errors import GuardError
from .models import WriteOutcome


def confirm_token(operation: str, target: str, payload: Mapping[str, Any] | None) -> str:
    """Derive the confirmation token for one specific mutation.

    The token is a function of the operation name, the target identifier and the
    canonical JSON form of the payload, so changing any field invalidates it.

    Args:
        operation: Stable operation id, e.g. ``"nv_delete_group"``.
        target: The object this mutation acts on, e.g. ``"nv.prod.api"``.
        payload: Request body, or ``None`` for payload-free operations.

    Returns:
        A 12-character lowercase hex token.
    """
    canonical = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{operation}|{target}|{canonical}".encode()).hexdigest()
    return digest[:12]


def authorise_write(
    settings: Settings,
    *,
    operation: str,
    toolset: str,
    target: str,
    effect: str,
    payload: Mapping[str, Any] | None,
    confirm: str | None,
    namespace: str | None = None,
) -> WriteOutcome | None:
    """Decide whether one mutating call may proceed.

    Args:
        settings: Active server settings.
        operation: Tool name, used in the token and the audit record.
        toolset: The tool's toolset tag, e.g. ``"policy_write"``.
        target: Human-readable identifier of the object being changed.
        effect: One-sentence description of what will change, for the plan.
        payload: The exact body that will be sent to the controller.
        confirm: Token supplied by the caller, or ``None`` on the first call.
        namespace: Namespace the change lands in, when the operation is scoped.

    Returns:
        ``None`` when the caller may proceed, or a
        :class:`~neuvector_mcp.models.WriteOutcome` with
        ``status="confirmation_required"`` that the tool must return verbatim.

    Raises:
        GuardError: when the operation is forbidden outright, or when the
            supplied token does not match.
    """
    if settings.read_only:
        raise GuardError(
            f"{operation} is a mutating operation and this server is running with "
            "NV_READ_ONLY=true. No request was sent to the controller."
        )
    if not settings.toolset_enabled(toolset):
        raise GuardError(
            f"{operation} belongs to toolset {toolset!r}, which is not enabled. "
            f"Enabled toolsets: {sorted(settings.toolsets)}."
        )
    if namespace and settings.allowed_namespaces and namespace not in settings.allowed_namespaces:
        raise GuardError(
            f"{operation} targets namespace {namespace!r}, which is outside "
            f"NV_ALLOWED_NAMESPACES ({sorted(settings.allowed_namespaces)})."
        )

    expected = confirm_token(operation, target, payload)
    if not settings.require_confirm_token:
        return None
    if confirm is None:
        return WriteOutcome(
            status="confirmation_required",
            operation=operation,
            target=target,
            effect=effect,
            payload=dict(payload or {}),
            confirm_token=expected,
            next_step=(
                f"Review 'effect' and 'payload'. To execute, call {operation} again "
                f"with identical arguments plus confirm={expected!r}."
            ),
        )
    if confirm != expected:
        raise GuardError(
            f"confirm token mismatch for {operation} on {target!r}. The arguments "
            "changed since the token was issued. Call again without 'confirm' to "
            "get a fresh plan and token."
        )
    return None
