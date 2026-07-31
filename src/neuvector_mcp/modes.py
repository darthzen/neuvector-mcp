"""Enforcement-mode transitions on ``PATCH /v1/service/config``.

Three things about that endpoint are not in the published API documentation and
were measured against a live 5.6.0 controller on 2026-07-31. Every one of them
fails *silently* - the controller answers 200 and changes nothing - so a tool
that trusts its own success status reports enforcement that is not there.

1. **The dimension is chosen by the payload field, not by the path.**
   ``RESTServiceBatchConfig`` carries five fields: ``services``, ``policy_mode``,
   ``profile_mode``, ``baseline_profile`` and ``not_scored``. Sending
   ``profile_mode`` to ``/v1/service/config`` moves the process/file profile and
   leaves network policy alone. The sibling route ``/v1/service/config/profile``
   is inert on every field; ``/v1/service/config/network`` honours only
   ``policy_mode``. This module therefore uses ``/v1/service/config`` alone.

2. **Mode moves must be adjacent.** The ladder is Discover -> Monitor -> Protect
   and the controller drops any two-rung jump. Going to Protect from Discover
   means sending Monitor first, in a separate call.

3. **A 200 is not evidence.** The only way to know a mode changed is to read the
   service back afterwards, which is what :func:`read_service_modes` is for.

The pure functions here decide *what* to send; the callers in ``tools`` own the
guard handshake and do the sending.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .client import NeuVectorClient, build_query

#: The enforcement ladder, weakest rung first. Only adjacent moves are accepted.
MODE_LADDER: tuple[str, ...] = ("Discover", "Monitor", "Protect")

#: Fields of ``RESTServiceBatchConfig`` that carry a mode and so must be stepped.
MODE_FIELDS: tuple[str, ...] = ("policy_mode", "profile_mode")

#: Every settable field, mode and non-mode alike. Each one is also a field of
#: ``RESTService``, which is what makes a read-back comparison possible.
SERVICE_CONFIG_FIELDS: tuple[str, ...] = (
    "policy_mode",
    "profile_mode",
    "baseline_profile",
    "not_scored",
)


def mode_steps(current: str, target: str) -> list[str]:
    """Rungs to send, in order, to move one service from ``current`` to ``target``.

    Args:
        current: Mode the controller reports today. An empty or unrecognised
            value means "could not be read".
        target: Mode the caller asked for; one of :data:`MODE_LADDER`.

    Returns:
        The ordered rungs, ending at ``target``. Empty when the service is
        already there. Never contains a two-rung jump.
    """
    if current == target:
        return []
    stop = MODE_LADDER.index(target)
    try:
        start = MODE_LADDER.index(current)
    except ValueError:
        # The current rung is unknown, so no walk can be computed. Monitor is
        # adjacent to both ends: reaching it first is legal from anywhere and is
        # the only move that cannot be silently dropped.
        return [target] if target == "Monitor" else ["Monitor", target]
    step = 1 if stop > start else -1
    return [MODE_LADDER[i] for i in range(start + step, stop + step, step)]


def plan_mode_patches(
    services: Sequence[str],
    config: Mapping[str, Any],
    observed: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Ordered ``PATCH /v1/service/config`` bodies that reach the state in ``config``.

    The last body returned is ``config`` itself - the payload the confirm token
    bound - and anything before it is an intermediate rung the controller insists
    on. Services already at the requested rung contribute no intermediate step,
    so re-applying Protect never dips through Monitor.

    Args:
        services: Service names in the batch, already sorted.
        config: The ``config`` object the caller asked for, ``services`` included.
        observed: Current field values per service, from :func:`read_service_modes`.

    Returns:
        Zero or more request bodies of the form ``{"config": {...}}``. Empty when
        every service already holds every value in ``config``, in which case
        nothing at all should be sent.
    """
    targets = {key: value for key, value in config.items() if key != "services"}
    if all(
        observed.get(service, {}).get(field) == value
        for service in services
        for field, value in targets.items()
    ):
        return []

    bodies: list[dict[str, Any]] = []
    for field in MODE_FIELDS:
        target = targets.get(field)
        if target is None:
            continue
        walks = {
            service: mode_steps(str(observed.get(service, {}).get(field, "") or ""), str(target))
            for service in services
        }
        # Every rung except each service's last one; the last rungs are exactly
        # what the caller's own payload sets, and it goes out at the end.
        for index in range(max((len(walk) for walk in walks.values()), default=0) - 1):
            batches: dict[str, list[str]] = {}
            for service, walk in walks.items():
                if index < len(walk) - 1:
                    batches.setdefault(walk[index], []).append(service)
            for value, members in sorted(batches.items()):
                bodies.append({"config": {"services": sorted(members), field: value}})

    bodies.append({"config": dict(config)})
    return bodies


async def read_service_modes(
    client: NeuVectorClient, services: Sequence[str]
) -> dict[str, dict[str, Any]]:
    """Read the current :data:`SERVICE_CONFIG_FIELDS` of each named service.

    One ``GET /v1/service`` per service: the batch endpoint takes a service list
    but the read side has no way to ask for several named services at once. The
    name filter is a prefix filter, so the exact name is matched again here.

    Args:
        client: Controller client.
        services: Service names, e.g. ``["api.prod"]``.

    Returns:
        ``{service: {field: value}}``. A service the controller does not know is
        absent from the mapping rather than present with empty values.
    """
    observed: dict[str, dict[str, Any]] = {}
    for name in services:
        params = build_query(start=0, limit=100, filters={"name": f"prefix,{name}"})
        items = await client.get_list("/v1/service", "services", params=params)
        for item in items:
            if isinstance(item, dict) and item.get("name") == name:
                observed[name] = {field: item.get(field) for field in SERVICE_CONFIG_FIELDS}
                break
    return observed


def describe_drift(
    services: Sequence[str],
    config: Mapping[str, Any],
    observed: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Fields the controller accepted but did not actually change.

    Args:
        services: Service names in the batch.
        config: The ``config`` object that was asked for.
        observed: Field values read back *after* the writes.

    Returns:
        One human-readable line per field that did not land, empty when the
        controller's state matches what was asked for.
    """
    return [
        f"{service}.{field}: asked for {value!r}, controller reports "
        f"{observed.get(service, {}).get(field)!r}"
        for service in services
        for field, value in sorted(config.items())
        if field != "services" and observed.get(service, {}).get(field) != value
    ]
