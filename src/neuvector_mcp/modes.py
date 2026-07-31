"""Enforcement-mode changes on ``PATCH /v1/service/config``.

Two things about that endpoint are not in the published API documentation. Both
were measured against a live 5.6.0 controller, and getting them wrong is silent
in both directions - the controller answers 200 either way.

1. **The dimension is chosen by the payload field, not by the path.**
   ``RESTServiceBatchConfig`` carries five fields: ``services``, ``policy_mode``,
   ``profile_mode``, ``baseline_profile`` and ``not_scored``. Sending
   ``profile_mode`` to ``/v1/service/config`` moves the process/file profile and
   leaves network policy alone. The sibling route ``/v1/service/config/profile``
   is inert on every field; ``/v1/service/config/network`` honours only
   ``policy_mode``. This module therefore uses ``/v1/service/config`` alone.

2. **The write is applied asynchronously.** A read issued immediately after the
   200 can still show the old value. Measured lag on 2026-07-31: 0.33-0.59s over
   five runs. :func:`verify_applied` polls across that window, because a single
   read taken too early reports a change that succeeded as a failure.

An earlier revision of this module also stepped every mode change through
``Monitor``, on the theory that the controller silently discards a two-rung move
along ``Discover -> Monitor -> Protect``. That theory was wrong: it was point 2
misread. Five consecutive single-call ``Discover -> Protect`` moves all landed,
on both dimensions, including with the other dimension already at ``Protect``.
The stepping is gone; the verification it was hiding behind is what actually
mattered and has been kept.

The pure functions here decide what to send and what counts as landed; the
callers in ``tools`` own the guard handshake and do the sending.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

from .client import NeuVectorClient, build_query

#: Every settable field of ``RESTServiceBatchConfig`` bar ``services``. Each one
#: is also a field of ``RESTService``, which is what makes read-back possible.
SERVICE_CONFIG_FIELDS: tuple[str, ...] = (
    "policy_mode",
    "profile_mode",
    "baseline_profile",
    "not_scored",
)

#: Read-back budget, sized off the measured 0.33-0.59s propagation lag with room
#: for a loaded controller. Module-level so tests can shrink them.
VERIFY_ATTEMPTS = 8
VERIFY_DELAY_S = 0.5


def pending_fields(
    services: Sequence[str],
    config: Mapping[str, Any],
    observed: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Fields of ``config`` that ``observed`` does not already satisfy.

    Args:
        services: Service names in the batch.
        config: The ``config`` object the caller asked for, ``services`` included.
        observed: Current field values per service, from :func:`read_service_modes`.

    Returns:
        One human-readable line per service-and-field still to change. Empty means
        the request is a no-op and nothing need be sent.
    """
    return [
        f"{service}.{field}: asked for {value!r}, controller reports "
        f"{observed.get(service, {}).get(field)!r}"
        for service in services
        for field, value in sorted(config.items())
        if field != "services" and observed.get(service, {}).get(field) != value
    ]


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


async def verify_applied(
    client: NeuVectorClient, services: Sequence[str], config: Mapping[str, Any]
) -> list[str]:
    """Poll the controller until it reflects ``config``, and report what never did.

    A 200 from ``PATCH /v1/service/config`` is not evidence, and neither is one
    read taken straight after it - the write lands a fraction of a second later.
    Returning early on the first clean read keeps the common case fast.

    Args:
        client: Controller client.
        services: Service names in the batch.
        config: The ``config`` object that was sent.

    Returns:
        Empty when everything landed. Otherwise one line per field that did not,
        naming the value the controller actually holds.
    """
    drift: list[str] = []
    for attempt in range(VERIFY_ATTEMPTS):
        drift = pending_fields(services, config, await read_service_modes(client, services))
        if not drift:
            return []
        if attempt + 1 < VERIFY_ATTEMPTS:
            await asyncio.sleep(VERIFY_DELAY_S)
    return drift
