"""Unit tests for the enforcement-mode ladder.

The tools that use these helpers are covered end to end in ``test_runtime_ops``
and ``test_guard``; what is proved here is the one invariant every one of those
depends on - no body ever asks the controller for a two-rung move, because a
two-rung move is accepted with 200 and silently discarded.
"""

from __future__ import annotations

import pytest

from conftest import FakeServices
from neuvector_mcp.modes import (
    MODE_LADDER,
    describe_drift,
    mode_steps,
    plan_mode_patches,
    read_service_modes,
)


@pytest.mark.parametrize(
    ("current", "target", "expected"),
    [
        ("Discover", "Protect", ["Monitor", "Protect"]),
        ("Protect", "Discover", ["Monitor", "Discover"]),
        ("Discover", "Monitor", ["Monitor"]),
        ("Monitor", "Protect", ["Protect"]),
        ("Protect", "Monitor", ["Monitor"]),
        ("Protect", "Protect", []),
        ("", "Protect", ["Monitor", "Protect"]),
        ("", "Monitor", ["Monitor"]),
        ("Unrecognised", "Discover", ["Monitor", "Discover"]),
    ],
)
def test_mode_steps_never_jumps_a_rung(current: str, target: str, expected: list[str]) -> None:
    steps = mode_steps(current, target)
    assert steps == expected
    walk = [current, *steps]
    for before, after in zip(walk, steps, strict=False):
        if before in MODE_LADDER:
            gap = abs(MODE_LADDER.index(after) - MODE_LADDER.index(before))
            assert gap <= 1, f"{before} -> {after} is a jump the controller would drop"


def test_plan_mode_patches_ends_with_the_payload_the_token_bound() -> None:
    config = {"services": ["api.prod"], "policy_mode": "Protect", "not_scored": True}
    bodies = plan_mode_patches(["api.prod"], config, {"api.prod": {"policy_mode": "Discover"}})

    assert bodies[-1] == {"config": config}
    assert bodies[0] == {"config": {"services": ["api.prod"], "policy_mode": "Monitor"}}


def test_plan_mode_patches_is_empty_when_nothing_would_change() -> None:
    config = {"services": ["api.prod"], "policy_mode": "Protect", "baseline_profile": "zero-drift"}
    observed = {"api.prod": {"policy_mode": "Protect", "baseline_profile": "zero-drift"}}

    assert plan_mode_patches(["api.prod"], config, observed) == []


def test_plan_mode_patches_still_writes_when_only_a_non_mode_field_differs() -> None:
    config = {"services": ["api.prod"], "policy_mode": "Protect", "not_scored": True}
    observed = {"api.prod": {"policy_mode": "Protect", "not_scored": False}}

    assert plan_mode_patches(["api.prod"], config, observed) == [{"config": config}]


def test_plan_mode_patches_groups_services_by_the_rung_they_need() -> None:
    config = {"services": ["a.prod", "b.prod", "c.prod"], "policy_mode": "Monitor"}
    observed = {
        "a.prod": {"policy_mode": "Discover"},
        "b.prod": {"policy_mode": "Protect"},
        "c.prod": {"policy_mode": "Monitor"},
    }

    # Every service is one rung from Monitor, so the single batch call does it.
    assert plan_mode_patches(["a.prod", "b.prod", "c.prod"], config, observed) == [
        {"config": config}
    ]


def test_plan_mode_patches_batches_a_shared_intermediate_rung() -> None:
    config = {"services": ["a.prod", "b.prod"], "policy_mode": "Protect"}
    observed = {"a.prod": {"policy_mode": "Discover"}, "b.prod": {"policy_mode": "Discover"}}

    bodies = plan_mode_patches(["a.prod", "b.prod"], config, observed)

    assert bodies == [
        {"config": {"services": ["a.prod", "b.prod"], "policy_mode": "Monitor"}},
        {"config": config},
    ]


def test_describe_drift_names_the_field_and_both_values() -> None:
    drift = describe_drift(
        ["api.prod"],
        {"services": ["api.prod"], "policy_mode": "Protect"},
        {"api.prod": {"policy_mode": "Monitor"}},
    )

    assert len(drift) == 1
    assert "api.prod.policy_mode" in drift[0]
    assert "'Protect'" in drift[0] and "'Monitor'" in drift[0]


def test_describe_drift_is_empty_when_the_state_matches() -> None:
    assert (
        describe_drift(
            ["api.prod"],
            {"services": ["api.prod"], "policy_mode": "Protect"},
            {"api.prod": {"policy_mode": "Protect"}},
        )
        == []
    )


async def test_read_service_modes_matches_the_exact_name(nv_client, nv_mock) -> None:
    """f_name is a prefix filter, so 'api.prod' also returns 'api.production'."""
    fake = FakeServices(
        {
            "api.prod": {"policy_mode": "Monitor", "profile_mode": "Discover"},
            "api.production": {"policy_mode": "Protect"},
        }
    ).install(nv_mock)

    observed = await read_service_modes(nv_client, ["api.prod"])

    assert observed == {
        "api.prod": {
            "policy_mode": "Monitor",
            "profile_mode": "Discover",
            "baseline_profile": None,
            "not_scored": None,
        }
    }
    assert fake.reads.call_count == 1


async def test_read_service_modes_omits_a_service_the_controller_does_not_know(
    nv_client, nv_mock
) -> None:
    FakeServices({"api.prod": {"policy_mode": "Monitor"}}).install(nv_mock)

    observed = await read_service_modes(nv_client, ["api.prod", "gone.prod"])

    assert set(observed) == {"api.prod"}
