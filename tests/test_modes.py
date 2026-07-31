"""Unit tests for service-mode read-back.

The tools that use these helpers are covered end to end in ``test_runtime_ops``
and ``test_guard``. What is proved here is the invariant those depend on: a
change is only called applied once the controller says so, and the read that
asks is patient enough to survive the controller's own write lag.
"""

from __future__ import annotations

from conftest import FakeServices
from neuvector_mcp import modes
from neuvector_mcp.modes import pending_fields, read_service_modes, verify_applied


def test_pending_fields_names_the_field_and_both_values() -> None:
    pending = pending_fields(
        ["api.prod"],
        {"services": ["api.prod"], "policy_mode": "Protect"},
        {"api.prod": {"policy_mode": "Monitor"}},
    )

    assert len(pending) == 1
    assert "api.prod.policy_mode" in pending[0]
    assert "'Protect'" in pending[0] and "'Monitor'" in pending[0]


def test_pending_fields_is_empty_when_the_state_matches() -> None:
    assert (
        pending_fields(
            ["api.prod"],
            {"services": ["api.prod"], "policy_mode": "Protect", "not_scored": True},
            {"api.prod": {"policy_mode": "Protect", "not_scored": True}},
        )
        == []
    )


def test_pending_fields_reports_a_non_mode_field_too() -> None:
    pending = pending_fields(
        ["api.prod"],
        {"services": ["api.prod"], "policy_mode": "Protect", "not_scored": True},
        {"api.prod": {"policy_mode": "Protect", "not_scored": False}},
    )

    assert len(pending) == 1
    assert "not_scored" in pending[0]


def test_pending_fields_spans_every_service_in_the_batch() -> None:
    pending = pending_fields(
        ["a.prod", "b.prod"],
        {"services": ["a.prod", "b.prod"], "policy_mode": "Protect"},
        {"a.prod": {"policy_mode": "Protect"}, "b.prod": {"policy_mode": "Discover"}},
    )

    assert len(pending) == 1
    assert pending[0].startswith("b.prod.")


async def test_verify_applied_waits_out_the_controller_write_lag(nv_client, nv_mock) -> None:
    """The real controller answers 200 before the change is readable."""
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}, lag_reads=3).install(nv_mock)
    config = {"services": ["api.prod"], "policy_mode": "Protect"}
    await nv_client.request("PATCH", "/v1/service/config", json={"config": config})

    drift = await verify_applied(nv_client, ["api.prod"], config)

    assert drift == [], "a change that lands late is not a change that failed"
    assert fake.mode("api.prod") == "Protect"
    assert fake.reads.call_count >= 3


async def test_verify_applied_gives_up_on_a_change_that_never_lands(nv_client, nv_mock) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Discover"}}, apply_writes=False).install(
        nv_mock
    )
    config = {"services": ["api.prod"], "policy_mode": "Protect"}
    await nv_client.request("PATCH", "/v1/service/config", json={"config": config})

    drift = await verify_applied(nv_client, ["api.prod"], config)

    assert len(drift) == 1
    assert "'Discover'" in drift[0]
    assert fake.reads.call_count == modes.VERIFY_ATTEMPTS, (
        "the whole budget is spent before failing"
    )


async def test_verify_applied_returns_on_the_first_clean_read(nv_client, nv_mock) -> None:
    fake = FakeServices({"api.prod": {"policy_mode": "Protect"}}).install(nv_mock)

    drift = await verify_applied(
        nv_client, ["api.prod"], {"services": ["api.prod"], "policy_mode": "Protect"}
    )

    assert drift == []
    assert fake.reads.call_count == 1, "the common case must not pay for the retry budget"


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
