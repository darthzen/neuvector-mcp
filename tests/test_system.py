"""Contract tests for the ``system_write`` toolset (tools/system.py).

Three mutating tools, every one of them cluster-wide:
``nv_update_system_config``, ``nv_set_namespace_tags``, ``nv_update_scan_config``.

The load-bearing assertions here are the negative ones: on a preview the mutating
route must have ``call_count == 0``, and on a confirmed call the body must contain
exactly the fields the caller set and nothing else. A PATCH that carried an unset
field would silently reset cluster-wide behaviour.
"""

from __future__ import annotations

import json

import pytest
import respx
from fastmcp import Client

from conftest import fixture, make_settings
from neuvector_mcp.config import DEFAULT_TOOLSETS
from neuvector_mcp.errors import PermissionError_, ValidationError_, classify
from neuvector_mcp.guard import confirm_token
from neuvector_mcp.models import _UNKNOWN, describe_change
from neuvector_mcp.server import build_server

pytestmark = pytest.mark.asyncio

GET_SYSTEM_CONFIG = "/v2/system/config"
PATCH_SYSTEM_CONFIG = "/v2/system/config"
PATCH_SCAN_CONFIG = "/v1/scan/config"
PATCH_DOMAIN = "/v1/domain/prod"


def _stub_system_config(nv_mock: respx.MockRouter) -> respx.Route:
    """Stub the pre-guard read of nv_update_system_config."""
    return nv_mock.get(GET_SYSTEM_CONFIG).respond(200, json=fixture("system_config_v2"))


# --- nv_update_system_config -------------------------------------------------


async def test_update_system_config_preview_sends_nothing(
    client, nv_mock: respx.MockRouter
) -> None:
    _stub_system_config(nv_mock)
    route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})

    result = await client.call_tool(
        "nv_update_system_config", {"new_service_policy_mode": "Protect"}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0, "the guard must not touch the mutating route"


async def test_update_system_config_preview_reads_current_config_only(
    client, nv_mock: respx.MockRouter
) -> None:
    """The one pre-guard network call (D.0.8) is a GET, and it is the only one."""
    get_route = _stub_system_config(nv_mock)
    patch_route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})

    result = await client.call_tool("nv_update_system_config", {"disable_net_policy": True})
    assert result.structured_content["status"] == "confirmation_required"
    assert get_route.call_count == 1
    assert patch_route.call_count == 0


async def test_update_system_config_effect_names_old_and_new_values(
    client, nv_mock: respx.MockRouter
) -> None:
    _stub_system_config(nv_mock)
    nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})

    result = await client.call_tool(
        "nv_update_system_config",
        {"new_service_policy_mode": "Protect", "xff_enabled": True},
    )
    effect = result.structured_content["effect"]
    assert "new_service_policy_mode 'Monitor' -> 'Protect'" in effect
    # xff_enabled is deliberately absent from the fixture, so its old value is the
    # _UNKNOWN sentinel; describe_change owns how that renders.
    assert "?" in effect
    assert describe_change("config_v2.misc_cfg.xff_enabled", _UNKNOWN, True) in effect


async def test_update_system_config_effect_degrades_when_read_fails(
    client, nv_mock: respx.MockRouter
) -> None:
    """A controller hiccup on the pre-read must not block the preview."""
    nv_mock.get(GET_SYSTEM_CONFIG).respond(500, json={})
    patch_route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})

    result = await client.call_tool(
        "nv_update_system_config",
        {"new_service_policy_mode": "Protect", "disable_net_policy": True},
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    effect = body["effect"]
    assert (
        describe_change("config_v2.svc_cfg.new_service_policy_mode", _UNKNOWN, "Protect") in effect
    )
    assert describe_change("net_config.disable_net_policy", _UNKNOWN, True) in effect
    assert "'Monitor'" not in effect, "no old value survived the failed read"
    assert patch_route.call_count == 0


async def test_update_system_config_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    _stub_system_config(nv_mock)
    route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})
    args = {
        "new_service_policy_mode": "Protect",
        "syslog_port": 514,
        "disable_net_policy": True,
    }
    plan = await client.call_tool("nv_update_system_config", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_update_system_config", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    sent = json.loads(route.calls.last.request.read())
    assert sent == {
        "config_v2": {
            "svc_cfg": {"new_service_policy_mode": "Protect"},
            "syslog_cfg": {"syslog_port": 514},
        },
        "net_config": {"disable_net_policy": True},
    }
    # Untouched sub-objects are ABSENT, not empty: an empty object is a request to
    # set nothing and the controller's behaviour with one is unverified.
    assert "atmo_config" not in sent
    assert set(sent["config_v2"]) == {"svc_cfg", "syslog_cfg"}


async def test_update_system_config_omits_unset_fields(client, nv_mock: respx.MockRouter) -> None:
    """Only the keys the caller set travel; falsy values are real values."""
    _stub_system_config(nv_mock)
    route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})
    args = {"xff_enabled": False, "cluster_name": "", "scanner_min_pods": 0}
    plan = await client.call_tool("nv_update_system_config", args)
    token = plan.structured_content["confirm_token"]

    await client.call_tool("nv_update_system_config", {**args, "confirm": token})
    sent = json.loads(route.calls.last.request.read())
    assert sent == {
        "config_v2": {
            "misc_cfg": {"cluster_name": "", "xff_enabled": False},
            "scanner_autoscale_cfg": {"min_pods": 0},
        }
    }
    # False, "" and 0 survived; nothing the caller left alone was sent.
    assert "net_config" not in sent
    assert "syslog_cfg" not in sent["config_v2"]
    assert "max_pods" not in sent["config_v2"]["scanner_autoscale_cfg"]


async def test_update_system_config_no_fields_raises(client, nv_mock: respx.MockRouter) -> None:
    get_route = _stub_system_config(nv_mock)
    route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_system_config", {})
    assert "needs at least one field to change" in str(excinfo.value)
    assert route.call_count == 0
    assert get_route.call_count == 0, "nothing is read before the payload is built"


async def test_update_system_config_response_secrets_redacted(
    client, nv_mock: respx.MockRouter
) -> None:
    """A controller that echoes its config back must not leak a credential."""
    secret = "n0t-a-real-pr0xy-p4ss"
    _stub_system_config(nv_mock)
    route = nv_mock.patch(PATCH_SYSTEM_CONFIG).respond(
        200,
        json={
            "config": {
                "proxy": {"registry_http_proxy_cfg": {"username": "svc", "password": secret}}
            }
        },
    )
    args = {"registry_http_proxy_status": True}
    plan = await client.call_tool("nv_update_system_config", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_update_system_config", {**args, "confirm": token})
    assert route.call_count == 1
    echoed = result.structured_content["controller_response"]
    assert echoed["config"]["proxy"]["registry_http_proxy_cfg"]["password"] == "***"
    assert secret not in json.dumps(result.structured_content)


# --- nv_set_namespace_tags ---------------------------------------------------


async def test_set_namespace_tags_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_DOMAIN).respond(200, json={})
    result = await client.call_tool(
        "nv_set_namespace_tags", {"namespace": "prod", "tags": ["PCI", "GDPR"]}
    )
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert "replacing its current tags" in body["effect"]
    assert route.call_count == 0


async def test_set_namespace_tags_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_DOMAIN).respond(200, json={})
    args = {"namespace": "prod", "tags": ["PCI", "GDPR"]}
    plan = await client.call_tool("nv_set_namespace_tags", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_set_namespace_tags", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {"name": "prod", "tags": ["GDPR", "PCI"]}
    }


async def test_set_namespace_tags_normalises_tag_order(client, nv_mock: respx.MockRouter) -> None:
    """Tags are a set: order and duplicates must not change the token or the body."""
    route = nv_mock.patch(PATCH_DOMAIN).respond(200, json={})
    first = await client.call_tool(
        "nv_set_namespace_tags", {"namespace": "prod", "tags": ["PCI", "GDPR"]}
    )
    second = await client.call_tool(
        "nv_set_namespace_tags", {"namespace": "prod", "tags": ["GDPR", "PCI", "PCI"]}
    )
    token = first.structured_content["confirm_token"]
    assert second.structured_content["confirm_token"] == token
    assert route.call_count == 0

    await client.call_tool(
        "nv_set_namespace_tags",
        {"namespace": "prod", "tags": ["PCI", "GDPR", "PCI"], "confirm": token},
    )
    assert json.loads(route.calls.last.request.read())["config"]["tags"] == ["GDPR", "PCI"]


async def test_set_namespace_tags_clears_with_empty_list(client, nv_mock: respx.MockRouter) -> None:
    """An explicit empty list is a real value: it clears the tags."""
    route = nv_mock.patch(PATCH_DOMAIN).respond(200, json={})
    args: dict[str, object] = {"namespace": "prod", "tags": []}
    plan = await client.call_tool("nv_set_namespace_tags", args)
    token = plan.structured_content["confirm_token"]

    await client.call_tool("nv_set_namespace_tags", {**args, "confirm": token})
    assert json.loads(route.calls.last.request.read()) == {"config": {"name": "prod", "tags": []}}


async def test_set_namespace_tags_outside_allowed_namespace_refused(
    nv_mock: respx.MockRouter,
) -> None:
    server = build_server(make_settings(allowed_namespaces=("staging",)))
    route = nv_mock.patch(PATCH_DOMAIN).respond(200, json={})
    async with Client(server) as c:
        with pytest.raises(Exception) as excinfo:
            await c.call_tool("nv_set_namespace_tags", {"namespace": "prod", "tags": ["PCI"]})
    assert "outside NV_ALLOWED_NAMESPACES" in str(excinfo.value)
    assert route.call_count == 0


# --- nv_update_scan_config ---------------------------------------------------


async def test_update_scan_config_preview_sends_nothing(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_SCAN_CONFIG).respond(200, json={})
    result = await client.call_tool("nv_update_scan_config", {"auto_scan": True})
    body = result.structured_content
    assert body["status"] == "confirmation_required"
    assert len(body["confirm_token"]) == 12
    assert route.call_count == 0


async def test_update_scan_config_confirmed_applies(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_SCAN_CONFIG).respond(200, json={})
    args = {"auto_scan": True, "enable_auto_scan_host": False}
    plan = await client.call_tool("nv_update_scan_config", args)
    token = plan.structured_content["confirm_token"]

    result = await client.call_tool("nv_update_scan_config", {**args, "confirm": token})
    assert result.structured_content["status"] == "applied"
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.read()) == {
        "config": {"auto_scan": True, "enable_auto_scan_host": False}
    }


async def test_update_scan_config_sends_only_provided_fields(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.patch(PATCH_SCAN_CONFIG).respond(200, json={})
    args = {"enable_auto_scan_workload": False}
    plan = await client.call_tool("nv_update_scan_config", args)
    token = plan.structured_content["confirm_token"]

    await client.call_tool("nv_update_scan_config", {**args, "confirm": token})
    sent = json.loads(route.calls.last.request.read())
    assert sent == {"config": {"enable_auto_scan_workload": False}}
    assert "auto_scan" not in sent["config"]
    assert "enable_auto_scan_host" not in sent["config"]


async def test_update_scan_config_no_fields_raises(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_SCAN_CONFIG).respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_scan_config", {})
    assert "needs at least one field to change" in str(excinfo.value)
    assert route.call_count == 0


# --- module-wide guarantees --------------------------------------------------


async def test_system_write_token_is_bound_to_arguments(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.patch(PATCH_SCAN_CONFIG).respond(200, json={})
    stale = confirm_token(
        "nv_update_scan_config",
        "cluster scan configuration",
        {"config": {"auto_scan": False}},
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_scan_config", {"auto_scan": True, "confirm": stale})
    assert "confirm token mismatch" in str(excinfo.value)
    assert route.call_count == 0


async def test_system_write_hidden_when_read_only(nv_mock: respx.MockRouter) -> None:
    server = build_server(make_settings(read_only=True, toolsets=DEFAULT_TOOLSETS))
    async with Client(server) as c:
        names = {t.name for t in await c.list_tools()}
    assert "nv_get_system_summary" in names
    assert "nv_update_system_config" not in names
    assert "nv_set_namespace_tags" not in names
    assert "nv_update_scan_config" not in names


async def test_system_write_error_codes_classify(client, nv_mock: respx.MockRouter) -> None:
    """code=6 is a validation error, code=25 a permission error."""
    invalid = {"code": 6, "error": "Request in wrong format"}
    denied = {"code": 25, "error": "Object access denied"}
    assert isinstance(classify(400, invalid), ValidationError_)
    assert isinstance(classify(403, denied), PermissionError_)

    route = nv_mock.patch(PATCH_SCAN_CONFIG).respond(400, json=invalid)
    args = {"auto_scan": True}
    plan = await client.call_tool("nv_update_scan_config", args)
    token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_update_scan_config", {**args, "confirm": token})
    assert "code=6" in str(excinfo.value)
    assert route.call_count == 1

    nv_mock.patch(PATCH_DOMAIN).respond(403, json=denied)
    tag_args = {"namespace": "prod", "tags": ["PCI"]}
    plan = await client.call_tool("nv_set_namespace_tags", tag_args)
    tag_token = plan.structured_content["confirm_token"]
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_set_namespace_tags", {**tag_args, "confirm": tag_token})
    assert "code=25" in str(excinfo.value)


async def test_system_write_annotations_declare_reversible_mutation(client) -> None:
    tools = {t.name: t for t in await client.list_tools()}
    for name in (
        "nv_update_system_config",
        "nv_set_namespace_tags",
        "nv_update_scan_config",
    ):
        annotations = tools[name].annotations
        assert annotations.readOnlyHint is False
        assert annotations.destructiveHint is False
        assert annotations.idempotentHint is True
