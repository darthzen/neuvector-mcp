"""policy_read toolset contract tests.

Every request is served by respx from tests/fixtures; nothing touches a network.
List-tool tests assert the outgoing query string as well as the projection,
because a wrong ``f_*`` name is the defect a response-only assertion cannot see.
"""

from __future__ import annotations

import json

import pytest
import respx

from conftest import fixture

pytestmark = pytest.mark.asyncio

RULES = "/v1/policy/rule"
RESPONSE_RULES = "/v1/response/rule"
DLP_SENSORS = "/v1/dlp/sensor"
WAF_SENSORS = "/v1/waf/sensor"
WAF_GROUPS = "/v1/waf/group"
WAF_RULES = "/v1/waf/rule"
ADMISSION_STATE = "/v1/admission/state"
ADMISSION_RULES = "/v1/admission/rules"
ASSESS = "/v1/assess/admission/rule"


# --- nv_list_network_rules -----------------------------------------------------
async def test_list_network_rules_sends_scope_and_filters(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get(RULES).respond(200, json=fixture("policy_rules"))
    result = await client.call_tool(
        "nv_list_network_rules",
        {
            "scope": "fed",
            "from_group": "nv.api.prod",
            "to_group": "nv.postgres.prod",
            "action": "allow",
            "cfg_type": "learned",
            "limit": 10,
        },
    )

    params = route.calls.last.request.url.params
    assert params["scope"] == "fed"
    assert params["f_from"] == "nv.api.prod"
    assert params["f_to"] == "nv.postgres.prod"
    assert params["f_action"] == "allow"
    assert params["f_cfg_type"] == "learned"
    assert params["start"] == "0"
    assert params["limit"] == "11", "must over-fetch by one to detect truncation"

    assert result.data.scope == "fed"
    assert [r.id for r in result.data.rules] == [10001, 20004, 20005]
    assert result.data.rules[0].from_group == "nv.api.prod"
    assert result.data.rules[0].to_group == "nv.postgres.prod"
    assert result.data.rules[0].learned is True
    assert result.data.rules[0].cfg_type == "learned"
    assert result.data.rules[1].cfg_type == "user_created"
    assert result.data.rules[2].disable is True


async def test_list_network_rules_scope_parameter(client, nv_mock: respx.MockRouter) -> None:
    """scope is an 'extra' query parameter, never an f_ filter, and defaults to local."""
    route = nv_mock.get(RULES).respond(200, json={"rules": []})
    await client.call_tool("nv_list_network_rules", {})
    params = route.calls.last.request.url.params
    assert params["scope"] == "local"
    assert "f_scope" not in params


async def test_list_network_rules_order_is_absolute_across_pages(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(RULES).respond(200, json=fixture("policy_rules"))
    result = await client.call_tool("nv_list_network_rules", {"start": 2, "limit": 2})
    assert result.data.rules[0].order == 2
    assert result.data.rules[1].order == 3


async def test_network_rule_projection_preserves_order(client, nv_mock: respx.MockRouter) -> None:
    """The controller's list order is evaluation order and must survive projection."""
    nv_mock.get(RULES).respond(200, json=fixture("policy_rules"))
    result = await client.call_tool("nv_list_network_rules", {"limit": 10})
    assert [r.id for r in result.data.rules] == [10001, 20004, 20005]
    assert [r.order for r in result.data.rules] == [0, 1, 2]


async def test_list_network_rules_truncates(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(RULES).respond(200, json=fixture("policy_rules"))
    result = await client.call_tool("nv_list_network_rules", {"limit": 2})

    assert route.calls.last.request.url.params["limit"] == "3"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint
    assert "evaluation order" in result.data.page.hint


# --- nv_get_network_rule -------------------------------------------------------
async def test_get_network_rule_projects(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{RULES}/20004").respond(200, json=fixture("policy_rule"))
    result = await client.call_tool("nv_get_network_rule", {"rule_id": 20004})
    assert result.data.id == 20004
    assert result.data.ports == "tcp/443,tcp/8443"
    assert result.data.applications == ["HTTPS"]
    assert result.data.match_counter == 91
    assert result.data.order == 0, "a single fetch carries no evaluation position"


async def test_get_network_rule_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{RULES}/99").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_network_rule", {"rule_id": 99})
    assert "no network rule with id 99" in str(excinfo.value)


async def test_get_network_rule_access_denied_is_classified(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(f"{RULES}/20004").respond(
        403, json={"code": 25, "error": "Object access denied", "message": "policy"}
    )
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_network_rule", {"rule_id": 20004})
    assert "code=25" in str(excinfo.value)


# --- nv_get_process_profile ----------------------------------------------------
async def test_get_process_profile_projects_entries(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/process_profile/nv.api.prod").respond(200, json=fixture("process_profile"))
    result = await client.call_tool("nv_get_process_profile", {"group_name": "nv.api.prod"})

    assert result.data.group == "nv.api.prod"
    assert result.data.mode == "Protect"
    assert result.data.hash_enabled is True
    assert result.data.entries_total == 3
    assert result.data.entries_truncated is False
    assert [e.name for e in result.data.entries] == ["python3", "sh", "curl"]
    assert result.data.entries[1].action == "deny"
    assert result.data.entries[1].uid == 0
    assert result.data.entries[2].cfg_type == "system_defined"


async def test_get_process_profile_caps_entries(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/process_profile/nv.api.prod").respond(200, json=fixture("process_profile"))
    result = await client.call_tool(
        "nv_get_process_profile", {"group_name": "nv.api.prod", "max_entries": 2}
    )
    assert result.data.entries_total == 3
    assert result.data.entries_truncated is True
    assert len(result.data.entries) == 2


async def test_get_process_profile_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/process_profile/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_process_profile", {"group_name": "nope"})
    assert "no process profile for group" in str(excinfo.value)


# --- nv_get_file_monitor_profile ----------------------------------------------
async def test_get_file_monitor_profile_reads_filters_key(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/file_monitor/nv.api.prod").respond(200, json=fixture("file_monitor_profile"))
    result = await client.call_tool("nv_get_file_monitor_profile", {"group_name": "nv.api.prod"})

    assert result.data.group == "nv.api.prod"
    assert result.data.envelope_keys == ["filters"]
    assert result.data.filters_total == 2
    assert result.data.filters_truncated is False
    assert result.data.filters[0].filter == "/etc/passwd"
    assert result.data.filters[0].behavior == "block"
    assert result.data.filters[1].recursive is True
    assert result.data.filters[1].applications == ["python3"]


async def test_get_file_monitor_profile_reads_nested_profile_key(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get("/v1/file_monitor/nv.api.prod").respond(
        200,
        json={
            "profile": {
                "filters": [
                    {
                        "filter": "/var/lib/secrets",
                        "recursive": True,
                        "behavior": "monitor",
                        "applications": [],
                        "group": "nv.api.prod",
                    }
                ]
            }
        },
    )
    result = await client.call_tool(
        "nv_get_file_monitor_profile", {"group_name": "nv.api.prod", "max_filters": 1}
    )
    assert result.data.envelope_keys == ["profile"]
    assert result.data.filters_total == 1
    assert result.data.filters[0].filter == "/var/lib/secrets"


async def test_get_file_monitor_profile_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get("/v1/file_monitor/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_file_monitor_profile", {"group_name": "nope"})
    assert "no file monitor profile for group" in str(excinfo.value)


# --- nv_list_response_rules ----------------------------------------------------
async def test_list_response_rules_sends_scope_and_filters(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get(RESPONSE_RULES).respond(200, json=fixture("response_rules"))
    result = await client.call_tool(
        "nv_list_response_rules",
        {"scope": "fed", "event": "security-event", "group": "nv.api.prod", "limit": 10},
    )

    params = route.calls.last.request.url.params
    assert params["scope"] == "fed"
    assert params["f_event"] == "security-event"
    assert params["f_group"] == "nv.api.prod"
    assert params["limit"] == "11"

    assert result.data.scope == "fed"
    assert [r.order for r in result.data.rules] == [0, 1, 2]
    assert result.data.rules[0].actions == ["quarantine", "webhook"]
    assert result.data.rules[0].webhooks == ["soc-slack"]
    assert result.data.rules[1].disable is True


async def test_response_rule_conditions_are_flattened(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(RESPONSE_RULES).respond(200, json=fixture("response_rules"))
    result = await client.call_tool("nv_list_response_rules", {"limit": 10})
    assert result.data.rules[0].conditions == [
        "name=Kubernetes.Privileged.Escalation",
        "level=Critical",
    ]
    assert result.data.rules[1].conditions == []


async def test_list_response_rules_truncates(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(RESPONSE_RULES).respond(200, json=fixture("response_rules"))
    result = await client.call_tool("nv_list_response_rules", {"limit": 2})
    assert route.calls.last.request.url.params["limit"] == "3"
    assert result.data.page.truncated is True
    assert "start=2" in result.data.page.hint


# --- nv_list_dlp_sensors -------------------------------------------------------
async def test_list_dlp_sensors_projects_names(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(DLP_SENSORS).respond(200, json=fixture("dlp_sensors"))
    result = await client.call_tool("nv_list_dlp_sensors", {"name_prefix": "acme-", "limit": 10})

    params = route.calls.last.request.url.params
    assert params["f_name"] == "prefix,acme-"
    assert params["limit"] == "11"

    assert [s.name for s in result.data.sensors] == [
        "sensor.creditcard",
        "acme-customer-ids",
        "acme-secrets",
    ]
    assert result.data.sensors[0].predefined is True
    assert result.data.sensors[0].rule_count == 2
    assert result.data.sensors[2].rule_count == 0


async def test_list_dlp_sensors_sends_no_scope_param(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(DLP_SENSORS).respond(200, json={"sensors": []})
    await client.call_tool("nv_list_dlp_sensors", {})
    assert "scope" not in route.calls.last.request.url.params


async def test_list_dlp_sensors_has_no_scope_argument(client) -> None:
    """Appendix A documents no scope on GET /v1/dlp/sensor; the schema must not offer one."""
    tools = {t.name: t for t in await client.list_tools()}
    properties = tools["nv_list_dlp_sensors"].inputSchema["properties"]
    assert "scope" not in properties
    assert "scope" in tools["nv_list_waf_sensors"].inputSchema["properties"]


async def test_list_dlp_sensors_truncates(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(DLP_SENSORS).respond(200, json=fixture("dlp_sensors"))
    result = await client.call_tool("nv_list_dlp_sensors", {"limit": 2})
    assert result.data.page.truncated is True
    assert "More DLP sensors exist" in result.data.page.hint


# --- nv_list_waf_sensors -------------------------------------------------------
async def test_list_waf_sensors_sends_scope(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(WAF_SENSORS).respond(200, json=fixture("waf_sensors"))
    result = await client.call_tool(
        "nv_list_waf_sensors", {"scope": "fed", "name_prefix": "acme-", "limit": 10}
    )

    params = route.calls.last.request.url.params
    assert params["scope"] == "fed"
    assert params["f_name"] == "prefix,acme-"
    assert result.data.scope == "fed"
    assert [s.name for s in result.data.sensors] == [
        "sensor.log4shell",
        "acme-sqli",
        "acme-xss",
    ]
    assert result.data.sensors[1].rule_count == 2


async def test_list_waf_sensors_truncates(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(WAF_SENSORS).respond(200, json=fixture("waf_sensors"))
    result = await client.call_tool("nv_list_waf_sensors", {"limit": 2})
    assert route.calls.last.request.url.params["limit"] == "3"
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint


# --- nv_get_waf_sensor ---------------------------------------------------------
async def test_get_waf_sensor_returns_pattern_bodies(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{WAF_SENSORS}/sensor.log4shell").respond(200, json=fixture("waf_sensor_detail"))
    result = await client.call_tool("nv_get_waf_sensor", {"sensor_name": "sensor.log4shell"})

    assert result.data.name == "sensor.log4shell"
    assert result.data.groups == ["nv.api.prod", "nv.web.prod"]
    assert [r.name for r in result.data.rules] == ["rule.log4shell", "rule.log4shell-url"]
    # The list tool deliberately omits regex bodies; this one must return them.
    assert result.data.rules[0].patterns[0].value == "\\$\\{jndi:"
    assert result.data.rules[0].patterns[0].context == "header"
    assert result.data.rules[0].id == 40000


async def test_get_waf_sensor_reads_predefine_not_predefined(
    client, nv_mock: respx.MockRouter
) -> None:
    # The controller field is 'predefine'. Reading 'predefined' would silently
    # report every shipped sensor as user-editable.
    nv_mock.get(f"{WAF_SENSORS}/sensor.log4shell").respond(200, json=fixture("waf_sensor_detail"))
    result = await client.call_tool("nv_get_waf_sensor", {"sensor_name": "sensor.log4shell"})
    assert result.data.predefined is True


async def test_get_waf_sensor_preserves_negative_op(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{WAF_SENSORS}/sensor.log4shell").respond(200, json=fixture("waf_sensor_detail"))
    result = await client.call_tool("nv_get_waf_sensor", {"sensor_name": "sensor.log4shell"})
    ops = [p.op for p in result.data.rules[1].patterns]
    assert ops == ["regex", "!regex"]


async def test_get_waf_sensor_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{WAF_SENSORS}/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_waf_sensor", {"sensor_name": "nope"})
    assert "nope" in str(excinfo.value)


# --- nv_list_waf_groups --------------------------------------------------------
async def test_list_waf_groups_sends_scope_and_projects_bindings(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get(WAF_GROUPS).respond(200, json=fixture("waf_groups"))
    result = await client.call_tool("nv_list_waf_groups", {"scope": "fed"})

    assert route.calls.last.request.url.params["scope"] == "fed"
    assert result.data.scope == "fed"
    assert [g.name for g in result.data.groups] == [
        "nv.api.prod",
        "nv.web.prod",
        "nv.cache.prod",
        "containers",
    ]
    assert result.data.groups[0].sensors[0].action == "deny"
    # 'exist' false marks a binding pointing at a deleted sensor.
    assert result.data.groups[1].sensors[1].exist is False


async def test_list_waf_groups_bound_only_filters_unbound(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(WAF_GROUPS).respond(200, json=fixture("waf_groups"))
    result = await client.call_tool("nv_list_waf_groups", {"bound_only": True})
    assert [g.name for g in result.data.groups] == ["nv.api.prod", "nv.web.prod"]


async def test_list_waf_groups_truncates(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(WAF_GROUPS).respond(200, json=fixture("waf_groups"))
    result = await client.call_tool("nv_list_waf_groups", {"limit": 2})
    assert result.data.page.truncated is True
    assert result.data.page.returned == 2
    assert "start=2" in result.data.page.hint


# --- nv_get_waf_group ----------------------------------------------------------
async def test_get_waf_group_projects_one_group(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{WAF_GROUPS}/nv.api.prod").respond(
        200, json={"waf_group": fixture("waf_groups")["waf_groups"][0]}
    )
    result = await client.call_tool("nv_get_waf_group", {"group_name": "nv.api.prod"})
    assert result.data.name == "nv.api.prod"
    assert result.data.status is True
    assert [s.name for s in result.data.sensors] == ["sensor.log4shell"]


async def test_get_waf_group_missing_raises(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(f"{WAF_GROUPS}/nope").respond(200, json={})
    with pytest.raises(Exception) as excinfo:
        await client.call_tool("nv_get_waf_group", {"group_name": "nope"})
    assert "nope" in str(excinfo.value)


# --- nv_list_waf_rules ---------------------------------------------------------
async def test_list_waf_rules_projects_catalogue(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(WAF_RULES).respond(200, json=fixture("waf_rules"))
    result = await client.call_tool("nv_list_waf_rules", {})
    assert result.data.page.returned == 3
    assert result.data.rules[0].id == 40000
    assert result.data.rules[0].patterns[0].context == "header"
    # A rule with no patterns must project as an empty list, not fail.
    assert result.data.rules[2].patterns == []


async def test_list_waf_rules_truncates(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(WAF_RULES).respond(200, json=fixture("waf_rules"))
    result = await client.call_tool("nv_list_waf_rules", {"limit": 2})
    assert result.data.page.truncated is True
    assert "start=2" in result.data.page.hint


# --- nv_get_admission_state ----------------------------------------------------
async def test_get_admission_state_projects_state_and_k8s_env(
    client, nv_mock: respx.MockRouter
) -> None:
    nv_mock.get(ADMISSION_STATE).respond(200, json=fixture("admission_state"))
    result = await client.call_tool("nv_get_admission_state", {})
    assert result.data.enable is True
    assert result.data.mode == "protect"
    assert result.data.default_action == "allow"
    assert result.data.adm_client_mode == "service"
    assert result.data.adm_svc_type == "ClusterIP"
    assert result.data.k8s_env is True


async def test_get_admission_state_handles_missing_state(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(ADMISSION_STATE).respond(200, json={})
    result = await client.call_tool("nv_get_admission_state", {})
    assert result.data.enable is False
    assert result.data.mode == ""
    assert result.data.k8s_env is False


# --- nv_list_admission_rules ---------------------------------------------------
async def test_list_admission_rules_sends_scope_and_filters(
    client, nv_mock: respx.MockRouter
) -> None:
    route = nv_mock.get(ADMISSION_RULES).respond(200, json=fixture("admission_rules"))
    result = await client.call_tool(
        "nv_list_admission_rules",
        {
            "scope": "fed",
            "rule_type": "deny",
            "cfg_type": "user_created",
            "category": "Kubernetes",
            "limit": 10,
        },
    )

    params = route.calls.last.request.url.params
    assert params["scope"] == "fed"
    assert params["f_rule_type"] == "deny"
    assert params["f_cfg_type"] == "user_created"
    assert params["f_category"] == "Kubernetes"
    assert params["limit"] == "11"

    assert result.data.scope == "fed"
    assert [r.id for r in result.data.rules] == [1000, 1001, 1002]
    assert result.data.rules[0].critical is True
    assert result.data.rules[0].containers == ["containers", "init_containers"]
    assert result.data.rules[2].disable is True


async def test_admission_criteria_flatten_sub_criteria(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(ADMISSION_RULES).respond(200, json=fixture("admission_rules"))
    result = await client.call_tool("nv_list_admission_rules", {"limit": 10})
    criteria = result.data.rules[0].criteria
    assert criteria[0] == "runAsPrivileged = true"
    assert criteria[1] == (
        "imageRegistry containsAny docker.io (sub: publishDays >= 30; imageScanned = false)"
    )
    assert result.data.rules[0].criteria_total == 3
    assert result.data.rules[0].criteria_truncated is False


async def test_list_admission_rules_caps_criteria(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.get(ADMISSION_RULES).respond(200, json=fixture("admission_rules"))
    result = await client.call_tool("nv_list_admission_rules", {"limit": 10, "max_criteria": 1})
    assert len(result.data.rules[0].criteria) == 1
    assert result.data.rules[0].criteria_total == 3
    assert result.data.rules[0].criteria_truncated is True


async def test_list_admission_rules_truncates(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.get(ADMISSION_RULES).respond(200, json=fixture("admission_rules"))
    result = await client.call_tool("nv_list_admission_rules", {"limit": 2})
    assert route.calls.last.request.url.params["limit"] == "3"
    assert result.data.page.truncated is True
    assert "narrow with rule_type/cfg_type" in result.data.page.hint


# --- nv_assess_admission_rule --------------------------------------------------
async def test_assess_admission_rule_sends_config_body(client, nv_mock: respx.MockRouter) -> None:
    route = nv_mock.post(ASSESS).respond(200, json=fixture("admission_assessment"))
    await client.call_tool(
        "nv_assess_admission_rule",
        {
            "rule_type": "deny",
            "criteria": [{"name": "runAsPrivileged", "op": "=", "value": "true"}],
        },
    )

    assert route.calls.last.request.method == "POST"
    assert json.loads(route.calls.last.request.read()) == {
        "config": {
            "category": "Kubernetes",
            "rule_type": "deny",
            "cfg_type": "user_created",
            "criteria": [
                {
                    "name": "runAsPrivileged",
                    "op": "=",
                    "value": "true",
                    "sub_criteria": [],
                }
            ],
            "containers": ["containers"],
            "rule_mode": "",
            "comment": "",
            "disable": False,
        }
    }


async def test_assess_admission_rule_counts_denials(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post(ASSESS).respond(200, json=fixture("admission_assessment"))
    result = await client.call_tool(
        "nv_assess_admission_rule",
        {
            "rule_type": "deny",
            "criteria": [{"name": "runAsPrivileged", "op": "=", "value": "true"}],
        },
    )

    assert result.data.global_mode == "protect"
    assert result.data.props_unavailable == ["imageSigned"]
    assert result.data.results_total == 3
    assert result.data.results_truncated is False
    assert result.data.denied_count == 2
    assert result.data.results[0].allowed is False
    assert result.data.results[0].matched_rules[0].id == 1000
    assert result.data.results[0].matched_rules[0].container_image.startswith("registry.")


async def test_assess_admission_rule_caps_results(client, nv_mock: respx.MockRouter) -> None:
    nv_mock.post(ASSESS).respond(200, json=fixture("admission_assessment"))
    result = await client.call_tool(
        "nv_assess_admission_rule",
        {
            "rule_type": "deny",
            "criteria": [{"name": "runAsPrivileged", "op": "=", "value": "true"}],
            "max_results": 1,
        },
    )
    assert result.data.results_total == 3
    assert result.data.results_truncated is True
    assert len(result.data.results) == 1
    assert result.data.denied_count == 1


async def test_assess_admission_rule_has_no_confirm_argument(client) -> None:
    """It is a dry run, so gate rule R5 forbids a confirm argument on it."""
    tools = {t.name: t for t in await client.list_tools()}
    assert "confirm" not in tools["nv_assess_admission_rule"].inputSchema["properties"]


async def test_assess_admission_rule_is_read_only_hint(client) -> None:
    """A non-mutating POST is still read-only: readOnlyHint describes the environment."""
    tools = {t.name: t for t in await client.list_tools()}
    annotations = tools["nv_assess_admission_rule"].annotations
    assert annotations.readOnlyHint is True
    assert annotations.destructiveHint is False
    assert annotations.idempotentHint is True
