"""Controller client contract tests.

These pin `client.py` (SPEC 7.2, appendix D). Every request is served by
`respx`; nothing here touches a real host. Retry tests patch
`neuvector_mcp.client.asyncio.sleep` so the suite never waits for real backoff.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx
import pytest
import respx

from conftest import CONTROLLER, make_settings
from neuvector_mcp.client import FILTER_OPS, NeuVectorClient, build_query
from neuvector_mcp.errors import (
    AuthError,
    NeuVectorMCPError,
    NotFoundError,
    PermissionError_,
    UpstreamError,
)

APIKEY_HEADER = "X-Auth-Apikey"
TOKEN_HEADER = "X-Auth-Token"

PASSWORD_MODE: dict[str, Any] = {
    "auth_mode": "password",
    "username": "nvadmin",
    "password": "hunter2",
    "api_access_key": None,
    "api_secret_key": None,
}


# --- fixtures -----------------------------------------------------------------


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    """respx router bound to the controller base URL. No route is pre-stubbed."""
    with respx.mock(base_url=CONTROLLER, assert_all_called=False) as mock_router:
        yield mock_router


@pytest.fixture
async def make_client(
    router: respx.MockRouter,
) -> AsyncIterator[Callable[..., NeuVectorClient]]:
    """Factory building a NeuVectorClient straight from Settings, no MCP server."""
    opened: list[httpx.AsyncClient] = []

    def _build(**overrides: Any) -> NeuVectorClient:
        settings = make_settings(**overrides)
        http = NeuVectorClient.build_http_client(settings)
        opened.append(http)
        return NeuVectorClient(settings, http)

    yield _build

    for http in opened:
        await http.aclose()


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record backoff delays instead of sleeping them."""
    recorded: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr("neuvector_mcp.client.asyncio.sleep", _fake_sleep)
    return recorded


# --- build_query (pure) -------------------------------------------------------


def test_build_query_empty() -> None:
    assert build_query() == {}


def test_build_query_paging() -> None:
    assert build_query(start=0, limit=50) == {"start": "0", "limit": "50"}


def test_build_query_negative_start_is_passed_through() -> None:
    # D.2.1: a negative start flips the controller to backward paging. The
    # client does not second-guess it.
    assert build_query(start=-10)["start"] == "-10"


def test_build_query_implicit_eq() -> None:
    assert build_query(filters={"domain": "prod"}) == {"f_domain": "prod"}


def test_build_query_explicit_operator() -> None:
    assert build_query(filters={"high": "gte,5"}) == {"f_high": "gte,5"}


@pytest.mark.parametrize("op", sorted(FILTER_OPS))
def test_build_query_accepts_every_documented_operator(op: str) -> None:
    assert build_query(filters={"x": f"{op},v"}) == {"f_x": f"{op},v"}


def test_build_query_rejects_unknown_operator() -> None:
    with pytest.raises(ValueError) as excinfo:
        build_query(filters={"x": "like,y"})
    message = str(excinfo.value)
    assert "like" in message
    for valid in FILTER_OPS:
        assert valid in message


def test_build_query_rejects_bare_comma_value() -> None:
    # D.2.2: the controller splits unconditionally on ',', so a plain value
    # containing a comma cannot be expressed and must not be sent silently.
    with pytest.raises(ValueError):
        build_query(filters={"name": "api,web"})


def test_build_query_multiple_filters() -> None:
    params = build_query(filters={"domain": "prod", "name": "prefix,api-"})
    assert params == {"f_domain": "prod", "f_name": "prefix,api-"}


def test_build_query_sort() -> None:
    assert build_query(sort={"reported_at": "desc"}) == {"s_reported_at": "desc"}
    assert build_query(sort={"reported_at": "asc"}) == {"s_reported_at": "asc"}

    with pytest.raises(ValueError) as excinfo:
        build_query(sort={"reported_at": "sideways"})  # type: ignore[dict-item]
    assert "asc" in str(excinfo.value)


def test_build_query_extra_booleans_lowercased() -> None:
    assert build_query(extra={"brief": True}) == {"brief": "true"}
    assert build_query(extra={"brief": False}) == {"brief": "false"}


def test_build_query_extra_scalars_stringified() -> None:
    assert build_query(extra={"scope": "local", "view": "pod", "depth": 2}) == {
        "scope": "local",
        "view": "pod",
        "depth": "2",
    }


def test_build_query_combined() -> None:
    assert build_query(
        start=10,
        limit=51,
        filters={"domain": "prod"},
        sort={"reported_at": "desc"},
        extra={"view": "pod", "brief": True},
    ) == {
        "start": "10",
        "limit": "51",
        "f_domain": "prod",
        "s_reported_at": "desc",
        "view": "pod",
        "brief": "true",
    }


# --- auth ---------------------------------------------------------------------


async def test_apikey_header_format(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    route = router.get("/v1/host").respond(200, json={"hosts": []})
    await make_client().request("GET", "/v1/host")

    headers = route.calls.last.request.headers
    assert headers[APIKEY_HEADER] == "test-access:test-secret"
    assert TOKEN_HEADER not in headers, "D.1.1: never send both auth headers"


async def test_apikey_login_probes_summary(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    route = router.get("/v1/system/summary").respond(200, json={"summary": {"hosts": 3}})
    auth_route = router.post("/v1/auth").respond(200, json={})

    identity = await make_client().login()

    assert route.call_count == 1
    assert auth_route.call_count == 0, "apikey auth is stateless; never POST /v1/auth"
    assert identity["mode"] == "apikey"
    assert identity["username"] == "test-access"
    assert route.calls.last.request.headers[APIKEY_HEADER] == "test-access:test-secret"


async def test_apikey_login_failure_raises(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/system/summary").respond(401, json={"code": 3, "error": "Auth failed"})
    with pytest.raises(AuthError):
        await make_client().login()


async def test_password_login_posts_auth_and_caches_token(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    auth_route = router.post("/v1/auth").respond(
        200,
        json={
            "token": {
                "token": "sess-token-1",
                "fullname": "admin",
                "global_permissions": [{"id": "config"}, {"id": "rt_scan"}],
            }
        },
    )
    summary_route = router.get("/v1/system/summary").respond(200, json={"summary": {}})

    client = make_client(**PASSWORD_MODE)
    identity = await client.login()

    assert auth_route.call_count == 1
    login_request = auth_route.calls.last.request
    assert json.loads(login_request.content) == {
        "password": {"username": "nvadmin", "password": "hunter2"}
    }
    assert APIKEY_HEADER not in login_request.headers
    assert identity["mode"] == "password"
    assert identity["username"] == "admin"
    assert identity["global_permissions"] == ["config", "rt_scan"]

    await client.request("GET", "/v1/system/summary")
    headers = summary_route.calls.last.request.headers
    assert headers[TOKEN_HEADER] == "sess-token-1"
    assert APIKEY_HEADER not in headers, "D.1.1: never send both auth headers"


async def test_password_login_without_token_raises_auth_error(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.post("/v1/auth").respond(200, json={"token": {}})
    with pytest.raises(AuthError) as excinfo:
        await make_client(**PASSWORD_MODE).login()
    assert "no token" in str(excinfo.value)


async def test_password_login_rejected_is_classified(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.post("/v1/auth").respond(401, json={"code": 3, "error": "Authentication failed"})
    with pytest.raises(AuthError) as excinfo:
        await make_client(**PASSWORD_MODE).login()
    assert "code=3" in str(excinfo.value)


async def test_logout_deletes_auth_in_password_mode(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.post("/v1/auth").respond(200, json={"token": {"token": "sess-token-1"}})
    delete_route = router.delete("/v1/auth").respond(200)

    client = make_client(**PASSWORD_MODE)
    await client.login()
    await client.logout()

    assert delete_route.call_count == 1
    assert delete_route.calls.last.request.headers[TOKEN_HEADER] == "sess-token-1"

    await client.logout()
    assert delete_route.call_count == 1, "the token is cleared; a second logout is a no-op"


async def test_logout_is_noop_in_apikey_mode(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    delete_route = router.delete("/v1/auth").respond(200)
    await make_client().logout()
    assert delete_route.call_count == 0


# --- retry --------------------------------------------------------------------


async def test_retries_transient_status(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    route = router.get("/v1/host").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(503),
            httpx.Response(200, json={"hosts": ["h1"]}),
        ]
    )

    result = await make_client().request("GET", "/v1/host")

    assert route.call_count == 3
    assert result == {"hosts": ["h1"]}
    assert sleeps == [0.5, 1.0], "SPEC 7.2: 0.5s then 1.0s exponential backoff"


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_retries_every_transient_status(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
    status: int,
) -> None:
    route = router.get("/v1/host").mock(
        side_effect=[httpx.Response(status), httpx.Response(200, json={"hosts": []})]
    )
    await make_client().request("GET", "/v1/host")
    assert route.call_count == 2
    assert sleeps == [0.5]


@pytest.mark.parametrize("code", [8, 9, 11, 19, 24, 55])
async def test_retries_transient_code(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
    code: int,
) -> None:
    route = router.get("/v1/host").mock(
        side_effect=[
            httpx.Response(500, json={"code": code, "error": "cluster busy"}),
            httpx.Response(200, json={"hosts": []}),
        ]
    )
    result = await make_client().request("GET", "/v1/host")

    assert route.call_count == 2
    assert result == {"hosts": []}
    assert sleeps == [0.5]


async def test_does_not_retry_permanent_code(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    route = router.get("/v1/group/nope").respond(404, json={"code": 7, "error": "Object not found"})
    with pytest.raises(NotFoundError):
        await make_client().request("GET", "/v1/group/nope")

    assert route.call_count == 1
    assert sleeps == []


@pytest.mark.parametrize("code", [4, 25, 30, 46])
async def test_does_not_retry_structural_codes(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
    code: int,
) -> None:
    route = router.get("/v1/host").respond(500, json={"code": code, "error": "refused"})
    with pytest.raises(NeuVectorMCPError):
        await make_client().request("GET", "/v1/host")
    assert route.call_count == 1
    assert sleeps == []


async def test_gives_up_after_three_attempts(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    route = router.get("/v1/host").respond(503)

    started = time.perf_counter()
    with pytest.raises(UpstreamError):
        await make_client().request("GET", "/v1/host")
    elapsed = time.perf_counter() - started

    assert route.call_count == 3, "SPEC 7.2: exactly 3 attempts, never a fourth"
    assert sleeps == [0.5, 1.0]
    assert elapsed < 0.5, "backoff must be patched out; the suite never really sleeps"


async def test_retries_connection_errors(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    route = router.get("/v1/host").mock(
        side_effect=[
            httpx.ConnectError("no route to host"),
            httpx.ConnectError("no route to host"),
            httpx.Response(200, json={"hosts": []}),
        ]
    )
    result = await make_client().request("GET", "/v1/host")
    assert route.call_count == 3
    assert result == {"hosts": []}
    assert sleeps == [0.5, 1.0]


async def test_timeout_is_retried_then_surfaces_as_upstream_error(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    route = router.get("/v1/host").mock(side_effect=httpx.ReadTimeout("timed out"))
    with pytest.raises(UpstreamError) as excinfo:
        await make_client().request("GET", "/v1/host")
    assert route.call_count == 3
    assert "timeout" in str(excinfo.value)
    assert sleeps == [0.5, 1.0]


# --- re-login -----------------------------------------------------------------


async def test_relogin_once_on_401_password_mode(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    auth_route = router.post("/v1/auth").respond(
        200, json={"token": {"token": "fresh-token", "fullname": "admin"}}
    )
    route = router.get("/v1/host").mock(
        side_effect=[
            httpx.Response(401, json={"code": 3, "error": "Authentication failed"}),
            httpx.Response(200, json={"hosts": []}),
        ]
    )

    result = await make_client(**PASSWORD_MODE).request("GET", "/v1/host")

    assert result == {"hosts": []}
    assert auth_route.call_count == 1, "exactly one re-login"
    assert route.call_count == 2, "the original request is retried exactly once"
    assert route.calls[1].request.headers[TOKEN_HEADER] == "fresh-token"
    assert sleeps == [], "a re-login is not a backoff retry"


async def test_no_relogin_loop(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    auth_route = router.post("/v1/auth").respond(
        200, json={"token": {"token": "fresh-token", "fullname": "admin"}}
    )
    route = router.get("/v1/host").respond(401, json={"code": 3, "error": "Auth failed"})

    with pytest.raises(AuthError):
        await make_client(**PASSWORD_MODE).request("GET", "/v1/host")

    assert auth_route.call_count == 1, "never a second re-login"
    assert route.call_count == 2
    assert sleeps == []


async def test_no_relogin_in_apikey_mode(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    auth_route = router.post("/v1/auth").respond(200, json={"token": {"token": "x"}})
    route = router.get("/v1/host").respond(401, json={"code": 3, "error": "Auth failed"})

    with pytest.raises(AuthError):
        await make_client().request("GET", "/v1/host")

    assert route.call_count == 1
    assert auth_route.call_count == 0
    assert sleeps == []


# --- envelopes ----------------------------------------------------------------


async def test_empty_body_is_success(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.patch("/v1/group/g").respond(200)
    assert await make_client().request("PATCH", "/v1/group/g", json={"config": {}}) == {}


async def test_204_body_is_success(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.delete("/v1/group/g").respond(204)
    assert await make_client().request("DELETE", "/v1/group/g") == {}


async def test_206_partial_content_is_success(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    # D.3.2: the controller writes 206 on some list paths. Any 2xx is success.
    router.get("/v1/host").respond(206, json={"hosts": ["h1"]})
    assert await make_client().request("GET", "/v1/host") == {"hosts": ["h1"]}


async def test_request_sends_query_params(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    route = router.get("/v1/host").respond(200, json={"hosts": []})
    params = build_query(start=0, limit=51, filters={"domain": "prod"})
    await make_client().request("GET", "/v1/host", params=params)

    url = route.calls.last.request.url
    assert url.params["start"] == "0"
    assert url.params["limit"] == "51"
    assert url.params["f_domain"] == "prod"


async def test_get_list_unwraps_envelope(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/group").respond(200, json={"groups": [{"name": "a"}, {"name": "b"}]})
    groups = await make_client().get_list("/v1/group", "groups")
    assert groups == [{"name": "a"}, {"name": "b"}]


async def test_get_list_missing_key_returns_empty(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/group").respond(200, json={})
    assert await make_client().get_list("/v1/group", "groups") == []


async def test_get_list_null_key_returns_empty(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/group").respond(200, json={"groups": None})
    assert await make_client().get_list("/v1/group", "groups") == []


async def test_get_list_passes_params(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    route = router.get("/v1/group").respond(200, json={"groups": []})
    await make_client().get_list("/v1/group", "groups", params={"f_domain": "prod"})
    assert route.calls.last.request.url.params["f_domain"] == "prod"


async def test_get_object_unwraps_envelope(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/group/g").respond(200, json={"group": {"name": "g", "kind": "container"}})
    assert await make_client().get_object("/v1/group/g", "group") == {
        "name": "g",
        "kind": "container",
    }


async def test_get_object_missing_key_returns_empty_dict(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/group/g").respond(200, json={})
    assert await make_client().get_object("/v1/group/g", "group") == {}


# --- error classification -----------------------------------------------------


async def test_non_json_body_is_classified(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    router.get("/v1/host").respond(
        500,
        text="<html><body>gateway exploded</body></html>",
        headers={"Content-Type": "text/html"},
    )
    with pytest.raises(UpstreamError) as excinfo:
        await make_client().request("GET", "/v1/host")
    assert "HTTP 500" in str(excinfo.value)
    assert sleeps == []


async def test_classify_prefers_code_over_status(
    router: respx.MockRouter,
    make_client: Callable[..., NeuVectorClient],
    sleeps: list[float],
) -> None:
    # D.4: the HTTP status is chosen per call site; `code` is the stable contract.
    route = router.get("/v1/group/g").respond(500, json={"code": 7, "error": "Object not found"})
    with pytest.raises(NotFoundError):
        await make_client().request("GET", "/v1/group/g")
    assert route.call_count == 1
    assert sleeps == []


async def test_error_message_includes_code_and_controller_text(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v2/workload/x").respond(
        403, json={"code": 25, "error": "Object access denied", "message": "domain prod"}
    )
    with pytest.raises(PermissionError_) as excinfo:
        await make_client().request("GET", "/v2/workload/x")

    message = str(excinfo.value)
    assert "code=25" in message
    assert "Object access denied" in message
    assert "domain prod" in message


async def test_secrets_never_appear_in_error_messages(
    router: respx.MockRouter, make_client: Callable[..., NeuVectorClient]
) -> None:
    router.get("/v1/host").respond(403, json={"code": 25, "error": "Object access denied"})
    with pytest.raises(PermissionError_) as excinfo:
        await make_client().request("GET", "/v1/host")
    assert "test-secret" not in str(excinfo.value)
