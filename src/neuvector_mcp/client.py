"""Async HTTP client for the NeuVector controller REST API.

Responsibilities, and nothing else:

* hold one :class:`httpx.AsyncClient` for the process lifetime
* attach the correct auth header on every request
* re-login exactly once when the controller rejects a session token
* apply the NeuVector query conventions (``start``/``limit``/``f_*``/``s_*``)
* refuse to send a path that escapes the endpoint the caller named
* convert non-2xx responses into typed exceptions from :mod:`.errors`
* never log a secret

Auth header rules (source: controller/rest/auth.go ``restReq2User``):

* API key:  ``X-Auth-Apikey: <access_key>:<secret_key>``  (stateless, no login)
* Password: ``POST /v1/auth`` then ``X-Auth-Token: <token>`` on later calls

The controller checks ``X-Auth-Token`` first and only falls back to
``X-Auth-Apikey``. Never send both.
"""

from __future__ import annotations

import asyncio
import re
import ssl
from collections.abc import Mapping, Sequence
from typing import Any, Literal
from urllib.parse import unquote

import httpx
import structlog

from .config import Settings
from .errors import (
    AuthError,
    NeuVectorMCPError,
    UpstreamError,
    ValidationError_,
    classify,
    is_retryable,
)

log = structlog.get_logger(__name__)

Method = Literal["GET", "POST", "PATCH", "DELETE"]

#: NeuVector filter comparison operators (controller/api/apis.go).
FILTER_OPS: frozenset[str] = frozenset(
    {"eq", "neq", "in", "notin", "gt", "gte", "lt", "lte", "prefix"}
)

_TOKEN_HEADER = "X-Auth-Token"
_APIKEY_HEADER = "X-Auth-Apikey"
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_S = 0.5

#: Characters permitted in an assembled controller path. Every tool builds its
#: path by interpolating a caller-supplied object name into an f-string, e.g.
#: ``f"/v1/group/{group_name}"``. This is the unreserved set plus the sub-delims
#: and ``%``, and deliberately excludes ``?``, ``#``, backslash, whitespace and
#: control characters -- the delimiters that let a name change which endpoint,
#: or which query, the request lands on.
_SAFE_PATH = re.compile(r"^/v[12]/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")


def validate_path(path: str) -> str:
    """Refuse a controller path that escapes the endpoint the tool named.

    ``httpx`` resolves ``..`` against the base URL before the request goes out,
    so an unvalidated object name is an endpoint selector::

        f"/v1/group/{group_name}" with group_name="../../v1/system/config"
        -> https://controller:10443/v1/system/config

    That defeats both the read-only flag and ``NV_TOOLSETS``, which gate which
    *tools* exist rather than which *endpoints* are reachable. It also defeats
    ``NV_ALLOWED_NAMESPACES``, and the confirmation token is derived from the
    same unvalidated string, so the handshake authorises the escape.

    Percent-encoded traversal is rejected too: ``httpx`` forwards ``%2e%2e``
    untouched and the controller is the one that decodes it, so the check runs
    against both the literal path and its decoded form.

    Args:
        path: The assembled path, e.g. ``"/v1/group/nv.api.prod"``.

    Returns:
        ``path`` unchanged. Legitimate names -- including the dots in
        ``nv.api.prod``, the colon in ``sha256:aaa111`` and the slash in a
        repository like ``library/api`` -- pass through byte-for-byte.

    Known limit, deliberate: ``/`` stays legal, because a registry image id IS a
    repository path (``GET /v1/scan/registry/{name}/image/{id}`` with
    ``id="library/api:1.4.2"``). So a name containing ``/`` can still select a
    DEEPER route under the same prefix -- ``nv_delete_registry("reg/scan")``
    reaches ``DELETE /v1/scan/registry/reg/scan`` instead of
    ``DELETE /v1/scan/registry/reg``. That cannot escalate: reaching a
    higher-privilege route means going UP the tree, which needs ``..``, and
    ``..`` is refused. The cost is a mislabelled plan, not a wider blast radius.

    Raises:
        ValidationError_: if the path is malformed or contains a traversal
            segment. Nothing is sent to the controller.
    """
    if not _SAFE_PATH.match(path):
        raise ValidationError_(
            f"refusing to send controller path {path!r}: it is not a well-formed "
            "/v1 or /v2 path, or an argument contained a URL delimiter such as "
            "'?', '#' or whitespace. Nothing was sent to the controller."
        )
    for candidate in (path, unquote(path)):
        if any(segment in ("..", ".") for segment in candidate.split("/")):
            raise ValidationError_(
                f"refusing to send controller path {path!r}: an argument contains a "
                "path traversal segment, which would redirect this call to a "
                "different controller endpoint. Nothing was sent to the controller."
            )
    return path


def build_query(
    *,
    start: int | None = None,
    limit: int | None = None,
    filters: Mapping[str, str] | None = None,
    sort: Mapping[str, Literal["asc", "desc"]] | None = None,
    extra: Mapping[str, str | int | bool] | None = None,
) -> dict[str, str]:
    """Render NeuVector query parameters.

    Filters use the ``f_<field>`` convention. A value may be a bare literal
    (implicit ``eq``) or ``"<op>,<value>"`` where ``<op>`` is one of
    :data:`FILTER_OPS`. Sorts use ``s_<field>=asc|desc``.

    Args:
        start: Zero-based offset. Negative values page backwards (controller
            behaviour), so callers that only want forward paging pass >= 0.
        limit: Maximum items to return. ``0`` means "controller default".
        filters: ``{"domain": "prod"}`` or ``{"cvedb_version": "gte,2024.1"}``.
        sort: ``{"reported_at": "desc"}``.
        extra: Endpoint-specific pairs such as ``{"scope": "local"}`` or
            ``{"view": "pod"}``.

    Returns:
        A flat ``dict[str, str]`` suitable for ``httpx``' ``params=``.

    Raises:
        ValueError: if a filter names an unknown comparison operator.
    """
    params: dict[str, str] = {}
    if start is not None:
        params["start"] = str(start)
    if limit is not None:
        params["limit"] = str(limit)
    for field, value in (filters or {}).items():
        text = str(value)
        if "," in text:
            op, _, rest = text.partition(",")
            if op not in FILTER_OPS:
                raise ValueError(
                    f"filter {field!r} uses unknown operator {op!r}; "
                    f"valid operators: {sorted(FILTER_OPS)}"
                )
            text = f"{op},{rest}"
        params[f"f_{field}"] = text
    for field, direction in (sort or {}).items():
        if direction not in ("asc", "desc"):
            raise ValueError(f"sort {field!r} must be 'asc' or 'desc', got {direction!r}")
        params[f"s_{field}"] = direction
    for key, value in (extra or {}).items():
        params[key] = str(value).lower() if isinstance(value, bool) else str(value)
    return params


class NeuVectorClient:
    """Thin, auth-aware wrapper over the controller REST API."""

    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self._s = settings
        self._http = http
        self._token: str | None = None
        self._login_lock = asyncio.Lock()
        #: Global permissions of the current identity, filled in by :meth:`login`.
        self.identity: dict[str, Any] = {}

    # -- construction -----------------------------------------------------------
    @classmethod
    def build_http_client(cls, settings: Settings) -> httpx.AsyncClient:
        """Create the underlying ``httpx.AsyncClient`` for these settings."""
        verify: bool | ssl.SSLContext | str
        if settings.ca_bundle:
            verify = settings.ca_bundle
        else:
            verify = settings.verify_tls
        return httpx.AsyncClient(
            base_url=settings.controller_url,
            verify=verify,
            timeout=httpx.Timeout(settings.request_timeout_s),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            follow_redirects=False,
        )

    # -- authentication ---------------------------------------------------------
    async def login(self) -> dict[str, Any]:
        """Establish an identity against the controller.

        In ``apikey`` mode no login request is made; the API key is stateless, so
        this method probes ``GET /v1/system/summary`` to fail fast on bad keys.

        In ``password`` mode this posts ``RESTAuthData`` to ``POST /v1/auth`` and
        caches the returned token.

        Returns:
            A dict with ``mode``, ``username`` and ``global_permissions``.

        Raises:
            AuthError: on rejected credentials.
        """
        if self._s.auth_mode == "apikey":
            await self.request("GET", "/v1/system/summary", authenticated=True)
            self.identity = {
                "mode": "apikey",
                "username": self._s.api_access_key,
                "global_permissions": ["unknown (api key)"],
            }
            return self.identity

        payload = {
            "password": {
                "username": self._s.username,
                "password": self._s.password,
            }
        }
        response = await self._http.post("/v1/auth", json=payload)
        if response.status_code != 200:
            raise classify(response.status_code, _safe_json(response))
        token_data = response.json().get("token") or {}
        token = token_data.get("token")
        if not token:
            raise AuthError("POST /v1/auth succeeded but returned no token")
        self._token = token
        self.identity = {
            "mode": "password",
            "username": token_data.get("fullname") or self._s.username,
            "global_permissions": [
                p.get("id") for p in (token_data.get("global_permissions") or [])
            ],
        }
        log.info("nv.login", mode="password", username=self.identity["username"])
        return self.identity

    async def logout(self) -> None:
        """Invalidate a password-mode session token. No-op for API keys."""
        if self._s.auth_mode == "password" and self._token:
            try:
                await self._http.delete("/v1/auth", headers=self._auth_headers())
            except httpx.HTTPError:  # pragma: no cover - best effort
                pass
            self._token = None

    def _auth_headers(self) -> dict[str, str]:
        if self._s.auth_mode == "apikey":
            return {_APIKEY_HEADER: f"{self._s.api_access_key}:{self._s.api_secret_key}"}
        if self._token:
            return {_TOKEN_HEADER: self._token}
        return {}

    # -- request path -----------------------------------------------------------
    async def request(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any | None = None,
        timeout_s: float | None = None,
        authenticated: bool = True,
        retry: bool | None = None,
        _relogin_done: bool = False,
    ) -> Any:
        """Perform one controller call and return the parsed JSON body.

        Args:
            method: HTTP verb.
            path: Absolute controller path beginning with ``/v1/`` or ``/v2/``.
            params: Query parameters, normally produced by :func:`build_query`.
            json: Request body, already shaped as the controller's ``REST*Data``.
            timeout_s: Per-call override; use
                ``settings.long_request_timeout_s`` for scan and bench calls.
            authenticated: Set ``False`` only for ``POST /v1/auth``.
            retry: Whether a transient failure may be re-sent. ``None`` means
                "retry ``GET`` only", which is the right answer for every
                current caller. A non-``GET`` retry can duplicate a write: a
                ``502``/``504`` or ``ERR_FAIL_WRITE_CLUSTER`` is returned after
                the controller has already accepted the request often enough
                that re-sending a ``POST`` risks a second object. Pass ``True``
                only for a write the controller treats as idempotent.
            _relogin_done: Internal recursion guard.

        Returns:
            Parsed JSON, or ``{}`` when the controller returns an empty body
            (common for ``PATCH``/``DELETE``).

        Raises:
            ValidationError_: if ``path`` escapes the endpoint the tool named.
            NeuVectorMCPError: for every non-2xx response, already classified.
        """
        validate_path(path)
        headers = self._auth_headers() if authenticated else {}
        may_retry = method == "GET" if retry is None else retry
        attempt = 0
        last_exc: NeuVectorMCPError | None = None

        while attempt < _MAX_ATTEMPTS:
            attempt += 1
            try:
                response = await self._http.request(
                    method,
                    path,
                    params=dict(params or {}),
                    json=json,
                    headers=headers,
                    timeout=timeout_s or self._s.request_timeout_s,
                )
            except httpx.TimeoutException as exc:
                last_exc = UpstreamError(f"controller timeout on {method} {path}: {exc}")
            except httpx.HTTPError as exc:
                last_exc = UpstreamError(f"controller unreachable on {method} {path}: {exc}")
            else:
                if 200 <= response.status_code < 300:
                    return _safe_json(response) or {}
                body = _safe_json(response)
                if (
                    response.status_code == 401
                    and self._s.auth_mode == "password"
                    and not _relogin_done
                ):
                    # Snapshot before contending for the lock. N concurrent 401s
                    # all queue here; without this check every one of them posts
                    # its own /v1/auth, which burns N-1 sessions for nothing and
                    # can trip the controller's ERR_TOO_MANY_LOGIN_USER. Whoever
                    # wins the lock re-logs in; the rest find a fresh token and
                    # go straight to the retry below, which rebuilds its headers
                    # from self._token and so picks the new one up.
                    stale_token = self._token
                    async with self._login_lock:
                        if self._token == stale_token:
                            await self.login()
                    return await self.request(
                        method,
                        path,
                        params=params,
                        json=json,
                        timeout_s=timeout_s,
                        authenticated=authenticated,
                        retry=retry,
                        _relogin_done=True,
                    )
                if not is_retryable(response.status_code, body):
                    raise classify(response.status_code, body)
                last_exc = classify(response.status_code, body)

            if not may_retry:
                raise last_exc
            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(_BACKOFF_BASE_S * (2 ** (attempt - 1)))

        raise last_exc or UpstreamError(f"{method} {path} failed after {_MAX_ATTEMPTS} attempts")

    # -- convenience ------------------------------------------------------------
    async def get_list(
        self,
        path: str,
        envelope_key: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> list[Any]:
        """GET a list endpoint and unwrap its envelope key.

        NeuVector wraps collections, e.g. ``GET /v1/group`` returns
        ``{"groups": [...]}``. Returns ``[]`` when the key is absent or null.
        """
        body = await self.request("GET", path, params=params)
        value = body.get(envelope_key) if isinstance(body, dict) else None
        return list(value) if isinstance(value, Sequence) and not isinstance(value, str) else []

    async def get_object(
        self, path: str, envelope_key: str, *, params: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        """GET a single-object endpoint and unwrap its envelope key."""
        body = await self.request("GET", path, params=params)
        value = body.get(envelope_key) if isinstance(body, dict) else None
        return dict(value) if isinstance(value, Mapping) else {}


def _safe_json(response: httpx.Response) -> Any:
    """Parse a response body as JSON, returning ``None`` when it is not JSON."""
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text[:500]
