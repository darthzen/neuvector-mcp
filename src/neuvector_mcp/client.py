"""Async HTTP client for the NeuVector controller REST API.

Responsibilities, and nothing else:

* hold one :class:`httpx.AsyncClient` for the process lifetime
* attach the correct auth header on every request
* re-login exactly once when the controller rejects a session token
* apply the NeuVector query conventions (``start``/``limit``/``f_*``/``s_*``)
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
import ssl
from collections.abc import Mapping, Sequence
from typing import Any, Literal

import httpx
import structlog

from .config import Settings
from .errors import AuthError, NeuVectorMCPError, UpstreamError, classify, is_retryable

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
    async def _send(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any | None = None,
        content: str | bytes | None = None,
        extra_headers: Mapping[str, str] | None = None,
        timeout_s: float | None = None,
        authenticated: bool = True,
        _relogin_done: bool = False,
    ) -> httpx.Response:
        """Perform one controller call and return the raw :class:`httpx.Response`.

        This is the single request path for the whole client: auth headers,
        retry/backoff, and the one-shot re-login on 401 all live here and
        nowhere else. :meth:`request`, :meth:`request_text` and
        :meth:`send_document` differ ONLY in how they encode the request body and
        decode the body of a 2xx response; every non-2xx response is classified
        here identically for all of them.

        Args:
            method: HTTP verb.
            path: Absolute controller path beginning with ``/v1/`` or ``/v2/``.
            params: Query parameters, normally produced by :func:`build_query`.
            json: JSON request body. Mutually exclusive with ``content``.
            content: Pre-encoded request body, for the endpoints that take a raw
                document rather than a JSON object. Mutually exclusive with ``json``.
            extra_headers: Per-call headers merged over the auth headers, e.g. a
                ``Content-Type`` override for a non-JSON body.
            timeout_s: Per-call override.
            authenticated: Set ``False`` only for ``POST /v1/auth``.
            _relogin_done: Internal recursion guard.

        Returns:
            The 2xx :class:`httpx.Response`, body undecoded.

        Raises:
            NeuVectorMCPError: for every non-2xx response, already classified.
        """
        headers = dict(self._auth_headers()) if authenticated else {}
        headers.update(extra_headers or {})
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
                    content=content,
                    headers=headers,
                    timeout=timeout_s or self._s.request_timeout_s,
                )
            except httpx.TimeoutException as exc:
                last_exc = UpstreamError(f"controller timeout on {method} {path}: {exc}")
            except httpx.HTTPError as exc:
                last_exc = UpstreamError(f"controller unreachable on {method} {path}: {exc}")
            else:
                if 200 <= response.status_code < 300:
                    return response
                body = _safe_json(response)
                if (
                    response.status_code == 401
                    and self._s.auth_mode == "password"
                    and not _relogin_done
                ):
                    async with self._login_lock:
                        await self.login()
                    return await self._send(
                        method,
                        path,
                        params=params,
                        json=json,
                        content=content,
                        extra_headers=extra_headers,
                        timeout_s=timeout_s,
                        authenticated=authenticated,
                        _relogin_done=True,
                    )
                if not is_retryable(response.status_code, body):
                    raise classify(response.status_code, body)
                last_exc = classify(response.status_code, body)

            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(_BACKOFF_BASE_S * (2 ** (attempt - 1)))

        raise last_exc or UpstreamError(f"{method} {path} failed after {_MAX_ATTEMPTS} attempts")

    async def request(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any | None = None,
        timeout_s: float | None = None,
        authenticated: bool = True,
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
            _relogin_done: Internal recursion guard.

        Returns:
            Parsed JSON, or ``{}`` when the controller returns an empty body
            (common for ``PATCH``/``DELETE``).

        Raises:
            NeuVectorMCPError: for every non-2xx response, already classified.
        """
        response = await self._send(
            method,
            path,
            params=params,
            json=json,
            timeout_s=timeout_s,
            authenticated=authenticated,
            _relogin_done=_relogin_done,
        )
        return _safe_json(response) or {}

    async def request_text(
        self,
        method: Method,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any | None = None,
        timeout_s: float | None = None,
    ) -> str:
        """Perform one controller call and return the WHOLE 2xx body as text.

        Use this, and only this, for the endpoints that answer with a document
        rather than a JSON object: every ``/v1/file/*`` export answers with YAML.

        Routing a YAML answer through :meth:`request` would hand it to
        :func:`_safe_json`, which cannot parse it and falls back to
        ``response.text[:500]`` - so the caller would receive a 500-character
        fragment of a document while the call still looked like a success. This
        method never truncates: capping a document is the caller's decision and
        the caller must report it, not discover it.

        Auth, retry, backoff and the one-shot re-login are :meth:`_send`'s, i.e.
        identical to :meth:`request`.

        Args:
            method: HTTP verb.
            path: Absolute controller path beginning with ``/v1/`` or ``/v2/``.
            params: Query parameters, normally produced by :func:`build_query`.
            json: JSON request body; the exports select what to export with one.
            timeout_s: Per-call override.

        Returns:
            The decoded response body, in full. ``""`` for an empty body.

        Raises:
            NeuVectorMCPError: for every non-2xx response, already classified.
        """
        response = await self._send(method, path, params=params, json=json, timeout_s=timeout_s)
        return response.text

    async def send_document(
        self,
        method: Method,
        path: str,
        *,
        document: str,
        content_type: str = "text/plain; charset=utf-8",
        params: Mapping[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> Any:
        """POST a raw text document as the request body and return the parsed JSON reply.

        The counterpart of :meth:`request_text`. The ``/v1/file/*/config`` import
        endpoints take the contents of a YAML file as the entire request body -
        not a JSON object wrapping it - and answer with JSON
        (``RESTImportTaskData``). ``json=`` cannot express that, because httpx
        would JSON-encode the document into a quoted string.

        Args:
            method: HTTP verb.
            path: Absolute controller path beginning with ``/v1/`` or ``/v2/``.
            document: The body, sent verbatim as UTF-8.
            content_type: ``Content-Type`` for the body. The default is one of the
                two values ``apis.yaml`` lists under ``consumes`` for these routes.
            params: Query parameters, normally produced by :func:`build_query`.
            timeout_s: Per-call override; imports are slow, so pass
                ``settings.long_request_timeout_s``.

        Returns:
            Parsed JSON, or ``{}`` when the controller returns an empty body.

        Raises:
            NeuVectorMCPError: for every non-2xx response, already classified.
        """
        response = await self._send(
            method,
            path,
            params=params,
            content=document.encode("utf-8"),
            extra_headers={"Content-Type": content_type},
            timeout_s=timeout_s,
        )
        return _safe_json(response) or {}

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
