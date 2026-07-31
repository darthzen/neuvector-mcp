"""Configuration for the NeuVector MCP server.

All configuration is supplied through environment variables prefixed ``NV_``.
Nothing is read from the filesystem except the optional ``*_FILE`` indirections,
which exist so Kubernetes Secrets can be mounted as files instead of env vars.

This module has no dependencies on any other module in this package.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Transport = Literal["stdio", "http"]
AuthMode = Literal["apikey", "password"]

#: Tool tags that may be enabled via ``NV_TOOLSETS``.
ALL_TOOLSETS: tuple[str, ...] = (
    # read-only toolsets
    "inventory",
    "vulnerability",
    "compliance",
    "events",
    "policy_read",
    "iam_read",
    # mutating toolsets
    "policy_write",
    "admission",
    "scan_ops",
    "runtime_ops",
    "iam_write",
    "system_write",
)

#: Toolsets enabled when ``NV_TOOLSETS`` is unset. Read-only by construction.
DEFAULT_TOOLSETS: tuple[str, ...] = (
    "inventory",
    "vulnerability",
    "compliance",
    "events",
    "policy_read",
    "iam_read",
)

#: Toolsets that contain at least one mutating tool.
MUTATING_TOOLSETS: frozenset[str] = frozenset(
    {
        "policy_write",
        "admission",
        "scan_ops",
        "runtime_ops",
        "iam_write",
        "system_write",
    }
)

#: Every toolset that is not mutating is read-only. A toolset is never mixed:
#: read tools and write tools never share a toolset tag, because R3 in
#: scripts/verify_spec.py derives ``readOnlyHint`` from the toolset.
READ_TOOLSETS: frozenset[str] = frozenset(ALL_TOOLSETS) - MUTATING_TOOLSETS


def _env(name: str, default: str | None = None) -> str | None:
    """Read ``NV_<name>``, falling back to the contents of ``NV_<name>_FILE``."""
    direct = os.environ.get(f"NV_{name}")
    if direct is not None and direct != "":
        return direct
    path = os.environ.get(f"NV_{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    return int(raw)


class Settings(BaseModel):
    """Immutable, fully validated server configuration."""

    model_config = {"frozen": True, "extra": "forbid"}

    # --- controller connection -------------------------------------------------
    controller_url: str = Field(
        description="Base URL of the NeuVector controller REST API, e.g. "
        "https://neuvector-svc-controller-api.cattle-neuvector-system:10443"
    )
    verify_tls: bool = True
    ca_bundle: str | None = None
    request_timeout_s: float = 30.0
    long_request_timeout_s: float = 300.0

    # --- controller credentials ----------------------------------------------
    auth_mode: AuthMode = "apikey"
    api_access_key: str | None = None
    api_secret_key: str | None = None
    username: str | None = None
    password: str | None = None

    # --- MCP surface -----------------------------------------------------------
    transport: Transport = "stdio"
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    http_path: str = "/mcp"
    http_bearer_tokens: dict[str, list[str]] = Field(default_factory=dict)

    # --- safety ----------------------------------------------------------------
    read_only: bool = True
    toolsets: tuple[str, ...] = DEFAULT_TOOLSETS
    require_confirm_token: bool = True
    allow_undocumented: bool = False
    allowed_namespaces: tuple[str, ...] = ()

    # --- response shaping ------------------------------------------------------
    max_items: int = 200
    max_response_chars: int = 60_000

    # --- observability ---------------------------------------------------------
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    audit_log_path: str | None = None

    @field_validator("controller_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("NV_CONTROLLER_URL must start with http:// or https://")
        return v.rstrip("/")

    @field_validator("toolsets")
    @classmethod
    def _known_toolsets(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(v) - set(ALL_TOOLSETS))
        if unknown:
            raise ValueError(f"unknown toolset(s) {unknown}; valid values: {sorted(ALL_TOOLSETS)}")
        return v

    @model_validator(mode="after")
    def _credentials_present(self) -> Settings:
        if self.auth_mode == "apikey":
            if not (self.api_access_key and self.api_secret_key):
                raise ValueError(
                    "auth_mode=apikey requires NV_API_ACCESS_KEY and NV_API_SECRET_KEY"
                )
        else:
            if not (self.username and self.password):
                raise ValueError("auth_mode=password requires NV_USERNAME and NV_PASSWORD")
        return self

    @model_validator(mode="after")
    def _read_only_consistency(self) -> Settings:
        if self.read_only:
            enabled_mutating = MUTATING_TOOLSETS.intersection(self.toolsets)
            if enabled_mutating:
                raise ValueError(
                    "NV_READ_ONLY=true conflicts with mutating toolset(s) "
                    f"{sorted(enabled_mutating)}; set NV_READ_ONLY=false to enable them"
                )
        return self

    # -- derived helpers --------------------------------------------------------
    def toolset_enabled(self, tag: str) -> bool:
        return tag in self.toolsets

    def redacted(self) -> dict[str, object]:
        """Config dump safe to write to logs."""
        data = self.model_dump()
        for key in (
            "api_secret_key",
            "password",
            "http_bearer_tokens",
        ):
            if data.get(key):
                data[key] = "***REDACTED***"
        return data


def load_settings() -> Settings:
    """Build :class:`Settings` from the process environment.

    Raises:
        pydantic.ValidationError: if the environment is incomplete or contradictory.
    """
    toolsets_raw = _env("TOOLSETS")
    toolsets = (
        tuple(t.strip() for t in toolsets_raw.split(",") if t.strip())
        if toolsets_raw
        else DEFAULT_TOOLSETS
    )

    tokens_raw = _env("HTTP_BEARER_TOKENS", "")
    bearer: dict[str, list[str]] = {}
    for entry in (tokens_raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        token, _, scopes = entry.partition(":")
        bearer[token] = [s for s in scopes.split("|") if s] or ["nv:read"]

    return Settings(
        controller_url=_env("CONTROLLER_URL", "https://127.0.0.1:10443") or "",
        verify_tls=_env_bool("VERIFY_TLS", True),
        ca_bundle=_env("CA_BUNDLE"),
        request_timeout_s=float(_env("REQUEST_TIMEOUT_S", "30") or 30),
        long_request_timeout_s=float(_env("LONG_REQUEST_TIMEOUT_S", "300") or 300),
        auth_mode=_env("AUTH_MODE", "apikey"),  # type: ignore[arg-type]
        api_access_key=_env("API_ACCESS_KEY"),
        api_secret_key=_env("API_SECRET_KEY"),
        username=_env("USERNAME"),
        password=_env("PASSWORD"),
        transport=_env("TRANSPORT", "stdio"),  # type: ignore[arg-type]
        http_host=_env("HTTP_HOST", "0.0.0.0") or "0.0.0.0",
        http_port=_env_int("HTTP_PORT", 8080),
        http_path=_env("HTTP_PATH", "/mcp") or "/mcp",
        http_bearer_tokens=bearer,
        read_only=_env_bool("READ_ONLY", True),
        toolsets=toolsets,
        require_confirm_token=_env_bool("REQUIRE_CONFIRM_TOKEN", True),
        allow_undocumented=_env_bool("ALLOW_UNDOCUMENTED", False),
        allowed_namespaces=tuple(
            n.strip() for n in (_env("ALLOWED_NAMESPACES", "") or "").split(",") if n.strip()
        ),
        max_items=_env_int("MAX_ITEMS", 200),
        max_response_chars=_env_int("MAX_RESPONSE_CHARS", 60_000),
        log_level=(_env("LOG_LEVEL", "INFO") or "INFO").upper(),
        log_format=_env("LOG_FORMAT", "json"),  # type: ignore[arg-type]
        audit_log_path=_env("AUDIT_LOG_PATH"),
    )
