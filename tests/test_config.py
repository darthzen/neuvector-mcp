"""Configuration contract tests.

These pin `config.py` (SPEC 5 and 7.1). Environment state is only ever touched
through `monkeypatch`, and the autouse `clean_nv_env` fixture strips every
inherited `NV_*` variable so no test can leak into the next one.
"""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from neuvector_mcp.config import (
    ALL_TOOLSETS,
    DEFAULT_TOOLSETS,
    MUTATING_TOOLSETS,
    READ_TOOLSETS,
    Settings,
    load_settings,
)
from neuvector_mcp.errors import ConfigError

CONTROLLER = "https://nv-controller.test:10443"
SECRET = "top-secret-value-9x"


@pytest.fixture(autouse=True)
def clean_nv_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every inherited NV_* variable so each test starts from nothing."""
    for name in [key for key in os.environ if key.startswith("NV_")]:
        monkeypatch.delenv(name, raising=False)


def set_minimal_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The smallest environment that yields a valid Settings."""
    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_API_ACCESS_KEY", "acc")
    monkeypatch.setenv("NV_API_SECRET_KEY", "sec")


# --- defaults -----------------------------------------------------------------


def test_defaults_are_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    settings = load_settings()

    assert settings.read_only is True
    assert settings.transport == "stdio"
    assert settings.toolsets == DEFAULT_TOOLSETS
    assert settings.require_confirm_token is True
    assert settings.auth_mode == "apikey"
    assert settings.allow_undocumented is False
    assert settings.max_items == 200
    assert settings.max_response_chars == 60_000


def test_default_toolsets_are_all_read_only() -> None:
    assert set(DEFAULT_TOOLSETS) <= READ_TOOLSETS
    assert MUTATING_TOOLSETS.isdisjoint(DEFAULT_TOOLSETS)


def test_controller_url_defaults_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NV_API_ACCESS_KEY", "acc")
    monkeypatch.setenv("NV_API_SECRET_KEY", "sec")
    assert load_settings().controller_url == "https://127.0.0.1:10443"


# --- controller URL -----------------------------------------------------------


def test_controller_url_must_have_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_CONTROLLER_URL", "nv.example:10443")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    assert "must start with http:// or https://" in str(excinfo.value)


def test_controller_url_trailing_slash_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_CONTROLLER_URL", "https://x:10443/")
    assert load_settings().controller_url == "https://x:10443"


def test_controller_url_plain_http_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_CONTROLLER_URL", "http://x:10443")
    assert load_settings().controller_url == "http://x:10443"


# --- credentials --------------------------------------------------------------


def test_apikey_mode_requires_both_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_AUTH_MODE", "apikey")
    monkeypatch.setenv("NV_API_ACCESS_KEY", "acc")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    assert "NV_API_ACCESS_KEY and NV_API_SECRET_KEY" in str(excinfo.value)


def test_password_mode_requires_username_and_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_AUTH_MODE", "password")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    assert "NV_USERNAME and NV_PASSWORD" in str(excinfo.value)


def test_password_mode_accepts_username_and_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_AUTH_MODE", "password")
    monkeypatch.setenv("NV_USERNAME", "nvadmin")
    monkeypatch.setenv("NV_PASSWORD", "hunter2")

    settings = load_settings()
    assert settings.auth_mode == "password"
    assert settings.username == "nvadmin"
    assert settings.api_access_key is None


# --- NV_<NAME>_FILE indirection ----------------------------------------------


def test_file_indirection(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_text("s3cret\n", encoding="utf-8")

    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_API_ACCESS_KEY", "acc")
    monkeypatch.setenv("NV_API_SECRET_KEY_FILE", str(secret_file))

    assert load_settings().api_secret_key == "s3cret"


def test_direct_env_beats_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-file\n", encoding="utf-8")

    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_API_SECRET_KEY", "from-env")
    monkeypatch.setenv("NV_API_SECRET_KEY_FILE", str(secret_file))

    assert load_settings().api_secret_key == "from-env"


def test_file_indirection_applies_to_non_secret_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    url_file = tmp_path / "url"
    url_file.write_text(f"{CONTROLLER}\n", encoding="utf-8")

    monkeypatch.setenv("NV_CONTROLLER_URL_FILE", str(url_file))
    monkeypatch.setenv("NV_API_ACCESS_KEY", "acc")
    monkeypatch.setenv("NV_API_SECRET_KEY", "sec")

    assert load_settings().controller_url == CONTROLLER


# --- toolsets -----------------------------------------------------------------


def test_unknown_toolset_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_TOOLSETS", "inventory,bogus")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    message = str(excinfo.value)
    assert "bogus" in message
    for valid in ALL_TOOLSETS:
        assert valid in message


def test_toolsets_are_split_and_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_TOOLSETS", " inventory , events ,")
    assert load_settings().toolsets == ("inventory", "events")


def test_read_only_conflicts_with_mutating_toolset(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_READ_ONLY", "true")
    monkeypatch.setenv("NV_TOOLSETS", "policy_write")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    message = str(excinfo.value)
    assert "policy_write" in message
    assert "NV_READ_ONLY=false" in message


def test_read_only_false_allows_mutating_toolset(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_READ_ONLY", "false")
    monkeypatch.setenv("NV_TOOLSETS", "policy_write")

    settings = load_settings()
    assert settings.read_only is False
    assert settings.toolsets == ("policy_write",)


def test_toolsets_split_is_read_or_write_never_both() -> None:
    overlap = MUTATING_TOOLSETS & READ_TOOLSETS
    union = MUTATING_TOOLSETS | READ_TOOLSETS
    assert overlap == frozenset()
    assert union == set(ALL_TOOLSETS)


def test_toolset_enabled_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    settings = load_settings()
    assert settings.toolset_enabled("inventory") is True
    assert settings.toolset_enabled("policy_write") is False


# --- boolean parsing ----------------------------------------------------------


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "True", "yes", "on", "  on  "])
def test_bool_parsing_true_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_READ_ONLY", raw)
    assert load_settings().read_only is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "off", "maybe"])
def test_bool_parsing_false_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_READ_ONLY", raw)
    assert load_settings().read_only is False


@pytest.mark.xfail(
    reason="DEFECT: _env() treats an empty NV_READ_ONLY as unset and falls back to the "
    "default True, but PHASE-1 test_bool_parsing requires '' to parse as false.",
)
def test_bool_parsing_empty_string_is_false(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_READ_ONLY", "")
    assert load_settings().read_only is False


def test_int_and_float_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_HTTP_PORT", "9443")
    monkeypatch.setenv("NV_MAX_ITEMS", "10")
    monkeypatch.setenv("NV_REQUEST_TIMEOUT_S", "5")
    monkeypatch.setenv("NV_LONG_REQUEST_TIMEOUT_S", "600")

    settings = load_settings()
    assert settings.http_port == 9443
    assert settings.max_items == 10
    assert settings.request_timeout_s == 5.0
    assert settings.long_request_timeout_s == 600.0


def test_allowed_namespaces_split(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_ALLOWED_NAMESPACES", "prod, staging ,")
    assert load_settings().allowed_namespaces == ("prod", "staging")


def test_http_bearer_tokens_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_HTTP_BEARER_TOKENS", " tok-a , tok-b ,")

    assert load_settings().http_bearer_tokens == ("tok-a", "tok-b")


def test_http_bearer_token_scope_suffix_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The old '<token>:<scope>' form fails at startup rather than half-working.

    Stripping the suffix silently would preserve the belief in a control that
    never existed; keeping it would make the whole string the token and 401 every
    request. Neither is a good failure, so this one is loud.
    """
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_HTTP_BEARER_TOKENS", f"{SECRET}:nv:read,tok-b")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    message = str(excinfo.value)
    assert "no longer accepted" in message
    assert SECRET not in message, "the error names the position, never the credential"


# --- startup failures must not print credentials ------------------------------


@pytest.mark.parametrize(
    ("env", "reason"),
    [
        ({"NV_TOOLSETS": "bogus"}, "unknown toolset"),
        ({"NV_CONTROLLER_URL": "nv.example:10443"}, "bad URL scheme"),
        ({"NV_READ_ONLY": "true", "NV_TOOLSETS": "policy_write"}, "read-only conflict"),
        ({"NV_HTTP_BEARER_TOKENS": f"{SECRET}:nv:read"}, "scope suffix"),
    ],
)
def test_no_startup_failure_prints_a_credential(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], reason: str
) -> None:
    """SPEC N8 on the startup path.

    A raw pydantic ValidationError renders ``input_value``, and for this model
    that is the whole settings dict -- NV_API_SECRET_KEY and NV_PASSWORD with it.
    On the HTTP transport the message goes to stderr, into the pod log, and on to
    whatever ships it. Every rejection route is checked, not just the one that
    prompted the fix.
    """
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_API_SECRET_KEY", SECRET)
    monkeypatch.setenv("NV_AUTH_MODE", "apikey")
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    rendered = f"{excinfo.value!r} {excinfo.value!s} {excinfo.traceback!r}"
    assert SECRET not in rendered, f"{reason} rejection leaked the secret key"
    assert excinfo.value.__cause__ is None, "the chained ValidationError would reprint it"


def test_password_is_not_printed_when_password_mode_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_AUTH_MODE", "password")
    monkeypatch.setenv("NV_PASSWORD", SECRET)  # username deliberately absent

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    assert "NV_USERNAME and NV_PASSWORD" in str(excinfo.value)
    assert SECRET not in f"{excinfo.value!r} {excinfo.value!s}"


# --- immutability and redaction ----------------------------------------------


def test_settings_are_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    settings = load_settings()
    with pytest.raises(ValidationError):
        settings.read_only = False  # type: ignore[misc]


def test_settings_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Settings(
            controller_url=CONTROLLER,
            api_access_key="acc",
            api_secret_key="sec",
            not_a_real_knob=True,
        )


def test_redacted_hides_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    set_minimal_env(monkeypatch)
    monkeypatch.setenv("NV_API_SECRET_KEY", SECRET)
    monkeypatch.setenv("NV_HTTP_BEARER_TOKENS", SECRET)

    settings = load_settings()
    redacted = settings.redacted()

    assert settings.api_secret_key == SECRET
    assert redacted["api_secret_key"] == "***REDACTED***"
    assert redacted["http_bearer_tokens"] == "***REDACTED***"
    assert SECRET not in repr(redacted)
    assert redacted["controller_url"] == CONTROLLER


def test_redacted_hides_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NV_CONTROLLER_URL", CONTROLLER)
    monkeypatch.setenv("NV_AUTH_MODE", "password")
    monkeypatch.setenv("NV_USERNAME", "nvadmin")
    monkeypatch.setenv("NV_PASSWORD", SECRET)

    redacted = load_settings().redacted()
    assert redacted["password"] == "***REDACTED***"
    assert redacted["username"] == "nvadmin"
    assert SECRET not in repr(redacted)
