class UserBrief(BaseModel):
    """One user account. Password material is structurally absent."""

    model_config = _BASE

    fullname: str = Field(
        description="Fully qualified user name; the id for nv_update_user_role and nv_delete_user."
    )
    username: str = Field(default="", description="Login name.")
    email: str = Field(default="", description="Email address on the account.")
    auth_server: str = Field(
        default="",
        description="Authentication server the user comes from; empty means a local account.",
    )
    role: str = Field(
        default="",
        description="Global role, e.g. admin, reader. Empty means namespace-scoped only.",
    )
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Namespace-scoped roles as role -> list of namespaces.",
    )
    timeout: int = Field(default=0, description="Session idle timeout in seconds.")
    locale: str = Field(default="", description="UI locale.")
    last_login_at: str = Field(default="", description="Human-readable last login time.")
    last_login_timestamp: int = Field(
        default=0, description="Unix epoch seconds of the last login, 0 if never."
    )
    login_count: int = Field(default=0, description="Successful logins recorded for this account.")
    default_password: bool = Field(
        default=True,
        description="True when the account still uses its default password. Treat as a finding. "
        "Defaults to True so a missing field never reads as safe.",
    )
    blocked_for_failed_login: bool = Field(
        default=False, description="True when locked out by failed logins."
    )
    blocked_for_password_expired: bool = Field(
        default=False, description="True when the password has expired."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "UserBrief":
        """Project a ``RESTUser``.

        ``password`` is NEVER read. See the tool notes: omission is a
        requirement, not an optimisation.
        """
        domains = raw.get("role_domains") or {}
        role_domains = (
            {
                str(role): [str(d) for d in (namespaces or [])]
                for role, namespaces in domains.items()
            }
            if isinstance(domains, dict)
            else {}
        )
        return cls(
            fullname=str(raw.get("fullname", "") or ""),
            username=str(raw.get("username", "") or ""),
            email=str(raw.get("email", "") or ""),
            auth_server=str(raw.get("server", "") or ""),
            role=str(raw.get("role", "") or ""),
            role_domains=role_domains,
            timeout=int(raw.get("timeout") or 0),
            locale=str(raw.get("locale", "") or ""),
            last_login_at=str(raw.get("last_login_at", "") or ""),
            last_login_timestamp=int(raw.get("last_login_timestamp") or 0),
            login_count=int(raw.get("login_count") or 0),
            default_password=bool(raw.get("default_password", True)),
            blocked_for_failed_login=bool(raw.get("blocked_for_failed_login", False)),
            blocked_for_password_expired=bool(raw.get("blocked_for_password_expired", False)),
        )


class UserList(BaseModel):
    """Result of ``nv_list_users``."""

    model_config = _BASE

    page: Page
    users: list[UserBrief]


class RolePermission(BaseModel):
    """One permission grant inside a role."""

    model_config = _BASE

    id: str = Field(description="Controller permission id, e.g. 'rt_policy' or 'admctrl'.")
    read: bool = Field(default=False, description="True when the role can read this area.")
    write: bool = Field(default=False, description="True when the role can change this area.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "RolePermission":
        """Project a ``RESTRolePermission``."""
        return cls(
            id=str(raw.get("id", "") or ""),
            read=bool(raw.get("read", False)),
            write=bool(raw.get("write", False)),
        )


class RoleBrief(BaseModel):
    """One role definition."""

    model_config = _BASE

    name: str = Field(description="Role name as referenced by users and API keys.")
    reserved: bool = Field(
        default=False,
        description="True for built-in roles, which cannot be modified or deleted.",
    )
    write_permission_count: int = Field(
        default=0,
        description="How many permission areas this role can change. 0 means read-only.",
    )
    permissions: list[RolePermission] = Field(
        default_factory=list, description="Permission grants making up the role."
    )
    comment: str = Field(default="", description="Role description, clipped to 500 characters.")

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "RoleBrief":
        """Project a ``RESTUserRole``."""
        perms = [
            RolePermission.from_api(p)
            for p in (raw.get("permissions") or [])
            if isinstance(p, dict)
        ]
        return cls(
            name=str(raw.get("name", "") or ""),
            reserved=bool(raw.get("reserved", False)),
            write_permission_count=sum(1 for p in perms if p.write),
            permissions=perms,
            comment=_clip(str(raw.get("comment", "") or ""), 500)[0],
        )


class RoleList(BaseModel):
    """Result of ``nv_list_roles``."""

    model_config = _BASE

    page: Page
    roles: list[RoleBrief]


#: Only these top-level keys of a server entry may be projected, and only 'name'
#: as a value. Everything else is reported as a key name or dropped. An
#: allowlist is used deliberately: a denylist would leak any secret field that a
#: future controller release adds.
_AUTH_SERVER_VALUE_ALLOWLIST: frozenset[str] = frozenset({"name"})

#: Key-name substrings that must never appear even in the reported key list.
_SECRET_KEY_MARKERS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "credential",
    "private",
    "key",
)


class AuthServerBrief(BaseModel):
    """One authentication server, reduced to non-sensitive facts.

    Appendix B contains no ``RESTServer`` / ``RESTServersData`` definition, so
    the set of secret-bearing fields cannot be enumerated from the schema. This
    model therefore projects VALUES for allowlisted keys only ('name') and
    reports every other key by NAME, with secret-looking names filtered out.
    """

    model_config = _BASE

    name: str = Field(description="Server name; matches the 'server' field on a user account.")
    config_blocks: list[str] = Field(
        default_factory=list,
        description="Configuration block key names present on this server, e.g. the protocol "
        "block that identifies it as LDAP, SAML or OIDC. Names only, never values.",
    )
    redacted_keys: list[str] = Field(
        default_factory=list,
        description="Key names withheld because they matched a secret marker (password, secret, "
        "token, credential, private, key). Their values are never read.",
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "AuthServerBrief":
        """Project one server entry through the value allowlist."""
        blocks: list[str] = []
        redacted: list[str] = []
        for key in raw:
            if key in _AUTH_SERVER_VALUE_ALLOWLIST:
                continue
            lowered = key.lower()
            if any(marker in lowered for marker in _SECRET_KEY_MARKERS):
                redacted.append(key)
            else:
                blocks.append(key)
        return cls(
            name=str(raw.get("name", "") or ""),
            config_blocks=sorted(blocks),
            redacted_keys=sorted(redacted),
        )


class AuthServerList(BaseModel):
    """Result of ``nv_list_auth_servers``."""

    model_config = _BASE

    page: Page
    servers: list[AuthServerBrief]


class ApiKeyBrief(BaseModel):
    """One API key's metadata. The secret is structurally absent."""

    model_config = _BASE

    apikey_name: str = Field(
        description="Key name, i.e. the access key; the id for nv_delete_api_key."
    )
    role: str = Field(default="", description="Global role the key carries.")
    role_domains: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Namespace-scoped roles as role -> list of namespaces.",
    )
    expiration_type: str = Field(
        default="",
        description="How expiry is expressed, e.g. hours or never, verbatim from the controller.",
    )
    expiration_hours: int = Field(
        default=0, description="Configured lifetime in hours, 0 when not hour-based."
    )
    expiration_timestamp: int = Field(
        default=0,
        description="Unix epoch seconds the key expires, 0 when it does not expire.",
    )
    created_timestamp: int = Field(default=0, description="Unix epoch seconds the key was created.")
    created_by_entity: str = Field(default="", description="Who or what created the key.")
    description: str = Field(
        default="", description="Operator description, clipped to 500 characters."
    )

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "ApiKeyBrief":
        """Project a ``RESTApikey``.

        ``apikey_secret`` is NEVER read. The controller returns it only from the
        creation call; there is no recovery path and this tool must not imply one.
        """
        domains = raw.get("role_domains") or {}
        role_domains = (
            {
                str(role): [str(d) for d in (namespaces or [])]
                for role, namespaces in domains.items()
            }
            if isinstance(domains, dict)
            else {}
        )
        return cls(
            apikey_name=str(raw.get("apikey_name", "") or ""),
            role=str(raw.get("role", "") or ""),
            role_domains=role_domains,
            expiration_type=str(raw.get("expiration_type", "") or ""),
            expiration_hours=int(raw.get("expiration_hours") or 0),
            expiration_timestamp=int(raw.get("expiration_timestamp") or 0),
            created_timestamp=int(raw.get("created_timestamp") or 0),
            created_by_entity=str(raw.get("created_by_entity", "") or ""),
            description=_clip(str(raw.get("description", "") or ""), 500)[0],
        )


class ApiKeyList(BaseModel):
    """Result of ``nv_list_api_keys``."""

    model_config = _BASE

    page: Page
    api_keys: list[ApiKeyBrief]
