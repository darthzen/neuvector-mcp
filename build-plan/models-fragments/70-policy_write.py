class GroupCriterionInput(BaseModel):
    """One group membership criterion. Mirrors RESTCriteriaEntry."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        min_length=1,
        description="Criterion key, i.e. the workload attribute to test. Controller field "
        "names, e.g. 'domain' (Kubernetes namespace), 'image', 'service', 'label', "
        "'node', 'container'. Copy an exact key from an existing group's criteria via "
        "nv_get_group rather than guessing; an unknown key is rejected with code 6.",
    )
    op: str = Field(
        min_length=1,
        description="Comparison operator the controller defines for group criteria, e.g. '=' "
        "or 'contains'. This is NOT the query-filter operator set used by list tools. "
        "Copy an exact operator from an existing group via nv_get_group.",
    )
    value: str = Field(
        description="Value to compare the key against. May be empty for operators that take none."
    )


class NetworkRuleInput(BaseModel):
    """One network policy rule to insert or reconfigure. Mirrors RESTPolicyRule."""

    model_config = ConfigDict(extra="forbid")

    from_group: str = Field(
        min_length=1,
        description="Source group name (controller field 'from'). The group must already "
        "exist; get names from nv_list_groups.",
    )
    to_group: str = Field(
        min_length=1,
        description="Destination group name (controller field 'to'). The group must already exist.",
    )
    action: Literal["allow", "deny"] = Field(
        description="'allow' permits the connection; 'deny' blocks it in Protect mode and "
        "logs a violation in Monitor mode."
    )
    ports: str = Field(
        default="any",
        description="Free-style port list exactly as the controller stores it, e.g. "
        "'tcp/443,tcp/8080-8090', 'udp/53' or 'any'. Copy the format from an existing "
        "rule via nv_list_network_rules.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Layer-7 application names the rule is scoped to, e.g. ['HTTP']. "
        "Empty means any application.",
    )
    comment: str = Field(
        default="",
        description="Free-text comment stored on the rule. Say why the rule exists; it is the "
        "only provenance an operator gets later.",
    )
    disable: bool = Field(
        default=False,
        description="True stores the rule but does not enforce it. Insert a risky rule disabled "
        "first, confirm it matches what you expect, then enable it.",
    )
    id: int | None = Field(
        default=None,
        ge=0,
        description="Existing rule id. REQUIRED for configure_rules, must be omitted for "
        "insert_rules (the controller assigns the id).",
    )


class ProcessProfileEntryInput(BaseModel):
    """One process profile entry to add, change or remove. Mirrors RESTProcessProfileEntryConfig."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        description="Process name as the enforcer reports it, e.g. 'nginx'. Match the exact "
        "spelling from nv_get_process_profile or from the 'process' incident that prompted "
        "this change.",
    )
    path: str = Field(
        min_length=1,
        description="Absolute executable path, e.g. '/usr/sbin/nginx'. Required by the "
        "controller; use '*' to mean any path only if an existing entry already does.",
    )
    action: Literal["allow", "deny"] = Field(
        description="'allow' permits the process; 'deny' blocks it. In Protect mode 'deny' "
        "kills the process immediately."
    )


class FileMonitorFilterInput(BaseModel):
    """One file-monitor filter to add, update or remove. Mirrors RESTFileMonitorFilterConfig."""

    model_config = ConfigDict(extra="forbid")

    filter: str = Field(
        min_length=1,
        description="Path or glob to watch, e.g. '/etc/nginx/*'. Copy the exact form from "
        "nv_get_file_monitor_profile.",
    )
    recursive: bool = Field(
        default=False, description="True watches subdirectories of the path as well."
    )
    behavior: str = Field(
        default="monitor",
        description="What the enforcer does on a hit: 'monitor' records a file incident and "
        "allows the write, 'block' denies the write in Protect mode. Values are not "
        "enumerated in the schema reference; copy an existing filter's value if unsure.",
    )
    applications: list[str] = Field(
        default_factory=list,
        description="Processes the filter applies to. Empty means any process.",
    )
