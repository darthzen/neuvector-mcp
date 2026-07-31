#: JSON field names whose VALUE is a credential. Exact-match, not substring:
#: every name here is a real field in appendix/B-schema-reference.md.
#:   password              RESTRegistryConfig, RESTUser, RESTJfrogXrayConfig, RESTProxyConfig
#:   auth_token            RESTRegistryConfig
#:   gitlab_private_token  RESTRegistryConfig
#:   secret_access_key     RESTAWSAccountKeyConfig
#:   json_key              RESTGCRKeyConfig
#:   personal_access_token RESTRemoteRepo_GitHubConfig
#:   apikey_secret         RESTApikey, RESTApikeyGenerated
SECRET_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "auth_token",
        "gitlab_private_token",
        "secret_access_key",
        "json_key",
        "personal_access_token",
        "apikey_secret",
    }
)

#: The single sentinel a preview payload shows in place of a credential.
REDACTED = "***"


def redact_secrets(obj: Any) -> Any:
    """Deep copy of ``obj`` with every :data:`SECRET_FIELDS` value replaced by '***'.

    Absent keys stay absent: this never introduces a field the controller was not
    going to receive, so the redacted copy has the same SHAPE as the wire copy and
    is therefore a stable basis for the confirmation token.
    """
    if isinstance(obj, dict):
        return {
            key: (REDACTED if key in SECRET_FIELDS else redact_secrets(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    return obj


def service_namespace(service_name: str) -> str:
    """Namespace of a NeuVector service name.

    NeuVector names a Kubernetes service group ``<service>.<namespace>`` (see
    ``RESTService.name`` and ``RESTService.domain`` in appendix B). Returns "" when
    the name carries no namespace suffix, e.g. a Docker-only service.
    """
    _, _, suffix = service_name.rpartition(".")
    return suffix if "." in service_name else ""
