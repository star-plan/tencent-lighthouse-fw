"""Shared data models for configuration, execution, and diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_IP_SOURCES = (
    "https://myip.ipip.net/s",
    "http://whois.pconline.com.cn/ipJson.jsp",
)


@dataclass(frozen=True, slots=True)
class AppDefaults:
    """Global defaults shared by all configured servers."""

    endpoint: str | None = None
    ip_sources: tuple[str, ...] = DEFAULT_IP_SOURCES
    request_timeout_seconds: float = 3.0
    history_limit: int = 20


@dataclass(frozen=True, slots=True)
class CredentialConfig:
    """Persistent metadata for one Tencent Cloud credential profile."""

    name: str
    region: str | None = None
    endpoint: str | None = None
    secret_id_env: str | None = None
    secret_key_env: str | None = None


@dataclass(frozen=True, slots=True)
class CredentialSecret:
    """Resolved secret material used to talk to Tencent Cloud."""

    secret_id: str
    secret_key: str


@dataclass(frozen=True, slots=True)
class ManagedRule:
    """A user-managed firewall rule template."""

    protocol: str
    port: str
    action: str = "ACCEPT"
    description: str = ""
    cidr: str = "AUTO"
    replace_existing_same_port: bool = True


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """A Lighthouse instance plus the rules that should be enforced on it."""

    name: str
    instance_id: str
    credential: str
    enabled: bool = True
    tags: tuple[str, ...] = ()
    region: str | None = None
    endpoint: str | None = None
    managed_rules: tuple[ManagedRule, ...] = ()


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Top-level application configuration stored on disk."""

    defaults: AppDefaults = field(default_factory=AppDefaults)
    credentials: dict[str, CredentialConfig] = field(default_factory=dict)
    servers: tuple[ServerConfig, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """A concrete firewall rule ready for diffing or execution."""

    protocol: str
    port: str
    cidr: str
    action: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class ServerRunResult:
    """The full preview/apply result for one configured server."""

    server_name: str
    instance_id: str
    credential_name: str
    status: str
    changed: bool
    delete_rules: tuple[RuleSpec, ...] = ()
    create_rules: tuple[RuleSpec, ...] = ()
    notes: tuple[str, ...] = ()
    request_ids: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RunSummary:
    """A whole run over one or more servers."""

    current_ip: str
    apply: bool
    results: tuple[ServerRunResult, ...]


@dataclass(frozen=True, slots=True)
class HistoryItem:
    """A trimmed execution-history record kept on disk."""

    timestamp: str
    mode: str
    current_ip: str
    selected_servers: tuple[str, ...]
    results: tuple[ServerRunResult, ...]


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """A single health-check item."""

    name: str
    status: str
    detail: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """The full health-check result."""

    checks: tuple[DoctorCheck, ...]

    @property
    def success(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

