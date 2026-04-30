"""Configuration loading, validation, serialization, and legacy import."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import tomli_w

from .models import (
    AppConfig,
    AppDefaults,
    CredentialConfig,
    ManagedRule,
    ServerConfig,
)


def default_config() -> AppConfig:
    """Return the default empty configuration used by a fresh install."""

    return AppConfig()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _as_non_empty_str(value: Any, where: str) -> str:
    _require(isinstance(value, str) and value.strip(), f"{where} 必须是非空字符串。")
    return value.strip()


def _as_optional_str(value: Any, where: str) -> str | None:
    if value is None:
        return None
    return _as_non_empty_str(value, where)


def _as_bool(value: Any, where: str) -> bool:
    _require(isinstance(value, bool), f"{where} 必须是布尔值。")
    return value


def _as_float(value: Any, where: str) -> float:
    _require(isinstance(value, (int, float)), f"{where} 必须是数值。")
    return float(value)


def _as_string_list(value: Any, where: str) -> tuple[str, ...]:
    _require(isinstance(value, list), f"{where} 必须是字符串数组。")
    result = []
    for index, item in enumerate(value):
        result.append(_as_non_empty_str(item, f"{where}[{index}]"))
    return tuple(result)


def _normalize_tags(tags: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    # 标签在 CLI / TUI / 文件导入多个入口都会出现，这里统一做去重与稳定排序。
    normalized = {tag.strip() for tag in tags if tag and tag.strip()}
    return tuple(sorted(normalized))


def _parse_defaults(data: dict[str, Any]) -> AppDefaults:
    defaults = data.get("defaults", {})
    _require(isinstance(defaults, dict), "[defaults] 必须是 table。")
    endpoint = _as_optional_str(defaults.get("endpoint"), "defaults.endpoint")
    ip_sources_raw = defaults.get("ip_sources", list(AppDefaults().ip_sources))
    request_timeout_seconds = defaults.get("request_timeout_seconds", AppDefaults().request_timeout_seconds)
    history_limit = defaults.get("history_limit", AppDefaults().history_limit)
    _require(isinstance(history_limit, int) and history_limit > 0, "defaults.history_limit 必须是正整数。")
    return AppDefaults(
        endpoint=endpoint,
        ip_sources=_as_string_list(ip_sources_raw, "defaults.ip_sources"),
        request_timeout_seconds=_as_float(request_timeout_seconds, "defaults.request_timeout_seconds"),
        history_limit=history_limit,
    )


def _parse_credentials(data: dict[str, Any]) -> dict[str, CredentialConfig]:
    credentials_table = data.get("credentials", {})
    _require(isinstance(credentials_table, dict), "[credentials] 必须是 table of tables。")
    credentials: dict[str, CredentialConfig] = {}
    for name, raw in credentials_table.items():
        _require(isinstance(raw, dict), f"[credentials.{name}] 必须是 table。")
        credentials[name] = CredentialConfig(
            name=name,
            region=_as_optional_str(raw.get("region"), f"credentials.{name}.region"),
            endpoint=_as_optional_str(raw.get("endpoint"), f"credentials.{name}.endpoint"),
            secret_id_env=_as_optional_str(raw.get("secret_id_env"), f"credentials.{name}.secret_id_env"),
            secret_key_env=_as_optional_str(raw.get("secret_key_env"), f"credentials.{name}.secret_key_env"),
        )
    return credentials


def _parse_managed_rules(raw_rules: Any, where: str) -> tuple[ManagedRule, ...]:
    _require(isinstance(raw_rules, list), f"{where} 必须是数组。")
    managed_rules = []
    for index, raw in enumerate(raw_rules):
        _require(isinstance(raw, dict), f"{where}[{index}] 必须是 table。")
        managed_rules.append(
            ManagedRule(
                protocol=_as_non_empty_str(raw.get("protocol", "TCP"), f"{where}[{index}].protocol").upper(),
                port=_as_non_empty_str(raw.get("port"), f"{where}[{index}].port"),
                action=_as_non_empty_str(raw.get("action", "ACCEPT"), f"{where}[{index}].action").upper(),
                description=str(raw.get("description", "") or ""),
                cidr=_as_non_empty_str(raw.get("cidr", "AUTO"), f"{where}[{index}].cidr"),
                replace_existing_same_port=_as_bool(
                    raw.get("replace_existing_same_port", True),
                    f"{where}[{index}].replace_existing_same_port",
                ),
            )
        )
    return tuple(managed_rules)


def _parse_servers(data: dict[str, Any]) -> tuple[ServerConfig, ...]:
    raw_servers = data.get("servers", [])
    _require(isinstance(raw_servers, list), "[[servers]] 必须是数组。")
    servers = []
    for index, raw in enumerate(raw_servers):
        _require(isinstance(raw, dict), f"servers[{index}] 必须是 table。")
        servers.append(
            ServerConfig(
                name=_as_non_empty_str(raw.get("name"), f"servers[{index}].name"),
                instance_id=_as_non_empty_str(raw.get("instance_id"), f"servers[{index}].instance_id"),
                credential=_as_non_empty_str(raw.get("credential"), f"servers[{index}].credential"),
                enabled=_as_bool(raw.get("enabled", True), f"servers[{index}].enabled"),
                tags=_normalize_tags(_as_string_list(raw.get("tags", []), f"servers[{index}].tags")),
                region=_as_optional_str(raw.get("region"), f"servers[{index}].region"),
                endpoint=_as_optional_str(raw.get("endpoint"), f"servers[{index}].endpoint"),
                managed_rules=_parse_managed_rules(raw.get("managed_rules", []), f"servers[{index}].managed_rules"),
            )
        )
    return tuple(servers)


def load_config_from_text(text: str) -> AppConfig:
    """Load config from TOML text and validate its full schema."""

    data = tomllib.loads(text)
    _require(isinstance(data, dict), "配置文件顶层必须是 TOML table。")
    return AppConfig(
        defaults=_parse_defaults(data),
        credentials=_parse_credentials(data),
        servers=_parse_servers(data),
    )


def load_config_from_path(path: Path) -> AppConfig:
    """Load config from disk; return a default config when the file does not exist."""

    if not path.exists():
        return default_config()
    return load_config_from_text(path.read_text(encoding="utf-8"))


def _credential_to_dict(credential: CredentialConfig) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if credential.region:
        data["region"] = credential.region
    if credential.endpoint:
        data["endpoint"] = credential.endpoint
    if credential.secret_id_env:
        data["secret_id_env"] = credential.secret_id_env
    if credential.secret_key_env:
        data["secret_key_env"] = credential.secret_key_env
    return data


def _rule_to_dict(rule: ManagedRule) -> dict[str, Any]:
    return {
        "protocol": rule.protocol,
        "port": rule.port,
        "action": rule.action,
        "description": rule.description,
        "cidr": rule.cidr,
        "replace_existing_same_port": rule.replace_existing_same_port,
    }


def _server_to_dict(server: ServerConfig) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": server.name,
        "instance_id": server.instance_id,
        "credential": server.credential,
        "enabled": server.enabled,
        "managed_rules": [_rule_to_dict(rule) for rule in server.managed_rules],
    }
    if server.tags:
        data["tags"] = list(server.tags)
    if server.region:
        data["region"] = server.region
    if server.endpoint:
        data["endpoint"] = server.endpoint
    return data


def dump_config_to_text(config: AppConfig) -> str:
    """Serialize AppConfig back to TOML."""

    payload: dict[str, Any] = {
        "defaults": {
            "endpoint": config.defaults.endpoint,
            "ip_sources": list(config.defaults.ip_sources),
            "request_timeout_seconds": config.defaults.request_timeout_seconds,
            "history_limit": config.defaults.history_limit,
        },
        "credentials": {
            name: _credential_to_dict(credential)
            for name, credential in sorted(config.credentials.items(), key=lambda item: item[0])
        },
        "servers": [_server_to_dict(server) for server in config.servers],
    }
    if payload["defaults"]["endpoint"] is None:
        del payload["defaults"]["endpoint"]
    return tomli_w.dumps(payload)


def save_config_to_path(config: AppConfig, path: Path) -> None:
    """Persist configuration to disk."""

    path.write_text(dump_config_to_text(config), encoding="utf-8")


def import_legacy_config_from_text(text: str) -> AppConfig:
    """Convert the legacy single-file TOML layout into the new AppConfig model."""

    data = tomllib.loads(text)
    _require(isinstance(data, dict), "旧配置文件顶层必须是 TOML table。")
    defaults = _parse_defaults(data)
    credentials_table = data.get("credentials", {})
    _require(isinstance(credentials_table, dict), "旧配置中的 [credentials] 必须是 table。")
    credentials: dict[str, CredentialConfig] = {}
    for name, raw in credentials_table.items():
        _require(isinstance(raw, dict), f"旧配置中的 [credentials.{name}] 必须是 table。")
        credentials[name] = CredentialConfig(
            name=name,
            region=_as_optional_str(raw.get("region"), f"credentials.{name}.region"),
            endpoint=_as_optional_str(raw.get("endpoint"), f"credentials.{name}.endpoint"),
            secret_id_env=_as_optional_str(raw.get("secret_id_env"), f"credentials.{name}.secret_id_env"),
            secret_key_env=_as_optional_str(raw.get("secret_key_env"), f"credentials.{name}.secret_key_env"),
        )

    raw_servers = data.get("servers", [])
    _require(isinstance(raw_servers, list), "旧配置中的 [[servers]] 必须是数组。")
    servers = []
    for index, raw in enumerate(raw_servers):
        _require(isinstance(raw, dict), f"旧配置中的 servers[{index}] 必须是 table。")
        servers.append(
            ServerConfig(
                name=_as_non_empty_str(raw.get("name"), f"servers[{index}].name"),
                instance_id=_as_non_empty_str(raw.get("instance_id"), f"servers[{index}].instance_id"),
                credential=_as_non_empty_str(raw.get("credential"), f"servers[{index}].credential"),
                enabled=True,
                tags=(),
                region=_as_optional_str(raw.get("region"), f"servers[{index}].region"),
                endpoint=_as_optional_str(raw.get("endpoint"), f"servers[{index}].endpoint"),
                managed_rules=_parse_managed_rules(raw.get("managed_rules", []), f"servers[{index}].managed_rules"),
            )
        )
    return AppConfig(defaults=defaults, credentials=credentials, servers=tuple(servers))

