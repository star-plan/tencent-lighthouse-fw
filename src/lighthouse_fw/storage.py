"""Persistent storage for config, secrets, and execution history."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

import keyring
from cryptography.fernet import Fernet
from platformdirs import user_config_dir, user_state_dir

from .config import default_config, import_legacy_config_from_text, load_config_from_path, save_config_to_path
from .models import (
    AppConfig,
    AppDefaults,
    CredentialConfig,
    CredentialSecret,
    HistoryItem,
    ManagedRule,
    RuleSpec,
    ServerConfig,
    ServerRunResult,
)


@dataclass(frozen=True, slots=True)
class AppPaths:
    """All on-disk paths used by the application."""

    config_dir: Path
    state_dir: Path
    config_file: Path
    secrets_file: Path
    local_key_file: Path
    history_file: Path


def get_app_paths() -> AppPaths:
    """Resolve the per-user config/state layout in a cross-platform way."""

    config_dir = Path(os.getenv("LHFW_CONFIG_DIR", "")).expanduser() if os.getenv("LHFW_CONFIG_DIR") else Path(
        user_config_dir("lighthouse-fw", "lighthouse-fw")
    )
    state_dir = Path(os.getenv("LHFW_STATE_DIR", "")).expanduser() if os.getenv("LHFW_STATE_DIR") else Path(
        user_state_dir("lighthouse-fw", "lighthouse-fw")
    )
    return AppPaths(
        config_dir=config_dir,
        state_dir=state_dir,
        config_file=config_dir / "config.toml",
        secrets_file=config_dir / "secrets.bin",
        local_key_file=config_dir / "secrets.key",
        history_file=state_dir / "history.json",
    )


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _tighten_permissions(path: Path) -> None:
    # Windows 对 chmod 的支持有限，但 POSIX 上至少要保证敏感文件只有当前用户可读写。
    if os.name != "nt" and path.exists():
        path.chmod(0o600)


def _keyring_backend_name() -> str:
    backend = keyring.get_keyring()
    return f"{backend.__class__.__module__}.{backend.__class__.__name__}"


def _can_use_secure_keyring() -> bool:
    backend = keyring.get_keyring()
    module_name = backend.__class__.__module__.lower()
    class_name = backend.__class__.__name__.lower()
    secure_tokens = ("windows", "macos", "secretservice", "kwallet", "libsecret")
    insecure_tokens = ("fail", "plaintext")
    if any(token in module_name or token in class_name for token in insecure_tokens):
        return False
    return any(token in module_name or token in class_name for token in secure_tokens)


class SecretStore:
    """Secret storage that prefers system keyring and falls back to an encrypted file."""

    service_name = "lighthouse-fw"

    def __init__(self, paths: AppPaths) -> None:
        self.paths = paths
        self.use_keyring = _can_use_secure_keyring()

    def describe_backend(self) -> str:
        if self.use_keyring:
            return f"system-keyring ({_keyring_backend_name()})"
        return f"encrypted-file ({self.paths.secrets_file.name})"

    def _credential_key(self, credential_name: str) -> str:
        return f"credential:{credential_name}"

    def _load_or_create_local_key(self) -> bytes:
        _ensure_parent(self.paths.local_key_file)
        if not self.paths.local_key_file.exists():
            self.paths.local_key_file.write_bytes(Fernet.generate_key())
            _tighten_permissions(self.paths.local_key_file)
        return self.paths.local_key_file.read_bytes().strip()

    def _load_file_payload(self) -> dict[str, dict[str, str]]:
        if not self.paths.secrets_file.exists():
            return {}
        key = self._load_or_create_local_key()
        fernet = Fernet(key)
        decrypted = fernet.decrypt(self.paths.secrets_file.read_bytes())
        payload = json.loads(decrypted.decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("本地加密 secrets 文件格式无效。")
        return payload

    def _save_file_payload(self, payload: dict[str, dict[str, str]]) -> None:
        _ensure_parent(self.paths.secrets_file)
        key = self._load_or_create_local_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
        self.paths.secrets_file.write_bytes(encrypted)
        _tighten_permissions(self.paths.secrets_file)

    def set_secret(self, credential_name: str, secret: CredentialSecret) -> None:
        if self.use_keyring:
            keyring.set_password(
                self.service_name,
                self._credential_key(credential_name),
                json.dumps(asdict(secret), ensure_ascii=False),
            )
            return
        payload = self._load_file_payload()
        payload[credential_name] = {
            "secret_id": secret.secret_id,
            "secret_key": secret.secret_key,
        }
        self._save_file_payload(payload)

    def get_secret(self, credential_name: str) -> CredentialSecret | None:
        if self.use_keyring:
            raw = keyring.get_password(self.service_name, self._credential_key(credential_name))
            if not raw:
                return None
            parsed = json.loads(raw)
            return CredentialSecret(secret_id=parsed["secret_id"], secret_key=parsed["secret_key"])
        payload = self._load_file_payload()
        raw = payload.get(credential_name)
        if not raw:
            return None
        return CredentialSecret(secret_id=raw["secret_id"], secret_key=raw["secret_key"])

    def clear_secret(self, credential_name: str) -> None:
        if self.use_keyring:
            try:
                keyring.delete_password(self.service_name, self._credential_key(credential_name))
            except keyring.errors.PasswordDeleteError:
                pass
            return
        payload = self._load_file_payload()
        payload.pop(credential_name, None)
        self._save_file_payload(payload)


class ConfigRepository:
    """High-level storage API used by CLI and TUI."""

    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or get_app_paths()
        self.secret_store = SecretStore(self.paths)

    def initialize(self) -> AppConfig:
        _ensure_parent(self.paths.config_file)
        _ensure_parent(self.paths.history_file)
        if not self.paths.config_file.exists():
            save_config_to_path(default_config(), self.paths.config_file)
        if not self.paths.history_file.exists():
            self.paths.history_file.write_text("[]", encoding="utf-8")
        return self.load_config()

    def load_config(self) -> AppConfig:
        return load_config_from_path(self.paths.config_file)

    def save_config(self, config: AppConfig) -> None:
        _ensure_parent(self.paths.config_file)
        save_config_to_path(config, self.paths.config_file)

    def resolve_secret(self, credential: CredentialConfig) -> CredentialSecret:
        stored_secret = self.secret_store.get_secret(credential.name)
        if stored_secret:
            return stored_secret
        if credential.secret_id_env and credential.secret_key_env:
            secret_id = os.getenv(credential.secret_id_env, "").strip()
            secret_key = os.getenv(credential.secret_key_env, "").strip()
            if secret_id and secret_key:
                return CredentialSecret(secret_id=secret_id, secret_key=secret_key)
        raise RuntimeError(
            f"credential {credential.name} 没有可用密钥。请先写入系统钥匙串/本地加密文件，或配置有效环境变量。"
        )

    def import_legacy_file(self, path: Path) -> AppConfig:
        legacy_config = import_legacy_config_from_text(path.read_text(encoding="utf-8"))
        current = self.load_config()
        merged_credentials = dict(current.credentials)
        merged_credentials.update(legacy_config.credentials)
        merged_servers = {server.name: server for server in current.servers}
        for server in legacy_config.servers:
            merged_servers[server.name] = server
        merged = AppConfig(
            defaults=legacy_config.defaults,
            credentials=merged_credentials,
            servers=tuple(merged_servers.values()),
        )
        self.save_config(merged)
        return merged

    def upsert_credential(self, credential: CredentialConfig) -> AppConfig:
        config = self.load_config()
        credentials = dict(config.credentials)
        credentials[credential.name] = credential
        updated = AppConfig(defaults=config.defaults, credentials=credentials, servers=config.servers)
        self.save_config(updated)
        return updated

    def update_defaults(self, defaults: AppDefaults) -> AppConfig:
        config = self.load_config()
        updated = AppConfig(defaults=defaults, credentials=config.credentials, servers=config.servers)
        self.save_config(updated)
        return updated

    def delete_credential(self, credential_name: str) -> AppConfig:
        config = self.load_config()
        if any(server.credential == credential_name for server in config.servers):
            raise RuntimeError(f"credential {credential_name} 仍被 server 引用，不能删除。")
        credentials = dict(config.credentials)
        credentials.pop(credential_name, None)
        self.secret_store.clear_secret(credential_name)
        updated = AppConfig(defaults=config.defaults, credentials=credentials, servers=config.servers)
        self.save_config(updated)
        return updated

    def set_credential_secret(self, credential_name: str, secret: CredentialSecret) -> None:
        self.secret_store.set_secret(credential_name, secret)

    def clear_credential_secret(self, credential_name: str) -> None:
        self.secret_store.clear_secret(credential_name)

    def upsert_server(self, server: ServerConfig) -> AppConfig:
        config = self.load_config()
        if server.credential not in config.credentials:
            raise RuntimeError(f"server {server.name} 引用了不存在的 credential: {server.credential}")
        servers_by_name = {item.name: item for item in config.servers}
        servers_by_name[server.name] = server
        updated = AppConfig(
            defaults=config.defaults,
            credentials=config.credentials,
            servers=tuple(servers_by_name.values()),
        )
        self.save_config(updated)
        return updated

    def delete_server(self, server_name: str) -> AppConfig:
        config = self.load_config()
        updated = AppConfig(
            defaults=config.defaults,
            credentials=config.credentials,
            servers=tuple(server for server in config.servers if server.name != server_name),
        )
        self.save_config(updated)
        return updated

    def set_server_enabled(self, server_name: str, enabled: bool) -> AppConfig:
        config = self.load_config()
        updated_servers = []
        found = False
        for server in config.servers:
            if server.name == server_name:
                found = True
                updated_servers.append(
                    ServerConfig(
                        name=server.name,
                        instance_id=server.instance_id,
                        credential=server.credential,
                        enabled=enabled,
                        tags=server.tags,
                        region=server.region,
                        endpoint=server.endpoint,
                        managed_rules=server.managed_rules,
                    )
                )
            else:
                updated_servers.append(server)
        if not found:
            raise RuntimeError(f"未找到 server: {server_name}")
        updated = AppConfig(
            defaults=config.defaults,
            credentials=config.credentials,
            servers=tuple(updated_servers),
        )
        self.save_config(updated)
        return updated

    def replace_server_rules(self, server_name: str, rules: tuple[ManagedRule, ...]) -> AppConfig:
        config = self.load_config()
        updated_servers = []
        found = False
        for server in config.servers:
            if server.name == server_name:
                found = True
                updated_servers.append(
                    ServerConfig(
                        name=server.name,
                        instance_id=server.instance_id,
                        credential=server.credential,
                        enabled=server.enabled,
                        tags=server.tags,
                        region=server.region,
                        endpoint=server.endpoint,
                        managed_rules=rules,
                    )
                )
            else:
                updated_servers.append(server)
        if not found:
            raise RuntimeError(f"未找到 server: {server_name}")
        updated = AppConfig(
            defaults=config.defaults,
            credentials=config.credentials,
            servers=tuple(updated_servers),
        )
        self.save_config(updated)
        return updated

    def append_history(self, item: HistoryItem) -> None:
        _ensure_parent(self.paths.history_file)
        history = self.load_history()
        config = self.load_config()
        trimmed = [item, *history][: config.defaults.history_limit]
        serialized = [self._history_item_to_dict(entry) for entry in trimmed]
        self.paths.history_file.write_text(json.dumps(serialized, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_history(self) -> list[HistoryItem]:
        if not self.paths.history_file.exists():
            return []
        raw = json.loads(self.paths.history_file.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            return []
        return [self._history_item_from_dict(item) for item in raw if isinstance(item, dict)]

    @staticmethod
    def _rule_to_dict(rule: RuleSpec) -> dict[str, str]:
        return {
            "protocol": rule.protocol,
            "port": rule.port,
            "cidr": rule.cidr,
            "action": rule.action,
            "description": rule.description,
        }

    @staticmethod
    def _rule_from_dict(data: dict[str, str]) -> RuleSpec:
        return RuleSpec(
            protocol=data["protocol"],
            port=data["port"],
            cidr=data["cidr"],
            action=data["action"],
            description=data.get("description", ""),
        )

    def _history_item_to_dict(self, item: HistoryItem) -> dict[str, object]:
        return {
            "timestamp": item.timestamp,
            "mode": item.mode,
            "current_ip": item.current_ip,
            "selected_servers": list(item.selected_servers),
            "results": [
                {
                    "server_name": result.server_name,
                    "instance_id": result.instance_id,
                    "credential_name": result.credential_name,
                    "status": result.status,
                    "changed": result.changed,
                    "delete_rules": [self._rule_to_dict(rule) for rule in result.delete_rules],
                    "create_rules": [self._rule_to_dict(rule) for rule in result.create_rules],
                    "notes": list(result.notes),
                    "request_ids": list(result.request_ids),
                    "error": result.error,
                }
                for result in item.results
            ],
        }

    def _history_item_from_dict(self, data: dict[str, object]) -> HistoryItem:
        results = []
        for raw in data.get("results", []):
            if not isinstance(raw, dict):
                continue
            results.append(
                ServerRunResult(
                    server_name=str(raw["server_name"]),
                    instance_id=str(raw["instance_id"]),
                    credential_name=str(raw["credential_name"]),
                    status=str(raw["status"]),
                    changed=bool(raw["changed"]),
                    delete_rules=tuple(
                        self._rule_from_dict(rule)
                        for rule in raw.get("delete_rules", [])
                        if isinstance(rule, dict)
                    ),
                    create_rules=tuple(
                        self._rule_from_dict(rule)
                        for rule in raw.get("create_rules", [])
                        if isinstance(rule, dict)
                    ),
                    notes=tuple(str(note) for note in raw.get("notes", [])),
                    request_ids=tuple(str(item) for item in raw.get("request_ids", [])),
                    error=str(raw["error"]) if raw.get("error") else None,
                )
            )
        return HistoryItem(
            timestamp=str(data["timestamp"]),
            mode=str(data["mode"]),
            current_ip=str(data["current_ip"]),
            selected_servers=tuple(str(item) for item in data.get("selected_servers", [])),
            results=tuple(results),
        )

