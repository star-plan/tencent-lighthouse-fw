"""Offline tests for config loading, storage fallback, and rule diff logic."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lighthouse_fw.config import AppConfig, import_legacy_config_from_text
from lighthouse_fw.models import AppDefaults, CredentialConfig, CredentialSecret, ManagedRule, RuleSpec
from lighthouse_fw.storage import AppPaths, ConfigRepository
from lighthouse_fw.updater import compute_incremental_update, execute_run


LEGACY_TOML = """
[defaults]
endpoint = "lighthouse.tencentcloudapi.com"
ip_sources = ["https://example.com/ip", "https://backup.example.com/ip"]
request_timeout_seconds = 5

[credentials.work]
secret_id_env = "TENCENT_SECRET_ID"
secret_key_env = "TENCENT_SECRET_KEY"
region = "ap-singapore"

[[servers]]
name = "prod-a"
instance_id = "lhins-123456"
credential = "work"
managed_rules = [
  { protocol = "TCP", port = "22", action = "ACCEPT", cidr = "AUTO", description = "ssh", replace_existing_same_port = true },
]
"""


class ConfigImportTests(unittest.TestCase):
    """Validate old TOML import and schema translation."""

    def test_import_legacy_config(self) -> None:
        config = import_legacy_config_from_text(LEGACY_TOML)
        self.assertEqual(config.defaults.endpoint, "lighthouse.tencentcloudapi.com")
        self.assertEqual(config.defaults.request_timeout_seconds, 5.0)
        self.assertEqual(config.defaults.ip_sources[0], "https://example.com/ip")
        self.assertIn("work", config.credentials)
        self.assertEqual(config.credentials["work"].region, "ap-singapore")
        self.assertEqual(len(config.servers), 1)
        self.assertEqual(config.servers[0].managed_rules[0].port, "22")


class SecretStorageTests(unittest.TestCase):
    """Use the encrypted-file fallback in a temp directory to avoid real user secrets."""

    def _paths(self, root: Path) -> AppPaths:
        return AppPaths(
            config_dir=root / "config",
            state_dir=root / "state",
            config_file=root / "config" / "config.toml",
            secrets_file=root / "config" / "secrets.bin",
            local_key_file=root / "config" / "secrets.key",
            history_file=root / "state" / "history.json",
        )

    def test_encrypted_secret_fallback_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._paths(Path(temp_dir))
            with patch("lighthouse_fw.storage._can_use_secure_keyring", return_value=False):
                repository = ConfigRepository(paths=paths)
                repository.initialize()
                repository.upsert_credential(CredentialConfig(name="work", region="ap-singapore"))
                repository.set_credential_secret(
                    "work",
                    CredentialSecret(secret_id="secret-id", secret_key="secret-key"),
                )
                resolved = repository.resolve_secret(CredentialConfig(name="work", region="ap-singapore"))
                self.assertEqual(resolved.secret_id, "secret-id")
                self.assertTrue(paths.secrets_file.exists())
                self.assertTrue(paths.local_key_file.exists())

    def test_update_defaults_persists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self._paths(Path(temp_dir))
            with patch("lighthouse_fw.storage._can_use_secure_keyring", return_value=False):
                repository = ConfigRepository(paths=paths)
                repository.initialize()
                repository.update_defaults(
                    AppDefaults(
                        endpoint="lighthouse.tencentcloudapi.com",
                        ip_sources=("https://example.com/ip",),
                        request_timeout_seconds=8.0,
                        history_limit=12,
                    )
                )
                loaded = repository.load_config()
                self.assertEqual(loaded.defaults.history_limit, 12)
                self.assertEqual(loaded.defaults.ip_sources, ("https://example.com/ip",))


class UpdaterTests(unittest.TestCase):
    """Exercise the diff engine without any Tencent Cloud dependency."""

    def test_compute_incremental_update_with_replacement(self) -> None:
        existing = [
            RuleSpec(protocol="TCP", port="22", cidr="1.1.1.1/32", action="ACCEPT", description="old"),
        ]
        managed_rules = (
            ManagedRule(
                protocol="TCP",
                port="22",
                action="ACCEPT",
                cidr="AUTO",
                description="ssh",
                replace_existing_same_port=True,
            ),
        )
        delete_rules, create_rules, changed, notes = compute_incremental_update(existing, managed_rules, "2.2.2.2")
        self.assertTrue(changed)
        self.assertEqual(delete_rules[0].cidr, "1.1.1.1/32")
        self.assertEqual(create_rules[0].cidr, "2.2.2.2/32")
        self.assertTrue(any("删除 1 条旧规则" in note for note in notes))

    def test_compute_incremental_update_when_already_up_to_date(self) -> None:
        existing = [
            RuleSpec(protocol="TCP", port="22", cidr="2.2.2.2/32", action="ACCEPT", description="ssh"),
        ]
        managed_rules = (
            ManagedRule(
                protocol="TCP",
                port="22",
                action="ACCEPT",
                cidr="AUTO",
                description="ssh",
                replace_existing_same_port=False,
            ),
        )
        delete_rules, create_rules, changed, notes = compute_incremental_update(existing, managed_rules, "2.2.2.2")
        self.assertFalse(changed)
        self.assertEqual(delete_rules, ())
        self.assertEqual(create_rules, ())
        self.assertTrue(any("无需修改" in note for note in notes))

    def test_execute_run_with_no_enabled_servers_short_circuits(self) -> None:
        summary = execute_run(
            config=AppConfig(),
            resolve_secret=lambda credential: None,
            apply_changes=False,
        )
        self.assertEqual(summary.current_ip, "-")
        self.assertEqual(summary.results, ())


if __name__ == "__main__":
    unittest.main()
