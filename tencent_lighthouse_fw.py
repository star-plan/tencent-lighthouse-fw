# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests>=2.32.0",
#   "tencentcloud-sdk-python>=3.0.0",
# ]
# ///
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import requests
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.lighthouse.v20200324 import lighthouse_client, models

try:
    import tomllib  # py311+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


@dataclass(frozen=True)
class CredentialProfile:
    name: str
    secret_id_env: str
    secret_key_env: str
    region: str | None = None
    endpoint: str | None = None


@dataclass(frozen=True)
class ManagedRule:
    protocol: str
    port: str
    action: str = "ACCEPT"
    description: str = ""
    cidr: str = "AUTO"  # AUTO => current_ip/32
    replace_existing_same_port: bool = True


@dataclass(frozen=True)
class ServerConfig:
    name: str
    instance_id: str
    credential: str
    region: str | None = None
    endpoint: str | None = None
    managed_rules: tuple[ManagedRule, ...] = ()


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def _as_str(value: Any, where: str) -> str:
    _require(isinstance(value, str) and value.strip(), f"Invalid {where}: expected non-empty string")
    return value.strip()


def _as_bool(value: Any, where: str) -> bool:
    _require(isinstance(value, bool), f"Invalid {where}: expected boolean")
    return bool(value)


def _find_ipv4(text: str) -> str | None:
    match = IPV4_RE.search(text)
    return match.group(0) if match else None


def get_public_ipv4(ip_sources: list[str], timeout_seconds: float) -> str:
    last_err: str | None = None
    headers = {"User-Agent": "tencent-lighthouse-fw/1.0"}
    for url in ip_sources:
        try:
            resp = requests.get(url, timeout=timeout_seconds, headers=headers)
            resp.raise_for_status()
            ip = _find_ipv4(resp.text)
            if ip:
                ipaddress.IPv4Address(ip)  # validate
                return ip
            last_err = f"{url}: no IPv4 found"
        except Exception as exc:
            last_err = f"{url}: {exc}"
    raise RuntimeError(f"Failed to get public IPv4 from all sources. Last error: {last_err}")


def load_config(path: Path) -> tuple[dict[str, Any], dict[str, CredentialProfile], list[ServerConfig]]:
    _require(path.exists(), f"Config not found: {path}")
    _require(tomllib is not None, "Python 3.11+ required (tomllib not found)")
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    defaults = data.get("defaults", {}) if isinstance(data, dict) else {}
    _require(isinstance(defaults, dict), "Invalid config: [defaults] must be a table")

    creds_table = data.get("credentials", {})
    _require(isinstance(creds_table, dict), "Invalid config: [credentials] must be a table of tables")

    credentials_out: dict[str, CredentialProfile] = {}
    for name, c in creds_table.items():
        _require(isinstance(c, dict), f"Invalid config: [credentials.{name}] must be a table")
        secret_id_env = _as_str(c.get("secret_id_env"), f"credentials.{name}.secret_id_env")
        secret_key_env = _as_str(c.get("secret_key_env"), f"credentials.{name}.secret_key_env")
        region = c.get("region")
        endpoint = c.get("endpoint")
        credentials_out[name] = CredentialProfile(
            name=name,
            secret_id_env=secret_id_env,
            secret_key_env=secret_key_env,
            region=_as_str(region, f"credentials.{name}.region") if region is not None else None,
            endpoint=_as_str(endpoint, f"credentials.{name}.endpoint") if endpoint is not None else None,
        )

    servers_list = data.get("servers")
    _require(isinstance(servers_list, list) and servers_list, "Invalid config: [[servers]] required")
    servers_out: list[ServerConfig] = []
    for idx, s in enumerate(servers_list):
        _require(isinstance(s, dict), f"Invalid config: servers[{idx}] must be a table")
        name = _as_str(s.get("name", f"server-{idx+1}"), f"servers[{idx}].name")
        instance_id = _as_str(s.get("instance_id"), f"servers[{idx}].instance_id")
        cred_name = _as_str(s.get("credential"), f"servers[{idx}].credential")
        region = s.get("region")
        endpoint = s.get("endpoint")

        managed_rules_raw = s.get("managed_rules", [])
        _require(isinstance(managed_rules_raw, list), f"Invalid config: servers[{idx}].managed_rules must be array")
        managed_rules: list[ManagedRule] = []
        for ridx, r in enumerate(managed_rules_raw):
            _require(isinstance(r, dict), f"Invalid config: servers[{idx}].managed_rules[{ridx}] must be a table")
            protocol = _as_str(r.get("protocol", defaults.get("protocol", "TCP")), "managed_rules.protocol")
            port = _as_str(r.get("port", defaults.get("port")), "managed_rules.port")
            action = _as_str(r.get("action", defaults.get("action", "ACCEPT")), "managed_rules.action").upper()
            description = str(r.get("description", defaults.get("ssh_rule_description", "")) or "")
            cidr = _as_str(r.get("cidr", "AUTO"), "managed_rules.cidr")
            replace_existing_same_port = r.get(
                "replace_existing_same_port", defaults.get("replace_existing_same_port", True)
            )
            managed_rules.append(
                ManagedRule(
                    protocol=protocol.upper(),
                    port=port,
                    action=action,
                    description=description,
                    cidr=cidr,
                    replace_existing_same_port=_as_bool(
                        replace_existing_same_port, "managed_rules.replace_existing_same_port"
                    ),
                )
            )

        servers_out.append(
            ServerConfig(
                name=name,
                instance_id=instance_id,
                credential=cred_name,
                region=_as_str(region, f"servers[{idx}].region") if region is not None else None,
                endpoint=_as_str(endpoint, f"servers[{idx}].endpoint") if endpoint is not None else None,
                managed_rules=tuple(managed_rules),
            )
        )

    return defaults, credentials_out, servers_out


def build_client(
    *,
    cred_profile: CredentialProfile,
    region: str,
    endpoint: str | None,
) -> lighthouse_client.LighthouseClient:
    secret_id = os.getenv(cred_profile.secret_id_env, "").strip()
    secret_key = os.getenv(cred_profile.secret_key_env, "").strip()
    _require(secret_id and secret_key, f"Missing env vars: {cred_profile.secret_id_env} / {cred_profile.secret_key_env}")

    cred = credential.Credential(secret_id, secret_key)
    http_profile = HttpProfile()
    if endpoint:
        http_profile.endpoint = endpoint
    client_profile = ClientProfile()
    client_profile.httpProfile = http_profile
    return lighthouse_client.LighthouseClient(cred, region, client_profile)


def describe_all_firewall_rules(
    client: lighthouse_client.LighthouseClient, instance_id: str
) -> tuple[int, list[models.FirewallRuleInfo]]:
    rules: list[models.FirewallRuleInfo] = []
    offset = 0
    limit = 100
    firewall_version: int | None = None
    while True:
        req = models.DescribeFirewallRulesRequest()
        req.InstanceId = instance_id
        req.Offset = offset
        req.Limit = limit
        resp = client.DescribeFirewallRules(req)

        firewall_version = int(resp.FirewallVersion)
        batch = list(resp.FirewallRuleSet or [])
        rules.extend(batch)

        total = int(resp.TotalCount)
        offset += len(batch)
        if offset >= total or not batch:
            break
    _require(firewall_version is not None, "DescribeFirewallRules returned no FirewallVersion")
    return firewall_version, rules


def _ruleinfo_to_rule(rule_info: models.FirewallRuleInfo) -> models.FirewallRule:
    r = models.FirewallRule()
    protocol = str(getattr(rule_info, "Protocol", "") or "").upper()
    r.Protocol = protocol or None
    r.Port = getattr(rule_info, "Port", None)
    cidr_block = str(getattr(rule_info, "CidrBlock", "") or "").strip()
    if cidr_block:
        r.CidrBlock = cidr_block
    r.Action = getattr(rule_info, "Action", None)
    r.FirewallRuleDescription = getattr(rule_info, "FirewallRuleDescription", "") or ""
    return r


def _matches_managed(rule: models.FirewallRuleInfo, managed: ManagedRule) -> bool:
    protocol = (getattr(rule, "Protocol", "") or "").upper()
    port = str(getattr(rule, "Port", "") or "")
    action = (getattr(rule, "Action", "") or "").upper()
    if protocol != managed.protocol or port != managed.port or action != managed.action:
        return False
    if managed.replace_existing_same_port:
        return True
    desc = str(getattr(rule, "FirewallRuleDescription", "") or "")
    return desc == (managed.description or "")


def _build_managed_rule(managed: ManagedRule, current_ipv4: str) -> models.FirewallRule:
    desired_cidr = managed.cidr
    if desired_cidr.strip().upper() == "AUTO":
        desired_cidr = f"{current_ipv4}/32"

    r = models.FirewallRule()
    r.Protocol = managed.protocol
    r.Port = managed.port
    r.Action = managed.action
    if managed.protocol == "ICMPV6":
        r.CidrBlock = None
    else:
        ipaddress.ip_network(desired_cidr, strict=False)
        r.CidrBlock = desired_cidr
    r.FirewallRuleDescription = managed.description or ""
    return r


def _rule_identity(rule: models.FirewallRule) -> tuple[str, str, str, str]:
    return (
        str(getattr(rule, "Protocol", "") or "").upper(),
        str(getattr(rule, "Port", "") or ""),
        str(getattr(rule, "CidrBlock", "") or "").strip(),
        str(getattr(rule, "Action", "") or "").upper(),
    )


def _dedupe_rules(rules: Iterable[models.FirewallRule]) -> tuple[list[models.FirewallRule], int]:
    deduped: list[models.FirewallRule] = []
    seen: set[tuple[str, str, str, str]] = set()
    removed = 0
    for rule in rules:
        identity = _rule_identity(rule)
        if identity in seen:
            removed += 1
            continue
        seen.add(identity)
        deduped.append(rule)
    return deduped, removed


def _ruleinfo_identity(rule: models.FirewallRuleInfo) -> tuple[str, str, str, str]:
    return (
        str(getattr(rule, "Protocol", "") or "").upper(),
        str(getattr(rule, "Port", "") or ""),
        str(getattr(rule, "CidrBlock", "") or "").strip(),
        str(getattr(rule, "Action", "") or "").upper(),
    )


def _compute_incremental_update(
    existing: list[models.FirewallRuleInfo],
    managed_rules: Iterable[ManagedRule],
    current_ipv4: str,
) -> tuple[list[models.FirewallRule], list[models.FirewallRule], bool, list[str]]:
    managed = list(managed_rules)
    if not managed:
        return [], [], False, ["no managed_rules configured; skipped"]

    delete_rules: list[models.FirewallRule] = []
    create_rules: list[models.FirewallRule] = []
    notes: list[str] = []
    for managed_rule in managed:
        desired_rule = _build_managed_rule(managed_rule, current_ipv4)
        matched_existing = [rule for rule in existing if _matches_managed(rule, managed_rule)]
        desired_matches = [rule for rule in matched_existing if _ruleinfo_identity(rule) == _rule_identity(desired_rule)]

        if len(matched_existing) == 1 and len(desired_matches) == 1:
            notes.append(f"{managed_rule.protocol} {managed_rule.port} already up-to-date; no changes")
            continue

        delete_rules.extend(_ruleinfo_to_rule(rule) for rule in matched_existing)
        create_rules.append(desired_rule)
        notes.append(
            f"{managed_rule.protocol} {managed_rule.port}: delete {len(matched_existing)} old rule(s), create 1 new rule"
        )

    delete_rules, deduped_deletes = _dedupe_rules(delete_rules)
    create_rules, deduped_creates = _dedupe_rules(create_rules)
    if deduped_deletes:
        notes.append(f"deduplicated {deduped_deletes} delete rule(s)")
    if deduped_creates:
        notes.append(f"deduplicated {deduped_creates} create rule(s)")

    changed = bool(delete_rules or create_rules)
    return delete_rules, create_rules, changed, notes


def _delete_firewall_rules(
    client: lighthouse_client.LighthouseClient,
    *,
    instance_id: str,
    firewall_version: int,
    delete_rules: list[models.FirewallRule],
) -> str:
    req = models.DeleteFirewallRulesRequest()
    req.InstanceId = instance_id
    req.FirewallRules = delete_rules
    req.FirewallVersion = firewall_version
    resp = client.DeleteFirewallRules(req)
    return str(resp.RequestId)


def _create_firewall_rules(
    client: lighthouse_client.LighthouseClient,
    *,
    instance_id: str,
    firewall_version: int,
    create_rules: list[models.FirewallRule],
) -> str:
    req = models.CreateFirewallRulesRequest()
    req.InstanceId = instance_id
    req.FirewallRules = create_rules
    req.FirewallVersion = firewall_version
    resp = client.CreateFirewallRules(req)
    return str(resp.RequestId)


def apply_incremental_update(
    client: lighthouse_client.LighthouseClient,
    *,
    instance_id: str,
    firewall_version: int,
    delete_rules: list[models.FirewallRule],
    create_rules: list[models.FirewallRule],
) -> list[str]:
    request_ids: list[str] = []
    if delete_rules:
        request_ids.append(
            "delete:" + _delete_firewall_rules(
                client, instance_id=instance_id, firewall_version=firewall_version, delete_rules=delete_rules
            )
        )
        firewall_version, _ = describe_all_firewall_rules(client, instance_id)
    if create_rules:
        request_ids.append(
            "create:" + _create_firewall_rules(
                client, instance_id=instance_id, firewall_version=firewall_version, create_rules=create_rules
            )
        )
    return request_ids


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Update Tencent Cloud Lighthouse firewall rules to whitelist current IP.")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).with_suffix(".toml")),
        help="Path to config TOML (default: next to script).",
    )
    parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run).")
    parser.add_argument("--ip", default="", help="Override public IPv4 (skip IP lookup).")
    parser.add_argument("--only-server", action="append", default=[], help="Only run for server name or instance_id.")
    parser.add_argument("--only-credential", action="append", default=[], help="Only run servers using credential name.")
    parser.add_argument("--sleep", type=float, default=0.0, help="Sleep seconds between servers (rate limit safety).")
    args = parser.parse_args(argv)

    defaults, cred_profiles, servers = load_config(Path(args.config))
    only_server = set(args.only_server or [])
    only_credential = set(args.only_credential or [])

    ip_sources = defaults.get("ip_sources", [])
    if not isinstance(ip_sources, list) or not ip_sources:
        ip_sources = ["https://myip.ipip.net/s", "http://whois.pconline.com.cn/ipJson.jsp"]
    ip_sources = [str(x) for x in ip_sources]
    timeout_seconds = float(defaults.get("request_timeout_seconds", 3))

    current_ip = args.ip.strip()
    if current_ip:
        ipaddress.IPv4Address(current_ip)
    else:
        current_ip = get_public_ipv4(ip_sources, timeout_seconds)

    print(f"Public IPv4: {current_ip}")
    print(f"Mode: {'APPLY' if args.apply else 'DRY-RUN'}")

    any_failed = False
    for server in servers:
        if only_server and server.name not in only_server and server.instance_id not in only_server:
            continue
        if only_credential and server.credential not in only_credential:
            continue

        cred_profile = cred_profiles.get(server.credential)
        _require(cred_profile is not None, f"Unknown credential profile: {server.credential} (server={server.name})")

        region = server.region or cred_profile.region
        _require(region is not None, f"Missing region for server {server.name} ({server.instance_id})")
        endpoint = server.endpoint or cred_profile.endpoint or str(defaults.get("endpoint") or "").strip() or None

        print(f"\n== {server.name} ({server.instance_id}) ==")
        try:
            client = build_client(cred_profile=cred_profile, region=region, endpoint=endpoint)
            fw_version, existing = describe_all_firewall_rules(client, server.instance_id)
            delete_rules, create_rules, changed, notes = _compute_incremental_update(
                existing, server.managed_rules, current_ip
            )
            for note in notes:
                print(f"- {note}")
            if not changed:
                continue
            if not args.apply:
                print(
                    f"- would delete {len(delete_rules)} rule(s) and create {len(create_rules)} rule(s) "
                    f"(FirewallVersion={fw_version})"
                )
                continue
            request_ids = apply_incremental_update(
                client,
                instance_id=server.instance_id,
                firewall_version=fw_version,
                delete_rules=delete_rules,
                create_rules=create_rules,
            )
            print(f"- applied ({', '.join(request_ids)})")
        except TencentCloudSDKException as exc:
            any_failed = True
            eprint(f"! TencentCloudSDKException on {server.name} ({server.instance_id}): {exc}")
        except Exception as exc:
            any_failed = True
            eprint(f"! Error on {server.name} ({server.instance_id}): {exc}")
        finally:
            if args.sleep > 0:
                time.sleep(args.sleep)

    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
