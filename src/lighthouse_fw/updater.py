"""Firewall diffing, selection, preview, and execution."""

from __future__ import annotations

import ipaddress
import time

from .ip_lookup import get_public_ipv4
from .lighthouse_api import TencentCloudSDKException, apply_incremental_update, build_client, describe_all_firewall_rules
from .models import (
    AppConfig,
    CredentialConfig,
    ManagedRule,
    RuleSpec,
    RunSummary,
    ServerConfig,
    ServerRunResult,
)


def _resolve_region(server: ServerConfig, credential_config: CredentialConfig) -> str:
    region = server.region or credential_config.region
    if not region:
        raise RuntimeError(f"server {server.name} 缺少 region，且其 credential 也没有 region。")
    return region


def _resolve_endpoint(config: AppConfig, server: ServerConfig, credential_config: CredentialConfig) -> str | None:
    return server.endpoint or credential_config.endpoint or config.defaults.endpoint


def _rule_identity(rule: RuleSpec) -> tuple[str, str, str, str]:
    return (rule.protocol.upper(), rule.port, rule.cidr.strip(), rule.action.upper())


def _dedupe_rules(rules: list[RuleSpec]) -> tuple[tuple[RuleSpec, ...], int]:
    deduped = []
    seen: set[tuple[str, str, str, str]] = set()
    removed = 0
    for rule in rules:
        identity = _rule_identity(rule)
        if identity in seen:
            removed += 1
            continue
        seen.add(identity)
        deduped.append(rule)
    return tuple(deduped), removed


def _matches_managed(existing_rule: RuleSpec, managed_rule: ManagedRule) -> bool:
    if (
        existing_rule.protocol.upper() != managed_rule.protocol.upper()
        or existing_rule.port != managed_rule.port
        or existing_rule.action.upper() != managed_rule.action.upper()
    ):
        return False
    if managed_rule.replace_existing_same_port:
        return True
    return existing_rule.description == (managed_rule.description or "")


def _build_desired_rule(managed_rule: ManagedRule, current_ipv4: str) -> RuleSpec:
    desired_cidr = managed_rule.cidr
    if desired_cidr.strip().upper() == "AUTO":
        desired_cidr = f"{current_ipv4}/32"
    if managed_rule.protocol.upper() != "ICMPV6":
        ipaddress.ip_network(desired_cidr, strict=False)
    return RuleSpec(
        protocol=managed_rule.protocol.upper(),
        port=managed_rule.port,
        cidr=desired_cidr,
        action=managed_rule.action.upper(),
        description=managed_rule.description or "",
    )


def compute_incremental_update(
    existing_rules: list[RuleSpec],
    managed_rules: tuple[ManagedRule, ...],
    current_ipv4: str,
) -> tuple[tuple[RuleSpec, ...], tuple[RuleSpec, ...], bool, tuple[str, ...]]:
    """Calculate the delete/create diff for a server without mutating anything."""

    if not managed_rules:
        return (), (), False, ("没有配置 managed_rules，已跳过。",)

    delete_rules: list[RuleSpec] = []
    create_rules: list[RuleSpec] = []
    notes: list[str] = []
    for managed_rule in managed_rules:
        desired_rule = _build_desired_rule(managed_rule, current_ipv4)
        matched_existing = [rule for rule in existing_rules if _matches_managed(rule, managed_rule)]
        desired_matches = [rule for rule in matched_existing if _rule_identity(rule) == _rule_identity(desired_rule)]
        if len(matched_existing) == 1 and len(desired_matches) == 1:
            notes.append(f"{managed_rule.protocol} {managed_rule.port} 已是最新状态，无需修改。")
            continue
        delete_rules.extend(matched_existing)
        create_rules.append(desired_rule)
        notes.append(
            f"{managed_rule.protocol} {managed_rule.port}: 删除 {len(matched_existing)} 条旧规则，创建 1 条新规则。"
        )

    delete_rules_out, removed_deletes = _dedupe_rules(delete_rules)
    create_rules_out, removed_creates = _dedupe_rules(create_rules)
    if removed_deletes:
        notes.append(f"去重了 {removed_deletes} 条重复删除规则。")
    if removed_creates:
        notes.append(f"去重了 {removed_creates} 条重复创建规则。")
    changed = bool(delete_rules_out or create_rules_out)
    return delete_rules_out, create_rules_out, changed, tuple(notes)


def select_servers(
    config: AppConfig,
    *,
    server_filters: tuple[str, ...] = (),
    credential_filters: tuple[str, ...] = (),
    tag_filters: tuple[str, ...] = (),
) -> list[ServerConfig]:
    """Apply CLI / TUI filters and return the enabled servers that should run."""

    server_filter_set = {item.strip() for item in server_filters if item.strip()}
    credential_filter_set = {item.strip() for item in credential_filters if item.strip()}
    tag_filter_set = {item.strip() for item in tag_filters if item.strip()}
    selected = []
    for server in config.servers:
        if not server.enabled:
            continue
        if server_filter_set and server.name not in server_filter_set and server.instance_id not in server_filter_set:
            continue
        if credential_filter_set and server.credential not in credential_filter_set:
            continue
        if tag_filter_set and not (set(server.tags) & tag_filter_set):
            continue
        selected.append(server)
    return selected


def execute_run(
    *,
    config: AppConfig,
    resolve_secret,
    apply_changes: bool,
    server_filters: tuple[str, ...] = (),
    credential_filters: tuple[str, ...] = (),
    tag_filters: tuple[str, ...] = (),
    ip_override: str | None = None,
    sleep_seconds: float = 0.0,
) -> RunSummary:
    """
    Run the firewall workflow for all selected servers.

    The flow is intentionally serial and continue-on-error because the user explicitly
    asked for predictable batch execution and a final per-server summary.
    """

    selected_servers = select_servers(
        config,
        server_filters=server_filters,
        credential_filters=credential_filters,
        tag_filters=tag_filters,
    )
    current_ip = ip_override.strip() if ip_override else ""
    if not selected_servers:
        return RunSummary(current_ip=current_ip or "-", apply=apply_changes, results=())
    if current_ip:
        ipaddress.IPv4Address(current_ip)
    else:
        current_ip = get_public_ipv4(config.defaults.ip_sources, config.defaults.request_timeout_seconds)
    results: list[ServerRunResult] = []
    for server in selected_servers:
        request_ids: tuple[str, ...] = ()
        delete_rules: tuple[RuleSpec, ...] = ()
        create_rules: tuple[RuleSpec, ...] = ()
        notes: tuple[str, ...] = ()
        changed = False
        try:
            credential_config = config.credentials.get(server.credential)
            if credential_config is None:
                raise RuntimeError(f"server {server.name} 引用了不存在的 credential: {server.credential}")
            credential_secret = resolve_secret(credential_config)
            client = build_client(
                credential_config=credential_config,
                credential_secret=credential_secret,
                region=_resolve_region(server, credential_config),
                endpoint=_resolve_endpoint(config, server, credential_config),
            )
            firewall_version, existing_rules = describe_all_firewall_rules(client, server.instance_id)
            delete_rules, create_rules, changed, notes = compute_incremental_update(
                existing_rules,
                server.managed_rules,
                current_ip,
            )
            status = "planned"
            if apply_changes:
                if changed:
                    request_ids = apply_incremental_update(
                        client,
                        instance_id=server.instance_id,
                        firewall_version=firewall_version,
                        delete_rules=delete_rules,
                        create_rules=create_rules,
                    )
                    status = "applied"
                else:
                    status = "noop"
            else:
                if not changed:
                    status = "noop"
            results.append(
                ServerRunResult(
                    server_name=server.name,
                    instance_id=server.instance_id,
                    credential_name=server.credential,
                    status=status,
                    changed=changed,
                    delete_rules=delete_rules,
                    create_rules=create_rules,
                    notes=notes,
                    request_ids=request_ids,
                )
            )
        except TencentCloudSDKException as exc:
            results.append(
                ServerRunResult(
                    server_name=server.name,
                    instance_id=server.instance_id,
                    credential_name=server.credential,
                    status="error",
                    changed=changed,
                    delete_rules=delete_rules,
                    create_rules=create_rules,
                    notes=notes,
                    error=str(exc),
                )
            )
        except Exception as exc:
            results.append(
                ServerRunResult(
                    server_name=server.name,
                    instance_id=server.instance_id,
                    credential_name=server.credential,
                    status="error",
                    changed=changed,
                    delete_rules=delete_rules,
                    create_rules=create_rules,
                    notes=notes,
                    error=str(exc),
                )
            )
        finally:
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
    return RunSummary(current_ip=current_ip, apply=apply_changes, results=tuple(results))

