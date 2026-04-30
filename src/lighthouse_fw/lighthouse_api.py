"""Tencent Cloud Lighthouse API helpers."""

from __future__ import annotations

import ipaddress

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.lighthouse.v20200324 import lighthouse_client, models

from .models import CredentialConfig, CredentialSecret, RuleSpec


def build_client(
    *,
    credential_config: CredentialConfig,
    credential_secret: CredentialSecret,
    region: str,
    endpoint: str | None,
) -> lighthouse_client.LighthouseClient:
    """Build a Tencent Cloud SDK client for one credential profile."""

    cred = credential.Credential(credential_secret.secret_id, credential_secret.secret_key)
    http_profile = HttpProfile()
    if endpoint:
        http_profile.endpoint = endpoint
    client_profile = ClientProfile()
    client_profile.httpProfile = http_profile
    return lighthouse_client.LighthouseClient(cred, region, client_profile)


def _sdk_rule_to_spec(rule_info: models.FirewallRuleInfo) -> RuleSpec:
    return RuleSpec(
        protocol=str(getattr(rule_info, "Protocol", "") or "").upper(),
        port=str(getattr(rule_info, "Port", "") or ""),
        cidr=str(getattr(rule_info, "CidrBlock", "") or "").strip(),
        action=str(getattr(rule_info, "Action", "") or "").upper(),
        description=str(getattr(rule_info, "FirewallRuleDescription", "") or ""),
    )


def _spec_to_sdk_rule(rule: RuleSpec) -> models.FirewallRule:
    firewall_rule = models.FirewallRule()
    firewall_rule.Protocol = rule.protocol
    firewall_rule.Port = rule.port
    firewall_rule.Action = rule.action
    firewall_rule.FirewallRuleDescription = rule.description
    if rule.protocol == "ICMPV6":
        firewall_rule.CidrBlock = None
    else:
        ipaddress.ip_network(rule.cidr, strict=False)
        firewall_rule.CidrBlock = rule.cidr
    return firewall_rule


def describe_all_firewall_rules(
    client: lighthouse_client.LighthouseClient,
    instance_id: str,
) -> tuple[int, list[RuleSpec]]:
    """Fetch every firewall rule for one Lighthouse instance."""

    rules: list[RuleSpec] = []
    offset = 0
    limit = 100
    firewall_version: int | None = None
    while True:
        request = models.DescribeFirewallRulesRequest()
        request.InstanceId = instance_id
        request.Offset = offset
        request.Limit = limit
        response = client.DescribeFirewallRules(request)
        firewall_version = int(response.FirewallVersion)
        batch = list(response.FirewallRuleSet or [])
        rules.extend(_sdk_rule_to_spec(rule_info) for rule_info in batch)
        total = int(response.TotalCount)
        offset += len(batch)
        if offset >= total or not batch:
            break
    if firewall_version is None:
        raise RuntimeError("DescribeFirewallRules 没有返回 FirewallVersion。")
    return firewall_version, rules


def _delete_firewall_rules(
    client: lighthouse_client.LighthouseClient,
    *,
    instance_id: str,
    firewall_version: int,
    delete_rules: tuple[RuleSpec, ...],
) -> str:
    request = models.DeleteFirewallRulesRequest()
    request.InstanceId = instance_id
    request.FirewallVersion = firewall_version
    request.FirewallRules = [_spec_to_sdk_rule(rule) for rule in delete_rules]
    response = client.DeleteFirewallRules(request)
    return str(response.RequestId)


def _create_firewall_rules(
    client: lighthouse_client.LighthouseClient,
    *,
    instance_id: str,
    firewall_version: int,
    create_rules: tuple[RuleSpec, ...],
) -> str:
    request = models.CreateFirewallRulesRequest()
    request.InstanceId = instance_id
    request.FirewallVersion = firewall_version
    request.FirewallRules = [_spec_to_sdk_rule(rule) for rule in create_rules]
    response = client.CreateFirewallRules(request)
    return str(response.RequestId)


def apply_incremental_update(
    client: lighthouse_client.LighthouseClient,
    *,
    instance_id: str,
    firewall_version: int,
    delete_rules: tuple[RuleSpec, ...],
    create_rules: tuple[RuleSpec, ...],
) -> tuple[str, ...]:
    """Apply a prepared rule diff and return the generated request ids."""

    request_ids: list[str] = []
    current_version = firewall_version
    if delete_rules:
        request_ids.append(
            "delete:" + _delete_firewall_rules(
                client,
                instance_id=instance_id,
                firewall_version=current_version,
                delete_rules=delete_rules,
            )
        )
        current_version, _ = describe_all_firewall_rules(client, instance_id)
    if create_rules:
        request_ids.append(
            "create:" + _create_firewall_rules(
                client,
                instance_id=instance_id,
                firewall_version=current_version,
                create_rules=create_rules,
            )
        )
    return tuple(request_ids)


def probe_credential_access(
    *,
    credential_config: CredentialConfig,
    credential_secret: CredentialSecret,
) -> str:
    """Run a read-only SDK call to verify the credential and endpoint are usable."""

    if not credential_config.region:
        raise RuntimeError(f"credential {credential_config.name} 缺少 region，无法执行远程探测。")
    client = build_client(
        credential_config=credential_config,
        credential_secret=credential_secret,
        region=credential_config.region,
        endpoint=credential_config.endpoint,
    )
    request = models.DescribeInstancesRequest()
    request.Limit = 1
    response = client.DescribeInstances(request)
    total_count = int(getattr(response, "TotalCount", 0) or 0)
    return f"成功访问 Lighthouse API，当前账号在 region={credential_config.region} 下可见实例数：{total_count}"


__all__ = [
    "TencentCloudSDKException",
    "apply_incremental_update",
    "build_client",
    "describe_all_firewall_rules",
    "probe_credential_access",
]

