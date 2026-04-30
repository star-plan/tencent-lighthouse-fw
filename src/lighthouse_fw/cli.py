"""CLI entry points built on Typer."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import rich.box
import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .lighthouse_api import TencentCloudSDKException, probe_credential_access
from .models import (
    AppDefaults,
    CredentialConfig,
    CredentialSecret,
    DoctorCheck,
    DoctorReport,
    HistoryItem,
    ManagedRule,
    ServerConfig,
    ServerRunResult,
)
from .storage import ConfigRepository
from .updater import execute_run


def _configure_windows_stdio_utf8() -> None:
    """Best-effort UTF-8 stdio setup for legacy Windows console encodings."""

    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                # Keep CLI functional even if the host stream can't be reconfigured.
                pass


_configure_windows_stdio_utf8()
console = Console()
app = typer.Typer(help="Tencent Cloud Lighthouse firewall manager.")
credential_app = typer.Typer(help="Manage credential metadata and secrets.")
server_app = typer.Typer(help="Manage servers and their managed rules.")
config_app = typer.Typer(help="Inspect local config.")
app.add_typer(config_app, name="config")
app.add_typer(credential_app, name="credential")
app.add_typer(server_app, name="server")


def _repository() -> ConfigRepository:
    repository = ConfigRepository()
    repository.initialize()
    return repository


def _format_rule(rule) -> str:
    return f"{rule.protocol}:{rule.port} {rule.action} {rule.cidr} {rule.description}".strip()


def _render_result_table(title: str, results: tuple[ServerRunResult, ...]) -> None:
    table = Table(title=title, box=rich.box.SIMPLE_HEAVY)
    table.add_column("Server")
    table.add_column("Credential")
    table.add_column("状态")
    table.add_column("删除")
    table.add_column("创建")
    table.add_column("说明")
    for result in results:
        detail = "\n".join(result.notes) if result.notes else "-"
        if result.error:
            detail = f"{detail}\n错误: {result.error}" if detail != "-" else f"错误: {result.error}"
        table.add_row(
            f"{result.server_name}\n{result.instance_id}",
            result.credential_name,
            result.status,
            str(len(result.delete_rules)),
            str(len(result.create_rules)),
            detail,
        )
    console.print(table)


def _render_rule_diff(results: tuple[ServerRunResult, ...]) -> None:
    for result in results:
        if result.error:
            continue
        console.print(f"\n[bold]{result.server_name}[/bold] ({result.instance_id})")
        if result.delete_rules:
            console.print("[red]待删除规则[/red]")
            for rule in result.delete_rules:
                console.print(f"  - {_format_rule(rule)}")
        if result.create_rules:
            console.print("[green]待创建规则[/green]")
            for rule in result.create_rules:
                console.print(f"  + {_format_rule(rule)}")
        if not result.delete_rules and not result.create_rules:
            console.print("  无变更。")


def _append_history(repository: ConfigRepository, mode: str, current_ip: str, results: tuple[ServerRunResult, ...]) -> None:
    repository.append_history(
        HistoryItem(
            timestamp=datetime.now(timezone.utc).isoformat(),
            mode=mode,
            current_ip=current_ip,
            selected_servers=tuple(result.server_name for result in results),
            results=results,
        )
    )


def _build_doctor_report(repository: ConfigRepository) -> DoctorReport:
    config = repository.load_config()
    checks: list[DoctorCheck] = [
        DoctorCheck(name="python-version", status="pass", detail="当前包要求 Python 3.11+。"),
        DoctorCheck(name="config-file", status="pass", detail=str(repository.paths.config_file)),
        DoctorCheck(name="secret-backend", status="pass", detail=repository.secret_store.describe_backend()),
    ]
    if not config.credentials:
        checks.append(DoctorCheck(name="credentials", status="skip", detail="当前没有配置 credential。"))
        return DoctorReport(checks=tuple(checks))

    for credential in config.credentials.values():
        try:
            secret = repository.resolve_secret(credential)
            detail = probe_credential_access(
                credential_config=credential,
                credential_secret=secret,
            )
            checks.append(
                DoctorCheck(
                    name=f"credential:{credential.name}",
                    status="pass",
                    detail=detail,
                )
            )
        except TencentCloudSDKException as exc:
            checks.append(
                DoctorCheck(
                    name=f"credential:{credential.name}",
                    status="fail",
                    detail=str(exc),
                )
            )
        except Exception as exc:
            checks.append(
                DoctorCheck(
                    name=f"credential:{credential.name}",
                    status="fail",
                    detail=str(exc),
                )
            )
    return DoctorReport(checks=tuple(checks))


@app.command("version")
def version() -> None:
    """Print the installed package version."""

    console.print(__version__)


@app.command("tui")
def tui() -> None:
    """Launch the TUI explicitly."""

    from .tui import run_tui

    run_tui()


@app.command("init")
def init() -> None:
    """Create the config/state directories and an empty config file."""

    repository = _repository()
    console.print(f"配置文件: {repository.paths.config_file}")
    console.print(f"历史文件: {repository.paths.history_file}")
    console.print(f"密钥后端: {repository.secret_store.describe_backend()}")


@app.command("import-legacy")
def import_legacy(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, help="旧版 tencent_lighthouse_fw.toml 路径。"),
) -> None:
    """Import legacy TOML into the new config model."""

    repository = _repository()
    updated = repository.import_legacy_file(path)
    console.print(f"已导入 {len(updated.credentials)} 个 credential，{len(updated.servers)} 个 server。")


@app.command("doctor")
def doctor() -> None:
    """Run health checks for the local environment and configured credentials."""

    repository = _repository()
    report = _build_doctor_report(repository)
    table = Table(title="lhfw doctor", box=rich.box.SIMPLE_HEAVY)
    table.add_column("检查项")
    table.add_column("状态")
    table.add_column("说明")
    for check in report.checks:
        table.add_row(check.name, check.status, check.detail)
    console.print(table)
    if not report.success:
        raise typer.Exit(code=1)


@app.command("run")
def run(
    apply_changes: bool = typer.Option(False, "--apply", help="实际写入腾讯云防火墙。"),
    yes: bool = typer.Option(False, "--yes", help="跳过 apply 前的显式确认。"),
    server_filters: list[str] = typer.Option([], "--server", help="按 server 名称或 instance_id 过滤。"),
    credential_filters: list[str] = typer.Option([], "--credential", help="按 credential 过滤。"),
    tag_filters: list[str] = typer.Option([], "--tag", help="按 server tag 过滤。"),
    ip_override: str = typer.Option("", "--ip", help="手动指定公网 IPv4。"),
    sleep_seconds: float = typer.Option(0.0, "--sleep", help="每台 server 之间的串行间隔秒数。"),
) -> None:
    """Preview or apply firewall changes for all selected enabled servers."""

    repository = _repository()
    config = repository.load_config()
    preview = execute_run(
        config=config,
        resolve_secret=repository.resolve_secret,
        apply_changes=False,
        server_filters=tuple(server_filters),
        credential_filters=tuple(credential_filters),
        tag_filters=tuple(tag_filters),
        ip_override=ip_override or None,
        sleep_seconds=0.0,
    )
    console.print(f"当前公网 IPv4: [bold]{preview.current_ip}[/bold]")
    _render_result_table("规则预览", preview.results)
    _render_rule_diff(preview.results)
    _append_history(repository, "dry-run", preview.current_ip, preview.results)

    if not apply_changes:
        failed = any(result.status == "error" for result in preview.results)
        if failed:
            raise typer.Exit(code=1)
        return

    if not yes and not typer.confirm("以上 diff 将写入腾讯云防火墙，确认继续吗？"):
        raise typer.Exit(code=1)

    applied = execute_run(
        config=config,
        resolve_secret=repository.resolve_secret,
        apply_changes=True,
        server_filters=tuple(server_filters),
        credential_filters=tuple(credential_filters),
        tag_filters=tuple(tag_filters),
        ip_override=preview.current_ip,
        sleep_seconds=sleep_seconds,
    )
    _render_result_table("执行结果", applied.results)
    _append_history(repository, "apply", applied.current_ip, applied.results)
    if any(result.status == "error" for result in applied.results):
        raise typer.Exit(code=1)


@config_app.command("show")
def show_config() -> None:
    """Show the current config overview."""

    repository = _repository()
    config = repository.load_config()
    console.print(f"defaults.endpoint = {config.defaults.endpoint or '-'}")
    console.print(f"defaults.request_timeout_seconds = {config.defaults.request_timeout_seconds}")
    console.print(f"defaults.history_limit = {config.defaults.history_limit}")
    console.print(f"defaults.ip_sources = {list(config.defaults.ip_sources)}")
    console.print(f"credentials = {list(config.credentials)}")
    console.print(f"servers = {[server.name for server in config.servers]}")


@config_app.command("set-defaults")
def set_defaults(
    endpoint: str = typer.Option("", "--endpoint", help="默认 endpoint。"),
    request_timeout_seconds: float = typer.Option(3.0, "--request-timeout-seconds", help="IP 查询超时秒数。"),
    history_limit: int = typer.Option(20, "--history-limit", help="执行历史保留条数。"),
    ip_source: list[str] = typer.Option([], "--ip-source", help="可重复的 IP 查询源，按顺序生效。"),
) -> None:
    """Update global defaults such as timeout, endpoint, and IP sources."""

    repository = _repository()
    config = repository.load_config()
    repository.update_defaults(
        AppDefaults(
            endpoint=endpoint or None,
            ip_sources=tuple(ip_source) if ip_source else config.defaults.ip_sources,
            request_timeout_seconds=request_timeout_seconds,
            history_limit=history_limit,
        )
    )
    console.print("已更新 defaults。")


@config_app.command("history")
def show_history() -> None:
    """Show recent run history."""

    repository = _repository()
    history = repository.load_history()
    if not history:
        console.print("暂无历史记录。")
        return
    for item in history:
        console.print(f"\n[bold]{item.timestamp}[/bold] mode={item.mode} ip={item.current_ip}")
        _render_result_table("历史摘要", item.results)


@credential_app.command("list")
def credential_list() -> None:
    """List all configured credential profiles."""

    repository = _repository()
    config = repository.load_config()
    table = Table(title="Credentials", box=rich.box.SIMPLE_HEAVY)
    table.add_column("名称")
    table.add_column("Region")
    table.add_column("Endpoint")
    table.add_column("Env")
    table.add_column("Secret")
    for credential in config.credentials.values():
        has_secret = repository.secret_store.get_secret(credential.name) is not None
        env_value = " / ".join(
            value for value in [credential.secret_id_env or "", credential.secret_key_env or ""] if value
        ) or "-"
        table.add_row(
            credential.name,
            credential.region or "-",
            credential.endpoint or "-",
            env_value,
            "stored" if has_secret else "missing",
        )
    console.print(table)


@credential_app.command("set")
def credential_set(
    name: str = typer.Argument(..., help="Credential 名称。"),
    region: str = typer.Option("", "--region", help="默认 region。"),
    endpoint: str = typer.Option("", "--endpoint", help="可选 endpoint。"),
    secret_id_env: str = typer.Option("", "--secret-id-env", help="可选 SecretId 环境变量名。"),
    secret_key_env: str = typer.Option("", "--secret-key-env", help="可选 SecretKey 环境变量名。"),
) -> None:
    """Create or update credential metadata."""

    repository = _repository()
    repository.upsert_credential(
        CredentialConfig(
            name=name,
            region=region or None,
            endpoint=endpoint or None,
            secret_id_env=secret_id_env or None,
            secret_key_env=secret_key_env or None,
        )
    )
    console.print(f"已保存 credential: {name}")


@credential_app.command("set-secret")
def credential_set_secret(
    name: str = typer.Argument(..., help="Credential 名称。"),
    secret_id: str = typer.Option(..., prompt=True, hide_input=True, help="Tencent Cloud SecretId。"),
    secret_key: str = typer.Option(..., prompt=True, hide_input=True, help="Tencent Cloud SecretKey。"),
) -> None:
    """Store secret material in the selected secret backend."""

    repository = _repository()
    repository.set_credential_secret(name, CredentialSecret(secret_id=secret_id, secret_key=secret_key))
    console.print(f"已为 {name} 写入密钥，后端={repository.secret_store.describe_backend()}")


@credential_app.command("clear-secret")
def credential_clear_secret(name: str = typer.Argument(..., help="Credential 名称。")) -> None:
    """Delete secret material for a credential profile."""

    repository = _repository()
    repository.clear_credential_secret(name)
    console.print(f"已清除 {name} 的已保存密钥。")


@credential_app.command("delete")
def credential_delete(name: str = typer.Argument(..., help="Credential 名称。")) -> None:
    """Delete a credential profile."""

    repository = _repository()
    repository.delete_credential(name)
    console.print(f"已删除 credential: {name}")


@server_app.command("list")
def server_list() -> None:
    """List all configured servers."""

    repository = _repository()
    config = repository.load_config()
    table = Table(title="Servers", box=rich.box.SIMPLE_HEAVY)
    table.add_column("名称")
    table.add_column("InstanceId")
    table.add_column("Credential")
    table.add_column("状态")
    table.add_column("Tags")
    table.add_column("Rules")
    for server in config.servers:
        table.add_row(
            server.name,
            server.instance_id,
            server.credential,
            "enabled" if server.enabled else "disabled",
            ", ".join(server.tags) or "-",
            str(len(server.managed_rules)),
        )
    console.print(table)


@server_app.command("set")
def server_set(
    name: str = typer.Argument(..., help="Server 名称。"),
    instance_id: str = typer.Option(..., "--instance-id", help="Lighthouse instance id。"),
    credential: str = typer.Option(..., "--credential", help="绑定的 credential 名称。"),
    region: str = typer.Option("", "--region", help="可选 region 覆盖。"),
    endpoint: str = typer.Option("", "--endpoint", help="可选 endpoint 覆盖。"),
    tag: list[str] = typer.Option([], "--tag", help="可重复的 tag。"),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="是否启用该 server。"),
) -> None:
    """Create or update a server definition."""

    repository = _repository()
    existing = next((server for server in repository.load_config().servers if server.name == name), None)
    managed_rules = existing.managed_rules if existing else ()
    repository.upsert_server(
        ServerConfig(
            name=name,
            instance_id=instance_id,
            credential=credential,
            enabled=enabled,
            tags=tuple(sorted({item.strip() for item in tag if item.strip()})),
            region=region or None,
            endpoint=endpoint or None,
            managed_rules=managed_rules,
        )
    )
    console.print(f"已保存 server: {name}")


@server_app.command("enable")
def server_enable(name: str = typer.Argument(..., help="Server 名称。")) -> None:
    """Enable one server."""

    repository = _repository()
    repository.set_server_enabled(name, True)
    console.print(f"已启用 server: {name}")


@server_app.command("disable")
def server_disable(name: str = typer.Argument(..., help="Server 名称。")) -> None:
    """Disable one server."""

    repository = _repository()
    repository.set_server_enabled(name, False)
    console.print(f"已禁用 server: {name}")


@server_app.command("delete")
def server_delete(name: str = typer.Argument(..., help="Server 名称。")) -> None:
    """Delete one server."""

    repository = _repository()
    repository.delete_server(name)
    console.print(f"已删除 server: {name}")


@server_app.command("rule-list")
def server_rule_list(name: str = typer.Argument(..., help="Server 名称。")) -> None:
    """List all managed rules for one server."""

    repository = _repository()
    config = repository.load_config()
    server = next((item for item in config.servers if item.name == name), None)
    if server is None:
        raise typer.BadParameter(f"未找到 server: {name}")
    table = Table(title=f"Rules: {name}", box=rich.box.SIMPLE_HEAVY)
    table.add_column("Index")
    table.add_column("Protocol")
    table.add_column("Port")
    table.add_column("CIDR")
    table.add_column("Action")
    table.add_column("Description")
    for index, rule in enumerate(server.managed_rules):
        table.add_row(str(index), rule.protocol, rule.port, rule.cidr, rule.action, rule.description or "-")
    console.print(table)


@server_app.command("rule-add")
def server_rule_add(
    name: str = typer.Argument(..., help="Server 名称。"),
    protocol: str = typer.Option(..., "--protocol", help="协议，例如 TCP。"),
    port: str = typer.Option(..., "--port", help="端口或端口范围。"),
    cidr: str = typer.Option("AUTO", "--cidr", help="CIDR，默认 AUTO。"),
    description: str = typer.Option("", "--description", help="规则描述。"),
    action: str = typer.Option("ACCEPT", "--action", help="动作，默认 ACCEPT。"),
    replace_existing_same_port: bool = typer.Option(
        True,
        "--replace-existing-same-port/--preserve-existing",
        help="是否替换相同协议/端口/动作的旧规则。",
    ),
) -> None:
    """Append one managed rule to a server."""

    repository = _repository()
    config = repository.load_config()
    server = next((item for item in config.servers if item.name == name), None)
    if server is None:
        raise typer.BadParameter(f"未找到 server: {name}")
    updated_rules = server.managed_rules + (
        ManagedRule(
            protocol=protocol.upper(),
            port=port,
            action=action.upper(),
            description=description,
            cidr=cidr,
            replace_existing_same_port=replace_existing_same_port,
        ),
    )
    repository.replace_server_rules(name, updated_rules)
    console.print(f"已向 {name} 添加规则。")


@server_app.command("rule-delete")
def server_rule_delete(
    name: str = typer.Argument(..., help="Server 名称。"),
    index: int = typer.Argument(..., help="规则序号，从 0 开始。"),
) -> None:
    """Delete one managed rule by index."""

    repository = _repository()
    config = repository.load_config()
    server = next((item for item in config.servers if item.name == name), None)
    if server is None:
        raise typer.BadParameter(f"未找到 server: {name}")
    if index < 0 or index >= len(server.managed_rules):
        raise typer.BadParameter(f"规则索引越界: {index}")
    updated_rules = tuple(rule for offset, rule in enumerate(server.managed_rules) if offset != index)
    repository.replace_server_rules(name, updated_rules)
    console.print(f"已删除 {name} 的规则 #{index}。")

