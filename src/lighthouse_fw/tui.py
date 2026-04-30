"""Interactive TUI for editing config, previewing diffs, and running updates."""

from __future__ import annotations

from dataclasses import replace

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Label, RichLog, Static, TabbedContent, TabPane

from .models import CredentialConfig, CredentialSecret, ManagedRule, ServerConfig
from .storage import ConfigRepository
from .updater import RunSummary, execute_run


class ConfirmScreen(ModalScreen[bool]):
    """Confirmation screen shown before apply."""

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self.title_text = title
        self.body_text = body

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(f"[bold]{self.title_text}[/bold]")
            yield Static(self.body_text)
            with Horizontal():
                yield Button("确认", id="confirm-yes", variant="success")
                yield Button("取消", id="confirm-no", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")


class CredentialEditorScreen(ModalScreen[dict[str, str] | None]):
    """Modal editor for credential metadata and optional secret material."""

    def __init__(self, credential: CredentialConfig | None = None) -> None:
        super().__init__()
        self.credential = credential
        self.show_secret = False

    def compose(self) -> ComposeResult:
        yield Static("[bold]Credential 编辑[/bold]")
        yield Label("名称")
        yield Input(value=self.credential.name if self.credential else "", id="credential-name")
        yield Label("Region")
        yield Input(value=self.credential.region or "" if self.credential else "", id="credential-region")
        yield Label("Endpoint")
        yield Input(value=self.credential.endpoint or "" if self.credential else "", id="credential-endpoint")
        yield Label("SecretId 环境变量名")
        yield Input(value=self.credential.secret_id_env or "" if self.credential else "", id="credential-secret-id-env")
        yield Label("SecretKey 环境变量名")
        yield Input(value=self.credential.secret_key_env or "" if self.credential else "", id="credential-secret-key-env")
        yield Label("SecretId（留空表示不修改）")
        yield Input(value="", id="credential-secret-id", password=True)
        yield Label("SecretKey（留空表示不修改）")
        yield Input(value="", id="credential-secret-key", password=True)
        with Horizontal():
            yield Button("临时显示/隐藏密钥", id="credential-toggle-secret")
            yield Button("保存", id="credential-save", variant="success")
            yield Button("取消", id="credential-cancel", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "credential-toggle-secret":
            self.show_secret = not self.show_secret
            self.query_one("#credential-secret-id", Input).password = not self.show_secret
            self.query_one("#credential-secret-key", Input).password = not self.show_secret
            return
        if event.button.id == "credential-cancel":
            self.dismiss(None)
            return
        if event.button.id == "credential-save":
            payload = {
                "name": self.query_one("#credential-name", Input).value.strip(),
                "region": self.query_one("#credential-region", Input).value.strip(),
                "endpoint": self.query_one("#credential-endpoint", Input).value.strip(),
                "secret_id_env": self.query_one("#credential-secret-id-env", Input).value.strip(),
                "secret_key_env": self.query_one("#credential-secret-key-env", Input).value.strip(),
                "secret_id": self.query_one("#credential-secret-id", Input).value.strip(),
                "secret_key": self.query_one("#credential-secret-key", Input).value.strip(),
            }
            self.dismiss(payload)


class RuleEditorScreen(ModalScreen[ManagedRule | None]):
    """Modal editor for one managed firewall rule."""

    def __init__(self, rule: ManagedRule | None = None) -> None:
        super().__init__()
        self.rule = rule

    def compose(self) -> ComposeResult:
        rule = self.rule or ManagedRule(protocol="TCP", port="")
        yield Static("[bold]Managed Rule 编辑[/bold]")
        yield Label("Protocol")
        yield Input(value=rule.protocol, id="rule-protocol")
        yield Label("Port")
        yield Input(value=rule.port, id="rule-port")
        yield Label("CIDR")
        yield Input(value=rule.cidr, id="rule-cidr")
        yield Label("Action")
        yield Input(value=rule.action, id="rule-action")
        yield Label("Description")
        yield Input(value=rule.description, id="rule-description")
        yield Checkbox("替换相同协议/端口/动作的旧规则", value=rule.replace_existing_same_port, id="rule-replace")
        with Horizontal():
            yield Button("保存", id="rule-save", variant="success")
            yield Button("取消", id="rule-cancel", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "rule-cancel":
            self.dismiss(None)
            return
        if event.button.id == "rule-save":
            self.dismiss(
                ManagedRule(
                    protocol=self.query_one("#rule-protocol", Input).value.strip().upper() or "TCP",
                    port=self.query_one("#rule-port", Input).value.strip(),
                    cidr=self.query_one("#rule-cidr", Input).value.strip() or "AUTO",
                    action=self.query_one("#rule-action", Input).value.strip().upper() or "ACCEPT",
                    description=self.query_one("#rule-description", Input).value.strip(),
                    replace_existing_same_port=self.query_one("#rule-replace", Checkbox).value,
                )
            )


class ServerEditorScreen(ModalScreen[ServerConfig | None]):
    """Modal editor for one server plus its full managed_rules list."""

    def __init__(self, credentials: list[str], server: ServerConfig | None = None) -> None:
        super().__init__()
        self.credentials = credentials
        self.server = server
        self.rules = list(server.managed_rules if server else ())

    def compose(self) -> ComposeResult:
        server = self.server or ServerConfig(name="", instance_id="", credential=self.credentials[0] if self.credentials else "")
        yield Static("[bold]Server 编辑[/bold]")
        yield Label(f"可用 credential: {', '.join(self.credentials) or '-'}")
        yield Label("名称")
        yield Input(value=server.name, id="server-name")
        yield Label("Instance ID")
        yield Input(value=server.instance_id, id="server-instance-id")
        yield Label("Credential")
        yield Input(value=server.credential, id="server-credential")
        yield Label("Region（可选覆盖）")
        yield Input(value=server.region or "", id="server-region")
        yield Label("Endpoint（可选覆盖）")
        yield Input(value=server.endpoint or "", id="server-endpoint")
        yield Label("Tags（逗号分隔）")
        yield Input(value=", ".join(server.tags), id="server-tags")
        yield Checkbox("启用该 server", value=server.enabled, id="server-enabled")
        yield Static("[bold]Managed Rules[/bold]")
        yield DataTable(id="server-rules-table")
        with Horizontal():
            yield Button("新增规则", id="rule-add")
            yield Button("编辑规则", id="rule-edit")
            yield Button("删除规则", id="rule-delete")
        with Horizontal():
            yield Button("保存", id="server-save", variant="success")
            yield Button("取消", id="server-cancel", variant="error")

    def on_mount(self) -> None:
        table = self.query_one("#server-rules-table", DataTable)
        table.add_columns("Index", "Protocol", "Port", "CIDR", "Action", "Description")
        self._refresh_rules_table()

    def _refresh_rules_table(self) -> None:
        table = self.query_one("#server-rules-table", DataTable)
        table.clear(columns=False)
        for index, rule in enumerate(self.rules):
            table.add_row(str(index), rule.protocol, rule.port, rule.cidr, rule.action, rule.description or "-")

    def _selected_rule_index(self) -> int | None:
        table = self.query_one("#server-rules-table", DataTable)
        cursor_row = table.cursor_row
        if cursor_row is None or cursor_row < 0 or cursor_row >= len(self.rules):
            return None
        return int(cursor_row)

    def _save_rule_callback(self, index: int | None):
        def callback(rule: ManagedRule | None) -> None:
            if rule is None:
                return
            if index is None:
                self.rules.append(rule)
            else:
                self.rules[index] = rule
            self._refresh_rules_table()

        return callback

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "server-cancel":
            self.dismiss(None)
            return
        if event.button.id == "rule-add":
            self.app.push_screen(RuleEditorScreen(), self._save_rule_callback(None))
            return
        if event.button.id == "rule-edit":
            index = self._selected_rule_index()
            if index is not None:
                self.app.push_screen(RuleEditorScreen(self.rules[index]), self._save_rule_callback(index))
            return
        if event.button.id == "rule-delete":
            index = self._selected_rule_index()
            if index is not None:
                del self.rules[index]
                self._refresh_rules_table()
            return
        if event.button.id == "server-save":
            tags = tuple(sorted({tag.strip() for tag in self.query_one("#server-tags", Input).value.split(",") if tag.strip()}))
            self.dismiss(
                ServerConfig(
                    name=self.query_one("#server-name", Input).value.strip(),
                    instance_id=self.query_one("#server-instance-id", Input).value.strip(),
                    credential=self.query_one("#server-credential", Input).value.strip(),
                    enabled=self.query_one("#server-enabled", Checkbox).value,
                    tags=tags,
                    region=self.query_one("#server-region", Input).value.strip() or None,
                    endpoint=self.query_one("#server-endpoint", Input).value.strip() or None,
                    managed_rules=tuple(self.rules),
                )
            )


class LighthouseTuiApp(App[None]):
    """Default TUI entry point used by `uvx lighthouse-fw` and `lhfw` without args."""

    BINDINGS = [("q", "quit", "退出"), ("r", "refresh", "刷新")]
    TITLE = "lighthouse-fw"

    def __init__(self, repository: ConfigRepository) -> None:
        super().__init__()
        self.repository = repository
        self.selected_servers: set[str] = set()
        self.server_order: list[str] = []
        self.credential_order: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Servers", id="tab-servers"):
                yield Static("在这里维护 server、tags、enabled 状态和完整 managed_rules。")
                yield DataTable(id="servers-table")
                with Horizontal():
                    yield Button("新增", id="server-add")
                    yield Button("编辑", id="server-edit")
                    yield Button("切换启用", id="server-toggle-enabled")
                    yield Button("切换选中", id="server-toggle-selected")
                    yield Button("删除", id="server-delete", variant="error")
            with TabPane("Credentials", id="tab-credentials"):
                yield Static("在这里维护 credential 元信息，以及按需写入/清空密钥。")
                yield DataTable(id="credentials-table")
                with Horizontal():
                    yield Button("新增", id="credential-add")
                    yield Button("编辑", id="credential-edit")
                    yield Button("清空密钥", id="credential-clear-secret")
                    yield Button("删除", id="credential-delete", variant="error")
            with TabPane("Run", id="tab-run"):
                yield Static("已选 server", id="run-selected-summary")
                yield Label("按标签选中（逗号分隔，匹配任一 tag）")
                yield Input(placeholder="prod, sg", id="run-tags")
                with Horizontal():
                    yield Button("按标签选中", id="run-select-by-tag")
                    yield Button("选中全部已启用", id="run-select-all")
                    yield Button("清空选中", id="run-clear-selection")
                with Horizontal():
                    yield Button("预览 Diff", id="run-preview")
                    yield Button("Apply", id="run-apply", variant="success")
                    yield Button("运行 Doctor", id="run-doctor")
                yield RichLog(id="run-log", wrap=True, highlight=False, markup=False)
            with TabPane("History", id="tab-history"):
                yield Static("最近 20 次执行历史（保留 diff 摘要和结果状态）。")
                yield DataTable(id="history-table")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#servers-table", DataTable).add_columns("选中", "名称", "InstanceId", "Credential", "状态", "Tags", "Rules")
        self.query_one("#credentials-table", DataTable).add_columns("名称", "Region", "Endpoint", "Env", "Secret")
        self.query_one("#history-table", DataTable).add_columns("时间", "模式", "IP", "结果数", "状态摘要")
        self.refresh_views()

    def action_refresh(self) -> None:
        self.refresh_views()

    def _log(self, text: str) -> None:
        self.query_one("#run-log", RichLog).write(text)

    def _current_server_name(self) -> str | None:
        table = self.query_one("#servers-table", DataTable)
        cursor_row = table.cursor_row
        if cursor_row is None or cursor_row < 0 or cursor_row >= len(self.server_order):
            return None
        return self.server_order[int(cursor_row)]

    def _current_credential_name(self) -> str | None:
        table = self.query_one("#credentials-table", DataTable)
        cursor_row = table.cursor_row
        if cursor_row is None or cursor_row < 0 or cursor_row >= len(self.credential_order):
            return None
        return self.credential_order[int(cursor_row)]

    def _format_result_summary(self, summary: RunSummary) -> str:
        lines = [f"mode={'apply' if summary.apply else 'dry-run'} ip={summary.current_ip}"]
        for result in summary.results:
            lines.append(
                f"- {result.server_name} [{result.status}] delete={len(result.delete_rules)} create={len(result.create_rules)}"
            )
            for rule in result.delete_rules:
                lines.append(f"    DELETE {rule.protocol}:{rule.port} {rule.cidr} {rule.action} {rule.description}")
            for rule in result.create_rules:
                lines.append(f"    CREATE {rule.protocol}:{rule.port} {rule.cidr} {rule.action} {rule.description}")
            for note in result.notes:
                lines.append(f"    NOTE   {note}")
            if result.error:
                lines.append(f"    ERROR  {result.error}")
        return "\n".join(lines)

    def refresh_views(self) -> None:
        config = self.repository.load_config()
        history = self.repository.load_history()

        servers_table = self.query_one("#servers-table", DataTable)
        servers_table.clear(columns=False)
        self.server_order = []
        available_names = {server.name for server in config.servers}
        self.selected_servers &= available_names
        for server in config.servers:
            self.server_order.append(server.name)
            servers_table.add_row(
                "✓" if server.name in self.selected_servers else "",
                server.name,
                server.instance_id,
                server.credential,
                "enabled" if server.enabled else "disabled",
                ", ".join(server.tags) or "-",
                str(len(server.managed_rules)),
            )

        credentials_table = self.query_one("#credentials-table", DataTable)
        credentials_table.clear(columns=False)
        self.credential_order = []
        for credential in config.credentials.values():
            self.credential_order.append(credential.name)
            has_secret = self.repository.secret_store.get_secret(credential.name) is not None
            env_value = " / ".join(
                value for value in [credential.secret_id_env or "", credential.secret_key_env or ""] if value
            ) or "-"
            credentials_table.add_row(
                credential.name,
                credential.region or "-",
                credential.endpoint or "-",
                env_value,
                "stored" if has_secret else "missing",
            )

        history_table = self.query_one("#history-table", DataTable)
        history_table.clear(columns=False)
        for item in history:
            summary = ", ".join(f"{result.server_name}:{result.status}" for result in item.results) or "-"
            history_table.add_row(item.timestamp, item.mode, item.current_ip, str(len(item.results)), summary)

        summary_text = ", ".join(sorted(self.selected_servers)) or "未显式选中；执行时会默认使用全部 enabled server。"
        self.query_one("#run-selected-summary", Static).update(f"已选 server: {summary_text}")

    def _save_credential_callback(self, existing_name: str | None = None):
        def callback(payload: dict[str, str] | None) -> None:
            if payload is None:
                return
            name = payload["name"]
            if not name:
                self._log("credential 名称不能为空。")
                return
            self.repository.upsert_credential(
                CredentialConfig(
                    name=name,
                    region=payload["region"] or None,
                    endpoint=payload["endpoint"] or None,
                    secret_id_env=payload["secret_id_env"] or None,
                    secret_key_env=payload["secret_key_env"] or None,
                )
            )
            if payload["secret_id"] and payload["secret_key"]:
                self.repository.set_credential_secret(
                    name,
                    CredentialSecret(secret_id=payload["secret_id"], secret_key=payload["secret_key"]),
                )
            if existing_name and existing_name != name:
                self.repository.delete_credential(existing_name)
            self.refresh_views()

        return callback

    def _save_server_callback(self):
        def callback(server: ServerConfig | None) -> None:
            if server is None:
                return
            if not server.name or not server.instance_id or not server.credential:
                self._log("server 名称、instance_id 和 credential 不能为空。")
                return
            self.repository.upsert_server(server)
            self.refresh_views()

        return callback

    def _run_filters(self) -> tuple[str, ...]:
        if self.selected_servers:
            return tuple(sorted(self.selected_servers))
        return ()

    def _tag_select(self) -> None:
        config = self.repository.load_config()
        tag_input = self.query_one("#run-tags", Input).value
        tags = {tag.strip() for tag in tag_input.split(",") if tag.strip()}
        if not tags:
            self._log("请输入至少一个 tag。")
            return
        self.selected_servers = {
            server.name for server in config.servers if server.enabled and tags.intersection(server.tags)
        }
        self.refresh_views()

    def _preview_selected(self) -> RunSummary:
        config = self.repository.load_config()
        summary = execute_run(
            config=config,
            resolve_secret=self.repository.resolve_secret,
            apply_changes=False,
            server_filters=self._run_filters(),
        )
        self._log(self._format_result_summary(summary))
        return summary

    def _apply_after_confirm(self, confirmed: bool, preview: RunSummary) -> None:
        if not confirmed:
            self._log("已取消 apply。")
            return
        config = self.repository.load_config()
        summary = execute_run(
            config=config,
            resolve_secret=self.repository.resolve_secret,
            apply_changes=True,
            server_filters=self._run_filters(),
            ip_override=preview.current_ip,
        )
        self._log(self._format_result_summary(summary))
        from .cli import _append_history

        _append_history(self.repository, "apply", summary.current_ip, summary.results)
        self.refresh_views()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "server-add":
            self.push_screen(ServerEditorScreen(list(self.repository.load_config().credentials)), self._save_server_callback())
            return
        if button_id == "server-edit":
            current_name = self._current_server_name()
            if not current_name:
                return
            config = self.repository.load_config()
            server = next((item for item in config.servers if item.name == current_name), None)
            if server:
                self.push_screen(
                    ServerEditorScreen(list(config.credentials), server),
                    self._save_server_callback(),
                )
            return
        if button_id == "server-toggle-enabled":
            current_name = self._current_server_name()
            if current_name:
                config = self.repository.load_config()
                server = next((item for item in config.servers if item.name == current_name), None)
                if server:
                    self.repository.set_server_enabled(current_name, not server.enabled)
                    self.refresh_views()
            return
        if button_id == "server-toggle-selected":
            current_name = self._current_server_name()
            if current_name:
                if current_name in self.selected_servers:
                    self.selected_servers.remove(current_name)
                else:
                    self.selected_servers.add(current_name)
                self.refresh_views()
            return
        if button_id == "server-delete":
            current_name = self._current_server_name()
            if current_name:
                self.repository.delete_server(current_name)
                self.selected_servers.discard(current_name)
                self.refresh_views()
            return

        if button_id == "credential-add":
            self.push_screen(CredentialEditorScreen(), self._save_credential_callback())
            return
        if button_id == "credential-edit":
            current_name = self._current_credential_name()
            if not current_name:
                return
            config = self.repository.load_config()
            credential = config.credentials.get(current_name)
            if credential:
                self.push_screen(CredentialEditorScreen(credential), self._save_credential_callback(current_name))
            return
        if button_id == "credential-clear-secret":
            current_name = self._current_credential_name()
            if current_name:
                self.repository.clear_credential_secret(current_name)
                self.refresh_views()
            return
        if button_id == "credential-delete":
            current_name = self._current_credential_name()
            if current_name:
                self.repository.delete_credential(current_name)
                self.refresh_views()
            return

        if button_id == "run-select-by-tag":
            self._tag_select()
            return
        if button_id == "run-select-all":
            self.selected_servers = {server.name for server in self.repository.load_config().servers if server.enabled}
            self.refresh_views()
            return
        if button_id == "run-clear-selection":
            self.selected_servers.clear()
            self.refresh_views()
            return
        if button_id == "run-preview":
            summary = self._preview_selected()
            from .cli import _append_history

            _append_history(self.repository, "dry-run", summary.current_ip, summary.results)
            self.refresh_views()
            return
        if button_id == "run-apply":
            preview = self._preview_selected()
            body = self._format_result_summary(preview)
            self.push_screen(
                ConfirmScreen("确认写入以下防火墙变更？", body),
                lambda confirmed: self._apply_after_confirm(confirmed, preview),
            )
            return
        if button_id == "run-doctor":
            from .cli import _build_doctor_report

            report = _build_doctor_report(self.repository)
            for check in report.checks:
                self._log(f"{check.name}: {check.status} - {check.detail}")
            return


def run_tui() -> None:
    """Launch the default TUI."""

    repository = ConfigRepository()
    repository.initialize()
    LighthouseTuiApp(repository).run()

