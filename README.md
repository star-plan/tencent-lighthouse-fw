# lighthouse-fw

一个面向 **Tencent Cloud Lighthouse 防火墙白名单更新** 的 Python 包，支持：

- `uvx lighthouse-fw` 直接进入 TUI
- `lhfw` / `uv run lhfw ...` 使用 CLI
- 管理 `credential`、`server`、`managed_rules`
- dry-run diff 预览 + apply 前显式确认
- Windows / Linux / macOS 跨平台配置布局
- 密钥优先系统钥匙串，无法使用时回退到本地加密文件

## English summary

`lighthouse-fw` is a Python package for managing Tencent Cloud Lighthouse firewall allowlist rules. It provides a default TUI entry point via `uvx lighthouse-fw`, a full CLI via `lhfw`, dry-run diff previews, explicit confirmation before apply, legacy config import, and a GitHub Actions + PyPI release path.

## 安装与运行

### 1. 直接用 `uvx`

默认进入 TUI：

```powershell
uvx lighthouse-fw
```

直接运行 CLI 子命令：

```powershell
uvx lighthouse-fw doctor
uvx lighthouse-fw run
```

### 2. 安装成工具命令

```powershell
uv tool install lighthouse-fw
lhfw doctor
lhfw tui
```

### 3. 仓库内本地运行

```powershell
uv run lhfw doctor
uv run lhfw tui
```

## 默认行为

- `uvx lighthouse-fw`：默认进入 TUI
- `lhfw doctor`：默认检查本地环境、密钥后端，以及 **credential 级** 腾讯云凭据 / API 可达性
- `lhfw run`：不带筛选条件时，默认运行所有 **enabled** 的 server
- `lhfw run --apply`：会先做 diff 预览，再要求显式确认

## 配置模型

当前包的持久化配置由三部分组成：

1. 普通配置：`config.toml`
2. 密钥：优先系统钥匙串；无安全后端时回退到本地加密文件 `secrets.bin`
3. 本地口令/密钥文件：`secrets.key`

server 支持：

- `enabled` 状态
- 多个自由标签 `tags`
- 完整 `managed_rules`

每条 `managed_rules` 支持：

- `protocol`
- `port`
- `cidr`
- `action`
- `description`
- `replace_existing_same_port`

## 常用 CLI

### 初始化

```powershell
lhfw init
```

### 查看配置

```powershell
lhfw config show
lhfw config history
```

### 设置 defaults

```powershell
lhfw config set-defaults `
  --endpoint lighthouse.tencentcloudapi.com `
  --request-timeout-seconds 4 `
  --history-limit 20 `
  --ip-source https://myip.ipip.net/s `
  --ip-source http://whois.pconline.com.cn/ipJson.jsp
```

### 管理 credential

```powershell
lhfw credential set work --region ap-singapore
lhfw credential set-secret work
lhfw credential list
```

如果你想继续使用环境变量，也可以只存 metadata：

```powershell
lhfw credential set work `
  --region ap-singapore `
  --secret-id-env TENCENT_SECRET_ID `
  --secret-key-env TENCENT_SECRET_KEY
```

### 管理 server

```powershell
lhfw server set sg-prod `
  --instance-id lhins-123456 `
  --credential work `
  --tag prod `
  --tag sg `
  --enabled
```

### 管理 rules

```powershell
lhfw server rule-add sg-prod `
  --protocol TCP `
  --port 22 `
  --cidr AUTO `
  --description "SSH"

lhfw server rule-list sg-prod
```

### 预览和执行

预览全部 enabled server：

```powershell
lhfw run
```

按 tag 过滤：

```powershell
lhfw run --tag prod --tag sg
```

实际写入：

```powershell
lhfw run --apply
```

## TUI 能力

当前默认 TUI 已支持：

- server 增删改
- credential 增删改
- 在 server 编辑界面内完整维护 `managed_rules`
- 批量选中 server
- 按 tag 批量选中
- diff 预览
- apply 前确认
- history 查看
- `doctor` 诊断入口

## 从旧脚本迁移

旧的 `tencent_lighthouse_fw.toml` 不再作为长期直接运行格式保留，但支持导入：

```powershell
lhfw import-legacy .\tencent_lighthouse_fw.toml
```

导入后会迁移：

- `defaults`
- `credentials.*`
- `[[servers]]`
- `managed_rules`

旧配置中的环境变量名也会被保留为新的 credential metadata。

## 安全说明

- 优先使用系统钥匙串
- 如果当前平台没有安全 keyring backend，会回退到本地加密文件
- `credential` 在 TUI 中默认隐藏，按需临时显示
- `doctor` 默认是只读检查，不会逐台 server 修改任何东西

## 开发与测试

```powershell
uv run python -m unittest discover -s tests -v
uv run lhfw doctor
```

## 发布

项目按 PyPI 发布路径设计：

- 包名：`lighthouse-fw`
- 命令名：`lhfw`
- 版本 tag：`v1.2.3`
- 认证：GitHub OIDC Trusted Publishing

推送版本 tag 后，GitHub Actions 会自动构建并发布到 PyPI。

