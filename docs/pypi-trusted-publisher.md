# PyPI Trusted Publisher 配置指南

本项目使用 PyPI 的 Trusted Publishing（OIDC）机制进行免密发布，无需手动创建或维护 API Token。

## 背景

GitHub Actions 会向 PyPI 提交一个短期的 OIDC 身份令牌，PyPI 通过匹配预先配置的"受信发布者"来验证身份。
只要 PyPI 端的配置与 GitHub Actions 实际触发时的 claims（声明）完全一致，发布就会自动成功。

## 首次配置步骤

### 1. 在 PyPI 添加受信发布者

打开以下链接（如果项目已存在，也可以在项目设置 → Publishing 里添加）：

```
https://pypi.org/manage/account/publishing/
```

按以下字段填写，**不能有拼写错误或大小写错误**：

| 字段 | 填写值 |
|---|---|
| PyPI project name | `lighthouse-fw` |
| Owner | `star-plan` |
| Repository name | `tencent-lighthouse-fw` |
| Workflow name | `lighthouse-fw-publish.yml` |
| Environment name | 留空（当前工作流未配置 environment） |

> 如果你将来给工作流 job 加了 `environment: pypi`，这里的 Environment name 也要同步填写为 `pypi`，否则依然会报 `invalid-publisher`。

### 2. 触发发布

推送符合 `v*.*.*` 格式的 tag 即可触发工作流：

```powershell
git tag v0.1.0
git push origin v0.1.0
```

## 排查 `invalid-publisher` 错误

报错原因：PyPI 端没有找到一条与 GitHub Actions OIDC claims **完全匹配**的受信发布者配置。

常见原因逐项核对：

1. **Workflow name 填错** — 应填文件名 `lighthouse-fw-publish.yml`，不是路径，不含 `.github/workflows/`。
2. **Owner 或 Repository 拼写错误** — 注意大小写，`star-plan` / `tencent-lighthouse-fw`。
3. **Environment 不匹配** — PyPI 端填了环境名，但 GitHub 工作流 job 没有 `environment:` 字段（或反过来）。两边必须同时有或同时没有。
4. **配到了 TestPyPI** — 确认是在 `pypi.org` 而非 `test.pypi.org` 配置。
5. **项目名与 pyproject.toml 不一致** — 当前包名为 `lighthouse-fw`，来自 `pyproject.toml` 的 `[project] name`。

## 工作流关键要点

发布 job 必须具备以下权限，缺少则无法获取 OIDC 令牌：

```yaml
permissions:
  id-token: write
```

当前工作流文件见 [.github/workflows/lighthouse-fw-publish.yml](../.github/workflows/lighthouse-fw-publish.yml)。

## 参考链接

- [PyPI Trusted Publishers 官方文档](https://docs.pypi.org/trusted-publishers/)
- [Adding a Trusted Publisher 到现有项目](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
- [pypa/gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish)
- [PyPA 发布指南](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/)
