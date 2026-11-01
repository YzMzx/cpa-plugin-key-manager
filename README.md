# cpa-plugin-key-manager

CLIProxyAPI 的 API Key 管控与用量统计插件：多 Key 治理、模型白名单、并发与额度限制、Token 用量看板、模型价格管理，全部数据存放在一个 SQLite 数据库里。

基于 [CLIProxyAPI 插件规范](https://help.router-for.me/cn/plugin/development.html)（C ABI `c-shared`，`ABIVersion = 1`，`SchemaVersion = 6`）开发。

---

## 功能

### API Key 管理
- 与 CPA 全局 `api-keys` 双向同步：插件里增删改 Key 会自动回写 `config.yaml` 的 `api-keys`。
- 每个 Key 可独立设置：启用状态、最大并发、模型白名单、上游凭证绑定、费用额度。
- 列表支持拖动调整显示顺序，顺序随库保存。
- 额度按费用（USD）计，`0` 表示不限额；超额请求直接返回 `429 insufficient_quota`（OpenAI / Anthropic SDK 兼容格式）。
- `重置额度` 只重置计量基线，不清历史用量与费用。

### 访问控制
- **模型白名单**：支持精确名、`*` / `?` 通配符、`!` 排除，命中失败返回 `403`（OpenAI / Anthropic 兼容 JSON），不触发上游请求。
- **模型列表过滤**：用受限 Key 请求 `/v1/models` 时只返回白名单内的模型；面板请求不加过滤，`X-Key-Guard-Catalog: all` 可显式取全量。
- **上游凭证绑定**：支持 `round-robin` / `fill-first` 调度与 `strict` 严格隔离。
- **并发限制**：按 Key 独立计数，流式请求在宿主终态回调时释放，超限返回 `429` + `Retry-After`。

### 用量统计
- 支持 OpenAI Chat Completions、OpenAI Responses、Anthropic Claude、Google Gemini 四种 usage 格式，流式分片按字段增量合并。
- 按「请求模型 + 服务端模型」二元组记账：上游替换只在明细里标注，不会拆成重复行。
- 请求去重：`request.complete` 与 `usage.handle` 协同，单次请求只统计一次。
- 全部 Token 数值自动按 K / M / B 显示（如 `12.3 M`、`1.02 B`）。

### 面板
- **概览**：按密钥统计消耗、5 张指标卡、Token 趋势（时 / 日 / 月，含缓存命中率曲线，悬停出数值浮层）、模型分布环形图（按次数 / Token / 费用切换）。
- **用量看板**：API Key、账号、模型三个维度的排行。
- **模型与价格**：价格默认从 [models.dev](https://models.dev/) 拉取（每 24 小时刷新），可手动覆盖任意模型或通配符规则，支持 `__default__` 兜底价与前缀降级匹配。
- 面板自动注入 CPA 管理后台菜单「API Key 管控与用量」，主题跟随 CPA，无需二次输入管理密钥。
- 标签栏胶囊最右侧有一个图标刷新按钮（悬停显示「刷新数据」），一次刷新页面上的所有数据（九张指标卡、按密钥统计、趋势、分布、看板排行、凭证与价格），刷新期间图标持续旋转并禁止重复触发。

---

## 数据持久化

v0.9.0 起 **SQLite 是唯一存储后端**，规则、用量、账本全部存在一个文件里。

| 项 | 说明 |
|---|---|
| 默认路径 | `<CLIProxyAPI 根目录>/data/key_usage.db` |
| 覆盖方式 | 配置 `storage.usage_db_file`，或环境变量 `CPA_KEY_MANAGER_USAGE_DB` |
| 引擎 | `modernc.org/sqlite`（纯 Go、无需 CGO） |
| 模式 | WAL、`busy_timeout=5000`、单连接 |
| 写锁 | `<db>.lock`（`flock` / `LockFileEx`），同一数据库只允许一个写入者 |
| 迁移 | `schema_migrations` 表，按版本事务执行，重复启动幂等 |
| 写入 | 增量 upsert，只写自上次落盘以来变动的行 |

主要表：`rules_state`（Key 规则 / 排序 / 默认策略 / 价格覆盖）、`key_usage`、`key_model_usage`、`account_usage`、`account_model_usage`、`usage_ledger`（概览账本，默认保留 90 天）。

### ⚠️ Docker 必须挂载数据目录

容器重建会删除镜像层里的数据。请确保 `data` 目录挂载到宿主机：

```yaml
services:
  cli-proxy-api:
    volumes:
      - ./data:/CLIProxyAPI/data
```

自定义了 `usage_db_file` 时挂载它所在的目录；**不能只读挂载**，SQLite 需要写 `-wal` / `-shm` / `.lock`。

> 数据库必须放在本地文件系统，不要用 NFS / SMB，否则文件锁不可靠。

---

## 安装

### 一键安装（推荐）

在 CLIProxyAPI 运行根目录执行：

```bash
# Linux / macOS / Git Bash
curl -fsSL https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.sh | bash
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.ps1 | iex
```

脚本会识别架构、下载对应 Release、校验 SHA256、安装到 `./plugins/`，并补齐 `config.yaml` 中的插件配置。

### 常用参数

```bash
./install.sh --dir /opt/CLIProxyAPI --version v0.9.7   # 指定根目录与版本
./install.sh --local ./cpa-plugin-key-manager-linux-amd64.tar.gz   # 本地包安装
./install.sh --init-only                                # 只补配置，不下载二进制
./install.sh --init-only --reset-data                   # 重置数据：旧库移到 data/backup-<时间戳>/
```

---

## 配置

`config.yaml` 里只需要两项配置，其余全部由插件在数据库内维护：

```yaml
plugins:
  enabled: true
  dir: ./plugins
  configs:
    cpa-plugin-key-manager:
      enabled: true
      storage:
        # 留空 = <CLIProxyAPI 根目录>/data/key_usage.db
        usage_db_file: ""
```

Key 规则、默认策略、模型价格覆盖都通过管理页面配置，**不要写进 `config.yaml`**。

---

## 使用

打开 CPA 管理后台 → 左侧菜单 **「API Key 管控与用量」**，或直接访问：

```
http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key-manager/ui
```

标签页：`概览` / `API Key 与规则管控` / `Token 用量统计看板` / `全局默认策略与凭证池` / `模型与价格`。

---

## 运维

```bash
# 查看数据库状态
curl -s -H "Authorization: Bearer <管理密钥>" \
  http://127.0.0.1:8317/v0/management/key-guard/overview \
  | jq '.diagnostics | {usage_db_file, usage_db_exists, usage_db_size}'

# 清理旧版本遗留的 JSON / .state 文件（默认 dry-run）
curl -fsSL https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/scripts/cleanup-legacy-json.sh -o cleanup-legacy-json.sh
chmod +x cleanup-legacy-json.sh
./cleanup-legacy-json.sh --root /opt/Docker/CLIProxyAPI               # 预览
./cleanup-legacy-json.sh --root /opt/Docker/CLIProxyAPI --apply        # 移入备份目录
```

`cleanup-legacy-json.sh` 只处理 `key_guard_rules.json`、`key_usage_stats.json`、`.state` 镜像、早期 `key_usage_stats.db` 与 `.bak` 残片，不会碰 `models_dev.json`、`key_usage.db*`、`config.yaml`；找不到有效数据库时拒绝执行。加 `--plugins-leftover` 可一并清理 `plugins/linux` 之类的旧解压残留。

---

## 源码编译

```bash
go test ./...

# Linux
CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key-manager.so .
# macOS
CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key-manager.dylib .
# Windows
go build -buildmode=c-shared -o cpa-plugin-key-manager.dll .
```

编译需要同级目录存在 `CLIProxyAPI` 源码 checkout（`go.mod` 里有 `replace` 指向 `../CLIProxyAPI`）。

---

## 相关链接

- 发布页：<https://github.com/YzMzx/cpa-plugin-key-manager/releases>
- 上游项目：<https://github.com/router-for-me/CLIProxyAPI>
