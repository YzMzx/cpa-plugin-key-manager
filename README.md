# cpa-plugin-key — CLIProxyAPI API Key 精细化管控与计费插件

`cpa-plugin-key` 是基于 [CLIProxyAPI 插件开发规范](https://help.router-for.me/cn/plugin/development.html)（C ABI `c-shared` 动态库架构，`ABIVersion = 1`，`SchemaVersion = 6`）开发的企业级多租户 API Key 治理与实时计费插件。

---

## 核心功能特性

1. **内置可视化管理后台与下游用户自查面板（`//go:embed` 零依赖内嵌 SPA）**
   - **自动注入 CPA 后台导航栏**：通过 `management.register` 自动在 CLIProxyAPI 管理后台左侧菜单注入 **「API Key 计费与管控」** 入口（`/v0/resource/plugins/cpa-plugin-key/ui`），无需修改任何宿主源码。
   - **管理员模式（CPA 后台内嵌或输入 Management Key）**：
     - **仪表盘与排行榜**：全局总消耗金额 (USD)、总 Token 数、实时活跃并发数，以及按 API Key / 按模型的消耗排行榜与占比进度条。
     - **API Key & 并发配额可视化 CRUD**：在网页端直接新建、随机生成、编辑、启用/禁用、删除下游 API Key，配置备注名、最大并发数（`max_concurrency`）、USD 配额上限（`quota_limit_usd`），以及一键重置账单。
     - **路由规则与上游凭证勾选绑定**：自动调用宿主 `host.auth.list` 列出所有已加载的上游 OAuth / API Key 凭证，支持可视化勾选绑定与 `round-robin` / `fill-first` / `strict` 策略配置。
     - **模型定价管理**：查看 `models.dev` 同步状态、实时检索官方模型参考价，并直接在网页上新增/修改/删除自定义模型价格覆盖（`custom_prices`）。
   - **API Key 用户自查模式（`/v0/resource/plugins/cpa-plugin-key/ui#account`）**：
     - 供普通下游用户使用自己的 API Key 登录，仅展示该 Key 自身的实时并发占用、配额余额进度、授权模型白名单及各模型 Token/USD 消费明细。
   - **动态持久化与热生效**：网页端增删改查的所有 API Key、规则和自定义价格自动原子落盘至 `./data/key_guard_rules.json`，修改后立即在内存中热生效，同时向下兼容 `config.yaml` 中的初始种子配置。

2. **按 API Key 维度的路由与访问控制（Pre-request）**
   - **模型白名单控制**：每个 API Key 可配置独立的 `allowed_models` 列表，支持精确匹配、`*`/`?` 通配符（如 `claude-3-5-*`、`gpt-4o*`）、`!` 排除规则，并自动兼容带思考后缀（如 `claude-3-7-sonnet-20250219(high)`）与带 Provider 前缀的模型名。越权访问直接短路返回兼容 OpenAI 与 Anthropic SDK 的 `403 Forbidden` JSON 错误，不触发任何上游请求。
   - **上游凭证绑定与租户隔离**：支持将特定 API Key 绑定至指定的上游凭证或凭证池（`auth_ids`、`providers`、`attributes`），支持池内 `round-robin`（轮询）与 `fill-first`（优先级）调度，以及 `strict: true` 严格租户隔离（当绑定凭证不可用时直接拒绝，防止跨租户借用公共凭证）。
   - **前端鉴权集成**：实现 `frontend_auth_provider` 能力，在插件 `keys` 中配置的 API Key 可直接通过鉴权。

2. **按 API Key 维度的最大并发限制（Pre-request & Post-response）**
   - 每个 API Key 可配置独立的 `max_concurrency` 最大并发数。
   - **流式生命周期安全**：基于 `RequestID` 跟踪每个请求槽位，在 `request.intercept_before` 申请槽位，在宿主终态回调 `request.complete`（非流式响应结束，或 SSE 流式传输正常 `[DONE]`、上游中断、客户端断开 `context.Canceled`）时**幂等释放**槽位，绝不在流式响应头返回时提前释放，也绝不会因重复回调导致计数器下溢为负数。
   - 达到并发上限时立即返回 `429 Too Many Requests`（附带 `Retry-After: 1`）。
   - **热重载安全**：在触发 `plugin.reconfigure` 热更新配置时，完整保留当前飞行中的并发槽位与已累计的账单数据。

3. **自动同步 `models.dev` 模型参考价格（Background Sync & Cache）**
   - 启动时优先加载本地磁盘缓存（`models_dev.json`），随后异步拉取 `https://models.dev/api.json` 并每 24 小时定时更新。
   - 提取每百万 Token（1M Tokens）的 `input`、`output`、`cache_read`、`cache_write` 价格（USD）。
   - 支持在配置文件 `custom_prices` 中按精确名称或通配符手动覆盖任意模型价格（优先级：`custom_prices` > `models.dev` > `default_price`）。
   - 当网络不可用或远端 JSON 异常时，通过 `host.log` 记录 `Warn` 日志并平滑降级至本地缓存/配置价格。

4. **多协议 Token 消耗统计与高精度费用计算（Post-response & Query）**
   - **多协议非流式与流式增量合并**：原生支持 **OpenAI Chat Completions**、**OpenAI Responses API (`response.usage`)**、**Anthropic Claude (`message_start` + `message_delta`)**、**Google Gemini (`usageMetadata`)** 四大协议格式。在流式分片拦截中按字段执行**非零增量合并（Merge）**，确保 Claude 在 `message_start` 中的 `input_tokens`/`cache_read_input_tokens`/`cache_creation_input_tokens` 与 `message_delta` 中的 `output_tokens` 完整聚合。
   - **`stream_options` 协议守卫**：仅对 `SourceFormat == "openai"` 且未显式携带 `stream_options.include_usage` 的流式请求自动注入 `"stream_options": {"include_usage": true}`，严禁向 `claude`、`gemini`、`openai-response` 注入，防止上游返回 `400 Bad Request`。
   - **防重记账与跨协议对齐**：协同 `request.complete` 与宿主 `usage.handle`，确保单次请求绝不重复计费，并在发生协议转换时取最完整的 Token 分量入账。
   - **高精度 USD 计算与 Windows 安全持久化**：内部采用 `int64` 纳美分（$10^{-9}\text{ USD}$）整型累加，对外输出保留 6 位小数（`$0.000000`）；持久化采用临时文件 `fsync` + 带轻量级重试的原子 `os.Rename`，兼容 Windows 文件锁机制。

---

## 目录结构

```text
cpa-plugin-key/
├── go.mod                      # Go Module 定义 (含对本地 ../CLIProxyAPI 的 replace 映射)
├── go.sum
├── Makefile                    # 跨平台编译与测试脚本
├── README.md                   # 插件说明文档
├── config.example.yaml         # 完整配置示例
├── main.go                     # C ABI 动态库导出入口 (cliproxy_plugin_init / Call / Free / Shutdown)
└── internal/
    ├── authz/                  # 通配符模型匹配、403/429 错误构造、上游凭证绑定调度器
    ├── limiter/                # 按 API Key + RequestID 的并发控制器
    ├── pricing/                # models.dev 异步同步器、缓存与高精度价格计算引擎
    ├── usage/                  # 多协议 Usage 提取器、增量合并、防重记账与原子 JSON 持久化
    ├── handler/                # Management API、自查 Dashboard 资源页与 CLI 命令行处理器
    └── plugin/                 # 插件核心生命周期、热重载管理与 Host Callback 桥接
```

---

## 快速安装与插件数据初始化

### 1. 一键在线安装并初始化数据（推荐）
进入您的 `CLIProxyAPI` 运行根目录后执行以下命令，脚本会自动识别系统架构、下载最新 Release 插件、校验 SHA256、安装至 `./plugins/`，并自动初始化 `./data/key_guard_rules.json`、`./data/key_usage_stats.json`、`./data/models_dev.json` 及 `config.yaml`：

- **Linux / macOS / Git Bash**：
  ```bash
  curl -LsSf https://raw.githubusercontent.com/YzMzx/cpa-plugin-key/main/install.sh | sh
  ```
- **Windows PowerShell**：
  ```powershell
  irm https://raw.githubusercontent.com/YzMzx/cpa-plugin-key/main/install.ps1 | iex
  ```

### 2. 手动安装与自定义数据初始化参数
您也可以将 `install.sh`（或 `install.ps1`）下载到本地，配合离线包、指定目录或重置数据选项使用：
```bash
# 下载安装脚本
curl -LsSfO https://raw.githubusercontent.com/YzMzx/cpa-plugin-key/main/install.sh
chmod +x install.sh

# 方式 A：指定 CLIProxyAPI 根目录与指定版本安装并初始化数据
./install.sh --dir /opt/CLIProxyAPI --version v0.2.0

# 方式 B：使用本地已下载的 Release 压缩包或本地编译的 .so/.dylib/.dll 手动安装并初始化数据
./install.sh --dir /opt/CLIProxyAPI --local ./cpa-plugin-key-linux-amd64.tar.gz

# 方式 C：仅初始化/修复插件数据目录 (data/*.json) 与 config.yaml，不重新下载二进制
./install.sh --dir /opt/CLIProxyAPI --init-only

# 方式 D：重置所有动态规则与账单统计数据为初始空白状态
./install.sh --dir /opt/CLIProxyAPI --init-only --reset-data
```

---

## 源码编译

### 1. 运行单元测试
```bash
go test -v ./...
```

### 2. 编译动态库插件
- **Windows (`.dll`)**：
  ```powershell
  go build -buildmode=c-shared -o cpa-plugin-key.dll .
  ```
- **Linux (`.so`)**：
  ```bash
  CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key.so .
  ```
- **macOS (`.dylib`)**：
  ```bash
  CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key.dylib .
  ```

将编译生成的 `cpa-plugin-key.dll`（或 `.so` / `.dylib`）放入 CLIProxyAPI 的 `plugins/` 目录，并参考 [`config.example.yaml`](./config.example.yaml) 在主 `config.yaml` 中启用即可。

---

## 用量查询方式

### 1. HTTP Management API（需携带 CLIProxyAPI 管理密钥）
- **查询所有或指定 Key 的用量与实时并发**：
  ```bash
  # JSON 格式
  curl -H "Authorization: Bearer <MANAGEMENT_KEY>" "http://127.0.0.1:8317/v0/management/key-guard/usage"

  # 按 API Key 或模型过滤，或输出 ASCII 表格 (?format=table)
  curl -H "Authorization: Bearer <MANAGEMENT_KEY>" "http://127.0.0.1:8317/v0/management/key-guard/usage?api_key=sk-tenant-alpha-prod&format=table"
  ```
- **查询 `models.dev` 价格同步状态及特定模型单价**：
  ```bash
  curl -H "Authorization: Bearer <MANAGEMENT_KEY>" "http://127.0.0.1:8317/v0/management/key-guard/pricing?model=claude-3-5-sonnet-20241022"
  ```
- **手动触发立即同步 `models.dev` 价格**：
  ```bash
  curl -X POST -H "Authorization: Bearer <MANAGEMENT_KEY>" "http://127.0.0.1:8317/v0/management/key-guard/pricing/sync"
  ```
- **重置统计数据（全局或指定 Key）**：
  ```bash
  curl -X POST -H "Authorization: Bearer <MANAGEMENT_KEY>" "http://127.0.0.1:8317/v0/management/key-guard/usage/reset?api_key=sk-tenant-alpha-prod"
  ```

### 2. 可视化管理后台与租户自查面板（Resource Route）
- **管理员可视化控制台**（亦可在 CPA 管理后台左侧菜单「API Key 计费与管控」直接打开）：
  `http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key/ui`
- **下游 API Key 用户自查页面**：
  `http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key/ui#account`
- **客户端通过 Header 自查 JSON 账单**：
  ```bash
  curl -H "X-Api-Key: sk-tenant-alpha-prod" "http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key/usage?mode=account&format=json"
  ```

### 3. CLI 命令行报表
```bash
# 打印所有 API Key 的 ASCII 统计报表
./cli-proxy-api -key-usage

# 查看指定 API Key 的 JSON 账单
./cli-proxy-api -key-usage -key-usage-key sk-tenant-alpha-prod -key-usage-json

# 重置统计数据
./cli-proxy-api -key-usage-reset
```
