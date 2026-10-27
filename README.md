# cpa-plugin-key-manager — CLIProxyAPI API Key 精细化管控与 Token 用量统计插件

`cpa-plugin-key-manager` 是基于 [CLIProxyAPI 插件开发规范](https://help.router-for.me/cn/plugin/development.html)（C ABI `c-shared` 动态库架构，`ABIVersion = 1`，`SchemaVersion = 6`）开发的多租户 API Key 治理与实时 Token 用量统计插件。

---

## 核心功能特性

1. **内置可视化管理页（`//go:embed` 零依赖内嵌 SPA，与 [Cli-Proxy-API-Management-Center](https://github.com/router-for-me/Cli-Proxy-API-Management-Center) 深度无缝融合）**
   - **免密无缝内嵌 & 主题完全同步**：通过 `management.register` 自动在 CLIProxyAPI 管理后台左侧导航栏注入 **「API Key 管控与用量」** 入口（`/v0/resource/plugins/cpa-plugin-key-manager/ui`），进入页面无需再次输入管理密钥，且主题不设独立开关，完全跟随 CPA 管理后台的暖灰浅色、纯白、深色主题实时同步。
   - **与 CPA 全局 `api-keys` 统一双向同步（绝不分两套 Key）**：插件自动读取并同步 CLIProxyAPI 主配置 `config.yaml` 中的全局 `api-keys`（以及 `/v0/management/api-keys`）；在插件页面新建、修改或删除 API Key 会自动同步回写 CPA 的 `config.yaml` 与内存配置。
   - **纯复选框（Checkbox）模型白名单与账号凭证绑定**：
     - **模型白名单复选框**：自动聚合宿主已加载凭证注册的模型（`host.auth.models`）、历史调用模型与主流模型库，支持按 Provider 分类筛选与一键全选/清空，无需手动输入模型规则。
     - **上游账号凭证复选框**：自动调用 `host.auth.list` 与 `host.auth.models` 列出所有可用账号凭证，全复选框勾选绑定并支持 `round-robin` / `fill-first` / `strict` 策略。
   - **动态持久化与热生效**：网页端增删改查的所有 API Key 规则自动原子落盘，并**镜像到多个持久位置**（CLIProxyAPI 认证目录下的 `key-manager/*.state`、`config.yaml` 所在目录、`data/` 目录），容器重建或 `data/` 被清空后启动时自动从最新副本恢复；修改后立即热生效。插件规则**不写入 `config.yaml`**（该文件会被 CPA 用内存副本整体重写，写进去必然丢失），`config.yaml` 只同步全局 `api-keys`。
   - **拖动排序**：API Key 列表支持拖动行首 ⠿ 手柄调整显示顺序，顺序保存在规则文件的 `key_order` 中，重启后保持。

2. **按 API Key 维度的路由与访问控制（Pre-request & Response Filter）**
   - **模型白名单访问控制**：每个 API Key 可配置独立的 `allowed_models` 列表，支持精确匹配、`*`/`?` 通配符（如 `claude-3-5-*`、`gpt-4o*`）、`!` 排除规则，并自动兼容带思考后缀与带 Provider 前缀的模型名。越权调用直接短路返回兼容 OpenAI 与 Anthropic SDK 的 `403 Forbidden` JSON 错误，不触发任何上游请求。
   - **模型列表拉取智能过滤（`/v1/models`）**：客户端使用特定 API Key 请求模型列表时，插件自动识别其鉴权身份并拦截过滤响应，**仅向该 Key 返回其白名单所允许的模型**，未授权的模型列表自动脱敏隐匿。
     - **管理面板始终看到完整目录**：来自 `management.html`（`Referer` 含 `management`）的请求不过滤，避免面板用受限 Key 调 `/models` 时误以为服务器模型缺失。
     - **脚本可显式取全量**：请求头加 `X-Key-Guard-Catalog: all` 即可跳过过滤。
   - **上游凭证绑定与租户隔离**：支持将特定 API Key 绑定至指定的上游凭证或凭证池（`auth_ids`、`credentials`、`providers`、`attributes`），支持池内 `round-robin`（轮询）与 `fill-first`（优先级）调度，以及 `strict: true` 严格租户隔离（当绑定凭证不可用时直接拒绝，防止跨租户借用公共凭证）。
   - **前端鉴权集成**：实现 `frontend_auth_provider` 能力，在插件 `keys` 中配置的 API Key 可直接通过鉴权。

3. **按 API Key 维度的最大并发限制（Pre-request & Post-response）**
   - 每个 API Key 可配置独立的 `max_concurrency` 最大并发数。
   - **流式生命周期安全**：基于 `RequestID` 跟踪每个请求槽位，在 `request.intercept_before` 申请槽位，在宿主终态回调 `request.complete`（非流式响应结束，或 SSE 流式传输正常 `[DONE]`、上游中断、客户端断开 `context.Canceled`）时**幂等释放**槽位，绝不在流式响应头返回时提前释放，也绝不会因重复回调导致计数器下溢为负数。
   - 达到并发上限时立即返回 `429 Too Many Requests`（附带 `Retry-After: 1`）。
   - **热重载安全**：在触发 `plugin.reconfigure` 热更新配置时，完整保留当前飞行中的并发槽位与已累计的 Token 统计数据。

4. **多协议 Token 用量统计（Post-response & Query）**
   - **多协议非流式与流式增量合并**：原生支持 **OpenAI Chat Completions**、**OpenAI Responses API (`response.usage`)**、**Anthropic Claude (`message_start` + `message_delta`)**、**Google Gemini (`usageMetadata`)** 四大协议格式。在流式分片拦截中按字段执行**非零增量合并（Merge）**，确保 Input、Output、Reasoning、Cache Read、Cache Write 各项 Token 完整聚合。
   - **`stream_options` 协议守卫**：仅对 `SourceFormat == "openai"` 且未显式携带 `stream_options.include_usage` 的流式请求自动注入 `"stream_options": {"include_usage": true}`，严禁向 `claude`、`gemini`、`openai-response` 注入，防止上游返回 `400 Bad Request`。
   - **防重记账与 Windows 安全持久化**：协同 `request.complete` 与宿主 `usage.handle`，确保单次请求绝不重复统计；持久化采用临时文件 `fsync` + 带轻量级重试的原子 `os.Rename`，兼容 Windows 文件锁机制。
   - **按「请求模型 + 服务端模型」二元组统计**：每次请求只落入一个二元组（例如请求 `gemini-3.8-flash-high` 而服务端实际返回 `gemini-3.8-flash-n`，即计入「请求 = …-high / 落地 = …-n」这一组）。明细表据此精确地按请求模型分组、在组下列出它实际落到过的每个服务端模型，**同一份数据不会被拆到多行、也不再需要模糊标注**；「按模型全局排行」仍按**服务端模型**汇总。费用计算按请求模型的价格查表，避免上游变体名查不到价格导致费用归零。

---

## 升级与数据迁移指南（从 cpa-plugin-key 升级至 cpa-plugin-key-manager）

从旧版 `cpa-plugin-key` 升级到 `cpa-plugin-key-manager` 时，**历史数据完全无损、无缝继承**：

1. **动态规则与用量统计文件无缝兼容**：
   - 规则文件 `./data/key_guard_rules.json` 与用量统计文件 `./data/key_usage_stats.json` 保持完全兼容，升级时**直接保留原有文件**，无需任何格式转换或手工处理。
2. **替换插件二进制文件**：
   - 将 `./plugins/cpa-plugin-key.{dll,so,dylib}` 替换为新的 `./plugins/cpa-plugin-key-manager.{dll,so,dylib}`，并删除旧版文件。
3. **更新配置文件 `config.yaml` 节点名称**：
   - 将 `config.yaml` 中 `plugins.configs.cpa-plugin-key` 修改为 `plugins.configs.cpa-plugin-key-manager` 即可（使用一键安装脚本 `install.sh` / `install.ps1` 会自动帮您检测并无缝迁移该节点）。
4. **管理后台路由地址变更**：
   - UI 资源路径更新为 `/v0/resource/plugins/cpa-plugin-key-manager/ui`。在 CPA 管理后台左侧菜单点击「API Key 管控与用量」会自动进入最新地址。

---

## 快速安装与插件数据初始化

### 1. 一键在线安装并初始化数据（推荐）
进入您的 `CLIProxyAPI` 运行根目录后执行以下命令，脚本会自动识别系统架构、下载最新 Release 插件、校验 SHA256、安装至 `./plugins/`，并自动初始化或无缝升级 `./data/` 及 `config.yaml`：

- **Linux / macOS / Git Bash**：
  ```bash
  curl -LsSf https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.sh | sh
  ```
- **Windows PowerShell**：
  ```powershell
  irm https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.ps1 | iex
  ```

### 2. 手动安装与自定义数据初始化参数
```bash
# 下载安装脚本
curl -LsSfO https://raw.githubusercontent.com/YzMzx/cpa-plugin-key-manager/main/install.sh
chmod +x install.sh

# 方式 A：指定 CLIProxyAPI 根目录与指定版本安装并初始化数据
./install.sh --dir /opt/CLIProxyAPI --version v0.5.0

# 方式 B：使用本地已下载的 Release 压缩包或本地编译的 .so/.dylib/.dll 手动安装并初始化数据
./install.sh --dir /opt/CLIProxyAPI --local ./cpa-plugin-key-manager-linux-amd64.tar.gz

# 方式 C：仅初始化/修复插件数据目录 (data/*.json) 与 config.yaml，不重新下载二进制
./install.sh --dir /opt/CLIProxyAPI --init-only

# 方式 D：重置所有动态规则与 Token 用量统计数据为初始空白状态
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
  go build -buildmode=c-shared -o cpa-plugin-key-manager.dll .
  ```
- **Linux (`.so`)**：
  ```bash
  CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key-manager.so .
  ```
- **macOS (`.dylib`)**：
  ```bash
  CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key-manager.dylib .
  ```

---

## 管理与用量查询方式

1. **CPA 管理后台可视化页面（免输密钥，主题跟随 CPA）**：
   直接在 CLIProxyAPI 管理后台左侧菜单点击 **「API Key 管控与用量」**，或访问 `http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key-manager/ui`。
2. **CLI 命令行报表**：
   ```bash
   # 打印所有 API Key 的 Token 用量统计报表
   ./cli-proxy-api -key-usage

   # 查看指定 API Key 的 JSON 统计
   ./cli-proxy-api -key-usage -key-usage-key sk-your-api-key -key-usage-json

   # 重置统计数据
   ./cli-proxy-api -key-usage-reset
   ```
