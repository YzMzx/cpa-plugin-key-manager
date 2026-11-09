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

### 统一设置（管理员）
- 新增「统一设置」页面，集中调整审计启用/保留天数/最大条数/单正文上限/逻辑总容量（最高 1 GiB）、用量刷盘间隔、账本保留天数、统计时区、价格同步 URL/周期/超时、自动请求 usage 及价格缓存文件路径。容量单位在页面中按 MiB 显示，保存为字节整数。
- 常规设置持久化到 SQLite `rules_state.settings`，保存后热应用，重启后优先于 YAML 初始值；不会覆盖密钥规则、默认策略或价格覆盖。缩短保留期、条数或总容量可能立即清理历史，必须明确确认。版本冲突会要求重新加载，未保存草稿不会被刷新悄悄覆盖。
- 密钥、默认策略/凭证池、模型价格通过设置页入口跳转至现有专用表单，不引入第二套重复配置。
- 「启动配置」仅编辑宿主 YAML 中本插件的启用、优先级和数据库路径；保留注释及其它宿主配置，文件版本校验后原子保存。管理鉴权统一由 CPA 宿主提供。
- 启动配置保存不迁移数据库，路径变更需另行确认并安排重启；宿主文件监听器可能提前重载甚至使当前插件页面失效。环境变量指定数据库时路径不可在前端覆盖。操作前备份，切换空库并不会自动带走原库中的规则/设置/历史。
- 设置页只保留当前有效参数；CPA 全局管理密钥、插件目录等宿主级设置由宿主维护，不在本插件越权改写。

### 请求审计（管理员）
- 筛选仅 API Key、备注名称、模型名称、结果四项；密钥使用掩码下拉和不可逆指纹，备注/模型支持包含搜索。请求 ID/Trace/时间查询接口仍兼容。
- 详情为固定右侧抽屉，支持本页上下条、Esc/遮罩关闭和焦点返回；元数据默认折叠。
- 正文状态统一简显：已保存为「已保存 JSON 明文」；未保存按超限、格式不支持、格式异常、关闭、繁忙等合并。详细大小及旧版脱敏/部分留存信息在详情单独显示，内部状态和过滤规则不变。
- **明文留存模式：保存 JSON 请求正文，不对普通文字脱敏；入库前过滤图片、音频、视频等文件载荷，新记录按两空格缩进换行，仅改变字符串外的空白，不重排字段、不合并重复键、不转换数字精度。正文中自行携带的密码、token、API Key、对话及个人信息会原样保留。请严格限制管理员、数据库及备份的访问权限。**请求鉴权头、响应正文和 URL 查询参数仍不记录。
- 默认启用，保留 7 天，最多 10,000 条，单正文 10 MiB（10,485,760 字节），审计逻辑总量 64 MiB；容量满时淘汰旧记录，接近 10 MiB 的正文通常只能保留约 6 条。
- JSON 正文不再走脱敏器，不受旧版元素 4096、嵌套 16 或大正文脱敏繁忙限制。媒体文件载荷按新规则过滤为 `[OMITTED:media]`，保留同请求正常文字、数值和工具定义。保留合法 UTF-8 JSON 对象/数组和 10 MiB 上限；格式无效、非 JSON、压缩内容、超限仍整段略过，不留半截原文。底层 JSON 解析器本身也有防异常极深嵌套保护。
- 审计保存前，从根请求的 `messages` / `input` / `contents` 数组（或根消息数组）移除 `role: "system"` 和 `role: "developer"` 的整条消息及其正文；保留 `user` / `assistant` / `tool` 等其它角色。仅处理审计副本，不修改实际发给上游的请求，不解释工具 Schema 或嵌套业务 JSON 中的同名字段。
- 无过滤的新记录状态为 `stored_raw`，媒体已过滤为 `stored_raw_media_filtered`，角色已过滤为 `stored_raw_system_filtered`，两者均过滤为 `stored_raw_system_media_filtered`；默认格式化保存，哈希对应过滤后实际保存内容。若缩进使内容超过单条上限，则完整保留原始表示，绝不因格式化膨胀而丢弃正文。SHA-256 对实际保存内容计算，不是防篡改证明。详情默认以两空格格式化显示，也可切换「保存原文」核对字节对应内容；历史记录仅格式化展示，不改写数据库和旧哈希。重复键、大整数、数值字面量和 Unicode 转义均保留。旧版已脱敏/略过的正文无法恢复原始内容。
- **IP 监控已移除：**不解析网络地址/代理头，不采集或显示客户端/Peer IP，不再提供 IP 筛选。数据库迁移清空旧的独立 IP 字段并移除索引；不修改用户正文自行包含的 IP 文本。旧备份/WAL/空闲页不保证安全擦除。
- 页面可计算审计逻辑占用、正文大小、条数、占比，以及共享数据库/WAL 实际文件大小。逻辑删除不保证立即缩小物理文件。
- 手动清理支持仅过期、1/3/7 天前、自定义日期前、全部审计；先预览再确认，5 分钟单次身份绑定令牌，只删除预览快照中的审计，不影响新增记录、密钥规则或用量。
- 只记录进入插件模型执行生命周期的新请求，不是全站抓包；存储写入有限等待，不阻断代理请求，失败计数可见，不承诺零丢失。审计记录默认持久化，重启不丢，但并未做数据库加密。

在 `plugins.configs.cpa-plugin-key-manager` 下可选配置：

```yaml
audit:
  enabled: true
  retention_days: 7
  max_records: 10000
  max_body_bytes: 10485760  # 旧配置若显式更小，仍按原值执行
  max_total_bytes: 67108864
```

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
        # 总览图表的分桶与「今日/昨日/近7日」边界所用时区，默认 UTC+8
        timezone: "Asia/Shanghai"
```

> 时区默认固定为 **UTC+8（Asia/Shanghai）**，与浏览器、服务器/容器时区无关：
> 图表横轴标签、按天/月聚合的边界、「今日」等范围都按北京时间切分。
> 数据库内部仍以 UTC 存储，只影响展示；如需其他时区可改 `storage.timezone`（IANA 名称，如 `UTC`、`Asia/Tokyo`）。

Key 规则、默认策略、模型价格覆盖都通过管理页面配置，**不要写进 `config.yaml`**。

---

## 使用

打开 CPA 管理后台 → 左侧菜单 **「API Key 管控与用量」**，或直接访问：

```
http://127.0.0.1:8317/v0/resource/plugins/cpa-plugin-key-manager/ui
```

标签页：`概览` / `API Key 与规则管控` / `Token 用量统计看板` / `全局默认策略与凭证池` / `模型与价格` / `请求审计` / `统一设置`。

---

## 运维

- 规则、用量、账本、审计和运行设置仅保存于当前 SQLite 数据库；不再搜索或导入旧 JSON / `.state` / 实验数据库。
- 备份完整数据目录，并在停止写入或使用一致性快照后备份数据库；现有 SQLite 数据不会因清理旧配置功能而被删除。
- 当前保留的 JSON 文件仅为模型价格缓存 `models_dev.json`，不是规则或用量后端。相对数据库/缓存路径固定以 CPA 根目录解析，不再拾取工作目录、用户目录等位置的同名历史文件；显式绝对路径仍支持。

## 源码编译

```bash
go test ./...
node --test web/settings.test.cjs web/runtime.test.cjs web/audit.test.cjs

# Linux
CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key-manager.so .
# macOS
CGO_ENABLED=1 go build -buildmode=c-shared -o cpa-plugin-key-manager.dylib .
# Windows
go build -buildmode=c-shared -o cpa-plugin-key-manager.dll .
```

编译需要同级目录存在 `CLIProxyAPI` 源码 checkout（`go.mod` 里有 `replace` 指向 `../CLIProxyAPI`）。

管理页源码位于 `web/`，按 API 客户端、认证桥、异步状态、日期格式化、事件委托与页面渲染拆分；构建时仍由 `web/embed.go` 拼装成单个 HTML 内嵌进动态库，无需 npm 安装或外部静态资源。具体契约和前端测试见 `web/README.md`。

规则变更先提交 SQLite，再通过 CPA 原生逐 Key 操作同步宿主；部分失败会显示“同步待重试”，刷新后重试，不再静默提示全部成功。界面使用 `X-Key-Guard-Revision` 防止旧页面覆盖新规则；未传此头的旧 API 客户端保留无条件写入的兼容模式。删除标记会立即阻止旧 Key 继续请求；改名需等待在途请求结束，历史用量保留，已用额度与晚到费用延续到新 Key。

v0.10.4 起，宿主同步同时支持新版 `server.host` / `server.port` / `server.tls` 和旧版顶层字段；混合配置以新版字段为准。同步失败会显示不含密钥的中文原因，`host_sync.error_code` 可区分配置、连接、超时、证书、鉴权及接口问题。升级后刷新可重试既有待同步状态，无需修改正常的 CPA 配置或清理数据库。

概览 `diagnostics.persistence` 提供最后成功落盘时间、待写入行数、刷盘错误和记账错误；异常也会在管理页提示。同路径热重载保留数据库句柄，切换数据库路径需重启。无效价格/时区会拒绝生效，不再降级为宽松默认规则。

---

## 相关链接

- 发布页：<https://github.com/YzMzx/cpa-plugin-key-manager/releases>
- 上游项目：<https://github.com/router-for-me/CLIProxyAPI>
