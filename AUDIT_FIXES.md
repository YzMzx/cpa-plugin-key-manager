# v0.11.3-pre.5 全项目审计修复记录

基线：93ba33e / 0.11.3-pre.4。本记录对应全项目审计后的代码修复，不替代历史发布记录，不表示已经部署。

## 修复与回归映射

| 审计问题 | 修复策略 | 回归入口 |
|---|---|---|
| 多认证来源身份错配 | caller scope/可信身份优先；未知scope和冲突身份拒绝；多不同凭据frontend拒绝 | [identity_security_test.go](<internal/plugin/identity_security_test.go>) |
| 特殊示例Key规则丢弃 | 去除样例字符串黑名单，保存规则实际进入运行配置 | [identity_security_test.go](<internal/plugin/identity_security_test.go>) |
| v8客户端Key导入失败 | 区分上游mapping和下游list；access显式存在优先；host错误在打开DB前拒绝 | [host_config_v8_test.go](<internal/plugin/host_config_v8_test.go>) |
| 编辑器有损权限往返 | 完整基线保留；模型排除、providers/attributes/strict/default quota不丢；解除限制需明确确认 | [runtime.test.cjs](<web/runtime.test.cjs>) |
| 旧草稿借用新revision | Key/价格编辑器固定打开时版本；缺版本拒绝提交 | [runtime.test.cjs](<web/runtime.test.cjs>) |
| 锁屏敏感状态及迟到回填 | client/app/各mutation消费者检查会话代际；modal单独所有权；全状态清理 | [runtime.test.cjs](<web/runtime.test.cjs>) |
| Reset用量破坏quota基线 | quota_usage独立持久累计；Reset只清展示；事务失败不发布内存 | [quota_regression_test.go](<internal/usage/quota_regression_test.go>)、[quota_reset_regression_test.go](<internal/plugin/quota_reset_regression_test.go>) |
| 迟到缓存重分类重复计费 | 保留原始输入语义和cacheWrite是否已含于输入；同执行费用可纠正下降 | [reconciliation_regression_test.go](<internal/usage/reconciliation_regression_test.go>)、[input_evidence_test.go](<internal/usage/input_evidence_test.go>) |
| 迟到服务模型价不升级 | 价格匹配等级；补齐身份可升级临时兜底，已确定报价保持快照 | [reconciliation_regression_test.go](<internal/usage/reconciliation_regression_test.go>) |
| 超界Token/聚合溢出 | 字面量严格整数解析；显式Invalid；聚合饱和带accounting_error，UI不将上界画为精确统计 | [reconciliation_regression_test.go](<internal/usage/reconciliation_regression_test.go>)、[quota_reset_regression_test.go](<internal/plugin/quota_reset_regression_test.go>)、[runtime.test.cjs](<web/runtime.test.cjs>) |
| 合并迟到执行的失败原子性 | 隔离候选贡献预演，验证后发布；关闭入口早拒绝，保留已计费用和Reset归属 | [merge_transaction_regression_test.go](<internal/usage/merge_transaction_regression_test.go>) |
| SQLite URI错址/锁分裂 | 正确file URI编码；DB与lock统一绝对/符号链接解析路径 | [path_test.go](<internal/sqlitestore/path_test.go>) |
| 审计伪Schema及JSON转义旁路 | schema只限精确协议路径；媒体对象自带enum/type不豁免；合法escaped slash识别 | [body_budget_regression_test.go](<internal/audit/body_budget_regression_test.go>) |
| 审计内存分配放大 | 复用replacer及key快路；非阻塞4并发/20MiB加权输入预算；128MiB扫描work与线上500ms合作deadline | [body_budget_regression_test.go](<internal/audit/body_budget_regression_test.go>)、[audit_body_budget_test.go](<internal/plugin/audit_body_budget_test.go>) |
| 安装器破坏已有YAML | 已有文件保持原字节，仅提示手动合并；不存在才排他创建 | [install_config_checksum_test.ps1](<scripts/install_config_checksum_test.ps1>) |
| SHA失败路径加固 | 唯一64hex清单项，hash工具非零即拒绝，即使stdout含正确哈希 | [install_config_checksum_test.ps1](<scripts/install_config_checksum_test.ps1>) |

## 数据与兼容变化

- SQLite migration 5从现存key_usage初始化quota_usage，只执行一次，不随Reset重建；升级前仍应一致性备份。旧版本已清除的历史费用无法自动恢复。回退旧二进制不等于回退新数据语义。
- 清空统计不释放额度，额度释放仍使用专用“重置额度”。近期执行去重仍为进程内状态；没有新增跨重启永久去重承诺。
- 多不同认证凭据或无法从可信scope解析的身份会被安全拒绝。旧宿主单一原始凭据回退仍依赖宿主先完成鉴权，不是独立认证器。未导入的native query-only Key若宿主只传scope而无原文无法恢复，也会拒绝而非匿名放行。
- 审计拥堵/预算超限可以整段省略正文；不会修改上游请求。500ms为合作式近似预算，标准库validation/hash/复制单步最多10MiB，不能抢占为硬截止；纯函数功能回归用确定work，线上走带deadline的Manager预算。没有重新加入4096元素上限。
- 媒体/角色过滤不是秘密脱敏；普通文本凭据/PII仍为明文模式，逻辑删除不保证物理擦除。
- 路径解析覆盖常规符号链接；不保证任意硬链接、运行中替换目录链接、NFS/SMB安全。
- 取消写请求不证明服务端未提交，前端不自动重试。
- 安装器不再尝试自动合并已有配置；二进制安装完成后必须人工核查启用配置。

## 最终验证结果

- 无缓存全包Go普通测试通过；最终全包race十个包全部通过（下列Windows本机参数）。
- go vet ./...、go mod verify、git diff --check通过。
- Node前端156/156通过；安装器68新增+13既有离线用例全部通过。
- 最后精确schema路径/escaped slash修改后，再跑5秒fuzz：24,396次执行，通过。
- 最终约1MiB密集小对象benchmark：18.14ms、9,656 B/op、7 allocs/op（单次本机样本；FilterRequestMedia，不包括数据库写入，累计分配不等于峰值内存）。
- Chrome真实DOM隔离冒烟通过，Windows c-shared最终构建通过；产物只用于临时验证，未部署。

## 验证方法

- 无缓存全包Go测试、go vet、全部Node测试、安装器68新增+13既有离线夹具；关键新增回归先证失败再修复。
- Windows race使用本机Zig真实同步API导入库与external linker，未禁用race、未使用空桩：

~~~powershell
$env:CGO_LDFLAGS = '-lapi-ms-win-core-synch-l1-2-0'
go test -race -ldflags=-linkmode=external -count=1 ./...
~~~

- 原默认链接方式缺WaitOnAddress/WakeByAddress*；仅加import而使用内部链接又缺memset。以上组合在本机实际运行race成功。它是本机验证参数，不写死进跨平台发布配置。
- Chrome 157.0.8103.78临时全网络拦截夹具：真实DOM/native modal、模型排除与provider/attribute保留、Key/价格版本、390px窄屏、锁屏清理通过；不是生产CPA登录验收。
- Windows c-shared编译到独立临时路径，未替换运行中的库。
- 短时schema/媒体fuzz通过；性能测试区分累计分配与峰值驻留，不以分配改善声称生产吞吐保证。

未验证：Linux/macOS实机、真实UNC共享、真实CPA父页面会话和上游供应商联调、断电/硬杀、生产压力、最新CVE扫描。修复验证阶段没有提交、推送、发布、安装或重启真实宿主；后续按用户授权纳入 v0.11.3-pre.5 发布，仍不包含生产部署。发布平台构建结果以 GitHub Actions 为准。
