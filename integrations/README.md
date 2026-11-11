# CPA 管理前端认证桥

本目录提供 cpa-plugin-key-manager 的 CPA 管理前端接入补丁。补丁基于官方 Cli-Proxy-API-Management-Center v1.27.3，提交 953fb2444350c6c36052dda46cac0abce6b23ea6；包含父页面实现与 53 项回归测试。

## 使用方式

- 仅更新插件即可复用 CPA 已保存的兼容登录凭证，包括 enc::v2:: 和旧版 v1 格式。
- 要在未勾选“记住密码”时免二次输入，还需使用接入认证桥的 CPA 管理页面。
- 在上述版本的管理前端源码目录执行：

~~~sh
git apply --check /path/to/cpa-management-auth-bridge.patch
git apply /path/to/cpa-management-auth-bridge.patch
bun install --frozen-lockfile
bun test tests/pluginAuthBridge.test.ts
bun run build
~~~

按既有 CPA 部署方式将生成的 dist/index.html 部署为 management.html。发布页另附已构建的 cpa-management-auth-bridge-v1.27.3.html，可重命名为 management.html 使用。该前端要求 CPA 支持 /v8/management；旧版宿主应在匹配的管理前端版本中适配补丁。替换前保留原管理页面；自动更新管理页面可能覆盖此自定义改动。

## 认证行为

插件与后台须同源（协议、域名、端口相同）。父页面仅响应当前插件的 /v0/resource/plugins/cpa-plugin-key-manager/ui 框架，验证来源窗口、当前页面路径与登录状态，返回当前管理凭证。插件切换标签产生的合法 tab 查询参数不影响重新认证。父页面退出、切换连接或凭证时，先撤销旧会话，再通知插件重新获取。

管理 API 继续由 CPA 校验 Management Key。独立打开插件且无可复用凭证时，保留手动输入；后台迟到就绪时支持重试。跨域认证共享和反向代理子路径部署尚未验证。

## 验证记录

插件前端 98 项测试、Go 页面嵌入测试及 Windows 插件构建通过。配套管理前端 53 项认证桥回归和 4 项两端联合测试通过，lint、TypeScript、单文件构建通过。本地使用 Bun 1.3.14（上游声明 1.4.3）；上游完整测试的 13 项失败已在未修改的同一提交复现：3 项 CRLF 源码断言、8 项 Windows Bun 子进程 ENOENT、2 项地区货币显示差异。没有进行实际运行 CPA 的浏览器登录验收。

上游管理前端：https://github.com/router-for-me/Cli-Proxy-API-Management-Center
