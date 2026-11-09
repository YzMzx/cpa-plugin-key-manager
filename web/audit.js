/* Administrator-only, read-only request audit. Bodies are fetched only on explicit selection. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardAudit = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const BASE = "/v0/management/key-guard/audit";
  const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const integer = value => Number.isSafeInteger(value) && value >= 0;
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const FILTERS = { key_fingerprint: "auditKey", key_label: "auditKeyLabel", model: "auditModel", outcome: "auditOutcome", ip: "auditIP" };
  const OUTCOMES = { unknown: "未知", succeeded: "成功", success: "成功", failed: "失败", cancelled: "取消", canceled: "取消", running: "进行中", in_progress: "进行中", pending: "进行中", rejected: "已拒绝" };
  const SOURCES = { host: "host · 宿主", peer: "peer · 直连", trustedproxy: "trustedproxy · 可信代理", unknown: "unknown · 未知" };
  const BODY_STATES = { omitted_busy: "大正文脱敏繁忙，正文已略过", omitted_unknown_schema: "未知请求结构，正文已略过", omitted_secret_collision: "敏感内容无法安全替换，正文已略过", omitted_secret_limit: "敏感内容校验超限，正文已略过", omitted_encoding: "编码不支持，正文已略过", omitted_non_json: "非 JSON 正文，已略过", omitted_invalid_json: "JSON 无效，正文已略过", omitted_input_limit: "输入正文超限，已略过", omitted_non_container: "非对象或数组 JSON，已略过", omitted_depth_limit: "JSON 嵌套深度超限，已略过", omitted_element_limit: "JSON 元素数量超限，已略过", omitted_string_limit: "JSON 字符串超限，已略过", omitted_number_limit: "JSON 数字超限，已略过", omitted_ambiguous_json: "JSON 存在歧义，已略过", omitted_output_limit: "脱敏后正文超限，已略过", redacted: "已保存脱敏 JSON", captured: "已保存脱敏 JSON", stored: "已保存脱敏 JSON", omitted: "正文已略过", non_json: "非 JSON 正文，已略过", too_large: "正文超过限制，已略过", empty: "无正文", disabled: "未保存正文", invalid_json: "无法解码 JSON，已略过", unavailable: "正文不可用" };
  function validateStatus(value) {
    if (!object(value) || typeof value.enabled !== "boolean" || !["retention_days", "max_records", "max_body_bytes", "max_total_bytes"].every(key => integer(value[key]))) throw new Error("审计状态响应格式无效");
    return value;
  }
  function validateList(value) {
    if (!object(value) || !Array.isArray(value.items) || !value.items.every(record => object(record) && typeof record.id === "string" && record.id !== "" && !own(record, "request_body")) || !integer(value.total) || !integer(value.offset) || !integer(value.limit) || value.limit < 1 || value.items.length > value.limit) throw new Error("审计列表响应格式无效；列表不得包含请求正文");
    validateStatus(value.status);
    return value;
  }
  function validateDetail(value, id) {
    if (!object(value) || !object(value.record) || value.record.id !== id) throw new Error("审计详情响应与所选记录不一致");
    validateStatus(value.status);
    return value;
  }
  function statusPayload(value) { return validateStatus(object(value) && own(value, "status") ? value.status : value); }
  const label = (mapping, value, fallback) => own(mapping, value) ? mapping[value] : text(value, fallback);
  function text(value, fallback = "未知") { return typeof value === "string" && value.trim() !== "" ? value : fallback; }
  function validTimestamp(value) {
    if (typeof value !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(value)) return false;
    const year = Number(value.slice(0, 4)), month = Number(value.slice(5, 7)), day = Number(value.slice(8, 10));
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || Number(value.slice(11, 13)) > 23 || Number(value.slice(14, 16)) > 59 || Number(value.slice(17, 19)) > 59) return false;
    const zone = value.endsWith("Z") ? "" : value.slice(-6);
    if (zone && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59)) return false;
    return Number.isFinite(Date.parse(value));
  }
  function timestamp(value, zone) {
    // Numeric 0/missing dates are unknown, never guessed as seconds or milliseconds.
    if (!validTimestamp(value)) return "未知";
    try { return new Intl.DateTimeFormat("zh-CN", { timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(new Date(value)); }
    catch (_) { return value; }
  }
  function bodyView(record) {
    const bodyLabel = label(BODY_STATES, record.body_state, "未知正文状态");
    const state = bodyLabel + (record.body_truncated ? " · 已触及限制，正文已略过" : "");
    const raw = record.request_body;
    if (record.body_truncated || !["stored", "redacted", "captured"].includes(record.body_state)) return { state, json: "正文已略过或未确认可展示的脱敏 JSON。" };
    if (raw === undefined || raw === null || raw === "") return { state, json: "无可显示的请求正文（可能为空、非 JSON 或已超过保存限制）。" };
    // Large retained JSON is already validated by the backend. Keep its compact
    // representation instead of allocating another parsed tree and pretty copy.
    if (typeof raw === "string" && raw.length > 256 * 1024) return { state: state + " · 大正文按紧凑 JSON 展示", json: raw };
    try { return { state, json: JSON.stringify(typeof raw === "string" ? JSON.parse(raw) : raw, null, 2) }; }
    catch (_) { return { state: state + " · JSON 解码失败", json: "正文不是可解码的 JSON，已略过展示。" }; }
  }
  function dateFilter(value) {
    if (!value) return "";
    if (!validTimestamp(value)) throw new Error("审计时间须为有效且含时区的 RFC3339，例如 2026-11-09T00:00:00+08:00");
    return value;
  }
  function queryString(filters, limit, offset) {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    for (const name of Object.keys(FILTERS)) {
      const value = String(filters[name] || "").trim();
      if (value) params.set(name, value);
    }
    return params.toString();
  }
  function bytes(value) {
    if (!integer(value)) return "未知";
    if (value >= 1024 * 1024) return (value / 1024 / 1024).toFixed(1) + " MiB";
    if (value >= 1024) return (value / 1024).toFixed(1) + " KiB";
    return value + " B";
  }
  function create({ document: doc, request, gate, isAuthenticated, getTimezone = () => "Asia/Shanghai", getKeyOptions = () => [] }) {
    let active = false;
    let selectedId = "";
    let status = null;
    let items = [];
    let total = 0;
    let limit = 50;
    let offset = 0;
    let loading = false;
    let filters = {};
    let returnFocus = null;
    let cleanupPreview = null;
    let cleanupBusy = false;
    const rowButtons = new Map();
    const rowsById = new Map();
    const element = id => doc.getElementById(id);
    const set = (id, value) => { const node = element(id); if (node) node.textContent = value; };
    const clear = node => { if (node) node.replaceChildren(); };
    function cell(parent, value, className) { const node = doc.createElement("td"); if (className) node.className = className; node.textContent = value; parent.appendChild(node); return node; }
    function messageRow(message) { const body = element("auditListBody"); clear(body); const row = doc.createElement("tr"); const td = cell(row, message, "cell-empty"); td.colSpan = 10; body.appendChild(row); }
    function renderStatus() {
      if (!status) return;
      const description = (status.enabled ? "审计已启用" : "审计未启用，不会生成新记录") + " · 保留 " + status.retention_days + " 天 · 最多 " + status.max_records + " 条 · 单正文 " + bytes(status.max_body_bytes) + " · 总量上限 " + bytes(status.max_total_bytes);
      set("auditStatus", description + (status.warning ? " · " + String(status.warning) : "") + (status.last_error ? " · 审计存储异常：" + String(status.last_error) : "") + (integer(status.capture_failures) && status.capture_failures > 0 ? " · 本次运行采集失败 " + status.capture_failures + " 次（可能有记录或终态缺失）" : ""));
    }
    function renderKeyOptions() {
      const select = element("auditKey");
      const chosen = filters.key_fingerprint || select.value || "";
      const options = new Map();
      const configured = getKeyOptions();
      if (Array.isArray(configured)) for (const option of configured) {
        if (option && typeof option.value === "string" && option.value) options.set(option.value, text(option.label, option.value.slice(0, 12)));
      }
      for (const record of items) if (record.key_fingerprint && !options.has(record.key_fingerprint)) options.set(record.key_fingerprint, text(record.key_label, "历史密钥") + " · " + record.key_fingerprint.slice(0, 12));
      if (chosen && !options.has(chosen)) options.set(chosen, "已选密钥 · " + chosen.slice(0, 12));
      clear(select);
      const all = doc.createElement("option"); all.value = ""; all.textContent = "全部 API Key"; select.appendChild(all);
      for (const [value, label] of options) { const option = doc.createElement("option"); option.value = value; option.textContent = label; select.appendChild(option); }
      select.value = chosen;
    }
    function renderPagination() {
      const page = total ? Math.floor(offset / limit) + 1 : 1;
      const pages = Math.max(1, Math.ceil(total / limit));
      set("auditPageInfo", "共 " + total + " 条 · 第 " + page + " / " + pages + " 页");
      element("auditPrevPage").disabled = loading || offset === 0;
      element("auditNextPage").disabled = loading || offset + limit >= total;
      element("auditPageSize").disabled = loading;
    }
    function renderList() {
      if (!items.length) { messageRow(status && !status.enabled ? "暂无记录；审计未启用" : "没有匹配的审计记录"); renderPagination(); return; }
      const body = element("auditListBody"); clear(body); rowButtons.clear(); rowsById.clear();
      for (const record of items) {
        const row = doc.createElement("tr");
        cell(row, timestamp(record.started_at, getTimezone()), "cell-nowrap");
        const ids = cell(row, text(record.request_id), "mono audit-list-cell"); const trace = doc.createElement("div"); trace.className = "audit-cell-secondary"; trace.textContent = "Trace: " + text(record.trace_id); ids.appendChild(trace);
        const key = cell(row, text(record.key_label), "audit-list-cell"); const fingerprint = doc.createElement("div"); fingerprint.className = "mono audit-cell-secondary"; fingerprint.textContent = text(record.key_fingerprint); key.appendChild(fingerprint);
        const models = cell(row, text(record.requested_model), "mono audit-list-cell"); const served = doc.createElement("div"); served.className = "audit-cell-secondary"; served.textContent = "服务: " + text(record.served_model); models.appendChild(served);
        cell(row, text(record.client_ip), "mono audit-list-cell");
        cell(row, label(SOURCES, record.ip_source, SOURCES.unknown), "audit-list-cell");
        cell(row, (label(OUTCOMES, record.outcome, "未知")) + " / " + (integer(record.status_code) && record.status_code > 0 ? record.status_code : "未知"), "cell-nowrap");
        cell(row, typeof record.duration_ms === "number" && Number.isFinite(record.duration_ms) && record.duration_ms >= 0 ? record.duration_ms.toFixed(1) + " ms" : "未知", "cell-nowrap");
        cell(row, (label(BODY_STATES, record.body_state, "未知正文状态")) + (record.body_truncated ? " · 超限略过" : ""), "audit-list-cell");
        const action = cell(row, ""); const button = doc.createElement("button"); button.type = "button"; button.className = "btn btn-sm"; button.dataset.auditId = record.id; button.textContent = "只读详情"; button.setAttribute("aria-controls", "auditDetailPanel"); button.setAttribute("aria-expanded", "false"); action.appendChild(button); rowButtons.set(record.id, button); rowsById.set(record.id, row);
        body.appendChild(row);
      }
      renderPagination();
    }
    function drawerState() {
      const index = items.findIndex(record => record.id === selectedId);
      set("auditDetailPosition", index < 0 ? "" : "本页第 " + (index + 1) + " / " + items.length + " 条 · Esc 关闭");
      element("auditDetailPrev").disabled = index <= 0;
      element("auditDetailNext").disabled = index < 0 || index >= items.length - 1;
      for (const [id, button] of rowButtons) button.setAttribute("aria-expanded", String(id === selectedId));
      for (const [id, row] of rowsById) { if (id === selectedId) row.classList.add("audit-row-selected"); else row.classList.remove("audit-row-selected"); }
    }
    function clearDetail(restoreFocus = false) {
      gate.cancel("audit-detail"); selectedId = "";
      element("auditDetail").classList.add("hidden");
      if (doc.body) doc.body.classList.remove("audit-detail-open");
      for (const id of ["auditDetailMessage", "auditRequestBody", "auditBodyState", "auditBodyHash", "auditDetailPosition"]) set(id, "");
      clear(element("auditDetailMetadata")); drawerState();
      const target = returnFocus; returnFocus = null;
      if (restoreFocus && active && isAuthenticated() && target && target.isConnected !== false && typeof target.focus === "function") target.focus({ preventScroll: true });
    }
    function shiftDetail(delta) {
      const index = items.findIndex(record => record.id === selectedId);
      const next = index + delta;
      if (index >= 0 && next >= 0 && next < items.length) return showDetail(items[next].id, null, true);
      return Promise.resolve();
    }
    function handleDrawerKey(event) {
      if (!selectedId || element("auditDetail").classList.contains("hidden")) return;
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); clearDetail(true); return; }
      if (event.key !== "Tab") return;
      const panel = element("auditDetailPanel");
      const focusable = typeof panel.querySelectorAll === "function" ? Array.from(panel.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex="0"]')) : [];
      if (!focusable.length) { event.preventDefault(); panel.focus({ preventScroll: true }); return; }
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && (doc.activeElement === first || !panel.contains(doc.activeElement))) { event.preventDefault(); last.focus({ preventScroll: true }); }
      else if (!event.shiftKey && (doc.activeElement === last || !panel.contains(doc.activeElement))) { event.preventDefault(); first.focus({ preventScroll: true }); }
    }
    function renderDetail(record) {
      const metadata = element("auditDetailMetadata"); clear(metadata);
      const rows = [
        ["审计 ID", record.id], ["请求 ID", record.request_id], ["Trace ID", record.trace_id],
        ["开始时间", timestamp(record.started_at, getTimezone())], ["完成时间", timestamp(record.completed_at !== undefined ? record.completed_at : record.complete_at, getTimezone())],
        ["方法 / 路径", text(record.method) + " " + text(record.path)], ["客户端 IP", text(record.client_ip)], ["直连 Peer IP", text(record.peer_ip)],
        ["IP 来源", SOURCES[record.ip_source] || text(record.ip_source, SOURCES.unknown)], ["IP 说明", text(record.ip_note, "无附加说明")],
        ["密钥备注 / 指纹", text(record.key_label) + " / " + text(record.key_fingerprint)], ["请求模型", text(record.requested_model)], ["服务模型", text(record.served_model)],
        ["协议 / 流式", text(record.protocol) + " / " + (typeof record.stream === "boolean" ? record.stream ? "是" : "否" : "未知")],
        ["结果 / 状态码", (OUTCOMES[record.outcome] || text(record.outcome)) + " / " + (integer(record.status_code) && record.status_code > 0 ? record.status_code : "未知")],
        ["耗时", typeof record.duration_ms === "number" && Number.isFinite(record.duration_ms) && record.duration_ms >= 0 ? record.duration_ms.toFixed(1) + " ms" : "未知"]
      ];
      for (const [label, value] of rows) { const dt = doc.createElement("dt"); dt.textContent = label; const dd = doc.createElement("dd"); dd.textContent = text(value); metadata.appendChild(dt); metadata.appendChild(dd); }
      const body = bodyView(record); set("auditBodyState", body.state); set("auditRequestBody", body.json); set("auditBodyHash", text(record.body_sha256, "未知 / 未保存脱敏内容哈希"));
    }
    function renderStorage(value) {
      if (!object(value) || !integer(value.records) || !integer(value.logical_bytes) || !integer(value.max_total_bytes)) throw new Error("占用统计响应格式无效");
      const percent = value.max_total_bytes ? Math.min(100, value.logical_bytes / value.max_total_bytes * 100).toFixed(1) : "0.0";
      set("auditStorageSummary", value.records + " 条 · 审计逻辑占用 " + bytes(value.logical_bytes) + " / " + bytes(value.max_total_bytes) + "（" + percent + "%）· 正文 " + bytes(value.request_body_bytes) + (integer(value.expired_records) ? " · 已过期 " + value.expired_records + " 条" : ""));
      set("auditStoragePhysical", "共享数据库文件 " + bytes(value.db_file_bytes) + " · WAL " + bytes(value.wal_file_bytes) + "（含规则、用量等；清理审计不保证文件立即缩小）");
    }
    async function loadStorage() {
      if (!active || !isAuthenticated()) return;
      const ticket = gate.begin("audit-storage"); element("auditStorageRefresh").disabled = true;
      try {
        const payload = await request(BASE + "/storage", { method: "GET", signal: ticket.signal });
        if (ticket.current() && active && isAuthenticated()) renderStorage(payload.storage);
      } catch (error) { if (ticket.current() && active && isAuthenticated() && error.name !== "AbortError") set("auditStorageSummary", "占用计算失败：" + error.message); }
      finally { if (ticket.current()) element("auditStorageRefresh").disabled = false; ticket.finish(); }
    }
    function resetCleanupPreview(message = "先预览影响范围，再确认执行；只清理审计，不影响密钥规则和用量账本。") {
      gate.cancel("audit-cleanup-preview"); cleanupPreview = null;
      if (!cleanupBusy) element("auditCleanupPreview").disabled = false;
      element("auditCleanupAcknowledge").checked = false; element("auditCleanupConfirm").disabled = true;
      element("auditCleanupConfirmation").classList.add("hidden"); set("auditCleanupMessage", message);
    }
    function cleanupSelection() {
      const choice = element("auditCleanupScope").value || "expired";
      if (choice === "expired" || choice === "all") return { scope: choice };
      if (["1d", "3d", "7d"].includes(choice)) return { scope: "before", before: new Date(Date.now() - Number(choice.slice(0, -1)) * 86400000).toISOString() };
      if (choice === "custom") {
        const before = element("auditCleanupBefore").value.trim(); dateFilter(before);
        if (!before || Date.parse(before) >= Date.now()) throw new Error("请输入含时区且早于当前时间的日期");
        return { scope: "before", before };
      }
      throw new Error("请选择有效的清理范围");
    }
    async function previewCleanup() {
      if (!active || !isAuthenticated() || cleanupBusy) return;
      resetCleanupPreview();
      let selection; try { selection = cleanupSelection(); } catch (error) { set("auditCleanupMessage", error.message); return; }
      const ticket = gate.begin("audit-cleanup-preview"); element("auditCleanupPreview").disabled = true;
      set("auditCleanupMessage", "正在计算清理范围，尚未删除任何记录…");
      try {
        const payload = await request(BASE + "/cleanup/preview", { method: "POST", body: JSON.stringify(selection), signal: ticket.signal });
        if (!ticket.current() || !active || !isAuthenticated()) return;
        const value = payload.preview;
        if (!object(value) || typeof value.token !== "string" || !value.token || !integer(value.records) || !integer(value.logical_bytes)) throw new Error("清理预览响应无效");
        cleanupPreview = value; if (payload.storage) renderStorage(payload.storage);
        set("auditCleanupMessage", "将永久删除 " + value.records + " 条审计记录 · 逻辑占用 " + bytes(value.logical_bytes) + " · 正文 " + bytes(value.request_body_bytes) + (value.before ? " · 截止 " + timestamp(value.before, getTimezone()) : "") + "。预览后新增记录不在此次清理范围。");
        if (value.records > 0) element("auditCleanupConfirmation").classList.remove("hidden");
      } catch (error) { if (ticket.current() && active && isAuthenticated() && error.name !== "AbortError") resetCleanupPreview("清理预览失败：" + error.message); }
      finally { if (!cleanupBusy) element("auditCleanupPreview").disabled = false; ticket.finish(); }
    }
    async function confirmCleanup() {
      if (!active || !isAuthenticated() || cleanupBusy || !cleanupPreview || !element("auditCleanupAcknowledge").checked) return;
      const token = cleanupPreview.token; cleanupPreview = null; cleanupBusy = true;
      element("auditCleanupConfirm").disabled = true; element("auditCleanupPreview").disabled = true;
      set("auditCleanupMessage", "正在清理已确认的审计记录…");
      const ticket = gate.begin("audit-cleanup");
      try {
        const payload = await request(BASE + "/cleanup", { method: "POST", body: JSON.stringify({ token, confirm: true }), signal: ticket.signal });
        if (!ticket.current() || !active || !isAuthenticated()) return;
        if (payload.ok !== true || !object(payload.deleted) || !integer(payload.deleted.records)) throw new Error("服务器未确认清理结果");
        const message = "已清理 " + payload.deleted.records + " 条审计记录 · 释放逻辑占用 " + bytes(payload.deleted.logical_bytes) + "；规则和用量账本保持不变。";
        resetCleanupPreview(message); clearDetail(); if (payload.storage) renderStorage(payload.storage);
        await loadList();
      } catch (error) { if (ticket.current() && active && isAuthenticated() && error.name !== "AbortError") resetCleanupPreview("清理结果未确认：" + error.message + "。请重新计算占用并预览，不要直接重复提交。"); }
      finally { cleanupBusy = false; element("auditCleanupPreview").disabled = false; ticket.finish(); }
    }
    async function loadStatus() {
      if (!active || !isAuthenticated()) return;
      const ticket = gate.begin("audit-status");
      try {
        const payload = await request(BASE + "/status", { method: "GET", signal: ticket.signal });
        if (!ticket.current() || !active || !isAuthenticated()) return;
        status = statusPayload(payload); renderStatus();
      } catch (error) {
        if (ticket.current() && active && isAuthenticated() && error.name !== "AbortError") set("auditStatus", "无法读取审计状态：" + error.message);
      } finally { ticket.finish(); }
    }
    async function loadList(correctBoundary = true) {
      if (!active || !isAuthenticated()) return;
      let query;
      try { query = queryString(filters, limit, offset); } catch (error) { set("auditListMessage", error.message); return; }
      clearDetail();
      const ticket = gate.begin("audit-list"); loading = true; items = []; messageRow("正在读取审计列表…"); renderPagination();
      set("auditListMessage", "正在读取审计列表；正文仅在点击详情时获取。");
      try {
        const payload = await request(BASE + "?" + query, { method: "GET", signal: ticket.signal });
        if (!ticket.current() || !active || !isAuthenticated()) return;
        validateList(payload); status = payload.status; total = payload.total; limit = payload.limit; offset = payload.offset;
        const maxOffset = total ? Math.floor((total - 1) / limit) * limit : 0;
        if (offset > maxOffset && correctBoundary) { offset = maxOffset; ticket.finish(); loading = false; return loadList(false); }
        if (offset > maxOffset) throw new Error("审计列表分页发生变化，请重试");
        items = payload.items; renderKeyOptions(); renderStatus(); renderList();
        set("auditListMessage", "列表不包含请求正文；仅供管理员只读查看。");
      } catch (error) {
        if (ticket.current() && active && isAuthenticated() && error.name !== "AbortError") {
          total = 0; offset = 0;
          set("auditListMessage", "审计列表读取失败：" + error.message);
          messageRow("未取得有效审计列表，请重试。");
        }
      } finally { if (ticket.current()) { loading = false; renderPagination(); } ticket.finish(); }
    }
    async function showDetail(id, trigger = null, preserveDrawer = false) {
      if (!active || !isAuthenticated() || !items.some(record => record.id === id)) return;
      const oldFocus = returnFocus;
      clearDetail(); selectedId = id; returnFocus = preserveDrawer ? oldFocus : trigger || rowButtons.get(id) || doc.activeElement;
      element("auditDetail").classList.remove("hidden");
      if (doc.body) doc.body.classList.add("audit-detail-open");
      element("auditDetailContent").scrollTop = 0;
      if (!preserveDrawer) element("auditMetadataSection").open = false;
      drawerState();
      if (!preserveDrawer) element("auditDetailClose").focus({ preventScroll: true });
      set("auditDetailMessage", "正在读取所选记录的脱敏请求详情…");
      const ticket = gate.begin("audit-detail");
      try {
        const payload = await request(BASE + "/detail?id=" + encodeURIComponent(id), { method: "GET", signal: ticket.signal });
        if (!ticket.current() || selectedId !== id || !active || !isAuthenticated()) return;
        validateDetail(payload, id); status = payload.status; renderStatus(); renderDetail(payload.record); set("auditDetailMessage", "只读详情 · 不记录或展示响应正文");
      } catch (error) {
        if (ticket.current() && selectedId === id && active && isAuthenticated() && error.name !== "AbortError") set("auditDetailMessage", "详情读取失败：" + error.message + "（记录可能已过期，请刷新列表）");
      } finally { ticket.finish(); }
    }
    function applyFilters() {
      const candidate = {};
      for (const [name, id] of Object.entries(FILTERS)) candidate[name] = element(id).value.trim();
      try { queryString(candidate, limit, 0); } catch (error) { set("auditListMessage", error.message); return Promise.resolve(); }
      filters = candidate; offset = 0; return loadList();
    }
    function resetFilters() { for (const id of Object.values(FILTERS)) element(id).value = ""; filters = {}; offset = 0; return loadList(); }
    function page(delta) { if (loading) return Promise.resolve(); const next = Math.max(0, offset + delta * limit); if (next === offset || (delta > 0 && next >= total)) return Promise.resolve(); offset = next; return loadList(); }
    async function refresh() { if (!active || !isAuthenticated()) return; await Promise.all([loadStatus(), loadList(), loadStorage()]); }
    function enter() { active = true; renderKeyOptions(); return refresh(); }
    function leave() { active = false; gate.cancel("audit-list"); gate.cancel("audit-status"); gate.cancel("audit-storage"); gate.cancel("audit-cleanup"); resetCleanupPreview(); loading = false; clearDetail(); renderPagination(); }
    function lock() { leave(); status = null; items = []; total = 0; set("auditStorageSummary", "需要管理员授权"); set("auditStoragePhysical", ""); element("auditCleanupBefore").value = ""; limit = 50; offset = 0; filters = {}; for (const id of Object.values(FILTERS)) element(id).value = ""; element("auditPageSize").value = "50"; set("auditStatus", "需要管理密钥授权后读取审计状态。"); set("auditListMessage", ""); messageRow("需要管理员授权"); renderPagination(); }
    function bind() {
      element("auditStorageRefresh").addEventListener("click", loadStorage);
      element("auditCleanupPreview").addEventListener("click", previewCleanup);
      element("auditCleanupConfirm").addEventListener("click", confirmCleanup);
      element("auditCleanupCancel").addEventListener("click", () => resetCleanupPreview());
      element("auditCleanupScope").addEventListener("change", () => { resetCleanupPreview(); const custom = element("auditCleanupScope").value === "custom"; if (custom) element("auditCleanupBeforeLabel").classList.remove("hidden"); else element("auditCleanupBeforeLabel").classList.add("hidden"); });
      element("auditCleanupBefore").addEventListener("input", () => resetCleanupPreview());
      element("auditCleanupAcknowledge").addEventListener("change", () => { element("auditCleanupConfirm").disabled = cleanupBusy || !cleanupPreview || !element("auditCleanupAcknowledge").checked; });
      element("auditFilterForm").addEventListener("submit", event => { event.preventDefault(); applyFilters(); });
      element("auditFilterReset").addEventListener("click", resetFilters);
      element("auditPrevPage").addEventListener("click", () => page(-1)); element("auditNextPage").addEventListener("click", () => page(1));
      element("auditPageSize").addEventListener("change", () => { const next = Number(element("auditPageSize").value); limit = [25, 50, 100].includes(next) ? next : 50; offset = 0; loadList(); });
      element("auditDetailClose").addEventListener("click", () => clearDetail(true));
      element("auditDetailPrev").addEventListener("click", () => shiftDetail(-1));
      element("auditDetailNext").addEventListener("click", () => shiftDetail(1));
      element("auditDetail").addEventListener("click", event => { if (event.target === element("auditDetail")) clearDetail(true); });
      element("auditDetail").addEventListener("keydown", handleDrawerKey);
      element("auditListBody").addEventListener("click", event => { const button = event.target.closest && event.target.closest("button[data-audit-id]"); if (button) showDetail(button.dataset.auditId, button); });
    }
    bind(); renderPagination();
    return { enter, leave, lock, refresh, applyFilters, resetFilters, page, showDetail, closeDetail: () => clearDetail(true), loadStorage, previewCleanup, confirmCleanup, isActive: () => active };
  }
  return { create, queryString, timestamp, bodyView, validateStatus, validateList, validateDetail, statusPayload };
});
