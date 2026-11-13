  const API_OVERVIEW       = "/v0/management/key-guard/overview";
  const API_KEYS_REORDER   = "/v0/management/key-guard/keys/reorder";
  const API_KEYS_CRUD      = "/v0/management/key-guard/keys";
  const API_DEFAULT_POLICY = "/v0/management/key-guard/default-policy";
  const API_USAGE_RESET    = "/v0/management/key-guard/usage/reset";
  const API_PRICING        = "/v0/management/key-guard/pricing";
  const API_PRICING_SYNC   = "/v0/management/key-guard/pricing/sync";
  const API_PRICING_CUSTOM = "/v0/management/key-guard/pricing/custom";
  const SESSION_KEY_NAME   = "cpa_plugin_key_manager_mgmt_session";
  const LEGACY_SESSION_KEY_NAME = "cpa_plugin_key_mgmt_session";

  if (window.parent !== window) {
    document.body.classList.add("embedded");
  }

  let activeManagementKey = "";
  let overviewData = null;
  let expandedDashKeys = {};
  let expandedDashAccounts = {};
  let revealedKeys = {};
  let overviewIndex = KeyGuardState.indexOverview({});
  let sessionEpoch = 0;
  let keyModalEpoch = 0;
  let keyModalRevision = null, keyModalBaseline = null;
  let priceModalRevision = null, priceModalBaseline = null;
  let defaultPolicyBaseline = null;
  const cloneRule = value => JSON.parse(JSON.stringify(value || {}));
  const sessionCurrent = epoch => epoch === sessionEpoch && !!activeManagementKey;
  // An editor owns both its baseline and revision until explicitly reopened/discarded.
  function revisionHeaders(revision) {
    if (revision === null || revision === undefined) throw new Error("缺少编辑版本，请重新打开编辑器后保存");
    return { "X-Key-Guard-Revision": String(revision) };
  }
  let priceModalEpoch = 0;
  const pendingMutations = new Set();
  let usageGroupsCache = new WeakMap();
  const requestGate = KeyGuardState.createRequestGate();
  let currentAdminTab = "tab-overview";
  let defaultPolicyDirty = false;
  let defaultPolicyRevision = null;
  let defaultPolicySaveInFlight = false;
  const keyDialog = KeyGuardDialogs.create(document.getElementById("keyModal"), {
    onClose: () => { keyModalEpoch++; keyModalBaseline = null; keyModalRevision = null; }
  });
  const priceDialog = KeyGuardDialogs.create(document.getElementById("priceModal"), {
    onClose: () => { priceModalEpoch++; priceModalRevision = null; priceModalBaseline = null; requestGate.cancel("modalPrice"); }
  });
  const auditView = KeyGuardAudit.create({
    document, request: (...args) => callManagementAPI(...args), gate: requestGate,
    isAuthenticated: () => !!activeManagementKey,
    getTimezone: () => currentTimezone(),
    getKeyOptions: () => (overviewData && overviewData.audit_key_options) || []
  });
  const settingsView = KeyGuardSettings.create({
    document, request: (...args) => callManagementAPI(...args), gate: requestGate,
    isAuthenticated: () => !!activeManagementKey,
    navigate: tab => switchAdminTab(tab),
    onSaved: async payload => { if (payload.overview) { applyOverviewData(payload.overview); await loadOverviewLedger(false); } else { await loadAdminOverview(); } }
  });
  const apiClient = KeyGuardClient.createClient({
    fetchImpl: (...args) => fetch(...args),
    getKey: () => activeManagementKey,
    getRevision: () => overviewData && overviewData.rules_revision,
    onUnauthorized: message => lockAdminWorkspace(message)
  });
  function overviewHealthMessage(data) {
    const messages = [];
    if (data && data.auth_files_error) messages.push(String(data.auth_files_error));
    if (data && data.summary && data.summary.accounting_error) messages.push("汇总统计异常（数值不可用）：" + data.summary.accounting_error);
    const sync = data && data.host_sync;
    if (sync && sync.pending) messages.push("规则已保存，宿主同步待重试" + (sync.error ? "：" + sync.error : ""));
    const persistence = data && data.diagnostics && data.diagnostics.persistence;
    if (persistence && persistence.last_error) messages.push("统计持久化失败，待重试：" + persistence.last_error);
    if (persistence && persistence.accounting_error) messages.push("统计记账异常：" + persistence.accounting_error);
    return messages.join("；");
  }
  const isCancelled = error => error && error.name === "AbortError";
  const currentTimezone = () => KeyGuardFormat.timezone(overviewData && overviewData.timezone);
  function setRefreshStatus(message, failed = false) {
    const element = document.getElementById("refreshStatus");
    if (!element) return;
    element.textContent = message || "";
    element.classList.toggle("hidden", !message);
    element.style.color = failed ? "var(--error-color)" : "var(--text-secondary)";
  }

  // Checkbox selection state for Modal ('km') and Default Policy ('dp')
  const selectorState = {
    km: {
      allModels: true,
      selectedModels: new Set(),
      providerFilter: "all",
      allCreds: true,
      selectedCreds: new Set(),
      loadedCreds: new Set()
    },
    dp: {
      allModels: true,
      selectedModels: new Set(),
      providerFilter: "all",
      allCreds: true,
      selectedCreds: new Set(),
      loadedCreds: new Set()
    }
  };

  function showToast(msg, isError = false) {
    // Page-level toasts sit below a native modal and cannot announce inside its inert background.
    const modalMessage = priceDialog.isOpen() ? document.getElementById("priceModalMessage") : keyDialog.isOpen() ? document.getElementById("keyModalMessage") : null;
    if (modalMessage) { modalMessage.textContent = msg; modalMessage.dataset.error = String(isError); return; }
    const box = document.getElementById("toastBox");
    const el = document.createElement("div");
    el.className = "toast";
    if (isError) el.style.borderLeftColor = "var(--error-color)";
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => el.remove(), 3400);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtInt(n) {
    return Number(n || 0).toLocaleString("en-US");
  }

  function maskKeyStr(k) {
    if (!k) return "-";
    if (k.length <= 8) return k.slice(0, 2) + "***";
    if (k.length <= 14) return k.slice(0, 4) + "..." + k.slice(-3);
    return k.slice(0, 7) + "..." + k.slice(-5);
  }

  function cleanBearerToken(val) {
    if (typeof val !== "string") return "";
    return val.replace(/^Bearer\s+/i, "").trim();
  }

  function readStoredManagementKeyFromStorage(storageObj) {
    return KeyGuardAuth.readStoredKey(storageObj, location, navigator.userAgent);
  }

  // Prefer the live host session so an old plugin cache cannot mask a rotated key.
  let parentSessionRevoked = false;
  let parentBridgeAvailable = false;
  async function discoverCPAManagementKey() {
    if (activeManagementKey) return activeManagementKey;
    if (window.parent !== window) {
      const fromBridge = await KeyGuardAuth.requestParentKey(window);
      if (parentSessionRevoked) return "";
      if (fromBridge) { parentBridgeAvailable = true; return cleanBearerToken(fromBridge); }
      if (parentBridgeAvailable) return "";
    }
    const fromLocal = readStoredManagementKeyFromStorage(window.localStorage);
    if (fromLocal) return fromLocal;
    if (window.parent !== window) {
      try {
        const fromParentLocal = readStoredManagementKeyFromStorage(window.parent.localStorage);
        if (fromParentLocal) return fromParentLocal;
      } catch (_) {}
    }
    try {
      const sessKey = sessionStorage.getItem(SESSION_KEY_NAME) || sessionStorage.getItem(LEGACY_SESSION_KEY_NAME);
      if (sessKey && sessKey.trim()) return cleanBearerToken(sessKey);
    } catch (_) {}
    return "";
  }

  function unlockAdminWorkspace(validKey) {
    activeManagementKey = validKey;
    try {
      if (parentBridgeAvailable) {
        // Host logout can destroy the iframe before its queued notification arrives.
        sessionStorage.removeItem(SESSION_KEY_NAME);
        sessionStorage.removeItem(LEGACY_SESSION_KEY_NAME);
      } else { sessionStorage.setItem(SESSION_KEY_NAME, validKey); }
    } catch (_) {}
    document.getElementById("authGateError").classList.add("hidden");
    document.getElementById("authGateView").classList.add("hidden");
    document.getElementById("adminWorkspace").classList.remove("hidden");
  }

  function lockAdminWorkspace(errMsg) {
    sessionEpoch++; activeManagementKey = "";
    keyModalEpoch++; keyModalBaseline = null; keyModalRevision = null;
    priceModalBaseline = null; priceModalRevision = null; defaultPolicyBaseline = null;
    defaultPolicySaveInFlight = false; pendingMutations.clear();
    globalRefreshInFlight = false;
    overviewState.expandedKeys = {}; overviewState.activeModel = "";
    dragSrcKey = null; dragOverKey = null; usageGroupsCache = new WeakMap();
    auditView.lock();
    settingsView.lock();
    requestGate.cancelAll(); apiClient.cancelAll();
    overviewState.loading = false;
    clearTimeout(modelsDevSearchTimer); modelsDevSearchTimer = null;
    priceModalEpoch++;
    keyDialog.close({ immediate: true }); priceDialog.close({ immediate: true }); closeModelPopover();
    document.querySelectorAll("dialog.modal input, dialog.modal select").forEach(input => { input.value = ""; });
    ["kmModelCheckList", "kmCredCheckList", "dpModelCheckList", "dpCredCheckList", "pmRefHint", "authGateKeyInput"].forEach(id => {
      const element = document.getElementById(id); if (element) { if ("value" in element) element.value = ""; else element.textContent = ""; }
    });
    for (const id of ["keyModalMessage", "priceModalMessage"]) document.getElementById(id).textContent = "";
    for (const state of Object.values(selectorState)) {
      state.selectedModels.clear(); state.selectedCreds.clear(); state.loadedCreds.clear();
      state.allModels = true; state.allCreds = true; state.providerFilter = "all";
    }
    for (const id of ["crudKeySearch", "quotaSearch", "dashKeySearch", "dashAccountSearch", "pricingTableSearch", "modelsDevSearchInput", "kmModelSearch", "kmCredSearch", "dpModelSearch", "dpCredSearch", "dpAllowUnlisted", "dpMaxConcurrency", "dpBindStrategy", "kmName", "kmQuotaLimit", "kmMaxConcurrency", "kmBindStrategy", "pmInputPrice", "pmOutputPrice", "pmCacheReadPrice", "pmCacheWritePrice"]) {
      const element = document.getElementById(id); if (element) element.value = "";
    }
    for (const id of ["ovTrendChart", "ovDonutChart", "ovModelList", "ovKeyTableBody", "ovKeyTableMeta", "ovTrendMeta", "ovMetricKeys", "ovMetricRequests", "ovMetricTokens", "ovMetricTokensSub", "ovMetricCost", "ovMetricCostSub", "ovMetricModels", "ovLegendInput", "ovLegendOutput", "ovLegendCache", "ovLegendHit", "kpiTotalTokens", "kpiTokenSub", "kpiCacheTokens", "kpiCacheSub", "kpiTotalRequests", "kpiReqSub", "kpiTotalCost", "kpiCostSub", "pricingSyncedCount", "pricingSyncSource", "pricingLastSyncAt", "pricingLastSyncErr", "pricingCustomCount", "pricingDefaultSub", "ovTrendTip", "priceModalTitle", "kmProviderPills", "dpProviderPills", "kmModelCountBadge", "dpModelCountBadge", "kmCredCountBadge", "dpCredCountBadge", "toastBox"]) {
      const element = document.getElementById(id); if (element) element.replaceChildren();
    }
    document.querySelectorAll("#adminWorkspace input, dialog.modal input, dialog.modal select").forEach(input => { input.value = ""; input.checked = false; });
    document.getElementById("btnSyncPricing").textContent = "立即从 models.dev 同步";
    document.querySelectorAll(".modal-footer button, #dpSaveBtn, #tabsRefreshBtn, #btnSyncPricing").forEach(button => { button.disabled = false; button.classList.remove("is-loading"); });
    revealedKeys = {}; expandedDashKeys = {}; expandedDashAccounts = {};
    overviewState.data = null;
    overviewTrendGeom = null;
    hideTrendTip();
    overviewIndex = KeyGuardState.indexOverview({});
    document.querySelectorAll("#adminWorkspace tbody, #modelPopover").forEach(element => { element.textContent = ""; });
    activeManagementKey = "";
    overviewData = null;
    defaultPolicyDirty = false; defaultPolicyRevision = null; renderDefaultPolicyDraftStatus();
    try {
      sessionStorage.removeItem(SESSION_KEY_NAME);
      sessionStorage.removeItem(LEGACY_SESSION_KEY_NAME);
    } catch (_) {}
    document.getElementById("adminWorkspace").classList.add("hidden");
    document.getElementById("authGateView").classList.remove("hidden");
    setRefreshStatus("");
    const errEl = document.getElementById("authGateError");
    if (errMsg) {
      errEl.textContent = errMsg;
      errEl.classList.remove("hidden");
    } else {
      errEl.classList.add("hidden");
    }
  }

  // Authenticated Management API request: all endpoints live under /v0/management/key-guard/*
  // which CLIProxyAPI protects with its Management Key middleware.
  async function callManagementAPI(path, options = {}, overrideKey = "") {
    const epoch = sessionEpoch;
    const method = String(options.method || "GET").toUpperCase();
    if (method === "GET" || method === "HEAD") {
      const result = await apiClient.request(path, options, overrideKey);
      if (epoch !== sessionEpoch) throw KeyGuardClient.aborted();
      return result;
    }
    if (pendingMutations.size) throw new Error("已有变更正在保存，请稍候再试");
    requestGate.cancel("overview");
    requestGate.cancel("ledger");
    const mutation = {}; pendingMutations.add(mutation);
    const keyOwner = keyModalEpoch, priceOwner = priceModalEpoch;
    const controls = Array.from(document.querySelectorAll(".modal-footer button, #dpSaveBtn"));
    const previous = controls.map(control => control.disabled);
    controls.forEach(control => { control.disabled = true; });
    try {
      const result = await apiClient.request(path, options, overrideKey);
      if (!sessionCurrent(epoch)) throw KeyGuardClient.aborted();
      requestGate.cancel("overview");
      return result;
    }
    finally {
      pendingMutations.delete(mutation);
      if (sessionCurrent(epoch)) controls.forEach((control, i) => {
        if (control.closest?.("#keyModal") && keyOwner !== keyModalEpoch) return;
        if (control.closest?.("#priceModal") && priceOwner !== priceModalEpoch) return;
        control.disabled = previous[i];
      });
    }
  }

  async function submitAuthGateKey() {
    const input = document.getElementById("authGateKeyInput");
    const candidate = cleanBearerToken(input ? input.value : "");
    if (!candidate) {
      lockAdminWorkspace("请输入有效的 CLIProxyAPI Management Key");
      return;
    }
    const btn = document.getElementById("authGateSubmitBtn");
    if (btn) btn.disabled = true;
    try {
      await loadAdminOverview(candidate);
      if (input) input.value = "";
    } catch (_) {
      // loadAdminOverview already displays error in authGateError on 401/403
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function switchAdminTab(tabId, options) {
    const opts = options || {};
    currentAdminTab = tabId;
    if (tabId === "tab-audit") { if (activeManagementKey) auditView.enter(); }
    else auditView.leave();
    if (tabId === "tab-settings") { if (activeManagementKey) settingsView.enter(); }
    else settingsView.leave();
    document.querySelectorAll(".admin-tab").forEach(s => s.classList.add("hidden"));
    const section = document.getElementById(tabId);
    if (section) section.classList.remove("hidden");
    document.querySelectorAll(".tab-btn").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-tab") === tabId);
    });
    // Keep the active tab in the URL so a refresh restores the same view.
    if (!opts.skipUrl) {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set("tab", String(tabId).replace(/^tab-/, ""));
        window.history.replaceState(null, "", url.toString());
      } catch (_) {}
    }
    if (tabId === "tab-overview" && activeManagementKey && !overviewState.data) {
      loadOverviewLedger(true);
    }
  }

  // Restores the tab requested in the URL (defaults to the overview tab).
  function restoreAdminTabFromUrl() {
    let tabId = "tab-overview";
    try {
      const param = new URL(window.location.href).searchParams.get("tab");
      if (param) {
        const candidate = "tab-" + param.replace(/^tab-/, "");
        if (document.getElementById(candidate)) tabId = candidate;
      }
    } catch (_) {}
    switchAdminTab(tabId, { skipUrl: true });
  }

  // ==================== ADMIN OVERVIEW & UNIFIED KEY SYNC ====================
  // Single global refresh: reloads the overview payload (KPI cards, key tables,
  // quota table, usage leaderboards, routing tables, pricing) and the ledger
  // blocks (trend, distribution, per-key breakdown) in one go.
  let globalRefreshInFlight = false;
  async function refreshAllData() {
    if (globalRefreshInFlight) return;
    const epoch = sessionEpoch;
    globalRefreshInFlight = true;
    const btn = document.getElementById("tabsRefreshBtn");
    if (btn) {
      btn.classList.add("is-loading");
      btn.disabled = true;
    }
    if (!overviewData) { showKpiSkeleton(); showKeysTabSkeleton(); showDashboardSkeleton(); }
    if (!overviewState.data) showOverviewSkeleton();
    try {
      await loadAdminOverview();
      if (!sessionCurrent(epoch)) return;
      if (currentAdminTab === "tab-audit" && activeManagementKey) await auditView.refresh();
      if (currentAdminTab === "tab-settings" && activeManagementKey) await settingsView.refresh();
      if (!sessionCurrent(epoch)) return;
      // Belt and braces: make sure the key/quota/leaderboard tables are painted even
      // if a late ledger refresh replaced them with placeholders.
      if (overviewData) {
        renderKeysCrudTable();
        renderQuotaTable();
        renderDashboardTables();
      }
    } catch (_) {
      // loadAdminOverview already surfaced the error via toast / lock screen.
    } finally {
      if (epoch !== sessionEpoch) return;
      globalRefreshInFlight = false;
      if (btn) {
        btn.classList.remove("is-loading");
        btn.disabled = false;
      }
    }
  }

  async function loadAdminOverview(candidateKey = "") {
    const ticket = requestGate.begin("overview");
    try {
      const keyToUse = cleanBearerToken(candidateKey || activeManagementKey || await discoverCPAManagementKey());
      if (!ticket.current()) return;
      if (!keyToUse) {
        lockAdminWorkspace();
        document.getElementById("authGateDesc").textContent = "未找到可共享的管理会话。请在管理中心保存登录，或输入 Management Key；未保存会话需要宿主提供安全认证桥。";
        return;
      }
      const data = await callManagementAPI(API_OVERVIEW, { method: "GET", signal: ticket.signal }, keyToUse);
      if (!ticket.current()) return;
      const wasAuthenticated = !!activeManagementKey;
      unlockAdminWorkspace(keyToUse);
      applyOverviewData(data);
      if (!wasAuthenticated && currentAdminTab === "tab-audit") await auditView.enter();
      if (!wasAuthenticated && currentAdminTab === "tab-settings") await settingsView.enter();
      if (!ticket.current()) return;
      const sync = data.host_sync;
      const healthMessage = overviewHealthMessage(data);
      setRefreshStatus(healthMessage, !!healthMessage);
      await loadOverviewLedger(!overviewState.data);
    } catch (err) {
      if (isCancelled(err) || !ticket.current()) return;
      if (activeManagementKey && overviewData) {
        renderDashboardKPIs(overviewData); renderKeysCrudTable(); renderQuotaTable(); renderDashboardTables();
        setRefreshStatus("刷新失败，显示上次成功数据：" + err.message, true);
        showToast("刷新失败，保留上次成功数据：" + err.message, true);
      } else { lockAdminWorkspace(err.message); }
      throw err;
    } finally { ticket.finish(); }
  }

  // refreshAfterMutation repaints from the overview a mutation endpoint returned
  // (top-level or under `overview`) instead of issuing another full reload. The
  // ledger blocks are re-queried only when the change can affect usage/cost.
  async function refreshAfterMutation(res, opts = {}) {
    if (!activeManagementKey) return;
    const payload = res && (res.overview || (res.summary && res.keys ? res : null));
    const sync = res && (res.host_sync || (payload && payload.host_sync));
    if (res && res.warning) showToast(String(res.warning), true);
    else if (sync && (sync.pending || sync.ok === false || sync.status === "pending" || sync.status === "failed")) showToast("规则已保存，宿主同步尚未完成，请稍后刷新确认", true);
    if (!applyOverviewData(payload)) {
      await loadAdminOverview();
      return;
    }
    const healthMessage = overviewHealthMessage(payload);
    setRefreshStatus(healthMessage, !!healthMessage);
    if (opts.ledger) await loadOverviewLedger(false);
  }
  // applyOverviewData stores a fresh overview payload and repaints every block that
  // is rendered from it. Mutation endpoints that already return the overview use
  // this directly instead of issuing another full reload.
  function applyOverviewData(data) {
    if (!KeyGuardClient.isOverview(data)) return false;
    overviewData = data;
    overviewIndex = KeyGuardState.indexOverview(data);
    usageGroupsCache = new WeakMap();
    renderDashboardKPIs(data);
    renderKeysCrudTable();
    renderQuotaTable();
    renderDashboardTables();
    initDefaultPolicySelectors();
    renderHostAuthTable();
    if (keyDialog.isOpen()) {
      renderCredCheckList("km");
      updateSelectorBadges("km");
    }
    renderPricingTab();
    return true;
  }

  function renderDashboardKPIs(data) {
    const s = data.summary || {};
    if (s.accounting_error) {
      for (const id of ["kpiTotalTokens", "kpiCacheTokens", "kpiTotalRequests", "kpiTotalCost"]) document.getElementById(id).textContent = "统计异常";
      for (const id of ["kpiTokenSub", "kpiCacheSub", "kpiReqSub", "kpiCostSub"]) document.getElementById(id).textContent = "汇总计数不可用：" + String(s.accounting_error);
      return;
    }
    document.getElementById("kpiTotalTokens").textContent = fmtTokenValue(s.total_tokens || 0);
    document.getElementById("kpiTokenSub").textContent =
      `输入: ${fmtTokenValue(s.input_tokens)} · 输出: ${fmtTokenValue(s.output_tokens)} · 推理: ${fmtTokenValue(s.reasoning_tokens)}`;
    const totalCache = (s.cache_read_tokens || 0) + (s.cache_write_tokens || 0);
    document.getElementById("kpiCacheTokens").textContent = fmtTokenValue(totalCache);
    document.getElementById("kpiCacheSub").textContent =
      `缓存读取: ${fmtTokenValue(s.cache_read_tokens)} · 缓存写入: ${fmtTokenValue(s.cache_write_tokens)}`;
    document.getElementById("kpiTotalRequests").textContent = fmtInt(s.total_requests || 0);
    const rate = s.total_requests > 0 ? ((s.success_requests / s.total_requests) * 100).toFixed(1) : "100.0";
    document.getElementById("kpiReqSub").textContent =
      `成功: ${fmtInt(s.success_requests)} · 失败: ${fmtInt(s.failed_requests)} (${rate}%)`;

    const totalCost = Number(s.total_cost_usd || 0);
    document.getElementById("kpiTotalCost").textContent = fmtMoneyNano(Math.round(totalCost * 1e9));
    const avgCost = (s.total_requests || 0) > 0 ? totalCost / s.total_requests : 0;
    document.getElementById("kpiCostSub").textContent =
      `平均每次请求 $${avgCost.toFixed(6)}`;
  }

  // ==================== PURE CHECKBOX SELECTORS (MODELS & CREDENTIALS) ====================
  function getAvailableModels() {
    const raw = (overviewData && overviewData.available_models) || [];
    return raw.filter(m => m && m.id && m.id.toLowerCase() !== "unknown" && !m.id.includes("*") && !m.id.includes("?") && !m.id.startsWith("!"));
  }

  function getAvailableCredentials() {
    return (overviewData && overviewData.auth_files) || [];
  }

  function loadSelectorFromRule(prefix, allowedModels, boundCreds) {
    const st = selectorState[prefix];
    const normModels = (allowedModels || []).map(s => s.trim()).filter(Boolean);
    const hasWildcardAll = normModels.length === 0 || normModels.includes("*");
    const validSelectedModels = normModels.filter(m => m !== "*");
    const isAllModels = hasWildcardAll;
    st.allModels = isAllModels;
    st.selectedModels = new Set(validSelectedModels);
    st.providerFilter = "all";

    const normCreds = (boundCreds || []).map(s => s.trim()).filter(Boolean);
    const isAllCreds = normCreds.length === 0;
    st.allCreds = isAllCreds;
    st.selectedCreds = new Set(normCreds);
    st.loadedCreds = new Set(normCreds);

    document.getElementById(prefix + "AllModelsCheck").checked = st.allModels;
    document.getElementById(prefix + "ModelPickerPanel").classList.toggle("hidden", st.allModels && !st.selectedModels.size);
    document.getElementById(prefix + "AllCredsCheck").checked = st.allCreds;
    document.getElementById(prefix + "CredPickerPanel").classList.toggle("hidden", st.allCreds);

    renderProviderPills(prefix);
    renderModelCheckList(prefix);
    renderCredCheckList(prefix);
    updateSelectorBadges(prefix);
  }

  function onToggleAllModels(prefix) {
    if (prefix === "dp") { if (defaultPolicySaveInFlight) return; markDefaultPolicyDirty(); }
    const st = selectorState[prefix];
    const checked = document.getElementById(prefix + "AllModelsCheck").checked;
    if (checked && st.selectedModels.size && !confirm("确定清除当前模型规则（包括排除规则），允许访问全部模型？")) {
      document.getElementById(prefix + "AllModelsCheck").checked = st.allModels; return;
    }
    st.allModels = checked;
    if (checked) st.selectedModels.clear();
    document.getElementById(prefix + "ModelPickerPanel").classList.toggle("hidden", st.allModels && !st.selectedModels.size);
    if (!st.allModels) {
      renderProviderPills(prefix);
      renderModelCheckList(prefix);
    }
    updateSelectorBadges(prefix);
  }

  function onToggleAllCreds(prefix) {
    if (prefix === "dp") { if (defaultPolicySaveInFlight) return; markDefaultPolicyDirty(); }
    const st = selectorState[prefix];
    const checked = document.getElementById(prefix + "AllCredsCheck").checked;
    if (checked && st.selectedCreds.size && !confirm("确定取消指定凭证限制？其它提供商、属性和严格绑定限制仍会保留。")) {
      document.getElementById(prefix + "AllCredsCheck").checked = st.allCreds; return;
    }
    st.allCreds = checked;
    document.getElementById(prefix + "CredPickerPanel").classList.toggle("hidden", st.allCreds);
    if (!st.allCreds) {
      renderCredCheckList(prefix);
    }
    updateSelectorBadges(prefix);
  }

  function updateSelectorBadges(prefix) {
    const st = selectorState[prefix];
    const mBadge = document.getElementById(prefix + "ModelCountBadge");
    if (st.allModels) {
      mBadge.textContent = st.selectedModels.size ? "全部模型，保留规则：" + Array.from(st.selectedModels).join("、") : "全部已有模型";
      mBadge.className = "tag ok";
    } else {
      mBadge.textContent = `已勾选 ${st.selectedModels.size} 项已有模型`;
      mBadge.className = st.selectedModels.size > 0 ? "tag plain" : "tag warn";
    }

    const cBadge = document.getElementById(prefix + "CredCountBadge");
    if (st.allCreds) {
      cBadge.textContent = "未限定具体凭证";
      cBadge.className = "tag ok";
    } else {
      cBadge.textContent = `已勾选 ${st.selectedCreds.size} 个凭证`;
      cBadge.className = st.selectedCreds.size > 0 ? "tag plain" : "tag warn";
    }
    const binding = ((prefix === "km" ? keyModalBaseline : defaultPolicyBaseline) || {}).upstream_binding;
    if (binding && (binding.providers?.length || Object.keys(binding.attributes || {}).length || binding.strict !== undefined)) {
      cBadge.textContent += " · 已有提供商 / 属性 / strict 设置保持不变";
    }
  }

  function renderProviderPills(prefix) {
    const st = selectorState[prefix];
    const models = getAvailableModels();
    const provSet = new Set(["all"]);
    models.forEach(m => { if (m.provider) provSet.add(m.provider); });
    const labels = {
      all: "全部",
      claude: "Claude",
      openai: "OpenAI / Codex",
      gemini: "Gemini",
      deepseek: "DeepSeek",
      qwen: "Qwen",
      xai: "xAI",
      zhipu: "GLM",
      kimi: "Kimi",
      other: "其它"
    };
    const container = document.getElementById(prefix + "ProviderPills");
    container.innerHTML = Array.from(provSet).map(p => {
      const active = st.providerFilter === p ? "active" : "";
      return `<button type="button" class="provider-pill ${active}" data-action="provider" data-prefix="${escapeHtml(prefix)}" data-value="${escapeHtml(p)}">${escapeHtml(labels[p] || p)}</button>`;
    }).join("");
  }

  function setProviderFilter(prefix, prov) {
    selectorState[prefix].providerFilter = prov;
    renderProviderPills(prefix);
    renderModelCheckList(prefix);
  }

  function getFilteredModelsForSelector(prefix) {
    const st = selectorState[prefix];
    const q = (document.getElementById(prefix + "ModelSearch")?.value || "").toLowerCase().trim();
    const baseModels = getAvailableModels().slice();
    const knownIDs = new Set(baseModels.map(m => m.id));
    // Include any custom or explicitly selected models that are not yet in CPA's model catalog
    st.selectedModels.forEach(m => {
      if (!knownIDs.has(m) && m !== "*") {
        baseModels.unshift({ id: m, provider: "custom", sources: [] });
      }
    });

    return baseModels.filter(m => {
      if (st.providerFilter !== "all" && m.provider !== st.providerFilter) return false;
      if (q && !m.id.toLowerCase().includes(q) && !(m.provider || "").toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function renderModelCheckList(prefix) {
    const st = selectorState[prefix];
    const list = getFilteredModelsForSelector(prefix);
    const container = document.getElementById(prefix + "ModelCheckList");
    if (list.length === 0) {
      container.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:14px;color:var(--text-tertiary)">当前暂无匹配的已有模型</div>`;
      return;
    }
    container.innerHTML = list.map(m => {
      const checked = st.selectedModels.has(m.id);
      return `<label class="check-item ${checked ? "checked" : ""}">
        <input type="checkbox" ${checked ? "checked" : ""} data-change="modelCheck" data-prefix="${escapeHtml(prefix)}" data-value="${escapeHtml(m.id)}">
        <div class="check-item-body">
          <div class="check-item-title mono">${escapeHtml(m.id)}</div>
          <div class="check-item-sub">${escapeHtml(m.provider || "model")}</div>
        </div>
      </label>`;
    }).join("");
  }

  function toggleModelCheckItem(prefix, modelId, isChecked) {
    if (prefix === "dp") { if (defaultPolicySaveInFlight) return; markDefaultPolicyDirty(); }
    const st = selectorState[prefix];
    if (isChecked) {
      st.selectedModels.add(modelId);
    } else {
      st.selectedModels.delete(modelId);
    }
    renderModelCheckList(prefix);
    updateSelectorBadges(prefix);
  }

  function batchCheckModels(prefix, checkAll) {
    if (prefix === "dp") { if (defaultPolicySaveInFlight) return; markDefaultPolicyDirty(); }
    const st = selectorState[prefix];
    st.allModels = false;
    document.getElementById(prefix + "AllModelsCheck").checked = false;
    document.getElementById(prefix + "ModelPickerPanel").classList.remove("hidden");

    const visible = getFilteredModelsForSelector(prefix);
    if (checkAll) {
      visible.forEach(m => st.selectedModels.add(m.id));
    } else {
      visible.forEach(m => st.selectedModels.delete(m.id));
    }
    renderModelCheckList(prefix);
    updateSelectorBadges(prefix);
  }

  function credentialIdentities(file) {
    return [file.name, file.id, file.auth_index].filter(Boolean);
  }

  function credentialIsSelected(prefix, file) {
    return credentialIdentities(file).some(id => selectorState[prefix].selectedCreds.has(id));
  }

  function credentialCanBind(file) {
    if (!file || file.disabled || file.unavailable) return false;
    const status = String(file.status || "").toLowerCase();
    return !["disabled", "error", "unknown", "unavailable", "removed", "missing"].includes(status);
  }

  function credentialPickerStatus(file) {
    if (file.status === "missing") return "未登记 / 已删除";
    if (file.disabled || file.status === "disabled") return "已禁用";
    if (file.unavailable || file.status === "error" || file.status === "unavailable") return "暂不可用";
    if (file.status === "unknown") return "状态未确认";
    return file.status || "active";
  }

  function getFilteredCredsForSelector(prefix) {
    const st = selectorState[prefix];
    const q = (document.getElementById(prefix + "CredSearch")?.value || "").toLowerCase().trim();
    const files = getAvailableCredentials();
    const knownVals = new Set(files.flatMap(credentialIdentities));
    const merged = files.slice();
    st.selectedCreds.forEach(c => {
      if (!knownVals.has(c)) {
        // Preserve existing restrictions, but never invent an active credential.
        merged.unshift({ id: c, name: c, provider: "bound", status: "missing" });
      }
    });

    return merged.filter(af => {
      if (!credentialCanBind(af) && !credentialIsSelected(prefix, af)) return false;
      if (!q) return true;
      const hay = [af.name, af.id, af.provider, af.type, af.email, af.account, af.label].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    });
  }

  function renderCredCheckList(prefix) {
    const st = selectorState[prefix];
    const list = getFilteredCredsForSelector(prefix);
    const container = document.getElementById(prefix + "CredCheckList");
    if (list.length === 0) {
      container.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:14px;color:var(--text-tertiary)">宿主当前未加载匹配的账号凭证</div>`;
      return;
    }
    container.innerHTML = list.map(af => {
      const val = af.name || af.id || af.auth_index;
      const checked = credentialIsSelected(prefix, af);
      const statusOk = credentialCanBind(af);
      const sub = [af.provider || af.type, af.email || af.account || af.label,
        !statusOk ? "所选凭证当前不可用；可取消勾选移除，不会自动放宽权限" : ""].filter(Boolean).join(" · ");
      const disabled = (!statusOk && !checked) || (prefix === "dp" && defaultPolicySaveInFlight);
      return `<label class="check-item ${checked ? "checked" : ""}">
        <input type="checkbox" ${checked ? "checked" : ""} ${disabled ? "disabled" : ""} data-change="credCheck" data-prefix="${escapeHtml(prefix)}" data-value="${escapeHtml(val)}">
        <div class="check-item-body">
          <div class="check-item-title mono">${escapeHtml(val)}</div>
          <div class="check-item-sub">${escapeHtml(sub || "可用凭证")}</div>
        </div>
        <span class="tag ${statusOk ? "ok" : "bad"}">${escapeHtml(credentialPickerStatus(af))}</span>
      </label>`;
    }).join("");
  }

  function toggleCredCheckItem(prefix, credVal, isChecked) {
    if (prefix === "dp") { if (defaultPolicySaveInFlight) return; markDefaultPolicyDirty(); }
    const st = selectorState[prefix];
    const file = getAvailableCredentials().find(f => credentialIdentities(f).includes(credVal));
    if (isChecked) {
      if (!credentialCanBind(file)) { renderCredCheckList(prefix); return; }
      st.selectedCreds.add(credVal);
    } else {
      for (const id of file ? credentialIdentities(file) : [credVal]) st.selectedCreds.delete(id);
    }
    renderCredCheckList(prefix);
    updateSelectorBadges(prefix);
  }

  function batchCheckCreds(prefix, checkAll) {
    if (prefix === "dp") { if (defaultPolicySaveInFlight) return; markDefaultPolicyDirty(); }
    const st = selectorState[prefix];
    st.allCreds = false;
    document.getElementById(prefix + "AllCredsCheck").checked = false;
    document.getElementById(prefix + "CredPickerPanel").classList.remove("hidden");

    const visible = getFilteredCredsForSelector(prefix);
    if (checkAll) {
      visible.filter(credentialCanBind).forEach(af => {
        if (!credentialIsSelected(prefix, af)) st.selectedCreds.add(af.name || af.id || af.auth_index);
      });
    } else {
      visible.forEach(af => credentialIdentities(af).forEach(id => st.selectedCreds.delete(id)));
    }
    renderCredCheckList(prefix);
    updateSelectorBadges(prefix);
  }

  function validateCredentialDraft(prefix) {
    const st = selectorState[prefix];
    if (st.allCreds) return true;
    const invalidNew = Array.from(st.selectedCreds).some(id => {
      if (st.loadedCreds.has(id)) return false;
      const file = getAvailableCredentials().find(f => credentialIdentities(f).includes(id));
      return !credentialCanBind(file);
    });
    if (!invalidNew) return true;
    showToast("新勾选的凭证已失效或状态未确认，请取消该项或重新选择后再保存", true);
    const input = document.querySelectorAll("#" + prefix + "CredCheckList input")[0];
    if (input) input.focus();
    return false;
  }

  function editedBinding(prefix, baseline, credentials) {
    const binding = cloneRule(baseline && baseline.upstream_binding);
    const loaded = selectorState[prefix].loadedCreds;
    const unchanged = credentials.length === loaded.size && credentials.every(id => loaded.has(id));
    // Preserve legacy auth_ids exactly unless the user edits credential selection.
    if (!unchanged) { delete binding.auth_ids; binding.credentials = credentials; }
    const strategy = document.getElementById(prefix + "BindStrategy").value;
    if (strategy !== (binding.strategy || "round-robin")) binding.strategy = strategy;
    return binding;
  }

  function exportSelectorValues(prefix) {
    const st = selectorState[prefix];
    const allowedModels = st.allModels ? ["*", ...st.selectedModels] : Array.from(st.selectedModels);
    const credentials = st.allCreds ? [] : Array.from(st.selectedCreds);
    return { allowedModels, credentials };
  }

  // ==================== TAB 1: UNIFIED API KEYS CRUD ====================

  // Provider detection for the coloured dot / subtle border of a model pill.
  function modelProviderKey(name) {
    const n = String(name || "").toLowerCase();
    if (n.includes("claude")) return "claude";
    if (n.includes("gemini")) return "gemini";
    if (n.includes("gpt") || n.startsWith("o1") || n.startsWith("o3") || n.includes("openai")) return "openai";
    if (n.includes("deepseek")) return "deepseek";
    return "other";
  }

  // Splits a model id into a high-contrast core (first two segments) and a muted
  // version/feature tail, e.g. claude-opus-4-6-thinking -> "claude-opus" + "-4-6-thinking".
  function splitModelName(name) {
    const raw = String(name || "");
    const parts = raw.split("-").filter(p => p !== "");
    if (parts.length <= 2) return { core: raw, tail: "" };
    const core = parts.slice(0, 2).join("-");
    return { core: core, tail: raw.slice(core.length) };
  }

  function modelPillHtml(name) {
    const provider = modelProviderKey(name);
    const split = splitModelName(name);
    return `<span class="model-pill prov-${provider}" title="${escapeHtml(name)}">` +
      `<span class="model-dot dot-${provider}"></span>` +
      `<span class="name mono"><span class="model-core">${escapeHtml(split.core)}</span>` +
      `<span class="model-tail">${escapeHtml(split.tail)}</span></span></span>`;
  }

  // Renders the whitelist cell: always one line, at most two pills plus a +N badge.
  function modelWhitelistCellHtml(apiKey, isAllModels, models) {
    if (isAllModels || models.length === 0) {
      return `<span class="tag ok">全部已有模型</span>`;
    }
    const shown = models.slice(0, 2).map(modelPillHtml).join("");
    const hidden = models.length - 2;
    const moreBtn = hidden > 0
      ? `<button type="button" class="model-more" data-key="${escapeHtml(apiKey)}" data-kind="models" data-action="entityPopover" title="查看全部 ${models.length} 个模型">+${hidden}</button>`
      : "";
    return `<div class="model-cell">${shown}${moreBtn}</div>`;
  }

  // ---- Bound credentials: aggregated channel badges + grouped popover ----
  // Channels are exactly the ones CPA can log into (Antigravity, Claude, Codex,
  // Kimi, Muse, xAI, Devin, Vertex AI) plus the configurable OpenAI-compatible
  // provider. A badge counts credentials per channel; the AI vendor is a separate
  // attribute shown inside the popover.
  const CRED_CHANNELS = [
    { test: /antigravity/, key: "antigravity", label: "Antigravity", vendor: "Gemini", dot: "gemini" },
    { test: /vertex/, key: "vertex", label: "Vertex AI", vendor: "Gemini", dot: "gemini" },
    { test: /claude/, key: "claude", label: "Claude", vendor: "Anthropic", dot: "claude" },
    { test: /codex/, key: "codex", label: "Codex", vendor: "OpenAI", dot: "openai" },
    { test: /kimi|moonshot/, key: "kimi", label: "Kimi", vendor: "Moonshot", dot: "kimi" },
    { test: /muse/, key: "muse", label: "Muse", vendor: "Meta", dot: "meta" },
    { test: /xai|grok/, key: "xai", label: "xAI", vendor: "xAI", dot: "xai" },
    { test: /devin/, key: "devin", label: "Devin", vendor: "Cognition", dot: "devin" }
  ];

  function compatChannel(subName) {
    // Every openai-compatible-* provider shares one badge; the configured name is
    // kept as a sub-channel so the popover can still separate them.
    return { key: "openai-compat", label: "OpenAI 兼容", vendor: "自定义", dot: "compat", sub: subName || "" };
  }

  function credChannelOf(name) {
    const file = authFileFor(name);
    const typeRaw = String((file && (file.type || file.provider)) || "").trim();
    const raw = String(name || "").trim();

    const compatFromType = /^openai-compatible-(.+)$/i.exec(typeRaw);
    if (compatFromType) return compatChannel(compatFromType[1].trim());
    if (/^openai-compatibility:/i.test(raw)) {
      const parts = raw.split(":");
      return compatChannel((parts[1] || "").trim());
    }

    const probe = (typeRaw || raw).toLowerCase();
    const def = CRED_CHANNELS.find(channel => channel.test.test(probe));
    if (def) return { key: def.key, label: def.label, vendor: def.vendor, dot: def.dot, sub: "" };

    const prefix = raw.split(/[-:]/)[0];
    return { key: "other:" + prefix.toLowerCase(), label: prefix || "其他", vendor: "未知", dot: "other", sub: "" };
  }

  function credProviderKey(name) {
    return credChannelOf(name).dot;
  }

  function splitCredentialName(name) {
    const raw = String(name || "");
    const colon = raw.indexOf(":");
    if (colon > 0) return { core: raw.slice(0, colon), tail: raw.slice(colon) };
    const dash = raw.indexOf("-");
    if (dash > 0) return { core: raw.slice(0, dash), tail: raw.slice(dash) };
    return { core: raw, tail: "" };
  }

  // Masks the account identity while keeping the channel prefix readable:
  //   antigravity-lyj109202@gmail.com.json -> antigravity-ly***02@gmail.com.json
  //   openai-compatibility:777-1:5df0f0b3d3 -> openai-compatibility:777-…f0f0b3d3
  function maskCredentialName(raw) {
    let text = String(raw || "");
    const colon = text.indexOf(":");
    const dash = text.indexOf("-");
    const cut = colon > 0 ? colon : (dash > 0 ? dash : -1);
    let prefix = "";
    if (cut > 0) {
      prefix = text.slice(0, cut + 1);
      text = text.slice(cut + 1);
    }
    const at = text.indexOf("@");
    if (at > 2) {
      const local = text.slice(0, at);
      const rest = text.slice(at);
      const head = local.slice(0, Math.min(2, local.length));
      const tail = local.slice(-2);
      return prefix + head + "***" + tail + rest;
    }
    if (text.length > 16) {
      return prefix + text.slice(0, 4) + "…" + text.slice(-6);
    }
    return prefix + text;
  }

  // auth_files carries the live status of every credential the host knows about.
  function authFileFor(credentialID) {
    const files = ((overviewData && overviewData.auth_files) || []);
    const target = String(credentialID || "").toLowerCase();
    return files.find(f => {
      const candidates = [f.id, f.name, f.auth_index, f.label, f.email, f.account];
      return candidates.some(c => String(c || "").toLowerCase() === target);
    }) || null;
  }

  function credentialStatusOf(credentialID) {
    const file = authFileFor(credentialID);
    if (!file || file.status === "missing" || file.status === "removed") return { key: "unknown", label: "未登记 / 已删除" };
    if (file.status === "unknown") return { key: "unknown", label: "状态未确认" };
    if (file.unavailable || file.status === "error") {
      const reason = String(file.status_message || "").toLowerCase();
      if (reason.includes("quota") || reason.includes("rate")) return { key: "limited", label: "限流中" };
      return { key: "error", label: "不可用" };
    }
    if (file.status === "disabled" || file.disabled) return { key: "disabled", label: "已禁用" };
    return { key: "active", label: "正常" };
  }

  function credPillHtml(name) {
    const channel = credChannelOf(name);
    const split = splitCredentialName(name);
    return `<span class="model-pill cred prov-${channel.dot}" title="${escapeHtml(name)}">` +
      `<span class="model-dot dot-${channel.dot}"></span>` +
      `<span class="name mono"><span class="model-core">${escapeHtml(split.core)}</span>` +
      `<span class="model-tail">${escapeHtml(split.tail)}</span></span></span>`;
  }

  // Groups credential ids by channel, largest group first. Rows keep their
  // sub-channel (the configured name behind an OpenAI-compatible provider).
  function credentialGroups(creds) {
    const map = new Map();
    for (const id of creds) {
      const channel = credChannelOf(id);
      if (!map.has(channel.key)) {
        map.set(channel.key, { key: channel.key, label: channel.label, vendor: channel.vendor, dot: channel.dot, items: [] });
      }
      map.get(channel.key).items.push({ id: id, sub: channel.sub });
    }
    const groups = Array.from(map.values());
    for (const group of groups) group.items.sort((a, b) => a.id.localeCompare(b.id));
    groups.sort((a, b) => b.items.length - a.items.length || a.label.localeCompare(b.label));
    return groups;
  }

  function credentialCellHtml(apiKey, strategyLabel, creds) {
    if (!creds.length) {
      return `<span class="tag ok">全部可用凭证</span>`;
    }
    const strategy = strategyLabel
      ? `<span class="tag warn" style="font-size:11px;padding:1px 7px">${escapeHtml(strategyLabel)}</span>`
      : "";

    // A single credential is shown directly, truncated at 160px.
    if (creds.length === 1) {
      return `<div class="model-cell">${strategy}<span class="single-cred">${credPillHtml(creds[0])}</span></div>`;
    }

    // Two or more collapse into one badge per channel.
    const groups = credentialGroups(creds);
    const shown = groups.slice(0, 3).map(group => {
      const title = `${group.label}: ${group.items.length} 个凭证 · 厂商 ${group.vendor}`;
      return `<button type="button" class="cred-badge prov-${group.dot}" data-key="${escapeHtml(apiKey)}" data-kind="creds" ` +
        `data-action="entityPopover" title="${escapeHtml(title)}">` +
        `<span class="model-dot dot-${group.dot}"></span>` +
        `<span class="cred-badge-label">${escapeHtml(group.label)}</span>` +
        `<span class="cred-badge-count mono">${group.items.length}</span></button>`;
    }).join("");
    const hiddenFamilies = groups.length - 3;
    const moreBtn = hiddenFamilies > 0
      ? `<button type="button" class="model-more" data-key="${escapeHtml(apiKey)}" data-kind="creds" ` +
        `data-action="entityPopover" title="还有 ${hiddenFamilies} 个渠道，共 ${creds.length} 个凭证">+${hiddenFamilies}</button>`
      : "";
    return `<div class="model-cell">${strategy}${shown}${moreBtn}</div>`;
  }

  // ---- Shared popover (rendered into <body> so table overflow never clips it) ----
  let popoverState = { apiKey: "", kind: "models", items: [], anchor: null };

  function allowedModelsFor(apiKey) {
    const rule = overviewIndex.rules.get(apiKey);
    const raw = (rule && rule.allowed_models && rule.allowed_models.length) ? rule.allowed_models : [];
    return Array.from(new Set(raw.filter(m => m && m !== "*")));
  }

  function boundCredentialsFor(apiKey) {
    const rule = overviewIndex.rules.get(apiKey);
    const ub = (rule && rule.upstream_binding) || {};
    return Array.from(new Set([].concat(ub.auth_ids || [], ub.credentials || []).filter(Boolean)));
  }

  function openEntityPopover(ev, trigger) {
    ev.preventDefault();
    ev.stopPropagation();
    const apiKey = trigger.getAttribute("data-key") || "";
    const kind = trigger.getAttribute("data-kind") || "models";
    const items = kind === "creds" ? boundCredentialsFor(apiKey) : allowedModelsFor(apiKey);
    const popover = document.getElementById("modelPopover");
    if (!popover) return;

    // Toggle off when the same trigger is clicked again.
    if (popover.classList.contains("open") && popoverState.apiKey === apiKey &&
        popoverState.kind === kind && popoverState.anchor === trigger) {
      closeModelPopover();
      return;
    }
    popoverState = { apiKey: apiKey, kind: kind, items: items, anchor: trigger };
    renderEntityPopover("");
    popover.classList.add("open");

    const rect = trigger.getBoundingClientRect();
    const width = popover.offsetWidth || 328;
    const height = popover.offsetHeight || 260;
    let left = rect.left + rect.width / 2 - width / 2;
    left = Math.max(8, Math.min(left, window.innerWidth - width - 8));
    let top = rect.bottom + 6;
    if (top + height > window.innerHeight - 8) {
      top = Math.max(8, rect.top - height - 6);
    }
    popover.style.left = left + "px";
    popover.style.top = top + "px";

    const input = document.getElementById("modelPopoverSearch");
    if (input) input.focus();
  }

  function renderEntityPopover(query, keepFocus) {
    const popover = document.getElementById("modelPopover");
    if (!popover) return;
    const isCreds = popoverState.kind === "creds";
    const q = String(query || "").trim().toLowerCase();
    const all = popoverState.items;

    let listHtml = "";
    let matchedCount = 0;
    if (isCreds) {
      // Grouped by channel; each row shows the sub-channel, masked identity and status.
      const groups = credentialGroups(all)
        .map(group => ({
          ...group,
          items: q ? group.items.filter(item => item.id.toLowerCase().includes(q)) : group.items
        }))
        .filter(group => group.items.length > 0);
      matchedCount = groups.reduce((sum, group) => sum + group.items.length, 0);
      listHtml = groups.map(group => {
        const rows = group.items.map(item => {
          const status = credentialStatusOf(item.id);
          const subTag = item.sub
            ? `<span class="cred-subchannel">${escapeHtml(item.sub)}</span>`
            : "";
          return `<div class="cred-row">` +
            `<span class="model-dot dot-${group.dot}"></span>` +
            subTag +
            `<span class="cred-row-name mono" title="${escapeHtml(item.id)}">${escapeHtml(maskCredentialName(item.id))}</span>` +
            `<span class="cred-status cred-status-${status.key}">${escapeHtml(status.label)}</span>` +
            `</div>`;
        }).join("");
        return `<div class="cred-group">` +
          `<div class="cred-group-title"><span class="model-dot dot-${group.dot}"></span>${escapeHtml(group.label)}` +
          `<span class="cred-channel-provider">厂商: ${escapeHtml(group.vendor)}</span>` +
          `<span class="cred-group-count mono">${group.items.length}</span></div>` +
          rows + `</div>`;
      }).join("");
    } else {
      const matched = q ? all.filter(m => m.toLowerCase().includes(q)) : all;
      matchedCount = matched.length;
      listHtml = matched.map(m => {
        const provider = modelProviderKey(m);
        return `<div class="model-popover-item"><span class="model-dot dot-${provider}"></span><span>${escapeHtml(m)}</span></div>`;
      }).join("");
    }

    const headLabel = isCreds ? "已绑定" : "共允许";
    const unit = isCreds ? "个账号凭证" : "个模型";
    const placeholder = isCreds ? "搜索凭证名称/ID..." : "搜索模型名...";
    const emptyLabel = isCreds ? "没有匹配的凭证" : "没有匹配的模型";

    popover.innerHTML = `
      <div class="model-popover-head">
        <span>${headLabel} <span class="mono" style="color:var(--text-primary)">${all.length}</span> ${unit}${q ? `（匹配 ${matchedCount}）` : ""}</span>
        <button type="button" class="model-popover-close" data-action="closePopover" title="关闭">×</button>
      </div>
      <input type="text" class="model-popover-search" id="modelPopoverSearch" placeholder="${placeholder}" value="${escapeHtml(query || "")}" data-input="popoverSearch">
      <div class="model-popover-list">${listHtml || `<div class="model-popover-empty">${emptyLabel}</div>`}</div>
      <div class="model-popover-foot">
        <button type="button" class="btn btn-sm" data-action="copyPopover">复制全部</button>
        <button type="button" class="btn btn-sm btn-primary" data-action="editPopover" data-value="${isCreds ? "creds" : "models"}">${isCreds ? "管理绑定凭证" : "编辑规则"}</button>
      </div>`;

    // Re-rendering replaces the input, so restore focus and caret while typing.
    if (keepFocus) {
      const input = document.getElementById("modelPopoverSearch");
      if (input) {
        input.focus();
        const end = input.value.length;
        input.setSelectionRange(end, end);
      }
    }
  }

  function closeModelPopover() {
    const popover = document.getElementById("modelPopover");
    if (popover) popover.classList.remove("open");
    popoverState = { apiKey: "", kind: "models", items: [], anchor: null };
  }

  function copyPopoverItems() {
    if (!popoverState.items.length) return;
    copyText(popoverState.items.join("\n"));
  }

  function editFromPopover(kind) {
    const apiKey = popoverState.apiKey;
    closeModelPopover();
    if (!apiKey) return;
    // Both footers open the same rule editor; the credential footer can preselect
    // the credential section through the second argument.
    openKeyModalByKey(apiKey, kind || "");
  }

  document.addEventListener("click", event => { if (!event.target.closest("[data-action], #modelPopover")) closeModelPopover(); });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModelPopover();
  });
  window.addEventListener("resize", () => closeModelPopover());

  function renderKeysCrudTable() {
    if (!overviewData) return;
    const keys = overviewData.keys || [];
    const snapKeys = (overviewData.usage && overviewData.usage.keys) || {};
    const q = (document.getElementById("crudKeySearch").value || "").toLowerCase().trim();

    const filtered = keys.filter(kr => {
      if (!q) return true;
      return (kr.api_key || "").toLowerCase().includes(q) || (kr.name || "").toLowerCase().includes(q);
    });

    const tbody = document.getElementById("crudKeysTableBody");
    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="cell-empty">暂无 API Key</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map((kr) => {
      const k = kr.api_key;
      const ks = snapKeys[k] || {};
      const enabled = kr.enabled !== false;
      const dispKey = maskKeyStr(k);
      const maxC = kr.max_concurrency || 0;

      const rawModels = (kr.allowed_models && kr.allowed_models.length) ? kr.allowed_models : ["*"];
      const isAllModels = rawModels.length === 0 || rawModels.includes("*");
      const allowedList = Array.from(new Set(rawModels.filter(m => m && m !== "*")));
      let modelsHtml = modelWhitelistCellHtml(k, isAllModels, allowedList);

      const ub = kr.upstream_binding || {};
      const creds = Array.from(new Set([].concat(ub.auth_ids || [], ub.credentials || [])));
      const strategyLabelMap = {
        "round-robin": "轮询",
        "fill-first": "优先级",
        "strict": "严格"
      };
      const dispStrat = strategyLabelMap[ub.strategy || "round-robin"] || (ub.strategy || "");
      const bindHtml = credentialCellHtml(k, creds.length > 0 ? dispStrat : "", creds);

      return `<tr class="key-row" data-key="${escapeHtml(k)}" draggable="true">
        <td class="drag-cell" title="拖动调整顺序">⠿</td>
        <td class="cell-nowrap">
          <span class="tag ${enabled ? "ok" : "bad"}" style="cursor:pointer" data-action="toggleKey" data-value="${escapeHtml(k)}" title="点击切换启用/禁用">
            ${enabled ? "启用" : "禁用"}
          </span>
        </td>
        <td class="cell-nowrap">
          <div class="key-cell">
            <span class="key-code">${escapeHtml(dispKey)}</span>
          </div>
        </td>
        <td class="cell-nowrap" style="font-weight:600;max-width:160px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(kr.name || "-")}</td>
        <td class="cell-nowrap mono">${maxC > 0 ? maxC : "不限"}</td>
        <td class="cell-nowrap mono">${fmtInt(ks.total_requests)} <span class="txt-muted">(${fmtInt(ks.success_requests)}/${fmtInt(ks.failed_requests)})</span></td>
        <td class="cell-nowrap">
          <span class="token-val">${fmtTokenValue(ks.total_tokens)}</span>
          <span class="mono" style="font-size:12px;color:var(--text-secondary)"> (${fmtTokenValue(ks.input_tokens)} / ${fmtTokenValue(ks.output_tokens)})</span>
        </td>
        <td class="col-models">${modelsHtml}</td>
        <td>${bindHtml}</td>
      </tr>`;
    }).join("");

    // A re-render invalidates the anchor of an open whitelist popover.
    closeModelPopover();
  }

  async function copyText(txt) {
    const epoch = sessionEpoch;
    try { await navigator.clipboard.writeText(txt); if (sessionCurrent(epoch)) showToast("已复制到剪贴板"); }
    catch (_) { if (sessionCurrent(epoch)) showToast("无法访问剪贴板，请允许浏览器剪贴板权限或手动复制", true); }
  }

  // ==================== API KEY DRAG & DROP ORDERING ====================
  let dragSrcKey = null;
  let dragOverKey = null;

  function onKeyRowDragStart(ev, key) {
    dragSrcKey = key;
    dragOverKey = null;
    if (ev.dataTransfer) {
      ev.dataTransfer.effectAllowed = "move";
      try { ev.dataTransfer.setData("text/plain", key); } catch (_) {}
    }
    const row = ev.target.closest && ev.target.closest(".key-row[data-key]");
    if (row) row.classList.add("dragging");
  }

  function onKeyRowDragOver(ev, key) {
    if (!dragSrcKey) return;
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = "move";
    if (dragOverKey === key) return;
    dragOverKey = key;
    document.querySelectorAll("#crudKeysTableBody tr.key-row").forEach(tr => {
      tr.classList.toggle("drag-over", tr.getAttribute("data-key") === key && key !== dragSrcKey);
    });
  }

  function onKeyRowDragEnd(ev) {
    dragSrcKey = null;
    dragOverKey = null;
    document.querySelectorAll("#crudKeysTableBody tr.key-row").forEach(tr => {
      tr.classList.remove("dragging", "drag-over");
    });
  }

  async function onKeyRowDrop(ev, targetKey) {
    const epoch = sessionEpoch;
    ev.preventDefault();
    const srcKey = dragSrcKey;
    onKeyRowDragEnd(ev);
    if (!srcKey || srcKey === targetKey) return;

    const current = ((overviewData && overviewData.keys) || []).map(k => k.api_key);
    const from = current.indexOf(srcKey);
    const to = current.indexOf(targetKey);
    if (from < 0 || to < 0) return;

    const next = current.slice();
    next.splice(from, 1);
    next.splice(to, 0, srcKey);

    // Do not mutate the committed snapshot until the server confirms the order.
    try {
      const res = await callManagementAPI(API_KEYS_REORDER, {
        method: "POST",
        body: JSON.stringify({ keys: next })
      });
      if (!sessionCurrent(epoch)) return;
      showToast("API Key 顺序已保存");
      await refreshAfterMutation(res);
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast(err.message, true);
      await loadAdminOverview();
    }
  }

  function generateRandomSkKey() {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let out = "sk-cpa-";
    const arr = new Uint32Array(28);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < arr.length; i++) {
      out += chars[arr[i] % chars.length];
    }
    document.getElementById("kmApiKey").value = out;
  }

  function openKeyModalByKey(apiKey, focusSection) {
    const found = overviewIndex.rules.get(apiKey);
    openKeyModal(found || null);
    if (focusSection === "creds") {
      // Scroll the credential picker into view so "管理绑定凭证" lands on the right block.
      const panel = document.getElementById("kmCredPickerPanel");
      if (panel && panel.scrollIntoView) panel.scrollIntoView({ block: "center" });
    }
  }

  function openKeyModal(rule) {
    keyModalEpoch++;
    keyModalRevision = overviewData && overviewData.rules_revision;
    keyModalBaseline = cloneRule(rule);
    rule = rule ? keyModalBaseline : null;
    document.getElementById("keyModalTitle").textContent = rule ? "编辑 API Key 管控规则" : "新建 API Key";
    document.getElementById("kmOriginalApiKey").value = rule ? rule.api_key : "";
    document.getElementById("kmApiKey").value = rule ? rule.api_key : "";
    document.getElementById("kmName").value = (rule && rule.name) || "";
    document.getElementById("kmMaxConcurrency").value = (rule && rule.max_concurrency) || 0;
    document.getElementById("kmQuotaLimit").value = (rule && rule.quota_limit_usd) || 0;
    document.getElementById("kmEnabled").value = (rule && rule.enabled === false) ? "false" : "true";

    const ub = (rule && rule.upstream_binding) || {};
    document.getElementById("kmBindStrategy").value = ub.strategy || "round-robin";
    const boundCreds = Array.from(new Set([].concat(ub.auth_ids || [], ub.credentials || [])));
    const allowedModels = (rule && rule.allowed_models && rule.allowed_models.length) ? rule.allowed_models : ["*"];

    loadSelectorFromRule("km", allowedModels, boundCreds);
    document.getElementById("keyModalMessage").textContent = "";
    document.querySelectorAll("#keyModal .modal-footer button").forEach(button => { button.disabled = false; });
    keyDialog.show();
  }

  function closeKeyModal() {
    return keyDialog.close();
  }

  async function submitKeyModal() {
    const epoch = sessionEpoch, modalOwner = keyModalEpoch;
    const origKey = document.getElementById("kmOriginalApiKey").value.trim();
    const apiKey = document.getElementById("kmApiKey").value.trim();
    if (!apiKey) {
      showToast("API Key 不能为空", true);
      return;
    }

    if (!validateCredentialDraft("km")) return;
    const { allowedModels, credentials } = exportSelectorValues("km");
    if (!selectorState.km.allModels && allowedModels.length === 0) {
      showToast("请至少勾选一个允许访问的模型，或勾选「允许访问全部模型」", true);
      return;
    }
    if (!selectorState.km.allCreds && credentials.length === 0) {
      showToast("请至少勾选一个绑定的账号凭证，或勾选「不限定具体凭证」", true);
      return;
    }

    const payload = {
      ...cloneRule(keyModalBaseline),
      api_key: apiKey,
      name: document.getElementById("kmName").value.trim(),
      enabled: document.getElementById("kmEnabled").value === "true",
      max_concurrency: parseInt(document.getElementById("kmMaxConcurrency").value || "0", 10) || 0,
      quota_limit_usd: Math.max(0, Number(document.getElementById("kmQuotaLimit").value || "0") || 0),
      allowed_models: allowedModels,
      upstream_binding: editedBinding("km", keyModalBaseline, credentials)
    };

    try {
      const res = await callManagementAPI(API_KEYS_CRUD, {
        method: "POST", headers: revisionHeaders(keyModalRevision), body: JSON.stringify(Object.assign({ orig_key: origKey }, payload))
      });
      if (!sessionCurrent(epoch) || modalOwner !== keyModalEpoch) return;
      closeKeyModal();
      showToast("API Key 与管控规则已保存");
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err) || modalOwner !== keyModalEpoch) return;
      showToast(err.message, true);
    }
  }

  async function quickToggleKeyEnabled(apiKey) {
    const epoch = sessionEpoch;
    const kr = overviewIndex.rules.get(apiKey);
    if (!kr) return;
    const next = kr.enabled === false ? true : false;
    const payload = Object.assign({}, kr, { enabled: next });
    try {
      const res = await callManagementAPI(API_KEYS_CRUD, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      if (!sessionCurrent(epoch)) return;
      showToast(`已${next ? "启用" : "禁用"} Key: ${kr.name || maskKeyStr(kr.api_key)}`);
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast(err.message, true);
    }
  }

  async function deleteKeyRule(apiKey) {
    const epoch = sessionEpoch;
    if (!confirm(`确定要删除 API Key [${maskKeyStr(apiKey)}] 吗？`)) return;
    try {
      const res = await callManagementAPI(API_KEYS_CRUD, {
        method: "DELETE", body: JSON.stringify({ api_key: apiKey })
      });
      if (!sessionCurrent(epoch)) return;
      showToast("API Key 删除规则已保存");
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast(err.message, true);
    }
  }

  async function resetUsageStats(apiKey) {
    const epoch = sessionEpoch;
    const desc = apiKey ? `Key [${maskKeyStr(apiKey)}]` : "所有 API Key";
    if (!confirm(`确定要清零 ${desc} 的累计 Token 用量统计吗？`)) return;
    try {
      const res = await callManagementAPI(API_USAGE_RESET, {
        method: "POST",
        body: JSON.stringify({ api_key: apiKey })
      });
      if (!sessionCurrent(epoch)) return;
      showToast(`已清零 ${desc} 的 Token 用量统计`);
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast(err.message, true);
    }
  }

  // ==================== API KEY QUOTA TABLE ====================
  const API_QUOTA_RESET = "/v0/management/key-guard/keys/quota/reset";

  function quotaUsageOf(rule) {
    const ks = ((overviewData && overviewData.usage && overviewData.usage.keys) || {})[rule.api_key] || {};
    const base = Number(rule.quota_used_base_usd || 0);
    const total = Number(ks.total_cost_usd || 0);
    const used = typeof rule.quota_used_usd === "number" && Number.isFinite(rule.quota_used_usd) && rule.quota_used_usd >= 0
      ? rule.quota_used_usd : Math.max(0, total - base);
    const limit = Math.max(0, Number(rule.quota_limit_usd || 0));
    const unlimited = limit <= 0;
    const remaining = unlimited ? 0 : Math.max(0, limit - used);
    const percent = unlimited ? 0 : Math.min(100, (used / limit) * 100);
    const lastUsedText = fmtDateTime(ks.last_request_at);
    return { used, limit, remaining, unlimited, percent, lastUsedText, exceeded: !unlimited && used >= limit };
  }

  function fmtDateTime(raw) { return KeyGuardFormat.dateTime(raw, currentTimezone()); }

  function quotaBarClass(percent, exceeded) {
    if (exceeded) return "quota-bar-fill quota-bar-critical";
    if (percent >= 80) return "quota-bar-fill quota-bar-warn";
    return "quota-bar-fill";
  }

  function renderQuotaTable() {
    const tbody = document.getElementById("quotaTableBody");
    if (!tbody || !overviewData) return;
    const rules = (overviewData.keys || []).slice();
    const q = (String((document.getElementById("quotaSearch") || {}).value || "")).trim().toLowerCase();
    const list = rules.filter(r => {
      if (!q) return true;
      return String(r.api_key || "").toLowerCase().includes(q) || String(r.name || "").toLowerCase().includes(q);
    });

    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="cell-empty">暂无 API Key</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(rule => {
      const usage = quotaUsageOf(rule);
      const label = rule.name ? `<span style="font-weight:600;color:var(--text-primary)">${escapeHtml(rule.name)}</span>` : "";
      const masked = escapeHtml(maskKeyStr(rule.api_key));
      const limitText = usage.unlimited
        ? `<span class="mono" style="color:var(--text-secondary)">Infinity</span>`
        : `<span class="mono">$${usage.limit.toFixed(2)}</span>`;
      const bar = usage.unlimited ? "" : `
        <div class="quota-bar"><div class="${quotaBarClass(usage.percent, usage.exceeded)}" style="width:${Math.max(1, usage.percent).toFixed(1)}%"></div></div>
        <span class="quota-bar-text">${usage.percent.toFixed(1)}%${usage.exceeded ? " · 已超额" : ""}</span>`;
      const usedText = usage.unlimited
        ? `<span class="mono">$${usage.used.toFixed(4)}</span> <span class="txt-muted">/ Infinity</span>`
        : `<span class="mono">$${usage.used.toFixed(4)}</span> <span class="txt-muted">/ $${usage.remaining.toFixed(4)}</span>`;
      return `<tr>
        <td class="cell-nowrap">
          <div class="ov-key-cell">
            <span class="mono" style="font-size:12px;color:var(--text-primary)">${masked}</span>
            ${label}
          </div>
        </td>
        <td>
          <div class="quota-limit-cell">${limitText}${bar}</div>
        </td>
        <td class="cell-nowrap">${usedText}</td>
        <td class="cell-nowrap mono" style="font-size:12px;color:var(--text-secondary)">${escapeHtml(usage.lastUsedText || "-")}</td>
        <td class="cell-nowrap">
          <div class="row-actions">
            <button type="button" class="btn btn-sm" data-action="copy" data-value="${escapeHtml(rule.api_key)}">复制密钥</button>
            <button type="button" class="btn btn-sm" data-action="editKey" data-value="${escapeHtml(rule.api_key)}">管理密钥</button>
            <button type="button" class="btn btn-sm" data-action="resetQuota" data-value="${escapeHtml(rule.api_key)}">重置额度</button>
            <button type="button" class="btn btn-sm btn-danger" data-action="deleteKey" data-value="${escapeHtml(rule.api_key)}">删除</button>
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  async function resetKeyQuota(apiKey) {
    const epoch = sessionEpoch;
    if (!apiKey) return;
    if (!confirm(`确定重置 Key [${maskKeyStr(apiKey)}] 的已用额度吗？\n（仅重置额度计量，不清空历史用量与费用统计）`)) return;
    try {
      const res = await callManagementAPI(API_QUOTA_RESET, {
        method: "POST",
        body: JSON.stringify({ api_key: apiKey })
      });
      if (!sessionCurrent(epoch)) return;
      showToast(`已重置 ${maskKeyStr(apiKey)} 的已用额度`);
      await refreshAfterMutation(res);
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast(err.message, true);
    }
  }

  // ==================== TAB 2: TOKEN USAGE LEADERBOARDS ====================
  // Statistics are stored per (requested model, served model) tuple, so grouping is
  // exact: every request lands in exactly one child row and totals never overlap.
  function buildRequestedModelGroups(tuples) {
    const groups = new Map();
    const same = (a, b) => String(a || "").toLowerCase() === String(b || "").toLowerCase();
    for (const ms of tuples) {
      if (!ms) continue;
      const served = String(ms.served_model || "").trim();
      const requested = String(ms.requested_model || "").trim() || served;
      if (!requested || !served) continue;
      if (!groups.has(requested)) {
        groups.set(requested, { requested: requested, children: [] });
      }
      groups.get(requested).children.push(ms);
    }
    const list = Array.from(groups.values());
    for (const group of list) {
      group.children.sort((a, b) => (b.total_tokens || 0) - (a.total_tokens || 0));
      group.totals = {
        requests: 0, success: 0, failed: 0, input: 0, output: 0,
        reasoning: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0
      };
      for (const ms of group.children) {
        group.totals.requests += ms.requests || 0;
        group.totals.success += ms.success_requests || 0;
        group.totals.failed += ms.failed_requests || 0;
        group.totals.input += ms.input_tokens || 0;
        group.totals.output += ms.output_tokens || 0;
        group.totals.reasoning += ms.reasoning_tokens || 0;
        group.totals.cacheRead += ms.cache_read_tokens || 0;
        group.totals.cacheWrite += ms.cache_write_tokens || 0;
        group.totals.totalTokens += ms.total_tokens || 0;
      }
      // Nothing was substituted: one row instead of a header plus an identical child.
      group.single = group.children.length === 1 &&
        same(group.children[0].served_model, group.requested);
    }
    list.sort((a, b) => (b.totals.totalTokens || 0) - (a.totals.totalTokens || 0));
    return list;
  }

  function usageGroups(owner) {
    if (!usageGroupsCache.has(owner)) {
      const models = Object.values(owner.models || {}).filter(model => model && (model.served_model || model.requested_model));
      usageGroupsCache.set(owner, { models, groups: buildRequestedModelGroups(models) });
    }
    return usageGroupsCache.get(owner);
  }

  function renderDashboardTables(keysOnly = false) {
    if (!overviewData) return;
    const snapKeys = (overviewData.usage && overviewData.usage.keys) || {};
    const rulesMap = overviewIndex.rules;

    const grandTotalTokens = (overviewData.summary && overviewData.summary.total_tokens) || 0;

    const q = (document.getElementById("dashKeySearch").value || "").toLowerCase().trim();
    const rows = Object.values(snapKeys).filter(ks => {
      const rawKey = (ks.api_key || ks.masked_key || "").trim();
      if (!rawKey || rawKey === "__anonymous__" || rawKey.toLowerCase() === "anonymous") return false;
      if (!q) return true;
      return (ks.api_key || "").toLowerCase().includes(q) ||
             (ks.masked_key || "").toLowerCase().includes(q) ||
             (ks.key_name || "").toLowerCase().includes(q);
    });

    rows.sort((a, b) => (b.total_tokens || 0) - (a.total_tokens || 0) || (b.total_requests || 0) - (a.total_requests || 0));

    const tbody = document.getElementById("dashKeyTableBody");
    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="cell-empty">暂无调用统计数据</td></tr>`;
    } else {
      let html = "";
      for (const ks of rows) {
        const rawKey = ks.api_key || ks.masked_key;
        const rule = rulesMap.get(rawKey) || {};
        const share = grandTotalTokens > 0 ? (((ks.total_tokens || 0) / grandTotalTokens) * 100).toFixed(1) : "0.0";
        const grouped = usageGroups(ks);
        const validModels = grouped.models;
        const groupCount = grouped.groups.length;
        const isExpanded = !!expandedDashKeys[rawKey];
        const keyNote = ks.key_name || rule.name || "";

        html += `<tr>
          <td class="cell-nowrap">
            <div class="mono" style="font-weight:600">${escapeHtml(ks.masked_key || maskKeyStr(rawKey))}</div>
            ${keyNote ? `<div class="txt-secondary-sm">${escapeHtml(keyNote)}</div>` : ""}
          </td>
          <td class="cell-nowrap mono">${fmtInt(ks.total_requests)} <span class="txt-muted">(${fmtInt(ks.success_requests)}/${fmtInt(ks.failed_requests)})</span></td>
          <td class="cell-nowrap mono">${fmtTokenValue(ks.input_tokens)}</td>
          <td class="cell-nowrap mono">${fmtTokenValue(ks.output_tokens)} <span class="txt-muted">(推理 ${fmtTokenValue(ks.reasoning_tokens)})</span></td>
          <td class="cell-nowrap mono">${fmtTokenValue(ks.cache_read_tokens)} / ${fmtTokenValue(ks.cache_write_tokens)}</td>
          <td class="cell-nowrap token-val">${fmtTokenValue(ks.total_tokens)}</td>
          <td style="min-width:120px">
            <div style="font-size:12px" class="mono">${share}%</div>
            <div class="bar"><div class="bar-fill" style="width:${share}%"></div></div>
          </td>
          <td class="cell-nowrap">
            <div class="row-actions">
              <button type="button" class="btn btn-sm" data-action="expandKey" data-value="${escapeHtml(rawKey)}">${isExpanded ? "收起" : "展开明细 (" + groupCount + ")"}</button>
              <button type="button" class="btn btn-sm btn-danger" data-action="resetUsage" data-value="${escapeHtml(rawKey)}">清零</button>
            </div>
          </td>
        </tr>`;

        if (isExpanded && validModels.length > 0) {
          const modelCells = (st) => `
              <td class="cell-nowrap mono">${fmtInt(st.requests)} (${fmtInt(st.success_requests !== undefined ? st.success_requests : st.success)}/${fmtInt(st.failed_requests !== undefined ? st.failed_requests : st.failed)})</td>
              <td class="cell-nowrap mono">${fmtTokenValue(st.input_tokens !== undefined ? st.input_tokens : st.input)}</td>
              <td class="cell-nowrap mono">${fmtTokenValue(st.output_tokens !== undefined ? st.output_tokens : st.output)} (推理 ${fmtTokenValue(st.reasoning_tokens !== undefined ? st.reasoning_tokens : st.reasoning)})</td>
              <td class="cell-nowrap mono">${fmtTokenValue(st.cache_read_tokens !== undefined ? st.cache_read_tokens : st.cacheRead)} / ${fmtTokenValue(st.cache_write_tokens !== undefined ? st.cache_write_tokens : st.cacheWrite)}</td>
              <td class="cell-nowrap token-val">${fmtTokenValue(st.total_tokens !== undefined ? st.total_tokens : st.totalTokens)}</td>`;
          for (const group of grouped.groups) {
            // Nothing substituted: one row carrying the requested model name.
            if (group.single) {
              const ms = group.children[0];
              html += `<tr class="model-group-row">
                <td class="cell-nowrap"><span class="mono" style="color:var(--text-primary);font-weight:600">${escapeHtml(group.requested)}</span> <span class="tag plain" style="font-size:10px">请求模型</span></td>${modelCells(ms)}
                <td colspan="2" class="txt-muted-xs">最后调用: ${escapeHtml(fmtDateTime(ms.last_used_at))}</td>
              </tr>`;
              continue;
            }
            const t = group.totals;
            html += `<tr class="model-group-row">
              <td class="cell-nowrap"><span class="mono" style="color:var(--text-primary);font-weight:700">${escapeHtml(group.requested)}</span> <span class="tag plain" style="font-size:10px">请求模型</span></td>${modelCells(t)}
              <td colspan="2" class="txt-muted-xs">落到 ${group.children.length} 个服务端模型</td>
            </tr>`;
            for (const ms of group.children) {
              const servedLabel = ms.served_model || group.requested;
              const swapped = String(servedLabel).toLowerCase() !== String(group.requested).toLowerCase();
              const hint = swapped
                ? ` <span class="tag plain" style="font-size:10px">已被上游替换</span>`
                : "";
              html += `<tr class="sub-row">
                <td class="cell-nowrap">↳ <span class="mono">${escapeHtml(servedLabel)}</span>${hint}</td>${modelCells(ms)}
                <td colspan="2" class="txt-muted-xs">最后调用: ${escapeHtml(fmtDateTime(ms.last_used_at))}</td>
              </tr>`;
            }
          }
        }
      }
      tbody.innerHTML = html;
    }

    if (keysOnly) return;
    // Model Token Leaderboard (aggregated by the upstream-served model)
    const modelAgg = {};
    let totalModelTokens = 0;
    for (const ks of rows) {
      if (!ks.models) continue;
      for (const ms of Object.values(ks.models)) {
        const m = String((ms && ms.served_model) || "").trim();
        if (!m || m.toLowerCase() === "unknown") continue;
        if (!modelAgg[m]) {
          modelAgg[m] = {
            model: m,
            requests: 0,
            success: 0,
            failed: 0,
            input: 0,
            output: 0,
            reasoning: 0,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 0
          };
        }
        const a = modelAgg[m];
        a.requests += ms.requests || 0;
        a.success += ms.success_requests || 0;
        a.failed += ms.failed_requests || 0;
        a.input += ms.input_tokens || 0;
        a.output += ms.output_tokens || 0;
        a.reasoning += ms.reasoning_tokens || 0;
        a.cacheRead += ms.cache_read_tokens || 0;
        a.cacheWrite += ms.cache_write_tokens || 0;
        a.totalTokens += ms.total_tokens || 0;
        totalModelTokens += ms.total_tokens || 0;
      }
    }

    const mRows = Object.values(modelAgg).sort((a, b) => b.totalTokens - a.totalTokens || b.requests - a.requests);
    const mBody = document.getElementById("dashModelTableBody");
    if (mRows.length === 0) {
      mBody.innerHTML = `<tr><td colspan="8" class="cell-empty">暂无模型 Token 消耗数据</td></tr>`;
    } else {
      mBody.innerHTML = mRows.map(m => {
        const share = totalModelTokens > 0 ? ((m.totalTokens / totalModelTokens) * 100).toFixed(1) : "0.0";
        return `<tr>
          <td class="mono" style="font-weight:600">${escapeHtml(m.model)}</td>
          <td class="mono">${fmtInt(m.requests)} (${fmtInt(m.success)}/${fmtInt(m.failed)})</td>
          <td class="mono">${fmtTokenValue(m.input)}</td>
          <td class="mono">${fmtTokenValue(m.output)}</td>
          <td class="mono">${fmtTokenValue(m.reasoning)}</td>
          <td class="mono">${fmtTokenValue(m.cacheRead)} / ${fmtTokenValue(m.cacheWrite)}</td>
          <td class="token-val">${fmtTokenValue(m.totalTokens)}</td>
          <td style="min-width:130px">
            <div style="font-size:12px" class="mono">${share}%</div>
            <div class="bar"><div class="bar-fill" style="width:${share}%"></div></div>
          </td>
        </tr>`;
      }).join("");
    }

    renderAccountUsageTable();
  }

  // ==================== USAGE BY UPSTREAM ACCOUNT & PROVIDER ====================
  function renderAccountUsageTable() {
    const tbody = document.getElementById("dashAccountTableBody");
    if (!tbody) return;
    const accounts = (overviewData && overviewData.usage && overviewData.usage.accounts) || {};
    const q = (document.getElementById("dashAccountSearch").value || "").toLowerCase().trim();

    const rows = Object.values(accounts)
      .filter(a => {
        if (!a) return false;
        if (!q) return true;
        return (a.auth_id || "").toLowerCase().includes(q) ||
          (a.provider || "").toLowerCase().includes(q) ||
          (a.last_model || "").toLowerCase().includes(q);
      })
      .sort((a, b) => (b.total_tokens || 0) - (a.total_tokens || 0) || (b.requests || 0) - (a.requests || 0));

    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="cell-empty">暂无账号维度的用量数据（需上游回报 usage.handle 后自动累计）</td></tr>`;
      return;
    }

    let html = "";
    for (const a of rows) {
      const authID = a.auth_id || a.auth_index || "-";
      const provider = a.provider || "unknown";
      const bucketKey = a.auth_id || a.auth_index || provider;
      const grouped = usageGroups(a);
      const modelList = grouped.models;
      const groupCount = grouped.groups.length;
      const isExpanded = !!expandedDashAccounts[bucketKey];
      const lastUsedHint = a.last_request_at
        ? `<div class="txt-muted-xs">最后: ${escapeHtml(fmtDateTime(a.last_request_at))}</div>`
        : "";
      const failed = a.failed_requests || 0;
      const reqCell = `${fmtInt(a.requests)} <span class="txt-muted">(${fmtInt(a.success_requests)}${failed > 0 ? `/<span style="color:var(--danger,#d9534f)">${fmtInt(failed)}</span>` : ""})</span>`;

      html += `<tr>
        <td class="cell-nowrap"><span class="tag plain mono">${escapeHtml(provider)}</span></td>
        <td class="cell-nowrap">
          <div class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(authID)}">${escapeHtml(authID)}</div>
          ${lastUsedHint}
        </td>
        <td class="cell-nowrap mono">${reqCell}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(a.input_tokens)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(a.output_tokens)} <span class="txt-muted">(推理 ${fmtTokenValue(a.reasoning_tokens)})</span></td>
        <td class="cell-nowrap mono">${fmtTokenValue(a.cache_read_tokens)} / ${fmtTokenValue(a.cache_write_tokens)}</td>
        <td class="cell-nowrap token-val">${fmtTokenValue(a.total_tokens)}</td>
        <td class="cell-nowrap">
          <button type="button" class="btn btn-sm" data-action="expandAccount" data-value="${escapeHtml(bucketKey)}">${isExpanded ? "收起" : "展开明细 (" + groupCount + ")"}</button>
        </td>
      </tr>`;

      if (isExpanded && modelList.length > 0) {
        // Label + name share one cell (colspan 2) so the arrow and the model name
        // are not separated by the wide provider/account columns.
        const acctCells = (st) => `
            <td class="cell-nowrap mono">${fmtInt(st.requests)} (${fmtInt(st.success_requests !== undefined ? st.success_requests : st.success)}/${fmtInt(st.failed_requests !== undefined ? st.failed_requests : st.failed)})</td>
            <td class="cell-nowrap mono">${fmtTokenValue(st.input_tokens !== undefined ? st.input_tokens : st.input)}</td>
            <td class="cell-nowrap mono">${fmtTokenValue(st.output_tokens !== undefined ? st.output_tokens : st.output)} (推理 ${fmtTokenValue(st.reasoning_tokens !== undefined ? st.reasoning_tokens : st.reasoning)})</td>
            <td class="cell-nowrap mono">${fmtTokenValue(st.cache_read_tokens !== undefined ? st.cache_read_tokens : st.cacheRead)} / ${fmtTokenValue(st.cache_write_tokens !== undefined ? st.cache_write_tokens : st.cacheWrite)}</td>
            <td class="cell-nowrap token-val">${fmtTokenValue(st.total_tokens !== undefined ? st.total_tokens : st.totalTokens)}</td>`;
        for (const group of grouped.groups) {
          if (group.single) {
            const ms = group.children[0];
            html += `<tr class="model-group-row">
              <td class="cell-nowrap" colspan="2"><span class="mono" style="color:var(--text-primary);font-weight:600">${escapeHtml(group.requested)}</span> <span class="tag plain" style="font-size:10px">请求模型</span></td>${acctCells(ms)}
              <td class="cell-nowrap" style="font-size:11px;color:var(--text-tertiary)">最后调用: ${escapeHtml(fmtDateTime(ms.last_used_at))}</td>
            </tr>`;
            continue;
          }
          const t = group.totals;
          html += `<tr class="model-group-row">
            <td class="cell-nowrap" colspan="2"><span class="mono" style="color:var(--text-primary);font-weight:700">${escapeHtml(group.requested)}</span> <span class="tag plain" style="font-size:10px">请求模型</span></td>${acctCells(t)}
            <td class="cell-nowrap" style="font-size:11px;color:var(--text-tertiary)">落到 ${group.children.length} 个服务端模型</td>
          </tr>`;
          for (const ms of group.children) {
            const servedLabel = ms.served_model || group.requested;
            const swapped = String(servedLabel).toLowerCase() !== String(group.requested).toLowerCase();
            const hint = swapped
              ? ` <span class="tag plain" style="font-size:10px">已被上游替换</span>`
              : "";
            html += `<tr class="sub-row">
              <td class="cell-nowrap" colspan="2">　↳ <span class="mono">${escapeHtml(servedLabel)}</span>${hint}</td>${acctCells(ms)}
              <td class="cell-nowrap" style="font-size:11px;color:var(--text-tertiary)">最后调用: ${escapeHtml(fmtDateTime(ms.last_used_at))}</td>
            </tr>`;
          }
        }
      }
    }
    tbody.innerHTML = html;
  }

  function toggleDashAccountExpand(bucketKey) {
    expandedDashAccounts[bucketKey] = !expandedDashAccounts[bucketKey];
    renderAccountUsageTable();
  }

  function toggleDashKeyExpand(rawKey) {
    expandedDashKeys[rawKey] = !expandedDashKeys[rawKey];
    renderDashboardTables(true);
  }

  // ==================== TAB 3: DEFAULT POLICY & CREDENTIALS ====================
  function renderDefaultPolicyDraftStatus(message = "") {
    const status = document.getElementById("dpDraftStatus");
    const conflict = defaultPolicyDirty && overviewData && defaultPolicyRevision !== overviewData.rules_revision;
    if (status) status.textContent = message || (conflict ? "服务器策略版本已变化，草稿已保留；请放弃修改并重新加载后再保存。" : defaultPolicyDirty ? "有未保存修改；刷新不会覆盖草稿。" : "");
    for (const id of ["dpAllowUnlisted", "dpMaxConcurrency", "dpBindStrategy", "dpAllModelsCheck", "dpAllCredsCheck"]) { const input = document.getElementById(id); if (input) input.disabled = defaultPolicySaveInFlight; }
    document.querySelectorAll("#dpModelCheckList input, #dpCredCheckList input").forEach(input => { input.disabled = defaultPolicySaveInFlight; });
    const discard = document.getElementById("dpDiscardBtn"); if (discard) discard.disabled = !defaultPolicyDirty || defaultPolicySaveInFlight;
    const save = document.getElementById("dpSaveBtn"); if (save) save.disabled = defaultPolicySaveInFlight;
  }
  function markDefaultPolicyDirty() {
    if (!overviewData || defaultPolicySaveInFlight) return;
    if (!defaultPolicyDirty) defaultPolicyRevision = overviewData.rules_revision;
    defaultPolicyDirty = true; renderDefaultPolicyDraftStatus();
  }
  function discardDefaultPolicyDraft() {
    if (defaultPolicySaveInFlight) return;
    defaultPolicyDirty = false; initDefaultPolicySelectors(); renderDefaultPolicyDraftStatus("已恢复服务器最新策略。");
  }
  function initDefaultPolicySelectors() {
    if (!overviewData || !overviewData.default_policy) return;
    if (defaultPolicyDirty || defaultPolicySaveInFlight) {
      renderProviderPills("dp"); renderModelCheckList("dp"); renderCredCheckList("dp"); updateSelectorBadges("dp");
      renderDefaultPolicyDraftStatus(); return;
    }
    defaultPolicyRevision = overviewData.rules_revision;
    defaultPolicyBaseline = cloneRule(overviewData.default_policy);
    const dp = defaultPolicyBaseline;
    document.getElementById("dpAllowUnlisted").value = dp.allow_unlisted_keys === false ? "false" : "true";
    document.getElementById("dpMaxConcurrency").value = dp.max_concurrency || 0;
    const ub = dp.upstream_binding || {};
    document.getElementById("dpBindStrategy").value = ub.strategy || "round-robin";

    const boundCreds = Array.from(new Set([].concat(ub.auth_ids || [], ub.credentials || [])));
    const allowedModels = (dp.allowed_models && dp.allowed_models.length) ? dp.allowed_models : ["*"];
    loadSelectorFromRule("dp", allowedModels, boundCreds); renderDefaultPolicyDraftStatus();
  }

  async function saveDefaultPolicy() {
    const epoch = sessionEpoch;
    if (defaultPolicySaveInFlight) return;
    if (!validateCredentialDraft("dp")) return;
    const { allowedModels, credentials } = exportSelectorValues("dp");
    if (!selectorState.dp.allModels && allowedModels.length === 0) {
      showToast("请至少勾选一个默认允许的模型，或勾选「允许访问全部模型」", true);
      return;
    }
    if (!selectorState.dp.allCreds && credentials.length === 0) {
      showToast("请至少勾选一个默认绑定的凭证，或勾选「不限定具体凭证」", true);
      return;
    }

    const payload = {
      ...cloneRule(defaultPolicyBaseline),
      allow_unlisted_keys: document.getElementById("dpAllowUnlisted").value === "true",
      max_concurrency: parseInt(document.getElementById("dpMaxConcurrency").value || "0", 10) || 0,
      allowed_models: allowedModels,
      upstream_binding: editedBinding("dp", defaultPolicyBaseline, credentials)
    };
    defaultPolicySaveInFlight = true; renderDefaultPolicyDraftStatus();
    try {
      const res = await callManagementAPI(API_DEFAULT_POLICY, {
        method: "POST",
        headers: revisionHeaders(defaultPolicyRevision),
        body: JSON.stringify(payload)
      });
      if (!sessionCurrent(epoch)) return;
      defaultPolicyDirty = false; defaultPolicySaveInFlight = false;
      showToast("全局默认策略已保存并立即生效");
      await refreshAfterMutation(res);
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      const message = err.status === 409 ? "策略已被其它会话更新，未保存草稿已保留；请放弃修改并重新加载后再保存。" : err.message;
      renderDefaultPolicyDraftStatus(message); showToast(message, true);
    } finally { if (sessionCurrent(epoch)) { defaultPolicySaveInFlight = false; renderDefaultPolicyDraftStatus(); } }
  }

  function renderHostAuthTable() {
    if (!overviewData) return;
    const files = overviewData.auth_files || [];
    const tbody = document.getElementById("hostAuthTableBody");

    if (files.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="cell-empty">宿主当前暂无已加载的上游凭证文件</td></tr>`;
      return;
    }

    tbody.innerHTML = files.map(af => {
      const idOrName = af.name || af.id || af.auth_index;
      const boundKeys = KeyGuardState.boundRules(overviewIndex, af);

      const statusOk = !af.disabled && !af.unavailable;
      return `<tr>
        <td class="mono" style="font-weight:600">${escapeHtml(idOrName)}</td>
        <td><span class="tag plain">${escapeHtml(af.provider || af.type || "unknown")}</span></td>
        <td>${escapeHtml(af.email || af.account || af.label || "-")}</td>
        <td><span class="tag ${statusOk ? "ok" : "bad"}">${escapeHtml(af.status || (statusOk ? "active" : "disabled"))}</span></td>
        <td class="mono">${af.priority || 0}</td>
        <td class="mono">${fmtInt(af.success)} / ${fmtInt(af.failed)}</td>
        <td>${boundKeys.length ? boundKeys.map(k => `<span class="tag plain">${escapeHtml(k.name || maskKeyStr(k.api_key))}</span>`).join(" ") : `<span class="txt-muted">公共池共享</span>`}</td>
      </tr>`;
    }).join("");
  }

  // ==================== TAB 0: QUOTA OVERVIEW (local ledger) ====================
  const API_LEDGER = "/v0/management/key-guard/ledger";
  const overviewState = {
    granularity: "hour",
    modelDim: "requests",
    range: "7d",
    activeModel: "",
    expandedKeys: {},
    loading: false,
    data: null
  };

  function fmtTokenValue(raw) {
    const n = Number(raw || 0);
    if (!Number.isFinite(n)) return "0";
    const abs = Math.abs(n);
    const units = [
      { div: 1e9, suffix: " B" },
      { div: 1e6, suffix: " M" },
      { div: 1e3, suffix: " K" },
      { div: 1, suffix: "" }
    ];
    let index = units.length - 1;
    for (let i = 0; i < units.length; i++) {
      if (abs >= units[i].div) { index = i; break; }
    }
    const digitsFor = (scaled) => (Math.abs(scaled) >= 100 ? 0 : Math.abs(scaled) >= 10 ? 1 : 2);
    let scaled = n / units[index].div;
    let digits = digitsFor(scaled);
    // 999,999 must read "1 M", not "1000 K": promote when rounding crosses 1000.
    if (index > 0 && Number(scaled.toFixed(digits)) >= 999.5) {
      index -= 1;
      scaled = n / units[index].div;
      digits = digitsFor(scaled);
    }
    return trimTrailingZeros(scaled.toFixed(digits)) + units[index].suffix;
  }

  function trimTrailingZeros(text) {
    return String(text).replace(/\.0+$/, "").replace(/(\.\d*?)0+$/, "$1");
  }

  function fmtMoneyNano(nanoUSD) {
    const usd = Number(nanoUSD || 0) / 1e9;
    if (usd === 0) return "$0.000000";
    const abs = Math.abs(usd);
    const digits = abs >= 1 ? 4 : abs >= 0.01 ? 6 : 8;
    return "$" + usd.toFixed(digits);
  }

  function overviewRangeBounds() {
    return KeyGuardFormat.rangeBounds(overviewState.range, currentTimezone(), new Date(), {
      from: (document.getElementById("ovFromDate") || {}).value,
      to: (document.getElementById("ovToDate") || {}).value
    });
  }

  function overviewQueryParams() {
    const bounds = overviewRangeBounds();
    const params = new URLSearchParams();
    params.set("from", bounds.from.toISOString());
    params.set("to", bounds.to.toISOString());
    params.set("granularity", overviewState.granularity);
    params.set("tz", currentTimezone());
    // The filter card was removed; the only remaining dimension is the model
    // selected by clicking a row of the distribution list.
    if (overviewState.activeModel) params.set("model", overviewState.activeModel);
    return params;
  }

  function setOverviewGranularity(gran) {
    overviewState.granularity = ["hour", "day", "month"].includes(gran) ? gran : "day";
    document.querySelectorAll("#ovGranularitySeg .seg-btn").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-gran") === overviewState.granularity);
    });
    loadOverviewLedger(true);
  }

  function setOverviewModelDim(dim) {
    overviewState.modelDim = ["requests", "tokens", "cost"].includes(dim) ? dim : "requests";
    document.querySelectorAll("#ovModelDimSeg .seg-btn").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-dim") === overviewState.modelDim);
    });
    renderModelDistribution();
  }


  async function loadOverviewLedger(showSkeleton, keyOverride = "") {
    if (!activeManagementKey && !keyOverride) return;
    const ticket = requestGate.begin("ledger");
    if (showSkeleton && !overviewState.data) showOverviewSkeleton();
    overviewState.loading = true;
    try {
      const params = overviewQueryParams();
      const data = await callManagementAPI(API_LEDGER + "?" + params.toString(), { method: "GET", signal: ticket.signal }, keyOverride || undefined);
      if (!ticket.current()) return;
      if (data.accounting_error) {
        // Saturated aggregates are not valid metrics, charts or dimensional filters.
        overviewState.data = null; overviewTrendGeom = null; hideTrendTip();
        const message = "账本统计异常（数值不可用）：" + String(data.accounting_error);
        for (const id of ["ovTrendChart", "ovDonutChart", "ovModelList"]) document.getElementById(id).textContent = message;
        for (const id of ["ovKeyTableBody", "ovKeyTableMeta", "ovTrendMeta", "ovTrendTip", "ovMetricTokensSub", "ovMetricCostSub", "ovLegendInput", "ovLegendOutput", "ovLegendCache", "ovLegendHit"]) document.getElementById(id)?.replaceChildren();
        for (const id of ["ovMetricKeys", "ovMetricRequests", "ovMetricTokens", "ovMetricCost", "ovMetricModels"]) document.getElementById(id).textContent = "统计异常";
        setRefreshStatus([overviewHealthMessage(overviewData), message].filter(Boolean).join("；"), true);
        return;
      }
      overviewState.data = data;
      renderOverviewAll();
      const healthMessage = overviewHealthMessage(overviewData);
      setRefreshStatus(healthMessage, !!healthMessage);
    } catch (err) {
      if (isCancelled(err) || !ticket.current()) return;
      if (overviewState.data) { renderOverviewAll(); showToast("账本更新失败，保留上次数据：" + err.message, true); }
      else renderOverviewEmpty(err.message);
    } finally { if (ticket.current()) overviewState.loading = false; ticket.finish(); }
  }

  function showOverviewSkeleton() {
    const trend = document.getElementById("ovTrendChart");
    if (trend) trend.innerHTML = `<div class="ov-skeleton" style="height:240px"></div>`;
    const donut = document.getElementById("ovDonutChart");
    if (donut) donut.innerHTML = `<div class="ov-skeleton" style="width:220px;height:220px;border-radius:50%"></div>`;
    const list = document.getElementById("ovModelList");
    if (list) list.innerHTML = `<div class="ov-skeleton" style="height:140px"></div>`;
    const keyBody = document.getElementById("ovKeyTableBody");
    if (keyBody) keyBody.innerHTML = `<tr><td colspan="8" style="padding:2px 0"><div class="ov-skeleton" style="height:96px;margin:8px"></div></td></tr>`;
  }

  // Table-wide skeleton rows so a refresh blanks the tables the same way the trend
  // chart does, instead of leaving stale numbers on screen while data is in flight.
  function skeletonRows(cols, rows) {
    const count = Math.max(1, rows || 3);
    let html = "";
    for (let i = 0; i < count; i++) {
      html += `<tr><td colspan="${cols}" style="padding:2px 0"><div class="ov-skeleton" style="height:34px;margin:6px 8px"></div></td></tr>`;
    }
    return html;
  }

  function showKeysTabSkeleton() {
    const quotaBody = document.getElementById("quotaTableBody");
    if (quotaBody) quotaBody.innerHTML = skeletonRows(5, 3);
    const keysBody = document.getElementById("crudKeysTableBody");
    if (keysBody) keysBody.innerHTML = skeletonRows(9, 4);
  }

  // Placeholder shimmer for the nine metric cards (four global + five overview ones)
  // while the refreshed payload is in flight.
  function showKpiSkeleton() {
    const valueIds = ["kpiTotalTokens", "kpiCacheTokens", "kpiTotalRequests", "kpiTotalCost"];
    const subIds = ["kpiTokenSub", "kpiCacheSub", "kpiReqSub", "kpiCostSub"];
    const metricIds = ["ovMetricKeys", "ovMetricRequests", "ovMetricTokens", "ovMetricCost", "ovMetricModels"];
    valueIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<span class="ov-skeleton kpi-skel-value"></span>`;
    });
    subIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<span class="ov-skeleton kpi-skel-sub"></span>`;
    });
    metricIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<span class="ov-skeleton kpi-skel-value"></span>`;
    });
  }

  function showDashboardSkeleton() {
    const keyBody = document.getElementById("dashKeyTableBody");
    if (keyBody) keyBody.innerHTML = skeletonRows(8, 4);
    const accountBody = document.getElementById("dashAccountTableBody");
    if (accountBody) accountBody.innerHTML = skeletonRows(8, 3);
    const modelBody = document.getElementById("dashModelTableBody");
    if (modelBody) modelBody.innerHTML = skeletonRows(8, 3);
  }

  function renderOverviewEmpty(message) {
    const trend = document.getElementById("ovTrendChart");
    if (trend) {
      trend.innerHTML = `<div class="ov-empty"><div>暂无可用数据</div><div style="font-size:11.5px">${escapeHtml(message || "最近 7 天没有调用记录")}</div></div>`;
    }
    const donut = document.getElementById("ovDonutChart");
    if (donut) donut.innerHTML = `<div class="ov-empty" style="min-height:200px"><div>无模型调用</div></div>`;
    const list = document.getElementById("ovModelList");
    if (list) list.innerHTML = `<div class="ov-empty" style="min-height:120px"><div>最近 7 天没有模型数据</div></div>`;
    const keyBody = document.getElementById("ovKeyTableBody");
    if (keyBody) keyBody.innerHTML = `<tr><td colspan="8" class="cell-empty">暂无密钥消耗数据</td></tr>`;
    ["ovMetricKeys", "ovMetricRequests", "ovMetricTokens", "ovMetricCost", "ovMetricModels"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = "-";
    });
  }

  function renderOverviewAll() {
    const data = overviewState.data;
    if (!data) return;
    renderOverviewMetrics(data);
    renderOverviewTrend(data);
    renderModelDistribution();
    renderOverviewKeyTable();
  }

  function renderOverviewMetrics(data) {
    const setText = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
    setText("ovMetricKeys", `${fmtInt(data.keys_total || 0)} / ${fmtInt(data.keys_available || 0)}`);
    setText("ovMetricRequests", fmtInt(data.requests || 0));
    setText("ovMetricTokens", fmtTokenValue(data.total_tokens || 0));
    setText("ovMetricCost", fmtMoneyNano(data.cost_nano_usd || 0));
    setText("ovMetricModels", fmtInt(data.model_count || 0));
    setText("ovMetricTokensSub",
      `入 ${fmtTokenValue(data.input_tokens)} · 出 ${fmtTokenValue(data.output_tokens)} · 缓存 ${fmtTokenValue(data.cache_read_tokens)}`);
    setText("ovMetricCostSub", "USD");
    setText("ovLegendInput", fmtTokenValue(data.input_tokens));
    setText("ovLegendOutput", fmtTokenValue(data.output_tokens));
    setText("ovLegendCache", fmtTokenValue(data.cache_read_tokens));
    const denom = Number(data.input_tokens || 0) + Number(data.cache_read_tokens || 0);
    const hit = denom > 0 ? (Number(data.cache_read_tokens || 0) / denom * 100) : 0;
    setText("ovLegendHit", hit.toFixed(1) + "%");
    const zoneName = String(data.timezone || "");
    const zoneHint = zoneName;
    const fmtRange = (raw) => String(raw || "").replace("T", " ").replace(/\.\d+/, "").replace(/([+-]\d{2}:\d{2}|Z)$/, "");
    setText("ovTrendMeta", `${data.active_days || 0} 个有使用记录的自然日 · ${fmtRange(data.from)} ~ ${fmtRange(data.to)}${zoneHint ? " · " + zoneHint : ""}`);
  }

  // ---- Trend chart (line series + hit-rate line, dual Y axis, hover tooltip) ----
  let overviewTrendGeom = null;

  function renderOverviewTrend(data) {
    const box = document.getElementById("ovTrendChart");
    if (!box) return;
    const series = (data.series || []).filter(s => s.total_tokens > 0 || s.requests > 0);
    if (!series.length) {
      overviewTrendGeom = null;
      box.innerHTML = `<div class="ov-empty"><div>最近 7 天暂无趋势数据</div><div style="font-size:11.5px">产生调用后会自动显示</div></div>`;
      return;
    }

    const W = 900, H = 280, padL = 56, padR = 52, padT = 16, padB = 34;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;
    const maxTokens = Math.max(1, ...series.map(s => Math.max(
      Number(s.input_tokens || 0),
      Number(s.output_tokens || 0),
      Number(s.cache_read_tokens || 0),
      Number(s.input_tokens || 0) + Number(s.output_tokens || 0) + Number(s.cache_read_tokens || 0)
    )));
    const slot = series.length > 1 ? plotW / (series.length - 1) : plotW;

    const yTok = v => padT + plotH - (v / maxTokens) * plotH;
    const yPct = v => padT + plotH - (Math.min(100, Math.max(0, v)) / 100) * plotH;

    const colors = { input: "#38bdf8", output: "#34d399", cache: "#a78bfa" };
    const xAt = i => (series.length > 1 ? padL + slot * i : padL + plotW / 2);

    // Three absolute-token lines (input / output / cache) on the left axis.
    const buildLine = (key, color) => {
      const pts = series.map((s, i) => ({ x: xAt(i), y: yTok(Number(s[key] || 0)), value: Number(s[key] || 0), label: s.label }));
      if (!pts.length) return { path: "", dots: "" };
      const path = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
      const dots = pts.map((p, i) =>
        `<circle class="ov-trend-dot" data-idx="${i}" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.8" fill="${color}" stroke="var(--bg-secondary)" stroke-width="1">` +
        `<title>${escapeHtml(p.label)} ${key === "input" ? "输入" : key === "output" ? "输出" : "缓存"} ${fmtTokenValue(p.value)}</title></circle>`
      ).join("");
      return { path, dots };
    };

    const inputLine = buildLine("input_tokens", colors.input);
    const outputLine = buildLine("output_tokens", colors.output);
    const cacheLine = buildLine("cache_read_tokens", colors.cache);

    // Cache hit-rate line on the right axis.
    const hitPoints = series.map((s, i) => ({ x: xAt(i), y: yPct(Number(s.cache_hit_rate || 0)), rate: Number(s.cache_hit_rate || 0), label: s.label }));
    const hitPath = hitPoints.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
    const hitDots = hitPoints.map((p, i) =>
      `<circle class="ov-trend-dot" data-idx="${i}" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.6" fill="#f59e0b"><title>${escapeHtml(p.label)} 命中率 ${p.rate.toFixed(1)}%</title></circle>`
    ).join("");

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map(frac => {
      const y = padT + plotH * (1 - frac);
      const tokLabel = fmtTokenValue(maxTokens * frac);
      return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="rgba(128,128,128,0.18)" stroke-dasharray="3 4"/>` +
        `<text x="${padL - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-tertiary)">${tokLabel}</text>` +
        `<text x="${W - padR + 8}" y="${(y + 3.5).toFixed(1)}" font-size="10" fill="#f59e0b">${(frac * 100).toFixed(0)}%</text>`;
    }).join("");

    const labelStep = Math.max(1, Math.ceil(series.length / 10));
    const xLabels = series.map((s, i) => {
      if (i % labelStep !== 0 && i !== series.length - 1) return "";
      const x = xAt(i);
      return `<text x="${x.toFixed(1)}" y="${H - padB + 16}" text-anchor="middle" font-size="10" fill="var(--text-tertiary)">${escapeHtml(s.label)}</text>`;
    }).join("");

    // Full-height invisible columns capture the pointer for the hover readout.
    const hoverZones = series.map((s, i) => {
      const width = series.length > 1 ? slot : plotW;
      const left = series.length > 1 ? xAt(i) - slot / 2 : padL;
      const x = Math.max(padL, Math.min(left, W - padR - 1));
      const w = Math.max(1, Math.min(width, W - padR - x));
      return `<rect class="ov-hover-zone" x="${x.toFixed(1)}" y="${padT}" width="${w.toFixed(1)}" height="${plotH.toFixed(1)}" ` +
        `fill="transparent" data-tip-index="${i}"></rect>`;
    }).join("");

    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Token 趋势折线图">
      ${gridLines}
      <line id="ovTrendGuide" x1="0" y1="${padT}" x2="0" y2="${padT + plotH}" stroke="rgba(148,163,184,0.65)" stroke-dasharray="4 4" style="display:none;pointer-events:none"/>
      <path d="${inputLine.path}" fill="none" stroke="${colors.input}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
      <path d="${outputLine.path}" fill="none" stroke="${colors.output}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
      <path d="${cacheLine.path}" fill="none" stroke="${colors.cache}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
      <path d="${hitPath}" fill="none" stroke="#f59e0b" stroke-width="1.6" stroke-dasharray="4 3" stroke-linejoin="round" stroke-linecap="round"/>
      <g>${inputLine.dots}${outputLine.dots}${cacheLine.dots}</g>
      <g>${hitDots}</g>
      <g>${xLabels}</g>
      <g>${hoverZones}</g>
    </svg>`;

    overviewTrendGeom = { series, xAt, slot, padL, padT, plotW, plotH };
  }

  function ensureTrendTip() {
    let tip = document.getElementById("ovTrendTip");
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "ovTrendTip";
      tip.className = "ov-chart-tip";
      document.body.appendChild(tip);
    }
    return tip;
  }

  function showTrendTip(evt, idx) {
    const geom = overviewTrendGeom;
    if (!geom) return;
    const point = geom.series[idx];
    if (!point) return;

    const guide = document.getElementById("ovTrendGuide");
    if (guide) {
      const x = geom.xAt(idx).toFixed(1);
      guide.setAttribute("x1", x);
      guide.setAttribute("x2", x);
      guide.style.display = "";
    }
    document.querySelectorAll("#ovTrendChart .ov-trend-dot").forEach(dot => {
      dot.setAttribute("r", Number(dot.getAttribute("data-idx")) === idx ? "4.6" : "2.8");
    });

    const tip = ensureTrendTip();
    tip.innerHTML = `
      <div class="ov-chart-tip-title">${escapeHtml(point.label)}</div>
      <div class="ov-chart-tip-row"><i style="background:#38bdf8"></i>输入<b>${fmtTokenValue(point.input_tokens)}</b></div>
      <div class="ov-chart-tip-row"><i style="background:#34d399"></i>输出<b>${fmtTokenValue(point.output_tokens)}</b></div>
      <div class="ov-chart-tip-row"><i style="background:#a78bfa"></i>缓存<b>${fmtTokenValue(point.cache_read_tokens)}</b></div>
      <div class="ov-chart-tip-row"><i style="background:#f59e0b"></i>缓存命中率<b>${Number(point.cache_hit_rate || 0).toFixed(1)}%</b></div>`;
    tip.style.display = "block";
    moveTrendTip(evt);
  }

  function moveTrendTip(evt) {
    const tip = document.getElementById("ovTrendTip");
    if (!tip || tip.style.display === "none") return;
    const pad = 14;
    const rect = tip.getBoundingClientRect();
    let left = (evt.clientX || 0) + pad;
    let top = (evt.clientY || 0) + pad;
    if (left + rect.width > window.innerWidth - 8) left = (evt.clientX || 0) - rect.width - pad;
    if (top + rect.height > window.innerHeight - 8) top = (evt.clientY || 0) - rect.height - pad;
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = Math.max(8, top) + "px";
  }

  function hideTrendTip() {
    const tip = document.getElementById("ovTrendTip");
    if (tip) tip.style.display = "none";
    const guide = document.getElementById("ovTrendGuide");
    if (guide) guide.style.display = "none";
    document.querySelectorAll("#ovTrendChart .ov-trend-dot").forEach(dot => dot.setAttribute("r", "2.8"));
  }

  // ---- Model distribution (donut + list) ----
  function modelDimValue(row) {
    if (overviewState.modelDim === "tokens") return Number(row.total_tokens || 0);
    if (overviewState.modelDim === "cost") return Number(row.cost_nano_usd || 0);
    return Number(row.requests || 0);
  }

  function modelDimText(row) {
    if (overviewState.modelDim === "tokens") return fmtTokenValue(row.total_tokens || 0);
    if (overviewState.modelDim === "cost") return fmtMoneyNano(row.cost_nano_usd || 0);
    return fmtInt(row.requests || 0) + " 次";
  }

  function renderModelDistribution() {
    const donutBox = document.getElementById("ovDonutChart");
    const listBox = document.getElementById("ovModelList");
    if (!donutBox || !listBox) return;
    const rows = ((overviewState.data || {}).models) || [];
    if (!rows.length) {
      donutBox.innerHTML = `<div class="ov-empty" style="min-height:200px"><div>暂无模型调用</div></div>`;
      listBox.innerHTML = `<div class="ov-empty" style="min-height:120px"><div>最近 7 天没有模型数据</div></div>`;
      return;
    }

    const values = rows.map(modelDimValue);
    const total = values.reduce((a, b) => a + b, 0);
    const palette = ["#38bdf8", "#34d399", "#f59e0b", "#a78bfa", "#f472b6", "#22d3ee", "#fbbf24", "#4ade80", "#818cf8", "#fb7185", "#2dd4bf", "#c084fc"];

    const R = 78, C = 110, STROKE = 26;
    const circumference = 2 * Math.PI * R;
    let offset = 0;
    let arcs = "";
    rows.forEach((row, i) => {
      const value = values[i];
      if (total <= 0 || value <= 0) return;
      const frac = value / total;
      const len = frac * circumference;
      const color = palette[i % palette.length];
      arcs += `<circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="${color}" stroke-width="${STROKE}" ` +
        `stroke-dasharray="${Math.max(0, len - 1.5).toFixed(2)} ${(circumference - Math.max(0, len - 1.5)).toFixed(2)}" ` +
        `stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 ${C} ${C})" opacity="0.92">` +
        `<title>${escapeHtml(row.model)} ${(frac * 100).toFixed(1)}%</title></circle>`;
      offset += len;
    });

    const centerLabel = overviewState.modelDim === "cost" ? fmtMoneyNano(total)
      : overviewState.modelDim === "tokens" ? fmtTokenValue(total)
      : fmtInt(total) + " 次";

    donutBox.innerHTML = `<svg viewBox="0 0 220 220" role="img" aria-label="模型调用分布">
      <circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="rgba(128,128,128,0.14)" stroke-width="${STROKE}"/>
      ${arcs}
      <text x="${C}" y="${C - 4}" text-anchor="middle" font-size="16" font-weight="700" fill="var(--text-primary)">${escapeHtml(centerLabel)}</text>
      <text x="${C}" y="${C + 16}" text-anchor="middle" font-size="10.5" fill="var(--text-tertiary)">${{requests:"调用次数",tokens:"Token 总量",cost:"费用合计"}[overviewState.modelDim]}</text>
    </svg>`;

    listBox.innerHTML = rows.map((row, i) => {
      const value = values[i];
      const share = total > 0 ? (value / total * 100) : 0;
      const active = overviewState.activeModel && overviewState.activeModel.toLowerCase() === String(row.model).toLowerCase();
      return `<div class="ov-model-row${active ? " active" : ""}" data-action="overviewModel" data-value="${escapeHtml(row.model)}">
        <span class="ov-swatch" style="background:${palette[i % palette.length]}"></span>
        <span class="ov-model-name" title="${escapeHtml(row.model)}">${escapeHtml(row.model)}</span>
        <span class="ov-model-share">${share.toFixed(1)}%</span>
        <span class="ov-model-num">${fmtInt(row.requests || 0)} 次</span>
        <span class="ov-model-num">${fmtTokenValue(row.total_tokens || 0)}</span>
        <span class="ov-model-num">${fmtMoneyNano(row.cost_nano_usd || 0)}</span>
      </div>`;
    }).join("");
  }

  function toggleOverviewModel(model) {
    const current = (overviewState.activeModel || "").toLowerCase();
    overviewState.activeModel = current === String(model).toLowerCase() ? "" : String(model);
    renderModelDistribution();
    loadOverviewLedger(true);
  }

  // ---- Per-key consumption table (expandable per-model rows) ----
  function renderOverviewKeyTable() {
    const tbody = document.getElementById("ovKeyTableBody");
    if (!tbody) return;
    const rows = ((overviewState.data || {}).key_rows) || [];
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="cell-empty">最近 7 天没有密钥消耗数据</td></tr>`;
      return;
    }
    const meta = document.getElementById("ovKeyTableMeta");
    // Configured keys (still present in the rules) vs. keys that only exist in the
    // ledger because they were deleted after producing traffic.
    const configured = new Set(((overviewData && overviewData.keys) || []).map(k => String(k.api_key || "")));
    rows.forEach(row => {
      row.__deleted = !configured.has(String(row.api_key || ""));
    });
    // Highest cost first; ties fall back to the token volume.
    rows.sort((a, b) => {
      const costDiff = Number(b.cost_nano_usd || 0) - Number(a.cost_nano_usd || 0);
      if (costDiff !== 0) return costDiff;
      return Number(b.total_tokens || 0) - Number(a.total_tokens || 0);
    });
    if (meta) {
      const totalModels = rows.reduce((sum, r) => sum + ((r.models || []).length), 0);
      const deletedCount = rows.filter(r => r.__deleted).length;
      meta.textContent = `${rows.length} 个密钥 · ${totalModels} 条模型消耗记录（近 7 天）` +
        (deletedCount ? ` · 含 ${deletedCount} 个已删除密钥` : "");
    }

    tbody.innerHTML = rows.map((row) => {
      const apiKey = String(row.api_key || "");
      const expanded = !!overviewState.expandedKeys[apiKey];
      const label = row.key_name || maskKeyStr(apiKey);
      const deletedTag = row.__deleted
        ? `<span class="tag bad" style="font-size:10.5px;padding:1px 6px" title="该密钥已从规则中删除，这里只保留历史用量">已删除</span>`
        : "";
      const head = `<tr class="ov-key-row${expanded ? " expanded" : ""}${row.__deleted ? " is-deleted" : ""}" data-action="overviewKey" data-value="${escapeHtml(apiKey)}">
        <td class="ov-key-toggle">${expanded ? "▾" : "▸"}</td>
        <td class="cell-nowrap">
          <div class="ov-key-cell">
            <span class="ov-key-line">
              <span class="mono" style="font-weight:600;color:var(--text-primary)">${escapeHtml(label)}</span>
              ${deletedTag}
            </span>
            ${row.key_name ? `<span class="mono" style="font-size:11px;color:var(--text-tertiary)">${escapeHtml(maskKeyStr(apiKey))}</span>` : ""}
          </div>
        </td>
        <td class="cell-nowrap mono">${fmtInt(row.requests || 0)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(row.input_tokens)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(row.output_tokens)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(row.cache_read_tokens)}</td>
        <td class="cell-nowrap mono" style="font-weight:600">${fmtTokenValue(row.total_tokens)}</td>
        <td class="cell-nowrap mono">${fmtMoneyNano(row.cost_nano_usd)}</td>
      </tr>`;

      if (!expanded) return head;
      const models = (row.models || []).map(m => `<tr class="ov-key-model-row">
        <td></td>
        <td class="cell-nowrap">↳ <span class="mono" style="color:var(--text-primary)">${escapeHtml(m.model)}</span></td>
        <td class="cell-nowrap mono">${fmtInt(m.requests || 0)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(m.input_tokens)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(m.output_tokens)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(m.cache_read_tokens)}</td>
        <td class="cell-nowrap mono">${fmtTokenValue(m.total_tokens)}</td>
        <td class="cell-nowrap mono">${fmtMoneyNano(m.cost_nano_usd)}</td>
      </tr>`).join("");
      return head + models;
    }).join("");
  }

  function toggleOverviewKey(apiKey) {
    if (!apiKey) return;
    overviewState.expandedKeys[apiKey] = !overviewState.expandedKeys[apiKey];
    renderOverviewKeyTable();
  }

  function expandAllOverviewKeys(expand) {
    const rows = ((overviewState.data || {}).key_rows) || [];
    if (expand) {
      rows.forEach(r => { if (r.api_key) overviewState.expandedKeys[r.api_key] = true; });
    } else {
      overviewState.expandedKeys = {};
    }
    renderOverviewKeyTable();
  }

  // ==================== TAB 4: MODELS & PRICING (models.dev + custom overrides) ====================
  let modelsDevSearchTimer = null;

  function fmtPriceNum(val) {
    const n = Number(val || 0);
    if (!Number.isFinite(n) || n === 0) return "$0";
    if (n >= 1) return "$" + n.toFixed(2).replace(/\.?0+$/, "");
    return "$" + n.toFixed(4).replace(/\.?0+$/, "");
  }

  function priceSourceTagHtml(source) {
    const src = String(source || "").toLowerCase();
    if (src === "custom_override") {
      return `<span class="tag warn">手动修改</span>`;
    }
    if (src.startsWith("models.dev(prefix:")) {
      const matched = String(source).replace(/^models\.dev\(prefix:/i, "").replace(/\)$/, "");
      return `<span class="tag ok" title="完整模型名未收录，按前缀降级匹配到 ${escapeHtml(matched)}">models.dev 前缀</span>`;
    }
    if (src.startsWith("models.dev")) {
      return `<span class="tag ok">models.dev</span>`;
    }
    if (src === "default_fallback") {
      return `<span class="tag plain">兜底默认价</span>`;
    }
    return `<span class="tag plain" style="color:var(--text-tertiary)">未匹配</span>`;
  }

  function renderPricingTab() {
    if (!overviewData) return;
    const ps = overviewData.pricing_status || {};
    const customMap = ps.custom_prices || {};
    const defPrice = ps.default_price || null;

    document.getElementById("pricingSyncedCount").textContent = fmtInt(ps.synced_model_keys || 0);
    document.getElementById("pricingSyncSource").textContent = "来源: " + (ps.sync_source || "未同步 (自动拉取 https://models.dev/api.json)");
    document.getElementById("pricingLastSyncAt").textContent = ps.last_sync_at ? fmtDateTime(ps.last_sync_at) : "尚未完成首次同步";

    const errEl = document.getElementById("pricingLastSyncErr");
    if (ps.last_sync_error) {
      errEl.textContent = "同步告警: " + ps.last_sync_error;
      errEl.style.color = "var(--error-color)";
    } else {
      errEl.textContent = "自动同步周期: 24 小时 · 状态正常";
      errEl.style.color = "var(--text-tertiary)";
    }

    const customKeys = Object.keys(customMap);
    document.getElementById("pricingCustomCount").textContent = fmtInt(customKeys.length);
    const defSubEl = document.getElementById("pricingDefaultSub");
    if (defPrice) {
      defSubEl.innerHTML =
        `兜底价: In <span class="mono">${fmtPriceNum(defPrice.input)}</span> / Out <span class="mono">${fmtPriceNum(defPrice.output)}</span> · ` +
        `<a href="javascript:void(0)" data-action="editPrice" data-value="__default__" style="color:var(--text-primary);text-decoration:underline">修改</a> · ` +
        `<a href="javascript:void(0)" data-action="deletePrice" data-value="__default__" style="color:var(--error-color);text-decoration:underline">清除</a>`;
    } else {
      defSubEl.innerHTML =
        `未设置兜底默认价 · <a href="javascript:void(0)" data-action="editPrice" data-value="__default__" style="color:var(--text-primary);text-decoration:underline">设置兜底价</a>`;
    }

    // Build the pricing list from the models the host actually advertises:
    // 1. Host available models (the same list the management center shows)
    // 2. Explicit custom overrides (including wildcard rules like gemini-3.8-*)
    // Models that only appear as an upstream substitution (e.g. gemini-4-argon-high
    // served instead of the requested name) are intentionally excluded.
    const rowsByModel = new Map();

    // 1. Available models on host
    for (const am of (overviewData.available_models || [])) {
      if (!am || !am.id) continue;
      const key = String(am.id).toLowerCase();
      rowsByModel.set(key, {
        model: am.id,
        provider: am.provider || modelProviderKey(am.id),
        price: am.price || { source: "unmatched" },
        refPrice: am.reference_price || null,
        isCustom: !!(customMap[key] || (am.price && am.price.source === "custom_override")),
        isExactCustom: !!customMap[key],
        isHostModel: true
      });
    }

    // 2. Explicit custom overrides (including wildcard rules like gemini-3.8-* that aren't literal host model IDs)
    for (const [pat, cp] of Object.entries(customMap)) {
      const key = String(pat).toLowerCase();
      if (rowsByModel.has(key)) {
        const existing = rowsByModel.get(key);
        existing.price = Object.assign({}, cp, { source: "custom_override" });
        existing.isCustom = true;
        existing.isExactCustom = true;
      } else {
        rowsByModel.set(key, {
          model: pat,
          provider: modelProviderKey(pat),
          price: Object.assign({}, cp, { source: "custom_override" }),
          refPrice: null,
          isCustom: true,
          isExactCustom: true,
          isHostModel: false
        });
      }
    }

    const sourceFilter = (document.getElementById("pricingSourceFilter").value || "all").toLowerCase();
    const q = (document.getElementById("pricingTableSearch").value || "").trim().toLowerCase();

    const list = Array.from(rowsByModel.values()).filter(item => {
      const src = String((item.price && item.price.source) || "unmatched").toLowerCase();
      if (sourceFilter === "custom" && src !== "custom_override") return false;
      if (sourceFilter === "models.dev" && !src.startsWith("models.dev")) return false;
      if (sourceFilter === "unmatched" && src !== "unmatched") return false;
      if (q) {
        return item.model.toLowerCase().includes(q) || String(item.provider || "").toLowerCase().includes(q);
      }
      return true;
    });

    // Sort: custom overrides first, then host available models, then alphabetical
    list.sort((a, b) => {
      if (a.isExactCustom !== b.isExactCustom) return a.isExactCustom ? -1 : 1;
      if (a.isCustom !== b.isCustom) return a.isCustom ? -1 : 1;
      if (a.isHostModel !== b.isHostModel) return a.isHostModel ? -1 : 1;
      return a.model.localeCompare(b.model);
    });

    const tbody = document.getElementById("pricingModelsTableBody");
    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="cell-empty">暂无匹配的模型价格记录</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(item => {
      const p = item.price || {};
      const ref = item.refPrice;
      const prov = modelProviderKey(item.model);
      const refText = ref
        ? `In ${fmtPriceNum(ref.input)} / Out ${fmtPriceNum(ref.output)}`
        : (String(p.source || "").startsWith("models.dev")
            ? `In ${fmtPriceNum(p.input)} / Out ${fmtPriceNum(p.output)}`
            : `-`);
      const resetBtn = item.isExactCustom
        ? `<button type="button" class="btn btn-sm btn-danger" data-action="deletePrice" data-value="${escapeHtml(item.model)}">恢复默认</button>`
        : "";
      return `<tr>
        <td class="cell-nowrap">
          <div style="display:inline-flex;align-items:center;gap:7px">
            <span class="model-dot dot-${prov}"></span>
            <span class="mono" style="font-weight:600;color:var(--text-primary)">${escapeHtml(item.model)}</span>
            ${item.model.includes("*") ? `<span class="tag plain" style="font-size:10px">通配符</span>` : ""}
          </div>
        </td>
        <td class="cell-nowrap">${priceSourceTagHtml(p.source)}</td>
        <td class="cell-nowrap mono">${fmtPriceNum(p.input)}</td>
        <td class="cell-nowrap mono">${fmtPriceNum(p.output)}</td>
        <td class="cell-nowrap mono">${fmtPriceNum(p.cache_read)}</td>
        <td class="cell-nowrap mono">${fmtPriceNum(p.cache_write)}</td>
        <td class="cell-nowrap mono" style="font-size:12px;color:var(--text-tertiary)">${escapeHtml(refText)}</td>
        <td class="cell-nowrap">
          <div class="row-actions">
            <button type="button" class="btn btn-sm" data-action="editPrice" data-value="${escapeHtml(item.model)}">修改价格</button>
            ${resetBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  async function triggerModelsDevSync() {
    const epoch = sessionEpoch;
    const btn = document.getElementById("btnSyncPricing");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "正在从 models.dev 拉取...";
    }
    try {
      const res = await callManagementAPI(API_PRICING_SYNC, { method: "POST" });
      if (!sessionCurrent(epoch)) return;
      showToast(`同步成功：已从 models.dev 更新 ${fmtInt(res.synced_models || 0)} 条模型价格`);
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast("同步失败: " + err.message, true);
    } finally {
      if (sessionCurrent(epoch) && btn) {
        btn.disabled = false;
        btn.textContent = "立即从 models.dev 同步";
      }
    }
  }

  function debouncedSearchModelsDev() {
    requestGate.cancel("priceSearch");
    if (modelsDevSearchTimer) clearTimeout(modelsDevSearchTimer);
    modelsDevSearchTimer = setTimeout(() => searchModelsDevCatalog(), 240);
  }

  async function searchModelsDevCatalog() {
    const input = document.getElementById("modelsDevSearchInput");
    const q = (input ? input.value : "").trim();
    const ticket = requestGate.begin("priceSearch");
    const tbody = document.getElementById("modelsDevSearchTableBody");
    try {
      const url = API_PRICING + "?search=" + encodeURIComponent(q) + "&limit=60";
      const res = await callManagementAPI(url, { method: "GET", signal: ticket.signal });
      if (!ticket.current()) return;
      const list = res.reference_models || [];
      if (list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="cell-empty">未在 models.dev 库中找到匹配的模型</td></tr>`;
        return;
      }
      tbody.innerHTML = list.map(entry => {
        const m = entry.model || "";
        const p = entry.price || {};
        const prov = modelProviderKey(m);
        return `<tr>
          <td class="cell-nowrap">
            <div style="display:inline-flex;align-items:center;gap:7px">
              <span class="model-dot dot-${prov}"></span>
              <span class="mono" style="font-weight:600">${escapeHtml(m)}</span>
            </div>
          </td>
          <td class="cell-nowrap mono">${fmtPriceNum(p.input)}</td>
          <td class="cell-nowrap mono">${fmtPriceNum(p.output)}</td>
          <td class="cell-nowrap mono">${fmtPriceNum(p.cache_read)}</td>
          <td class="cell-nowrap mono">${fmtPriceNum(p.cache_write)}</td>
          <td class="cell-nowrap">
            <button type="button" class="btn btn-sm" data-action="loadPrice" data-value="${escapeHtml(m)}" data-price="${escapeHtml(JSON.stringify(p))}">载入并修改</button>
          </td>
        </tr>`;
      }).join("");
    } catch (err) {
      if (!isCancelled(err) && ticket.current()) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--error-color)">检索失败: ${escapeHtml(err.message)}</td></tr>`;
    } finally { ticket.finish(); }
  }

  function openPriceModal(modelName) {
    priceModalEpoch++; requestGate.cancel("modalPrice");
    priceModalRevision = overviewData && overviewData.rules_revision;
    const norm = String(modelName || "").trim();
    const titleEl = document.getElementById("priceModalTitle");
    const modelInput = document.getElementById("pmModelInput");
    const refHint = document.getElementById("pmRefHint");
    modelInput.value = norm;
    refHint.textContent = "";

    let p = { input: 0, output: 0, cache_read: 0, cache_write: 0 };
    const ps = (overviewData && overviewData.pricing_status) || {};
    const customMap = ps.custom_prices || {};

    if (norm === "__default__") {
      titleEl.textContent = "设置全局兜底默认价格 (__default__)";
      if (ps.default_price) p = ps.default_price;
      refHint.textContent = "当模型既未命中手动修改规则、也未在 models.dev 中找到时使用此兜底价格。";
    } else if (norm) {
      titleEl.textContent = "修改模型价格: " + norm;
      const low = norm.toLowerCase();
      if (customMap[low]) {
        p = customMap[low];
      } else {
        const am = overviewIndex.models.get(low);
        if (am && am.price) p = am.price;
      }
    } else {
      titleEl.textContent = "新增自定义模型价格";
    }

    priceModalBaseline = cloneRule(p);
    document.getElementById("pmInputPrice").value = Number(p.input || 0);
    document.getElementById("pmOutputPrice").value = Number(p.output || 0);
    document.getElementById("pmCacheReadPrice").value = Number(p.cache_read || 0);
    document.getElementById("pmCacheWritePrice").value = Number(p.cache_write || 0);
    document.getElementById("priceModalMessage").textContent = "";
    document.querySelectorAll("#priceModal .modal-footer button").forEach(button => { button.disabled = false; });
    priceDialog.show();
  }

  function openPriceModalWithValues(modelName, input, output, cacheRead, cacheWrite) {
    priceModalEpoch++; requestGate.cancel("modalPrice");
    priceModalRevision = overviewData && overviewData.rules_revision;
    priceModalBaseline = { input, output, cache_read: cacheRead, cache_write: cacheWrite };
    document.getElementById("priceModalTitle").textContent = "修改模型价格: " + modelName;
    document.getElementById("pmModelInput").value = modelName;
    document.getElementById("pmInputPrice").value = Number(input || 0);
    document.getElementById("pmOutputPrice").value = Number(output || 0);
    document.getElementById("pmCacheReadPrice").value = Number(cacheRead || 0);
    document.getElementById("pmCacheWritePrice").value = Number(cacheWrite || 0);
    document.getElementById("pmRefHint").textContent = "已载入 models.dev 基准价格，修改后保存即可作为自定义覆盖规则生效。";
    document.getElementById("priceModalMessage").textContent = "";
    document.querySelectorAll("#priceModal .modal-footer button").forEach(button => { button.disabled = false; });
    priceDialog.show();
  }

  function closePriceModal() {
    return priceDialog.close();
  }

  async function fillPriceModalFromModelsDev() {
    const model = (document.getElementById("pmModelInput").value || "").trim();
    const refHint = document.getElementById("pmRefHint");
    const modalVersion = priceModalEpoch;
    const ticket = requestGate.begin("modalPrice");
    if (!model || model === "__default__") {
      showToast("请先输入具体的模型名称", true);
      ticket.finish();
      return;
    }
    try {
      const res = await callManagementAPI(API_PRICING + "?model=" + encodeURIComponent(model), { method: "GET", signal: ticket.signal });
      if (!ticket.current() || modalVersion !== priceModalEpoch || document.getElementById("pmModelInput").value.trim() !== model || !priceDialog.isOpen()) return;
      const q = res.query || {};
      const p = q.price || {};
      if (!q.found) {
        refHint.textContent = `未在 models.dev 中找到 "${model}" 的基准价格，请手动填写。`;
        return;
      }
      document.getElementById("pmInputPrice").value = Number(p.input || 0);
      document.getElementById("pmOutputPrice").value = Number(p.output || 0);
      document.getElementById("pmCacheReadPrice").value = Number(p.cache_read || 0);
      document.getElementById("pmCacheWritePrice").value = Number(p.cache_write || 0);
      refHint.textContent = `已填入基准价格（来源: ${p.source || "models.dev"}）`;
    } catch (err) {
      if (!isCancelled(err) && ticket.current()) showToast("查询基准价格失败: " + err.message, true);
    } finally { ticket.finish(); }
  }

  async function submitPriceModal() {
    const epoch = sessionEpoch, modalOwner = priceModalEpoch;
    const model = (document.getElementById("pmModelInput").value || "").trim();
    if (!model) {
      showToast("模型名称或匹配规则不能为空", true);
      return;
    }
    const price = {
      ...cloneRule(priceModalBaseline),
      input: Math.max(0, Number(document.getElementById("pmInputPrice").value || 0)),
      output: Math.max(0, Number(document.getElementById("pmOutputPrice").value || 0)),
      cache_read: Math.max(0, Number(document.getElementById("pmCacheReadPrice").value || 0)),
      cache_write: Math.max(0, Number(document.getElementById("pmCacheWritePrice").value || 0))
    };
    if ([price.input, price.output, price.cache_read, price.cache_write].some(value => !Number.isFinite(value) || value < 0)) { showToast("价格必须是有效的非负数", true); return; }
    try {
      const res = await callManagementAPI(API_PRICING_CUSTOM, {
        method: "POST",
        headers: revisionHeaders(priceModalRevision),
        body: JSON.stringify({ model, price })
      });
      if (!sessionCurrent(epoch) || modalOwner !== priceModalEpoch) return;
      closePriceModal();
      showToast(`已保存模型 "${model}" 的价格配置`);
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err) || modalOwner !== priceModalEpoch) return;
      showToast("保存价格失败: " + err.message, true);
    }
  }

  async function deleteCustomModelPrice(model) {
    const epoch = sessionEpoch;
    const norm = String(model || "").trim();
    if (!norm) return;
    try {
      const res = await callManagementAPI(API_PRICING_CUSTOM + "?model=" + encodeURIComponent(norm), {
        method: "DELETE"
      });
      if (!sessionCurrent(epoch)) return;
      showToast(norm === "__default__" ? "已清除全局兜底默认价格" : `已恢复模型 "${norm}" 为 models.dev 默认价格`);
      await refreshAfterMutation(res, { ledger: true });
    } catch (err) {
      if (!sessionCurrent(epoch) || isCancelled(err)) return;
      showToast("恢复默认价格失败: " + err.message, true);
    }
  }

  for (const id of ["dpAllowUnlisted", "dpMaxConcurrency", "dpBindStrategy"]) {
    document.getElementById(id).addEventListener("input", markDefaultPolicyDirty);
    document.getElementById(id).addEventListener("change", markDefaultPolicyDirty);
  }

  KeyGuardEvents.bind(document, {
    actions: {
      discardDefaultPolicy: () => discardDefaultPolicyDraft(),
      provider: (value, el) => setProviderFilter(el.dataset.prefix, value),
      entityPopover: (_value, el, event) => openEntityPopover(event, el),
      closePopover: () => closeModelPopover(), copyPopover: () => copyPopoverItems(),
      editPopover: value => editFromPopover(value), toggleKey: value => quickToggleKeyEnabled(value),
      copy: value => copyText(value), editKey: value => openKeyModalByKey(value),
      resetQuota: value => resetKeyQuota(value), deleteKey: value => deleteKeyRule(value),
      expandKey: value => toggleDashKeyExpand(value), resetUsage: value => resetUsageStats(value),
      expandAccount: value => toggleDashAccountExpand(value),
      overviewModel: value => toggleOverviewModel(value), overviewKey: value => toggleOverviewKey(value),
      editPrice: value => openPriceModal(value), deletePrice: value => deleteCustomModelPrice(value),
      loadPrice: (value, el) => { const p = JSON.parse(el.dataset.price); openPriceModalWithValues(value, p.input, p.output, p.cache_read, p.cache_write); }
    },
    change: {
      modelCheck: (value, el) => toggleModelCheckItem(el.dataset.prefix, value, el.checked),
      credCheck: (value, el) => toggleCredCheckItem(el.dataset.prefix, value, el.checked)
    },
    input: { popoverSearch: (_value, el) => renderEntityPopover(el.value, true) },
    drag: { dragstart: onKeyRowDragStart, dragover: onKeyRowDragOver, drop: onKeyRowDrop, dragend: onKeyRowDragEnd },
    tip: { pointerover: showTrendTip, pointermove: moveTrendTip, pointerout: hideTrendTip }
  }, error => { if (!isCancelled(error)) showToast(error.message || "操作失败", true); });

  KeyGuardAuth.listenParentSession(window, {
    onReady: () => {
      parentBridgeAvailable = true;
      parentSessionRevoked = false;
      try { sessionStorage.removeItem(SESSION_KEY_NAME); sessionStorage.removeItem(LEGACY_SESSION_KEY_NAME); } catch (_) {}
      if (!activeManagementKey) loadAdminOverview().catch(() => {});
    },
    onLogout: () => {
      parentBridgeAvailable = true;
      parentSessionRevoked = true;
      lockAdminWorkspace("管理中心会话已退出或变更，请重新登录");
    }
  });

  async function retryHostAuthentication() {
    const button = document.getElementById("authGateRetryBtn");
    if (button) button.disabled = true;
    try { await loadAdminOverview(); } catch (_) {}
    finally { if (button) button.disabled = false; }
  }

  window.addEventListener("storage", event => {
    if (!parentBridgeAvailable && event.key === "cli-proxy-auth" && activeManagementKey && !readStoredManagementKeyFromStorage(window.localStorage)) lockAdminWorkspace("管理中心会话已退出，请重新验证");
  });
  window.addEventListener("pagehide", () => { requestGate.cancelAll(); apiClient.cancelAll(); });

  restoreAdminTabFromUrl();
  loadAdminOverview().catch(() => {});
