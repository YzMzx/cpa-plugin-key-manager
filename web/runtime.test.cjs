const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const Client = require("./client.js");
const State = require("./state.js");
const Format = require("./formatters.js");
const Auth = require("./auth.js");
const Events = require("./events.js");
const Audit = require("./audit.js");
const Settings = require("./settings.js");
const response = (body, status = 200, type = "application/json") => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": type } });
const overview = (extra = {}) => ({ summary: { total_tokens: 12, total_requests: 2, total_cost_nano_usd: 10 }, keys: [], usage: { keys: {}, accounts: {} }, default_policy: {}, available_models: [], auth_files: [], timezone: "UTC", rules_revision: 4, ...extra });
const ledger = (extra = {}) => ({ series: [], models: [], requests: 2, total_tokens: 12, from: "2026-01-01T00:00:00Z", to: "2026-01-02T00:00:00Z", ...extra });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const tick = () => new Promise(done => setImmediate(done));

function environment(fetchImpl = async () => response(overview())) {
  const elements = new Map();
  const htmlIds = new Set([...fs.readFileSync(path.join(__dirname, "index.html"), "utf8").matchAll(/id="([^"]+)"/g)].map(match => match[1]));
  const listeners = new Map();
  const classes = () => { const set = new Set(); return { add: (...items) => items.forEach(item => set.add(item)), remove: (...items) => items.forEach(item => set.delete(item)), contains: item => set.has(item), toggle: (item, force) => { const add = force === undefined ? !set.has(item) : force; if (add) set.add(item); else set.delete(item); return add; } }; };
  const element = id => {
    if (/^(?:setting|settings)/.test(id)) assert.ok(htmlIds.has(id), "page accessed missing settings DOM: " + id);
    if (!elements.has(id)) elements.set(id, { id, value: "", textContent: "", innerHTML: "", disabled: false, checked: false, style: {}, dataset: {}, classList: classes(), focus() {}, setSelectionRange() {}, getAttribute() { return null; }, setAttribute() {}, addEventListener(type, handler) { (this.listeners ||= {})[type] = handler; }, replaceChildren() { this.textContent = ""; this.children = []; }, appendChild(child) { (this.children ||= []).push(child); return child; }, remove() {} });
    return elements.get(id);
  };
  const doc = { body: { classList: classes() }, getElementById: element,
    createElement: () => ({ className: "", style: {}, dataset: {}, textContent: "", children: [], classList: classes(), setAttribute() {}, focus() {}, appendChild(child) { this.children.push(child); return child; }, replaceChildren() { this.children = []; this.textContent = ""; }, remove() {} }),
    querySelectorAll: selector => {
      if (selector.includes(".modal-backdrop input")) return [element("kmApiKey"), element("kmOriginalApiKey"), element("pmModelInput")];
      if (selector.includes("#adminWorkspace tbody")) return [element("crudKeysTableBody"), element("dashKeyTableBody"), element("dashAccountTableBody"), element("modelPopover")];
      return [];
    },
    addEventListener: (type, handler) => { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(handler); }, removeEventListener() {}
  };
  element("toastBox").appendChild = () => {};
  const store = new Map();
  const storage = { getItem: key => store.get(key) || null, setItem: (key, value) => store.set(key, value), removeItem: key => store.delete(key) };
  const windowListeners = new Map();
  const win = { location: { href: "http://localhost/ui", origin: "http://localhost", host: "localhost" }, history: { replaceState() {} }, addEventListener(type, handler) { if (!windowListeners.has(type)) windowListeners.set(type, []); windowListeners.get(type).push(handler); }, localStorage: storage };
  win.parent = win;
  const context = vm.createContext({ window: win, document: doc, location: win.location, navigator: { userAgent: "test", clipboard: { writeText: async () => {} } }, sessionStorage: storage,
    KeyGuardClient: Client, KeyGuardState: State, KeyGuardFormat: Format, KeyGuardAuth: Auth, KeyGuardEvents: Events, KeyGuardAudit: Audit, KeyGuardSettings: Settings,
    fetch: fetchImpl, Headers, Response, AbortController, URL, URLSearchParams, TextEncoder, TextDecoder, atob, console, confirm: () => true,
    setTimeout: (fn, ms) => { const timer = setTimeout(fn, ms); timer.unref(); return timer; }, clearTimeout });
  // Skip only automatic page boot. All production functions and delegated bindings execute unchanged.
  const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8").replace(/  restoreAdminTabFromUrl\(\);\s*loadAdminOverview\(\)\.catch\(\(\) => \{\}\);\s*$/, "");
  vm.runInContext(source, context);
  const run = code => vm.runInContext(code, context);
  run("activeManagementKey = 'test-admin'");
  return { run, context, element, listeners, windowListeners, doc, store };
}

test("API validates status, JSON, content type, schemas and optimistic revision", async () => {
  let options;
  const client = Client.createClient({ getKey: () => "secret", getRevision: () => 42, fetchImpl: async (_, opts) => { options = opts; return response({ ok: true, overview: overview() }); } });
  await client.request("/keys", { method: "POST", body: "{}" });
  assert.equal(options.headers.get("X-Key-Guard-Revision"), "42");
  assert.equal(options.headers.get("Authorization"), "Bearer secret");
  for (const [body, status, type, pattern] of [["bad", 200, "application/json", /JSON/], [{}, 200, "application/json", /概览/], [overview(), 200, "text/html", /类型/], [{ error: { message: "disk failed" } }, 500, "application/json", /disk failed/], [{ error: "conflict" }, 409, "application/json", /刷新后重试/]]) {
    const failing = Client.createClient({ getKey: () => "secret", fetchImpl: async () => response(body, status, type) });
    await assert.rejects(failing.request("/overview"), pattern);
  }
  assert.throws(() => Client.validateResponse("/ledger", "GET", {}), /账本/);
  assert.throws(() => Client.validateResponse("/pricing?search=x", "GET", {}), /检索/);
  assert.throws(() => Client.validateResponse("/pricing?model=x", "GET", { query: {} }), /价格/);
  assert.throws(() => Client.validateResponse("/keys", "POST", {}), /未确认/);
});

test("API timeout includes stalled fetch and stalled response body", async () => {
  for (const fetchImpl of [() => new Promise(() => {}), async () => ({ status: 200, text: () => new Promise(() => {}) })]) {
    const client = Client.createClient({ getKey: () => "key", timeoutMs: 10, fetchImpl });
    await assert.rejects(client.request("/overview"), /超时/);
  }
});

test("401 immediately invalidates auth even with non-JSON body and cancels other requests", async () => {
  let client;
  let locked = false;
  const blocked = deferred();
  client = Client.createClient({ getKey: () => "key", onUnauthorized: () => { locked = true; client.cancelAll(); }, fetchImpl: path => path === "/blocked" ? blocked.promise : Promise.resolve(response("login required", 401, "text/plain")) });
  const pending = client.request("/blocked");
  const pendingCheck = assert.rejects(pending, error => error.name === "AbortError");
  await assert.rejects(client.request("/unauthorized"));
  await pendingCheck;
  assert.equal(locked, true);
  blocked.resolve(response(overview()));
});

test("request ownership rejects stale completion and authentication epochs", () => {
  const gate = State.createRequestGate();
  const a = gate.begin("ledger");
  const b = gate.begin("ledger");
  assert.equal(a.current(), false); assert.equal(a.signal.aborted, true); assert.equal(b.current(), true);
  const independent = gate.begin("price");
  b.finish(); assert.equal(independent.current(), true);
  gate.cancelAll(); assert.equal(independent.current(), false); assert.equal(independent.signal.aborted, true);
});

test("calendar boundaries follow configured zones and 23/25 hour DST days", () => {
  const shanghai = Format.rangeBounds("today", "Asia/Shanghai", new Date("2026-03-08T12:00:00Z"));
  assert.equal(shanghai.from.toISOString(), "2026-03-07T16:00:00.000Z");
  const spring = Format.rangeBounds("today", "America/New_York", new Date("2026-03-08T12:00:00Z"));
  assert.equal(spring.from.toISOString(), "2026-03-08T05:00:00.000Z");
  assert.equal(spring.to.getTime() - spring.from.getTime() + 1, 23 * 3600000);
  const autumn = Format.rangeBounds("today", "America/New_York", new Date("2026-11-01T12:00:00Z"));
  assert.equal(autumn.to.getTime() - autumn.from.getTime() + 1, 25 * 3600000);
  assert.equal(Format.dateTime("2026-01-01T23:04:05Z", "UTC"), "2026-01-01 23:04:05");
  assert.equal(Format.dateTime("2026-01-01T23:04:05Z", "Asia/Tokyo"), "2026-01-02 08:04:05");
  assert.equal(Format.timezone("not/a-zone"), "Asia/Shanghai");
});

test("calendar custom range uses local inclusive end, including DST", () => {
  const range = Format.rangeBounds("custom", "America/New_York", new Date("2026-03-08T12:00:00Z"), { from: "2026-03-08", to: "2026-03-08" });
  assert.equal(range.from.toISOString(), "2026-03-08T05:00:00.000Z");
  assert.equal(range.to.toISOString(), "2026-03-09T03:59:59.999Z");
});

test("embedded login prefers live host credentials over stale cached sessions", async () => {
  const env = environment();
  const win = env.context.window;
  const listeners = new Set();
  win.crypto = require("node:crypto").webcrypto;
  win.addEventListener = (_type, fn) => listeners.add(fn);
  win.removeEventListener = (_type, fn) => listeners.delete(fn);
  win.parent = { location: win.location, postMessage(data) {
    queueMicrotask(() => { for (const fn of [...listeners]) fn({ source: win.parent, origin: win.location.origin, data: { ...data, type: "response", managementKey: "live-host" } }); });
  } };
  env.store.set("cpa_plugin_key_manager_mgmt_session", "stale-session");
  env.store.set("managementKey", "stale-storage");
  env.run('activeManagementKey = ""');
  assert.equal(await env.run("discoverCPAManagementKey()"), "live-host");
});

test("bridge credentials stay in memory when iframe removal drops logout notifications", async () => {
  const env = environment();
  env.store.set("cpa_plugin_key_manager_mgmt_session", "old-cache");
  env.store.set("cpa_plugin_key_mgmt_session", "old-legacy-cache");
  env.run('parentBridgeAvailable = true; unlockAdminWorkspace("ephemeral-host-key")');
  assert.equal(env.run("activeManagementKey"), "ephemeral-host-key");
  assert.equal(env.store.has("cpa_plugin_key_manager_mgmt_session"), false);
  assert.equal(env.store.has("cpa_plugin_key_mgmt_session"), false);
  // A new document shares the tab storage, but the destroyed iframe receives no logout.
  const next = environment();
  for (const [key, value] of env.store) next.store.set(key, value);
  next.run('activeManagementKey = ""');
  assert.equal(await next.run("discoverCPAManagementKey()"), "");
});

test("host logout cancels overview and prevents a late response from unlocking the page", async () => {
  const pending = deferred();
  const env = environment(() => pending.promise);
  const win = env.context.window;
  win.parent = {};
  env.store.set("cpa_plugin_key_manager_mgmt_session", "cached");
  const loading = env.run("loadAdminOverview()");
  const receive = data => { for (const fn of env.windowListeners.get("message")) fn({ source: win.parent, origin: win.location.origin, data: { channel: Auth.CHANNEL, ...data } }); };
  receive({ type: "logout" });
  pending.resolve(response(overview()));
  await loading;
  assert.equal(env.run("activeManagementKey"), "");
  assert.equal(env.run("overviewData"), null);
  assert.equal(env.store.has("cpa_plugin_key_manager_mgmt_session"), false);
  assert.equal(env.element("adminWorkspace").classList.contains("hidden"), true);
  assert.equal(await env.run("discoverCPAManagementKey()"), "");
});

test("live bridge authentication survives unrelated saved host metadata updates", () => {
  const env = environment();
  env.run('parentBridgeAvailable = true; unlockAdminWorkspace("live-host")');
  env.store.set("cli-proxy-auth", JSON.stringify({ state: { rememberPassword: false, serverVersion: "new-version" } }));
  for (const listener of env.windowListeners.get("storage")) listener({ key: "cli-proxy-auth" });
  assert.equal(env.run("activeManagementKey"), "live-host");
  env.run("parentBridgeAvailable = false");
  for (const listener of env.windowListeners.get("storage")) listener({ key: "cli-proxy-auth" });
  assert.equal(env.run("activeManagementKey"), "");
});

test("host ready retries a missing initial login and retry button stays bounded", async () => {
  const env = environment();
  env.context.window.parent = {};
  env.run('activeManagementKey = ""; var loginAttempts = 0; loadAdminOverview = async () => { loginAttempts++; };');
  for (const fn of env.windowListeners.get("message")) fn({ source: env.context.window.parent, origin: env.context.window.location.origin, data: { channel: Auth.CHANNEL, type: "ready" } });
  await tick();
  assert.equal(env.run("loginAttempts"), 1);
  await env.run("retryHostAuthentication()");
  assert.equal(env.run("loginAttempts"), 2);
  assert.equal(env.element("authGateRetryBtn").disabled, false);
});

test("bridge requires exact parent, origin, channel and nonce", async () => {
  const parent = {};
  const base = { source: parent, origin: "https://host", data: { channel: Auth.CHANNEL, type: "response", nonce: "n", managementKey: "secret" } };
  assert.equal(Auth.validBridgeReply(base, parent, "https://host", "n"), true);
  for (const changed of [{ source: {} }, { origin: "https://evil" }, { data: { ...base.data, nonce: "other" } }, { data: { ...base.data, type: "request" } }]) assert.equal(Auth.validBridgeReply({ ...base, ...changed }, parent, "https://host", "n"), false);
  assert.equal(await Auth.requestParentKey({ parent: { location: { origin: "https://evil" } }, location: { origin: "https://host" } }), "");
});

test("delegated events pass quotes, backslashes and newlines as data without executing them", () => {
  const listeners = new Map();
  const document = { addEventListener: (name, fn) => listeners.set(name, fn), removeEventListener() {} };
  const hostile = "x');globalThis.injected=true;//\\\n\"<>&";
  let actual;
  Events.bind(document, { actions: { copy: value => { actual = value; } }, change: {}, input: {}, drag: {}, tip: {} });
  const button = { dataset: { action: "copy", value: hostile } };
  listeners.get("click")({ target: { closest: () => button }, preventDefault() {}, stopPropagation() {} });
  assert.equal(actual, hostile); assert.equal(globalThis.injected, undefined);
});

test("generated markup has no inline events and static HTML controls remain", () => {
  const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");
  assert.doesNotMatch(source, /\bon[a-z]+\s*=/i);
  assert.doesNotMatch(source, /__reactFiber|XMLHttpRequest|API_CPA_KEYS|API_KEYS_SYNC|writeCPAGlobalKeys/);
  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  assert.match(html, /onclick="refreshAllData\(\)"/);
  const env = environment();
  const key = "key'\\\n\"<>&";
  env.context.fixture = overview({ keys: [{ api_key: key, allowed_models: ["model'\""], upstream_binding: {} }] });
  env.run("overviewData = fixture; overviewIndex = KeyGuardState.indexOverview(fixture); renderKeysCrudTable(); renderQuotaTable();");
  const generated = env.element("crudKeysTableBody").innerHTML + env.element("quotaTableBody").innerHTML;
  assert.doesNotMatch(generated, /\bon[a-z]+\s*=/i);
  assert.match(generated, /data-key="key&#39;/);
});

test("overview schema errors keep prior data and show refresh failure instead of zeros", async () => {
  const env = environment(async () => response({}));
  env.context.fixture = overview();
  env.run("overviewData = fixture; renderDashboardKPIs = () => {}; renderKeysCrudTable = () => {}; renderQuotaTable = () => {}; renderDashboardTables = () => {};");
  await assert.rejects(env.run("loadAdminOverview()"), /概览/);
  assert.equal(env.run("overviewData.summary.total_tokens"), 12);
  assert.match(env.element("refreshStatus").textContent, /上次成功数据/);
});

test("overview is read-only, loads timezone before ledger and mutations carry revision", async () => {
  const calls = [];
  const env = environment(async (url, options) => {
    calls.push({ url, options });
    return response(url.endsWith("/overview") ? overview({ timezone: "America/New_York" }) : ledger());
  });
  env.run("applyOverviewData = value => { overviewData = value; return true; }; renderOverviewAll = () => {};");
  await env.run("loadAdminOverview()");
  assert.equal(calls[0].options.method, "GET"); assert.match(calls[0].url, /overview$/);
  assert.match(calls[1].url, /tz=America%2FNew_York/);
  assert.ok(calls.every(call => call.options.method === "GET"));
});

test("late ledger response cannot replace newest filter result even when transport ignores abort", async () => {
  const calls = [];
  const env = environment(() => { const job = deferred(); calls.push(job); return job.promise; });
  env.run("renderOverviewAll = () => {}; overviewState.data = {}; showOverviewSkeleton = () => {};");
  const a = env.run("loadOverviewLedger(false)");
  env.run("overviewState.granularity = 'day'");
  const b = env.run("loadOverviewLedger(false)");
  calls[1].resolve(response(ledger({ total_tokens: 200 })));
  await b;
  calls[0].resolve(response(ledger({ total_tokens: 1 })));
  await a;
  assert.equal(env.run("overviewState.data.total_tokens"), 200);
});

test("late reference price cannot fill a different or closed model modal", async () => {
  const pending = deferred();
  const env = environment(() => pending.promise);
  env.element("pmModelInput").value = "model-a";
  env.element("priceModalBackdrop").classList.add("open");
  const task = env.run("fillPriceModalFromModelsDev()");
  env.run("openPriceModalWithValues('model-b', 2, 3, 4, 5)");
  pending.resolve(response({ query: { found: true, price: { input: 99, output: 99 } } }));
  await task;
  assert.equal(env.element("pmModelInput").value, "model-b");
  assert.equal(env.element("pmInputPrice").value, 2);
});

test("late price search cannot overwrite the current query", async () => {
  const requests = [];
  const env = environment(() => { const job = deferred(); requests.push(job); return job.promise; });
  env.element("modelsDevSearchInput").value = "a";
  const a = env.run("searchModelsDevCatalog()");
  env.element("modelsDevSearchInput").value = "b";
  const b = env.run("searchModelsDevCatalog()");
  requests[1].resolve(response({ reference_models: [{ model: "model-b", price: {} }] })); await b;
  requests[0].resolve(response({ reference_models: [{ model: "model-a", price: {} }] })); await a;
  assert.match(env.element("modelsDevSearchTableBody").innerHTML, /model-b/);
  assert.doesNotMatch(env.element("modelsDevSearchTableBody").innerHTML, /model-a/);
});

test("lock closes all modals, clears sensitive fields and cancels old async work", async () => {
  const pending = deferred();
  const env = environment(() => pending.promise);
  env.element("keyModalBackdrop").classList.add("open"); env.element("priceModalBackdrop").classList.add("open");
  env.element("kmApiKey").value = "sensitive"; env.element("kmOriginalApiKey").value = "sensitive";
  env.element("pmModelInput").value = "secret-model";
  const old = env.run("callManagementAPI('/overview')");
  const rejected = assert.rejects(old, error => error.name === "AbortError");
  env.run("lockAdminWorkspace('expired')"); await rejected;
  assert.equal(env.element("keyModalBackdrop").classList.contains("open"), false);
  assert.equal(env.element("priceModalBackdrop").classList.contains("open"), false);
  assert.equal(env.element("kmApiKey").value, ""); assert.equal(env.element("kmOriginalApiKey").value, "");
  assert.equal(env.run("activeManagementKey"), "");
  pending.resolve(response(overview()));
  await tick();
  assert.equal(env.run("overviewData"), null);
});

test("indexes retain key order and special identifiers without prototype collisions", () => {
  const rule = { api_key: "__proto__", upstream_binding: { credentials: ["Team.JSON", "Team.JSON"] } };
  const index = State.indexOverview(overview({ keys: [rule] }));
  assert.equal(index.rules.get("__proto__"), rule);
  assert.deepEqual(State.boundRules(index, { id: "team.json", name: "team.json" }), [rule]);
});

test("account and key expansion repaint only their respective table regions", () => {
  const env = environment();
  env.run("var painted = []; renderDashboardTables = keysOnly => painted.push(keysOnly ? 'key' : 'all'); renderAccountUsageTable = () => painted.push('account'); toggleDashAccountExpand('a'); toggleDashKeyExpand('k');");
  assert.equal(env.run("painted.join(',')"), "account,key");
});

test("auth theme references only defined fallback tokens", () => {
  const css = fs.readFileSync(path.join(__dirname, "app.css"), "utf8");
  assert.doesNotMatch(css, /var\(--(?:bg-card|shadow-md|error-badge-[a-z]+)\)/);
  for (const token of ["floating-surface", "shadow", "failure-badge-bg", "failure-badge-border", "failure-badge-text"]) assert.match(css, new RegExp("--" + token + ":"));
});

test("same-origin bridge has bounded fallback without randomUUID", async () => {
  const listeners = new Set();
  let request;
  const win = { location: { origin: "http://intranet" }, crypto: { getRandomValues: bytes => bytes.fill(7) },
    addEventListener: (_type, handler) => listeners.add(handler), removeEventListener: (_type, handler) => listeners.delete(handler) };
  win.parent = { location: { origin: "http://intranet" }, postMessage: data => {
    request = data;
    queueMicrotask(() => { for (const handler of listeners) handler({ source: win.parent, origin: win.location.origin, data: { ...data, type: "response", managementKey: "shared-key" } }); });
  } };
  assert.equal(await Auth.requestParentKey(win, 20), "shared-key");
  assert.equal(request.nonce.length, 48); assert.equal(listeners.size, 0);
  win.parent.postMessage = () => {};
  assert.equal(await Auth.requestParentKey(win, 5), ""); assert.equal(listeners.size, 0);
});

test("every static HTML event function still resolves after modularization", () => {
  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  const env = environment();
  const names = new Set();
  for (const match of html.matchAll(/\bon[a-z]+="([^"]*)"/g)) {
    for (const call of match[1].matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)) {
      if (!["if"].includes(call[1])) names.add(call[1]);
    }
  }
  assert.ok(names.size > 15);
  for (const name of names) assert.equal(env.run("typeof " + name), "function", name + " must remain available to static HTML");
});

test("delegated change drag and popover clicks retain expected behavior", () => {
  const env = environment();
  env.run("var actions = []; toggleModelCheckItem = (...args) => actions.push(args); openEntityPopover = (_event, element) => actions.push(element.dataset.key);");
  const model = { dataset: { change: "modelCheck", prefix: "km", value: "model'\\\n" }, checked: true };
  for (const handler of env.listeners.get("change")) handler({ target: model });
  assert.equal(env.run("actions[0][1]"), model.dataset.value);
  assert.equal(env.run("actions[0][2]"), true);
  const row = { dataset: { key: "key'\\" }, classList: { add: name => { row.added = name; } } };
  for (const handler of env.listeners.get("dragstart")) handler({ target: { closest: () => row }, dataTransfer: { setData() {} } });
  assert.equal(row.added, "dragging");
  const button = { dataset: { action: "entityPopover", key: "key'" } };
  const event = { target: { closest: selector => selector === "[data-action]" || selector.includes("[data-action],") ? button : null }, preventDefault() {}, stopPropagation() {} };
  for (const handler of env.listeners.get("click")) handler(event);
  assert.equal(env.run("actions[1]"), "key'");
});

test("overview applies warning and host_sync pending without claiming host success", async () => {
  const env = environment();
  env.run("applyOverviewData = value => { overviewData = value; return true; }; loadOverviewLedger = async () => {};");
  env.context.result = { ok: true, overview: overview({ host_sync: { pending: true, error: "write failed" } }) };
  await env.run("refreshAfterMutation(result)");
  assert.match(env.element("refreshStatus").textContent, /待重试.*write failed/);
});

test("runtime rejects duplicate mutations and sends the current rules revision", async () => {
  const pending = deferred(); let sent;
  const env = environment(async (_path, options) => { sent = options; return pending.promise; });
  env.context.fixture = overview({ rules_revision: 123 }); env.run("overviewData = fixture");
  const first = env.run("callManagementAPI('/keys', { method: 'POST', body: '{}' })");
  await assert.rejects(env.run("callManagementAPI('/keys', { method: 'POST', body: '{}' })"), /正在保存/);
  assert.equal(sent.headers.get("X-Key-Guard-Revision"), "123");
  pending.resolve(response({ ok: true, overview: overview() })); await first;
});


test("closing and reopening the same price model invalidates the previous query", async () => {
  const pending = deferred(); const env = environment(() => pending.promise);
  env.run("openPriceModal('same-model')");
  const task = env.run("fillPriceModalFromModelsDev()");
  env.run("closePriceModal(); openPriceModal('same-model')");
  pending.resolve(response({ query: { found: true, price: { input: 99 } } })); await task;
  assert.equal(env.element("pmInputPrice").value, 0);
});

test("nested malformed payloads and negative prices are rejected before rendering", async () => {
  assert.equal(Client.isOverview(overview({ available_models: "bad" })), false);
  assert.equal(Client.isOverview(overview({ usage: { keys: { broken: null } } })), false);
  assert.throws(() => Client.validateResponse("/pricing?search=x", "GET", { reference_models: [null] }), /检索/);
  assert.throws(() => Client.validateResponse("/pricing?model=x", "GET", { query: { found: true, price: { input: -1 } } }), /价格/);
  const client = Client.createClient({ getKey: () => "key", fetchImpl: async () => response("null", 500) });
  await assert.rejects(client.request("/overview"), /HTTP 500/);
});

test("quota table uses authoritative renamed-key usage, with backward compatible fallback", () => {
  const env = environment();
  env.context.fixture = overview({ usage: { keys: { renamed: { total_cost_usd: 3 } } } });
  env.run("overviewData = fixture");
  assert.equal(env.run("quotaUsageOf({api_key:'renamed', quota_limit_usd:10, quota_used_base_usd:1, quota_used_usd:7}).used"), 7);
  assert.equal(env.run("quotaUsageOf({api_key:'renamed', quota_limit_usd:10, quota_used_base_usd:1, quota_used_usd:7}).remaining"), 3);
  assert.equal(env.run("quotaUsageOf({api_key:'renamed', quota_limit_usd:10, quota_used_base_usd:1}).used"), 2);
  assert.equal(env.run("quotaUsageOf({api_key:'renamed', quota_limit_usd:10, quota_used_base_usd:1, quota_used_usd:0}).used"), 0);
});

test("overview exposes persistence and accounting failures instead of hiding them", () => {
 const env = environment();
 env.context.health = overview({diagnostics:{persistence:{last_error:"disk full", accounting_error:"aggregate overflow"}}});
 const message = env.run("overviewHealthMessage(health)");
 assert.match(message,/disk full/); assert.match(message,/aggregate overflow/);
});

test("audit tab uses administrator endpoints and tab exit cancels its detail", async () => {
 const status = {enabled:true,retention_days:7,max_records:100,max_body_bytes:1024,max_total_bytes:10000};
 const detail = deferred(); const calls = [];
 const env = environment(async (url, opts) => { calls.push({url,opts}); if(url.includes("/audit/detail"))return detail.promise; if(url.endsWith("/audit/status"))return response({status}); if(url.includes("/audit?"))return response({items:[{id:"audit-a",request_id:"req-a"}],total:1,limit:50,offset:0,status}); if(url.includes("/ledger"))return response(ledger()); return response(overview()); });
 env.run('switchAdminTab("tab-audit")'); await tick(); await tick();
 assert.ok(calls.some(call=>call.url.includes("/audit?limit=50&offset=0")));
 const pending = env.run('auditView.showDetail("audit-a")'); const request = calls.find(call=>call.url.includes("/audit/detail"));
 env.run('switchAdminTab("tab-pricing")'); assert.ok(request.opts.signal.aborted);
 detail.resolve(response({record:{id:"audit-a",request_body:{secret:"late"}},status})); await pending;
 assert.equal(env.element("auditRequestBody").textContent, ""); assert.equal(env.element("auditDetail").classList.contains("hidden"),true);
 assert.ok(calls.filter(call=>call.url.includes("/audit")).every(call=>call.url.startsWith("/v0/management/")&&call.opts.method==="GET"));
});

test("global refresh reloads active audit tab and lock clears its detail and filters", async () => {
 const status = {enabled:true,retention_days:7,max_records:100,max_body_bytes:1024,max_total_bytes:10000}; const calls=[];
 const env=environment(async(url)=>{calls.push(url);if(url.endsWith("/audit/status"))return response({status});if(url.includes("/audit/detail"))return response({record:{id:"audit-a",body_state:"stored",request_body:{messages:["sensitive"]}},status});if(url.includes("/audit?"))return response({items:[{id:"audit-a"}],total:1,limit:50,offset:0,status});if(url.includes("/ledger"))return response(ledger());return response(overview());});
 env.run('switchAdminTab("tab-audit")');await tick();await tick();await env.run('auditView.showDetail("audit-a")');
 env.element("auditKeyLabel").value="sensitive-trace"; const before=calls.filter(url=>url.includes("/audit?")).length;
 await env.run("refreshAllData()"); assert.ok(calls.filter(url=>url.includes("/audit?")).length>before);
 await env.run('auditView.showDetail("audit-a")');assert.match(env.element("auditRequestBody").textContent,/sensitive/);
 env.run('lockAdminWorkspace("expired")');assert.equal(env.element("auditRequestBody").textContent,"");assert.equal(env.element("auditKeyLabel").value,"");assert.equal(env.element("auditDetail").classList.contains("hidden"),true);
});

test("audit 401 clears detail and filters through the production API auth lifecycle", async () => {
 const status={enabled:true,retention_days:7,max_records:100,max_body_bytes:1024,max_total_bytes:10000};let detailRequests=0;
 const env=environment(async url=>{if(url.endsWith("/audit/status"))return response({status});if(url.includes("/audit?"))return response({items:[{id:"audit-a"},{id:"audit-b"}],total:2,limit:50,offset:0,status});if(url.includes("/audit/detail")){detailRequests++;return detailRequests===1?response({record:{id:"audit-a",body_state:"stored",request_body:{private:"conversation"}},status}):response("unauthorized",401,"text/plain");}return response(overview());});
 env.run('switchAdminTab("tab-audit")');await tick();await tick();await env.run('auditView.showDetail("audit-a")');assert.match(env.element("auditRequestBody").textContent,/conversation/);
 env.element("auditKeyLabel").value="sensitive-remark";await env.run('auditView.showDetail("audit-b")');assert.equal(env.run("activeManagementKey"),"");assert.equal(env.element("auditRequestBody").textContent,"");assert.equal(env.element("auditKeyLabel").value,"");assert.equal(env.element("auditDetail").classList.contains("hidden"),true);
});

test("production API client accepts audit cleanup preview then confirmed apply",async()=>{
 const auditStatus={enabled:true,retention_days:7,max_records:100,max_body_bytes:10485760,max_total_bytes:67108864};
 const storage={records:2,logical_bytes:2048,request_body_bytes:1024,max_total_bytes:67108864,db_file_bytes:4096,wal_file_bytes:0};
 let deleted=0;const env=environment(async(url,opts)=>{
  if(url.endsWith("/audit/status"))return response({status:auditStatus});
  if(url.endsWith("/audit/storage"))return response({storage});
  if(url.includes("/audit?"))return response({items:[],total:0,limit:50,offset:0,status:auditStatus});
  if(url.endsWith("/audit/cleanup/preview"))return response({ok:true,preview:{token:"preview-token",records:2,logical_bytes:2048,request_body_bytes:1024},storage});
  if(url.endsWith("/audit/cleanup")){deleted++;return response({ok:true,deleted:{records:2,logical_bytes:2048},storage:{...storage,records:0,logical_bytes:0}});}
  return response(overview());
 });
 env.run('switchAdminTab("tab-audit")');await tick();await tick();
 env.element("auditCleanupScope").value="all";await env.run("auditView.previewCleanup()");
 assert.match(env.element("auditCleanupMessage").textContent,/2 条/);assert.equal(deleted,0);
 env.element("auditCleanupAcknowledge").checked=true;await env.run("auditView.confirmCleanup()");assert.equal(deleted,1);assert.match(env.element("auditCleanupMessage").textContent,/已清理 2 条/);
});

test("settings tab retains dirty unit draft on global refresh, saves with fresh CAS and clears on lock",async()=>{
 const setting={audit:{enabled:true,retention_days:7,max_records:10000,max_body_bytes:10485760,max_total_bytes:67108864},storage:{flush_interval_seconds:10,ledger_retention_days:90,timezone:"Asia/Shanghai",pricing_cache_file:"data/prices.json"},pricing:{sync_url:"https://models.dev/api.json",sync_interval_hours:24,http_timeout_seconds:30,auto_inject_include_usage:true}};
 const calls=[];let version=7;const env=environment(async(url,options)=>{calls.push({url,options});if(url.endsWith("/settings")){if(options.method==="PUT"){const body=JSON.parse(options.body);assert.equal(body.expected_revision,7);assert.equal(options.headers.get("X-Key-Guard-Revision"),"7");version=8;return response({ok:true,settings:body.settings,rules_revision:version});}return response({settings:setting,rules_revision:version});}if(url.includes("/ledger"))return response(ledger());return response(overview({rules_revision:version}));});
 env.run('switchAdminTab("tab-settings")');await tick();await tick();assert.equal(env.element("settingAuditTotalMiB").value,"64");
 env.element("settingAuditTotalMiB").value="512";env.element("settingAuditTotalMiB").listeners.input();assert.equal(env.run("settingsView.isDirty()"),true);
 const readCount=calls.filter(call=>call.url.endsWith("/settings")&&call.options.method==="GET").length;await env.run("refreshAllData()");assert.equal(env.element("settingAuditTotalMiB").value,"512");assert.equal(calls.filter(call=>call.url.endsWith("/settings")&&call.options.method==="GET").length,readCount);
 await env.run("settingsView.save()");assert.equal(env.run("settingsView.isDirty()"),false);assert.ok(calls.some(call=>call.url.endsWith("/settings")&&call.options.method==="PUT"));
 env.element("settingBootstrapDB").value="unsaved-path";env.run('lockAdminWorkspace("expired")');assert.equal(env.element("settingBootstrapDB").value,"");assert.equal(env.element("settingTimezone").value,"");assert.equal(env.element("settingsSave").disabled,true);
});

test("deleting a key never places its plaintext in the management URL",async()=>{
 const calls=[];const key='sk-delete-sensitive-&?';
 const env=environment(async(url,opts={})=>{calls.push({url,opts});return response({ok:true,overview:overview({rules_revision:5})});});
 await env.run('deleteKeyRule('+JSON.stringify(key)+')');
 const request=calls.find(call=>call.opts.method==="DELETE");assert.ok(request);assert.equal(request.url,"/v0/management/key-guard/keys");assert.deepEqual(JSON.parse(request.opts.body),{api_key:key});assert.ok(!request.url.includes(key));assert.equal(request.url.includes("api_key="),false);
});

test("default policy draft survives refresh and unrelated CRUD across all selector edit paths",()=>{
 const env=environment();const initial=overview({rules_revision:4,default_policy:{allow_unlisted_keys:true,max_concurrency:1,allowed_models:["model-a"],upstream_binding:{strategy:"round-robin",credentials:["cred-a"]}},available_models:[{id:"model-a"},{id:"model-b"}],auth_files:[{name:"cred-a"},{name:"cred-b"}]});
 env.context.initial=initial;env.run("applyOverviewData(initial)");
 env.element("dpMaxConcurrency").value="7";env.element("dpMaxConcurrency").listeners.input();
 env.run('toggleModelCheckItem("dp","model-b",true);toggleCredCheckItem("dp","cred-b",true)');
 env.context.changed=overview({rules_revision:5,default_policy:{allow_unlisted_keys:false,max_concurrency:2,allowed_models:["server-only"],upstream_binding:{strategy:"fill-first",credentials:[]}},available_models:[{id:"model-a"},{id:"model-b"}],auth_files:[{name:"cred-a"},{name:"cred-b"}]});
 env.run("applyOverviewData(changed)");assert.equal(env.element("dpMaxConcurrency").value,"7");assert.equal(env.element("dpAllowUnlisted").value,"true");assert.equal(env.run('selectorState.dp.selectedModels.has("model-b")'),true);assert.equal(env.run('selectorState.dp.selectedCreds.has("cred-b")'),true);assert.equal(env.run("defaultPolicyRevision"),4);assert.match(env.element("dpDraftStatus").textContent,/版本已变化/);
 env.run("discardDefaultPolicyDraft()");assert.equal(env.element("dpMaxConcurrency").value,2);assert.equal(env.element("dpAllowUnlisted").value,"false");assert.equal(env.run("defaultPolicyDirty"),false);assert.equal(env.run("defaultPolicyRevision"),5);
 for(const expression of ['onToggleAllModels("dp")','onToggleAllCreds("dp")','batchCheckModels("dp",true)','batchCheckCreds("dp",true)']){env.run(expression);assert.equal(env.run("defaultPolicyDirty"),true);env.run("discardDefaultPolicyDraft()");}
});

test("default policy saves its draft revision, rebases only after success and preserves 409 edits",async()=>{
 const calls=[];let conflict=false;const env=environment(async(url,opts={})=>{calls.push({url,opts});if(url.includes("default-policy")){if(conflict)return response({error:{message:"stale"}},409);return response({ok:true,overview:overview({rules_revision:5,default_policy:JSON.parse(opts.body)})});}return response(overview());});
 env.context.initial=overview({rules_revision:4,default_policy:{allow_unlisted_keys:true,max_concurrency:1,allowed_models:["*"],upstream_binding:{strategy:"round-robin",credentials:[]}}});env.run("applyOverviewData(initial)");
 env.element("dpMaxConcurrency").value="8";env.element("dpMaxConcurrency").listeners.change();await env.run("saveDefaultPolicy()");
 let request=calls.find(call=>call.url.includes("default-policy"));assert.equal(request.opts.headers.get("X-Key-Guard-Revision"),"4");assert.equal(JSON.parse(request.opts.body).max_concurrency,8);assert.equal(env.run("defaultPolicyDirty"),false);assert.equal(env.run("defaultPolicyRevision"),5);
 conflict=true;env.element("dpMaxConcurrency").value="9";env.element("dpMaxConcurrency").listeners.input();env.run("overviewData.rules_revision=6");await env.run("saveDefaultPolicy()");assert.equal(env.run("defaultPolicyDirty"),true);assert.equal(env.element("dpMaxConcurrency").value,"9");assert.equal(env.run("defaultPolicyRevision"),5);assert.match(env.element("dpDraftStatus").textContent,/版本已变化/);
 env.run('lockAdminWorkspace("expired")');assert.equal(env.run("defaultPolicyDirty"),false);assert.equal(env.run("defaultPolicyRevision"),null);
});
