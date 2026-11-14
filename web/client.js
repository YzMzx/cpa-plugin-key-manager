/* Dependency-free management API client; shared by the embedded page and Node tests. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardClient = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
  class APIError extends Error {
    constructor(message, status = 0) { super(message); this.name = "APIError"; this.status = status; }
  }
  function aborted() { const error = new Error("请求已取消"); error.name = "AbortError"; return error; }
  const finite = value => typeof value === "number" && Number.isFinite(value);
  const price = value => object(value) && ["input", "output", "cache_read", "cache_write"].every(key => value[key] === undefined || (finite(value[key]) && value[key] >= 0));
  function isOverview(value) {
    return object(value) && object(value.summary) && Array.isArray(value.keys) &&
      value.keys.every(key => object(key) && typeof key.api_key === "string") &&
      object(value.default_policy) && object(value.usage) && object(value.usage.keys) &&
      Object.values(value.usage.keys).every(object) &&
      (value.auth_files === undefined || (Array.isArray(value.auth_files) && value.auth_files.every(object))) &&
      (value.available_models === undefined || (Array.isArray(value.available_models) && value.available_models.every(model => object(model) && typeof model.id === "string"))) &&
      ["total_tokens", "total_requests", "total_cost_nano_usd"].every(key =>
        typeof value.summary[key] === "number" && Number.isFinite(value.summary[key]));
  }
  function validateResponse(path, method, data) {
    if (!object(data)) throw new APIError("服务器响应格式无效，未更新当前数据");
    const endpoint = path.split("?")[0];
    if (method === "GET" && endpoint.endsWith("/overview")) {
      if (!isOverview(data)) throw new APIError("概览响应缺少有效统计数据，已保留上次数据");
    } else if (method === "GET" && endpoint.endsWith("/ledger")) {
      if (!Array.isArray(data.series) || !data.series.every(object) || !Array.isArray(data.models) || !data.models.every(object) ||
          !finite(data.requests) || !finite(data.total_tokens) ||
          typeof data.from !== "string" || typeof data.to !== "string") {
        throw new APIError("账本响应格式无效，已保留上次数据");
      }
    } else if (method === "GET" && endpoint.endsWith("/pricing")) {
      const query = new URLSearchParams(path.split("?")[1] || "");
      if (query.has("search") && (!Array.isArray(data.reference_models) || !data.reference_models.every(entry => object(entry) && typeof entry.model === "string" && price(entry.price)))) throw new APIError("价格检索响应格式无效");
      if (query.has("model") && (!object(data.query) || typeof data.query.found !== "boolean" || (data.query.found && !price(data.query.price)))) throw new APIError("模型价格响应格式无效");
    } else if (method !== "GET" && method !== "HEAD") {
      if (data.ok !== true && !isOverview(data)) throw new APIError("服务器未确认变更成功，请刷新确认状态");
    }
    if (data.overview !== undefined && !isOverview(data.overview)) throw new APIError("变更响应的概览格式无效，请刷新确认状态");
    return data;
  }
  // Optional endpoint budgets include the full response, before JSON parsing. Stream when available.
  async function readBoundedResponse(response, maxBytes, signal) {
    if (maxBytes === undefined) return response.text();
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new APIError("响应预算无效");
    const length = response.headers.get("Content-Length");
    if (length && Number(length) > maxBytes) throw new APIError("服务器响应超过安全读取预算");
    if (!response.body || typeof response.body.getReader !== "function") {
      const value = await response.text();
      if (new TextEncoder().encode(value).length > maxBytes) throw new APIError("服务器响应超过安全读取预算");
      return value;
    }
    const reader = response.body.getReader(), decoder = new TextDecoder();
    const chunks = []; let size = 0;
    const cancelRead = () => { reader.cancel().catch(() => {}); };
    if (signal) signal.addEventListener("abort", cancelRead, { once: true });
    try {
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > maxBytes) { await reader.cancel(); throw new APIError("服务器响应超过安全读取预算"); }
        chunks.push(decoder.decode(chunk.value, { stream: true }));
      }
      chunks.push(decoder.decode()); return chunks.join("");
    } finally { if (signal) signal.removeEventListener("abort", cancelRead); reader.releaseLock(); }
  }
  function createClient({ fetchImpl = globalThis.fetch.bind(globalThis), getKey, getRevision = () => undefined,
      onUnauthorized = () => {}, timeoutMs = 15000 } = {}) {
    const controllers = new Set();
    let epoch = 0;
    function cancelAll() { epoch++; for (const controller of controllers) controller.abort(); controllers.clear(); }
    async function request(path, options = {}, overrideKey = "") {
      const key = String(overrideKey || getKey() || "").replace(/^Bearer\s+/i, "").trim();
      if (!key) throw new APIError("需要 CLIProxyAPI Management Key 授权访问", 401);
      const generation = epoch;
      const method = String(options.method || "GET").toUpperCase();
      const headers = new Headers(options.headers || {});
      headers.set("Accept", "application/json");
      headers.set("Authorization", "Bearer " + key);
      headers.set("X-Management-Key", key);
      if (options.body !== undefined && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
      const revision = getRevision();
      if (method !== "GET" && method !== "HEAD" && revision !== undefined && revision !== null && !headers.has("X-Key-Guard-Revision")) headers.set("X-Key-Guard-Revision", String(revision));
      const controller = new AbortController();
      controllers.add(controller);
      const externalSignal = options.signal;
      const cancel = () => controller.abort();
      if (externalSignal) { if (externalSignal.aborted) cancel(); else externalSignal.addEventListener("abort", cancel, { once: true }); }
      let timer;
      let onAbort;
      const interruption = new Promise((_, reject) => {
        onAbort = () => reject(aborted());
        controller.signal.addEventListener("abort", onAbort, { once: true });
        if (controller.signal.aborted) onAbort();
        timer = setTimeout(() => { reject(new APIError("请求超时，请重试；若是保存操作，请先刷新确认结果")); controller.abort(); }, timeoutMs);
      });
      try {
        const task = (async () => {
          const { responseMaxBytes, ...fetchOptions } = options;
          const response = await fetchImpl(path, { ...fetchOptions, method, headers, signal: controller.signal });
          if (generation !== epoch || controller.signal.aborted) throw aborted();
          if (response.status === 401 || response.status === 403) {
            onUnauthorized("Management Key 已失效或未授权，请重新验证");
            throw new APIError("Management Key 已失效或未授权", response.status);
          }
          const text = await readBoundedResponse(response, responseMaxBytes, controller.signal);
          if (generation !== epoch || controller.signal.aborted) throw aborted();
          let data;
          try { data = JSON.parse(text); } catch (_) {
            throw new APIError("服务器返回非 JSON 数据 (HTTP " + response.status + ")，已保留当前数据", response.status);
          }
          if (!response.ok) {
            const detail = object(data) ? ((object(data.error) ? data.error.message : data.error) || data.message || "请求失败") : "请求失败";
            throw new APIError(response.status === 409 ? (String(path).includes("/audit/cleanup/jobs") ? String(detail) + "；请先查询任务核实状态，不会自动重试写请求" : String(path).includes("/audit/cleanup") ? String(detail) + "；请重新预览清理范围" : "规则已被其它会话更新，请刷新后重试") : String(detail) + " (HTTP " + response.status + ")", response.status);
          }
          const contentType = response.headers.get("Content-Type") || "";
          if (!contentType.toLowerCase().includes("application/json")) throw new APIError("服务器响应类型不是 JSON，未更新当前数据", response.status);
          return validateResponse(path, method, data);
        })();
        const result = await Promise.race([task, interruption]);
        // A sibling 401/logout may cancel after task settled but before this continuation.
        if (generation !== epoch || controller.signal.aborted) throw aborted();
        return result;
      } finally {
        clearTimeout(timer); controllers.delete(controller);
        controller.signal.removeEventListener("abort", onAbort);
        if (externalSignal) externalSignal.removeEventListener("abort", cancel);
      }
    }
    return { request, cancelAll };
  }
  return { APIError, createClient, isOverview, validateResponse, aborted };
});
