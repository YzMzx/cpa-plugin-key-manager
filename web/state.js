/* Request ownership and snapshot indexes; no DOM or external dependencies. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardState = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  function createRequestGate() {
    const scopes = new Map();
    let epoch = 0;
    function cancel(name) { const old = scopes.get(name); if (old) old.controller.abort(); scopes.delete(name); }
    function begin(name) {
      cancel(name);
      const controller = new AbortController();
      const entry = { controller, epoch };
      scopes.set(name, entry);
      return { signal: controller.signal,
        current: () => scopes.get(name) === entry && entry.epoch === epoch && !controller.signal.aborted,
        finish: () => { if (scopes.get(name) === entry) scopes.delete(name); } };
    }
    function cancelAll() { epoch++; for (const name of Array.from(scopes.keys())) cancel(name); }
    return { begin, cancel, cancelAll };
  }
  function indexOverview(data) {
    const rules = new Map();
    const credentialKeys = new Map();
    const models = new Map();
    for (const model of data.available_models || []) models.set(String(model.id).toLowerCase(), model);
    for (const rule of data.keys || []) {
      rules.set(rule.api_key, rule);
      const binding = rule.upstream_binding || {};
      for (const id of new Set([...(binding.auth_ids || []), ...(binding.credentials || [])])) {
        const normalized = String(id).toLowerCase();
        if (!credentialKeys.has(normalized)) credentialKeys.set(normalized, new Set());
        credentialKeys.get(normalized).add(rule);
      }
    }
    return { rules, credentialKeys, models };
  }
  function boundRules(index, credential) {
    const result = new Set();
    for (const id of [credential.id, credential.name, credential.auth_index]) {
      if (!id) continue;
      for (const rule of index.credentialKeys.get(String(id).toLowerCase()) || []) result.add(rule);
    }
    return Array.from(result);
  }
  return { createRequestGate, indexOverview, boundRules };
});
