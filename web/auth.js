/* Explicit same-origin authentication bridge. Never inspect framework internals or intercept host traffic. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardAuth = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const CHANNEL = "cpa-plugin-key-manager:auth:v1";
  function validBridgeReply(event, parent, origin, nonce) {
    const data = event.data;
    return event.source === parent && event.origin === origin && data &&
      data.channel === CHANNEL && data.type === "response" && data.nonce === nonce &&
      typeof data.managementKey === "string";
  }
  function requestParentKey(win, timeoutMs = 450) {
    if (!win || win.parent === win) return Promise.resolve("");
    try { if (win.parent.location.origin !== win.location.origin) return Promise.resolve(""); }
    catch (_) { return Promise.resolve(""); }
    const crypto = win.crypto;
    if (!crypto || typeof crypto.getRandomValues !== "function") return Promise.resolve("");
    const bytes = new Uint8Array(24); crypto.getRandomValues(bytes);
    const nonce = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
    return new Promise(resolve => {
      let timer;
      const finish = key => { clearTimeout(timer); win.removeEventListener("message", receive); resolve(key); };
      const receive = event => {
        if (event.source === win.parent && event.origin === win.location.origin && event.data && event.data.channel === CHANNEL && event.data.type === "logout") finish("");
        else if (validBridgeReply(event, win.parent, win.location.origin, nonce)) finish(event.data.managementKey.trim());
      };
      win.addEventListener("message", receive);
      timer = setTimeout(() => finish(""), timeoutMs);
      try { win.parent.postMessage({ channel: CHANNEL, type: "request", nonce }, win.location.origin); }
      catch (_) { finish(""); }
    });
  }
  function readStoredKey(storage, location, userAgent = "") {
    if (!storage) return "";
    const clean = value => typeof value === "string" ? value.replace(/^Bearer\s+/i, "").trim() : "";
    const decode = raw => {
      if (!raw) return "";
      const match = /^enc::v([12])::/.exec(raw);
      if (!match) return raw.startsWith("enc::") ? "" : raw;
      const secret = new TextEncoder().encode("cli-proxy-api-webui::secure-storage|" + location.host + (match[1] === "1" ? "|" + userAgent : ""));
      const binary = atob(raw.slice(match[0].length));
      const bytes = Uint8Array.from(binary, (value, index) => value.charCodeAt(0) ^ secret[index % secret.length]);
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    };
    try {
      const raw = storage.getItem("cli-proxy-auth");
      if (raw) {
        let parsed = JSON.parse(decode(raw));
        if (typeof parsed === "string") parsed = JSON.parse(parsed);
        const state = parsed && (parsed.state || parsed);
        if (state && state.rememberPassword === false) return "";
        if (state && state.apiBase && new URL(state.apiBase, location.origin).origin !== location.origin) return "";
        const key = clean(state && state.managementKey);
        if (key) return key;
      }
    } catch (_) {}
    for (const name of ["managementKey", "cpa-management-key", "management_key"]) {
      try {
        const value = decode(storage.getItem(name));
        let key;
        try { key = clean(JSON.parse(value)); } catch (_) { key = clean(value); }
        if (key) return key;
      } catch (_) {}
    }
    return "";
  }
  function listenParentSession(win, { onReady, onLogout }) {
    const receive = event => {
      if (!win || win.parent === win || event.source !== win.parent || event.origin !== win.location.origin) return;
      const data = event.data;
      if (!data || data.channel !== CHANNEL) return;
      if (data.type === "ready") onReady();
      if (data.type === "logout") onLogout();
    };
    win.addEventListener("message", receive);
    return () => win.removeEventListener("message", receive);
  }
  return { CHANNEL, validBridgeReply, requestParentKey, readStoredKey, listenParentSession };
});
