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
        if (validBridgeReply(event, win.parent, win.location.origin, nonce)) finish(event.data.managementKey.trim());
      };
      win.addEventListener("message", receive);
      timer = setTimeout(() => finish(""), timeoutMs);
      try { win.parent.postMessage({ channel: CHANNEL, type: "request", nonce }, win.location.origin); }
      catch (_) { finish(""); }
    });
  }
  return { CHANNEL, validBridgeReply, requestParentKey };
});
