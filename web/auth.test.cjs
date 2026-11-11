const test = require("node:test");
const assert = require("node:assert/strict");
const Auth = require("./auth.js");
const location = { host: "localhost:8317", origin: "http://localhost:8317" };
const storage = values => ({ getItem: name => values[name] || null });
function encode(value, version, userAgent = "old-browser") {
  const key = Buffer.from("cli-proxy-api-webui::secure-storage|" + location.host + (version === 1 ? "|" + userAgent : ""));
  const data = Buffer.from(value);
  return "enc::v" + version + "::" + Buffer.from(data.map((value, index) => value ^ key[index % key.length])).toString("base64");
}

test("saved CPA v1 and v2 sessions decode, including Unicode and nested JSON", () => {
  const value = JSON.stringify({ state: { managementKey: "Bearer test-管理", apiBase: location.origin, rememberPassword: true }, version: 0 });
  for (const version of [1, 2]) {
    const saved = storage({ "cli-proxy-auth": encode(value, version) });
    assert.equal(Auth.readStoredKey(saved, location, "old-browser"), "test-管理");
    if (version === 2) assert.equal(Auth.readStoredKey(saved, location, "new-browser"), "test-管理");
  }
  assert.equal(Auth.readStoredKey(storage({ "cli-proxy-auth": JSON.stringify(value) }), location), "test-管理");
});

test("bad records do not suppress valid aliases and unsupported encodings are never tokens", () => {
  for (const bad of ["bad-json", "enc::v2::%%%", "enc::v3::abc"]) {
    assert.equal(Auth.readStoredKey(storage({ "cli-proxy-auth": bad, managementKey: encode(JSON.stringify("alias-key"), 2) }), location), "alias-key");
    assert.equal(Auth.readStoredKey(storage({ managementKey: bad.startsWith("enc::") ? bad : "enc::v3::abc" }), location), "");
  }
  assert.equal(Auth.readStoredKey({ getItem() { throw new Error("blocked"); } }, location), "");
});

test("host sessions for a different backend or without remember-password are not reused", () => {
  for (const state of [{ apiBase: "https://other.example", managementKey: "foreign" }, { rememberPassword: false, managementKey: "ephemeral" }]) {
    assert.equal(Auth.readStoredKey(storage({ "cli-proxy-auth": encode(JSON.stringify({ state }), 2), managementKey: "stale-alias" }), location), "");
  }
});

test("only exact parent and origin can announce ready or logout", () => {
  let receive, ready = 0, logout = 0;
  const win = { parent: {}, location, addEventListener(_type, handler) { receive = handler; }, removeEventListener(_type, handler) { assert.equal(handler, receive); receive = null; } };
  const stop = Auth.listenParentSession(win, { onReady: () => ready++, onLogout: () => logout++ });
  const base = { source: win.parent, origin: location.origin, data: { channel: Auth.CHANNEL, type: "logout" } };
  for (const changed of [{ source: {} }, { origin: "https://other.example" }, { data: { channel: "other", type: "logout" } }]) receive({ ...base, ...changed });
  assert.equal(logout, 0);
  receive(base); receive({ ...base, data: { channel: Auth.CHANNEL, type: "ready" } });
  assert.equal(logout, 1); assert.equal(ready, 1); stop();
});

test("logout terminates a pending bridge request and rejects its late response", async () => {
  const listeners = new Set();
  const win = { location, crypto: require("node:crypto").webcrypto, addEventListener(_type, fn) { listeners.add(fn); }, removeEventListener(_type, fn) { listeners.delete(fn); } };
  win.parent = { location, postMessage(data) {
    for (const fn of [...listeners]) fn({ source: win.parent, origin: location.origin, data: { channel: Auth.CHANNEL, type: "logout" } });
    for (const fn of [...listeners]) fn({ source: win.parent, origin: location.origin, data: { ...data, type: "response", managementKey: "late-key" } });
  } };
  assert.equal(await Auth.requestParentKey(win, 50), "");
  assert.equal(listeners.size, 0);
});
