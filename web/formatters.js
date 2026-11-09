/* Calendar calculations use the configured IANA zone, including DST boundaries. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardFormat = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const DEFAULT_TIMEZONE = "Asia/Shanghai";
  const dateFormats = new Map();
  const stampFormats = new Map();
  const validZones = new Map([[DEFAULT_TIMEZONE, DEFAULT_TIMEZONE]]);
  function timezone(raw) {
    const name = String(raw || DEFAULT_TIMEZONE);
    if (!validZones.has(name)) {
      try { new Intl.DateTimeFormat("en", { timeZone: name }); validZones.set(name, name); }
      catch (_) { validZones.set(name, DEFAULT_TIMEZONE); }
    }
    return validZones.get(name);
  }
  function formatter(cache, zone, options) {
    zone = timezone(zone);
    if (!cache.has(zone)) cache.set(zone, new Intl.DateTimeFormat("en-CA", { timeZone: zone, ...options }));
    return cache.get(zone);
  }
  function dateParts(date, zone) {
    const parts = formatter(dateFormats, zone, { year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(date);
    const get = kind => Number(parts.find(part => part.type === kind).value);
    return { y: get("year"), m: get("month"), d: get("day") };
  }
  function startOfDay(y, m, d, zone) {
    // Binary-search the first instant of the target local calendar day. This also
    // handles zones whose DST transition skips midnight (a day can begin at 01:00).
    const normalized = new Date(Date.UTC(y, m - 1, d));
    const target = normalized.getUTCFullYear() * 10000 + (normalized.getUTCMonth() + 1) * 100 + normalized.getUTCDate();
    let lo = normalized.getTime() - 36 * 3600000;
    let hi = normalized.getTime() + 36 * 3600000;
    while (hi - lo > 1) {
      const mid = Math.floor((lo + hi) / 2);
      const p = dateParts(new Date(mid), zone);
      if (p.y * 10000 + p.m * 100 + p.d >= target) hi = mid;
      else lo = mid;
    }
    return new Date(hi);
  }
  function rangeBounds(range, zone, now = new Date(), custom = {}) {
    zone = timezone(zone);
    const today = dateParts(now, zone);
    const day = offset => startOfDay(today.y, today.m, today.d + offset, zone);
    let from = day(-6), to = new Date(day(1).getTime() - 1);
    if (range === "today") from = day(0);
    else if (range === "yesterday") { from = day(-1); to = new Date(day(0).getTime() - 1); }
    else if (range === "30d") from = day(-29);
    else if (range === "custom") {
      const parse = (raw, fallback, next) => {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(raw || "")) return fallback;
        const [y, m, d] = raw.split("-").map(Number);
        const test = new Date(Date.UTC(y, m - 1, d));
        if (test.getUTCFullYear() !== y || test.getUTCMonth() + 1 !== m || test.getUTCDate() !== d) return fallback;
        const result = startOfDay(y, m, d + (next ? 1 : 0), zone);
        return next ? new Date(result.getTime() - 1) : result;
      };
      from = parse(custom.from, from, false); to = parse(custom.to, to, true);
    }
    return { from, to };
  }
  function dateTime(raw, zone) {
    const text = String(raw || "").trim();
    if (!text) return "-";
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return text;
    const parts = formatter(stampFormats, zone, { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).formatToParts(date);
    const get = kind => parts.find(part => part.type === kind).value;
    return get("year") + "-" + get("month") + "-" + get("day") + " " + get("hour") + ":" + get("minute") + ":" + get("second");
  }
  return { DEFAULT_TIMEZONE, timezone, dateParts, startOfDay, rangeBounds, dateTime };
});
