/* Delegated generated UI events. Attribute values remain data, never JavaScript. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardEvents = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  function bind(doc, handlers, onError = () => {}) {
    const listeners = [];
    const listen = (type, fn) => { doc.addEventListener(type, fn); listeners.push([type, fn]); };
    listen("click", event => {
      const element = event.target.closest && event.target.closest("[data-action]");
      if (!element || element.disabled) return;
      const handler = handlers.actions[element.dataset.action];
      if (!handler) return;
      event.preventDefault();
      event.stopPropagation();
      const value = element.dataset.value || "";
      try {
        const result = handler(value, element, event);
        if (result && typeof result.then === "function") {
          element.disabled = true;
          result.catch(onError).finally(() => { element.disabled = false; });
        }
      } catch (error) { onError(error); }
    });
    for (const [type, attribute] of [["change", "change"], ["input", "input"]]) {
      listen(type, event => {
        const element = event.target;
        const handler = element.dataset && handlers[attribute] && handlers[attribute][element.dataset[attribute]];
        if (handler) handler(element.dataset.value || "", element, event);
      });
    }
    for (const type of ["dragstart", "dragover", "drop", "dragend"]) {
      listen(type, event => {
        const row = event.target.closest && event.target.closest(".key-row[data-key]");
        if (row && handlers.drag[type]) {
          try { const result = handlers.drag[type](event, row.dataset.key); if (result && result.catch) result.catch(onError); }
          catch (error) { onError(error); }
        }
      });
    }
    for (const type of ["pointerover", "pointermove", "pointerout"]) {
      listen(type, event => {
        const element = event.target.closest && event.target.closest("[data-tip-index]");
        if (element && handlers.tip[type]) handlers.tip[type](event, Number(element.dataset.tipIndex));
      });
    }
    return () => { for (const [type, listener] of listeners) doc.removeEventListener(type, listener); };
  }
  return { bind };
});
