/* Native modal lifecycle; CSS owns entry/exit, with a small top-layer exit fallback. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardDialogs = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const displaySupport = new WeakMap();
  function supportsTopLayerExit(doc) {
    const view = doc.defaultView;
    if (!view?.CSS?.supports?.("overlay", "auto") || !view.CSS.supports("transition-behavior", "allow-discrete")) return false;
    if (displaySupport.has(doc)) return displaySupport.get(doc);
    // Parsing allow-discrete is insufficient in browsers that don't transition display.
    const probe = doc.createElement("div");
    probe.style.cssText = "position:fixed;pointer-events:none;transition:display 1s allow-discrete !important;display:block;";
    doc.body.appendChild(probe);
    view.getComputedStyle(probe).display;
    probe.style.display = "none";
    const supported = view.getComputedStyle(probe).display === "block";
    probe.remove(); displaySupport.set(doc, supported);
    return supported;
  }
  function create(dialog, { onClose = () => {} } = {}) {
    const doc = dialog.ownerDocument;
    let generation = 0, closing = null, notified = false;
    const notify = () => { if (!notified) { notified = true; onClose(); } };
    function show() {
      generation++; closing = null; notified = false;
      dialog.removeAttribute("data-closing");
      dialog.removeAttribute("data-immediate");
      dialog.returnValue = "";
      if (!dialog.open) dialog.showModal();
    }
    function close({ immediate = false } = {}) {
      if (immediate) {
        generation++; closing = null;
        // Authentication loss must not leave sensitive content in a fading top layer.
        dialog.setAttribute("data-immediate", "");
        dialog.removeAttribute("data-closing");
        if (dialog.open) { notify(); dialog.close(); }
        return Promise.resolve();
      }
      if (!dialog.open) return Promise.resolve();
      if (closing) return closing;
      notify();
      if (supportsTopLayerExit(doc)) { dialog.close(); return Promise.resolve(); }
      const version = ++generation;
      dialog.setAttribute("data-closing", "");
      const animations = dialog.getAnimations({ subtree: true });
      if (!animations.length) { dialog.removeAttribute("data-closing"); dialog.close(); return Promise.resolve(); }
      closing = (async () => {
        let timer;
        try {
          await Promise.race([
            Promise.allSettled(animations.map(animation => animation.finished)),
            new Promise(resolve => { timer = setTimeout(resolve, 2000); })
          ]);
        } finally { clearTimeout(timer); }
        if (generation !== version) return;
        closing = null; dialog.removeAttribute("data-closing");
        if (dialog.open) dialog.close();
      })();
      return closing;
    }
    dialog.addEventListener("cancel", event => {
      if (supportsTopLayerExit(doc)) notify();
      else { event.preventDefault(); close(); }
    });
    dialog.addEventListener("close", () => {
      // A queued close event from a previous opening must not clear a new draft.
      if (dialog.open) return;
      generation++; closing = null; dialog.removeAttribute("data-closing");
      notify(); dialog.returnValue = "";
    });
    const prototype = doc.defaultView?.HTMLDialogElement?.prototype;
    if (!prototype || !("closedBy" in prototype)) {
      let pressedOutside = false;
      const outside = event => {
        const rect = dialog.getBoundingClientRect();
        return event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
      };
      dialog.addEventListener("pointerdown", event => { pressedOutside = event.isPrimary !== false && event.button === 0 && outside(event); });
      dialog.addEventListener("pointerup", event => {
        const dismiss = pressedOutside && event.isPrimary !== false && event.button === 0 && outside(event);
        pressedOutside = false;
        if (dismiss) close();
      });
      dialog.addEventListener("pointercancel", () => { pressedOutside = false; });
    }
    return { show, close, isOpen: () => dialog.open && !notified };
  }
  return { create };
});
