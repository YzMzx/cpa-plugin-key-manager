const test = require("node:test");
const assert = require("node:assert/strict");
const Dialogs = require("./dialogs.js");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// This models API/event ordering, not browser rendering or native focus trapping.
function fixture({ overlay = false, discrete = false, displayTransition = false, closedBy = false } = {}) {
  const listeners = new Map(), attributes = new Map(), queued = [], probes = [];
  const calls = { show: 0, close: 0, cleanup: 0, animations: [], styles: 0, supports: [] };
  const prototype = closedBy ? { closedBy: "any" } : {};
  const doc = {
    defaultView: {
      HTMLDialogElement: { prototype },
      CSS: { supports(property, value) {
        calls.supports.push([property, value]);
        return property === "overlay" ? overlay : property === "transition-behavior" && discrete;
      } },
      getComputedStyle(probe) {
        calls.styles++;
        return { display: probe.style.display === "none" && !displayTransition ? "none" : "block" };
      }
    },
    body: { appendChild(probe) { probe.connected = true; } },
    createElement(tag) {
      assert.equal(tag, "div");
      const probe = { style: {}, connected: false, remove() { this.connected = false; this.removed = true; } };
      probes.push(probe);
      return probe;
    }
  };
  Object.defineProperty(doc, "activeElement", { get() { assert.fail("focus belongs to the native dialog"); } });
  const dialog = {
    ownerDocument: doc, open: false, returnValue: "old-result", animations: [],
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
    setAttribute(name, value) { attributes.set(name, value); },
    removeAttribute(name) { attributes.delete(name); },
    hasAttribute(name) { return attributes.has(name); },
    showModal() { assert.equal(this.open, false); calls.show++; this.open = true; },
    close() {
      assert.equal(this.open, true);
      calls.close++; this.open = false;
      queued.push(() => emit("close"));
    },
    getAnimations(options) {
      calls.animations.push({ options, closing: attributes.has("data-closing") });
      return this.animations;
    },
    getBoundingClientRect() { return { left: 100, right: 300, top: 100, bottom: 250 }; },
    focus() { assert.fail("manual focus must not override native focus"); },
    querySelector() { assert.fail("manual focus must not select a control"); }
  };
  function emit(type, fields = {}) {
    const event = { target: dialog, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...fields };
    for (const listener of listeners.get(type) || []) listener(event);
    return event;
  }
  const controller = Dialogs.create(dialog, { onClose() { calls.cleanup++; } });
  return {
    dialog, controller, calls, probes, listeners, emit,
    flushClose() { while (queued.length) queued.shift()(); },
    cancel() { const event = emit("cancel"); if (!event.defaultPrevented && dialog.open) dialog.close(); return event; },
    pointer(type, x, y, fields = {}) { return emit(type, { clientX: x, clientY: y, button: 0, isPrimary: true, ...fields }); }
  };
}

function animate(f) {
  const pending = deferred();
  f.dialog.animations = [{ finished: pending.promise }];
  return pending;
}

const turn = async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); };

test("showModal is idempotent and leaves focus to the browser", () => {
  const f = fixture();
  f.dialog.setAttribute("data-closing", ""); f.dialog.setAttribute("data-immediate", "");
  f.controller.show(); f.controller.show();
  assert.equal(f.calls.show, 1);
  assert.equal(f.controller.isOpen(), true);
  assert.equal(f.dialog.returnValue, "");
  assert.equal(f.dialog.hasAttribute("data-closing"), false);
  assert.equal(f.dialog.hasAttribute("data-immediate"), false);
});

test("close is harmless when closed and cleanup runs once per opening", async () => {
  const f = fixture();
  await f.controller.close();
  assert.equal(f.calls.cleanup, 0);
  f.controller.show();
  await f.controller.close(); await f.controller.close();
  assert.equal(f.calls.close, 1); assert.equal(f.calls.cleanup, 1);
  f.flushClose(); f.emit("close");
  assert.equal(f.calls.cleanup, 1);
  f.controller.show(); await f.controller.close(); f.flushClose();
  assert.equal(f.calls.cleanup, 2);
});

test("external native close resets returnValue and cleans up once", () => {
  const f = fixture(); f.controller.show();
  f.dialog.returnValue = "saved"; f.dialog.close();
  assert.equal(f.calls.cleanup, 0);
  f.flushClose(); f.emit("close");
  assert.equal(f.calls.cleanup, 1);
  assert.equal(f.controller.isOpen(), false);
  assert.equal(f.dialog.returnValue, "");
});

test("fallback cancel routes through animation and repeated cancel does not repeat cleanup", async () => {
  const f = fixture(), pending = animate(f); f.controller.show();
  assert.equal(f.cancel().defaultPrevented, true);
  assert.equal(f.cancel().defaultPrevented, true);
  assert.equal(f.calls.cleanup, 1); assert.equal(f.dialog.open, true);
  assert.equal(f.controller.isOpen(), false);
  pending.resolve(); await turn(); f.flushClose();
  assert.equal(f.calls.close, 1); assert.equal(f.calls.cleanup, 1);
});

test("light dismiss requires primary left-button press and release outside the bounds", async t => {
  const cases = [
    ["left backdrop", [99, 150], [99, 150], {}, {}, true],
    ["right backdrop", [301, 150], [301, 150], {}, {}, true],
    ["top backdrop", [150, 99], [150, 99], {}, {}, true],
    ["bottom backdrop", [150, 251], [150, 251], {}, {}, true],
    ["dialog padding", [101, 101], [101, 101], {}, {}, false],
    ["left border", [100, 150], [100, 150], {}, {}, false],
    ["right border", [300, 150], [300, 150], {}, {}, false],
    ["top border", [150, 100], [150, 100], {}, {}, false],
    ["bottom border", [150, 250], [150, 250], {}, {}, false],
    ["selection drag out", [150, 150], [99, 150], {}, {}, false],
    ["drag into content", [99, 150], [150, 150], {}, {}, false],
    ["right click", [99, 150], [99, 150], { button: 2 }, { button: 2 }, false],
    ["nonprimary press", [99, 150], [99, 150], { isPrimary: false }, {}, false],
    ["nonprimary release", [99, 150], [99, 150], {}, { isPrimary: false }, false],
    ["nonleft release", [99, 150], [99, 150], {}, { button: 2 }, false]
  ];
  for (const [name, down, up, downFields, upFields, dismiss] of cases) await t.test(name, () => {
    const f = fixture(); f.controller.show();
    f.pointer("pointerdown", ...down, downFields); f.pointer("pointerup", ...up, upFields);
    assert.equal(f.calls.close, dismiss ? 1 : 0);
    assert.equal(f.calls.cleanup, dismiss ? 1 : 0);
    assert.equal(f.controller.isOpen(), !dismiss);
  });
});

test("pointer cancel and pointerup without a new press cannot dismiss", () => {
  const f = fixture(); f.controller.show();
  f.pointer("pointerup", 10, 10);
  f.pointer("pointerdown", 10, 10); f.emit("pointercancel"); f.pointer("pointerup", 10, 10);
  assert.equal(f.calls.close, 0);
  f.pointer("pointerdown", 10, 10); f.pointer("pointerup", 10, 10); f.flushClose();
  f.controller.show(); f.pointer("pointerup", 10, 10);
  assert.equal(f.calls.close, 1); assert.equal(f.controller.isOpen(), true);
});

test("native closedBy support does not install duplicate pointer-dismiss handlers", () => {
  const f = fixture({ closedBy: true }); f.controller.show();
  for (const name of ["pointerdown", "pointerup", "pointercancel"]) assert.equal(f.listeners.has(name), false);
  f.pointer("pointerdown", 10, 10); f.pointer("pointerup", 10, 10);
  assert.equal(f.dialog.open, true);
  f.dialog.close(); f.flushClose();
  assert.equal(f.calls.cleanup, 1);
});

test("fallback waits for every subtree animation while logically closing immediately", async () => {
  const f = fixture(), first = deferred(), second = deferred();
  f.dialog.animations = [{ finished: first.promise }, { finished: second.promise }]; f.controller.show();
  const closing = f.controller.close();
  assert.equal(f.controller.close(), closing);
  assert.equal(f.calls.cleanup, 1); assert.equal(f.controller.isOpen(), false);
  assert.equal(f.dialog.open, true); assert.equal(f.dialog.hasAttribute("data-closing"), true);
  assert.deepEqual(f.calls.animations, [{ options: { subtree: true }, closing: true }]);
  first.resolve(); await turn(); assert.equal(f.calls.close, 0);
  second.resolve(); await closing; f.flushClose();
  assert.equal(f.calls.close, 1); assert.equal(f.calls.cleanup, 1);
  assert.equal(f.dialog.hasAttribute("data-closing"), false);
});

test("rejected animation is settled without rejecting close or repeating cleanup", async () => {
  const f = fixture(), pending = animate(f); f.controller.show();
  const closing = f.controller.close(); pending.reject(new Error("animation canceled"));
  await assert.doesNotReject(closing); f.flushClose();
  assert.equal(f.dialog.open, false); assert.equal(f.calls.cleanup, 1);
});

test("fallback has a bounded timeout when an animation never finishes", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(); animate(f); f.controller.show();
  const closing = f.controller.close();
  t.mock.timers.tick(1999); await turn(); assert.equal(f.dialog.open, true);
  t.mock.timers.tick(1); await closing; f.flushClose();
  assert.equal(f.calls.close, 1); assert.equal(f.calls.cleanup, 1);
});

test("rapid reopen invalidates the old animation close without hiding the new draft", async () => {
  const f = fixture(), pending = animate(f); f.controller.show();
  const oldClose = f.controller.close(); f.controller.show();
  assert.equal(f.calls.show, 1); assert.equal(f.controller.isOpen(), true);
  assert.equal(f.dialog.hasAttribute("data-closing"), false);
  pending.resolve(); await oldClose;
  assert.equal(f.calls.close, 0); assert.equal(f.calls.cleanup, 1);
  f.dialog.animations = []; await f.controller.close(); f.flushClose();
  assert.equal(f.calls.close, 1); assert.equal(f.calls.cleanup, 2);
});

test("a queued old close event cannot clear a reopened dialog", async () => {
  const f = fixture(); f.controller.show(); await f.controller.close();
  f.controller.show(); f.dialog.returnValue = "new-draft"; f.flushClose();
  assert.equal(f.controller.isOpen(), true); assert.equal(f.calls.cleanup, 1);
  assert.equal(f.dialog.returnValue, "new-draft");
  await f.controller.close(); f.flushClose();
  assert.equal(f.calls.cleanup, 2); assert.equal(f.dialog.returnValue, "");
});

test("security close bypasses animation and invalidates an in-flight fade immediately", async () => {
  const f = fixture(), pending = animate(f); f.controller.show();
  const oldClose = f.controller.close();
  await f.controller.close({ immediate: true });
  assert.equal(f.dialog.open, false); assert.equal(f.calls.close, 1);
  assert.equal(f.dialog.hasAttribute("data-immediate"), true);
  assert.equal(f.dialog.hasAttribute("data-closing"), false);
  assert.equal(f.calls.cleanup, 1);
  f.controller.show(); f.flushClose(); pending.resolve(); await oldClose;
  assert.equal(f.controller.isOpen(), true); assert.equal(f.calls.close, 1);
  assert.equal(f.dialog.hasAttribute("data-immediate"), false);
  await f.controller.close({ immediate: true }); f.flushClose();
  assert.equal(f.calls.cleanup, 2); assert.equal(f.calls.animations.length, 1);
});

test("security close skips the display probe and animation API altogether", async () => {
  const f = fixture({ overlay: true, discrete: true, displayTransition: true });
  animate(f); f.controller.show(); await f.controller.close({ immediate: true });
  assert.equal(f.dialog.open, false); assert.equal(f.calls.cleanup, 1);
  assert.equal(f.calls.animations.length, 0); assert.equal(f.probes.length, 0);
  f.flushClose(); await f.controller.close({ immediate: true });
  assert.equal(f.calls.cleanup, 1);
});

test("native top-layer exit closes directly and caches the removed display probe", async () => {
  const f = fixture({ overlay: true, discrete: true, displayTransition: true });
  animate(f); f.controller.show(); await f.controller.close(); f.flushClose();
  assert.equal(f.dialog.open, false); assert.equal(f.calls.animations.length, 0);
  assert.equal(f.probes.length, 1); assert.equal(f.probes[0].removed, true);
  assert.equal(f.probes[0].connected, false); assert.equal(f.calls.styles, 2);
  assert.match(f.probes[0].style.cssText, /transition:display 1s allow-discrete !important/);
  f.controller.show(); await f.controller.close(); f.flushClose();
  assert.equal(f.probes.length, 1); assert.equal(f.calls.cleanup, 2);
});

test("native supported cancel keeps browser default close and cleans up only once", () => {
  const f = fixture({ overlay: true, discrete: true, displayTransition: true, closedBy: true });
  f.controller.show(); assert.equal(f.cancel().defaultPrevented, false);
  assert.equal(f.calls.cleanup, 1); assert.equal(f.dialog.open, false);
  f.flushClose(); assert.equal(f.calls.cleanup, 1); assert.equal(f.calls.animations.length, 0);
});

test("CSS parsing support without real display transitions still uses the exit fallback", async () => {
  const f = fixture({ overlay: true, discrete: true, displayTransition: false });
  const pending = animate(f); f.controller.show(); const closing = f.controller.close();
  assert.equal(f.probes.length, 1); assert.equal(f.probes[0].removed, true);
  assert.equal(f.dialog.open, true); assert.equal(f.dialog.hasAttribute("data-closing"), true);
  assert.equal(f.calls.animations.length, 1);
  pending.resolve(); await closing; f.flushClose();
  f.dialog.animations = []; f.controller.show(); await f.controller.close(); f.flushClose();
  assert.equal(f.probes.length, 1); assert.equal(f.calls.cleanup, 2);
});

test("missing overlay or discrete support never mistakes parsing for native top-layer exit", async t => {
  for (const support of [{ overlay: false, discrete: true }, { overlay: true, discrete: false }]) await t.test(JSON.stringify(support), async () => {
    const f = fixture({ ...support, displayTransition: true }), pending = animate(f);
    f.controller.show(); const closing = f.controller.close();
    assert.equal(f.probes.length, 0); assert.equal(f.dialog.open, true);
    assert.equal(f.calls.animations.length, 1);
    pending.resolve(); await closing; f.flushClose(); assert.equal(f.calls.cleanup, 1);
  });
});
