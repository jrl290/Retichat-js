// Guards for EventEmitter.once().
//
// `once` is not a convenience here — Resource and Link both use it for terminal
// events, and firing twice is user-visible:
//
//   link.js      resource.once("concluded", ...)  -> emits "resource" to the app
//   resource.js  resource.once("concluded", ...)  -> unregister()
//   resource.js  resource.once("failed", ...)     -> unregister()
//
// A second "concluded" therefore delivers the same received resource to the UI
// twice (a duplicate message) and unregisters an already-unregistered transfer.
//
// The subtlety is that `emit` does not call listeners synchronously — it does
// `setTimeout(() => listener(...), 0)` per listener. So self-removal alone
// cannot make a listener fire-once: two emits in the same tick both queue a
// call to the wrapper before either has run. Only the `fired` flag closes that
// window. Removing the flag makes "the same event emitted twice in one tick"
// below fail with 2 calls.
//
// EventEmitter has no imports, so unlike the other suites here it can be
// imported directly under Node rather than lifted out of the source text.

import assert from "node:assert/strict";
import test from "node:test";

import EventEmitter from "./lib/rns/utils/events.js";

/** emit() defers listeners by a timer, so every assertion has to wait a tick. */
function drain() {
    return new Promise((resolve) => setTimeout(resolve, 5));
}

test("a once listener fires on the first emit", async () => {
    const emitter = new EventEmitter();
    const seen = [];
    emitter.once("concluded", (...args) => seen.push(args));

    emitter.emit("concluded", { hash: "abc" }, 7);
    await drain();

    assert.deepEqual(seen, [[{ hash: "abc" }, 7]], "the listener must receive every emitted argument");
});

test("the same event emitted twice in one tick still fires once", async () => {
    const emitter = new EventEmitter();
    let calls = 0;
    emitter.once("concluded", () => calls++);

    // Both emits queue their timer before either listener body runs, which is
    // exactly what a resource concluding from two code paths looks like.
    emitter.emit("concluded");
    emitter.emit("concluded");
    await drain();

    assert.equal(calls, 1, "a duplicate emit must not deliver the resource twice");
});

test("emits in separate ticks also fire once", async () => {
    const emitter = new EventEmitter();
    let calls = 0;
    emitter.once("concluded", () => calls++);

    emitter.emit("concluded");
    await drain();
    emitter.emit("concluded");
    await drain();

    assert.equal(calls, 1);
});

test("a once listener is removed from the listener list", async () => {
    const emitter = new EventEmitter();
    emitter.once("concluded", () => {});

    emitter.emit("concluded");
    await drain();

    // Left in place, these accumulate for the lifetime of the link: every
    // resource attaches two of them.
    assert.deepEqual(emitter.eventListenersMap.get("concluded"), [], "the wrapper must not be retained");
});

test("once listeners for different events are independent", async () => {
    const emitter = new EventEmitter();
    const fired = [];
    emitter.once("concluded", () => fired.push("concluded"));
    emitter.once("failed", () => fired.push("failed"));

    emitter.emit("failed", "checksum mismatch");
    await drain();

    assert.deepEqual(fired, ["failed"], "concluding must not be triggered by a failure");
    assert.equal(emitter.eventListenersMap.get("concluded").length, 1, "the unrelated listener must survive");
});

test("a once listener removing itself does not skip other listeners", async () => {
    const emitter = new EventEmitter();
    const fired = [];
    emitter.once("concluded", () => fired.push("first"));
    emitter.on("concluded", () => fired.push("second"));

    emitter.emit("concluded");
    await drain();

    // `off` rebuilds the array while emit is iterating it; if it mutated in
    // place instead, the second listener would be skipped by the index shift.
    assert.deepEqual(fired, ["first", "second"]);
});
