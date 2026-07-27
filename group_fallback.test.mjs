import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./lib/rns/group_fallback.js", import.meta.url), "utf8");
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const { GroupDeliveryEvidence, GroupFallbackRegistry } = await import(moduleUrl);

function harness() {
    const timers = new Map();
    let nextTimer = 1;
    const registry = new GroupFallbackRegistry(
        callback => {
            const timer = nextTimer++;
            timers.set(timer, callback);
            return timer;
        },
        timer => timers.delete(timer),
    );
    return {
        registry,
        fire() {
            for (const [timer, callback] of [...timers]) {
                timers.delete(timer);
                callback();
            }
        },
    };
}

test("direct proof suppresses group propagation fallback", () => {
    const { registry, fire } = harness();
    let fallbacks = 0;
    registry.schedule("packet", 5_000, () => fallbacks++);

    assert.equal(registry.prove("packet"), true);
    fire();
    assert.equal(fallbacks, 0);
});

test("missing proof starts exactly one fallback", () => {
    const { registry, fire } = harness();
    let fallbacks = 0;
    assert.equal(registry.schedule("packet", 5_000, () => fallbacks++), true);
    assert.equal(registry.schedule("packet", 5_000, () => fallbacks++), false);

    fire();
    fire();
    assert.equal(fallbacks, 1);
    assert.equal(registry.prove("packet"), false);
});

test("clear cancels pending fallbacks", () => {
    const { registry, fire } = harness();
    let fallbacks = 0;
    registry.schedule("one", 5_000, () => fallbacks++);
    registry.schedule("two", 5_000, () => fallbacks++);

    registry.clear();
    fire();
    assert.equal(fallbacks, 0);
});

test("default timer wrappers preserve the host receiver", () => {
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    const host = globalThis;
    let callback;
    let cleared = null;
    globalThis.setTimeout = function (scheduled) {
        assert.equal(this, host);
        callback = scheduled;
        return 42;
    };
    globalThis.clearTimeout = function (timer) {
        assert.equal(this, host);
        cleared = timer;
    };

    try {
        const registry = new GroupFallbackRegistry();
        registry.schedule("packet", 5_000, () => {});
        assert.equal(registry.prove("packet"), true);
        assert.equal(cleared, 42);
        assert.equal(typeof callback, "function");
    } finally {
        globalThis.setTimeout = originalSetTimeout;
        globalThis.clearTimeout = originalClearTimeout;
    }
});

test("first delivery evidence wins and settles once", async () => {
    const directFirst = new GroupDeliveryEvidence("member-a");
    assert.equal(directFirst.fulfill("direct"), true);
    assert.equal(directFirst.fulfill("propagation"), false);
    assert.deepEqual(await directFirst.promise, {memberHash: "member-a", method: "direct"});

    const propagationFirst = new GroupDeliveryEvidence("member-b");
    assert.equal(propagationFirst.fulfill("propagation"), true);
    assert.equal(propagationFirst.fulfill("direct"), false);
    assert.deepEqual(await propagationFirst.promise, {memberHash: "member-b", method: "propagation"});
});