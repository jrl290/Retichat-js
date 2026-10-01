/**
 * test_virtual_time.mjs, the virtual clock that keeps the suite's clock
 * tests (link_request_resource.test.mjs, resource.test.mjs) independent of
 * how loaded the machine is. Its contract, as those tests rely on it:
 *
 *   - work takes no virtual time: a timer set before a long computation still
 *     comes after the real macrotasks that computation queues;
 *   - the clock moves only when no counted macrotask (setImmediate, a 0 or
 *     1 ms timer) is pending, and then to the earliest timer, which runs
 *     alone, with every microtask run before the next;
 *   - Date.now() reads the clock; a cleared timer never runs; clearing a
 *     counted macrotask releases the clock;
 *   - uninstall() puts the real functions back and drops waiting timers.
 *
 * Run: node --test virtual_time.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import { installVirtualTime, useVirtualTime } from "./test_virtual_time.mjs";
import { within } from "./test_link_pair.mjs";

const realSetTimeout = globalThis.setTimeout;
const realDateNow = Date.now;

/** Burn `ms` of wall-clock time on the CPU, as a loaded machine would. */
function busy(ms) {
    const until = realDateNow() + ms;
    while (realDateNow() < until) { /* spin */ }
}

test("work takes no virtual time: a 150 ms timer comes after the macrotasks a 200 ms computation queues", async (t) => {
    const clock = useVirtualTime(t);
    const order = [];
    const budget = new Promise((resolve) => setTimeout(() => { order.push(`budget at ${clock.elapsed()}`); resolve(); }, 150));
    busy(200);                                    // on the wall clock the budget is overdue
    setTimeout(() => order.push("event"), 0);
    setImmediate(() => order.push("delivery"));
    await budget;
    assert.equal(order.length, 3, order.join(", "));
    assert.equal(order.at(-1), "budget at 150", "the budget runs out only after the work is done, at exactly 150 ms");
    assert.deepEqual(order.slice(0, 2).sort(), ["delivery", "event"]);
});

test("the clock does not move while a chain of macrotasks runs, however long the chain", async (t) => {
    const clock = useVirtualTime(t);
    const order = [];
    const fired = new Promise((resolve) => setTimeout(() => { order.push("timer"); resolve(); }, 10));
    let hops = 0;
    await new Promise((resolve) => {
        const hop = () => {
            hops++;
            busy(2);
            if (hops === 50) { order.push("chain done"); resolve(); return; }
            if (hops % 2) setImmediate(hop); else setTimeout(hop, 0);
        };
        setImmediate(hop);
    });
    assert.equal(clock.elapsed(), 0, "100 ms of hops took no virtual time");
    await fired;
    assert.deepEqual(order, ["chain done", "timer"]);
    assert.equal(clock.elapsed(), 10);
});

test("timers run earliest first, ties in the order they were set, one per macrotask with microtasks between", async (t) => {
    const clock = useVirtualTime(t);
    const order = [];
    const all = Promise.all([
        new Promise((resolve) => setTimeout(() => { order.push(`A@${clock.elapsed()}`); resolve(); }, 20)),
        new Promise((resolve) => setTimeout(() => {
            order.push(`B@${clock.elapsed()}`);
            Promise.resolve().then(() => order.push("B's microtask"));
            resolve();
        }, 10)),
        new Promise((resolve) => setTimeout(() => { order.push(`C@${clock.elapsed()}`); resolve(); }, 10)),
    ]);
    await all;
    assert.deepEqual(order, ["B@10", "B's microtask", "C@10", "A@20"]);
});

test("Date.now() reads the virtual clock, and only timers move it", async (t) => {
    const clock = useVirtualTime(t);
    const t0 = Date.now();
    busy(50);
    assert.equal(Date.now(), t0, "50 ms on the CPU: no virtual time");
    await new Promise((resolve) => setTimeout(resolve, 2_500));
    assert.equal(Date.now() - t0, 2_500);
    assert.equal(clock.now(), Date.now());
});

test("a cleared timer never runs; clearing a counted macrotask releases the clock", async (t) => {
    const clock = useVirtualTime(t);
    const ran = [];
    const cleared = setTimeout(() => ran.push("cleared timer"), 5);
    clearTimeout(cleared);
    clearImmediate(setImmediate(() => ran.push("cleared immediate")));
    clearTimeout(setTimeout(() => ran.push("cleared 0 ms timer"), 0));
    assert.equal(clock.pending(), 0, "a cleared macrotask no longer holds the clock");
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.deepEqual(ran, []);
    assert.equal(clock.elapsed(), 30, "the clock moved: nothing cleared still holds it");
});

test("a hang fails at the bound's virtual time instead of waiting it out", async (t) => {
    const clock = useVirtualTime(t);
    await assert.rejects(within(new Promise(() => {}), 20_000, "nothing"), /nothing did not settle within 20000 ms/);
    assert.equal(clock.elapsed(), 20_000);
});

test("uninstall() puts the real functions back and drops waiting timers; setInterval is refused", async () => {
    const saved = [globalThis.setTimeout, globalThis.clearTimeout, globalThis.setImmediate, globalThis.clearImmediate, globalThis.setInterval, Date.now];
    const clock = installVirtualTime();
    assert.throws(() => installVirtualTime(), /already installed/);
    assert.throws(() => setInterval(() => {}, 10), /not supported/);
    let ran = false;
    setTimeout(() => { ran = true; }, 5);
    assert.equal(clock.waiting(), 1);
    clock.uninstall();
    assert.deepEqual([globalThis.setTimeout, globalThis.clearTimeout, globalThis.setImmediate, globalThis.clearImmediate, globalThis.setInterval, Date.now], saved);
    assert.equal(clock.waiting(), 0);
    await new Promise((resolve) => realSetTimeout(resolve, 20));
    assert.equal(ran, false, "a timer left waiting at uninstall belonged to the test");
});
