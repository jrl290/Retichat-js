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
 *   - uninstall() puts the real functions back and drops waiting timers;
 *   - a livelock (LIVELOCK_TURNS macrotasks in a row without the clock
 *     moving) is red and is stopped: the test's bound is still reached, a
 *     test with no bound fails instead of hanging, and the loop ends with
 *     its test.
 *
 * Run: node --test virtual_time.test.mjs
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { LIVELOCK_TURNS, installVirtualTime, useVirtualTime } from "./test_virtual_time.mjs";
import { within } from "./test_link_pair.mjs";

const realSetTimeout = globalThis.setTimeout;
const realSetImmediate = globalThis.setImmediate;
const realDateNow = Date.now;

/** `n` real turns of the event loop, outside any virtual clock. */
async function realTurns(n) {
    for (let i = 0; i < n; i++) await new Promise((resolve) => realSetImmediate(resolve));
}

/**
 * Two ends that answer each other again and again, the shape of a transfer
 * that asks for the same window forever: each hop is a delivery (an
 * immediate) and re-arms a watchdog. So that a broken clock makes these
 * tests red rather than hanging the file, the loop gives up by itself at
 * three times the livelock bound, and `stop()` ends it from outside.
 */
function pingPong() {
    const loop = { hops: 0, watchdogs: 0, stopped: false, stop() { loop.stopped = true; } };
    let watchdog = null;
    const hop = () => {
        if (loop.stopped || loop.hops === 3 * LIVELOCK_TURNS) return;
        loop.hops++;
        clearTimeout(watchdog);
        watchdog = setTimeout(() => { loop.watchdogs++; }, 50);
        setImmediate(hop);
    };
    setImmediate(hop);
    return loop;
}

/** A run of `n` macrotasks, alternating an immediate and a 0 ms timer, that ends by itself. */
const run = (n) => new Promise((resolve) => {
    let left = n;
    const hop = () => {
        if (--left === 0) resolve();
        else if (left % 2) setImmediate(hop);
        else setTimeout(hop, 0);
    };
    setImmediate(hop);
});

// Should a broken clock still hang one of these tests, this per-test
// timeout turns that into red. It is wall clock, so it is a failure bound
// only and far beyond any load: the slowest of them, 100,000 hops, takes
// about 1.5 s on an idle machine and 12 s under the suite at load 40.
const HANG_BOUND = { timeout: 600_000 };

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

test("a livelock is stopped where it is declared: the test's bound is reached, and uninstall() makes it red", HANG_BOUND, async () => {
    const said = [];
    const clock = installVirtualTime({ onLivelock: (line) => said.push(line) });
    const loop = pingPong();
    try {
        await assert.rejects(within(new Promise(() => {}), 5_000, "the transfer"), /the transfer did not settle within 5000 ms/,
            "the bound is reached although the loop never waited for a timer");
        assert.equal(loop.hops, LIVELOCK_TURNS, "the loop ran exactly LIVELOCK_TURNS macrotasks, then its next one was dropped");
        assert.deepEqual(clock.livelock(), { at: 0, dropped: 1 }, "declared before the clock ever moved");
        assert.deepEqual(said, [
            "⚠ test_virtual_time.mjs: livelock: 100000 macrotasks ran one after another at 0 virtual ms without the clock " +
            "moving (work that never waits for a timer); dropping every macrotask from here on: the loop stops, and the " +
            "test fails at its bound or as never settling",
        ], "said once, as it happened");
        assert.equal(clock.elapsed(), 5_000, "then the clock moved as it always does: the bound fired at its virtual time");
        assert.equal(loop.watchdogs, 1, "the loop's last watchdog ran on the way, at 50 ms");
        assert.throws(() => clock.uninstall(), /virtual time: a livelock: 100000 macrotasks ran one after another at 0 virtual ms/,
            "uninstall() makes the test red, whatever happened after");
        const hops = loop.hops;
        await realTurns(20);
        assert.equal(loop.hops, hops, "the loop does not outlive its test");
    } finally {
        loop.stop();
        try { clock.uninstall(); } catch { /* the livelock's own error: an assertion above has failed */ }
    }
});

test("one macrotask short of the bound is not a livelock, and the count starts again when the clock moves", HANG_BOUND, async () => {
    const clock = installVirtualTime({ livelockTurns: 200 });
    try {
        const fired = new Promise((resolve) => setTimeout(resolve, 10));
        await run(199);
        assert.equal(clock.elapsed(), 0, "199 macrotasks, immediates and 0 ms timers: the clock still holds for them");
        await fired;
        assert.equal(clock.elapsed(), 10);
        await run(199);
        await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(clock.elapsed(), 20);
        assert.equal(clock.livelock(), null);
    } finally {
        clock.uninstall();                         // no livelock: does not throw
    }
    assert.throws(() => installVirtualTime({ livelockTurns: 0 }), /livelockTurns must be at least 1/);
});

test("a run that reaches the bound is a livelock and red, even if it would have ended by itself", HANG_BOUND, async () => {
    const said = [];
    const clock = installVirtualTime({ livelockTurns: 200, onLivelock: (line) => said.push(line) });
    let threw = null;
    try {
        await run(200);                            // its 200th macrotask resolves it: nothing left to drop
        assert.deepEqual(clock.livelock(), { at: 0, dropped: 0 });
        assert.equal(said.length, 1);
    } finally {
        try { clock.uninstall(); } catch (err) { threw = err; }
    }
    assert.match(String(threw), /a livelock: 200 macrotasks ran one after another at 0 virtual ms/);
});

test("a livelocked test with no bound fails, and its file exits, instead of hanging npm test", HANG_BOUND, async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "virtual-time-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const file = join(dir, "livelock.test.mjs");
    writeFileSync(file, [
        'import test, { afterEach, beforeEach } from "node:test";',
        `import { installVirtualTime } from ${JSON.stringify(new URL("./test_virtual_time.mjs", import.meta.url).href)};`,
        "let clock;",
        "beforeEach(() => { clock = installVirtualTime({ livelockTurns: 1000 }); });",
        "afterEach(() => clock.uninstall());",
        'test("two ends that answer each other forever, with no bound", async () => {',
        "    // Gives up by itself at 50 times the bound, so a broken clock fails the assertions below rather than hanging.",
        "    await new Promise(() => { let n = 0; const hop = () => { if (++n < 50_000) setImmediate(hop); }; hop(); });",
        "});",
        'test("a test after it", () => {});',
        "",
    ].join("\n"));
    // NODE_TEST_CONTEXT tells a child to report to this runner; this one reports to us.
    const { NODE_TEST_CONTEXT, ...env } = process.env;
    const { code, out } = await new Promise((resolve) => {
        execFile(process.execPath, ["--test", file], { env, timeout: HANG_BOUND.timeout }, (err, stdout, stderr) =>
            resolve({ code: err ? (err.killed ? "killed: it hung" : err.code) : 0, out: stdout + stderr }));
    });
    assert.equal(code, 1, out);
    assert.match(out, /⚠ test_virtual_time\.mjs: livelock: 1000 macrotasks ran one after another/, "said on stderr by default");
    assert.match(out, /✖ two ends that answer each other forever, with no bound/);
    assert.match(out, /Promise resolution is still pending but the event loop has already resolved/);
});
