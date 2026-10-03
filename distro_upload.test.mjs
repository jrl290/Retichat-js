/**
 * lib/distro_upload.js: the proof of an upload made for the distro (the
 * RFed SPEC §17.11 sent-copy and the §17.12 membership message), with its
 * DESIGN_PRINCIPLES §1 watch. Review of Retichat-js 69ff01e (2026-10-03):
 * both were said sent when their packet was queued
 * (CHECK_THESE_THINGS_FIRST §14). The app's use of it is tested in
 * distro_channels.test.mjs and distro_sent_sync.test.mjs.
 *
 * Run: node --test distro_upload.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { DistroUploads, PROOF_LIVE_MS } from "./lib/distro_upload.js";

/** DistroUploads on a virtual clock, its timers run by the test. */
function uploads() {
    const clock = { now: 1_000 };
    const timers = [];
    const logged = [];
    const u = new DistroUploads({
        now: () => clock.now,
        setTimer: (fn, ms) => { const timer = { fn, ms, cleared: false }; timers.push(timer); return timer; },
        clearTimer: (timer) => { timer.cleared = true; },
        log: { error: (line) => logged.push(["error", line]), warn: (line) => logged.push(["warn", line]) },
    });
    const fire = () => timers.filter((timer) => !timer.cleared).forEach((timer) => { timer.cleared = true; timer.fn(); });
    return { u, clock, timers, logged, fire };
}

const outcome = (upload) => upload.outcome.then((v) => ["proved", v], (e) => ["lost", e.message]);

test("a proof within 5 s decides it, quietly, and stops the §1 watch", async () => {
    const { u, clock, timers, logged } = uploads();
    const upload = u.track("the join of #x");
    u.left(upload);
    assert.deepEqual(timers.map((timer) => timer.ms), [PROOF_LIVE_MS + 1]);
    clock.now += 300;
    assert.equal(u.proved(upload), true);
    assert.deepEqual(await outcome(upload), ["proved", { waitedMs: 300 }]);
    assert.equal(timers[0].cleared, true);
    assert.deepEqual(logged, []);
    assert.equal(u.proved(upload), false, "decided once");
    assert.equal(u.lost(upload, "late"), false, "a loss after the proof changes nothing");
});

test("§1: 5 s without a proof is said then; a proof after it is logged with its time and still decides it", async () => {
    const { u, clock, logged, fire } = uploads();
    const upload = u.track("the leave of #x");
    u.left(upload);
    fire();
    assert.equal(logged.length, 1);
    assert.match(logged[0][1], /^\[distro\] §1 VIOLATION: the propagation node has not proved the leave of #x within 5 s/);
    clock.now += 7_250;
    assert.equal(u.proved(upload), true);
    assert.match(logged[1][1], /§1 VIOLATION: the propagation node proved the leave of #x 7250 ms after its upload \(a late success is a failure\)/);
    assert.deepEqual(await outcome(upload), ["proved", { waitedMs: 7_250 }]);
});

test("a loss decides it and stops the watch; a proof that still comes is logged and changes nothing", async () => {
    const { u, timers, logged } = uploads();
    const upload = u.track("the sent-copy for 01234567");
    u.left(upload);
    assert.equal(u.lost(upload, "its packet was lost (the exchange failed)"), true);
    assert.deepEqual(await outcome(upload), ["lost", "its packet was lost (the exchange failed)"]);
    assert.equal(timers[0].cleared, true, "no §1 line for an upload already known lost");
    assert.equal(u.proved(upload), false);
    assert.deepEqual(logged, [["warn", "[distro] the sent-copy for 01234567 was proved after all, after it was reported lost"]]);
});

test("an upload lost before it left starts no watch, and nobody need wait on it", async () => {
    const { u, timers } = uploads();
    const upload = u.track("the join of #y");
    u.lost(upload, "the propagation link closed before the upload");
    u.left(upload);
    assert.deepEqual(timers, [], "a settled upload is not watched");
    assert.deepEqual(await outcome(upload), ["lost", "the propagation link closed before the upload"]);
});

// Review of 9f058e9 (2026-10-03): disconnect() and the propagation link's
// close decided nothing, so an upload whose proof could no longer come
// stayed open, and its §1 watch said 5 s later that the proof or the
// exchange would decide it.

test("cut() decides every open upload lost, stops its §1 watch, and leaves the decided ones alone", async () => {
    const { u, timers, logged, fire } = uploads();
    const a = u.track("the join of #a", "link1");
    const b = u.track("the sent-copy for 01234567", "link2", "packet");
    const proved = u.track("the leave of #c", "link1");
    for (const x of [a, b, proved]) u.left(x);
    u.proved(proved);
    assert.equal(u.cut("the connection stopped before the propagation node proved it"), 2);
    assert.deepEqual(await outcome(a), ["lost", "the connection stopped before the propagation node proved it"]);
    assert.deepEqual(await outcome(b), ["lost", "the connection stopped before the propagation node proved it"]);
    assert.deepEqual(await outcome(proved), ["proved", { waitedMs: 0 }]);
    assert.ok(timers.every((timer) => timer.cleared));
    fire();
    assert.deepEqual(logged, [], "no §1 line for a proof nobody waits for any more");
    assert.equal(u.cut("again"), 0, "nothing left open");
});

test("cut(why, link) decides only the uploads made on that link", async () => {
    const { u } = uploads();
    const onIt = u.track("the join of #a", "link1");
    const other = u.track("the join of #b", "link2");
    const resource = u.track("the sent-copy for 89abcdef", "link1", "resource");
    assert.equal(u.cut("the propagation link closed before the propagation node proved it", "link1"), 2);
    assert.deepEqual(await outcome(onIt), ["lost", "the propagation link closed before the propagation node proved it"]);
    assert.deepEqual(await outcome(resource), ["lost", "the propagation link closed before the propagation node proved it"]);
    assert.equal(other.settled, null);
    assert.equal(u.proved(other), true);
});

test("a proof after a loss tells the upload's owner once, so what it carried is owed no more", () => {
    const { u } = uploads();
    const upload = u.track("the join of #a", "link1");
    let told = 0;
    upload.onLateProof = () => told++;
    u.left(upload);
    u.lost(upload, "its packet was lost (the exchange failed)");
    assert.equal(u.proved(upload), false, "it decides nothing");
    assert.equal(u.proved(upload), false);
    assert.equal(told, 1);
    const proved = u.track("the leave of #b", "link1");
    proved.onLateProof = () => told++;
    u.proved(proved);
    u.proved(proved);
    assert.equal(told, 1, "a proof of one proved already is no late proof");
});
