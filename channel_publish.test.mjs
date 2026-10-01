/**
 * What decides a channel post's status (lib/channel_publish.js): rfed's echo
 * of the post makes it "sent"; a definite failure, or last the ceiling,
 * "failed"; a late echo still makes a failed post "sent", and is a §1
 * violation; the ceiling and the §1 clock start when the publish left.
 *
 * 2026-10-01: James, after the retichat.com deploy: "Channels don't seem to
 * update their chat send indicator when a message successfully hits the
 * rfed node." On the staging chain (Retichat-js f56346c) the record went
 * "sent" 0.55 s and 1.6 s after the send while the bubble kept "sending";
 * the app's side of that is channel_send_status.test.mjs and the page's
 * channel_send_status_page.test.mjs. This file is the outcome itself.
 *
 * Run: node --test channel_publish.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { ChannelPublishes, ECHO_LIVE_MS } from "./lib/channel_publish.js";

/** A ChannelPublishes on a clock the test moves (`advance`), and what it
 *  says: `outcomes` (each sent/failed call) and `lines` (its §1 log). */
function publishes() {
    let now = 1_000_000;
    let timers = [];
    const lines = [];
    const outcomes = [];
    const p = new ChannelPublishes({
        now: () => now,
        setTimer: (fn, ms) => { const t = { at: now + ms, fn }; timers.push(t); return t; },
        clearTimer: (t) => { timers = timers.filter((x) => x !== t); },
        log: { error: (line) => lines.push(line) },
    });
    const advance = (ms) => {
        const until = now + ms;
        for (;;) {
            const due = timers.filter((t) => t.at <= until).sort((a, b) => a.at - b.at)[0];
            if (!due) break;
            timers = timers.filter((t) => t !== due);
            now = due.at;
            due.fn();
        }
        now = until;
    };
    const track = (key) => p.track(key, {
        sent: (detail) => outcomes.push({ key, status: "sent", ...detail }),
        failed: (why, detail) => outcomes.push({ key, status: "failed", why, ...detail }),
    });
    return { p, advance, track, outcomes, lines, timers: () => timers.length };
}

const KEY = "ab".repeat(16) + ":1790894643281";
const CEILING = 14_500;
const settled = async (promise) => promise.then(() => "sent", (e) => `failed: ${e.message}`);

test("rfed's echo makes the post sent, at once, and nothing is left armed", async () => {
    const c = publishes();
    const post = c.track(KEY);
    const outcome = c.p.left(post, CEILING);
    c.advance(1_600);
    assert.equal(c.p.echoed(KEY), true, "a post it tracks");
    assert.equal(post.status, "sent");
    assert.deepEqual(c.outcomes, [{ key: KEY, status: "sent", waitedMs: 1_600, late: false, proved: false }]);
    assert.equal(await settled(outcome), "sent");
    assert.equal(c.timers(), 0, "the ceiling is cleared");
    assert.deepEqual(c.lines, [], "within 5 s: no §1 line");
    assert.equal(c.p.echoed(KEY), false, "a second copy of the echo is not a post it tracks");
    assert.equal(c.outcomes.length, 1);
});

test("rfed's proof alone is not sent: rfed proves a publish before it looks at it", async () => {
    const c = publishes();
    const post = c.track(KEY);
    const outcome = c.p.left(post, CEILING);
    c.advance(500);
    c.p.proved(post);
    c.advance(CEILING - 501);
    assert.equal(post.status, "sending", "proved, and still sending up to the ceiling");
    assert.deepEqual(c.outcomes, []);
    c.advance(1);
    assert.equal(post.status, "failed", "the ceiling, as a last resort");
    assert.deepEqual(c.outcomes, [{ key: KEY, status: "failed", why: `rfed sent no echo of the post within ${CEILING} ms`, proved: true }]);
    assert.match(await settled(outcome), /rfed received it: its proof came/, "the failure says rfed had received it");
});

test("the ceiling and the §1 clock start when the publish left, not when the post was tracked", async () => {
    // An oversized post is a Resource: tracked before its transfer, left at
    // its proof. A transfer longer than the ceiling is not a failure (§1 bulk
    // transfers: the Resource's own events decide it).
    const c = publishes();
    const post = c.track(KEY);
    c.advance(60_000);
    assert.equal(post.status, "sending");
    assert.equal(c.timers(), 0, "nothing armed before the publish left");
    const outcome = c.p.left(post, CEILING);
    c.advance(2_000);
    c.p.echoed(KEY);
    assert.equal(c.outcomes[0].waitedMs, 2_000, "measured from the publish leaving");
    assert.deepEqual(c.lines, []);
    assert.equal(await settled(outcome), "sent");
});

test("an echo that comes before the publish is seen to leave is sent, and leaving afterwards arms nothing", async () => {
    // rfed proves a Resource, then takes it in and fans it out; its echo can
    // reach the page in the same exchange as the proof.
    const c = publishes();
    const post = c.track(KEY);
    assert.equal(c.p.echoed(KEY), true);
    assert.equal(post.status, "sent");
    assert.equal(await settled(c.p.left(post, CEILING)), "sent");
    assert.equal(c.timers(), 0);
    c.advance(CEILING * 2);
    assert.deepEqual(c.outcomes.map((o) => o.status), ["sent"]);
});

test("a definite failure fails the post now; rfed's echo after it makes it sent, and says it was late (§1)", async () => {
    const c = publishes();
    const post = c.track(KEY);
    const outcome = c.p.left(post, CEILING);
    c.advance(300);
    assert.equal(c.p.failed(post, "its packet was lost (exchange failed)"), true);
    assert.equal(post.status, "failed");
    assert.equal(await settled(outcome), "failed: its packet was lost (exchange failed)");
    assert.equal(c.timers(), 0, "the ceiling has nothing left to do");
    assert.equal(c.p.failed(post, "again"), false, "one failure");
    c.advance(ECHO_LIVE_MS + 700);
    assert.equal(c.p.echoed(KEY), true, "a failed post is still tracked for its echo");
    assert.equal(post.status, "sent", "rfed has it: the truth outranks the failure");
    assert.deepEqual(c.outcomes.map((o) => [o.status, o.late ?? null]), [["failed", null], ["sent", true]]);
    assert.equal(c.lines.length, 1);
    assert.match(c.lines[0], /§1 VIOLATION: rfed's echo of channel post .* came 6000 ms after the publish left/);
    assert.match(c.lines[0], /had been shown failed, and is now sent/);
    assert.equal(c.p.failed(post, "after sent"), false, "a sent post is never failed");
});

test("an echo later than 5 s but under the ceiling is sent, and a §1 violation; exactly 5 s is not", () => {
    const c = publishes();
    const a = c.track("a:1");
    c.p.left(a, CEILING);
    c.advance(ECHO_LIVE_MS);
    c.p.echoed("a:1");
    assert.deepEqual(c.lines, [], "exactly 5 s is within the rule");
    const b = c.track("b:2");
    c.p.left(b, CEILING);
    c.advance(ECHO_LIVE_MS + 1);
    c.p.echoed("b:2");
    assert.equal(b.status, "sent", "never failed for being late");
    assert.equal(c.lines.length, 1);
    assert.match(c.lines[0], /^\[retichat\] §1 VIOLATION: .* came 5001 ms after the publish left \(a late success is a failure\)$/);
});

test("the connection stopping fails what is still sending, and nothing is tracked after it", async () => {
    const c = publishes();
    const sending = c.track("s:1");
    const outcome = c.p.left(sending, CEILING);
    const failedEarlier = c.track("f:2");
    c.p.failed(failedEarlier, "lost");
    c.p.clear("the connection stopped before rfed accepted the post");
    assert.equal(sending.status, "failed");
    assert.equal(await settled(outcome), "failed: the connection stopped before rfed accepted the post");
    assert.equal(c.timers(), 0);
    assert.equal(c.p.echoed("s:1"), false);
    assert.equal(c.p.echoed("f:2"), false);
    assert.deepEqual(c.outcomes.map((o) => `${o.key} ${o.status}`), ["f:2 failed", "s:1 failed"]);
});

test("a post that fails before anyone waits on it raises no unhandled rejection", async (t) => {
    const unhandled = [];
    const onUnhandled = (e) => unhandled.push(e);
    process.on("unhandledRejection", onUnhandled);
    t.after(() => process.off("unhandledRejection", onUnhandled));
    const c = publishes();
    const post = c.track(KEY);
    c.p.failed(post, "its Resource failed");
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(unhandled, []);
});

test("an echo for a post it does not track is not one", () => {
    const c = publishes();
    assert.equal(c.p.echoed("cd".repeat(16) + ":1"), false);
    assert.deepEqual(c.outcomes, []);
});
