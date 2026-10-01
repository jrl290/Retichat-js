/**
 * What decides a channel post's status (lib/channel_publish.js): rfed's
 * answer to the /channel/publish request, or its echo of the post,
 * whichever comes first, makes it "sent"; rfed's refusal, the request's own
 * failure, or another definite failure makes it "failed"; an answer or an
 * echo after a failure still makes it "sent"; the §1 clock runs from the
 * moment rfed holds the request to its answer, never over a transfer.
 *
 * 2026-10-01: James, after the retichat.com deploy: "Channels don't seem to
 * update their chat send indicator when a message successfully hits the
 * rfed node." On the staging chain (Retichat-js f56346c) the record went
 * "sent" 0.55 s and 1.6 s after the send while the bubble kept "sending";
 * the app's side of that is channel_send_status.test.mjs and the page's
 * channel_send_status_page.test.mjs. The review of 2af0e9b (which decided
 * on the echo alone) found, on the same chain, a 30 KB post's §1 line
 * counting the 8.8 s of rfed's echo Resource, and a 60 KB post shown
 * failed while rfed's echo of it was still arriving, 15 s after rfed had
 * stored it; and that a post the connection's stop failed was forgotten,
 * so its echo could not make it "sent". This file is the outcome itself;
 * channel_send_status.test.mjs runs it with the shipped app code over a
 * real link pair.
 *
 * Run: node --test channel_publish.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { ChannelPublishes, ANSWER_LIVE_MS, CHANNEL_PUBLISH_PATH, publishRefusal } from "./lib/channel_publish.js";

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
    const track = (key = KEY) => p.track(key, {
        sent: (detail) => outcomes.push({ key, status: "sent", ...detail }),
        failed: (why) => outcomes.push({ key, status: "failed", why }),
    });
    return { p, advance, track, outcomes, lines, timers: () => timers.length };
}

const KEY = "ab".repeat(16) + ":1790894643281";
const OK = [true, null];
const settled = async (promise) => promise.then(() => "sent", (e) => `failed: ${e.message}`);

test("the path is rfed.link's publish, and rfed's answer reads as Link.md says", () => {
    assert.equal(CHANNEL_PUBLISH_PATH, "/channel/publish");
    assert.equal(publishRefusal([true, null]), null);
    assert.equal(publishRefusal([false, "stamp_invalid"]), "rfed refused it (stamp_invalid)");
    assert.equal(publishRefusal([false, null]), "rfed refused it (no reason given)");
    assert.match(publishRefusal(true), /^rfed's answer was not \[ok, reason\]: true$/, "a bare bool is not the publish answer");
    assert.match(publishRefusal(null), /not \[ok, reason\]/);
});

test("rfed's answer makes the post sent, at once, and its §1 clock stops", async () => {
    const c = publishes();
    const post = c.track();
    c.p.left(post);
    assert.equal(c.timers(), 1, "the §1 clock runs from the moment rfed holds it");
    c.advance(40);
    assert.equal(c.p.answered(post, OK), true);
    assert.equal(post.status, "sent");
    assert.deepEqual(c.outcomes, [{ key: KEY, status: "sent", via: "rfed's answer", late: false }]);
    assert.equal(await settled(post.outcome), "sent");
    assert.equal(c.timers(), 0, "nothing is left armed");
    assert.equal(c.p.echoed(KEY), false, "its echo, which follows, is just the post coming back");
    assert.equal(c.outcomes.length, 1, "shown once");
    assert.deepEqual(c.lines, []);
});

test("rfed's echo before its answer makes the post sent; the answer then only stops the clock", async () => {
    const c = publishes();
    const post = c.track();
    c.p.left(post);
    c.advance(30);
    assert.equal(c.p.echoed(KEY), true);
    assert.equal(post.status, "sent");
    assert.equal(c.timers(), 1, "rfed still owes its answer");
    c.advance(1);
    assert.equal(c.p.answered(post, OK), false, "already decided");
    assert.equal(c.timers(), 0);
    assert.deepEqual(c.outcomes.map((o) => [o.status, o.via]), [["sent", "rfed's echo"]]);
    assert.deepEqual(c.lines, []);
});

test("rfed's refusal fails the post with its reason, at once: not the ceiling", async () => {
    const c = publishes();
    const post = c.track();
    c.p.left(post);
    c.advance(50);
    assert.equal(c.p.answered(post, [false, "stamp_invalid"]), true);
    assert.equal(post.status, "failed");
    assert.deepEqual(c.outcomes, [{ key: KEY, status: "failed", why: "rfed refused it (stamp_invalid)" }]);
    assert.equal(await settled(post.outcome), "failed: rfed refused it (stamp_invalid)");
    assert.equal(c.timers(), 0);
});

test("the request's own failure (the link's budget, a closed link, a failed request Resource) fails the post", async () => {
    const c = publishes();
    const post = c.track();
    c.p.left(post);
    c.advance(ANSWER_LIVE_MS);
    assert.deepEqual(c.lines, [], "exactly 5 s is within the rule");
    c.advance(9_000);
    assert.equal(c.p.unanswered(post, "no response within 14000 ms"), true);
    assert.equal(post.status, "failed");
    assert.equal(await settled(post.outcome), "failed: no response within 14000 ms");
    assert.equal(c.lines.length, 1, "the 5 s were said once, when they were up");
    assert.match(c.lines[0], /^\[retichat\] §1 VIOLATION: rfed has not answered the publish of channel post abababab.* within 5 s of holding it \(the post is still sending\)/);
    assert.equal(c.timers(), 0);
    assert.equal(c.p.answered(post, OK), false, "the request is over: nothing answers it now");

    const d = publishes();
    const never = d.track();
    assert.equal(d.p.unanswered(never, "sending the request as a Resource failed: the Resource failed"), true,
        "a request Resource that failed never left: no §1 clock ran");
    assert.equal(d.timers(), 0);
    assert.deepEqual(d.lines, []);
});

test("§1: an answer later than 5 s after rfed held the request is said, with its time; it still decides", async () => {
    const c = publishes();
    const post = c.track();
    c.p.left(post);
    c.advance(ANSWER_LIVE_MS + 1);
    assert.equal(c.lines.length, 1);
    c.advance(1_499);
    assert.equal(c.p.answered(post, OK), true);
    assert.equal(post.status, "sent", "a late success decides nothing else: it is said");
    assert.equal(c.lines.length, 2);
    assert.match(c.lines[1], /§1 VIOLATION: rfed answered the publish of channel post abababab.* 6500 ms after it held it \(a late success is a failure\)/);
});

test("the §1 clock starts when rfed holds the request: a request Resource's transfer is never counted", async () => {
    const c = publishes();
    const post = c.track();
    // A 60 KB post's request Resource crossing for 15 s: not yet held.
    c.advance(15_000);
    assert.equal(c.timers(), 0, "no clock before rfed holds it (§1 bulk transfers: its progress is watched, not its total)");
    c.p.left(post);
    c.advance(120);
    c.p.answered(post, OK);
    assert.deepEqual(c.lines, []);
    assert.equal(post.status, "sent");

    // An answer handled before the Resource's proof (it came first on the
    // wire): it never "left", and nothing is late.
    const d = publishes();
    const early = d.track();
    d.advance(20_000);
    assert.equal(d.p.answered(early, OK), true);
    d.p.left(early);
    assert.equal(d.timers(), 0, "left() after the answer arms nothing");
    assert.deepEqual(d.lines, []);
});

test("a failed post stays tracked: rfed's echo, or its answer still pending, makes it sent", async () => {
    // A lost exchange failed it at once (D3); rfed had taken the batch.
    const c = publishes();
    const post = c.track();
    c.p.left(post);
    c.advance(200);
    assert.equal(c.p.failed(post, "its packet was lost (HTTP 502)"), true);
    assert.equal(await settled(post.outcome), "failed: its packet was lost (HTTP 502)");
    c.advance(300);
    assert.equal(c.p.answered(post, OK), true);
    assert.equal(post.status, "sent");
    assert.deepEqual(c.outcomes.map((o) => [o.status, o.late ?? null]), [["failed", null], ["sent", true]]);

    // The request's budget ran out; rfed's echo came after it.
    const d = publishes();
    const slow = d.track();
    d.p.left(slow);
    d.advance(14_000);
    d.p.unanswered(slow, "no response within 14000 ms");
    d.advance(2_000);
    assert.equal(d.p.echoed(KEY), true);
    assert.equal(slow.status, "sent");
    assert.deepEqual(d.outcomes.at(-1), { key: KEY, status: "sent", via: "rfed's echo", late: true });
});

test("a post whose link closed (the connection stopped) is failed by that event, and its echo on the next connection makes it sent", async () => {
    const c = publishes();
    const post = c.track(KEY);
    c.p.left(post);
    c.advance(100);
    // link.js _linkClosed fails every request still pending on the link.
    assert.equal(c.p.unanswered(post, "the link closed before a response"), true);
    assert.equal(post.status, "failed");
    assert.equal(await settled(post.outcome), "failed: the link closed before a response");
    assert.equal(c.timers(), 0, "the request is over: no §1 clock runs on");
    c.advance(ANSWER_LIVE_MS * 2);
    assert.deepEqual(c.lines, []);

    // rfed had it: its echo comes on the next connection (its stream, or a pull).
    assert.equal(c.p.echoed(KEY), true, "still tracked");
    assert.equal(post.status, "sent");
    assert.deepEqual(c.outcomes.at(-1), { key: KEY, status: "sent", via: "rfed's echo", late: true });
    assert.equal(c.p.echoed(KEY), false, "once");
});

test("an echo of a post it does not track is not its business", () => {
    const c = publishes();
    assert.equal(c.p.echoed("ef".repeat(16) + ":1"), false);
    assert.deepEqual(c.outcomes, []);
});
