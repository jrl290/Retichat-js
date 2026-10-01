/**
 * DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30): a Resource's total
 * duration is not measured against 5 s; from its advertisement on it must
 * show progress (a part received, a window answered, a hashmap update, the
 * proof) at least every 5 s. A longer silence is a §1 violation, asserted and
 * logged as one, once per silence, with its end logged when progress comes
 * again, and it never fails the transfer: the Resource's own events
 * (concluded, failed, cancelled, link closed) decide that. A
 * re-advertisement is not progress.
 *
 * Every Resource watches itself (lib/rns/resource.js bulkStart … bulkStop):
 * sent or received, bare data, request or response. Until 2026-10-01 only
 * the Resources of a DM the web sent were watched (lib/send_progress.js
 * SendTransfers), so the photos, rfed.link pushes, /get responses and
 * distro fan-out it received were never asserted (round 3 staging). A
 * message's Resource is now watched by the Resource alone, under the
 * message's label: SendTransfers keeps no watch, so nothing is logged twice.
 *
 * Two real Links joined in process (test_link_pair.mjs), on virtual time
 * (test_virtual_time.mjs): a silence is exactly the delay a test injects.
 *
 * Run: node --test bulk_transfer_rule.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { afterEach, beforeEach } from "node:test";

import Link from "./lib/rns/link.js";
import MsgPack from "./lib/rns/msgpack.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import { SendTransfers } from "./lib/send_progress.js";
import { linkPair, once, within } from "./test_link_pair.mjs";
import { installVirtualTime } from "./test_virtual_time.mjs";
import { install } from "./test_app_source.mjs";

let clock = null;
let lines = null;
beforeEach(() => {
    clock = installVirtualTime();
    lines = [];
    Resource.bulkLog = {
        error: (m) => lines.push({ at: clock.elapsed(), level: "error", m }),
        warn: (m) => lines.push({ at: clock.elapsed(), level: "warn", m }),
    };
});
afterEach(() => {
    Resource.bulkLog = console;
    clock.uninstall();
    clock = null;
});

const bytes = (n, k = 7) => Buffer.from(Array.from({ length: n }, (_, i) => (i * k) % 251));
const violations = () => lines.filter((l) => l.level === "error" && l.m.startsWith("[§1] VIOLATION"));
const resumed = () => lines.filter((l) => l.level === "warn" && / progress again after /.test(l.m));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A `delay` for linkPair: from the `nth` packet that `which(packet, from)`
 * selects on, every one it selects is held until `ms` after that one was
 * sent. One stall per `which`.
 */
function stallFrom(which, nth, ms) {
    let seen = 0;
    let until = null;
    return (packet, from) => {
        if (!which(packet, from)) return 0;
        const now = Date.now();
        if (until === null && ++seen === nth) until = now + ms;
        return until !== null && now < until ? until - now : 0;
    };
}

const requestsFrom = (side) => (packet, from) => from === side && packet.context === Packet.RESOURCE_REQ;

test("a received and a sent Resource silent for 7 s: each logged once, at 5 s, then progress again; the transfer completes", async () => {
    // The receiver's third window request is held for 7 s: the sender has
    // nothing to answer and the receiver gets no part, both for 7 s. The
    // receiver's own watchdog asks again at 4 s (not progress: that request
    // is held too).
    const { a, b } = linkPair({ delay: stallFrom(requestsFrom("b"), 3, 7_000) });
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const payload = bytes(30_000);
    const received = once(b, "resource").then(({ data }) => data);
    const start = clock.elapsed();
    const sent = await within(a.sendResource(payload), 120_000, "the transfer");
    assert.ok((await received).equals(payload), "delivered whole: the silence decided nothing");

    const v = violations();
    assert.equal(v.length, 2, `one violation for each end: ${JSON.stringify(lines)}`);
    assert.match(v.find((l) => / sent Resource /.test(l.m))?.m ?? "", /^\[§1\] VIOLATION sent Resource [0-9a-f]{12} \(30000 B, link [0-9a-f]{12}\): no progress for 5 s \(\d+\.\d s since it started, \d+\.\d% done\); the Resource's own events decide its outcome$/);
    assert.match(v.find((l) => / received Resource /.test(l.m))?.m ?? "", /^\[§1\] VIOLATION received Resource [0-9a-f]{12} \(30000 B, link [0-9a-f]{12}\): no progress for 5 s/);
    const r = resumed();
    assert.equal(r.length, 2, "and one 'progress again' for each");
    for (const line of r) assert.match(line.m, /progress again after 7\.0 s of silence$/);
    for (const line of v) {
        const again = r.find((x) => x.m.includes(line.m.match(/Resource ([0-9a-f]{12})/)[1]) && x.m.includes(line.m.includes(" sent ") ? " sent " : " received "));
        assert.equal(again.at - line.at, 2_000, "the silence was asserted at 5 s and ended at 7 s");
    }
    assert.equal(clock.elapsed() - start, 7_000, "the stall was all the time it took");
    assert.deepEqual(sent.bulkSilences.map((s) => s.silentMs), [7_000], "its bookkeeping: one silence, 7 s");
});

test("a silence is logged once however long it lasts, and the Resource's own watchdog decides the outcome: a re-advertisement is not progress", async () => {
    // Nobody answers the advertisement (b takes no Resource). On a link
    // whose RTT is 1 s the sender re-advertises at 7, 14, 21 and 28 s and
    // fails at 35 s (RNS Resource.py: MAX_ADV_RETRIES, each after
    // link.rtt x TRAFFIC_TIMEOUT_FACTOR + PROCESSING_GRACE).
    const { a } = linkPair({ rttMs: 1_000 });
    const start = clock.elapsed();
    let failedAt = null;
    const sending = a.sendResource(bytes(2_000)).catch((e) => { failedAt = clock.elapsed(); throw e; });
    const resource = a.outgoingResources[0];

    await sleep(5_100);
    assert.equal(violations().length, 1, "asserted at 5 s");
    assert.equal(violations()[0].at - start, 5_000);
    assert.equal(resource.status, Resource.ADVERTISED, "and nothing failed for it");
    assert.equal(failedAt, null);

    await assert.rejects(within(sending, 120_000, "the advertisement"), /no response to the resource advertisement/);
    assert.equal(failedAt - start, 35_000, "failed by its own watchdog, at its own time");
    assert.equal(violations().length, 1, "once per silence: 35 s of it, four re-advertisements and all");
    assert.equal(resumed().length, 0, "a re-advertisement is not progress");
    assert.match(lines.at(-1).m, /^\[§1\] sent Resource [0-9a-f]{12} \(2000 B, link [0-9a-f]{12}\): failed: no response to the resource advertisement after 35\.0 s of silence$/);
});

test("a transfer that moves for over 20 s with a window every 0.8 s is never a violation", async () => {
    const { a, b } = linkPair({ rttMs: 800, delay: () => 400 });
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const payload = bytes(100_000, 3);
    const received = once(b, "resource").then(({ data }) => data);
    const start = clock.elapsed();
    await within(a.sendResource(payload), 600_000, "the transfer");
    assert.ok((await received).equals(payload));
    assert.ok(clock.elapsed() - start > 20_000, `${clock.elapsed() - start} ms in all, far over 5 s`);
    assert.deepEqual(lines, [], "its total time is never counted against 5 s");
});

test("a hashmap update is progress: a receiver that gets one every 4 s, and no part, is never silent for 5 s", async () => {
    // A Resource of 300 parts maps 74 per advertisement. The receiver takes
    // the advertisement, then (no part arriving at all) the sender's hashmap
    // updates for segments 1, 2 and 3, 4 s apart: progress every 4 s.
    const { a, b } = linkPair({ drop: (packet, from) => from === "b" });   // nothing reaches the sender
    const sender = new Resource(a);
    sender.initiator = true;
    sender.prepareOutgoing(bytes(464 * 300, 9));
    const receiver = Resource.accept(b, MsgPack.unpack(sender.packAdvertisement(0)));
    assert.ok(receiver, "the advertisement is taken");
    const update = (segment) => {
        const from = segment * Resource.HASHMAP_MAX_LEN * Resource.MAPHASH_LEN;
        const map = sender.hashmapRaw.subarray(from, from + Resource.HASHMAP_MAX_LEN * Resource.MAPHASH_LEN);
        receiver.waitingForHashmapUpdate = true;   // as after a request that ran out of map
        receiver.onHashmapUpdate(Buffer.concat([sender.hash, MsgPack.pack([segment, map])]));
    };
    for (const segment of [1, 2, 3]) {
        await sleep(4_000);
        update(segment);
    }
    await sleep(4_500);
    assert.deepEqual(violations(), [], "every gap was 4 s");
    assert.equal(receiver.hashmapHeight, 296, "the updates were taken");
    await sleep(1_000);
    assert.equal(violations().length, 1, "and the next 5 s without one is a violation");
    receiver.cancel("done");
});

test("the watch ends with the Resource: concluded, failed or its link closed, no timer is left and nothing is logged after", async () => {
    // Concluded.
    const pair = linkPair();
    pair.b.setResourceStrategy(Link.ACCEPT_ALL);
    const incoming = once(pair.b, "resource");
    const done = await pair.a.sendResource(bytes(9_000));
    const { resource: got } = await incoming;
    for (const r of [done, got]) {
        assert.equal(r.bulkEnded, true);
        assert.equal(r.bulkTimer, null, "its timer cleared");
    }

    // The link closed mid-transfer: the parts never arrive.
    const { a, b } = linkPair({ drop: (packet) => packet.context === Packet.RESOURCE });
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const sending = a.sendResource(bytes(5_000));
    await sleep(1_000);
    const [out] = a.outgoingResources;
    const [inc] = b.incomingResources;
    const incFailed = once(inc, "failed");
    a.close();                                    // LINKCLOSE reaches b
    await assert.rejects(within(sending, 2_000, "the sending Resource"), /link closed/);
    assert.equal(await within(incFailed, 2_000, "the receiving Resource"), "link closed");
    for (const r of [out, inc]) {
        assert.equal(r.status, Resource.FAILED);
        assert.equal(r.bulkTimer, null, "its timer cleared");
    }
    await sleep(60_000);
    assert.deepEqual(lines, [], "nothing after its end: the watch is the Resource's, and ends with it");
});

test("request and response Resources are watched like any other (an rfed.link push, a /get answer)", async () => {
    // b answers a's request with a response over the MDU. The request
    // Resource stalls 7 s (b's third window request held), then the response
    // Resource does (a's third window request held).
    const stallRequest = stallFrom(requestsFrom("b"), 3, 7_000);
    const stallResponse = stallFrom(requestsFrom("a"), 3, 7_000);
    const { a, b } = linkPair({ delay: (packet, from) => Math.max(stallRequest(packet, from), stallResponse(packet, from)) });
    b.on("request", ({ requestId, data }) => b.sendResponse(requestId, Buffer.concat([Buffer.from(data), Buffer.from(data)])));
    const requestId = a.sendRequest("/lxmf/delivery", bytes(20_000));
    const response = await within(a.responseFor(requestId), 600_000, "the response");
    assert.equal(Buffer.from(response).length, 40_000);

    const kinds = violations().map((l) => l.m.match(/^\[§1\] VIOLATION (sent|received) (request|response) Resource /)?.slice(1).join(" "));
    assert.deepEqual(kinds.sort(), ["received request", "received response", "sent request", "sent response"]);
    assert.equal(resumed().length, 4);
});

test("a DM's Resource is watched by the Resource alone, under the message's label: one line per silence, none from SendTransfers", async (t) => {
    const errors = [];
    const warns = [];
    const real = { error: console.error, warn: console.warn };
    console.error = (...a) => errors.push(a.join(" "));
    console.warn = (...a) => warns.push(a.join(" "));
    Resource.bulkLog = console;   // where the shipped page logs them
    t.after(() => { console.error = real.error; console.warn = real.warn; });

    const { a, b } = linkPair({ delay: stallFrom(requestsFrom("b"), 3, 7_000) });
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const self = { _onSendProgress: [], _sendTransfers: new SendTransfers() };
    install(self, {}, ["_sendWithProgress(link, data, convHash, msgId, label)"]);
    await within(self._sendWithProgress(a, bytes(30_000), "c".repeat(32), "0123456789abcdef", "direct"), 120_000, "the DM's Resource");

    const v = errors.filter((m) => m.startsWith("[§1] VIOLATION"));
    assert.equal(v.length, 2, `one for the DM's Resource, one for its receiver, nothing twice: ${JSON.stringify(v)}`);
    assert.match(v.find((m) => m.includes("direct transfer")) ?? "", /^\[§1\] VIOLATION direct transfer of 01234567 to cccccccc \(sent Resource [0-9a-f]{12} \(30000 B, link [0-9a-f]{12}\)\): no progress for 5 s/);
    const again = warns.filter((m) => m.startsWith("[§1] direct transfer of 01234567 to cccccccc"));
    assert.equal(again.length, 1);
    assert.match(again[0], /progress again after 7\.0 s of silence$/);
    assert.equal(self._sendTransfers.inFlight("0123456789abcdef"), false, "its end still reaches SendTransfers");
});

test("the §1 assertion carries its NEVER REMOVE comment, and SendTransfers keeps no watch of its own", async () => {
    const resource = await readFile(new URL("./lib/rns/resource.js", import.meta.url), "utf8");
    assert.match(resource, /\/\/ NEVER REMOVE EVER — see DESIGN_PRINCIPLES\.md §1[^\n]*\n\s+Resource\.bulkLog\.error\?\.\(`\[§1\] VIOLATION/);
    const sendProgress = await readFile(new URL("./lib/send_progress.js", import.meta.url), "utf8");
    assert.doesNotMatch(sendProgress, /setTimeout|setTimer|VIOLATION/, "a second watch would log every silence of a DM twice");
});
