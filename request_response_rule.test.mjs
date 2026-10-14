/**
 * DESIGN_PRINCIPLES §1 for a request on a link: once the peer holds it (its
 * packet sent, or its Resource proved: DELIVERED), its response must begin
 * within 5 s. A request whose response has not begun by then is said, once,
 * as a §1 violation, and a response that begins later is said with its
 * time: a late success is a failure. The watch decides nothing: the
 * response, or the request's own failure (its timeout, its lost packet, the
 * link closing), decides the request. A response that arrives as a Resource
 * is from then on a bulk transfer, watched by the Resource itself
 * (bulk_transfer_rule.test.mjs), and so are the waits between a split
 * response's segments.
 *
 * Until 2026-10-13 nothing watched a request on a link but a channel post's
 * publish (lib/channel_publish.js), so the web's requests to rfed
 * (_rfedRequest) and its /get requests could answer late unseen. That
 * publish still watches itself, and the link keeps no second watch on it
 * (responseWatch: false).
 *
 * Two real Links joined in process (test_link_pair.mjs), on virtual time
 * (test_virtual_time.mjs): a wait is exactly the delay a test injects.
 *
 * Run: node --test request_response_rule.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { afterEach, beforeEach } from "node:test";

import Link from "./lib/rns/link.js";
import MsgPack from "./lib/rns/msgpack.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import { linkPair, sendSplit, within } from "./test_link_pair.mjs";
import { installVirtualTime } from "./test_virtual_time.mjs";

let clock = null;
let lines = null;
let bulk = null;
beforeEach(() => {
    clock = installVirtualTime();
    lines = [];
    bulk = [];
    Link.requestLog = { error: (m) => lines.push({ at: clock.elapsed(), m }) };
    Resource.bulkLog = { error: (m) => bulk.push(m), warn: (m) => bulk.push(m) };
});
afterEach(() => {
    Link.requestLog = console;
    Resource.bulkLog = console;
    clock.uninstall();
    clock = null;
});

const bytes = (n, k = 7) => Buffer.from(Array.from({ length: n }, (_, i) => (i * k) % 251));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const quiet = { log() {}, warn() {}, error() {} };

/** `b` answers every request `ms` after it arrives, with `value(request)`. */
function answerAfter(b, ms, value = () => true) {
    b.on("request", (request) => setTimeout(() => b.sendResponse(request.requestId, value(request)), ms));
}

/** The pair, with console quiet for the links' own logging. */
function pair(options) {
    const { log, warn } = console;
    console.log = quiet.log; console.warn = quiet.warn;
    const p = linkPair(options);
    return { ...p, restore: () => Object.assign(console, { log, warn }) };
}

test("a response that begins within 5 s of the request's delivery is not said; exactly 5 s is within the rule", async () => {
    const { a, b, restore } = pair();
    answerAfter(b, 5_000);
    const id = a.sendRequest("/distro/pull", null, { timeoutMs: 20_000 });
    assert.equal(await within(a.responseFor(id), 30_000, "the response"), true);
    assert.deepEqual(lines, []);
    restore();
});

test("no response 5 s after delivery is said once; the response after it is said with its time, and still decides the request", async () => {
    const { a, b, restore } = pair();
    answerAfter(b, 6_500, () => [true, null]);
    const id = a.sendRequest("/channel/subscribe", null, { timeoutMs: 20_000 });
    assert.deepEqual(await within(a.responseFor(id), 30_000, "the response"), [true, null], "a late success decides nothing else: it is said");
    assert.equal(lines.length, 2);
    assert.equal(lines[0].at, 5_001, "the first millisecond past 5 s");
    assert.match(lines[0].m, /^\[§1\] VIOLATION request [0-9a-f]{12} \/channel\/subscribe \(link [0-9a-f]{12}\): no response 5 s after it was delivered; its response, or its own failure, decides it$/);
    assert.equal(lines[1].at, 6_500);
    assert.match(lines[1].m, /^\[§1\] VIOLATION request [0-9a-f]{12} \/channel\/subscribe \(link [0-9a-f]{12}\): its response began 6500 ms after it was delivered \(a late success is a failure\)$/);
    restore();
});

test("a request that fails before 5 s leaves no line: its own failure decided it", async () => {
    const { a, restore } = pair();
    const timedOut = a.sendRequest("/rfed/pull", null, { timeoutMs: 3_000 });
    await assert.rejects(within(a.responseFor(timedOut), 30_000, "the timeout"), /no response within 3000 ms/);
    const lost = a.sendRequest("/rfed/pull", Buffer.from([1]), { timeoutMs: 20_000 });
    const [receipt] = a.pendingRequests;
    a.requestPacketsLost(a.attachedInterface, new Set([receipt.packetHash]), "HTTP 503");
    await assert.rejects(a.responseFor(lost), /its packet was lost \(HTTP 503\)/);
    await sleep(10_000);
    assert.deepEqual(lines, []);
    restore();
});

test("a response Resource that begins after 5 s is said once, at its beginning; its transfer is the bulk rule's", async () => {
    const { a, b, restore } = pair({ delay: (p) => (p.context === Packet.RESOURCE ? 100 : 0) });
    const page = bytes(60_000);
    answerAfter(b, 6_000, () => page);
    const id = a.sendRequest("/distro/pull", null, { timeoutMs: 20_000 });
    const response = await within(a.responseFor(id), 120_000, "the response Resource");
    assert.ok(Buffer.from(response).equals(page));
    assert.deepEqual(lines.map((l) => l.m.replace(/[0-9a-f]{12}/g, "…")), [
        "[§1] VIOLATION request … /distro/pull (link …): no response 5 s after it was delivered; its response, or its own failure, decides it",
        "[§1] VIOLATION request … /distro/pull (link …): its response began 6000 ms after it was delivered (a late success is a failure)",
    ], "the transfer itself, longer than 5 s, is not this watch's: each part kept it moving");
    restore();
});

test("a request sent as a Resource is watched from its proof, not from its send", async () => {
    // Each part of the request Resource takes 2 s: its transfer is far
    // longer than 5 s, and moving all along (the bulk rule).
    const { a, b, restore } = pair({ delay: (p, from) => (from === "a" && p.context === Packet.RESOURCE ? 2_000 : 0) });
    answerAfter(b, 4_000);
    const startedAt = Date.now();
    const id = a.sendRequestPacked("/channel/publish", Buffer.concat([Buffer.from([0xc5, 0x9c, 0x40]), bytes(40_000)]), { timeoutMs: 20_000 });
    assert.equal(await within(a.responseFor(id), 120_000, "the response"), true);
    assert.ok(Date.now() - startedAt > 9_000, `the request took ${Date.now() - startedAt} ms from its send`);
    assert.deepEqual(lines, [], "4 s after the peer proved it");
    restore();
});

test("a split response: its first segment ends the watch, and the waits between segments are the bulk rule's, not a second watch", async () => {
    // Segments of 5 KB (as bulk_transfer_rule.test.mjs), so a split needs kilobytes.
    const saved = Resource.MAX_EFFICIENT_SIZE;
    Resource.MAX_EFFICIENT_SIZE = 5_000;
    try {
        const { a, b, restore } = pair();
        const data = bytes(9_000);
        b.on("request", (request) => setTimeout(() => {
            sendSplit(b, MsgPack.pack([request.requestId, data]), { requestId: request.requestId, isResponse: true, between: () => sleep(7_000) })
                .catch(() => {});
        }, 1_000));
        const id = a.sendRequest("/distro/pull", null, { timeoutMs: 20_000 });
        const response = await within(a.responseFor(id), 120_000, "the split response");
        assert.ok(Buffer.from(response).equals(data));
        assert.deepEqual(lines, [], "the response began 1 s after delivery");
        assert.ok(bulk.some((m) => /VIOLATION received split response Resource .* waiting for segment 2\/2: no progress for 5 s/.test(m)),
            `the 7 s between segments is the bulk rule's: ${JSON.stringify(bulk)}`);
        restore();
    } finally {
        Resource.MAX_EFFICIENT_SIZE = saved;
    }
});

test("responseWatch: false keeps no watch on the request: a caller that watches it itself (a channel post's publish)", async () => {
    const { a, b, restore } = pair();
    answerAfter(b, 6_500);
    const id = a.sendRequest("/channel/publish", null, { timeoutMs: 20_000, responseWatch: false });
    assert.equal(await within(a.responseFor(id), 30_000, "the response"), true);
    assert.deepEqual(lines, []);
    restore();
});

test("both §1 lines carry their NEVER REMOVE comment, and a channel post's publish keeps only its own watch", async () => {
    const link = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");
    const marked = link.match(/\/\/ NEVER REMOVE EVER — see DESIGN_PRINCIPLES\.md §1\n\s+Link\.requestLog\.error\?\.\(`\[§1\] VIOLATION/g) ?? [];
    assert.equal(marked.length, 2);
    assert.equal((link.match(/Link\.requestLog\.error/g) ?? []).length, 2, "every line of the watch is marked");
    const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
    const publish = app.slice(app.indexOf("link.sendRequestPacked(CHANNEL_PUBLISH_PATH"), app.indexOf("link.responseFor(requestId).then("));
    assert.match(publish, /onDelivered: \(\) => this\._channelPublishes\.left\(tracked\)/);
    assert.match(publish, /responseWatch: false/);
});
