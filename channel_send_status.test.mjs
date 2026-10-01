/**
 * A CHANNEL POST'S STATUS REACHES ITS BUBBLE: the app's side of
 * lib/channel_publish.js.
 *
 * 2026-10-01, after the retichat.com deploy, James: "Channels don't seem to
 * update their chat send indicator when a message successfully hits the
 * rfed node." Reproduced on the private staging chain (Retichat-js f56346c,
 * the code in production): a post through the composer, its record and its
 * bubble sampled every 25 ms. The record went "sent" 1.6 s after the send
 * (rfed's proof +1596 ms, its echo +1597 ms) and 0.55 s on a second post;
 * the bubble said "sending" 25 s later, both times. sendChannelMessage
 * wrote "sent" to the store and announced only channel-send-complete, an
 * event the open chat answers by adding rows that are missing; the one
 * event that repaints a bubble's status (msg null) came with rfed's proof,
 * while the record still said "sending". A failed post was never shown
 * either.
 *
 * These run the shipped sendChannelMessage, _setChannelPostStatus,
 * _handleChannelPacket and _onPacketsLost over the real ChannelMsgStore,
 * the real channel envelope and the real ChannelPublishes (on a clock the
 * test moves), with a stand-in rfed.channel link. channel_send_status_page.test.mjs
 * runs the real page.
 *
 * Run: node --test channel_send_status.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Link from "./lib/rns/link.js";
import { channelLxmPack, channelLxmUnpack, channelIdentity, channelComputeStamp } from "./lib/rns/rfed_channel.js";
import { ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { ChannelPublishes } from "./lib/channel_publish.js";
import { app, build, install, methodBody, memoryStorage } from "./test_app_source.mjs";

const CHANNEL = "public.indicator";
const CEILING = 14_500;
const quiet = { log() {}, warn() {}, error() {} };

/**
 * A client that holds #public.indicator and publishes to a stand-in
 * rfed.channel link: `link.sent` holds each publish, `link.resource` the
 * Resource of an oversized one (resolve or reject it). `events` holds every
 * event the client gives the UI, with the post's stored status when it came.
 */
function client({ subscribe = async () => null } = {}) {
    const me = Identity.create();
    const storage = memoryStorage();
    const ChannelMsgStore = build("ChannelMsgStore", { sGet: storage.sGet, sSet: storage.sSet });
    const names = { get: storage.sGet, set: storage.sSet };
    const channel = { channelName: CHANNEL, channelHash: channelIdentity(CHANNEL).hash.toString("hex"), stampCost: null, isSubscribed: true };
    const ChannelStore = { get: (n) => (n === CHANNEL ? channel : null), getByHash: (h) => (h === channel.channelHash ? channel : null), touch() {} };
    const own = Destination.hash(me, "lxmf", "delivery").toString("hex");

    let now = 2_000_000;
    let timers = [];
    const lines = [];
    const publishes = new ChannelPublishes({
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

    const link = {
        rtt: 500, sent: [], hashes: [], resource: null,
        send(payload) {
            this.sent.push(Buffer.from(payload));
            const packetHash = Buffer.alloc(32, this.sent.length);
            this.hashes.push(packetHash.toString("hex"));
            return { packetHash };
        },
        sendResource(payload) {
            this.sent.push(Buffer.from(payload));
            return new Promise((resolve, reject) => { this.resource = { resolve, reject }; });
        },
    };
    const env = {
        IdMgr: { has: true, id: me, hash: me.hash.toString("hex") }, Destination, Link, Buffer, console: quiet,
        ChannelMsgStore, ChannelStore, channelLxmPack, channelLxmUnpack, channelComputeStamp,
        ChannelPostNamesStore: new ChannelPostNames(names), ChannelSenderNamesStore: new ChannelSenderNames(names),
        OwnNames: { channel: null }, rfedRequestTimeoutMs: () => CEILING,
        DistroManager: { has: false }, Harness: { event() {} }, ContactStore: { keep: () => null },
        ownLxmfDestinationHash: () => own, sentTimeMs, MsgStore: { get: () => [] },
    };
    const events = [];
    const self = {
        _onMsg: [], _rfedSendChain: Promise.resolve(), _pendingPacketHashes: new Map(), _pendingTimeouts: new Map(),
        _channelPublishes: publishes,
        _exchangeIsDown: () => false,
        _ensureChannelSubscribed: subscribe,
        _ensureChannelStreamConfigured: async () => {},
        _ensureRfedLink: async () => link,
    };
    install(self, env, [
        "async sendChannelMessage(channelName, content)",
        "_setChannelPostStatus(channelName, msgId, status)",
        "_handleChannelPacket(packetData)",
        "_onPacketsLost({ packetHashes, reason })",
    ]);
    const record = () => ChannelMsgStore.get(CHANNEL).find((m) => m.dir === "out");
    self._onMsg.push((msg, name) => events.push({ kind: msg?.kind ?? "status", name, status: record()?.status ?? null }));
    /** rfed's echo of publish `i`: what it pushes back, the post without a stamp. */
    const echo = (i = 0) => self._handleChannelPacket(link.sent[i]);
    const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };
    return { self, link, events, record, echo, advance, settle, lines, timers: () => timers.length, own };
}

const outcome = (promise) => promise.then(() => "sent", (e) => `failed: ${e.message}`);

test("a post is sent when rfed's echo of it comes back, and the open chat is told so: the bubble's event follows the record", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "hello channel"));
    await c.settle();
    assert.equal(c.link.sent.length, 1, "published as one packet");
    assert.equal(c.record().status, "sending");

    // rfed's proof: it received the bytes. Not yet "sent" (it proves before
    // it checks the stamp and stores the post).
    const entry = c.self._pendingPacketHashes.get(c.link.hashes[0].slice(0, 32));
    assert.ok(entry?.channelPost, "the publish packet is known for its proof and a lost exchange");
    entry.onProof(entry.messageId);
    await c.settle();
    assert.equal(c.record().status, "sending", "the proof alone is not sent");

    // rfed's echo (its fan-out to this subscriber): rfed has the post.
    const before = c.events.length;
    c.advance(7);
    assert.equal(c.echo(), true, "the echo is held, never shown twice");
    assert.equal(c.record().status, "sent");
    assert.deepEqual(c.events.slice(before, before + 1), [{ kind: "status", name: CHANNEL, status: "sent" }],
        "the status event comes with the change, so the bubble repaints at once");
    assert.equal(await sending, "sent");
    await c.settle();
    assert.deepEqual(c.events.map((e) => [e.kind, e.status]),
        [["channel-send-pending", "sending"], ["status", "sent"], ["channel-send-complete", "sent"]]);
    assert.equal(c.self._pendingPacketHashes.size, 0, "nothing is left waiting");
    assert.equal(c.timers(), 0);
    assert.deepEqual(c.lines, []);
});

test("rfed's echo alone makes it sent: a proof lost on its way back does not fail a post rfed has", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "proof lost"));
    await c.settle();
    c.advance(1_000);
    c.echo();
    assert.equal(c.record().status, "sent");
    assert.equal(await sending, "sent");
    c.advance(CEILING * 2);
    assert.equal(c.record().status, "sent", "nothing fails it later");
});

test("no echo: the ceiling fails the post, the bubble is told, and an echo after that still makes it sent (§1 said)", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "slow node"));
    await c.settle();
    c.advance(CEILING - 1);
    assert.equal(c.record().status, "sending", "the ceiling is the last resort, from the moment the publish left");
    c.advance(1);
    assert.equal(c.record().status, "failed");
    assert.equal(c.events.at(-1).kind, "status", "the failure is shown");
    assert.match(await sending, /^failed: rfed sent no echo of the post within 14500 ms$/);
    await c.settle();

    c.advance(3_000);
    const before = c.events.length;
    assert.equal(c.echo(), true);
    assert.equal(c.record().status, "sent", "rfed has it after all: the truth outranks the failure");
    assert.deepEqual(c.events.slice(before), [{ kind: "status", name: CHANNEL, status: "sent" }]);
    assert.equal(c.lines.length, 1);
    assert.match(c.lines[0], /§1 VIOLATION: .* came 17500 ms after the publish left/);
});

test("an exchange that lost the publish packet fails the post at once; rfed's echo, should rfed have taken it, makes it sent", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "into a failing exchange"));
    await c.settle();
    c.advance(200);
    c.self._onPacketsLost({ packetHashes: [c.link.hashes[0]], reason: "HTTP 502" });
    assert.equal(c.record().status, "failed", "a definite failure: not the ceiling");
    assert.equal(c.events.at(-1).kind, "status");
    assert.equal(await sending, "failed: its packet was lost (HTTP 502)");
    assert.equal(c.timers(), 0, "the ceiling has nothing left to do");
    c.advance(400);
    c.echo();
    assert.equal(c.record().status, "sent");
    assert.deepEqual(c.lines, [], "600 ms after it left: within §1");
});

test("an oversized post goes as a Resource and waits for its echo from the Resource's proof; the Resource's failure fails it", async () => {
    const big = "x".repeat(900);
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, big));
    await c.settle();
    assert.ok(c.link.resource, "a Resource, not a packet");
    c.advance(CEILING * 3);
    assert.equal(c.record().status, "sending", "the transfer is not measured against the ceiling (§1 bulk transfers)");
    c.link.resource.resolve();
    await c.settle();
    c.advance(CEILING - 1);
    assert.equal(c.record().status, "sending");
    c.echo();
    assert.equal(c.record().status, "sent");
    assert.equal(await sending, "sent");

    const d = client();
    const failing = outcome(d.self.sendChannelMessage(CHANNEL, big));
    await d.settle();
    d.link.resource.reject(new Error("the Resource failed"));
    assert.equal(await failing, "failed: the Resource failed");
    assert.equal(d.record().status, "failed");
    assert.ok(d.events.some((e) => e.kind === "status" && e.status === "failed"), "the failure is shown");
});

test("rfed's echo that comes before its Resource reports a failure leaves the post sent", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "y".repeat(900)));
    await c.settle();
    c.echo();
    c.link.resource.reject(new Error("the proof was lost"));
    assert.equal(await sending, "sent", "rfed has the post");
    assert.equal(c.record().status, "sent");
});

test("a post that fails before it is published (the subscription is refused) is failed, and the bubble is told", async () => {
    const c = client({ subscribe: async () => { throw new Error("RFed refused subscription"); } });
    assert.equal(await outcome(c.self.sendChannelMessage(CHANNEL, "refused")), "failed: RFed refused subscription");
    assert.equal(c.record().status, "failed");
    assert.deepEqual(c.events.map((e) => [e.kind, e.status]),
        [["channel-send-pending", "sending"], ["status", "failed"], ["channel-send-complete", "failed"]]);
    assert.equal(c.link.sent.length, 0);
});

test("app.js changes a channel post's status only through _setChannelPostStatus, which tells the UI", () => {
    const calls = [...app.matchAll(/ChannelMsgStore\.updateStatus\(/g)].map((m) => m.index);
    const body = methodBody("_setChannelPostStatus(channelName, msgId, status)");
    const at = app.indexOf(body);
    assert.equal(calls.length, 1, "one call site");
    assert.ok(calls[0] > at && calls[0] < at + body.length, "and it is _setChannelPostStatus");
    assert.match(body, /this\._onMsg\.forEach\(fn => fn\(null, channelName\)\)/, "the status event");
});

test("the open chat brings each outgoing bubble to its record's status on every message event, patching only what differs", () => {
    const records = [
        { id: "a", dir: "out", status: "sent" },
        { id: "b", dir: "out", status: "sending" },
        { id: "c", dir: "in", status: "delivered" },
        { id: "d", dir: "out", status: "failed" },
        { id: "e", dir: "out", status: "sent" },
    ];
    const span = (status) => ({ getAttribute: (n) => (n === "data-msg-status" ? status : null) });
    const row = (id, status) => ({
        getAttribute: (n) => (n === "data-msg-id" ? id : null),
        querySelector: (q) => (q === ".msg-status" && status ? span(status) : null),
    });
    // a and b show "sending"; c has no status; d shows "failed"; e is not on screen.
    const rows = [row("a", "sending"), row("b", "sending"), row("c", null), row("d", "failed")];
    const list = { querySelectorAll: (q) => (q === ".msg-row[data-msg-id]" ? rows : []) };
    const patched = [];
    const self = {
        state: { activeHash: CHANNEL },
        _chatRecords: () => records,
        _statusIcon: (s) => ({ sending: "●", sent: "✓", failed: "✗", proved: "✓✓" })[s] ?? "",
        _updateMsgStatusDOM: (chat, id, status) => patched.push([chat, id, status]),
    };
    install(self, { document: { getElementById: (id) => (id === "msg-list" ? list : null) } }, ["_syncOpenChatStatuses()"]);
    self._syncOpenChatStatuses();
    assert.deepEqual(patched, [[CHANNEL, "a", "sent"]]);
    self.state.activeHash = null;
    self._syncOpenChatStatuses();
    assert.equal(patched.length, 1, "no open chat, nothing to do");
});
