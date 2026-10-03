/**
 * A CHANNEL POST'S STATUS REACHES ITS BUBBLE, DECIDED BY RFED'S ANSWER:
 * the app's side of lib/channel_publish.js, over a real link.
 *
 * 2026-10-01, after the retichat.com deploy, James: "Channels don't seem to
 * update their chat send indicator when a message successfully hits the
 * rfed node." Reproduced on the private staging chain (Retichat-js f56346c,
 * the code in production): a post through the composer, its record and its
 * bubble sampled every 25 ms. The record went "sent" 1.6 s after the send
 * (rfed's proof +1596 ms, its echo +1597 ms) and 0.55 s on a second post;
 * the bubble said "sending" 25 s later, both times. sendChannelMessage
 * wrote "sent" to the store and announced only channel-send-complete, an
 * event the open chat answers by adding rows that are missing.
 *
 * 2af0e9b fixed the bubble and decided on rfed's echo of the post. Its
 * review, on the same chain: a 30 KB post's echo is a Resource of its own
 * (8.8 s), so its §1 line counted that whole transfer against 5 s; a 60 KB
 * post was shown failed while rfed's echo of it was still arriving, 15 s
 * after rfed had stored it; and the connection's stop forgot a failed post,
 * so its echo could not make it "sent". The post is now the /channel/publish
 * request on rfed.link (RFed-spec/Link.md), and rfed's answer, one packet
 * from the same ingest, decides it whatever its size.
 *
 * These run the shipped sendChannelMessage, _setChannelPostStatus,
 * _handleChannelPacket, _onRfedLinkPush, _onPacketsLost and disconnect over
 * the real ChannelMsgStore, the real channel envelope, the real
 * ChannelPublishes and two real Links joined in-process (test_link_pair.mjs):
 * the client's rfed.link and rfed's end of it, which the test drives as rfed
 * does (the request, its answer, its fan-out pushed back as /delivery). All
 * on virtual time (test_virtual_time.mjs), so a delay on the wire is a
 * delay, however loaded the machine. channel_send_status_page.test.mjs runs
 * the real page.
 *
 * Run: node --test channel_send_status.test.mjs
 */
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import { channelLxmPack, channelLxmUnpack, channelIdentity, channelComputeStamp } from "./lib/rns/rfed_channel.js";
import { ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { ChannelPublishes, CHANNEL_PUBLISH_PATH } from "./lib/channel_publish.js";
import { DistroUploads } from "./lib/distro_upload.js";
import { app, build, constValue, install, methodBody, memoryStorage, compile } from "./test_app_source.mjs";
import { linkPair, within } from "./test_link_pair.mjs";
import { installVirtualTime } from "./test_virtual_time.mjs";

const CHANNEL = "public.indicator";
const CEILING = 14_500;
const quiet = { log() {}, warn() {}, error() {} };
const RFED_LINK_PUSH_HASHES = constValue("RFED_LINK_PUSH_HASHES", {
    Cryptography, Buffer,
    RFED_LINK_PUSH_DELIVERY: constValue("RFED_LINK_PUSH_DELIVERY"),
    RFED_LINK_PUSH_LXMF: constValue("RFED_LINK_PUSH_LXMF"),
    RFED_LINK_PUSH_NOTIFY: constValue("RFED_LINK_PUSH_NOTIFY"),
});
const PUBLISH_PATH_HASH = Cryptography.truncatedHash(Buffer.from("/channel/publish", "utf8")).toString("hex");

let clock = null;
let bulkLog = null;
const bulkLines = [];
beforeEach(() => {
    clock = installVirtualTime();
    bulkLog = Resource.bulkLog;
    bulkLines.length = 0;
    Resource.bulkLog = { error: (l) => bulkLines.push(l), warn: (l) => bulkLines.push(l), log() {} };
});
afterEach(() => {
    Resource.bulkLog = bulkLog;
    clock.uninstall();
    clock = null;
});

/**
 * A client that holds #public.indicator, with its rfed.link (`a`) joined to
 * rfed's end (`b`). `rfed.publishes` holds each /channel/publish request rfed
 * took; `rfed.answer(i, value)` answers one, `rfed.push(i)` is rfed's fan-out
 * of it back to this device (a /delivery request on the link). `events` holds
 * every event the client gives the UI, with the post's stored status then.
 */
function client({ subscribe = async () => null, pair = {} } = {}) {
    const me = Identity.create();
    const storage = memoryStorage();
    const ChannelMsgStore = build("ChannelMsgStore", { sGet: storage.sGet, sSet: storage.sSet });
    const names = { get: storage.sGet, set: storage.sSet };
    const channel = { channelName: CHANNEL, channelHash: channelIdentity(CHANNEL).hash.toString("hex"), stampCost: null, isSubscribed: true };
    const ChannelStore = { get: (n) => (n === CHANNEL ? channel : null), getByHash: (h) => (h === channel.channelHash ? channel : null), touch() {} };
    const own = Destination.hash(me, "lxmf", "delivery").toString("hex");

    const { a, b, wire } = linkPair({ rttMs: 50, ...pair });
    const lines = [];
    const publishes = new ChannelPublishes({ log: { error: (line) => lines.push(line) } });

    const env = {
        IdMgr: { has: true, id: me, hash: me.hash.toString("hex") }, Destination, Link, Buffer, MsgPack, console: quiet,
        ChannelMsgStore, ChannelStore, channelLxmPack, channelLxmUnpack, channelComputeStamp, CHANNEL_PUBLISH_PATH,
        ChannelPostNamesStore: new ChannelPostNames(names), ChannelSenderNamesStore: new ChannelSenderNames(names),
        OwnNames: { channel: null }, rfedRequestTimeoutMs: () => CEILING, RFED_LINK_PUSH_HASHES,
        DistroManager: { has: false }, Harness: { event() {} }, ContactStore: { keep: () => null },
        ownLxmfDestinationHash: () => own, sentTimeMs, MsgStore: { get: () => [] },
    };
    const events = [];
    const linksAsked = [];
    const self = {
        _onMsg: [], _rfedSendChain: Promise.resolve(), _pendingPacketHashes: new Map(), _pendingTimeouts: new Map(),
        _channelPublishes: publishes,
        _rfedLinks: new Map([["link", a]]),
        _exchangeIsDown: () => false,
        _ensureChannelSubscribed: subscribe,
        _ensureChannelStreamConfigured: async () => {},
        _rfedLinkAvailable: () => true,
        _waitForRfedService: async () => assert.fail("rfed.link is known"),
        _ensureRfedLink: async (aspects) => { linksAsked.push(aspects.join(".")); return a; },
    };
    install(self, env, [
        "sendingIdentity()",
        "async sendChannelMessage(channelName, content)",
        "_setChannelPostStatus(channelName, msgId, status)",
        "_handleChannelPacket(packetData)",
        "_onPacketsLost({ packetHashes, reason })",
        "_onRfedLinkPush(link, requestId, pathHash, data)",
    ]);
    // _ensureRfedLink's own wiring of rfed.link: the node's pushes.
    a.on("request", ({ requestId, path, data }) => self._onRfedLinkPush(a, requestId, path, data));

    const record = () => ChannelMsgStore.get(CHANNEL).find((m) => m.dir === "out");
    self._onMsg.push((msg, name) => events.push({ kind: msg?.kind ?? "status", name, status: record()?.status ?? null }));

    const rfed = { publishes: [], waiting: [] };
    b.on("request", (r) => {
        if (Buffer.from(r.path).toString("hex") !== PUBLISH_PATH_HASH) return;
        rfed.publishes.push(r);
        rfed.waiting.splice(0).forEach((w) => w());
    });
    /** rfed has taken publish `i`. */
    rfed.took = (i = 0) => (rfed.publishes.length > i ? Promise.resolve()
        : within(new Promise((resolve) => rfed.waiting.push(() => rfed.publishes.length > i && resolve())), 60_000, `rfed takes publish ${i}`));
    rfed.answer = (i = 0, value = [true, null]) => b.sendResponse(rfed.publishes[i].requestId, value);
    /** rfed's fan-out of publish `i` to this subscriber on rfed.link: channel_hash | blob. */
    rfed.push = (i = 0) => b.sendRequest("/delivery", Buffer.from(rfed.publishes[i].data));

    /** Resolve once the post's record says `status`. */
    const recordSays = (status, label = status) => within(new Promise((resolve) => {
        const check = () => (record()?.status === status ? resolve() : setTimeout(check, 1));
        check();
    }), 60_000, `the record says ${label}`);
    return { self, a, b, wire, rfed, events, record, recordSays, lines, own, linksAsked };
}

const outcome = (promise) => promise.then(() => "sent", (e) => `failed: ${e.message}`);
const statusEvents = (c) => c.events.map((e) => [e.kind, e.status]);

test("a post is one /channel/publish request on rfed.link; rfed pushes it back and answers, and the bubble says sent at once", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "hello channel"));
    await c.rfed.took(0);
    assert.deepEqual(c.linksAsked, ["link"], "on rfed.link, not on rfed.channel");
    assert.equal(c.wire.a.filter((p) => p.context === Packet.REQUEST).length, 1, "one REQUEST packet");
    const data = Buffer.from(c.rfed.publishes[0].data);
    assert.equal(data.subarray(0, 16).toString("hex"), channelIdentity(CHANNEL).hash.toString("hex"), "rfed's ingest form: channel_hash | blob");
    assert.equal(channelLxmUnpack(CHANNEL, data)?.content, "hello channel");
    assert.equal(c.record().status, "sending");

    // rfed's ingest: it stores the post, fans it out (this device too), and answers.
    c.rfed.push(0);
    c.rfed.answer(0);
    assert.equal(await sending, "sent");
    assert.equal(c.record().status, "sent");
    const sentAt = c.events.findIndex((e) => e.kind === "status");
    assert.deepEqual(c.events[sentAt], { kind: "status", name: CHANNEL, status: "sent" }, "the status event comes with the change");
    assert.deepEqual(statusEvents(c), [["channel-send-pending", "sending"], ["status", "sent"], ["channel-send-complete", "sent"]]);
    assert.equal(c.self._pendingPacketHashes.size, 0, "nothing is left waiting");
    assert.deepEqual(c.lines, []);
    c.a.close();
});

test("rfed's answer alone makes it sent: no echo is needed (a device whose stream is not bound gets none)", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "no stream"));
    await c.rfed.took(0);
    c.rfed.answer(0, [true, null]);
    assert.equal(await sending, "sent");
    assert.equal(c.record().status, "sent");
    assert.deepEqual(c.lines, []);
    c.a.close();
});

test("rfed's refusal fails the post at once with rfed's reason, and the bubble is told", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "bad stamp"));
    await c.rfed.took(0);
    const before = Date.now();
    c.rfed.answer(0, [false, "stamp_invalid"]);
    assert.equal(await sending, "failed: rfed refused it (stamp_invalid)");
    assert.ok(Date.now() - before < 1_000, "at the answer, not at a ceiling");
    assert.equal(c.record().status, "failed");
    assert.deepEqual(statusEvents(c), [["channel-send-pending", "sending"], ["status", "failed"], ["channel-send-complete", "failed"]]);
    c.a.close();
});

test("a large post: its request Resource takes seconds, rfed answers as it ingests, and the bubble says sent while rfed's echo of it is still arriving; no §1 line", async () => {
    // Every Resource part takes 1.8 s on the wire, both ways: the request
    // Resource and rfed's echo of it (a /delivery request Resource) each
    // take several seconds. The answer is one packet.
    const c = client({ pair: { rttMs: 2_000, delay: (p) => (p.context === Packet.RESOURCE ? 1_800 : 0) } });
    const text = "long post ".repeat(800);
    const startedAt = Date.now();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, text));
    await c.rfed.took(0);
    const tookAt = Date.now();
    assert.ok(tookAt - startedAt > 5_000, `the request Resource took ${tookAt - startedAt} ms: over 5 s, and not a §1 matter (bulk transfers)`);
    assert.equal(c.wire.a.filter((p) => p.context === Packet.REQUEST).length, 0, "no REQUEST packet: a request Resource");
    assert.equal(channelLxmUnpack(CHANNEL, Buffer.from(c.rfed.publishes[0].data))?.content, text);

    // rfed's ingest: the fan-out first (a Resource back to this device), then the answer.
    c.rfed.push(0);
    c.rfed.answer(0);
    assert.equal(await sending, "sent");
    const sentAt = Date.now();
    assert.ok(sentAt - tookAt < 1_000, `sent ${sentAt - tookAt} ms after rfed took it`);
    assert.ok(c.a.incomingResources.length > 0, "rfed's echo of it is still a transfer in progress");
    assert.equal(c.record().status, "sent");

    // The echo concludes later and changes nothing.
    await within(new Promise((resolve) => {
        const check = () => (c.a.incomingResources.length === 0 ? resolve() : setTimeout(check, 50));
        check();
    }), 60_000, "the echo's Resource ends");
    assert.ok(Date.now() - sentAt > 2_000, "the echo came seconds after the answer");
    assert.equal(c.record().status, "sent");
    assert.deepEqual(statusEvents(c).filter(([k]) => k === "status"), [["status", "sent"]], "shown once");
    assert.deepEqual(c.lines, [], "no §1 line: the request was held when its Resource was proved, and answered at once");
    assert.deepEqual(bulkLines.filter((l) => /VIOLATION/.test(l)), [], "each transfer kept moving");
    c.a.close();
});

test("an exchange that lost the request packet fails the post at once; rfed's answer, should rfed have taken it, makes it sent", async () => {
    const c = client();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "into a failing exchange"));
    await c.rfed.took(0);
    const request = c.wire.a.find((p) => p.context === Packet.REQUEST);
    c.self._onPacketsLost({ packetHashes: [request.getHash().toString("hex")], reason: "HTTP 502" });
    assert.equal(c.record().status, "failed", "a definite failure: not the ceiling");
    assert.equal(c.events.at(-1).kind, "status", "the failure is shown");
    assert.equal(await sending, "failed: its packet was lost (HTTP 502)");
    c.rfed.answer(0);
    await c.recordSays("sent");
    assert.deepEqual(c.events.filter((e) => e.kind === "status").map((e) => e.status), ["failed", "sent"]);
    assert.deepEqual(c.lines, []);
    c.a.close();
});

test("no answer: the §1 watch says so at 5 s, the request's own budget fails the post, and rfed's echo after that makes it sent", async () => {
    const c = client();
    const startedAt = Date.now();
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "silent node"));
    await c.rfed.took(0);
    assert.equal(await sending, `failed: no response within ${CEILING} ms`);
    assert.ok(Date.now() - startedAt >= CEILING, "the budget, from the moment rfed held the request");
    assert.equal(c.record().status, "failed");
    assert.equal(c.lines.length, 1);
    assert.match(c.lines[0], /§1 VIOLATION: rfed has not answered the publish of channel post .* within 5 s of holding it \(the post is still sending\)/);

    c.self._handleChannelPacket(Buffer.from(c.rfed.publishes[0].data));
    assert.equal(c.record().status, "sent", "rfed has it after all: the truth outranks the failure");
    assert.equal(c.events.at(-1).status, "sent");
    c.a.close();
});

test("a request Resource that fails fails the post on that event, and no §1 clock ran", async () => {
    const c = client({ pair: { drop: (p, from) => from === "a" && p.context === Packet.RESOURCE_ADV } });
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "unreachable ".repeat(100)));
    assert.match(await sending, /^failed: sending the request as a Resource failed: /);
    assert.equal(c.record().status, "failed");
    assert.equal(c.rfed.publishes.length, 0);
    assert.deepEqual(c.lines, [], "rfed never held it");
    c.a.close();
});

test("disconnect(): the shipped stop closes rfed.link, which fails the post; rfed's echo on the next connection makes it sent", async () => {
    const c = client();
    Object.assign(c.self, {
        _annTimer: null, _unhookPageLifecycle() {}, _rfedReopenArmed: new Set(), _pendingTickets: new Map(),
        _rfedLinkPromises: new Map(), _rfedServiceReady: new Set(["link"]), _rfedServiceWaiters: new Map(),
        _rfedOpenedChannelHashes: new Set(), _rfedPullState: new Map(), _rfedStampRefreshed: new Set(),
        _rfedSubscriptionPromises: new Map(), _rfedUnsubscribes: new Map(), _rfedStreamPromises: new Map(), _groupLinks: new Map(),
        _groupLinkPromises: new Map(), _groupPeerReady: new Set(), _groupPeerWaiters: new Map(),
        _groupPathsRequested: new Set(), _groupFallbacks: new Map(), _setStatus() {},
        _distroUploads: new DistroUploads(), _distroOutboxInFlight: new Map(),
    });
    const disconnect = compile("disconnect()", { clearInterval() {}, clearTimeout() {}, console: quiet })(c.self);
    const sending = outcome(c.self.sendChannelMessage(CHANNEL, "posted as the tab was taken over"));
    await c.rfed.took(0);
    disconnect();
    assert.equal(c.a.status, Link.CLOSED);
    assert.equal(await sending, "failed: the link closed before a response");
    assert.equal(c.record().status, "failed");
    assert.equal(c.events.at(-1).kind === "status" || c.events.at(-1).kind === "channel-send-complete", true);
    assert.ok(c.events.some((e) => e.kind === "status" && e.status === "failed"), "the failure is shown");

    // rfed had it, and the next connection's stream (or pull) brings it back.
    assert.equal(c.self._handleChannelPacket(Buffer.from(c.rfed.publishes[0].data)), true, "held, never shown twice");
    assert.equal(c.record().status, "sent");
    assert.equal(c.events.at(-1).status, "sent");
    assert.deepEqual(c.lines, []);
});

test("a post that fails before it is published (the subscription is refused) is failed, and the bubble is told", async () => {
    const c = client({ subscribe: async () => { throw new Error("RFed refused subscription"); } });
    assert.equal(await outcome(c.self.sendChannelMessage(CHANNEL, "refused")), "failed: RFed refused subscription");
    assert.equal(c.record().status, "failed");
    assert.deepEqual(statusEvents(c), [["channel-send-pending", "sending"], ["status", "failed"], ["channel-send-complete", "failed"]]);
    assert.equal(c.rfed.publishes.length, 0);
    assert.deepEqual(c.linksAsked, []);
    c.a.close();
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
