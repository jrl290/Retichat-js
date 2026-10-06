/**
 * REGRESSION GUARD — a link attempt whose LINKREQUEST is lost fails at once.
 *
 * Review of 2026-09-30: an attempt could start while the exchange still
 * counted as up (a fetch in flight), and lose its LINKREQUEST when that
 * exchange then failed. PostInterface reports exactly that ("lost": the
 * batch of a failed or abandoned exchange, or a packet handed to a down
 * exchange), but the attempt ignored it and waited out its establishment
 * timeout. When the exchange came back within it, the doomed attempt
 * swallowed the return (_redriveRfedLink starts nothing while an attempt is
 * coming up), failed, and was parked for an rfed.link announce that comes
 * every 6 h.
 *
 * Now Reticulum hands the interface's report to the link
 * (Link.requestLost), which closes at once — a named event, not a clock
 * (DESIGN_PRINCIPLES §1), as app-links fails an attempt with no usable
 * interface at once (SendErr::NoUsableInterface). RNS waits
 * establishment_timeout; link.js says why this departs. Not for an
 * exchange a check abandoned: its batch may have reached the node, so that
 * attempt waits for its LRPROOF or its timeout, as in RNS.
 *
 * The real PostInterface runs against a scripted node (a fake fetch) inside
 * a real Reticulum, with real Links. The app test runs the real shipped
 * method bodies from app.js. Timers of 0 ms (the EventEmitter's deferral)
 * run for real; every other timer is captured, and fired only by hand.
 *
 * Run: node --test link_request_lost.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { Reticulum, Identity, Destination, Link, Packet } from "./lib/rns/reticulum.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";
import Interface from "./lib/rns/interfaces/interface.js";
import { compile, constValue, methodName } from "./test_app_source.mjs";
import { DistroUploads } from "./lib/distro_upload.js";

// ── Harness (as exchange_truth.test.mjs) ───────────────────────────────────

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const tick = () => new Promise((resolve) => realSetTimeout(resolve, 0));

/** Wait (a few macrotasks at most) for `probe` to return something truthy. A failure mechanism only. */
async function eventually(probe, what) {
    for (let i = 0; i < 100; i++) {
        const value = probe();
        if (value) return value;
        await tick();
    }
    throw new Error(`never happened: ${what}`);
}

function fakeTimers(t) {
    const timers = [];
    globalThis.setTimeout = (fn, ms, ...args) => {
        if (!ms) return realSetTimeout(fn, 0, ...args);
        const timer = { fn, ms, cleared: false, fired: false };
        timers.push(timer);
        return timer;
    };
    globalThis.clearTimeout = (timer) => {
        if (timer && typeof timer === "object" && "cleared" in timer) timer.cleared = true;
        else realClearTimeout(timer);
    };
    t.after(() => { globalThis.setTimeout = realSetTimeout; globalThis.clearTimeout = realClearTimeout; });
    return {
        timers,
        armed: (ms) => timers.filter((x) => !x.cleared && !x.fired && (ms === undefined || x.ms === ms)),
        fire(timer) { timer.fired = true; timer.fn(); },
    };
}

function fakeNode(t) {
    const requests = [];
    globalThis.fetch = (url, options) => new Promise((resolve, reject) => {
        const request = {
            path: new URL(url).pathname.replace(/^\/reticulum/, ""),
            body: JSON.parse(options.body),
            settled: false,
            respond(status, json = {}) {
                if (request.settled) return;
                request.settled = true;
                resolve({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(json) });
            },
            fail(message = "Failed to fetch") {
                if (request.settled) return;
                request.settled = true;
                reject(new TypeError(message));
            },
        };
        options.signal?.addEventListener("abort", () => {
            if (request.settled) return;
            request.settled = true;
            reject(new DOMException("The operation was aborted.", "AbortError"));
        });
        requests.push(request);
    });
    t.after(() => { delete globalThis.fetch; });
    return {
        requests,
        pending: (path) => eventually(
            () => requests.find((r) => !r.settled && r.path === `/v1/interfaces/${path}`),
            `a ${path} request`),
        /** Every LINKREQUEST the node was handed, as packet hashes (hex). */
        linkRequests: () => requests.flatMap((r) => r.body.packets ?? [])
            .map((b64) => Packet.fromBytes(Buffer.from(b64, "base64")))
            .filter((p) => p.packetType === Packet.LINKREQUEST)
            .map((p) => p.packetHash.toString("hex")),
    };
}

const REGISTERED = {
    interface_id: "1".repeat(32), session_token: "2".repeat(32),
    idle_exchange_interval_ms: 1000, max_batch_packets: 64, max_packet_bytes: 500,
};

const quiet = (t) => {
    const { log, warn, error } = console;
    console.log = () => {}; console.warn = () => {}; console.error = () => {};
    t.after(() => Object.assign(console, { log, warn, error }));
};

/** A real Reticulum whose one interface is a real PostInterface, up. */
async function upExchange(t, node, { rns = new Reticulum(), before } = {}) {
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    before?.(iface); // RnsClient.connect: _followExchange(iface) before addInterface
    rns.addInterface(iface);
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => iface.isUp, "up");
    return { rns, iface };
}

const rfedNode = Identity.create();
const linkDestination = (rns) => new Destination(rns, rfedNode, Destination.OUT, Destination.SINGLE, "rfed", "link");
const ESTABLISHMENT_MS = (Link.DEFAULT_PER_HOP_TIMEOUT + Link.ESTABLISHMENT_TIMEOUT_PER_HOP * Link.DEFAULT_ESTABLISHMENT_HOPS) * 1000;

/** A link attempt over `rns`, its "close" events recorded. */
function attempt(rns) {
    const link = new Link();
    const closes = [];
    link.on("close", () => closes.push(link.closeReason));
    link.establish(linkDestination(rns));
    return { link, closes };
}

// ── The stack ──────────────────────────────────────────────────────────────

test("an attempt whose LINKREQUEST a failed exchange takes with it fails at once, not on its establishment timeout", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { rns } = await upExchange(t, node);

    const { link, closes } = attempt(rns);
    const [watchdog] = clock.armed(ESTABLISHMENT_MS);
    assert.ok(watchdog, "the establishment watchdog is armed, as RNS arms it");
    const carrying = await node.pending("exchange");
    assert.deepEqual(node.linkRequests(), [link.requestPacketHash], "the LINKREQUEST is in this batch, under the hash the interface reports");

    carrying.fail();
    await eventually(() => closes.length === 1, "the attempt closed");
    assert.equal(link.status, Link.CLOSED);
    assert.equal(link.closeReason, Link.TIMEOUT, "the reason an establishment that does not complete gets");
    assert.match(link.requestLostReason, /Failed to fetch/, "and why");
    assert.equal(watchdog.fired, false, "no clock decided it");
    assert.equal(watchdog.cleared, true, "and none is left running");
});

test("an attempt started while the exchange is down fails at once, and nothing leaves the browser", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { rns, iface } = await upExchange(t, node);
    clock.fire(clock.armed(1000)[0]);
    (await node.pending("exchange")).fail();
    await eventually(() => iface.isDown, "down");

    const sent = node.requests.length;
    const { link, closes } = attempt(rns);
    await eventually(() => closes.length === 1, "the attempt closed");
    assert.equal(link.status, Link.CLOSED);
    assert.match(link.requestLostReason, /down/);
    assert.equal(clock.armed(ESTABLISHMENT_MS).length, 0);
    assert.equal(node.requests.length, sent, "the LINKREQUEST never left");
});

/**
 * The node's answer to a LINKREQUEST it took: a real responder (the
 * rfed.link destination in a second Reticulum) accepts it and proves it.
 * Returns the LRPROOF as the exchange delivers it (base64).
 */
async function lrproofFor(requestBase64) {
    class Capture extends Interface {
        constructor() { super("rfed side"); this.sent = []; }
        connect() {}
        sendData(data) { this.sent.push(Buffer.from(data)); }
    }
    const rfed = new Reticulum();
    const wire = new Capture();
    rfed.addInterface(wire);
    const destination = rfed.registerDestination(rfedNode, Destination.IN, Destination.SINGLE, "rfed", "link");
    destination.on("link_request", (link) => link.accept());
    rfed.onPacketReceived(Packet.fromBytes(Buffer.from(requestBase64, "base64")), wire);
    const [proof] = await eventually(() => wire.sent.length && wire.sent, "the node's LRPROOF");
    assert.equal(Packet.fromBytes(proof).context, Packet.LRPROOF);
    return proof.toString("base64");
}

test("an exchange a check abandoned does not fail the attempt: the node may have taken its LINKREQUEST, and the LRPROOF the next exchange brings establishes the link", async (t) => {
    // Review of 2026-09-30: requestLost closed the attempt for every report,
    // also for the batch of an exchange check() abandoned (the page became
    // visible, came online, or back from the cache), whose fate cannot be
    // known. When the node had taken it, its LRPROOF came in the exchange
    // check() started and was dropped; and as an abandoned exchange marks no
    // "down", no return followed to re-drive the link.
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { rns, iface } = await upExchange(t, node);

    const { link, closes } = attempt(rns);
    const [watchdog] = clock.armed(ESTABLISHMENT_MS);
    const carrying = await node.pending("exchange");
    const [request] = carrying.body.packets;
    assert.deepEqual(node.linkRequests(), [link.requestPacketHash]);

    iface.check("visible"); // the fetch may hang on a dead connection: abandoned
    const next = await node.pending("exchange"); // check() exchanges again at once
    assert.notEqual(next, carrying);
    await tick(); await tick();
    assert.equal(link.status, Link.PENDING, "an abandoned exchange is no proof that the request never left");
    assert.deepEqual(closes, []);
    assert.equal(link.requestLostReason, undefined);
    assert.equal(watchdog.cleared || watchdog.fired, false, "it waits for its LRPROOF or its establishment timeout, as RNS waits");
    assert.equal(iface.isDown, false, "and an abandoned exchange marks no down, so no return would re-drive a closed attempt");

    // The node had taken the batch: rfed's LRPROOF comes in the next exchange.
    next.respond(200, { delivery_packets: [await lrproofFor(request)] });
    await eventually(() => link.status === Link.ACTIVE, "the link established on the LRPROOF");
    assert.deepEqual(closes, []);
    assert.equal(watchdog.fired, false);
    assert.equal(node.linkRequests().length, 1, "nothing was sent again");

    // An abandoned report never fails an attempt, on any interface.
    const other = attempt(rns);
    rns.onPacketsLost(iface, { packetHashes: [other.link.requestPacketHash], reason: "exchange abandoned by a check", abandoned: true });
    await tick(); await tick();
    assert.equal(other.link.status, Link.PENDING);
    rns.onPacketsLost(iface, { packetHashes: [other.link.requestPacketHash], reason: "Failed to fetch" });
    await eventually(() => other.closes.length === 1, "a failed exchange's report fails it");
});

test("only a report of this attempt's own LINKREQUEST, from every interface it went to, while it waits for its proof, fails it", async (t) => {
    quiet(t);
    fakeTimers(t);
    class Silent extends Interface {
        connect() {}
        sendData() {}
    }
    const rns = new Reticulum();
    const a = new Silent("a");
    const b = new Silent("b");
    rns.addInterface(a);
    rns.addInterface(b);

    const { link, closes } = attempt(rns);
    const lost = (iface, packetHashes) => iface.emit("lost", { packetHashes, reason: "test" });
    lost(a, ["ff".repeat(32)]);
    await tick(); await tick();
    assert.equal(link.status, Link.PENDING, "another packet's loss");
    lost(a, [link.requestPacketHash]);
    await tick(); await tick();
    assert.equal(link.status, Link.PENDING, "still on its way on the other interface (one that never reports loss keeps the attempt to its watchdog)");
    lost(a, [link.requestPacketHash]);
    await tick(); await tick();
    assert.equal(link.status, Link.PENDING, "the same interface twice is still one interface");
    lost(b, [link.requestPacketHash]);
    await eventually(() => closes.length === 1, "lost on every interface it went to");
    assert.equal(link.status, Link.CLOSED);

    // A link that has its proof no longer depends on its request (an
    // abandoned batch may have reached the node after all).
    const up = attempt(rns);
    up.link.status = Link.ACTIVE;
    lost(a, [up.link.requestPacketHash]);
    lost(b, [up.link.requestPacketHash]);
    await tick(); await tick();
    assert.equal(up.link.status, Link.ACTIVE);
    assert.deepEqual(up.closes, []);
});

// ── The app: the exchange's return is not swallowed ─────────────────────────

const APP_CONSTS = Object.fromEntries([
    "RFED_PERSISTENT_KEYS", "RFED_LINK_IDLE", "RFED_LINK_ESTABLISHING", "RFED_LINK_ESTABLISHED",
    "RFED_LINK_FAILED", "RFED_PENDING_TIMEOUT_MS",
].map((name) => [name, constValue(name)]));

const APP_METHODS = [
    "_followExchange(iface)", "_onPageResume(trigger)", "_exchangeIsDown()", "_redriveRfedLink(key, trigger)",
    "_ensureRfedLink(aspects)", "_rfedPersistentBound(key)", "_rfedDeferUntilAnnounce(key, label, run)",
    "_rfedRunPending(key)",
];

test("the exchange's return is not swallowed by an attempt whose LINKREQUEST the failed exchange lost: it re-drives rfed.link once", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const env = {
        ...APP_CONSTS, Link, Date, console,
        IdMgr: { id: Identity.create() }, ActiveTab: { held: true }, DistroManager: { has: true },
        ChannelStore: { getAll: () => [] }, RFED_LINK_MAX_REQUEST_SIZE: 1_000_129,
    };
    const calls = [];
    const self = {
        _rfedLinks: new Map(), _rfedLinkPromises: new Map(), _rfedLinkState: new Map(), _rfedPending: new Map(),
        _rfedServiceReady: new Set(["link"]), _rfedReopenArmed: new Set(), _rfedOpenedChannelHashes: new Set(),
        _rfedStreamPromises: new Map(), _propLink: null,
        _setStatus() {}, _onExchangeRegistered() {}, _onPacketsLost() {}, _sendDistroNeverLeft() {},
        _onRfedLinkPush() {}, _handleChannelPacket() {}, _onRfedLinkClosed() {},
        _onRfedLinkEstablished: async () => { calls.push("established"); },
        _pullOpenedChannels: () => calls.push("channel-pull"),
        _pullDistroMessages: () => calls.push("distro-pull"),
        _fetchPropagatedMessages() {}, _redrivePropagationLink() {},
    };
    for (const signature of APP_METHODS) self[methodName(signature)] = compile(signature, env)(self);
    // RnsClient.connect(): the exchange is followed before addInterface() connects it.
    const rns = self._rns = new Reticulum();
    self._getRfedDest = () => linkDestination(rns);
    await upExchange(t, node, { rns, before: (iface) => self._followExchange(iface) });

    // rfed.link closed under us and is re-opened while the exchange still
    // counts as up; the exchange carrying the LINKREQUEST then fails.
    assert.equal(self._redriveRfedLink("link", "close"), true);
    const carrying = await node.pending("exchange");
    assert.equal(node.linkRequests().length, 1);
    const [doomed] = rns.links;
    carrying.fail();
    await eventually(() => self._rfedPending.has("link"), "the failed attempt is parked");
    assert.equal(doomed.status, Link.CLOSED, "failed on the interface's report");
    assert.equal(self._rfedLinkState.get("link"), APP_CONSTS.RFED_LINK_FAILED, "as any attempt that does not establish");
    assert.equal(self._rfedPending.get("link").label, "rfed.link re-open", "parked as every failed re-open is");
    assert.equal(self._rfedLinkPromises.has("link"), false, "nothing is coming up any more");
    assert.equal(clock.armed(ESTABLISHMENT_MS).length, 0, "and no establishment timeout is left to wait out");

    // The exchange comes back (the reconnect wait, then a 200).
    const [reconnect] = clock.armed(PostInterface.RECONNECT_WAIT_MS);
    clock.fire(reconnect);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => node.linkRequests().length === 2, "the return re-drove the link");
    const fresh = rns.links.at(-1);
    assert.notEqual(fresh, doomed);
    assert.equal(fresh.status, Link.PENDING, "one new attempt, on its way");
    assert.equal(self._rfedLinkPromises.has("link"), true);
    await tick(); await tick();
    assert.equal(node.linkRequests().length, 2, "exactly one: the return is one event");
    assert.deepEqual(calls, [], "nothing is pulled before a link is up");
});

const PROPAGATION_METHODS = [
    "_followExchange(iface)", "_onPageResume(trigger)", "_exchangeIsDown()", "_establishPropagationLink()",
    "_redrivePropagationLink(trigger)", "_onPropagationLinkClosed(link, established)",
];

test("the propagation link too: the attempt fails on its lost LINKREQUEST, waits for an event, and the exchange's return re-drives it once", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const propagationNode = Identity.create();
    const env = {
        Link, Identity, Buffer, Destination, Date, console, RFED_PERSISTENT_KEYS: constValue("RFED_PERSISTENT_KEYS"),
        IdMgr: { id: Identity.create() }, ActiveTab: { held: true }, DistroManager: { has: false }, RnsClient: {},
    };
    const calls = [];
    const self = {
        _cfg: { propagationNodePubKey: propagationNode.getPublicKey().toString("hex"), propagationNodeHash: "b".repeat(32) },
        _propLink: null, _propLinkPromise: null, _propReopenArmed: false, _distroUploads: new DistroUploads(),
        _rfedLinks: new Map(), _rfedReopenArmed: new Set(),
        _setStatus() {}, _onExchangeRegistered() {}, _onPacketsLost() {}, _sendDistroNeverLeft() {},
        _onPropagationLinkEstablished: async () => { calls.push("established"); },
        _redriveRfedLink: () => false, _pullOpenedChannels() {}, _pullDistroMessages() {},
        _fetchPropagatedMessages: () => calls.push("fetch"),
    };
    for (const signature of PROPAGATION_METHODS) self[methodName(signature)] = compile(signature, env)(self);
    const rns = self._rns = new Reticulum();
    await upExchange(t, node, { rns, before: (iface) => self._followExchange(iface) });

    // The node's announce (or an upload) starts an attempt; the exchange
    // carrying its LINKREQUEST fails.
    assert.equal(self._redrivePropagationLink("announce"), true);
    const doomed = self._propLink;
    const carrying = await node.pending("exchange");
    assert.deepEqual(node.linkRequests(), [doomed.requestPacketHash]);
    carrying.fail();
    await eventually(() => self._propLink === null, "the attempt is over");
    assert.equal(doomed.status, Link.CLOSED, "failed on the interface's report");
    assert.equal(self._propLinkPromise, null, "nothing is coming up");
    assert.equal(clock.armed(ESTABLISHMENT_MS).length, 0, "no establishment timeout left to wait out");

    // The exchange comes back: one new attempt.
    clock.fire(clock.armed(PostInterface.RECONNECT_WAIT_MS)[0]);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => node.linkRequests().length === 2, "the return re-drove the propagation link");
    assert.notEqual(self._propLink, doomed);
    assert.equal(self._propLink.status, Link.PENDING);
    await tick(); await tick();
    assert.equal(node.linkRequests().length, 2, "exactly one");
    assert.deepEqual(calls, []);
});
