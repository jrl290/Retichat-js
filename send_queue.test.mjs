/**
 * REGRESSION GUARD — a message sent while the page is initializing is
 * queued, not lost; a propagated copy is not lost while the propagation link
 * is initializing or re-establishing.
 *
 * James, 2026-09-24: "if a message is sent while the page connections are
 * initializing, the message should be queued until the initialization is
 * finished". Until then:
 *   - a DM sent before connect() finished threw "Not connected" (an alert,
 *     the text left in the composer), and a group message sent then failed
 *     on a TypeError;
 *   - a DM's propagated copy was dropped when the propagation link was not
 *     up ("cannot propagate", return), which is every send from a fresh
 *     browser that has not heard the node's announce yet;
 *   - _flushPropagation(), meant to send those once the link came up,
 *     iterated MsgStore._messages, which has never existed, so it never
 *     sent anything;
 *   - a superseded STALE propagation link's close rejected the attempt that
 *     replaced it and dropped it, and disconnect() left the old link in
 *     place for reconnect() to reuse on the stopped interface.
 *
 * The initialization-complete signal (DESIGN_PRINCIPLES §5) is the first
 * "registered" of this connection's exchange interface; there was none.
 *
 * These tests run the real shipped method bodies from app.js — and the real
 * MsgStore / GroupMsgStore over an in-memory localStorage — against stubs.
 * No clock decides a result: timers are captured and fired by hand.
 *
 * Run: node --test send_queue.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
const css = await readFile(new URL("./style.css", import.meta.url), "utf8");

function braceMatch(from, label) {
    const bodyStart = app.indexOf("{", from);
    let depth = 0;
    for (let i = bodyStart; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}") {
            depth--;
            if (depth === 0) return [bodyStart, i];
        }
    }
    throw new Error(`could not brace-match ${label}`);
}

function extractMethod(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const [open, close] = braceMatch(start + signature.length, signature);
    return app.slice(open + 1, close);
}

/** The object literal of a top-level `const NAME = { … };`. */
function extractObject(name) {
    const start = app.indexOf(`\nconst ${name} = {`);
    assert.notEqual(start, -1, `${name} is missing from app.js`);
    const [open, close] = braceMatch(start, name);
    return app.slice(open, close + 1);
}

/** A real method body, `this.` read as `self.`, its free names bound from env. */
function compile(signature, env) {
    const body = extractMethod(signature).replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
        .split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params,
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

const methodName = (signature) => signature.replace(/^async /, "").split("(")[0];
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");

// Link events are delivered on a later macrotask (utils/events.js defers every
// listener with setTimeout 0); a timer queued after the event observes them.
const afterLinkEvents = () => new Promise((resolve) => setTimeout(resolve, 0));

/** localStorage as sGet/sSet see it: JSON in, JSON out, survives a "reload". */
function makeStorage() {
    const data = new Map();
    return {
        data,
        sGet: (k) => (data.has(k) ? JSON.parse(data.get(k)) : null),
        sSet: (k, v) => data.set(k, JSON.stringify(v)),
    };
}

/**
 * A stub RnsClient carrying the real bodies of `methods`, over the real
 * message stores. Timers are captured, not run: `timers` holds {fn, ms}.
 */
function makeClient({ storage = makeStorage(), contacts = [], groups = [], methods = [], env: extra = {} } = {}) {
    let clock = 1_000;
    const FakeDate = { now: () => ++clock };
    const Harness = { recordInbound() {}, event() {}, error() {} };
    const MsgStore = new Function("sGet", "sSet", "Harness", "Date", `return ${extractObject("MsgStore")};`)(
        storage.sGet, storage.sSet, Harness, FakeDate);
    const GroupMsgStore = new Function("sGet", "sSet", "Date", `return ${extractObject("GroupMsgStore")};`)(
        storage.sGet, storage.sSet, FakeDate);
    const contactMap = new Map(contacts.map((c) => [c.destHash, c]));
    const ContactStore = {
        get: (h) => contactMap.get(h) ?? null,
        getAll: () => [...contactMap.values()],
        touch() {}, setReachable() {}, propagationDelay: () => 5,
    };
    const groupMap = new Map(groups.map((g) => [g.groupId, g]));
    const GroupStore = { get: (id) => groupMap.get(id) ?? null, getAll: () => [...groupMap.values()], _save() {} };
    const logs = [];
    const quiet = { log: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")) };
    const timers = [];
    const cleared = [];
    const env = {
        MsgStore, GroupMsgStore, ContactStore, GroupStore, Harness, console: quiet,
        setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
        clearTimeout: (id) => { if (id !== undefined) cleared.push(id); },
        Identity, Buffer, Destination, LXMessage, Link, Packet,
        ...extra,
    };
    const self = {
        _initialized: false,
        _onMsg: [],
        _pendingTimeouts: new Map(),
        _pendingPacketHashes: new Map(),
    };
    for (const signature of methods) self[methodName(signature)] = compile(signature, env)(self);
    return { self, MsgStore, GroupMsgStore, storage, logs, timers, cleared };
}

const peer = Identity.create();
const me = Identity.create();
const contactFor = (identity) => ({ destHash: lxmfHash(identity), publicKey: identity.getPublicKey().toString("hex"), isDistro: false });

// ── A/B: queued until initialization finishes ──────────────────────────────

const QUEUE_METHODS = ["sendMessage(contact, content)", "_dispatchQueued()", "_onExchangeRegistered()", "_exchangeIsDown()"];

function makeQueueClient(options) {
    const c = makeClient({ methods: QUEUE_METHODS, ...options });
    c.dispatched = [];
    c.self._dispatchMessage = (contact, msg) => {
        // What the store says at the moment of dispatch: the claim must
        // already be persisted.
        const stored = c.MsgStore.get(contact.destHash).find((m) => m.id === msg.id);
        c.dispatched.push({ to: contact.destHash, content: msg.content, waitForAtDispatch: stored.waitFor });
    };
    c.self.sendingIdentity = () => ({ identity: me, hash: null, isDistro: false }); // no router before connect()
    c.self._announce = () => {};
    c.self._requestPropagationPath = () => {};
    c.self._cfg = { rfedNodeHash: "" };
    return c;
}

test("a DM sent before initialization is stored queued, not thrown, and dispatched once when it finishes", () => {
    const alice = contactFor(peer);
    const bob = contactFor(Identity.create());
    // Bob is enumerated first; Alice's message is older and must go first.
    const c = makeQueueClient({ contacts: [bob, alice] });

    // Before connect(): no _rns, no _lxmfRouter. No "Not connected".
    const first = c.self.sendMessage(alice, "first");
    c.self.sendMessage(bob, "second");
    assert.equal(first.status, "queued");
    assert.equal(first.waitFor, "init");
    assert.equal(c.dispatched.length, 0, "nothing leaves before initialization");
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((m) => [m.dir, m.content, m.status, m.waitFor]),
        [["out", "first", "queued", "init"]], "persisted as queued");

    c.self._onExchangeRegistered();
    assert.equal(c.self._initialized, true);
    assert.deepEqual(c.dispatched.map((d) => d.content), ["first", "second"], "each once, oldest first");
    assert.deepEqual(c.dispatched.map((d) => d.waitForAtDispatch), [null, null], "claimed and persisted before dispatch");

    // A 401 re-registration fires "registered" again.
    c.self._onExchangeRegistered();
    assert.equal(c.dispatched.length, 2, "not again on a second registration");
    // Nor if the queue is walked again for any reason.
    c.self._dispatchQueued();
    assert.equal(c.dispatched.length, 2, "a claimed record is never dispatched twice");

    // Once initialized, a send goes at once.
    const third = c.self.sendMessage(alice, "third");
    assert.equal(third.status, "sending");
    assert.equal(third.waitFor, undefined);
    assert.deepEqual(c.dispatched.map((d) => d.content), ["first", "second", "third"]);
});

test("a queued DM survives a reload and goes after the next initialization", () => {
    const alice = contactFor(peer);
    const storage = makeStorage();
    const before = makeQueueClient({ storage, contacts: [alice] });
    before.self.sendMessage(alice, "typed while the page loaded");
    // The tab reloads before it initialized: a fresh client over the same localStorage.
    const after = makeQueueClient({ storage, contacts: [alice] });
    after.self._onExchangeRegistered();
    assert.deepEqual(after.dispatched.map((d) => d.content), ["typed while the page loaded"]);
    assert.equal(before.dispatched.length, 0);
});

test("a queued DM whose contact has no public key stays queued, and says so", () => {
    const alice = contactFor(peer);
    const c = makeQueueClient({ contacts: [alice] });
    c.self.sendMessage(alice, "held");
    alice.publicKey = null;
    try {
        c.self._onExchangeRegistered();
    } finally { alice.publicKey = peer.getPublicKey().toString("hex"); }
    assert.equal(c.dispatched.length, 0);
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((m) => [m.status, m.waitFor]), [["queued", "init"]]);
    assert.ok(c.logs.some((l) => l.includes("stays queued")), "logged");
});

test("sendMessage keeps the public-key guard", () => {
    const c = makeQueueClient({ contacts: [] });
    assert.throws(() => c.self.sendMessage({ destHash: "a".repeat(32), publicKey: null }, "x"), /No public key/);
});

test("a group message sent before initialization is queued and fanned out once when it finishes", async () => {
    const OWN = lxmfHash(me);
    const M1 = lxmfHash(peer);
    const M2 = "c".repeat(32);
    const group = { groupId: "9".repeat(32), groupName: "G", members: new Map([[OWN, "accepted"], [M1, "accepted"], [M2, "invited"]]) };
    const c = makeClient({
        groups: [group],
        methods: ["async sendGroupMessage(groupId, content)", "async _dispatchGroupMessage(groupId, outMsg)", ...QUEUE_METHODS],
    });
    c.self._announce = () => {};
    c.self._requestPropagationPath = () => {};
    c.self._cfg = { rfedNodeHash: "" };
    c.self.ownHash = null; // no router before connect()
    const fanouts = [];
    c.self._fanoutGroupEnvelope = async (targets, content, fields) => {
        fanouts.push({ targets, content, fields });
        return { fulfilled: targets.length, total: targets.length, methods: [] };
    };

    const stored = await c.self.sendGroupMessage(group.groupId, "hello group");
    assert.equal(stored.status, "queued");
    assert.equal(stored.waitFor, "init");
    assert.equal(fanouts.length, 0, "nothing leaves before initialization");

    c.self.ownHash = OWN; // connect() built the router
    c.self._onExchangeRegistered();
    await afterLinkEvents();
    assert.equal(fanouts.length, 1);
    assert.deepEqual(fanouts[0].targets, [M1], "own address and invited members excluded");
    assert.equal(fanouts[0].content, "hello group");
    assert.equal(fanouts[0].fields.groupSender, OWN);
    const after = c.GroupMsgStore.get(group.groupId)[0];
    assert.equal(after.status, "sent");
    assert.equal(after.waitFor, null);
    assert.equal(after.srcHash, OWN, "signed as whoever sent it once connected");

    c.self._onExchangeRegistered();
    c.self._dispatchQueued();
    await afterLinkEvents();
    assert.equal(fanouts.length, 1, "once");
});

test("a registration from an interface disconnect() stopped does not initialize the connection", () => {
    // The hooks live in _followExchange() since 2026-09-25 (U6); they are
    // driven for real in exchange_truth.test.mjs.
    assert.match(extractMethod("async connect()"), /this\._followExchange\(iface\);\s*this\._rns\.addInterface\(iface\);/);
    const follow = extractMethod("_followExchange(iface)");
    assert.match(follow, /const current = \(\) => this\._rns\?\.interfaces\?\.includes\(iface\);/);
    assert.match(follow, /iface\.on\("registered", \(\) => \{\s*if \(current\(\)\) this\._onExchangeRegistered\(\);/);
    assert.match(extractMethod("disconnect()"), /this\._initialized = false;/);
});

// ── C: the propagated copy is parked, never dropped ─────────────────────────

const PROPAGATION_METHODS = [
    "async _propagateMessage(contact, outMsg)", "async _flushPropagation()", "_signerFor(srcHash)",
    "_armSendCeiling(contactHash, msgId)", "_failSending(contactHash, msgId)",
];

/** The real propagation-link lifecycle, with only the wire handshake skipped. */
function makePropagationClient({ nodeKnown, contacts }) {
    const uploads = [];
    class OfflineLink extends Link {
        establish() { this.initiator = true; this.status = Link.PENDING; }
        async sendResource(data) { uploads.push(data); }
    }
    const node = Identity.create();
    const c = makeClient({
        contacts,
        methods: [...PROPAGATION_METHODS, "_establishPropagationLink()", "_ensurePropagationLink()"],
        env: { Link: OfflineLink, IdMgr: { id: me }, DistroManager: { has: false }, RnsClient: {} },
    });
    Object.assign(c.self, {
        _cfg: { propagationNodePubKey: nodeKnown ? node.getPublicKey().toString("hex") : "", propagationNodeHash: "b".repeat(32) },
        _rns: {
            registerDestination: (identity) => ({ hash: Destination.hash(identity, "lxmf", "delivery") }),
            sendData() {},
        },
        _propLink: null, _propLinkPromise: null, _propLinkUpWaiters: [],
        sendingIdentity: () => ({ identity: me, hash: lxmfHash(me), isDistro: false }),
        _fetchPropagatedMessages() {},
    });
    c.retries = [];
    c.self._retryPropagationLink = (ms) => c.retries.push(ms);
    c.built = [];
    c.self._buildPropagationPacked = async (packed, publicKeyHex) => {
        c.built.push({ packed, publicKeyHex });
        return Buffer.alloc(Link.MDU + 1); // over the MDU: a Resource upload
    };
    // Keep hold of every flush so a test can await it.
    const flush = c.self._flushPropagation;
    c.flushes = [];
    c.self._flushPropagation = () => { const p = flush(); c.flushes.push(p); return p; };
    c.node = node;
    c.uploads = uploads;
    c.OfflineLink = OfflineLink;
    return c;
}

const sendingRecord = (c, contact, content) => c.MsgStore.add(contact.destHash, {
    dir: "out", content, status: "sending", srcHash: lxmfHash(me), destHash: contact.destHash,
});

test("a copy with no propagation link is parked, then propagated once when the link is established", async () => {
    const alice = contactFor(peer);
    // A fresh browser: the node's identity is not known until its announce.
    const c = makePropagationClient({ nodeKnown: false, contacts: [alice] });
    const a = sendingRecord(c, alice, "parked then flushed");
    const b = sendingRecord(c, alice, "proved while parked");

    await c.self._propagateMessage(alice, a);
    await c.self._propagateMessage(alice, b);
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((m) => [m.status, m.waitFor]),
        [["queued", "propagation"], ["queued", "propagation"]], "parked and persisted, not dropped");
    assert.equal(c.uploads.length, 0);

    // B's direct proof lands while it is parked.
    c.MsgStore.updateStatus(alice.destHash, b.id, "proved");

    // The node announces; _initPropagation establishes the link.
    c.self._cfg.propagationNodePubKey = c.node.getPublicKey().toString("hex");
    c.self._establishPropagationLink();
    const link = c.self._propLink;
    link.status = Link.ACTIVE;
    link.emit("established");
    await afterLinkEvents();
    await Promise.all(c.flushes);
    await afterLinkEvents();

    assert.equal(c.uploads.length, 1, "only the parked, unproved copy");
    assert.equal(c.built[0].packed.subarray(0, 16).toString("hex"), alice.destHash, "addressed to the contact");
    assert.equal(c.built[0].publicKeyHex, alice.publicKey, "encrypted to the contact");
    const [storedA, storedB] = c.MsgStore.get(alice.destHash);
    assert.equal(storedA.status, "propagated");
    assert.equal(storedA.waitFor, null, "claimed before the upload");
    assert.equal(storedB.status, "proved", "delivery outranks the parked copy");
    assert.deepEqual(c.timers.filter((t) => t.ms === 30000).length, 1, "the 30 s ceiling is armed for the flushed copy");

    // The link drops and comes back: "established" again.
    link.emit("established");
    await afterLinkEvents();
    await Promise.all(c.flushes);
    assert.equal(c.uploads.length, 1, "propagated once");
});

test("the flush never touches a record still inside its direct window", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    sendingRecord(c, alice, "direct attempt in flight");
    c.self._propLink = { status: Link.ACTIVE, sendResource: async (data) => { c.uploads.push(data); } };
    await c.self._flushPropagation();
    await afterLinkEvents();
    assert.equal(c.built.length + c.uploads.length, 0, "its own fallback timer propagates it; a second upload is a double delivery");
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((m) => [m.status, m.waitFor]), [["sending", undefined]]);
    assert.equal(c.timers.length, 0, "no ceiling re-armed for it either");
});

test("the 30 s ceiling fails a send still \"sending\", never a parked copy", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: false, contacts: [alice] });
    c.self._dispatchMessage = compile("_dispatchMessage(contact, outMsg)", {
        MsgStore: c.MsgStore, ContactStore: { propagationDelay: () => 5, setReachable() {} }, Harness: {},
        console: { log() {}, warn() {} }, setTimeout: (fn, ms) => { c.timers.push({ fn, ms }); return c.timers.length; },
    })(c.self);
    c.self._sendPacket = () => {}; // the direct attempt never answers

    const parked = sendingRecord(c, alice, "parked");
    c.self._dispatchMessage(alice, parked);
    const [fallback, ceiling] = c.timers.splice(0);
    assert.equal(fallback.ms, 5000);
    assert.equal(ceiling.ms, 30000, "the existing ceiling");
    await fallback.fn();
    await afterLinkEvents();
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "queued");
    ceiling.fn();
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "queued", "a parked copy is not a failed send");

    const silent = sendingRecord(c, alice, "no answer at all");
    c.self._dispatchMessage(alice, silent);
    c.timers.find((t) => t.ms === 30000).fn();
    assert.equal(c.MsgStore.get(alice.destHash)[1].status, "failed");
});

test("a direct failure after the copy was parked leaves it parked for the flush", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: false, contacts: [alice] });
    c.self._dispatchMessage = compile("_dispatchMessage(contact, outMsg)", {
        MsgStore: c.MsgStore, ContactStore: { propagationDelay: () => 5, setReachable() {} }, Harness: {},
        console: { log() {}, warn() {} }, setTimeout: (fn, ms) => { c.timers.push({ fn, ms }); return c.timers.length; },
    })(c.self);
    let directFailed;
    c.self._sendPacket = (hash, key, content, id, onProof, onError) => { directFailed = () => onError(id); };
    const m = sendingRecord(c, alice, "direct link never came up");
    c.self._dispatchMessage(alice, m);
    await c.timers.find((t) => t.ms === 5000).fn();
    await afterLinkEvents();
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "queued");
    // The peer's delivery link closes before establishment, long after.
    directFailed();
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((r) => [r.status, r.waitFor]), [["queued", "propagation"]],
        "a failed flag here would make the flush skip it, and the copy would be lost");
});

test("a direct failure starts the copy at once, once, and does not show the message failed", async () => {
    // As on Android and iOS: the DIRECT failure is not the bubble's outcome,
    // the copy is. Until 2026-09-24 the web client showed ✗ and only sent
    // the copy when the propagation delay ran out.
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    c.self._dispatchMessage = compile("_dispatchMessage(contact, outMsg)", {
        MsgStore: c.MsgStore, ContactStore: { propagationDelay: () => 5, setReachable() {} }, Harness: {},
        console: { log() {}, warn() {} }, setTimeout: (fn, ms) => { c.timers.push({ fn, ms }); return c.timers.length; },
    })(c.self);
    const started = [];
    c.self._propagateMessage = async (contact, msg) => { started.push(msg.id); };
    let directFailed;
    c.self._sendPacket = (hash, key, content, id, onProof, onError) => { directFailed = () => onError(id); };
    const m = sendingRecord(c, alice, "the link failed");
    c.self._dispatchMessage(alice, m);
    directFailed();
    assert.deepEqual(started, [m.id], "the copy went at the failure, not after the delay");
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "sending", "not shown failed while the copy goes");
    await c.timers.find((t) => t.ms === 5000).fn();
    assert.deepEqual(started, [m.id], "the delay does not send a second copy");
});

test("a direct send that throws is failed and sends no copy, as before", () => {
    // It never left: the error reaches the composer, and the §17.11 rule
    // (a send that throws never leaves) holds.
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    c.self._dispatchMessage = compile("_dispatchMessage(contact, outMsg)", {
        MsgStore: c.MsgStore, ContactStore: { propagationDelay: () => 5, setReachable() {} }, Harness: {},
        console: { log() {}, warn() {} }, setTimeout: (fn, ms) => { c.timers.push({ fn, ms }); return c.timers.length; },
    })(c.self);
    const started = [];
    c.self._propagateMessage = async (contact, msg) => { started.push(msg.id); };
    c.self._sendPacket = (hash, key, content, id, onProof, onError) => { onError(id); throw new Error("send refused"); };
    const m = sendingRecord(c, alice, "refused at once");
    assert.throws(() => c.self._dispatchMessage(alice, m), /send refused/);
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "failed");
    assert.deepEqual(started, []);
});

test("a propagation proof never downgrades a direct proof", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    let finishUpload;
    const link = { status: Link.ACTIVE, sendResource: () => new Promise((resolve) => { finishUpload = resolve; }) };
    c.self._ensurePropagationLink = async () => link;
    const m = sendingRecord(c, alice, "both ways");
    await c.self._propagateMessage(alice, m);
    c.MsgStore.updateStatus(alice.destHash, m.id, "proved"); // the direct proof wins the race
    finishUpload();
    await afterLinkEvents();
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "proved");
});

test("a direct proof that lands while the propagation link comes up stops the upload", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    let linkUp;
    const link = { status: Link.ACTIVE, sendResource: async (data) => { c.uploads.push(data); } };
    c.self._ensurePropagationLink = () => new Promise((resolve) => { linkUp = () => resolve(link); });
    const m = sendingRecord(c, alice, "proved while the link handshakes");
    const propagating = c.self._propagateMessage(alice, m);
    c.MsgStore.updateStatus(alice.destHash, m.id, "proved");
    linkUp();
    await propagating;
    assert.equal(c.built.length + c.uploads.length, 0, "no stamp mined, nothing uploaded");
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "proved");
});

/** Park `texts` as copies waiting for the propagation link. */
function parkedRecords(c, contact, texts) {
    return texts.map((text) => {
        const r = sendingRecord(c, contact, text);
        c.MsgStore.update(contact.destHash, r.id, { status: "queued", waitFor: "propagation" });
        return r;
    });
}

/** Resolves "hung" if `p` has not settled by the next few macrotasks: a failure mechanism only. */
const settledOrHung = (p) => Promise.race([
    p.then(() => "settled"),
    new Promise((resolve) => setTimeout(() => resolve("hung"), 50)),
]);

test("a flush that loses its link leaves the rest parked and starts no link of its own", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    parkedRecords(c, alice, ["one", "two", "three"]);
    c.self._establishPropagationLink();
    const link = c.self._propLink;
    // The link closes while the first copy's stamp is mined.
    const build = c.self._buildPropagationPacked;
    c.self._buildPropagationPacked = async (...args) => { link.status = Link.CLOSED; return build(...args); };
    let attempts = 0;
    const establish = c.self._establishPropagationLink;
    c.self._establishPropagationLink = () => { attempts++; return establish(); };

    link.status = Link.ACTIVE;
    link.emit("established");
    await afterLinkEvents();
    assert.equal(await settledOrHung(Promise.all(c.flushes)), "settled", "the flush ends instead of waiting on a new link");

    assert.equal(c.uploads.length, 0, "nothing uploaded onto the closed link");
    assert.equal(attempts, 0, "the flush starts no link attempt: one per record would be a retry loop");
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((m) => [m.status, m.waitFor]),
        [["queued", "propagation"], ["queued", "propagation"], ["queued", "propagation"]],
        "all three wait for the next \"established\"");
});

test("two overlapping flushes propagate each parked copy once", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: true, contacts: [alice] });
    parkedRecords(c, alice, ["one", "two", "three"]);
    c.self._establishPropagationLink();
    const link = c.self._propLink;
    link.status = Link.ACTIVE;
    // Mining waits until released, so the second flush starts mid-way.
    const gates = [];
    const build = c.self._buildPropagationPacked;
    c.self._buildPropagationPacked = (...args) => new Promise((resolve) => gates.push(() => resolve(build(...args))));

    link.emit("established");
    await afterLinkEvents();
    c.self._flushPropagation(); // "established" again while the first flush mines
    for (let i = 0; i < 10; i++) {
        gates.splice(0).forEach((open) => open());
        await afterLinkEvents();
    }
    assert.equal(await settledOrHung(Promise.all(c.flushes)), "settled");
    assert.equal(c.uploads.length, 3, "one upload per parked copy, however many flushes ran");
});

test("the propagation link retry stays down once disconnected", () => {
    const c = makeClient({ methods: ["_retryPropagationLink(delayMs)"], env: { Link } });
    Object.assign(c.self, { _propLink: null, _propRetryTimer: null });
    c.self._rns = null; // disconnect() has run; its reject reached the retry's catch
    c.self._retryPropagationLink(8000);
    assert.equal(c.timers.length, 0, "no timer to start a link on a stopped Reticulum");
    c.self._rns = {};
    c.self._retryPropagationLink(8000);
    assert.equal(c.timers.length, 1, "connected, the retry is armed as before");
});

test("a queued message storage cannot keep is refused, so it stays in the composer", () => {
    const alice = contactFor(peer);
    const full = makeStorage();
    full.sSet = () => {}; // localStorage full: sSet swallows the failed write
    const c = makeQueueClient({ storage: full, contacts: [alice] });
    assert.throws(() => c.self.sendMessage(alice, "not kept"), /Could not store the message/);
});

test("a superseded propagation link's close leaves the current attempt alone", async () => {
    const c = makePropagationClient({ nodeKnown: true, contacts: [] });
    c.self._ensurePropagationLink();
    const old = c.self._propLink;
    // Established long ago (the handler cleared the attempt), then quiet: STALE.
    Object.assign(c.self, { _propLinkPromise: null, _propLinkResolve: null, _propLinkReject: null });
    old.status = Link.STALE;

    // An upload needs the link: a STALE link is not up, so a new attempt starts.
    const attempt = c.self._ensurePropagationLink();
    const current = c.self._propLink;
    assert.notEqual(current, old);
    let rejected = null;
    attempt.catch((e) => { rejected = e; });

    // The old link's keepalive watchdog tears it down.
    old.status = Link.CLOSED;
    old.emit("close");
    await afterLinkEvents();
    assert.equal(rejected, null, "the current attempt is not rejected");
    assert.equal(c.self._propLink, current, "nor dropped");
    assert.equal(c.self._propLinkPromise, attempt);
    assert.deepEqual(c.retries, [], "nor a retry scheduled");

    // The current link's own close still does all three.
    current.status = Link.CLOSED;
    current.emit("close");
    await afterLinkEvents();
    assert.match(rejected?.message ?? "", /closed before establishment/);
    assert.equal(c.self._propLink, null);
    assert.deepEqual(c.retries, [4000]);
});

test("disconnect resets the propagation link, its retry and initialization", () => {
    const c = makeClient({ methods: ["disconnect()", "_ensurePropagationLink()"], env: { clearInterval() {} } });
    let closed = 0;
    const oldLink = { status: Link.ACTIVE, close() { closed++; } }; // still thinks it is ACTIVE
    Object.assign(c.self, {
        _annTimer: null, _monTimer: null,
        _pendingTickets: new Map(), _rfedLinks: new Map(), _rfedLinkPromises: new Map(),
        _rfedServiceReady: new Set(), _rfedServiceWaiters: new Map(), _rfedOpenedChannelHashes: new Set(),
        _rfedPullState: new Map(), _rfedStampRefreshed: new Set(), _rfedSubscriptionPromises: new Map(),
        _rfedStreamPromises: new Map(), _rfedPendingEchoes: new Map(),
        _groupLinks: new Map(), _groupLinkPromises: new Map(), _groupPeerReady: new Set(),
        _groupPeerWaiters: new Map(), _groupPathsRequested: new Set(), _groupFallbacks: new Map(),
        _propLinkUpWaiters: [], _propLinkReject: null,
        _rns: { interfaces: [] }, _setStatus() {},
        _propLink: oldLink, _propRetryTimer: 77, _propagationInitialized: true, _initialized: true,
        _cfg: { propagationNodePubKey: "a".repeat(128), propagationNodeHash: "b".repeat(32) },
    });
    c.self.disconnect();
    assert.equal(c.self._propLink, null);
    assert.equal(closed, 1, "the old link is closed");
    assert.ok(c.cleared.includes(77), "the retry timer is cleared");
    assert.equal(c.self._propRetryTimer, null);
    assert.equal(c.self._propagationInitialized, false, "the next announce re-initializes propagation");
    assert.equal(c.self._initialized, false, "sends queue until the next connection initializes");

    // reconnect(): an upload must get a new link, not the stopped interface's.
    let established = 0;
    c.self._establishPropagationLink = () => { established++; c.self._propLinkPromise = Promise.resolve("new"); };
    c.self._ensurePropagationLink();
    assert.equal(established, 1);
});

// ── D: the queued status renders ────────────────────────────────────────────

test("every status change of a queued record repaints the bubble", async () => {
    const alice = contactFor(peer);
    const c = makePropagationClient({ nodeKnown: false, contacts: [alice] });
    c.self._dispatchMessage = compile("_dispatchMessage(contact, outMsg)", {
        MsgStore: c.MsgStore, ContactStore: { propagationDelay: () => 5, setReachable() {} }, Harness: {},
        console: { log() {}, warn() {} }, setTimeout: (fn, ms) => { c.timers.push({ fn, ms }); return c.timers.length; },
    })(c.self);
    c.self._sendPacket = () => {};
    const repaints = [];
    c.self._onMsg = [(msg, hash) => { if (msg === null) repaints.push([hash, c.MsgStore.get(hash).at(-1).status]); }];

    const queued = c.MsgStore.add(alice.destHash, { dir: "out", content: "q", status: "queued", waitFor: "init" });
    c.self._dispatchMessage(alice, queued); // ⏳ → ●
    await c.timers.find((t) => t.ms === 5000).fn();
    await afterLinkEvents(); // ● → ⏳ (parked)
    c.self._propLink = { status: Link.ACTIVE, sendResource: async () => {} };
    c.self._ensurePropagationLink = async () => c.self._propLink;
    await c.self._flushPropagation(); // ⏳ → ● (claimed), then ✓ when the upload is proved
    await afterLinkEvents();
    assert.deepEqual(repaints.map(([, status]) => status), ["sending", "queued", "sending", "propagated"]);
    assert.ok(repaints.every(([hash]) => hash === alice.destHash));
});

test("a queued message shows an hourglass, styled like the other statuses", () => {
    const icon = new Function("status", extractMethod("_statusIcon(status)"));
    assert.equal(icon("queued"), "⏳");
    assert.equal(icon("sending"), "●");
    assert.match(css, /\.msg-status\.queued\s*\{/);
});
