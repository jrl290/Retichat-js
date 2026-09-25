/**
 * REGRESSION GUARD — a DM and its propagated copy are one LXMF message, and
 * a recipient that gets both keeps one.
 *
 * James, 2026-09-24: "please make sure that duplicate messages are able to be
 * deduped". Until then:
 *   - LXMessage.pack() stamped Date.now() on every call, ignoring the
 *     message's own timestamp (LXMessage.py pack() keeps it);
 *   - _propagateMessage built the propagated copy with a new timestamp and a
 *     new ticket, so it was a different message with a different hash;
 *   - the receive path had no duplicate check by message hash, and the
 *     propagated fetch emitted messages with no hash at all.
 * A recipient that got the direct message and then fetched the copy from the
 * node showed it twice. LXMF keeps one (LXMRouter.py has_message, LXMF-rust
 * lxmf_delivery); the copy Android and iOS now build (LXMF-rust
 * propagated_copy) keeps the hash, and so does this client's.
 *
 * These tests run the real shipped method bodies from app.js and the real
 * LXMRouter against stubs, with real identities, real LXMF packing and real
 * encryption. No clock decides a result.
 *
 * Run: node --test lxmf_dedupe.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, { GROUP_FIELDS } from "./lib/rns/lxmf/lxmf.js";
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { GroupDeliveryEvidence } from "./lib/rns/group_fallback.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

// lxmf_router.js imports reticulum.js, whose module graph needs the browser
// importmap. Its own imports are pointed at the modules they name, so the
// real router runs here.
const routerSource = (await readFile(new URL("./lib/rns/lxmf/lxmf_router.js", import.meta.url), "utf8"))
    .replace(`import {Destination, LXMessage} from "../reticulum.js";`,
        `import Destination from "${new URL("./lib/rns/destination.js", import.meta.url)}";\n` +
        `import LXMessage from "${new URL("./lib/rns/lxmf/lxmf_message.js", import.meta.url)}";`)
    .replaceAll(`from "../`, `from "${new URL("./lib/rns/", import.meta.url)}`);
assert.doesNotMatch(routerSource, /reticulum\.js/);
const { default: LXMRouter } = await import(`data:text/javascript;base64,${Buffer.from(routerSource).toString("base64")}`);

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

/** The body of connect()'s `this._lxmfRouter.on("message", (lxmfMsg) => { … })`. */
function compileMessageHandler(env) {
    const marker = `this._lxmfRouter.on("message", (lxmfMsg) => {`;
    const start = app.indexOf(marker);
    assert.notEqual(start, -1, "the router's message handler is missing from app.js");
    const [open, close] = braceMatch(start + marker.length - 1, "message handler");
    const body = app.slice(open + 1, close).replaceAll("this.", "self.");
    const names = Object.keys(env);
    const fn = new Function(...names, "self", "lxmfMsg", body);
    return (self) => (lxmfMsg) => fn(...names.map((n) => env[n]), self, lxmfMsg);
}

const methodName = (signature) => signature.replace(/^async /, "").split("(")[0];
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const hex = (b) => Buffer.from(b).toString("hex");

// Router events are delivered on a later macrotask (utils/events.js defers
// every listener with setTimeout 0); a timer queued after them observes them.
const afterEvents = () => new Promise((resolve) => setTimeout(resolve, 0));

/** localStorage as sGet/sSet see it: JSON in, JSON out, survives a "reload". */
function makeStorage() {
    const data = new Map();
    return {
        data,
        sGet: (k) => (data.has(k) ? JSON.parse(data.get(k)) : null),
        sSet: (k, v) => data.set(k, JSON.stringify(v)),
    };
}

const Harness = { recordInbound() {}, event() {}, error() {} };
const realMsgStore = (storage) => new Function("sGet", "sSet", "Harness", `return ${extractObject("MsgStore")};`)(
    storage.sGet, storage.sSet, Harness);
/** A fresh LxmfSeen over `storage`, as a page load builds it. */
const loadLxmfSeen = (storage) => {
    const seen = new Function("sGet", "sSet", `return ${extractObject("LxmfSeen")};`)(storage.sGet, storage.sSet);
    seen.init();
    return seen;
};

/** Pin Date.now() while `fn` runs, to the end of what it returns. */
function at(ms, fn) {
    const realNow = Date.now;
    Date.now = () => ms;
    let result;
    try { result = fn(); } catch (e) { Date.now = realNow; throw e; }
    if (!(result instanceof Promise)) { Date.now = realNow; return result; }
    return result.finally(() => { Date.now = realNow; });
}

const FIELD_TICKET = 0x0C;

// ── LXMessage.pack() keeps the timestamp ────────────────────────────────────

function lxm(from, to, content, fields = new Map([[FIELD_TICKET, "00112233aabbccdd"]])) {
    const msg = new LXMessage();
    msg.sourceHash = Buffer.from(lxmfHash(from), "hex");
    msg.destinationHash = Buffer.from(lxmfHash(to), "hex");
    msg.title = "";
    msg.content = content;
    msg.fields = fields;
    return msg;
}

test("pack() keeps a timestamp that is set and records the one it stamps", () => {
    const alice = Identity.create();
    const bob = Identity.create();

    const set = lxm(alice, bob, "set");
    set.timestamp = 1790000000.25;
    const packedSet = at(1_800_000_000_000, () => set.pack(alice, false));
    assert.equal(MsgPack.unpack(packedSet.subarray(96))[0], 1790000000.25, "the message's own timestamp, not now");

    const unset = lxm(alice, bob, "unset");
    const first = at(1_790_000_123_456, () => unset.pack(alice, false));
    assert.equal(unset.timestamp, 1790000123.456, "stamped once and recorded");
    assert.equal(MsgPack.unpack(first.subarray(96))[0], 1790000123.456);
    const again = at(1_790_000_999_000, () => unset.pack(alice, false));
    assert.ok(again.equals(first), "packing it again is the same message, whatever the clock says");
});

test("the hash pack() keeps is the hash a receiver computes", () => {
    const alice = Identity.create();
    const bob = Identity.create();
    const msg = lxm(alice, bob, "hash me");
    const packed = msg.pack(alice, false);
    const received = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16));
    assert.equal(hex(msg.hash), hex(received.hash));
    assert.equal(hex(LXMessage.hashOf(packed.subarray(0, 16), packed.subarray(16, 32), packed.subarray(96))), hex(msg.hash));
});

// ── the propagated copy is the direct message ───────────────────────────────

/** The real _sendPacket and _propagateMessage over the real MsgStore. */
function makeSender({ storage, me }) {
    const MsgStore = realMsgStore(storage);
    const env = {
        MsgStore, Harness, Identity, Buffer, Destination, LXMessage, Link, Packet,
        IdMgr: { id: me },
        ContactStore: { setReachable() {} },
        console: { log() {}, warn() {} },
    };
    const self = {
        _onMsg: [],
        _pendingTickets: new Map(),
        _pendingPacketHashes: new Map(),
        _cfg: { propagationNodeHash: "b".repeat(32) },
        sendingIdentity: () => ({ identity: me, hash: lxmfHash(me), isDistro: false }),
    };
    const direct = [];
    self._rns = {
        registerDestination: (identity) => {
            const hash = Destination.hash(identity, "lxmf", "delivery");
            return { hash, send: (data) => { direct.push(Buffer.concat([hash, data])); return Buffer.alloc(32, 1); } };
        },
        sendData() {},
    };
    self._sendOverPeerLink = () => assert.fail("a short message goes as one packet");
    const copies = [];
    const link = { status: Link.ACTIVE, sendResource: async () => {} };
    self._ensurePropagationLink = async () => link;
    self._buildPropagationPacked = async (packed) => { copies.push(packed); return Buffer.alloc(Link.MDU + 1); };
    for (const signature of [
        "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
        "async _propagateMessage(contact, outMsg)", "_signerFor(srcHash)",
    ]) self[methodName(signature)] = compile(signature, env)(self);
    return { self, MsgStore, direct, copies };
}

/** Hash of a full packing (destination hash first), as the recipient's router computes it. */
const hashOfPacked = (packed) => hex(LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16)).hash);
const ticketOfPacked = (packed) => MsgPack.unpack(packed.subarray(96))[3].get(FIELD_TICKET);

test("the propagated copy is the direct message, with its hash, even after a reload", async () => {
    const me = Identity.create();
    const peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const storage = makeStorage();

    const before = makeSender({ storage, me });
    const record = before.MsgStore.add(contact.destHash, { dir: "out", content: "hello once", status: "sending", srcHash: lxmfHash(me), destHash: contact.destHash });
    at(1_790_000_000_000, () => before.self._sendPacket(contact.destHash, contact.publicKey, "hello once", record.id, () => {}, () => {}));
    assert.equal(before.direct.length, 1);
    const persisted = before.MsgStore.get(contact.destHash)[0];
    assert.equal(typeof persisted.lxmfTimestamp, "number", "the direct message's timestamp is persisted");
    assert.match(persisted.lxmfTicket, /^[0-9a-f]{16}$/, "and its ticket");

    // The copy is parked and the tab reloads: a fresh client over the same storage.
    // A minute later: the copy must not take the clock's word for its timestamp.
    const after = makeSender({ storage, me });
    await at(1_790_000_060_000, () => after.self._propagateMessage(contact, persisted));
    assert.equal(after.copies.length, 1);
    const [directPacked] = before.direct;
    const [copyPacked] = after.copies;
    assert.equal(hashOfPacked(copyPacked), hashOfPacked(directPacked), "one message, one hash");
    assert.equal(ticketOfPacked(copyPacked), ticketOfPacked(directPacked), "the direct ticket, so its delivery notification proves the record");
    assert.ok(copyPacked.equals(directPacked), "byte for byte the direct message");
});

test("a copy parked across a distro import is still signed as the direct message was", async () => {
    // Direct as the device; before the parked copy goes, a distro is loaded
    // and becomes the sender. The copy keeps the device's signature, so the
    // same hash: the source is part of it.
    const me = Identity.create();
    const distro = Identity.create();
    const peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const storage = makeStorage();
    const before = makeSender({ storage, me });
    const record = before.MsgStore.add(contact.destHash, { dir: "out", content: "as the device", status: "sending", srcHash: lxmfHash(me), destHash: contact.destHash });
    before.self._sendPacket(contact.destHash, contact.publicKey, "as the device", record.id, () => {}, () => {});
    const after = makeSender({ storage, me });
    after.self.ownHash = lxmfHash(me);
    after.self.sendingIdentity = () => ({ identity: distro, hash: lxmfHash(distro), isDistro: true });
    await after.self._propagateMessage(contact, after.MsgStore.get(contact.destHash)[0]);
    assert.equal(hashOfPacked(after.copies[0]), hashOfPacked(before.direct[0]), "signed by the device, one hash");
});

test("a record never sent direct gets a message of its own, ticket and all", async () => {
    const me = Identity.create();
    const peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const c = makeSender({ storage: makeStorage(), me });
    const record = c.MsgStore.add(contact.destHash, { dir: "out", content: "same words", status: "sending", srcHash: lxmfHash(me), destHash: contact.destHash });
    c.self._sendPacket(contact.destHash, contact.publicKey, "same words", record.id, () => {}, () => {});
    // A distro address is never sent direct: its record has neither.
    c.MsgStore.update(contact.destHash, record.id, { lxmfTimestamp: undefined, lxmfTicket: undefined });
    const bare = c.MsgStore.get(contact.destHash)[0];
    assert.equal("lxmfTimestamp" in bare || "lxmfTicket" in bare, false);

    await c.self._propagateMessage(contact, bare);
    assert.equal(c.copies.length, 1);
    assert.match(ticketOfPacked(c.copies[0]), /^[0-9a-f]{16}$/, "a ticket as before");
    assert.notEqual(ticketOfPacked(c.copies[0]), ticketOfPacked(c.direct[0]));
    assert.notEqual(hashOfPacked(c.copies[0]), hashOfPacked(c.direct[0]));
});

// ── the recipient keeps one ─────────────────────────────────────────────────

/**
 * A recipient: the real LXMRouter feeding the real message handler, the real
 * propagated fetch, and the real MsgStore and LxmfSeen over `storage`.
 */
function makeRecipient({ me, storage = makeStorage() }) {
    const MsgStore = realMsgStore(storage);
    const LxmfSeen = loadLxmfSeen(storage);
    const logs = [];
    const quiet = { log: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")) };
    const contacts = new Map();
    const ContactStore = {
        isContact: (h) => contacts.has(h), add: (h) => { contacts.set(h, { destHash: h }); return contacts.get(h); },
        get: (h) => contacts.get(h) ?? null, touch() {}, setReachable() {}, _save() {},
    };
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    const router = new LXMRouter({ registerDestination: () => destination }, me);
    const self = {
        _onMsg: [],
        _pendingTickets: new Map(),
        _lxmfRouter: router,
        transfers: [],
        groups: [],
    };
    self._handleDistroIdentityTransfer = (...a) => self.transfers.push(a);
    self._handleGroupMessage = (...a) => self.groups.push(a);
    const handler = compileMessageHandler({
        Buffer, LxmfSeen, Harness, console: quiet, RnsClient: { ownHash: hex(destination.hash) },
        LXMF, LXMessage, ContactStore, MsgStore,
    })(self);
    const emitted = [];
    router.on("message", (m) => { emitted.push(m); handler(m); });

    // The node holds `blobs` (lxmf_data, destination hash first); /get lists,
    // downloads and purges them.
    const node = { blobs: [], purged: [] };
    const tid = (blob) => LXMessage.hashOf(blob, Buffer.alloc(0), Buffer.alloc(0)); // any stable id
    self._propLink = { status: Link.ACTIVE, sendRequest: (path, data) => ({ path, data }) };
    self._waitForResponse = async (link, { data: [wants, haves] }) => {
        if (haves) { node.purged.push(...haves); return true; }
        if (wants) return wants.map((id) => node.blobs.find((b) => tid(b).equals(Buffer.from(id))));
        return node.blobs.map(tid);
    };
    self._fetchPropagatedMessages = compile("async _fetchPropagatedMessages()", {
        Link, Buffer, MsgPack, LXMessage, IdMgr: { id: me }, console: quiet,
    })(self);
    const link = { send() {} };
    return {
        self, router, MsgStore, LxmfSeen, storage, logs, emitted, node, destination,
        /** Direct, as a single packet to the delivery destination. */
        packet: (packed) => destination.emit("packet", { data: packed.subarray(16), packet: { prove() {} } }),
        /** Direct, over a delivery link. */
        overLink: (packed) => router.handleLinkPayload(link, packed),
        /** Left on the propagation node, encrypted to us. */
        leaveOnNode: (packed) => node.blobs.push(Buffer.concat([packed.subarray(0, 16), me.encrypt(packed.subarray(16))])),
        fetch: () => self._fetchPropagatedMessages(),
    };
}

const inbox = (r, from) => r.MsgStore.get(lxmfHash(from)).filter((m) => m.dir === "in").map((m) => m.content);

for (const path of ["packet", "overLink"]) {
    test(`a message received direct (${path}) and then fetched from the node is stored once`, async () => {
        const alice = Identity.create();
        const bob = Identity.create();
        const r = makeRecipient({ me: bob });
        const packed = lxm(alice, bob, "only once").pack(alice, false);

        r[path](packed);
        await afterEvents();
        r.leaveOnNode(packed);
        await r.fetch();
        await afterEvents();

        assert.deepEqual(inbox(r, alice), ["only once"]);
        assert.equal(r.emitted.length, 2, "both arrivals reached the handler");
        assert.equal(hex(r.emitted[1].hash), hex(r.emitted[0].hash), "the fetch gives the copy the router's hash");
        assert.ok(r.logs.some((l) => /duplicate LXMF message [0-9a-f]{12} from [0-9a-f]{12} ignored/.test(l)), "the drop is logged");
        assert.equal(r.node.purged.length, 1, "the copy is still purged from the node");
    });
}

test("a copy fetched first keeps the later direct arrival out", async () => {
    const alice = Identity.create();
    const bob = Identity.create();
    const r = makeRecipient({ me: bob });
    const packed = lxm(alice, bob, "fetched first").pack(alice, false);
    r.leaveOnNode(packed);
    await r.fetch();
    await afterEvents();
    r.overLink(packed);
    await afterEvents();
    assert.deepEqual(inbox(r, alice), ["fetched first"]);
});

test("two different messages are both stored, even with the same words", async () => {
    const alice = Identity.create();
    const bob = Identity.create();
    const r = makeRecipient({ me: bob });
    const first = at(1_790_000_000_000, () => lxm(alice, bob, "same words").pack(alice, false));
    const second = at(1_790_000_000_001, () => lxm(alice, bob, "same words").pack(alice, false));
    r.overLink(first);
    await afterEvents();
    r.leaveOnNode(second);
    await r.fetch();
    await afterEvents();
    assert.deepEqual(inbox(r, alice), ["same words", "same words"]);
});

test("a duplicate is dropped before anything reads it", async () => {
    const alice = Identity.create();
    const bob = Identity.create();
    const r = makeRecipient({ me: bob });
    const group = lxm(alice, bob, "group hello", new Map([[GROUP_FIELDS.GROUP_ID, "9".repeat(32)]])).pack(alice, false);
    const transfer = lxm(alice, bob, "", new Map([[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_TRANSFER_TYPE], [LXMF.FIELD_CUSTOM_DATA, "a".repeat(128)]])).pack(alice, false);
    for (const packed of [group, transfer]) {
        r.overLink(packed);
        await afterEvents();
        r.leaveOnNode(packed);
    }
    await r.fetch();
    await afterEvents();
    assert.equal(r.self.groups.length, 1, "the group action runs once");
    assert.equal(r.self.transfers.length, 1, "the transfer offer is made once");
});

test("the seen hashes survive a reload", async () => {
    const alice = Identity.create();
    const bob = Identity.create();
    const storage = makeStorage();
    const packed = lxm(alice, bob, "before the reload").pack(alice, false);
    const before = makeRecipient({ me: bob, storage });
    before.overLink(packed);
    await afterEvents();

    const after = makeRecipient({ me: bob, storage });
    after.leaveOnNode(packed);
    await after.fetch();
    await afterEvents();
    assert.deepEqual(inbox(after, alice), ["before the reload"], "the copy still on the node is not a new message");
});

test("the seen hashes are bounded: the oldest go first", () => {
    const storage = makeStorage();
    const seen = loadLxmfSeen(storage);
    assert.equal(seen.LIMIT, 2000);
    const hashes = Array.from({ length: seen.LIMIT + 1 }, (_, i) => i.toString(16).padStart(64, "0"));
    // A stored list over the limit (an older build) is trimmed on load.
    storage.sSet("lxmf_seen", hashes);
    const loaded = loadLxmfSeen(storage);
    assert.equal(loaded.check(hashes[0]), false, "the oldest was dropped on load");
    assert.equal(storage.sGet("lxmf_seen").length, 2000);
    assert.equal(loaded.check(hashes[1]), false, "and the next oldest when that one was recorded");
    assert.equal(loaded.check(hashes.at(-1)), true, "the newest is still known");
    assert.equal(storage.sGet("lxmf_seen").length, 2000);
});

test("a message with no hash is processed, and says so", async () => {
    const alice = Identity.create();
    const bob = Identity.create();
    const r = makeRecipient({ me: bob });
    const bare = { sourceHash: Buffer.from(lxmfHash(alice), "hex"), content: "no hash", title: "", fields: new Map(), timestamp: 1 };
    r.router.emit("message", bare);
    r.router.emit("message", bare);
    await afterEvents();
    assert.deepEqual(inbox(r, alice), ["no hash", "no hash"], "never dropped: nothing to recognise it by");
    assert.ok(r.logs.some((l) => l.includes("has no LXMF hash")));
});

test("a delivery notification for the propagated copy proves the record: it carries the direct ticket", async () => {
    const me = Identity.create();
    const peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const storage = makeStorage();
    const s = makeSender({ storage, me });
    const record = s.MsgStore.add(contact.destHash, { dir: "out", content: "prove me", status: "sending", srcHash: lxmfHash(me), destHash: contact.destHash });
    s.self._sendPacket(contact.destHash, contact.publicKey, "prove me", record.id,
        (id) => s.MsgStore.updateStatus(contact.destHash, id, "proved"), () => {});
    await s.self._propagateMessage(contact, s.MsgStore.get(contact.destHash)[0]);

    // The peer got the copy and answers with its ticket and no content; the
    // sender's handler matches it to the pending direct attempt.
    const r = makeRecipient({ me, storage });
    r.self._pendingTickets = s.self._pendingTickets;
    const notification = lxm(peer, me, "", new Map([[FIELD_TICKET, ticketOfPacked(s.copies[0])]])).pack(peer, false);
    r.overLink(notification);
    await afterEvents();
    assert.equal(r.MsgStore.get(contact.destHash)[0].status, "proved");
});

// ── the group fallback already uploads the direct envelope ──────────────────

test("the group propagation fallback uploads the exact direct envelope, so the same hash", async () => {
    const me = Identity.create();
    const member = Identity.create();
    const memberHash = lxmfHash(member);
    const contact = { destHash: memberHash, publicKey: member.getPublicKey().toString("hex") };
    const env = {
        ContactStore: { get: () => contact, add: () => contact },
        Identity, Buffer, Destination, LXMessage, GROUP_FIELDS, GroupDeliveryEvidence, Link,
        IdMgr: { id: me },
        console: { log() {}, warn() {} },
    };
    const direct = [];
    const uploaded = [];
    let fallback;
    const self = {
        _pendingPacketHashes: new Map(),
        _cfg: { displayName: "Me" },
        _lxmfRouter: { destination: { hash: Destination.hash(me, "lxmf", "delivery") } },
        _rns: { registerDestination: (identity) => ({ hash: Destination.hash(identity, "lxmf", "delivery") }) },
        _groupFallbacks: { schedule: (key, ms, fn) => { fallback = fn; return true; }, prove() {} },
        _ensureGroupLink: async () => ({ link: { send: (bytes) => { direct.push(bytes); return { packetHash: Buffer.alloc(32, 2) }; } } }),
        _ensurePropagationLink: async () => ({ send: () => ({ packetHash: Buffer.alloc(32, 3) }) }),
        _buildPropagationPacked: async (packed) => { uploaded.push(packed); return Buffer.alloc(8); },
    };
    for (const signature of [
        "async _sendGroupEnvelope(memberHash, content, fields)",
        "_deliverGroupEnvelope(memberHash, fullLxmfBytes, publicKeyHex)",
        "async _sendGroupPropagationFallback(fullLxmfBytes, publicKeyHex, memberHash)",
    ]) self[methodName(signature)] = compile(signature, env)(self);

    self._sendGroupEnvelope(memberHash, "group words", { groupId: "9".repeat(32), groupSender: lxmfHash(me) });
    await afterEvents();
    await fallback(); // no direct proof within the fallback window
    assert.equal(direct.length, 1);
    assert.equal(uploaded.length, 1);
    assert.ok(uploaded[0].equals(direct[0]), "the same bytes go both ways");
    assert.equal(hashOfPacked(uploaded[0]), hashOfPacked(direct[0]));
});
