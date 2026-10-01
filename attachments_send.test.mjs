/**
 * SENDING ATTACHMENTS — the paperclip's files go as FIELD_FILE_ATTACHMENTS
 * [[name, bytes], ...] at their original size, by every path a DM takes:
 * direct (one Resource on the peer's delivery link), its propagated copy (a
 * Resource on the propagation link, the same message and hash), and to a
 * distro address (propagated only).
 *
 *   Limits, checked before anything is stored, with a message that says
 *   which (lib/attachment_limits.js): at most 5 attachments (iOS), LXMF's
 *   delivery limit of 1,000,000 B, and the per-sync limit the propagation
 *   node announces. A group takes none: group relays carry text only.
 *
 *   Progress: 0.10 + 0.90 x the Resource's fraction while SENDING, only up
 *   (LXMF/LXMessage.py __update_transfer_progress, LXMF-rust 4125139).
 *
 *   Outcome: a moving transfer is never failed by the 30 s send ceiling: the
 *   Resource's own end decides, and a silence of more than 5 s is a logged §1
 *   violation (DESIGN_PRINCIPLES §1, bulk transfers). The propagation
 *   fallback counts only time without transfer activity (app-links 07bea51
 *   Timer P), so a photo still moving direct gets no second upload.
 *
 * Run: node --test attachments_send.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import { FIELD_FILE_ATTACHMENTS, mimeForName } from "./lib/rns/lxmf/lxmf.js";
import * as DN from "./lib/display_name.js";
import { AttachmentStore, attachmentKey, memoryBackend } from "./lib/attachment_store.js";
import {
    MAX_ATTACHMENTS, NAME_FIELD_MAX, PROPAGATION_UPLOAD_OVERHEAD, attachmentRefusal, estimatePackedSize, formatSize,
} from "./lib/attachment_limits.js";
import { SendTransfers, transferProgress, PROGRESS_START, QUIET_MS } from "./lib/send_progress.js";
import { linkPair, settle, within } from "./test_link_pair.mjs";
import { build, compile, constValue, install, memoryStorage, methodBody } from "./test_app_source.mjs";

const quiet = { log() {}, warn() {}, error() {} };
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const LIMIT = LXMRouter.DELIVERY_LIMIT * 1000;
const file = (name, n, fill = 1) => ({ name, bytes: Buffer.alloc(n, fill) });

// ── limits ──────────────────────────────────────────────────────────────────

test("the limits: LXMF's delivery limit for every DM, the node's per-sync limit for its upload, 5 files", () => {
    assert.equal(LIMIT, 1_000_000);
    assert.equal(MAX_ATTACHMENTS, 5, "iOS PhotosPicker maxSelectionCount");
    assert.equal(attachmentRefusal({ count: 1, packedSize: 999_000, deliveryLimit: LIMIT }), null);
    assert.match(attachmentRefusal({ count: 1, packedSize: 1_000_001, deliveryLimit: LIMIT }),
        /would be 1\.00 MB\. An LXMF message can be at most 1\.00 MB, the most any recipient accepts/);
    assert.match(attachmentRefusal({ count: 6, packedSize: 10, deliveryLimit: LIMIT }), /At most 5 attachments/);
    // rfed's staging default: 10,240 KB per sync. A node configured lower:
    assert.equal(attachmentRefusal({ count: 1, packedSize: 900_000, deliveryLimit: LIMIT, perSyncKb: 10_240 }), null);
    assert.match(attachmentRefusal({ count: 1, packedSize: 300_000, deliveryLimit: LIMIT, perSyncKb: 256 }),
        /propagation node takes at most 256 KB at a time \(its announced limit\)/);
    assert.equal(attachmentRefusal({ count: 1, packedSize: 256_000 - PROPAGATION_UPLOAD_OVERHEAD, deliveryLimit: LIMIT, perSyncKb: 256 }), null,
        "exactly at the limit goes");
    assert.notEqual(attachmentRefusal({ count: 1, packedSize: 256_001 - PROPAGATION_UPLOAD_OVERHEAD, deliveryLimit: LIMIT, perSyncKb: 256 }), null);
    assert.equal(formatSize(999), "999 B");
    assert.equal(formatSize(256_000), "256 KB");
});

test("the composer's estimate never undercounts the message as _sendPacket packs it", () => {
    const me = Identity.create(), peer = Identity.create();
    const attachments = [file("a.jpg", 400_000, 3), file("b.png", 300_000, 4)];
    const estimate = estimatePackedSize("caption", attachments);
    for (const name of [null, "x".repeat(64), "😀".repeat(64)]) {
        const m = new LXMessage();
        m.sourceHash = Buffer.from(lxmfHash(me), "hex");
        m.destinationHash = Buffer.from(lxmfHash(peer), "hex");
        m.title = "";
        m.content = "caption";
        m.fields = new Map([[0x0C, "0123456789abcdef"]]);
        DN.applyToFields(m.fields, name === null ? DN.ABSENT : DN.nameState(name));
        m.fields.set(FIELD_FILE_ATTACHMENTS, attachments.map((a) => [a.name, a.bytes]));
        const packed = m.pack(me, false);
        assert.ok(estimate >= packed.length, `${estimate} >= ${packed.length} (name ${name?.length ?? "none"})`);
        assert.ok(estimate - packed.length <= NAME_FIELD_MAX + 16, "and close: at most the name's room over");
    }
});

test("the propagation node's announced limits are read from its announce ([3] per-transfer, [4] per-sync)", () => {
    const parse = compile("_parsePropagationNodeLimits(appData)", { MsgPack, Buffer, Number, Math })({});
    const announce = (t, s) => MsgPack.pack([false, 1_790_000_000, true, t, s, [16, 3, 18], new Map()]);
    assert.deepEqual(parse(announce(256, 10_240)), { perTransferKb: 256, perSyncKb: 10_240 });
    assert.deepEqual(parse(announce(256.0, 10240.7)), { perTransferKb: 256, perSyncKb: 10_240 }, "int() of each, as pn_announce_data_is_valid");
    for (const bad of [null, Buffer.alloc(0), MsgPack.pack([false, 1, true, 256]), MsgPack.pack([false, 1, true, "x", 2, [1, 2, 3], {}]),
        MsgPack.pack([false, 1, true, 256, -1, [1, 2, 3], {}]), Buffer.from([0xc1])]) {
        assert.equal(parse(bad), null);
    }
    const handler = methodBody("async connect()");
    assert.match(handler, /const limits = this\._parsePropagationNodeLimits\(event\.announce\.appData\);[\s\S]*?sSet\("propagationLimits", limits\)/);
});

// ── the send path ───────────────────────────────────────────────────────────

/** A web client's DM send path over the real stores and attachment store. */
function sender({ backend = memoryBackend({ persistent: true }), perSyncKb = null, initialized = true } = {}) {
    const me = Identity.create();
    const storage = memoryStorage();
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness: { recordInbound() {} }, Date });
    const Attachments = new AttachmentStore(backend, { warn() {} });
    const contacts = new Map();
    const timers = [];
    const env = {
        MsgStore, Attachments, attachmentKey, Cryptography, Identity, Buffer, Destination, LXMessage, LXMRouter, Link, Packet,
        FIELD_FILE_ATTACHMENTS, mimeForName, formatSize, attachmentRefusal, estimatePackedSize, console: quiet,
        applyDisplayName: DN.applyToFields, crypto: globalThis.crypto, Harness: { error() {} },
        ContactStore: { allow() {}, touch() {}, setReachable() {}, propagationDelay: (h) => (contacts.get(h)?.isDistro ? 0 : 5), getAll: () => [...contacts.values()] },
        GroupStore: { getAll: () => [] }, GroupMsgStore: { get: () => [] },
        setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; }, clearTimeout() {},
        sGet: () => null,
    };
    const direct = [];
    const resources = [];
    const self = {
        _initialized: initialized, _onMsg: [], _onSendProgress: [], _onAttachmentState: [],
        _pendingTickets: new Map(), _pendingPacketHashes: new Map(), _pendingTimeouts: new Map(),
        _sendTransfers: new SendTransfers({ setTimer: () => null, clearTimer() {} }),
        _cfg: { propagationNodeHash: "b".repeat(32), propagationLimits: perSyncKb === null ? null : { perTransferKb: 256, perSyncKb } },
        _exchangeIsDown: () => false,
        _decideMessageName: () => DN.ABSENT, _recordNameDelivered() {},
        sendingIdentity: () => ({ identity: me, hash: lxmfHash(me), isDistro: false }),
        _sendDistroSentCopy: async () => {},
        _rns: { registerDestination: (identity) => ({ hash: Destination.hash(identity, "lxmf", "delivery"), send: (d) => { direct.push(d); return Buffer.alloc(32, 1); } }) },
        _sendOverPeerLink: (contactHash, key, packed, representation, messageId) => direct.push({ packed, representation, messageId }),
        _ensurePropagationLink: async () => ({ status: Link.ACTIVE, sendResource: async (data) => { resources.push(data); } }),
        _buildPropagationPacked: async (packed) => Buffer.concat([Buffer.alloc(Link.MDU + 1), packed]),
    };
    install(self, env, [
        "sendMessage(contact, content, attachments = [])", "_dispatchMessage(contact, outMsg)",
        "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
        "async _propagateMessage(contact, outMsg)", "_signerFor(srcHash)",
        "_armSendCeiling(contactHash, msgId)", "_failSending(contactHash, msgId)",
        "_keepAttachments(store, convHash, record, found, fieldsUnreadable = null)",
        "attachmentRefusal(contact, content, attachments)", "_propagationLimits()",
        "_attachmentFieldNow(record)", "async _attachmentField(record)",
        "_sendWithProgress(link, data, convHash, msgId, label)",
        "_dispatchQueued()", "async _dispatchWarmed(contact, msg)",
    ]);
    return { me, MsgStore, Attachments, backend, contacts, timers, direct, resources, self };
}

const contactOf = (identity, extra = {}) => ({ destHash: lxmfHash(identity), publicKey: identity.getPublicKey().toString("hex"), isDistro: false, ...extra });
const fieldsOf = (packed) => MsgPack.unpack(packed.subarray(96))[3];

test("a DM with attachments goes direct as one Resource carrying 0x05 [[name, bytes], ...] at original size", async () => {
    const s = sender();
    const peer = Identity.create();
    const c = contactOf(peer);
    s.contacts.set(c.destHash, c);
    const photo = file("IMG_0001.jpg", 600_000, 7);
    const doc = file("notes.pdf", 1000, 8);
    const rec = s.self.sendMessage(c, "", [photo, doc]);
    assert.equal(rec.status, "sending");
    assert.equal(rec.content, "", "captionless");
    assert.deepEqual(rec.attachments.map(({ name, mime, size, field }) => ({ name, mime, size, field })), [
        { name: "IMG_0001.jpg", mime: "image/jpeg", size: 600_000, field: 5 },
        { name: "notes.pdf", mime: "application/pdf", size: 1000, field: 5 },
    ]);
    const [sent] = s.direct;
    assert.equal(sent.representation, LXMessage.RESOURCE);
    const field = fieldsOf(sent.packed).get(FIELD_FILE_ATTACHMENTS);
    assert.deepEqual(field.map(([n, b]) => [n, Buffer.from(b).length]), [["IMG_0001.jpg", 600_000], ["notes.pdf", 1000]]);
    assert.ok(Buffer.from(field[0][1]).equals(photo.bytes), "the bytes as picked: nothing downscaled");
    await settle();
    assert.equal(s.MsgStore.get(c.destHash)[0].attachments[0].stored, "persisted", "kept for the bubble");
});

test("its propagated copy is the same message, attachments and hash, even read back from the store", async () => {
    const s = sender();
    const peer = Identity.create();
    const c = contactOf(peer);
    s.contacts.set(c.destHash, c);
    s.self.sendMessage(c, "photo", [file("a.png", 50_000, 2)]);
    await settle();
    const rec = s.MsgStore.get(c.destHash)[0];
    assert.equal(s.Attachments.peek(rec.attachments[0].key), null, "no longer in memory: the copy reads it back");
    await s.self._propagateMessage(c, rec);
    assert.equal(s.resources.length, 1, "a Resource on the propagation link");
    const copy = s.resources[0].subarray(Link.MDU + 1);
    const direct = s.direct[0].packed;
    assert.ok(copy.equals(direct), "byte for byte the direct message, so the recipient keeps one");
});

test("to a distro address: propagated only, with its attachments", async () => {
    const s = sender();
    const peer = Identity.create();
    const c = contactOf(peer, { isDistro: true });
    s.contacts.set(c.destHash, c);
    const rec = s.self.sendMessage(c, "", [file("x.png", 2000, 5)]);
    assert.equal(s.direct.length, 0, "no direct attempt");
    const fallback = s.timers.find((t) => t.ms === 0);
    await fallback.f();
    await settle();
    assert.equal(s.resources.length, 1);
    assert.deepEqual(fieldsOf(s.resources[0].subarray(Link.MDU + 1)).get(5).map(([n]) => n), ["x.png"]);
    assert.equal(s.MsgStore.get(c.destHash).find((m) => m.id === rec.id).status, "propagated");
});

test("refused before anything is stored: too many, over LXMF's limit, over the node's per-sync limit", () => {
    const s = sender({ perSyncKb: 256 });
    const peer = Identity.create();
    const c = contactOf(peer);
    assert.throws(() => s.self.sendMessage(c, "", Array.from({ length: 6 }, (_, i) => file(`${i}.png`, 10))), /At most 5 attachments/);
    assert.throws(() => s.self.sendMessage(c, "", [file("huge.jpg", 1_000_000)]), /An LXMF message can be at most 1\.00 MB/);
    assert.throws(() => s.self.sendMessage(c, "", [file("big.jpg", 300_000)]), /takes at most 256 KB at a time/);
    assert.deepEqual(s.MsgStore.get(c.destHash), [], "nothing stored, nothing sent: the composer keeps it");
    assert.equal(s.direct.length, 0);
    const ok = sender({ perSyncKb: 10_240 });
    assert.equal(ok.self.sendMessage(c, "", [file("big.jpg", 900_000)]).status, "sending", "900 KB goes with staging's limits");
});

test("_sendPacket's own check of the message as built: over LXMF's limit it is failed, with why, never sent", () => {
    const s = sender();
    const peer = Identity.create();
    const c = contactOf(peer);
    const rec = s.MsgStore.add(c.destHash, { dir: "out", content: "", status: "sending" });
    s.self._keepAttachments(s.MsgStore, c.destHash, rec, [{ name: "x.bin", mime: "application/octet-stream", bytes: Buffer.alloc(1_000_000), field: 5 }]);
    let failed = null;
    assert.throws(() => s.self._sendPacket(c.destHash, c.publicKey, "", rec.id, null, (id) => { failed = id; }), /at most 1\.00 MB/);
    assert.equal(failed, rec.id);
    assert.match(s.MsgStore.get(c.destHash)[0].sendError, /at most 1\.00 MB/);
    assert.equal(s.direct.length, 0);
});

test("the propagated copy over the node's per-sync limit is not uploaded, and the record says why", async () => {
    const s = sender({ perSyncKb: 10 });
    const peer = Identity.create();
    const c = contactOf(peer);
    const rec = s.MsgStore.add(c.destHash, { dir: "out", content: "", status: "sending", srcHash: lxmfHash(s.me) });
    s.self._keepAttachments(s.MsgStore, c.destHash, rec, [{ name: "p.png", mime: "image/png", bytes: Buffer.alloc(20_000), field: 5 }]);
    await s.self._propagateMessage(c, s.MsgStore.get(c.destHash)[0]);
    assert.equal(s.resources.length, 0);
    assert.match(s.MsgStore.get(c.destHash)[0].sendError, /over the 10 KB the propagation node takes/);
});

test("a DM queued before initialization (or a reload) is sent with its attachments read back from the store", async () => {
    const backend = memoryBackend({ persistent: true });
    const before = sender({ backend, initialized: false });
    const peer = Identity.create();
    const c = contactOf(peer);
    before.contacts.set(c.destHash, c);
    const queued = before.self.sendMessage(c, "later", [file("q.png", 30_000, 6)]);
    assert.equal(queued.status, "queued");
    await settle();
    assert.equal(before.Attachments.peek(queued.attachments[0].key), null);
    before.self._initialized = true;
    before.self._dispatchQueued();
    await settle();
    const [sent] = before.direct;
    assert.ok(sent, "dispatched");
    assert.equal(Buffer.from(fieldsOf(sent.packed).get(5)[0][1]).length, 30_000);
    assert.equal(before.Attachments.peek(queued.attachments[0].key), null, "and let go after");

    // Session-only bytes do not survive the reload: the message fails, saying why.
    const session = sender({ backend: Promise.reject(new Error("no IndexedDB")), initialized: false });
    session.contacts.set(c.destHash, c);
    const q2 = session.self.sendMessage(c, "", [file("s.png", 100)]);
    await settle();
    session.Attachments._mem.clear();   // what a reload leaves
    session.self._initialized = true;
    session.self._dispatchQueued();
    await settle();
    const after = session.MsgStore.get(c.destHash).find((m) => m.id === q2.id);
    assert.equal(after.status, "failed");
    assert.match(after.sendError, /kept for an earlier session only/);
    assert.equal(session.direct.length, 0, "never sent without its attachment");
});

// ── progress ────────────────────────────────────────────────────────────────

test("progress is 0.10 + 0.90 x fraction, only ever up, across the message's transfers", () => {
    assert.equal(PROGRESS_START, 0.10);
    assert.equal(transferProgress(0), 0.10);
    assert.equal(transferProgress(1), 1);
    assert.equal(transferProgress(0.5), 0.55);
    assert.equal(transferProgress(7), 1);
    assert.equal(transferProgress(NaN), 0.10);
    const t = new SendTransfers({ setTimer: () => null, clearTimer() {} });
    const direct = t.begin("m", "direct");
    const copy = t.begin("m", "propagated");
    assert.equal(t.progress(direct, 0.2), transferProgress(0.2));
    assert.equal(t.progress(copy, 0.1), null, "a slower parallel transfer cannot pull the bar back");
    assert.equal(t.progress(direct, 0.2), null, "no change, no report");
    assert.equal(t.progress(copy, 0.5), transferProgress(0.5));
    assert.equal(t.progressOf("m"), transferProgress(0.5));
    t.settle("m");
    assert.equal(t.progress(copy, 0.9), null, "nothing reported once the message has its outcome");
    assert.equal(t.progressOf("m"), null);
});

test("a real Resource's progress reaches the message through _sendWithProgress, rising to 1.0", async () => {
    const { a, b } = linkPair();
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const self = { _onSendProgress: [], _sendTransfers: new SendTransfers({ setTimer: () => null, clearTimer() {} }) };
    install(self, {}, ["_sendWithProgress(link, data, convHash, msgId, label)"]);
    const seen = [];
    self._onSendProgress.push((conv, id, p) => seen.push([conv, id, p]));
    await within(self._sendWithProgress(a, Buffer.alloc(100_000, 1), "c".repeat(32), "msg1", "direct"), 20_000, "the Resource");
    assert.ok(seen.length >= 3, `several reports: ${seen.length}`);
    assert.ok(seen.every(([conv, id]) => conv === "c".repeat(32) && id === "msg1"));
    const values = seen.map(([, , p]) => p);
    assert.ok(values.every((v, i) => i === 0 || v > values[i - 1]), "strictly rising");
    assert.ok(values[0] >= 0.10);
    assert.equal(values.at(-1), 1);
    assert.equal(self._sendTransfers.inFlight("msg1"), false, "ended");
});

// ── §1 for bulk transfers ───────────────────────────────────────────────────

function fakeClock() {
    let now = 0;
    let seq = 0;
    const timers = new Map();
    return {
        now: () => now,
        setTimer: (fn, ms) => { timers.set(++seq, { fn, at: now + ms }); return seq; },
        clearTimer: (id) => timers.delete(id),
        advance(ms) {
            const until = now + ms;
            for (;;) {
                const next = [...timers.entries()].filter(([, t]) => t.at <= until).sort((x, y) => x[1].at - y[1].at)[0];
                if (!next) break;
                timers.delete(next[0]);
                now = next[1].at;
                next[1].fn();
            }
            now = until;
        },
    };
}

test("§1: a transfer silent for more than 5 s is logged as a violation, once, and never failed for it", () => {
    const clock = fakeClock();
    const errors = [];
    const warns = [];
    const t = new SendTransfers({ ...clock, log: { error: (m) => errors.push(m), warn: (m) => warns.push(m) } });
    assert.equal(QUIET_MS, 5_000);
    const h = t.begin("m", "direct transfer of m");
    // A photo over the relay: a window answered every 4 s for two minutes.
    for (let i = 1; i <= 30; i++) {
        clock.advance(4_000);
        t.progress(h, i / 31);
    }
    assert.deepEqual(errors, [], "minutes long, but never silent for 5 s: no violation");
    clock.advance(5_001);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /\[§1\] VIOLATION direct transfer of m: no progress for 5 s/);
    clock.advance(20_000);
    assert.equal(errors.length, 1, "logged once per silence");
    assert.equal(t.inFlight("m"), true, "still in flight: the silence decides nothing");
    t.progress(h, 0.99);
    assert.match(warns[0], /progress again after 25\.0 s of silence/);
    assert.deepEqual(t.violations.map((v) => [v.msgId, v.silentMs]), [["m", 25_001]]);
    t.end(h, true);
    clock.advance(60_000);
    assert.equal(errors.length, 1, "an ended transfer is not watched");
});

test("the §1 assertion carries its NEVER REMOVE comment", async () => {
    const { readFile } = await import("node:fs/promises");
    const source = await readFile(new URL("./lib/send_progress.js", import.meta.url), "utf8");
    assert.match(source, /\/\/ NEVER REMOVE EVER — see DESIGN_PRINCIPLES\.md §1[^\n]*\n\s+this\._log\.error\?\.\(`\[§1\] VIOLATION/);
});

// ── the send ceiling and the propagation fallback ───────────────────────────

/** _dispatchMessage, _armSendCeiling and _failSending on captured timers. */
function dispatcher() {
    const clock = fakeClock();
    const storage = memoryStorage();
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness: { recordInbound() {} }, Date });
    const timers = [];
    const env = {
        MsgStore, Harness: { error() {} }, console: quiet,
        ContactStore: { propagationDelay: () => 5, setReachable() {} },
        setTimeout: (f, ms) => { const t = { f, ms, at: clock.now() + ms }; timers.push(t); return t; },
        clearTimeout: (t) => { if (t) t.cleared = true; },
    };
    const transfers = new SendTransfers({ ...clock, log: quiet });
    const self = {
        _onMsg: [], _pendingTimeouts: new Map(), _sendTransfers: transfers,
        _decideMessageName: () => null, _recordNameDelivered() {},
        sendingIdentity: () => ({ hash: "a".repeat(32), isDistro: false }),
    };
    install(self, env, ["_dispatchMessage(contact, outMsg)", "_armSendCeiling(contactHash, msgId)", "_failSending(contactHash, msgId)"]);
    const fire = (t) => { t.fired = true; t.f(); };
    const pending = (ms) => timers.filter((t) => t.ms === ms && !t.fired && !t.cleared);
    return { clock, MsgStore, timers, transfers, self, fire, pending };
}

test("the 30 s ceiling does not fail a send whose Resource is still moving; the Resource's end decides", () => {
    const d = dispatcher();
    const conv = "c".repeat(32);
    const rec = d.MsgStore.add(conv, { dir: "out", content: "", status: "sending" });
    const transfer = d.transfers.begin(rec.id, "direct");
    d.self._armSendCeiling(conv, rec.id);
    for (let i = 1; i <= 10; i++) { d.clock.advance(3_000); d.transfers.progress(transfer, i / 20); }
    d.fire(d.pending(30_000)[0]);
    assert.equal(d.MsgStore.get(conv)[0].status, "sending", "still moving at 30 s: not failed");
    assert.equal(d.pending(30_000).length, 0, "nothing re-armed while it moves");
    // It fails (its own watchdog, a refusal, the link closing): the ceiling
    // runs again from there, giving the propagated copy the same 30 s.
    d.transfers.end(transfer, false);
    assert.equal(d.pending(30_000).length, 1);
    d.fire(d.pending(30_000)[0]);
    assert.equal(d.MsgStore.get(conv)[0].status, "failed");
});

test("a text DM with nothing in flight still fails at the ceiling, as before", () => {
    const d = dispatcher();
    const conv = "c".repeat(32);
    const rec = d.MsgStore.add(conv, { dir: "out", content: "hi", status: "sending" });
    d.self._armSendCeiling(conv, rec.id);
    d.fire(d.pending(30_000)[0]);
    assert.equal(d.MsgStore.get(conv)[0].status, "failed");
});

test("the propagation fallback waits while the direct Resource moves, then goes after 5 s of quiet (Timer P)", () => {
    const d = dispatcher();
    const peer = { destHash: "d".repeat(32), publicKey: "00", isDistro: false };
    const rec = d.MsgStore.add(peer.destHash, { dir: "out", content: "", status: "sending" });
    let transfer;
    d.self._sendPacket = (hash, key, content, id) => { transfer = d.transfers.begin(id, "direct"); };
    const copies = [];
    d.self._propagateMessage = async (contact, msg) => { copies.push(msg.id); };
    d.self._dispatchMessage(peer, rec);
    const [fallback, ceiling] = d.timers;
    assert.deepEqual([fallback.ms, ceiling.ms], [5_000, 30_000], "armed as before: the fallback, then the ceiling");
    d.clock.advance(4_000);
    d.transfers.progress(transfer, 0.3);
    d.clock.advance(1_000);
    d.fire(fallback);
    assert.deepEqual(copies, [], "moving 1 s ago: no second upload of the photo");
    const rearmed = d.pending(4_000);
    assert.equal(rearmed.length, 1, "it waits the rest of the quiet window");
    d.clock.advance(4_000);
    d.fire(rearmed[0]);
    assert.deepEqual(copies, [rec.id], "5 s without activity: the copy goes");
});

test("a fallback with nothing moving goes at once, as before", () => {
    const d = dispatcher();
    const peer = { destHash: "e".repeat(32), publicKey: "00", isDistro: false };
    const rec = d.MsgStore.add(peer.destHash, { dir: "out", content: "text", status: "sending" });
    d.self._sendPacket = () => {};
    const copies = [];
    d.self._propagateMessage = async (contact, msg) => { copies.push(msg.id); };
    d.self._dispatchMessage(peer, rec);
    d.fire(d.timers[0]);
    assert.deepEqual(copies, [rec.id]);
});

// ── groups take no attachment ───────────────────────────────────────────────

const REFUSAL = constValue("GROUP_ATTACHMENT_REFUSAL");

test("the paperclip in a group says why a group takes no attachment", () => {
    assert.match(REFUSAL, /group messages that are relayed carry text only, in every Retichat client/);
    const notices = [];
    const app = { state: { activeHash: "g".repeat(32) }, _composerNotice: (t) => notices.push(t) };
    install(app, { GroupStore: { isGroupChat: () => true }, ChannelStore: { get: () => null }, GROUP_ATTACHMENT_REFUSAL: REFUSAL }, ["_pickAttachments()"]);
    app._pickAttachments();
    assert.deepEqual(notices, [REFUSAL]);
});

function composer({ chat, group = false, attachments = [], text = "", refusal = null }) {
    const notices = [];
    const sent = [];
    const ta = { value: text, style: {} };
    const app = {
        state: { activeHash: chat }, _pendingAttachments: new Map(attachments.length ? [[chat, attachments]] : []),
        _composerNotice: (t) => notices.push(t), _syncOpenChatMessages() {}, _refreshSidebar() {}, _scrollChatBottom() {},
        _renderComposerTray() {},
    };
    install(app, {
        document: { getElementById: () => ta }, requestAnimationFrame() {}, alert: (m) => assert.fail(m), console: quiet,
        GroupStore: { isGroupChat: () => group }, ChannelStore: { get: () => null },
        ContactStore: { get: (h) => ({ destHash: h, publicKey: "00" }) },
        GROUP_ATTACHMENT_REFUSAL: REFUSAL,
        RnsClient: {
            attachmentRefusal: () => refusal,
            sendMessage: (c, content, atts) => sent.push({ content, atts }),
            sendGroupMessage: async (id, content) => sent.push({ group: id, content }),
        },
    }, ["sendMessage()"]);
    return { app, notices, sent, ta };
}

test("a group message with attachments is refused in the composer; nothing is sent", () => {
    const c = composer({ chat: "g".repeat(32), group: true, attachments: [file("a.png", 3)], text: "look" });
    c.app.sendMessage();
    assert.deepEqual(c.notices, [REFUSAL]);
    assert.deepEqual(c.sent, []);
    assert.equal(c.ta.value, "look", "the draft stays");
});

test("a DM over its limits is refused in the composer with why; the draft and the attachments stay", () => {
    const c = composer({ chat: "d".repeat(32), attachments: [file("big.jpg", 3)], text: "caption", refusal: "too big because" });
    c.app.sendMessage();
    assert.deepEqual(c.notices, ["too big because"]);
    assert.deepEqual(c.sent, []);
    assert.equal(c.ta.value, "caption");
    assert.equal(c.app._pendingAttachments.get("d".repeat(32)).length, 1);

    const ok = composer({ chat: "d".repeat(32), attachments: [file("a.jpg", 3)], text: "" });
    ok.app.sendMessage();
    assert.equal(ok.sent.length, 1, "a captionless attachment sends");
    assert.equal(ok.sent[0].content, "");
    assert.equal(ok.sent[0].atts.length, 1);
    assert.equal(ok.app._pendingAttachments.size, 0, "and the tray empties");
});
