/**
 * RECEIVING ATTACHMENTS — every path a message reaches the web client by keeps
 * what it carries, at the size it was sent:
 *
 *   the router (lib/rns/lxmf/lxmf_router.js) and connect()'s handler behind
 *   it: an opportunistic packet, a link packet, a link Resource, and a message
 *   fetched from the propagation node (/get);
 *   _handleDistroBlob: a blob for this device's distro (rfed.link push, the
 *   stream, /distro/pull), and a §17.11 sent-copy from a sibling device;
 *   _handleGroupMessage: a group message.
 *
 * The ticket trap (LXMF-rust 06c40e1): a captionless attachment from a sender
 * that includes its ticket is a message, never a delivery notification; the
 * reference's ticket [expires, ticket] is never looked up as one of ours; and
 * _handleDistroBlob answers false (rfed's push gets that answer) whenever it
 * kept nothing.
 *
 * These run the real shipped code: the router, LXMessage, the message
 * handler, _keepAttachments, _fetchPropagatedMessages, _handleDistroBlob and
 * _handleGroupMessage cut out of app.js (test_app_source.mjs), the real
 * MsgStore and ContactStore, and an attachment store over a memory backend.
 *
 * Run: node --test attachments_receive.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, { GROUP_FIELDS } from "./lib/rns/lxmf/lxmf.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Link from "./lib/rns/link.js";
import EventEmitter from "./lib/rns/utils/events.js";
import * as DN from "./lib/display_name.js";
import { AttachmentStore, attachmentKey, memoryBackend } from "./lib/attachment_store.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { linkPair, settle, within } from "./test_link_pair.mjs";
import { build, compile, constValue, install, installPropagated, memoryStorage, messageHandler } from "./test_app_source.mjs";

const quiet = { log() {}, warn() {}, error() {} };
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const sha = (b) => Cryptography.fullHash(Buffer.from(b)).toString("hex");
const PLACEHOLDER = constValue("DISTRO_ATTACHMENT_PLACEHOLDER");
const WEB_TICKET = "0123456789abcdef";
const pythonTicket = () => [1_792_000_000.0, Buffer.alloc(16, 9)];   // LXMF include_ticket: [expires, ticket]

let clock = 1_790_000_000;
/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content, fields = new Map()) {
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = Buffer.from(lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(toHash, "hex");
    m.title = "";
    m.content = content;
    m.fields = fields;
    const packed = m.pack(from, false);
    packed.lxmfHash = m.hash.toString("hex");
    return packed;
}

/** A PNG-ish payload of exactly n bytes, distinct per seed. */
const payload = (n, seed = 1) => {
    const b = Buffer.alloc(n);
    for (let i = 0; i < n; i++) b[i] = (i * 31 + seed * 7) & 0xff;
    return b;
};

/** What a page keeps for a message: the stores and the attachment store. */
function page(me) {
    const storage = memoryStorage();
    const Harness = { recordInbound() {}, event() {}, error() {} };
    const ContactStore = build("ContactStore", {
        sGet: storage.sGet, sSet: storage.sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });
    const GroupMsgStore = build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date });
    const DistroSeen = build("DistroSeen", { sGet: storage.sGet, sSet: storage.sSet });
    const backend = memoryBackend({ persistent: true });
    const Attachments = new AttachmentStore(backend, { warn() {} });
    const groups = new Map();
    const GroupStore = { getAll: () => [...groups.values()], get: (id) => groups.get(id) ?? null, memberStatus: () => undefined,
        isClosed: () => false, heldChanges: () => [], _save() {} };
    const self = {
        _onMsg: [], _pendingTickets: new Map(), _onAttachmentState: [], ownHash: lxmfHash(me),
        _handleDistroIdentityTransfer() {},
    };
    install(self, { MsgStore, GroupMsgStore, ContactStore, GroupStore, Attachments, attachmentKey, Cryptography, console: quiet }, [
        "_keepAttachments(store, convHash, record, found, fieldsUnreadable = null)",
        "_findRecord(msgId)",
        "async attachmentsFor(msgId)",
    ]);
    install(self, {
        GroupStore, GroupMsgStore, ContactStore, console: quiet, Date, Buffer, LXMF, sentTimeMs,
        ownLxmfDestinationHash: () => lxmfHash(me),
        // The group rule is not what this tests: it lets the plain post
        // through, and the post is its source's own (privacy_filter.test.mjs
        // pins the rule and GROUP_SENDER).
        PrivacyFilter: { groupAccepts: () => true, groupMember: (group, src) => src },
    }, ["_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)"]);
    return { me, storage, ContactStore, MsgStore, GroupMsgStore, DistroSeen, Attachments, backend, groups, self };
}

/** The router as connect() builds it, with the real handler behind it. */
function recipient() {
    const me = Identity.create();
    const p = page(me);
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    const router = new LXMRouter({ registerDestination: () => destination }, me);
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness: { event() {} }, console: quiet,
        RnsClient: { ownHash: lxmfHash(me) }, LXMF, LXMessage, ContactStore: p.ContactStore, MsgStore: p.MsgStore,
        decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(p.self);
    router.on("message", handle);
    const proofs = [];
    return {
        ...p, router, destination, proofs, myHash: lxmfHash(me),
        packet(packed) {
            destination.emit("packet", { data: packed.subarray(16), packet: { prove: () => proofs.push(1) } });
        },
    };
}

async function deliveryLink(r) {
    const pair = linkPair();
    pair.b.accept = () => {};
    r.destination.emit("link_request", pair.b);
    await settle();
    return pair;
}

/** The record of the message whose LXMF hash `h`, in the conversation with `peer`. */
const byHash = (r, peer, h) => r.MsgStore.get(peer).find((m) => m.lxmfHash === h);

async function storedBytes(r, msgId) {
    await settle(2);
    return r.self.attachmentsFor(msgId);
}

// ── the router: every direct path ───────────────────────────────────────────

test("an opportunistic packet: a small attachment is kept, with the message's LXMF hash on the record", async () => {
    const r = recipient();
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const file = payload(40, 1);
    const p = lxm(sender, r.myHash, "", new Map([[0x05, [["tiny.png", file]]]]));
    r.packet(p);
    await settle();
    const rec = byHash(r, S, p.lxmfHash);
    assert.ok(rec, "stored, found by its LXMF hash");
    assert.equal(rec.content, "", "captionless: content stays empty");
    assert.equal(r.proofs.length, 1);
    assert.deepEqual(await storedBytes(r, rec.id), [{ name: "tiny.png", size: 40, sha256: sha(file), mime: "image/png", field: 5, stored: "persisted" }]);
});

test("a link Resource: a 200 KB photo arrives whole (hashmap updates and all), with its caption", async () => {
    const r = recipient();
    const { a } = await deliveryLink(r);
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const photo = payload(200 * 1024, 2);
    const p = lxm(sender, r.myHash, "a caption", new Map([[0x05, [["IMG_0001.jpg", photo]]]]));
    await within(a.sendResource(p), 30_000, "the photo's Resource");
    await settle(6);
    const rec = byHash(r, S, p.lxmfHash);
    assert.equal(rec.content, "a caption");
    assert.deepEqual(rec.attachments.map(({ name, size, sha256, field }) => ({ name, size, sha256, field })),
        [{ name: "IMG_0001.jpg", size: 204_800, sha256: sha(photo), field: 5 }]);
    const [got] = await storedBytes(r, rec.id);
    assert.equal(got.sha256, sha(photo), "byte for byte, read back from the store");
});

test("a link Resource: the staging matrix's largest photo (900 KB) arrives at its original size", async () => {
    const r = recipient();
    const { a } = await deliveryLink(r);
    const sender = Identity.create();
    const photo = payload(900 * 1024, 5);
    const p = lxm(sender, r.myHash, "", new Map([[0x0C, pythonTicket()], [0x05, [["big.png", photo]]]]));
    assert.ok(p.length < LXMRouter.DELIVERY_LIMIT * 1000, "within LXMF's delivery limit, so the link takes it");
    await within(a.sendResource(p), 60_000, "the 900 KB Resource");
    await settle(6);
    const rec = byHash(r, lxmfHash(sender), p.lxmfHash);
    assert.equal(rec.content, "", "captionless, ticket and all: a message");
    const [got] = await storedBytes(r, rec.id);
    assert.deepEqual([got.size, got.sha256], [photo.length, sha(photo)]);
});

test("a link packet with a FIELD_IMAGE (Sideband, MeshChat): shown as an image named by its type", async () => {
    const r = recipient();
    const { a } = await deliveryLink(r);
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const img = payload(60, 3);
    const p = lxm(sender, r.myHash, "", new Map([[0x06, ["webp", img]]]));
    a.send(p);
    await settle(6);
    const rec = byHash(r, S, p.lxmfHash);
    assert.deepEqual(rec.attachments.map(({ name, mime, field }) => ({ name, mime, field })), [{ name: "webp", mime: "image/webp", field: 6 }]);
});

test("propagated (/get): the fetched message keeps its attachment", async () => {
    const r = recipient();
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const file = payload(5000, 4);
    const p = lxm(sender, r.myHash, "from the node", new Map([[0x05, [["report.pdf", file]]]]));
    const blob = Buffer.concat([Buffer.from(r.myHash, "hex"), r.me.encrypt(p.subarray(16))]);
    const self = {
        _lxmfRouter: r.router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) return true;
            if (wants) return [blob];
            return [Buffer.from([1])];
        },
    };
    await installPropagated(self, { Link, Buffer, LXMessage, MsgPack, IdMgr: { id: r.me }, console: quiet })._fetchPropagatedMessages();
    await settle();
    const rec = byHash(r, S, p.lxmfHash);
    assert.equal(rec.content, "from the node");
    assert.deepEqual((await storedBytes(r, rec.id)).map(({ name, sha256, mime }) => ({ name, sha256, mime })),
        [{ name: "report.pdf", sha256: sha(file), mime: "application/pdf" }]);
});

test("propagated (/get): a fields map that cannot be decoded costs the attachments, never the message, and it is purged", async () => {
    // The task's "every receive path": /get ran its own msgpack pre-parse,
    // which threw on such a map before fromBytes could fall back, so the
    // message was lost, never purged, and downloaded again on every fetch
    // (review of adee619).
    const r = recipient();
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const head = MsgPack.pack([(clock += 1), Buffer.alloc(0), Buffer.from("keep this text")]);
    const raw = Buffer.concat([Buffer.from([0x94]), head.subarray(1), Buffer.from([0x81, 0x05, 0xd4, 0x01, 0x00])]);
    assert.throws(() => MsgPack.unpack(raw), "msgpack cannot decode this fields map");
    const dest = Buffer.from(r.myHash, "hex"), src = Buffer.from(S, "hex");
    const signature = sender.sign(Buffer.concat([dest, src, raw, LXMessage.hashOf(dest, src, raw)]));
    const blob = Buffer.concat([dest, r.me.encrypt(Buffer.concat([src, signature, raw]))]);
    const tid = Buffer.alloc(32, 0x5a);
    const purged = [];
    const self = {
        _lxmfRouter: r.router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) { purged.push(...haves.map((h) => Buffer.from(h).toString("hex"))); return true; }
            if (wants) return [blob];
            return [tid];
        },
    };
    await installPropagated(self, { Link, Buffer, LXMessage, MsgPack, IdMgr: { id: r.me }, console: quiet })._fetchPropagatedMessages();
    await settle();
    const [rec] = r.MsgStore.get(S);
    assert.ok(rec, "stored");
    assert.equal(rec.content, "keep this text");
    assert.equal(rec.fieldsUnreadable, true, "and the bubble says part of it could not be read");
    assert.deepEqual(purged, [tid.toString("hex")], "purged from the node, so it is not downloaded again");
});

// ── the ticket trap, on the router path ─────────────────────────────────────

test("a captionless attachment with a ticket is a message, whoever's ticket it is (LXMF-rust 06c40e1)", async () => {
    const r = recipient();
    const sender = Identity.create();
    const S = lxmfHash(sender);
    for (const [ticket, field] of [
        [pythonTicket(), [0x05, [["a.png", payload(30, 5)]]]],
        [pythonTicket(), [0x06, ["png", payload(30, 6)]]],
        [WEB_TICKET, [0x07, [0x10, payload(30, 7)]]],
    ]) {
        const p = lxm(sender, r.myHash, "", new Map([[0x0C, ticket], field]));
        r.packet(p);
        await settle();
        const rec = byHash(r, S, p.lxmfHash);
        assert.ok(rec, `field 0x0${field[0]} with a ${Array.isArray(ticket) ? "Python" : "web"} ticket is stored`);
        assert.equal(rec.content, "");
        assert.equal(rec.attachments.length, 1);
    }
});

test("a ticket-only message is a delivery notification; only a ticket of ours is ever looked up", async () => {
    const r = recipient();
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const looked = [];
    const realGet = r.self._pendingTickets.get.bind(r.self._pendingTickets);
    r.self._pendingTickets.get = (k) => { looked.push(k); return realGet(k); };
    let proved = null;
    r.self._pendingTickets.set(WEB_TICKET, { contactHash: S, messageId: "m1", onProof: (id) => { proved = id; } });

    // The reference's ticket on an empty message: not ours, never looked up,
    // and (LXMF-rust parity) a notification, so nothing is stored.
    r.packet(lxm(sender, r.myHash, "", new Map([[0x0C, pythonTicket()]])));
    await settle();
    assert.deepEqual(looked, [], "an [expires, ticket] is never a key of ours");
    assert.deepEqual(r.MsgStore.get(S), []);

    // Ours, waiting: it proves the message it was sent with.
    r.packet(lxm(sender, r.myHash, "", new Map([[0x0C, WEB_TICKET]])));
    await settle();
    assert.equal(proved, "m1");
    assert.deepEqual(looked, [WEB_TICKET]);
    assert.deepEqual(r.MsgStore.get(S), []);
});

// ── the distro path ─────────────────────────────────────────────────────────

/** _handleDistroBlob for a page holding distro identity `distro`. */
function distroPage({ device = Identity.create(), distro = Identity.create() } = {}) {
    const p = page(device);
    p.self._handleDistroBlob = compile("_handleDistroBlob(distroHash, blob)", {
        DistroManager: { identity: distro, lxmfDeliveryHash: lxmfHash(distro) },
        MsgPack, Buffer, DistroSeen: p.DistroSeen, Harness: { event() {}, error() {} },
        ContactStore: p.ContactStore, MsgStore: p.MsgStore, LXMF, Cryptography, LXMessage, decodeDisplayName: DN.decodePayload,
        ownLxmfDestinationHash: () => lxmfHash(device), console: quiet, DISTRO_ATTACHMENT_PLACEHOLDER: PLACEHOLDER,
        sentTimeMs,
    })(p.self);
    const D = lxmfHash(distro);
    /** A blob as rfed hands it over: D | encrypted(source | signature | payload). */
    const blob = (packed) => Buffer.concat([Buffer.from(D, "hex"), distro.encrypt(packed.subarray(16))]);
    return { ...p, device, distro, D, blob };
}

test("distro: a captionless photo with a ticket is kept (true); its LXMF hash and bytes are on the record", async () => {
    const d = distroPage();
    const sender = Identity.create();
    const S = lxmfHash(sender);
    const photo = payload(100_000, 8);
    for (const ticket of [pythonTicket(), WEB_TICKET]) {
        const p = lxm(sender, d.D, "", new Map([[0x0C, ticket], [0x05, [["photo.jpg", photo]]]]));
        assert.equal(d.self._handleDistroBlob(null, d.blob(p)), true);
        const rec = byHash(d, S, p.lxmfHash);
        assert.ok(rec, "stored, by its LXMF hash");
        assert.equal(rec.content, "", "no placeholder: it has an attachment");
        assert.equal((await storedBytes(d, rec.id))[0].sha256, sha(photo));
    }
});

test("distro: a notification for a ticket we are not waiting on keeps nothing, so it answers false", () => {
    const d = distroPage();
    const sender = Identity.create();
    const p = lxm(sender, d.D, "", new Map([[0x0C, pythonTicket()]]));
    const looked = [];
    d.self._pendingTickets.get = (k) => { looked.push(k); return undefined; };
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), false, "rfed is not told the web holds it");
    assert.deepEqual(looked, [], "the reference's ticket is never looked up as ours");
    assert.deepEqual(d.MsgStore.get(lxmfHash(sender)), []);
    // Not recorded as seen: a later copy is judged again, not answered "held".
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), false);

    const ours = lxm(sender, d.D, "", new Map([[0x0C, WEB_TICKET]]));
    assert.equal(d.self._handleDistroBlob(null, d.blob(ours)), false, "ours, but nothing waits on it");
    let proved = null;
    d.self._pendingTickets = new Map([[WEB_TICKET, { contactHash: "x", messageId: "m9", onProof: (id) => { proved = id; } }]]);
    const again = lxm(sender, d.D, "", new Map([[0x0C, WEB_TICKET]]));
    assert.equal(d.self._handleDistroBlob(null, d.blob(again)), true, "its proof was taken");
    assert.equal(proved, "m9");
});

test("distro: a kept message answers true, and so does a later copy of it; a dropped one never does", () => {
    const d = distroPage();
    const sender = Identity.create();
    const p = lxm(sender, d.D, "hello", new Map());
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), true);
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), true, "already held");
    assert.equal(d.MsgStore.get(lxmfHash(sender)).length, 1);
    assert.equal(d.self._handleDistroBlob(null, Buffer.alloc(40)), false, "too short");
    const other = Identity.create();
    const notOurs = Buffer.concat([Buffer.from(lxmfHash(other), "hex"), other.encrypt(p.subarray(16))]);
    assert.equal(d.self._handleDistroBlob(null, notOurs), false, "not for this distro");
});

test("distro: a message with neither text nor an attachment shows iOS's placeholder", () => {
    const d = distroPage();
    const sender = Identity.create();
    const p = lxm(sender, d.D, "  ", new Map([[0x07, "not an audio pair"]]));
    // 0x07 malformed: no attachment, but something could not be read.
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), true);
    const rec = d.MsgStore.get(lxmfHash(sender))[0];
    assert.equal(rec.attachmentsSkipped, 1, "the bubble says an attachment could not be read");
    const bare = lxm(sender, d.D, "", new Map([[0xFB, "some.other.type"]]));
    assert.equal(d.self._handleDistroBlob(null, d.blob(bare)), true);
    assert.equal(d.MsgStore.get(lxmfHash(sender))[1].content, PLACEHOLDER);
    assert.equal(PLACEHOLDER, "[Attachment not available via the distro address]", "iOS's words");
});

test("distro: a fields map that cannot be decoded costs the attachments, never the message", () => {
    // Android 702e5fb: a stranger's map lost the text for good, and every
    // later copy was deduped as seen.
    const d = distroPage();
    const sender = Identity.create();
    const head = MsgPack.pack([(clock += 1), Buffer.alloc(0), Buffer.from("keep this text")]);
    const raw = Buffer.concat([Buffer.from([0x94]), head.subarray(1), Buffer.from([0x81, 0x05, 0xd4, 0x01, 0x00])]);
    const dest = Buffer.from(d.D, "hex"), src = Buffer.from(lxmfHash(sender), "hex");
    const signature = sender.sign(Buffer.concat([dest, src, raw, LXMessage.hashOf(dest, src, raw)]));
    const blob = Buffer.concat([dest, d.distro.encrypt(Buffer.concat([src, signature, raw]))]);
    assert.equal(d.self._handleDistroBlob(null, blob), true);
    const [rec] = d.MsgStore.get(lxmfHash(sender));
    assert.equal(rec.content, "keep this text");
    assert.equal(rec.fieldsUnreadable, true);
});

// ── §17.11 sent-copies ──────────────────────────────────────────────────────

const OTHER_DEVICE = "fedcba9876543210fedcba9876543210";
const R = "0123456789abcdef0123456789abcdef";
const sentMarker = (extra = []) => new Map([[0xFB, "rfed.distro.sent"], [0xFC, R], [0xFD, OTHER_DEVICE], ...extra]);

test("a sibling's captionless photo arrives as its text-only copy: iOS's placeholder, not an empty bubble", () => {
    const d = distroPage();
    const p = lxm(d.distro, d.D, "", sentMarker());
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), true);
    const [rec] = d.MsgStore.get(R);
    assert.equal(rec.dir, "out");
    assert.equal(rec.content, PLACEHOLDER, "iOS ChatRepository.swift handleDistroSentCopy");
    const withText = lxm(d.distro, d.D, "with a caption", sentMarker());
    d.self._handleDistroBlob(null, d.blob(withText));
    assert.equal(d.MsgStore.get(R)[1].content, "with a caption");
});

test("a sent-copy that does carry an attachment keeps it (the spec's copies are text only, but none is thrown away)", async () => {
    const d = distroPage();
    const file = payload(500, 9);
    const p = lxm(d.distro, d.D, "", sentMarker([[0x05, [["x.png", file]]]]));
    assert.equal(d.self._handleDistroBlob(null, d.blob(p)), true);
    const [rec] = d.MsgStore.get(R);
    assert.equal(rec.content, "");
    assert.equal((await storedBytes(d, rec.id))[0].sha256, sha(file));
});

// ── groups ──────────────────────────────────────────────────────────────────

test("a group message keeps its attachments; a captionless one is no longer \"(empty)\"", async () => {
    const me = Identity.create();
    const p = page(me);
    const G = "9".repeat(32);
    p.groups.set(G, { groupId: G, groupName: "G", members: new Map(), lastActivity: 0 });
    const sender = Identity.create();
    const S = lxmfHash(sender);
    p.ContactStore.keep(S);
    const photo = payload(800, 4);
    const fields = new Map([[GROUP_FIELDS.GROUP_ID, G], [0x05, [["g.png", photo]]]]);
    const packed = lxm(sender, lxmfHash(me), "", fields);
    const m = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16));
    p.self._handleGroupMessage(m, S, "", LXMessage.extractGroupFields(m.fields));
    const [rec] = p.GroupMsgStore.get(G);
    assert.equal(rec.content, "");
    assert.equal(rec.lxmfHash, m.hash.toString("hex"));
    assert.equal((await storedBytes(p, rec.id))[0].sha256, sha(photo));

    const bare = lxm(sender, lxmfHash(me), "", new Map([[GROUP_FIELDS.GROUP_ID, G]]));
    const mb = LXMessage.fromBytes(bare.subarray(16), bare.subarray(0, 16));
    p.self._handleGroupMessage(mb, S, "", LXMessage.extractGroupFields(mb.fields));
    assert.equal(p.GroupMsgStore.get(G)[1].content, "(empty)", "nothing at all is still \"(empty)\"");
});
