/**
 * A live push of this device's own propagated message on rfed.link is taken
 * once, as a /get result is, and the /get never fetches or stores it again.
 *
 * _bindRfedLinkForDistroPush binds rfed.link with this device's lxmf.delivery
 * hash (/propagation/stream/open), so rfed pushes the device's propagated
 * messages there as /lxmf/delivery requests as it stores them (RFed-spec
 * Link.md, path map). Until 2026-10-01 _onRfedLinkPush sent every such push
 * to _handleDistroBlob, which refused anything not addressed to the distro:
 * on round 3 staging every propagated message to the web (photos up to
 * ~921 KB, ~27 s each) crossed the relay twice, the refused push and then the
 * /get, and was delivered only when something triggered a /get.
 *
 * Now (app.js _onRfedLinkPush → _onPropagatedPush → _ingestPropagatedBlob,
 * as Android's PropagationStream.onPush and iOS's configurePropagationStream
 * hand such a push to LXMF-rust ingest_propagated_lxmf, the path a /get
 * result takes): decrypted with the device identity, the privacy filter as on
 * /get, the router; answered true when held. rfed keeps the message in its
 * messagestore whatever the answer (lxmf_propagation.rs
 * dispatch_live_or_notify), so its transient id is recorded (PropagatedHeld,
 * LXMF's locally_delivered_transient_ids) and the next /get puts it in its
 * haves without downloading it (LXMRouter.py message_list_response).
 *
 * The shipped methods cut out of app.js (test_app_source.mjs), the real
 * LXMRouter, LXMessage, MsgStore, LxmfSeen and message handler, real
 * identities and encryption, and a real request over two in-process Links
 * (test_link_pair.mjs): rfed is one end, the page the other.
 *
 * Run: node --test propagated_push.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Link from "./lib/rns/link.js";
import EventEmitter from "./lib/rns/utils/events.js";
import * as DN from "./lib/display_name.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { linkPair, settle, within } from "./test_link_pair.mjs";
import { build, constValue, install, installPropagated, memoryStorage, messageHandler, propagatedHeld } from "./test_app_source.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery");
const Harness = { recordInbound() {}, event() {}, error() {} };
const RFED_LINK_PUSH_HASHES = constValue("RFED_LINK_PUSH_HASHES", {
    Cryptography, Buffer,
    RFED_LINK_PUSH_DELIVERY: constValue("RFED_LINK_PUSH_DELIVERY"),
    RFED_LINK_PUSH_LXMF: constValue("RFED_LINK_PUSH_LXMF"),
    RFED_LINK_PUSH_NOTIFY: constValue("RFED_LINK_PUSH_NOTIFY"),
});

let clock = 1_790_000_000;
/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content) {
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = lxmfHash(from);
    m.destinationHash = Buffer.from(toHash);
    m.title = "";
    m.content = content;
    m.fields = new Map();
    return m.pack(from, false);
}

/** What a propagation node stores, returns on /get and pushes: destination | encrypted(rest). */
const stored = (encryptTo, packed) => Buffer.concat([packed.subarray(0, 16), encryptTo.encrypt(packed.subarray(16))]);
/** Its transient id, the SHA-256 of those bytes (LXMF validate_pn_stamp; rfed lists it on /get). */
const tidOf = (blob) => hex(Cryptography.fullHash(blob));

/**
 * A page holding identity `me` over `storage` (a reload is a second page on
 * the same storage), with the propagation node (`node`) behind its /get and
 * rfed at the far end of its rfed.link. `filter` is the router's privacy
 * filter (none: everything passes); `distro` an identity the page holds as
 * its distro.
 */
function page({ me = Identity.create(), storage = memoryStorage(), node = propagationNode(), filter = null, distro = null } = {}) {
    const logs = [];
    const log = { log: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")) };
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });
    const LxmfSeen = build("LxmfSeen", { sGet: storage.sGet, sSet: storage.sSet });
    LxmfSeen.init();
    const contacts = new Map();
    const ContactStore = {
        known: (h) => contacts.has(h), keep: (h) => { if (!contacts.has(h)) contacts.set(h, { destHash: h, hidden: true }); return contacts.get(h); },
        get: (h) => contacts.get(h) ?? null, touch() {}, setReachable() {}, _save() {},
        acceptMessageName() { return false; },
    };
    const destination = new EventEmitter();
    destination.hash = lxmfHash(me);
    const router = new LXMRouter({ registerDestination: () => destination }, me, { filter });
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const self = { _onMsg: [], _pendingTickets: new Map(), _lxmfRouter: router, _handleDistroIdentityTransfer() {}, _handleGroupMessage() {} };
    router.on("message", messageHandler({
        Buffer, LxmfSeen, Harness, console: log, RnsClient: { ownHash: hex(destination.hash) },
        LXMF, LXMessage, ContactStore, MsgStore, decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self));

    // /get over the propagation link: list, download one at a time, purge.
    self._propLink = { status: Link.ACTIVE, sendRequest: (path, data) => data };
    self._waitForResponse = (link, request) => node.answer(request);
    let decrypts = 0;
    let parses = 0;
    const IdMgr = { id: { decrypt: (b) => { decrypts++; return me.decrypt(b); } } };
    const counted = new Proxy(LXMessage, { get: (t, k) => (k === "fromBytes" ? (...a) => { parses++; return LXMessage.fromBytes(...a); } : t[k]) });
    installPropagated(self, { Link, Buffer, LXMessage: counted, MsgPack, IdMgr, console: log, PropagatedHeld: propagatedHeld(storage) });

    // rfed.link, as _ensureRfedLink wires it: rfed is `a`, this page `b`.
    const distroBlobs = [];
    self._handleDistroBlob = (hash, blob) => { distroBlobs.push(hex(blob)); return true; };
    self._handleChannelPacket = () => false;
    self._pullDistroMessages = () => {};
    const DistroManager = distro ? { has: true, lxmfDeliveryHash: hex(lxmfHash(distro)) } : { has: false };
    install(self, { RFED_LINK_PUSH_HASHES, DistroManager, Harness, Buffer, console: log }, ["_onRfedLinkPush(link, requestId, pathHash, data)"]);
    const { a: rfed, b } = linkPair();
    b.on("request", ({ requestId, path, data }) => self._onRfedLinkPush(b, requestId, path, data));

    return {
        me, self, node, logs, emitted, distroBlobs, myHash: destination.hash,
        decrypts: () => decrypts, parses: () => parses,
        /** rfed pushes `blob` as `/lxmf/delivery` and resolves with the page's answer. */
        push: (blob) => within(rfed.responseFor(rfed.sendRequest("/lxmf/delivery", blob)), 60_000, "the push's answer"),
        fetch: async () => { await self._fetchPropagatedMessages(); await settle(); },
        inbox: (from) => MsgStore.get(hex(lxmfHash(from))).filter((m) => m.dir === "in").map((m) => m.content),
    };
}

/** The node's messagestore, by transient id, and what /get asked of it. */
function propagationNode() {
    const node = {
        store: new Map(), downloads: [], purged: [], onDownload: null,
        hold(blob) { node.store.set(tidOf(blob), blob); return tidOf(blob); },
        async answer([wants, haves]) {
            if (haves) {
                for (const id of haves) { node.purged.push(hex(id)); node.store.delete(hex(id)); }
                return true;
            }
            if (wants) {
                const id = hex(wants[0]);
                node.downloads.push(id);
                const blob = node.store.get(id);
                await node.onDownload?.(id);
                return blob ? [blob] : [];
            }
            return [...node.store.keys()].map((k) => Buffer.from(k, "hex"));
        },
    };
    return node;
}

test("a live push of this device's own message is stored once and answered true; the next /get purges it without downloading it", async () => {
    const p = page();
    const sender = Identity.create();
    const content = "a photo's worth of text ".repeat(1_250);     // 30 KB: a request Resource on rfed.link
    const blob = stored(p.me, lxm(sender, p.myHash, content));
    assert.ok(blob.length > Link.MDU * 50);
    const tid = p.node.hold(blob);                                 // rfed stores it, then pushes it

    assert.equal(await p.push(blob), true, "rfed is told the page holds it");
    await settle();
    assert.deepEqual(p.inbox(sender), [content], "stored, once");

    await p.fetch();
    assert.deepEqual(p.node.downloads, [], "never fetched again");
    assert.deepEqual(p.node.purged, [tid], "but purged from the node, which listed it");
    assert.deepEqual(p.inbox(sender), [content], "and not stored again");
    assert.deepEqual(p.emitted, [content], "the router saw it once");
    assert.ok(p.logs.some((l) => l.includes("[1/4] 1 already held here (received live, or by an earlier fetch): purged without downloading")));

    await p.fetch();
    assert.ok(p.logs.some((l) => l.includes("[1/4] No pending messages")), "nothing left on the node");
});

test("a message taken live is still held after a reload: the /get after it purges it without downloading it", async () => {
    const storage = memoryStorage();
    const me = Identity.create();
    const node = propagationNode();
    const sender = Identity.create();
    const before = page({ me, storage, node });
    const blob = stored(me, lxm(sender, before.myHash, "taken live, then the tab reloaded"));
    const tid = node.hold(blob);
    assert.equal(await before.push(blob), true);
    await settle();

    const after = page({ me, storage, node });
    await after.fetch();
    assert.deepEqual(node.downloads, []);
    assert.deepEqual(node.purged, [tid]);
    assert.deepEqual(after.inbox(sender), ["taken live, then the tab reloaded"], "one record, kept over the reload");
});

test("a push that lands while /get downloads the same message: the copy /get returns is purged and not read", async () => {
    const p = page();
    const sender = Identity.create();
    const blob = stored(p.me, lxm(sender, p.myHash, "both at once"));
    const tid = p.node.hold(blob);
    const answers = [];
    p.node.onDownload = async (id) => { if (id === tid) answers.push(await p.push(blob)); };

    await p.fetch();
    assert.deepEqual(answers, [true]);
    assert.deepEqual(p.node.downloads, [tid], "it was on its way when the push landed");
    assert.deepEqual(p.node.purged, [tid]);
    assert.deepEqual(p.emitted, ["both at once"], "the returned copy never reached the router");
    assert.equal(p.parses(), 1, "nor was it parsed");
    assert.deepEqual(p.inbox(sender), ["both at once"]);
    assert.ok(p.logs.some((l) => l.includes("arrived live while it downloaded: this copy is ignored, purged")));
});

test("a push that lands between the listing and that message's download is not downloaded", async () => {
    const p = page();
    const sender = Identity.create();
    const first = stored(p.me, lxm(sender, p.myHash, "first, by /get"));
    const second = stored(p.me, lxm(sender, p.myHash, "second, live"));
    const t1 = p.node.hold(first);
    const t2 = p.node.hold(second);
    p.node.onDownload = async (id) => { if (id === t1) assert.equal(await p.push(second), true); };

    await p.fetch();
    assert.deepEqual(p.node.downloads, [t1], "only the one not yet held");
    assert.deepEqual(p.node.purged.sort(), [t1, t2].sort(), "both purged");
    assert.deepEqual(p.inbox(sender).sort(), ["first, by /get", "second, live"].sort());
    assert.ok(p.logs.some((l) => l.includes(`${t2.slice(0, 8)} arrived live meanwhile: not downloaded, purged`)));
});

test("a message /get took first: its push is answered true and not read again", async () => {
    const p = page();
    const sender = Identity.create();
    const blob = stored(p.me, lxm(sender, p.myHash, "fetched first"));
    p.node.hold(blob);
    await p.fetch();
    const decrypts = p.decrypts();

    assert.equal(await p.push(blob), true, "already held");
    await settle();
    assert.equal(p.decrypts(), decrypts, "not decrypted again");
    assert.deepEqual(p.inbox(sender), ["fetched first"]);
    assert.deepEqual(p.emitted, ["fetched first"]);
});

test("the privacy filter on a push, as on /get: a stranger's is dropped after the decrypt, unparsed and unstored, answered as taken, and purged by the next /get without a download", async () => {
    const friend = Identity.create();
    const stranger = Identity.create();
    const filter = {
        acceptsSource: (source) => hex(source) === hex(lxmfHash(friend)),
        acceptsMessage: () => true,
    };
    const p = page({ filter });
    const theirs = stored(p.me, lxm(stranger, p.myHash, "from a stranger"));
    const ours = stored(p.me, lxm(friend, p.myHash, "from a friend"));
    const tStranger = p.node.hold(theirs);
    const tFriend = p.node.hold(ours);

    // As the reference and the phones answer it: LXMF's lxmf_propagation
    // returns True for a message lxmf_delivery then ignores, and records it as
    // delivered; Android's and iOS's stream link proves every push.
    assert.equal(await p.push(theirs), true);
    assert.equal(p.decrypts(), 1, "decrypted: its source is inside the ciphertext");
    assert.equal(p.parses(), 0, "and nothing more: the drop costs nothing past the decrypt");
    assert.deepEqual(p.inbox(stranger), [], "nothing stored");
    assert.equal(await p.push(ours), true);
    await settle();
    assert.deepEqual(p.inbox(friend), ["from a friend"]);

    await p.fetch();
    assert.deepEqual(p.node.downloads, [], "neither is downloaded");
    assert.deepEqual(p.node.purged.sort(), [tStranger, tFriend].sort(), "both purged");
    assert.deepEqual(p.inbox(stranger), []);
});

test("a push that cannot be read is refused, and left to the /get, which downloads it and purges it unread", async () => {
    const p = page();
    const sender = Identity.create();
    const other = Identity.create();
    const blob = stored(other, lxm(sender, p.myHash, "encrypted to someone else's key"));   // addressed here, unreadable
    const tid = p.node.hold(blob);

    assert.equal(await p.push(blob), false, "rfed is told it was not taken");
    assert.ok(p.logs.some((l) => /rfed\.link push [0-9a-f]{8} decrypt failed .*: refused, left to the next \/get/.test(l)));
    await p.fetch();
    assert.deepEqual(p.node.downloads, [tid]);
    assert.deepEqual(p.node.purged, [tid]);
    assert.ok(p.logs.some((l) => l.includes(`${tid.slice(0, 8)} decrypt failed`) && l.includes("purged unread")));
});

test("a distro push still goes to the distro's handler, untouched; a push for neither address is refused", async () => {
    const distro = Identity.create();
    const p = page({ distro });
    const sender = Identity.create();
    const fanout = stored(distro, lxm(sender, lxmfHash(distro), "to the distro"));
    assert.equal(await p.push(fanout), true, "the distro handler's answer");
    assert.deepEqual(p.distroBlobs, [hex(fanout)], "the whole blob, as before");
    assert.deepEqual(p.emitted, [], "the device's router never sees it");
    assert.equal(p.decrypts(), 0);

    const elsewhere = Identity.create();
    const stray = stored(elsewhere, lxm(sender, lxmfHash(elsewhere), "to someone else"));
    assert.equal(await p.push(stray), false);
    assert.deepEqual(p.distroBlobs, [hex(fanout)]);
    assert.ok(p.logs.some((l) => l.includes("neither this device's address nor its distro's — refused")));

    // With no distro held, the device's own still goes to the router.
    const plain = page();
    const own = stored(plain.me, lxm(sender, plain.myHash, "to the device"));
    assert.equal(await plain.push(own), true);
    await settle();
    assert.deepEqual(plain.inbox(sender), ["to the device"]);
    assert.deepEqual(plain.distroBlobs, []);
});
