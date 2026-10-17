/**
 * RATCHETS IN THE PAGE — app.js over lib/rns (ratchets.test.mjs has the lib).
 *
 *   - OwnRatchets keeps the lxmf.delivery ratchet keys, RNS's ratchet file
 *     as base64, one key per destination; a stored value that is not one is
 *     refused and left in place.
 *   - PeerRatchets keeps a peer's announced ratchet across page loads only
 *     for a destination this page encrypted to with it, a peer ContactStore
 *     has a row for, or one kept already: every announcer stays in memory
 *     (Identity.knownRatchets), as in RNS, but localStorage, which the
 *     messages share and whose writes sSet drops silently when it is full,
 *     does not grow with every announce heard. Written only on a change;
 *     an entry older than RATCHET_EXPIRY (30 days) is dropped at load.
 *   - IdMgr removes both when the identity is forgotten or replaced.
 *   - A propagated message is encrypted to the recipient's ratchet
 *     (_buildPropagationPacked, as LXMessage.py packs it with dest.encrypt),
 *     and one encrypted to this page's ratchet is decrypted
 *     (_ingestPropagatedBlob, through LXMRouter.decryptPropagated); one to
 *     an older ratchet is taken, purged and answered once the older
 *     ratchets were tried, without holding the page.
 *   - app.js over a lib older than ratchets (a cached or restored lib/)
 *     reads and sends as before, and leaves the kept ratchets as they are.
 *   - The distro announce carries no ratchet: several devices hold the
 *     distro identity, and the phones build its announce without one.
 *
 * Run: node --test ratchets_app.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Packet from "./lib/rns/packet.js";
import Announce from "./lib/rns/announce.js";
import MsgPack from "./lib/rns/msgpack.js";
import Link from "./lib/rns/link.js";
import { Reticulum } from "./lib/rns/reticulum.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Cryptography from "./lib/rns/cryptography.js";
import * as DN from "./lib/display_name.js";
import { syncClaimFor, buildSealedUpload } from "./lib/distro_sync.js";
import { app, build, compile, constValue, fn, install, installPropagated, methodBody } from "./test_app_source.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const pub = (ratchet) => Identity.ratchetPublicBytes(ratchet);
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery");
const quiet = { log() {}, warn() {}, error() {} };
const SECOND = 1000;
const DAY = 24 * 60 * 60;

/** Nothing remembered from another test, nothing persisted. */
function fresh() {
    Identity.knownRatchets.clear();
    Identity.ratchetStore = null;
}

/** localStorage, and app.js's sGet, sSet and sSetKept over it. */
function storage() {
    const data = new Map();
    let writes = 0;
    const localStorage = {
        getItem: (k) => (data.has(k) ? data.get(k) : null),
        setItem: (k, v) => { writes++; data.set(k, String(v)); },
        removeItem: (k) => { data.delete(k); },
    };
    const env = { localStorage, PFX: "retichat_" };
    return {
        ...env, data,
        writes: () => writes,
        sGet: fn("sGet", "k", env),
        sSet: fn("sSet", "k, v", env),
        sSetKept: fn("sSetKept", "k, v", env),
    };
}

/** The page's ratchet stores and IdMgr over `page`; `contacts` holds the
 *  destination hashes (hex) ContactStore has a row for. */
function stores(page, contacts = new Set()) {
    const PeerRatchets = build("PeerRatchets", {
        sGet: page.sGet, sSet: page.sSet, localStorage: page.localStorage, PFX: page.PFX,
        Identity, Buffer, ContactStore: { known: (h) => contacts.has(h) },
    });
    PeerRatchets.init();
    const OwnRatchets = build("OwnRatchets", { localStorage: page.localStorage, PFX: page.PFX, sSetKept: page.sSetKept, Buffer });
    const IdMgr = build("IdMgr", {
        sGet: page.sGet, sSet: page.sSet, ID_KEY: "identity_private_key",
        Identity, Buffer, Destination, OwnRatchets, PeerRatchets,
    });
    return { PeerRatchets, OwnRatchets, IdMgr };
}

/** `identity`'s lxmf.delivery with ratchets, announced once: as a peer that
 *  announced its ratchet and this page heard it (remembered in this process). */
function announcedPeer(identity) {
    const destination = new Destination({ sendData() {} }, identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");
    destination.enableRatchets(Destination.memoryRatchetStore());
    destination.announce(MsgPack.pack([null, null, []]));
    return destination;
}

/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content) {
    const m = new LXMessage();
    m.sourceHash = lxmfHash(from);
    m.destinationHash = Buffer.from(toHash);
    m.title = "";
    m.content = content;
    m.fields = new Map();
    return m.pack(from, false);
}

/** A ratchet store holding `blob` (Destination.packRatchets), as OwnRatchets' holds it in localStorage. */
function storeOf(blob = null) {
    return { load: () => blob, save: (next) => { blob = Buffer.from(next); return true; } };
}

/** Resolves once `done()` holds, looking every millisecond; rejects after `ms`. */
function until(done, ms = 20_000) {
    const end = Date.now() + ms;
    return new Promise((resolve, reject) => {
        const check = () => (done() ? resolve() : Date.now() > end ? reject(new Error(`not done in ${ms} ms`)) : setTimeout(check, 1));
        check();
    });
}

test("PeerRatchets keeps a contact's ratchet and one encrypted to, not every announcer's; every one is used while the page runs; written only on a change; a kept destination's new ratchet replaces it", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const page = storage();
    const contacts = new Set();
    const { PeerRatchets } = stores(page, contacts);
    Identity.ratchetStore = PeerRatchets;
    const kept = () => page.sGet("ratchets_known_v1") ?? {};

    const stranger = Identity.create(), contact = Identity.create();
    const S = lxmfHash(stranger), C = lxmfHash(contact);
    contacts.add(hex(C));
    const [rS, rC, rS2] = [pub(Identity.generateRatchet()), pub(Identity.generateRatchet()), pub(Identity.generateRatchet())];
    Identity.rememberRatchet(S, rS);
    Identity.rememberRatchet(C, rC);
    assert.deepEqual(Object.keys(kept()), [hex(C)], "the contact's is kept, the stranger's announce is not");
    assert.deepEqual(kept()[hex(C)], [hex(rC), now / SECOND], "[ratchet, received]");
    assert.equal(hex(Identity.getRatchet(S)), hex(rS), "the stranger's is in memory, used while the page runs");

    Identity.fromPublicKey(stranger.getPublicKey()).encryptFor(S, Buffer.from("hello"));
    assert.deepEqual(Object.keys(kept()).sort(), [hex(C), hex(S)].sort(), "encrypted to with its ratchet: kept");
    const writes = page.writes();
    Identity.fromPublicKey(stranger.getPublicKey()).encryptFor(S, Buffer.from("again"));
    Identity.rememberRatchet(C, rC);
    assert.equal(page.writes(), writes, "nothing changed, nothing written");

    now += 60 * SECOND;
    Identity.rememberRatchet(S, rS2);
    assert.deepEqual(kept()[hex(S)], [hex(rS2), now / SECOND], "a kept destination's new ratchet replaces the old one");
    fresh();
});

test("after a reload a kept ratchet is used at once, a stranger's that was only announced is not; an entry older than RATCHET_EXPIRY is dropped at load", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const page = storage();
    const contacts = new Set();
    const first = stores(page, contacts).PeerRatchets;
    Identity.ratchetStore = first;
    const C = lxmfHash(Identity.create()), S = lxmfHash(Identity.create());
    contacts.add(hex(C));
    const [rC, rS] = [pub(Identity.generateRatchet()), pub(Identity.generateRatchet())];
    Identity.rememberRatchet(C, rC);
    Identity.rememberRatchet(S, rS);

    // the next page load
    Identity.knownRatchets.clear();
    now += (Identity.RATCHET_EXPIRY - 60) * SECOND;
    Identity.ratchetStore = stores(page, contacts).PeerRatchets;
    assert.equal(hex(Identity.getRatchet(C)), hex(rC), "the contact's, from storage");
    assert.equal(Identity.getRatchet(S), null, "the stranger's was never kept: the identity key until it announces again");

    // thirty days after it was received
    Identity.knownRatchets.clear();
    now += 2 * 60 * SECOND;
    const writes = page.writes();
    Identity.ratchetStore = stores(page, contacts).PeerRatchets;
    assert.deepEqual(page.sGet("ratchets_known_v1"), {}, "dropped at load");
    assert.equal(page.writes(), writes + 1, "and the key rewritten once");
    assert.equal(Identity.getRatchet(C), null);
    fresh();
});

test("OwnRatchets keeps the delivery destination's keys as RNS's ratchet file in base64, read back on the next load; a stored value that is not one is refused and left in place", (t) => {
    fresh();
    const errors = [];
    t.mock.method(console, "error", (...a) => errors.push(a.join(" ")));
    const page = storage();
    const { OwnRatchets } = stores(page);
    const me = Identity.create();
    const own = hex(lxmfHash(me));
    const router = new LXMRouter(new Reticulum(), me, { ratchets: OwnRatchets.store(own) });
    router.announce();
    const stored = page.localStorage.getItem(`retichat_ratchets_${own}`);
    const blob = Buffer.from(JSON.parse(stored), "base64");
    assert.deepEqual(Destination.unpackRatchets(me, blob).map(hex), router.destination.ratchets.map(hex));
    assert.equal(hex(blob), hex(Destination.packRatchets(me, router.destination.ratchets)), "byte for byte the file RNS writes");
    const next = new LXMRouter(new Reticulum(), me, { ratchets: OwnRatchets.store(own) });
    assert.deepEqual(next.destination.ratchets.map(hex), router.destination.ratchets.map(hex), "the next load reads them");

    for (const [why, value] of [
        ["not JSON", "{not json"],
        ["not a string", JSON.stringify({ a: 1 })],
        ["another identity's file", JSON.stringify(Destination.packRatchets(Identity.create(), [Identity.generateRatchet()]).toString("base64"))],
    ]) {
        errors.length = 0;
        page.localStorage.setItem(`retichat_ratchets_${own}`, value);
        const refused = new LXMRouter(new Reticulum(), me, { ratchets: OwnRatchets.store(own) });
        assert.equal(refused.destination.ratchets, null, `${why}: refused`);
        assert.equal(page.localStorage.getItem(`retichat_ratchets_${own}`), value, `${why}: left in place`);
        assert.match(errors.join("\n"), /could not be loaded/, `${why}: said`);
    }
});

test("forgetting the identity, or replacing it with another, removes its stored ratchets and the kept peer ratchets; importing the same identity again does not", () => {
    fresh();
    const page = storage();
    const { PeerRatchets, OwnRatchets, IdMgr } = stores(page);
    const peer = "ab".repeat(16);
    const own = (identity) => `retichat_ratchets_${hex(lxmfHash(identity))}`;
    const fill = (identity) => {
        new LXMRouter(new Reticulum(), identity, { ratchets: OwnRatchets.store(hex(lxmfHash(identity))) }).announce();
        PeerRatchets.encryptedTo(peer, { ratchet: Buffer.alloc(32, 1), received: Date.now() / 1000 });
        assert.ok(page.localStorage.getItem(own(identity)));
        assert.ok(page.localStorage.getItem("retichat_ratchets_known_v1"));
    };

    const me = IdMgr.create();
    fill(me);
    IdMgr.importHex(IdMgr.privKey);
    assert.ok(page.localStorage.getItem(own(me)), "the same identity again: its ratchets stay");
    assert.ok(PeerRatchets.load(peer));

    IdMgr.forget();
    assert.equal(page.localStorage.getItem(own(me)), null, "forgotten: its ratchets go");
    assert.equal(page.localStorage.getItem("retichat_ratchets_known_v1"), null, "and the kept peer ratchets");
    assert.equal(PeerRatchets.load(peer), null, "from memory too, so nothing writes them back");

    const second = IdMgr.create();
    fill(second);
    const third = IdMgr.importHex(Identity.create().getPrivateKey().toString("hex"));
    assert.notEqual(hex(third.hash), hex(second.hash));
    assert.equal(page.localStorage.getItem(own(second)), null, "replaced by another identity: the old one's ratchets go");
    assert.equal(page.localStorage.getItem("retichat_ratchets_known_v1"), null);
});

test("_buildPropagationPacked encrypts a propagated message to the recipient's ratchet, and keeps that ratchet", async () => {
    fresh();
    const page = storage();
    const { PeerRatchets } = stores(page);
    Identity.ratchetStore = PeerRatchets;
    const sender = Identity.create(), peer = Identity.create();
    const peerDelivery = announcedPeer(peer);
    const build = compile("async _buildPropagationPacked(lxmfPacked, peerPublicKeyHex, sealed = null, syncSig = null)", {
        Identity, Buffer, MsgPack, Harness: { error() {} }, console: quiet, syncClaimFor, buildSealedUpload,
    })({ _computePropagationStamp: async () => Buffer.alloc(32, 0x5a) });
    const packed = lxm(sender, peerDelivery.hash, "propagated, to the ratchet");
    const upload = MsgPack.unpack(await build(packed, hex(peer.getPublicKey())));
    const lxmfData = Buffer.from(upload[1][0]);
    assert.equal(hex(lxmfData.subarray(0, 16)), hex(peerDelivery.hash));
    const ciphertext = lxmfData.subarray(16, lxmfData.length - 32);
    assert.throws(() => peer.decrypt(ciphertext), "not to the identity key");
    assert.equal(hex(peerDelivery.decrypt(ciphertext)), hex(packed.subarray(16)), "to the ratchet the recipient announced");
    assert.deepEqual(Object.keys(page.sGet("ratchets_known_v1")), [hex(peerDelivery.hash)], "encrypted to: kept across a reload");
    fresh();
});

test("_ingestPropagatedBlob decrypts a propagated message encrypted to this page's ratchet (a /get result or an rfed.link push), and says which key", async (t) => {
    fresh();
    const lines = [];
    t.mock.method(console, "log", (...a) => lines.push(a.join(" ")));
    const me = Identity.create(), sender = Identity.create();
    const router = new LXMRouter(new Reticulum(), me, { ratchets: Destination.memoryRatchetStore() });
    router.announce();
    const ratchet = router.destination.ratchets[0];
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const self = installPropagated({ _lxmfRouter: router }, { Link, Buffer, LXMessage, MsgPack, console: quiet });
    const recipient = Identity.fromPublicKey(me.getPublicKey());
    const blob = (content, to) => {
        const packed = lxm(sender, router.destination.hash, content);
        return Buffer.concat([packed.subarray(0, 16), recipient.encrypt(packed.subarray(16), to)]);
    };
    const own = hex(router.destination.hash).slice(0, 8);

    const toRatchet = blob("to my ratchet", pub(ratchet));
    assert.throws(() => me.decrypt(toRatchet.subarray(16)), "the identity key alone cannot open it");
    assert.deepEqual(self._ingestPropagatedBlob(toRatchet, "test"), { kept: true, unread: null });
    assert.ok(lines.includes(`[RATCHET] decrypt dest=${own} key=${hex(Identity.ratchetId(pub(ratchet)))}`));

    assert.deepEqual(self._ingestPropagatedBlob(blob("to my identity key", null), "test"), { kept: true, unread: null });
    assert.ok(lines.includes(`[RATCHET] decrypt dest=${own} key=identity`));

    assert.deepEqual(await self._ingestPropagatedBlob(blob("to a ratchet not held", pub(Identity.generateRatchet())), "test"), { kept: false, unread: "decrypt failed" });
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.deepEqual(emitted, ["to my ratchet", "to my identity key"]);
});

test("the distro announce carries no ratchet: flag bit 0 unset, nothing between the random hash and the signature", async () => {
    fresh();
    const distro = Identity.create();
    const distroHash = lxmfHash(distro);
    // even with a ratchet remembered for the distro's address and this page's own lxmf.delivery announcing one
    Identity.rememberRatchet(distroHash, pub(Identity.generateRatchet()));
    new LXMRouter(new Reticulum(), Identity.create(), { ratchets: Destination.memoryRatchetStore() }).announce();
    const payloads = [];
    const publish = compile("async _publishDistroAnnounce()", {
        DistroManager: { has: true, identity: distro, hash: hex(distro.hash) },
        Destination, Packet, MsgPack, Buffer, LXMF, OwnNames: { announce: null }, console: quiet,
    })({ _rns: {}, _rfedRequest: async (aspects, path, payload) => { payloads.push(payload); return true; } });
    assert.equal(await publish(), true);
    const [value] = MsgPack.unpack(payloads[0]);
    assert.equal(value[0], 0x00, "flag bit 0 = 0: no ratchet");
    const appData = MsgPack.pack([null, null, [LXMF.SF_RFED_DISTRO]]);
    const announceData = Buffer.from(value).subarray(1);
    assert.equal(announceData.length, 64 + 10 + 10 + 64 + appData.length);
    const packet = new Packet();
    packet.packetType = Packet.ANNOUNCE;
    packet.contextFlag = Packet.FLAG_UNSET;
    packet.destinationHash = distroHash;
    packet.data = announceData;
    const announce = Announce.fromPacket(packet);
    assert.ok(announce, "validates as an announce without a ratchet");
    assert.equal(announce.ratchet, null);
    fresh();
});

test("app.js: the router gets OwnRatchets' store for this identity's lxmf.delivery; nothing else enables ratchets; the propagated paths go through the ratchet-aware calls", () => {
    assert.match(methodBody("async connect()"), /new LXMRouter\(this\._rns, IdMgr\.id, \{ filter: PrivacyFilter, tickets: OutboundTickets, ratchets: OwnRatchets\.store\(ownLxmfDestinationHash\(\)\) \}\)/);
    assert.doesNotMatch(app, /\.enableRatchets\(/, "only LXMRouter enables ratchets, on lxmf.delivery");
    assert.match(app, /\nIdentity\.ratchetStore = PeerRatchets;\n/);
    assert.match(methodBody("_ingestPropagatedBlob(lxmfData, label)"), /this\._lxmfRouter\.decryptPropagated\(lxmfData\.slice\(16\)\)/);
    assert.match(methodBody("async _buildPropagationPacked(lxmfPacked, peerPublicKeyHex, sealed = null, syncSig = null)"), /peerIdentity\.encryptFor\(destHash, rest\)/);
});

test("a propagated message to an older ratchet is taken once the older ratchets were tried: _ingestPropagatedBlob gives a promise of it, /get purges it as read, and an rfed.link push is answered held only then", async (t) => {
    fresh();
    const lines = [];
    t.mock.method(console, "log", (...a) => lines.push(a.join(" ")));
    const me = Identity.create(), sender = Identity.create();
    const keys = Array.from({ length: 3 * Destination.RATCHETS_PER_TASK }, () => Identity.generateRatchet());
    const router = new LXMRouter(new Reticulum(), me, { ratchets: storeOf(Destination.packRatchets(me, keys)) });
    const older = pub(keys[2 * Destination.RATCHETS_PER_TASK]);   // in the second slice of the older ones
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const recipient = Identity.fromPublicKey(me.getPublicKey());
    const blob = (content) => {
        const packed = lxm(sender, router.destination.hash, content);
        return Buffer.concat([packed.subarray(0, 16), recipient.encrypt(packed.subarray(16), older)]);
    };
    const logs = [];
    const log = { log: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")), error() {} };
    const listed = hex(Buffer.alloc(32, 1));
    const node = new Map([[listed, blob("fetched")]]);
    const purged = [];
    const self = installPropagated({
        _lxmfRouter: router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) { purged.push(...haves.map(hex)); return true; }
            if (wants) return [node.get(hex(wants[0]))];
            return [...node.keys()].map((k) => Buffer.from(k, "hex"));
        },
    }, { Link, Buffer, LXMessage, MsgPack, console: log });
    const RFED_LINK_PUSH_HASHES = constValue("RFED_LINK_PUSH_HASHES", {
        Cryptography, Buffer,
        RFED_LINK_PUSH_DELIVERY: constValue("RFED_LINK_PUSH_DELIVERY"),
        RFED_LINK_PUSH_LXMF: constValue("RFED_LINK_PUSH_LXMF"),
        RFED_LINK_PUSH_NOTIFY: constValue("RFED_LINK_PUSH_NOTIFY"),
    });
    install(self, { RFED_LINK_PUSH_HASHES, DistroManager: { has: false }, Harness: { event() {} }, Buffer, console: log }, ["_onRfedLinkPush(link, requestId, pathHash, data)"]);

    const taken = self._ingestPropagatedBlob(blob("ingested"), "test");
    assert.ok(taken instanceof Promise, "the older ratchets are tried later");
    assert.deepEqual(await taken, { kept: true, unread: null });
    assert.ok(lines.includes(`[RATCHET] decrypt dest=${hex(router.destination.hash).slice(0, 8)} key=${hex(Identity.ratchetId(older))}`), "with the ratchet that opened it");

    await self._fetchPropagatedMessages();
    assert.deepEqual(purged, [listed], "purged");
    assert.deepEqual(logs.filter((l) => l.includes("purged unread")), [], "as read, not unread");

    const responses = [];
    const link = { sendResponse: (requestId, held) => responses.push([hex(requestId), held]) };
    self._onRfedLinkPush(link, Buffer.from("01", "hex"), Buffer.from(RFED_LINK_PUSH_HASHES.lxmf, "hex"), blob("pushed"));
    assert.deepEqual(responses, [], "not answered before the older ratchets were tried");
    await until(() => responses.length > 0);
    assert.deepEqual(responses, [["01", true]], "held");

    await until(() => emitted.length === 3);
    assert.deepEqual(emitted, ["ingested", "fetched", "pushed"]);
    fresh();
});

test("a peer that announced before ContactStore had a row for it (a DM's sender, a group member) has its ratchet kept once the row is made: after a reload it is used at once", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const page = storage();
    /** The page's PeerRatchets and ContactStore over `page`, each over the other as in app.js. */
    const load = () => {
        let ContactStore = null;
        const PeerRatchets = build("PeerRatchets", {
            sGet: page.sGet, sSet: page.sSet, localStorage: page.localStorage, PFX: page.PFX,
            Identity, Buffer, ContactStore: { known: (h) => ContactStore.known(h) },
        });
        ContactStore = build("ContactStore", {
            sGet: page.sGet, sSet: page.sSet, LXMF, Date,
            migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
            cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt, PeerRatchets,
        });
        ContactStore.init();
        PeerRatchets.init();
        Identity.ratchetStore = PeerRatchets;
        return ContactStore;
    };
    const ContactStore = load();
    const kept = () => page.sGet("ratchets_known_v1") ?? {};
    const sender = lxmfHash(Identity.create()), member = lxmfHash(Identity.create());
    const [rSender, rMember] = [pub(Identity.generateRatchet()), pub(Identity.generateRatchet())];
    const announced = now / SECOND;
    Identity.rememberRatchet(sender, rSender);
    Identity.rememberRatchet(member, rMember);
    assert.deepEqual(kept(), {}, "strangers when they announced: in memory only");

    now += 60 * SECOND;
    ContactStore.keep(hex(sender));   // its DM arrived: a hidden row
    ContactStore.allowHeldGroupMembers([{ groupStatus: "active", members: new Map([[hex(member), {}]]) }]);
    assert.deepEqual(kept(), { [hex(sender)]: [hex(rSender), announced], [hex(member)]: [hex(rMember), announced] },
        "kept once each has a row, with the time it was announced");

    // the next page load
    Identity.knownRatchets.clear();
    load();
    assert.equal(hex(Identity.getRatchet(sender)), hex(rSender), "used at once, before it announces again");
    assert.equal(hex(Identity.getRatchet(member)), hex(rMember));
    fresh();
});

test("at load the page reads the kept ratchets and gives Identity its store (the top-level PeerRatchets block, run as the page runs it): a kept ratchet is used with nothing else called", (t) => {
    fresh();
    const now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const page = storage();
    const contact = lxmfHash(Identity.create());
    const ratchet = pub(Identity.generateRatchet());
    page.sSet("ratchets_known_v1", { [hex(contact)]: [hex(ratchet), now / SECOND - 60] });
    const first = "\nconst PeerRatchets = {", last = "\nIdentity.ratchetStore = PeerRatchets;\n";
    const start = app.indexOf(first), end = app.indexOf(last, start);
    assert.ok(start !== -1 && end !== -1, "the block is in app.js");
    const env = { sGet: page.sGet, sSet: page.sSet, localStorage: page.localStorage, PFX: page.PFX, Identity, Buffer, ContactStore: { known: () => false } };
    const PeerRatchets = new Function(...Object.keys(env), `${app.slice(start, end + last.length)}\nreturn PeerRatchets;`)(...Object.values(env));
    assert.equal(Identity.ratchetStore, PeerRatchets, "Identity's store");
    assert.equal(hex(Identity.getRatchet(contact)), hex(ratchet), "the kept ratchet, read at load");
    fresh();
});

test("app.js over a lib older than ratchets (cached, or restored by a rollback): a router with no decryptPropagated reads a propagated message with the identity key, an Identity with no encryptFor encrypts to the identity key, and PeerRatchets leaves the kept ratchets unwritten", async () => {
    fresh();
    const me = Identity.create(), sender = Identity.create();

    const router = new LXMRouter(new Reticulum(), me);
    router.decryptPropagated = undefined;   // the older router's
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const self = installPropagated({ _lxmfRouter: router }, { Link, Buffer, LXMessage, MsgPack, IdMgr: { id: me }, console: quiet });
    const packed = lxm(sender, router.destination.hash, "to the identity key");
    const lxmfData = Buffer.concat([packed.subarray(0, 16), Identity.fromPublicKey(me.getPublicKey()).encrypt(packed.subarray(16))]);
    assert.deepEqual(self._ingestPropagatedBlob(lxmfData, "test"), { kept: true, unread: null });
    await until(() => emitted.length === 1);
    assert.deepEqual(emitted, ["to the identity key"]);

    const peer = Identity.create();
    const OlderIdentity = { fromPublicKey: (key) => { const identity = Identity.fromPublicKey(key); return { encrypt: (data) => identity.encrypt(data) }; } };
    const upload = compile("async _buildPropagationPacked(lxmfPacked, peerPublicKeyHex, sealed = null, syncSig = null)", {
        Identity: OlderIdentity, Buffer, MsgPack, Harness: { error() {} }, console: quiet, syncClaimFor, buildSealedUpload,
    })({ _computePropagationStamp: async () => Buffer.alloc(32, 0x5a) });
    const toPeer = lxm(sender, lxmfHash(peer), "uploaded");
    const sent = Buffer.from(MsgPack.unpack(await upload(toPeer, hex(peer.getPublicKey())))[1][0]);
    assert.equal(hex(peer.decrypt(sent.subarray(16, sent.length - 32))), hex(toPeer.subarray(16)), "to the identity key");

    const page = storage();
    const stored = { ["ab".repeat(16)]: ["cd".repeat(32), 1_800_000_000] };
    page.sSet("ratchets_known_v1", stored);
    const writes = page.writes();
    build("PeerRatchets", {
        sGet: page.sGet, sSet: page.sSet, localStorage: page.localStorage, PFX: page.PFX,
        Identity: {}, Buffer, ContactStore: { known: () => false },   // the older Identity: no RATCHET_EXPIRY
    }).init();
    assert.equal(page.writes(), writes, "nothing written");
    assert.deepEqual(page.sGet("ratchets_known_v1"), stored, "left as it was");
    fresh();
});

test("the key backup says what it does not bring back: what senders sealed to this browser's ratchets before a restore elsewhere (James, 2026-10-17)", () => {
    const body = methodBody("_buildDeviceIdentitySection()");
    const shown = body.slice(body.indexOf("if (this.state.revealDeviceKey) {"));
    assert.match(shown, /"A restored key opens new messages\. Messages sent to you before you restore it may not open\."/);
    assert.ok(shown.indexOf("A restored key") < shown.indexOf("\"secret-value\""), "with the warning, above the key itself");
});
