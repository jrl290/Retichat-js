/**
 * RATCHETS — RNS 1.5.2 Identity and Destination, LXMF 1.1.1 LXMRouter and
 * LXMessage.
 *
 * The web's own lxmf.delivery has ratchets, as LXMF enables them on every
 * delivery destination it registers (LXMRouter.py register_delivery_identity):
 * the first announce after a load rotates, later ones every
 * RATCHET_INTERVAL; the newest 512 keys are kept in RNS's ratchet file
 * format, signed, and a file that is corrupt or signed by another identity
 * is refused, never replaced; the announce carries the newest public key,
 * signed, with the context flag. What peers encrypt to any of the keys, or
 * to the identity key, is decrypted, and a key the destination does not
 * hold is not.
 *
 * A peer's ratchet is remembered from its announce once the announce
 * validated, and every LXMF path encrypts to it: the opportunistic packet
 * (Destination.encrypt), the paper message (LXMessage.toLxmUri) and the
 * propagated one (app.js _buildPropagationPacked, in ratchets_app.test.mjs),
 * as LXMessage.py pack does with dest.encrypt.
 *
 * The app.js side (where the keys are stored, the propagated paths, forget,
 * which peers' ratchets outlive the page) is ratchets_app.test.mjs.
 *
 * Run: node --test ratchets.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Fernet from "./lib/rns/fernet.js";
import Packet from "./lib/rns/packet.js";
import Announce from "./lib/rns/announce.js";
import Constants from "./lib/rns/constants.js";
import MsgPack from "./lib/rns/msgpack.js";
import { Reticulum } from "./lib/rns/reticulum.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import { clean } from "./lib/display_name.js";
import { settle } from "./test_link_pair.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const pub = (ratchet) => Identity.ratchetPublicBytes(ratchet);
const idOf = (ratchet) => hex(Identity.ratchetId(pub(ratchet)));
const SECOND = 1000;
const APP_DATA = MsgPack.pack([null, null, []]);
/** Where an announce's data starts in a HEADER_1 packet: flags, hops, destination, context. */
const DATA_START = 2 + 16 + 1;
/** Where the ratchet sits in the announce data: public key, name hash, random hash. */
const RATCHET_START = 64 + 10 + 10;

/** Nothing remembered from another test, nothing persisted. */
function fresh() {
    Identity.knownRatchets.clear();
    Identity.ratchetStore = null;
}

/** A ratchet store that counts its loads and saves; `blob` is what it holds. */
function countingStore(blob = null) {
    const store = {
        blob, loads: 0, saves: 0,
        load: () => { store.loads++; return store.blob; },
        save: (next) => { store.saves++; store.blob = Buffer.from(next); return true; },
    };
    return store;
}

/** `identity`'s lxmf.delivery, inbound, with ratchets on `store`; `sent`
 *  holds the raw packets its announces send. */
function delivery(identity, store = Destination.memoryRatchetStore()) {
    const sent = [];
    const destination = new Destination({ sendData: (raw) => sent.push(Buffer.from(raw)) }, identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");
    destination.enableRatchets(store);
    return { destination, sent, store };
}

/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content) {
    const m = new LXMessage();
    m.sourceHash = Destination.hash(from, "lxmf", "delivery");
    m.destinationHash = Buffer.from(toHash);
    m.title = "";
    m.content = content;
    m.fields = new Map();
    return m.pack(from, false);
}

test("own ratchets: none stored starts an empty list, stored at once; the first announce rotates, the next only after RATCHET_INTERVAL; a reload keeps the keys and rotates again", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const me = Identity.create();
    const store = countingStore();
    const { destination } = delivery(me, store);
    assert.deepEqual(destination.ratchets, [], "an empty list");
    assert.equal(store.saves, 1, "stored at once, as RNS writes a new, empty ratchet file");
    assert.deepEqual(Destination.unpackRatchets(me, store.blob), []);

    destination.announce(APP_DATA);
    assert.equal(destination.ratchets.length, 1, "the first announce after a load rotates");
    const first = destination.ratchets[0];
    assert.equal(store.saves, 2, "and stores the new key before the announce carries it");

    now += (Destination.RATCHET_INTERVAL - 1) * SECOND;
    destination.announce(APP_DATA);
    assert.equal(destination.ratchets.length, 1, "not again before RATCHET_INTERVAL (30 min)");
    now += 2 * SECOND;
    destination.announce(APP_DATA);
    assert.equal(destination.ratchets.length, 2, "rotated once the interval passed");
    assert.ok(destination.ratchets[1].equals(first), "newest first");
    assert.deepEqual(Destination.unpackRatchets(me, store.blob).map(hex), destination.ratchets.map(hex), "stored");

    const reloaded = delivery(me, store).destination;
    assert.deepEqual(reloaded.ratchets.map(hex), destination.ratchets.map(hex), "the next page load reads the same keys");
    reloaded.announce(APP_DATA);
    assert.equal(reloaded.ratchets.length, 3, "the time of the last rotation is not stored: the first announce after a load rotates (RNS)");
});

test("rotation keeps the newest RATCHET_COUNT (512) keys and stores them", () => {
    fresh();
    const me = Identity.create();
    const old = Array.from({ length: Destination.RATCHET_COUNT }, () => Identity.generateRatchet());
    const store = countingStore(Destination.packRatchets(me, old));
    const { destination } = delivery(me, store);
    assert.equal(destination.ratchets.length, 512);
    const added = Buffer.alloc(32, 0x42);
    assert.equal(destination.rotateRatchets(added), true);
    assert.equal(destination.ratchets.length, 512);
    assert.ok(destination.ratchets[0].equals(added), "the new key first");
    assert.deepEqual(destination.ratchets.slice(1).map(hex), old.slice(0, 511).map(hex), "the oldest one dropped");
    assert.deepEqual(Destination.unpackRatchets(me, store.blob).map(hex), destination.ratchets.map(hex));
});

test("a rotation storage refuses is undone: no announce carries a ratchet that is not stored", () => {
    fresh();
    const me = Identity.create();
    const kept = [Identity.generateRatchet()];
    const store = countingStore(Destination.packRatchets(me, kept));
    const { destination, sent } = delivery(me, store);
    store.save = () => false;
    destination.announce(APP_DATA);
    assert.deepEqual(destination.ratchets.map(hex), kept.map(hex), "the new key is dropped");
    assert.equal(destination.latestRatchetTime, 0, "and the next announce tries again");
    assert.equal(hex(Announce.fromPacket(Packet.fromBytes(sent.at(-1))).ratchet), hex(pub(kept[0])), "the stored key is announced");
});

test("the stored ratchets are RNS's ratchet file byte for byte; a blob signed by another identity, or corrupt, is refused and left in place", (t) => {
    fresh();
    const errors = [];
    t.mock.method(console, "error", (...a) => errors.push(a.join(" ")));
    const me = Identity.create(), other = Identity.create();
    const keys = [Identity.generateRatchet(), Identity.generateRatchet()];
    const blob = Destination.packRatchets(me, keys);
    // umsgpack.packb({"signature": sign(packed), "ratchets": packed}), packed = umsgpack.packb([bin32, bin32])
    const packed = Buffer.from("92" + keys.map((k) => "c420" + hex(k)).join(""), "hex");
    assert.equal(hex(blob), "82" + "a9" + hex(Buffer.from("signature")) + "c440" + hex(me.sign(packed))
        + "a8" + hex(Buffer.from("ratchets")) + "c4" + packed.length.toString(16) + hex(packed));
    assert.deepEqual(Destination.unpackRatchets(me, blob).map(hex), keys.map(hex));

    for (const [why, stored] of [
        ["signed by another identity", Destination.packRatchets(other, keys)],
        ["cut short", blob.subarray(0, blob.length - 5)],
        ["not msgpack", Buffer.from("not a ratchet file")],
        ["a key of 31 bytes", Destination.packRatchets(me, [Buffer.alloc(31, 1)])],
    ]) {
        errors.length = 0;
        const store = countingStore(Buffer.from(stored));
        const { destination, sent } = delivery(me, store);
        assert.equal(destination.ratchets, null, `${why}: refused, so no ratchets`);
        assert.equal(store.saves, 0, `${why}: never replaced`);
        assert.ok(store.blob.equals(Buffer.from(stored)), `${why}: left in storage`);
        assert.match(errors.join("\n"), /could not be loaded/, `${why}: said`);
        destination.announce(APP_DATA);
        assert.equal(Packet.fromBytes(sent.at(-1)).contextFlag, Packet.FLAG_UNSET, `${why}: its announce carries no ratchet`);
    }
});

test("the announce carries the newest ratchet, signed, with the context flag; the web's own Announce parser validates it; the destination's own ratchet is remembered", () => {
    fresh();
    const me = Identity.create();
    const { destination, sent } = delivery(me);
    destination.announce(APP_DATA);
    const raw = sent.at(-1);
    const packet = Packet.fromBytes(raw);
    assert.equal(packet.contextFlag, Packet.FLAG_SET);
    const announce = Announce.fromPacket(packet);
    assert.ok(announce, "validates");
    assert.equal(hex(announce.ratchet), hex(pub(destination.ratchets[0])));
    assert.equal(hex(announce.appData), hex(APP_DATA));
    assert.equal(hex(Identity.getRatchet(destination.hash)), hex(announce.ratchet), "its own ratchet is remembered too (RNS Destination.announce)");

    const altered = Buffer.from(raw);
    altered[DATA_START + RATCHET_START] ^= 0x01;
    assert.equal(Announce.fromPacket(Packet.fromBytes(altered)), null, "the ratchet is signed: altered, the announce is invalid");
});

test("buildAnnounceData's seams (random hash, new ratchet) make the announce the same bytes every time", () => {
    fresh();
    const me = Identity.fromPrivateKey(Buffer.alloc(64, 3));
    const randomHash = Buffer.from("00112233445566778899", "hex");
    const newRatchet = Buffer.alloc(32, 9);
    const build = () => delivery(me).destination.buildAnnounceData(APP_DATA, { randomHash, newRatchet });
    const a = build(), b = build();
    assert.equal(hex(a.announceData), hex(b.announceData));
    assert.equal(a.contextFlag, Packet.FLAG_SET);
    assert.equal(hex(a.announceData.subarray(64 + 10, RATCHET_START)), hex(randomHash));
    assert.equal(hex(a.announceData.subarray(RATCHET_START, RATCHET_START + 32)), hex(pub(newRatchet)));
});

test("with the longest Announce Display Name the web can set, the ratchet announce still fits the MTU in transport (HEADER_2)", () => {
    fresh();
    const name = clean("\u{1F600}".repeat(100));
    assert.equal(Buffer.byteLength(name, "utf8"), 256, "64 scalars of 4 bytes, the cap (DISPLAY_NAMES.md §3 rule 5)");
    const me = Identity.create();
    const { destination, sent } = delivery(me);
    const router = new LXMRouter({ registerDestination: () => destination }, me);
    router.setAnnounceName(name);
    router.announce();
    const raw = sent.at(-1);
    assert.equal(Packet.fromBytes(raw).contextFlag, Packet.FLAG_SET, "with the ratchet");
    const data = raw.length - DATA_START;
    assert.equal(data, 64 + 10 + 10 + 32 + 64 + 262, "keys, name hash, random hash, ratchet, signature, app_data");
    assert.ok(data <= Constants.PACKET_MDU, `${data} bytes of announce data, at most ${Constants.PACKET_MDU}`);
    assert.ok(raw.length + 16 <= Constants.MTU, `${raw.length + 16} bytes with a transport id, at most ${Constants.MTU}`);
});

test("a peer's ratchet is remembered from its validated announce (never a forged one), and Destination.encrypt encrypts to it: the identity key cannot open it, the ratchet can", (t) => {
    fresh();
    const lines = [];
    t.mock.method(console, "log", (...a) => lines.push(a.join(" ")));
    const peer = Identity.create();
    const { destination: peerDelivery, sent } = delivery(peer);
    peerDelivery.announce(APP_DATA);
    Identity.knownRatchets.clear(); // what the peer remembered of itself is not what this page heard

    const rns = new Reticulum();
    const iface = { name: "test", hash: Buffer.alloc(16) };
    const forged = Buffer.from(sent.at(-1));
    forged[DATA_START + RATCHET_START] ^= 0x01;
    rns.onPacketReceived(Packet.fromBytes(forged), iface);
    assert.equal(Identity.getRatchet(peerDelivery.hash), null, "a forged announce's ratchet is never remembered");
    rns.onPacketReceived(Packet.fromBytes(sent.at(-1)), iface);
    const ratchet = Identity.getRatchet(peerDelivery.hash);
    assert.equal(hex(ratchet), hex(pub(peerDelivery.ratchets[0])), "remembered once the announce validated");

    const out = rns.registerDestination(Identity.fromPublicKey(peer.getPublicKey()), Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
    const plaintext = Buffer.from("to the ratchet");
    const ciphertext = out.encrypt(plaintext);
    assert.equal(hex(out.latestRatchetId), idOf(peerDelivery.ratchets[0]));
    assert.ok(lines.includes(`[RATCHET] encrypt dest=${hex(out.hash).slice(0, 8)} key=${idOf(peerDelivery.ratchets[0])}`));
    assert.throws(() => peer.decrypt(ciphertext), "the identity key does not open it");
    assert.equal(hex(peer.decrypt(ciphertext, [peerDelivery.ratchets[0]], true)), hex(plaintext), "the ratchet key does");
    assert.equal(hex(peerDelivery.decrypt(ciphertext)), hex(plaintext), "and so does the peer's delivery destination");
    assert.equal(hex(peerDelivery.latestRatchetId), idOf(peerDelivery.ratchets[0]));

    const unknown = rns.registerDestination(Identity.create(), Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
    unknown.encrypt(plaintext);
    assert.ok(lines.includes(`[RATCHET] encrypt dest=${hex(unknown.hash).slice(0, 8)} key=identity`), "no ratchet known: the identity key");
});

test("a newer ratchet replaces the one remembered; one received more than RATCHET_EXPIRY ago is not loaded from the store", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const dest = Buffer.alloc(16, 1);
    const [a, b] = [pub(Identity.generateRatchet()), pub(Identity.generateRatchet())];
    Identity.rememberRatchet(dest, a);
    Identity.rememberRatchet(dest, b);
    assert.equal(hex(Identity.getRatchet(dest)), hex(b));

    const kept = new Map();
    Identity.ratchetStore = { load: (k) => kept.get(k) ?? null, remembered() {}, encryptedTo() {} };
    const old = Buffer.alloc(16, 2), recent = Buffer.alloc(16, 3);
    kept.set(hex(old), { ratchet: a, received: now / SECOND - Identity.RATCHET_EXPIRY - 1 });
    kept.set(hex(recent), { ratchet: a, received: now / SECOND - Identity.RATCHET_EXPIRY + 60 });
    assert.equal(Identity.getRatchet(old), null, "expired: the identity key is used");
    assert.equal(hex(Identity.getRatchet(recent)), hex(a));
    fresh();
});

test("the paper message (LXMessage.toLxmUri) is encrypted to the recipient's ratchet, as LXMessage.py packs a PAPER message with dest.encrypt", () => {
    fresh();
    const sender = Identity.create(), peer = Identity.create();
    const { destination: peerDelivery } = delivery(peer);
    peerDelivery.announce(APP_DATA); // remembered in this process: as if heard
    const m = new LXMessage();
    m.sourceHash = Destination.hash(sender, "lxmf", "delivery");
    m.destinationHash = peerDelivery.hash;
    m.title = "";
    m.content = "on paper";
    m.fields = new Map();
    const uri = m.toLxmUri(sender, Identity.fromPublicKey(peer.getPublicKey()));
    const data = Buffer.from(uri.slice("lxm://".length).replace(/-/g, "+").replace(/_/g, "/"), "base64");
    assert.equal(hex(data.subarray(0, 16)), hex(peerDelivery.hash));
    assert.throws(() => peer.decrypt(data.subarray(16)), "not to the identity key");
    assert.ok(peerDelivery.decrypt(data.subarray(16)), "to the ratchet");
});

test("decrypt opens a ciphertext to the newest ratchet, to the identity key and to an older ratchet, and refuses one to a ratchet it does not hold; latestRatchetId says which key", () => {
    fresh();
    const me = Identity.create();
    const keys = [Identity.generateRatchet(), Identity.generateRatchet(), Identity.generateRatchet()];
    const { destination } = delivery(me, countingStore(Destination.packRatchets(me, keys)));
    const sender = Identity.fromPublicKey(me.getPublicKey());
    const plaintext = Buffer.from("hello");
    for (const [why, ratchet] of [["the newest ratchet", keys[0]], ["the identity key", null], ["an older ratchet", keys[2]]]) {
        destination.latestRatchetId = Buffer.alloc(10);
        assert.equal(hex(destination.decrypt(sender.encrypt(plaintext, ratchet ? pub(ratchet) : null))), hex(plaintext), why);
        assert.equal(destination.latestRatchetId === null ? null : hex(destination.latestRatchetId), ratchet ? idOf(ratchet) : null, why);
    }
    assert.equal(destination.decrypt(sender.encrypt(plaintext, pub(Identity.generateRatchet()))), null, "a ratchet it does not hold");
    assert.equal(destination.latestRatchetId, null);
    assert.equal(destination.decrypt(Buffer.alloc(32, 1)), null, "too short to be a token");
});

test("with ratchets enforced, a ciphertext to the identity key is refused and one to a ratchet is opened (left off everywhere, as LXMF's default)", () => {
    fresh();
    const me = Identity.create();
    const keys = [Identity.generateRatchet()];
    const { destination } = delivery(me, countingStore(Destination.packRatchets(me, keys)));
    const sender = Identity.fromPublicKey(me.getPublicKey());
    const plaintext = Buffer.from("hello");
    assert.equal(destination.ratchetsEnforced, false, "off unless enforceRatchets() is called");
    const without = new Destination(null, Identity.create(), Destination.IN, Destination.SINGLE, "lxmf", "delivery");
    assert.equal(without.enforceRatchets(), false, "refused without ratchets, as RNS's enforce_ratchets() is");
    assert.equal(without.ratchetsEnforced, false);
    assert.equal(destination.enforceRatchets(), true);
    assert.equal(destination.decrypt(sender.encrypt(plaintext)), null, "the identity key is refused");
    assert.equal(hex(destination.decrypt(sender.encrypt(plaintext, pub(keys[0])))), hex(plaintext));
    assert.throws(() => me.decrypt(sender.encrypt(plaintext), keys, true), /enforcement|HMAC/);
    assert.throws(() => me.decrypt(sender.encrypt(plaintext), null, true), /enforcement/, "no ratchets at all: nothing opens");
});

test("decrypt reloads the stored ratchets once when another page stored newer ones, and does not decrypt twice when they are unchanged", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const me = Identity.create();
    const store = countingStore();
    const page = delivery(me, store).destination;
    page.announce(APP_DATA);
    const other = delivery(me, store).destination; // another page of the same identity
    other.announce(APP_DATA);                      // rotates and stores [new, old]
    assert.equal(page.ratchets.length, 1);
    assert.equal(other.ratchets.length, 2);

    const sender = Identity.fromPublicKey(me.getPublicKey());
    const plaintext = Buffer.from("to the other page's newest ratchet");
    const decrypts = t.mock.method(me, "decrypt");
    assert.equal(hex(page.decrypt(sender.encrypt(plaintext, pub(other.ratchets[0])))), hex(plaintext));
    assert.equal(decrypts.mock.callCount(), 2, "its own keys, then once more with the stored ones");
    assert.deepEqual(page.ratchets.map(hex), other.ratchets.map(hex), "the stored ratchets are now its own");

    decrypts.mock.resetCalls();
    assert.equal(page.decrypt(sender.encrypt(plaintext, pub(Identity.generateRatchet()))), null);
    assert.equal(decrypts.mock.callCount(), 1, "the stored ratchets are the ones loaded: not tried again");
});

test("LXMRouter enables ratchets on lxmf.delivery with the store it is given, and only there: rfed.delivery has none, nor a router given no store (an app.js older than ratchets)", () => {
    fresh();
    const me = Identity.create();
    const keys = [Identity.generateRatchet()];
    const store = countingStore(Destination.packRatchets(me, keys));
    const rns = new Reticulum();
    const router = new LXMRouter(rns, me, { ratchets: store });
    assert.deepEqual(router.destination.ratchets.map(hex), keys.map(hex), "loaded from the store given");
    const rfedDelivery = rns.registerDestination(me, Destination.IN, Destination.SINGLE, "rfed", "delivery");
    assert.equal(rfedDelivery.ratchets, null);
    const { contextFlag, announceData } = rfedDelivery.buildAnnounceData();
    assert.equal(contextFlag, Packet.FLAG_UNSET);
    assert.equal(announceData.length, 64 + 10 + 10 + 64, "no ratchet in it");

    // An app.js from before ratchets builds the router with {filter, tickets}
    // only: its delivery destination announces no ratchet, so no peer
    // encrypts to one that page could not keep, nor decrypt when propagated.
    const old = new LXMRouter(new Reticulum(), Identity.create(), { filter: null, tickets: null });
    assert.equal(old.destination.ratchets, null, "no store given: no ratchets");
    assert.equal(old.destination.buildAnnounceData(APP_DATA).contextFlag, Packet.FLAG_UNSET, "and its announce carries none");
});

test("the delivery destination rotates at RNS's 30 minutes, as LXMF leaves it (James, 2026-10-17: parity), so at the web's 5-minute announces a ratchet is held about 12 days", (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const destination = new LXMRouter(new Reticulum(), Identity.create(), { ratchets: Destination.memoryRatchetStore() }).destination;
    assert.equal(Destination.RATCHET_INTERVAL, 30 * 60);
    assert.equal(destination.ratchetInterval, Destination.RATCHET_INTERVAL, "LXMRouter.py register_delivery_identity sets no interval");
    // RNS Destination.set_ratchet_interval, which LXMF does not call: only a
    // whole number above 0 is taken.
    const other = new LXMRouter(new Reticulum(), Identity.create(), { ratchets: Destination.memoryRatchetStore() }).destination;
    for (const bad of [0, -1, 1.5, "60", null]) assert.equal(other.setRatchetInterval(bad), false, String(bad));
    assert.equal(other.ratchetInterval, Destination.RATCHET_INTERVAL);
    assert.equal(other.setRatchetInterval(60), true);
    assert.equal(other.ratchetInterval, 60);

    // The page announcing every 5 minutes (announceIntervalMs); each
    // announce rotates when due (rotateRatchets, as buildAnnounceData calls
    // it), so every 35 minutes, at the first announce past the 30. A
    // ratchet is dropped once 512 newer ones are kept, about 12 days in,
    // although a sender that heard it last may use it for 30
    // (Identity.get_ratchet): what it sends after that is not opened here.
    const ANNOUNCE = 300;
    destination.rotateRatchets();
    const first = destination.ratchets[0];
    const start = now / SECOND;
    while (destination.ratchets.some((r) => r.equals(first))) {
        now += ANNOUNCE * SECOND;
        destination.rotateRatchets();
    }
    const days = (now / SECOND - start) / (24 * 60 * 60);
    assert.ok(days > 11 && days < 13, `dropped ${days.toFixed(1)} days in`);
});

test("an opportunistic packet encrypted to the delivery destination's ratchet is decrypted and handed on, and says which key opened it", async (t) => {
    fresh();
    const lines = [];
    t.mock.method(console, "log", (...a) => lines.push(a.join(" ")));
    const me = Identity.create(), sender = Identity.create();
    const router = new LXMRouter(new Reticulum(), me, { ratchets: Destination.memoryRatchetStore() });
    router.announce(); // its own ratchet, remembered, so the sender below encrypts to it
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const out = new Destination(null, Identity.fromPublicKey(me.getPublicKey()), Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
    const packed = lxm(sender, router.destination.hash, "opportunistic, to the ratchet");
    const ciphertext = out.encrypt(packed.subarray(16));
    assert.throws(() => me.decrypt(ciphertext), "not to the identity key");
    let proved = 0;
    router.destination.onPacket({ packetType: Packet.DATA, data: ciphertext, prove: () => proved++ });
    await settle();
    assert.deepEqual(emitted, ["opportunistic, to the ratchet"]);
    assert.equal(proved, 1);
    assert.ok(lines.includes(`[RATCHET] decrypt dest=${hex(router.destination.hash).slice(0, 8)} key=${idOf(router.destination.ratchets[0])}`));
    assert.ok(lines.some((l) => l.startsWith(`[RATCHET] announce dest=${hex(router.destination.hash).slice(0, 8)} ratchet=${idOf(router.destination.ratchets[0])} count=1`)));
});

/**
 * Records each Identity.decrypt `identity` makes (the keys it was given) and
 * the turn of the event loop it ran in: `turn` counts setImmediate
 * callbacks, one in every turn, so two decrypts with different turns had
 * other tasks run between them.
 */
function decryptTrace(t, identity) {
    const calls = [];
    let turn = 0, spinning = true;
    const spin = () => { turn++; if (spinning) setImmediate(spin); };
    setImmediate(spin);
    const stop = () => { spinning = false; };
    t.after(stop);
    const decrypt = identity.decrypt.bind(identity);
    t.mock.method(identity, "decrypt", (data, ratchets, enforce, receiver) => {
        calls.push({ turn, ratchets: ratchets ? ratchets.map(hex) : null, identityKey: !enforce });
        return decrypt(data, ratchets, enforce, receiver);
    });
    return { calls, stop };
}

test("decryptSoon decides the newest ratchet and the identity key at once; the older ratchets are tried RATCHETS_PER_TASK at a time, the page running between two slices; it accepts what decrypt() accepts", async (t) => {
    fresh();
    const me = Identity.create();
    const keys = Array.from({ length: Destination.RATCHET_COUNT }, () => Identity.generateRatchet());
    const { destination } = delivery(me, countingStore(Destination.packRatchets(me, keys)));
    const sender = Identity.fromPublicKey(me.getPublicKey());
    const plaintext = Buffer.from("hello");
    const to = (ratchet) => sender.encrypt(plaintext, ratchet ? pub(ratchet) : null);

    for (const [why, ratchet] of [["the newest ratchet", keys[0]], ["the identity key", null]]) {
        const got = destination.decryptSoon(to(ratchet));
        assert.ok(Buffer.isBuffer(got), `${why}: at once, not a promise`);
        assert.equal(hex(got), hex(plaintext), why);
        assert.equal(destination.latestRatchetId === null ? null : hex(destination.latestRatchetId), ratchet ? idOf(ratchet) : null, why);
    }

    assert.ok(Destination.RATCHETS_PER_TASK >= 1 && Destination.RATCHETS_PER_TASK <= 32, "a slice is a few tens of key exchanges at most, never the whole scan");
    const trace = decryptTrace(t, me);
    const older = destination.decryptSoon(to(keys[300]));
    assert.ok(older instanceof Promise, "an older ratchet: later");
    assert.equal(trace.calls.length, 1, "at once, only the first two keys");
    assert.deepEqual(trace.calls[0].ratchets, [hex(keys[0])]);
    assert.equal(trace.calls[0].identityKey, true);
    assert.equal(hex(await older), hex(plaintext), "opened by ratchet 300");
    assert.equal(hex(destination.latestRatchetId), idOf(keys[300]));
    const slices = trace.calls.slice(1);
    assert.equal(slices.length, Math.ceil(300 / Destination.RATCHETS_PER_TASK), "a slice at a time, up to the one holding it");
    for (const [i, call] of slices.entries()) {
        assert.ok(call.ratchets.length <= Destination.RATCHETS_PER_TASK, `slice ${i}: at most ${Destination.RATCHETS_PER_TASK} keys`);
        assert.equal(call.identityKey, false, `slice ${i}: the identity key was tried already`);
        if (i > 0) assert.ok(call.turn > slices[i - 1].turn, `slice ${i}: other tasks ran since the slice before`);
    }
    assert.deepEqual(slices.flatMap((c) => c.ratchets), keys.slice(1, 1 + slices.length * Destination.RATCHETS_PER_TASK).map(hex), "in decrypt()'s order");

    trace.calls.length = 0;
    const none = destination.decryptSoon(to(Identity.generateRatchet()));
    assert.ok(none instanceof Promise);
    assert.equal(await none, null, "a ratchet it does not hold: refused, as decrypt() refuses it");
    assert.equal(trace.calls.length, 1 + Math.ceil((keys.length - 1) / Destination.RATCHETS_PER_TASK), "every ratchet once");
    assert.equal(destination.latestRatchetId, null);
    trace.stop();

    // With ratchets enforced the identity key is left out at once too.
    destination.enforceRatchets();
    assert.equal(await destination.decryptSoon(to(null)), null, "the identity key is refused");
    assert.equal(hex(await destination.decryptSoon(to(keys[20]))), hex(plaintext));
});

test("decryptSoon, when every ratchet failed and another page stored newer ones, loads them and tries once more; with the same blob it does not", async (t) => {
    fresh();
    let now = 1_800_000_000 * SECOND;
    t.mock.method(Date, "now", () => now);
    const me = Identity.create();
    const store = countingStore();
    const page = delivery(me, store).destination;
    page.announce(APP_DATA);
    now += 10 * SECOND;
    const other = delivery(me, store).destination; // another page of the same identity
    other.announce(APP_DATA);
    now += (Destination.RATCHET_INTERVAL + 1) * SECOND;
    other.announce(APP_DATA);                      // stores [newest, new, old]
    assert.equal(page.ratchets.length, 1);
    assert.equal(other.ratchets.length, 3);

    const sender = Identity.fromPublicKey(me.getPublicKey());
    const plaintext = Buffer.from("to the other page's newest ratchet");
    const got = page.decryptSoon(sender.encrypt(plaintext, pub(other.ratchets[0])));
    assert.ok(got instanceof Promise);
    assert.equal(hex(await got), hex(plaintext));
    assert.deepEqual(page.ratchets.map(hex), other.ratchets.map(hex), "the stored ratchets are now its own");

    const loads = store.loads;
    assert.equal(await page.decryptSoon(sender.encrypt(plaintext, pub(Identity.generateRatchet()))), null);
    assert.equal(store.loads, loads + 1, "the stored blob read once, the same as loaded: not tried again");
});

test("an opportunistic packet to an older ratchet is handled once the older ratchets were tried, and a packet after it is not held behind it", async (t) => {
    fresh();
    const me = Identity.create(), sender = Identity.create();
    const keys = Array.from({ length: Destination.RATCHET_COUNT }, () => Identity.generateRatchet());
    const store = countingStore(Destination.packRatchets(me, keys));
    const router = new LXMRouter(new Reticulum(), me, { ratchets: store });
    const lines = [];
    t.mock.method(console, "log", (...a) => lines.push(a.join(" ")));
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const recipient = Identity.fromPublicKey(me.getPublicKey());
    const packet = (content, ratchet) => {
        const packed = lxm(sender, router.destination.hash, content);
        let proved = 0;
        return { packetType: Packet.DATA, data: recipient.encrypt(packed.subarray(16), ratchet ? pub(ratchet) : null), prove: () => proved++, proofs: () => proved };
    };

    const old = packet("to ratchet 400", keys[400]);
    const newest = packet("to the newest ratchet", keys[0]);
    const junk = packet("to a ratchet not held", Identity.generateRatchet());
    router.destination.onPacket(old);
    router.destination.onPacket(junk);
    router.destination.onPacket(newest);
    await settle();
    assert.deepEqual(emitted, ["to the newest ratchet"], "the newest ratchet's packet at once, not behind the others");
    assert.equal(newest.proofs(), 1);
    const dest = hex(router.destination.hash).slice(0, 8);
    assert.deepEqual(lines.filter((l) => l.startsWith("[RATCHET] decrypt")), [`[RATCHET] decrypt dest=${dest} key=${idOf(keys[0])}`],
        "the key that opened it, though the older ratchets were tried for the other two since");

    const until = (done, ms = 20_000) => new Promise((resolve, reject) => {
        const end = Date.now() + ms;
        const check = () => (done() ? resolve() : Date.now() > end ? reject(new Error(`not done in ${ms} ms`)) : setTimeout(check, 1));
        check();
    });
    await until(() => emitted.length === 2 && lines.some((l) => l.includes("could not be decrypted; dropped")));
    assert.deepEqual(emitted, ["to the newest ratchet", "to ratchet 400"]);
    assert.equal(old.proofs(), 1, "proved once handled");
    assert.equal(junk.proofs(), 0, "no key opens it: dropped, unproved");
    assert.deepEqual(lines.filter((l) => l.startsWith("[RATCHET] decrypt")), [`[RATCHET] decrypt dest=${dest} key=${idOf(keys[0])}`, `[RATCHET] decrypt dest=${dest} key=${idOf(keys[400])}`],
        "with the id of the ratchet that opened it");
});

test("encrypting with no seams draws a new ephemeral key and a new IV every time (to the identity key and to a ratchet), and Fernet a new IV", () => {
    fresh();
    const to = Identity.fromPublicKey(Identity.create().getPublicKey());
    const ratchet = pub(Identity.generateRatchet());
    const plaintext = Buffer.from("the same plaintext");
    for (const [why, r] of [["the identity key", null], ["a ratchet", ratchet]]) {
        const [a, b] = [to.encrypt(plaintext, r), to.encrypt(plaintext, r)];
        assert.notEqual(hex(a.subarray(0, 32)), hex(b.subarray(0, 32)), `${why}: a new ephemeral key`);
        assert.notEqual(hex(a.subarray(32, 48)), hex(b.subarray(32, 48)), `${why}: a new IV`);
    }
    const fernet = new Fernet(Buffer.alloc(64, 1));
    assert.notEqual(hex(fernet.encrypt(plaintext).subarray(0, 16)), hex(fernet.encrypt(plaintext).subarray(0, 16)), "Fernet: a new IV");
});
