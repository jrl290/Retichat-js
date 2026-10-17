/**
 * REGRESSION GUARD — the web's ratchets are RNS 1.5.2's, byte for byte.
 *
 * ratchet_vectors.json is made by tools/ratchet_vectors.py, which runs RNS
 * 1.5.2's and LXMF 1.1.1's own code with only their randomness and clock
 * fixed; its --check fails when the file drifted from a fresh run. The test
 * pins the file's SHA-256, so a changed file fails here before anything is
 * compared with it. Against it, the web's own code:
 *   - gives each ratchet RNS's public key and ratchet id;
 *   - reads Python's ratchet file only once its signature checks out
 *     (one bit changed, or another identity, and it is refused), and writes
 *     the same keys as the same bytes;
 *   - taken through the generator's steps on its clock and keys (enable,
 *     three rotations, the announce), stores Python's file and sends
 *     Python's announce packet; built from the same identity, random hash,
 *     ratchet and app_data, the announce data and context flag are Python's;
 *   - parses Python's announce: the ratchet is read, and signed; heard
 *     through Reticulum it is remembered, and the next Destination.encrypt
 *     to that destination is Python's ciphertext given the same ephemeral key
 *     and IV;
 *   - decrypts the four decrypt cases as RNS did, with ratchets enforced and
 *     not, and reports the ratchet id RNS reported;
 *   - encrypts the encrypt case to the same bytes.
 *
 * Run: node --test ratchet_vectors.test.mjs
 */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { x25519 } from "@noble/curves/ed25519";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Packet from "./lib/rns/packet.js";
import Announce from "./lib/rns/announce.js";
import Cryptography from "./lib/rns/cryptography.js";
import MsgPack from "./lib/rns/msgpack.js";
import { Reticulum } from "./lib/rns/reticulum.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";

const raw = readFileSync(new URL("./ratchet_vectors.json", import.meta.url));
const vectors = JSON.parse(raw.toString("utf8"));
const bytes = (h) => Buffer.from(h, "hex");
const hex = (b) => Buffer.from(b).toString("hex");
/** A ratchet id as hex; null (RNS's None) and undefined stay as they are. */
const idHex = (id) => (id == null ? id : hex(id));
const SECOND = 1000;

const identity = Identity.fromPrivateKey(bytes(vectors.identity.private_key_hex));
const deliveryHash = bytes(vectors.identity.lxmf_delivery_hash_hex);
/** The three ratchet private keys, newest first, as Destination.ratchets holds them. */
const ratchets = vectors.ratchets.map((r) => bytes(r.private_key_hex));
const file = bytes(vectors.ratchet_file.file_hex);
const appData = bytes(vectors.announce.app_data_hex);
/** A latestRatchetId left over from before: each decrypt must replace it. */
const STALE = Buffer.from("a stale ratchet id");
/** Where the ratchet sits in a HEADER_1 announce packet: flags, hops,
 *  destination hash, context; then public key, name hash, random hash. */
const RATCHET_AT = 2 + 16 + 1 + 64 + 10 + 10;

/** Nothing remembered from another test, nothing persisted. */
function fresh() {
    Identity.knownRatchets.clear();
    Identity.ratchetStore = null;
}

/** The web's [RATCHET] and other log lines, kept out of the test output. */
function quiet(t) {
    t.mock.method(console, "log", () => {});
}

/** A ratchet store holding `blob`; `saves` counts what is stored in it. */
function store(blob = null) {
    const kept = {
        blob, saves: 0,
        load: () => kept.blob,
        save: (next) => { kept.saves++; kept.blob = Buffer.from(next); return true; },
    };
    return kept;
}

/** The vector identity's lxmf.delivery, inbound, with ratchets on `ratchetStore`;
 *  `sent` holds the raw packets its announces send. */
function delivery(ratchetStore) {
    const sent = [];
    const destination = new Destination({ sendData: (r) => sent.push(Buffer.from(r)) }, identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");
    destination.enableRatchets(ratchetStore);
    return { destination, sent };
}

/** Identity.decrypt's plaintext as hex, or null when no key opened it: the
 *  web throws there (the token's HMAC fails under every key tried) where RNS
 *  returns None. Any other error is a failure of the test. */
function opened(decrypt) {
    try {
        return hex(decrypt());
    } catch (e) {
        if (!/HMAC was invalid/.test(e.message)) throw e;
        return null;
    }
}

test("the vector file is the one the generator wrote: format 1, SHA-256 43e95056…; RNS's constants and the identity's addresses are the web's", () => {
    assert.equal(createHash("sha256").update(raw).digest("hex"), "43e950561c7bb70138d299e45fd3fddd3e8ac51def6bda286bb99afbddc02e00");
    assert.equal(vectors.format_version, 1);
    assert.equal(vectors.generator, "Retichat-js tools/ratchet_vectors.py (RNS 1.5.2, LXMF 1.1.1)");

    const c = vectors.constants;
    assert.equal(Identity.RATCHETSIZE_IN_BITS, c.RATCHETSIZE);
    assert.equal(Identity.RATCHET_EXPIRY, c.RATCHET_EXPIRY);
    assert.equal(Destination.RATCHET_COUNT, c.RATCHET_COUNT);
    assert.equal(Destination.RATCHET_INTERVAL, c.RATCHET_INTERVAL);

    assert.equal(hex(identity.getPublicKey()), vectors.identity.public_key_hex);
    assert.equal(hex(identity.hash), vectors.identity.identity_hash_hex);
    const destination = new Destination(null, identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");
    assert.equal(hex(destination.hash), vectors.identity.lxmf_delivery_hash_hex);
    assert.equal(hex(destination.nameHash), vectors.identity.name_hash_hex);
});

test("ratchet ids: each ratchet's public key, and its id (SHA-256 of the public key, first 10 bytes), are RNS's", () => {
    const all = [...vectors.ratchets.map((r, i) => [`ratchets[${i}]`, r]), ["unlisted_ratchet", vectors.unlisted_ratchet]];
    for (const [name, r] of all) {
        const pub = Identity.ratchetPublicBytes(bytes(r.private_key_hex));
        assert.equal(hex(pub), r.public_key_hex, `${name}: public key`);
        const id = Identity.ratchetId(pub);
        assert.equal(id.length, vectors.constants.ratchet_id_length, `${name}: id length`);
        assert.equal(hex(id), r.ratchet_id_hex, `${name}: id`);
    }
    assert.equal(new Set(all.map(([, r]) => r.ratchet_id_hex)).size, 4, "four different keys");
    assert.equal(vectors.announce.ratchet_public_hex, vectors.ratchets[0].public_key_hex, "(the announce carries the newest)");
    assert.equal(vectors.announce.ratchet_id_hex, vectors.ratchets[0].ratchet_id_hex);
});

test("Python's ratchet file is read once its signature checks out, refused with one bit changed or under another identity, and the web writes the same keys as the same bytes", (t) => {
    quiet(t);
    const f = vectors.ratchet_file;

    // Its parts: {"signature", "ratchets"} in that order, the signature the
    // identity's over the packed keys.
    const persisted = MsgPack.unpack(file);
    assert.deepEqual([...persisted.keys()], ["signature", "ratchets"]);
    assert.equal(hex(persisted.get("signature")), f.signature_hex);
    assert.equal(hex(persisted.get("ratchets")), f.packed_ratchets_hex);
    assert.equal(identity.validate(bytes(f.signature_hex), bytes(f.packed_ratchets_hex)), true);
    assert.equal(hex(MsgPack.pack(ratchets)), f.packed_ratchets_hex, "the keys packed as RNS's umsgpack packs them");

    // Read.
    assert.deepEqual(Destination.unpackRatchets(identity, file).map(hex), vectors.ratchets.map((r) => r.private_key_hex), "newest first");
    assert.deepEqual(Destination.unpackRatchets(identity, bytes(f.empty_file_hex)), [], "the empty file enable_ratchets wrote first");

    // Written: Ed25519 is deterministic, so the same keys are the same file.
    assert.equal(hex(Destination.packRatchets(identity, ratchets)), f.file_hex);
    assert.equal(hex(Destination.packRatchets(identity, [])), f.empty_file_hex);

    // Refused.
    const flipped = (blob, at) => {
        const copy = Buffer.from(blob);
        copy[at] ^= 0x01;
        return copy;
    };
    const signatureAt = file.indexOf(bytes(f.signature_hex));
    const keyAt = file.indexOf(ratchets[1]);
    assert.ok(signatureAt > 0 && keyAt > signatureAt);
    const empty = bytes(f.empty_file_hex);
    const emptySignatureAt = empty.indexOf(Buffer.from(MsgPack.unpack(empty).get("signature")));
    assert.ok(emptySignatureAt > 0);
    for (const [why, blob, by] of [
        ["one bit of the signature changed", flipped(file, signatureAt), identity],
        ["one bit of a key changed", flipped(file, keyAt + 7), identity],
        ["one bit of the empty file's signature changed", flipped(empty, emptySignatureAt), identity],
        ["read as another identity's", file, Identity.create()],
    ]) {
        assert.throws(() => Destination.unpackRatchets(by, blob), /Invalid ratchet file signature/, why);
    }

    // The page's lxmf.delivery, its store holding Python's file: Python's
    // address, the three keys as stored and the file not rewritten, and what
    // Python encrypted to the newest key opens.
    const kept = store(file);
    const router = new LXMRouter(new Reticulum(), identity, { ratchets: kept });
    assert.equal(hex(router.destination.hash), vectors.identity.lxmf_delivery_hash_hex);
    assert.deepEqual(router.destination.ratchets.map(hex), vectors.ratchets.map((r) => r.private_key_hex));
    assert.equal(kept.saves, 0, "read, not rewritten");
    const newest = vectors.decrypt_cases.find((c) => c.name === "newest_ratchet");
    assert.equal(hex(router.destination.decrypt(bytes(newest.ciphertext_hex))), newest.plaintext_hex);
    assert.equal(hex(router.destination.latestRatchetId), vectors.ratchets[0].ratchet_id_hex);
});

test("taken through the generator's steps on its clock and keys (enable, three rotations, the announce), the web stores Python's ratchet file and sends Python's announce packet", (t) => {
    fresh();
    quiet(t);
    const f = vectors.ratchet_file;
    const a = vectors.announce;
    let now = f.rotated_at[0] * SECOND;
    t.mock.method(Date, "now", () => now);
    // The keys in the order RNS generated them, oldest first; a fourth
    // rotation, which RNS did not make, would add the unlisted key.
    const generated = [...ratchets].reverse().concat([bytes(vectors.unlisted_ratchet.private_key_hex)]);
    const generate = t.mock.method(Identity, "generateRatchet", () => Buffer.from(generated.shift()));
    // RNS's random hash is get_random_hash()[0:5] | the emitted time: the
    // other 11 of the 16 bytes are never used.
    t.mock.method(Cryptography, "getRandomHash", () => Buffer.concat([bytes(a.random_hash_hex).subarray(0, 5), Buffer.alloc(11, 0xee)]));

    const kept = store();
    const { destination, sent } = delivery(kept);
    assert.deepEqual(destination.ratchets, []);
    assert.equal(hex(kept.blob), f.empty_file_hex, "enableRatchets stores RNS's empty file");

    for (const [i, at] of f.rotated_at.entries()) {
        now = at * SECOND;
        assert.equal(destination.rotateRatchets(), true);
        assert.deepEqual(destination.ratchets.map(hex), vectors.ratchets.slice(2 - i).map((r) => r.private_key_hex), `rotation ${i + 1}, at ${at}: newest first`);
    }
    assert.equal(hex(kept.blob), f.file_hex, "after the three rotations the stored file is Python's, byte for byte");

    now = a.emitted_at * SECOND;
    destination.announce(appData);
    assert.equal(generate.mock.callCount(), 3, `the announce, ${a.emitted_at - f.rotated_at[2]} s after the last rotation, rotates none (RATCHET_INTERVAL)`);
    assert.equal(hex(kept.blob), f.file_hex, "and the stored file is unchanged");
    assert.equal(sent.length, 1);
    const packet = Packet.fromBytes(sent[0]);
    assert.equal(hex(packet.data.subarray(64 + 10, 64 + 20)), a.random_hash_hex, "random hash: the 5 random bytes, then the emitted time, 5 bytes big-endian");
    assert.equal(hex(sent[0]), a.packet_hex, "Python's announce packet, byte for byte");
    assert.equal(hex(packet.packetHash), a.packet_hash_hex);
});

test("built from Python's identity, random hash, ratchet and app_data, the web's announce data is Python's, with the context flag set", (t) => {
    fresh();
    quiet(t);
    const a = vectors.announce;
    const { destination } = delivery(store());
    // enableRatchets keeps no rotation time, so the first build rotates
    // newRatchet in at the front: given the two older keys, the list is then
    // Python's three.
    destination.ratchets = ratchets.slice(1);
    const { announceData, contextFlag } = destination.buildAnnounceData(appData, { randomHash: bytes(a.random_hash_hex), newRatchet: ratchets[0] });
    assert.deepEqual(destination.ratchets.map(hex), vectors.ratchets.map((r) => r.private_key_hex));

    // Part by part first, so a difference says where it starts.
    let at = 0;
    for (const [name, value] of [
        ["public key", vectors.identity.public_key_hex],
        ["name hash", vectors.identity.name_hash_hex],
        ["random hash", a.random_hash_hex],
        ["ratchet", a.ratchet_public_hex],
        ["signature", a.signature_hex],
        ["app_data", a.app_data_hex],
    ]) {
        assert.equal(hex(announceData.subarray(at, at + value.length / 2)), value, name);
        at += value.length / 2;
    }
    assert.equal(at, announceData.length, "nothing after the app_data");
    assert.equal(hex(announceData), a.announce_data_hex);
    assert.equal(identity.validate(bytes(a.signature_hex), bytes(a.signed_data_hex)), true, "the signature is over Python's signed data");

    assert.equal(contextFlag, a.context_flag);
    assert.equal(contextFlag, Packet.FLAG_SET, "set: the announce carries a ratchet");
});

test("the web's Announce parser reads Python's announce: the signature is valid and the ratchet is read; with the ratchet or the context flag changed it is refused", () => {
    const a = vectors.announce;
    const packet = Packet.fromBytes(bytes(a.packet_hex));
    assert.equal(packet.flags, parseInt(a.flags_hex, 16));
    assert.equal(packet.contextFlag, a.context_flag);
    assert.equal(packet.hops, a.hops);
    assert.equal(packet.context, parseInt(a.context_hex, 16));
    assert.equal(hex(packet.destinationHash), vectors.identity.lxmf_delivery_hash_hex);
    assert.equal(hex(packet.data), a.announce_data_hex);
    assert.equal(hex(packet.packetHash), a.packet_hash_hex);

    const announce = Announce.fromPacket(packet);
    assert.ok(announce, "valid: the signature checks out and the destination hash is the identity's lxmf.delivery");
    assert.equal(hex(announce.ratchet), a.ratchet_public_hex);
    assert.equal(hex(Identity.ratchetId(announce.ratchet)), a.ratchet_id_hex);
    assert.equal(hex(announce.identity.getPublicKey()), vectors.identity.public_key_hex);
    assert.equal(hex(announce.appData), a.app_data_hex);

    const altered = bytes(a.packet_hex);
    altered[RATCHET_AT] ^= 0x01;
    assert.equal(Announce.fromPacket(Packet.fromBytes(altered)), null, "the ratchet is signed: one bit changed, the announce is refused");
    const unflagged = bytes(a.packet_hex);
    unflagged[0] &= ~0x20;
    assert.equal(Announce.fromPacket(Packet.fromBytes(unflagged)), null, "without the context flag the ratchet is read as the signature: refused");
});

test("heard through Reticulum, Python's announce has its ratchet remembered (an altered one does not), and Destination.encrypt to it is Python's ciphertext given the same ephemeral key and IV", (t) => {
    fresh();
    quiet(t);
    const a = vectors.announce;
    const e = vectors.encrypt_case;
    const rns = new Reticulum();
    const iface = { name: "test", hash: Buffer.alloc(16) };

    const altered = bytes(a.packet_hex);
    altered[RATCHET_AT] ^= 0x01;
    rns.onPacketReceived(Packet.fromBytes(altered), iface);
    assert.equal(Identity.getRatchet(deliveryHash), null, "an altered announce's ratchet is never remembered");
    rns.onPacketReceived(Packet.fromBytes(bytes(a.packet_hex)), iface);
    assert.equal(hex(Identity.getRatchet(deliveryHash)), a.ratchet_public_hex, "remembered once the announce validated");

    // The sender holds only the public key. The encrypt case is RNS's
    // Identity.encrypt to the announced ratchet, which is what RNS's
    // Destination.encrypt does once that ratchet is known.
    assert.equal(e.ratchet_public_hex, a.ratchet_public_hex);
    const sender = Identity.fromPublicKey(bytes(vectors.identity.public_key_hex));
    const out = rns.registerDestination(sender, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
    const seams = { ephemeralPrivateKey: bytes(e.ephemeral_private_hex), iv: bytes(e.iv_hex) };
    const encrypt = t.mock.method(sender, "encrypt", (data, ratchet) => Identity.prototype.encrypt.call(sender, data, ratchet, seams));
    assert.equal(hex(out.encrypt(bytes(e.plaintext_hex))), e.ciphertext_hex);
    assert.equal(encrypt.mock.callCount(), 1);
    assert.equal(hex(encrypt.mock.calls[0].arguments[1]), a.ratchet_public_hex, "to the remembered ratchet");
    assert.equal(hex(out.latestRatchetId), a.ratchet_id_hex, "and says which (RNS Destination.latest_ratchet_id)");
});

for (const c of vectors.decrypt_cases) {
    test(`decrypt case ${c.name}, ${c.encrypted_to}: RNS's result and reported ratchet id, ratchets enforced and not`, (t) => {
        quiet(t);
        assert.deepEqual(c.results.map((r) => r.enforce_ratchets), [false, true]);
        const ciphertext = bytes(c.ciphertext_hex);
        for (const r of c.results) {
            const mode = `enforce_ratchets ${r.enforce_ratchets}`;
            if (r.plaintext_hex !== null) {
                assert.equal(r.plaintext_hex, c.plaintext_hex, `${mode}: (the case's own plaintext)`);
            }

            // Identity.decrypt with the three ratchets, newest first, as the
            // generator called RNS's.
            const receiver = { latestRatchetId: STALE };
            assert.equal(opened(() => identity.decrypt(ciphertext, ratchets, r.enforce_ratchets, receiver)), r.plaintext_hex, `Identity.decrypt, ${mode}`);
            assert.equal(idHex(receiver.latestRatchetId), r.ratchet_id_hex, `Identity.decrypt, ${mode}: the ratchet id reported`);

            // The destination whose store holds Python's ratchet file.
            const { destination } = delivery(store(file));
            if (r.enforce_ratchets) {
                destination.enforceRatchets();
            }
            destination.latestRatchetId = STALE;
            const plaintext = destination.decrypt(ciphertext);
            assert.equal(plaintext === null ? null : hex(plaintext), r.plaintext_hex, `Destination.decrypt, ${mode}`);
            assert.equal(idHex(destination.latestRatchetId), r.ratchet_id_hex, `Destination.decrypt, ${mode}: latestRatchetId`);
        }
    });
}

test("the encrypt case: Identity.encrypt given the ratchet, the ephemeral key and the IV is Python's ciphertext byte for byte, through Python's shared and derived keys", () => {
    const e = vectors.encrypt_case;
    const sender = Identity.fromPublicKey(bytes(vectors.identity.public_key_hex));
    const ephemeral = bytes(e.ephemeral_private_hex);
    const ratchet = bytes(e.ratchet_public_hex);
    const seams = { ephemeralPrivateKey: ephemeral, iv: bytes(e.iv_hex) };
    assert.equal(e.ratchet_public_hex, vectors.ratchets[0].public_key_hex, "(to the newest ratchet)");

    // The intermediates first, so a difference says where it starts.
    assert.equal(hex(x25519.getPublicKey(ephemeral)), e.ephemeral_public_hex);
    const shared = Buffer.from(x25519.getSharedSecret(ephemeral, ratchet));
    assert.equal(hex(shared), e.shared_key_hex);
    assert.equal(hex(Cryptography.hkdf(64, shared, sender.hash)), e.derived_key_hex, "HKDF-SHA256 to 64 bytes, salted with the identity hash, no info");

    const token = sender.encrypt(bytes(e.plaintext_hex), ratchet, seams);
    assert.equal(hex(token.subarray(0, 32)), e.ephemeral_public_hex, "ephemeral public key");
    assert.equal(hex(token.subarray(32, 48)), e.iv_hex, "IV");
    assert.equal(hex(token), e.ciphertext_hex);

    // It opens with ratchets enforced, with the newest ratchet.
    const receiver = { latestRatchetId: STALE };
    assert.equal(hex(identity.decrypt(token, ratchets, true, receiver)), e.plaintext_hex);
    assert.equal(idHex(receiver.latestRatchetId), vectors.ratchets[0].ratchet_id_hex);

    // The ratchet is what it was encrypted to: the same ephemeral key and IV
    // to the identity key give another token, which enforcement refuses.
    const toIdentity = sender.encrypt(bytes(e.plaintext_hex), null, seams);
    assert.notEqual(hex(toIdentity), e.ciphertext_hex);
    assert.equal(opened(() => identity.decrypt(toIdentity, ratchets, true)), null);
    assert.equal(opened(() => identity.decrypt(toIdentity, ratchets, false)), e.plaintext_hex);
});
