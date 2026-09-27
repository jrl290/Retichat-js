/**
 * REGRESSION GUARD — LXMF signatures and channel key binding
 * (LXMF-rust/DISPLAY_NAMES.md §7 and §2.3; audit H4 and H3).
 *
 * Until 2026-09-27 the web client never validated an LXMF signature
 * (lxmf_message.js: "todo validate signature"), so anyone holding the
 * recipient's public key could claim any contact's source hash and name.
 * It now computes the reference's three outcomes (LXMessage.py
 * unpack_from_bytes / validate_signature): validated, source unknown,
 * signature invalid.
 *
 * Channel unpack remembered the prelude key under the CLAIMED source hash
 * without checking that the key produces it; anyone who knows a channel's
 * name could plant a key under a contact's hash. A post whose key does not
 * bind is now rejected.
 *
 * Run: node --test lxmf_signature.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Cryptography from "./lib/rns/cryptography.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import { channelLxmPack, channelLxmUnpack, channelIdentity, channelDeliveryHash } from "./lib/rns/rfed_channel.js";
import { nameState, CLEAR } from "./lib/display_name.js";

const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery");

function packed(from, to, content = "hi", fields = new Map()) {
    const m = new LXMessage();
    m.sourceHash = lxmfHash(from);
    m.destinationHash = lxmfHash(to);
    m.title = "";
    m.content = content;
    m.fields = fields;
    return { bytes: m.pack(from, false), hash: m.hash };
}

/** The identity store as app.js builds it: source hash → identity. */
const store = (...identities) => (source) =>
    identities.find((i) => lxmfHash(i).equals(Buffer.from(source))) ?? null;

test("a genuine message from a known source is validated", () => {
    const alice = Identity.create(), bob = Identity.create();
    const { bytes, hash } = packed(alice, bob);
    const m = LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16), store(alice));
    assert.equal(m.signatureValidated, true);
    assert.equal(m.unverifiedReason, null);
    assert.equal(m.signatureState, "validated");
    assert.ok(m.hash.equals(hash), "the reference's message hash");
});

test("an unknown source is SOURCE_UNKNOWN, not invalid", () => {
    const alice = Identity.create(), bob = Identity.create();
    const { bytes } = packed(alice, bob);
    const m = LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16), store());
    assert.equal(m.signatureValidated, false);
    assert.equal(m.unverifiedReason, LXMessage.SOURCE_UNKNOWN);
    assert.equal(m.signatureState, "unknown");
    assert.equal(LXMessage.SOURCE_UNKNOWN, 0x01, "reference value");
});

test("a flipped signature byte, or a forger claiming a contact's hash, is SIGNATURE_INVALID", () => {
    const alice = Identity.create(), bob = Identity.create(), mallory = Identity.create();
    const { bytes } = packed(alice, bob);
    const tampered = Buffer.from(bytes);
    tampered[16 + 16 + 5] ^= 0x01;
    const m = LXMessage.fromBytes(tampered.subarray(16), tampered.subarray(0, 16), store(alice));
    assert.equal(m.signatureState, "invalid");
    assert.equal(m.unverifiedReason, LXMessage.SIGNATURE_INVALID);
    assert.equal(LXMessage.SIGNATURE_INVALID, 0x02, "reference value");

    // Mallory signs with her own key but claims Alice's source hash.
    const forged = new LXMessage();
    forged.sourceHash = lxmfHash(alice);
    forged.destinationHash = lxmfHash(bob);
    forged.title = ""; forged.content = "it's me, Alice"; forged.fields = new Map([[0xD1, Buffer.from("Alice")]]);
    const f = forged.pack(mallory, false);
    assert.equal(LXMessage.fromBytes(f.subarray(16), f.subarray(0, 16), store(alice)).signatureState, "invalid");
});

test("a stamped message (a fifth payload element) validates over the first four, as the reference", () => {
    const alice = Identity.create(), bob = Identity.create();
    const { bytes, hash } = packed(alice, bob, "stamped");
    const payload = MsgPack.unpack(bytes.subarray(96));
    const withStamp = Buffer.concat([bytes.subarray(0, 96), MsgPack.pack([...payload, Buffer.alloc(32, 9)])]);
    const m = LXMessage.fromBytes(withStamp.subarray(16), withStamp.subarray(0, 16), store(alice));
    assert.equal(m.signatureState, "validated");
    assert.ok(m.hash.equals(hash), "the hash leaves the stamp out");
    assert.ok(LXMessage.hashOf(withStamp.subarray(0, 16), withStamp.subarray(16, 32), withStamp.subarray(96)).equals(hash));
});

test("without a destination hash nothing validates, and the store's failure never passes a name", () => {
    const alice = Identity.create(), bob = Identity.create();
    const { bytes } = packed(alice, bob);
    assert.equal(LXMessage.fromBytes(bytes.subarray(16), null, store(alice)).signatureState, "invalid");
    const throwing = () => { throw new Error("store broken"); };
    assert.equal(LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16), throwing).signatureState, "invalid");
});

test("the router's default store is LXMessage.recall, which the app installs", () => {
    const alice = Identity.create(), bob = Identity.create();
    const { bytes } = packed(alice, bob);
    const saved = LXMessage.recall;
    try {
        LXMessage.recall = store(alice);
        assert.equal(LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16)).signatureState, "validated");
    } finally {
        LXMessage.recall = saved;
    }
});

// ── Channel key binding (§2.3) ──────────────────────────────────────────────

const CHANNEL = "public.display-name-tests";

/** A post whose prelude carries `preludeKeyOf`'s key but whose LXMF source
 *  and signature are `signer`'s: the forgery the binding check stops. */
function forgedPost(signer, preludeKeyOf, content = "forged") {
    const destHash = channelDeliveryHash(CHANNEL);
    const sourceHash = lxmfHash(signer);
    const payload = MsgPack.pack([Date.now() / 1000, Buffer.alloc(0), Buffer.from(content), new Map()]);
    const hashed = Buffer.concat([destHash, sourceHash, payload]);
    const signature = signer.sign(Buffer.concat([hashed, Cryptography.fullHash(hashed)]));
    const plain = Buffer.concat([Buffer.from("RTID"), preludeKeyOf.getPublicKey(), sourceHash, signature, payload]);
    const { identity, hash } = channelIdentity(CHANNEL);
    return Buffer.concat([hash, identity.encrypt(plain)]);
}

test("a genuine post unpacks, with its sender key bound to its source", () => {
    const alice = Identity.create();
    const { wire } = channelLxmPack(CHANNEL, alice, "hello channel");
    const post = channelLxmUnpack(CHANNEL, wire);
    assert.ok(post);
    assert.ok(post.sourceHash.equals(lxmfHash(alice)));
    assert.ok(Buffer.from(post.senderPubKey).equals(alice.getPublicKey()));
    assert.equal(post.content, "hello channel");
    assert.equal(post.displayName.state, "absent");
});

test("a post whose prelude key does not produce the claimed source is rejected", () => {
    const alice = Identity.create(), mallory = Identity.create();
    // Mallory claims Alice's hash, signs with her own key and puts her own
    // key in the prelude: the signature verifies against the prelude, so only
    // the binding check stops it planting Mallory's key under Alice's hash.
    const destHash = channelDeliveryHash(CHANNEL);
    const payload = MsgPack.pack([Date.now() / 1000, Buffer.alloc(0), Buffer.from("I am Alice"), new Map([[0xD1, Buffer.from("Alice")]])]);
    const hashed = Buffer.concat([destHash, lxmfHash(alice), payload]);
    const signature = mallory.sign(Buffer.concat([hashed, Cryptography.fullHash(hashed)]));
    const plain = Buffer.concat([Buffer.from("RTID"), mallory.getPublicKey(), lxmfHash(alice), signature, payload]);
    const { identity, hash } = channelIdentity(CHANNEL);
    assert.equal(channelLxmUnpack(CHANNEL, Buffer.concat([hash, identity.encrypt(plain)])), null);

    // With the victim's real key in the prelude the binding passes but the
    // signature (Mallory's) does not: rejected too.
    assert.equal(channelLxmUnpack(CHANNEL, forgedPost(mallory, alice)), null);
});

test("§2.3 channel posts carry 0xD1 as bin, only when told to, and it round-trips", () => {
    const alice = Identity.create();
    const named = channelLxmUnpack(CHANNEL, channelLxmPack(CHANNEL, alice, "x", nameState("Alice")).wire);
    assert.deepEqual(named.displayName, { state: "name", name: "Alice" });
    assert.ok(Buffer.isBuffer(named.fields.get(0xD1)), "bin on the wire");
    const cleared = channelLxmUnpack(CHANNEL, channelLxmPack(CHANNEL, alice, "x", CLEAR).wire);
    assert.equal(cleared.displayName.state, "clear");
    const plain = channelLxmUnpack(CHANNEL, channelLxmPack(CHANNEL, alice, "x").wire);
    assert.equal(plain.fields.size, 0, "no name: the fields map stays empty, the old wire shape");
});
