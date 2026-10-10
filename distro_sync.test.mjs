/**
 * THE DISTRO SYNC PROOF — RFed-rust SPEC.md §17.13, RFed-spec LXMFProp.md
 * §10.5, DISTRO-SYNC-PROOF-DESIGN.md §4, §5, §7 "Web" and §13.1 "Web"
 * (approved by James, 2026-10-10).
 *
 * A device's own uploads to its distro D, the §17.11 sent-copy and the
 * §17.12 membership message C (both: James, 2026-10-10, Q1), prove with D's
 * key that they are sync, and RFed then wakes no device for them. Here:
 *
 *   1. lib/distro_sync.js against the golden vector, LXMF-rust
 *      tests/distro_sync_vectors.json (copied as distro_sync_vectors.json,
 *      and checked against the original whenever ../LXMF-rust holds it): the
 *      signed bytes, the signature, the claim, and the envelope with and
 *      without it, byte for byte; the envelope's shape, every value native
 *      msgpack (CHECK_THESE_THINGS_FIRST §11); sealing, and every refusal.
 *   2. The page (the shipped method bodies from app.js, test_app_source.mjs):
 *      both kinds sealed in the write that owes them, before any upload;
 *      every upload of an entry carrying the same sealed bytes, never
 *      encrypted again; the proof only for the configured RFed's own
 *      propagation node (§5.4), never with lxmfPropagationOverride; a
 *      sent-copy owed to a distro given up still proved; an entry owed
 *      before this built as before; a message that cannot be sealed, a
 *      stored proof that is not the message's, a stored pair that is
 *      broken (each said, and recorded as a "distro-sync-proof" Harness
 *      error, the proof lost and never the message), and a stamp that
 *      cannot be computed.
 *
 * Run: node --test distro_sync.test.mjs
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Cryptography from "./lib/rns/cryptography.js";
import MsgPack from "./lib/rns/msgpack.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import Link from "./lib/rns/link.js";
import { readHead, skipValue } from "./lib/rns/msgpack_raw.js";
import { channelSyncFields, readChannelSync } from "./lib/channel_sync.js";
import { DistroUploads } from "./lib/distro_upload.js";
import { DistroOutbox, UnprovedUploads, channelSyncEntryId, sentCopyEntryId, syncProofKept } from "./lib/distro_outbox.js";
import {
    DISTRO_SYNC_KEY, DISTRO_SYNC_SIGNED_LEN, buildSealedUpload, sealForSync, syncClaimFor, syncClaimRefusal, syncSignedBytes,
    syncTransientId,
} from "./lib/distro_sync.js";
import { compile, install, memoryStorage } from "./test_app_source.mjs";

const COPY = new URL("./distro_sync_vectors.json", import.meta.url);
const ORIGINAL = new URL("../LXMF-rust/tests/distro_sync_vectors.json", import.meta.url);
const V = JSON.parse(readFileSync(COPY, "utf8"));
const hex = (h) => Buffer.from(h, "hex");
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery");
const D = Identity.fromPrivateKey(hex(V.distro.private_key_hex));
const SEALED = hex(V.sealed_hex);
const STAMP = hex(V.stamp_hex);
const SIG = hex(V.sig_hex);
const PUB = hex(V.distro.public_key_hex);

// ── 1. The golden vector (lib/distro_sync.js) ─────────────────────────────

test("the vectors here are LXMF-rust's own: distro_sync_vectors.json is a byte-for-byte copy of LXMF-rust tests/distro_sync_vectors.json", { skip: existsSync(ORIGINAL) ? false : "../LXMF-rust/tests/distro_sync_vectors.json is not in this tree: the copy is checked by its own bytes alone" }, () => {
    assert.equal(readFileSync(COPY, "utf8"), readFileSync(ORIGINAL, "utf8"), "the copy is stale: copy LXMF-rust tests/distro_sync_vectors.json again");
});

test("the golden vector's distro D: its key, identity hash and lxmf.delivery hash", () => {
    assert.equal(D.getPublicKey().toString("hex"), V.distro.public_key_hex);
    assert.equal(D.hash.toString("hex"), V.distro.identity_hash_hex);
    assert.equal(lxmfHash(D).toString("hex"), V.distro.lxmf_delivery_hash_hex);
    assert.equal(hex(V.packed_hex).subarray(0, 16).toString("hex"), V.distro.lxmf_delivery_hash_hex, "packed to D");
    assert.equal(SEALED.subarray(0, 16).toString("hex"), V.distro.lxmf_delivery_hash_hex, "sealed for D");
});

test("the golden vector: transient id, id, the 65 signed bytes and D's signature over them, byte for byte", () => {
    const transientId = syncTransientId(SEALED);
    assert.equal(transientId.toString("hex"), V.transient_id_hex, "SHA-256(sealed)");
    assert.equal(transientId.subarray(0, 16).toString("hex"), V.id_hex);
    const signed = syncSignedBytes(SEALED.subarray(0, 16), transientId);
    assert.equal(signed.length, DISTRO_SYNC_SIGNED_LEN);
    assert.equal(signed.toString("hex"), V.signed_hex);
    assert.equal(signed.subarray(0, 16).toString("ascii"), "rfed.distro.sync", "the tag");
    assert.equal(signed[16], 0x01, "the version at offset 16");
    assert.ok(signed.subarray(17, 33).equals(SEALED.subarray(0, 16)), "D_hash");
    assert.ok(signed.subarray(33).equals(transientId), "ends with the transient id");
    assert.equal(D.sign(signed).toString("hex"), V.sig_hex, "Ed25519 is deterministic: the same signature as Python and Rust");
    assert.equal(D.validate(SIG, signed), true);
    assert.throws(() => syncSignedBytes(SEALED.subarray(0, 15), transientId), /16 bytes/);
    assert.throws(() => syncSignedBytes(SEALED.subarray(0, 16), transientId.subarray(1)), /32 bytes/);
});

test("the golden vector: the claim, and the upload with it and without it, byte for byte", () => {
    const claim = syncClaimFor(SEALED, PUB, SIG);
    assert.deepEqual(claim.map((b) => b.toString("hex")), [V.id_hex, V.distro.public_key_hex, V.sig_hex]);
    assert.equal(syncClaimRefusal(claim, SEALED), null);
    assert.equal(Buffer.concat([SEALED, STAMP]).toString("hex"), V.lxmf_data_hex);
    const envelope = buildSealedUpload(SEALED, STAMP, claim, V.timebase);
    assert.equal(envelope.toString("hex"), V.envelope_hex);
    assert.equal(buildSealedUpload(SEALED, STAMP, null, V.timebase).toString("hex"), V.envelope_legacy_hex,
        "without a claim: LXMF's two-element upload, as every upload was before");
    // The extension is the envelope's third element, alone.
    let pos = readHead(envelope, 0).end;
    pos = skipValue(envelope, pos);
    pos = skipValue(envelope, pos);
    assert.equal(envelope.subarray(pos).toString("hex"), V.extension_hex);
});

test("the upload's shape: a three-element array whose third element is a map from the str key to native arrays of bin, nothing packed beforehand and wrapped in bin (CHECK_THESE_THINGS_FIRST §11)", () => {
    const envelope = buildSealedUpload(SEALED, STAMP, syncClaimFor(SEALED, PUB, SIG), V.timebase);
    assert.equal(envelope[0], 0x93, "fixarray(3)");
    const top = readHead(envelope, 0);
    let pos = top.end;
    assert.equal(envelope[pos], 0xcb, "the timebase is a float 64");
    pos = skipValue(envelope, pos);
    const messages = readHead(envelope, pos);
    assert.deepEqual([messages.kind, messages.count], ["array", 1], "an array of one message");
    const lxmfData = readHead(envelope, messages.end);
    assert.equal(lxmfData.kind, "bin");
    assert.equal(Buffer.from(lxmfData.raw).toString("hex"), V.lxmf_data_hex, "lxmf_data = sealed | stamp, as bin");
    pos = lxmfData.end;
    const extension = readHead(envelope, pos);
    assert.deepEqual([extension.kind, extension.count, envelope[pos]], ["map", 1, 0x81], "a fixmap of one key");
    const key = readHead(envelope, extension.end);
    assert.deepEqual([key.kind, Buffer.from(key.raw).toString(), envelope[extension.end]], ["str", DISTRO_SYNC_KEY, 0xb0], "the key, a fixstr(16)");
    const claims = readHead(envelope, key.end);
    assert.deepEqual([claims.kind, claims.count], ["array", 1], "an array of one claim, never a bin holding one");
    const claim = readHead(envelope, claims.end);
    assert.deepEqual([claim.kind, claim.count], ["array", 3], "a claim is fixarray(3)");
    let at = claim.end;
    const fields = [];
    for (let i = 0; i < 3; i++) {
        const field = readHead(envelope, at);
        fields.push([field.kind, field.raw.length]);
        at = field.end;
    }
    assert.deepEqual(fields, [["bin", 16], ["bin", 64], ["bin", 64]], "id, distro key and signature, each a bin");
    assert.equal(at, envelope.length, "nothing after the extension");
    // msgpackr reads it back as the reader rules expect: data[2] a Map.
    const data = MsgPack.unpack(envelope);
    assert.equal(data.length, 3);
    assert.ok(data[2] instanceof Map);
    assert.deepEqual(data[2].get(DISTRO_SYNC_KEY).map((c) => c.map((b) => Buffer.from(b).toString("hex"))), [[V.id_hex, V.distro.public_key_hex, V.sig_hex]]);
});

test("sealForSync: D_hash | D.encrypt(packed[16..]), once, and D's signature over it, which RFed would accept", () => {
    const packed = hex(V.packed_hex);
    const { sealed, sig } = sealForSync(D, packed);
    assert.ok(sealed.subarray(0, 16).equals(lxmfHash(D)), "sealed[0..16] == D_hash");
    assert.ok(D.decrypt(sealed.subarray(16)).equals(packed.subarray(16)), "D opens it to the packed message");
    assert.equal(sig.length, 64);
    assert.equal(D.validate(sig, syncSignedBytes(lxmfHash(D), syncTransientId(sealed))), true);
    assert.equal(syncClaimRefusal(syncClaimFor(sealed, PUB, sig), sealed), null, "a claim RFed accepts");
    // The message inside is D's, signed by D: LXMF's signature still validates.
    const hashed = Buffer.concat([packed.subarray(0, 32), packed.subarray(96)]);
    assert.ok(D.validate(packed.subarray(32, 96), Buffer.concat([hashed, Cryptography.fullHash(hashed)])));
    // Encryption is random: sealing again gives other bytes, so it is done once, when the message is owed.
    assert.ok(!sealForSync(D, packed).sealed.equals(sealed));
});

test("sealForSync refuses, with nothing made: an identity without D's private key, a message not addressed to D, one too short to be LXMF", () => {
    const packed = hex(V.packed_hex);
    assert.throws(() => sealForSync(Identity.fromPublicKey(PUB), packed), /no private key/);
    assert.throws(() => sealForSync(null, packed), /no private key/);
    assert.throws(() => sealForSync(Identity.create(), packed), /not addressed to the distro/);
    assert.throws(() => sealForSync(D, packed.subarray(0, 96)), /longer than 96 bytes/);
});

test("a claim RFed would refuse is refused here too, and never built: another identity's key, another message, no tag or version, a device key, a register-style signature, a wrong id, fields of the wrong size", () => {
    const transientId = syncTransientId(SEALED);
    const dHash = SEALED.subarray(0, 16);
    const id = transientId.subarray(0, 16);
    const other = Identity.create();
    const refusal = (claim) => syncClaimRefusal(claim, SEALED);
    assert.equal(refusal([id, PUB, SIG]), null);
    assert.equal(refusal([id, other.getPublicKey(), other.sign(syncSignedBytes(dHash, transientId))]), "distro key is not the message's destination");
    const elsewhere = Cryptography.fullHash(Buffer.from("another message"));
    assert.equal(refusal([id, PUB, D.sign(syncSignedBytes(dHash, elsewhere))]), "signature invalid", "a signature over another transient id");
    assert.equal(refusal([id, PUB, D.sign(Buffer.concat([dHash, transientId]))]), "signature invalid", "without the tag and version");
    assert.equal(refusal([id, PUB, Identity.create().sign(syncSignedBytes(dHash, transientId))]), "signature invalid", "a device's key");
    assert.equal(refusal([id, PUB, D.sign(Identity.create().getPublicKey())]), "signature invalid", "a register-style signature over a device_pubkey");
    assert.equal(refusal([Buffer.alloc(16, 1), PUB, SIG]), "id is not the message's");
    assert.equal(refusal([transientId.subarray(0, 15), PUB, SIG]), "not a claim");
    assert.equal(refusal([id, PUB.subarray(0, 63), SIG]), "not a claim");
    assert.equal(refusal([id, Buffer.concat([PUB, Buffer.alloc(1)]), SIG]), "not a claim");
    assert.equal(refusal([id, PUB, SIG.subarray(0, 63)]), "not a claim");
    assert.equal(refusal([id, PUB, Buffer.concat([SIG, Buffer.alloc(1)])]), "not a claim");
    assert.equal(refusal([id, PUB]), "not a claim");
    assert.equal(refusal("junk"), "not a claim");
    assert.throws(() => syncClaimFor(SEALED, other.getPublicKey(), SIG), /not this message's: distro key/);
    assert.throws(() => syncClaimFor(SEALED, PUB, Buffer.alloc(64)), /not this message's: signature invalid/);
    assert.throws(() => buildSealedUpload(SEALED, STAMP, [Buffer.alloc(16), PUB, SIG], V.timebase), /not this message's: id/);
    assert.throws(() => buildSealedUpload(SEALED, STAMP.subarray(1), null, V.timebase), /32 bytes/, "a stamp is 32 bytes");
    assert.throws(() => buildSealedUpload(SEALED.subarray(0, 16), STAMP, null, V.timebase), /longer than 16 bytes/);
});

// ── 2. The page (app.js) ──────────────────────────────────────────────────

const R = "0123456789abcdef0123456789abcdef";
const CHANNEL = { channelName: "public.sync", channelHash: "cd".repeat(16) };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

const METHODS = [
    "async _sendDistroSentCopy(recipientHex, title, content)", "_sendDistroChannelSync(op, ch, atMs)",
    "_sealForDistroSync(packed, label)", "_distroSyncProofGoes(link)", "_oweDistro(entry)",
    "async _sendDistroOutbox(link, trigger)", "_distroAttemptOpen(entry, link)", "_unprovedSince(entry, comingUp)",
    "async _uploadOwed(link, entry, comingUp = null)", "_stillOwed(entry)", "_dropMembershipOwedToOtherDistros()",
    "_distroOwedOutcome(entry, how, error, goesNow = false)", "_distroOwedNeverLeft(entry, error)",
    "_uploadForDistro(link, propagationPacked, label)",
    "async _buildPropagationPacked(lxmfPacked, peerPublicKeyHex, sealed = null, syncSig = null)",
];

/**
 * A device holding `distro`, with the shipped outbox, sealing, gate and
 * build. The configured RFed is `rfed` (its identity hash), and the
 * propagation node is the one connect() resolves: `override`, or the hash
 * derived from the RFed. Its links go to `node` (the resolved node unless
 * given). The stamp is a stand-in (each one different) that records what it
 * was mined over; everything else is the page's. Uploads over the MDU go as
 * Resources whose end the test decides (`resources`), packets are proved
 * when the test says (`prove`).
 */
function device({ distro = Identity.create(), override = "", node = null, rfed = Cryptography.getRandomHash().subarray(0, 16).toString("hex"), seal = sealForSync, stamps = "auto" } = {}) {
    const storage = memoryStorage();
    const derived = Destination.hash({ hash: hex(rfed) }, "lxmf", "propagation").toString("hex");
    const resolved = override || derived;
    const logged = [];
    const log = { log() {}, warn: (...a) => logged.push(["warn", a.join(" ")]), error: (...a) => logged.push(["error", a.join(" ")]) };
    const events = [];
    const Harness = {
        event: (kind, detail) => events.push({ kind, detail }),
        error: (where, e) => events.push({ kind: "error", detail: { where, message: e?.message ?? String(e) } }),
    };
    const DistroManager = {};
    const hold = (identity) => Object.assign(DistroManager, identity
        ? { has: true, identity, lxmfDeliveryHash: lxmfHash(identity).toString("hex"), pubKey: identity.getPublicKey().toString("hex") }
        : { has: false, identity: null, lxmfDeliveryHash: null, pubKey: null });
    hold(distro);
    const uploads = [];     // every propagation upload, as handed to the link
    const resources = [];   // the Resources' ends, oldest first: { resolve, reject }
    const minedOver = [];   // what each stamp was mined over
    const me = Identity.create();
    const makeLink = (to = node ?? resolved) => ({
        status: Link.ACTIVE,
        destination: { hash: hex(to) },
        newLinkPacket: (context, data) => ({ packetHash: Cryptography.fullHash(Buffer.from(data)), pack: () => Buffer.from(data) }),
        _transmit(raw) {
            if (this.status !== Link.ACTIVE) return null;
            uploads.push(Buffer.from(raw));
            return raw;
        },
        sendResource(data) {
            uploads.push(Buffer.from(data));
            return new Promise((resolve, reject) => resources.push({ resolve, reject }));
        },
    });
    const env = {
        Buffer, Identity, Destination, Cryptography, MsgPack, LXMessage, LXMF, Harness, console: log, DistroManager,
        Link: { MDU: Link.MDU, ACTIVE: Link.ACTIVE }, Packet: { NONE: 0x00 },
        DistroOutboxStore: new DistroOutbox({ get: storage.sGet, set: storage.sSet }), sentCopyEntryId, channelSyncEntryId,
        channelSyncFields, ownLxmfDestinationHash: () => lxmfHash(me).toString("hex"),
        sealForSync: seal, syncClaimFor, buildSealedUpload, syncProofKept,
    };
    let n = 0;
    const self = {
        ownHash: lxmfHash(me).toString("hex"),
        _cfg: { rfedNodeHash: rfed, lxmfPropagationOverride: override, propagationNodeHash: resolved },
        _propLink: null, _distroOutboxInFlight: new Map(), _propComingUps: 0, _distroUnproved: new UnprovedUploads(),
        _pendingPacketHashes: new Map(), _distroUploads: new DistroUploads({ log: { error() {}, warn() {} } }),
        _computePropagationStamp: async (data) => {
            minedOver.push(Buffer.from(data));
            return stamps === "auto" ? Buffer.alloc(32, ++n) : stamps(data);
        },
    };
    install(self, env, METHODS);
    /** A propagation link comes up: what is owed goes on it, as its "established" handler sends it. */
    const establish = async (to) => {
        const link = makeLink(to);
        self._propLink = link;
        await self._sendDistroOutbox(link, "established");
        await tick();
        return link;
    };
    /** The propagation node proves the last upload packet. */
    const prove = () => {
        const [key, pending] = [...self._pendingPacketHashes].at(-1) ?? [];
        if (!pending) return false;
        self._pendingPacketHashes.delete(key);
        pending.onProof?.(pending.messageId);
        return true;
    };
    return {
        self, env, storage, distro, hold, uploads, resources, minedOver, logged, events, establish, prove, derived, resolved,
        owed: () => env.DistroOutboxStore.list(),
        errors: () => logged.filter(([level]) => level === "error").map(([, line]) => line),
        sendCopy: async (content = "hello from the web") => { await self._sendDistroSentCopy(R, "", content); await tick(); },
        join: async (at = 1_790_000_000_000) => { self._sendDistroChannelSync("join", CHANNEL, at); await tick(); },
    };
}

/** An upload as RFed reads it: data[1][0] is lxmf_data = sealed | stamp, and data[2], when present, the claims. */
function readUpload(upload) {
    const data = MsgPack.unpack(upload);
    const lxmfData = Buffer.from(data[1][0]);
    const claims = data.length > 2 ? data[2].get(DISTRO_SYNC_KEY).map((c) => c.map((b) => Buffer.from(b))) : null;
    return { elements: data.length, timebase: data[0], sealed: lxmfData.subarray(0, -32), stamp: lxmfData.subarray(-32), claims };
}

test("both kinds, the sent-copy and the membership message C, are sealed when they are owed, in the write that owes them and before any upload (James, 2026-10-10, Q1)", async () => {
    const d = device();
    await d.sendCopy();
    await d.join();
    assert.deepEqual(d.uploads, [], "no propagation link: nothing uploaded yet");
    const stored = d.storage.sGet("distro_outbox_v1");
    assert.deepEqual(stored.map((e) => e.kind), ["sent", "channel"]);
    for (const entry of stored) {
        assert.equal(typeof entry.sealed, "string", `${entry.label}: sealed, in storage`);
        assert.equal(typeof entry.syncSig, "string", `${entry.label}: its proof, in storage`);
        const sealed = Buffer.from(entry.sealed, "base64");
        const packed = Buffer.from(entry.packed, "base64");
        assert.ok(sealed.subarray(0, 16).equals(lxmfHash(d.distro)), "sealed for D");
        assert.ok(d.distro.decrypt(sealed.subarray(16)).equals(packed.subarray(16)), "the message packed when the user acted, encrypted to D");
        assert.equal(d.distro.validate(Buffer.from(entry.syncSig, "base64"), syncSignedBytes(sealed.subarray(0, 16), syncTransientId(sealed))), true, "signed by D");
    }
    assert.equal(readChannelSync(Buffer.from(stored[1].packed, "base64").subarray(96)).sync.op, "join");
    assert.deepEqual(d.errors(), []);
});

test("on the configured RFed's own propagation node each kind goes with D's proof, and every upload of it carries the same sealed bytes, never encrypted again: only the stamp and the timebase are new", async () => {
    for (const kind of ["sent", "channel"]) {
        const d = device();
        if (kind === "sent") await d.sendCopy(); else await d.join();
        const [entry] = d.owed();
        const link1 = await d.establish();
        assert.equal(d.uploads.length, 1, `${kind}: uploaded`);
        const first = readUpload(d.uploads[0]);
        assert.equal(first.elements, 3, `${kind}: the three-element upload, with the proof`);
        assert.ok(first.sealed.equals(Buffer.from(entry.sealed, "base64")), `${kind}: the bytes sealed when it was owed`);
        assert.ok(d.minedOver[0].equals(first.sealed), `${kind}: the stamp is mined over the sealed message`);
        assert.equal(first.claims.length, 1);
        assert.equal(syncClaimRefusal(first.claims[0], first.sealed), null, `${kind}: a proof RFed accepts`);
        assert.ok(first.claims[0][1].equals(d.distro.getPublicKey()), "D's key");
        assert.ok(d.uploads[0].length > Link.MDU, "with the proof it is a Resource (Stage 0 covers its never-left)");

        // Its Resource fails: owed still, and the next coming-up uploads it again.
        d.resources.shift().reject(new Error("no response to the resource advertisement"));
        await tick();
        assert.equal(d.owed().length, 1);
        link1.status = 0x04;
        await d.establish();
        assert.equal(d.uploads.length, 2, `${kind}: uploaded again at the coming-up`);
        const second = readUpload(d.uploads[1]);
        assert.ok(second.sealed.equals(first.sealed), `${kind}: byte for byte the same sealed message, so RFed holds it under the same id and fans it out once`);
        assert.deepEqual(second.claims.map((c) => c.map((b) => b.toString("hex"))), first.claims.map((c) => c.map((b) => b.toString("hex"))), "the same proof");
        assert.ok(!second.stamp.equals(first.stamp), "a new stamp");
        d.resources.shift().resolve();
        await tick();
        assert.deepEqual([d.owed(), d.errors()], [[], []], `${kind}: proved, owed no more`);
    }
});

test("the client gate (DISTRO-SYNC-PROOF-DESIGN.md §5.4): any override, and any link to another node, gets LXMF's two-element upload, the same sealed bytes, and no proof", async () => {
    const lxmd = Cryptography.getRandomHash().subarray(0, 16).toString("hex");
    const viaOverride = device({ override: lxmd });
    await viaOverride.sendCopy();
    await viaOverride.establish();
    const plain = readUpload(viaOverride.uploads[0]);
    assert.equal(plain.elements, 2, "lxmfPropagationOverride: two elements, as LXMF takes");
    assert.ok(plain.sealed.equals(Buffer.from(viaOverride.owed()[0].sealed, "base64")), "still the sealed bytes");
    assert.equal(viaOverride.uploads[0].subarray(0, 1)[0], 0x92);

    // An override that names the RFed's own node is still an override.
    const rfed = Cryptography.getRandomHash().subarray(0, 16).toString("hex");
    const derived = Destination.hash({ hash: hex(rfed) }, "lxmf", "propagation").toString("hex");
    const named = device({ rfed, override: derived });
    await named.sendCopy();
    await named.establish();
    assert.equal(readUpload(named.uploads[0]).elements, 2);

    // A link to another node than the derived one (a propagation key stored for an earlier RFed).
    const stale = device({ node: lxmd });
    await stale.sendCopy();
    await stale.establish();
    assert.equal(readUpload(stale.uploads[0]).elements, 2);

    // The gate itself.
    const gate = device({ rfed });
    const goes = (cfg, to) => {
        gate.self._cfg = cfg;
        return gate.self._distroSyncProofGoes(to === undefined ? undefined : { destination: to === null ? undefined : { hash: hex(to) } });
    };
    const base = { rfedNodeHash: rfed, lxmfPropagationOverride: "", propagationNodeHash: derived };
    assert.equal(goes(base, derived), true, "the derived node, and the link goes to it");
    assert.equal(goes({ ...base, lxmfPropagationOverride: derived, propagationNodeHash: derived }, derived), false, "an override");
    assert.equal(goes({ ...base, lxmfPropagationOverride: lxmd, propagationNodeHash: lxmd }, lxmd), false);
    assert.equal(goes(base, lxmd), false, "a link to another node");
    assert.equal(goes(base, null), false, "a link that names no node");
    assert.equal(goes(base, undefined), false, "no link");
    assert.equal(goes({ ...base, propagationNodeHash: lxmd }, derived), false, "a resolved node that is not the derived one");
    assert.equal(goes({ ...base, rfedNodeHash: "" }, derived), false, "no RFed configured");
    gate.self._cfg = undefined;
    assert.equal(gate.self._distroSyncProofGoes({ destination: { hash: hex(derived) } }), false, "not connected");
});

test("a sent-copy owed to a distro this device has since given up still goes to that distro with that distro's proof", async () => {
    const d = device();
    const first = d.distro;
    await d.sendCopy();
    d.hold(Identity.create());
    await d.establish();
    assert.equal(d.uploads.length, 1);
    const upload = readUpload(d.uploads[0]);
    assert.equal(upload.elements, 3);
    assert.ok(upload.sealed.subarray(0, 16).equals(lxmfHash(first)), "to the distro it was made for");
    assert.ok(upload.claims[0][1].equals(first.getPublicKey()), "proved with that distro's key");
    assert.equal(syncClaimRefusal(upload.claims[0], upload.sealed), null);
});

test("an entry owed before entries were sealed is built as before: encrypted anew each upload, and no proof", async () => {
    const d = device();
    await d.sendCopy();
    const { sealed, syncSig, ...old } = d.owed()[0];
    assert.ok(sealed && syncSig);
    d.env.DistroOutboxStore.put(old);
    const link1 = await d.establish();
    const first = readUpload(d.uploads[0]);
    assert.equal(first.elements, 2);
    const packed = Buffer.from(old.packed, "base64");
    assert.ok(d.distro.decrypt(first.sealed.subarray(16)).equals(packed.subarray(16)), "encrypted to D at build time");
    // Lost, then the next coming-up: the old builder encrypts it again.
    const pending = d.resources.shift();
    if (pending) pending.reject(new Error("failed")); else d.self._distroUploads.cut("the propagation link closed", link1);
    await tick();
    link1.status = 0x04;
    await d.establish();
    const second = readUpload(d.uploads[1]);
    assert.equal(second.elements, 2);
    assert.ok(!second.sealed.equals(first.sealed), "encrypted anew, as before");
});

/** The Harness errors the page recorded: [where, message]. */
const harnessErrors = (d) => d.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]);

test("a message that cannot be sealed is said as an error, recorded as a Harness error a staging stage counts, owed without a proof, and built as before", async () => {
    const d = device({ seal: () => { throw new Error("the distro identity has no private key: a sync proof needs D's signature"); } });
    await d.sendCopy();
    const [entry] = d.owed();
    assert.equal("sealed" in entry || "syncSig" in entry, false, "owed without them");
    assert.equal(d.errors().length, 1);
    assert.match(d.errors()[0], /could not be sealed for the distro sync proof \(the distro identity has no private key/);
    assert.deepEqual(harnessErrors(d), [["distro-sync-proof", "the distro identity has no private key: a sync proof needs D's signature"]],
        "exactly one, so a page that quietly stopped proving is seen");
    await d.establish();
    const upload = readUpload(d.uploads[0]);
    assert.equal(upload.elements, 2, "no proof");
    assert.ok(d.distro.decrypt(upload.sealed.subarray(16)).equals(Buffer.from(entry.packed, "base64").subarray(16)), "the legacy build");
});

test("a stored proof that is not the message's is never sent: said as an error, recorded as a Harness error, and the sealed message goes without it", async () => {
    const d = device();
    await d.sendCopy();
    const entry = d.owed()[0];
    d.env.DistroOutboxStore.put({ ...entry, syncSig: Buffer.alloc(64, 7).toString("base64") });
    await d.establish();
    const upload = readUpload(d.uploads[0]);
    assert.equal(upload.elements, 2, "no proof RFed would refuse");
    assert.ok(upload.sealed.equals(Buffer.from(entry.sealed, "base64")), "the sealed bytes, not encrypted again");
    assert.equal(d.errors().length, 1);
    assert.match(d.errors()[0], /The distro sync proof kept with this upload is not its own \(the sync claim is not this message's: signature invalid\)/);
    assert.deepEqual(harnessErrors(d), [["distro-sync-proof", "the sync claim is not this message's: signature invalid"]], "exactly one");
});

test("a stored pair that is broken (half of it, not base64, or without the distro's key: a corrupted row) costs the proof, never the message: it stays owed, goes as one owed before entries were sealed, and that is said and recorded (review of Retichat-js 7b69904)", async () => {
    for (const [why, broken] of [
        ["syncSig missing", (e) => { const { syncSig, ...rest } = e; return rest; }],
        ["sealed missing", (e) => { const { sealed, ...rest } = e; return rest; }],
        ["syncSig not base64", (e) => ({ ...e, syncSig: "not base64!" })],
        ["without the distro's key (the distro held is its own)", (e) => { const { distroKey, ...rest } = e; return rest; }],
    ]) {
        const d = device();
        await d.sendCopy();
        const entry = d.owed()[0];
        d.storage.sSet("distro_outbox_v1", [broken(entry)]);
        assert.equal(d.owed().length, 1, `${why}: still owed`);
        await d.establish();
        assert.equal(d.uploads.length, 1, `${why}: uploaded`);
        const upload = readUpload(d.uploads[0]);
        assert.equal(upload.elements, 2, `${why}: no proof`);
        assert.ok(d.distro.decrypt(upload.sealed.subarray(16)).equals(Buffer.from(entry.packed, "base64").subarray(16)), `${why}: the message, encrypted to D at build time`);
        assert.equal(d.errors().length, 1, why);
        assert.match(d.errors()[0], /The distro sync proof kept with the sent-copy for 01234567 \(§17\.11\) is broken \(half of it, not base64, or without the distro's key\): it goes without it, built as before/);
        assert.deepEqual(harnessErrors(d), [["distro-sync-proof", "the distro sync proof kept with the sent-copy for 01234567 (§17.11) is broken"]], `${why}: exactly one`);
        d.resources.shift()?.resolve();
        d.prove();
        await tick();
        assert.deepEqual(d.owed(), [], `${why}: proved, owed no more`);
    }
});

test("a sealed upload whose stamp cannot be computed is not built: nothing is sent, the failure is said, and the message stays owed for the next coming-up", async () => {
    const d = device({ stamps: () => null });
    await d.sendCopy();
    await d.establish();
    assert.deepEqual(d.uploads, [], "no stampless upload: the node would refuse it");
    assert.equal(d.owed().length, 1);
    assert.deepEqual(d.events.map((e) => [e.kind, e.detail.message]), [["error", "its propagation stamp could not be computed"]]);
    assert.equal(d.self._distroUnproved.size, 1, "recorded, so the next coming-up sends it");
});

test("the page's builder makes the golden vector's upload, byte for byte, from the stored sealed bytes and proof", async (t) => {
    const realNow = Date.now;
    Date.now = () => V.timebase * 1000;
    t.after(() => { Date.now = realNow; });
    const self = { _computePropagationStamp: async (data) => { assert.ok(Buffer.from(data).equals(SEALED), "mined over the sealed message"); return STAMP; } };
    const env = { Buffer, Identity, MsgPack, console: { log() {}, warn() {}, error() {} }, syncClaimFor, buildSealedUpload };
    const build = compile("async _buildPropagationPacked(lxmfPacked, peerPublicKeyHex, sealed = null, syncSig = null)", env)(self);
    const packed = hex(V.packed_hex);
    assert.equal((await build(packed, V.distro.public_key_hex, SEALED, SIG)).toString("hex"), V.envelope_hex);
    assert.equal((await build(packed, V.distro.public_key_hex, SEALED, null)).toString("hex"), V.envelope_legacy_hex);
});
