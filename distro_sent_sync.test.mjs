/**
 * REGRESSION GUARD — RFed SPEC §17.11 sent-message sync.
 *
 * A device that sends as its distro D also propagates a copy of the message
 * to D, marked 0xFB = "rfed.distro.sent", 0xFC = recipient, 0xFD = the
 * sending device's own lxmf.delivery address. RFed fans it out to every
 * device of D; each one stores it as an OUTGOING message in the conversation
 * with the recipient, except the sender, which recognises its own echo by
 * 0xFD. Without this, a message sent from the phone never appears on the
 * laptop, and the conversation there shows only the other side.
 *
 * These tests run the real shipped method bodies from app.js against stubs,
 * with real identities, real LXMF packing and real encryption.
 *
 * Run: node --test distro_sent_sync.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

function extractMethod(source, signature) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const bodyStart = source.indexOf("{", start + signature.length);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
            depth--;
            if (depth === 0) return source.slice(bodyStart + 1, i);
        }
    }
    throw new Error(`could not brace-match ${signature}`);
}

const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");

const R = "0123456789abcdef0123456789abcdef";          // the recipient
const OTHER_DEVICE = "fedcba9876543210fedcba9876543210"; // another device of D

// ── helper ──────────────────────────────────────────────────────────────────

test("constants match upstream LXMF and LXMF-rust distro.rs", () => {
    assert.equal(LXMF.FIELD_CUSTOM_TYPE, 0xFB);
    assert.equal(LXMF.FIELD_CUSTOM_DATA, 0xFC);
    assert.equal(LXMF.FIELD_CUSTOM_META, 0xFD);
    assert.equal(LXMF.DISTRO_SENT_TYPE, "rfed.distro.sent");
});

test("distroSentCopyFromFields reads a valid marker, str or bin", () => {
    const str = new Map([[0xFB, "rfed.distro.sent"], [0xFC, R], [0xFD, OTHER_DEVICE]]);
    assert.deepEqual(LXMF.distroSentCopyFromFields(str), { toHex: R, byHex: OTHER_DEVICE });
    const enc = (s) => new TextEncoder().encode(s);
    const bin = new Map([[0xFB, enc("rfed.distro.sent")], [0xFC, enc(R.toUpperCase())], [0xFD, enc(OTHER_DEVICE.toUpperCase())]]);
    assert.deepEqual(LXMF.distroSentCopyFromFields(bin), { toHex: R, byHex: OTHER_DEVICE }, "bin values, lowercased");
});

test("a bad 0xFC keeps the marker but has no recipient (drop, not today's path)", () => {
    for (const bad of ["abc", R + "00", "zz" + R.slice(2), "", null]) {
        const fields = new Map([[0xFB, "rfed.distro.sent"], [0xFD, OTHER_DEVICE]]);
        if (bad !== null) fields.set(0xFC, bad);
        assert.deepEqual(LXMF.distroSentCopyFromFields(fields), { toHex: null, byHex: OTHER_DEVICE }, `0xFC=${bad}`);
    }
    assert.deepEqual(LXMF.distroSentCopyFromFields(new Map([[0xFB, "rfed.distro.sent"], [0xFC, R]])),
        { toHex: R, byHex: "" }, "missing 0xFD is an empty sender, as in distro.rs");
});

test("other custom types and non-maps carry no marker", () => {
    assert.equal(LXMF.distroSentCopyFromFields(new Map([[0xFB, "rfed.distro.transfer"], [0xFC, R], [0xFD, OTHER_DEVICE]])), null);
    assert.equal(LXMF.distroSentCopyFromFields(new Map([[0xFC, R], [0xFD, OTHER_DEVICE]])), null);
    assert.equal(LXMF.distroSentCopyFromFields(new Map()), null);
    assert.equal(LXMF.distroSentCopyFromFields(null), null);
    assert.equal(LXMF.distroSentCopyFromFields(undefined), null);
    assert.equal(LXMF.distroSentCopyFromFields({ 0xFB: "rfed.distro.sent" }), null);
});

// ── send ────────────────────────────────────────────────────────────────────

test("sendMessage sends the copy once, only when sending as the distro to someone else", () => {
    const body = extractMethod(app, "sendMessage(contact, content)");
    const calls = body.match(/_sendDistroSentCopy\(/g) || [];
    assert.equal(calls.length, 1, "exactly one call site in sendMessage");
    assert.match(body, /if \(sender\.isDistro && contact\.destHash !== sender\.hash\) \{\s*this\._sendDistroSentCopy\(contact\.destHash, "", content\)/);
    const copyAt = body.indexOf("_sendDistroSentCopy(");
    assert.ok(copyAt < body.indexOf("setTimeout("), "sent before, not inside, the propagation fallback timer");
    // After, not before, M's dispatch: a _sendPacket that throws ends
    // sendMessage before the copy starts, so siblings never show a message
    // that never left.
    assert.ok(copyAt > body.indexOf("this._sendPacket("), "sent only after the direct dispatch returned");
    // No other path that can re-send the same message may copy it again.
    for (const sig of ["async _flushPropagation()", "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
        "_sendOverPeerLink(contactHash, publicKeyHex, packed, representation, messageId, onProof, onError)", "_sendDistroViaLxmf()"]) {
        assert.doesNotMatch(extractMethod(app, sig), /_sendDistroSentCopy|DISTRO_SENT_TYPE/, `${sig} must not copy`);
    }
    assert.equal((app.match(/_sendDistroSentCopy\(/g) || []).length, 2, "one definition, one call");
});

function makeSend({ distro, deviceHash }) {
    const body = extractMethod(app, "async _sendDistroSentCopy(recipientHex, title, content)");
    const sent = [];
    const link = { send: (d) => { sent.push({ kind: "packet", data: d }); return {}; },
        sendResource: async (d) => { sent.push({ kind: "resource", data: d }); } };
    const self = {
        ownHash: deviceHash,
        _whenPropagationLinkUp: async () => link,
        _ensurePropagationLink: async () => { throw new Error("the copy must not start the propagation link"); },
        // Identity passthrough so the test can read the LXMF bytes back.
        _buildPropagationPacked: async (packed, pubKeyHex) => { self.encryptedTo = pubKeyHex; return packed; },
    };
    const DistroManager = distro
        ? { has: true, identity: distro, lxmfDeliveryHash: lxmfHash(distro), pubKey: distro.getPublicKey().toString("hex") }
        : { has: false, identity: null, lxmfDeliveryHash: null, pubKey: null };
    const Harness = { event() {}, error() {} };
    const Link = { MDU: 100000 };
    const fn = new Function("DistroManager", "LXMessage", "LXMF", "Buffer", "Link", "Harness", "self", "recipientHex", "title", "content",
        `return (async () => {${body.replaceAll("this.", "self.")}})();`);
    return { run: (to, content) => fn(DistroManager, LXMessage, LXMF, Buffer, Link, Harness, self, to, "", content), sent, self };
}

test("the copy is D→D, signed by D, with 0xFB/0xFC/0xFD, propagated to D", async () => {
    const distro = Identity.create();
    const D = lxmfHash(distro);
    const { run, sent, self } = makeSend({ distro, deviceHash: OTHER_DEVICE });
    await run(R, "hello from the phone");
    assert.equal(sent.length, 1, "one upload");
    assert.equal(self.encryptedTo, distro.getPublicKey().toString("hex"), "encrypted to D");
    const packed = sent[0].data;
    assert.equal(packed.subarray(0, 16).toString("hex"), D, "destination D");
    assert.equal(packed.subarray(16, 32).toString("hex"), D, "source D");
    const payload = packed.subarray(96);
    const hashed = Buffer.concat([packed.subarray(0, 32), payload]);
    assert.ok(distro.validate(packed.subarray(32, 96), Buffer.concat([hashed, Cryptography.fullHash(hashed)])), "signed with D's key");
    const [, title, content, fields] = MsgPack.unpack(payload);
    assert.equal(Buffer.from(title).toString(), "");
    assert.equal(Buffer.from(content).toString(), "hello from the phone");
    assert.equal(fields.get(0xFB), "rfed.distro.sent");
    assert.equal(fields.get(0xFC), R);
    assert.equal(fields.get(0xFD), OTHER_DEVICE);
    assert.equal(fields.has(0x0C), false, "no ticket: no delivery notification for the copy");
});

test("the copy waits for the propagation link and never starts it", () => {
    // Starting the link runs _flushPropagation(), which would re-propagate
    // the original message while its direct attempt is still in flight.
    const body = extractMethod(app, "async _sendDistroSentCopy(recipientHex, title, content)");
    assert.doesNotMatch(body, /_ensurePropagationLink|_establishPropagationLink/);
    assert.match(body, /await this\._whenPropagationLinkUp\(recipientHex\)/);
    const wait = extractMethod(app, "_whenPropagationLinkUp(recipientHex)");
    assert.doesNotMatch(wait, /_ensurePropagationLink|_establishPropagationLink/);
    const establish = extractMethod(app, "_establishPropagationLink()");
    assert.match(establish, /this\._propLinkUpWaiters\.splice\(0\)[\s\S]*waiter\.resolve\(link\)/, "released when the link comes up");
});

test("no copy without a distro, or to the distro itself", async () => {
    const none = makeSend({ distro: null, deviceHash: OTHER_DEVICE });
    await none.run(R, "x");
    assert.equal(none.sent.length, 0);
    const distro = Identity.create();
    const self = makeSend({ distro, deviceHash: OTHER_DEVICE });
    await self.run(lxmfHash(distro), "x");
    assert.equal(self.sent.length, 0);
});

// ── receive ─────────────────────────────────────────────────────────────────

function blobFor(distro, { signer = distro, fields, content = "hi there" }) {
    const D = Buffer.from(lxmfHash(distro), "hex");
    const msg = new LXMessage();
    msg.sourceHash = Buffer.from(lxmfHash(signer), "hex");
    msg.destinationHash = D;
    msg.title = "";
    msg.content = content;
    msg.fields = fields;
    const packed = msg.pack(signer, false);
    return Buffer.concat([D, distro.encrypt(packed.subarray(16))]);
}

function makeReceiver(distro, deviceHash) {
    const body = extractMethod(app, "_handleDistroBlob(distroHash, blob)");
    const stored = [];
    const contacts = new Set();
    const seen = new Set();
    const MsgStore = { add: (hash, m) => { const s = { id: String(stored.length), timestamp: -1, ...m }; stored.push({ hash, msg: s }); return s; } };
    const ContactStore = { isContact: (h) => contacts.has(h), add: (h) => contacts.add(h), touch() {} };
    const DistroSeen = { check: (k) => { if (seen.has(k)) return true; seen.add(k); return false; } };
    const Harness = { event() {}, error() {} };
    const DistroManager = { identity: distro, lxmfDeliveryHash: lxmfHash(distro) };
    const events = [];
    const self = {
        ownHash: deviceHash,
        _pendingTickets: new Map(),
        _onMsg: [(m, peer) => events.push({ m, peer })],
        _ticketFromFields: () => null,
    };
    const fn = new Function("DistroManager", "MsgPack", "Buffer", "DistroSeen", "Harness", "ContactStore", "MsgStore",
        "LXMF", "Cryptography", "ownLxmfDestinationHash", "self", "distroHash", "blob",
        `${body.replaceAll("this.", "self.")}`);
    const run = (blob) => fn(DistroManager, MsgPack, Buffer, DistroSeen, Harness, ContactStore, MsgStore,
        LXMF, Cryptography, () => deviceHash, self, null, blob);
    return { run, stored, contacts, events };
}

const marker = (to, by) => new Map([[0xFB, "rfed.distro.sent"], [0xFC, to], [0xFD, by]]);
const ME = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

test("another device's copy is stored as OUTGOING in the conversation with R", () => {
    const distro = Identity.create();
    const D = lxmfHash(distro);
    const rx = makeReceiver(distro, ME);
    const blob = blobFor(distro, { fields: marker(R, OTHER_DEVICE), content: "sent on the phone" });
    const before = Date.now();
    assert.equal(rx.run(blob), true);
    assert.equal(rx.stored.length, 1);
    const { hash, msg } = rx.stored[0];
    assert.equal(hash, R, "the conversation with the recipient, not with D");
    assert.equal(msg.dir, "out");
    assert.equal(msg.status, "sent", "never delivered/proved");
    assert.equal(msg.srcHash, D, "from the distro, i.e. me");
    assert.equal(msg.via, "distro");
    assert.equal(msg.content, "sent on the phone");
    assert.ok(Math.abs(msg.timestamp - before) < 5000, "the copy's LXMF timestamp, in ms");
    assert.ok(rx.contacts.has(R), "conversation created");
    assert.equal(rx.events.length, 1);
    assert.equal(rx.events[0].peer, R);

    assert.equal(rx.run(blob), true, "stream + pull of the same copy");
    assert.equal(rx.stored.length, 1, "stored once");
});

test("this device's own echo is dropped (and deduped)", () => {
    const distro = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { fields: marker(R, ME) })), true);
    assert.equal(rx.stored.length, 0);
    assert.equal(rx.events.length, 0);
});

test("a copy with a malformed 0xFC is dropped", () => {
    const distro = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { fields: marker("not-a-hash", OTHER_DEVICE) })), true);
    assert.equal(rx.stored.length, 0);
});

test("the marker from a source other than our distro is ignored", () => {
    const distro = Identity.create();
    const stranger = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { signer: stranger, fields: marker(R, OTHER_DEVICE) })), true);
    assert.equal(rx.stored.length, 0);
});

test("a copy claiming source D without D's signature is dropped", () => {
    const distro = Identity.create();
    const forger = Identity.create();
    const D = Buffer.from(lxmfHash(distro), "hex");
    const msg = new LXMessage();
    msg.sourceHash = D; msg.destinationHash = D; msg.title = ""; msg.content = "forged";
    msg.fields = marker(R, OTHER_DEVICE);
    const packed = msg.pack(forger, false);
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(Buffer.concat([D, distro.encrypt(packed.subarray(16))])), true);
    assert.equal(rx.stored.length, 0);
});

test("a fan-out message without the marker keeps today's behaviour", () => {
    const distro = Identity.create();
    const sender = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { signer: sender, fields: new Map(), content: "hello D" })), true);
    assert.equal(rx.stored.length, 1);
    assert.equal(rx.stored[0].hash, lxmfHash(sender));
    assert.equal(rx.stored[0].msg.dir, "in");
    assert.equal(rx.stored[0].msg.status, "delivered");
});
