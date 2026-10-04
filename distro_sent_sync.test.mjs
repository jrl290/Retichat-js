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
import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import { decodePayload as decodeDisplayName } from "./lib/display_name.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { DistroUploads } from "./lib/distro_upload.js";
import { DistroOutbox, UnprovedUploads, channelSyncEntryId, sentCopyEntryId } from "./lib/distro_outbox.js";
import { install, memoryStorage } from "./test_app_source.mjs";

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

test("a DM's dispatch sends the copy once, only when sending as the distro to someone else", () => {
    // _dispatchMessage holds the send path since sends made before
    // initialization are queued: sendMessage dispatches at once when it can,
    // _dispatchQueued dispatches each queued record once when it can't.
    const body = extractMethod(app, "_dispatchMessage(contact, outMsg)");
    const calls = body.match(/_sendDistroSentCopy\(/g) || [];
    assert.equal(calls.length, 1, "exactly one call site in _dispatchMessage");
    assert.match(body, /if \(sender\.isDistro && contact\.destHash !== sender\.hash\) \{\s*this\._sendDistroSentCopy\(contact\.destHash, "", content\)/);
    const copyAt = body.indexOf("_sendDistroSentCopy(");
    assert.ok(copyAt < body.indexOf("setTimeout("), "sent before, not inside, the propagation fallback timer");
    // After, not before, M's dispatch: a _sendPacket that throws ends
    // _dispatchMessage before the copy starts, so siblings never show a
    // message that never left.
    assert.ok(copyAt > body.indexOf("this._sendPacket("), "sent only after the direct dispatch returned");
    // One dispatch per user message, from either entry point.
    for (const sig of ["sendMessage(contact, content, attachments = [])", "_dispatchQueued()"]) {
        assert.equal((extractMethod(app, sig).match(/this\._dispatchMessage\(/g) || []).length, 1, `${sig} dispatches once`);
    }
    // No other path that can re-send the same message may copy it again.
    for (const sig of ["sendMessage(contact, content, attachments = [])", "_dispatchQueued()", "async _propagateMessage(contact, outMsg)",
        "async _flushPropagation()", "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
        "_sendOverPeerLink(contactHash, publicKeyHex, packed, representation, messageId, onProof, onError)", "_sendDistroViaLxmf()"]) {
        assert.doesNotMatch(extractMethod(app, sig), /_sendDistroSentCopy|DISTRO_SENT_TYPE/, `${sig} must not copy`);
    }
    assert.equal((app.match(/_sendDistroSentCopy\(/g) || []).length, 2, "one definition, one call");
});

/** Every macrotask queued before this one has run. */
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * The shipped send path of the copy: _sendDistroSentCopy owes it to the
 * distro (lib/distro_outbox.js), and it goes on the propagation link when
 * the link is up (`linkUp`) or when it comes up (`up()`, the "established"
 * handler's _sendDistroOutbox).
 */
function makeSend({ distro, deviceHash, proofs = "auto", linkUp = true }) {
    const sent = [];
    const events = [];
    const storage = memoryStorage();
    // The propagation link, as _uploadForDistro uses it: a packet is built
    // (newLinkPacket), transmitted, and proved by the node at once
    // (`proofs: "auto"`) or when the test calls prove().
    const link = {
        status: Link.ACTIVE,
        newLinkPacket: (context, data) => ({ packetHash: Cryptography.fullHash(Buffer.from(data)), pack: () => Buffer.from(data) }),
        _transmit: (raw) => {
            sent.push({ kind: "packet", data: raw });
            if (proofs === "auto") queueMicrotask(prove);
            return raw;
        },
        sendResource: async (d) => { sent.push({ kind: "resource", data: d }); },
    };
    const self = {
        ownHash: deviceHash,
        _propLink: linkUp ? link : null,
        _distroOutboxInFlight: new Map(),
        _propComingUps: 0,
        _distroUnproved: new UnprovedUploads(),
        _ensurePropagationLink: async () => { throw new Error("the copy must not start the propagation link"); },
        _establishPropagationLink: () => { throw new Error("the copy must not start the propagation link"); },
        // Identity passthrough so the test can read the LXMF bytes back.
        _buildPropagationPacked: async (packed, pubKeyHex) => { self.encryptedTo = pubKeyHex; return packed; },
        _pendingPacketHashes: new Map(),
        _distroUploads: new DistroUploads({ log: { error() {}, warn() {} } }),
    };
    /** The propagation node's proof of the last upload packet. */
    function prove() {
        const [key, pending] = [...self._pendingPacketHashes].at(-1) ?? [];
        if (!pending) return false;
        self._pendingPacketHashes.delete(key);
        pending.onProof(pending.messageId);
        return true;
    }
    const DistroManager = distro
        ? { has: true, identity: distro, lxmfDeliveryHash: lxmfHash(distro), pubKey: distro.getPublicKey().toString("hex") }
        : { has: false, identity: null, lxmfDeliveryHash: null, pubKey: null };
    const Harness = {
        event: (kind, detail) => events.push({ kind, detail }),
        error: (where, e) => events.push({ kind: "error", detail: { where, message: e.message } }),
    };
    const quiet = { log() {}, warn() {}, error() {} };
    const env = {
        DistroManager, LXMessage, LXMF, Buffer, Cryptography, Packet, Harness, console: quiet,
        Link: { MDU: 100000, ACTIVE: Link.ACTIVE },
        DistroOutboxStore: new DistroOutbox({ get: storage.sGet, set: storage.sSet }), sentCopyEntryId, channelSyncEntryId,
    };
    install(self, env, [
        "async _sendDistroSentCopy(recipientHex, title, content)", "_oweDistro(entry)", "async _sendDistroOutbox(link, trigger)",
        "_distroAttemptOpen(entry, link)", "_unprovedSince(entry, comingUp)", "async _uploadOwed(link, entry, comingUp = null)", "_stillOwed(entry)",
        "_dropMembershipOwedToOtherDistros()", "_distroOwedOutcome(entry, how, error, goesNow = false)", "_uploadForDistro(link, propagationPacked, label)",
    ]);
    return {
        run: async (to, content) => { await self._sendDistroSentCopy(to, "", content); await tick(); },
        /** The propagation link comes up: its "established" handler sends what is owed. */
        up: async () => { self._propLink = link; await self._sendDistroOutbox(link, "established"); await tick(); },
        owed: () => env.DistroOutboxStore.list(),
        sent, self, events, prove,
    };
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

test("the copy is said propagated when the propagation node proves it, never when its packet is queued", async () => {
    // Review of 69ff01e (2026-10-03), CHECK_THESE_THINGS_FIRST §14: until
    // then the log said "propagated" and "distro-sent-copy" fired as soon as
    // link.send queued the packet, with nothing watching for the proof.
    const distro = Identity.create();
    const send = makeSend({ distro, deviceHash: OTHER_DEVICE, proofs: "manual" });
    await send.run(R, "hello");
    assert.equal(send.sent.length, 1, "uploaded");
    assert.deepEqual(send.events, [], "not propagated while unproved");
    assert.equal(send.owed().length, 1, "owed until the node proves it");
    assert.equal(send.prove(), true);
    await tick();
    assert.deepEqual(send.events, [{ kind: "distro-sent-copy", detail: { to: R.slice(0, 12), how: "packet" } }]);
    assert.deepEqual(send.owed(), []);
});

test("with no propagation link up the copy is owed, never lost and never a reason to start the link; it goes when the link comes up", async () => {
    // Review of 9f058e9 (2026-10-03): the copy waited in memory on
    // _whenPropagationLinkUp, which rejected at once while the propagation
    // node's key was unknown and was rejected by disconnect(), so it was
    // lost and the sibling never showed the message.
    const distro = Identity.create();
    const send = makeSend({ distro, deviceHash: OTHER_DEVICE, linkUp: false });
    await send.run(R, "while the link is down");
    assert.deepEqual([send.sent.length, send.owed().length, send.events], [0, 1, []]);
    await send.up();
    assert.equal(send.sent.length, 1);
    assert.equal(Buffer.from(MsgPack.unpack(send.sent[0].data.subarray(96))[2]).toString(), "while the link is down");
    await tick();
    assert.deepEqual(send.owed(), []);
    assert.deepEqual(send.events.map((e) => e.kind), ["distro-sent-copy"]);
});

test("the copy waits for the propagation link and never starts it: the link's own events send it", () => {
    // When M's propagation link comes up is M's own fallback timer's call.
    // (Starting it once meant a flush that re-propagated M inside its direct
    // window; _flushPropagation now uploads only parked copies.)
    for (const sig of ["async _sendDistroSentCopy(recipientHex, title, content)", "_oweDistro(entry)", "async _sendDistroOutbox(link, trigger)",
        "async _uploadOwed(link, entry, comingUp = null)", "_uploadForDistro(link, propagationPacked, label)"]) {
        assert.doesNotMatch(extractMethod(app, sig), /_ensurePropagationLink|_establishPropagationLink/, sig);
    }
    assert.match(extractMethod(app, "async _sendDistroSentCopy(recipientHex, title, content)"), /this\._oweDistro\(\{/);
    assert.doesNotMatch(app, /_whenPropagationLinkUp|_propLinkUpWaiters/, "nothing waits in memory for the link any more");
    // "established": after identify, with the parked DM copies.
    assert.match(extractMethod(app, "async _onPropagationLinkEstablished(link)"),
        /this\._flushPropagation\(\);\s*this\._sendDistroOutbox\(link, "established"\);/);
    // "recovered" (STALE -> ACTIVE), on the current link only: makePropagationLink below.
    assert.match(extractMethod(app, "_establishPropagationLink()"), /this\._sendDistroOutbox\(link, "recovered"\)/);
});

/**
 * `source` with its comments taken out and nothing else: strings, template
 * literals and regular expression literals are kept as they are, so what is
 * left is what the code says, not what its comments say about it. A "/"
 * begins a regular expression where an expression may begin (after an
 * operator, a bracket or a keyword), as a JavaScript parser decides it.
 */
function withoutComments(source) {
    const n = source.length;
    let i = 0, out = "", last = "", word = "";
    const regexMayFollow = () => /[\w$]/.test(last)
        ? /^(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(word)
        : last === "" || "(,=:[!&|?{};+-*%<>~^}".includes(last);
    const literal = (start) => { out += source.slice(start, i); last = "\""; word = ""; };
    const string = (quote) => {
        const start = i++;
        while (i < n && source[i] !== quote) i += source[i] === "\\" ? 2 : 1;
        i++;
        literal(start);
    };
    const regex = () => {
        const start = i++;
        let inClass = false;
        for (; source[i] !== "/" || inClass; i++) {
            if (i >= n || source[i] === "\n") throw new Error(`an unterminated regular expression at ${start}`);
            if (source[i] === "\\") i++;
            else if (source[i] === "[") inClass = true;
            else if (source[i] === "]") inClass = false;
        }
        i++;
        while (/[a-z]/.test(source[i] ?? "")) i++;
        literal(start);
    };
    const template = () => {
        out += source[i++];
        while (i < n && source[i] !== "`") {
            if (source[i] === "\\") { out += source.slice(i, i + 2); i += 2; }
            else if (source[i] === "$" && source[i + 1] === "{") { out += "${"; i += 2; last = "{"; word = ""; code(true); out += "}"; i++; }
            else out += source[i++];
        }
        out += "`"; i++;
        last = "\""; word = "";
    };
    const code = (inPlaceholder) => {
        let depth = 0;
        while (i < n) {
            const c = source[i], next = source[i + 1];
            if (c === "/" && next === "/") { while (i < n && source[i] !== "\n") i++; }
            else if (c === "/" && next === "*") {
                const end = source.indexOf("*/", i + 2);
                if (end === -1) throw new Error(`an unterminated comment at ${i}`);
                out += " ";
                i = end + 2;
            }
            else if (c === "'" || c === "\"") string(c);
            else if (c === "`") template();
            else if (c === "/" && regexMayFollow()) regex();
            else {
                if (inPlaceholder && c === "{") depth++;
                if (inPlaceholder && c === "}") { if (depth === 0) return; depth--; }
                out += c;
                i++;
                if (!/\s/.test(c)) { word = /[\w$]/.test(c) ? (/[\w$]/.test(last) ? word + c : c) : ""; last = c; }
            }
        }
    };
    code(false);
    return out;
}

/**
 * The body of the listener `source` registers with `link.on("<event>", () => {`,
 * which must be there exactly once.
 */
function linkListener(source, event) {
    const opener = `link.on("${event}", () => {`;
    const start = source.indexOf(opener);
    assert.notEqual(start, -1, `no ${opener}`);
    assert.equal(source.indexOf(opener, start + 1), -1, `a second ${opener}`);
    let depth = 0;
    for (let i = start + opener.length - 1; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}" && --depth === 0) return source.slice(start + opener.length, i);
    }
    throw new Error(`could not brace-match ${opener}`);
}

test("_sendDistroOutbox runs when the propagation link comes up and at no other time: 'established' and the current link's 'recovered' are its only callers, directly or through the 'established' work", async () => {
    // Each call is one coming-up (_propComingUps) and lets every upload whose
    // failure was recorded before it go again, so a third caller would send
    // an upload again on the strength of its own failure (James, 2026-10-03;
    // DESIGN_PRINCIPLES §3, what a device owes its distro). Review of 74fbbcd
    // (RV2b): the test above checks only that the two calls are there, and a
    // third, on page resume, passed every test. Review of 9d45faa (RW2):
    // counting the flush's own name let a caller in one step away, through
    // _onPropagationLinkEstablished, which runs the flush every time; a
    // propagation announce that re-ran it while the link was up passed every
    // test. So the 'established' work is pinned as the flush is, the two
    // calls must sit in the listeners of the link they belong to, and only
    // the Link fires those two events. What this cannot see is a call that
    // never writes these names whole: one assembled at run time
    // ("_send" + "DistroOutbox") or found by reflection.
    const code = withoutComments(app);
    // Only the comments are gone: what is left still parses, and keeps the
    // code's strings.
    const check = spawnSync(process.execPath, ["--input-type=module", "--check"], { input: code, encoding: "utf8" });
    assert.equal(check.status, 0, `app.js without its comments does not parse: ${check.stderr}`);
    assert.doesNotMatch(code, /NEVER REMOVE/);
    assert.match(code, /"it goes when the propagation link is next up \(DESIGN_PRINCIPLES §3, the distro exception\)"/);
    assert.match(code, /\n {4}async _sendDistroOutbox\(link, trigger\) \{/);
    assert.equal(code.match(/_sendDistroOutbox/g).length, 3, "the method and its two calls: nothing else names it");
    assert.match(code, /\n {4}async _onPropagationLinkEstablished\(link\) \{/);
    assert.equal(code.match(/_onPropagationLinkEstablished/g).length, 2,
        "the 'established' work and its one call, from the link's \"established\": nothing else names it, as it runs the flush");
    assert.equal(extractMethod(code, "async _onPropagationLinkEstablished(link)").match(/_sendDistroOutbox/g)?.length, 1);
    const establish = extractMethod(code, "_establishPropagationLink()");
    assert.match(establish, /\n {8}const link = new Link\(\);\n/, "the listeners are the new link's own");
    assert.equal(establish.match(/_sendDistroOutbox/g)?.length, 1);
    assert.equal(linkListener(establish, "established").match(/this\._onPropagationLinkEstablished\(link\);/g)?.length, 1,
        "the 'established' work runs from the link's \"established\" listener");
    assert.equal(linkListener(establish, "recovered").match(/this\._sendDistroOutbox\(link, "recovered"\);/g)?.length, 1,
        "the flush runs from the link's \"recovered\" listener");
    // Only the Link fires "established" and "recovered" (lib/rns/link.js):
    // once its handshake completes, as initiator or as responder, and when a
    // STALE link hears from its peer (_recoverIfStale). The page fires no
    // event of a link to run those listeners again, nor reaches into them.
    const fired = [...code.matchAll(/\.\s*emit\s*(\?\.)?\s*\(\s*([^,)]*)/g)].map((m) => m[2].trim());
    assert.equal(fired.length, code.match(/\.\s*emit\b/g).length, "every .emit in app.js is called, with its event named");
    assert.ok(fired.length > 0 && fired.every((name) => /^"[\w-]+"$/.test(name) && !["\"established\"", "\"recovered\""].includes(name)),
        `app.js fires only named events other than a link's coming up: ${fired.join(", ")}`);
    assert.doesNotMatch(code, /eventListenersMap/);
    const lib = new URL("./lib/", import.meta.url);
    const scripts = (await readdir(lib, { recursive: true })).filter((f) => f.endsWith(".js"));
    assert.ok(scripts.includes("distro_upload.js") && scripts.includes("rns/link.js"));
    for (const file of scripts) {
        const source = withoutComments(await readFile(new URL(file, lib), "utf8"));
        // Nor does any other script of the page name the flush or the work.
        assert.doesNotMatch(source, /_sendDistroOutbox|_propComingUps|_onPropagationLinkEstablished/, `lib/${file}`);
        const comingUp = { established: source.match(/\bemit\(\s*["']established["']/g)?.length ?? 0,
                           recovered: source.match(/\bemit\(\s*["']recovered["']/g)?.length ?? 0 };
        assert.deepEqual(comingUp, file === "rns/link.js" ? { established: 2, recovered: 1 } : { established: 0, recovered: 0 },
            `lib/${file} fires a link's coming up only where the Link comes up`);
    }
    for (const page of ["index.html", "debug.html", "debug-standalone.html"]) {
        assert.doesNotMatch(await readFile(new URL(`./${page}`, import.meta.url), "utf8"),
            /_sendDistroOutbox|_propComingUps|_onPropagationLinkEstablished/, page);
    }
});

// Link events are delivered on a later macrotask (utils/events.js defers every
// listener with setTimeout 0). A timer queued after the event has fired runs
// after its listeners, so awaiting one observes their effects deterministically.
const afterLinkEvents = () => new Promise((resolve) => setTimeout(resolve, 0));

function makePropagationLink() {
    const establish = extractMethod(app, "_establishPropagationLink()");
    // The real Link and its real onPacket; only the wire handshake is skipped,
    // since establishment itself is not what is under test.
    class OfflineLink extends Link {
        establish() { this.initiator = true; this.status = Link.PENDING; }
    }
    const pn = Identity.create();
    const flushes = [];
    const self = {
        _cfg: { propagationNodePubKey: pn.getPublicKey().toString("hex"), propagationNodeHash: "b".repeat(32) },
        _rns: { registerDestination: () => ({}) },
        _propLink: null,
        _propLinkPromise: null,
        _distroUploads: new DistroUploads({ log: { error() {}, warn() {} } }),
        _sendDistroOutbox: (link, trigger) => { flushes.push([trigger, link]); },
        // The 'established' work runs the flush (_onPropagationLinkEstablished).
        _onPropagationLinkEstablished: (link) => { flushes.push(["established", link]); },
        _onPropagationLinkClosed() {},
    };
    new Function("Identity", "Buffer", "Destination", "Link", "self", establish.replaceAll("this.", "self."))(
        Identity, Buffer, Destination, OfflineLink, self);
    return { self, flushes };
}

/** Run `fn` with console.log silenced (the link lifecycle logs each event). */
async function hushed(fn) {
    const realLog = console.log;
    console.log = () => {};
    try { await fn(); } finally { console.log = realLog; }
}

test("a recovery of a link that is no longer the propagation link sends nothing", async () => {
    const { self, flushes } = makePropagationLink();
    const old = self._propLink;
    old.status = Link.STALE;
    old.staleSince = Date.now();
    // A new link attempt replaced it before the old one heard from the PN.
    self._propLink = { status: Link.PENDING };
    await hushed(async () => {
        old.onPacket({ context: Packet.KEEPALIVE, data: Buffer.from([0xFE]) });
        await afterLinkEvents();
    });
    assert.deepEqual(flushes, [], "what is owed waits for the current link's \"established\"");
});

test("what the distro is owed goes when a STALE propagation link recovers", async () => {
    const { self, flushes } = makePropagationLink();
    const link = self._propLink;
    assert.ok(link instanceof Link, "the real Link class");
    // Established earlier, then quiet for staleTime: the keepalive watchdog
    // marked it STALE.
    link.status = Link.STALE;
    link.staleSince = Date.now();
    // The PN answers a keepalive. Link.onPacket takes the link straight back
    // to ACTIVE, with no re-establishment, so "established" never fires.
    await hushed(async () => {
        link.onPacket({ context: Packet.KEEPALIVE, data: Buffer.from([0xFE]) });
        assert.equal(link.status, Link.ACTIVE);
        await afterLinkEvents();
    });
    assert.deepEqual(flushes, [["recovered", link]], "sent on the recovery, not left for a re-establishment that may never come");
});

test("the propagation link's 'established' runs the 'established' work once, and its recovery only the flush; making the link runs neither", async () => {
    // Review of 9d45faa (RW2): the 'established' work runs the flush, so it
    // runs on the link's establishment and nothing else.
    const { self, flushes } = makePropagationLink();
    const link = self._propLink;
    assert.deepEqual(flushes, [], "nothing runs until the link comes up");
    await hushed(async () => {
        link.status = Link.ACTIVE;
        link.emit("established");
        await afterLinkEvents();
    });
    assert.deepEqual(flushes, [["established", link]]);
    await hushed(async () => {
        link.status = Link.STALE;
        link.staleSince = Date.now();
        link.onPacket({ context: Packet.KEEPALIVE, data: Buffer.from([0xFE]) });
        await afterLinkEvents();
    });
    assert.deepEqual(flushes, [["established", link], ["recovered", link]]);
});

test("the propagation link's close decides the uploads made on it lost, and only those; a superseded link's too", async () => {
    // Review of 9f058e9 (2026-10-03): no proof can come over a closed link,
    // and nothing decided such an upload, so its §1 watch fired 5 s later
    // saying the proof or the exchange would decide it.
    const outcome = (u) => u.outcome.then(() => "proved", (e) => `lost: ${e.message}`);
    const { self } = makePropagationLink();
    const link = self._propLink;
    const onIt = self._distroUploads.track("the join of #x (§17.12)", link);
    const elsewhere = self._distroUploads.track("the sent-copy for 01234567 (§17.11)", { other: true });
    self._distroUploads.left(onIt);
    await hushed(async () => {
        link.status = Link.CLOSED;
        link._linkClosed();
        await afterLinkEvents();
    });
    assert.equal(await outcome(onIt), "lost: the propagation link closed before the propagation node proved it");
    assert.equal(onIt.watch, null, "its §1 watch stopped");
    assert.equal(elsewhere.settled, null, "an upload on another link is not this close's");

    // A STALE link replaced by a new attempt closes later, superseded.
    const { self: s2 } = makePropagationLink();
    const old = s2._propLink;
    const upload = s2._distroUploads.track("the leave of #y (§17.12)", old);
    s2._propLink = { status: Link.PENDING };
    await hushed(async () => {
        old.status = Link.CLOSED;
        old._linkClosed();
        await afterLinkEvents();
    });
    assert.equal(await outcome(upload), "lost: the propagation link closed before the propagation node proved it");
});

test("no copy without a distro, or to the distro itself", async () => {
    const none = makeSend({ distro: null, deviceHash: OTHER_DEVICE });
    await none.run(R, "x");
    assert.equal(none.sent.length, 0);
    assert.deepEqual(none.owed(), []);
    const distro = Identity.create();
    const self = makeSend({ distro, deviceHash: OTHER_DEVICE });
    await self.run(lxmfHash(distro), "x");
    assert.equal(self.sent.length, 0);
    assert.deepEqual(self.owed(), []);
});

// ── receive ─────────────────────────────────────────────────────────────────

// LXMessage.pack() stamps Date.now() / 1000 as the LXMF timestamp. Pinning it
// lets a test tell the copy's own timestamp from the moment it arrived, and
// know the src:ts key the receiver dedupes on.
function packAt(timestampMs, pack) {
    const realNow = Date.now;
    Date.now = () => timestampMs;
    try { return pack(); } finally { Date.now = realNow; }
}

function blobFor(distro, { signer = distro, fields, content = "hi there", timestampMs = Date.now() }) {
    const D = Buffer.from(lxmfHash(distro), "hex");
    const msg = new LXMessage();
    msg.sourceHash = Buffer.from(lxmfHash(signer), "hex");
    msg.destinationHash = D;
    msg.title = "";
    msg.content = content;
    msg.fields = fields;
    const packed = packAt(timestampMs, () => msg.pack(signer, false));
    return Buffer.concat([D, distro.encrypt(packed.subarray(16))]);
}

function makeReceiver(distro, deviceHash) {
    const body = extractMethod(app, "_handleDistroBlob(distroHash, blob)");
    const stored = [];
    const contacts = new Set();
    const seen = new Set();
    const MsgStore = { add: (hash, m) => { const s = { id: String(stored.length), timestamp: -1, ...m }; stored.push({ hash, msg: s }); return s; } };
    // The rows the receiver keeps: keep() only, a hidden row (James,
    // 2026-10-02: a distro message makes no contact); no add() to call.
    const ContactStore = { keep: (h) => contacts.add(h), touch() {}, acceptMessageName() { return false; } };
    const DistroSeen = { check: (k) => { if (seen.has(k)) return true; seen.add(k); return false; }, forget: (k) => seen.delete(k) };
    const harness = [];
    const Harness = { event: (name, data) => harness.push({ name, data }), error() {} };
    const DistroManager = { identity: distro, lxmfDeliveryHash: lxmfHash(distro) };
    const events = [];
    const self = {
        ownHash: deviceHash,
        _pendingTickets: new Map(),
        _onMsg: [(m, peer) => events.push({ m, peer })],
    };
    const fn = new Function("DistroManager", "MsgPack", "Buffer", "DistroSeen", "Harness", "ContactStore", "MsgStore",
        "LXMF", "Cryptography", "ownLxmfDestinationHash", "LXMessage", "decodeDisplayName", "sentTimeMs", "self", "distroHash", "blob",
        `${body.replaceAll("this.", "self.")}`);
    const run = (blob) => fn(DistroManager, MsgPack, Buffer, DistroSeen, Harness, ContactStore, MsgStore,
        LXMF, Cryptography, () => deviceHash, LXMessage, decodeDisplayName, sentTimeMs, self, null, blob);
    return { run, stored, contacts, events, seen, harness };
}

const marker = (to, by) => new Map([[0xFB, "rfed.distro.sent"], [0xFC, to], [0xFD, by]]);
const ME = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

test("another device's copy is stored as OUTGOING in the conversation with R", () => {
    const distro = Identity.create();
    const D = lxmfHash(distro);
    const rx = makeReceiver(distro, ME);
    // Sent an hour before it arrives here (a laptop that was asleep): the
    // bubble must sit where the message was sent, not where it was synced.
    const sentAtMs = Date.now() - 3_600_000;
    const blob = blobFor(distro, { fields: marker(R, OTHER_DEVICE), content: "sent on the phone", timestampMs: sentAtMs });
    assert.equal(rx.run(blob), true);
    assert.equal(rx.stored.length, 1);
    const { hash, msg } = rx.stored[0];
    assert.equal(hash, R, "the conversation with the recipient, not with D");
    assert.equal(msg.dir, "out");
    assert.equal(msg.status, "sent", "never delivered/proved");
    assert.equal(msg.srcHash, D, "from the distro, i.e. me");
    assert.equal(msg.via, "distro");
    assert.equal(msg.content, "sent on the phone");
    assert.equal(msg.timestamp, sentAtMs, "the copy's LXMF timestamp in ms, not its arrival time");
    assert.ok(rx.contacts.has(R), "the recipient's row kept (hidden: no contact), so the conversation shows by its messages");
    assert.equal(rx.events.length, 1);
    assert.equal(rx.events[0].peer, R);

    assert.equal(rx.run(blob), true, "stream + pull of the same copy");
    assert.equal(rx.stored.length, 1, "stored once");
});

test("this device's own echo is dropped (and deduped)", () => {
    const distro = Identity.create();
    const D = lxmfHash(distro);
    const rx = makeReceiver(distro, ME);
    const sentAtMs = Date.now() - 60_000;
    const echo = blobFor(distro, { fields: marker(R, ME), timestampMs: sentAtMs });
    assert.equal(rx.run(echo), true);
    assert.equal(rx.stored.length, 0);
    assert.equal(rx.events.length, 0);
    // Recorded as seen BEFORE the 0xFD drop, under the same src:ts key as
    // every fan-out message, so a re-delivery (stream + PULL) stops at the
    // dedupe instead of being re-parsed as a fresh copy (§17.11).
    const key = `${D}:${sentAtMs / 1000}`;
    assert.deepEqual([...rx.seen], [key], "the echo's src:ts key is recorded");
    assert.equal(rx.run(echo), true, "re-delivery of the echo");
    assert.equal(rx.stored.length, 0);
    assert.deepEqual(rx.harness.map((e) => e.name), ["distro-dup"], "the repeat is caught as a duplicate");
});

// A copy whose payload carries a fifth element (an LXMF stamp). LXMF signs the
// four-element payload and appends the stamp afterwards, so the signature is
// over [timestamp, title, content, fields] only.
function stampedBlobFor(distro, { fields, content, timestampMs }) {
    const D = Buffer.from(lxmfHash(distro), "hex");
    const payload4 = [timestampMs / 1000, Buffer.from(""), Buffer.from(content), fields];
    const hashed = Buffer.concat([D, D, Buffer.from(MsgPack.pack(payload4))]);
    const signature = distro.sign(Buffer.concat([hashed, Cryptography.fullHash(hashed)]));
    const packed5 = Buffer.from(MsgPack.pack([...payload4, Buffer.alloc(32, 7)]));
    return Buffer.concat([D, distro.encrypt(Buffer.concat([D, signature, packed5]))]);
}

test("a genuine copy that carries a stamp is stored (the stamp is not signed)", () => {
    const distro = Identity.create();
    const rx = makeReceiver(distro, ME);
    const sentAtMs = Date.now() - 5_000;
    assert.equal(rx.run(stampedBlobFor(distro, { fields: marker(R, OTHER_DEVICE), content: "stamped", timestampMs: sentAtMs })), true);
    assert.equal(rx.stored.length, 1, "a stamp must not make a genuine copy fail rule 2");
    assert.equal(rx.stored[0].msg.content, "stamped");
});

test("a forged copy is dropped at the signature rule even when it claims to be this device's echo", () => {
    const distro = Identity.create();
    const forger = Identity.create();
    const rx = makeReceiver(distro, ME);
    // Claims source D (blobFor sets sourceHash to the signer's hash, so build
    // it as D and sign with the forger's key) and 0xFD = this device.
    const D = Buffer.from(lxmfHash(distro), "hex");
    const msg = new LXMessage();
    msg.sourceHash = D; msg.destinationHash = D; msg.title = ""; msg.content = "forged";
    msg.fields = marker(R, ME);
    const packed = msg.pack(forger, false);
    const forged = Buffer.concat([D, distro.encrypt(packed.subarray(16))]);
    const warnings = [];
    const realWarn = console.warn;
    const realLog = console.log;
    console.warn = (...a) => warnings.push(a.join(" "));
    console.log = () => {};
    // false since 2026-09-30: nothing was kept, so rfed is not told the web
    // holds it (a push answers with this), and a later copy is judged again.
    try { assert.equal(rx.run(forged), false); } finally { console.warn = realWarn; console.log = realLog; }
    assert.equal(rx.stored.length, 0);
    assert.deepEqual([...rx.seen], [], "not recorded as seen");
    assert.ok(warnings.some((w) => w.includes("fails the distro signature")), `rule 2 speaks before rule 3: ${warnings}`);
});

test("a copy whose 0xFC is the distro itself is dropped (rule 4)", () => {
    const distro = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { fields: marker(lxmfHash(distro), OTHER_DEVICE) })), false, "nothing kept");
    assert.equal(rx.stored.length, 0, "never opens a chat with the distro address");
});

test("a copy with a malformed 0xFC is dropped", () => {
    const distro = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { fields: marker("not-a-hash", OTHER_DEVICE) })), false, "nothing kept");
    assert.equal(rx.stored.length, 0);
});

test("the marker from a source other than our distro is ignored", () => {
    const distro = Identity.create();
    const stranger = Identity.create();
    const rx = makeReceiver(distro, ME);
    assert.equal(rx.run(blobFor(distro, { signer: stranger, fields: marker(R, OTHER_DEVICE) })), false, "nothing kept");
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
    assert.equal(rx.run(Buffer.concat([D, distro.encrypt(packed.subarray(16))])), false, "nothing kept");
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
