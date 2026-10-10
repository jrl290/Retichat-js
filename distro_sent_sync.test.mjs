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
 * With `blank`, what those literals hold is spaces instead (their newlines
 * kept, a template's ${…} code kept), so code without comments keeps its
 * length and only its shape is left: its names and its brackets, and no
 * bracket of a string among them (members, below).
 */
function withoutComments(source, blank = false) {
    const n = source.length;
    let i = 0, out = "", last = "", word = "";
    const regexMayFollow = () => /[\w$]/.test(last)
        ? /^(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(word)
        : last === "" || "(,=:[!&|?{};+-*%<>~^}".includes(last);
    const text = (said) => blank ? said.replace(/[^\n]/g, " ") : said;
    const literal = (start) => { out += text(source.slice(start, i)); last = "\""; word = ""; };
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
        out += text(source[i++]);
        while (i < n && source[i] !== "`") {
            if (source[i] === "\\") { out += text(source.slice(i, i + 2)); i += 2; }
            else if (source[i] === "$" && source[i + 1] === "{") { out += "${"; i += 2; last = "{"; word = ""; code(true); out += "}"; i++; }
            else out += text(source[i++]);
        }
        out += text("`"); i++;
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

/** How many times the global `pattern` matches `source`. */
const count = (source, pattern) => source.match(pattern)?.length ?? 0;

/**
 * The top-level statements of `code` (its comments out) and the members of
 * each top-level object and class, as { name, start, end }: a declaration
 * is named by what it declares, any other statement as "statement: " and
 * the first name it says ("statement: import", "statement: console.log"),
 * and a member, at four spaces in, as "Object.member". A member runs to the
 * next one, or to its object's end. Brackets are counted in the code's
 * shape (withoutComments with `blank`), so none of a string counts.
 */
function members(code) {
    const shape = withoutComments(code, true);
    assert.equal(shape.length, code.length, "the code's shape is the code, place for place");
    const spans = [];
    let depth = 0, top = null, member = null, at = 0;
    const end = (span, where) => { if (span) { span.end = where; spans.push(span); } return null; };
    for (const line of shape.split("\n")) {
        const said = code.slice(at, at + line.length);
        if (depth === 0 && /^\S/.test(line)) {
            member = end(member, at);
            end(top, at);
            const name = said.match(/^(?:export\s+(?:default\s+)?)?(?:(?:const|let|var)\s+|window\.|(?:async\s+)?function\s*\*?\s*|class\s+)([\w$]+)/)?.[1]
                ?? `statement: ${said.match(/^[\w$.]+/)?.[0] ?? said.trim()}`;
            const holds = /^(?:(?:export\s+)?(?:const|let|var)\s+[\w$]+|window\.[\w$]+)\s*=\s*\{$|^(?:export\s+(?:default\s+)?)?class\s/.test(said.trimEnd());
            top = { name, start: at, end: code.length, holds };
        } else if (depth === 1 && top?.holds && /^ {4}[\w$*]/.test(line)) {
            const name = said.match(/^ {4}(?:(?:async|get|set|static)\s+)*\*?([\w$]+)\s*[(:=]/)?.[1];
            if (name) { end(member, at); member = { name: `${top.name}.${name}`, start: at, end: code.length }; }
        }
        for (let i = 0; i < line.length; i++) {
            if (line[i] === "{") depth++;
            else if (line[i] === "}" && --depth === 0) member = end(member, at + i + 1);
        }
        at += line.length + 1;
    }
    end(member, code.length);
    end(top, code.length);
    return spans;
}

/**
 * Where each occurrence of `what` sits in `code` (its comments out): the
 * member around it, or the top-level statement (members, above). A name
 * (a string) is matched whole, in the code and in its strings alike, so a
 * computed call (this["name"]), a bound alias or a destructured one names
 * it too; a pattern is matched as it is.
 */
function sites(code, what, spans = members(code)) {
    const pattern = typeof what === "string" ? new RegExp(`(?<![\\w$])${what.replaceAll("$", "\\$")}(?![\\w$])`, "g") : what;
    return [...code.matchAll(pattern)].map((m) =>
        spans.filter((s) => s.start <= m.index && m.index < s.end).sort((a, b) => b.start - a.start)[0]?.name ?? "?");
}

/** The text of the one member or top-level statement of `spans` called `name`. */
function memberText(code, spans, name) {
    const found = spans.filter((s) => s.name === name);
    assert.equal(found.length, 1, `one ${name}`);
    return code.slice(found[0].start, found[0].end);
}

test("the per-entry upload (_uploadOwed) has today's four callers and no other, and the upload it makes (_uploadForDistro) that one: the coming-up pass, the user's own action (_oweDistro), the third ruling's send on a replaced link's close or loss report, decided only where it is decided today, and the exchange's return for what never left the device (_sendDistroNeverLeft)", async () => {
    // _uploadOwed reads an entry's failure record only when a coming-up
    // pass calls it (`comingUp`). Called without one, it uploads at once
    // whatever the record says, which is right for its three other callers
    // alone: the user's own action, whose message is packed in that action
    // and so was never uploaded before; the exchange's return, which sends
    // only a message whose last upload never left the device, nothing of it
    // sent and so no failure to hold it back (James, 2026-10-06; below);
    // and the third ruling's send
    // (DESIGN_PRINCIPLES §3, what a device owes its distro): an upload on a
    // STALE link that a newer link replaced, decided not proved by that
    // link's own close (James, 2026-10-03) or by the exchange's report that
    // its packet was lost (James, 2026-10-04) while the newer link is up,
    // goes once on the newer link at once. Any other caller, or another way
    // to reach one of these three, would send an upload again on the
    // strength of its own failure alone. Verifier of 2683ea4 (RX1): the
    // test above pinned the pass's callers but not this one's, and an
    // lxmf.propagation announce that uploaded every owed entry through it
    // passed every test. So the three calls are pinned where they sit, and
    // so is everything that reaches each one:
    //   - the pass: its callers, by the test above;
    //   - the user's own action: _oweDistro, called only with a message
    //     packed in that same call, by _sendDistroSentCopy (from a DM's
    //     dispatch; "a DM's dispatch sends the copy once" pins where) and
    //     by _sendDistroChannelSync (from _syncChannelMembership, from the
    //     user's joinChannel and leaveChannel); everything above those, up
    //     to the user's own click or key, by the test below (the verifier
    //     of b6c7f7f, R12 to R14: this pin stopped at those three, and the
    //     window's "online" dispatching every failed DM again, or leaving
    //     and joining every channel again, passed every test);
    //   - the exchange's return: _sendDistroNeverLeft, named in its own
    //     definition and in one call, in the "back" branch of
    //     _followExchange's "up" listener, which runs only for an "up" that
    //     follows a "down" (the page_resume and exchange_truth suites); it
    //     sends only a message _distroUnproved records as never left, and
    //     that record is made only for an upload the exchange reported
    //     `unsent`, which only DistroUploads.neverLeft decides, from
    //     _onPacketsLost alone; an upload begun for the message ends the
    //     record (_uploadOwed), so a loss after the packet left is a failure
    //     again and waits for the next coming-up. It arms no timer;
    //   - the third ruling's send: where it goes is set only when its
    //     upload is decided with a newer propagation link up, and an upload
    //     is decided only by DistroUploads.lost, which the page calls for
    //     the exchange's loss report, a Resource's failure and a packet
    //     that never left, and by DistroUploads.cut, for the propagation
    //     link's own close and for disconnect(). The page closes a
    //     propagation link only in disconnect(), once it has let go of it;
    //     only the Link fires its "close", and only the exchange its "lost".
    //     Every place the page and lib/ say close or lost (and lib/ a
    //     link's coming-up or recovery) is pinned, and the page fires one
    //     event of its own, so a new close, loss report or coming-up is
    //     caught however it is written (an optional call such as
    //     link.close?.(), which the list of closes alone missed, an alias,
    //     a computed link["emit"](…)). Below the page, each is
    //     reached only from today's places: DistroUploads.cut from the page
    //     alone, a Link's close from its own five, and the exchange's loss
    //     report from its own four (the verifier of b6c7f7f, R6 to R8: a
    //     cut by the §1 watch, a STALE Link firing its close and the
    //     exchange reporting its queue lost on going down were each caught
    //     by another suite alone);
    //   - the upload itself: _uploadForDistro, called by _uploadOwed alone
    //     (the verifier of b6c7f7f, R15 to R17: a bound alias of it, run
    //     over every owed entry on the window's "online", skipped
    //     _uploadOwed and its failure record and passed every test; on an
    //     announce, it and a direct call were caught by other suites alone).
    // A Resource's own failure reaches the third ruling's send too, as the
    // code stands, and neither ruling names it (the verifier of 2683ea4,
    // question 1 for James). It is pinned here as it is, so that no other
    // path joins it unnoticed. What this cannot see is a call that never
    // writes these names whole, as for the test above.
    const code = withoutComments(app);
    const method = (signature) => extractMethod(code, signature);
    const spans = members(code);

    // The per-entry upload, and its three calls.
    assert.match(code, /\n {4}async _uploadOwed\(link, entry, comingUp = null\) \{/);
    assert.equal(count(code, /_uploadOwed/g), 5, "the method and its four calls: nothing else names it");
    assert.deepEqual(sites(code, "_uploadOwed", spans), ["RnsClient._oweDistro", "RnsClient._sendDistroOutbox", "RnsClient._sendDistroNeverLeft", "RnsClient._uploadOwed", "RnsClient._uploadOwed"]);
    const pass = method("async _sendDistroOutbox(link, trigger)");
    assert.equal(count(pass, /_uploadOwed/g), 1);
    assert.match(pass, /if \(this\._unprovedSince\(entry, comingUp\)\) \{\s*console\.log\([^\n]*\);\s*continue;\s*\}\s*await this\._uploadOwed\(link, entry, comingUp\);/,
        "the coming-up pass leaves what failed since its coming-up, and hands that coming-up on, so the record is read again once the upload is built");
    const owe = method("_oweDistro(entry)");
    assert.equal(count(owe, /_uploadOwed/g), 1);
    assert.match(owe, /const link = this\._propLink;\s*if \(link\?\.status === Link\.ACTIVE\) \{\s*this\._uploadOwed\(link, entry\);\s*return;\s*\}/,
        "the user's own action goes at once while the propagation link is up");
    // The exchange's return (James, 2026-10-06): an upload that never left the device is no failure, and goes when the
    // exchange is back, as well as at the next coming-up. It sends only what is recorded never left, still owed, with no
    // attempt open, on the propagation link while that is up; it is not a coming-up (it never names the pass, the failure
    // record or the count), and it arms no timer.
    const never = method("async _sendDistroNeverLeft(trigger)");
    assert.equal(count(never, /_uploadOwed/g), 1);
    assert.match(never, /^\s*const link = this\._propLink;\s*if \(!this\._rns \|\| !ActiveTab\.held \|\| link\?\.status !== Link\.ACTIVE\) return;/,
        "only the tab holding the identity, and only on the propagation link while it is up: a link coming up sends these itself");
    assert.match(never, /const owed = DistroOutboxStore\.list\(\)\.filter\(\(entry\) => this\._distroUnproved\.neverLeft\(entry\)\);/,
        "what never left, and nothing else owed");
    assert.match(never, /if \(this\._propLink !== link \|\| link\.status !== Link\.ACTIVE\) \{[^}]*return;\s*\}\s*if \(!this\._distroUnproved\.neverLeft\(entry\) \|\| !this\._stillOwed\(entry\) \|\| this\._distroAttemptOpen\(entry, link\)\) continue;\s*await this\._uploadOwed\(link, entry\);/,
        "each checked again when its turn comes, and never one with an attempt open: no double send");
    assert.doesNotMatch(never, /setTimeout|setInterval|setImmediate|requestAnimationFrame|requestIdleCallback/, "an event, never a clock (DESIGN_PRINCIPLES §5)");
    assert.doesNotMatch(never, /_propComingUps|_unprovedSince|_distroUnproved\.(?:record|forget|clearNeverLeft|recordNeverLeft)\(|_sendDistroOutbox/,
        "not a coming-up: it counts none, releases no failure record and runs no pass");
    assert.equal(count(code, /_sendDistroNeverLeft/g), 2, "the method and its one call: nothing else names it");
    assert.match(method("_followExchange(iface)"), /if \(back\) \{\s*this\._onPageResume\("exchange back"\);\s*this\._sendDistroNeverLeft\("exchange back"\);\s*\}/,
        "the exchange's return, the interface's own up-edge after a down, and no page event");
    const upload = method("async _uploadOwed(link, entry, comingUp = null)");
    assert.equal(count(upload, /_uploadOwed/g), 1, "the third ruling's send, and no other");
    assert.match(upload, /\}, \(error\) => \{\s*landed\(\);\s*if \(upload\.settled === "never-left"\) \{\s*this\._distroOwedNeverLeft\(entry, error\);\s*return;\s*\}\s*if \(goesOn && goesOn === this\._propLink && goesOn\.status === Link\.ACTIVE\s*&& this\._stillOwed\(entry\) && !this\._distroAttemptOpen\(entry, goesOn\)\) \{\s*this\._distroOwedOutcome\(entry, upload\.how, error, true\);\s*this\._uploadOwed\(goesOn, entry\);\s*return;\s*\}/,
        "the third ruling's send: on its upload's failure, never one that never left the device (said as no failure, James, 2026-10-06), to the newer link only while that is still the propagation link and up");
    // The upload itself: _uploadOwed hands it to _uploadForDistro, and nothing else does.
    assert.deepEqual(sites(code, "_uploadForDistro", spans), ["RnsClient._uploadOwed", "RnsClient._uploadForDistro"],
        "_uploadForDistro: made, and called by _uploadOwed alone, which reads the failure record");
    assert.equal(count(upload, /\bupload = this\._uploadForDistro\(link, propagationPacked, entry\.label\);/g), 1);

    // Where it goes is set only when this upload is decided, with a newer link up.
    assert.match(upload, /let goesOn = null;\s*const decided = \(\) => \{\s*unproved\(\);\s*const newer = this\._propLink;\s*if \(newer && upload\.link !== newer\) goesOn = newer;\s*\};\s*upload\.onLost = decided;\s*if \(upload\.settled === "lost"\) decided\(\);\s*upload\.outcome\.then\(/);
    assert.equal(count(code, /\bgoesOn\b/g), 7, "goesOn: declared, set by the decision, read by the send");
    assert.equal(count(upload, /\bgoesOn\s*=(?!=)/g), 2, "set to null, then only by the decision");
    assert.equal(count(code, /\bdecided\b/g), 3, "the decision: made, given to the upload, and run for an upload decided before it left");
    assert.equal(count(code, /\bonLost\b/g), 1, "the page gives an upload its onLost once, and calls it nowhere");
    // An upload is decided never left (James, 2026-10-06) only by DistroUploads.neverLeft, which the page calls for a packet
    // the exchange reports `unsent`; its record is made only by the owner's onNeverLeft, which takes no part in goesOn, and
    // ended by an upload begun for the message and by forget().
    assert.equal(count(code, /\bonNeverLeft\b/g), 1, "the page gives an upload its onNeverLeft once, and calls it nowhere");
    assert.equal(count(upload, /upload\.onNeverLeft = neverLeft;/g), 1);
    assert.equal(count(code, /\.\s*neverLeft\s*\(/g), 3, "neverLeft: the upload's decision, and two reads of the record (the return's list and its check)");
    assert.equal(count(code, /_distroUploads\.neverLeft\(/g), 1, "decided in one place");
    assert.equal(count(code, /_distroUnproved\.recordNeverLeft\(/g), 1, "the record is made in one place: the upload's onNeverLeft");
    assert.equal(count(code, /_distroUnproved\.clearNeverLeft\(/g), 1, "and ended when an upload of the message begins");
    assert.match(upload, /^\s*const flight = \{ link, packed: entry\.packed \};\s*this\._distroOutboxInFlight\.set\(entry\.id, flight\);\s*this\._distroUnproved\.clearNeverLeft\(entry\);/,
        "ended as the attempt begins, whatever it comes to");
    assert.match(upload, /const neverLeft = \(\) => \{\s*if \(DistroOutboxStore\.get\(entry\.id\)\?\.packed === entry\.packed\) this\._distroUnproved\.recordNeverLeft\(entry\);\s*\};/,
        "recorded while this message is the one owed under its id, with no coming-up: a never-left upload is no failure");
    assert.equal(count(upload, /_distroOwedNeverLeft\(/g), 1, "a never-left upload is said as no failure, in one place, and takes no part in the third ruling's send");

    // An upload is decided by DistroUploads.lost and .cut, at today's five places.
    assert.equal(count(code, /_distroUploads/g), 12, "the field and its eleven calls: no alias");
    assert.deepEqual(code.match(/\.\s*(?:lost|cut)\s*\(/g), [".cut(", ".lost(", ".lost(", ".lost(", ".cut("],
        "nothing else in the page is told .lost or .cut");
    assert.match(method("_onPacketsLost({ packetHashes, reason, unsent = [] })"),
        /if \(pending\?\.distroUpload\) \{\s*if \(unsent\.includes\(packetHash\)\) \{\s*this\._distroUploads\.neverLeft\(pending\.distroUpload, pending\.resourceAdvert\s*\? `its Resource's first advertisement never left: \$\{reason\}` : `its packet never left: \$\{reason\}`\);\s*if \(pending\.resourceAdvert\) \{\s*this\._pendingPacketHashes\.delete\(packetHash\.slice\(0, 32\)\);\s*pending\.resource\.cancel\("its first advertisement never left the device"\);\s*\}\s*\} else if \(!pending\.resourceAdvert\) this\._distroUploads\.lost\(pending\.distroUpload, `its packet was lost \(\$\{reason\}\)`\);\s*continue;\s*\}/,
        "the exchange's loss report (James, 2026-10-04), and its report that the packet never left, which is no loss (James, 2026-10-06); "
        + "a Resource's first advertisement never left is the same, and cancels the Resource on this device, and a loss report for it decides nothing (James, 2026-10-10)");
    assert.equal(count(code, /\bdistroUpload\b/g), 5,
        "the loss report knows an upload by the entry _uploadForDistro makes for its packet's proof, or for its Resource's first advertisement, and by nothing else");
    assert.equal(count(code, /\bresourceAdvert\b/g), 4, "an advertisement's entry: made by _uploadForDistro alone, and read by the loss report alone");
    assert.equal(count(code, /_onPacketsLost/g), 2, "the loss report's handler and its one call");
    assert.match(method("_followExchange(iface)"), /iface\.on\("lost", \(lost\) => \{\s*if \(current\(\)\) this\._onPacketsLost\(lost\);\s*\}\);/,
        "the loss report is the exchange's \"lost\"");
    const forDistro = method("_uploadForDistro(link, propagationPacked, label)");
    assert.equal(count(forDistro, /_distroUploads\.lost\(/g), 2);
    assert.match(forDistro, /\}\)\.then\(\s*\(\) => \{ ended\(\); this\._distroUploads\.proved\(upload\); \},\s*\(error\) => \{ ended\(\); this\._distroUploads\.lost\(upload, `its Resource failed/,
        "a Resource's own failure, once its first advertisement has left (ruling of 2026-10-04)");
    assert.match(forDistro, /link\.sendResource\(propagationPacked, \{\s*onFirstAdvertisement: \(packetHash, resource\) => \{\s*advertKey = packetHash\.slice\(0, 16\)\.toString\("hex"\);\s*advert = \{\s*contactHash: DistroManager\.lxmfDeliveryHash,\s*messageId: advertKey,\s*distroUpload: upload,\s*resourceAdvert: true,\s*resource,\s*onProof: \(\) => \{\},\s*\};\s*this\._pendingPacketHashes\.set\(advertKey, advert\);\s*\},\s*\}\)/,
        "the Resource's first advertisement is tracked before it can go, so the exchange's report that it never left reaches _onPacketsLost (James, 2026-10-10); its proof, were it ever proved, decides nothing");
    assert.match(forDistro, /^\s*if \(this\._propLink !== link \|\| link\.status !== Link\.ACTIVE\) return null;/);
    assert.match(forDistro, /if \(link\._transmit\(raw\) === null\) \{\s*this\._pendingPacketHashes\.delete\(proofKey\);\s*this\._distroUploads\.lost\(upload, "the propagation link closed before the upload"\);/,
        "a packet that never left, on the link checked to be the propagation link in the same task: no newer link is up");
    const establish = method("_establishPropagationLink()");
    assert.equal(count(linkListener(establish, "close"), /this\._distroUploads\.cut\("the propagation link closed before the propagation node proved it", link\);/g), 1,
        "the propagation link's own close (James, 2026-10-03)");
    const disconnect = method("disconnect()");
    assert.equal(count(disconnect, /this\._distroUploads\.cut\("the connection stopped before the propagation node proved it"\);/g), 1, "disconnect()");
    assert.match(disconnect, /const propLink = this\._propLink;\s*this\._propLink = null;\s*try \{ propLink\?\.close\(\); \} catch\(e\) \{\}/,
        "disconnect() lets go of the propagation link before it closes it");
    assert.doesNotMatch(disconnect, /\bawait\b|\.then\(/,
        "and in its cut's own task, so no decision's outcome finds a newer link that is the propagation link");

    // Nothing else closes a propagation link, or fires a link's close or a loss report.
    assert.deepEqual([...code.matchAll(/([\w$]+(?:\.[\w$]+)*)\s*(?:\?\.|\.)\s*close\s*\(/g)].map((m) => m[1]),
        ["existing.link", "link", "link", "entry.link", "propLink", "GroupStore"],
        "today's closes: a group link, a refused rfed.link, disconnect()'s rfed.links, group links and the propagation link it let go of, and a group. "
        + "A close of a propagation link decides the uploads on it, and a newer link up sends them at once (the third ruling): only its own close may");
    assert.doesNotMatch(code, /_linkClosed/, "the page never runs a link's close for it");
    // And every place the page says close or lost, or fires an event, so that a close of a link or a loss report
    // is new here however it is written: an optional call (link.close?.()), an alias, a computed name. Names are
    // read in the code (shape: its strings blanked), and the event names whole in its strings, so a log line that
    // says "emit" or "closed" is not one.
    const shape = withoutComments(code, true);
    assert.deepEqual(sites(shape, "close", spans), ["GroupStore.close", "RnsClient._markGroupPeerReady",
        "RnsClient._closeRefusedRfedLink", "RnsClient.disconnect", "RnsClient.disconnect", "RnsClient.disconnect", "App._quitGroup",
        "App._renderSettingsModal", "App._renderSettingsModal", "App._renderIdentityModal", "App._renderIdentityModal"],
        "close in the page's code: the closes above, a group's close, and two dialogs' own close");
    assert.deepEqual(sites(code, /(["'`])(?:close|lost)\1/g, spans), ["RnsClient._followExchange", "RnsClient._establishPropagationLink",
        "RnsClient._onPropagationLinkClosed", "RnsClient._uploadOwed", "RnsClient._ensureGroupLink", "RnsClient._ensureRfedLink", "RnsClient._onRfedLinkClosed"],
        "\"close\" and \"lost\": the links' close listeners, the loss report's listener, two re-drives' reasons and an upload's state");
    assert.deepEqual([...sites(shape, "emit", spans), ...sites(code, /(["'`])emit\1/g, spans)], ["RnsClient._ingestPropagatedBlob"],
        "the page fires one event of its own, so no link's coming-up, close or loss report, however it is written (link[\"emit\"](…) too)");
    const fired = [...code.matchAll(/\.\s*emit\s*(\?\.)?\s*\(\s*([^,)]*)/g)].map((m) => m[2].trim());
    assert.ok(fired.every((name) => !["\"close\"", "\"lost\""].includes(name)), `app.js fires no link's close and no loss report: ${fired.join(", ")}`);
    const lib = new URL("./lib/", import.meta.url);
    const scripts = (await readdir(lib, { recursive: true })).filter((f) => f.endsWith(".js"));
    assert.ok(scripts.includes("distro_upload.js") && scripts.includes("rns/link.js") && scripts.includes("rns/interfaces/post_interface.js"));
    const named = /_uploadOwed|_uploadForDistro|_oweDistro|_sendDistroSentCopy|_sendDistroChannelSync|_syncChannelMembership|_onPacketsLost|_distroUploads|goesOn/;
    const closesAndLosses = {};
    for (const file of scripts) {
        const source = withoutComments(await readFile(new URL(file, lib), "utf8"));
        assert.doesNotMatch(source, named, `lib/${file}`);
        assert.equal(count(source, /\bemit\s*\(\s*["'`]lost["'`]/g), file === "rns/interfaces/post_interface.js" ? 1 : 0,
            `lib/${file}: only the exchange reports packets lost`);
        const fileSpans = members(source);
        const said = [...sites(withoutComments(source, true), "close", fileSpans), ...sites(source, /(["'`])(?:close|lost|established|recovered)\1/g, fileSpans)];
        if (said.length) closesAndLosses[file] = said;
    }
    assert.deepEqual(closesAndLosses, {
        "distro_upload.js": ["DistroUploads.proved", "DistroUploads.lost"],
        "rns/interfaces/direct_sockets_interface.js": ["DirectSocketsInterface._cleanup"],
        "rns/interfaces/post_interface.js": ["PostInterface._lose"],
        "rns/interfaces/tcp_client_interface.js": ["TCPClientInterface.connect"],
        "rns/interfaces/websocket_client_interface.js": ["WebsocketClientInterface.connectInBrowser", "WebsocketClientInterface.connectInNodeJs"],
        "rns/link.js": ["Link.close", "Link.validateProof", "Link._recoverIfStale", "Link._linkClosed", "Link.onLinkRequestRtt"],
        "rns/lxmf/lxmf_router.js": ["LXMRouter.constructor"],
        "rns/reticulum.js": ["Reticulum.addInterface"],
    }, "lib/ says close, lost, established and recovered only where it does today: a socket's close and the close events of the sockets "
        + "it reads, the Link's own close(), and the close, coming-up and recovery it fires, the exchange's loss report and Reticulum's "
        + "listener of it, the LXMF router's listener of a link's coming-up, and an upload's state. So no script under lib/ closes a link, "
        + "or fires a link's close or coming-up or a loss report anew, however it is written");
    const linkSource = withoutComments(await readFile(new URL("rns/link.js", lib), "utf8"));
    assert.equal(count(linkSource, /\bemit\s*\(\s*["'`]close["'`]/g), 1, "a Link fires its close once in its code");
    assert.match(extractMethod(linkSource, "_linkClosed()"), /\bthis\.emit\("close"\);/, "a Link fires its close when it closes, and only then");
    const uploads = withoutComments(await readFile(new URL("distro_upload.js", lib), "utf8"));
    assert.equal(count(uploads, /\bonLost\b/g), 2, "an upload's onLost: made empty, and told only by lost()");
    assert.equal(count(uploads, /\bonNeverLeft\b/g), 2, "an upload's onNeverLeft: made empty, and told only by neverLeft()");
    assert.match(extractMethod(uploads, "neverLeft(upload, why)"), /upload\.reject\(new Error\(why\)\);\s*upload\.onNeverLeft\?\.\(\);/);
    assert.equal(count(uploads, /\bneverLeft\s*\(/g), 1, "neverLeft(): itself, and no call in lib/: the page decides it, from the exchange's report");
    assert.match(extractMethod(uploads, "lost(upload, why)"), /upload\.reject\(new Error\(why\)\);\s*upload\.onLost\?\.\(\);/);
    assert.equal(count(uploads, /\blost\s*\(/g), 2, "lost(): itself, and cut()'s call");
    assert.match(extractMethod(uploads, "cut(why, link = null)"), /if \(this\.lost\(upload, why\)\) cut\+\+;/);
    assert.equal(count(uploads, /\bcut\s*\(/g), 1, "cut(): itself, called by the page alone (the link's close and disconnect())");
    assert.deepEqual(sites(linkSource, "_linkClosed"), ["Link.onPacket", "Link._linkClosed", "Link._startEstablishmentWatchdog", "Link.requestLost", "Link._watchdogStep", "Link.close"],
        "a Link closes on its peer's LINKCLOSE, its establishment's timeout, its link request lost, its STALE grace run out and its own close(), and nowhere else");
    const exchange = withoutComments(await readFile(new URL("rns/interfaces/post_interface.js", lib), "utf8"));
    const exchangeSpans = members(exchange);
    assert.deepEqual(sites(exchange, "_lose", exchangeSpans), ["PostInterface.block", "PostInterface.sendData", "PostInterface._runExchange", "PostInterface._runExchange", "PostInterface._lose"],
        "the exchange reports packets lost when it is refused, when one is sent while it is down, and when an exchange fails or a check abandons it, and nowhere else");
    assert.match(memberText(exchange, exchangeSpans, "PostInterface._lose"), /this\.emit\('lost', \{ packetHashes: hashes\(packets\), reason, abandoned, unsent: hashes\(unsent\) \}\);/);
    // James, 2026-10-06 (DESIGN_PRINCIPLES §3, what a device owes its distro): an upload whose packet the exchange says
    // went into no request is no failure, and goes at the exchange's return. A packet of a batch an exchange carried, or
    // gave up on, may have reached the node, and a loss after that waits for the next coming-up. So `unsent` is only what a
    // down or blocked exchange refused and what was still in the queue (spliced out of it by block() and by a failed exchange,
    // and never the batch in flight): this is where a batch could be passed as unsent, and none is.
    assert.deepEqual([...exchange.matchAll(/this\._lose\(([^;]*)\);/g)].map((m) => m[1].replace(/\s+/g, " ")), [
        "queued, reason, { unsent: queued }",
        "[data], this._blocked ?? 'the exchange is down', { unsent: [data] }",
        "batch.packets, `exchange abandoned by a check`, { abandoned: true }",
        "[...batch.packets, ...queued], err.message, { unsent: queued }",
    ], "what the exchange reports lost, and the part of it that was never sent");
    assert.equal(count(exchange, /const queued = this\._outboundQueue\.splice\(0\);/g), 2, "the queue, in block() and in a failed exchange, and nothing else");
    assert.equal(count(exchange, /\bunsent\b/g), 6, "`unsent`: _lose's parameter, the emit's key and argument, and the three callers' one each");
    for (const page of ["index.html", "debug.html", "debug-standalone.html"]) {
        assert.doesNotMatch(await readFile(new URL(`./${page}`, import.meta.url), "utf8"), named, page);
    }

    // The user's own action: _oweDistro owes a message packed in that same call, from the user's join, leave or DM.
    assert.equal(count(code, /_oweDistro/g), 3, "the method and its two calls");
    for (const signature of ["async _sendDistroSentCopy(recipientHex, title, content)", "_sendDistroChannelSync(op, ch, atMs)"]) {
        const body = method(signature);
        assert.equal(count(body, /_oweDistro/g), 1, signature);
        assert.match(body, /const msg = new LXMessage\(\);[\s\S]*const packed = msg\.pack\(DistroManager\.identity, false\);\s*this\._oweDistro\(\{[^}]*\bpacked: Buffer\.from\(packed\)\.toString\("base64"\),/,
            `${signature} owes the message it has just packed`);
    }
    assert.equal(count(code, /_sendDistroSentCopy/g), 2, "made in a DM's dispatch alone");
    assert.equal(count(method("_dispatchMessage(contact, outMsg)"), /_sendDistroSentCopy/g), 1);
    assert.equal(count(code, /_sendDistroChannelSync/g), 2, "made for the user's own join or leave alone");
    const membership = method("_syncChannelMembership(op, ch)");
    assert.match(membership, /const atMs = ChannelMembershipStore\.stampLocal\(ch\.channelHash, op, Date\.now\(\)\);[\s\S]*this\._sendDistroChannelSync\(op, ch, atMs\);/,
        "each action stamped after any before it on the channel, so its message is a new one");
    assert.equal(count(membership, /_sendDistroChannelSync/g), 1);
    assert.equal(count(code, /_syncChannelMembership/g), 3, "the user's join and leave");
    assert.equal(count(method("async joinChannel(channelName)"), /this\._syncChannelMembership\("join", ch\);/g), 1);
    assert.equal(count(method("async leaveChannel(channelName)"), /this\._syncChannelMembership\("leave", ch\);/g), 1);
});

test("what reaches the user's own action (_oweDistro) begins with the user and nothing else: a DM from the composer, a join from the channel form, a leave from the channel's Leave button, the test harness's send, join and leave, and a DM sent before the exchange first registered", async () => {
    // _oweDistro uploads at once while the propagation link is up and reads
    // no failure record, which is right only for a message the user's own
    // action has just packed (the test above pins its two callers, each
    // owing the message it has just packed). The verifier of b6c7f7f (R12
    // to R14, R5): that pin stopped at a DM's dispatch, joinChannel and
    // leaveChannel, so the window's "online" dispatching every failed DM
    // again (by name, or through a bound alias of _dispatchMessage), or
    // leaving and joining every channel again, passed every test, and so did
    // debug.html naming _dispatchMessage. Each would owe the distro a new
    // message on the strength of a failure alone, with the user doing
    // nothing. So everything above those two callers is pinned here, every
    // place each name is written, up to where it begins:
    //   - a DM: the composer's send button and Enter key, in the DM, group
    //     and channel views (App.sendMessage sends what the composer holds,
    //     and a DM only to the open chat's contact), the harness's send, and
    //     _dispatchQueued, which sends once each DM the user sent before the
    //     exchange first registered after a connect: only sendMessage queues
    //     a DM for it ("init"), and only disconnect() makes it wait again;
    //   - a join: the channel form's Join button and Enter key, and the
    //     harness's joinChannel;
    //   - a leave: the channel's Leave button, once confirmed, and the
    //     harness's leaveChannel.
    // The harness (window.RetichatTest) is the staging tests' hand on the
    // page, acting as the user: nothing in the page calls it, no script
    // under lib/ reaches the page's objects, and the pages reach none of
    // this (debug.html reads the harness's events, identity, distro and
    // ready, and nothing else). The page clicks none of its own controls
    // but the attachment picker's hidden file input, and fires no DOM
    // event; h() makes each on… property a listener of that event. And the
    // bytes an upload sends come only from what is owed: the one outbox,
    // the attempts in flight and the failure records, each read where it is
    // read today, the outbox's storage key named by lib/distro_outbox.js
    // alone. What this cannot see is a name assembled at run time or found
    // by reflection, as for the tests above.
    const code = withoutComments(app);
    const spans = members(code);
    const at = (what) => sites(code, what, spans);
    const member = (name) => memberText(code, spans, name);

    // Every place each name is written, in the code or in a string.
    const places = {
        _sendDistroSentCopy: ["RnsClient._dispatchMessage", "RnsClient._sendDistroSentCopy"],
        _sendDistroChannelSync: ["RnsClient._syncChannelMembership", "RnsClient._sendDistroChannelSync"],
        _dispatchMessage: ["RnsClient.sendMessage", "RnsClient._dispatchMessage", "RnsClient._dispatchQueued"],
        sendMessage: ["RnsClient.sendMessage", "App._buildDmChatView", "App._buildGroupChatView", "App._buildChannelChatView",
            "App._composerKeydown", "App.sendMessage", "App.sendMessage", "RetichatTest.send"],
        _composerKeydown: ["App._buildDmChatView", "App._buildGroupChatView", "App._buildChannelChatView", "App._composerKeydown"],
        _dispatchQueued: ["RnsClient._dispatchQueued", "RnsClient._onExchangeRegistered"],
        _onExchangeRegistered: ["RnsClient._followExchange", "RnsClient._onExchangeRegistered"],
        _followExchange: ["RnsClient._followExchange", "RnsClient.connect"],
        _syncChannelMembership: ["RnsClient._syncChannelMembership", "RnsClient.joinChannel", "RnsClient.leaveChannel"],
        joinChannel: ["RnsClient.joinChannel", "App._renderChannelForm", "RetichatTest.joinChannel", "RetichatTest.joinChannel", "RetichatTest.help"],
        leaveChannel: ["RnsClient.leaveChannel", "App._renderChannelInfoModal", "RetichatTest.leaveChannel", "RetichatTest.leaveChannel", "RetichatTest.help"],
        doJoin: ["App._renderChannelForm", "App._renderChannelForm", "App._renderChannelForm"],
        RetichatTest: ["RetichatTest", "RetichatTest.help", "statement: console.log", "statement: console.log"],
        DistroOutboxStore: ["DistroOutboxStore", "RnsClient._oweDistro", "RnsClient._oweDistro", "RnsClient._sendDistroOutbox",
            "RnsClient._sendDistroNeverLeft", "RnsClient._uploadOwed", "RnsClient._uploadOwed", "RnsClient._uploadOwed",
            "RnsClient._uploadOwed", "RnsClient._stillOwed", "RnsClient._dropMembershipOwedToOtherDistros", "RetichatTest.distroOwed"],
        DistroOutbox: ["statement: import", "DistroOutboxStore"],
        _distroOutboxInFlight: ["RnsClient._distroOutboxInFlight", "RnsClient._distroAttemptOpen", "RnsClient._uploadOwed",
            "RnsClient._uploadOwed", "RnsClient._uploadOwed", "RnsClient._dropMembershipOwedToOtherDistros"],
        _distroUnproved: ["RnsClient._distroUnproved", "RnsClient._oweDistro", "RnsClient._sendDistroNeverLeft", "RnsClient._sendDistroNeverLeft",
            "RnsClient._unprovedSince", "RnsClient._uploadOwed", "RnsClient._uploadOwed", "RnsClient._uploadOwed", "RnsClient._uploadOwed",
            "RnsClient._dropMembershipOwedToOtherDistros"],
        _sendDistroNeverLeft: ["RnsClient._followExchange", "RnsClient._sendDistroNeverLeft"],
    };
    for (const [name, where] of Object.entries(places)) assert.deepEqual(at(name), where, `${name}: written where it is today, and nowhere else`);

    // A DM: the composer's Enter key and send button in each chat view, the harness's send, and App.sendMessage's
    // one call, with what the composer holds, to the open chat's contact.
    for (const view of ["App._buildDmChatView", "App._buildGroupChatView", "App._buildChannelChatView"]) {
        const built = member(view);
        assert.match(built, /h\("textarea", \{\s*id: "composer-input",(?:\s*\w+: [^\n]*,)*?\s*onKeydown: \(e\) => this\._composerKeydown\(e\),/, `${view}: the composer's keys`);
        assert.match(built, /h\("button", \{\s*className: "btn-send",(?:\s*disabled: !c\.publicKey,)?\s*onClick: \(\) => this\.sendMessage\(\),\s*\}/, `${view}: the send button's click`);
    }
    assert.match(member("App._composerKeydown"), /^ {4}_composerKeydown\(e\) \{\s*if \(!enterSends\(e, [^\n]*\)\) return;\s*e\.preventDefault\(\);\s*this\.sendMessage\(\);\s*\},\s*$/,
        "Enter, as lib/message_text.js enterSends decides it, and nothing else");
    const composer = member("App.sendMessage");
    assert.match(composer, /const ta = document\.getElementById\("composer-input"\);[\s\S]*const content = ta\.value\.trim\(\);/);
    assert.match(composer, /const c = ContactStore\.get\(this\.state\.activeHash\);[\s\S]*RnsClient\.sendMessage\(c, content, attachments\);/);
    assert.match(member("RetichatTest.send"), /const stored = RnsClient\.sendMessage\(contact, content \|\| 'E2E test ' \+ Date\.now\(\)\);/);
    assert.equal(count(member("RnsClient.sendMessage"), /this\._dispatchMessage\(contact, outMsg\);/g), 1);

    // A DM the user sent before the exchange first registered after a connect: sent once, at that registration.
    assert.match(member("RnsClient._onExchangeRegistered"), /if \(!this\._initialized\) \{\s*this\._initialized = true;\s*this\._dispatchQueued\(\);\s*\}/);
    assert.match(member("RnsClient._followExchange"), /iface\.on\("registered", \(\) => \{\s*if \(current\(\)\) this\._onExchangeRegistered\(\);\s*\}\);/);
    assert.match(member("RnsClient.connect"), /\n {8}this\._followExchange\(iface\);\n/, "the exchange connect() makes, once");
    const initialized = /\b_initialized\s*(?::|=(?!=))\s*(\w+)/g;
    assert.deepEqual(at(initialized), ["RnsClient._initialized", "RnsClient._onExchangeRegistered", "RnsClient.disconnect"],
        "_initialized: set where it is today, and nowhere else");
    assert.deepEqual([...code.matchAll(initialized)].map((m) => m[1]), ["false", "true", "false"],
        "set at the first registration, and made to wait again by disconnect() alone");
    assert.deepEqual(at(/(["'`])init\1/g), ["RnsClient.sendMessage", "RnsClient._dispatchQueued", "RnsClient.sendGroupMessage"],
        "a DM waits for the registration only as sendMessage queues it (a group message has no copy)");
    assert.match(member("RnsClient.sendMessage"), /if \(!this\._initialized\) \{\s*const queued = MsgStore\.add\(contact\.destHash, \{\s*dir: "out", content, status: "queued", waitFor: "init",/);
    assert.match(member("RnsClient._dispatchQueued"), /MsgStore\.update\(contact\.destHash, msg\.id, \{ waitFor: null \}\);\s*this\._dispatchMessage\(contact, msg\);/,
        "a queued DM waits no more before it goes, so it goes once");

    // A join: the channel form's Join button and Enter key. A leave: the channel's Leave button, once confirmed.
    // And the harness's join and leave, one call each; no member of the harness calls its send.
    const form = member("App._renderChannelForm");
    assert.match(form, /const doJoin = \(\) => \{\s*if \(!inp\) return;\s*const v = validateChannelName\(inp\.value, mode\(\)\);\s*if \(!v\.ok\) \{ refresh\(\); return; \}\s*RnsClient\.joinChannel\(v\.name\)\.then\(/);
    assert.match(form, /onKeydown: \(e\) => \{ if \(e\.key === "Enter"\) doJoin\(\); \},/);
    assert.match(form, /joinBtn = h\("button", \{ className: "btn btn-primary btn-block", onClick: doJoin,/);
    assert.match(member("App._renderChannelInfoModal"), /onClick: \(\) => \{\s*if \(!confirm\(`Leave #\$\{ch\.channelName\}\?`\)\) return;\s*RnsClient\.leaveChannel\(ch\.channelName\)\.then\(/);
    assert.match(member("RetichatTest.joinChannel"), /^ {4}joinChannel\(name\) \{ return RnsClient\.joinChannel\(name\)\.then\(/);
    assert.match(member("RetichatTest.leaveChannel"), /^ {4}leaveChannel\(name\) \{ return RnsClient\.leaveChannel\(name\)\.then\(\(\) => true\); \},/);
    assert.deepEqual(at("send").filter((where) => where.startsWith("RetichatTest")), ["RetichatTest.help", "RetichatTest.help", "RetichatTest.send"],
        "the harness's send, and its help's two words for it");

    // The page clicks none of its own controls but the attachment picker's file input, and fires no DOM event;
    // h() makes each on… property its element's listener of that event.
    assert.deepEqual(at(/\.\s*click\s*\(/g), ["App._pickAttachments"], "the page clicks the attachment picker's file input, and nothing else");
    assert.doesNotMatch(code, /\bdispatchEvent\b|\brequestSubmit\b|\bnew\s+(?:Keyboard|Mouse|Pointer|Submit|Input|Focus|UI|Custom)?Event\s*\(/);
    const h = member("h");
    assert.match(h, /else if \(k\.startsWith\("on"\) && typeof v === "function"\) el\.addEventListener\(k\.slice\(2\)\.toLowerCase\(\), v\);\n/);
    assert.equal(count(h, /addEventListener/g), 1, "and no other listener");
    assert.doesNotMatch(code, /distro_outbox_v1/, "the outbox's storage is read through DistroOutboxStore alone");

    // Nor does a script under lib/ or a page: lib/ reaches no object of the page, index.html loads app.js and
    // nothing else, debug-standalone.html not even that (its console has its own stack), and debug.html reads the
    // harness alone.
    const named = /_sendDistroSentCopy|_sendDistroChannelSync|_dispatchMessage|_dispatchQueued|_onExchangeRegistered|_followExchange|_composerKeydown|\bsendMessage\b|\bjoinChannel\b|\bleaveChannel\b|_syncChannelMembership|DistroOutboxStore|_distroOutboxInFlight|_distroUnproved|_sendDistroNeverLeft/;
    const lib = new URL("./lib/", import.meta.url);
    const scripts = (await readdir(lib, { recursive: true })).filter((f) => f.endsWith(".js"));
    assert.ok(scripts.includes("distro_outbox.js") && scripts.includes("message_text.js"));
    for (const file of scripts) {
        const source = withoutComments(await readFile(new URL(file, lib), "utf8"));
        assert.doesNotMatch(source, named, `lib/${file}`);
        assert.doesNotMatch(source, /\b(?:RetichatTest|Debug|RnsClient|App)\b/, `lib/${file} reaches no object of the page`);
        assert.equal(count(source, /distro_outbox_v1/g), file === "distro_outbox.js" ? 1 : 0, `lib/${file}: the outbox's storage key is lib/distro_outbox.js's`);
    }
    const page = (name) => readFile(new URL(`./${name}`, import.meta.url), "utf8");
    const [index, debug, standalone] = await Promise.all(["index.html", "debug.html", "debug-standalone.html"].map(page));
    for (const [name, html] of [["index.html", index], ["debug.html", debug], ["debug-standalone.html", standalone]]) {
        assert.doesNotMatch(html, named, name);
        assert.doesNotMatch(html, /distro_outbox_v1/, name);
    }
    assert.deepEqual(index.match(/<script\b[^>]*>/g), ["<script type=\"importmap\">", "<script type=\"module\" src=\"app.js\">"], "index.html: the import map and app.js");
    assert.doesNotMatch(standalone, /app\.js|RetichatTest/, "debug-standalone.html loads no app.js");
    assert.deepEqual(debug.match(/<script\b[^>]*>/g), ["<script type=\"importmap\">", "<script>", "<script type=\"module\" src=\"app.js\">", "<script type=\"module\">"]);
    const opened = debug.lastIndexOf("<script type=\"module\">");
    const reader = withoutComments(debug.slice(opened + "<script type=\"module\">".length, debug.indexOf("</script>", opened)));
    assert.deepEqual([...reader.matchAll(/\bT\s*\.\s*([\w$]+)/g)].map((m) => m[1]), ["events", "identity", "distro", "ready"], "debug.html reads the harness");
    assert.deepEqual([count(reader, /\bT\b/g), count(reader, /\bDebug\b/g), count(reader, /\bRetichatTest\b/g)], [6, 3, 3],
        "and holds it as T, which it shows the console as window.Debug, and nowhere else");
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
