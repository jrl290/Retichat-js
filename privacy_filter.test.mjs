/**
 * THE PRIVACY FILTER — which received LXMF messages the web client keeps,
 * and what a dropped one costs.
 *
 * Parity target: iOS UserPreferences.filterStrangers (on by default),
 * ChatRepository.swift allowlistDecision / groupMessagePolicy; Android
 * DeliveryPolicy.kt (the same rule). With the filter on, a DM is kept only
 * from an allowlisted contact, a group invite only from an allowlisted
 * source, any other group message when the group exists here; a distro
 * identity transfer is offered whoever sent it; distro fan-out is never
 * filtered.
 *
 * "Drop costs nothing" (James, 2026-09-30): the LXMF router asks the filter
 * on the decrypted bytes (the source, bytes 0..16 of the plaintext) before
 * it proves or parses anything, then again after the parse and before the
 * proof. A source that is neither allowlisted nor a member here (a
 * stranger) is read only as far as its group id and action: a group
 * message for a group held here is kept, as iOS keeps it, and anything
 * else is dropped. A dropped message gets no proof, no parse, no ticket
 * remembered, no row, no name and no bubble. On every path:
 * opportunistic packets, link packets, link Resources (transferred first:
 * the source is inside) and messages fetched from the propagation node
 * (still purged).
 *
 * Also here: the migration's one-time allowlisting of held groups' members,
 * and the Identity screen's hint for receiving a distro identity.
 *
 * These run the real shipped code: lib/rns/lxmf/lxmf_router.js, and
 * ContactStore, GroupStore, PrivacyFilter, MsgStore, the router's message
 * handler, _fetchPropagatedMessages, sendMessage and _handleDistroBlob
 * extracted from app.js and compiled over stubs.
 *
 * Run: node --test privacy_filter.test.mjs
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
import LXMF, { GROUP_FIELDS } from "./lib/rns/lxmf/lxmf.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import EventEmitter from "./lib/rns/utils/events.js";
import * as DN from "./lib/display_name.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { addInOrder } from "./lib/message_order.js";
import { linkPair, settle, within } from "./test_link_pair.mjs";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

// ── extraction (as display_names_wiring.test.mjs) ──────────────────────────

function braceMatch(from, label) {
    const open = app.indexOf("{", from);
    let depth = 0;
    for (let i = open; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}" && --depth === 0) return [open, i];
    }
    throw new Error(`could not brace-match ${label}`);
}
function methodBody(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const [open, close] = braceMatch(start + signature.length, signature);
    return app.slice(open + 1, close);
}
function objectLiteral(name) {
    const start = app.indexOf(`\nconst ${name} = {`);
    assert.notEqual(start, -1, `${name} is missing from app.js`);
    const [open, close] = braceMatch(start, name);
    return app.slice(open, close + 1);
}
function functionBody(name) {
    const start = app.indexOf(`\nfunction ${name}(`);
    assert.notEqual(start, -1, `function ${name} is missing from app.js`);
    const [open, close] = braceMatch(app.indexOf(")", start), name);
    return app.slice(open + 1, close);
}
const params = (signature) => signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
    .split(",").map((p) => p.trim()).filter(Boolean);
function compile(signature, env) {
    const body = methodBody(signature).replaceAll("this.", "self.");
    const names = Object.keys(env);
    const f = new Function(...names, "self", ...params(signature),
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => f(...names.map((n) => env[n]), self, ...args);
}
function build(name, env) {
    env = { addInOrder, ...env };   // the message stores' order (lib/message_order.js)
    const names = Object.keys(env);
    return new Function(...names, `return ${objectLiteral(name)};`)(...names.map((n) => env[n]));
}
function fn(name, args, env) {
    const names = Object.keys(env);
    return new Function(...names, `return function(${args}) {${functionBody(name)}};`)(...names.map((n) => env[n]));
}
/** The body of connect()'s router message handler. */
function messageHandler(env) {
    const marker = `this._lxmfRouter.on("message", (lxmfMsg) => {`;
    const start = app.indexOf(marker);
    assert.notEqual(start, -1);
    const [open, close] = braceMatch(start + marker.length - 1, "message handler");
    const body = app.slice(open + 1, close).replaceAll("this.", "self.");
    const names = Object.keys(env);
    const f = new Function(...names, "self", "lxmfMsg", body);
    return (self) => (lxmfMsg) => f(...names.map((n) => env[n]), self, lxmfMsg);
}

/** A top-level function of app.js, compiled over `env`, with its own
 *  parameter list. */
function appFunction(name, env) {
    const m = app.match(new RegExp(`\\nfunction ${name}\\(([^)]*)\\)`));
    assert.ok(m, `function ${name} is missing from app.js`);
    return fn(name, m[1], env);
}
/** The group trust rule as app.js defines it: shouldProcessGroupMessage
 *  over groupTrustsSource. */
function groupRule() {
    const groupTrustsSource = appFunction("groupTrustsSource", {});
    return { groupTrustsSource, shouldProcessGroupMessage: appFunction("shouldProcessGroupMessage", { groupTrustsSource }) };
}

// ── fixtures ────────────────────────────────────────────────────────────────

function memory() {
    const data = new Map();
    return {
        data,
        sGet: (k) => (data.has(k) ? JSON.parse(data.get(k)) : null),
        sSet: (k, v) => data.set(k, JSON.stringify(v)),
    };
}
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const hex = (b) => Buffer.from(b).toString("hex");
const quiet = { log() {}, warn() {}, error() {} };
const FIELD_TICKET = 0x0C;
const TICKET = "0123456789abcdef";

/** The real ContactStore, GroupStore, PrivacyFilter and MsgStore over one
 *  storage, as a page load builds them. */
function stores(me, storage = memory()) {
    const events = [];
    const Harness = { recordInbound() {}, event: (kind, detail) => events.push({ kind, detail }), error() {} };
    const { sGet, sSet } = storage;
    const ContactStore = build("ContactStore", {
        sGet, sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    const GroupStore = build("GroupStore", {
        sGet, sSet, Buffer, crypto: globalThis.crypto, Date, IdMgr: { hash: null },
        ownLxmfDestinationHash: () => lxmfHash(me),
    });
    GroupStore.init();
    const PrivacyFilter = build("PrivacyFilter", {
        sGet, sSet, ContactStore, GroupStore, Harness, LXMF, LXMessage, Buffer, ...groupRule(),
    });
    PrivacyFilter.init();
    const MsgStore = build("MsgStore", { sGet, sSet, Harness, Date });
    const drops = () => events.filter((e) => e.kind === "privacy-drop").map((e) => e.detail);
    return { storage, Harness, events, drops, ContactStore, GroupStore, PrivacyFilter, MsgStore };
}

/**
 * A web client receiving: the real LXMRouter given the real PrivacyFilter,
 * as connect() builds it, and the real message handler behind it.
 */
function recipient({ me = Identity.create(), storage } = {}) {
    const s = stores(me, storage);
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    const router = new LXMRouter({ registerDestination: () => destination }, me, { filter: s.PrivacyFilter });
    const self = { _onMsg: [], _pendingTickets: new Map(), groups: [], transfers: [] };
    self._handleGroupMessage = (...a) => self.groups.push(a);
    self._handleDistroIdentityTransfer = (...a) => self.transfers.push(a);
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness: s.Harness, console: quiet,
        RnsClient: { ownHash: lxmfHash(me) }, LXMF, LXMessage, ContactStore: s.ContactStore, MsgStore: s.MsgStore,
        decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self);
    const emitted = [];
    router.on("message", (m) => { emitted.push(m); handle(m); });
    const proofs = [];
    return {
        me, ...s, router, destination, self, emitted, proofs,
        /** An opportunistic packet: what the destination hands the router
         *  once it has decrypted it (source | signature | payload). */
        packet(packed) {
            destination.emit("packet", { data: packed.subarray(16), packet: { prove: () => proofs.push(packed) } });
        },
    };
}

/** `b` of a link pair, as an incoming LXMF delivery link of `r`'s router. */
async function deliveryLink(r) {
    const pair = linkPair();
    pair.b.accept = () => {};                     // already established here
    r.destination.emit("link_request", pair.b);
    await settle();
    return pair;
}

/** Count LXMessage.fromBytes calls (msgpack, hash and signature check). */
function watchParses(t) {
    const real = LXMessage.fromBytes;
    const calls = [];
    LXMessage.fromBytes = (...a) => { calls.push(a); return real.apply(LXMessage, a); };
    t.after(() => { LXMessage.fromBytes = real; });
    return calls;
}

let clock = Date.now() / 1000;
/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, to, content, fields = new Map()) {
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = Buffer.from(lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(lxmfHash(to), "hex");
    m.title = "";
    m.content = content;
    m.fields = fields;
    return m.pack(from, false);
}
const named = (name, fields = []) => new Map([[0xD1, new Map([[0, Buffer.from(name)]])], ...fields]);
const ticketed = (fields = []) => new Map([...fields, [FIELD_TICKET, TICKET]]);
const linkReplies = (wire) => wire.b.filter((p) => p.packetType === Packet.DATA && p.context === Packet.NONE);
const linkProofs = (wire) => wire.b.filter((p) => p.packetType === Packet.PROOF && p.context === Packet.NONE);

// ── on by default, persisted ───────────────────────────────────────────────

test("the filter is on by default, and the Settings toggle is persisted and applied at once", () => {
    const me = Identity.create();
    const s = memory();
    assert.equal(stores(me, s).PrivacyFilter.on, true, "on with nothing stored (iOS and Android default)");
    stores(me, s).PrivacyFilter.set(false);
    assert.equal(s.sGet("filterStrangers"), false);
    assert.equal(stores(me, s).PrivacyFilter.on, false, "a reload keeps it off");
    stores(me, s).PrivacyFilter.set(true);
    assert.equal(stores(me, s).PrivacyFilter.on, true);

    const settings = methodBody("_renderSettingsModal()");
    assert.match(settings, /h\("h3", \{\}, "Privacy"\)/, "a Privacy section, as on iOS and Android");
    assert.match(settings, /"Privacy filter"/);
    assert.match(settings, /"Only accept messages from contacts you have explicitly added"/, "the natives' words");
    assert.match(settings, /checked: PrivacyFilter\.on,/);
    assert.match(settings, /onChange: \(e\) => \{ PrivacyFilter\.set\(e\.target\.checked\); \}/, "applied on change, no Save needed");
    assert.match(methodBody("async connect()"), /new LXMRouter\(this\._rns, IdMgr\.id, \{ filter: PrivacyFilter, tickets: OutboundTickets \}\)/,
        "the router is built with the filter, so no message arrives before it");
});

// ── the drop costs nothing: every path ─────────────────────────────────────

test("opportunistic: a stranger's packet is dropped before its proof and its parse; a contact's is proved and kept", async (t) => {
    const r = recipient();
    const stranger = Identity.create(), friend = Identity.create();
    const S = lxmfHash(stranger), F = lxmfHash(friend);
    r.ContactStore.add(F);
    r.ContactStore.allow(F);
    const parses = watchParses(t);

    r.packet(lxm(stranger, r.me, "hello from nowhere", named("Stranger")));
    await settle();
    assert.equal(r.proofs.length, 0, "no proof");
    assert.equal(parses.length, 0, "never parsed: no msgpack, no signature check");
    assert.equal(r.emitted.length, 0, "the handler never hears of it");
    assert.equal(r.ContactStore.get(S), null, "no row, so no name");
    assert.deepEqual(r.MsgStore.get(S), [], "nothing stored");
    assert.deepEqual(r.drops(), [{ src: S.slice(0, 12), path: "opportunistic", at: "source" }], "the filter saw the 16-byte source");

    r.packet(lxm(friend, r.me, "hello friend"));
    await settle();
    assert.equal(r.proofs.length, 1, "proved");
    assert.deepEqual(r.MsgStore.get(F).map((m) => m.content), ["hello friend"]);
});

test("opportunistic: a packet the destination could not decrypt is not proved", async () => {
    // RNS Destination.receive calls LXMF only with plaintext; until
    // 2026-09-30 the router proved it and then failed to parse it.
    const r = recipient();
    let proved = 0;
    r.destination.emit("packet", { data: null, packet: { prove: () => proved++ } });
    await settle();
    assert.equal(proved, 0);
    assert.equal(r.emitted.length, 0);
});

test("link packet: a stranger's is never proved, parsed or answered; a contact's is proved", async (t) => {
    const r = recipient();
    const { a, wire } = await deliveryLink(r);
    const stranger = Identity.create(), friend = Identity.create();
    const S = lxmfHash(stranger), F = lxmfHash(friend);
    r.ContactStore.add(F);
    r.ContactStore.allow(F);
    const parses = watchParses(t);

    a.send(lxm(stranger, r.me, "hi there", ticketed([[0xD1, new Map([[0, Buffer.from("Stranger")]])]])));
    await settle(6);
    assert.equal(wire.a.length, 1, "the stranger's packet went over the link");
    assert.equal(wire.b.length, 0, "and nothing came back: no proof, no ticket reply");
    assert.equal(parses.length, 0, "never parsed");
    assert.equal(r.emitted.length, 0);
    assert.equal(r.ContactStore.get(S), null);
    assert.deepEqual(r.drops(), [{ src: S.slice(0, 12), path: "link", at: "source" }]);

    a.send(lxm(friend, r.me, "hi friend", ticketed()));
    await settle(6);
    assert.equal(linkProofs(wire).length, 1, "proved once (until 2026-09-30 the link proved it and the router again)");
    assert.equal(linkReplies(wire).length, 0, "and nothing else: LXMF has no ticket reply (lxmf_tickets.test.mjs)");
    assert.deepEqual(r.MsgStore.get(F).map((m) => m.content), ["hi friend"]);

    // Only the delivery link waits for the router: any other link still
    // proves every data packet as it arrives (Link.proveAll).
    const plain = linkPair();
    plain.b.on("packet", () => {});
    plain.a.send(Buffer.alloc(40, 7));
    await settle(6);
    assert.equal(plain.b.proveAll, true);
    assert.equal(linkProofs(plain.wire).length, 1);
});

test("a packet whose source the filter keeps is proved even when it does not parse (LXMF delivery_packet), on both paths; a stranger's is not", async () => {
    // LXMRouter.py delivery_packet proves before it parses, and LXMF gives
    // link packets to the same function (delivery_link_established). Only
    // the filter's drops go unproved.
    const r = recipient();
    const friend = Identity.create(), stranger = Identity.create();
    const F = lxmfHash(friend), S = lxmfHash(stranger);
    r.ContactStore.add(F);
    r.ContactStore.allow(F);
    const junk = (src) => Buffer.concat([Buffer.from(src, "hex"), Buffer.alloc(64, 1), Buffer.from([0xc1, 0xc1])]);

    let proved = 0;
    r.destination.emit("packet", { data: junk(F), packet: { prove: () => proved++ } });
    r.destination.emit("packet", { data: junk(S), packet: { prove: () => proved++ } });
    await settle();
    assert.equal(proved, 1, "opportunistic: the contact's unparseable packet is proved, the stranger's is not");

    const { a, wire } = await deliveryLink(r);
    a.send(Buffer.concat([r.destination.hash, junk(F)]));
    await settle(6);
    assert.equal(linkProofs(wire).length, 1, "link: the contact's unparseable packet is proved, as before 2026-09-30");
    a.send(Buffer.concat([r.destination.hash, junk(S)]));
    await settle(6);
    assert.equal(linkProofs(wire).length, 1, "link: the stranger's is not");
    assert.equal(r.emitted.length, 0, "neither is a message");
    assert.deepEqual(r.drops().map((d) => [d.src, d.path]), [[S.slice(0, 12), "opportunistic"], [S.slice(0, 12), "link"]]);
});

test("a link payload with no plaintext is ignored and never proved, whatever the filter says", () => {
    // RNS Link.receive calls LXMF only with what it decrypted (RNS/Link.py
    // receive); with the filter off every source passes step 1, so only this
    // guard keeps the parse-failure proof above off such a payload.
    const r = recipient();
    r.PrivacyFilter.set(false);
    let proved = 0;
    for (const payload of [null, undefined]) {
        assert.equal(r.router.handleLinkPayload(null, payload, "link", () => proved++), false);
    }
    assert.equal(proved, 0);
    assert.deepEqual(r.drops(), [], "and it is no privacy drop");
});

test("link Resource: a stranger's is transferred (its source is inside) but dropped unparsed, with no ticket reply", async (t) => {
    const r = recipient();
    const { a, wire } = await deliveryLink(r);
    const stranger = Identity.create(), friend = Identity.create();
    const S = lxmfHash(stranger), F = lxmfHash(friend);
    r.ContactStore.add(F);
    r.ContactStore.allow(F);
    const big = "x".repeat(3000);   // over the link MDU: LXMF sends it as a Resource
    const fromStranger = lxm(stranger, r.me, big, ticketed());
    const fromFriend = lxm(friend, r.me, big, ticketed());
    const parses = watchParses(t);

    // An LXMF delivery link is not identified, so the advertisement cannot
    // be judged; the Resource protocol proves it on assembly (RNS/Resource.py).
    await within(a.sendResource(fromStranger), 5000, "the stranger's Resource");
    await settle(6);
    assert.equal(parses.length, 0, "never parsed");
    assert.equal(r.emitted.length, 0);
    assert.equal(linkReplies(wire).length, 0, "no ticket reply");
    assert.equal(r.ContactStore.get(S), null);
    assert.deepEqual(r.drops(), [{ src: S.slice(0, 12), path: "resource", at: "source" }]);

    await within(a.sendResource(fromFriend), 5000, "the contact's Resource");
    await settle(6);
    assert.equal(r.emitted.length, 1);
    assert.equal(linkReplies(wire).length, 0, "nor a kept one: LXMF has no ticket reply");
    assert.equal(r.MsgStore.get(F)[0].content.length, 3000);
});

test("propagated: a stranger's message is dropped after decryption and before any parse, and still purged from the node", async (t) => {
    const r = recipient();
    const stranger = Identity.create(), friend = Identity.create();
    const S = lxmfHash(stranger), F = lxmfHash(friend);
    r.ContactStore.add(F);
    r.ContactStore.allow(F);
    const myHash = r.destination.hash;
    const blobs = [lxm(stranger, r.me, "stored for you", named("Stranger")), lxm(friend, r.me, "stored by a friend")]
        .map((p) => Buffer.concat([myHash, r.me.encrypt(p.subarray(16))]));
    const ids = blobs.map((_, i) => Buffer.from([i + 1]));
    const purged = [];
    let unpacks = 0;
    const self = {
        _lxmfRouter: r.router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) { purged.push(...haves.map((h) => h[0])); return true; }
            if (wants) return [blobs[wants[0][0] - 1]];
            return ids;
        },
    };
    const fetch = compile("async _fetchPropagatedMessages()", {
        Link, Buffer, LXMessage, IdMgr: { id: r.me }, console: quiet,
        MsgPack: { unpack: (b) => { unpacks++; return MsgPack.unpack(b); } },
    })(self);
    const parses = watchParses(t);

    await fetch();
    await settle();
    assert.deepEqual(r.emitted.map((m) => m.content), ["stored by a friend"]);
    assert.equal(parses.length, 1, "only the contact's message was parsed");
    assert.equal(unpacks, 0, "no msgpack pre-parse of its own: fromBytes, counted above, is the only parse, and never of the stranger's");
    assert.deepEqual(purged.sort(), [1, 2], "both are reported as had, so the node purges both (LXMRouter.py message_get_response)");
    assert.equal(r.ContactStore.get(S), null);
    assert.deepEqual(r.drops(), [{ src: S.slice(0, 12), path: "propagated", at: "source" }]);
});

test("a filter that throws drops the message, unproved", async () => {
    const me = Identity.create(), friend = Identity.create();
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    const errors = [];
    const realError = console.error;
    console.error = (...a) => errors.push(a.join(" "));
    try {
        const router = new LXMRouter({ registerDestination: () => destination }, me, {
            filter: { acceptsSource() { throw new Error("a bug"); }, acceptsMessage: () => true },
        });
        const emitted = [];
        router.on("message", (m) => emitted.push(m));
        let proved = 0;
        destination.emit("packet", { data: lxm(friend, me, "hi").subarray(16), packet: { prove: () => proved++ } });
        await settle();
        assert.deepEqual([proved, emitted.length], [0, 0]);
        assert.ok(errors.some((e) => /privacy filter failed .*a bug.*dropped/.test(e)), "and says so");
    } finally {
        console.error = realError;
    }
});

// ── the rule ───────────────────────────────────────────────────────────────

test("filter off: a stranger's DM is kept and listed as before, but not allowlisted; back on, the next one is dropped", async () => {
    const r = recipient();
    const stranger = Identity.create();
    const S = lxmfHash(stranger);
    r.PrivacyFilter.set(false);
    r.packet(lxm(stranger, r.me, "first", named("Sam")));
    await settle();
    assert.equal(r.proofs.length, 1, "proved");
    assert.equal(r.ContactStore.isContact(S), true, "auto-added and listed, as before the filter");
    assert.equal(r.ContactStore.allowlisted(S), false, "a plain row, as iOS and Android make for a sender they accept");
    assert.equal(r.ContactStore.get(S).messageName, "Sam", "its name taken");
    assert.equal(r.MsgStore.get(S).length, 1);

    r.PrivacyFilter.set(true);
    r.packet(lxm(stranger, r.me, "second", named("Samuel")));
    await settle();
    assert.equal(r.proofs.length, 1, "not proved");
    assert.equal(r.MsgStore.get(S).length, 1, "not stored");
    assert.equal(r.ContactStore.get(S).messageName, "Sam", "and its name not taken");
});

test("a co-member who is not allowlisted: group traffic for a held group is kept; a DM is dropped unproved and records no name", async (t) => {
    const r = recipient();
    const inviter = Identity.create(), member = Identity.create();
    const I = lxmfHash(inviter), M = lxmfHash(member);
    const G = "9".repeat(32), OTHER = "8".repeat(32);
    r.GroupStore.addPending(G, "G", I, [M]);
    r.ContactStore.keep(M);                      // its key and names, hidden
    assert.equal(r.ContactStore.allowlisted(M), false);

    r.packet(lxm(member, r.me, "", named("Member", [[GROUP_FIELDS.GROUP_ID, G], [GROUP_FIELDS.GROUP_ACTION, "accept"]])));
    await settle();
    assert.equal(r.proofs.length, 1, "a group message for a group held here passes whoever sends it (groupMessagePolicy)");
    assert.equal(r.self.groups.length, 1, "and reaches the group handler");
    assert.equal(r.ContactStore.get(M).messageName, "Member", "named after the policy kept it");

    const parses = watchParses(t);
    r.packet(lxm(member, r.me, "psst, a DM", named("Renamed")));
    await settle();
    assert.equal(parses.length, 1, "the source passed step 1 (a member), so it was parsed ...");
    assert.equal(r.proofs.length, 1, "... and then dropped before the proof");
    assert.deepEqual(r.MsgStore.get(M), [], "nothing stored");
    assert.equal(r.ContactStore.get(M).messageName, "Member", "a dropped message records no name");
    assert.equal(r.ContactStore.isContact(M), false, "still not listed");

    r.packet(lxm(member, r.me, "hi", new Map([[GROUP_FIELDS.GROUP_ID, OTHER]])));
    await settle();
    assert.equal(r.proofs.length, 1, "a group message for a group not held here is dropped unproved");

    r.packet(lxm(member, r.me, "", new Map([[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_TRANSFER_TYPE], [LXMF.FIELD_CUSTOM_DATA, "a".repeat(128)]])));
    await settle();
    assert.equal(r.proofs.length, 2, "a distro identity transfer is offered whoever sends it (iOS, Android)");
    assert.equal(r.self.transfers.length, 1);
    assert.deepEqual(r.drops().map((d) => d.at), ["message", "message"]);
});

test("a co-member's DM over a link or fetched from the node is dropped after the parse: unproved, unanswered, still purged", async () => {
    const r = recipient();
    const inviter = Identity.create(), member = Identity.create();
    const M = lxmfHash(member);
    r.GroupStore.addPending("9".repeat(32), "G", lxmfHash(inviter), [M]);
    const { a, wire } = await deliveryLink(r);

    a.send(lxm(member, r.me, "a DM on a link", ticketed()));
    await settle(6);
    assert.equal(wire.b.length, 0, "no proof and no ticket reply");
    await within(a.sendResource(lxm(member, r.me, "y".repeat(3000), ticketed())), 5000, "the member's Resource");
    await settle(6);
    assert.equal(linkReplies(wire).length, 0, "no ticket reply for the Resource either");

    const blob = Buffer.concat([r.destination.hash, r.me.encrypt(lxm(member, r.me, "a DM left on the node").subarray(16))]);
    const purged = [];
    const self = {
        _lxmfRouter: r.router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) { purged.push(...haves.map((h) => h[0])); return true; }
            return wants ? [blob] : [Buffer.from([7])];
        },
    };
    await compile("async _fetchPropagatedMessages()", {
        Link, Buffer, MsgPack, LXMessage, IdMgr: { id: r.me }, console: quiet,
    })(self)();
    await settle();
    assert.deepEqual(purged, [7], "reported as had, so the node purges it");
    assert.equal(r.emitted.length, 0, "none of the three reached the handler");
    assert.deepEqual(r.MsgStore.get(M), []);
    assert.deepEqual(r.drops().map((d) => [d.path, d.at]), [["link", "message"], ["resource", "message"], ["propagated", "message"]]);
});

test("a group invite is kept only from an allowlisted contact: a channel poster's or an auto-added stranger's is dropped unproved", async () => {
    const r = recipient();
    const poster = Identity.create(), stranger = Identity.create(), friend = Identity.create();
    const P = lxmfHash(poster), S = lxmfHash(stranger), F = lxmfHash(friend);
    const invite = (from, groupId) => lxm(from, r.me, "", new Map([[GROUP_FIELDS.GROUP_ID, groupId], [GROUP_FIELDS.GROUP_ACTION, "invite"],
        [GROUP_FIELDS.GROUP_MEMBERS, `${lxmfHash(from)},${lxmfHash(r.me)}`]]));
    r.ContactStore.keep(P, poster.getPublicKey().toString("hex"));     // a channel poster's bound key
    r.ContactStore.add(S);                                              // auto-added while the filter was off
    r.ContactStore.add(F);
    r.ContactStore.allow(F);

    r.packet(invite(poster, "1".repeat(32)));
    r.packet(invite(stranger, "2".repeat(32)));
    await settle();
    assert.equal(r.proofs.length, 0, "neither is proved");
    assert.equal(r.self.groups.length, 0, "nor reaches the group handler");
    assert.deepEqual(r.drops().map((d) => [d.src, d.at]), [[P.slice(0, 12), "source"], [S.slice(0, 12), "source"]]);

    r.packet(invite(friend, "3".repeat(32)));
    await settle();
    assert.equal(r.proofs.length, 1);
    assert.equal(r.self.groups.length, 1, "the contact's invite is processed");
});

test("a group invite from a co-member who is not allowlisted passes step 1 and is dropped by the router at step 2, unproved", async () => {
    // The router's own invite rule (acceptsMessage): the handler's check
    // would drop it too, but only after the router had proved it, telling
    // the inviter the invite was delivered.
    const r = recipient();
    const inviter = Identity.create(), member = Identity.create();
    const I = lxmfHash(inviter), M = lxmfHash(member);
    r.GroupStore.addPending("9".repeat(32), "G", I, [M]);
    r.ContactStore.keep(M);                      // a co-member: its key, hidden
    const invite = (groupId) => lxm(member, r.me, "", new Map([[GROUP_FIELDS.GROUP_ID, groupId], [GROUP_FIELDS.GROUP_ACTION, "invite"],
        [GROUP_FIELDS.GROUP_MEMBERS, `${M},${lxmfHash(r.me)}`]]));

    r.packet(invite("4".repeat(32)));
    await settle();
    assert.equal(r.proofs.length, 0, "not proved");
    assert.equal(r.self.groups.length, 0, "never reaches the group handler");
    assert.deepEqual(r.drops(), [{ src: M.slice(0, 12), path: "opportunistic", at: "message" }], "a member, so dropped after the parse");

    r.ContactStore.allow(M);
    r.packet(invite("5".repeat(32)));
    await settle();
    assert.equal(r.proofs.length, 1, "once allowlisted, its invite is proved");
    assert.equal(r.self.groups.length, 1, "and processed");
});

// ── a stranger: only a group message for a group held here (iOS) ──────────

/** The real _handleGroupMessage behind `r`'s handler, over its real
 *  GroupStore and ContactStore and a real GroupMsgStore. */
function withGroupHandler(r) {
    const GroupMsgStore = build("GroupMsgStore", { sGet: r.storage.sGet, sSet: r.storage.sSet, Date, ContactStore: r.ContactStore });
    const own = () => lxmfHash(r.me);
    r.self.ownHash = own();
    r.self._onMsg = [];
    r.self._performGroupRelay = () => {};
    r.self._rememberGroupMemberKeys = () => [];
    r.self._keepAttachments = () => {};
    r.self._handleGroupMessage = compile("_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)", {
        GroupStore: r.GroupStore, GroupMsgStore, ContactStore: r.ContactStore, console: quiet, Date, Buffer,
        ownLxmfDestinationHash: own, PrivacyFilter: r.PrivacyFilter, sentTimeMs,
    })(r.self);
    return GroupMsgStore;
}

/** Count the router's look at a stranger's group entries. */
function watchPeeks(t) {
    const real = LXMessage.peekGroupFields;
    const calls = [];
    LXMessage.peekGroupFields = (...a) => { const got = real.apply(LXMessage, a); calls.push(got); return got; };
    t.after(() => { LXMessage.peekGroupFields = real; });
    return calls;
}

/** Every value msgpackr decodes (MsgPack.unpack), as it was decoded. */
function watchUnpacks(t) {
    const real = MsgPack.unpack;
    const decoded = [];
    MsgPack.unpack = (...a) => { const got = real.apply(MsgPack, a); decoded.push(got); return got; };
    t.after(() => { MsgPack.unpack = real; });
    return decoded;
}

/** One /get fetch of `packed` messages through the shipped
 *  _fetchPropagatedMessages; returns the transient ids it purged. */
async function fetchPropagated(r, packed) {
    const blobs = packed.map((p) => Buffer.concat([r.destination.hash, r.me.encrypt(p.subarray(16))]));
    const purged = [];
    const self = {
        _lxmfRouter: r.router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) { purged.push(...haves.map((h) => h[0])); return true; }
            if (wants) return [blobs[wants[0][0] - 1]];
            return blobs.map((_, i) => Buffer.from([i + 1]));
        },
    };
    await compile("async _fetchPropagatedMessages()", {
        Link, Buffer, MsgPack, LXMessage, IdMgr: { id: r.me }, console: quiet,
    })(self)();
    await settle();
    return purged;
}

test("a stranger's group message for a group held here is kept and proved, as iOS keeps it, on every path; named only once kept", async (t) => {
    // iOS groupMessagePolicy asks only whether the group exists here
    // (ChatRepository.swift shouldProcessGroupMessage); James, 2026-09-30:
    // the web keeps it too. Typically a member someone else's re-invite
    // added, whom this client's member list does not have.
    const r = recipient();
    const posts = withGroupHandler(r);
    const member = Identity.create(), stranger = Identity.create();
    const S = lxmfHash(stranger);
    const G = r.GroupStore.create("G", [lxmfHash(member)]).groupId;
    assert.equal(r.PrivacyFilter.knows(S), false, "neither allowlisted nor in any member list here");
    const inG = (extra = []) => new Map([[0xD1, new Map([[0, Buffer.from("Stan")]])], [GROUP_FIELDS.GROUP_ID, G], ...extra]);
    const received = () => posts.get(G).filter((m) => m.dir === "in").map((m) => [m.content, m.srcHash]);
    const parses = watchParses(t);

    r.packet(lxm(stranger, r.me, "opportunistic", inG()));
    await settle();
    assert.equal(r.proofs.length, 1, "proved");
    assert.equal(parses.length, 1, "parsed once it was seen to be one");
    assert.deepEqual(received(), [["opportunistic", S]], "stored in the group");
    const row = r.ContactStore.get(S);
    assert.deepEqual([row.hidden, row.messageName, r.ContactStore.allowlisted(S), r.ContactStore.isContact(S)],
        [true, "Stan", false, false], "named under §5.2 after the policy kept it (source unknown: fills the empty slot); not a contact");

    // The Retichat-field form of the group id (§10, senders after the switch).
    r.packet(lxm(stranger, r.me, "new form", new Map([[0xD1, new Map([[1, G]])]])));
    await settle();
    assert.equal(r.proofs.length, 2);

    // A link packet and a link Resource: proved, as any message kept (and
    // nothing else sent back: LXMF has no ticket reply).
    const { a, wire } = await deliveryLink(r);
    a.send(lxm(stranger, r.me, "link packet", ticketed([[GROUP_FIELDS.GROUP_ID, G]])));
    await settle(6);
    assert.equal(linkProofs(wire).length, 1, "the link packet is proved");
    assert.equal(linkReplies(wire).length, 0, "and no ticket reply");
    await within(a.sendResource(lxm(stranger, r.me, "r".repeat(3000), ticketed([[GROUP_FIELDS.GROUP_ID, G]]))), 5000, "the stranger's Resource");
    await settle(6);
    assert.equal(r.emitted.at(-1)?.content, "r".repeat(3000), "the Resource is kept");
    assert.equal(linkReplies(wire).length, 0, "with no ticket reply");

    // Fetched from the propagation node.
    const purged = await fetchPropagated(r, [lxm(stranger, r.me, "propagated", inG())]);
    assert.deepEqual(purged, [1]);

    assert.deepEqual(received().map(([c]) => c.slice(0, 16)), ["opportunistic", "new form", "link packet", "r".repeat(16), "propagated"]);
    assert.deepEqual(r.drops(), [], "nothing dropped");
    assert.equal(r.events.filter((e) => e.kind === "privacy-group-stranger").length, 5, "each let in by the look at its group");
});

test("a stranger's other messages are dropped after a look at their group id and action only: no proof, no parse, no ticket reply, no name, no row", async (t) => {
    const r = recipient();
    withGroupHandler(r);
    const member = Identity.create(), stranger = Identity.create();
    const S = lxmfHash(stranger);
    const held = r.GroupStore.create("G", [lxmfHash(member)]).groupId;
    const OTHER = "8".repeat(32);
    const parses = watchParses(t);
    const peeks = watchPeeks(t);
    const decoded = watchUnpacks(t);
    const transfer = [[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_TRANSFER_TYPE], [LXMF.FIELD_CUSTOM_DATA, "a".repeat(128)]];
    const cases = [
        ["a DM", named("Stranger")],
        ["a DM with an attachment", named("Stranger", [[0x05, [[Buffer.from("a.bin"), Buffer.alloc(150, 1)]]]])],
        ["a group message for a group not held here", named("Stranger", [[GROUP_FIELDS.GROUP_ID, OTHER]])],
        ["an invite to a group held here (an invite needs an allowlisted source)", named("Stranger", [[GROUP_FIELDS.GROUP_ID, held],
            [GROUP_FIELDS.GROUP_ACTION, "invite"], [GROUP_FIELDS.GROUP_MEMBERS, `${S},${lxmfHash(r.me)}`]])],
        ["a distro identity transfer (Add another device is strict)", new Map(transfer)],
    ];
    for (const [label, fields] of cases) r.packet(lxm(stranger, r.me, label, fields));
    await settle();
    assert.equal(r.proofs.length, 0, "none is proved");
    assert.equal(parses.length, 0, "none is parsed: no full msgpack decode, no hash, no signature check");
    assert.equal(peeks.length, cases.length, "each was looked at once");
    assert.deepEqual(decoded, [OTHER, held, "invite"], "and only group ids and actions were decoded: no name, attachment or member list");
    assert.equal(r.emitted.length, 0);
    assert.equal(r.ContactStore.get(S), null, "no row, so no name");
    assert.deepEqual(r.MsgStore.get(S), []);
    assert.equal(r.self.transfers.length, 0, "no transfer offered");
    assert.deepEqual(r.drops().map((d) => d.at), cases.map(() => "source"));

    // A transfer that also names a held group is let in by the look, then
    // dropped after the parse: still a transfer, still a stranger's.
    r.packet(lxm(stranger, r.me, "", new Map([...transfer, [GROUP_FIELDS.GROUP_ID, held]])));
    await settle();
    assert.deepEqual([r.proofs.length, r.self.transfers.length, r.emitted.length], [0, 0, 0]);
    assert.deepEqual(r.drops().at(-1), { src: S.slice(0, 12), path: "opportunistic", at: "message" });

    // A link packet with a ticket, a link Resource, a /get: dropped the same.
    const { a, wire } = await deliveryLink(r);
    a.send(lxm(stranger, r.me, "a DM on a link", ticketed(named("Stranger"))));
    await settle(6);
    await within(a.sendResource(lxm(stranger, r.me, "q".repeat(3000), ticketed([[GROUP_FIELDS.GROUP_ID, OTHER]]))), 5000, "the Resource");
    await settle(6);
    assert.equal(linkProofs(wire).length, 0, "no proof on the link");
    assert.equal(linkReplies(wire).length, 0, "no ticket reply");
    const purged = await fetchPropagated(r, [lxm(stranger, r.me, "left on the node", named("Stranger"))]);
    assert.deepEqual(purged, [1], "still purged from the node");
    assert.equal(parses.length, 1, "only the transfer naming a held group was ever parsed");
    assert.deepEqual(r.drops().slice(-3).map((d) => [d.path, d.at]), [["link", "source"], ["resource", "source"], ["propagated", "source"]]);
    assert.equal(r.ContactStore.get(S), null);

    // The cheap path is unchanged: a contact's or a member's message is let
    // through on its source alone, with no look at its group entries.
    const friend = Identity.create();
    r.ContactStore.add(lxmfHash(friend));
    r.ContactStore.allow(lxmfHash(friend));
    const looked = peeks.length;
    r.packet(lxm(friend, r.me, "a DM", named("Friend", [[GROUP_FIELDS.GROUP_ID, OTHER]])));
    r.packet(lxm(member, r.me, "in the group", new Map([[GROUP_FIELDS.GROUP_ID, held]])));
    await settle();
    assert.equal(peeks.length, looked, "no look for a source the filter knows");
    assert.equal(r.proofs.length, 1, "the member's group message is proved (the friend's names a group not held here)");
});

test("a stranger's packet let in as a group message but not parseable is not proved; a known source's still is", async (t) => {
    const r = recipient();
    const member = Identity.create(), stranger = Identity.create(), friend = Identity.create();
    const G = r.GroupStore.create("G", [lxmfHash(member)]).groupId;
    r.ContactStore.allow(lxmfHash(friend));
    const real = LXMessage.fromBytes;
    LXMessage.fromBytes = () => null;
    t.after(() => { LXMessage.fromBytes = real; });

    r.packet(lxm(stranger, r.me, "x", new Map([[GROUP_FIELDS.GROUP_ID, G]])));
    r.packet(lxm(friend, r.me, "x"));
    await settle();
    assert.equal(r.proofs.length, 1, "only the friend's (LXMF delivery_packet proves before it parses)");
    const { a, wire } = await deliveryLink(r);
    a.send(lxm(stranger, r.me, "y", new Map([[GROUP_FIELDS.GROUP_ID, G]])));
    await settle(6);
    a.send(lxm(friend, r.me, "y"));
    await settle(6);
    assert.equal(linkProofs(wire).length, 1, "the same on a link");
    assert.equal(r.router.admission(lxm(stranger, r.me, "z", new Map([[GROUP_FIELDS.GROUP_ID, G]])).subarray(16), "t"), "group");
    assert.equal(r.router.admission(lxm(friend, r.me, "z").subarray(16), "t"), "source");
    assert.equal(r.router.admission(lxm(stranger, r.me, "z").subarray(16), "t"), null);
});

test("a distro sent copy reaching this device's own address is dropped before the group policy, whoever sent it and filter on or off: unproved, unanswered, unnamed, unstored (iOS)", async () => {
    // RFed SPEC §17.11: a sent copy is addressed to the distro and arrives
    // only as fan-out (_handleDistroBlob). iOS handleIncomingMessage drops
    // one that reaches its router, before it asks the group policy. Review
    // of 1553d80: a stranger's that named a group held here was let in by
    // the look at its group id, then kept and proved (a contact's or a
    // member's always had been, shown as their incoming message).
    const r = recipient();
    const posts = withGroupHandler(r);
    const member = Identity.create(), stranger = Identity.create(), friend = Identity.create();
    const S = lxmfHash(stranger), F = lxmfHash(friend), M = lxmfHash(member);
    r.ContactStore.add(F);
    r.ContactStore.allow(F);
    const G = r.GroupStore.create("G", [M]).groupId;
    const inG = [[GROUP_FIELDS.GROUP_ID, G]];
    const sentCopy = (extra = []) => named("Me", [[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_SENT_TYPE],
        [LXMF.FIELD_CUSTOM_DATA, "c".repeat(32)], [LXMF.FIELD_CUSTOM_META, "d".repeat(32)], ...extra]);
    const copyDrops = () => r.events.filter((e) => e.kind === "sent-copy-drop").map((e) => [e.detail.src, e.detail.path]);
    const groupIn = () => posts.get(G).filter((m) => m.dir === "in").map((m) => m.content);

    // Opportunistic: a stranger's naming a held group (let in by the look),
    // a contact's DM and a member's group message.
    r.packet(lxm(stranger, r.me, "stranger, held group", sentCopy(inG)));
    r.packet(lxm(friend, r.me, "contact, a DM", sentCopy()));
    r.packet(lxm(member, r.me, "member, held group", sentCopy(inG)));
    await settle();
    assert.equal(r.proofs.length, 0, "none is proved");
    assert.equal(r.emitted.length, 0, "none reaches the message handler");

    // A link packet with a ticket, a link Resource with a ticket, a /get.
    const { a, wire } = await deliveryLink(r);
    a.send(lxm(stranger, r.me, "on a link", ticketed([...sentCopy(inG)])));
    await settle(6);
    await within(a.sendResource(lxm(friend, r.me, "s".repeat(3000), ticketed([...sentCopy()]))), 5000, "the Resource");
    await settle(6);
    assert.equal(linkProofs(wire).length, 0, "no proof on the link");
    assert.equal(linkReplies(wire).length, 0, "no ticket reply");
    const purged = await fetchPropagated(r, [lxm(member, r.me, "left on the node", sentCopy(inG))]);
    assert.deepEqual(purged, [1], "still purged from the node");

    // Filter off: still dropped (it is no privacy rule).
    r.PrivacyFilter.set(false);
    r.packet(lxm(stranger, r.me, "filter off", sentCopy()));
    await settle();
    r.PrivacyFilter.set(true);

    assert.deepEqual(copyDrops(), [[S, "opportunistic"], [F, "opportunistic"], [M, "opportunistic"],
        [S, "link"], [F, "resource"], [M, "propagated"], [S, "opportunistic"]].map(([h, p]) => [h.slice(0, 12), p]));
    assert.deepEqual(r.drops(), [], "none is counted a privacy drop");
    assert.equal(r.proofs.length, 0);
    assert.equal(r.emitted.length, 0);
    assert.deepEqual(groupIn(), [], "nothing in the group");
    assert.deepEqual([r.MsgStore.get(F), r.MsgStore.get(S)], [[], []], "no DM");
    assert.equal(r.ContactStore.get(S), null, "no row for the stranger");
    assert.equal(r.ContactStore.get(F).messageName, null, "no name taken");
    assert.equal(r.ContactStore.get(M), null);

    // The marker is what dropped them: the same messages without it are kept.
    r.packet(lxm(stranger, r.me, "stranger, held group", named("Stan", inG)));
    r.packet(lxm(friend, r.me, "contact, a DM", named("Fran")));
    r.packet(lxm(member, r.me, "member, held group", named("Mo", inG)));
    await settle();
    assert.equal(r.proofs.length, 3);
    assert.deepEqual(groupIn(), ["stranger, held group", "member, held group"]);
    assert.deepEqual(r.MsgStore.get(F).map((m) => m.content), ["contact, a DM"]);
    assert.equal(r.ContactStore.get(F).messageName, "Fran");
});

test("LXMessage.peekGroupFields reads the group id and action as the full parse does: every Retichat-field vector", async () => {
    const fieldVectors = JSON.parse(await readFile(new URL("../LXMF-rust/tests/retichat_field_vectors.json", import.meta.url), "utf8"));
    // [timestamp, title, content, fields], the fields as the vector's bytes.
    const payload = (fieldsHex, content = Buffer.from("hello")) => Buffer.concat([Buffer.from([0x94]),
        MsgPack.pack(1700000000.5), MsgPack.pack(Buffer.from("t")), MsgPack.pack(content), Buffer.from(fieldsHex, "hex")]);
    assert.ok(fieldVectors.decode.length >= 30);
    for (const v of fieldVectors.decode) {
        const want = v.group.group_id === null ? null : { groupId: v.group.group_id, groupAction: v.group.group_action };
        assert.deepEqual(LXMessage.peekGroupFields(payload(v.fields_msgpack_hex)), want, v.name);
        const full = LXMessage.extractGroupFields(LXMessage.decodePayload(payload(v.fields_msgpack_hex)).fields);
        assert.deepEqual(full ? { groupId: full.groupId, groupAction: full.groupAction } : null, want, `the full parse agrees: ${v.name}`);
    }
    const G = "0123456789abcdef0123456789abcdef";
    const fieldsHex = (m) => MsgPack.pack(m).toString("hex");
    // A float field number reads as that integer in msgpackr, so here too.
    assert.deepEqual(LXMessage.peekGroupFields(payload("81cb406a200000000000" + MsgPack.pack(new Map([[1, G]])).toString("hex"))),
        { groupId: G, groupAction: null }, "0xD1 as a float64 key");
    assert.equal(LXMessage.extractGroupFields(LXMessage.decodePayload(
        payload("81cb406a200000000000" + MsgPack.pack(new Map([[1, G]])).toString("hex"))).fields)?.groupId, G);
    // A big content and attachment are skipped, not read.
    assert.deepEqual(LXMessage.peekGroupFields(payload(fieldsHex(new Map([[0x05, [[Buffer.from("a"), Buffer.alloc(100000)]]], [0xA0, G]])),
        Buffer.alloc(200000))), { groupId: G, groupAction: null });
    // Not a payload, or cut short: no group.
    for (const bad of [Buffer.alloc(0), Buffer.from([0x93, 0x01, 0xa0, 0xa0]), Buffer.from([0xc1]),
        payload(fieldsHex(new Map([[0xA0, G]]))).subarray(0, 30), Buffer.from([0x94, 0x01, 0xa0, 0xa0, 0xc0])]) {
        assert.equal(LXMessage.peekGroupFields(bad), null, bad.toString("hex"));
    }
});

// ── James's group trust rule (2026-10-01) ─────────────────────────────────
//
// "Groups start by invite. If the invite doesn't come from someone on the
// allowlist, it is ignored. If the invite is accepted, the other group
// members are considered allowed." A group control message (accept, leave,
// relay_req, any action) for a group held here is taken only from a source
// that is allowlisted or a current member of that group; a plain group
// message is still kept from anyone (James, 2026-09-30).

/** `r` with the real group handler, a held group G (created here: this
 *  device accepted, `members` invited) and every relay it is asked for. */
function trustFixture(members) {
    const r = recipient();
    const posts = withGroupHandler(r);
    const relays = [];
    r.self._performGroupRelay = (...a) => relays.push(a);
    const G = r.GroupStore.create("G", members).groupId;
    const memberList = () => [...r.GroupStore.get(G).members.entries()].sort();
    const notices = () => posts.get(G).filter((m) => m.dir === "system").map((m) => [m.content, m.actor ?? null]);
    const control = (action, extra = []) => new Map([[0xD1, new Map([[0, Buffer.from("Named")]])], [GROUP_FIELDS.GROUP_ID, G],
        [GROUP_FIELDS.GROUP_ACTION, action], ...extra]);
    const sender = (h) => [GROUP_FIELDS.GROUP_SENDER, h];
    return { r, posts, relays, G, memberList, notices, control, sender };
}

test("group trust rule: a stranger's accept, leave or relay_req for a held group is dropped before its proof on every path: no member, no allowlisting, no relay, no row, no name", async (t) => {
    const member = Identity.create(), stranger = Identity.create(), other = Identity.create();
    const M = lxmfHash(member), S = lxmfHash(stranger), X = lxmfHash(other);
    const f = trustFixture([M]);
    const { r, G } = f;
    const before = f.memberList();
    const parses = watchParses(t);
    const cases = [
        ["its own accept", f.control("accept", [f.sender(S)])],
        ["an accept for a hash it claims", f.control("accept", [f.sender(X)])],
        ["an accept with no GROUP_SENDER", f.control("accept")],
        ["a leave in a member's name", f.control("leave", [f.sender(M)])],
        ["its own leave", f.control("leave", [f.sender(S)])],
        ["a relay request", f.control("relay_req", [f.sender(S), [GROUP_FIELDS.GROUP_RELAY_SEEN, S]])],
        ["a relay done", f.control("relay_done", [f.sender(S)])],
        ["an action this client does not know", f.control("promote", [f.sender(S)])],
    ];
    for (const [label, fields] of cases) r.packet(lxm(stranger, r.me, label, fields));
    await settle();

    // A link packet, a link Resource and a /get: dropped the same.
    const { a, wire } = await deliveryLink(r);
    a.send(lxm(stranger, r.me, "", ticketed([...f.control("accept", [f.sender(S)])])));
    await settle(6);
    await within(a.sendResource(lxm(stranger, r.me, "z".repeat(3000), ticketed([...f.control("relay_req", [f.sender(S)])]))), 5000, "the Resource");
    await settle(6);
    const purged = await fetchPropagated(r, [lxm(stranger, r.me, "", f.control("leave", [f.sender(M)]))]);

    assert.equal(r.proofs.length, 0, "none is proved");
    assert.deepEqual([linkProofs(wire).length, linkReplies(wire).length], [0, 0], "nothing back on the link");
    assert.deepEqual(purged, [1], "still purged from the node");
    assert.equal(parses.length, 0, "none is parsed: the look at the group id and action decided");
    assert.equal(r.emitted.length, 0, "the handler never hears of one");
    assert.deepEqual(f.memberList(), before, "the members are as they were: nobody added, nobody left");
    assert.deepEqual(f.relays, [], "nothing relayed");
    assert.deepEqual([r.ContactStore.get(S), r.ContactStore.get(X)], [null, null], "no row, so no allowlisting and no name");
    assert.equal(r.ContactStore.allowlisted(M), false, "and the member's standing is untouched");
    assert.deepEqual(f.notices(), [], "no notice");
    assert.deepEqual(r.drops().map((d) => [d.path, d.at]),
        [...cases.map(() => ["opportunistic", "source"]), ["link", "source"], ["resource", "source"], ["propagated", "source"]]);
    assert.equal(r.events.filter((e) => e.kind === "privacy-group-stranger").length, 0);

    // A plain message from the same stranger, for the same group, is kept
    // and proved (James, 2026-09-30, as iOS keeps it).
    r.packet(lxm(stranger, r.me, "just talking", new Map([[GROUP_FIELDS.GROUP_ID, G]])));
    await settle();
    assert.equal(r.proofs.length, 1, "proved");
    assert.deepEqual(f.posts.get(G).filter((m) => m.dir === "in").map((m) => [m.content, m.srcHash]), [["just talking", S]]);
    assert.deepEqual(f.memberList(), before, "and it makes nobody a member");
    assert.equal(r.ContactStore.allowlisted(S), false, "nor allowlisted");
});

test("group trust rule: a member of another group, or one who left this one, is no source for this group's control messages: parsed, then dropped unproved", async () => {
    const member = Identity.create(), elsewhere = Identity.create(), gone = Identity.create();
    const M = lxmfHash(member), E = lxmfHash(elsewhere), L = lxmfHash(gone);
    const f = trustFixture([M, L]);
    const { r } = f;
    r.GroupStore.create("Other", [E]);
    r.GroupStore.updateMember(f.G, L, "left");
    const before = f.memberList();

    r.packet(lxm(elsewhere, r.me, "", f.control("accept", [f.sender(E)])));
    r.packet(lxm(elsewhere, r.me, "", f.control("relay_req", [f.sender(E)])));
    r.packet(lxm(gone, r.me, "", f.control("accept", [f.sender(L)])));
    await settle();
    assert.equal(r.proofs.length, 0, "none is proved");
    assert.deepEqual(f.memberList(), before);
    assert.deepEqual(f.relays, []);
    assert.deepEqual([r.ContactStore.allowlisted(E), r.ContactStore.allowlisted(L)], [false, false]);
    assert.deepEqual(r.drops().map((d) => [d.src, d.at]), [[E, "message"], [E, "message"], [L, "message"]].map(([h, at]) => [h.slice(0, 12), at]),
        "each passed step 1 as a member of some group held here, and was dropped after the parse");

    // Their plain messages for the group are kept.
    r.packet(lxm(elsewhere, r.me, "hi", new Map([[GROUP_FIELDS.GROUP_ID, f.G]])));
    await settle();
    assert.equal(r.proofs.length, 1);
});

test("group trust rule: an allowed source's accept brings in the member it names (GROUP_SENDER) as a member, allowed; a current member's too; a hash that is none is ignored", async () => {
    const member = Identity.create(), friend = Identity.create(), n1 = Identity.create(), n2 = Identity.create(), stranger = Identity.create();
    const M = lxmfHash(member), F = lxmfHash(friend), N1 = lxmfHash(n1), N2 = lxmfHash(n2), S = lxmfHash(stranger);
    const f = trustFixture([M]);
    const { r, G } = f;
    r.ContactStore.add(F);
    r.ContactStore.allow(F);                                // an allowlisted contact, not in G

    // The allowlisted contact relays N1's accept: N1 is a member, allowed.
    r.packet(lxm(friend, r.me, "", f.control("accept", [f.sender(N1)])));
    // M, invited here and not allowlisted, a current member: its own accept,
    // and one it relays for N2.
    r.packet(lxm(member, r.me, "", f.control("accept", [f.sender(M)])));
    r.packet(lxm(member, r.me, "", f.control("accept", [f.sender(N2)])));
    await settle();
    assert.equal(r.proofs.length, 3, "each is proved");
    const status = (h) => r.GroupStore.get(G).members.get(h);
    assert.deepEqual([N1, M, N2].map(status), ["accepted", "accepted", "accepted"], "members, accepted");
    assert.deepEqual([N1, M, N2].map((h) => r.ContactStore.allowlisted(h)), [true, true, true], "and they pass the filter from now on");
    assert.deepEqual([N1, N2].map((h) => [r.ContactStore.get(h).hidden, r.ContactStore.isContact(h)]), [[true, false], [true, false]],
        "a hidden row each, listed nowhere (audit L4)");
    assert.equal(r.ContactStore.allowlisted(F), true, "the relayer was already");
    assert.deepEqual(f.notices().filter(([text]) => text === "joined the group").map(([, actor]) => actor), [N1, M, N2]);

    // N1, brought in, is now an allowed source: its DM is kept, and its
    // relay request is honoured for the member it names.
    r.packet(lxm(n1, r.me, "a DM from a new member"));
    r.packet(lxm(n1, r.me, "relay this", f.control("relay_req", [f.sender(N1), [GROUP_FIELDS.GROUP_RELAY_SEEN, M]])));
    await settle();
    assert.deepEqual(r.MsgStore.get(N1).map((m) => m.content), ["a DM from a new member"]);
    assert.equal(f.relays.length, 1, "relayed");
    const [group, content, originalSender, seen, requester] = f.relays[0];
    assert.deepEqual([group.groupId, content, originalSender, seen, requester], [G, "relay this", N1, [M], N1]);

    // A member's leave marks it, from an allowed source.
    r.packet(lxm(member, r.me, "", f.control("leave", [f.sender(M)])));
    await settle();
    assert.equal(status(M), "left");

    // An allowed source's accept that names no destination hash adds nothing.
    const junk = "x".repeat(32);
    r.packet(lxm(friend, r.me, "", f.control("accept", [f.sender(junk)])));
    await settle();
    assert.equal(r.GroupStore.get(G).members.has(junk), false, "no such member");
    assert.equal(r.ContactStore.get(junk), null, "and no row");

    // With the filter off every source passes it (PrivacyFilter.allows, as
    // for invites; iOS allowlistDecision filter-disabled): a stranger's
    // accept is taken then.
    r.PrivacyFilter.set(false);
    r.packet(lxm(stranger, r.me, "", f.control("accept", [f.sender(S)])));
    await settle();
    assert.equal(status(S), "accepted", "filter off: taken");
});

test("accepting an invite allows every member of the group, whatever row it has; this device never gets one, and a member with no key holds the accept back (iOS, Android)", () => {
    // James, 2026-10-01: "If the invite is accepted, the other group
    // members are considered allowed." iOS acceptGroupInvite and Android
    // allowlist every member through ensureAllowlistedContact, which also
    // creates a row; all three hold the accept back until every member's
    // key has arrived (a key is kept on a row), so no member is row-less
    // here when it is accepted.
    const me = Identity.create();
    const ME = lxmfHash(me);
    const { ContactStore, GroupStore } = stores(me);
    const [inviter, keyed, named, listed, keyless] = [1, 2, 3, 4, 5].map(() => Identity.create());
    const [I, K, N, Ls, KL] = [inviter, keyed, named, listed, keyless].map(lxmfHash);
    const key = (id) => id.getPublicKey().toString("hex");
    ContactStore.add(I, false, key(inviter));
    ContactStore.allow(I);                                         // the allowlisted inviter
    ContactStore.keep(K, key(keyed));                              // a co-member's key, hidden
    ContactStore.keep(N, null, true);                              // a name-only row...
    ContactStore.get(N).publicKey = key(named);                    // ...whose key an announce brought
    ContactStore.add(Ls, false, key(listed));                      // listed, not allowlisted (kept while the filter was off)
    const G = "d".repeat(32);
    GroupStore.addPending(G, "G", I, [K, N, Ls, ME]);
    const alerts = [];
    const sent = [];
    const accept = compile("_acceptGroupInvite(groupId)", {
        GroupStore, ContactStore, GroupMsgStore: { addSystem() {} }, console: quiet,
        RnsClient: { ownHash: ME, _requestGroupPeer() {}, sendGroupAccept: async (id) => { sent.push(id); } },
        alert: (m) => alerts.push(m),
    })({ render() {} });

    accept(G);
    assert.deepEqual([alerts.length, sent], [0, [G]], "accepted and announced");
    assert.equal(GroupStore.get(G).groupStatus, "active");
    assert.deepEqual([I, K, N, Ls].map((h) => ContactStore.allowlisted(h)), [true, true, true, true], "every member passes the filter");
    assert.equal(ContactStore.get(N).nameOnly, false, "a name-only row is one no longer");
    assert.deepEqual([K, N].map((h) => ContactStore.get(h).hidden), [true, true], "hidden rows stay hidden (audit L4)");
    assert.equal(ContactStore.isContact(Ls), true, "and a listed one listed");
    assert.equal(ContactStore.get(ME), null, "never this device");

    // A member whose key has not arrived (no row) holds the accept back.
    const H = "e".repeat(32);
    GroupStore.addPending(H, "H", I, [KL, ME]);
    accept(H);
    assert.equal(alerts.length, 1, "Still receiving member keys");
    assert.equal(GroupStore.get(H).groupStatus, "pending");
    assert.equal(ContactStore.get(KL), null, "nothing allowed before the user's accept");
});

/**
 * A group the user has not accepted (pending), from an allowlisted
 * inviter I listing B, C and D, whose keys are known (hidden rows, not
 * allowlisted), and X, a key known here and in no list. Before the user
 * answers: B tries to speak for others, B, C and D accept or leave for
 * themselves, I relays X's accept, and B posts naming C.
 */
async function pendingGroup() {
    const r = recipient();
    const posts = withGroupHandler(r);
    const relays = [];
    r.self._performGroupRelay = (...a) => relays.push(a);
    const ids = { inviter: Identity.create(), b: Identity.create(), c: Identity.create(), d: Identity.create(), x: Identity.create() };
    const [I, B, C, D, X] = Object.values(ids).map(lxmfHash);
    const ME = lxmfHash(r.me);
    const key = (id) => id.getPublicKey().toString("hex");
    r.ContactStore.add(I, false, key(ids.inviter));
    r.ContactStore.allow(I);
    for (const id of [ids.b, ids.c, ids.d, ids.x]) r.ContactStore.keep(lxmfHash(id), key(id));
    const G = "c".repeat(32);
    r.GroupStore.addPending(G, "G", I, [B, C, D, ME]);
    const control = (action, sender = null, extra = []) => new Map([[GROUP_FIELDS.GROUP_ID, G], [GROUP_FIELDS.GROUP_ACTION, action],
        ...(sender ? [[GROUP_FIELDS.GROUP_SENDER, sender]] : []), ...extra]);
    const status = (h) => r.GroupStore.get(G)?.members.get(h);
    const allowed = (...hs) => hs.map((h) => r.ContactStore.allowlisted(h));
    const incoming = () => (r.storage.sGet("gmsg_" + G) ?? []).filter((m) => m.dir === "in").map((m) => [m.content, m.srcHash]);

    // B, listed and not allowed, speaks for others: each is parsed (B is in
    // a member list here, so step 1 lets it through) and dropped unproved.
    r.packet(lxm(ids.b, r.me, "", control("accept", X)));
    r.packet(lxm(ids.b, r.me, "", control("leave", C)));
    r.packet(lxm(ids.b, r.me, "relay me", control("relay_req", B, [[GROUP_FIELDS.GROUP_RELAY_SEEN, B]])));
    r.packet(lxm(ids.b, r.me, "", control("relay_done", B)));
    r.packet(lxm(ids.b, r.me, "", control("promote", B)));
    await settle();
    assert.equal(r.proofs.length, 0, "none is proved");
    assert.deepEqual(r.drops().map((d) => [d.src, d.at]), Array(5).fill([B.slice(0, 12), "message"]),
        "each dropped after the parse, before the proof");
    assert.deepEqual([status(X), status(C)], [undefined, "invited"], "nobody added, nobody left");
    assert.deepEqual(relays, [], "nothing relayed for a pending group's listed member");
    assert.deepEqual(allowed(X, B, C), [false, false, false], "nobody allowed");

    // For themselves: B with its own GROUP_SENDER, C with none, D's leave.
    // Recorded (the group fans out to accepted members only), and nobody
    // is allowed by it.
    r.packet(lxm(ids.b, r.me, "", control("accept", B.toUpperCase())));
    r.packet(lxm(ids.c, r.me, "", control("accept")));
    r.packet(lxm(ids.d, r.me, "", control("leave", D)));
    await settle();
    assert.equal(r.proofs.length, 3, "each is proved");
    assert.deepEqual([B, C, D].map(status), ["accepted", "accepted", "left"]);
    assert.deepEqual(allowed(B, C, D), [false, false, false], "a member of a pending group is allowed nothing by its own accept");

    // The allowlisted inviter relays X's accept: X is a member, allowed
    // only if the user accepts.
    r.packet(lxm(ids.inviter, r.me, "", control("accept", X)));
    await settle();
    assert.equal(status(X), "accepted");
    assert.equal(r.ContactStore.allowlisted(X), false, "not allowed before the user accepts");

    // B's post naming C is kept and shown as B's (it speaks only for itself).
    r.packet(lxm(ids.b, r.me, "from B, naming C", new Map([[GROUP_FIELDS.GROUP_ID, G], [GROUP_FIELDS.GROUP_SENDER, C]])));
    await settle();
    assert.equal(r.proofs.length, 5);
    assert.deepEqual(incoming(), [["from B, naming C", B]]);
    return { r, ids, I, B, C, D, X, ME, G, posts, relays, control, status, allowed, incoming };
}

test("group trust rule, a group the user has not accepted: a listed member who is not allowed accepts or leaves for itself only, allowed nothing by it; it cannot speak for anyone, leave in another's name or have this client relay", async () => {
    // James, 2026-10-01: "If the invite is accepted, the other group
    // members are considered allowed." Until the user accepts, the members
    // an invite lists are only listed (groupTrustsSource).
    const p = await pendingGroup();

    // The user declines: nobody the group brought is left allowed, and X's
    // DM is dropped unproved.
    const decline = compile("_declineGroupInvite(groupId)", {
        confirm: () => true, GroupMsgStore: p.posts, GroupStore: p.r.GroupStore,
        document: { body: { classList: { remove() {} } } },
    })({ state: { activeHash: null }, render() {} });
    decline(p.G);
    assert.equal(p.r.GroupStore.get(p.G), null, "declined");
    assert.deepEqual(p.allowed(p.B, p.C, p.D, p.X), [false, false, false, false], "a decline leaves nobody allowed");
    const proofs = p.r.proofs.length;
    p.r.packet(lxm(p.ids.x, p.r.me, "hello from X"));
    p.r.packet(lxm(p.ids.b, p.r.me, "hello from B"));
    await settle();
    assert.equal(p.r.proofs.length, proofs, "their DMs are dropped unproved");
    assert.deepEqual([p.r.MsgStore.get(p.X), p.r.MsgStore.get(p.B)], [[], []]);
});

test("group trust rule: once the user accepts, every member is allowed, the one an allowed member's accept brought in included, and a member speaks for others", async () => {
    const p = await pendingGroup();
    const alerts = [];
    const accept = compile("_acceptGroupInvite(groupId)", {
        GroupStore: p.r.GroupStore, ContactStore: p.r.ContactStore, GroupMsgStore: p.posts, console: quiet,
        RnsClient: { ownHash: p.ME, _requestGroupPeer() {}, sendGroupAccept: async () => {} },
        alert: (m) => alerts.push(m),
    })({ render() {} });
    accept(p.G);
    assert.deepEqual(alerts, [], "every member's key is here");
    assert.equal(p.r.GroupStore.get(p.G).groupStatus, "active");
    assert.deepEqual(p.allowed(p.I, p.B, p.C, p.X), [true, true, true, true], "every member is allowed, X included");

    // Now B is a member of a group the user accepted: its relayed accept
    // brings in the member it names, allowed (rule item 4), and its relay
    // request is honoured.
    const n = Identity.create(), N = lxmfHash(n);
    p.r.packet(lxm(p.ids.b, p.r.me, "", p.control("accept", N)));
    p.r.packet(lxm(p.ids.b, p.r.me, "relay me", p.control("relay_req", p.B, [[GROUP_FIELDS.GROUP_RELAY_SEEN, p.B]])));
    await settle();
    assert.deepEqual([p.status(N), p.r.ContactStore.allowlisted(N)], ["accepted", true]);
    assert.equal(p.relays.length, 1, "relayed");
});

/**
 * A web client that holds a group invite and answers it with the real
 * handlers: _handleGroupMessage behind the router, the real
 * _rememberGroupMemberKeys, _acceptGroupInvite and _declineGroupInvite.
 */
function answeringClient() {
    const r = recipient();
    const posts = withGroupHandler(r);
    const relays = [];
    r.self._performGroupRelay = (...a) => relays.push(a);
    const ME = lxmfHash(r.me);
    r.self._rememberGroupMemberKeys = compile("_rememberGroupMemberKeys(memberKeys)", {
        Buffer, Identity, Destination, ContactStore: r.ContactStore, console: quiet, ownLxmfDestinationHash: () => ME,
    })(r.self);
    const alerts = [];
    const acceptInvite = compile("_acceptGroupInvite(groupId)", {
        GroupStore: r.GroupStore, ContactStore: r.ContactStore, GroupMsgStore: posts, console: quiet,
        RnsClient: { ownHash: ME, _requestGroupPeer() {}, sendGroupAccept: async () => {} },
        alert: (m) => alerts.push(m),
    })({ render() {} });
    const declineInvite = compile("_declineGroupInvite(groupId)", {
        confirm: () => true, GroupMsgStore: posts, GroupStore: r.GroupStore,
        document: { body: { classList: { remove() {} } } },
    })({ state: { activeHash: null }, render() {} });
    /** `from`'s invite to group `groupId` listing `members` (identities),
     *  each with its key, as one invite chunk. */
    const invite = (from, groupId, members) => lxm(from, r.me, "", new Map([[GROUP_FIELDS.GROUP_ID, groupId],
        [GROUP_FIELDS.GROUP_ACTION, "invite"], [GROUP_FIELDS.GROUP_SENDER, lxmfHash(from)],
        [GROUP_FIELDS.GROUP_MEMBERS, [...members.map(lxmfHash), ME].join(",")],
        [GROUP_FIELDS.GROUP_MEMBER_KEYS, members.map((id) => `${lxmfHash(id)}:${id.getPublicKey().toString("base64")}`).join(",")]]));
    const relayRequest = (from, groupId) => lxm(from, r.me, "relay this", new Map([[GROUP_FIELDS.GROUP_ID, groupId],
        [GROUP_FIELDS.GROUP_ACTION, "relay_req"], [GROUP_FIELDS.GROUP_SENDER, lxmfHash(from)],
        [GROUP_FIELDS.GROUP_RELAY_FOR, lxmfHash(from)], [GROUP_FIELDS.GROUP_RELAY_SEEN, lxmfHash(from)]]));
    const allowed = (...ids) => ids.map((id) => r.ContactStore.allowlisted(lxmfHash(id)));
    const dms = (id) => r.MsgStore.get(lxmfHash(id)).map((m) => m.content);
    return { r, ME, posts, relays, alerts, acceptInvite, declineInvite, invite, relayRequest, allowed, dms };
}

test("group trust rule: an invite allows nobody, its listed co-members and its inviter included, until the user accepts it; a decline, or no answer, leaves them as they were", async () => {
    // James, 2026-10-01: "If the invite is accepted, the other group
    // members are considered allowed." Until then an allowlisted contact's
    // invite allowlisted every co-member whose key checked out the moment
    // it arrived (iOS handleGroupInvite and Android still do), so a
    // declined or never-answered invite left them allowed. The keys are
    // still kept as the invite arrives: the accept needs every one.
    const c = answeringClient();
    const { r } = c;
    const [inviter, b, d] = [1, 2, 3].map(() => Identity.create());
    const [I, B] = [inviter, b].map(lxmfHash);
    r.ContactStore.add(I, false, inviter.getPublicKey().toString("hex"));
    r.ContactStore.allow(I);                                         // the user's contact
    const G1 = "1".repeat(32), G2 = "2".repeat(32), G3 = "3".repeat(32);

    r.packet(c.invite(inviter, G1, [inviter, b]));
    await settle();
    assert.equal(r.proofs.length, 1, "the allowlisted contact's invite is proved");
    assert.equal(r.GroupStore.get(G1)?.groupStatus, "pending");
    assert.equal(r.ContactStore.get(B)?.publicKey, b.getPublicKey().toString("hex"), "the co-member's key is kept as the invite arrives");
    assert.deepEqual(c.allowed(b), [false], "but he is not allowed by the invite");
    assert.equal(r.ContactStore.get(B).hidden, true, "and is listed nowhere (audit L4)");

    // Unanswered, B's DM is dropped unproved: he is listed in a held group,
    // so step 1 lets him through, and step 2 drops a DM from a source that
    // is not allowlisted.
    r.packet(lxm(b, r.me, "a DM while the invite waits"));
    await settle();
    assert.equal(r.proofs.length, 1, "unproved");
    assert.deepEqual(c.dms(b), []);
    assert.deepEqual(r.drops().at(-1), { src: B.slice(0, 12), path: "opportunistic", at: "message" });

    // Declined: nobody is left allowed, and B's DM is still dropped.
    c.declineInvite(G1);
    assert.equal(r.GroupStore.get(G1), null);
    assert.deepEqual(c.allowed(b), [false], "a decline leaves nobody allowed");
    r.packet(lxm(b, r.me, "a DM after the decline"));
    await settle();
    assert.deepEqual([r.proofs.length, c.dms(b)], [1, []], "dropped unproved");

    // Accepted: every member is allowed, and B's DM is kept.
    r.packet(c.invite(inviter, G2, [inviter, b]));
    await settle();
    assert.deepEqual(c.allowed(b), [false], "a second invite allows nobody either");
    c.acceptInvite(G2);
    assert.deepEqual(c.alerts, [], "every member's key arrived with the invite");
    assert.equal(r.GroupStore.get(G2).groupStatus, "active");
    assert.deepEqual(c.allowed(inviter, b), [true, true], "the user's accept allows every member");
    r.packet(lxm(b, r.me, "a DM once the group is accepted"));
    await settle();
    assert.deepEqual(c.dms(b), ["a DM once the group is accepted"]);
    assert.equal(r.proofs.length, 3, "proved");

    // With the filter off an invite is taken from anyone (as iOS), and still
    // allows nobody: back on, the stranger who invited, and the member it
    // listed, are dropped like any stranger.
    const s = Identity.create();
    r.PrivacyFilter.set(false);
    r.packet(c.invite(s, G3, [s, d]));
    await settle();
    assert.equal(r.GroupStore.get(G3)?.groupStatus, "pending", "filter off: the stranger's invite is taken");
    assert.deepEqual(c.allowed(s, d), [false, false], "and allows nobody, the inviter included");
    r.PrivacyFilter.set(true);
    const proofs = r.proofs.length;
    r.packet(lxm(s, r.me, "a DM from the inviter"));
    r.packet(lxm(d, r.me, "a DM from the member it listed"));
    await settle();
    assert.deepEqual([r.proofs.length, c.dms(s), c.dms(d)], [proofs, [], []], "both dropped unproved");
});

test("group trust rule: a plain post names its author (GROUP_SENDER) only from a source the group trusts; a stranger's is its own, whichever member, or this device, it names", async () => {
    // A stranger's plain post for a held group is kept and proved (James,
    // 2026-09-30); shown as written by a member it names, that would be a
    // false outcome (iOS handleGroupChatMessage still shows it so).
    const member = Identity.create(), author = Identity.create(), relayer = Identity.create(), stranger = Identity.create();
    const [M, A, R, S] = [member, author, relayer, stranger].map(lxmfHash);
    const f = trustFixture([M, A, R]);
    const { r, G } = f;
    const ME = lxmfHash(r.me);
    r.ContactStore.keep(M);
    r.ContactStore.allow(M);                                 // allowed (the user created the group with it)
    assert.equal(r.ContactStore.allowlisted(R), false, "R is a current member, not allowlisted");
    const post = (content, sender) => new Map([[GROUP_FIELDS.GROUP_ID, G], ...(sender ? [f.sender(sender)] : [])]);

    r.packet(lxm(stranger, r.me, "I am M, send me the keys", post(null, M)));
    r.packet(lxm(stranger, r.me, "I am you", post(null, ME)));
    r.packet(lxm(stranger, r.me, "I am A", post(null, A.toUpperCase())));
    r.packet(lxm(member, r.me, "A's words, relayed by M", post(null, A)));
    r.packet(lxm(relayer, r.me, "A's words, relayed by R", post(null, A)));
    r.packet(lxm(member, r.me, "M's own", post(null)));
    await settle();
    assert.equal(r.proofs.length, 6, "each is kept and proved");
    assert.deepEqual(f.posts.get(G).filter((m) => m.dir === "in").map((m) => [m.content, m.srcHash]), [
        ["I am M, send me the keys", S],
        ["I am you", S],
        ["I am A", S],
        ["A's words, relayed by M", A],
        ["A's words, relayed by R", A],
        ["M's own", M],
    ]);
    assert.deepEqual(f.memberList().map(([h]) => h).includes(S), false, "the stranger is no member");
    assert.equal(r.ContactStore.allowlisted(S), false, "nor allowed");
});

// ── the allowlist ──────────────────────────────────────────────────────────

test("migration: rows stored before the filter — listed ones become allowlisted, hidden and name-only ones do not", () => {
    const me = Identity.create();
    const s = memory();
    const row = (h, extra = {}) => ({ destHash: h, localName: null, messageName: null, announceName: null, legacyName: null, lastSeen: 1, ...extra });
    const [a, b, c, d, e] = ["a", "b", "c", "d", "e"].map((x) => x.repeat(32));
    s.sSet("contacts_v2", [
        row(a),                                          // before hidden rows existed: a contact
        row(b, { hidden: false, nameOnly: false }),      // a listed contact (or an auto-added stranger)
        row(c, { hidden: true }),                        // a group member's or channel poster's
        row(d, { hidden: true, nameOnly: true }),        // a group sender's name only
        row(e, { hidden: false, allowlisted: false }),   // stored by this build: left as it is
    ]);
    const { ContactStore } = stores(me, s);
    assert.deepEqual([a, b, c, d, e].map((h) => ContactStore.allowlisted(h)), [true, true, false, false, false]);
    assert.ok(s.sGet("contacts_v2").every((x) => typeof x.allowlisted === "boolean"), "persisted");
    const again = stores(me, s).ContactStore;
    assert.deepEqual([a, b, c, d, e].map((h) => again.allowlisted(h)), [true, true, false, false, false], "a second load changes nothing");
    assert.deepEqual([c, d].map((h) => again.get(h).hidden), [true, true], "and lists nothing");
});

test("migration, once: every member of a group held as active passes the filter, rows created where none exist (the group trust rule); a pending group's and this device's do not", () => {
    // James, 2026-10-01: "If the invite is accepted, the other group
    // members are considered allowed." As the phones allowlisted every
    // member at create or accept (iOS createGroupChat / acceptGroupInvite
    // through ensureAllowlistedContact, Android NamesMigration).
    const me = Identity.create(), distro = Identity.create();
    const ME = lxmfHash(me), DISTRO = lxmfHash(distro);
    const row = (h, extra = {}) => ({ destHash: h, localName: null, messageName: null, messageNameAt: null, announceName: null,
        legacyName: null, lastSeen: 1, hidden: true, nameOnly: false, ...extra });
    const [created, accepted, pending, poster, nameOnly, listed, later, rowless] = ["1", "2", "3", "4", "5", "6", "7", "8"].map((x) => x.repeat(32));
    const junk = "not a destination hash, 32 chars";
    const group = (groupId, groupStatus, members) => ({ groupId, groupName: "G", groupStatus, lastActivity: 1,
        members: [[ME, "accepted"], ...members].map(([hash, status]) => ({ hash, status })) });
    const groups = [
        group("a".repeat(32), "active", [[created, "invited"], [nameOnly, "accepted"], [listed, "accepted"], [DISTRO, "invited"], [junk, "invited"]]),  // created here
        group("b".repeat(32), "active", [[accepted, "accepted"], [rowless, "left"]]),                                                                // accepted here
        group("c".repeat(32), "pending", [[pending, "accepted"]]),                                                                                    // not accepted
    ];
    const contacts = (allowlistedKey) => [
        row(created), row(accepted), row(pending), row(poster), row(nameOnly, { nameOnly: true, messageName: "Nell" }),
        row(listed, { hidden: false }), row(ME),
    ].map((c) => (allowlistedKey ? { ...c, allowlisted: false } : c));
    const OWN = [ME, me.hash.toString("hex"), DISTRO];

    // A user who already ran round 2's first step (every row has the key),
    // and one who runs both now (no row has it).
    for (const ranFirstStep of [true, false]) {
        const s = memory();
        s.sSet("contacts_v2", contacts(ranFirstStep));
        s.sSet("groups_v1", groups);
        const { ContactStore, GroupStore } = stores(me, s);
        assert.equal(ContactStore.allowHeldGroupMembers(GroupStore.getAll(), OWN), ranFirstStep ? 5 : 4,
            `members allowed now (first step ran before: ${ranFirstStep})`);
        const allowed = (h) => ContactStore.allowlisted(h);
        assert.deepEqual([created, accepted, nameOnly, listed, rowless].map(allowed), [true, true, true, true, true],
            "every member of a group held as active: a hidden row, a name-only row, a listed one, and one with no row");
        assert.deepEqual([pending, poster, ME].map(allowed), [false, false, false],
            "a pending group's member, a channel poster and this device stay as they are");
        assert.deepEqual([ContactStore.get(DISTRO), ContactStore.get(junk)], [null, null], "no row for this device's distro, nor for a member that is no hash");
        const made = ContactStore.get(rowless);
        assert.deepEqual([made.hidden, made.nameOnly, made.allowlisted, made.publicKey], [true, false, true, null],
            "a member with no row gets a hidden, allowlisted one (iOS ensureAllowlistedContact)");
        assert.deepEqual([ContactStore.get(nameOnly).nameOnly, ContactStore.get(nameOnly).messageName], [false, "Nell"], "a name-only row is one no longer; its name kept");
        assert.deepEqual([created, accepted, nameOnly, rowless].map((h) => ContactStore.get(h).hidden), [true, true, true, true], "and nothing is listed");
        assert.equal(ContactStore.isContact(listed), true, "a listed row stays listed");
        assert.equal(s.sGet("groupMembersAllowlisted"), 2, "recorded with this version's marker");
        assert.ok(s.sGet("contacts_v2").some((c) => c.destHash === rowless && c.allowlisted === true), "persisted");

        // Once: a member met afterwards is not allowlisted by a later load.
        ContactStore.keep(later);
        GroupStore.updateMember("b".repeat(32), later, "accepted");
        const again = stores(me, s);
        assert.equal(again.ContactStore.allowHeldGroupMembers(again.GroupStore.getAll(), OWN), 0);
        assert.deepEqual([created, rowless, later].map((h) => again.ContactStore.allowlisted(h)), [true, true, false], "persisted, and run once");
    }

    // Who ran the narrower first version (23af39f: hidden rows only, marker
    // `true`) runs this one once more: its name-only, listed and row-less
    // members are allowed now.
    const s = memory();
    s.sSet("contacts_v2", contacts(true).map((c) => ([created, accepted].includes(c.destHash) ? { ...c, allowlisted: true } : c)));
    s.sSet("groups_v1", groups);
    s.sSet("groupMembersAllowlisted", true);
    const narrow = stores(me, s);
    assert.equal(narrow.ContactStore.allowHeldGroupMembers(narrow.GroupStore.getAll(), OWN), 3);
    assert.deepEqual([nameOnly, listed, rowless].map((h) => narrow.ContactStore.allowlisted(h)), [true, true, true]);
    assert.equal(s.sGet("groupMembersAllowlisted"), 2);

    // App.start runs it once the identity is loaded and the groups hold
    // this device's delivery hash, with this device's hashes and its distro's.
    const start = methodBody("async start()");
    const own = start.indexOf("GroupStore.migrateOwnMemberHash();");
    const step = start.indexOf("ContactStore.allowHeldGroupMembers(GroupStore.getAll(),\n            [ownLxmfDestinationHash(), IdMgr.hash, DistroManager.lxmfDeliveryHash].filter(Boolean));");
    assert.ok(own > start.indexOf("IdMgr.load()") && step > own, "after IdMgr.load() and migrateOwnMemberHash()");
    assert.ok(step < start.indexOf("ActiveTab.start"), "before the first message can arrive");
});

test("the Identity screen says where a distro identity is received: add the sending device first, and this device's address", () => {
    // "Add another device" onto the web is strict (James, 2026-09-30): the
    // transfer comes from the other device's own address, which the filter
    // drops unless that device is a contact here.
    class El {
        constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.style = {}; this.className = ""; }
        appendChild(c) { this.children.push(c); return c; }
        setAttribute(k, v) { this.attrs[k] = String(v); }
        addEventListener() {}
        get text() { return this.children.map((c) => (c instanceof El ? c.text : c.textContent)).join(" "); }
        find(pred) {
            for (const c of this.children) {
                if (!(c instanceof El)) continue;
                if (pred(c)) return c;
                const f = c.find(pred);
                if (f) return f;
            }
            return null;
        }
    }
    const document = { createElement: (tag) => new El(tag), createTextNode: (text) => ({ textContent: text }) };
    const h = fn("h", "tag, a={}, ...kids", { document });
    const kvRow = fn("kvRow", "key, value, opts = {}", { h, navigator: {}, setTimeout });
    const OWN = "0123456789abcdef0123456789abcdef";
    const section = (DistroManager, ownHash = OWN) => compile("_buildDistroIdentitySection()", {
        h, kvRow, DistroManager, RnsClient: { ownHash }, ownLxmfDestinationHash: () => OWN,
    })({ state: {} })();

    const receive = section({ has: false });
    const hint = receive.find((c) => c.attrs.id === "distro-receive-hint");
    assert.ok(hint, "a hint where the user receives it (no distro identity yet: Generate / Import)");
    assert.match(hint.text, /first add that device as a contact here/);
    // By which address: the phones show the Distro address first, with its
    // own Contact link and the "Add another device" button, but the
    // transfer is signed as the device, so a contact made from the distro
    // link leaves it dropped (review of 23af39f).
    assert.match(hint.text, /by its own address: the Contact link under “This device” on its Identity screen/,
        "the section the phones call “This device”");
    assert.match(hint.text, /\(“Device Identity” on a web page\)/, "and this page calls “Device Identity”");
    assert.match(methodBody("_buildDeviceIdentitySection()"), /h\("h3", \{\}, "Device Identity"\)/, "as this page titles it");
    assert.match(hint.text, /not its Distro address\. The transfer comes from the device's own address, so a contact made from its Distro address does not let it through/);
    assert.match(hint.text, /turn the Privacy filter off/);
    assert.match(hint.text, /dropped and nothing appears/);
    assert.match(hint.text, /“Add another device”/, "named as the phones and this page name it");
    const address = receive.find((c) => c.className === "kv-row" && /This device/.test(c.text));
    assert.ok(address, "this device's address, to give the other device");
    assert.match(address.text, new RegExp(OWN));
    assert.match(section({ has: false }, null).find((c) => c.className === "kv-row" && /This device/.test(c.text)).text,
        new RegExp(OWN), "before the router is up, from the identity");

    const sending = section({ has: true, lxmfDeliveryHash: "d".repeat(32), hash: "e".repeat(32), pubKey: "f".repeat(128), exportLxmaUri: () => "lxma://x" });
    assert.equal(sending.find((c) => c.attrs.id === "distro-receive-hint"), null, "not on the sending side");
});

test("the user allowlists a peer by adding it, writing to it, or creating a group with it", () => {
    const me = Identity.create();
    const { ContactStore, MsgStore } = stores(me);
    const peer = Identity.create();
    const P = lxmfHash(peer);
    ContactStore.add(P, false, peer.getPublicKey().toString("hex"));   // a stranger kept while the filter was off
    assert.equal(ContactStore.allowlisted(P), false);
    const send = compile("sendMessage(contact, content, attachments = [])", { ContactStore, MsgStore, console: quiet })({
        _initialized: false, sendingIdentity: () => ({ hash: lxmfHash(me) }),
    });
    send(ContactStore.get(P), "hello back");
    assert.equal(ContactStore.allowlisted(P), true, "the user's own DM allowlists the recipient");

    // Add Contact, New Conversation (a hash or an lxma:// link) and the
    // harness's addPeer: listed and allowlisted.
    for (const signature of ["_renderAddContactModal()", "_renderDirectForm(top, scroll, footer)"]) {
        assert.match(methodBody(signature), /ContactStore\.add\(hash, false, publicKey\);\s+ContactStore\.allow\(hash\);/, signature);
    }
    assert.match(app, /addPeer\(destHash, publicKeyHex\) \{[\s\S]*?ContactStore\.add\(destHash, false, publicKeyHex \|\| null\);\s+ContactStore\.allow\(destHash\);/);
    // Creating a group allowlists its members (iOS createGroupChat).
    assert.match(methodBody("_renderGroupForm(top, scroll, footer)"), /for \(const hash of selected\) ContactStore\.allow\(hash\);/);
});

test("adding an allowlisted row keeps it allowlisted: a hidden co-member's first DM lists it, and its next DM still passes", async () => {
    // _acceptGroupInvite allowlists members and keeps them hidden; the
    // message handler lists the row with ContactStore.add on a first DM
    // (as _handleDistroBlob does for a distro sender).
    const r = recipient();
    const member = Identity.create();
    const M = lxmfHash(member);
    r.ContactStore.allow(M);
    assert.deepEqual([r.ContactStore.isContact(M), r.ContactStore.allowlisted(M)], [false, true], "allowlisted and hidden");

    r.packet(lxm(member, r.me, "first DM"));
    await settle();
    assert.deepEqual([r.ContactStore.isContact(M), r.ContactStore.allowlisted(M)], [true, true], "listed, still allowlisted");
    r.packet(lxm(member, r.me, "second DM"));
    await settle();
    assert.deepEqual(r.MsgStore.get(M).map((m) => m.content), ["first DM", "second DM"]);
    assert.equal(r.proofs.length, 2, "both proved");

    // add() on its own, and keep(), leave the mark as it is either way.
    const other = "c".repeat(32);
    r.ContactStore.add(other);
    r.ContactStore.add(other);
    assert.equal(r.ContactStore.allowlisted(other), false, "add() does not allowlist");
    r.ContactStore.allow(other);
    r.ContactStore.add(other, true);
    r.ContactStore.keep(other);
    assert.equal(r.ContactStore.allowlisted(other), true);
});

test("distro fan-out is never filtered: a stranger's message to the distro is stored, listed and not allowlisted", () => {
    const me = Identity.create(), distro = Identity.create(), stranger = Identity.create();
    const S = lxmfHash(stranger), D = Buffer.from(lxmfHash(distro), "hex");
    const { ContactStore, MsgStore, PrivacyFilter } = stores(me);
    assert.equal(PrivacyFilter.on, true);
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = Buffer.from(S, "hex");
    m.destinationHash = D;
    m.title = "";
    m.content = "to your distro";
    m.fields = new Map();
    const blob = Buffer.concat([D, distro.encrypt(m.pack(stranger, false).subarray(16))]);
    // Anything that asked the filter would throw inside the method and be
    // reported as a dropped blob (false).
    const trap = new Proxy({}, { get: () => { throw new Error("the distro path asked the privacy filter"); } });
    const handleBlob = compile("_handleDistroBlob(distroHash, blob)", {
        DistroManager: { identity: distro, lxmfDeliveryHash: lxmfHash(distro) },
        MsgPack, Buffer, DistroSeen: { check: () => false }, Harness: { event() {}, error() {} },
        ContactStore, MsgStore, LXMF, Cryptography, LXMessage, decodeDisplayName: DN.decodePayload,
        ownLxmfDestinationHash: () => lxmfHash(me), PrivacyFilter: trap, console: quiet, sentTimeMs,
    })({ ownHash: lxmfHash(me), _pendingTickets: new Map(), _onMsg: [] });
    assert.equal(handleBlob(null, blob), true);
    assert.deepEqual(MsgStore.get(S).map((x) => x.content), ["to your distro"]);
    assert.deepEqual([ContactStore.isContact(S), ContactStore.allowlisted(S)], [true, false],
        "a plain row, as iOS and Android make (ensureContact)");
});
