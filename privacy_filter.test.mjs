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
 * proof. A dropped message gets no proof, no parse, no delivery-ticket
 * reply, no row, no name and no bubble. On every path: opportunistic
 * packets, link packets, link Resources (transferred first: the source is
 * inside) and messages fetched from the propagation node (still purged).
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
        sGet, sSet, ContactStore, GroupStore, Harness, LXMF, LXMessage, Buffer,
        shouldProcessGroupMessage: fn("shouldProcessGroupMessage", "groupAction, inviterAllowed, groupExists", {}),
    });
    PrivacyFilter.init();
    const MsgStore = build("MsgStore", { sGet, sSet, Harness, Date });
    const drops = () => events.filter((e) => e.kind === "privacy-drop").map((e) => e.detail);
    return { storage, Harness, drops, ContactStore, GroupStore, PrivacyFilter, MsgStore };
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
        decodeDisplayName: DN.decodePayload,
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
    assert.match(methodBody("async connect()"), /new LXMRouter\(this\._rns, IdMgr\.id, \{ filter: PrivacyFilter \}\)/,
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

test("link packet: a stranger's is never proved, parsed or answered; a contact's is proved and gets its ticket reply", async (t) => {
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
    assert.equal(linkReplies(wire).length, 1, "and answered with the ticket reply");
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
    assert.equal(linkReplies(wire).length, 1, "the contact's gets its ticket reply");
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
        ownLxmfDestinationHash: () => lxmfHash(me), PrivacyFilter: trap, console: quiet,
    })({ ownHash: lxmfHash(me), _pendingTickets: new Map(), _onMsg: [] });
    assert.equal(handleBlob(null, blob), true);
    assert.deepEqual(MsgStore.get(S).map((x) => x.content), ["to your distro"]);
    assert.deepEqual([ContactStore.isContact(S), ContactStore.allowlisted(S)], [true, false],
        "a plain row, as iOS and Android make (ensureContact)");
});
