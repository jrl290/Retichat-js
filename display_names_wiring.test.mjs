/**
 * DISPLAY NAMES IN THE APP — LXMF-rust/DISPLAY_NAMES.md as app.js applies it.
 *
 * These run the real shipped code from app.js (object literals and method
 * bodies, extracted and compiled over stubs), with real identities, real
 * LXMF packing, real channel envelopes and the real name stores:
 *
 *   §4.1  DMs and group envelopes carry 0xD1 as bin under the ledger; the
 *         decision is made once and kept on the record, so the direct send
 *         and the propagated copy are the same bytes; a delivery proof
 *         records it, a propagation never does.
 *   §4.2  channel posts carry the Channel Display Name by the channel rule.
 *   §5.1  contacts hold localName / messageName / announceName.
 *   §5.2  a received name is taken by the signature table, on the direct,
 *         group and distro paths.
 *   §5.3  one resolver: labels and system notices are named at render.
 *   §5.4  contacts and the own name migrate.
 *   §6    three settings, applied at once.
 *   §2.3  channel posts that fail the key binding plant nothing.
 *
 * Run: node --test display_names_wiring.test.mjs
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
import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import { GroupDeliveryEvidence } from "./lib/rns/group_fallback.js";
import {
    channelLxmPack, channelLxmUnpack, channelIdentity, channelDeliveryHash, channelComputeStamp,
} from "./lib/rns/rfed_channel.js";
import * as DN from "./lib/display_name.js";
import { NameLedger, ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

// ── extraction ──────────────────────────────────────────────────────────────

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
const methodName = (signature) => signature.replace(/^async /, "").split("(")[0];
function compile(signature, env) {
    const body = methodBody(signature).replaceAll("this.", "self.");
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params(signature),
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}
function build(name, env) {
    const names = Object.keys(env);
    return new Function(...names, `return ${objectLiteral(name)};`)(...names.map((n) => env[n]));
}
function fn(name, args, env) {
    const names = Object.keys(env);
    return new Function(...names, `return function(${args}) {${functionBody(name)}};`)(...names.map((n) => env[n]));
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
const nowSecs = () => Math.floor(Date.now() / 1000);
const quiet = { log() {}, warn() {}, error() {} };
const Harness = { recordInbound() {}, event() {}, error() {} };

/** The real ContactStore over `storage`, as a page load builds it. */
function contactStore(storage) {
    const store = build("ContactStore", {
        sGet: storage.sGet, sSet: storage.sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    store.init();
    return store;
}
const msgStore = (storage) => build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });

// ── §5.4 / §5.1 contacts ───────────────────────────────────────────────────

test("§5.4 contacts migrate as they load: nameCustomized → localName, else legacyName, placeholders dropped", () => {
    const s = memory();
    const a = "a".repeat(32), b = "b".repeat(32), c = "c".repeat(32), d = "d".repeat(32), e = "e".repeat(32), f = "f".repeat(32);
    s.sSet("contacts_v2", [
        { destHash: a, displayName: "My Al", nameCustomized: true, publicKey: null, lastSeen: 6 },
        { destHash: b, displayName: "Bobby", nameCustomized: false, publicKey: null, lastSeen: 5 },
        { destHash: c, displayName: "?cccccccc", nameCustomized: false, publicKey: null, lastSeen: 4 },
        { destHash: d, displayName: "Retichat", nameCustomized: false, publicKey: null, lastSeen: 3 },
        { destHash: e, displayName: "Anonymous Peer", nameCustomized: false, publicKey: null, lastSeen: 2 },
        // Migrated by the first three-slot build: the name went to messageName.
        { destHash: f, localName: null, messageName: "Fred", announceName: null, publicKey: null, lastSeen: 1 },
    ]);
    const store = contactStore(s);
    const slots = (h) => [store.get(h).localName, store.get(h).messageName, store.get(h).legacyName];
    assert.deepEqual(slots(a), ["My Al", null, null]);
    assert.deepEqual(slots(b), [null, null, "Bobby"], "legacyName: its origin is unknown");
    assert.deepEqual(slots(c), [null, null, null]);
    assert.deepEqual(slots(d), [null, null, null], "the unnamed Android sender's placeholder");
    assert.deepEqual(slots(e), [null, null, null], "MeshChatX's, Columba's and lxmd's placeholder");
    assert.deepEqual(slots(f), [null, null, "Fred"], "moved out of messageName");
    assert.equal(store.name(b), "Bobby", "a legacy name still shows");
    assert.equal(store.name(c), "cccccccc…", "the placeholder is gone; the resolver's short hash shows");
    assert.equal(store.name(d), "dddddddd…");
    const saved = s.sGet("contacts_v2");
    assert.ok(saved.every((x) => !("displayName" in x) && !("nameCustomized" in x) && "legacyName" in x), "persisted in the new shape");
    assert.equal(store.listed().length, 6, "migrated rows stay listed");

    // §5.1: legacyName is dropped by a named announce, and by an accepted
    // 0xD1 — and then the contact's own names win over it.
    store.updateFromAnnounce(b, { appData: MsgPack.pack([null, null, []]) });
    assert.equal(store.get(b).legacyName, "Bobby", "an announce without a name keeps it");
    store.updateFromAnnounce(b, { appData: MsgPack.pack([Buffer.from("Robert"), 8]) });
    assert.deepEqual([store.get(b).legacyName, store.name(b)], [null, "Robert"], "a named announce drops it");
    assert.equal(store.acceptMessageName(f, DN.nameState("Fred"), "invalid", nowSecs()), false);
    assert.equal(store.get(f).legacyName, "Fred", "an ignored 0xD1 keeps it");
    assert.equal(store.acceptMessageName(f, DN.CLEAR, "validated", nowSecs()), true);
    assert.deepEqual([store.get(f).legacyName, store.name(f)], [null, "ffffffff…"], "an accepted clear drops it");
});

test("§5.1 announce names are replaced on every announce and cleared by a nameless one", () => {
    const store = contactStore(memory());
    const h = "d".repeat(32);
    store.add(h);
    store.updateFromAnnounce(h, { appData: MsgPack.pack([Buffer.from("Ann"), 8]) });
    assert.equal(store.get(h).announceName, "Ann");
    assert.equal(store.name(h), "Ann");
    store.updateFromAnnounce(h, { appData: MsgPack.pack([Buffer.from("Anonymous Peer"), 8]) });
    assert.equal(store.get(h).announceName, null, "MeshChatX/Columba placeholder is no name");
    store.updateFromAnnounce(h, { appData: MsgPack.pack(["Ann2", null, []]) });
    store.updateFromAnnounce(h, { appData: MsgPack.pack([null, null, []]) });
    assert.equal(store.get(h).announceName, null);
});

test("§5.1 rename: the field holds only the local name, Save untouched changes nothing, empty clears (audit M5)", () => {
    const store = contactStore(memory());
    const h = "e".repeat(32);
    store.add(h);
    store.acceptMessageName(h, DN.nameState("Provided"), "validated", nowSecs());
    assert.match(methodBody("_renderContactInfoModal()"), /value: c\.localName \?\? "",/,
        "the field is pre-filled with the local name only, never the provided one");
    const save = compile("_saveContactInfo()", {
        document: { getElementById: () => ({ value: "" }) }, ContactStore: store,
    });
    const self = { state: { contactInfoHash: h }, render() {} };
    save(self)();
    assert.equal(store.get(h).localName, null, "Save on the untouched field");
    assert.equal(store.get(h).messageName, "Provided", "the provided name is still the provided name");
    assert.equal(store.name(h), "Provided");
    store.setLocalName(h, "  Mine\n");
    assert.equal(store.name(h), "Mine", "cleaned");
    store.setLocalName(h, "");
    assert.equal(store.get(h).localName, null, "cleared");
    assert.equal(store.name(h), "Provided");
    store.add(h, false, "ab".repeat(64));
    assert.equal(store.get(h).messageName, "Provided", "re-adding keeps the names");
});

// ── §5.2 the identity store and the router's message handler ───────────────

function recallFor({ contacts, device = null, distro = null }) {
    return fn("recallLxmfIdentity", "sourceHash", {
        Buffer, Identity, Destination,
        IdMgr: { has: !!device, id: device },
        ownLxmfDestinationHash: () => (device ? lxmfHash(device) : null),
        DistroManager: { has: !!distro, identity: distro, lxmfDeliveryHash: distro ? lxmfHash(distro) : null },
        ContactStore: contacts,
    });
}

test("the identity store: own identities and contact keys that bind to their hash, nothing else", () => {
    const store = contactStore(memory());
    const alice = Identity.create(), mallory = Identity.create(), me = Identity.create(), distro = Identity.create();
    store.add(lxmfHash(alice), false, alice.getPublicKey().toString("hex"));
    // A key that does not produce the hash it is stored under (a pasted
    // lxma:// link with someone else's key) must never validate anything.
    const bob = "b0".repeat(16);
    store.add(bob, false, mallory.getPublicKey().toString("hex"));
    const recall = recallFor({ contacts: store, device: me, distro });
    assert.equal(recall(Buffer.from(lxmfHash(alice), "hex")).getPublicKey().toString("hex"), alice.getPublicKey().toString("hex"));
    assert.equal(recall(Buffer.from(bob, "hex")), null);
    assert.equal(recall(Buffer.from(lxmfHash(me), "hex")), me);
    assert.equal(recall(Buffer.from(lxmfHash(distro), "hex")), distro);
    assert.equal(recall(Buffer.from("f".repeat(32), "hex")), null);
    assert.match(app, /\nLXMessage\.recall = recallLxmfIdentity;\n/, "installed as the LXMF identity store");
});

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

function makeReceiver(me) {
    const storage = memory();
    const ContactStore = contactStore(storage);
    const MsgStore = msgStore(storage);
    const self = { _onMsg: [], _pendingTickets: new Map(), groups: [], transfers: [] };
    self._handleGroupMessage = (...a) => self.groups.push(a);
    self._handleDistroIdentityTransfer = (...a) => self.transfers.push(a);
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness, console: quiet,
        RnsClient: { ownHash: lxmfHash(me) }, LXMF, LXMessage, ContactStore, MsgStore,
        decodeDisplayName: DN.decodePayload,
    })(self);
    const recall = recallFor({ contacts: ContactStore, device: me });
    /** Deliver `packed` (full packing) as the router would. */
    const deliver = (packed) => handle(LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), recall));
    return { ContactStore, MsgStore, self, deliver };
}

/** LXMF timestamps (seconds) that always move forward: §5.2 takes a name
 *  only from a message newer than the last, and two messages packed in the
 *  same millisecond would otherwise tie. */
let clock = Date.now() / 1000;
const tick = () => (clock += 1);

function lxm(from, to, content, fields, signer = from, timestamp = tick()) {
    const m = new LXMessage();
    m.timestamp = timestamp;
    m.sourceHash = Buffer.from(lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(lxmfHash(to), "hex");
    m.title = "";
    m.content = content;
    m.fields = fields;
    return m.pack(signer, false);
}
const named = (name) => new Map([[0xD1, Buffer.from(name)]]);

test("§5.2 direct messages: validated sets and clears, unknown fills only an empty name, invalid is ignored", () => {
    const me = Identity.create(), alice = Identity.create(), mallory = Identity.create();
    const r = makeReceiver(me);
    const A = lxmfHash(alice);

    // First message from a stranger: no key yet, so the source is unknown.
    r.deliver(lxm(alice, me, "hi", named("Alice")));
    assert.equal(r.ContactStore.get(A).messageName, "Alice", "unknown source fills the empty name");
    r.deliver(lxm(alice, me, "hi again", named("Alicia")));
    assert.equal(r.ContactStore.get(A).messageName, "Alice", "unknown source never replaces one");
    r.deliver(lxm(alice, me, "clear?", new Map([[0xD1, Buffer.alloc(0)]])));
    assert.equal(r.ContactStore.get(A).messageName, "Alice", "unknown source never clears");

    // The key arrives (announce or path response): now validated.
    r.ContactStore.get(A).publicKey = alice.getPublicKey().toString("hex");
    r.deliver(lxm(alice, me, "renamed", named("Alicia")));
    assert.equal(r.ContactStore.get(A).messageName, "Alicia", "validated replaces");
    r.deliver(lxm(alice, me, "forged", named("Mallory"), mallory));
    assert.equal(r.ContactStore.get(A).messageName, "Alicia", "an invalid signature changes nothing");
    assert.equal(r.MsgStore.get(A).filter((m) => m.dir === "in").length, 5, "every message is still kept, as the reference keeps it");
    r.deliver(lxm(alice, me, "no field", new Map()));
    assert.equal(r.ContactStore.get(A).messageName, "Alicia", "absent changes nothing");
    r.deliver(lxm(alice, me, "clear", new Map([[0xD1, Buffer.alloc(0)]])));
    assert.equal(r.ContactStore.get(A).messageName, null, "validated clear");
    r.deliver(lxm(alice, me, "dict", new Map([[0xD1, new Map([["x", 1]])], [0x10, "Old"]])));
    assert.equal(r.ContactStore.get(A).messageName, null, "a Map is never a name; 0x10 is not read");
});

test("§5.2 group messages name the LXMF source before the group branch (audit H11)", () => {
    const me = Identity.create(), bob = Identity.create();
    const r = makeReceiver(me);
    const B = lxmfHash(bob);
    r.ContactStore.add(B, false, bob.getPublicKey().toString("hex"));
    const fields = new Map([[0xD1, Buffer.from("Bob")], [GROUP_FIELDS.GROUP_ID, "9".repeat(32)], [GROUP_FIELDS.GROUP_SENDER, B]]);
    r.deliver(lxm(bob, me, "group hello", fields));
    assert.equal(r.self.groups.length, 1, "handed to the group handler");
    assert.equal(r.ContactStore.get(B).messageName, "Bob");
    assert.equal(r.MsgStore.get(B).length, 0, "and not stored as a DM");
});

test("§5.2 the router's handler creates no row for a sender it has none for; the group branch decides", () => {
    const me = Identity.create(), carol = Identity.create();
    const r = makeReceiver(me);
    const fields = new Map([[0xD1, Buffer.from("Carol")], [GROUP_FIELDS.GROUP_ID, "9".repeat(32)]]);
    r.deliver(lxm(carol, me, "group hello", fields));
    assert.equal(r.self.groups.length, 1);
    assert.equal(r.ContactStore.get(lxmfHash(carol)), null, "a message the group branch may still drop plants nothing");
});

// ── §5.3 the resolver on every surface ─────────────────────────────────────

test("§5.3 group labels and system notices are resolved when shown, and follow a later name", () => {
    const store = contactStore(memory());
    const h = "f".repeat(32);
    store.add(h);
    const channelNames = new ChannelSenderNames({ get: () => null, set() {} });
    const env = { ContactStore: store, ChannelSenderNamesStore: channelNames, channelPosterName: DN.channelPosterName };
    const systemText = fn("systemMessageText", "m", env);
    const groupLabel = fn("groupSenderLabel", "m", env);
    const channelLabel = fn("channelSenderLabel", "channelName, m", env);
    const notice = { dir: "system", content: "joined the group", actor: h };
    const post = { dir: "in", content: "x", srcHash: h };
    assert.equal(systemText(notice), "ffffffff… joined the group");
    assert.deepEqual(groupLabel(post), { label: "ffffffff…", secondary: null });
    store.acceptMessageName(h, DN.nameState("Fay"), "validated", nowSecs());
    assert.equal(systemText(notice), "Fay joined the group", "the stored notice never froze a name");
    assert.deepEqual(groupLabel(post), { label: "Fay", secondary: null });
    assert.equal(systemText({ dir: "system", content: "You joined \"G\"" }), "You joined \"G\"");
    assert.equal(groupLabel({ dir: "out", srcHash: h }), null, "own messages carry no label");

    assert.deepEqual(channelLabel("public.x", post), { label: "Fay", secondary: null }, "contact chain");
    channelNames.apply("public.x", h, DN.nameState("Pseud"), Date.now());
    assert.deepEqual(channelLabel("public.x", post), { label: "Pseud", secondary: "ffffffff…" },
        "the channel name, with the short hash beside it");
    assert.deepEqual(channelLabel("public.y", post), { label: "Fay", secondary: null }, "per channel");
});

test("§5.3 no surface builds a name from displayName or a \"?hash\" placeholder any more", () => {
    assert.doesNotMatch(app, /\b(c|contact|existing|stored)\??\.displayName\b/, "no contact.displayName left");
    assert.doesNotMatch(app, /"\?" \+/, "no ?hash labels");
    assert.doesNotMatch(app, /senderName: srcHashHex\.slice|slice\(0, ?12\) : null\)/, "no frozen hash12 channel labels");
    assert.doesNotMatch(app, /senderNameFromFields|fields\.(get|set)\(0x10\b/, "0x10 is retired");
    assert.doesNotMatch(app, /\|\| "Retichat Web"|displayName: "Retichat Web"/, "no placeholder name is sent");
    assert.doesNotMatch(app, /suppressSenderName/, "invites carry the name like any message");
});

test("the group invite notice and the distro import prompt name the sender through the resolver (audit M14)", () => {
    const handler = methodBody("_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)");
    assert.match(handler, /GroupMsgStore\.addSystem\(groupId, `invited you to "\$\{groupName \|\| "Group"\}"`, srcHash\)/);
    assert.match(handler, /GroupMsgStore\.addSystem\(groupId, "joined the group", actualSender\)/);
    assert.match(handler, /GroupMsgStore\.addSystem\(groupId, "left the group", actualSender\)/);
    const transfer = methodBody("_handleDistroIdentityTransfer(lxmfMsg, srcHash, privateKeyHex)");
    assert.match(transfer, /const senderName = ContactStore\.name\(srcHash\);/);
});

// ── §5.4 / §6 own names ────────────────────────────────────────────────────

function ownNames(storage, rns = { applyAnnounceName() {} }) {
    const names = build("OwnNames", {
        sGet: storage.sGet, sSet: storage.sSet, RnsClient: rns,
        cleanDisplayName: DN.clean, cleanAnnounceName: DN.cleanAnnounce, migrateOwnDisplayName: DN.migrateOwnDisplayName,
    });
    names.init();
    return names;
}

test("§5.4 the old display name becomes the Message Display Name; placeholders become empty", () => {
    for (const [legacy, configDefault, want] of [
        ["James", "Retichat Web (E2E)", "James"],
        ["Retichat Web", null, null],
        ["Retichat Web (E2E)", "Retichat Web (E2E)", null],
    ]) {
        const s = memory();
        s.sSet("displayName", legacy);
        const names = ownNames(s);
        names.finishMigration(configDefault);
        assert.equal(names.message, want, legacy);
        assert.equal(names.announce, null, "the Announce Display Name starts empty");
        assert.equal(names.channel, null);
        assert.equal(s.sGet("displayName"), null, "the legacy key is gone");
        assert.equal(ownNames(s).message, want, "persisted");
    }
    const fresh = ownNames(memory());
    assert.deepEqual([fresh.announce, fresh.message, fresh.channel], [null, null, null], "all empty by default");
});

test("§6 the three names are independent, cleaned when saved, and the announce name applies at once", () => {
    let applied = 0;
    const s = memory();
    const names = ownNames(s, { applyAnnounceName: () => applied++ });
    assert.equal(names.setMessage("  Me\t"), "Me");
    assert.equal(names.announce, null, "no fallback between names");
    assert.equal(names.channel, null);
    assert.equal(names.setAnnounce("Public Me"), "Public Me");
    assert.equal(applied, 1, "the router gets the new announce name immediately");
    assert.equal(names.setChannel("‮Pseud"), "Pseud", "bidi override stripped");
    assert.equal(names.setMessage(""), null, "cleared");
    const again = ownNames(s);
    assert.deepEqual([again.announce, again.message, again.channel], ["Public Me", null, "Pseud"]);
});

test("§6 Settings shows the three names with the spec's text; the stale announce hint is gone (audit L7)", () => {
    const settings = methodBody("_renderSettingsModal()");
    for (const text of [
        "Announce Display Name",
        "Public. Sent in your announces to the whole network, including other Reticulum apps. Leave empty to stay anonymous.",
        "Message Display Name",
        "Sent inside your messages, only to the people you message.",
        "Channel Display Name",
        "Shown on your channel posts. Anyone who can read a channel can see it. Leave empty to post without a name.",
    ]) assert.ok(settings.includes(text), text);
    assert.doesNotMatch(app, /Shown in your announces on the network/);
    assert.doesNotMatch(methodBody("async _saveSettings()"), /displayName/, "names are not tied to reconnecting");
});

// ── §4.1 sending DMs ───────────────────────────────────────────────────────

function makeSender({ me, messageName = "Alice", storage = memory() }) {
    const MsgStore = msgStore(storage);
    const ledger = new NameLedger({ get: storage.sGet, set: storage.sSet });
    const timers = [];
    const direct = [];
    const copies = [];
    const env = {
        MsgStore, Harness, Identity, Buffer, Destination, LXMessage, Link, Packet, console: quiet,
        IdMgr: { id: me },
        ContactStore: { setReachable() {}, propagationDelay: () => 5 },
        setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; },
        clearTimeout() {},
        applyDisplayName: DN.applyToFields,
        NameLedgerStore: ledger, OwnNames: { message: messageName },
    };
    const self = {
        _onMsg: [], _pendingTickets: new Map(), _pendingPacketHashes: new Map(), _pendingTimeouts: new Map(),
        _cfg: { propagationNodeHash: "b".repeat(32) },
        sendingIdentity: () => ({ identity: me, hash: lxmfHash(me), isDistro: false }),
        _rns: {
            registerDestination: (identity) => {
                const hash = Destination.hash(identity, "lxmf", "delivery");
                return { hash, send: (data) => { direct.push(Buffer.concat([hash, data])); return Buffer.alloc(32, direct.length); } };
            },
            sendData() {},
        },
        _sendOverPeerLink: () => assert.fail("short messages go as one packet"),
        _ensurePropagationLink: async () => ({ status: Link.ACTIVE, sendResource: async () => {} }),
        _buildPropagationPacked: async (packed) => { copies.push(packed); return Buffer.alloc(Link.MDU + 1); },
    };
    for (const signature of [
        "_dispatchMessage(contact, outMsg)",
        "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
        "async _propagateMessage(contact, outMsg)", "_signerFor(srcHash)",
        "_decideMessageName(sourceHex, recipientHex)", "_recordNameDelivered(contactHash, msgId)",
        "_armSendCeiling(contactHash, msgId)", "_failSending(contactHash, msgId)",
    ]) self[methodName(signature)] = compile(signature, env)(self);
    const send = (contact, content) => {
        const record = MsgStore.add(contact.destHash, { dir: "out", content, status: "sending", srcHash: lxmfHash(me), destHash: contact.destHash });
        self._dispatchMessage(contact, record);
        return record;
    };
    const prove = () => { for (const [key, p] of [...self._pendingPacketHashes]) { self._pendingPacketHashes.delete(key); p.onProof(p.messageId); } };
    return { self, MsgStore, ledger, timers, direct, copies, send, prove };
}
const nameIn = (packed) => DN.decodeField(MsgPack.unpack(packed.subarray(96))[3]);
const hashOf = (packed) => LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16)).hash.toString("hex");

test("§4.1 a DM carries the Message Display Name as bin until a delivery confirms it (audit H5)", () => {
    const me = Identity.create(), peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const s = makeSender({ me });
    s.send(contact, "first");
    assert.deepEqual(nameIn(s.direct[0]), DN.nameState("Alice"));
    assert.equal(MsgPack.unpack(s.direct[0].subarray(96))[3].get(0xD1).constructor.name, "Buffer", "bin, not str");
    s.send(contact, "second, before any proof");
    assert.deepEqual(nameIn(s.direct[1]), DN.nameState("Alice"), "nothing confirmed yet: still sent");
    s.prove();
    assert.equal(s.ledger.lookup(lxmfHash(me), contact.destHash).digest, DN.digestHex("Alice"), "recorded on DELIVERED");
    s.send(contact, "third");
    assert.equal(nameIn(s.direct[2]).state, "absent", "confirmed: no name");
});

test("§4.1 the propagated copy carries the same decision, so the same bytes and hash", async () => {
    const me = Identity.create(), peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const s = makeSender({ me });
    const record = s.send(contact, "twice");
    await s.timers.find((t) => t.ms === 5000).f();
    assert.equal(s.copies.length, 1);
    assert.ok(s.copies[0].equals(s.direct[0]), "byte-identical");
    assert.equal(hashOf(s.copies[0]), hashOf(s.direct[0]), "LxmfSeen sees one message");
    assert.deepEqual(s.MsgStore.get(contact.destHash).find((m) => m.id === record.id).lxmfName, DN.nameState("Alice"),
        "the decision is on the record");
    assert.equal(s.ledger.lookup(lxmfHash(me), contact.destHash), null, "a propagated copy never records");
});

test("§4.1 a distro address gets the name on its propagated copy too", async () => {
    const me = Identity.create(), peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: true };
    const s = makeSender({ me });
    s.send(contact, "to a distro");
    await s.timers.find((t) => t.ms === 5000).f(); // the stub's propagation delay
    assert.equal(s.direct.length, 0);
    assert.deepEqual(nameIn(s.copies[0]), DN.nameState("Alice"));
});

test("§4.1 with no Message Display Name nothing is sent, and a name once delivered is cleared once", () => {
    const me = Identity.create(), peer = Identity.create();
    const contact = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };
    const storage = memory();
    const unnamed = makeSender({ me, messageName: null, storage });
    unnamed.send(contact, "anonymous");
    assert.equal(nameIn(unnamed.direct[0]).state, "absent");
    unnamed.ledger.recordDelivered(lxmfHash(me), contact.destHash, DN.nameState("Old"), nowSecs());
    const again = makeSender({ me, messageName: null, storage });
    again.send(contact, "cleared");
    assert.equal(nameIn(again.direct[0]).state, "clear", "an empty 0xD1");
    again.prove();
    again.send(contact, "after");
    assert.equal(nameIn(again.direct[1]).state, "absent", "once");
});

test("§4.1 messages to one's own devices never carry a name", () => {
    for (const sig of ["async _sendDistroSentCopy(recipientHex, title, content)", "_sendDistroViaLxmf()"]) {
        assert.doesNotMatch(methodBody(sig), /applyDisplayName|_decideMessageName|0xD1/, sig);
    }
});

// ── §4.1 group envelopes ───────────────────────────────────────────────────

test("§4.1 group envelopes (invites included) carry the name per member; only a direct delivery records it", async () => {
    const me = Identity.create(), member = Identity.create();
    const memberHash = lxmfHash(member);
    const contact = { destHash: memberHash, publicKey: member.getPublicKey().toString("hex") };
    const storage = memory();
    const ledger = new NameLedger({ get: storage.sGet, set: storage.sSet });
    const env = {
        ContactStore: { get: () => contact, add: () => contact, keep: () => contact },
        Identity, Buffer, Destination, LXMessage, GROUP_FIELDS, GroupDeliveryEvidence, Link, console: quiet,
        IdMgr: { id: me }, applyDisplayName: DN.applyToFields, NameLedgerStore: ledger, OwnNames: { message: "Me" },
    };
    const direct = [];
    const self = {
        _pendingPacketHashes: new Map(),
        _lxmfRouter: { destination: { hash: Destination.hash(me, "lxmf", "delivery") } },
        _rns: { registerDestination: (identity) => ({ hash: Destination.hash(identity, "lxmf", "delivery") }) },
        _groupFallbacks: { schedule() { return true; }, prove() {} },
        _ensureGroupLink: async () => ({ link: { send: (bytes) => { direct.push(bytes); return { packetHash: Buffer.alloc(32, direct.length) }; } } }),
    };
    for (const signature of [
        "async _sendGroupEnvelope(memberHash, content, fields)",
        "_deliverGroupEnvelope(memberHash, fullLxmfBytes, publicKeyHex, onDelivered = null)",
        "_decideMessageName(sourceHex, recipientHex)",
    ]) self[methodName(signature)] = compile(signature, env)(self);

    const invite = self._sendGroupEnvelope(memberHash, "", { groupId: "9".repeat(32), groupAction: "invite", groupSender: lxmfHash(me) });
    await new Promise((r) => setTimeout(r, 0));
    assert.deepEqual(nameIn(direct[0]), DN.nameState("Me"), "the invite carries the name");
    assert.equal(ledger.lookup(lxmfHash(me), memberHash), null);
    const [[, pending]] = self._pendingPacketHashes;
    pending.onProof();
    await invite;
    assert.equal(ledger.lookup(lxmfHash(me), memberHash).digest, DN.digestHex("Me"), "direct proof records");
    self._sendGroupEnvelope(memberHash, "hello", { groupId: "9".repeat(32), groupSender: lxmfHash(me) });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(nameIn(direct[1]).state, "absent");
    assert.match(methodBody("_deliverGroupEnvelope(memberHash, fullLxmfBytes, publicKeyHex, onDelivered = null)"),
        /if \(method === "direct" && onDelivered\) onDelivered\(\);/, "never on a propagation fulfil");
});

// ── §5.2 the distro path ───────────────────────────────────────────────────

test("§5.2 a message unwrapped from the distro names its sender by the same table", () => {
    const distro = Identity.create(), alice = Identity.create(), mallory = Identity.create();
    const D = Buffer.from(lxmfHash(distro), "hex");
    const storage = memory();
    const ContactStore = contactStore(storage);
    const A = lxmfHash(alice);
    ContactStore.add(A, false, alice.getPublicKey().toString("hex"));
    const recall = recallFor({ contacts: ContactStore, distro });
    const body = methodBody("_handleDistroBlob(distroHash, blob)").replaceAll("this.", "self.");
    const env = {
        DistroManager: { has: true, identity: distro, lxmfDeliveryHash: lxmfHash(distro) },
        MsgPack, Buffer, DistroSeen: { check: () => false }, Harness, ContactStore, MsgStore: msgStore(storage),
        LXMF, Cryptography, ownLxmfDestinationHash: () => "e".repeat(32), decodeDisplayName: DN.decodePayload,
        console: quiet,
        LXMessage: new Proxy(LXMessage, { get: (t, k) => (k === "verify"
            ? (d, s, sig, p) => LXMessage.verify(d, s, sig, p, recall) : t[k]) }),
    };
    const run = new Function(...Object.keys(env), "self", "distroHash", "blob", body);
    const self = { ownHash: "e".repeat(32), _pendingTickets: new Map(), _onMsg: [], _ticketFromFields: () => null };
    const blob = (signer, name, timestamp = tick()) => {
        const m = new LXMessage();
        m.timestamp = timestamp;
        m.sourceHash = Buffer.from(A, "hex"); m.destinationHash = D; m.title = ""; m.content = "via distro";
        m.fields = named(name);
        const packed = m.pack(signer, false);
        return Buffer.concat([D, distro.encrypt(packed.subarray(16))]);
    };
    assert.equal(run(...Object.values(env), self, null, blob(alice, "Alice")), true);
    assert.equal(ContactStore.get(A).messageName, "Alice", "validated");
    assert.equal(run(...Object.values(env), self, null, blob(mallory, "Mallory")), true);
    assert.equal(ContactStore.get(A).messageName, "Alice", "a forged signature is ignored");

    // §5.2 order on the distro path: the LXMF timestamp of the unwrapped
    // message, not the time it was pulled.
    const t = tick() + 1000;
    run(...Object.values(env), self, null, blob(alice, "Alicia", t));
    assert.deepEqual([ContactStore.get(A).messageName, ContactStore.get(A).messageNameAt], ["Alicia", t]);
    run(...Object.values(env), self, null, blob(alice, "Alice again", t - 500));
    assert.equal(ContactStore.get(A).messageName, "Alicia", "an older message pulled late does not undo a newer name");
});

// ── channels: §2.3 binding, §5.2 channel names, §4.2 posting ───────────────

const CHANNEL = "public.names";

function makeChannelReceiver(me) {
    const storage = memory();
    const ContactStore = contactStore(storage);
    const stores = {
        ChannelSenderNamesStore: new ChannelSenderNames({ get: storage.sGet, set: storage.sSet }),
        ChannelPostNamesStore: new ChannelPostNames({ get: storage.sGet, set: storage.sSet }),
    };
    const posts = [];
    const env = {
        Buffer, DistroManager: { has: false }, Harness, console: quiet, channelLxmUnpack, ContactStore,
        ChannelStore: { getByHash: () => ({ channelName: CHANNEL }), touch() {} },
        ChannelMsgStore: { add: (c, m) => posts.push(m) },
        ownLxmfDestinationHash: () => lxmfHash(me),
        ...stores,
    };
    const self = { _rfedPendingEchoes: new Map(), _onMsg: [] };
    const handle = compile("_handleChannelPacket(packetData)", env)(self);
    return { handle, ContactStore, posts, ...stores };
}

test("§2.3 a channel post that fails the key binding is dropped and plants no key (audit H3)", () => {
    const me = Identity.create(), alice = Identity.create(), mallory = Identity.create();
    const r = makeChannelReceiver(me);
    const destHash = channelDeliveryHash(CHANNEL);
    const payload = MsgPack.pack([Date.now() / 1000, Buffer.alloc(0), Buffer.from("I am Alice"), named("Alice")]);
    const hashed = Buffer.concat([destHash, Buffer.from(lxmfHash(alice), "hex"), payload]);
    const signature = mallory.sign(Buffer.concat([hashed, Cryptography.fullHash(hashed)]));
    const plain = Buffer.concat([Buffer.from("RTID"), mallory.getPublicKey(), Buffer.from(lxmfHash(alice), "hex"), signature, payload]);
    const { identity, hash } = channelIdentity(CHANNEL);
    assert.equal(r.handle(Buffer.concat([hash, identity.encrypt(plain)])), false);
    assert.equal(r.ContactStore.get(lxmfHash(alice)), null, "no contact, no key under Alice's hash");
    assert.equal(r.posts.length, 0);
});

test("§5.2 a post's 0xD1 sets that sender's channel name, never the contact's name", () => {
    const me = Identity.create(), alice = Identity.create();
    const r = makeChannelReceiver(me);
    const A = lxmfHash(alice);
    assert.equal(r.handle(channelLxmPack(CHANNEL, alice, "hello", DN.nameState("Pseud")).wire), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "Pseud");
    assert.equal(r.ContactStore.get(A).messageName, null, "never the contact's messageName");
    assert.equal(r.ContactStore.get(A).publicKey, alice.getPublicKey().toString("hex"), "the bound key is kept");
    assert.deepEqual(r.posts[0], { dir: "in", content: "hello", status: "delivered", srcHash: A }, "no frozen label");
    assert.equal(r.ChannelPostNamesStore.channels[CHANNEL].senders.includes(A), true, "noted as a sender (§4.2 rule 2)");
    r.handle(channelLxmPack(CHANNEL, alice, "bye", DN.CLEAR).wire);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), null, "cleared");
});

test("§4.2 own posts carry the Channel Display Name by the channel rule, recorded once RFed has them", async () => {
    const me = Identity.create();
    const storage = memory();
    const posts = new ChannelPostNames({ get: storage.sGet, set: storage.sSet });
    const sent = [];
    const records = [];
    const env = {
        IdMgr: { has: true, id: me }, Destination, Link, Buffer, console: quiet, channelLxmPack, channelComputeStamp,
        ChannelMsgStore: { add: (c, m) => { records.push(m); return { id: String(records.length), ...m }; }, updateStatus() {} },
        ChannelStore: { get: () => ({ channelName: CHANNEL, stampCost: null }), touch() {} },
        ChannelPostNamesStore: posts, OwnNames: { channel: "Pseud", message: "Not this one" },
    };
    const self = {
        _onMsg: [], _rfedSendChain: Promise.resolve(), _chanSeenIds: new Set(),
        _exchangeIsDown: () => false,
        _ensureChannelSubscribed: async () => {}, _ensureChannelStreamConfigured: async () => {},
        _ensureRfedLink: async () => ({ send: (payload) => { sent.push(payload); return { packetHash: Buffer.alloc(32) }; } }),
        _waitForRfedPublishEcho: async () => {}, _waitForRfedPublishProof: async () => {},
    };
    const post = compile("async sendChannelMessage(channelName, content)", env)(self);
    const nameOf = (wire) => channelLxmUnpack(CHANNEL, wire).displayName;
    await post(CHANNEL, "first");
    assert.deepEqual(nameOf(sent[0]), DN.nameState("Pseud"), "first post; the channel name, never the message name");
    await post(CHANNEL, "second");
    assert.equal(nameOf(sent[1]).state, "absent");
    posts.noteSender(CHANNEL, "c0ffee".padEnd(32, "0"), lxmfHash(me), Date.now() + 1);
    await post(CHANNEL, "third");
    assert.deepEqual(nameOf(sent[2]), DN.nameState("Pseud"), "a new sender posted since");
    env.OwnNames.channel = null;
    await post(CHANNEL, "fourth");
    assert.equal(nameOf(sent[3]).state, "clear", "unset after a real name: clear once");
    await post(CHANNEL, "fifth");
    assert.equal(nameOf(sent[4]).state, "absent");
});

test("§5.3 the open DM's header follows a name that arrives while it is open (audit L3)", () => {
    const store = contactStore(memory());
    const h = "a1".repeat(16);
    store.add(h);
    const el = () => ({ textContent: "" });
    const header = { ".header-name": el(), ".header-avatar": el(), ".header-hash": el() };
    const view = { querySelector: (q) => header[q] ?? null };
    const self = {
        state: { activeHash: h },
        root: { querySelector: () => view },
        _refreshNameLabels() { assert.fail("a DM has no sender labels"); },
    };
    const sync = compile("_syncOpenChatChrome()", {
        ContactStore: store, GroupStore: { isGroupChat: () => false }, ChannelStore: { get: () => null },
    })(self);
    let notified = 0;
    store.onChange(() => { notified++; sync(); });
    notified = 0;
    store.acceptMessageName(h, DN.nameState("Zed"), "validated", nowSecs());
    assert.equal(notified, 1, "a new name notifies the store's listeners");
    assert.equal(header[".header-name"].textContent, "Zed");
    assert.equal(header[".header-avatar"].textContent, "Z");
    assert.match(methodBody("_wire()"), /ContactStore\.onChange\(\(\) => \{[\s\S]*?this\._syncOpenChatChrome\(\);/,
        "the app wires the store to the header");
});

// ── §3 rule 1 on received str values (review JS-DN-1) ──────────────────────

/** A signed LXMF message whose fields map is `fieldsBytes`, raw: msgpackr
 *  cannot write a str holding invalid UTF-8, a foreign packer can. */
function rawLxm(from, toHash, fieldsBytes, signer = from, timestamp = tick()) {
    const payload = Buffer.concat([Buffer.from([0x94]), MsgPack.pack(timestamp),
        MsgPack.pack(Buffer.alloc(0)), MsgPack.pack(Buffer.from("raw")), fieldsBytes]);
    const hashed = Buffer.concat([Buffer.from(toHash, "hex"), Buffer.from(lxmfHash(from), "hex"), payload]);
    const signature = signer.sign(Buffer.concat([hashed, Cryptography.fullHash(hashed)]));
    return Buffer.concat([hashed.subarray(0, 32), signature, payload]);
}
const strName = (hexBytes) => Buffer.from(`81ccd1${(0xa0 | (hexBytes.length / 2)).toString(16)}${hexBytes}`, "hex");
const ALICE_BAD = "416c696365ed";   // "Alice" + a stray 0xED
const ALICIA_STR = "416c69636961";  // "Alicia", valid UTF-8, as str

test("§3 rule 1: a str 0xD1 holding invalid UTF-8 is absent on the direct path; a valid str is a name", () => {
    const me = Identity.create(), alice = Identity.create();
    const r = makeReceiver(me);
    const A = lxmfHash(alice);
    r.deliver(rawLxm(alice, lxmfHash(me), strName(ALICE_BAD)));
    assert.equal(r.ContactStore.get(A).messageName, null, "unknown source, but nothing to fill: the value is absent");
    r.ContactStore.get(A).publicKey = alice.getPublicKey().toString("hex");
    r.deliver(rawLxm(alice, lxmfHash(me), strName(ALICIA_STR)));
    assert.equal(r.ContactStore.get(A).messageName, "Alicia", "a str name is accepted (§2.1)");
    r.deliver(rawLxm(alice, lxmfHash(me), strName(ALICE_BAD)));
    assert.equal(r.ContactStore.get(A).messageName, "Alicia", "validated, but absent changes nothing — never \"Alice\\uFFFD\"");
    assert.equal(r.MsgStore.get(A).filter((m) => m.dir === "in").length, 3, "the messages themselves are kept");
});

test("§3 rule 1 on channel posts: an invalid str 0xD1 sets no channel name", () => {
    const me = Identity.create(), alice = Identity.create();
    const r = makeChannelReceiver(me);
    const A = lxmfHash(alice);
    const post = (fieldsBytes) => {
        const destHash = channelDeliveryHash(CHANNEL);
        const packed = rawLxm(alice, destHash.toString("hex"), fieldsBytes);
        const plain = Buffer.concat([Buffer.from("RTID"), alice.getPublicKey(), packed.subarray(16)]);
        const { identity, hash } = channelIdentity(CHANNEL);
        return Buffer.concat([hash, identity.encrypt(plain)]);
    };
    assert.equal(r.handle(post(strName(ALICIA_STR))), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "Alicia");
    assert.equal(r.handle(post(strName(ALICE_BAD))), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "Alicia", "absent: unchanged");
});

// ── §5.2 the propagated-fetch path ─────────────────────────────────────────

test("§5.2 a message fetched from the propagation node is verified and named by the same table", async () => {
    const me = Identity.create(), alice = Identity.create(), mallory = Identity.create();
    const r = makeReceiver(me);
    const A = lxmfHash(alice);
    const myHash = Buffer.from(lxmfHash(me), "hex");
    r.ContactStore.add(A, false, alice.getPublicKey().toString("hex"));
    const recall = recallFor({ contacts: r.ContactStore, device: me });
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness, console: quiet,
        RnsClient: { ownHash: lxmfHash(me) }, LXMF, LXMessage, ContactStore: r.ContactStore, MsgStore: r.MsgStore,
        decodeDisplayName: DN.decodePayload,
    })(r.self);
    const ACTIVE = 2;
    const fetchAll = async (packedMessages) => {
        const stored = packedMessages.map((p) => Buffer.concat([myHash, me.encrypt(p.subarray(16))]));
        const ids = stored.map((_, i) => Buffer.from([i]));
        const link = { status: ACTIVE, sendRequest: (path, data) => data };
        const self = {
            _propLink: link,
            _lxmfRouter: { destination: { hash: myHash }, emit: (event, message) => handle(message) },
            async _waitForResponse(l, request) {
                if (request[0] === null && request[1] === null) return ids;
                if (request[0]) return [stored[request[0][0][0]]];
                return true; // purge
            },
        };
        await compile("async _fetchPropagatedMessages()", {
            Link: { ACTIVE }, Buffer, MsgPack, console: quiet, IdMgr: { id: me },
            LXMessage: new Proxy(LXMessage, { get: (t, k) => (k === "fromBytes"
                ? (d, h) => LXMessage.fromBytes(d, h, recall) : t[k]) }),
        })(self)();
    };
    await fetchAll([lxm(alice, me, "stored for you", named("Alice"))]);
    assert.equal(r.ContactStore.get(A).messageName, "Alice", "validated");
    await fetchAll([lxm(alice, me, "forged", named("Mallory"), mallory)]);
    assert.equal(r.ContactStore.get(A).messageName, "Alice", "an invalid signature is ignored");
    await fetchAll([rawLxm(alice, lxmfHash(me), strName(ALICE_BAD))]);
    assert.equal(r.ContactStore.get(A).messageName, "Alice", "an invalid-UTF-8 str is absent");
    assert.equal(r.MsgStore.get(A).filter((m) => m.dir === "in").length, 3);

    // §5.2 order: a propagated copy that lands after a later direct message
    // does not bring the old name back.
    const t = tick() + 1000;
    r.deliver(lxm(alice, me, "direct, later", named("Alicia"), alice, t));
    assert.equal(r.ContactStore.get(A).messageName, "Alicia");
    await fetchAll([lxm(alice, me, "sent earlier, stored at the node", named("Alice"), alice, t - 60)]);
    assert.equal(r.ContactStore.get(A).messageName, "Alicia");
    assert.equal(r.ContactStore.get(A).messageNameAt, t);
});

// ── audit L4: this device is never its own contact ────────────────────────

test("audit L4: group member keys and own channel posts never add this device as a contact", () => {
    const me = Identity.create(), bob = Identity.create();
    const store = contactStore(memory());
    const remember = compile("_rememberGroupMemberKeys(memberKeys)", {
        Buffer, Identity, Destination, ContactStore: store, console: quiet, ownLxmfDestinationHash: () => lxmfHash(me),
    })({ ownHash: lxmfHash(me) });
    remember([
        [lxmfHash(me), me.getPublicKey().toString("base64")],
        [lxmfHash(bob), bob.getPublicKey().toString("base64")],
    ]);
    assert.equal(store.get(lxmfHash(me)), null, "no yourself row");
    assert.equal(store.get(lxmfHash(bob)).publicKey, bob.getPublicKey().toString("hex"), "other members still get their key");

    const r = makeChannelReceiver(me);
    assert.equal(r.handle(channelLxmPack(CHANNEL, me, "my own post", DN.ABSENT).wire), true);
    assert.equal(r.ContactStore.get(lxmfHash(me)), null, "an own post from the channel history");
    assert.equal(r.posts.length, 1, "the post itself is still shown");
});

test("§5.3 an open Group Info modal relabels its members when a name arrives", () => {
    const store = contactStore(memory());
    const me = "e".repeat(32), h = "a2".repeat(16);
    store.add(h);
    const el = (text) => ({ textContent: text, style: {} });
    const row = (hash, text) => {
        const parts = { ".member-name": el(text), ".member-avatar": el(text.charAt(0).toUpperCase()) };
        return { parts, getAttribute: () => hash, querySelector: (q) => parts[q] ?? null };
    };
    const rows = [row(h, DN.shortHash(h)), row(me, "You")];
    const env = { ContactStore: store, ownLxmfDestinationHash: () => me, avatarHue: () => 120 };
    const self = {
        state: { showGroupInfo: true },
        root: { querySelectorAll: (q) => (q === ".modal-sheet [data-member-hash]" ? rows : []) },
    };
    self._groupMemberLabel = compile("_groupMemberLabel(hash)", env)(self);
    self._paintMemberAvatar = compile("_paintMemberAvatar(avatar, name)", env)(self);
    const refresh = compile("_refreshGroupInfoNames()", env)(self);
    store.acceptMessageName(h, DN.nameState("Zoe"), "validated", nowSecs());
    refresh();
    assert.equal(rows[0].parts[".member-name"].textContent, "Zoe");
    assert.equal(rows[0].parts[".member-avatar"].textContent, "Z");
    assert.equal(rows[1].parts[".member-name"].textContent, "You", "this device stays \"You\"");
    assert.match(methodBody("_wire()"), /ContactStore\.onChange\(\(\) => \{[\s\S]*?this\._refreshGroupInfoNames\(\);/,
        "the app wires the store to the open modal");
    assert.match(methodBody("_renderGroupInfoModal()"), /"data-member-hash": hash/, "the rows it relabels");
});

test("§5.3 system notices stored with a frozen name get an actor when the member can be identified", () => {
    const store = contactStore(memory());
    const alice = "a1b2c3d4".repeat(4), bob = "b0b0b0b0".repeat(4), carol = "c0c0c0c0".repeat(4), carl = "c0c0c0c0" + "d".repeat(24);
    store.add(bob);
    store.acceptMessageName(bob, DN.nameState("Bob"), "validated", nowSecs());
    const nameOf = (h) => store.name(h);
    const legacy = fn("legacyNoticeActor", "content, memberHashes, nameOf", {});
    const members = [alice, bob, carol, carl];
    assert.deepEqual(legacy("?a1b2c3d4 joined the group", members, nameOf), { actor: alice, content: "joined the group" });
    assert.deepEqual(legacy("a1b2c3d4 left the group", members, nameOf), { actor: alice, content: "left the group" });
    assert.deepEqual(legacy("Bob invited you to \"Team A\"", members, nameOf), { actor: bob, content: "invited you to \"Team A\"" });
    assert.equal(legacy("c0c0c0c0 joined the group", members, nameOf), null, "two members share the prefix: left as it is");
    assert.equal(legacy("Mallory joined the group", members, nameOf), null, "no member resolves to it");
    assert.equal(legacy("You joined \"Team A\"", members, nameOf), null, "own notices have no actor");
    assert.equal(legacy("Group \"x\" created", members, nameOf), null);

    const storage = memory();
    const GroupMsgStore = build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, legacyNoticeActor: legacy, Date });
    const groupId = "9".repeat(32);
    storage.sSet("gmsg_" + groupId, [
        { id: "1", dir: "system", content: "?a1b2c3d4 joined the group" },
        { id: "2", dir: "system", content: "joined the group", actor: bob },
        { id: "3", dir: "in", content: "?a1b2c3d4 joined the group", srcHash: bob },
    ]);
    GroupMsgStore.migrateLegacyNotices([{ groupId, members: new Map(members.map((h) => [h, "accepted"])) }], nameOf);
    const [first, second, third] = GroupMsgStore.get(groupId);
    assert.deepEqual([first.actor, first.content], [alice, "joined the group"], "named when shown from now on");
    assert.deepEqual(second, { id: "2", dir: "system", content: "joined the group", actor: bob }, "new notices untouched");
    assert.equal(third.actor, undefined, "only system notices");
    assert.match(app, /\nGroupMsgStore\.migrateLegacyNotices\(GroupStore\.getAll\(\), \(hash\) => ContactStore\.name\(hash\)\);\n/,
        "run as the page loads");
});

// ── §5.2 order on the direct path ──────────────────────────────────────────

test("§5.2 order: a name is taken only from a message newer than the one that last set or cleared it", () => {
    const me = Identity.create(), alice = Identity.create();
    const r = makeReceiver(me);
    const A = lxmfHash(alice);
    r.ContactStore.add(A, false, alice.getPublicKey().toString("hex"));
    const t = tick() + 1000;
    r.deliver(lxm(alice, me, "newer", named("New"), alice, t));
    assert.deepEqual([r.ContactStore.get(A).messageName, r.ContactStore.get(A).messageNameAt], ["New", t]);
    r.deliver(lxm(alice, me, "older, arriving late", named("Old"), alice, t - 10));
    assert.equal(r.ContactStore.get(A).messageName, "New");
    r.deliver(lxm(alice, me, "older clear", new Map([[0xD1, Buffer.alloc(0)]]), alice, t - 5));
    assert.equal(r.ContactStore.get(A).messageName, "New", "an older clear is ignored too");
    r.deliver(lxm(alice, me, "repeat", named("New"), alice, t + 10));
    assert.equal(r.ContactStore.get(A).messageNameAt, t + 10, "a repeat of the current name advances the timestamp");
    r.deliver(lxm(alice, me, "between", named("Mid"), alice, t + 5));
    assert.equal(r.ContactStore.get(A).messageName, "New", "so one older than the repeat loses");
    r.deliver(lxm(alice, me, "clear", new Map([[0xD1, Buffer.alloc(0)]]), alice, t + 20));
    assert.equal(r.ContactStore.get(A).messageName, null);
    r.deliver(lxm(alice, me, "old name after the clear", named("New"), alice, t + 15));
    assert.equal(r.ContactStore.get(A).messageName, null, "the clear stands");
    assert.equal(r.ContactStore.get(A).messageNameAt, t + 20, "persisted with the row");
    assert.equal(JSON.parse(JSON.stringify(r.ContactStore.get(A))).messageNameAt, t + 20);
});

// ── §5.2 senders with no row: kept hidden, named everywhere ───────────────

const GROUP = "9".repeat(32);

/** The router's handler with the real _handleGroupMessage behind it. */
function makeGroupReceiver(me, memberHashes) {
    const r = makeReceiver(me);
    const groups = new Map([[GROUP, {
        groupId: GROUP, groupName: "G", groupStatus: "active", lastActivity: 0,
        members: new Map([[lxmfHash(me), "accepted"], ...memberHashes.map((h) => [h, "invited"])]),
    }]]);
    const notices = [];
    const posts = [];
    const GroupStore = {
        get: (id) => groups.get(id) ?? null,
        addPending: (id, groupName, inviter, members) => groups.set(id, {
            groupId: id, groupName, groupStatus: "pending", members: new Map(members.map((h) => [h, "invited"])) }),
        updateMember: (id, h, status) => groups.get(id).members.set(h, status),
        _save() {},
    };
    const GroupMsgStore = {
        addSystem: (id, content, actor) => notices.push({ dir: "system", content, actor }),
        add: (id, m) => posts.push(m),
    };
    const own = () => lxmfHash(me);
    r.self.ownHash = own();
    r.self._performGroupRelay = () => {};
    r.self._rememberGroupMemberKeys = compile("_rememberGroupMemberKeys(memberKeys)", {
        Buffer, Identity, Destination, ContactStore: r.ContactStore, console: quiet, ownLxmfDestinationHash: own,
    })(r.self);
    r.self._handleGroupMessage = compile("_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)", {
        GroupStore, GroupMsgStore, ContactStore: r.ContactStore, console: quiet, Date, ownLxmfDestinationHash: own,
        shouldProcessGroupMessage: fn("shouldProcessGroupMessage", "groupAction, inviterKnown, groupExists", {}),
    })(r.self);
    const systemText = fn("systemMessageText", "m", { ContactStore: r.ContactStore });
    const groupLabel = fn("groupSenderLabel", "m", { ContactStore: r.ContactStore });
    return { ...r, groups, notices, posts, systemText, groupLabel };
}
const groupFields = (name, action = null, extra = []) => new Map([
    ...(name === null ? [] : [[0xD1, Buffer.from(name)]]),
    [GROUP_FIELDS.GROUP_ID, GROUP],
    ...(action ? [[GROUP_FIELDS.GROUP_ACTION, action]] : []),
    ...extra,
]);

test("§5.2 a group member with no row still gets its name: a hidden row, named on every group surface", () => {
    const me = Identity.create(), carol = Identity.create();
    const C = lxmfHash(carol);
    const r = makeGroupReceiver(me, [C]);
    assert.equal(r.ContactStore.get(C), null, "a member the web user has never added and holds no key for");

    const t = tick() + 1000;
    r.deliver(lxm(carol, me, "", groupFields("Carol", "accept", [[GROUP_FIELDS.GROUP_SENDER, C]]), carol, t));
    const row = r.ContactStore.get(C);
    assert.ok(row, "the name has somewhere to live");
    assert.deepEqual([row.messageName, row.messageNameAt, row.hidden], ["Carol", t, true],
        "source unknown (no key yet): the name fills the empty slot");
    assert.equal(r.systemText(r.notices.at(-1)), "Carol joined the group", "the system notice");
    assert.equal(r.ContactStore.name(C), "Carol", "the member list's resolver");
    assert.equal(r.ContactStore.isContact(C), false, "not a contact");
    assert.equal(r.ContactStore.listed().some((c) => c.destHash === C), false, "not in the contact list (audit L4)");

    // The key arrives: later messages are validated and rename her, in order.
    r.ContactStore.get(C).publicKey = carol.getPublicKey().toString("hex");
    r.deliver(lxm(carol, me, "hi all", groupFields("Caz", null, [[GROUP_FIELDS.GROUP_SENDER, C]]), carol, t + 10));
    assert.deepEqual(r.groupLabel(r.posts.at(-1)), { label: "Caz", secondary: null }, "the group sender label");
    r.deliver(lxm(carol, me, "old, relayed late", groupFields("Carol", null, [[GROUP_FIELDS.GROUP_SENDER, C]]), carol, t + 5));
    assert.equal(r.ContactStore.name(C), "Caz", "an older group message does not undo it");

    // A DM from her makes her a contact, with what the row already holds.
    r.deliver(lxm(carol, me, "a DM", new Map(), carol, t + 20));
    assert.equal(r.ContactStore.isContact(C), true);
    assert.equal(r.ContactStore.listed().some((c) => c.destHash === C), true, "listed now there is a conversation");
    assert.equal(r.ContactStore.name(C), "Caz");
    assert.equal(r.ContactStore.get(C).publicKey, carol.getPublicKey().toString("hex"));
});

test("§5.2 a message the group branch drops creates no row; a hidden row still counts as known to invites", () => {
    const me = Identity.create(), dave = Identity.create(), bob = Identity.create();
    const r = makeGroupReceiver(me, []);
    const D = lxmfHash(dave), B = lxmfHash(bob);
    const other = "8".repeat(32);
    r.deliver(lxm(dave, me, "", new Map([[0xD1, Buffer.from("Dave")], [GROUP_FIELDS.GROUP_ID, other],
        [GROUP_FIELDS.GROUP_ACTION, "invite"], [GROUP_FIELDS.GROUP_MEMBERS, `${D},${lxmfHash(me)}`]])));
    assert.equal(r.groups.has(other), false, "a stranger's invite is dropped, as before");
    assert.equal(r.ContactStore.get(D), null, "and leaves no row, so a second invite from him is dropped too");
    r.deliver(lxm(dave, me, "to an unknown group", new Map([[0xD1, Buffer.from("Dave")], [GROUP_FIELDS.GROUP_ID, other]])));
    assert.equal(r.ContactStore.get(D), null);

    // Bob is a member of another group: his key arrived with its invite, so
    // he has a hidden row. An invite from him is processed, as when every
    // such row was a listed contact.
    r.self._rememberGroupMemberKeys([[B, bob.getPublicKey().toString("base64")]]);
    assert.equal(r.ContactStore.get(B).hidden, true);
    r.deliver(lxm(bob, me, "", new Map([[0xD1, Buffer.from("Bob")], [GROUP_FIELDS.GROUP_ID, other],
        [GROUP_FIELDS.GROUP_ACTION, "invite"], [GROUP_FIELDS.GROUP_MEMBERS, `${B},${lxmfHash(me)}`]])));
    assert.equal(r.groups.get(other)?.groupStatus, "pending", "the invite from a known member arrives");
    assert.equal(r.systemText(r.notices.at(-1)), "Bob invited you to \"Group\"", "named by the validated 0xD1");
});

test("audit L4: group members and channel posters are kept as hidden rows, never listed as contacts", () => {
    const me = Identity.create(), bob = Identity.create(), alice = Identity.create();
    const B = lxmfHash(bob), A = lxmfHash(alice);
    const store = contactStore(memory());
    compile("_rememberGroupMemberKeys(memberKeys)", {
        Buffer, Identity, Destination, ContactStore: store, console: quiet, ownLxmfDestinationHash: () => lxmfHash(me),
    })({ ownHash: lxmfHash(me) })([[B, bob.getPublicKey().toString("base64")]]);
    assert.equal(store.get(B).hidden, true, "a group member's key");
    assert.equal(store.isContact(B), false);
    assert.deepEqual(store.listed(), []);

    // Accepting an invite keeps every member (their keys, their names)
    // without adding them as contacts.
    const accept = compile("_acceptGroupInvite(groupId)", {
        GroupStore: { get: () => ({ groupName: "G", members: new Map([[B, "accepted"], [A, "invited"], [lxmfHash(me), "invited"]]) }), accept() {} },
        ContactStore: store, GroupMsgStore: { addSystem() {} }, console: quiet,
        RnsClient: { ownHash: lxmfHash(me), _requestGroupPeer() {}, sendGroupAccept: async () => {} },
        alert: () => assert.fail("keys are all there"),
    });
    store.keep(A, alice.getPublicKey().toString("hex"));
    accept({ render() {} })(GROUP);
    assert.deepEqual([store.get(A).hidden, store.get(B).hidden], [true, true]);
    assert.equal(store.get(lxmfHash(me)), null, "never this device");
    assert.deepEqual(store.listed(), []);

    const c = makeChannelReceiver(me);
    assert.equal(c.handle(channelLxmPack(CHANNEL, alice, "a post", DN.nameState("Pseud")).wire), true);
    assert.equal(c.ContactStore.get(A).hidden, true, "a channel poster's bound key");
    assert.equal(c.ContactStore.get(A).publicKey, alice.getPublicKey().toString("hex"));
    assert.deepEqual(c.ContactStore.listed(), []);

    // Adding the contact by hand lists the row, names and key included.
    store.acceptMessageName(A, DN.nameState("Alice"), "validated", nowSecs());
    store.add(A);
    assert.equal(store.isContact(A), true);
    assert.deepEqual(store.listed().map((x) => x.destHash), [A]);
    assert.deepEqual([store.get(A).messageName, store.get(A).publicKey], ["Alice", alice.getPublicKey().toString("hex")]);
    assert.equal(store.keep(A).hidden, false, "keeping a contact leaves it a contact");

    // Rows stored before the flag existed are contacts.
    const s = memory();
    s.sSet("contacts_v2", [{ destHash: B, localName: null, messageName: null, announceName: null, legacyName: null, lastSeen: 1 }]);
    assert.equal(contactStore(s).isContact(B), true);

    for (const method of ["_buildSidebarContent()", "_renderDirectForm(top, scroll, footer)", "_renderGroupForm(top, scroll, footer)"]) {
        const body = methodBody(method);
        assert.match(body, /ContactStore\.listed\(\)/, `${method} lists contacts only`);
        assert.doesNotMatch(body, /ContactStore\.getAll\(\)/, method);
    }
    for (const method of ["async _sendGroupEnvelope(memberHash, content, fields)", "async openGroupConversation(groupId)",
        "_rememberGroupMemberKeys(memberKeys)", "_handleChannelPacket(packetData)", "_acceptGroupInvite(groupId)"]) {
        assert.doesNotMatch(methodBody(method), /ContactStore\.add\(/, `${method} never adds a contact`);
    }
});

// ── §5.2 order on channel posts ────────────────────────────────────────────

test("§5.2 channel order: history pulled late never undoes a poster's newer channel name", () => {
    const me = Identity.create(), alice = Identity.create();
    const r = makeChannelReceiver(me);
    const A = lxmfHash(alice);
    const post = (fields, timestamp) => {
        const destHash = channelDeliveryHash(CHANNEL);
        const packed = rawLxm(alice, destHash.toString("hex"), MsgPack.pack(fields), alice, timestamp);
        const plain = Buffer.concat([Buffer.from("RTID"), alice.getPublicKey(), packed.subarray(16)]);
        const { identity, hash } = channelIdentity(CHANNEL);
        return Buffer.concat([hash, identity.encrypt(plain)]);
    };
    const t = tick() + 1000;
    assert.equal(r.handle(post(named("New"), t)), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "New");
    assert.equal(r.handle(post(named("Old"), t - 100)), true, "the older post is still shown");
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "New", "but its name does not win");
    assert.equal(r.handle(post(new Map([[0xD1, Buffer.alloc(0)]]), t - 50)), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "New", "nor does an older clear");
    assert.equal(r.handle(post(named("New"), t + 100)), true);
    assert.equal(r.ChannelSenderNamesStore.entry(CHANNEL, A).at, Math.round((t + 100) * 1000), "a newer repeat advances it");
    assert.equal(r.handle(post(named("Mid"), t + 50)), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), "New");
    assert.equal(r.handle(post(new Map([[0xD1, Buffer.alloc(0)]]), t + 200)), true);
    assert.equal(r.ChannelSenderNamesStore.get(CHANNEL, A), null, "a newer clear");
});

// ── §3 the own announce name ───────────────────────────────────────────────

test("§3 the own Announce Display Name is cleaned with the announce rules: \"Anonymous Peer\" is never broadcast", () => {
    let applied = 0;
    const s = memory();
    const names = ownNames(s, { applyAnnounceName: () => applied++ });
    assert.equal(names.setAnnounce("  anonymous   PEER "), null, "no name, as LXMF-rust's clean_announce");
    assert.equal(names.announce, null);
    assert.equal(applied, 1, "the router is told at once");
    assert.equal(s.sGet("announceDisplayName"), "");
    assert.equal(names.setAnnounce("Anonymous Peers"), "Anonymous Peers", "only the exact placeholder");
    assert.equal(names.setMessage("Anonymous Peer"), "Anonymous Peer", "the Message Display Name is not an announce name");

    const stored = memory();
    stored.sSet("announceDisplayName", "Anonymous Peer"); // saved by the build that cleaned it with clean()
    assert.equal(ownNames(stored).announce, null, "a stored one loads as no name");
    assert.match(methodBody("applyAnnounceName()"), /setAnnounceName\(OwnNames\.announce\)/, "what the router announces");
});
