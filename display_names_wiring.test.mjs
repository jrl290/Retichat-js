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
        cleanDisplayName: DN.clean, acceptMessageName: DN.acceptMessageName,
    });
    store.init();
    return store;
}
const msgStore = (storage) => build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });

// ── §5.4 / §5.1 contacts ───────────────────────────────────────────────────

test("§5.4 contacts migrate as they load: nameCustomized → localName, else messageName, ?hash dropped", () => {
    const s = memory();
    const a = "a".repeat(32), b = "b".repeat(32), c = "c".repeat(32);
    s.sSet("contacts_v2", [
        { destHash: a, displayName: "My Al", nameCustomized: true, publicKey: null, lastSeen: 3 },
        { destHash: b, displayName: "Bobby", nameCustomized: false, publicKey: null, lastSeen: 2 },
        { destHash: c, displayName: "?cccccccc", nameCustomized: false, publicKey: null, lastSeen: 1 },
    ]);
    const store = contactStore(s);
    assert.deepEqual([store.get(a).localName, store.get(a).messageName], ["My Al", null]);
    assert.deepEqual([store.get(b).localName, store.get(b).messageName], [null, "Bobby"]);
    assert.deepEqual([store.get(c).localName, store.get(c).messageName], [null, null]);
    assert.equal(store.name(c), "cccccccc…", "the placeholder is gone; the resolver's short hash shows");
    const saved = s.sGet("contacts_v2");
    assert.ok(saved.every((x) => !("displayName" in x) && !("nameCustomized" in x)), "persisted in the new shape");
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
    store.acceptMessageName(h, DN.nameState("Provided"), "validated");
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
        decodeDisplayName: DN.decodeField,
    })(self);
    const recall = recallFor({ contacts: ContactStore, device: me });
    /** Deliver `packed` (full packing) as the router would. */
    const deliver = (packed) => handle(LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), recall));
    return { ContactStore, MsgStore, self, deliver };
}

function lxm(from, to, content, fields, signer = from) {
    const m = new LXMessage();
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

test("§5.2 a group member who is not a contact gets no contact just to hold a name", () => {
    const me = Identity.create(), carol = Identity.create();
    const r = makeReceiver(me);
    const fields = new Map([[0xD1, Buffer.from("Carol")], [GROUP_FIELDS.GROUP_ID, "9".repeat(32)]]);
    r.deliver(lxm(carol, me, "group hello", fields));
    assert.equal(r.ContactStore.get(lxmfHash(carol)), null);
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
    store.acceptMessageName(h, DN.nameState("Fay"), "validated");
    assert.equal(systemText(notice), "Fay joined the group", "the stored notice never froze a name");
    assert.deepEqual(groupLabel(post), { label: "Fay", secondary: null });
    assert.equal(systemText({ dir: "system", content: "You joined \"G\"" }), "You joined \"G\"");
    assert.equal(groupLabel({ dir: "out", srcHash: h }), null, "own messages carry no label");

    assert.deepEqual(channelLabel("public.x", post), { label: "Fay", secondary: null }, "contact chain");
    channelNames.apply("public.x", h, DN.nameState("Pseud"));
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
        cleanDisplayName: DN.clean, migrateOwnDisplayName: DN.migrateOwnDisplayName,
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
        ContactStore: { get: () => contact, add: () => contact },
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
        LXMF, Cryptography, ownLxmfDestinationHash: () => "e".repeat(32), decodeDisplayName: DN.decodeField,
        console: quiet,
        LXMessage: new Proxy(LXMessage, { get: (t, k) => (k === "verify"
            ? (d, s, sig, p, _r, u) => LXMessage.verify(d, s, sig, p, recall, u) : t[k]) }),
    };
    const run = new Function(...Object.keys(env), "self", "distroHash", "blob", body);
    const self = { ownHash: "e".repeat(32), _pendingTickets: new Map(), _onMsg: [], _ticketFromFields: () => null };
    const blob = (signer, name) => {
        const m = new LXMessage();
        m.sourceHash = Buffer.from(A, "hex"); m.destinationHash = D; m.title = ""; m.content = "via distro";
        m.fields = named(name);
        const packed = m.pack(signer, false);
        return Buffer.concat([D, distro.encrypt(packed.subarray(16))]);
    };
    assert.equal(run(...Object.values(env), self, null, blob(alice, "Alice")), true);
    assert.equal(ContactStore.get(A).messageName, "Alice", "validated");
    assert.equal(run(...Object.values(env), self, null, blob(mallory, "Mallory")), true);
    assert.equal(ContactStore.get(A).messageName, "Alice", "a forged signature is ignored");
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
    store.acceptMessageName(h, DN.nameState("Zed"), "validated");
    assert.equal(notified, 1, "a new name notifies the store's listeners");
    assert.equal(header[".header-name"].textContent, "Zed");
    assert.equal(header[".header-avatar"].textContent, "Z");
    assert.match(methodBody("_wire()"), /ContactStore\.onChange\(\(\) => \{[\s\S]*?this\._syncOpenChatChrome\(\);/,
        "the app wires the store to the header");
});
