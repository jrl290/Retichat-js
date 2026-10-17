/**
 * Reactions (REACTIONS-DESIGN.md, revision 2): LXMF's FIELD_REACTION (0x40)
 * read and written (lib/rns/lxmf/lxmf.js), the rules a record's reactions
 * follow (lib/reactions.js), and the shipped app.js code over them: every
 * receive path takes a reaction before any bubble, row or chat-list change
 * and applies it only inside the chat it arrived in; a DM reaction, a Group
 * reaction and their Distro syncs are written as the design says; every
 * Group post carries its post id (0xD1 key 11), through relays too; the
 * Distro Sync of a send carries M's hash (key 12) and a reaction's 0x40;
 * and the react op of the Distro Sync of Group actions round-trips.
 *
 * reactions_vectors.json holds the new wire forms, written by an encoder of
 * its own as Python's umsgpack writes them, for LXMF-rust to check too.
 *
 * Run: node --test reactions.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, { FIELD_REACTION, REACTION_TO, REACTION_CONTENT, readReaction, reactionField } from "./lib/rns/lxmf/lxmf.js";
import { readHead, skipValue } from "./lib/rns/msgpack_raw.js";
import * as DN from "./lib/display_name.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { applyGroupFields, readPostId, readSentHash, setPostId, RF_GROUP_POST_ID, RF_SENT_HASH, FIELD_RETICHAT } from "./lib/retichat_field.js";
import { groupSyncFields, readGroupSync, readGroupSyncFields, inviteMembers } from "./lib/group_sync.js";
import { sentCopyEntryId, groupSyncEntryId } from "./lib/distro_outbox.js";
import { QUICK_REACTIONS, applyReaction, reactionOf, reactionChips } from "./lib/reactions.js";
import {
    app, build, compile, install, messageHandler, fn, constValue, memoryStorage, installGroupSelf,
    GROUP_STATUS_METHODS, groupStatusEnv,
} from "./test_app_source.mjs";

const V = JSON.parse(readFileSync(new URL("./reactions_vectors.json", import.meta.url), "utf8"));
const hex = (b) => Buffer.from(b).toString("hex");
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const DEVICE = "0123456789abcdef0123456789abcdef";
const REACTION_METHODS = ["_applyReaction(store, convHash, record, reactor, emoji, at)", "_takeReaction(reaction, chat)"];

/** console for compiled code: its lines kept, to check what is said. */
function logger() {
    const lines = [];
    const say = (...a) => lines.push(a.map(String).join(" "));
    return { lines, console: { log: say, warn: say, error: say } };
}

/** An LXMF payload [timestamp, title, content, fields] with these raw fields bytes. */
function payloadWith(fieldsBytes) {
    const ts = Buffer.alloc(9);
    ts[0] = 0xcb;
    ts.writeDoubleBE(1790000000.5, 1);
    return Buffer.concat([Buffer.from([0x94]), ts, Buffer.from([0xc4, 0x00, 0xc4, 0x00]), fieldsBytes]);
}

/** The full packing of a message from `from` to `to` (an identity, or a
 *  delivery hash), signed by `signer`, at `timestamp` (s). */
let clock = 1790000000;
function packed(from, to, { content = "", fields = new Map(), signer = from, timestamp = (clock += 1) } = {}) {
    const m = new LXMessage();
    m.timestamp = timestamp;
    m.sourceHash = Buffer.from(lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(typeof to === "string" ? to : lxmfHash(to), "hex");
    m.title = "";
    m.content = content;
    m.fields = fields;
    const bytes = m.pack(signer, false);
    return { bytes, hash: hex(m.hash), timestamp };
}
const reactionFields = (to, emoji, extra = []) => new Map([...extra, [FIELD_REACTION, reactionField(Buffer.from(to, "hex"), emoji)]]);

// ── the wire: FIELD_REACTION ────────────────────────────────────────────────

test("0x40 as written: REACTION_TO the target's bytes and REACTION_CONTENT its UTF-8, both bin; read back from a packed message", () => {
    assert.equal(FIELD_REACTION, 0x40);
    assert.equal(REACTION_TO, 0x00);
    assert.equal(REACTION_CONTENT, 0x01);
    const to = Buffer.alloc(32, 7);
    const field = reactionField(to, "👍");
    assert.deepEqual([...field.keys()], [0, 1]);
    assert.ok(field.get(0) instanceof Uint8Array && field.get(1) instanceof Uint8Array, "both bin");
    assert.equal(Buffer.from(field.get(1)).toString(), "👍");
    const a = Identity.create(), b = Identity.create();
    const { bytes } = packed(a, b, { fields: new Map([[FIELD_REACTION, field]]) });
    const read = readReaction(bytes.subarray(96));
    assert.deepEqual({ to: hex(read.to), content: read.content }, { to: hex(to), content: "👍" });
    // LXMessage reads it once, from the bytes, for every receive path.
    assert.deepEqual(LXMessage.fromBytes(bytes.subarray(16), Buffer.from(lxmfHash(b), "hex")).reaction, read);
    // A removal is an empty content; a reaction over 64 bytes is never written.
    assert.equal(readReaction(packed(a, b, { fields: new Map([[FIELD_REACTION, reactionField(to, "")]]) }).bytes.subarray(96)).content, "");
    assert.doesNotThrow(() => reactionField(to, "a".repeat(64)));
    assert.throws(() => reactionField(to, "a".repeat(65)), /64/);
    assert.throws(() => reactionField(to, "é".repeat(33)), /64/, "bytes, not characters");
    assert.equal(LXMessage.fromBytes(packed(a, b, { content: "hi" }).bytes.subarray(16)).reaction, null, "no 0x40, no reaction");
});

test("0x40 as read: bin or str values, keys of any width; a missing key, content over 64 bytes, or a value of another type refused with why; no map is no reaction", () => {
    const to = Buffer.alloc(32, 9);
    const enc = (v) => Buffer.from(MsgPack.pack(v));
    const cases = [
        ["bin and bin", Buffer.concat([Buffer.from([0x81, 0x40, 0x82, 0x00]), enc(to), Buffer.from([0x01]), enc(Buffer.from("❤️"))]), "❤️"],
        ["str content", Buffer.concat([Buffer.from([0x81, 0x40, 0x82, 0x00]), enc(to), Buffer.from([0x01]), enc("😂")]), "😂"],
        ["uint 8 keys", Buffer.concat([Buffer.from([0x81, 0xcc, 0x40, 0x82, 0xcc, 0x00]), enc(to), Buffer.from([0xcc, 0x01]), enc("🙏")]), "🙏"],
        ["uint 32 and int 64 keys", Buffer.concat([Buffer.from([0x81, 0xce, 0, 0, 0, 0x40, 0x82, 0xd3, 0, 0, 0, 0, 0, 0, 0, 0]), enc(to),
            Buffer.from([0xd0, 0x01]), enc("😮")]), "😮"],
    ];
    for (const [label, fields, content] of cases) {
        const r = readReaction(payloadWith(fields));
        assert.equal(r.problem, undefined, label);
        assert.equal(hex(r.to), hex(to), label);
        assert.equal(r.content, content, label);
    }
    const refused = [
        ["no REACTION_TO", Buffer.concat([Buffer.from([0x81, 0x40, 0x81, 0x01]), enc("👍")]), /REACTION_TO/],
        ["no REACTION_CONTENT", Buffer.concat([Buffer.from([0x81, 0x40, 0x81, 0x00]), enc(to)]), /REACTION_CONTENT/],
        ["65 bytes", Buffer.concat([Buffer.from([0x81, 0x40, 0x82, 0x00]), enc(to), Buffer.from([0x01]), enc(Buffer.alloc(65, 1))]), /64/],
        ["REACTION_TO an int", Buffer.concat([Buffer.from([0x81, 0x40, 0x82, 0x00, 0x05, 0x01]), enc("👍")]), /REACTION_TO/],
        ["content nil", Buffer.concat([Buffer.from([0x81, 0x40, 0x82, 0x00]), enc(to), Buffer.from([0x01, 0xc0])]), /REACTION_CONTENT/],
    ];
    for (const [label, fields, why] of refused) {
        const r = readReaction(payloadWith(fields));
        assert.match(r.problem, why, label);
        assert.equal(r.notAMap, undefined, label);
    }
    const notMap = readReaction(payloadWith(Buffer.concat([Buffer.from([0x81, 0x40]), enc("👍")])));
    assert.equal(notMap.notAMap, true);
    assert.ok(notMap.problem);
    assert.equal(readReaction(payloadWith(Buffer.from([0x80]))), null);
    assert.equal(readReaction(Buffer.from([0xc1])), null, "unreadable bytes: no reaction, never a throw");
});

test("reactions_vectors.json: every 0x40 vector is read as it expects, from the payload and from LXMF's reader", () => {
    assert.equal(V.reaction.length, 15);
    for (const v of V.reaction) {
        const r = readReaction(Buffer.from(v.payload_hex, "hex"));
        const got = r === null ? { reaction: null }
            : r.problem ? { refused: true, not_a_map: !!r.notAMap }
            : { refused: false, to_hex: hex(r.to), content: r.content };
        assert.deepEqual(got, v.expected, v.name);
        assert.deepEqual(LXMF.reactionOfPayload(Buffer.from(v.payload_hex, "hex")), r, v.name);
    }
    // What the web writes for a vector it could write is read the same.
    for (const name of ["direct", "group", "removal"]) {
        const v = V.reaction.find((x) => x.name === name);
        const web = payloadWith(Buffer.from(MsgPack.pack(new Map([[FIELD_REACTION, reactionField(Buffer.from(v.expected.to_hex, "hex"), v.expected.content)]]))));
        const r = readReaction(web);
        assert.deepEqual({ refused: false, to_hex: hex(r.to), content: r.content }, v.expected, `${name}: the web's own bytes`);
    }
});

test("reactions_vectors.json: keys 11 and 12 of the Retichat field are read as they expect; the web writes them as str", () => {
    for (const v of V.retichat_field) {
        const fields = MsgPack.unpack(Buffer.from(v.fields_hex, "hex"));
        assert.deepEqual({ post_id: readPostId(fields), sent_hash: readSentHash(fields) }, v.expected, v.name);
    }
    assert.equal(RF_GROUP_POST_ID, 11);
    assert.equal(RF_SENT_HASH, 12);
    const fields = setPostId(new Map(), "7C0E5F1A2B3C4D5E6F708192A3B4C5D6");
    assert.equal(fields.get(FIELD_RETICHAT).get(11), "7c0e5f1a2b3c4d5e6f708192a3b4c5d6", "lowercased");
    assert.throws(() => setPostId(new Map(), "xyz"));
    const sent = LXMF.setSentHash(new Map(), "ab".repeat(32));
    assert.equal(LXMF.sentHashFromFields(sent), "ab".repeat(32));
    assert.throws(() => LXMF.setSentHash(new Map(), "ab"));
});

// ── the rules: lib/reactions.js ─────────────────────────────────────────────

test("apply_reaction: one per reactor, a newer one replaces it, an older or equal one is ignored, a removal is kept so a late older one cannot bring it back; the input is never changed", () => {
    const A = "a".repeat(32), B = "b".repeat(32);
    const one = applyReaction(undefined, A, "👍", 1000);
    assert.deepEqual(one, { [A]: { e: "👍", t: 1000 } });
    assert.equal(applyReaction(one, A, "❤️", 999), null, "older: ignored");
    assert.equal(applyReaction(one, A, "❤️", 1000), null, "as new: ignored");
    const two = applyReaction(one, A, "❤️", 1001);
    assert.deepEqual(two, { [A]: { e: "❤️", t: 1001 } }, "newer: replaces");
    assert.deepEqual(one, { [A]: { e: "👍", t: 1000 } }, "the input is untouched");
    const gone = applyReaction(two, A, "", 1002);
    assert.deepEqual(gone[A], { e: "", t: 1002 }, "a removal is kept");
    assert.equal(applyReaction(gone, A, "👍", 1001), null, "an older one after the removal does not bring it back");
    const both = applyReaction(gone, B, "👍", 5);
    assert.deepEqual(Object.keys(both).sort(), [A, B], "reactors are independent");
    assert.equal(reactionOf(both, A), "");
    assert.equal(reactionOf(both, B), "👍");
    assert.equal(reactionOf(undefined, B), "");
    assert.throws(() => applyReaction({}, "A".repeat(32), "👍", 1), /32 lowercase hex/);
    assert.throws(() => applyReaction({}, A, null, 1));
    assert.throws(() => applyReaction({}, A, "👍", NaN));
    assert.deepEqual(QUICK_REACTIONS, ["👍", "❤️", "😂", "😮", "😢", "🙏"]);
});

test("the chips: grouped by reaction with a count, in the order each was made, a removal none, highlighted when one of the user's addresses holds it", () => {
    const [A, B, C, ME] = ["a", "b", "c", "d"].map((x) => x.repeat(32));
    const reactions = { [A]: { e: "❤️", t: 3 }, [B]: { e: "👍", t: 1 }, [C]: { e: "👍", t: 2 }, [ME]: { e: "", t: 9 } };
    assert.deepEqual(reactionChips(reactions, (h) => h === ME), [
        { emoji: "👍", count: 2, mine: false, reactors: [B, C] },
        { emoji: "❤️", count: 1, mine: false, reactors: [A] },
    ]);
    reactions[ME] = { e: "❤️", t: 10 };
    assert.deepEqual(reactionChips(reactions, (h) => h === ME).map((c) => [c.emoji, c.count, c.mine]), [["👍", 2, false], ["❤️", 2, true]]);
    assert.deepEqual(reactionChips(undefined), []);
    assert.deepEqual(reactionChips({ [A]: { e: "", t: 1 } }), []);
});

// ── a page receiving ────────────────────────────────────────────────────────

/** The groupTrustsSource rule and its friends, as app.js defines them. */
function groupRule() {
    const fnOf = (name, env) => fn(name, app.match(new RegExp(`\\nfunction ${name}\\(([^)]*)\\)`))[1], env);
    const groupTrustsSource = fnOf("groupTrustsSource", {});
    const GROUP_ACTIONS_THAT_RELAY = constValue("GROUP_ACTIONS_THAT_RELAY");
    return { groupTrustsSource, GROUP_ACTIONS_THAT_RELAY,
        shouldProcessGroupMessage: fnOf("shouldProcessGroupMessage", { groupTrustsSource, GROUP_ACTIONS_THAT_RELAY }) };
}

/**
 * A web page of identity `me`: the real ContactStore, GroupStore,
 * PrivacyFilter, MsgStore and GroupMsgStore over one storage, the shipped
 * router message handler, _handleGroupMessage and the reaction methods on
 * `self`, and LXMessage.recall over the keys `known` (hex → Identity).
 * `ui` is every _onMsg event, `inbox` every record told to the harness as
 * received, `relays` every _performGroupRelay call.
 */
function page(me) {
    const storage = memoryStorage();
    const { sGet, sSet } = storage;
    const events = [];
    const inbox = [];
    const Harness = { recordInbound: (h, m) => inbox.push([h, m.id]), event: (kind, detail) => events.push({ kind, detail }), error() {} };
    const ContactStore = build("ContactStore", {
        sGet, sSet, LXMF, Date, migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    const own = lxmfHash(me);
    const GroupStore = build("GroupStore", { sGet, sSet, Buffer, crypto: globalThis.crypto, Date, IdMgr: { hash: null }, ownLxmfDestinationHash: () => own });
    GroupStore.init();
    const PrivacyFilter = build("PrivacyFilter", { sGet, sSet, ContactStore, GroupStore, Harness, LXMF, LXMessage, Buffer, ...groupRule() });
    PrivacyFilter.init();
    const MsgStore = build("MsgStore", { sGet, sSet, Harness, Date });
    const GroupMsgStore = build("GroupMsgStore", { sGet, sSet, Date, ContactStore });
    const { lines, console } = logger();
    const known = new Map([[own, me]]);
    LXMessage.recall = (hash) => known.get(hex(hash)) ?? null;
    const ui = [];
    const relays = [];
    const self = {
        ownHash: own, _pendingTickets: new Map(), _onMsg: [(m, peer) => ui.push({ m, peer })],
        _keepAttachments: () => {}, _performGroupRelay: (...a) => relays.push(a), _rememberGroupMemberKeys: () => [],
        _handleDistroIdentityTransfer: () => assert.fail("no transfer here"),
    };
    install(self, { applyReaction, Harness, console, Buffer }, REACTION_METHODS);
    installGroupSelf(self, { GroupStore, own, me });
    install(self, {
        GroupStore, GroupMsgStore, ContactStore, console, Date, Buffer, ownLxmfDestinationHash: () => own, PrivacyFilter, sentTimeMs,
        LXMessage, LXMF, Harness, ...groupStatusEnv(),
    }, ["_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo, arrival = null)", ...GROUP_STATUS_METHODS]);
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness, console, RnsClient: { ownHash: own }, LXMF, LXMessage, ContactStore, MsgStore,
        decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self);
    return {
        me, own, self, storage, events, inbox, ui, relays, lines, known, ContactStore, GroupStore, MsgStore, GroupMsgStore,
        /** Know `identity`'s key, as a contact or an announce gives it. */
        know(identity) { known.set(lxmfHash(identity), identity); },
        /** A message as the router hands it on (its bytes, read once). */
        receive({ bytes }) { handle(LXMessage.fromBytes(bytes.subarray(16), Buffer.from(own, "hex"))); },
        /** Everything a reaction must leave alone: the records of every
         *  chat, the rows, the groups, what was told as received. */
        snapshot() {
            const rows = [...storage.data.entries()].filter(([k]) => /^(msg_|gmsg_)/.test(k))
                .map(([k, v]) => [k, JSON.parse(v).map((m) => m.id)]);
            return { rows, contacts: ContactStore.getAll().map((c) => c.destHash).sort(),
                groups: GroupStore.getAll().map((g) => [g.groupId, g.lastActivity]), inbox: inbox.length };
        },
    };
}

test("a direct reaction is applied to the message of that chat it names, by the reactor's address, at its own time: no bubble, no row, no chat, nothing told as received; the open chat is told 'reaction' alone", () => {
    const me = Identity.create(), peer = Identity.create();
    const p = page(me);
    p.know(peer);
    p.ContactStore.add(lxmfHash(peer), peer.getPublicKey().toString("hex"));
    const m = packed(peer, me, { content: "lunch?" });
    p.receive(m);
    const P = lxmfHash(peer);
    const [target] = p.MsgStore.get(P);
    assert.equal(target.lxmfHash, m.hash, "a received DM keeps its LXMF hash");
    const before = p.snapshot();
    p.ui.length = 0;
    const r = packed(peer, me, { fields: reactionFields(m.hash, "👍", [[0x0C, Buffer.from("0123456789abcdef", "hex")]]) });
    p.receive(r);
    assert.deepEqual(p.snapshot(), before, "no record, row, group or inbox change: a ticketed reaction is no delivery notification and no bubble");
    assert.deepEqual(p.MsgStore.get(P)[0].reactions, { [P]: { e: "👍", t: sentTimeMs(r.timestamp) } });
    assert.deepEqual(p.ui, [{ m: { kind: "reaction", id: target.id }, peer: P }]);
    // Replaced by a newer one, a removal kept, an older one ignored.
    p.receive(packed(peer, me, { fields: reactionFields(m.hash, "❤️"), timestamp: r.timestamp + 5 }));
    p.receive(packed(peer, me, { fields: reactionFields(m.hash, ""), timestamp: r.timestamp + 6 }));
    p.receive(packed(peer, me, { fields: reactionFields(m.hash, "😂"), timestamp: r.timestamp + 2 }));
    assert.deepEqual(p.MsgStore.get(P)[0].reactions, { [P]: { e: "", t: sentTimeMs(r.timestamp + 6) } });
    assert.ok(p.lines.some((l) => /ignored: the reaction held from it is as new or newer/.test(l)));
    assert.deepEqual(p.snapshot(), before);
});

test("find_target stays in the chat: a reaction naming a message of another chat, or one not held, is dropped with one line, and makes no chat or contact for its stranger", () => {
    const me = Identity.create(), peer = Identity.create(), other = Identity.create(), stranger = Identity.create();
    const p = page(me);
    for (const id of [peer, other]) { p.know(id); p.ContactStore.add(lxmfHash(id), id.getPublicKey().toString("hex")); }
    p.know(stranger);
    const m = packed(peer, me, { content: "only between us" });
    p.receive(m);
    const before = p.snapshot();
    p.ui.length = 0;
    p.lines.length = 0;
    p.receive(packed(other, me, { fields: reactionFields(m.hash, "😮") }));
    p.receive(packed(stranger, me, { fields: reactionFields(m.hash, "😮") }));
    p.receive(packed(peer, me, { fields: reactionFields("ee".repeat(32), "😮") }));
    p.receive(packed(peer, me, { fields: reactionFields(m.hash.slice(0, 32), "😮") }));
    assert.deepEqual(p.snapshot(), before, "no record, row or chat anywhere");
    assert.equal(p.MsgStore.get(lxmfHash(peer))[0].reactions, undefined, "the target is untouched");
    assert.deepEqual(p.ui, []);
    assert.equal(p.lines.filter((l) => /reaction dropped: target \w+ not in the chat with/.test(l)).length, 4, p.lines.join("\n"));
});

test("a refused 0x40 is dropped with one line and never a bubble; one that is no map leaves the message as it always was; a reaction whose signature fails is dropped", () => {
    const me = Identity.create(), peer = Identity.create(), forger = Identity.create();
    const p = page(me);
    p.know(peer);
    p.ContactStore.add(lxmfHash(peer), peer.getPublicKey().toString("hex"));
    const P = lxmfHash(peer);
    const m = packed(peer, me, { content: "hello" });
    p.receive(m);
    const before = p.snapshot();
    p.lines.length = 0;
    p.receive(packed(peer, me, { fields: new Map([[FIELD_REACTION, new Map([[0, Buffer.from(m.hash, "hex")], [1, Buffer.alloc(65, 0x61)]])]]) }));
    p.receive(packed(peer, me, { fields: new Map([[FIELD_REACTION, new Map([[1, Buffer.from("👍")]])]]) }));
    assert.deepEqual(p.snapshot(), before);
    assert.equal(p.lines.filter((l) => /^\[retichat\] reaction dropped: /.test(l)).length, 2, p.lines.join("\n"));
    // Signed by another key in the peer's name.
    p.receive(packed(peer, me, { fields: reactionFields(m.hash, "👎"), signer: forger }));
    assert.equal(p.MsgStore.get(P)[0].reactions, undefined);
    assert.ok(p.lines.some((l) => /reaction dropped: its signature does not verify/.test(l)));
    // 0x40 that is no map: a message as before.
    p.receive(packed(peer, me, { content: "a thumbs up", fields: new Map([[FIELD_REACTION, "👍"]]) }));
    assert.deepEqual(p.MsgStore.get(P).map((x) => x.content), ["hello", "a thumbs up"]);
});

// ── Groups ──────────────────────────────────────────────────────────────────

const POST_ID = "7c0e5f1a2b3c4d5e6f708192a3b4c5d6";
/** Group envelope fields as _sendGroupEnvelope writes them (old top-level
 *  entries until the switch), with a post id and a 0x40 when given. */
function envelope(group, { sender = null, postId = null, reaction = null, action = null, relayFor = null } = {}) {
    const fields = applyGroupFields(new Map(), { groupId: group, groupSender: sender, groupPostId: postId, groupAction: action, groupRelayFor: relayFor });
    if (reaction) fields.set(FIELD_REACTION, reactionField(Buffer.from(reaction.to, "hex"), reaction.content));
    return fields;
}

test("a Group post's id (key 11) is kept as postId on the received record; a Group reaction names it by its 16 bytes, attributed as a post is (a relayed copy to GROUP_SENDER), applied in that Group only: no record, the Group's order unchanged", () => {
    const me = Identity.create(), alice = Identity.create(), bob = Identity.create();
    const p = page(me);
    for (const id of [alice, bob]) { p.know(id); p.ContactStore.keep(lxmfHash(id), id.getPublicKey().toString("hex")); }
    const [A, B] = [alice, bob].map(lxmfHash);
    const G = p.GroupStore.create("G", [A, B]).groupId;
    const G2 = p.GroupStore.create("G2", [A, B]).groupId;
    p.receive(packed(alice, me, { content: "post one", fields: envelope(G, { sender: A, postId: POST_ID }) }));
    p.receive(packed(alice, me, { content: "no id: an older client", fields: envelope(G, { sender: A }) }));
    const [post, old] = p.GroupMsgStore.get(G).filter((m) => m.dir === "in");
    assert.equal(post.postId, POST_ID);
    assert.equal(old.postId, undefined);
    const before = p.snapshot();
    p.ui.length = 0;
    const r1 = packed(bob, me, { fields: envelope(G, { sender: B, reaction: { to: POST_ID, content: "👍" } }) });
    p.receive(r1);
    // Alice's reaction relayed by Bob: GROUP_SENDER Alice, attributed to her.
    const r2 = packed(bob, me, { fields: envelope(G, { sender: A, relayFor: A, reaction: { to: POST_ID, content: "❤️" } }) });
    p.receive(r2);
    assert.deepEqual(p.GroupMsgStore.get(G).find((m) => m.id === post.id).reactions, {
        [B]: { e: "👍", t: sentTimeMs(r1.timestamp) },
        [A]: { e: "❤️", t: sentTimeMs(r2.timestamp) },
    });
    assert.deepEqual(p.ui.map((e) => [e.m.kind, e.peer]), [["reaction", G], ["reaction", G]]);
    // The same post id in another Group, and an id not held: dropped there.
    p.lines.length = 0;
    p.receive(packed(alice, me, { fields: envelope(G2, { sender: A, reaction: { to: POST_ID, content: "😢" } }) }));
    p.receive(packed(alice, me, { fields: envelope(G, { sender: A, reaction: { to: "ab".repeat(16), content: "😢" } }) }));
    assert.equal(p.lines.filter((l) => /reaction dropped: target/.test(l)).length, 2, p.lines.join("\n"));
    assert.deepEqual(p.snapshot(), before, "no record, row or Group order change on any of them");
});

test("a Group reaction reaching the distro goes through the same Group handler: applied to the post, kept (so recorded as seen), no record", () => {
    const me = Identity.create(), alice = Identity.create();
    const p = page(me);
    p.know(alice);
    p.ContactStore.keep(lxmfHash(alice), alice.getPublicKey().toString("hex"));
    const A = lxmfHash(alice);
    const G = p.GroupStore.create("G", [A]).groupId;
    p.receive(packed(alice, me, { content: "post", fields: envelope(G, { sender: A, postId: POST_ID }) }));
    const before = p.snapshot();
    const r = packed(alice, me, { fields: envelope(G, { sender: A, reaction: { to: POST_ID, content: "😮" } }) });
    const msg = LXMessage.fromBytes(r.bytes.subarray(16), r.bytes.subarray(0, 16));
    const verdict = p.self._handleGroupMessage(msg, A, "", LXMessage.groupInfo(msg), { via: "distro", blob: r.bytes, hash: r.hash });
    assert.equal(verdict, "kept");
    assert.deepEqual(p.GroupMsgStore.get(G).find((m) => m.dir === "in").reactions, { [A]: { e: "😮", t: sentTimeMs(r.timestamp) } });
    assert.deepEqual(p.snapshot(), before);
    const stray = packed(alice, me, { fields: envelope(G, { sender: A, reaction: { to: "cd".repeat(16), content: "😮" } }) });
    const strayMsg = LXMessage.fromBytes(stray.bytes.subarray(16), stray.bytes.subarray(0, 16));
    assert.equal(p.self._handleGroupMessage(strayMsg, A, "", LXMessage.groupInfo(strayMsg), { via: "distro", blob: stray.bytes, hash: stray.hash }), "dropped",
        "a post not held: dropped, so not recorded as seen");
});

test("a relay request carries what is relayed: its post id and its 0x40 go to the relay", () => {
    const me = Identity.create(), alice = Identity.create(), bob = Identity.create();
    const p = page(me);
    for (const id of [alice, bob]) { p.know(id); p.ContactStore.keep(lxmfHash(id), id.getPublicKey().toString("hex")); }
    const [A, B] = [alice, bob].map(lxmfHash);
    const G = p.GroupStore.create("G", [A, B]).groupId;
    p.GroupStore.get(G).members.set(A, "accepted");
    const req = envelope(G, { sender: A, action: "relay_req", relayFor: A, postId: POST_ID, reaction: { to: POST_ID, content: "🙏" } });
    p.receive(packed(alice, me, { fields: req }));
    assert.equal(p.relays.length, 1);
    const carried = p.relays[0][5];
    assert.equal(carried.postId, POST_ID);
    assert.deepEqual({ to: hex(carried.reaction.to), content: carried.reaction.content }, { to: POST_ID, content: "🙏" });
    p.receive(packed(alice, me, { content: "relay this", fields: envelope(G, { sender: A, action: "relay_req", relayFor: A, postId: POST_ID }) }));
    assert.deepEqual([p.relays[1][1], p.relays[1][5].postId, p.relays[1][5].reaction], ["relay this", POST_ID, null]);
});

// ── sending ─────────────────────────────────────────────────────────────────

/** _sendGroupEnvelope over stubs: what each member's copy is, as bytes. */
function envelopeSender(me) {
    const sent = [];
    const self = {
        _decideMessageName: () => null,
        _deliverGroupEnvelope: (member, bytes) => { sent.push({ member, bytes }); return Promise.resolve({ method: "direct" }); },
        _rns: { registerDestination: (id) => ({ hash: Destination.hash(id, "lxmf", "delivery") }) },
    };
    const keys = new Map();
    const ContactStore = { keep: (h) => ({ destHash: h, publicKey: keys.get(h) }), get: (h) => ({ destHash: h, publicKey: keys.get(h) }) };
    install(self, {
        ContactStore, Identity, Destination, Buffer, LXMessage, LXMF, applyDisplayName: DN.applyToFields, applyGroupFields,
        NameLedgerStore: { recordDelivered() {} }, IdMgr: { id: me }, Date,
    }, ["async _sendGroupEnvelope(memberHash, content, fields, signer = null, onSubmitted = null)",
        "async _fanoutGroupEnvelope(targets, content, fields, signer = null, onSubmitted = null)"]);
    self._lxmfRouter = { destination: { hash: Buffer.from(lxmfHash(me), "hex") } };
    return { self, sent, member(id) { keys.set(lxmfHash(id), id.getPublicKey().toString("hex")); return lxmfHash(id); } };
}

test("every member's copy of a Group post carries its post id as 0xD1 key 11; a relayed copy carries the request's post id and 0x40", async () => {
    const me = Identity.create(), alice = Identity.create(), bob = Identity.create();
    const s = envelopeSender(me);
    const [A, B] = [s.member(alice), s.member(bob)];
    const G = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
    const signer = { identity: me, hash: lxmfHash(me) };
    await s.self._fanoutGroupEnvelope([A, B], "post", { groupId: G, groupSender: signer.hash, groupPostId: POST_ID }, signer);
    assert.equal(s.sent.length, 2);
    for (const { member, bytes } of s.sent) {
        const m = LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16));
        assert.equal(LXMessage.groupInfo(m).postId, POST_ID, member);
        assert.equal(m.reaction, null);
    }
    // The relay: _performGroupRelay hands `carried` on to each relayed copy.
    const relay = { _groupSigner: () => signer, _groupSelf: () => new Set([signer.hash]), groupFormerDistroText: () => null, fanned: [], sentTo: [] };
    relay._fanoutGroupEnvelope = (targets, content, fields, by) => { relay.fanned.push(fields); return s.self._fanoutGroupEnvelope(targets, content, fields, by); };
    relay._sendGroupEnvelope = async (...a) => relay.sentTo.push(a);
    install(relay, { console: logger().console }, ["async _performGroupRelay(group, content, originalSender, alreadySeen, requester, carried = null)"]);
    const C = lxmfHash(Identity.create());
    const group = { groupId: G, groupName: "G", groupStatus: "active", members: new Map([[A, "accepted"], [B, "accepted"], [C, "accepted"], [signer.hash, "accepted"]]) };
    s.sent.length = 0;
    const to = POST_ID;
    await relay._performGroupRelay(group, "", C, [], A, { postId: POST_ID, reaction: { to: Buffer.from(to, "hex"), content: "😂" } });
    assert.deepEqual(s.sent.map((x) => x.member), [B]);
    const copy = LXMessage.fromBytes(s.sent[0].bytes.subarray(16), s.sent[0].bytes.subarray(0, 16));
    assert.equal(LXMessage.groupInfo(copy).postId, POST_ID);
    assert.deepEqual({ to: hex(copy.reaction.to), content: copy.reaction.content }, { to, content: "😂" });
    assert.equal(LXMessage.groupInfo(copy).groupSender, C, "attributed to the original sender");
});

test("sendGroupReaction: REACTION_TO the post id's 16 bytes, no content, Group Fanned out to the accepted members but the user, applied at once as the group signer, the react op owed with its time and post id", async () => {
    const me = Identity.create();
    const own = lxmfHash(me);
    const storage = memoryStorage();
    const GroupMsgStore = build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date, ContactStore: {} });
    const [A, B, C] = ["a", "b", "c"].map((x) => x.repeat(32));
    const G = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
    const group = { groupId: G, groupName: "G", groupStatus: "active", members: new Map([[own, "accepted"], [A, "accepted"], [B, "invited"], [C, "accepted"]]) };
    const record = GroupMsgStore.add(G, { dir: "in", content: "post", srcHash: A, postId: POST_ID });
    const fanned = [];
    const owed = [];
    const ui = [];
    const self = {
        _initialized: true, _exchangeIsDown: () => false, _onMsg: [(m, peer) => ui.push([m, peer])],
        _groupSigner: () => ({ identity: me, hash: own }), _groupSelf: () => new Set([own]),
        _fanoutGroupEnvelope: async (targets, content, fields, signer, onSubmitted) => { fanned.push({ targets, content, fields, signer }); onSubmitted(); return { fulfilled: targets.length, total: targets.length }; },
        _syncGroupAction: (...a) => owed.push(a),
    };
    const { console } = logger();
    install(self, { applyReaction, Harness: { event() {} }, console, Buffer }, REACTION_METHODS);
    install(self, { GroupStore: { get: () => group }, GroupMsgStore, Buffer, LXMF, Date, console },
        ["async sendGroupReaction(groupId, record, emoji)"]);
    const before = Date.now();
    await self.sendGroupReaction(G, record, "🙏");
    assert.equal(fanned.length, 1);
    assert.deepEqual(fanned[0].targets, [A, C], "accepted members but the user");
    assert.equal(fanned[0].content, "");
    assert.deepEqual({ group: fanned[0].fields.groupId, sender: fanned[0].fields.groupSender, action: fanned[0].fields.groupAction }, { group: G, sender: own, action: undefined });
    assert.equal(hex(fanned[0].fields.reaction.to), POST_ID, "the post id's 16 bytes");
    assert.equal(fanned[0].fields.reaction.to.length, 16);
    const held = GroupMsgStore.get(G)[0].reactions[own];
    assert.equal(held.e, "🙏");
    assert.ok(held.t >= before);
    assert.deepEqual(owed, [["react", G, { content: "🙏", atMs: held.t, postId: POST_ID }]]);
    assert.deepEqual(ui, [[{ kind: "reaction", id: record.id }, G]]);
    // A post without an id, a group not joined, content no receiver takes: refused, nothing applied or sent.
    await assert.rejects(self.sendGroupReaction(G, { ...record, postId: undefined }, "👍"), /post id/);
    await assert.rejects(self.sendGroupReaction(G, record, "a".repeat(65)), /64/);
    group.groupStatus = "pending";
    await assert.rejects(self.sendGroupReaction(G, record, "👍"), /joined/);
    assert.equal(fanned.length, 1);
    assert.equal(GroupMsgStore.get(G)[0].reactions[own].e, "🙏");
});

test("a Group post gets a 32-hex post id, kept on its record before anything goes, written on every member copy and owed in its post sync", async () => {
    const me = Identity.create();
    const own = lxmfHash(me);
    const storage = memoryStorage();
    const GroupMsgStore = build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date, ContactStore: {} });
    const A = "a".repeat(32);
    const G = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
    const group = { groupId: G, groupName: "G", groupStatus: "active", members: new Map([[own, "accepted"], [A, "accepted"]]) };
    const fanned = [];
    const owed = [];
    const self = {
        _initialized: true, _exchangeIsDown: () => false, _onMsg: [],
        _groupSigner: () => ({ identity: me, hash: own }), _groupSelf: () => new Set([own]), groupFormerDistroText: () => null,
        _fanoutGroupEnvelope: async (targets, content, fields, signer, onSubmitted) => { fanned.push(fields); onSubmitted(); return { fulfilled: 1, total: 1 }; },
        _syncGroupAction: (...a) => owed.push(a),
    };
    install(self, { GroupStore: { get: () => group, _save() {} }, GroupMsgStore, Buffer, crypto: globalThis.crypto, Date, console: logger().console },
        ["async sendGroupMessage(groupId, content)", "async _dispatchGroupMessage(groupId, outMsg)"]);
    await self.sendGroupMessage(G, "hello all");
    await self.sendGroupMessage(G, "again");
    const [one, two] = GroupMsgStore.get(G);
    assert.match(one.postId, /^[0-9a-f]{32}$/);
    assert.notEqual(one.postId, two.postId, "each post its own");
    assert.deepEqual(fanned.map((f) => f.groupPostId), [one.postId, two.postId]);
    assert.deepEqual(owed.map((a) => [a[0], a[2].postId]), [["post", one.postId], ["post", two.postId]]);
    // A post queued by an app.js older than reactions gets one when it goes.
    const queued = GroupMsgStore.add(G, { dir: "out", content: "queued", status: "queued", srcHash: own });
    await self._dispatchGroupMessage(G, queued);
    const id = GroupMsgStore.get(G).find((m) => m.id === queued.id).postId;
    assert.match(id, /^[0-9a-f]{32}$/);
    assert.equal(fanned.at(-1).groupPostId, id);
});

// ── direct reactions sent, and the Distro Sync of a send ────────────────────

/** A sending page: sendReaction over a stub transport, the shipped
 *  _sendDistroSentCopy behind it owing to a stub outbox. */
function reactingPage({ distro = null } = {}) {
    const me = Identity.create();
    const storage = memoryStorage();
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness: { recordInbound() {} }, Date });
    const D = distro ? lxmfHash(distro) : null;
    const dispatched = [];
    const owed = [];
    const self = {
        ownHash: lxmfHash(me), _initialized: true, _exchangeIsDown: () => false, _onMsg: [],
        sendingIdentity: () => (distro ? { identity: distro, hash: D, isDistro: true } : { identity: me, hash: lxmfHash(me), isDistro: false }),
        _rns: { registerDestination: (id) => ({ hash: Destination.hash(id, "lxmf", "delivery") }) },
        _dispatchReaction: (...a) => dispatched.push(a),
        _oweDistro: (entry) => owed.push(entry), _sealForDistroSync: () => ({}),
    };
    const { console } = logger();
    install(self, { applyReaction, Harness: { event() {}, error() {} }, console, Buffer }, REACTION_METHODS);
    install(self, {
        Identity, Destination, LXMessage, LXMF, Buffer, MsgStore, sentTimeMs, console, Harness: { error() {} }, Cryptography, sentCopyEntryId,
        DistroManager: distro ? { has: true, identity: distro, lxmfDeliveryHash: D, pubKey: distro.getPublicKey().toString("hex") } : { has: false },
    }, ["sendReaction(contact, record, emoji)", "async _sendDistroSentCopy(recipientHex, title, content, sent = null)"]);
    return { me, self, MsgStore, dispatched, owed, D };
}

test("sendReaction: an otherwise-empty LXMF message carrying only 0x40, REACTION_TO the target's LXMF hash, sent the way a text goes, applied at once at its own time; nothing owed to a distro not held", () => {
    const peer = Identity.create();
    const P = lxmfHash(peer);
    const s = reactingPage();
    const contact = { destHash: P, publicKey: peer.getPublicKey().toString("hex") };
    const target = s.MsgStore.add(P, { dir: "in", content: "hi", lxmfHash: "cd".repeat(32) });
    const hash = s.self.sendReaction(contact, target, "😂");
    assert.equal(s.dispatched.length, 1);
    const [c, dest, packedBytes, h] = s.dispatched[0];
    assert.equal(c, contact);
    assert.equal(hex(dest.hash), P);
    assert.equal(h, hash);
    const m = LXMessage.fromBytes(packedBytes.subarray(16), packedBytes.subarray(0, 16));
    assert.equal(hex(m.hash), hash);
    assert.equal(m.signatureValidated || m.unverifiedReason === LXMessage.SOURCE_UNKNOWN, true);
    assert.equal(m.title.toString(), "");
    assert.equal(m.content.toString(), "");
    assert.deepEqual([...m.fields.keys()], [FIELD_REACTION], "nothing but 0x40");
    assert.deepEqual({ to: hex(m.reaction.to), content: m.reaction.content }, { to: "cd".repeat(32), content: "😂" });
    assert.deepEqual(s.MsgStore.get(P)[0].reactions, { [s.self.ownHash]: { e: "😂", t: sentTimeMs(m.timestamp) } });
    assert.deepEqual(s.owed, []);
    assert.equal(s.MsgStore.get(P).length, 1, "no record of its own");
    assert.throws(() => s.self.sendReaction(contact, { id: "x", content: "no hash" }, "👍"), /LXMF hash/);
    assert.throws(() => s.self.sendReaction({ destHash: P }, target, "👍"), /public key/);
    s.self._exchangeIsDown = () => true;
    assert.throws(() => s.self.sendReaction(contact, target, "👍"), /Not connected/);
    assert.equal(s.dispatched.length, 1);
});

/** A receiving device of `distro`: the shipped _handleDistroBlob over the
 *  real MsgStore, the reaction methods, and a stub ContactStore. */
function distroDevice(distro, device = DEVICE) {
    const D = lxmfHash(distro);
    const storage = memoryStorage();
    const Harness = { recordInbound() {}, event() {}, error() {} };
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });
    const kept = new Set();
    const ContactStore = { keep: (h) => kept.add(h), touch() {}, acceptMessageName() { return false; } };
    const seen = new Set();
    const DistroSeen = { check: (k) => { if (seen.has(k)) return true; seen.add(k); return false; }, forget: (k) => seen.delete(k) };
    const { lines, console } = logger();
    const ui = [];
    const self = { ownHash: device, _pendingTickets: new Map(), _onMsg: [(m, peer) => ui.push({ m, peer })], _learnDistroSibling() {}, _keepAttachments: () => {} };
    install(self, { applyReaction, Harness, console, Buffer }, REACTION_METHODS);
    install(self, {
        DistroManager: { has: true, identity: distro, lxmfDeliveryHash: D }, MsgPack, Buffer, DistroSeen, Harness, ContactStore, MsgStore,
        LXMF, Cryptography, ownLxmfDestinationHash: () => device, LXMessage, decodeDisplayName: DN.decodePayload, sentTimeMs, console,
        DISTRO_ATTACHMENT_PLACEHOLDER: "[placeholder]",
    }, ["_handleDistroBlob(distroHash, blob)"]);
    return {
        D, self, MsgStore, kept, lines, ui,
        /** A packed message to D, as its fan-out blob. */
        take({ bytes }) { return self._handleDistroBlob(D, Buffer.concat([bytes.subarray(0, 16), distro.encrypt(bytes.subarray(16))])); },
        rows: () => [...storage.data.keys()].filter((k) => k.startsWith("msg_")).map((k) => [k, MsgStore.get(k.slice(4)).length]),
    };
}

test("Distro Fanout: a received message keeps its LXMF hash, and a reaction to it from the same source is applied in that chat; from anyone else it is dropped; neither makes a bubble, a row or a chat", () => {
    const distro = Identity.create(), peer = Identity.create(), other = Identity.create();
    LXMessage.recall = (h) => [peer, other].find((i) => lxmfHash(i) === hex(h)) ?? null;
    const d = distroDevice(distro);
    const P = lxmfHash(peer);
    const m = packed(peer, d.D, { content: "to the distro" });
    assert.equal(d.take(m), true);
    assert.equal(d.MsgStore.get(P)[0].lxmfHash, m.hash);
    const rows = d.rows();
    const kept = [...d.kept];
    d.ui.length = 0;
    const r = packed(peer, d.D, { fields: reactionFields(m.hash, "👍") });
    assert.equal(d.take(r), true);
    assert.deepEqual(d.MsgStore.get(P)[0].reactions, { [P]: { e: "👍", t: sentTimeMs(r.timestamp) } });
    assert.deepEqual(d.ui, [{ m: { kind: "reaction", id: d.MsgStore.get(P)[0].id }, peer: P }]);
    assert.equal(d.take(packed(other, d.D, { fields: reactionFields(m.hash, "😢") })), false, "dropped: not in the chat with its source");
    assert.ok(d.lines.some((l) => /reaction dropped: target \w+ not in the chat with/.test(l)));
    assert.deepEqual(d.rows(), rows);
    assert.deepEqual([...d.kept], kept, "no row for anyone");
});

test("the Distro Sync of a send: written with M's hash as key 12, and with M's 0x40 when M is a reaction; the other device stores M with that hash, and applies the reaction as the distro's in the chat with the recipient, with no bubble", async () => {
    const distro = Identity.create(), peer = Identity.create();
    LXMessage.recall = (h) => (lxmfHash(peer) === hex(h) ? peer : lxmfHash(distro) === hex(h) ? distro : null);
    const P = lxmfHash(peer);
    const sender = reactingPage({ distro });
    const contact = { destHash: P, publicKey: peer.getPublicKey().toString("hex") };
    // A text DM's copy names M by its hash (key 12).
    const M = "ab".repeat(32);
    await sender.self._sendDistroSentCopy(P, "", "see you", { hash: M });
    const copy = Buffer.from(sender.owed[0].packed, "base64");
    const readCopy = LXMessage.fromBytes(copy.subarray(16), copy.subarray(0, 16));
    assert.equal(LXMF.sentHashFromFields(LXMessage.routingFields(readCopy)), M);
    assert.equal(readCopy.reaction, null);
    // Another device stores it under M's hash.
    const other = distroDevice(distro, "fe".repeat(16));
    assert.equal(other.take({ bytes: copy }), true);
    const [stored] = other.MsgStore.get(P);
    assert.deepEqual([stored.dir, stored.content, stored.lxmfHash], ["out", "see you", M]);
    // A reaction sent as the distro: the copy carries 0x40 and its hash.
    const target = sender.MsgStore.add(P, { dir: "out", content: "see you", lxmfHash: M });
    const hash = sender.self.sendReaction(contact, target, "❤️");
    assert.equal(sender.owed.length, 2, "the Distro Sync of this send owed");
    const reactionCopy = Buffer.from(sender.owed[1].packed, "base64");
    const read = LXMessage.fromBytes(reactionCopy.subarray(16), reactionCopy.subarray(0, 16));
    assert.equal(LXMF.sentHashFromFields(LXMessage.routingFields(read)), hash, "key 12: the reaction's own hash");
    assert.deepEqual({ to: hex(read.reaction.to), content: read.reaction.content }, { to: M, content: "❤️" });
    assert.equal(read.content.toString(), "");
    assert.equal(LXMF.distroSentCopyFromFields(LXMessage.routingFields(read)).toHex, P);
    // Received: applied as D's in the chat with P, no record of its own.
    other.ui.length = 0;
    assert.equal(other.take({ bytes: reactionCopy }), true);
    assert.equal(other.MsgStore.get(P).length, 1, "no bubble");
    assert.equal(other.MsgStore.get(P)[0].reactions[other.D].e, "❤️");
    assert.deepEqual(other.ui.map((e) => e.m.kind), ["reaction"]);
    // One whose target is not in that chat: dropped, said, no bubble.
    sender.self.sendReaction(contact, { id: "elsewhere", lxmfHash: "ef".repeat(32) }, "😮");
    assert.equal(other.take({ bytes: Buffer.from(sender.owed.at(-1).packed, "base64") }), false);
    assert.equal(other.MsgStore.get(P).length, 1);
    assert.ok(other.lines.some((l) => /reaction dropped: target \w+ not in the chat with/.test(l)));
});

// ── the Distro Sync of Group actions: post id and react ─────────────────────

const D_HEX = V.distro_lxmf_delivery_hash_hex;

/** at_ms written as uint 64 (0xcf), as Python and Rust write it, in place of
 *  the web's int 64 (0xd3), in the fields map `b`. */
function asUint64AtMs(b) {
    const out = Buffer.from(b);
    const top = readHead(out, 0);
    let p = top.end;
    for (let i = 0; i < top.count; i++) {
        const key = readHead(out, p);
        const valueAt = key.end;
        if (key.kind === "int" && key.int === 0xfc) {
            const array = readHead(out, valueAt);
            let q = array.end;
            q = skipValue(out, q);
            q = skipValue(out, q);
            if (out[q] === 0xd3) out[q] = 0xcf;
        }
        p = skipValue(out, valueAt);
    }
    return out;
}

test("reactions_vectors.json: the web writes each post and react G's fields as the vector's bytes (at_ms as an int 64 its one difference), and reads every G vector as it expects", () => {
    assert.equal(V.group_sync.length, 17);
    for (const v of V.group_sync) {
        const bytes = Buffer.from(v.fields_hex, "hex");
        assert.deepEqual(readGroupSyncFields(bytes, 0, D_HEX), v.expected, v.name);
        if (!v.writer) continue;
        const web = Buffer.from(MsgPack.pack(groupSyncFields(v.sync, D_HEX, V.device_hex)));
        assert.equal(asUint64AtMs(web).toString("hex"), v.fields_hex, `${v.name}: the web's bytes`);
        assert.deepEqual(readGroupSyncFields(web, 0, D_HEX), v.expected, `${v.name}: the web's bytes read back`);
    }
    assert.throws(() => groupSyncFields({ op: "react", group_id: V.group_id, at_ms: 1, content: "👍", left: [] }, D_HEX, V.device_hex), /post_id/);
    assert.throws(() => groupSyncFields({ op: "post", group_id: V.group_id, at_ms: 1, text: "x", left: [], post_id: "nope" }, D_HEX, V.device_hex), /post_id/);
});

/** The shipped _sendDistroGroupSync (and _applyGroupSync behind a G
 *  received) for a D-group, over stubs. */
function groupSyncPage(distro) {
    const D = lxmfHash(distro);
    const storage = memoryStorage();
    const GroupMsgStore = build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date, ContactStore: {} });
    const groups = new Map();
    const GroupStore = { get: (id) => groups.get(id) ?? null, isClosed: () => false, _save() {} };
    const owed = [];
    const { lines, console } = logger();
    const ui = [];
    const self = { ownHash: DEVICE, _onMsg: [(m, peer) => ui.push({ m, peer })], _oweDistro: (e) => owed.push(e), _sealForDistroSync: () => ({}), _groupSyncKeys: () => [] };
    install(self, { applyReaction, Harness: { event() {} }, console, Buffer }, REACTION_METHODS);
    install(self, {
        DistroManager: { has: true, identity: distro, lxmfDeliveryHash: D, pubKey: distro.getPublicKey().toString("hex") },
        DistroLeftStore: { of: () => [] }, LXMessage, LXMF, Buffer, Cryptography, groupSyncFields, groupSyncEntryId, inviteMembers,
        ownLxmfDestinationHash: () => DEVICE, GroupStore, GroupMsgStore, TextEncoder, console, Date, DISTRO_ATTACHMENT_PLACEHOLDER: "[placeholder]",
    }, ["_sendDistroGroupSync(op, group, extra = null)", "_applyGroupSync(sync, group, facts)"]);
    return { D, self, groups, GroupMsgStore, owed, lines, ui };
}

test("the react op round-trips: _sendDistroGroupSync writes [react, group_id, at_ms, content, left, post_id] signed by D; a post sync carries its post id after left; another device applies each", () => {
    const distro = Identity.create();
    const g = groupSyncPage(distro);
    const G = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
    const group = { groupId: G, groupName: "G", groupStatus: "active", ownMember: g.D, members: new Map([[g.D, "accepted"]]) };
    g.groups.set(G, group);
    g.self._sendDistroGroupSync("post", group, { text: "a post", atMs: 1790000700000, postId: POST_ID });
    g.self._sendDistroGroupSync("react", group, { content: "👍", atMs: 1790000700500, postId: POST_ID });
    g.self._sendDistroGroupSync("react", group, { content: "", atMs: 1790000700900, postId: POST_ID });
    const reads = g.owed.map((e) => {
        const packedG = Buffer.from(e.packed, "base64");
        assert.equal(LXMessage.verify(packedG.subarray(0, 16), packedG.subarray(16, 32), packedG.subarray(32, 96), packedG.subarray(96), () => distro).validated, true);
        return { read: readGroupSync(packedG.subarray(96), g.D), hash: LXMessage.hashOf(packedG.subarray(0, 16), packedG.subarray(16, 32), packedG.subarray(96)).toString("hex") };
    });
    assert.deepEqual(reads.map(({ read }) => [read.op, read.at_ms, read.text, read.content, read.post_id, read.problem]), [
        ["post", 1790000700000, "a post", null, POST_ID, null],
        ["react", 1790000700500, null, "👍", POST_ID, null],
        ["react", 1790000700900, null, "", POST_ID, null],
    ]);
    // On another device of D: the post filed with its id, the reactions applied as D, the later removal kept.
    const other = groupSyncPage(distro);
    other.groups.set(G, { ...group, members: new Map(group.members) });
    assert.equal(other.self._applyGroupSync(reads[0].read, other.groups.get(G), { hash: reads[0].hash }), "kept");
    const [post] = other.GroupMsgStore.get(G);
    assert.deepEqual([post.dir, post.content, post.postId], ["out", "a post", POST_ID]);
    other.ui.length = 0;
    assert.equal(other.self._applyGroupSync(reads[1].read, other.groups.get(G), { hash: reads[1].hash }), "kept");
    assert.deepEqual(other.GroupMsgStore.get(G)[0].reactions, { [other.D]: { e: "👍", t: 1790000700500 } });
    assert.equal(other.self._applyGroupSync(reads[2].read, other.groups.get(G), { hash: reads[2].hash }), "kept");
    assert.deepEqual(other.GroupMsgStore.get(G)[0].reactions, { [other.D]: { e: "", t: 1790000700900 } });
    assert.equal(other.GroupMsgStore.get(G).length, 1, "no record for a reaction");
    assert.deepEqual(other.ui.map((e) => e.m.kind), ["reaction", "reaction"]);
    // A reaction to a post not held, or for a group not joined here: dropped, said.
    assert.equal(other.self._applyGroupSync({ ...reads[1].read, post_id: "ab".repeat(16) }, other.groups.get(G), { hash: "x" }), "dropped");
    other.groups.get(G).groupStatus = "pending";
    assert.equal(other.self._applyGroupSync(reads[1].read, other.groups.get(G), { hash: "y" }), "dropped");
    assert.equal(other.self._applyGroupSync(reads[1].read, null, { hash: "z" }), "dropped");
    assert.equal(other.lines.filter((l) => /dropped/.test(l)).length, 3, other.lines.join("\n"));
});

// ── the pins ────────────────────────────────────────────────────────────────

test("every receive path checks for a reaction before it stores, notifies or reorders: the direct handler, Distro Fanout, the Distro Sync of a send, Groups (direct and via the distro, relayed copies) and the Distro Sync of Group actions", () => {
    const methodText = (sig) => {
        const start = app.indexOf(`\n    ${sig} {`);
        assert.notEqual(start, -1, sig);
        return app.slice(start, app.indexOf("\n    },\n", start));
    };
    const handler = app.slice(app.indexOf('this._lxmfRouter.on("message", (lxmfMsg) => {'));
    const before = (text, a, b, what) => assert.ok(text.indexOf(a) !== -1 && text.indexOf(a) < text.indexOf(b), what);
    before(handler, "const reaction = lxmfMsg.reaction ?? null;", "LXMF.isDeliveryNotification(", "direct: before the delivery notification");
    before(handler, "const reaction = lxmfMsg.reaction ?? null;", "MsgStore.add(srcHash", "direct: before the bubble");
    const blob = methodText("_handleDistroBlob(distroHash, blob)");
    before(blob, "const reaction = LXMF.reactionOfPayload(payloadBytes);\n                if (reaction && !reaction.notAMap)", "ContactStore.keep(recipientHex);", "the Distro Sync of a send: before the row and the bubble");
    const fanout = blob.slice(blob.indexOf("if (channelSync) {"));
    before(fanout, "const reaction = LXMF.reactionOfPayload(payloadBytes);", "LXMF.isDeliveryNotification(", "Distro Fanout: before the delivery notification");
    before(fanout, "const reaction = LXMF.reactionOfPayload(payloadBytes);", "ContactStore.keep(srcHashHex);", "Distro Fanout: before the row");
    const groupHandler = methodText("_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo, arrival = null)");
    before(groupHandler, "const reaction = groupAction ? null : (lxmfMsg.reaction ?? null);", "GroupMsgStore.add(", "Groups: before the bubble");
    before(groupHandler, "if (!PrivacyFilter.groupAccepts(", "const reaction = groupAction ? null", "Groups: after the group trust rule");
    assert.match(methodText("_applyGroupSync(sync, group, facts)"), /if \(sync\.op === "react"\) \{[\s\S]*?return this\._takeReaction\(/);
    // A reaction moves nothing in the chat list: neither applying it nor the page's repaint touches an order.
    const applying = methodText("_applyReaction(store, convHash, record, reactor, emoji, at)") + methodText("_takeReaction(reaction, chat)");
    assert.doesNotMatch(applying, /lastActivity|ContactStore|GroupStore|\.add\(|_refreshSidebar/);
    assert.match(app, /if \(msg\.kind === "reaction"\) \{\s*if \(inActiveChat\) this\._repaintReactions\(peerHash, msg\.id\);\s*return;\s*\}/);
    assert.doesNotMatch(methodText("_repaintReactions(convHash, msgId)"), /_refreshSidebar|render\(\)/);
});

test("the page: no inline style attributes and no user-select: none on messages; the react button, its menu and the chips are h() elements wired by onClick", async () => {
    const css = readFileSync(new URL("./style.css", import.meta.url), "utf8");
    for (const rule of css.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
        if (/msg-|message-list/.test(rule[1])) assert.doesNotMatch(rule[2], /user-select:\s*none/, rule[1].trim());
    }
    for (const sel of [".msg-react-btn", ".msg-menu", ".msg-reactions", ".msg-reaction.mine", ".msg-row.show-actions .msg-react-btn", ".msg-line"]) {
        assert.ok(css.includes(sel), sel);
    }
    const ui = ["_buildMessageActions(m, text)", "_buildReactionChips(m)", "_toggleMessageMenu(e, msgId, text)", "_messageRowClick(e)", "_copyMessageText(text)"]
        .map((sig) => { const at = app.indexOf(`\n    ${sig} {`); assert.notEqual(at, -1, sig); return app.slice(at, app.indexOf("\n    },\n", at)); }).join("\n");
    assert.doesNotMatch(ui, /setAttribute\("style"|style:\s*"|innerHTML|addEventListener/);
    assert.match(ui, /navigator\.clipboard\.writeText\(text\)/);
});
