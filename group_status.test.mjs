/**
 * MEMBER STATUSES AND KEYS — the wire and the module half (RFed-spec
 * Group.md, "Member statuses and keys (2026-10-06)"; LXMF-rust
 * DISPLAY_NAMES.md §10 key 10). What lib/ does, with no page around it:
 *
 *   - key 10 of the Retichat field (GROUP_STATUSES, an array of bin): read
 *     from the Retichat field only, written there in both send forms, each
 *     packed message a bin and never wrapped again
 *     (CHECK_THESE_THINGS_FIRST.md section 11);
 *   - the sender's key an accept or leave carries, and how it binds
 *     (boundSenderKey): the key derives the lxmf.delivery destination that is
 *     the entry's hash and the message's source;
 *   - LXMessage.fromBytes checking such a message under the key it carries
 *     when none is held: validated, invalid (forged), or still unknown;
 *   - what a message is worth by its signature and the switch
 *     (statusChangeVerdict);
 *   - the packed message a creator keeps and passes on, exactly as received.
 *
 * The page's half (who may send what, what it changes, the creator's copies
 * and answers) is group_statuses.test.mjs; the vectors the phones check
 * against are group_status_vectors.test.mjs.
 *
 * Run: node --test group_status.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import * as RF from "./lib/retichat_field.js";
import {
    boundSenderKey, deliveryHashOf, packedHeld, packedMessage, senderKeyEntry, statusChangeVerdict,
    PACKED_HEADER_LENGTH, STATUS_PACKED_LIMIT, STATUS_PAYLOAD_LIMIT,
} from "./lib/group_status.js";
import { build } from "./test_app_source.mjs";
import { lxm, lxmfHash, hex, oldFields, newFields } from "./test_group_net.mjs";

const G = "0123456789abcdef0123456789abcdef";
const keyOf = (identity) => senderKeyEntry(lxmfHash(identity), identity.getPublicKey().toString("hex"));
const keysMap = (...pairs) => new Map(pairs.map(([hash, encoded]) => [hash, encoded]));
/** A receiver's identity store: the keys of `holders` (identities) only. */
const store = (...holders) => {
    const byHash = new Map(holders.map((id) => [lxmfHash(id), id]));
    return (source) => byHash.get(Buffer.from(source).toString("hex")) ?? null;
};
/** `bytes` (destination | source | signature | payload) as a receiver holding the keys of `holders` parses it. */
const parse = (bytes, ...holders) => LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16), store(...holders));

// ── key 10 of the Retichat field ──────────────────────────────────────────

test("key 10 is GROUP_STATUSES, a Retichat-field entry with no old field: not a group entry, the table of nine is unchanged", () => {
    assert.equal(RF.RF_GROUP_STATUSES, 10);
    assert.equal(RF.groupEntry(10), null, "it is not one of the str/bool entries with an old top-level field");
    assert.deepEqual(RF.GROUP_ENTRIES.map((e) => e.key), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert.ok(RF.RF_GROUP_STATUSES <= RF.RF_MAX_KEY, "one byte on the wire");
});

test("setStatuses writes key 10 into the Retichat field, an array of bin, whatever the switch says; the other keys are kept, in ascending order", () => {
    const first = Buffer.from("first packed message");
    const second = Buffer.from([0, 1, 2, 255]);
    for (const switched of [false, true]) {
        const fields = new Map([[0xD1, new Map([[0, Buffer.from("Dee")]])]]);
        RF.applyGroupFields(fields, { groupId: G, groupAction: "status", groupSender: "a".repeat(32), groupStatuses: [first, second] }, switched);
        const map = fields.get(0xD1);
        assert.deepEqual([...map.keys()], switched ? [0, 1, 4, 5, 10] : [0, 10], `${switched ? "after" : "before"} the switch: key 10 is in the Retichat field, the rest where it was`);
        assert.deepEqual(map.get(10), [first, second]);
        if (!switched) {
            assert.equal(fields.get(0xA0), G, "before the switch the group entries stay in the old fields");
            assert.equal(fields.get(0xA3), "status");
            assert.equal(fields.get(0xA4), "a".repeat(32));
        } else {
            assert.equal(fields.has(0xA0), false);
        }
        // On the wire the elements are bin (c4/c5), in a msgpack array, once.
        const wire = MsgPack.pack(fields);
        const decoded = MsgPack.unpack(wire);
        const got = decoded.get(0xD1).get(10);
        assert.ok(Array.isArray(got) && got.every((e) => e instanceof Uint8Array), "an array of bin");
        assert.deepEqual(got.map(hex), [hex(first), hex(second)], "each element is the packed message itself, not msgpack of it");
        assert.ok(hex(wire).includes("0a92c414" + hex(first) + "c404" + hex(second)), "key 10, array of two, bin 20 bytes, bin 4 bytes");
    }
});

test("an empty GROUP_STATUSES is written and read as an empty array; none given writes nothing; a non-array or a non-bin element is refused when written", () => {
    const withEmpty = RF.applyGroupFields(new Map(), { groupId: G, groupAction: "status", groupStatuses: [] }, false);
    assert.deepEqual(RF.readStatuses(MsgPack.unpack(MsgPack.pack(withEmpty))), []);
    const without = RF.applyGroupFields(new Map(), { groupId: G, groupAction: "accept" }, true);
    assert.equal(without.get(0xD1).has(10), false);
    assert.throws(() => RF.setStatuses(new Map(), "nope"), TypeError);
    assert.throws(() => RF.setStatuses(new Map(), ["a string"]), TypeError);
    assert.throws(() => RF.setStatuses(new Map(), [Buffer.from("ok"), 7]), TypeError);
});

test("readStatuses reads key 10 of the Retichat field only: not from a top-level field, not from a non-map 0xD1, not a non-array; elements are returned as they came", () => {
    const element = Buffer.from("x");
    assert.deepEqual(RF.readStatuses(new Map([[0xD1, new Map([[10, [element, "str", 5]]])]])), [element, "str", 5]);
    for (const fields of [
        new Map(), new Map([[0xD1, new Map([[1, G]])]]),
        new Map([[0xAA, [element]]]), new Map([[10, [element]]]), new Map([[0xA9, [element]]]),   // no old field exists for it
        new Map([[0xD1, [element]]]), new Map([[0xD1, new Map([[10, "not an array"]])]]), new Map([[0xD1, new Map([[10, null]])]]),
        null, undefined, "x",
    ]) assert.equal(RF.readStatuses(fields), null, JSON.stringify([...(fields instanceof Map ? fields.keys() : [])]));
});

test("LXMessage.extractGroupFields carries the statuses; every entry before them reads as before", () => {
    const a = Buffer.from("a"), b = Buffer.from("bb");
    const fields = new Map([[0xA0, G], [0xA3, "status"], [0xA4, "c".repeat(32)], [0xD1, new Map([[10, [a, b]]])]]);
    const got = LXMessage.extractGroupFields(fields);
    assert.deepEqual([got.groupId, got.groupAction, got.groupSender, got.statuses], [G, "status", "c".repeat(32), [a, b]]);
    assert.equal(LXMessage.extractGroupFields(new Map([[0xA0, G], [0xA3, "accept"]])).statuses, null, "an accept has none");
    assert.equal(LXMessage.extractGroupFields(new Map([[0xD1, new Map([[10, [a]]])]])), null, "statuses are no group id: not a group message");
});

// ── the sender's key ──────────────────────────────────────────────────────

test("an accept's or leave's key entry is the invite chunk's form: hash:base64 of the 64-byte public key, the hash its lxmf.delivery destination", () => {
    const id = Identity.create();
    const entry = senderKeyEntry(lxmfHash(id), id.getPublicKey().toString("hex"));
    const [hash, encoded] = entry.split(":");
    assert.equal(hash, lxmfHash(id));
    assert.equal(hash, deliveryHashOf(id.getPublicKey()));
    assert.equal(Buffer.from(encoded, "base64").toString("hex"), id.getPublicKey().toString("hex"));
    assert.match(encoded, /^[A-Za-z0-9+/]{86}==$/, "what extractGroupFields' reader of a member key accepts");
    const got = LXMessage.extractGroupFields(oldFields({ id: G, action: "accept", sender: hash, keys: entry }));
    assert.deepEqual([...got.memberKeys], [[hash, encoded]]);
});

test("boundSenderKey: the key binds when it derives the entry's hash and the entry's hash is the LXMF source; anything else is no key", () => {
    const alice = Identity.create(), bob = Identity.create(), mallory = Identity.create();
    const A = lxmfHash(alice), B = lxmfHash(bob), M = lxmfHash(mallory);
    const entry = (hash, id) => [hash, id.getPublicKey().toString("base64")];

    const bound = boundSenderKey(keysMap(entry(A, alice)), A);
    assert.equal(bound.getPublicKey().toString("hex"), alice.getPublicKey().toString("hex"), "the Identity the carried key loads as");
    assert.equal(boundSenderKey(keysMap(entry(A, alice)), A.toUpperCase()).hash.toString("hex"), alice.hash.toString("hex"), "the hash is read in lower case");

    assert.equal(boundSenderKey(keysMap(entry(A, mallory)), A), null, "a key that does not derive the hash: mallory's key under alice's hash");
    assert.equal(boundSenderKey(keysMap(entry(B, bob)), A), null, "an entry for another hash is not the sender's, though it binds to itself");
    assert.equal(boundSenderKey(keysMap(entry(B, bob), entry(A, alice)), A) !== null, true, "the sender's own entry is found among others");
    assert.equal(boundSenderKey(keysMap(entry(B, bob), entry(A, mallory)), A), null, "and the others do not bind it");
    assert.equal(boundSenderKey(keysMap(), A), null, "no entry");
    assert.equal(boundSenderKey(null, A), null);
    assert.equal(boundSenderKey(keysMap([A, Buffer.alloc(63, 1).toString("base64")]), A), null, "63 bytes");
    assert.equal(boundSenderKey(keysMap([A, Buffer.alloc(65, 1).toString("base64")]), A), null, "65 bytes");
    assert.equal(boundSenderKey(keysMap([A, 12]), A), null, "not a string");
    assert.equal(boundSenderKey(keysMap(entry(M, mallory)), 5), null, "a source that is not a hex string");
});

test("a carried key reaches the reader whole: each form of the entry, an old field 0xA8 or key 9 of the Retichat field, and only the form's own entries are read", () => {
    const id = Identity.create();
    const entry = keyOf(id);
    for (const [form, fields] of [["old field", oldFields({ id: G, action: "accept", sender: lxmfHash(id), keys: entry })],
        ["Retichat field", newFields({ id: G, action: "accept", sender: lxmfHash(id), keys: entry })]]) {
        const got = LXMessage.extractGroupFields(fields);
        assert.deepEqual([...got.memberKeys.keys()], [lxmfHash(id)], form);
        assert.equal(LXMessage.carriedSenderKey(fields, Buffer.from(lxmfHash(id), "hex")).getPublicKey().toString("hex"), id.getPublicKey().toString("hex"), form);
    }
    // An invite's key entry is no sender's key: only an accept or a leave carries one that counts.
    for (const action of ["invite", "relay_req", "relay_done", "status", null]) {
        const f = oldFields({ id: G, action, sender: lxmfHash(id), keys: entry });
        assert.equal(LXMessage.carriedSenderKey(f, Buffer.from(lxmfHash(id), "hex")), null, String(action));
    }
    assert.equal(LXMessage.carriedSenderKey(null, Buffer.alloc(16)), null);
    assert.equal(LXMessage.carriedSenderKey(new Map(), Buffer.alloc(16)), null);
});

// ── the signature, under a held key or the one carried ───────────────────

function accept(from, to, { action = "accept", key = true, signer = from, carry = from, form = "old", extra = {} } = {}) {
    const entries = { id: G, action, sender: lxmfHash(from), ...extra };
    if (key) entries.keys = keyOf(carry);
    return lxm(from, to, "", (form === "old" ? oldFields : newFields)(entries), { signer });
}

test("an accept or leave from a source whose key is not held is validated under the key it carries, in either form; the message says which key it carried", () => {
    const creator = Identity.create(), alice = Identity.create();
    for (const form of ["old", "new"]) for (const action of ["accept", "leave"]) {
        const bytes = accept(alice, creator, { action, form });
        const m = parse(bytes, creator);                                   // the receiver holds only the creator's key
        assert.equal(m.signatureState, "validated", `${form} ${action}`);
        assert.equal(m.signatureValidated, true);
        assert.equal(m.unverifiedReason, null);
        assert.equal(m.senderKey.toString("hex"), alice.getPublicKey().toString("hex"), "the bound key");
        assert.equal(hex(m.hash), hex(LXMessage.hashOf(m.destinationHash, m.sourceHash, m.packedPayload)), "the hash is the message's own");
    }
});

test("a carried key that binds checks the signature: one made by someone else is invalid (forged), as under a held key", () => {
    const creator = Identity.create(), alice = Identity.create(), mallory = Identity.create();
    const forged = accept(alice, creator, { signer: mallory });         // alice's real key, mallory's signature
    const m = parse(forged, creator);
    assert.deepEqual([m.signatureState, m.signatureValidated, m.unverifiedReason], ["invalid", false, LXMessage.SIGNATURE_INVALID]);
    assert.equal(m.senderKey.toString("hex"), alice.getPublicKey().toString("hex"), "the key still bound: the message is its sender's by claim, not by signature");
    // Held key, same answer.
    const held = parse(forged, creator, alice);
    assert.equal(held.signatureState, "invalid");
    // The honest one is validated both ways.
    assert.equal(parse(accept(alice, creator), creator, alice).signatureState, "validated");
});

test("a key that does not bind is no key: the message stays unknown, whoever signed it; a key for another hash is ignored; none carried is unknown", () => {
    const creator = Identity.create(), alice = Identity.create(), bob = Identity.create(), mallory = Identity.create();
    // mallory's key under alice's hash (derives mallory's destination, not alice's)
    const wrong = lxm(alice, creator, "", oldFields({ id: G, action: "accept", sender: lxmfHash(alice),
        keys: `${lxmfHash(alice)}:${mallory.getPublicKey().toString("base64")}` }));
    const m = parse(wrong, creator);
    assert.deepEqual([m.signatureState, m.unverifiedReason, m.senderKey], ["unknown", LXMessage.SOURCE_UNKNOWN, null], "alice signed it, and it cannot be told: the carried key is not alice's");
    // forged AND not binding: still only unknown, not invalid
    const both = lxm(alice, creator, "", oldFields({ id: G, action: "accept", sender: lxmfHash(alice),
        keys: `${lxmfHash(alice)}:${mallory.getPublicKey().toString("base64")}` }), { signer: mallory });
    assert.equal(parse(both, creator).signatureState, "unknown");
    // an entry for bob, binding to bob, in alice's accept: not the sender's key
    const other = lxm(alice, creator, "", oldFields({ id: G, action: "accept", sender: lxmfHash(alice), keys: keyOf(bob) }));
    assert.deepEqual([parse(other, creator).signatureState, parse(other, creator).senderKey], ["unknown", null]);
    // none
    const none = accept(alice, creator, { key: false });
    assert.deepEqual([parse(none, creator).signatureState, parse(none, creator).senderKey], ["unknown", null]);
    // with the sender's key held, the same keyless message is validated, and carries no key
    assert.deepEqual([parse(none, creator, alice).signatureState, parse(none, creator, alice).senderKey], ["validated", null]);
    // a key that does not bind never overrides a held key's verdict
    assert.equal(parse(wrong, creator, alice).signatureState, "validated");
});

test("only an accept or a leave is checked under a carried key: an invite, a plain message and a relay carry keys that decide nothing for their source", () => {
    const creator = Identity.create(), alice = Identity.create();
    for (const action of ["invite", "relay_req", null]) {
        const bytes = lxm(alice, creator, "", oldFields({ id: G, action, sender: lxmfHash(alice), keys: keyOf(alice) }));
        const m = parse(bytes, creator);
        assert.deepEqual([m.signatureState, m.senderKey], ["unknown", null], String(action));
    }
});

test("a message from a source that is no group message is checked as before; one whose destination is unknown is not checked at all", () => {
    const creator = Identity.create(), alice = Identity.create();
    const plain = lxm(alice, creator, "hello");
    assert.equal(parse(plain, creator).signatureState, "unknown");
    assert.equal(parse(plain, creator, alice).signatureState, "validated");
    const bytes = accept(alice, creator);
    const noDestination = LXMessage.fromBytes(bytes.subarray(16), null, store(creator));
    assert.equal(noDestination.signatureState, "invalid", "no destination hash: nothing can be validated (as before)");
    assert.equal(noDestination.senderKey.toString("hex"), alice.getPublicKey().toString("hex"));
});

test("a stamped accept (a fifth payload element) is verified under its carried key like any other: the stamp is not signed", () => {
    const creator = Identity.create(), alice = Identity.create();
    const bytes = accept(alice, creator);
    const [destination, rest] = [bytes.subarray(0, 16), bytes.subarray(16)];
    const payload = rest.subarray(16 + 64);
    // Re-pack the payload with a fifth element appended: a longer array header, the same first four.
    const four = MsgPack.unpack(payload);
    assert.equal(four.length, 4);
    const unstamped = payload.subarray(1);                                 // drop the array header (0x94)
    const stamped = Buffer.concat([Buffer.from([0x95]), unstamped, Buffer.from([0xc4, 0x04, 1, 2, 3, 4])]);
    const message = Buffer.concat([destination, rest.subarray(0, 16 + 64), stamped]);
    const m = parse(message, creator);
    assert.equal(m.signatureState, "validated");
    assert.equal(hex(packedMessage(m)), hex(message), "and the copy a creator keeps is the message as it came, stamp and all");
});

// ── what it is worth ──────────────────────────────────────────────────────

test("statusChangeVerdict: verified counts, forged is ignored, unverifiable counts until the switch and is held from it; unchecked is never counted", () => {
    for (const [signature, switched, want] of [
        ["validated", false, "count"], ["validated", true, "count"],
        ["invalid", false, "ignore"], ["invalid", true, "ignore"],
        ["unknown", false, "count"], ["unknown", true, "hold"],
        [null, false, "ignore"], [undefined, true, "ignore"], ["nonsense", false, "ignore"],
    ]) assert.equal(statusChangeVerdict(signature, switched), want, `${signature} switched=${switched}`);
});

// ── the packed message ────────────────────────────────────────────────────

test("packedMessage is the message exactly as received: destination, source, signature, payload; null for one that was not parsed from bytes", () => {
    const creator = Identity.create(), alice = Identity.create();
    const bytes = accept(alice, creator, { form: "new" });
    const m = parse(bytes, creator);
    const packed = packedMessage(m);
    assert.equal(hex(packed), hex(bytes));
    assert.deepEqual([packed.length >= PACKED_HEADER_LENGTH, hex(packed.subarray(0, 16)), hex(packed.subarray(16, 32))], [true, lxmfHash(creator), lxmfHash(alice)]);
    // What a member's client (or a creator) unpacks again is the same message.
    const again = parse(packed, creator);
    assert.deepEqual([again.signatureState, hex(again.hash)], [m.signatureState, hex(m.hash)]);
    assert.equal(packedMessage(new LXMessage()), null);
    assert.equal(packedMessage(null), null);
});

test("packedHeld is the packed message of a held accept: the held entry's destination, source, signature and signed payload", () => {
    const creator = Identity.create(), alice = Identity.create();
    const bytes = accept(alice, creator, { key: false });
    const m = parse(bytes, creator);
    const entry = {
        src: lxmfHash(alice), dest: hex(m.destinationHash), signature: hex(m.signature),
        payload: LXMessage.signedPayload(m.packedPayload).toString("base64"),
    };
    assert.equal(hex(packedHeld(entry)), hex(bytes));
    assert.equal(parse(packedHeld(entry), alice).signatureState, "validated");
});

test("the limits agree: a creator keeps and passes on a packed message of at most 96 bytes plus the payload limit the held store has, and GroupStore carries that number", () => {
    assert.equal(PACKED_HEADER_LENGTH, 16 + 16 + 64);
    assert.equal(STATUS_PAYLOAD_LIMIT, 2048);
    assert.equal(STATUS_PACKED_LIMIT, PACKED_HEADER_LENGTH + STATUS_PAYLOAD_LIMIT);
    const GroupStore = build("GroupStore", { sGet: () => null, sSet() {}, Buffer, crypto: globalThis.crypto, Date, IdMgr: { hash: null }, ownLxmfDestinationHash: () => "0".repeat(32) });
    assert.equal(GroupStore.STATUS_PACKED_LIMIT, STATUS_PACKED_LIMIT, "app.js keeps its own literal (the store is built where the lib is not): this pins them together");
    assert.equal(GroupStore.HELD_PAYLOAD_LIMIT, STATUS_PAYLOAD_LIMIT);
});
