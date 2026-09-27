/**
 * THE RETICHAT FIELD 0xD1 — LXMF-rust/DISPLAY_NAMES.md §2.1 and §10, the web
 * client's half.
 *
 * Runs the SAME vectors as LXMF-rust (tests/retichat_field_vectors.json, read
 * from that crate, not copied), so the clients cannot drift apart:
 *
 *   decode  the name (key 0 of the 0xD1 map, from the payload bytes) and all
 *           nine group entries by the transition rule — from the map when it
 *           holds the entry with its type, else from the old 0xA0-0xA8
 *           field, one entry at a time — through retichat_field.js and the
 *           reader the app uses, LXMessage.extractGroupFields.
 *   encode  both send forms byte for byte: the old top-level fields (the
 *           form sent while GROUP_ENTRIES_IN_RETICHAT_FIELD is false) and the
 *           map (the form after the switch around 2026-10-26).
 *
 * Then: a name/group map the JS encodes is the very bytes of the Rust
 * vectors and decodes the same; the app's group envelope in both forms, read
 * back by the app's own reader.
 *
 * Run: node --test retichat_field.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, { GROUP_FIELDS } from "./lib/rns/lxmf/lxmf.js";
import * as DN from "./lib/display_name.js";
import * as RF from "./lib/retichat_field.js";

const vectors = JSON.parse(await readFile(
    new URL("../LXMF-rust/tests/retichat_field_vectors.json", import.meta.url), "utf8"));
const hex = (s) => Buffer.from(s, "hex");
/** A packed LXMF payload [timestamp, title, content, <fields bytes>]. */
const payloadWith = (fieldsBytes) => Buffer.concat([hex("94cb41d9d7a4b8000000c400c400"), fieldsBytes]);
const KEYS = new Map(vectors.keys.map((k) => [k.name, k]));
const GROUP_NAMES = vectors.keys.filter((k) => k.key !== 0).map((k) => k.name);

/** The nine group entries of a fields map as the vectors spell them. */
const groupOf = (fields) => Object.fromEntries(GROUP_NAMES.map((name) => [name, RF.readGroupEntry(fields, KEYS.get(name).key)]));

test("§10 keys: the constants are the table of the shared vectors", () => {
    assert.equal(RF.FIELD_RETICHAT, 0xD1);
    assert.equal(LXMF.FIELD_RETICHAT, 0xD1);
    assert.equal(RF.RF_MAX_KEY, 127);
    assert.equal(vectors.keys.length, 10);
    for (const k of vectors.keys) {
        assert.equal(RF[k.constant], k.key, k.constant);
        if (k.type === "name") {
            assert.equal(k.key, RF.RF_DISPLAY_NAME);
            assert.equal(k.legacy_field, null);
            continue;
        }
        const entry = RF.groupEntry(k.key);
        assert.equal(entry.legacy, k.legacy_field, k.name);
        assert.equal(entry.type, k.type, k.name);
        assert.ok(Object.values(GROUP_FIELDS).includes(k.legacy_field), `${k.name}: GROUP_FIELDS still names the old field`);
    }
    assert.deepEqual(RF.GROUP_ENTRIES.map((e) => e.key), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert.equal(RF.groupEntry(0), null, "key 0 is the name, not a group entry");
    assert.equal(RF.groupEntry(10), null);
});

test("§10 the switch has not happened: senders write the old fields", () => {
    assert.equal(RF.GROUP_ENTRIES_IN_RETICHAT_FIELD, false, "the switch is around 2026-10-26, not before");
});

test("§2.1 / §10 decode: every shared vector — the name from the payload bytes", () => {
    assert.ok(vectors.decode.length >= 30);
    for (const v of vectors.decode) {
        const got = DN.decodePayload(payloadWith(hex(v.fields_msgpack_hex)));
        assert.equal(got.state, v.state, v.name);
        assert.equal(got.state === "name" ? got.name : null, v.display_name, v.name);
    }
});

test("§2.1 decode: every shared vector — the name from a decoded fields map (decodeField)", () => {
    for (const v of vectors.decode) {
        const got = DN.decodeField(MsgPack.unpack(hex(v.fields_msgpack_hex)));
        assert.equal(got.state, v.state, v.name);
        assert.equal(got.state === "name" ? got.name : null, v.display_name, v.name);
    }
});

test("§10 decode: every shared vector — the nine group entries, entry by entry, map wins", () => {
    for (const v of vectors.decode) {
        assert.deepEqual(Object.keys(v.group).sort(), [...GROUP_NAMES].sort(), v.name);
        assert.deepEqual(groupOf(MsgPack.unpack(hex(v.fields_msgpack_hex))), v.group, v.name);
    }
});

test("§10 decode: every shared vector — through the app's reader, LXMessage.extractGroupFields", () => {
    const members = (s) => (s ? s.split(",").map((h) => h.trim()).filter((h) => h.length === 32) : []);
    for (const v of vectors.decode) {
        const got = LXMessage.extractGroupFields(MsgPack.unpack(hex(v.fields_msgpack_hex)));
        const g = v.group;
        if (g.group_id === null) {
            assert.equal(got, null, `${v.name}: no group id, not a group message`);
            continue;
        }
        assert.equal(got.groupId, g.group_id, v.name);
        assert.equal(got.groupName, g.group_name, v.name);
        assert.equal(got.groupAction, g.group_action, v.name);
        assert.equal(got.groupSender, g.group_sender, v.name);
        assert.equal(got.relayFor, g.group_relay_for, v.name);
        assert.equal(got.relayDone, g.group_relay_done, v.name);
        assert.deepEqual(got.members, members(g.group_members), v.name);
        assert.deepEqual(got.relaySeen, members(g.group_relay_seen), v.name);
        assert.ok(got.memberKeys instanceof Map, v.name);
    }
});

test("§2.1 a Map at 0xD1 is never read as a name or a group id; the old form's lax types are gone", () => {
    const dict = new Map([[0xD1, new Map([["r", 1], [1, new Map([["x", 1]])]])]]);
    assert.equal(DN.decodeField(dict).state, "absent");
    assert.equal(LXMessage.extractGroupFields(dict), null, "a map entry that is not a str is no group id");
    assert.equal(LXMessage.extractGroupFields(new Map([[0xA0, new Map([[0, Buffer.from("Bob")]])]])), null,
        "a Map at 0xA0 is no group id either");
    assert.equal(LXMessage.extractGroupFields(new Map([[0xA0, Buffer.from("9".repeat(32))]])), null,
        "bin is not a str (strict, as every client)");
    const g = LXMessage.extractGroupFields(new Map([[0xA0, "9".repeat(32)], [0xA7, "true"], [0xA3, 1]]));
    assert.equal(g.relayDone, null, "a str is not a bool");
    assert.equal(g.groupAction, null, "an int is not a str");
    const bothForms = new Map([[0xA0, "old"], [0xD1, new Map([[0, Buffer.from("Bob")], [1, "9".repeat(32)]])]]);
    assert.equal(LXMessage.extractGroupFields(bothForms).groupId, "9".repeat(32), "the map wins");
    assert.deepEqual(DN.decodeField(bothForms), DN.nameState("Bob"), "the name beside it");
});

test("§10 encode: every shared vector, both send forms, byte for byte", () => {
    assert.ok(vectors.encode.length >= 5);
    for (const v of vectors.encode) {
        for (const [inMap, want] of [[false, v.legacy_hex], [true, v.retichat_hex]]) {
            const fields = MsgPack.unpack(hex(v.start_hex));
            for (const { key, value } of v.entries) RF.setGroupEntryAs(fields, key, value, inMap);
            assert.equal(MsgPack.pack(fields).toString("hex"), want, `${v.name} (${inMap ? "map" : "old fields"})`);
        }
        const fields = MsgPack.unpack(hex(v.start_hex));
        for (const { key, value } of v.entries) RF.setGroupEntry(fields, key, value);
        assert.equal(MsgPack.pack(fields).toString("hex"), RF.GROUP_ENTRIES_IN_RETICHAT_FIELD ? v.retichat_hex : v.legacy_hex,
            `${v.name}: the constant picks the form`);
    }
});

test("§10 encode: writing one form removes the entry from the other", () => {
    const fields = MsgPack.unpack(hex("82cca0a56f6c646964ccd18200c403426f6201a36e6577"));
    RF.setGroupEntryAs(fields, RF.RF_GROUP_ID, "9".repeat(32), false);
    assert.equal(RF.readEntry(fields, RF.RF_GROUP_ID), undefined, "gone from the map");
    assert.deepEqual(DN.decodeField(fields), DN.nameState("Bob"), "the name stays");
    RF.setGroupEntryAs(fields, RF.RF_GROUP_ID, "8".repeat(32), true);
    assert.equal(RF.topLevel(fields, 0xA0), undefined, "gone from the old field");
    assert.equal(MsgPack.pack(fields).toString("hex"),
        `81ccd18200c403426f6201d920${Buffer.from("8".repeat(32)).toString("hex")}`);
    RF.setGroupEntryAs(fields, RF.RF_GROUP_RELAY_DONE, true, false);
    assert.equal(RF.topLevel(fields, 0xA7), true);
    assert.throws(() => RF.setGroupEntryAs(new Map(), RF.RF_GROUP_ID, Buffer.from("x"), false), TypeError, "bin is not a str");
    assert.throws(() => RF.setGroupEntryAs(new Map(), RF.RF_GROUP_RELAY_DONE, "true", true), TypeError);
    assert.throws(() => RF.setGroupEntryAs(new Map(), 0, "Bob", true), RangeError, "key 0 is the name");
    assert.throws(() => RF.setGroupEntryAs(new Map(), 10, "x", true), RangeError);
});

test("§2.1 the name entry: key 0 merged into the map, other entries kept, an empty map dropped", () => {
    const fields = new Map([[0x0C, "t"]]);
    RF.setEntry(fields, 4, "leave");
    DN.applyToFields(fields, DN.nameState("Alice"));
    assert.equal(MsgPack.pack(fields).toString("hex"), "82 0c a174 ccd1 82 00c405416c696365 04a56c65617665".replaceAll(" ", ""),
        "key 0 goes first, beside the group entry");
    DN.applyToFields(fields, DN.CLEAR);
    assert.deepEqual(DN.decodeField(fields), DN.CLEAR);
    DN.applyToFields(fields, DN.ABSENT);
    assert.equal(MsgPack.pack(fields).toString("hex"), "820ca174ccd18104a56c65617665", "absent removes only key 0");
    RF.removeEntry(fields, 4);
    assert.equal(MsgPack.pack(fields).toString("hex"), "810ca174", "no empty 0xD1 left behind");
    assert.equal(DN.applyToFields(new Map(), DN.ABSENT).size, 0, "absent on an empty message adds nothing");
    // A received map with wide keys: replaced, not duplicated.
    const wide = MsgPack.unpack(hex("81ce000000d182cf0000000000000000a3426f6201a167"));
    DN.applyToFields(wide, DN.nameState("Eve"));
    assert.equal(RF.retichatMap(wide).size, 2);
    DN.applyToFields(wide, DN.nameState("Mallory"));
    assert.equal(RF.retichatMap(wide).size, 2, "a wide key 0 is key 0");
    assert.equal(wide.size, 1, "one 0xD1");
    // A 0xD1 that is not a map is replaced by one.
    const bin = MsgPack.unpack(hex("81ccd1c403426f62"));
    DN.applyToFields(bin, DN.nameState("Bob"));
    assert.equal(MsgPack.pack(bin).toString("hex"), "81ccd18100c403426f62");
});

test("interop: a name and group map the JS encodes is the Rust vector byte for byte, and decodes the same", () => {
    const all = vectors.encode.find((v) => v.name === "every entry");
    const group = Object.fromEntries(all.entries.map(({ key, value }) => [key, value]));
    const envelope = {
        groupId: group[1], groupMembers: group[2], groupName: group[3], groupAction: group[4], groupSender: group[5],
        groupRelaySeen: group[6], groupRelayFor: group[7], groupRelayDone: group[8], groupMemberKey: group[9],
    };
    // The new form, the name decided first as app.js does: one 0xD1 map, keys 0-9.
    const inMap = RF.applyGroupFields(DN.applyToFields(new Map(), DN.nameState("Bob")), envelope, true);
    const both = vectors.decode.find((v) => v.name === "all group entries and the name in the Retichat field");
    assert.equal(MsgPack.pack(inMap).toString("hex"), both.fields_msgpack_hex);
    // The old form, the name appended after the app's fields as LXMF-rust's
    // router does: exactly the "name in the map, group entries in the old
    // fields" vector.
    const oldForm = vectors.decode.find((v) => v.name.startsWith("name in the map, group entries in the old fields"));
    const legacy = DN.applyToFields(RF.applyGroupFields(new Map(), {
        groupId: oldForm.group.group_id, groupAction: oldForm.group.group_action,
    }, false), DN.nameState("Bob"));
    assert.equal(MsgPack.pack(legacy).toString("hex"), oldForm.fields_msgpack_hex);
    // Without a name: all nine in the old fields is the old-form vector.
    const plain = RF.applyGroupFields(new Map(), envelope, false);
    assert.equal(MsgPack.pack(plain).toString("hex"), all.legacy_hex);
    // Each decodes as the vectors say, by both readers.
    for (const [fields, v] of [[inMap, both], [legacy, oldForm]]) {
        const bytes = MsgPack.pack(fields);
        const name = DN.decodePayload(payloadWith(bytes));
        assert.equal(name.state, v.state, v.name);
        assert.equal(name.name ?? null, v.display_name, v.name);
        assert.deepEqual(groupOf(MsgPack.unpack(bytes)), v.group, v.name);
    }
});

test("applyGroupFields writes what the envelope always carried: group id always, the rest only when set", () => {
    const f = RF.applyGroupFields(new Map(), { groupId: "9".repeat(32), groupName: "", groupAction: null, groupRelayDone: false }, false);
    assert.deepEqual([...f.keys()], [0xA0, 0xA7]);
    assert.equal(f.get(0xA7), false, "relay_done false is sent");
    const m = RF.applyGroupFields(new Map(), { groupId: "9".repeat(32), groupRelayDone: false }, true);
    assert.deepEqual([...m.keys()], [0xD1]);
    assert.deepEqual([...RF.retichatMap(m).keys()], [1, 8]);
});
