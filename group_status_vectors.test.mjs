/**
 * THE SHARED VECTORS FOR MEMBER STATUSES AND KEYS — LXMF-rust
 * tests/group_status_vectors.json (RFed-spec Group.md, "Member statuses and
 * keys (2026-10-06)"; DISPLAY_NAMES.md §10 key 10).
 *
 * The file is for the phones to check themselves against, so it is data:
 * fixed identities, packed accept and leave messages (with and without the
 * sender's key, in both group forms), `status` messages carrying them, and
 * the verdict each is owed. Here:
 *
 *   1. The committed file is exactly what tools/group_status_vectors.mjs
 *      generates, so it cannot go stale: the file in ../LXMF-rust/tests/, or,
 *      while that tree is on a branch that does not hold it yet, the copy
 *      committed on its `group-statuses` branch; a test that finds neither
 *      says so and is skipped, never passed.
 *   2. Every vector is run through the shipped web code the way a phone would
 *      run it, from the file's own bytes: each message's verdict by what the
 *      receiver holds; each status's elements; what a receiver of a status
 *      does with each element before and from the switch; what a creator
 *      answers.
 *   3. The shipped sender produces what the vectors say a build after this
 *      change sends.
 *
 * Run: node --test group_status_vectors.test.mjs
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import * as RF from "./lib/retichat_field.js";
import { render, VECTORS_PATH } from "./tools/group_status_vectors.mjs";
import { groupClient, settle, hex } from "./test_group_net.mjs";

const LXMF_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "LXMF-rust");

/** The committed vectors: the working tree's file, else the copy on LXMF-rust's group-statuses branch, else null. */
function committed() {
    if (existsSync(VECTORS_PATH)) return { text: readFileSync(VECTORS_PATH, "utf8"), where: VECTORS_PATH };
    try {
        const text = execFileSync("git", ["-C", LXMF_DIR, "show", "group-statuses:tests/group_status_vectors.json"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
        return { text, where: "LXMF-rust branch group-statuses" };
    } catch {
        return null;
    }
}
const found = committed();
const skip = found ? false : "group_status_vectors.json is in neither ../LXMF-rust/tests/ nor its group-statuses branch: not checked";
const vectors = found ? JSON.parse(found.text) : null;

test("the committed vectors are exactly what tools/group_status_vectors.mjs generates, and the generator is reproducible", { skip }, () => {
    assert.equal(found.text, render(), `${found.where} is stale: run node tools/group_status_vectors.mjs --write in Retichat-js and commit it in LXMF-rust`);
    assert.equal(render(), render(), "the same bytes every time: fixed keys, fixed times, deterministic signatures");
    assert.ok(found.text.endsWith("}\n"));
});

// ── the file, as a phone reads it ─────────────────────────────────────────

const identities = vectors ? new Map(vectors.identities.map((i) => [i.name, { ...i, identity: Identity.fromPrivateKey(Buffer.from(i.private_key_hex, "hex")) }])) : null;
const byName = (list) => new Map(list.map((x) => [x.name, x]));
const bytes = (h) => Buffer.from(h, "hex");
const nameOfHash = (hash) => [...identities.values()].find((i) => i.lxmf_delivery_hash_hex === hash)?.name ?? hash;

/** A receiver's identity store holding the keys of `names`. */
const holding = (names) => {
    const byHash = new Map(names.map((n) => [identities.get(n).lxmf_delivery_hash_hex, identities.get(n).identity]));
    return (source) => byHash.get(hex(source)) ?? null;
};
const verdictOf = (m) => ({ validated: "verified", invalid: "forged", unknown: "unverifiable" })[m.signatureState];
const holders = { none: [], all: ["alice", "bob", "carol", "dave", "erin", "frank"] };

test("the identities are what the file says: public key, identity hash, lxmf.delivery hash and key entry derive from the private key", { skip }, () => {
    assert.deepEqual(vectors.identities.map((i) => i.name), ["creator", "alice", "bob", "carol", "dave", "erin", "frank", "mallory"]);
    for (const i of identities.values()) {
        assert.equal(hex(i.identity.getPublicKey()), i.public_key_hex, i.name);
        assert.equal(hex(i.identity.hash), i.identity_hash_hex, i.name);
        assert.equal(i.key_entry, `${i.lxmf_delivery_hash_hex}:${Buffer.from(i.public_key_hex, "hex").toString("base64")}`, i.name);
        assert.match(i.key_entry.split(":")[1], /^[A-Za-z0-9+/]{86}==$/);
    }
    assert.equal(vectors.group.group_members, vectors.group.members.map((n) => identities.get(n).lxmf_delivery_hash_hex).join(","));
});

test("every message's verdict, for a receiver holding no member's key and one holding every member's, is what the shipped code reaches from the file's bytes; and what it does with each follows", { skip }, () => {
    assert.ok(vectors.messages.length >= 9);
    for (const spec of vectors.messages) {
        const packed = bytes(spec.packed_hex);
        assert.equal(hex(packed.subarray(0, 16)), identities.get(spec.destination).lxmf_delivery_hash_hex, `${spec.name}: addressed to the creator`);
        assert.equal(hex(packed.subarray(16, 32)), identities.get(spec.source).lxmf_delivery_hash_hex, `${spec.name}: from its source`);
        for (const context of ["none", "all"]) {
            const m = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), holding(holders[context]));
            assert.equal(verdictOf(m), spec.verdict[context], `${spec.name}: holding ${context}`);
            const signature = m.signatureState;
            // verified counts, forged is ignored, unverifiable counts before the switch and is held from it
            const before = signature === "validated" || signature === "unknown" ? "counts" : "ignored";
            const from = signature === "validated" ? "counts" : signature === "unknown" ? "held" : "ignored";
            assert.deepEqual([before, from], [spec.outcome_before_switch[context], spec.outcome_from_switch[context]], `${spec.name}: what it is worth, holding ${context}`);
        }
        // The key it carries, when it binds, is the sender's own: the message says so.
        const bound = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), holding([]));
        const carriesBinding = spec.carries_key_of !== null && spec.key_entry_hash_of === spec.source && spec.carries_key_of === spec.source;
        assert.equal(bound.senderKey !== null, carriesBinding, `${spec.name}: a key that binds is the sender's own`);
        // The fields map alone is the payload's fields.
        const fields = MsgPack.unpack(bytes(spec.fields_msgpack_hex));
        assert.equal(MsgPack.pack(fields).toString("hex"), spec.fields_msgpack_hex, `${spec.name}: shortest forms: it re-encodes to itself`);
        const g = LXMessage.extractGroupFields(fields);
        assert.deepEqual([g.groupId, g.groupAction, g.groupSender], [vectors.group.group_id, spec.action, identities.get(spec.source).lxmf_delivery_hash_hex], spec.name);
        const entry = spec.carries_key_of === null ? [] : [[identities.get(spec.key_entry_hash_of).lxmf_delivery_hash_hex, Buffer.from(identities.get(spec.carries_key_of).public_key_hex, "hex").toString("base64")]];
        assert.deepEqual([...g.memberKeys], entry, `${spec.name}: the key entry`);
        // Where the entries are, by form: legacy in the old top-level fields, retichat in 0xD1.
        if (spec.form === "legacy") {
            assert.ok(fields.has(0xA0) && fields.has(0xA3) && fields.has(0xA4), spec.name);
            assert.equal(fields.has(0xA8), spec.carries_key_of !== null, spec.name);
            assert.deepEqual([...fields.get(0xD1).keys()], [0], `${spec.name}: the Retichat field holds the name alone`);
        } else {
            assert.deepEqual([...fields.keys()], [0xD1], spec.name);
            assert.deepEqual([...fields.get(0xD1).keys()], [0, 1, 4, 5, ...(spec.carries_key_of !== null ? [9] : [])], spec.name);
        }
    }
});

test("the statuses: signed by the creator, the group entries as the form selects, key 10 of the Retichat field an array of bin holding exactly the listed messages, one per member, by member hash ascending", { skip }, () => {
    const messages = byName(vectors.messages);
    assert.equal(vectors.statuses.length, 4);
    for (const spec of vectors.statuses) {
        const packed = bytes(spec.packed_hex);
        const m = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), holding([]));
        const creator = identities.get("creator");
        const forCreator = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), (s) => (hex(s) === creator.lxmf_delivery_hash_hex ? creator.identity : null));
        assert.equal(forCreator.signatureState, "validated", `${spec.name}: signed by the creator`);
        assert.equal(m.signatureState, "unknown", `${spec.name}: and by nobody whose key is not held`);
        assert.equal(hex(packed.subarray(0, 16)), identities.get(spec.destination).lxmf_delivery_hash_hex, spec.name);
        const g = LXMessage.extractGroupFields(m.fields);
        assert.deepEqual([g.groupId, g.groupAction, g.groupSender], [spec.group_entries.group_id, "status", spec.group_entries.group_sender], spec.name);
        assert.equal(spec.group_entries.group_sender, creator.lxmf_delivery_hash_hex);
        assert.equal(hex(MsgPack.pack(m.fields)), spec.fields_msgpack_hex, `${spec.name}: the fields re-encode to themselves`);
        assert.ok(Array.isArray(g.statuses) && g.statuses.every((e) => e instanceof Uint8Array), `${spec.name}: an array of bin`);
        assert.deepEqual(g.statuses.map(hex), spec.statuses.map((e) => messages.get(e.message).packed_hex), `${spec.name}: the listed messages, byte for byte`);
        const members = spec.statuses.map((e) => e.member);
        assert.equal(new Set(members).size, members.length, `${spec.name}: one element for each member`);
        assert.deepEqual(members.map((n) => identities.get(n).lxmf_delivery_hash_hex), members.map((n) => identities.get(n).lxmf_delivery_hash_hex).sort(), `${spec.name}: by member hash ascending`);
        assert.equal(members.includes("creator") || members.includes(spec.destination), false, `${spec.name}: neither the creator's nor the recipient's own`);
        for (const e of spec.statuses) assert.equal(messages.get(e.message).source, e.member, `${spec.name}: ${e.message} is ${e.member}'s`);
        // Key 10 is in the Retichat field whatever the form; the other entries are where the form puts them.
        const inMap = m.fields.get(0xD1);
        assert.ok(inMap.has(10), spec.name);
        if (spec.form === "legacy") {
            assert.deepEqual([...inMap.keys()], [0, 10], `${spec.name}: the name and key 10`);
            assert.ok(m.fields.has(0xA0) && m.fields.get(0xA3) === "status" && m.fields.get(0xA4) === creator.lxmf_delivery_hash_hex, spec.name);
        } else {
            assert.deepEqual([...inMap.keys()], [0, 1, 4, 5, 10], spec.name);
            assert.equal([...m.fields.keys()].some((k) => k >= 0xA0 && k <= 0xA8), false, spec.name);
        }
        assert.deepEqual([RF.readStatuses(m.fields).length, RF.readStatuses(MsgPack.unpack(MsgPack.pack(m.fields))).length], [spec.statuses.length, spec.statuses.length], spec.name);
    }
});

// ── the receiver of a status, from the file's bytes ──────────────────────

/** Frank (the file's receiver) as a web client that accepted the group, holding the keys of `names`. */
function frankHolding(names, switched) {
    const frank = identities.get("frank");
    const r = groupClient({ me: frank.identity, switched });
    const creator = identities.get("creator");
    const gid = vectors.group.group_id;
    r.GroupStore.addPending(gid, "G", creator.lxmf_delivery_hash_hex, vectors.group.members.map((n) => identities.get(n).lxmf_delivery_hash_hex));
    for (const n of names) r.know({ own: identities.get(n).lxmf_delivery_hash_hex, pubKey: identities.get(n).public_key_hex });
    r.GroupStore.accept(gid);
    return r;
}

test("a receiver of status_to_frank does, element by element, what the file says, holding no member's key and every member's, before the switch and from it, whichever form the status came in", { skip }, async () => {
    const gid = vectors.group.group_id;
    const statuses = byName(vectors.statuses);
    assert.equal(vectors.receiver_outcomes.length, 4);
    for (const expected of vectors.receiver_outcomes) for (const form of ["legacy", "retichat"]) {
        const label = `holding ${expected.holds_keys_of.length === 1 ? "no member's key" : "every member's key"}, ${expected.switch} the switch, ${form} form`;
        const r = frankHolding(expected.holds_keys_of, expected.switch === "from");
        await r.receive(bytes(statuses.get(`${expected.status}_${form}`).packed_hex));
        assert.equal(r.proofs.length, 1, `${label}: the creator's status is proved`);
        const after = Object.fromEntries(vectors.group.members.map((n) => [n, r.status(gid, identities.get(n).lxmf_delivery_hash_hex)]));
        assert.deepEqual(after, expected.member_status_after, label);
        assert.deepEqual(r.GroupStore.heldChanges().map((e) => ({ member: nameOfHash(e.src), action: e.action })).sort((a, b) => (a.member < b.member ? -1 : 1)),
            expected.held_after.slice().sort((a, b) => (a.member < b.member ? -1 : 1)), `${label}: held`);
        const tally = r.events.find((e) => e.kind === "group-status-received").detail;
        const outcomes = expected.elements.map((e) => e.outcome);
        assert.deepEqual([tally.elements, tally.counted, tally.held, tally.skipped],
            [outcomes.length, outcomes.filter((o) => o === "counted").length, outcomes.filter((o) => o === "held").length, outcomes.filter((o) => o === "skipped").length], label);
        // The notices: one for each member that counted, "left" for a leave.
        const said = r.notices(gid).map(([text, who]) => [text, nameOfHash(who)]).sort();
        const want = expected.elements.filter((e) => e.outcome === "counted").map((e) => [vectors.messages.find((m) => m.name === e.message).action === "leave" ? "left the group" : "joined the group", e.member]).sort();
        assert.deepEqual(said, want, `${label}: said once each`);
    }
});

test("a status with no elements, from the file, is the creator's valid answer and changes nothing", { skip }, async () => {
    const alice = identities.get("alice");
    const statuses = byName(vectors.statuses);
    for (const form of ["legacy", "retichat"]) {
        const r = groupClient({ me: alice.identity });
        const gid = vectors.group.group_id;
        r.GroupStore.addPending(gid, "G", identities.get("creator").lxmf_delivery_hash_hex, vectors.group.members.map((n) => identities.get(n).lxmf_delivery_hash_hex).concat(r.own).filter((h, i, all) => all.indexOf(h) === i));
        r.know({ own: identities.get("creator").lxmf_delivery_hash_hex, pubKey: identities.get("creator").public_key_hex });
        r.GroupStore.accept(gid);
        await r.receive(bytes(statuses.get(`status_empty_to_alice_${form}`).packed_hex));
        assert.equal(r.proofs.length, 1, form);
        assert.deepEqual(r.events.find((e) => e.kind === "group-status-received").detail, { group: gid.slice(0, 8), elements: 0, counted: 0, held: 0, skipped: 0 }, form);
    }
});

// ── the creator, from the file's bytes ───────────────────────────────────

test("a creator that receives each message answers it with a status exactly when the file says: only an accept that carries its sender's own key", { skip }, async () => {
    const gid = vectors.group.group_id;
    for (const context of ["none", "all"]) for (const spec of vectors.messages) {
        const creator = identities.get("creator");
        const c = groupClient({ me: creator.identity });
        const members = vectors.group.members.filter((n) => n !== "creator").map((n) => identities.get(n));
        // The group the vectors name, created by this device: it is the creator (invited into by itself) and has accepted it.
        c.GroupStore.addPending(gid, "G", creator.lxmf_delivery_hash_hex, vectors.group.members.map((n) => identities.get(n).lxmf_delivery_hash_hex));
        c.GroupStore.accept(gid);
        assert.equal(c.GroupStore.get(gid).creator, creator.lxmf_delivery_hash_hex);
        for (const n of holders[context]) c.know({ own: identities.get(n).lxmf_delivery_hash_hex, pubKey: identities.get(n).public_key_hex });
        c.reachable(...members.map((i) => i.lxmf_delivery_hash_hex));
        // A sender whose key the creator cannot learn any other way must have it carried: the key is not held under "none".
        await c.receive(bytes(spec.packed_hex));
        await settle();
        const answered = c.decoded().filter(({ message }) => LXMessage.extractGroupFields(message.fields)?.groupAction === "status").map(({ to }) => nameOfHash(to));
        assert.deepEqual(answered, spec.creator_answers ? [spec.source] : [], `${spec.name}, the creator holding ${context}`);
        // What it keeps follows what counted: a copy of exactly the bytes, or none.
        const counted = spec.outcome_before_switch[context] === "counts";
        assert.deepEqual(c.GroupStore.statusMessages(gid).map((s) => [nameOfHash(s.member), s.action, hex(s.packed)]),
            counted ? [[spec.source, spec.action, spec.packed_hex]] : [], `${spec.name}, the creator holding ${context}: kept only when it counts`);
    }
});

// ── the sender, against the file ─────────────────────────────────────────

test("the shipped sender writes what the file says a build after this change writes: alice's accept carries her own key entry, in the old field before the switch and in key 9 of the Retichat field after", async () => {
    const gid = vectors.group.group_id;
    const alice = identities.get("alice");
    for (const switched of [false, true]) {
        const a = groupClient({ me: alice.identity, switched });
        const members = vectors.group.members.map((n) => identities.get(n));
        a.GroupStore.addPending(gid, "G", identities.get("creator").lxmf_delivery_hash_hex, members.map((i) => i.lxmf_delivery_hash_hex));
        for (const i of members) if (i.name !== "alice") a.know({ own: i.lxmf_delivery_hash_hex, pubKey: i.public_key_hex });
        a.reachable(...members.map((i) => i.lxmf_delivery_hash_hex));
        a.page._acceptGroupInvite(gid);
        await settle();
        const toCreator = a.decoded().find(({ to }) => to === identities.get("creator").lxmf_delivery_hash_hex).message;
        const spec = vectors.messages.find((m) => m.name === (switched ? "alice_accept_keyed_retichat" : "alice_accept_keyed_legacy"));
        const vector = LXMessage.extractGroupFields(MsgPack.unpack(bytes(spec.fields_msgpack_hex)));
        const sent = LXMessage.extractGroupFields(toCreator.fields);
        assert.deepEqual([sent.groupId, sent.groupAction, sent.groupSender, [...sent.memberKeys]], [vector.groupId, vector.groupAction, vector.groupSender, [...vector.memberKeys]], `${switched ? "after" : "before"} the switch: the same entries`);
        assert.equal(sent.memberKeys.size, 1);
        assert.deepEqual([...toCreator.fields.keys()].filter((k) => k !== 0xD1), [...MsgPack.unpack(bytes(spec.fields_msgpack_hex)).keys()].filter((k) => k !== 0xD1), `${switched ? "after" : "before"} the switch: the same fields, the Retichat field aside`);
        const where = (fields) => (switched ? fields.get(0xD1).get(9) : fields.get(0xA8));
        assert.equal(where(toCreator.fields), alice.key_entry, "the entry as the file spells it");
        assert.equal(where(MsgPack.unpack(bytes(spec.fields_msgpack_hex))), alice.key_entry, "and as the vector carries it");
        if (switched) {
            const keys = (fields) => [...fields.get(0xD1).keys()].filter((k) => k !== RF.RF_DISPLAY_NAME);
            assert.deepEqual(keys(toCreator.fields), keys(MsgPack.unpack(bytes(spec.fields_msgpack_hex))), "the same keys of the Retichat field, the name aside");
        }
        assert.equal(toCreator.signatureValidated, true);
    }
});
