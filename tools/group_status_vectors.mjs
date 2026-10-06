#!/usr/bin/env node
/**
 * Generates the shared test vectors for the group member statuses and keys
 * (RFed-spec Group.md, "Member statuses and keys (2026-10-06)"; LXMF-rust
 * DISPLAY_NAMES.md §10 key 10):
 *
 *     LXMF-rust/tests/group_status_vectors.json
 *
 * The phones check themselves against that file (Retichat-ios,
 * Retichat-android; LXMF-rust's app glue), so it is data, not code: fixed test
 * identities, packed accept and leave messages as a member's client sends them
 * (with and without the sender's key, in both group forms), `status` messages
 * carrying them, and the verdict each is owed. Retichat-js's
 * group_status_vectors.test.mjs regenerates it and requires the committed copy
 * to be this output, and runs every vector through the shipped web code.
 *
 *     node tools/group_status_vectors.mjs           print the vectors
 *     node tools/group_status_vectors.mjs --write   write LXMF-rust/tests/group_status_vectors.json
 *     node tools/group_status_vectors.mjs --check   exit 1 unless that file is exactly this output
 *
 * Everything is reproducible: each identity's private key is the SHA-256 of a
 * fixed string (and is listed in the file), Ed25519 signatures are
 * deterministic (RFC 8032), timestamps are fixed, and msgpack writes the
 * shortest forms. The expected verdicts below are written by hand from the
 * spec, not read from the code: buildVectors() asserts the shipped code
 * agrees with each before it returns, so a disagreement stops the generator.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";
import Identity from "../lib/rns/identity.js";
import Destination from "../lib/rns/destination.js";
import LXMessage from "../lib/rns/lxmf/lxmf_message.js";
import MsgPack from "../lib/rns/msgpack.js";
import * as RF from "../lib/retichat_field.js";
import { senderKeyEntry, statusChangeVerdict } from "../lib/group_status.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const VECTORS_PATH = join(ROOT, "..", "LXMF-rust", "tests", "group_status_vectors.json");

const hex = (b) => Buffer.from(b).toString("hex");
const sha = (s) => createHash("sha256").update(s).digest();

// ── the cast ───────────────────────────────────────────────────────────────

/**
 * creator   made the group and answers each accept with a status
 * alice, bob, carol, dave, erin   the members whose messages the vectors carry
 * frank     a member that accepts late: the receiver of the statuses
 * mallory   signs what is not its to sign
 */
const CAST = ["creator", "alice", "bob", "carol", "dave", "erin", "frank", "mallory"];
const NAMES = { creator: "Creator", alice: "Alice", bob: "Bob", carol: "Carol", dave: "Dave", erin: "Erin", frank: "Frank", mallory: "Mallory" };
const GROUP_ID = "5e71ac2d0b1c4f6e9a3d8e7f6c5b4a39";
const MEMBERS = ["creator", "alice", "bob", "carol", "dave", "erin", "frank"];
const T0 = 1790000000.5;

function identityOf(name) {
    // x25519 private key | ed25519 seed: 64 bytes, as Identity.fromPrivateKey takes it.
    return Identity.fromPrivateKey(Buffer.concat([sha(`group_status_vectors/${name}/x25519`), sha(`group_status_vectors/${name}/ed25519`)]));
}
const IDENTITIES = new Map(CAST.map((name) => [name, identityOf(name)]));
const lxmf = (name) => Destination.hash(IDENTITIES.get(name), "lxmf", "delivery").toString("hex");
const keyEntry = (name) => senderKeyEntry(lxmf(name), IDENTITIES.get(name).getPublicKey().toString("hex"));

// ── messages ───────────────────────────────────────────────────────────────

/**
 * What each message is, and the verdict it is owed, by what the receiver holds.
 *   from      the LXMF source (whose hash it names)
 *   signer    who signs it
 *   carries   whose key entry it carries (null: none: a client from before this change)
 *   form      "legacy": group entries in the old top-level fields 0xA0-0xA8, the name in a 0xD1 appended after them
 *             (until the switch); "retichat": every entry, the name too, in the Retichat field 0xD1 (after it)
 *   as        the key entry's hash, when it is not the sender's (a key that does not bind)
 *   verdict   {none, all}: "verified", "forged" or "unverifiable" for a receiver holding no member's key (none) and
 *             one holding every member's (all). Group.md, "Verifying an accept or leave".
 *   answers   whether the creator answers it with a status: an accept that carries its sender's own key, and nothing else
 *             (Group.md, "The creator's answer: status").
 */
const MESSAGES = [
    { name: "alice_accept_keyed_legacy", action: "accept", from: "alice", signer: "alice", carries: "alice", form: "legacy",
      why: "an accept as a build after this change sends it before the switch: the sender's own key in the old field 0xA8",
      verdict: { none: "verified", all: "verified" }, answers: true },
    { name: "alice_accept_keyed_retichat", action: "accept", from: "alice", signer: "alice", carries: "alice", form: "retichat",
      why: "the same accept after the switch: the key is entry 9 of the Retichat field",
      verdict: { none: "verified", all: "verified" }, answers: true },
    { name: "bob_leave_keyed_retichat", action: "leave", from: "bob", signer: "bob", carries: "bob", form: "retichat",
      why: "a leave (a decline is this very message) carries the sender's key as an accept does",
      verdict: { none: "verified", all: "verified" }, answers: false },
    { name: "bob_accept_keyless_legacy", action: "accept", from: "bob", signer: "bob", carries: null, form: "legacy",
      why: "an accept from a client from before this change: no key",
      verdict: { none: "unverifiable", all: "verified" }, answers: false },
    { name: "carol_accept_forged", action: "accept", from: "carol", signer: "mallory", carries: "carol", form: "retichat",
      why: "carol's hash and carol's real key, signed by mallory: invalid under the key it carries, which binds",
      verdict: { none: "forged", all: "forged" }, answers: false },
    { name: "dave_accept_key_not_binding", action: "accept", from: "dave", signer: "dave", carries: "mallory", as: "dave", form: "retichat",
      why: "signed by dave, but the entry under dave's hash holds mallory's key: it derives mallory's destination, so it does not bind and is no key",
      verdict: { none: "unverifiable", all: "verified" }, answers: false },
    { name: "dave_accept_forged_key_not_binding", action: "accept", from: "dave", signer: "mallory", carries: "mallory", as: "dave", form: "retichat",
      why: "mallory under dave's name, carrying her own key as dave's: nothing binds, so with no key held for dave it cannot be told from dave's own",
      verdict: { none: "unverifiable", all: "forged" }, answers: false },
    { name: "erin_accept_keyless_legacy", action: "accept", from: "erin", signer: "erin", carries: null, form: "legacy",
      why: "a keyless accept from a client from before this change",
      verdict: { none: "unverifiable", all: "verified" }, answers: false },
    { name: "erin_leave_forged_keyless", action: "leave", from: "erin", signer: "mallory", carries: null, form: "legacy",
      why: "a leave in erin's name signed by mallory, no key carried: only a held key shows it forged",
      verdict: { none: "unverifiable", all: "forged" }, answers: false },
];

/** What a receiver does with a message by its verdict, before the switch and from it (Group.md): verified counts,
 *  forged is ignored, unverifiable counts until the switch and is held from it. */
const OUTCOME = { verified: ["counts", "counts"], forged: ["ignored", "ignored"], unverifiable: ["counts", "held"] };

function groupFields(m) {
    const entries = { groupId: GROUP_ID, groupAction: m.action, groupSender: lxmf(m.from) };
    if (m.carries) entries.groupMemberKey = senderKeyEntry(m.as ? lxmf(m.as) : lxmf(m.carries), IDENTITIES.get(m.carries).getPublicKey().toString("hex"));
    return groupEnvelope(entries, m.form, NAMES[m.from]);
}

/** The fields map of a group envelope in `form`, the sender's name (key 0 of the Retichat field) included. */
function groupEnvelope(entries, form, name) {
    const fields = new Map();
    if (form === "retichat") {
        RF.setEntry(fields, RF.RF_DISPLAY_NAME, Buffer.from(name));
        RF.applyGroupFields(fields, entries, true);
    } else {
        RF.applyGroupFields(fields, entries, false);
        RF.setEntry(fields, RF.RF_DISPLAY_NAME, Buffer.from(name));      // 0xD1 holding the name (and key 10, in a status), after the old fields
    }
    return fields;
}

let clock = T0;
function pack({ from, to, signer, fields }) {
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = Buffer.from(lxmf(from), "hex");
    m.destinationHash = Buffer.from(lxmf(to), "hex");
    m.title = "";
    m.content = "";
    m.fields = fields;
    const packed = m.pack(IDENTITIES.get(signer), false);
    return { timestamp: m.timestamp, packed, hash: m.hash, fieldsBytes: MsgPack.pack(fields) };
}

/** The verdict the shipped code reaches for `packed` for a receiver holding the keys of `holders` (names). */
function shippedVerdict(packed, holders) {
    const byHash = new Map(holders.map((n) => [lxmf(n), IDENTITIES.get(n)]));
    const m = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), (source) => byHash.get(hex(source)) ?? null);
    return { validated: "verified", invalid: "forged", unknown: "unverifiable" }[m.signatureState];
}

// ── the vectors ────────────────────────────────────────────────────────────

export function buildVectors() {
    clock = T0;
    // The keys a receiver holds: none of the members', or all of them (the members listed; mallory is no member).
    const holders = { none: [], all: ["alice", "bob", "carol", "dave", "erin", "frank"] };

    const messages = MESSAGES.map((spec) => {
        const built = pack({ from: spec.from, to: "creator", signer: spec.signer, fields: groupFields(spec) });
        for (const context of ["none", "all"]) {
            const got = shippedVerdict(built.packed, holders[context]);
            if (got !== spec.verdict[context]) throw new Error(`${spec.name}: the shipped code says ${got} for a receiver holding ${context}, the spec ${spec.verdict[context]}`);
        }
        return {
            name: spec.name,
            why: spec.why,
            action: spec.action,
            source: spec.from,
            destination: "creator",
            signed_by: spec.signer,
            carries_key_of: spec.carries,
            key_entry_hash_of: spec.carries ? (spec.as ?? spec.carries) : null,
            form: spec.form,
            timestamp: built.timestamp,
            fields_msgpack_hex: hex(built.fieldsBytes),
            packed_hex: hex(built.packed),
            message_hash_hex: hex(built.hash),
            verdict: spec.verdict,
            outcome_before_switch: Object.fromEntries(Object.entries(spec.verdict).map(([c, v]) => [c, OUTCOME[v][0]])),
            outcome_from_switch: Object.fromEntries(Object.entries(spec.verdict).map(([c, v]) => [c, OUTCOME[v][1]])),
            creator_answers: spec.answers,
        };
    });
    for (const m of messages) {
        // The verdict decides what counts: the shipped statusChangeVerdict says the same as the table.
        const named = { count: "counts", hold: "held", ignore: "ignored" };
        for (const context of ["none", "all"]) {
            const signature = { verified: "validated", forged: "invalid", unverifiable: "unknown" }[m.verdict[context]];
            if (named[statusChangeVerdict(signature, false)] !== m.outcome_before_switch[context]) throw new Error(`${m.name}: before the switch`);
            if (named[statusChangeVerdict(signature, true)] !== m.outcome_from_switch[context]) throw new Error(`${m.name}: from the switch`);
        }
    }
    const byName = new Map(messages.map((m) => [m.name, m]));

    // One status to frank: for each other listed member (not the creator, not frank) the newest message the creator
    // holds, by member hash ascending, one element each. Both forms of the status itself.
    const statusMembers = [
        { member: "alice", message: "alice_accept_keyed_retichat" },
        { member: "bob", message: "bob_leave_keyed_retichat" },
        { member: "carol", message: "carol_accept_forged" },
        { member: "dave", message: "dave_accept_key_not_binding" },
        { member: "erin", message: "erin_accept_keyless_legacy" },
    ].sort((a, b) => (lxmf(a.member) < lxmf(b.member) ? -1 : 1));
    const elementsOf = (list) => list.map((e) => Buffer.from(byName.get(e.message).packed_hex, "hex"));

    const statuses = [];
    for (const [name, list, to] of [["status_to_frank", statusMembers, "frank"], ["status_empty_to_alice", [], "alice"]]) {
        for (const form of ["legacy", "retichat"]) {
            const fields = groupEnvelope({ groupId: GROUP_ID, groupAction: "status", groupSender: lxmf("creator"), groupStatuses: elementsOf(list) }, form, NAMES.creator);
            const built = pack({ from: "creator", to, signer: "creator", fields });
            statuses.push({
                name: `${name}_${form}`,
                why: name === "status_to_frank"
                    ? "the creator's answer to frank's accept: every other listed member's newest counted accept or leave, as it received it"
                    : "the creator's answer to the first accept: nobody else has answered, so the array is empty (a valid answer)",
                source: "creator",
                destination: to,
                signed_by: "creator",
                form,
                timestamp: built.timestamp,
                group_entries: { group_id: GROUP_ID, group_action: "status", group_sender: lxmf("creator") },
                statuses: list.map((e) => ({ member: e.member, message: e.message })),
                fields_msgpack_hex: hex(built.fieldsBytes),
                packed_hex: hex(built.packed),
                message_hash_hex: hex(built.hash),
            });
        }
    }

    // What the receiver of status_to_frank ends up with, by what it holds and whether the switch has happened.
    const receiverOutcomes = [];
    for (const context of ["none", "all"]) {
        for (const [index, switchName] of [[0, "before"], [1, "from"]]) {
            const elements = statusMembers.map((e) => {
                const m = byName.get(e.message);
                const outcome = { counts: "counted", held: "held", ignored: "skipped" }[(index === 0 ? m.outcome_before_switch : m.outcome_from_switch)[context]];
                return { member: e.member, message: e.message, verdict: m.verdict[context], outcome };
            });
            const after = Object.fromEntries(MEMBERS.map((member) => {
                if (member === "creator" || member === "frank") return [member, "accepted"];
                const e = elements.find((x) => x.member === member);
                if (!e || e.outcome !== "counted") return [member, "invited"];
                return [member, byName.get(e.message).action === "leave" ? "left" : "accepted"];
            }));
            receiverOutcomes.push({
                status: "status_to_frank", receiver: "frank", holds_keys_of: ["creator", ...holders[context]], switch: switchName,
                elements, member_status_after: after,
                held_after: elements.filter((e) => e.outcome === "held").map((e) => ({ member: e.member, action: byName.get(e.message).action })),
            });
        }
    }

    return {
        spec: "RFed-spec Group.md, \"Member statuses and keys (2026-10-06)\"; LXMF-rust/DISPLAY_NAMES.md section 10, key 10 (RF_GROUP_STATUSES)",
        notes: [
            "Generated by Retichat-js tools/group_status_vectors.mjs; do not edit by hand. The same file is checked by Retichat-js (group_status_vectors.test.mjs), and is for Retichat-ios and Retichat-android to run.",
            "All *_hex values are lowercase hex. packed_hex is a whole LXMF message as a member's client sent it: destination (16) | source (16) | signature (64) | msgpack payload [timestamp, title, content, fields]; the signature is over destination | source | payload | SHA-256(destination | source | payload) (LXMessage.py). fields_msgpack_hex is the fields map alone.",
            "identities: each private_key_hex is x25519 private key (32) | ed25519 seed (32), so identities can be rebuilt; public_key_hex is the 64-byte public key; lxmf_delivery_hash_hex is the lxmf.delivery destination hash, the 'hash' of a GROUP_MEMBER_KEYS entry and a message's source; key_entry is the entry, hash:base64(public key), as an invite chunk carries it and an accept or leave carries its sender's own.",
            "messages: accept and leave messages addressed to the creator, group `group.group_id`. form legacy: the group entries in the old top-level fields 0xA0-0xA8 (GROUP_ENTRIES_IN_RETICHAT_FIELD false: until the switch around 2026-10-26) and the name in a 0xD1 holding only it; form retichat: every entry and the name in the Retichat field 0xD1. carries_key_of is whose key the message's GROUP_MEMBER_KEYS entry holds (null: none); key_entry_hash_of is the hash the entry names (a key that does not bind sits under another member's hash).",
            "verdict (Group.md, Verifying an accept or leave), for a receiver that holds no member's key (none) and one that holds every member's (all): verified = the LXMF signature is valid under a key the receiver holds, or under the key the message carries for its own sender once bound (the key derives the lxmf.delivery destination that equals the entry's hash, and that hash is the message's source); forged = the signature is invalid under such a key; unverifiable = no key held, none carried, or the carried one does not bind. A key that does not bind is no key.",
            "outcome_before_switch / outcome_from_switch: counts / held / ignored. Verified counts; forged is ignored; unverifiable counts until the switch and is held from it (until its sender's key arrives). The verdict is decided in the receive path that still holds the packed message; the group rules (only about its sender, only from a listed member, a leave final) apply to what counts.",
            "creator_answers: whether a creator that receives the message answers it with a status: only an accept that carries its sender's own key (and so verifies and counts); never a leave, a keyless accept or a forged one.",
            "statuses: `status` messages from the creator. The group entries are group_entries (the creator is GROUP_SENDER); GROUP_STATUSES is key 10 of the Retichat field in both forms (it has no old field), an array of bin, each element the packed_hex of the messages listed in `statuses`, one for each member that has answered, never the creator's own nor the recipient's, by member lxmf.delivery hash ascending. Each element is checked on its own as if it had arrived directly; its destination is the creator, not the receiver.",
            "receiver_outcomes: what a receiver that has accepted the group (frank) does with status_to_frank, element by element, for a receiver holding no member's key and one holding every member's, before the switch and from it. outcome is counted, held or skipped (a forged element, or one that fails a group rule); member_status_after is every member's status at the receiver afterwards, starting from creator accepted, frank accepted, the rest invited; held_after is what waits for a key.",
        ],
        identities: CAST.map((name) => {
            const id = IDENTITIES.get(name);
            return {
                name,
                display_name: NAMES[name],
                private_key_hex: hex(Buffer.concat([sha(`group_status_vectors/${name}/x25519`), sha(`group_status_vectors/${name}/ed25519`)])),
                public_key_hex: hex(id.getPublicKey()),
                identity_hash_hex: hex(id.hash),
                lxmf_delivery_hash_hex: lxmf(name),
                key_entry: keyEntry(name),
            };
        }),
        group: {
            group_id: GROUP_ID,
            creator: "creator",
            members: MEMBERS,
            group_members: MEMBERS.map(lxmf).join(","),
        },
        messages,
        statuses,
        receiver_outcomes: receiverOutcomes,
    };
}

export const render = (vectors = buildVectors()) => JSON.stringify(vectors, null, 2) + "\n";

// ── command line ───────────────────────────────────────────────────────────

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    const text = render();
    if (process.argv.includes("--write")) {
        writeFileSync(VECTORS_PATH, text);
        console.log(`wrote ${VECTORS_PATH} (${text.length} bytes)`);
    } else if (process.argv.includes("--check")) {
        const have = existsSync(VECTORS_PATH) ? readFileSync(VECTORS_PATH, "utf8") : null;
        if (have === text) console.log("group_status_vectors.json is current");
        else { console.error(`${VECTORS_PATH} is ${have === null ? "missing" : "not what this script generates"}: run it with --write`); process.exit(1); }
    } else {
        process.stdout.write(text);
    }
}
