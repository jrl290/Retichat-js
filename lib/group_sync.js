/**
 * Groups and the distro: RFed-rust SPEC.md §17.14, "Groups and the distro"
 * (James, 2026-10-10; GROUPS-DISTRO-DESIGN.md §7, §10, §11.1). The wire
 * rules only, no network, no DOM: app.js sends and applies them
 * (RnsClient._sendDistroGroupSync, _handleDistroBlob,
 * _handleDistroGroupSync).
 *
 * The user's own create, accept, leave (a decline, a leave or a delete) and
 * post in a group whose own address is the distro D travel to D's other
 * devices as one LXMF message G from D to D, through the distro fan-out, as
 * a §17.12 membership message does:
 *
 *   0x0C FIELD_TICKET       an empty bin: no ticket, but it makes older
 *                           clients take G for a delivery notification and
 *                           drop it. Never read here.
 *   0xFB FIELD_CUSTOM_TYPE  "rfed.distro.group"
 *   0xFC FIELD_CUSTOM_DATA  a native msgpack array, never a bin holding
 *                           packed msgpack (CHECK_THESE_THINGS_FIRST.md §11):
 *                             ["create", group_id, at_ms, name, members, keys, left]
 *                             ["accept", group_id, at_ms, name, members, keys, creator, left]
 *                             ["leave",  group_id, at_ms, left]
 *                             ["post",   group_id, at_ms, text, left]
 *   0xFD FIELD_CUSTOM_META  the sending device's own lxmf.delivery address
 *
 * A received G is read from the payload's bytes (msgpack_raw.js), not from
 * msgpackr's decoding, as lib/channel_sync.js reads C: msgpackr hands an
 * integral float back as a plain number, and rule 4 takes only an integer
 * at_ms. The readings are LXMF-rust's (lxmf_rust::distro::read_group_sync),
 * pinned by its golden vectors (distro_group_sync_vectors.json, copied
 * here and checked byte for byte by group_sync.test.mjs).
 */

import MsgPack from "./rns/msgpack.js";
import { readHead, skipValue } from "./rns/msgpack_raw.js";
import { RF_GROUP_ID, RF_GROUP_ACTION, RF_GROUP_NAME, readEntry, readGroupEntry, topLevel, groupEntry } from "./retichat_field.js";

export const DISTRO_GROUP_TYPE = "rfed.distro.group";

/** The four 0xFB strings that make a message the distro's own (GROUPS-
 *  DISTRO-DESIGN.md §5): a message carrying one is never a group message,
 *  whatever group entries it also carries. */
export const DISTRO_MARKERS = Object.freeze([
    "rfed.distro.transfer", // §17.9
    "rfed.distro.sent",     // §17.11
    "rfed.distro.channel",  // §17.12
    DISTRO_GROUP_TYPE,      // §17.14
]);

/** The largest at_ms: 2^53 − 1, exact in every JSON reader (§10.2). */
export const MAX_AT_MS = Number.MAX_SAFE_INTEGER;

/** At most this many ids in a G's `left` (§10.2). */
export const GROUP_SYNC_LEFT_MAX = 32;

export const GROUP_SYNC_OPS = Object.freeze(["create", "accept", "leave", "post"]);

const FIELD_TICKET = 0x0C;
const FIELD_CUSTOM_TYPE = 0xFB;
const FIELD_CUSTOM_DATA = 0xFC;
const FIELD_CUSTOM_META = 0xFD;

const HEX32 = /^[0-9a-fA-F]{32}$/;
const LOWER_HEX32 = /^[0-9a-f]{32}$/;

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
const lossyUtf8 = new TextDecoder("utf-8");

/**
 * The code points the invite parser trims from each GROUP_MEMBERS entry:
 * Unicode Zs and U+0009, which is Swift's CharacterSet.whitespaces, and no
 * other (LXMF-rust is_invite_space, 1a1ed8b; the vectors' invite_space).
 * Not JavaScript's trim(), which also strips \n, \r, \v, \f, U+2028,
 * U+2029 and U+FEFF: a list naming D wrapped in a newline would name D
 * here and not on the phones, and the devices would disagree on who is
 * listed.
 */
export const INVITE_SPACE = Object.freeze([
    0x0009, 0x0020, 0x00A0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
    0x202F, 0x205F, 0x3000,
]);
const INVITE_SPACE_SET = new Set(INVITE_SPACE);

/** Whether code point `cp` is one the invite parser trims. */
export function isInviteSpace(cp) {
    return INVITE_SPACE_SET.has(cp);
}

/** `s` with every invite space (isInviteSpace) at either end removed. Each
 *  invite space is one UTF-16 code unit and no surrogate, so a code unit
 *  that is one is that code point, and half of a surrogate pair never is. */
function trimInviteSpace(s) {
    let start = 0;
    let end = s.length;
    while (start < end && INVITE_SPACE_SET.has(s.charCodeAt(start))) start++;
    while (end > start && INVITE_SPACE_SET.has(s.charCodeAt(end - 1))) end--;
    return s.slice(start, end);
}

/**
 * The members a GROUP_MEMBERS csv lists, with the phones' invite parser
 * (iOS/Android DeliveryPolicy.members; LXMF-rust invite_members): split on
 * ',', each entry trimmed of invite space (INVITE_SPACE) at both ends, kept
 * when it is then exactly 32 lowercase hex, the first of each. An entry in
 * uppercase is no member: the phones count only lowercase. Used for every
 * invite on the web (LXMessage.extractGroupFields) and for a G's `members`
 * (rule 4), so a G names D exactly when an invite with that list does.
 */
export function inviteMembers(csv) {
    if (typeof csv !== "string" || csv.length === 0) return [];
    const out = [];
    const seen = new Set();
    for (const raw of csv.split(",")) {
        const entry = trimInviteSpace(raw);
        if (!LOWER_HEX32.test(entry) || seen.has(entry)) continue;
        seen.add(entry);
        out.push(entry);
    }
    return out;
}

/** The text of a decoded 0xFB value (str or bin), else null. */
function markerText(value) {
    if (typeof value === "string") return value;
    if (value instanceof Uint8Array) {
        try { return strictUtf8.decode(value); } catch { return null; }
    }
    return null;
}

/** Whether a decoded fields Map carries one of the four distro markers. */
export function carriesDistroMarker(fields) {
    const type = markerText(topLevel(fields, FIELD_CUSTOM_TYPE));
    return type !== null && DISTRO_MARKERS.includes(type);
}

/**
 * GROUPS-DISTRO-DESIGN.md §7, for a decoded fields Map: the group entries
 * the distro unwrap reports, computed here as LXMF-rust computes them for
 * the phones.
 *   has_group_id  a GROUP_ID entry in either form (key 1 of 0xD1, or the
 *                 old 0xA0), of any type, and no distro marker in 0xFB.
 *                 This routes a message to the group branch (§6.1 step 2),
 *                 so a malformed id is dropped there, never filed as a DM.
 *   group_id      GROUP_ID by Group.md's reader rule (retichat_field.js
 *                 readGroupEntry: key 1 of 0xD1 when it is a str, else
 *                 0xA0 when that is), when it is 32 hex, lowercased; else
 *                 null.
 *   group_action, group_name  by the same rule, as sent; null when absent.
 * All false/null when a distro marker is present (its group entries are
 * never read).
 */
export function groupEntriesOf(fields) {
    const none = { has_group_id: false, group_id: null, group_action: null, group_name: null };
    if (!(fields instanceof Map) || carriesDistroMarker(fields)) return none;
    const inRetichat = readEntry(fields, RF_GROUP_ID) !== undefined;
    const inLegacy = topLevel(fields, groupEntry(RF_GROUP_ID).legacy) !== undefined;
    if (!inRetichat && !inLegacy) return none;
    const id = readGroupEntry(fields, RF_GROUP_ID);
    return {
        has_group_id: true,
        group_id: typeof id === "string" && HEX32.test(id) ? id.toLowerCase() : null,
        group_action: readGroupEntry(fields, RF_GROUP_ACTION),
        group_name: readGroupEntry(fields, RF_GROUP_NAME),
    };
}

/**
 * The fields of a group sync G (§10.1, §10.2), as a Map in the wire order
 * (0x0C, 0xFB, 0xFC, 0xFD). `sync` is the §7 group_sync object without
 * `by` and `problem`: { op, group_id, at_ms, name, members, keys, creator,
 * text, left }, with exactly the keys its op uses (the others absent or
 * null). `dHex` is D's lxmf.delivery hash, `deviceHex` this device's own.
 *
 * at_ms goes as a BigInt, so msgpackr writes it as an int 64 (0xd3), as
 * channelSyncFields writes C's (a JS number above 32 bits would go as a
 * float 64, which rule 4 refuses). Every reader takes it by value: rmpv and
 * umsgpack write the same value as a uint 64 (0xcf), so these bytes are the
 * vectors' with that one type byte different (the variant
 * accept_web_form_int64_at_ms is this form, byte for byte).
 *
 * What is written is read back with readGroupSyncFields first, and refused
 * (thrown) unless rule 4 takes it, as LXMF-rust set_group_sync_fields
 * refuses: a G the siblings would drop is never owed.
 */
export function groupSyncFields(sync, dHex, deviceHex) {
    if (typeof dHex !== "string" || !HEX32.test(dHex)) throw new Error("a group sync names its distro D (32 hex)");
    if (typeof deviceHex !== "string" || !HEX32.test(deviceHex)) throw new Error("0xFD is the sending device's own lxmf.delivery address");
    if (!sync || typeof sync !== "object") throw new Error("no group sync to write");
    const { op } = sync;
    if (!GROUP_SYNC_OPS.includes(op)) throw new Error(`a group sync's op is create, accept, leave or post, not ${op}`);
    const used = { create: ["name", "members", "keys"], accept: ["name", "members", "keys", "creator"], leave: [], post: ["text"] }[op];
    for (const key of ["name", "members", "keys", "creator", "text"]) {
        const present = sync[key] !== undefined && sync[key] !== null;
        if (present && !used.includes(key)) throw new Error(`a ${op} carries no ${key}`);
        if (!present && used.includes(key)) throw new Error(`a ${op} carries its ${key}`);
    }
    if (typeof sync.group_id !== "string" || !HEX32.test(sync.group_id)) throw new Error("group_id is 32 hex");
    if (!Number.isSafeInteger(sync.at_ms) || sync.at_ms < 0) throw new Error(`at_ms is an integer from 0 to 2^53 − 1, not ${sync.at_ms}`);
    if (!Array.isArray(sync.left)) throw new Error("left is an array");
    if (sync.left.length > GROUP_SYNC_LEFT_MAX) throw new Error(`left holds at most ${GROUP_SYNC_LEFT_MAX} ids`);
    const left = sync.left.map((id) => {
        if (typeof id !== "string" || !HEX32.test(id)) throw new Error("each id in left is 32 hex");
        return id.toLowerCase();
    });
    const data = [op, sync.group_id.toLowerCase(), BigInt(sync.at_ms)];
    if (op === "create" || op === "accept") {
        if (typeof sync.name !== "string") throw new Error("name is a str");
        if (typeof sync.members !== "string") throw new Error("members is a str");
        if (!Array.isArray(sync.keys) || sync.keys.some((k) => typeof k !== "string")) throw new Error("keys is an array of str");
        data.push(sync.name, sync.members, [...sync.keys]);
        if (op === "accept") {
            if (typeof sync.creator !== "string" || !HEX32.test(sync.creator)) throw new Error("creator is 32 hex");
            data.push(sync.creator.toLowerCase());
        }
    } else if (op === "post") {
        if (typeof sync.text !== "string") throw new Error("text is a str");
        data.push(sync.text);
    }
    data.push(left);
    const fields = new Map([
        [FIELD_TICKET, new Uint8Array(0)],
        [FIELD_CUSTOM_TYPE, DISTRO_GROUP_TYPE],
        [FIELD_CUSTOM_DATA, data],
        [FIELD_CUSTOM_META, deviceHex.toLowerCase()],
    ]);
    const check = readGroupSyncFields(MsgPack.pack(fields), 0, dHex);
    if (!check || check.problem !== null) throw new Error(`the group sync would be refused by its receivers: ${check?.problem ?? "it is not one"}`);
    return fields;
}

/** The value positions of every entry of the map at `pos` whose key is the
 *  integer `key`, in order (a repeated key: the last is what msgpackr and
 *  rmpv keep). */
function entriesOf(b, pos, key) {
    const map = readHead(b, pos);
    if (map.kind !== "map") return null;
    const found = [];
    pos = map.end;
    for (let i = 0; i < map.count; i++) {
        const k = readHead(b, pos);
        pos = skipValue(b, pos);
        if (k.kind === "int" && k.int === key) found.push(pos);
        pos = skipValue(b, pos);
    }
    return found;
}

/** The head of the last entry of the map at `pos` with integer key `key`, or null. */
function lastEntry(b, pos, key) {
    const found = entriesOf(b, pos, key);
    if (!found || found.length === 0) return null;
    const at = found[found.length - 1];
    return { pos: at, head: readHead(b, at) };
}

/** A str or bin value as text, strict UTF-8, else null. */
function strictText(head) {
    if (head.kind !== "str" && head.kind !== "bin") return null;
    try { return strictUtf8.decode(head.raw); } catch { return null; }
}

/** A str value (never a bin) of valid UTF-8, else null. */
function strOnly(head) {
    if (head.kind !== "str") return null;
    try { return strictUtf8.decode(head.raw); } catch { return null; }
}

/** A str or bin value as text, invalid UTF-8 replaced (U+FFFD), else null:
 *  how LXMF-rust reads a G's name and text (from_utf8_lossy). */
function lossyText(head) {
    if (head.kind !== "str" && head.kind !== "bin") return null;
    return lossyUtf8.decode(head.raw);
}

/** A str of 32 hex, lowercased, else null. */
function hexId(head) {
    const s = strOnly(head);
    return s !== null && HEX32.test(s) ? s.toLowerCase() : null;
}

/** The §7 group_sync object for a reading that fails rule 4. */
function refused(by, problem) {
    return { by, problem, op: null, group_id: null, at_ms: null, name: null, members: null, keys: null, creator: null, text: null, left: null };
}

/**
 * Rule 4 of §11.1 on the fields map at `pos` of bytes `b`, for distro D
 * (`dHex`): null when the map's 0xFB (str or bin, the last entry) is not
 * "rfed.distro.group"; otherwise the §7 group_sync object, every key
 * present, in its order:
 *   { by, problem, op, group_id, at_ms, name, members, keys, creator, text, left }
 * `by` is 0xFD's text lowercased, "" when absent; it is not checked.
 * `problem` is null when the form passes rule 4, else why not, and then
 * every key after it is null. Rule 4: 0xFC a native array; op a str, one of
 * the four; group_id a str of 32 hex (read lowercased); at_ms an integer
 * from 0 to 2^53 − 1 in any integer encoding (by value, never the type
 * byte); for create and accept, name a str or bin, members a str whose
 * csv, parsed with the invite parser (inviteMembers), names D, keys an
 * array of str; for accept, creator a str of 32 hex, listed, not D; for
 * post, text a str or bin; for every op, left an array of at most 32 str
 * of 32 hex (read lowercased). Elements after left are ignored. A name or
 * text that is not valid UTF-8 is read with U+FFFD; an op, members, key
 * or id that is not is refused.
 */
export function readGroupSyncFields(b, pos, dHex) {
    let type;
    try {
        type = lastEntry(b, pos, FIELD_CUSTOM_TYPE);
    } catch {
        return null;
    }
    if (!type || strictText(type.head) !== DISTRO_GROUP_TYPE) return null;
    let by = "";
    try {
        const meta = lastEntry(b, pos, FIELD_CUSTOM_META);
        by = ((meta && strictText(meta.head)) ?? "").toLowerCase();
    } catch { /* the map was walked once already */ }
    const bad = (problem) => refused(by, problem);
    const d = typeof dHex === "string" ? dHex.toLowerCase() : "";
    try {
        const data = lastEntry(b, pos, FIELD_CUSTOM_DATA);
        if (!data) return bad("it carries no 0xFC");
        if (data.head.kind !== "array") return bad(`its 0xFC is a ${data.head.kind}, not a native array`);
        const count = data.head.count;
        const heads = [];
        let p = data.head.end;
        for (let i = 0; i < count; i++) {
            heads.push({ head: readHead(b, p), at: p });
            p = skipValue(b, p);
        }
        if (count === 0) return bad("its 0xFC is empty");
        const op = strOnly(heads[0].head);
        if (!GROUP_SYNC_OPS.includes(op)) return bad(`its op is ${op === null ? "not a str" : JSON.stringify(op)}, not create, accept, leave or post`);
        const need = { create: 7, accept: 8, leave: 4, post: 5 }[op];
        if (count < need) return bad(`a ${op} has ${need} elements, ending with left; this one has ${count}`);
        const groupId = hexId(heads[1].head);
        if (groupId === null) return bad("its group_id is not a str of 32 hex");
        const at = heads[2].head;
        if (at.kind !== "int" || !Number.isSafeInteger(at.int) || at.int < 0) return bad("its at_ms is not an integer from 0 to 2^53 − 1");
        const out = { by, problem: null, op, group_id: groupId, at_ms: at.int, name: null, members: null, keys: null, creator: null, text: null, left: null };
        if (op === "create" || op === "accept") {
            const name = lossyText(heads[3].head);
            if (name === null) return bad("its name is not a str or bin");
            const members = strOnly(heads[4].head);
            if (members === null) return bad("its members is not a str of UTF-8");
            const listed = inviteMembers(members);
            if (!listed.includes(d)) return bad("its members does not name D");
            const keysHead = heads[5].head;
            if (keysHead.kind !== "array") return bad("its keys is not an array");
            const keys = [];
            let kp = keysHead.end;
            for (let i = 0; i < keysHead.count; i++) {
                const k = strOnly(readHead(b, kp));
                if (k === null) return bad("its keys holds a value that is not a str of UTF-8");
                keys.push(k);
                kp = skipValue(b, kp);
            }
            Object.assign(out, { name, members, keys });
            if (op === "accept") {
                const creator = hexId(heads[6].head);
                if (creator === null) return bad("its creator is not a str of 32 hex");
                if (creator === d) return bad("its creator is D");
                if (!listed.includes(creator)) return bad("its creator is not listed");
                out.creator = creator;
            }
        } else if (op === "post") {
            const text = lossyText(heads[3].head);
            if (text === null) return bad("its text is not a str or bin");
            out.text = text;
        }
        const leftHead = heads[need - 1].head;
        if (leftHead.kind !== "array") return bad("its left is not an array");
        if (leftHead.count > GROUP_SYNC_LEFT_MAX) return bad(`its left holds ${leftHead.count} ids, more than ${GROUP_SYNC_LEFT_MAX}`);
        const left = [];
        let lp = leftHead.end;
        for (let i = 0; i < leftHead.count; i++) {
            const id = hexId(readHead(b, lp));
            if (id === null) return bad("its left holds a value that is not a str of 32 hex");
            left.push(id);
            lp = skipValue(b, lp);
        }
        out.left = left;
        return out;
    } catch (e) {
        return bad(`its fields cannot be read (${e.message})`);
    }
}

/**
 * The group sync of a received LXMF message, from its packed payload
 * [timestamp, title, content, fields, (stamp)] (readGroupSyncFields on its
 * fields map): null when it is none, else the §7 group_sync object.
 */
export function readGroupSync(packedPayload, dHex) {
    if (!(packedPayload instanceof Uint8Array)) return null;
    try {
        const top = readHead(packedPayload, 0);
        if (top.kind !== "array" || top.count < 4) return null;
        let pos = top.end;
        for (let i = 0; i < 3; i++) pos = skipValue(packedPayload, pos);
        return readGroupSyncFields(packedPayload, pos, dHex);
    } catch {
        return null;
    }
}

/**
 * §11.1 rules 1-4, in order; the first that drops ends the check (rule 0,
 * the repeat, is the caller's: DistroSeen under gsync:<hash>). `read` is
 * readGroupSync's result (not null). Facts:
 *   fromDistro      the unwrapped source is D (rule 1);
 *   signedByDistro  the signature validates under D's key, over the payload
 *                   as received (rule 2, as §17.11 rule 2);
 *   ownDeviceHex    this device's own lxmf.delivery address (rule 3).
 * Returns { verdict: "drop", rule, reason } (dropped with a log line),
 * { verdict: "echo" } (this device's own G: dropped, recorded as seen), or
 * { verdict: "apply", sync, by } (rule 5 and the apply table next).
 */
export function groupSyncDisposition(read, { fromDistro, signedByDistro, ownDeviceHex }) {
    const drop = (rule, reason) => ({ verdict: "drop", rule, reason });
    if (!fromDistro) return drop(1, "its source is not this device's distro");
    if (!signedByDistro) return drop(2, "it fails the distro signature");
    if (ownDeviceHex && read.by === String(ownDeviceHex).toLowerCase()) return { verdict: "echo" };
    if (read.problem !== null) return drop(4, read.problem);
    return { verdict: "apply", sync: read, by: read.by };
}

