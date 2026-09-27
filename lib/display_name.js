/**
 * Display names — the JS mirror of LXMF-rust `display_name` and the rules of
 * LXMF-rust/DISPLAY_NAMES.md that every client applies itself.
 *
 * The contract is DISPLAY_NAMES.md; where this file and the spec disagree the
 * spec wins. The cleaning function is tested against the same vectors as the
 * Rust crate (LXMF-rust/tests/display_name_vectors.json), read from that file
 * by display_names.test.mjs.
 *
 * Nothing here touches storage or the network: the persistent stores (the
 * name ledger, the channel posting state, received channel names) live in
 * name_ledger.js.
 */

import { Buffer } from "buffer";
import Cryptography from "./rns/cryptography.js";

/** §2.1: field 0xD1, FIELD_DISPLAY_NAME. */
export const FIELD_DISPLAY_NAME = 0xD1;

/** §3 rule 5: names are cut to this many Unicode scalar values. */
export const MAX_SCALARS = 64;

/** §4.1: a name confirmed delivered is sent again after this many seconds. */
export const NAME_REFRESH_SECS = 30 * 24 * 60 * 60;

/** §4.2: a channel post carries the name again after this many seconds. */
export const CHANNEL_NAME_REFRESH_SECS = 24 * 60 * 60;

/** MeshChatX's and Columba's placeholder: an announce carrying it is anonymous. */
export const ANONYMOUS_PEER = "Anonymous Peer";

/** Unicode White_Space (PropList.txt). Rule 2 turns each into U+0020. */
function isWhiteSpace(cp) {
    return (cp >= 0x09 && cp <= 0x0D) || cp === 0x20 || cp === 0x85 || cp === 0xA0 ||
        cp === 0x1680 || (cp >= 0x2000 && cp <= 0x200A) || cp === 0x2028 || cp === 0x2029 ||
        cp === 0x202F || cp === 0x205F || cp === 0x3000;
}

/** Rule 3: removed outright. U+200C and U+200D are kept. */
function isRemoved(cp) {
    return cp <= 0x1F || cp === 0x7F || (cp >= 0x80 && cp <= 0x9F) ||
        (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) ||
        cp === 0x200B || cp === 0x200E || cp === 0x200F || cp === 0x2060 || cp === 0xFEFF;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Raw bytes (or a JS string) to text, or null when it is not valid UTF-8. */
function toText(raw) {
    if (typeof raw === "string") {
        // A JS string that holds a lone surrogate cannot have come from
        // valid UTF-8 (rule 1).
        for (let i = 0; i < raw.length; i++) {
            const c = raw.charCodeAt(i);
            if (c >= 0xD800 && c <= 0xDBFF) {
                const next = raw.charCodeAt(i + 1);
                if (!(next >= 0xDC00 && next <= 0xDFFF)) return null;
                i++;
            } else if (c >= 0xDC00 && c <= 0xDFFF) {
                return null;
            }
        }
        return raw;
    }
    if (!(raw instanceof Uint8Array)) return null;
    try {
        return strictUtf8.decode(raw);
    } catch {
        return null;
    }
}

/**
 * DISPLAY_NAMES.md §3: raw bytes (or a string) to a display name, or null.
 *   1. invalid UTF-8 is null;
 *   2. every White_Space character becomes U+0020 (so U+0085 becomes a
 *      space before rule 3 could remove it as a C1 control);
 *   3. C0/C1 controls, DEL, bidi embeddings/overrides/isolates, U+200B,
 *      U+200E, U+200F, U+2060 and U+FEFF are removed;
 *   4. runs of spaces collapse to one, both ends are trimmed;
 *   5. cut to 64 scalars, then trailing U+0020 and U+200D are stripped
 *      (repeatedly, as LXMF-rust does);
 *   6. empty is null.
 */
export function clean(raw) {
    const text = toText(raw);
    if (text === null) return null;
    const out = [];
    let afterSpace = true; // leading spaces are trimmed as they arrive
    for (const ch of text) {
        let cp = ch.codePointAt(0);
        if (isWhiteSpace(cp)) cp = 0x20;
        if (isRemoved(cp)) continue;
        if (cp === 0x20) {
            if (afterSpace) continue;
            afterSpace = true;
        } else {
            afterSpace = false;
        }
        out.push(cp);
    }
    out.length = Math.min(out.length, MAX_SCALARS);
    while (out.length && (out[out.length - 1] === 0x20 || out[out.length - 1] === 0x200D)) out.pop();
    return out.length ? String.fromCodePoint(...out) : null;
}

/** §3, announce names only: clean(), and "Anonymous Peer" (ASCII case-insensitive) is null. */
export function cleanAnnounce(raw) {
    const name = clean(raw);
    if (name === null) return null;
    return name.toLowerCase() === ANONYMOUS_PEER.toLowerCase() ? null : name;
}

/** §4.1: the first 16 bytes of SHA-256 over the name's UTF-8, as hex. null hashes "". */
export function digestHex(name) {
    return Buffer.from(Cryptography.sha256(Buffer.from(name ?? "", "utf8"))).subarray(0, 16).toString("hex");
}

/** The digest of "no name": SHA-256("") cut to 16 bytes. A literal, not
 *  digestHex(null): this module is evaluated before app.js installs the
 *  global Buffer the browser's crypto shim hashes with, so nothing here may
 *  hash at load time. display_names.test.mjs checks it against the vectors. */
export const EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb924";

/**
 * What a 0xD1 value says (§3, last table). A plain object so it can be kept
 * on a stored record: { state: "absent" } | { state: "clear" } |
 * { state: "name", name }.
 */
export const ABSENT = Object.freeze({ state: "absent" });
export const CLEAR = Object.freeze({ state: "clear" });
export const nameState = (name) => ({ state: "name", name });

/** Decode one 0xD1 value. Only bin and str count (§2.1); a Map, array, int,
 *  nil or bool is absent — never "[object Map]".
 *
 *  A received value must be passed as its raw bytes (decodePayload,
 *  announceNameFromAppData): msgpackr has already rewritten a str holding
 *  invalid UTF-8 by the time it hands over a JS string — to U+FFFD under
 *  Node, to whatever its lax browser decoder makes of the bytes ("ÿ" for a
 *  lone 0xFF, "/" for the overlong C0 AF) — so rule 1 can no longer see it.
 *  A string here is for values this client made itself. */
export function decodeValue(value) {
    let raw;
    if (value instanceof Uint8Array) raw = value;
    else if (typeof value === "string") raw = value;
    else return ABSENT;
    if (raw.length === 0) return CLEAR;
    const name = clean(raw);
    return name === null ? ABSENT : nameState(name);
}

/** Decode 0xD1 from a decoded LXMF fields map. Anything but a Map is absent.
 *  The retired 0x10 is never read. Only for maps this client built: a
 *  received message is read with decodePayload, from its bytes. */
export function decodeField(fields) {
    if (!(fields instanceof Map)) return ABSENT;
    if (!fields.has(FIELD_DISPLAY_NAME)) return ABSENT;
    return decodeValue(fields.get(FIELD_DISPLAY_NAME));
}

// ── Raw msgpack reading ─────────────────────────────────────────────────────
// Just enough of msgpack to find a value in received bytes and hand back the
// raw bytes of a str or bin, which msgpackr cannot (see decodeValue).

/** The value at `pos`: { kind, end, raw?, count?, int? }. Throws on
 *  truncated input. kind is "str", "bin", "map", "array", "int" or "other";
 *  for map/array `end` is the end of the header and `count` its entries. */
function readHead(b, pos) {
    const need = (n) => { if (pos + n > b.length) throw new RangeError("truncated msgpack"); };
    need(1);
    const t = b[pos];
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const len = (size, at) => { need(at - pos + size); return size === 1 ? b[at] : size === 2 ? view.getUint16(at) : view.getUint32(at); };
    const bytes = (kind, start, n) => { need(start - pos + n); return { kind, end: start + n, raw: b.subarray(start, start + n) }; };
    const skip = (n) => { need(n); return { kind: "other", end: pos + n }; };
    if (t <= 0x7f) return { kind: "int", end: pos + 1, int: t };
    if (t <= 0x8f) return { kind: "map", end: pos + 1, count: t & 0x0f };
    if (t <= 0x9f) return { kind: "array", end: pos + 1, count: t & 0x0f };
    if (t <= 0xbf) return bytes("str", pos + 1, t & 0x1f);
    if (t >= 0xe0) return { kind: "int", end: pos + 1, int: t - 0x100 };
    switch (t) {
        case 0xc4: return bytes("bin", pos + 2, len(1, pos + 1));
        case 0xc5: return bytes("bin", pos + 3, len(2, pos + 1));
        case 0xc6: return bytes("bin", pos + 5, len(4, pos + 1));
        case 0xd9: return bytes("str", pos + 2, len(1, pos + 1));
        case 0xda: return bytes("str", pos + 3, len(2, pos + 1));
        case 0xdb: return bytes("str", pos + 5, len(4, pos + 1));
        case 0xc7: return skip(3 + len(1, pos + 1));
        case 0xc8: return skip(4 + len(2, pos + 1));
        case 0xc9: return skip(6 + len(4, pos + 1));
        case 0xcc: need(2); return { kind: "int", end: pos + 2, int: b[pos + 1] };
        case 0xcd: need(3); return { kind: "int", end: pos + 3, int: view.getUint16(pos + 1) };
        case 0xce: need(5); return { kind: "int", end: pos + 5, int: view.getUint32(pos + 1) };
        case 0xcf: need(9); return { kind: "int", end: pos + 9, int: Number(view.getBigUint64(pos + 1)) };
        case 0xd0: need(2); return { kind: "int", end: pos + 2, int: view.getInt8(pos + 1) };
        case 0xd1: need(3); return { kind: "int", end: pos + 3, int: view.getInt16(pos + 1) };
        case 0xd2: need(5); return { kind: "int", end: pos + 5, int: view.getInt32(pos + 1) };
        case 0xd3: need(9); return { kind: "int", end: pos + 9, int: Number(view.getBigInt64(pos + 1)) };
        case 0xdc: return { kind: "array", end: pos + 3, count: len(2, pos + 1) };
        case 0xdd: return { kind: "array", end: pos + 5, count: len(4, pos + 1) };
        case 0xde: return { kind: "map", end: pos + 3, count: len(2, pos + 1) };
        case 0xdf: return { kind: "map", end: pos + 5, count: len(4, pos + 1) };
        case 0xc0: case 0xc2: case 0xc3: return skip(1);
        case 0xca: return skip(5);
        case 0xcb: return skip(9);
        case 0xd4: return skip(3);
        case 0xd5: return skip(4);
        case 0xd6: return skip(6);
        case 0xd7: return skip(10);
        case 0xd8: return skip(18);
        default: throw new RangeError(`msgpack type 0x${t.toString(16)} is not valid`);
    }
}

/** The end of the whole value at `pos`, nested contents included. */
function skipValue(b, pos) {
    let pending = 1;
    while (pending > 0) {
        const h = readHead(b, pos);
        pending--;
        if (h.kind === "map") pending += 2 * h.count;
        else if (h.kind === "array") pending += h.count;
        pos = h.end;
    }
    return pos;
}

/** A str or bin value as a Uint8Array of its raw bytes; anything else null. */
const rawBytesOf = (h) => (h.kind === "str" || h.kind === "bin") ? h.raw : null;

/**
 * §2.1 / §3: the 0xD1 state of a received LXMF message, read from the raw
 * bytes of its packed payload [timestamp, title, content, fields, (stamp)],
 * so a str holding invalid UTF-8 is Absent (rule 1), as in LXMF-rust.
 * Absent when the payload has no fields map or cannot be read. If the map
 * repeats the key the first one counts, as in LXMF-rust decode_field.
 */
export function decodePayload(packedPayload) {
    if (!(packedPayload instanceof Uint8Array)) return ABSENT;
    try {
        const b = packedPayload;
        const top = readHead(b, 0);
        if (top.kind !== "array" || top.count < 4) return ABSENT;
        let pos = top.end;
        for (let i = 0; i < 3; i++) pos = skipValue(b, pos);
        const map = readHead(b, pos);
        if (map.kind !== "map") return ABSENT;
        pos = map.end;
        for (let i = 0; i < map.count; i++) {
            const key = readHead(b, pos);
            pos = skipValue(b, pos);
            if (key.kind === "int" && key.int === FIELD_DISPLAY_NAME) {
                const raw = rawBytesOf(readHead(b, pos));
                return raw === null ? ABSENT : decodeValue(raw);
            }
            pos = skipValue(b, pos);
        }
        return ABSENT;
    } catch {
        return ABSENT;
    }
}

/** The 0xD1 value a name state puts in a message (§2.1): nothing for absent,
 *  an empty bin for clear, the cleaned name as bin. Always a Buffer, never a
 *  JS string, which msgpack would send as str. */
export function fieldValue(state) {
    if (!state || state.state === "absent") return null;
    if (state.state === "clear") return Buffer.alloc(0);
    return Buffer.from(state.name, "utf8");
}

/** Put the name state into an outgoing fields map (no-op for absent). */
export function applyToFields(fields, state) {
    const value = fieldValue(state);
    if (value !== null) fields.set(FIELD_DISPLAY_NAME, value);
    return fields;
}

/**
 * §2.2 / §5.1: the announce name in lxmf.delivery app_data — the first
 * element of the 0.5.0+ list, or the whole of the original raw format —
 * cleaned with the announce rules. The first element is read as raw bytes
 * whether it is bin or str (see decodeValue: a msgpackr-decoded str would
 * hide invalid UTF-8).
 */
export function announceNameFromAppData(appData) {
    if (appData == null || appData.length === 0) return null;
    const b = Uint8Array.from(appData);
    const first = b[0];
    if ((first >= 0x90 && first <= 0x9f) || first === 0xdc || first === 0xdd) {
        try {
            skipValue(b, 0); // the whole list must read, as rmpv's read_value
            const top = readHead(b, 0);
            if (top.count === 0) return null;
            const raw = rawBytesOf(readHead(b, top.end));
            return raw === null ? null : cleanAnnounce(raw);
        } catch {
            return null;
        }
    }
    return cleanAnnounce(b);
}

/** §5.3: the first 8 hex characters and an ellipsis, on every surface. */
export function shortHash(hex) {
    return `${String(hex ?? "").slice(0, 8)}…`;
}

/** The three signature outcomes of an LXMF message (§5.2, §7). */
export const SIG_VALIDATED = "validated";
export const SIG_UNKNOWN = "unknown";
export const SIG_INVALID = "invalid";

/**
 * §5.2: the messageName a contact holds after a 0xD1 arrives.
 * Returns the new value (a string or null); equal to `current` when nothing
 * changes.
 *
 *   signature  | Name(s)                        | Clear
 *   validated  | s                              | null
 *   unknown    | s only if current is null      | ignored
 *   invalid    | ignored                        | ignored
 */
export function acceptMessageName(current, field, signature) {
    const now = current ?? null;
    if (!field || field.state === "absent") return now;
    if (signature === SIG_VALIDATED) return field.state === "name" ? field.name : null;
    if (signature === SIG_UNKNOWN) return (field.state === "name" && now === null) ? field.name : now;
    return now;
}

/** §5.3: contact label — localName ?? messageName ?? announceName ?? shortHash. */
export function contactName(contact, hash) {
    return contact?.localName ?? contact?.messageName ?? contact?.announceName ?? shortHash(hash ?? contact?.destHash);
}

/**
 * §5.3: channel post label — channelName ?? contact chain ?? shortHash.
 * When the label is the channel name, `secondary` is the 8-hex short hash
 * shown next to it: channel names are public and anyone can pick any name.
 */
export function channelPosterName(channelName, contact, hash) {
    if (channelName) return { label: channelName, secondary: shortHash(hash) };
    return { label: contactName(contact, hash), secondary: null };
}

/**
 * §4.1 decision for one outgoing message, from the name ledger row for
 * (source, recipient): { digest, confirmedAt } in seconds, or null.
 *   Name set:   include it unless the row holds this name's digest and is at
 *               most 30 days old (exactly 30 days is not older).
 *   Name unset: an empty 0xD1 only when the row records a real name.
 */
export function decide(messageName, row, nowSecs) {
    if (messageName) {
        const fresh = !!row && row.digest === digestHex(messageName) && nowSecs - row.confirmedAt <= NAME_REFRESH_SECS;
        return fresh ? ABSENT : nameState(messageName);
    }
    return (row && row.digest !== EMPTY_DIGEST) ? CLEAR : ABSENT;
}

/**
 * §4.2: whether a channel post carries the Channel Display Name.
 * `state` is that channel's { lastDigest, lastIncludedAt, lastNewSenderAt },
 * times in milliseconds, any of them absent before the first post:
 *   1. lastDigest differs from the current name's digest (first post, or
 *      the name changed);
 *   2. a sender not seen before in this channel has posted since
 *      lastIncludedAt;
 *   3. more than 24 hours have passed since lastIncludedAt.
 * With no name set, the post clears once if the last included name was real.
 */
export function decideChannelPost(channelName, state, nowMs) {
    const lastDigest = state?.lastDigest ?? null;
    const lastIncludedAt = state?.lastIncludedAt ?? 0;
    if (channelName) {
        if (lastDigest !== digestHex(channelName)) return nameState(channelName);
        if ((state?.lastNewSenderAt ?? 0) > lastIncludedAt) return nameState(channelName);
        if (nowMs - lastIncludedAt > CHANNEL_NAME_REFRESH_SECS * 1000) return nameState(channelName);
        return ABSENT;
    }
    return (lastDigest !== null && lastDigest !== EMPTY_DIGEST) ? CLEAR : ABSENT;
}

/** The digest a name state records (§4.1 / §4.2); null for absent. */
export function stateDigest(state) {
    if (!state || state.state === "absent") return null;
    return digestHex(state.state === "name" ? state.name : null);
}

/**
 * §5.4, the web client: one contact record from before the three name slots
 * to the new shape. `nameCustomized` → localName; otherwise messageName;
 * a "?hash" placeholder is dropped. Records already migrated are returned
 * unchanged. Returns a new object.
 */
export function migrateContact(c) {
    if (!c || typeof c !== "object") return c;
    if ("localName" in c || "messageName" in c || "announceName" in c) {
        const { displayName, nameCustomized, ...rest } = c;
        return rest;
    }
    const { displayName, nameCustomized, ...rest } = c;
    const placeholder = typeof displayName !== "string" || /^\?[0-9a-f]{0,32}$/i.test(displayName.trim());
    const kept = placeholder ? null : (clean(displayName) ?? null);
    return {
        ...rest,
        localName: nameCustomized ? kept : null,
        messageName: nameCustomized ? null : kept,
        announceName: null,
    };
}

/**
 * §5.4 settings: the old single display name becomes the Message Display
 * Name, except the "Retichat Web" placeholder and a node's config.json
 * default, which were pre-filled rather than typed.
 */
export function migrateOwnDisplayName(saved, configDefault) {
    if (typeof saved !== "string") return null;
    const name = clean(saved);
    if (name === null) return null;
    if (name === "Retichat Web") return null;
    if (configDefault && name === clean(configDefault)) return null;
    return name;
}
