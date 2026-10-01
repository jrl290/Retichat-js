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
import { readHead, skipValue } from "./rns/msgpack_raw.js";
import {
    FIELD_RETICHAT, RF_DISPLAY_NAME, retichatMap, readEntry, setEntry, removeEntry,
} from "./retichat_field.js";

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

/** Decode the name, key 0 of the Retichat field 0xD1 (§2.1), from a decoded
 *  LXMF fields map. Anything but a Map is absent, and so is a 0xD1 that is
 *  not a map (it is ignored whole). The retired 0x10 is never read. Only for
 *  maps this client built: a received message is read with decodePayload,
 *  from its bytes. */
export function decodeField(fields) {
    if (!retichatMap(fields)) return ABSENT;
    return decodeValue(readEntry(fields, RF_DISPLAY_NAME));
}

// ── Raw msgpack reading ─────────────────────────────────────────────────────
// A received name is read from the bytes (msgpack_raw.js), because msgpackr
// cannot hand back the raw bytes of a str (see decodeValue).

/** A str or bin value as a Uint8Array of its raw bytes; anything else null. */
const rawBytesOf = (h) => (h.kind === "str" || h.kind === "bin") ? h.raw : null;

/** The raw bytes of the value of the first entry of the map whose header is
 *  at `pos` with integer key `target` (any width; str and negative keys
 *  never match), as the head of that value, or null when there is none. */
function findInMap(b, pos, target) {
    const map = readHead(b, pos);
    if (map.kind !== "map") return null;
    pos = map.end;
    for (let i = 0; i < map.count; i++) {
        const key = readHead(b, pos);
        pos = skipValue(b, pos);
        if (key.kind === "int" && key.int === target) return { pos, head: readHead(b, pos) };
        pos = skipValue(b, pos);
    }
    return null;
}

/**
 * §2.1 / §3: the name state of a received LXMF message — key 0 of the
 * Retichat field 0xD1 — read from the raw bytes of its packed payload
 * [timestamp, title, content, fields, (stamp)], so a str holding invalid
 * UTF-8 is Absent (rule 1), as in LXMF-rust. Absent when the payload has no
 * fields map or cannot be read, when 0xD1 is not a map (it is ignored whole:
 * a bin or str at 0xD1 is not a name) or holds no key 0. If a map repeats a
 * key the first one counts, as in LXMF-rust decode_field.
 */
export function decodePayload(packedPayload) {
    if (!(packedPayload instanceof Uint8Array)) return ABSENT;
    try {
        const b = packedPayload;
        const top = readHead(b, 0);
        if (top.kind !== "array" || top.count < 4) return ABSENT;
        let pos = top.end;
        for (let i = 0; i < 3; i++) pos = skipValue(b, pos);
        const field = findInMap(b, pos, FIELD_RETICHAT);
        if (!field || field.head.kind !== "map") return ABSENT;
        const name = findInMap(b, field.pos, RF_DISPLAY_NAME);
        if (!name) return ABSENT;
        const raw = rawBytesOf(name.head);
        return raw === null ? ABSENT : decodeValue(raw);
    } catch {
        return ABSENT;
    }
}

/** The key-0 value a name state puts in the Retichat field (§2.1): nothing
 *  for absent, an empty bin for clear, the cleaned name as bin. Always a
 *  Buffer, never a JS string, which msgpack would send as str. */
export function fieldValue(state) {
    if (!state || state.state === "absent") return null;
    if (state.state === "clear") return Buffer.alloc(0);
    return Buffer.from(state.name, "utf8");
}

/** Put the name state into an outgoing fields map, as LXMF-rust
 *  name_ledger prepare_outbound: key 0 of the Retichat field 0xD1 is set
 *  (merged beside any other entries, the map kept in key order) or, for
 *  absent, removed — and a map left empty is dropped, so a message with no
 *  Retichat entries carries no 0xD1. Only key 0 is touched. */
export function applyToFields(fields, state) {
    const value = fieldValue(state);
    if (value === null) return removeEntry(fields, RF_DISPLAY_NAME);
    return setEntry(fields, RF_DISPLAY_NAME, value);
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
 * §5.2, the signature table alone: whether a received 0xD1 is accepted and
 * the messageName it gives. { accept: false } when it is ignored.
 *
 *   signature  | Name(s)                        | Clear
 *   validated  | s                              | null
 *   unknown    | s only if current is null      | ignored
 *   invalid    | ignored                        | ignored
 *
 * Accepting a repeat of the current name is still an accept: the caller
 * records the message's timestamp (§5.2, order).
 */
export function messageNameVerdict(current, field, signature) {
    const now = current ?? null;
    if (!field || field.state === "absent") return { accept: false };
    if (signature === SIG_VALIDATED) return { accept: true, name: field.state === "name" ? field.name : null };
    if (signature === SIG_UNKNOWN && field.state === "name" && now === null) return { accept: true, name: field.name };
    return { accept: false };
}

/**
 * §5.2: the messageName a contact holds after a 0xD1 arrives, by the
 * signature table alone (no ordering). Returns the new value (a string or
 * null); equal to `current` when nothing changes.
 */
export function acceptMessageName(current, field, signature) {
    const verdict = messageNameVerdict(current, field, signature);
    return verdict.accept ? verdict.name : (current ?? null);
}

/**
 * §5.1 / §5.2: a received 0xD1 applied to a contact's name slots
 * { messageName, messageNameAt, legacyName }, with the order rule: a Name or
 * Clear is accepted only from a message whose LXMF timestamp (seconds) is
 * newer than messageNameAt, and accepting a validated one records that
 * timestamp, a repeat of the current name included (a source-unknown fill
 * leaves it as it was). An accepted 0xD1 drops legacyName.
 *
 * Returns the new slots, or null when the 0xD1 is not accepted (nothing
 * changes, the timestamp included). A timestamp that is not a finite number
 * cannot be ordered and is never accepted.
 */
export function acceptMessageNameAt(slots, field, signature, timestamp) {
    if (!field || field.state === "absent") return null;
    const ts = Number(timestamp);
    if (timestamp == null || !Number.isFinite(ts)) return null;
    const at = slots?.messageNameAt;
    if (at != null && Number.isFinite(at) && !(ts > at)) return null;
    const verdict = messageNameVerdict(slots?.messageName ?? null, field, signature);
    if (!verdict.accept) return null;
    // Only a validated message records its time. A source-unknown name only
    // fills an empty slot: its timestamp is the sender's unverifiable claim,
    // and recording it would let a forged far-future message lock out every
    // later validated name from the real sender (as iOS c720698, Android 16765e6).
    const recordsTime = signature === SIG_VALIDATED;
    return { messageName: verdict.name, messageNameAt: recordsTime ? ts : (at ?? null), legacyName: null };
}

/**
 * §5.2 channel names, per (channel, sender): an older post (history pulled
 * late) never undoes the name set or cleared by a newer one. `entry` is the
 * stored { name, at } (post time in ms) or null. Only a post strictly newer
 * than `at` sets or clears the name and records its time; one at the same
 * time is ignored, as Android acceptChannelName (`postAt <= currentAt` is
 * Unchanged) and iOS DisplayNames.isNewer (`messageTime > heldAt`) do. A
 * newer post repeating the name or the clear still advances `at`. Returns
 * the new entry, or null when ignored.
 */
export function acceptChannelName(entry, field, postAtMs) {
    if (!field || field.state === "absent") return null;
    const ts = Number(postAtMs);
    if (postAtMs == null || !Number.isFinite(ts)) return null;
    const at = entry?.at;
    if (at != null && Number.isFinite(at) && ts <= at) return null;
    return { name: field.state === "name" ? field.name : null, at: ts };
}

/** §5.3: contact label — localName ?? messageName ?? announceName ?? legacyName ?? shortHash. */
export function contactName(contact, hash) {
    return contact?.localName ?? contact?.messageName ?? contact?.announceName ?? contact?.legacyName
        ?? shortHash(hash ?? contact?.destHash);
}

/**
 * §5.3: channel post label — a main label and an optional secondary (grey)
 * text. Channel names are public and anyone can pick any name, so a channel
 * name never stands alone:
 *
 *   The poster has              | label        | secondary
 *   a channelName and localName | localName    | channelName
 *   a channelName, no localName | channelName  | shortHash
 *   no channelName              | contact chain| none
 *
 * `secondaryKind` says which the secondary text is ("channel", "hash" or
 * null), so the bubble can set a hash in monospace and a name in text.
 * Notifications for channel posts name the poster the same way, main label
 * then secondary text ("Mum · Night Owl", "Night Owl · 1a2b3c4d…"), so a
 * channel name never stands alone there either (§5.3, LXMF-rust 84ac13a;
 * iOS DisplayNames.channelNotificationTitle, Android RfedChannelClient
 * notificationSenderName). The web shows no notifications today; one
 * added later takes `label · secondary`.
 */
export function channelPosterName(channelName, contact, hash) {
    if (channelName && contact?.localName) {
        return { label: contact.localName, secondary: channelName, secondaryKind: "channel" };
    }
    if (channelName) return { label: channelName, secondary: shortHash(hash), secondaryKind: "hash" };
    return { label: contactName(contact, hash), secondary: null, secondaryKind: null };
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

/** §5.4: a hash form, 8 to 32 hex with or without "?" before or "…" after. */
function isHashForm(name) {
    return /^\??[0-9a-f]{8,32}\u2026?$/i.test(name.trim());
}

/**
 * §5.4 "never lose a name the user typed": the one customized value the old
 * web build wrote without the user typing it. Its rename field was
 * pre-filled with "?" + the contact's first 8 hex, and Save marked that
 * customized. So a customized hash form is dropped only when its hex is a
 * prefix of this contact's own hash; any other value, "deadbeef" or
 * "?cafebabe" typed for someone else included, is the user's.
 */
function isOwnHashPrefill(name, destHash) {
    if (!isHashForm(name) || typeof destHash !== "string") return false;
    const hex = name.trim().replace(/^\?/, "").replace(/\u2026$/, "").toLowerCase();
    return destHash.toLowerCase().startsWith(hex);
}

/**
 * §5.4: the names that were never typed and are dropped wherever they were
 * not: hash forms (8 to 32 hex, with or without a leading "?" or a trailing
 * "…"), "Retichat", "Retichat Web" and "Anonymous Peer", all
 * case-insensitive. Unnamed Android and web senders used to send the first
 * two as names; MeshChatX, Columba and lxmd announce the third.
 */
export function isPlaceholderName(name) {
    if (typeof name !== "string") return false;
    const v = name.trim();
    if (isHashForm(v)) return true;
    const lower = v.toLowerCase();
    return lower === "retichat" || lower === "retichat web" || lower === ANONYMOUS_PEER.toLowerCase();
}

/**
 * §5.4, the web client: one contact record to the current shape.
 *   - Before the three name slots (displayName + nameCustomized):
 *     nameCustomized → localName (a hash form, which the old rename field
 *     was pre-filled with, is dropped); otherwise legacyName, unless a
 *     placeholder.
 *   - Rows from the first three-slot build (no legacyName key) put migrated
 *     names in messageName, where they would outrank a newer announce name
 *     for good: that messageName moves to legacyName, unless a placeholder.
 *     It carries no messageNameAt, so it cannot be told from one received
 *     then; as a legacyName it still shows, until the next 0xD1 or named
 *     announce replaces it.
 * Records already in the current shape are returned unchanged but for the
 * dropped legacy keys. Returns a new object.
 */
export function migrateContact(c) {
    if (!c || typeof c !== "object") return c;
    const { displayName, nameCustomized, ...rest } = c;
    if ("localName" in c || "messageName" in c || "announceName" in c) {
        if ("legacyName" in c) return rest;
        const old = typeof rest.messageName === "string" ? clean(rest.messageName) : null;
        return {
            ...rest,
            messageName: null,
            messageNameAt: null,
            legacyName: old !== null && !isPlaceholderName(old) ? old : null,
        };
    }
    const name = typeof displayName === "string" ? clean(displayName) : null;
    return {
        ...rest,
        localName: nameCustomized && name !== null && !isOwnHashPrefill(name, rest.destHash) ? name : null,
        messageName: null,
        messageNameAt: null,
        announceName: null,
        legacyName: !nameCustomized && name !== null && !isPlaceholderName(name) ? name : null,
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
