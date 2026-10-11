/**
 * A payload Python LXMF refuses whole for its msgpack, judged as Python LXMF
 * judges it (RFed SPEC §17.14 "Repeated keys", James's ruling of 2026-10-11:
 * parity; "Unhashable keys" and "Nesting", decided 2026-10-11).
 *
 * LXMF 1.1.1 reads a message with RNS's vendored umsgpack, and
 * LXMessage.unpack_from_bytes lets any of its errors through, so LXMRouter
 * drops the message whole. Three of them are about a payload's shape, in any
 * map or array at any depth:
 * - a map that repeats a key (DuplicateKeyException);
 * - a map whose key is a map, or an array that holds a map at any depth
 *   (UnhashableKeyException: umsgpack turns an array key into a tuple, which
 *   Python cannot hash when it holds a dict);
 * - a payload nested deeper than umsgpack's recursion reaches on the
 *   delivery path (RecursionError): NESTING_MAX_DEPTH.
 * refuseAsPython does the same here, on the payload's bytes, for every LXMF
 * payload this client reads: LXMessage.decodePayload (the direct path, the
 * propagated messages, a `status`'s elements, and the distro path, app.js
 * _handleDistroBlob) and a channel post (rfed_channel.js channelLxmUnpack),
 * before any field is read. No reader of the group entries, a group sync or
 * a membership message ever sees such a payload. LXMF-rust
 * (src/msgpack_keys.rs, b873c00) does the same for the phones.
 *
 * msgpackr cannot be asked: it keeps the last of a repeated key, takes a map
 * or an array as a key, recurses as deep as the bytes go, and a JS Map
 * compares keys by SameValueZero, which is not Python's equality. So the
 * bytes are walked, in one linear pass and without recursion, in the order
 * umsgpack reads them, so the reason given is the first umsgpack meets: a
 * key is read whole before it is judged, a map key is refused before its
 * value is read, and an array key's value is read before the key is hashed.
 * Two keys of one map are one key when Python says so:
 * - integers, floats and booleans of one numeric value, whatever the
 *   encoding: 1, 0xcc 0x01, 1.0 (float 32 or 64) and true are one key, 0 and
 *   -0.0 too; compared exactly (2^64 − 1 is not the float 2^64); NaN is no
 *   key's equal, not even NaN's;
 * - str of the same code points (by their bytes, never normalised), bin of
 *   the same bytes; a str is never a bin;
 * - nil and nil;
 * - ext of the same type and data, a timestamp (ext −1) by its instant to the
 *   microsecond, as Python's datetime compares it.
 * An array key is never compared (umsgpack makes it a tuple and skips the
 * check), and is read when it holds no map. The refused, key_equality and
 * nesting vectors of distro_group_sync_vectors.json, checked against the
 * reference, pin each case.
 */

import { Buffer } from "buffer";

/** The start of every refusal's text (isRefusal). */
export const REFUSED_WHOLE = "refused whole:";

/** A payload refused whole: already said once (refuseAsPython), so a
 *  caller that logs its own failures does not say it again. */
export class RefusedPayload extends Error {
    constructor(why, reason = null) {
        super(why);
        this.name = "RefusedPayload";
        this.refused = true;
        /** "repeated_key", "unhashable_key" or "too_deep" (refusal). */
        this.reason = reason;
    }
}

/** Whether `error` is a refusal refuseAsPython has said already. */
export function isRefusal(error) {
    return error instanceof RefusedPayload || error?.refused === true;
}

const hex = (bytes) => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("hex");
const lossyUtf8 = new TextDecoder("utf-8");

/** A float's key: by its exact value when it is integral (so 1.0 is 1 and
 *  -0.0 is 0, and 2^64 is not 2^64 − 1), else by the value itself (a double
 *  prints uniquely); null for NaN, which equals nothing. */
function floatKey(f) {
    if (Number.isNaN(f)) return null;
    return Number.isInteger(f) ? `n:${BigInt(f)}` : `f:${f}`;
}

/** The instant of a timestamp ext's data, in microseconds since the epoch,
 *  as umsgpack makes it (nanoseconds floored to microseconds); null for a
 *  length it refuses (another refusal than this one). */
function timestampMicros(data) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let seconds, nanoseconds;
    if (data.length === 4) {
        seconds = BigInt(view.getUint32(0));
        nanoseconds = 0n;
    } else if (data.length === 8) {
        const value = view.getBigUint64(0);
        seconds = value & 0x3ffffffffn;
        nanoseconds = value >> 34n;
    } else if (data.length === 12) {
        nanoseconds = BigInt(view.getUint32(0));
        seconds = view.getBigInt64(4);
    } else {
        return null;
    }
    return seconds * 1000000n + nanoseconds / 1000n;
}

/**
 * The value at `pos`: { kind, end, count?, key?, label? }. kind is "map",
 * "array" or "scalar"; for a map or array `end` is the end of its header and
 * `count` its entries. A scalar's `key` is how Python compares it as a map
 * key (null: never equal to anything), `label` how the log names it.
 * Throws on truncated input or an invalid type byte.
 */
function readItem(b, pos) {
    const need = (n) => { if (pos + n > b.length) throw new RangeError("truncated msgpack"); };
    need(1);
    const t = b[pos];
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const int = (value, size) => ({ kind: "scalar", end: pos + size, key: `n:${value}`, label: String(value) });
    const lenAt = (size) => { need(1 + size); return size === 1 ? b[pos + 1] : size === 2 ? view.getUint16(pos + 1) : view.getUint32(pos + 1); };
    const bytes = (kind, start, n) => {
        need(start - pos + n);
        const raw = b.subarray(start, start + n);
        const label = kind === "s"
            ? JSON.stringify(lossyUtf8.decode(raw).slice(0, 48))
            : `bin ${hex(raw.subarray(0, 24))}${raw.length > 24 ? "..." : ""}`;
        return { kind: "scalar", end: start + n, key: `${kind}:${hex(raw)}`, label };
    };
    const ext = (start, n) => {
        need(start - pos + 1 + n);
        const type = view.getInt8(start);
        const data = b.subarray(start + 1, start + 1 + n);
        const micros = type === -1 ? timestampMicros(data) : null;
        return {
            kind: "scalar", end: start + 1 + n,
            key: micros !== null ? `t:${micros}` : `e:${type}:${hex(data)}`,
            label: `ext ${type} ${hex(data.subarray(0, 24))}${data.length > 24 ? "..." : ""}`,
        };
    };
    const float = (f, size) => ({ kind: "scalar", end: pos + size, key: floatKey(f), label: Object.is(f, -0) ? "-0.0" : String(f) });
    if (t <= 0x7f) return int(t, 1);
    if (t <= 0x8f) return { kind: "map", end: pos + 1, count: t & 0x0f };
    if (t <= 0x9f) return { kind: "array", end: pos + 1, count: t & 0x0f };
    if (t <= 0xbf) return bytes("s", pos + 1, t & 0x1f);
    if (t >= 0xe0) return int(t - 0x100, 1);
    switch (t) {
        case 0xc0: return { kind: "scalar", end: pos + 1, key: "nil", label: "nil" };
        case 0xc2: return { kind: "scalar", end: pos + 1, key: "n:0", label: "false" };
        case 0xc3: return { kind: "scalar", end: pos + 1, key: "n:1", label: "true" };
        case 0xc4: return bytes("b", pos + 2, lenAt(1));
        case 0xc5: return bytes("b", pos + 3, lenAt(2));
        case 0xc6: return bytes("b", pos + 5, lenAt(4));
        case 0xc7: return ext(pos + 2, lenAt(1));
        case 0xc8: return ext(pos + 3, lenAt(2));
        case 0xc9: return ext(pos + 5, lenAt(4));
        case 0xca: need(5); return float(view.getFloat32(pos + 1), 5);
        case 0xcb: need(9); return float(view.getFloat64(pos + 1), 9);
        case 0xcc: need(2); return int(b[pos + 1], 2);
        case 0xcd: need(3); return int(view.getUint16(pos + 1), 3);
        case 0xce: need(5); return int(view.getUint32(pos + 1), 5);
        case 0xcf: need(9); return int(view.getBigUint64(pos + 1), 9);
        case 0xd0: need(2); return int(view.getInt8(pos + 1), 2);
        case 0xd1: need(3); return int(view.getInt16(pos + 1), 3);
        case 0xd2: need(5); return int(view.getInt32(pos + 1), 5);
        case 0xd3: need(9); return int(view.getBigInt64(pos + 1), 9);
        case 0xd4: return ext(pos + 1, 1);
        case 0xd5: return ext(pos + 1, 2);
        case 0xd6: return ext(pos + 1, 4);
        case 0xd7: return ext(pos + 1, 8);
        case 0xd8: return ext(pos + 1, 16);
        case 0xd9: return bytes("s", pos + 2, lenAt(1));
        case 0xda: return bytes("s", pos + 3, lenAt(2));
        case 0xdb: return bytes("s", pos + 5, lenAt(4));
        case 0xdc: return { kind: "array", end: pos + 3, count: lenAt(2) };
        case 0xdd: return { kind: "array", end: pos + 5, count: lenAt(4) };
        case 0xde: return { kind: "map", end: pos + 3, count: lenAt(2) };
        case 0xdf: return { kind: "map", end: pos + 5, count: lenAt(4) };
        default: throw new RangeError(`msgpack type 0x${t.toString(16)} is not valid`);
    }
}

/** RFed SPEC §17.14 "Nesting" (decided 2026-10-11: one limit, Python's
 *  measured delivery-path depth): no value of a payload may be deeper than
 *  this, the payload itself at depth 0, its fields map at 1, a field's value
 *  at 2, and anything in an array or a map (a key too) one deeper than it.
 *  So a field holds at most 492 nested arrays or maps whose innermost is
 *  empty, or 491 whose innermost holds anything. That is where Python LXMF
 *  1.1.1 (RNS 1.5.2's umsgpack, CPython 3.13, recursion limit 1000) refuses a
 *  propagated message on its delivery path, measured end to end by LXMF-rust
 *  tests/delivery_nesting_probe.py; LXMF-rust msgpack_keys.rs
 *  NESTING_MAX_DEPTH. One limit for every client. */
export const NESTING_MAX_DEPTH = 493;

/** A container's bytes, `b[start, end)`, for the log: its kind and hex, cut. */
function containerLabel(b, kind, start, end) {
    const bytes = b.subarray(start, end);
    return `${kind} ${hex(bytes.subarray(0, 24))}${bytes.length > 24 ? "..." : ""}`;
}

/**
 * The first reason Python LXMF refuses the msgpack value at the start of
 * `bytes` (a payload, at depth 0) whole, in the order umsgpack reads its
 * bytes, or null when it reads it:
 * - { reason: "repeated_key", depth, key }: a map at `depth` (its own: the
 *   payload 0, the fields map 1, the Retichat field's map 2) repeats a key;
 * - { reason: "unhashable_key", depth, key }: a map at `depth` has a key that
 *   is a map, or an array holding a map at any depth;
 * - { reason: "too_deep", depth }: a value at `depth`, past NESTING_MAX_DEPTH.
 * `key` names the key for the log. Bytes it cannot walk (cut short, an
 * invalid type byte) end the walk: a refusal before them is still found, and
 * what follows is left to the decode, which fails on them as it did. It
 * never recurses and stops at the first refusal, so a payload nested far
 * past the limit costs NESTING_MAX_DEPTH steps.
 */
export function refusal(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes ?? []);
    // The containers being read: { kind, map, left, keyNext, seen, depth,
    // start, holdsMap (a map was met inside it), arrayKey (the array key
    // whose value is being read) }.
    const open = [];
    let pos = 0;
    // Item `done` has been read whole, in container `p`: its key judged, or
    // the array key before it hashed. A refusal, or null.
    const complete = (p, done) => {
        p.left--;
        if (!p.map) return null;
        if (p.keyNext) {
            p.keyNext = false;
            // A map is no key: refused before its value is read.
            if (done.kind === "map") return { reason: "unhashable_key", depth: p.depth, key: done.label };
            // An array key is never compared; its value is read, then the key
            // is hashed, which fails when it holds a map.
            if (done.kind === "array") { p.arrayKey = done; return null; }
            if (done.key !== null) {
                if (p.seen.has(done.key)) return { reason: "repeated_key", depth: p.depth, key: done.label };
                p.seen.add(done.key);
            }
            return null;
        }
        p.keyNext = true;
        const arrayKey = p.arrayKey;
        p.arrayKey = null;
        return arrayKey?.holdsMap ? { reason: "unhashable_key", depth: p.depth, key: arrayKey.label } : null;
    };
    try {
        do {
            const start = pos;
            const item = readItem(b, pos);
            pos = item.end;
            const depth = open.length ? open.at(-1).depth + 1 : 0;
            if (depth > NESTING_MAX_DEPTH) return { reason: "too_deep", depth };
            if (item.kind === "map") for (const container of open) container.holdsMap = true;
            if (item.kind !== "scalar" && item.count > 0) {
                const map = item.kind === "map";
                open.push({ kind: item.kind, map, left: map ? 2 * item.count : item.count, keyNext: true,
                    seen: map ? new Set() : null, depth, start, holdsMap: false, arrayKey: null });
                continue;
            }
            // Read whole: a scalar, or an empty map or array; and with it
            // every container it was the last item of.
            let done = item.kind === "scalar"
                ? { kind: "scalar", key: item.key, label: item.label, holdsMap: false }
                : { kind: item.kind, label: containerLabel(b, item.kind, start, pos), holdsMap: false };
            while (open.length) {
                const p = open.at(-1);
                const refused = complete(p, done);
                if (refused) return refused;
                if (p.left > 0) break;
                open.pop();
                done = { kind: p.kind, label: containerLabel(b, p.kind, p.start, pos), holdsMap: p.holdsMap };
            }
        } while (open.length);
    } catch {
        return null;
    }
    return null;
}

/** What each reason says, and the reference's exception and the rule of
 *  RFed SPEC §17.14 that follows it (LXMF-rust msgpack_keys.rs Refusal). */
const REASONS = {
    repeated_key: { says: (r) => `a map at depth ${r.depth} repeats a key (${r.key})`,
        source: 'umsgpack DuplicateKeyException; RFed SPEC §17.14 "Repeated keys"' },
    unhashable_key: { says: (r) => `a map at depth ${r.depth} has a key Python cannot hash (${r.key})`,
        source: 'umsgpack UnhashableKeyException; RFed SPEC §17.14 "Unhashable keys"' },
    too_deep: { says: (r) => `a value at depth ${r.depth} is nested past depth ${NESTING_MAX_DEPTH}`,
        source: 'RecursionError on its delivery path; RFed SPEC §17.14 "Nesting"' },
};

/**
 * Refuse a payload Python LXMF refuses whole (refusal): throws RefusedPayload
 * (its `reason` the refusal's), having logged the one line that says so,
 * "[LXMF] <what> refused whole: <why>, as Python LXMF refuses it (<source>)",
 * as LXMF-rust logs it. `what` names the message (e.g. "LXMF message from
 * <source>"). Returns nothing when Python reads it.
 */
export function refuseAsPython(bytes, what) {
    const refused = refusal(bytes);
    if (!refused) return;
    const reason = REASONS[refused.reason];
    const why = `${REFUSED_WHOLE} ${reason.says(refused)}, as Python LXMF refuses it (${reason.source})`;
    console.log(`[LXMF] ${what} ${why}`);
    throw new RefusedPayload(why, refused.reason);
}
