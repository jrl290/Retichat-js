/**
 * A msgpack map that repeats a key, judged as Python LXMF judges it (RFed
 * SPEC §17.14 "Repeated keys"; James's ruling of 2026-10-11: parity).
 *
 * LXMF 1.1.1 reads a message with RNS's vendored umsgpack, whose map reader
 * raises DuplicateKeyException when a key is already in the dict it is
 * building, in any map at any depth; LXMRouter drops the message whole.
 * refuseRepeatedKeys does the same here, on the payload's bytes, for every
 * LXMF payload this client reads: LXMessage.decodePayload (the direct path,
 * the propagated messages, and the distro path, app.js _handleDistroBlob)
 * and a channel post (rfed_channel.js channelLxmUnpack), before any field is
 * read. No reader of the group entries, a group sync or a membership message
 * ever sees such a map. LXMF-rust (src/msgpack_keys.rs, 16a9902) does the
 * same for the phones.
 *
 * msgpackr cannot be asked: it keeps the last of a repeated key, and a JS
 * Map compares keys by SameValueZero, which is not Python's equality. So the
 * bytes are walked (one linear pass, in the order umsgpack reads them, so
 * the repeat named is the one Python raises on), and two keys of one map are
 * one key when Python says so:
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
 * check). A map key umsgpack refuses for another reason
 * (UnhashableKeyException), which this rule does not cover. The key_equality
 * and refused vectors of distro_group_sync_vectors.json, checked against the
 * reference, pin each case.
 */

import { Buffer } from "buffer";

/** The start of every refusal's text (isRefusal). */
export const REFUSED_WHOLE = "refused whole:";

/** A payload refused whole: already said once (refuseRepeatedKeys), so a
 *  caller that logs its own failures does not say it again. */
export class RefusedPayload extends Error {
    constructor(why) {
        super(why);
        this.name = "RefusedPayload";
        this.refused = true;
    }
}

/** Whether `error` is a refusal refuseRepeatedKeys has said already. */
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

/**
 * The first map in the msgpack value at the start of `bytes`, at any depth
 * (keys included), that repeats a key as Python's umsgpack judges it, in the
 * order umsgpack reads the value: { depth, key }, depth 0 for the value
 * itself (the payload), 1 for the fields map, 2 for the Retichat field's map;
 * `key` names the repeated key for the log. null when no map repeats a key.
 * Bytes it cannot walk (cut short, an invalid type byte) end the walk: a
 * repeat before them is still found, and what follows is left to the decode,
 * which fails on them as it did.
 */
export function repeatedKey(bytes) {
    const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes ?? []);
    const open = []; // the containers being read: { left, map, keyNext, seen, depth }
    let pos = 0;
    try {
        do {
            const item = readItem(b, pos);
            const parent = open.at(-1);
            if (parent) {
                if (parent.map && parent.keyNext && item.kind === "scalar" && item.key !== null) {
                    if (parent.seen.has(item.key)) return { depth: parent.depth, key: item.label };
                    parent.seen.add(item.key);
                }
                parent.left--;
                if (parent.map) parent.keyNext = !parent.keyNext;
            }
            pos = item.end;
            const depth = parent ? parent.depth + 1 : 0;
            if (item.kind === "map" && item.count > 0) open.push({ left: 2 * item.count, map: true, keyNext: true, seen: new Set(), depth });
            else if (item.kind === "array" && item.count > 0) open.push({ left: item.count, map: false, depth });
            while (open.length && open.at(-1).left === 0) open.pop();
        } while (open.length);
    } catch {
        return null;
    }
    return null;
}

/**
 * Refuse a payload that repeats a key: throws RefusedPayload, having logged
 * the one line that says so, "[LXMF] <what> refused whole: a map at depth N
 * repeats a key (K), as Python LXMF refuses it ...". `what` names the message
 * (e.g. "LXMF message from <source>"). Returns nothing when no map repeats a
 * key.
 */
export function refuseRepeatedKeys(bytes, what) {
    const repeat = repeatedKey(bytes);
    if (!repeat) return;
    const why = `${REFUSED_WHOLE} a map at depth ${repeat.depth} repeats a key (${repeat.key}), as Python LXMF refuses it (umsgpack DuplicateKeyException; RFed SPEC §17.14 "Repeated keys")`;
    console.log(`[LXMF] ${what} ${why}`);
    throw new RefusedPayload(why);
}
