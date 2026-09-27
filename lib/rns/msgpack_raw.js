/**
 * Just enough msgpack to walk received bytes without decoding them.
 *
 * msgpackr decodes, and decoding loses what the sender sent: a str holding
 * invalid UTF-8 comes back rewritten, a float that happens to be integral
 * comes back as a plain number that re-packs as an int, a uint64 re-packs as
 * an int64. Where the exact bytes matter — a display name that must be
 * cleaned from its bytes (DISPLAY_NAMES.md §3), the payload a signature was
 * made over — they are read with these instead.
 */

/** The value at `pos`: { kind, end, raw?, count?, int? }. Throws on
 *  truncated input. kind is "str", "bin", "map", "array", "int" or "other";
 *  for map/array `end` is the end of the header and `count` its entries. */
export function readHead(b, pos) {
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
export function skipValue(b, pos) {
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

/**
 * The msgpack bytes of the list made of the first `count` elements of the
 * packed list `packed`, copied byte for byte, or null when `packed` is not a
 * list longer than `count`. A sender that packs [a, b, c, d] and later
 * [a, b, c, d, stamp] writes the same bytes for a..d both times, so this is
 * exactly what it signed — whatever packer it used.
 */
export function listPrefix(packed, count) {
    if (count > 15) throw new RangeError("listPrefix writes a fixarray header");
    const b = packed instanceof Uint8Array ? packed : Uint8Array.from(packed);
    const top = readHead(b, 0);
    if (top.kind !== "array" || top.count <= count) return null;
    let end = top.end;
    for (let i = 0; i < count; i++) end = skipValue(b, end);
    const out = new Uint8Array(1 + end - top.end);
    out[0] = 0x90 | count;
    out.set(b.subarray(top.end, end), 1);
    return out;
}
