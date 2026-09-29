import { Packr } from "msgpackr";
import { readHead } from "./msgpack_raw.js";

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/**
 * `data`, with every str whose bytes are not valid UTF-8 — map keys and
 * nested values included — replaced by an empty str. The same bytes are
 * returned, uncopied, when there is none.
 *
 * Why (2026-09-29): the browser build of msgpackr (the importmap's esm.sh
 * bundle, and Node too without msgpackr-extract) decodes str with its own
 * loop, readStringJS, for strings of 16-64 bytes and for shorter ones
 * holding any non-ASCII byte. In 1.11.2 that loop never checks the string's
 * end, so a truncated multi-byte sequence reads the next value's bytes as
 * continuation bytes: the rest of the payload is parsed from the wrong
 * offset, and an LXMF payload either fails to parse or, worse, parses with
 * different fields than every other client sees. It also turns a lone 0xFF
 * into "ÿ" and the overlong C0 AF into "/". 1.11.14 still reads past the
 * end; 2.1.0 bounds it but keeps the text with U+FFFD. No option turns the
 * loop off.
 *
 * Found from the raw bytes (msgpack_raw.js), the str's length always bounds
 * it, and emptying it keeps every count and offset of the value intact. An
 * invalid str reads as empty, as in LXMF-rust, which the Retichat clients
 * this one talks to run: lx_message value_to_binary makes such a title or
 * content empty, and DISPLAY_NAMES.md §3 rule 1 makes such a name absent
 * (display_name.js reads names from the raw bytes itself). The Python
 * reference instead rejects the whole message (umsgpack
 * InvalidStringException). Signatures are checked over the received bytes,
 * never over what this returns.
 *
 * A value it cannot walk (truncated, an invalid type byte) is returned as
 * is, so msgpackr's own handling of malformed input is unchanged.
 */
export function emptyInvalidStrs(data) {
    const b = data instanceof Uint8Array ? data : new Uint8Array(data);
    const invalid = []; // [start, end) of each invalid str value, header included
    let pos = 0;
    let pending = 1;
    while (pending > 0) {
        let h;
        try {
            h = readHead(b, pos);
        } catch {
            return data;
        }
        pending--;
        if (h.kind === "map") pending += 2 * h.count;
        else if (h.kind === "array") pending += h.count;
        else if (h.kind === "str" && h.raw.length > 0) {
            try {
                strictUtf8.decode(h.raw);
            } catch {
                invalid.push([pos, h.end]);
            }
        }
        pos = h.end;
    }
    if (invalid.length === 0) return data;

    const removed = invalid.reduce((n, [s, e]) => n + (e - s) - 1, 0);
    const out = new Uint8Array(b.length - removed);
    let from = 0;
    let to = 0;
    for (const [s, e] of invalid) {
        out.set(b.subarray(from, s), to);
        to += s - from;
        out[to++] = 0xa0; // fixstr of length 0
        from = e;
    }
    out.set(b.subarray(from), to);
    return out;
}

class MsgPack {

    static packer() {
        return new Packr({
            // we must disable conversion to javascript maps to avoid integer keys being converted to strings by js
            // using a Map instead of a JS object allows us to preserve sending an integer based key
            // this is needed otherwise msgunpack in LXMF router will use a string key, and looking up by integer key
            // will mean this field will not be found, even though it exists...
            mapsAsObjects: false,
        });
    }

    /**
     * Packs the provided data with msgpack.
     * @param data the data to pack
     * @returns {Buffer}
     */
    static pack(data) {
        return this.packer().pack(data);
    }

    /**
     * Unpacks the provided data with msgpack. A str that is not valid UTF-8
     * comes back empty (see emptyInvalidStrs for why).
     * @param data the data to unpack
     * @returns {any}
     */
    static unpack(data) {
        return this.packer().unpack(emptyInvalidStrs(data));
    }

}

export default MsgPack;
