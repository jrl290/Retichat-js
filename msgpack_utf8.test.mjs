/**
 * MSGPACK STR UTF-8 — lib/rns/msgpack.js empties a str that is not valid
 * UTF-8 before msgpackr decodes it, so the rest of the value parses right.
 *
 * msgpackr 1.11.2's pure-JS string decoder (readStringJS, what the browser's
 * esm.sh build always uses) reads continuation bytes without checking the
 * str's end: a truncated multi-byte sequence swallows the next value's bytes,
 * so an LXMF payload fails to parse or parses with the wrong fields. It also
 * decodes a lone 0xFF as "ÿ" and the overlong C0 AF as "/". Under Node the
 * npm package normally uses the native msgpackr-extract decoder instead, so
 * this file turns that off before msgpackr loads and checks it did: the
 * cases below then run the exact decoder the browser runs.
 *
 * An invalid str reads as empty, as in LXMF-rust (lx_message value_to_binary;
 * DISPLAY_NAMES.md §3 rule 1 for names, pinned in display_names_wiring).
 *
 * Run: node --test msgpack_utf8.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";

// Before anything imports msgpackr (dynamic imports only below this line).
process.env.MSGPACKR_NATIVE_ACCELERATION_DISABLED = "true";
const { isNativeAccelerationEnabled, Packr } = await import("msgpackr");
const { default: MsgPack, emptyInvalidStrs } = await import("./lib/rns/msgpack.js");

const fixstr = (bytes) => Buffer.concat([Buffer.from([0xa0 | bytes.length]), Buffer.from(bytes)]);
const str8 = (bytes) => Buffer.concat([Buffer.from([0xd9, bytes.length]), Buffer.from(bytes)]);
const str16 = (bytes) => { const h = Buffer.alloc(3); h[0] = 0xda; h.writeUInt16BE(bytes.length, 1); return Buffer.concat([h, Buffer.from(bytes)]); };
const f64 = (x) => { const b = Buffer.alloc(9); b[0] = 0xcb; b.writeDoubleBE(x, 1); return b; };
const bin = (s) => { const d = Buffer.from(s); return Buffer.concat([Buffer.from([0xc4, d.length]), d]); };
const ascii = (s) => [...Buffer.from(s, "ascii")];
const text = (v) => Buffer.from(v).toString();

// An LXMF payload [timestamp, title, content, fields] whose fields are
// {0xD1: {0: bin "Alice"}}, the Retichat field with a display name.
const FIELDS = Buffer.concat([Buffer.from([0x81, 0xcc, 0xd1, 0x81, 0x00]), bin("Alice")]);
const payload = (content, fields = FIELDS) =>
    Buffer.concat([Buffer.from([0x94]), f64(1790000000.5), bin("Title"), content, fields]);

/** The four parts of an unpacked payload, as the LXMF receive path reads them. */
function assertIntactPayload(out, content, what) {
    assert.equal(out.length, 4, `${what}: four elements`);
    assert.equal(out[0], 1790000000.5, `${what}: timestamp`);
    assert.equal(text(out[1]), "Title", `${what}: title`);
    assert.equal(out[2], content, `${what}: content`);
    assert.ok(out[3] instanceof Map && out[3].get(0xd1) instanceof Map, `${what}: fields is {0xD1: {...}}`);
    assert.deepEqual([...out[3].keys()], [0xd1], `${what}: fields has only 0xD1`);
    assert.equal(text(out[3].get(0xd1).get(0)), "Alice", `${what}: the name in the fields`);
}

const INVALID = [
    ["a truncated 3-byte sequence ending a 20-byte str8 (swallows the fields map header)",
        str8([...ascii("hello world 1234567"), 0xe2])],
    ["a truncated 4-byte sequence ending a 20-byte fixstr (fields parse wrong, silently)",
        fixstr([...ascii("hello world 1234567"), 0xf0])],
    ["a lone 0xFF in a short str (msgpackr: \"ÿ\")", fixstr([0x61, 0x62, 0x63, 0xff])],
    ["an overlong C0 AF in a short str (msgpackr: \"/\")", fixstr([0x61, 0xc0, 0xaf, 0x62])],
    ["a UTF-8-encoded surrogate ED A0 80", fixstr([0x61, 0xed, 0xa0, 0x80])],
    ["a stray continuation byte in a 70-byte str16", str16([...ascii("x".repeat(69)), 0x80])],
];

test("the cases run msgpackr's pure-JS string decoder, as the browser does", () => {
    assert.equal(isNativeAccelerationEnabled, false,
        "MSGPACKR_NATIVE_ACCELERATION_DISABLED must take effect, or these cases test the native decoder");
});

for (const [what, content] of INVALID) {
    test(`an LXMF payload whose content is ${what} parses right, with the content empty`, () => {
        assertIntactPayload(MsgPack.unpack(payload(content)), "", what);
    });
}

test("the unguarded decoder really misreads these payloads (why the guard exists)", (t) => {
    const raw = (b) => new Packr({ mapsAsObjects: false }).unpack(b);
    const truncated4 = raw(payload(INVALID[1][1]));
    // The fields come back as {0: Alice} instead of {0xD1: {0: Alice}}.
    t.diagnostic(`msgpackr alone: fields keys ${JSON.stringify([...truncated4[3].keys()])}, content ${JSON.stringify(truncated4[2])}`);
    t.diagnostic(`msgpackr alone: lone 0xFF -> ${JSON.stringify(raw(payload(INVALID[2][1]))[2])}, C0 AF -> ${JSON.stringify(raw(payload(INVALID[3][1]))[2])}`);
});

test("an invalid str is emptied as a map key and deep inside fields too, the rest intact", () => {
    const badKeyFields = Buffer.concat([Buffer.from([0x82]), fixstr([0x6b, 0xff]), bin("v"), Buffer.from([0xcc, 0xd1, 0x80])]);
    const k = MsgPack.unpack(payload(fixstr(ascii("ok")), badKeyFields));
    assert.equal(k[2], "ok");
    assert.deepEqual([...k[3].keys()], ["", 0xd1]);
    assert.equal(text(k[3].get("")), "v");

    // {0xD1: {1: [1, <"a" + a lone lead byte>, "tail"]}}
    const deep = Buffer.concat([Buffer.from([0x81, 0xcc, 0xd1, 0x81, 0x01, 0x93, 0x01]), fixstr([0x61, 0xc3]), fixstr(ascii("tail"))]);
    const d = MsgPack.unpack(payload(fixstr(ascii("ok")), deep));
    assert.deepEqual(d[3].get(0xd1).get(1), [1, "", "tail"]);
});

test("valid UTF-8 of every length the decoder treats differently comes back unchanged", () => {
    const samples = [
        "",
        "hi",
        "é",
        "snow ☃",
        "héllo wörld – ok",                    // 16-64 bytes: the manual loop
        "emoji 😀 and 𝄞 in a middle-sized str",  // 4-byte sequences (surrogate pairs)
        "日本語のテキスト".repeat(3),             // 72 bytes: TextDecoder
    ];
    for (const s of samples) {
        const bytes = [...Buffer.from(s, "utf8")];
        const packed = payload(bytes.length < 32 ? fixstr(bytes) : str8(bytes));
        assert.equal(emptyInvalidStrs(packed), packed, `no copy for valid bytes (${JSON.stringify(s)})`);
        assertIntactPayload(MsgPack.unpack(packed), s, JSON.stringify(s));
    }
});

test("what the client packs still round-trips, str keys and values included", () => {
    const fields = new Map([[0xd1, new Map([[0, Buffer.from("Zoë")]])], [2, "naïve – ok"]]);
    const packed = MsgPack.pack([1790000000.25, Buffer.from("t"), Buffer.from("c"), fields, new Map([["clé", "välue"]])]);
    const out = MsgPack.unpack(packed);
    assert.equal(out[3].get(2), "naïve – ok");
    assert.equal(text(out[3].get(0xd1).get(0)), "Zoë");
    assert.equal(out[4].get("clé"), "välue");
});

test("malformed msgpack the guard cannot walk is left to msgpackr, unchanged", () => {
    const outcome = (fn) => {
        try { return { threw: false, value: JSON.stringify(fn(), (k, v) => v instanceof Map ? [...v] : v) }; }
        catch (e) { return { threw: true, message: e.message }; }
    };
    const raw = (b) => new Packr({ mapsAsObjects: false }).unpack(b);
    const cases = [
        payload(fixstr(ascii("ok"))).subarray(0, 12),   // truncated inside the title
        payload(fixstr(ascii("ok"))).subarray(0, 1),    // only the array header
        Buffer.from([0x92, 0xc1, 0x01]),                // 0xc1, a type byte msgpack never uses
    ];
    for (const b of cases) {
        assert.equal(emptyInvalidStrs(b), b, `returned as is: ${b.toString("hex")}`);
        assert.deepEqual(outcome(() => MsgPack.unpack(b)), outcome(() => raw(b)), `bytes ${b.toString("hex")}`);
    }
});
