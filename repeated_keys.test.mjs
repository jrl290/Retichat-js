/**
 * lib/rns/msgpack_keys.js: a msgpack map that repeats a key, judged as
 * Python LXMF's umsgpack judges it (RFed SPEC §17.14 "Repeated keys"; James,
 * 2026-10-11: parity). The vectors (group_sync.test.mjs: refused,
 * key_equality) pin the cases the reference was asked about; these pin what
 * the walk itself must get right where a JavaScript reading would go wrong:
 * integers past 2^53, -0, float 32, timestamps, keys that are containers,
 * any depth, the order umsgpack reads in, cut-short bytes, and deep nesting.
 *
 * Run: node --test repeated_keys.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { repeatedKey, refuseRepeatedKeys, isRefusal, REFUSED_WHOLE } from "./lib/rns/msgpack_keys.js";

const hex = (h) => Buffer.from(h.replace(/\s+/g, ""), "hex");
/** A map {a: 0, b: 1} of two keys given as msgpack hex. */
const pair = (a, b) => hex("82" + a + "00" + b + "01");
const repeats = (a, b) => repeatedKey(pair(a, b)) !== null;

test("numbers are one key by their exact value, whatever their encoding, as Python compares int, float and bool", () => {
    assert.equal(repeats("cf0000000000000001", "d30000000000000001"), true, "uint 64 and int 64");
    assert.equal(repeats("ca3f800000", "c3"), true, "float 32 1.0 and true");
    assert.equal(repeats("c2", "cb8000000000000000"), true, "false and -0.0");
    // 2^53 + 1 is not the float 2^53, though a JavaScript Number makes them one.
    assert.equal(repeats("cf0020000000000001", "cb4340000000000000"), false, "2^53 + 1 and 2^53");
    assert.equal(repeats("cf0020000000000000", "cb4340000000000000"), true, "2^53 and 2^53");
    assert.equal(repeats("cfffffffffffffffff", "d3ffffffffffffffff"), false, "2^64 − 1 and −1");
    assert.equal(repeats("d38000000000000000", "cbc3e0000000000000"), true, "−2^63 and the float −2^63");
    assert.equal(repeats("cb7ff0000000000000", "cbfff0000000000000"), false, "+inf and −inf");
    assert.equal(repeats("ca7fc00000", "ca7fc00000"), false, "NaN (float 32) twice");
    assert.equal(repeats("cb3fb999999999999a", "ca3dcccccd"), false, "0.1 and float 32 0.1: two values");
    assert.equal(repeats("01", "02"), false);
});

test("str by its bytes (never normalised, invalid UTF-8 included), bin by its bytes, never a str and a bin; ext by type and data; a timestamp by its instant to the microsecond", () => {
    assert.equal(repeats("a2c3a9", "a2c3a9"), true);
    assert.equal(repeats("a1ff", "a1fe"), false, "two invalid strs, different bytes");
    assert.equal(repeats("a1ff", "a1ff"), true, "the same invalid bytes");
    assert.equal(repeats("a161", "d90161"), true, "fixstr and str 8 of one text");
    assert.equal(repeats("c40161", "c50001" + "61"), true, "bin 8 and bin 16 of one byte string");
    assert.equal(repeats("c0", "c0"), true, "nil");
    // One second and 999 ns (floored to microseconds) is one second; 1000 ns is not.
    const ts32 = "d6ff00000001";
    assert.equal(repeats(ts32, "c70cff" + "000003e7" + "0000000000000001"), true, "timestamp 32 and 96: 1 s and 1 s + 999 ns");
    assert.equal(repeats(ts32, "c70cff" + "000003e8" + "0000000000000001"), false, "1 s and 1 s + 1000 ns");
    // timestamp 64: nanoseconds in the high 30 bits, seconds in the low 34.
    assert.equal(repeats(ts32, "d7ff" + "0000000000000001"), true, "timestamp 32 and 64 of one second");
    assert.equal(repeats("d5ff0001", "d5ff0001"), true, "an ext −1 of a length no timestamp has: by its data");
});

test("container keys are never compared (an array is a tuple umsgpack skips; a map is refused for another reason), but a repeat inside one is found", () => {
    assert.equal(repeatedKey(pair("9101", "9101")), null, "[1] twice");
    assert.equal(repeatedKey(pair("810101", "810101")), null, "{1: 1} twice: not this rule");
    assert.deepEqual(repeatedKey(hex("81" + "9182" + "0100" + "0101" + "c0")), { depth: 2, key: "1" }, "inside a key: {[{1: 0, 1: 1}]: nil}");
});

test("any depth: the payload is depth 0, its fields map 1, the Retichat field's map 2; two maps with the same keys are no repeat", () => {
    const payload = (fields) => hex("94" + "cb41daab8c00000000" + "c400" + "c400" + fields);
    assert.deepEqual(repeatedKey(payload("820f01" + "0f02")), { depth: 1, key: "15" });
    assert.deepEqual(repeatedKey(payload("81ccd1" + "820101" + "0102")), { depth: 2, key: "1" });
    assert.deepEqual(repeatedKey(payload("81ccd1" + "810a" + "820000" + "0001")), { depth: 3, key: "0" });
    assert.equal(repeatedKey(payload("82" + "01" + "810101" + "02" + "810101")), null, "two maps, each with its own keys");
    assert.equal(repeatedKey(payload("80")), null);
    assert.equal(repeatedKey(hex("01")), null, "a scalar");
    // A fifth element (a stamp) and beyond is read too, as umsgpack reads it.
    assert.deepEqual(repeatedKey(hex("95" + "cb41daab8c00000000" + "c400" + "c400" + "80" + "820101" + "0102")), { depth: 1, key: "1" });
});

test("the repeat named is the one umsgpack raises on: the first met in reading order, an inner one in an earlier value before an outer one later", () => {
    // {1: {7: 0, 7: 1}, 1: 2}: umsgpack reads key 1, then the inner map (and raises there).
    assert.deepEqual(repeatedKey(hex("82" + "01" + "82" + "0700" + "0701" + "01" + "02")), { depth: 1, key: "7" });
});

test("bytes it cannot walk end the walk: a repeat before them is found; none after is invented", () => {
    assert.deepEqual(repeatedKey(hex("83" + "0100" + "0101" + "02")), { depth: 0, key: "1" }, "cut short after the repeat");
    assert.equal(repeatedKey(hex("83" + "0100" + "0201")), null, "cut short before any repeat");
    assert.equal(repeatedKey(hex("82" + "0100" + "c1")), null, "an invalid type byte");
    assert.deepEqual(repeatedKey(hex("df7fffffff" + "0100" + "0101")), { depth: 0, key: "1" }, "a count past the end: walked as far as the bytes go");
    assert.equal(repeatedKey(new Uint8Array(0)), null);
});

test("deep nesting is walked in one pass, without recursion", () => {
    const depth = 200_000;
    const nested = Buffer.concat([Buffer.alloc(depth, 0x91), hex("820100" + "0101")]);
    assert.deepEqual(repeatedKey(nested), { depth, key: "1" });
    const distinct = Buffer.concat([Buffer.alloc(depth, 0x91), hex("820100" + "0201")]);
    assert.equal(repeatedKey(distinct), null);
});

test("refuseRepeatedKeys says it once and throws the refusal; it says nothing for a payload that repeats no key", () => {
    const lines = [];
    const saved = console.log;
    console.log = (...a) => lines.push(a.join(" "));
    let thrown = null;
    try {
        refuseRepeatedKeys(pair("cca0", "cd00a0"), "a test message");
    } catch (e) {
        thrown = e;
    } finally {
        console.log = saved;
    }
    assert.ok(isRefusal(thrown));
    assert.ok(thrown.message.startsWith(REFUSED_WHOLE));
    assert.deepEqual(lines, [`[LXMF] a test message ${thrown.message}`]);
    assert.match(thrown.message, /^refused whole: a map at depth 0 repeats a key \(160\), as Python LXMF refuses it \(umsgpack DuplicateKeyException; RFed SPEC §17\.14 "Repeated keys"\)$/);
    assert.equal(refuseRepeatedKeys(pair("01", "02"), "a test message"), undefined);
    assert.equal(isRefusal(new Error("msgpack decode error")), false);
});
