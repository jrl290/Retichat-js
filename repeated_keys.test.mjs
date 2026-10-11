/**
 * lib/rns/msgpack_keys.js: a payload Python LXMF refuses whole for its
 * msgpack, judged as Python LXMF's umsgpack judges it (RFed SPEC §17.14
 * "Repeated keys", James, 2026-10-11: parity; "Unhashable keys" and
 * "Nesting", decided 2026-10-11). The vectors (group_sync.test.mjs: refused,
 * key_equality, nesting) pin the cases the reference was asked about; these
 * pin what the walk itself must get right where a JavaScript reading would
 * go wrong: integers past 2^53, -0, float 32, timestamps, keys that are
 * containers, any depth, the order umsgpack reads in, cut-short bytes, and
 * nesting far past the limit without recursion. And the channel path, which
 * refuses with the same walk (rfed_channel.js channelLxmUnpack).
 *
 * Run: node --test repeated_keys.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { refusal, refuseAsPython, isRefusal, REFUSED_WHOLE, NESTING_MAX_DEPTH } from "./lib/rns/msgpack_keys.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Cryptography from "./lib/rns/cryptography.js";
import { channelIdentity, channelDeliveryHash, channelLxmUnpack, CHANNEL_POST_REFUSED } from "./lib/rns/rfed_channel.js";

const hex = (h) => Buffer.from(h.replace(/\s+/g, ""), "hex");
/** A map {a: 0, b: 1} of two keys given as msgpack hex. */
const pair = (a, b) => hex("82" + a + "00" + b + "01");
const repeats = (a, b) => refusal(pair(a, b))?.reason === "repeated_key";
/** refusal() of a repeat: { reason: "repeated_key", depth, key }. */
const repeat = (depth, key) => ({ reason: "repeated_key", depth, key });

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
    assert.equal(refusal(pair("9101", "9101")), null, "[1] twice");
    assert.equal(refusal(pair("90", "90")), null, "[] twice");
    assert.equal(refusal(pair("919101", "919101")), null, "[[1]] twice");
    assert.deepEqual(refusal(pair("810101", "810101")), { reason: "unhashable_key", depth: 0, key: "map 810101" }, "{1: 1} twice: the first is no key");
    assert.deepEqual(refusal(hex("81" + "9182" + "0100" + "0101" + "c0")), repeat(2, "1"), "inside a key: {[{1: 0, 1: 1}]: nil}");
});

test("Unhashable keys: a map key, or an array key that holds a map at any depth, at any depth of the payload; an array key that holds no map is read", () => {
    // { 0xA0: "id", <key>: 0 }
    const beside = (key) => refusal(hex("82" + "cca0" + "a26964" + key + "00"));
    const unhashable = (label) => ({ reason: "unhashable_key", depth: 0, key: label });
    assert.deepEqual(beside("80"), unhashable("map 80"), "{}");
    assert.deepEqual(beside("810102"), unhashable("map 810102"), "{1: 2}");
    assert.deepEqual(beside("9180"), unhashable("array 9180"), "[{}]");
    assert.deepEqual(beside("92" + "01" + "91" + "91" + "80"), unhashable("array 9201919180"), "[1, [[{}]]]");
    for (const [key, what] of [["90", "[]"], ["919101", "[[1]]"], ["93" + "c40161" + "d40500" + "cb7ff8000000000000", "[bin, ext, NaN]"]]) {
        assert.equal(refusal(hex("81" + key + "c0")), null, `${what} is read`);
    }
    // At any depth: in 0xD1's key 10, and in a map in an array in a field.
    assert.deepEqual(refusal(hex("81" + "ccd1" + "81" + "0a" + "81" + "80" + "00")), { reason: "unhashable_key", depth: 2, key: "map 80" });
    const payload = (fields) => hex("94" + "cb3ff0000000000000" + "c400" + "c400" + fields);
    assert.deepEqual(refusal(payload("81" + "77" + "91" + "81" + "80" + "01")), { reason: "unhashable_key", depth: 3, key: "map 80" });
});

test("the reason is the first umsgpack meets: a key is read whole before it is judged, a map key is refused before its value is read, an array key's value is read before the key is hashed (the refused vectors' reasons, checked against the reference)", () => {
    const twice = "82" + "0000" + "0000";                    // {0: 0, 0: 0}
    assert.deepEqual(refusal(hex("81" + twice + "c0")), repeat(1, "0"), "{ {0: 0, 0: 0}: nil }: the key's own repeat first");
    assert.deepEqual(refusal(hex("81" + "80" + twice)), { reason: "unhashable_key", depth: 0, key: "map 80" }, "{ {}: {0: 0, 0: 0} }: the map key, before its value");
    assert.deepEqual(refusal(hex("81" + "9180" + twice)), repeat(1, "0"), "{ [{}]: {0: 0, 0: 0} }: the array key's value first");
    assert.deepEqual(refusal(hex("83" + "9180" + "c0" + "05c0" + "05c0")), { reason: "unhashable_key", depth: 0, key: "array 9180" },
        "{ [{}]: nil, 5: nil, 5: nil }: the array key, once its value is read, before the repeat");
    assert.deepEqual(refusal(hex("83" + "05c0" + "05" + twice + "80c0")), repeat(0, "5"), "{ 5: nil, 5: {...}, {}: nil }: the repeat, met first");
});

test("any depth: the payload is depth 0, its fields map 1, the Retichat field's map 2; two maps with the same keys are no repeat", () => {
    const payload = (fields) => hex("94" + "cb41daab8c00000000" + "c400" + "c400" + fields);
    assert.deepEqual(refusal(payload("820f01" + "0f02")), repeat(1, "15"));
    assert.deepEqual(refusal(payload("81ccd1" + "820101" + "0102")), repeat(2, "1"));
    assert.deepEqual(refusal(payload("81ccd1" + "810a" + "820000" + "0001")), repeat(3, "0"));
    assert.equal(refusal(payload("82" + "01" + "810101" + "02" + "810101")), null, "two maps, each with its own keys");
    assert.equal(refusal(payload("80")), null);
    assert.equal(refusal(hex("01")), null, "a scalar");
    // A fifth element (a stamp) and beyond is read too, as umsgpack reads it.
    assert.deepEqual(refusal(hex("95" + "cb41daab8c00000000" + "c400" + "c400" + "80" + "820101" + "0102")), repeat(1, "1"));
});

test("the repeat named is the one umsgpack raises on: the first met in reading order, an inner one in an earlier value before an outer one later", () => {
    // {1: {7: 0, 7: 1}, 1: 2}: umsgpack reads key 1, then the inner map (and raises there).
    assert.deepEqual(refusal(hex("82" + "01" + "82" + "0700" + "0701" + "01" + "02")), repeat(1, "7"));
});

test("bytes it cannot walk end the walk: a repeat before them is found; none after is invented", () => {
    assert.deepEqual(refusal(hex("83" + "0100" + "0101" + "02")), repeat(0, "1"), "cut short after the repeat");
    assert.equal(refusal(hex("83" + "0100" + "0201")), null, "cut short before any repeat");
    assert.equal(refusal(hex("82" + "0100" + "c1")), null, "an invalid type byte");
    assert.deepEqual(refusal(hex("df7fffffff" + "0100" + "0101")), repeat(0, "1"), "a count past the end: walked as far as the bytes go");
    assert.deepEqual(refusal(hex("82" + "80")), { reason: "unhashable_key", depth: 0, key: "map 80" }, "a map key, cut short after it");
    assert.equal(refusal(new Uint8Array(0)), null);
});

/** `levels` arrays nested, the innermost holding `leaf` (hex; "" for none). */
const arrays = (levels, leaf = "") => Buffer.concat([Buffer.alloc(levels - 1, 0x91), hex((leaf ? "91" : "90") + leaf)]);
/** A payload [1.0, b"", b"", {0x77: field}]: the field's value at depth 2. */
const inAField = (field) => Buffer.concat([hex("94" + "cb3ff0000000000000" + "c400" + "c400" + "8177"), field]);

test("Nesting: a value at depth 493 is read, at 494 refused, whatever it is (an array, a map, a key, a scalar); 492 arrays nested in a field are the limit", () => {
    assert.equal(NESTING_MAX_DEPTH, 493);
    assert.equal(refusal(inAField(arrays(492))), null, "492 arrays in a field, the innermost empty at depth 493");
    assert.deepEqual(refusal(inAField(arrays(493))), { reason: "too_deep", depth: 494 }, "493 arrays");
    assert.equal(refusal(inAField(arrays(491, "a161"))), null, "a str at depth 493");
    assert.deepEqual(refusal(inAField(arrays(492, "00"))), { reason: "too_deep", depth: 494 }, "an int at depth 494");
    const maps = (levels) => Buffer.concat([Buffer.from("8100".repeat(levels - 1), "hex"), hex("80")]);
    assert.equal(refusal(inAField(maps(492))), null, "492 maps {0: ...} in a field");
    assert.deepEqual(refusal(inAField(maps(493))), { reason: "too_deep", depth: 494 }, "493 maps");
    const key = (levels) => inAField(Buffer.concat([hex("81"), arrays(levels), hex("00")]));
    assert.equal(refusal(key(491)), null, "a key nesting to depth 493");
    assert.deepEqual(refusal(key(492)), { reason: "too_deep", depth: 494 }, "a key nesting to depth 494");
});

test("nesting far past the limit is refused in one pass, without recursion, at the first value past it: the bytes after it are never walked", () => {
    const depth = 200_000;
    const nested = Buffer.concat([Buffer.alloc(depth, 0x91), hex("820100" + "0101")]);
    assert.deepEqual(refusal(nested), { reason: "too_deep", depth: NESTING_MAX_DEPTH + 1 }, "too deep before the repeat at its bottom is met");
    assert.deepEqual(refusal(Buffer.concat([Buffer.alloc(depth, 0x91), hex("90")])), { reason: "too_deep", depth: 494 });
    // Cut short after the limit: still refused, as the first value past it was read.
    assert.deepEqual(refusal(Buffer.alloc(600, 0x91)), { reason: "too_deep", depth: 494 });
});

test("refuseAsPython says it once and throws the refusal, in LXMF-rust's words for each reason; it says nothing for a payload Python reads", () => {
    const refused = (bytes) => {
        const lines = [];
        const saved = console.log;
        console.log = (...a) => lines.push(a.join(" "));
        let thrown = null;
        try {
            refuseAsPython(bytes, "a test message");
        } catch (e) {
            thrown = e;
        } finally {
            console.log = saved;
        }
        assert.ok(isRefusal(thrown));
        assert.ok(thrown.message.startsWith(REFUSED_WHOLE));
        assert.deepEqual(lines, [`[LXMF] a test message ${thrown.message}`]);
        return thrown;
    };
    const twice = refused(pair("cca0", "cd00a0"));
    assert.equal(twice.reason, "repeated_key");
    assert.match(twice.message, /^refused whole: a map at depth 0 repeats a key \(160\), as Python LXMF refuses it \(umsgpack DuplicateKeyException; RFed SPEC §17\.14 "Repeated keys"\)$/);
    const map = refused(hex("81" + "80" + "c0"));
    assert.equal(map.reason, "unhashable_key");
    assert.match(map.message, /^refused whole: a map at depth 0 has a key Python cannot hash \(map 80\), as Python LXMF refuses it \(umsgpack UnhashableKeyException; RFed SPEC §17\.14 "Unhashable keys"\)$/);
    // 495 arrays: the outermost at depth 0, the innermost at 494.
    const deep = refused(arrays(NESTING_MAX_DEPTH + 2));
    assert.equal(deep.reason, "too_deep");
    assert.match(deep.message, /^refused whole: a value at depth 494 is nested past depth 493, as Python LXMF refuses it \(RecursionError on its delivery path; RFed SPEC §17\.14 "Nesting"\)$/);
    assert.equal(refuseAsPython(pair("01", "02"), "a test message"), undefined);
    assert.equal(refuseAsPython(arrays(NESTING_MAX_DEPTH + 1), "a test message"), undefined, "494 arrays: the innermost at 493");
    assert.equal(isRefusal(new Error("msgpack decode error")), false);
});

/** A channel post on #`name` from `sender` whose LXMF payload is `payload`
 *  (bytes), packed, signed and sealed as channelLxmPack does it. */
function channelPost(name, sender, payload) {
    const sourceHash = Destination.hash(sender, "lxmf", "delivery");
    const hashedPart = Buffer.concat([channelDeliveryHash(name), sourceHash, payload]);
    const signature = sender.sign(Buffer.concat([hashedPart, Cryptography.fullHash(hashedPart)]));
    const prelude = Buffer.concat([Buffer.from("RTID"), sender.getPublicKey(), sourceHash, signature, payload]);
    const { identity, hash } = channelIdentity(name);
    return Buffer.concat([hash, identity.encrypt(prelude)]);
}

test("the channel path refuses with the same walk: a post whose payload repeats a key, has a key Python cannot hash or nests past depth 493 is refused whole with one line (CHANNEL_POST_REFUSED), and one at the limit is read", () => {
    const sender = Identity.create();
    const said = (run) => {
        const lines = [];
        const saved = { log: console.log, warn: console.warn };
        console.log = console.warn = (...a) => lines.push(a.join(" "));
        try { return { result: run(), lines }; } finally { Object.assign(console, saved); }
    };
    const post = (fields) => channelPost("general", sender, Buffer.concat([hex("94" + "cb41daab8c00000000" + "c400" + "c40178"), fields]));
    const read = said(() => channelLxmUnpack("general", post(hex("80"))));
    assert.equal(read.result?.content, "x", `the prelude and signature as channelLxmPack makes them: ${read.lines.join(" | ")}`);
    for (const [fields, why] of [
        [hex("82" + "0101" + "0102"), /repeats a key \(1\)/],
        [hex("81" + "80" + "c0"), /has a key Python cannot hash \(map 80\)/],
        [Buffer.concat([hex("8177"), arrays(493)]), /a value at depth 494 is nested past depth 493/],
    ]) {
        const { result, lines } = said(() => channelLxmUnpack("general", post(fields)));
        assert.equal(result, CHANNEL_POST_REFUSED, String(why));
        assert.equal(lines.length, 1, lines.join(" | "));
        assert.match(lines[0], /^\[LXMF\] channel post from [0-9a-f]{12} on #general refused whole: /);
        assert.match(lines[0], why);
    }
    const atTheLimit = said(() => channelLxmUnpack("general", post(Buffer.concat([hex("8177"), arrays(492)]))));
    assert.equal(atTheLimit.result?.content, "x", "492 arrays in a field: read");
    assert.deepEqual(atTheLimit.lines, []);
});
