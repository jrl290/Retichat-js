/**
 * REGRESSION GUARD — the browser's signed registration is the protocol's,
 * byte for byte.
 *
 * Reticulum-post REGISTRATION-STAGE1.md §4.2, §5 and §15; §14's
 * registration_vectors.test.mjs. registration_vectors.json is a copy of
 * Reticulum-post's php/tests/vectors/registration_vectors.json, format 6,
 * made by tools/registration_vectors.py from RNS 1.5.2 and checked
 * independently by tools/check_registration_vectors.php. The test pins the
 * copy's SHA-256, the one the spec pins, so a changed copy fails here before
 * anything is compared with it. signRegistration() reproduces the browser
 * vectors' signed bytes, field by field, their signatures and their request
 * bodies; decryptSessionToken() reads their tokens with the browser's
 * identity alone; and both tokens_negative fail.
 *
 * Run: node --test registration_vectors.test.mjs
 */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { Identity } from "./lib/rns/reticulum.js";
import { decryptSessionToken, signRegistration } from "./lib/rns/interfaces/post_interface.js";

const raw = readFileSync(new URL("./registration_vectors.json", import.meta.url));
const vectors = JSON.parse(raw.toString("utf8"));
const identity = (name) => Identity.fromPrivateKey(Buffer.from(vectors.identities[name].private_key_hex, "hex"));
const registration = (id) => vectors.registrations.find((r) => r.id === id);

test("the vector file is the copy the spec pins: format 6, SHA-256 7d2bcfee…", () => {
    assert.equal(createHash("sha256").update(raw).digest("hex"), "7d2bcfee1742a6421a05e2b212c04182cc94247d53128ad91d35139fb07304ef");
    assert.equal(vectors.format_version, 6);
    assert.equal(vectors.constants.register_domain, "reticulum-post/register/v1");
    assert.deepEqual(vectors.constants.signed_field_order, ["domain", "challenge", "public_key", "name", "bitrate", "mtu", "client", "mode",
        "transport", "peer_url", "peer_interface_id", "peer_session_token"]);
});

for (const id of ["browser-first", "browser-reregister"]) {
    test(`signRegistration() reproduces ${id}'s signed bytes, field by field, its signature and its request body`, () => {
        const r = registration(id);
        const me = identity(r.identity);
        const given = r.request_body;
        assert.equal(given.registration.challenge, vectors.challenges.find((c) => c.id === r.challenge_id).challenge_hex, "(the vector's own challenge)");
        const { body, signed } = signRegistration(me, { name: given.name, bitrate: given.bitrate, mtu: given.mtu, mode: given.metadata.mode },
            given.registration.challenge);

        let offset = 0;
        for (const index of Object.keys(r.signed_fields).map(Number).sort((a, b) => a - b)) {
            const field = r.signed_fields[index];
            const length = field.lp_hex.length / 2;
            assert.equal(signed.subarray(offset, offset + length).toString("hex"), field.lp_hex, `${id}: field ${index}, ${field.name}`);
            offset += length;
        }
        assert.equal(offset, signed.length, `${id}: nothing after the twelve fields`);
        assert.equal(signed.toString("hex"), r.signed_bytes_hex);
        assert.equal(body.registration.signature, r.signature_hex, "Ed25519 is deterministic: the same signature");
        assert.equal(me.validate(Buffer.from(r.signature_hex, "hex"), signed), true);
        assert.deepEqual(body, given);
        assert.equal(JSON.stringify(body), JSON.stringify(given), "the same body, key for key, in the same order");
    });

    test(`${id}'s token decrypts to its plaintext with the browser's identity`, () => {
        const r = registration(id);
        assert.equal(r.response_example.session_token_encrypted, r.encrypted_token.session_token_encrypted_hex);
        assert.equal(r.response_example.identity_hash, vectors.identities[r.identity].identity_hash_hex);
        assert.match(r.encrypted_token.plaintext_utf8, /^[0-9a-f]{64}$/);
        assert.equal(decryptSessionToken(identity(r.identity), r.response_example.session_token_encrypted), r.encrypted_token.plaintext_utf8);
    });
}

test("both tokens_negative fail: one ciphertext bit flipped, and the wrong identity", () => {
    assert.deepEqual(vectors.tokens_negative.map((n) => n.id), ["token-tampered-ciphertext", "token-wrong-identity"]);
    for (const negative of vectors.tokens_negative) {
        assert.equal(negative.expected, "decrypt_fails");
        assert.equal(decryptSessionToken(identity(negative.identity), negative.session_token_encrypted_hex), null, negative.id);
    }
});

test("decryptSessionToken() never throws: anything that is not a token for this identity is null", () => {
    const me = identity("browser");
    const token = registration("browser-first").response_example.session_token_encrypted;
    for (const notOne of [undefined, null, 42, "", "zz", "abc", token.toUpperCase(), token.slice(0, 64), token.slice(0, -2), "00".repeat(160)]) {
        assert.equal(decryptSessionToken(me, notOne), null, String(notOne).slice(0, 20));
    }
});

test("signRegistration() refuses what §4.2 cannot carry", () => {
    const me = identity("browser");
    const fields = { name: "Retichat Web", bitrate: 1000000, mtu: 500, mode: 1 };
    const challenge = registration("browser-first").request_body.registration.challenge;
    assert.throws(() => signRegistration(me, fields, challenge.toUpperCase()), TypeError, "a challenge is lower-case hex");
    assert.throws(() => signRegistration(me, fields, challenge.slice(2)), TypeError, "of 96 characters");
    assert.throws(() => signRegistration(me, { ...fields, mode: 256 }, challenge), RangeError, "mode is a u8");
    assert.throws(() => signRegistration(me, { ...fields, mtu: 2 ** 32 }, challenge), RangeError, "mtu a u32");
    assert.throws(() => signRegistration(me, { ...fields, bitrate: -1 }, challenge), RangeError);
    assert.throws(() => signRegistration(me, { ...fields, bitrate: 1.5 }, challenge), RangeError);
    assert.throws(() => signRegistration(me, { ...fields, name: "x".repeat(70_000) }, challenge), RangeError, "lp() holds 65535 bytes");
});
