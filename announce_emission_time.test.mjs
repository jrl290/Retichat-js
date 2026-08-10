// Guards for the emission time carried in an announce's random hash.
//
// Reference: RNS Destination.announce() — the 10-byte "random hash" is
// 5 random bytes followed by the emission time in seconds as 5 big-endian
// bytes. We used to fill both halves with random bytes (there was a `fixme`
// saying the timestamp "doesn't seem to be used for anything else"). It is used,
// and getting it wrong is not a local problem:
//
// Transport nodes keep the newest emission time they have seen per destination
// and use it to decide whether an announce carries fresher routing information
// than the path they already hold. Random bytes decode to values on the order of
// 10^12 seconds — tens of thousands of years in the future. Once a peer records
// one, every subsequent genuine announce looks older and is discarded, so the
// destination's path can never be refreshed again on that node. The damage
// outlives us: it is cached on other people's nodes.
//
// Because that failure is invisible from our side, these assert on the actual
// bytes we put on the wire. As in the other suites here, the real shipped method
// is lifted out of destination.js and run against stubs, since the module graph
// resolves `@noble/curves` through the browser importmap.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./lib/rns/destination.js", import.meta.url), "utf8");

function extractMethod(signature) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from destination.js`);

    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
            depth--;
            if (depth === 0) return source.slice(bodyStart + 1, i);
        }
    }
    throw new Error(`could not brace-match ${signature}`);
}

const PUBLIC_KEY = Buffer.alloc(64, 0x11);
const NAME_HASH = Buffer.alloc(10, 0x22);
const DEST_HASH = Buffer.alloc(16, 0x33);
const SIGNATURE = Buffer.alloc(64, 0x44);

// Offsets into announceData, which is publicKey ‖ nameHash ‖ randomHash ‖ ...
const RANDOM_HASH_START = PUBLIC_KEY.length + NAME_HASH.length;
const RANDOM_HASH_END = RANDOM_HASH_START + 10;

let randomCounter = 0;

const CryptographyStub = {
    // Distinguishable, non-repeating, and never a plausible timestamp — so a
    // regression that puts random bytes back in the second half is unambiguous.
    getRandomHash() {
        randomCounter++;
        return Buffer.alloc(32, randomCounter);
    },
};

class PacketStub {
    static HEADER_1 = 0x00;
    static ANNOUNCE = 0x01;
    static NONE = 0x00;
    static FLAG_UNSET = 0x00;
    static FLAG_SET = 0x01;
    pack() { return this.data; }
}

const TransportStub = { BROADCAST: 0x00 };

const body = extractMethod("announce(appDataBytes = null)");
const announce = new Function(
    "Cryptography",
    "Packet",
    "Transport",
    `return function announce(appDataBytes = null) {${body}};`,
)(CryptographyStub, PacketStub, TransportStub);

/** A destination that captures the announce it would have transmitted. */
function newDestination() {
    return {
        hash: DEST_HASH,
        nameHash: NAME_HASH,
        type: 0x00,
        sent: [],
        signed: [],
        identity: {
            getPublicKey: () => PUBLIC_KEY,
            sign(data) { this.owner.signed.push(Buffer.from(data)); return SIGNATURE; },
        },
        rns: { sendData(raw) { this.owner.sent.push(Buffer.from(raw)); } },
    };
}

function emitAnnounce(appDataBytes = null) {
    const destination = newDestination();
    destination.identity.owner = destination;
    destination.rns.owner = destination;
    announce.call(destination, appDataBytes);

    assert.equal(destination.sent.length, 1, "announce() must transmit exactly one packet");
    const announceData = destination.sent[0];
    return {
        announceData,
        signedData: destination.signed[0],
        randomHash: announceData.slice(RANDOM_HASH_START, RANDOM_HASH_END),
    };
}

/** Runs fn with Date.now() pinned, so the expected bytes are exact. */
function withClock(unixSeconds, fn) {
    const real = Date.now;
    Date.now = () => unixSeconds * 1000;
    try {
        return fn();
    } finally {
        Date.now = real;
    }
}

test("the announce carries the emission time, not random bytes", () => {
    const { randomHash } = emitAnnounce();

    assert.equal(randomHash.length, 10, "the random hash is 10 bytes");

    const emitted = randomHash.readUIntBE(5, 5);
    const now = Math.floor(Date.now() / 1000);
    assert.ok(
        Math.abs(emitted - now) <= 5,
        `emission time ${emitted} must be the current unix time (~${now}); random bytes here poison the path on every node that sees them`,
    );
});

test("the emission time is written big-endian at the exact byte offsets", () => {
    // 0x00_5F_5E_10_00 = 1600000000, a value with distinct bytes so a
    // little-endian or misaligned write cannot coincidentally match.
    const { randomHash } = withClock(1600000000, () => emitAnnounce());

    assert.deepEqual(
        randomHash.slice(5),
        Buffer.from([0x00, 0x5f, 0x5e, 0x10, 0x00]),
        "bytes 5..10 must be the emission time, big-endian",
    );
});

test("the first five bytes are still random", () => {
    const first = emitAnnounce().randomHash.slice(0, 5);
    const second = emitAnnounce().randomHash.slice(0, 5);

    // Two announces from the same destination in the same second must not be
    // byte-identical, or they are indistinguishable to a receiver.
    assert.notDeepEqual(first, second, "the leading five bytes must vary between announces");
});

test("the emission time is inside the signed data", () => {
    const { randomHash, signedData } = withClock(1600000000, () => emitAnnounce());

    // If the signature covered a different random hash than the one we transmit,
    // every receiver would reject the announce as forged.
    assert.ok(signedData.includes(randomHash), "the signature must commit to the transmitted random hash");
    assert.equal(
        signedData.indexOf(randomHash),
        DEST_HASH.length + PUBLIC_KEY.length + NAME_HASH.length,
        "signed data is destHash ‖ publicKey ‖ nameHash ‖ randomHash",
    );
});

test("a later announce reports a later emission time", () => {
    const earlier = withClock(1600000000, () => emitAnnounce()).randomHash.readUIntBE(5, 5);
    const later = withClock(1600000600, () => emitAnnounce()).randomHash.readUIntBE(5, 5);

    // Direction matters: a receiver keeps the newest time it has seen, so an
    // announce that goes backwards is silently ignored.
    assert.ok(later > earlier, "emission time must advance with the clock");
    assert.equal(later - earlier, 600, "and advance by the elapsed seconds");
});

test("app data does not displace the emission time", () => {
    const appData = Buffer.from("retichat", "utf8");
    const { randomHash, announceData } = withClock(1600000000, () => emitAnnounce(appData));

    assert.deepEqual(randomHash.slice(5), Buffer.from([0x00, 0x5f, 0x5e, 0x10, 0x00]));
    assert.ok(announceData.includes(appData), "app data is appended after the announce fields");
});
