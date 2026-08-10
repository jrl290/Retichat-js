// UNFORGIVABLE REGRESSION GUARD — do not delete, do not weaken.
//
// `Reticulum.destinations` is the INBOUND DISPATCH TABLE. Only IN destinations
// may be in it, and a hash may appear at most once.
// Reference: RNS/Transport.py register_destination().
//
// This has broken more than once. When it breaks, every OUT destination built
// from a contact's public key (app.js builds one per send) lands in the dispatch
// table. The moment you message your own address — or an address you have also
// adopted, such as a distro identity — an OUT copy of your own hash is in the
// table alongside your real IN destination. Inbound packets then hit the
// key-less copy, which overwrites `packet.destination`, and you get:
//
//   [http-exchange] Failed to parse packet: scalar must be hex string or Uint8Array
//       -> Identity.decrypt() with privateKeyBytes = null
//   Uncaught Error: private key must be hex string or Uint8Array
//       -> Identity.sign() from Packet.prove() with signaturePrivateKeyBytes = null
//
// Inbound LXMF delivery dies silently from that point on.
//
// The rest of the module graph resolves `@noble/curves` through the browser
// importmap, so it cannot be imported under Node. Instead we lift the real
// shipped `registerDestination` out of reticulum.js and run it against stubs,
// so this tests actual behaviour rather than the text of the file.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./lib/rns/reticulum.js", import.meta.url), "utf8");

function extractMethod(signature) {
    // Match the definition, not the usage example in the JSDoc above it.
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from reticulum.js`);

    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
            depth--;
            if (depth === 0) {
                return source.slice(bodyStart + 1, i);
            }
        }
    }
    throw new Error(`could not brace-match ${signature}`);
}

class DestinationStub {
    static IN = "IN";
    static OUT = "OUT";

    constructor(rns, identity, direction, type, appName, ...aspects) {
        this.rns = rns;
        this.identity = identity;
        this.direction = direction;
        this.type = type;
        this.appName = appName;
        this.aspects = aspects;
        this.hash = Buffer.from(identity.hashHex, "hex");
        this.listeners = [];
    }
}

const body = extractMethod("registerDestination(identity, direction, type, appName, ...aspects)");
const registerDestination = new Function(
    "Destination",
    `return function registerDestination(identity, direction, type, appName, ...aspects) {${body}};`,
)(DestinationStub);

const ownIdentity = { hashHex: "8dd11089dd02".padEnd(32, "0"), private: true };
const peerIdentity = { hashHex: "1762c0559eae".padEnd(32, "0"), private: false };

function newRns() {
    return { destinations: [] };
}

test("OUT destinations never enter the inbound dispatch table", () => {
    const rns = newRns();

    const out = registerDestination.call(rns, peerIdentity, DestinationStub.OUT, "SINGLE", "lxmf", "delivery");

    assert.equal(out.direction, DestinationStub.OUT, "caller must still receive a usable OUT destination");
    assert.deepEqual(rns.destinations, [], "an OUT destination must NOT be registered for inbound dispatch");
});

test("messaging your own address does not shadow your IN destination", () => {
    const rns = newRns();

    const inbound = registerDestination.call(rns, ownIdentity, DestinationStub.IN, "SINGLE", "lxmf", "delivery");
    // app.js builds an OUT destination from the contact's public key on every
    // send — including when the contact is yourself, or an adopted distro address.
    registerDestination.call(rns, { ...ownIdentity, private: false }, DestinationStub.OUT, "SINGLE", "lxmf", "delivery");

    assert.equal(rns.destinations.length, 1, "self-send must not add a second entry for our own hash");
    assert.equal(rns.destinations[0], inbound, "our real IN destination must remain the only match");
    assert.equal(rns.destinations[0].identity.private, true, "the registered identity must still hold private keys");
});

test("re-registering an IN destination returns the original object", () => {
    const rns = newRns();

    const first = registerDestination.call(rns, ownIdentity, DestinationStub.IN, "SINGLE", "lxmf", "delivery");
    first.listeners.push("lxmf-router");

    const second = registerDestination.call(rns, ownIdentity, DestinationStub.IN, "SINGLE", "lxmf", "delivery");

    assert.equal(second, first, "a fresh object would drop the LXMRouter listeners and silently stop delivery");
    assert.deepEqual(second.listeners, ["lxmf-router"]);
    assert.equal(rns.destinations.length, 1);
});

test("distinct IN destinations are both registered", () => {
    const rns = newRns();

    registerDestination.call(rns, ownIdentity, DestinationStub.IN, "SINGLE", "lxmf", "delivery");
    registerDestination.call(rns, peerIdentity, DestinationStub.IN, "SINGLE", "lxmf", "delivery");

    assert.equal(rns.destinations.length, 2);
});

test("only registerDestination may write to the dispatch table", () => {
    const writes = source.match(/this\.destinations\.push\(/g) ?? [];
    assert.equal(
        writes.length,
        1,
        "something other than registerDestination is pushing into the inbound dispatch table, " +
        "which bypasses the IN-only and unique-hash rules",
    );
});
