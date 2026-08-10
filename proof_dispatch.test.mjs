// Guards for the PROOF dispatch in Reticulum.onPacketReceived().
//
// Three different things arrive as packetType PROOF and they are told apart
// only by context. Getting that wrong is silent, so it is worth pinning:
//
//   context LRPROOF       link request proof   -> Link.validateProof()
//   context RESOURCE_PRF  resource proof       -> Link.onResourceProof()
//   context anything else delivery proof       -> emit("proof", ...)
//
// The dangerous pair is the last two. A resource proof is addressed to the LINK
// hash and carries `resourceHash + proof` as its payload. The delivery-proof
// branch takes `data.slice(0, 16)` of any link-addressed proof and treats it as
// the hash of a message it sent. Without the RESOURCE_PRF branch a resource
// proof therefore falls through and announces the delivery of a message whose
// "hash" is really the first half of a resource hash — LXMF marks an arbitrary
// outbound message delivered, and meanwhile the resource sender never gets its
// proof and the transfer hangs at the last part.
//
// The module graph resolves `@noble/curves` through the browser importmap and
// cannot be imported under Node, so — as in destination_registry.test.mjs — the
// real shipped method is lifted out of reticulum.js and run against stubs. That
// keeps this honest about behaviour instead of asserting on the file's text.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./lib/rns/reticulum.js", import.meta.url), "utf8");

function extractMethod(signature) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from reticulum.js`);

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

// Real wire values, copied from packet.js / destination.js. If those change,
// these must change with them or the test silently stops exercising the branch.
const PacketStub = {
    DATA: 0x00,
    ANNOUNCE: 0x01,
    LINKREQUEST: 0x02,
    PROOF: 0x03,
    NONE: 0x00,
    RESOURCE_PRF: 0x05,
    LRPROOF: 0xff,
};
const DestinationStub = { SINGLE: 0x00, LINK: 0x03, IN: 0x11, OUT: 0x12 };
const IdentityStub = { SIGLENGTH_IN_BYTES: 64 };
const LinkStub = { PENDING: "pending", ACTIVE: "active", ECPUBSIZE: 64 };

const body = extractMethod("onPacketReceived(packet, receivingInterface)");
const onPacketReceived = new Function(
    "Packet",
    "Destination",
    "Identity",
    "Link",
    "Announce",
    `return function onPacketReceived(packet, receivingInterface) {${body}};`,
)(PacketStub, DestinationStub, IdentityStub, LinkStub, { fromPacket: () => null });

const LINK_HASH = Buffer.from("3eeb4ea3ea504f1f8c6b1d2e5a7b9c0d", "hex");

/** A link that records which handler the dispatcher chose. */
function newLink(hash = LINK_HASH) {
    return {
        hash,
        status: LinkStub.ACTIVE,
        resourceProofs: [],
        linkProofs: [],
        dataPackets: [],
        onResourceProof(packet) { this.resourceProofs.push(packet); },
        validateProof(packet) { this.linkProofs.push(packet); },
        onPacket(packet) { this.dataPackets.push(packet); },
    };
}

function newRns(links) {
    return {
        links,
        destinations: [],
        emitted: [],
        emit(event, payload) { this.emitted.push({ event, payload }); },
        isLocalDestination: () => false,
        onAnnounceReceived: () => {},
    };
}

/** A resource proof: addressed to the link, payload is resourceHash + proof. */
function resourceProofPacket(resourceHash) {
    return {
        hops: 0,
        packetType: PacketStub.PROOF,
        context: PacketStub.RESOURCE_PRF,
        destinationType: DestinationStub.LINK,
        destinationHash: LINK_HASH,
        data: Buffer.concat([resourceHash, Buffer.alloc(64, 0xaa)]),
    };
}

const RESOURCE_HASH = Buffer.from("d7e08998ffb76881f27c649622402041", "hex");

test("a resource proof reaches the link's resource handler", () => {
    const link = newLink();
    const rns = newRns([link]);
    const packet = resourceProofPacket(RESOURCE_HASH);

    onPacketReceived.call(rns, packet, { name: "post", hash: "iface" });

    assert.equal(link.resourceProofs.length, 1, "the resource proof must be delivered to the link");
    assert.equal(link.resourceProofs[0], packet);
});

test("a resource proof is not mistaken for a delivery proof", () => {
    const link = newLink();
    const rns = newRns([link]);

    onPacketReceived.call(rns, resourceProofPacket(RESOURCE_HASH), { name: "post", hash: "iface" });

    // This is the regression. The delivery-proof branch would emit "proof" with
    // provedPacketHash = the first 16 bytes of the resource hash, and LXMF would
    // mark an unrelated outbound message delivered.
    assert.deepEqual(rns.emitted, [], "a resource proof must not be reported as a message delivery");
    assert.equal(link.linkProofs.length, 0, "and it is not a link request proof either");
});

test("an ordinary link delivery proof still emits proof", () => {
    const link = newLink();
    const rns = newRns([link]);
    const provedHash = Buffer.from("0f75ac15961b7d2b1577a57bdb1fda3c", "hex");

    onPacketReceived.call(rns, {
        hops: 0,
        packetType: PacketStub.PROOF,
        context: PacketStub.NONE,
        destinationType: DestinationStub.LINK,
        destinationHash: LINK_HASH,
        data: Buffer.concat([provedHash, Buffer.alloc(64, 0xbb)]),
    }, { name: "post", hash: "iface" });

    // Proving the branches are actually distinguishable: same packet type, same
    // link-addressed shape, different context, different destination.
    assert.equal(rns.emitted.length, 1, "delivery proofs must still be reported");
    assert.equal(rns.emitted[0].event, "proof");
    assert.ok(rns.emitted[0].payload.provedPacketHash.equals(provedHash.slice(0, 16)));
    assert.equal(link.resourceProofs.length, 0);
});

test("a resource proof for another link is not delivered to ours", () => {
    const ours = newLink();
    const theirs = newLink(Buffer.from("ad0fdccf03c04e4322a67c22bb3bc103", "hex"));
    const rns = newRns([ours, theirs]);

    const packet = resourceProofPacket(RESOURCE_HASH);
    packet.destinationHash = theirs.hash;
    onPacketReceived.call(rns, packet, { name: "post", hash: "iface" });

    assert.equal(ours.resourceProofs.length, 0, "proofs are matched by link hash, not broadcast");
    assert.equal(theirs.resourceProofs.length, 1);
});

test("a link request proof still reaches validateProof", () => {
    const link = newLink();
    link.status = LinkStub.PENDING;
    const rns = newRns([link]);

    onPacketReceived.call(rns, {
        hops: 0,
        packetType: PacketStub.PROOF,
        context: PacketStub.LRPROOF,
        destinationType: DestinationStub.LINK,
        destinationHash: LINK_HASH,
        data: Buffer.alloc(IdentityStub.SIGLENGTH_IN_BYTES + LinkStub.ECPUBSIZE / 2, 0xcc),
    }, { name: "post", hash: "iface" });

    assert.equal(link.linkProofs.length, 1, "LRPROOF must not be captured by the resource branch");
    assert.equal(link.resourceProofs.length, 0);
    assert.deepEqual(rns.emitted, []);
});
