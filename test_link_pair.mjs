/**
 * Test support (not a test, not deployed): two real Links joined by an
 * in-process wire.
 *
 * `a` is the initiator and `b` the responder of one established link. They
 * share the link id and the derived key, as the two ends of a real link do
 * after the handshake, and each holds the other's link signing key, so link
 * packet proofs verify. Every packet one side transmits is packed for real,
 * parsed back with Packet.fromBytes and routed to the other side the way
 * reticulum.js routes inbound packets: DATA to onPacket, a RESOURCE_PRF to
 * onResourceProof, any other PROOF to onPacketProof.
 *
 * Delivery is asynchronous (one macrotask per packet), so a transfer runs as
 * a sequence of events rather than as recursion, and `drop(packet, fromName)`
 * can lose any packet on the way.
 */
import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";

export function linkPair({ rttMs = 50, drop = null } = {}) {
    const hash = crypto.randomBytes(16);
    const derivedKey = crypto.randomBytes(64);
    const wire = { a: [], b: [] };
    const make = (name, initiator) => {
        const link = new Link();
        link.name = name;
        link.initiator = initiator;
        link.status = Link.ACTIVE;
        link.hash = hash;
        link.derivedKey = derivedKey;
        link.attachedInterface = { name: `wire-${name}` };
        link.signaturePrivateKeyBytes = Buffer.from(ed25519.utils.randomPrivateKey());
        link.signaturePublicKeyBytes = Buffer.from(ed25519.getPublicKey(link.signaturePrivateKeyBytes));
        link.rtt = rttMs;
        link._updateKeepalive();
        link.activatedAt = Date.now();
        link.lastInbound = link.activatedAt;
        return link;
    };
    const a = make("a", true);
    const b = make("b", false);
    a.peerSignaturePublicKeyBytes = b.signaturePublicKeyBytes;
    b.peerSignaturePublicKeyBytes = a.signaturePublicKeyBytes;

    const route = (from, to) => (raw) => {
        const packet = Packet.fromBytes(Buffer.from(raw));
        wire[from.name].push(packet);
        if (drop && drop(packet, from.name)) return;
        setImmediate(() => {
            if (packet.packetType === Packet.DATA) to.onPacket(packet);
            else if (packet.packetType === Packet.PROOF && packet.context === Packet.RESOURCE_PRF) to.onResourceProof(packet);
            else if (packet.packetType === Packet.PROOF) to.onPacketProof(packet);
        });
    };
    a.destination = { rns: { sendData: route(a, b) } };
    b.destination = { rns: { sendData: route(b, a) } };
    return { a, b, wire };
}

/** Resolve on the first `event` the emitter fires (events are async). */
export function once(emitter, event) {
    return new Promise((resolve) => emitter.once(event, (...args) => resolve(args.length > 1 ? args : args[0])));
}

/** Let queued deliveries and events run. */
export function settle(rounds = 3) {
    let p = Promise.resolve();
    for (let i = 0; i < rounds; i++) p = p.then(() => new Promise((r) => setTimeout(r, 0)));
    return p;
}
