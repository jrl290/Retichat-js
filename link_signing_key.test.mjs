/**
 * REGRESSION GUARD — the link request carries the initiator's real Ed25519
 * signing key.
 *
 * RNS/Link.py __init__ (initiator): `self.sig_pub_bytes =
 * self.sig_pub.public_bytes()` from a fresh Ed25519 key, and the link request
 * is `pub_bytes + sig_pub_bytes`. The responder keeps those 32 bytes as
 * `peer_sig_pub` and checks every link-packet proof the initiator sends with
 * them (Link.validate, Packet.validate_link_proof).
 *
 * Until 2026-09-30 link.js built that half with `x25519.getPublicKey()` of the
 * Ed25519 private key: a Montgomery point, not the Ed25519 public key. The
 * link still came up (nothing in establishment checks the initiator's
 * signature), but every link-packet proof this client signed as initiator
 * failed at the peer, so the peer's receipt for that packet could only time
 * out.
 *
 * Run: node --test link_signing_key.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519";

import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import Destination from "./lib/rns/destination.js";
import Identity from "./lib/rns/identity.js";

test("the link request's signing key verifies the initiator's link proofs", () => {
    const peer = Identity.create();
    const sent = [];
    const destination = {
        hash: Buffer.alloc(16, 0x42),
        type: Destination.SINGLE,
        identity: peer,
        rns: { registerLink() {}, sendData: (raw) => sent.push(raw) },
    };
    const link = new Link();
    link.establish(destination, 1);
    link._clearEstablishmentWatchdog();

    assert.equal(sent.length, 1, "one link request went out");
    const request = Packet.fromBytes(sent[0]);
    assert.equal(request.packetType, Packet.LINKREQUEST);
    const carriedSigningKey = request.data.subarray(32, 64);

    assert.ok(
        carriedSigningKey.equals(Buffer.from(ed25519.getPublicKey(link.signaturePrivateKeyBytes))),
        "bytes 32..64 of the link request are the Ed25519 public key of the link's signing key",
    );

    // What the responder does with it (RNS/Link.py validate, on a proof of a
    // packet it sent over the link).
    const packetHash = Buffer.alloc(32, 0x5a);
    const signature = link.sign(packetHash);
    assert.equal(ed25519.verify(signature, packetHash, carriedSigningKey), true,
        "a link-packet proof signed by the initiator verifies with the key its link request carried");
});
