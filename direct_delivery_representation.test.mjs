/**
 * REGRESSION GUARD — how a direct (1:1) LXMF message reaches its peer.
 *
 * LXMF/LXMessage.py pack(): content up to 295 bytes goes as one packet to
 * the destination; larger content goes over a link, as one link packet up
 * to 319 bytes of content and as a Resource above that. Until 2026-09-23
 * _sendPacket sent one packet whatever the size. Packet.pack() has its MTU
 * check disabled, so a 722-character message left the browser as an
 * oversized packet that every hop dropped silently — the phone never saw
 * a link request, and the web console showed only "SEND to".
 *
 * Run: node --test direct_delivery_representation.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import Constants from "./lib/rns/constants.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

test("the size limits match the reference with default RNS parameters", () => {
    assert.equal(Constants.PACKET_ENCRYPTED_MDU, 383, "RNS.Packet.ENCRYPTED_MDU");
    assert.equal(Constants.LINK_MDU, 431, "RNS.Link.MDU");
    assert.equal(LXMessage.LXMF_OVERHEAD, 112);
    assert.equal(LXMessage.ENCRYPTED_PACKET_MAX_CONTENT, 295);
    assert.equal(LXMessage.LINK_PACKET_MAX_CONTENT, 319);
});

const packedWithContent = (contentSize) => Buffer.alloc(LXMessage.LXMF_OVERHEAD + contentSize);

test("the plan follows LXMessage.pack() at each boundary", () => {
    const plan = (contentSize) => LXMessage.deliveryPlan(packedWithContent(contentSize));
    assert.deepEqual(plan(0), { method: LXMessage.OPPORTUNISTIC, representation: LXMessage.PACKET });
    assert.deepEqual(plan(295), { method: LXMessage.OPPORTUNISTIC, representation: LXMessage.PACKET });
    assert.deepEqual(plan(296), { method: LXMessage.DIRECT, representation: LXMessage.PACKET });
    assert.deepEqual(plan(319), { method: LXMessage.DIRECT, representation: LXMessage.PACKET });
    assert.deepEqual(plan(320), { method: LXMessage.DIRECT, representation: LXMessage.RESOURCE });
    assert.deepEqual(plan(722), { method: LXMessage.DIRECT, representation: LXMessage.RESOURCE });
});

test("a link packet or Resource carries the whole packing, a destination packet drops the hash", () => {
    // Reference __as_packet: OPPORTUNISTIC sends packed[16:], DIRECT sends packed.
    const start = app.indexOf("    _sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError) {");
    assert.notEqual(start, -1);
    const body = app.slice(start, app.indexOf("\n    },", start));
    assert.match(body, /msg\.pack\(sender\.identity, false\)/, "packs with the destination hash");
    assert.match(body, /LXMessage\.deliveryPlan\(packed\)/, "asks the reference rule");
    assert.match(body, /dest\.send\(packed\.subarray\(LXMessage\.DESTINATION_LENGTH\)\)/, "destination packet omits the hash");
    assert.match(body, /_sendOverPeerLink\(/, "direct delivery goes to the link path");
    assert.doesNotMatch(body, /msg\.pack\(sender\.identity, true\)/, "no unconditional single packet");
});

test("the link path sends a link packet or a Resource and reports failure", () => {
    const start = app.indexOf("    _sendOverPeerLink(");
    assert.notEqual(start, -1);
    const body = app.slice(start, app.indexOf("\n    },", start));
    assert.match(body, /_ensureGroupLink\(contactHash, publicKeyHex\)/, "reuses the per-peer delivery link");
    assert.match(body, /link\.sendResource\(packed\)/, "Resource carries the whole packing");
    assert.match(body, /link\.send\(packed\)/, "link packet carries the whole packing");
    assert.match(body, /_pendingPacketHashes\.set\(truncatedHex/, "link packet proof is matched");
    assert.match(body, /onError\(messageId\)/, "a failed link or transfer marks the message failed");
});
