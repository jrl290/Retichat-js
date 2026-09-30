// REGRESSION GUARD — do not delete, do not weaken.
//
// The client must keep its links alive. Until 2026-08-17 it sent no KEEPALIVE
// packets at all: RNS/Link.py's __watchdog_job had never been ported. On a
// quiet link the intermediate transport nodes' link tables expired while this
// client still reported ACTIVE, so requests were accepted locally and then
// vanished in transit with no error at either end. Measured that day:
// /rfed/pull burned its full 43-49s budget on links a few minutes old, while a
// freshly-established link answered normally.
//
// 2026-09-30: parity with the RNS 1.5.2 watchdog (Link.py:743-766,
// 1131-1135, 938). On 2026-09-29 (stage_sim section c) an idle web client's
// rfed.link went STALE and closed silently: rfed's 1.5.2 pong gate skipped
// the client's only ping, the client sent no final keepalive at the stale
// tick, and its timeout teardown sent no LINKCLOSE, so rfed kept pushing into
// a link the browser had dropped. The tests below pin the four halves:
// the final keepalive on entering STALE, the quiet-outbound trigger, the
// LINKCLOSE on the timeout teardown, and the responder's pong gate.
//
// keepaliveAction() is deliberately a pure static: the defect was a logic gap,
// and logic gaps belong in unit tests rather than in a 60-second integration
// wait. The behavioural tests drive a real Link through _watchdogStep() and
// onPacket() with a fake wire.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { ed25519, x25519 } from "@noble/curves/ed25519";

import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import Identity from "./lib/rns/identity.js";
import MsgPack from "./lib/rns/msgpack.js";
import Resource from "./lib/rns/resource.js";

const base = {
    now: 1000,
    lastInbound: 1000,
    lastOutbound: 1000,
    lastKeepalive: 0,
    activatedAt: 900,
    keepalive: 30,
    staleTime: 60,
    initiator: true,
    status: Link.ACTIVE,
};
const IDLE = { ping: false, next: "idle" };

/** A real, keyed, ACTIVE link whose wire is an array of parsed packets. */
function liveLink({ initiator = true, rttMs = 500 } = {}) {
    const link = new Link();
    link.initiator = initiator;
    link.status = Link.ACTIVE;
    link.hash = crypto.randomBytes(16);
    link.derivedKey = crypto.randomBytes(64);
    link.attachedInterface = { name: "test" };
    link.signaturePrivateKeyBytes = Buffer.from(ed25519.utils.randomPrivateKey());
    link.rtt = rttMs;
    link._updateKeepalive();
    link.activatedAt = Date.now();
    const wire = [];
    link.destination = { rns: { sendData: (raw) => wire.push(Packet.fromBytes(raw)) } };
    return { link, wire };
}

const pkt = (context, data) => ({ context, data: Buffer.from(data) });
// Listeners run on a later macrotask (utils/events.js).
const afterLinkEvents = () => new Promise((resolve) => setTimeout(resolve, 0));

test("reference constants match RNS/Link.py", () => {
    assert.equal(Link.KEEPALIVE_MAX_RTT, 1.75);
    assert.equal(Link.KEEPALIVE_MAX, 360.0);
    assert.equal(Link.KEEPALIVE_MIN, 5.0);
    assert.equal(Link.STALE_FACTOR, 2.0);
    assert.equal(Link.KEEPALIVE_TIMEOUT_FACTOR, 4.0);
    assert.equal(Link.STALE_GRACE, 5.0);
});

// ── keepaliveAction: the pure decision ────────────────────────────────────

test("a fresh link is idle", () => {
    assert.deepEqual(Link.keepaliveAction(base), IDLE);
});

test("initiator pings once the keepalive interval elapses", () => {
    assert.deepEqual(
        Link.keepaliveAction({ ...base, now: 1031 }),
        { ping: true, next: "idle" },
        "no traffic for keepalive seconds must produce a ping",
    );
});

test("the responder never pings — it only answers", () => {
    assert.deepEqual(Link.keepaliveAction({ ...base, now: 1031, initiator: false }), IDLE,
        "only the initiator pings (reference asymmetry; rfed answers)");
});

test("a link that just pinged does not ping again", () => {
    // The ping itself is outbound traffic.
    assert.deepEqual(Link.keepaliveAction({ ...base, now: 1031, lastKeepalive: 1030, lastOutbound: 1030 }), IDLE);
});

test("quiet outbound alone triggers a ping (Link.py:749)", () => {
    // The peer has been sending (heard 11 s ago), this side has sent nothing
    // for a keepalive period. The peer hears nothing from us, so without a
    // ping it would time the link out at its own stale time.
    assert.deepEqual(
        Link.keepaliveAction({ ...base, now: 1031, lastInbound: 1020, lastOutbound: 1000 }),
        { ping: true, next: "idle" },
    );
});

test("at the stale tick the initiator sends a final ping and goes STALE (Link.py:749-755)", () => {
    // The watchdog ticks every second from when it started, not from the
    // ping: here the regular ping went out 0.9 s after heard+K, so at the
    // first tick past stale_time the last keepalive is only 29.3 s old. The
    // reference's contract still sends the final keepalive.
    const heard = 1000;
    assert.deepEqual(
        Link.keepaliveAction({ ...base, lastInbound: heard, lastOutbound: heard + 30.9, lastKeepalive: heard + 30.9, now: heard + 60.2 }),
        { ping: true, next: "stale" },
    );
    // Aligned ticks: the same decision.
    assert.deepEqual(
        Link.keepaliveAction({ ...base, lastInbound: heard, lastOutbound: heard + 30, lastKeepalive: heard + 30, now: heard + 60 }),
        { ping: true, next: "stale" },
    );
    // A responder goes STALE without pinging.
    assert.deepEqual(
        Link.keepaliveAction({ ...base, initiator: false, lastInbound: heard, now: heard + 60.2 }),
        { ping: false, next: "stale" },
    );
});

test("a proved packet counts as hearing the peer", () => {
    // RNS/Link.py: last heard = max(last_inbound, last_proof, activated_at).
    assert.deepEqual(
        Link.keepaliveAction({ ...base, lastInbound: 900, lastProof: 1020, lastOutbound: 1020, now: 1031 }),
        IDLE,
    );
    assert.equal(
        Link.keepaliveAction({ ...base, lastInbound: 900, lastProof: 0, lastOutbound: 1020, now: 1031 }).next,
        "stale",
        "without the proof the same link is past its stale time",
    );
});

test("STALE tears down only after the grace window", () => {
    const stale = { ...base, status: Link.STALE, staleSince: 1060, staleGrace: 10 };
    assert.deepEqual(Link.keepaliveAction({ ...stale, now: 1065 }), IDLE);
    assert.deepEqual(Link.keepaliveAction({ ...stale, now: 1070 }), { ping: false, next: "teardown" });
});

test("a zero grace window still allows at least one second", () => {
    const stale = { ...base, status: Link.STALE, staleSince: 1060, staleGrace: 0 };
    assert.deepEqual(Link.keepaliveAction({ ...stale, now: 1060 }), IDLE);
    assert.equal(Link.keepaliveAction({ ...stale, now: 1061 }).next, "teardown");
});

test("non-active, non-stale links are always idle", () => {
    for (const status of [Link.PENDING, Link.HANDSHAKE, Link.CLOSED]) {
        assert.deepEqual(Link.keepaliveAction({ ...base, now: 9999, status }), IDLE);
    }
});

test("keepalive interval scales from RTT and clamps to the reference bounds", async () => {
    const source = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");
    assert.match(source, /_updateKeepalive\(\)\s*\{/, "_updateKeepalive must exist");

    // Drive the real method against a bare object.
    const proto = Link.prototype;
    const probe = (rttMs) => {
        const o = { rtt: rttMs };
        proto._updateKeepalive.call(o);
        return o;
    };
    // A LAN-fast link floors at KEEPALIVE_MIN.
    assert.equal(probe(1).keepalive, Link.KEEPALIVE_MIN);
    // The formula reaches KEEPALIVE_MAX exactly at KEEPALIVE_MAX_RTT (1.75s)
    // and clamps beyond it.
    assert.equal(probe(1750).keepalive, Link.KEEPALIVE_MAX);
    assert.equal(probe(60_000).keepalive, Link.KEEPALIVE_MAX);
    // Something in between scales linearly.
    const mid = probe(500);
    assert.ok(mid.keepalive > Link.KEEPALIVE_MIN && mid.keepalive < Link.KEEPALIVE_MAX,
        `rtt=500ms should scale between the bounds, got ${mid.keepalive}`);
    assert.equal(mid.staleTime, mid.keepalive * Link.STALE_FACTOR);

    // Sanity against the deployment this client actually runs on: measured
    // RTT here is 3-6s, far above KEEPALIVE_MAX_RTT, so every real link uses
    // KEEPALIVE_MAX = 360s. That must stay comfortably under the PHP node's
    // link_transport_ttl_seconds (900s, config.template.toml) or the relay
    // drops the link table entry between pings and the keepalives accomplish
    // nothing. 360 < 900 holds with margin; if either constant moves, this
    // assertion is where the conflict surfaces.
    const liveRtt = probe(5_000);
    assert.equal(liveRtt.keepalive, Link.KEEPALIVE_MAX);
    assert.ok(liveRtt.keepalive < 900,
        "keepalive interval must stay under the PHP relay's link TTL (900s)");
});

test("KEEPALIVE packets are NOT encrypted", async () => {
    const source = await readFile(new URL("./lib/rns/packet.js", import.meta.url), "utf8");
    assert.equal(Packet.KEEPALIVE, 0xFA, "wire constant must match the reference");
    assert.match(
        source,
        /this\.context === Packet\.KEEPALIVE\)\{[\s\S]{0,700}?ciphertext = this\.data/,
        "KEEPALIVE must bypass encryption — the peer handles it before its " +
        "decrypt step, and a 48-byte encrypted token is silently dropped there, " +
        "which stops last_inbound refreshing and kills the link anyway",
    );
    // ...but the neighbouring link contexts must still be encrypted.
    assert.doesNotMatch(
        source,
        /context >= Packet\.KEEPALIVE/,
        "LINKIDENTIFY (0xFB) and LRRTT (0xFE) sit above KEEPALIVE numerically " +
        "but ARE encrypted — a range check here breaks both",
    );
});

// ── The watchdog on a real link ───────────────────────────────────────────

test("a STALE timeout sends LINKCLOSE before it closes, with reason TIMEOUT (Link.py:761-766)", async () => {
    const { link, wire } = liveLink({ initiator: true, rttMs: 500 });
    const K = link.keepalive * 1000;
    const heard = Date.now();
    link.lastInbound = heard;
    link.activatedAt = heard;
    link.lastOutbound = heard;
    const order = [];
    link.on("close", () => order.push("close"));
    const originalSendData = link.destination.rns.sendData;
    link.destination.rns.sendData = (raw) => { order.push(`tx:${raw[18].toString(16)}`); originalSendData(raw); };

    // The regular ping, a keepalive period after the last traffic.
    link._watchdogStep(heard + K + 900);
    assert.equal(wire.length, 1);
    assert.equal(wire[0].context, Packet.KEEPALIVE);
    assert.deepEqual([...wire[0].data], [0xFF]);
    assert.equal(link.status, Link.ACTIVE);
    // _transmit stamps the real clock; put the ping where the simulated
    // clock had it, 0.9 s after heard + K, as a real 1 s tick would.
    link.lastKeepalive = link.lastOutbound = heard + K + 900;

    // The stale tick, 0.2 s past stale_time and so 29.3 s after that ping:
    // the final ping goes out first, then the link is STALE.
    link._watchdogStep(heard + 2 * K + 200);
    assert.equal(wire.length, 2, "the final keepalive");
    assert.equal(wire[1].context, Packet.KEEPALIVE);
    assert.deepEqual([...wire[1].data], [0xFF]);
    assert.equal(link.status, Link.STALE);

    // Grace (rtt*4 + 5 s) not over yet: nothing.
    link._watchdogStep(link.staleSince + link.staleGrace * 1000 - 100);
    assert.equal(link.status, Link.STALE);
    assert.equal(wire.length, 2);

    // Grace over: LINKCLOSE carrying the link id, then CLOSED / TIMEOUT.
    link._watchdogStep(link.staleSince + link.staleGrace * 1000);
    assert.equal(wire.length, 3);
    assert.equal(wire[2].context, Packet.LINKCLOSE, "the teardown packet");
    assert.ok(link.decrypt(wire[2].data).equals(link.hash), "LINKCLOSE carries the link id, encrypted");
    assert.equal(link.status, Link.CLOSED);
    assert.equal(link.closeReason, Link.TIMEOUT);
    await afterLinkEvents();
    assert.deepEqual(order, ["tx:fa", "tx:fa", "tx:fc", "close"]);
});

test("a peer that answers the final keepalive keeps the link", async () => {
    const { link, wire } = liveLink({ initiator: true });
    const K = link.keepalive * 1000;
    const heard = Date.now() - 2 * K - 200;
    Object.assign(link, { lastInbound: heard, activatedAt: heard, lastOutbound: heard + K, lastKeepalive: heard + K });
    link._watchdogStep(Date.now());
    assert.equal(link.status, Link.STALE);
    link.onPacket(pkt(Packet.KEEPALIVE, [0xFE]));
    assert.equal(link.status, Link.ACTIVE, "the pong recovers it");
    link._watchdogStep(Date.now() + 60_000);
    assert.notEqual(link.status, Link.CLOSED);
    assert.equal(wire.filter((p) => p.context === Packet.LINKCLOSE).length, 0);
});

test("the responder pongs only when its outbound has been quiet for a keepalive (Link.py:1131-1135)", () => {
    const { link, wire } = liveLink({ initiator: false });
    const K = link.keepalive * 1000;

    link.lastOutbound = Date.now() - K + 5_000;       // spoke 5 s inside the period
    link.onPacket(pkt(Packet.KEEPALIVE, [0xFF]));
    assert.equal(wire.length, 0, "recent outbound already told the initiator the link is alive");

    link.lastOutbound = Date.now() - K - 1;           // quiet for a full period
    link.onPacket(pkt(Packet.KEEPALIVE, [0xFF]));
    assert.equal(wire.length, 1);
    assert.equal(wire[0].context, Packet.KEEPALIVE);
    assert.deepEqual([...wire[0].data], [0xFE]);
    assert.ok(Date.now() - link.lastOutbound < 1000, "the pong counts as outbound");
    assert.equal(link.lastKeepalive, link.lastOutbound, "as a keepalive");

    link.onPacket(pkt(Packet.KEEPALIVE, [0xFF]));
    assert.equal(wire.length, 1, "a second ping right after is not answered again");
});

test("an initiator ignores a ping entirely (Link.py:938)", async () => {
    const { link, wire } = liveLink({ initiator: true });
    link.status = Link.STALE;
    link.staleSince = Date.now();
    link.lastInbound = 1234;
    const seen = [];
    link.on("recovered", () => seen.push("recovered"));
    link.onPacket(pkt(Packet.KEEPALIVE, [0xFF]));
    await afterLinkEvents();
    assert.equal(link.status, Link.STALE, "a ping is not the peer answering");
    assert.equal(link.lastInbound, 1234, "and does not count as inbound");
    assert.equal(wire.length, 0, "nor is it answered");
    assert.deepEqual(seen, []);
});

test("inbound traffic refreshes lastInbound before any handler can return", () => {
    const { link } = liveLink({ initiator: true });
    link.lastInbound = 1;
    link.onPacket(pkt(Packet.KEEPALIVE, [0xFE]));
    assert.ok(link.lastInbound > 1, "a link carrying nothing but keepalives is not stale");
    link.lastInbound = 1;
    // A resource request that does not decrypt returns early; it was still heard.
    link.onPacket(pkt(Packet.RESOURCE_REQ, crypto.randomBytes(40)));
    assert.ok(link.lastInbound > 1);
});

test("every link send updates lastOutbound; only a keepalive updates lastKeepalive", () => {
    const { link, wire } = liveLink({ initiator: true });
    const identity = Identity.create();
    const sends = {
        "send()": () => link.send(Buffer.from("hello")),
        "identify()": () => link.identify(identity),
        "sendRequest()": () => link.sendRequest("/path", null),
        "sendResponse()": () => link.sendResponse(Buffer.alloc(16, 1), true),
        "proveLinkPacket()": () => link.proveLinkPacket({ packetHash: crypto.randomBytes(32) }),
        "a Resource advertisement": () => { Resource.send(link, Buffer.alloc(2000, 7)).catch(() => {}); },
    };
    for (const [name, send] of Object.entries(sends)) {
        link.lastOutbound = 0;
        link.lastKeepalive = 7;
        const before = wire.length;
        send();
        assert.ok(wire.length > before, `${name} put a packet on the wire`);
        assert.ok(link.lastOutbound > 0, `${name} updates lastOutbound`);
        assert.equal(link.lastKeepalive, 7, `${name} is not a keepalive`);
    }
    for (const r of [...link.outgoingResources]) r.fail("test over");

    link.lastOutbound = 0;
    link._sendKeepalive();
    assert.ok(link.lastOutbound > 0);
    assert.equal(link.lastKeepalive, link.lastOutbound, "a keepalive updates both");

    link.lastOutbound = 0;
    link.close();
    assert.ok(link.lastOutbound > 0, "the teardown packet is outbound too");
});

test("the RTT packet is outbound traffic, so the quiet-outbound clock starts at activation", () => {
    const peer = Identity.create();
    const link = new Link();
    const sent = [];
    const destination = { hash: Buffer.alloc(16, 9), type: 0, identity: peer,
        rns: { registerLink() {}, activateLink(l) { l.status = Link.ACTIVE; l.activatedAt = Date.now(); }, sendData: (raw) => sent.push(raw) } };
    link.establish(destination, 1);
    link._clearEstablishmentWatchdog();
    // Answer as the responder would: an ephemeral X25519 key, and a signature
    // by the destination identity over link id | that key | its signing key.
    const responderPub = Buffer.from(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
    const signed = Buffer.concat([link.hash, responderPub, peer.signaturePublicKeyBytes]);
    const proof = { data: Buffer.concat([peer.sign(signed), responderPub]), receivingInterface: { name: "if" } };
    link.lastOutbound = 0;
    link.validateProof(proof);
    link._clearKeepaliveWatchdog();
    assert.equal(link.status, Link.ACTIVE);
    const rttPacket = Packet.fromBytes(sent.at(-1));
    assert.equal(rttPacket.context, Packet.LRRTT);
    assert.ok(link.lastOutbound > 0, "the RTT packet set lastOutbound");
});

test("the responder reads the initiator's reported RTT as seconds (RNS/Link.py rtt_packet)", () => {
    const { link } = liveLink({ initiator: false });
    link.status = Link.HANDSHAKE;
    link.requestTime = Date.now() - 400;                   // measured ~400 ms
    link.destination.rns.activateLink = (l) => { l.status = Link.ACTIVE; };
    const packet = { data: link.encrypt(MsgPack.pack(2.0)) }; // the initiator measured 2 s
    link.onLinkRequestRtt(packet);
    link._clearKeepaliveWatchdog();
    assert.equal(link.rtt, 2000, "max(measured 400 ms, reported 2 s) is 2000 ms");
    assert.equal(link.keepalive, Math.min(Link.KEEPALIVE_MAX, 2.0 * (Link.KEEPALIVE_MAX / Link.KEEPALIVE_MAX_RTT)));
});

test("a resource proof is inbound traffic: it refreshes lastInbound and recovers a STALE link", () => {
    // RNS/Transport.py:2722-2724 hands a RESOURCE_PRF to link.receive().
    const { link } = liveLink({ initiator: true });
    link.status = Link.STALE;
    link.staleSince = Date.now();
    link.lastInbound = 1;
    link.onResourceProof({ context: Packet.RESOURCE_PRF, data: Buffer.alloc(64, 3) });
    assert.ok(link.lastInbound > 1);
    assert.equal(link.status, Link.ACTIVE);
});

test("a valid proof from the peer sets lastProof; a forged one does not", () => {
    const { link } = liveLink({ initiator: true });
    const peerKey = Buffer.from(ed25519.utils.randomPrivateKey());
    link.peerSignaturePublicKeyBytes = Buffer.from(ed25519.getPublicKey(peerKey));
    const packetHash = crypto.randomBytes(32);
    link.lastProof = 0;
    assert.equal(link.onPacketProof({ data: Buffer.concat([packetHash, Buffer.alloc(64, 1)]) }), false);
    assert.equal(link.lastProof, 0);
    assert.equal(link.onPacketProof({ data: Buffer.concat([packetHash, Buffer.from(ed25519.sign(packetHash, peerKey))]) }), true);
    assert.ok(link.lastProof > 0);
});

test("a STALE link that hears its peer is ACTIVE again and says so, once", async () => {
    // Recovery is the one STALE -> ACTIVE transition. Before 2026-09-24 it
    // emitted nothing, so anything waiting for ACTIVE (the §17.11 sent-copy's
    // _whenPropagationLinkUp) stayed queued until a teardown and a fresh
    // "established" that might never come. It is the same link, so
    // "established" must NOT fire: its handlers identify, flush and pull.
    const link = new Link();
    link.initiator = true;
    link.status = Link.STALE;
    link.staleSince = Date.now();
    const seen = [];
    for (const event of ["recovered", "established", "close"]) {
        link.on(event, () => seen.push(event));
    }
    const pong = { context: Packet.KEEPALIVE, data: Buffer.from([0xFE]) };

    link.onPacket(pong);
    assert.equal(link.status, Link.ACTIVE);
    assert.equal(link.staleSince, null);
    await afterLinkEvents();
    assert.deepEqual(seen, ["recovered"]);

    // Traffic on a link that is already ACTIVE is not a recovery.
    link.onPacket(pong);
    await afterLinkEvents();
    assert.deepEqual(seen, ["recovered"], "only the STALE -> ACTIVE transition emits");
});
