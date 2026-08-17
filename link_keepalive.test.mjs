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
// rfed has always implemented the responder half (bounces 0xFE for every
// 0xFF), so this was purely a missing client half.
//
// keepaliveAction() is deliberately a pure static: the defect was a logic gap,
// and logic gaps belong in unit tests rather than in a 60-second integration
// wait.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";

const base = {
    now: 1000,
    lastInbound: 1000,
    lastKeepalive: 0,
    activatedAt: 900,
    keepalive: 30,
    staleTime: 60,
    initiator: true,
    status: Link.ACTIVE,
};

test("reference constants match RNS/Link.py", () => {
    assert.equal(Link.KEEPALIVE_MAX_RTT, 1.75);
    assert.equal(Link.KEEPALIVE_MAX, 360.0);
    assert.equal(Link.KEEPALIVE_MIN, 5.0);
    assert.equal(Link.STALE_FACTOR, 2.0);
    assert.equal(Link.KEEPALIVE_TIMEOUT_FACTOR, 4.0);
});

test("a fresh link is idle", () => {
    assert.equal(Link.keepaliveAction(base), "idle");
});

test("initiator pings once the keepalive interval elapses", () => {
    assert.equal(
        Link.keepaliveAction({ ...base, now: 1031 }),
        "keepalive",
        "no inbound for keepalive seconds must produce a ping",
    );
});

test("the responder never pings — it only answers", () => {
    assert.equal(
        Link.keepaliveAction({ ...base, now: 1031, initiator: false }),
        "idle",
        "only the initiator pings (reference asymmetry; rfed answers)",
    );
});

test("a link that just pinged does not ping again", () => {
    assert.equal(
        Link.keepaliveAction({ ...base, now: 1031, lastKeepalive: 1030 }),
        "idle",
    );
});

test("no inbound for staleTime goes STALE, and outranks pinging", () => {
    assert.equal(
        Link.keepaliveAction({ ...base, now: 1061, lastKeepalive: 0 }),
        "stale",
        "past staleTime another ping cannot help — the link must go STALE",
    );
});

test("STALE tears down only after the grace window", () => {
    const stale = { ...base, status: Link.STALE, staleSince: 1060, staleGrace: 10 };
    assert.equal(Link.keepaliveAction({ ...stale, now: 1065 }), "idle");
    assert.equal(Link.keepaliveAction({ ...stale, now: 1070 }), "teardown");
});

test("a zero grace window still allows at least one second", () => {
    const stale = { ...base, status: Link.STALE, staleSince: 1060, staleGrace: 0 };
    assert.equal(Link.keepaliveAction({ ...stale, now: 1060 }), "idle");
    assert.equal(Link.keepaliveAction({ ...stale, now: 1061 }), "teardown");
});

test("non-active, non-stale links are always idle", () => {
    for (const status of [Link.PENDING, Link.HANDSHAKE, Link.CLOSED]) {
        assert.equal(Link.keepaliveAction({ ...base, now: 9999, status }), "idle");
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

test("inbound traffic refreshes lastInbound before any handler can return", async () => {
    const source = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");
    const start = source.indexOf("onPacket(packet) {");
    assert.notEqual(start, -1);
    const head = source.slice(start, start + 1400);
    const refreshPos = head.indexOf("this.lastInbound = Date.now()");
    const keepalivePos = head.indexOf("Packet.KEEPALIVE");
    assert.ok(refreshPos > -1, "onPacket must refresh lastInbound");
    assert.ok(
        keepalivePos === -1 || refreshPos < keepalivePos,
        "lastInbound must be refreshed BEFORE the keepalive branch returns — " +
        "otherwise a link carrying nothing but keepalives is declared stale",
    );
});
