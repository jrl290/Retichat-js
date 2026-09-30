// REGRESSION GUARD — do not delete, do not weaken.
//
// Link establishment must always reach a terminal state.
//
//   Reticulum-master/RNS/Link.py  __watchdog_job (line 772)
//     while self.status == Link.PENDING (or HANDSHAKE):
//         if time.time() >= self.request_time + self.establishment_timeout:
//             self.status = Link.CLOSED
//             self.teardown_reason = Link.TIMEOUT
//             self.link_closed()          # fires the closed callbacks
//
// This stack did not implement that transition (link.js carried a literal
// "// todo start watchdog"). A link whose LINKREQUEST was lost in transit
// stayed PENDING forever and never emitted "close".
//
// Why that was fatal rather than merely untidy: app.js settles its
// establishment promise ONLY from the "established" and "close" events
// (_establishPropagationLink). _ensurePropagationLink() hands that promise to
// every caller, and _retryPropagationLink() drives its retry loop from the
// promise REJECTING. So one lost LINKREQUEST wedged the client permanently:
//
//   [retichat] 🔗 Establishing propagation link to 0f75ac15961b...
//   [retichat] ✉️ SEND to 70ecb427e01b... content="s3-32682275"
//   <silence for the rest of the run — no send, no retry, no error>
//
// The browser's LINKREQUEST was accepted by its local PHP node (inbound
// packet 6820527, hops=1, filter_status=accepted) but never arrived at the
// propagation node, which logged no LINKREQUEST for 65 seconds either side.
//
// This is NOT "a timeout as a fix" — it does not make establishment faster or
// more likely to succeed. It restores the reference implementation's
// guarantee that an attempt terminates, so the existing retry path can run.
//
// These drive a real Link (link.js imports under Node through package.json's
// devDependencies), so they test the shipped behaviour rather than the text of
// the file. Events are recorded synchronously by replacing the instance's emit.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import test, { mock } from "node:test";

import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";

const linkSource = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");

function extractMethod(source, signature, label) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from ${label}`);

    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
            depth--;
            if (depth === 0) return source.slice(bodyStart + 1, i);
        }
    }
    throw new Error(`could not brace-match ${signature} in ${label}`);
}

/** A PENDING link wired to the real shipped watchdog. */
function makeLink(establishmentTimeout) {
    const link = new Link();
    link.status = Link.PENDING;
    link.establishmentTimeout = establishmentTimeout;
    link.hash = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    link.events = [];
    link.emit = function (name) { this.events.push(name); };
    return link;
}

test("establishment constants match the Python reference", () => {
    // RNS/Reticulum.py:144  DEFAULT_PER_HOP_TIMEOUT = 6
    // RNS/Link.py:75        ESTABLISHMENT_TIMEOUT_PER_HOP = DEFAULT_PER_HOP_TIMEOUT
    // RNS/Link.py:116       TIMEOUT = 0x01
    assert.match(linkSource, /static DEFAULT_PER_HOP_TIMEOUT = 6;/);
    assert.match(linkSource, /static ESTABLISHMENT_TIMEOUT_PER_HOP = 6;/);
    assert.match(linkSource, /static TIMEOUT = 0x01;/);
});

test("establish() arms the watchdog", () => {
    const body = extractMethod(linkSource, "establish(destination, hops = Link.DEFAULT_ESTABLISHMENT_HOPS)", "link.js");
    assert.match(body, /this\._startEstablishmentWatchdog\(\)/,
        "establish() must arm the watchdog, or a lost LINKREQUEST hangs forever");
    assert.match(body, /Link\.DEFAULT_PER_HOP_TIMEOUT\s*\n?\s*\+\s*Link\.ESTABLISHMENT_TIMEOUT_PER_HOP \* Math\.max\(1, hops\)/,
        "establishment_timeout must follow the reference formula");
});

test("a link still PENDING at the deadline closes with reason TIMEOUT", () => {
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
        const link = makeLink(30_000);
        link._startEstablishmentWatchdog();

        mock.timers.tick(29_999);
        assert.deepEqual(link.events, [], "must not close before the deadline");
        assert.equal(link.status, Link.PENDING);

        mock.timers.tick(1);
        assert.deepEqual(link.events, ["close"], "a stalled establishment must emit close");
        assert.equal(link.status, Link.CLOSED);
        assert.equal(link.closeReason, Link.TIMEOUT);
    } finally {
        mock.timers.reset();
    }
});

test("a link that becomes ACTIVE is never closed by the watchdog", () => {
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
        const link = makeLink(30_000);
        link._startEstablishmentWatchdog();

        // onLinkRequestRtt() clears the watchdog before activating the link.
        link._clearEstablishmentWatchdog();
        link.status = Link.ACTIVE;

        mock.timers.tick(120_000);
        assert.deepEqual(link.events, [], "an established link must never be torn down by the watchdog");
        assert.equal(link.status, Link.ACTIVE);
    } finally {
        mock.timers.reset();
    }
});

test("the watchdog is disarmed on every terminal transition", () => {
    // onLinkRequestRtt() disarms it before activating the responder's link.
    const body = extractMethod(linkSource, "onLinkRequestRtt(packet)", "link.js");
    assert.match(body, /this\._clearEstablishmentWatchdog\(\)/,
        "onLinkRequestRtt(packet) must disarm the watchdog");

    // close(), and a LINKCLOSE from the peer, on a link that has its keys.
    const keyed = () => {
        const link = makeLink(30_000);
        link.status = Link.HANDSHAKE;
        link.derivedKey = crypto.randomBytes(64);
        link.attachedInterface = { name: "test" };
        link.destination = { rns: { sendData() {} } };
        link._startEstablishmentWatchdog();
        assert.ok(link._establishmentTimer, "armed");
        return link;
    };
    const closed = keyed();
    closed.close();
    assert.equal(closed._establishmentTimer, null, "close() must disarm the watchdog");
    assert.deepEqual(closed.events, ["close"]);

    const peerClosed = keyed();
    peerClosed.onPacket({ context: Packet.LINKCLOSE, data: peerClosed.encrypt(peerClosed.hash) });
    assert.equal(peerClosed.status, Link.CLOSED);
    assert.equal(peerClosed._establishmentTimer, null, "the LINKCLOSE branch must disarm the watchdog");
    assert.deepEqual(peerClosed.events, ["close"]);
});
