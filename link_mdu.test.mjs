// REGRESSION GUARD — do not delete, do not weaken.
//
// A link data packet carries at most Link.MDU bytes of plaintext. That is a
// protocol constant derived from the Reticulum MTU, not a tunable:
//
//   Reticulum-master/RNS/Link.py
//     MDU = floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD)
//                 / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
//     MTU=500, IFAC_MIN_SIZE=1, HEADER_MINSIZE=2+1+16=19,
//     TOKEN_OVERHEAD=48, AES128_BLOCKSIZE=16  =>  431
//
// When Link.send() did not check this, a long channel message produced an
// over-MTU frame. Our PHP PostInterface answered:
//
//   POST /reticulum/v1/interfaces/exchange 400 (Bad Request)
//   [http-exchange] Exchange failed: HTTP 400: {"error":"packet too large","index":0}
//
// and the user saw the unrelated-looking
// "No RFed stream acceptance for #public.general within 10 seconds",
// because the 400 rejects the WHOLE exchange batch — every other packet
// queued alongside the oversized one is discarded too.
//
// Raising max_packet_bytes is NOT the fix. 500 is the Reticulum MTU; inflating
// it would make us incompatible with every conformant node.
//
// The module graph resolves `@noble/curves` through the browser importmap, so
// it cannot be imported under Node. We lift the real shipped methods out of
// the sources and run them against stubs, so this tests actual behaviour
// rather than the text of the files.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import Constants from "./lib/rns/constants.js";

const linkSource = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");
const postSource = await readFile(new URL("./lib/rns/interfaces/post_interface.js", import.meta.url), "utf8");

function extractMethod(source, signature, label) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from ${label}`);

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
    throw new Error(`could not brace-match ${signature} in ${label}`);
}

// The value the Python reference computes.
const REFERENCE_MDU = Math.floor((500 - 1 - 19 - 48) / 16) * 16 - 1;

// Link.MDU is defined in terms of Constants so that resource.js can use the
// same figure without importing link.js, so read it from there.
function shippedMdu() {
    assert.match(linkSource, /static MDU\s*=\s*Constants\.LINK_MDU;/, "Link.MDU no longer comes from Constants.LINK_MDU");
    return Constants.LINK_MDU;
}

class PacketStub {
    pack() {
        this.packed = true;
        return { length: 0 };
    }
}

function makeLink(mdu, sent) {
    const body = extractMethod(linkSource, "send(data)", "link.js");
    const builderBody = extractMethod(linkSource, "newLinkPacket(context, data, packetType)", "link.js");
    const scope = (source, args) => new Function("Link", "Packet", "Transport", "Destination", source)(
        { MDU: mdu },
        PacketStub,
        { BROADCAST: "BROADCAST" },
        { LINK: "LINK" },
        ...args,
    );
    const send = scope(`return function send(data) {${body}};`, []);
    const newLinkPacket = scope(
        `return function newLinkPacket(context, data, packetType) {${builderBody}};`,
        [],
    );
    return {
        hash: "hash",
        attachedInterface: "iface",
        destination: { rns: { sendData: (raw, iface) => sent.push({ raw, iface }) } },
        send,
        newLinkPacket,
    };
}

test("Link.MDU matches the Python reference", () => {
    assert.equal(shippedMdu(), REFERENCE_MDU);
    assert.equal(shippedMdu(), 431);
});

test("a payload at the MDU is sent", () => {
    const sent = [];
    const link = makeLink(REFERENCE_MDU, sent);
    link.send(Buffer.alloc(REFERENCE_MDU));
    assert.equal(sent.length, 1);
});

test("a payload one byte over the MDU is refused, not transmitted", () => {
    const sent = [];
    const link = makeLink(REFERENCE_MDU, sent);
    assert.throws(
        () => link.send(Buffer.alloc(REFERENCE_MDU + 1)),
        /exceeds the link MDU/,
    );
    assert.equal(sent.length, 0, "an over-MTU frame must never reach the interface");
});

test("PostInterface refuses to queue a packet larger than the node advertised", () => {
    const body = extractMethod(postSource, "sendData(data)", "post_interface.js");
    const sendData = new Function(`return function sendData(data) {${body}};`)();

    const errors = [];
    const originalError = console.error;
    console.error = (msg) => errors.push(msg);
    try {
        const iface = {
            _maxPacketBytes: 500,
            _outboundQueue: [],
            _flushIfIdle() { this.flushed = (this.flushed ?? 0) + 1; },
            sendData,
        };

        iface.sendData(Buffer.alloc(500));
        assert.equal(iface._outboundQueue.length, 1, "a conforming packet must still be queued");

        iface.sendData(Buffer.alloc(501));
        assert.equal(
            iface._outboundQueue.length,
            1,
            "an oversized packet must not be queued: it would 400 the whole batch and take every other queued packet with it",
        );
        assert.equal(errors.length, 1, "the drop must be reported loudly, never silently");
    } finally {
        console.error = originalError;
    }
});

test("the channel sender checks the payload before mining the stamp", async () => {
    const appSource = await readFile(new URL("./app.js", import.meta.url), "utf8");
    const send = appSource.indexOf("sendChannelMessage");
    assert.notEqual(send, -1);

    const guard = appSource.indexOf("Link.MDU", send);
    const mine = appSource.indexOf("channelComputeStamp(", send);
    assert.notEqual(guard, -1, "sendChannelMessage must size-check against Link.MDU");
    assert.ok(
        guard < mine,
        "the size check must run before the proof-of-work, otherwise the stamp is mined for a packet that cannot be sent",
    );
});
