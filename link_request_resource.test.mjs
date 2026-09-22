/**
 * Requests and responses that do not fit one link packet travel as Resources.
 *
 * RNS/Link.py request(): `if len(packed_request) <= self.mdu` the request is a
 * REQUEST packet, otherwise the packed request goes as a Resource flagged as a
 * request (advertisement flag bit 3, `q` = request id = truncated hash of the
 * packed request); handle_request() answers over the MDU with a Resource
 * flagged as a response (bit 4). Link.receive() accepts both before any
 * resource strategy is consulted (Link.py:1036-1066).
 *
 * Until 2026-09-22 this client neither sent nor recognised either form: an
 * rfed.link push larger than 431 bytes was assembled as bare data, handed to
 * the channel ingest under the wrong path, and never answered, so the node
 * moved the blob to the deferred queue and the client only saw it on the next
 * /channel/pull.
 *
 * link.js cannot be imported under Node (its module graph needs the browser
 * importmap), so the link methods are lifted from source and run against
 * stubs, as request_wire_format.test.mjs does. resource.js can be imported.
 *
 * Run: node --test link_request_resource.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Cryptography from "./lib/rns/cryptography.js";
import MsgPack from "./lib/rns/msgpack.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";

const linkSource = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");
const MDU = 431;

function extractMethod(source, signature) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from link.js`);
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

/** Run a lifted link method with `this` bound to `self` and the given globals. */
function lift(signature, self, globals) {
    const params = signature.slice(signature.indexOf("(") + 1, signature.indexOf(")")).split(",").map((p) => p.trim()).filter(Boolean);
    const body = extractMethod(linkSource, signature);
    const names = Object.keys(globals);
    const fn = new Function(...params, ...names, "self", body.replaceAll("this.", "self."));
    return (...args) => fn(...args, ...names.map((n) => globals[n]), self);
}

// ── The advertisement carries the request/response flags and id ──────────

class WireOnly {
    constructor() {
        this.rtt = 0.05;
        this.hash = Buffer.alloc(16, 0xAB);
        this.attachedInterface = { name: "fake" };
        this.incomingResources = [];
        this.outgoingResources = [];
        this.frames = [];
        this.destination = { rns: { sendData: (raw) => this.frames.push(raw) } };
    }
    encrypt(data) {
        const padding = 16 - (data.length % 16);
        const padded = Buffer.concat([data, Buffer.alloc(padding, padding)]);
        return Buffer.concat([Buffer.alloc(16, 0x11), padded, Buffer.alloc(32, 0x22)]);
    }
    decrypt(data) {
        const padded = data.slice(16, data.length - 32);
        return padded.slice(0, padded.length - padded[padded.length - 1]);
    }
    newLinkPacket(context, data, packetType) {
        return { context, data, packetType: packetType ?? Packet.DATA, pack() { return this; } };
    }
}

test("a request Resource advertises flag bit 3 and its request id; a response bit 4", () => {
    const link = new WireOnly();
    const requestId = Buffer.alloc(16, 0x5a);
    const request = new Resource(link);
    request.initiator = true;
    request.requestId = requestId;
    request.isRequest = true;
    request.prepareOutgoing(Buffer.alloc(900, 1));
    const adv = MsgPack.unpack(request.packAdvertisement(0));
    const get = (k) => (adv instanceof Map ? adv.get(k) : adv[k]);
    assert.equal((Number(get("f")) >> 3) & 1, 1, "request flag (u)");
    assert.equal((Number(get("f")) >> 4) & 1, 0, "not a response");
    assert.ok(Buffer.from(get("q")).equals(requestId), "q carries the request id");

    const response = new Resource(link);
    response.initiator = true;
    response.requestId = requestId;
    response.isResponse = true;
    response.prepareOutgoing(Buffer.alloc(900, 2));
    const adv2 = MsgPack.unpack(response.packAdvertisement(0));
    const get2 = (k) => (adv2 instanceof Map ? adv2.get(k) : adv2[k]);
    assert.equal((Number(get2("f")) >> 4) & 1, 1, "response flag (p)");
    assert.equal((Number(get2("f")) >> 3) & 1, 0, "not a request");

    const plain = new Resource(link);
    plain.initiator = true;
    plain.prepareOutgoing(Buffer.alloc(900, 3));
    const adv3 = MsgPack.unpack(plain.packAdvertisement(0));
    const get3 = (k) => (adv3 instanceof Map ? adv3.get(k) : adv3[k]);
    assert.equal(Number(get3("f")) & 0b11000, 0, "bare data carries neither flag");
    assert.equal(get3("q"), null);
});

test("an accepted advertisement records whether it is a request or a response", () => {
    const link = new WireOnly();
    const requestId = Buffer.alloc(16, 0x77);
    const sender = new Resource(link);
    sender.initiator = true;
    sender.requestId = requestId;
    sender.isRequest = true;
    sender.prepareOutgoing(Buffer.alloc(600, 9));
    const receiver = Resource.accept(new WireOnly(), MsgPack.unpack(sender.packAdvertisement(0)));
    assert.ok(receiver, "accepted");
    assert.equal(receiver.isRequest, true);
    assert.equal(receiver.isResponse, false);
    assert.ok(receiver.requestId.equals(requestId));
});

// ── The link sends over the MDU as a Resource, and dispatches on arrival ──

test("a request over the MDU goes as a request Resource whose id is the packed request's hash", () => {
    const sent = { resources: [], packets: [] };
    const self = {
        _sendWithContext(data, context) {
            sent.packets.push({ data, context });
            return { getTruncatedHash: () => Buffer.alloc(16, 0xcd) };
        },
    };
    const ResourceStub = {
        send(link, data, options) {
            sent.resources.push({ data, options });
            return Promise.resolve();
        },
    };
    const send = lift("_sendRequestPayload(requestPayload)", self, {
        Link: { MDU }, Packet: { REQUEST: 0x09 }, Cryptography, Resource: ResourceStub, Buffer, console,
    });

    const small = Buffer.alloc(MDU, 1);
    assert.ok(send(small).equals(Buffer.alloc(16, 0xcd)));
    assert.equal(sent.packets.length, 1, "at the MDU it is still one packet");
    assert.equal(sent.resources.length, 0);

    const big = Buffer.alloc(MDU + 1, 2);
    const id = send(big);
    assert.equal(sent.packets.length, 1, "one byte over the MDU is not a packet");
    assert.equal(sent.resources.length, 1);
    assert.equal(sent.resources[0].options.isRequest, true);
    assert.ok(id.equals(Cryptography.truncatedHash(big)), "request id = truncated hash of the packed request (RNS/Link.py:497)");
    assert.ok(sent.resources[0].options.requestId.equals(id));
});

test("a response over the MDU goes as a response Resource carrying the request id", () => {
    const sent = { resources: [], packets: [] };
    const self = {
        _sendWithContext(data, context) { sent.packets.push({ data, context }); },
    };
    const ResourceStub = { send(link, data, options) { sent.resources.push({ data, options }); return Promise.resolve(); } };
    const sendResponse = lift("sendResponse(requestId, responseData)", self, {
        Link: { MDU }, Packet: { RESPONSE: 0x0A }, MsgPack, Resource: ResourceStub, Buffer, console,
    });
    const requestId = Buffer.alloc(16, 0x31);
    sendResponse(requestId, true);
    assert.equal(sent.packets.length, 1);
    assert.equal(sent.packets[0].context, 0x0A);

    sendResponse(requestId, Buffer.alloc(2000, 7));
    assert.equal(sent.resources.length, 1);
    assert.equal(sent.resources[0].options.isResponse, true);
    assert.ok(sent.resources[0].options.requestId.equals(requestId));
    const [id, value] = MsgPack.unpack(sent.resources[0].data);
    assert.ok(Buffer.from(id).equals(requestId), "packed like a RESPONSE packet: [request_id, response]");
    assert.equal(Buffer.from(value).length, 2000);
});

test("a concluded request Resource is dispatched as a request with the reference's id and path", () => {
    const events = [];
    const self = { hash: Buffer.alloc(16, 1), emit: (name, payload) => events.push({ name, payload }) };
    const dispatch = lift("_dispatchConcludedResource(resource)", self, { MsgPack, Cryptography, console });

    const pathHash = Cryptography.truncatedHash(Buffer.from("/lxmf/delivery"));
    const body = Buffer.alloc(1200, 0xEE);
    const packed = MsgPack.pack([1790000000.5, pathHash, body]);
    dispatch({ isRequest: true, isResponse: false, data: packed });
    assert.equal(events.length, 1);
    assert.equal(events[0].name, "request");
    assert.ok(events[0].payload.requestId.equals(Cryptography.truncatedHash(packed)), "request id = truncated hash of the packed request (RNS/Link.py:870)");
    assert.ok(Buffer.from(events[0].payload.path).equals(pathHash), "path is the 16-byte path hash, as on a REQUEST packet");
    assert.equal(Buffer.from(events[0].payload.data).length, 1200);

    const requestId = Buffer.alloc(16, 0x42);
    dispatch({ isRequest: false, isResponse: true, data: MsgPack.pack([requestId, Buffer.alloc(700, 3)]) });
    assert.equal(events[1].name, "response");
    assert.ok(Buffer.from(events[1].payload.requestId).equals(requestId));

    dispatch({ isRequest: false, isResponse: false, data: Buffer.alloc(500, 4) });
    assert.equal(events[2].name, "resource", "bare data still reaches the resource event");

    dispatch({ isRequest: true, isResponse: false, data: Buffer.from("not msgpack at all") });
    assert.equal(events.length, 3, "a malformed request resource is dropped, not dispatched");
});

test("a request or response Resource is accepted even under ACCEPT_NONE", () => {
    // The advertisement branch of Link.onPacket, lifted with its guard. We
    // give it a strategy of ACCEPT_NONE and a request-flagged advertisement.
    const branchStart = linkSource.indexOf("else if(packet.context === Packet.RESOURCE_ADV){");
    const branchEnd = linkSource.indexOf("\n        }\n", branchStart) + 11;
    const branch = linkSource.slice(branchStart + "else if(packet.context === Packet.RESOURCE_ADV)".length, branchEnd);
    const accepted = [];
    const self = {
        resourceStrategy: 0, // ACCEPT_NONE
        decrypt: (d) => d,
        _dispatchConcludedResource() {},
    };
    const ResourceStub = { accept(link, adv) { accepted.push(adv); return { once() {} }; } };
    const run = new Function("packet", "Packet", "MsgPack", "Resource", "Link", "console", "self",
        branch.replaceAll("this.", "self."));
    const packet = (flags, q) => ({ context: 0x02, data: MsgPack.pack(new Map([["f", flags], ["q", q], ["h", Buffer.alloc(32)]])) });
    run(packet(0x01, null), { RESOURCE_ADV: 0x02 }, MsgPack, ResourceStub, { ACCEPT_NONE: 0 }, console, self);
    assert.equal(accepted.length, 0, "bare data honours ACCEPT_NONE");
    run(packet(0x01 | (1 << 3), Buffer.alloc(16, 1)), { RESOURCE_ADV: 0x02 }, MsgPack, ResourceStub, { ACCEPT_NONE: 0 }, console, self);
    assert.equal(accepted.length, 1, "a request Resource is accepted regardless of the strategy (RNS/Link.py:1036)");
    run(packet(0x01 | (1 << 4), Buffer.alloc(16, 1)), { RESOURCE_ADV: 0x02 }, MsgPack, ResourceStub, { ACCEPT_NONE: 0 }, console, self);
    assert.equal(accepted.length, 2, "so is a response Resource");
});
