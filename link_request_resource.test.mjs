/**
 * Requests and responses over a link, and the ones that travel as Resources.
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
 * 2026-09-30, RNS/Link.py RequestReceipt parity: the link tracks its pending
 * requests. A response Resource is accepted only for one of them; while it
 * transfers the request is RECEIVING and its timeout does not fire (a
 * /distro/pull page of photos, or a large /get, was thrown away half
 * transferred by a flat timer in app.js); a request sent as a Resource starts
 * its timeout only once the peer has proved it; a failed response transfer
 * or a closing link fails the request at once. Responses over 1 MiB arrive
 * as split Resources and are received whole.
 *
 * Review fixes, 2026-09-30: a request Resource is taken only by a link that
 * handles requests and within its maxRequestSize (Link.py:1036-1042); a
 * response the link refuses fails its request at once (response_rejected);
 * a failed request releases its half-assembled split response; and a request
 * whose response is already arriving is not put back to waiting when the
 * promise of its own Resource settles late.
 *
 * Run: node --test link_request_resource.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import Cryptography from "./lib/rns/cryptography.js";
import Link from "./lib/rns/link.js";
import MsgPack from "./lib/rns/msgpack.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import { linkPair, once, sendSplit, settle, within } from "./test_link_pair.mjs";

const bytes = (n, k = 7) => Buffer.from(Array.from({ length: n }, (_, i) => (i * k) % 251));
const advertisementsFrom = (wire) => wire.filter((p) => p.context === Packet.RESOURCE_ADV);

/** Answer every request on `link` with `answer(request)`, as a responder would. */
function respondWith(link, answer) {
    link.on("request", (request) => {
        const value = answer(request);
        if (value !== undefined) link.sendResponse(request.requestId, value);
    });
}

/**
 * Advertise, from `link`, a response Resource for `requestId` carrying
 * `value`, with `fields` set on the Resource before it is built and its
 * advertisement edited by `edit(map)` on the way out.
 */
function advertiseResponse(link, requestId, value, { fields = {}, edit = () => {} } = {}) {
    const r = new Resource(link);
    r.initiator = true;
    r.requestId = Buffer.from(requestId);
    r.isResponse = true;
    Object.assign(r, fields);
    r.prepareOutgoing(MsgPack.pack([requestId, value]));
    const pack = r.packAdvertisement.bind(r);
    r.packAdvertisement = (segment) => {
        const adv = MsgPack.unpack(pack(segment));
        const map = adv instanceof Map ? adv : new Map(Object.entries(adv));
        edit(map);
        return MsgPack.pack(map);
    };
    r.once("failed", () => {});
    r.advertise();
    return r;
}
const claimBz2 = (map) => map.set("f", Number(map.get("f")) | 0x02);

// ── The advertisement carries the request/response flags and id ──────────

test("a request Resource advertises flag bit 3 and its request id; a response bit 4", () => {
    const { a } = linkPair({ drop: () => true });
    const requestId = Buffer.alloc(16, 0x5a);
    const make = (fields) => {
        const r = new Resource(a);
        r.initiator = true;
        Object.assign(r, fields);
        r.prepareOutgoing(Buffer.alloc(900, 1));
        const adv = MsgPack.unpack(r.packAdvertisement(0));
        return (k) => (adv instanceof Map ? adv.get(k) : adv[k]);
    };
    const request = make({ requestId, isRequest: true });
    assert.equal((Number(request("f")) >> 3) & 1, 1, "request flag (u)");
    assert.equal((Number(request("f")) >> 4) & 1, 0, "not a response");
    assert.ok(Buffer.from(request("q")).equals(requestId), "q carries the request id");
    const response = make({ requestId, isResponse: true });
    assert.equal((Number(response("f")) >> 4) & 1, 1, "response flag (p)");
    assert.equal((Number(response("f")) >> 3) & 1, 0, "not a request");
    const plain = make({});
    assert.equal(Number(plain("f")) & 0b11000, 0, "bare data carries neither flag");
    assert.equal(plain("q"), null);
});

// ── Requests ──────────────────────────────────────────────────────────────

test("a request at the MDU is one REQUEST packet; one byte over goes as a request Resource", async () => {
    const { a, b, wire } = linkPair();
    const requests = [];
    b.on("request", (r) => requests.push(r));

    // [timestamp(9), path hash(18), data]: data sized so the whole is exactly the MDU.
    const fixed = MsgPack.pack([Date.now() / 1000, Buffer.alloc(16), Buffer.alloc(0)]).length;
    const small = a.sendRequest("/p", Buffer.alloc(Link.MDU - fixed - 1));
    assert.equal(wire.a.at(-1).context, Packet.REQUEST, "at the MDU it is still one packet");
    const big = a.sendRequest("/p", Buffer.alloc(Link.MDU));
    const adv = MsgPack.unpack(a.decrypt(advertisementsFrom(wire.a).at(-1).data));
    const q = Buffer.from(adv instanceof Map ? adv.get("q") : adv.q);
    assert.ok(q.equals(big), "the request Resource's q is the request id");
    await settle(40);
    assert.equal(requests.length, 2);
    assert.ok(requests[0].requestId.equals(small), "the packet request's id is its truncated packet hash");
    assert.ok(Buffer.from(requests[1].path).equals(Cryptography.truncatedHash(Buffer.from("/p"))), "path is the 16-byte path hash");
    assert.equal(big.length, 16);
    assert.ok(requests[1].requestId.equals(big), "the receiver derives the same id from the assembled bytes (RNS/Link.py:870)");
    a.close();   // nobody answers: fail the two requests rather than wait out their budget
});

test("a request Resource is accepted even under ACCEPT_NONE, and so is the response to one", async () => {
    const { a, b } = linkPair();
    assert.equal(a.resourceStrategy, Link.ACCEPT_NONE);
    assert.equal(b.resourceStrategy, Link.ACCEPT_NONE);
    respondWith(b, (request) => ["echo", Buffer.from(request.data)]);
    const id = a.sendRequest("/echo", bytes(2000));
    const [label, echoed] = await within(a.responseFor(id), 3000, "the response");
    assert.equal(label, "echo");
    assert.ok(Buffer.from(echoed).equals(bytes(2000)), "request and response both crossed as Resources");
});

test("a request Resource is taken only by a link that handles requests, and only within its maxRequestSize", async () => {
    // RNS/Link.py:1036-1042: accepted only where the destination has request
    // handlers (here: a "request" listener on the link), and only when its
    // data size is within max_request_size. With no handler it is ignored.
    {
        const { a, wire } = linkPair();
        const id = a.sendRequest("/p", bytes(2000));
        await settle(30);
        assert.ok(advertisementsFrom(wire.a).length >= 1, "the request went as a Resource");
        assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_REQ).length, 0, "no handler: nothing asked for");
        assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_RCL).length, 0, "no handler: ignored, not refused");
        a.close();
        await assert.rejects(a.responseFor(id));
    }
    {
        const { a, b, wire } = linkPair();
        b.on("request", () => assert.fail("a request over maxRequestSize reached the handler"));
        b.maxRequestSize = 2000;          // the packed request is 2000 bytes of data plus its envelope
        const id = a.sendRequest("/p", bytes(2000), { timeoutMs: 60_000 });
        await assert.rejects(within(a.responseFor(id), 3000, "the refused request"), /the peer rejected the resource/);
        assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_RCL).length, 1, "refused at its advertisement");
        assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_REQ).length, 0, "not one part was asked for");
    }
    {
        const { a, b } = linkPair();
        b.maxRequestSize = 3000;
        respondWith(b, (request) => Buffer.from(request.data).length);
        const id = a.sendRequest("/p", bytes(2000));
        assert.equal(await within(a.responseFor(id), 3000, "the response"), 2000, "within the limit: taken and answered");
    }
});

// ── Responses belong to pending requests ──────────────────────────────────

test("a response, packet or Resource, is taken only for a pending request (Link.py handle_response)", async () => {
    const { a, b, wire } = linkPair();
    const responses = [];
    a.on("response", (r) => responses.push(r));
    const stranger = Buffer.alloc(16, 0x77);
    b.sendResponse(stranger, "small");
    b.sendResponse(stranger, bytes(3000));
    await settle(20);
    assert.equal(responses.length, 0, "no response event for a request that was never sent");
    assert.equal(a.incomingResources.length, 0, "the response Resource was not accepted");
    assert.equal(wire.a.filter((p) => p.context === Packet.RESOURCE_REQ).length, 0, "no part of it was asked for");
    for (const r of [...b.outgoingResources]) r.cancel("test over");
});

test("an advertisement flagged as both request and response is a request (ResourceAdvertisement.is_request first)", async () => {
    // Until 2026-09-30 the response flag won here, while the concluded
    // Resource was then dispatched as a request. Now the link decides as the
    // reference does: a request, so a link with no request handler ignores
    // it even when a request of that id is pending.
    const { a, b, wire } = linkPair();
    b.on("request", (request) => {
        advertiseResponse(b, request.requestId, bytes(3000), { edit: (map) => map.set("f", Number(map.get("f")) | 0x08) });
    });
    const id = a.sendRequest("/get", null, { timeoutMs: 60_000 });
    await settle(30);
    assert.ok(advertisementsFrom(wire.b).length >= 1, "the doubly flagged Resource was advertised");
    assert.equal(wire.a.filter((p) => p.context === Packet.RESOURCE_REQ).length, 0, "not taken as the response");
    assert.equal(a._pendingRequest(id).status, Link.REQUEST_DELIVERED, "the request still waits for its response");
    a.close();
});

test("a response Resource's transfer does not run into the request's timeout", async () => {
    // Every part takes 25 ms: a 200 KB response takes far longer than the
    // 150 ms the request has for its response to start.
    const { a, b } = linkPair({ delay: (p) => (p.context === Packet.RESOURCE ? 25 : 0) });
    const page = bytes(200_000, 3);
    respondWith(b, () => page);
    const progress = [];
    const started = Date.now();
    const id = a.sendRequest("/distro/pull", null, { timeoutMs: 150, onProgress: (p) => progress.push(p) });
    const response = await within(a.responseFor(id), 20_000, "the response");
    assert.ok(Date.now() - started > 300, "the transfer outlasted the request timeout");
    assert.ok(Buffer.from(response).equals(page));
    assert.ok(progress.length > 2 && progress.at(-1) === 1, "the request reports the response's progress");
    assert.equal(a.pendingRequests.length, 0);
});

test("a request sent as a Resource starts its timeout only once the peer has proved it", async () => {
    // The request itself (40 KB) takes longer to upload than its timeout.
    const { a, b } = linkPair({ delay: (p, from) => (from === "a" && p.context === Packet.RESOURCE ? 10 : 0) });
    respondWith(b, () => "got it");
    const started = Date.now();
    const id = a.sendRequest("/lxmf/delivery", bytes(40_000), { timeoutMs: 40 });
    assert.equal(a._pendingRequest(id).status, Link.REQUEST_SENT, "no clock while the request uploads");
    assert.equal(await within(a.responseFor(id), 20_000, "the response"), "got it");
    assert.ok(Date.now() - started > 80, "the upload took longer than the request's timeout");
});

test("a request whose response is already arriving is not put back to waiting when its own Resource settles", async () => {
    // PostInterface hands a poll's packets over in one synchronous loop, so
    // the proof of a request Resource and the response's advertisement can
    // be handled back to back, before the request Resource's promise
    // settles. The request is then RECEIVING; until 2026-09-30 the late
    // settlement put it back to DELIVERED with its timer running, and a first
    // part slower than the timeout failed a response mid-transfer. The
    // advertisement-first order is covered too.
    for (const order of ["proof first", "advertisement first"]) {
        const held = [];
        let holding = true;
        const { a, b } = linkPair({
            drop: (p, from) => {
                if (from === "b" && holding && (p.context === Packet.RESOURCE_PRF || p.context === Packet.RESOURCE_ADV)) {
                    held.push(p);
                    return true;
                }
                return false;
            },
            delay: (p, from) => (from === "b" && p.context === Packet.RESOURCE ? 300 : 0),
        });
        respondWith(b, () => bytes(1500));
        const id = a.sendRequest("/get", bytes(2000), { timeoutMs: 150 });
        for (let i = 0; i < 400 && held.length < 2; i++) await settle(1);
        holding = false;
        const proof = held.find((p) => p.context === Packet.RESOURCE_PRF);
        const advertisement = held.find((p) => p.context === Packet.RESOURCE_ADV);
        assert.ok(proof && advertisement, `${order}: both packets were held`);
        if (order === "proof first") { a.onResourceProof(proof); a.onPacket(advertisement); }
        else { a.onPacket(advertisement); a.onResourceProof(proof); }
        await settle(5);
        const receipt = a._pendingRequest(id);
        assert.equal(receipt.status, Link.REQUEST_RECEIVING, `${order}: the response is arriving`);
        assert.equal(receipt.timer, null, `${order}: no timeout runs while it arrives`);
        const response = await within(a.responseFor(id), 5000, `${order}: the response`);
        assert.ok(Buffer.from(response).equals(bytes(1500)), `${order}: the response arrived whole, after its 150 ms budget`);
    }
});

test("a request whose response never starts fails after its timeout", async () => {
    const { a } = linkPair();
    const id = a.sendRequest("/nobody/home", null, { timeoutMs: 60 });
    await assert.rejects(within(a.responseFor(id), 2000), /no response within 60 ms/);
    assert.equal(a.pendingRequests.length, 0);
});

test("a response transfer that fails fails its request at once", async () => {
    // Parts never arrive; then the responder gives up (ICL).
    const { a, b } = linkPair({ drop: (p) => p.context === Packet.RESOURCE });
    respondWith(b, () => bytes(5000));
    const id = a.sendRequest("/get", null, { timeoutMs: 60 });
    await settle(10);
    assert.equal(a._pendingRequest(id).status, Link.REQUEST_RECEIVING);
    b.outgoingResources[0].cancel("the responder gave up");
    await assert.rejects(within(a.responseFor(id), 2000), /the response transfer failed/);
});

test("a response the link refuses fails its request at once, saying why (Link.py response_rejected)", async () => {
    // Until 2026-09-30 the request waited out its whole timeout and then
    // reported "no response within N ms": false, as a response had come and
    // been refused.
    {
        const { a, b, wire } = linkPair();
        b.on("request", (request) => { advertiseResponse(b, request.requestId, bytes(3000), { edit: claimBz2 }); });
        const id = a.sendRequest("/get", null, { timeoutMs: 60_000 });
        await assert.rejects(within(a.responseFor(id), 2000, "the refused response"), /the response was refused: .*compressed/);
        assert.equal(wire.a.filter((p) => p.context === Packet.RESOURCE_RCL).length, 1, "the refusal went back to the responder");
        assert.equal(a.pendingRequests.length, 0);
    }
    // A later segment of a split response the link is not reassembling is refused, and fails its request too.
    const saved = Resource.MAX_EFFICIENT_SIZE;
    Resource.MAX_EFFICIENT_SIZE = 5000;
    try {
        const { a, b } = linkPair();
        b.on("request", (request) => {
            advertiseResponse(b, request.requestId, bytes(4000), {
                fields: { segmentIndex: 2, totalSegments: 2, totalSize: 9000, originalHash: Buffer.alloc(32, 0x42) },
            });
        });
        const id = a.sendRequest("/pull", null, { timeoutMs: 60_000 });
        await assert.rejects(within(a.responseFor(id), 2000, "the refused segment"), /the response was refused: segment 2\/2 of a split Resource this link is not reassembling/);
    } finally {
        Resource.MAX_EFFICIENT_SIZE = saved;
    }
});

test("a refused advertisement leaves a request whose response is already transferring to that transfer", async () => {
    const { a, b, wire } = linkPair({ delay: (p, from) => (from === "b" && p.context === Packet.RESOURCE ? 50 : 0) });
    let request = null;
    respondWith(b, (r) => { request = r; return bytes(5000); });
    const id = a.sendRequest("/get", null, { timeoutMs: 60_000 });
    for (let i = 0; i < 200 && a._pendingRequest(id)?.status !== Link.REQUEST_RECEIVING; i++) await settle(1);
    assert.equal(a._pendingRequest(id).status, Link.REQUEST_RECEIVING);
    advertiseResponse(b, request.requestId, bytes(3000, 3), { edit: claimBz2 });   // a second, unreadable response
    const response = await within(a.responseFor(id), 5000, "the response");
    assert.equal(wire.a.filter((p) => p.context === Packet.RESOURCE_RCL).length, 1, "the second advertisement was refused while the request was pending");
    assert.ok(Buffer.from(response).equals(bytes(5000)), "the transfer that was under way answered the request");
});

test("closing the link fails every pending request, from either end", async () => {
    for (const closer of ["a", "b"]) {
        const pair = linkPair();
        const id = pair.a.sendRequest("/slow", null, { timeoutMs: 60_000 });
        pair[closer].close();
        await assert.rejects(within(pair.a.responseFor(id), 2000), /the link closed before a response/, `closed by ${closer}`);
        assert.equal(pair.a.pendingRequests.length, 0);
    }
});

test("a closed link sends nothing, and a request on it fails at once", () => {
    const { a, wire } = linkPair();
    a.close();
    const sent = wire.a.length;
    assert.throws(() => a.sendRequest("/p", null), /the link is closed/);
    a.send(Buffer.from("into the void"));
    assert.equal(wire.a.length, sent, "RNS/Packet.py send(): a closed link drops the packet");
});

// ── Split responses ───────────────────────────────────────────────────────

test("a response over 1 MiB arrives as a split Resource and is received whole", async () => {
    const { a, b } = linkPair();
    // A /distro/pull page of six 200 KB blobs: ~1.2 MB, two segments.
    const page = [true, Array.from({ length: 6 }, (_, i) => bytes(200_000, 11 + i)), false];
    b.on("request", (request) => {
        const packed = MsgPack.pack([request.requestId, page]);
        assert.ok(packed.length > Resource.MAX_EFFICIENT_SIZE);
        sendSplit(b, packed, { requestId: request.requestId, isResponse: true });
    });
    const progress = [];
    const id = a.sendRequest("/distro/pull", null, { timeoutMs: 200, onProgress: (p) => progress.push(p) });
    const [ok, blobs, more] = await within(a.responseFor(id), 60_000, "the split response");
    assert.equal(ok, true);
    assert.equal(more, false);
    assert.equal(blobs.length, 6);
    blobs.forEach((blob, i) => assert.ok(Buffer.from(blob).equals(bytes(200_000, 11 + i)), `blob ${i}`));
    assert.ok(progress.every((p, i) => i === 0 || p >= progress[i - 1]), "progress rises across the segments");
    assert.equal(a._splitAssemblies.size, 0);
});

test("between two segments of a response the request waits again, times out if the next never comes, and releases the first", async () => {
    const saved = Resource.MAX_EFFICIENT_SIZE;
    Resource.MAX_EFFICIENT_SIZE = 5000;
    try {
        const { a, b } = linkPair();
        b.on("request", (request) => {
            const packed = MsgPack.pack([request.requestId, bytes(9000)]);
            sendSplit(b, packed, { requestId: request.requestId, isResponse: true, segments: 1 });
        });
        const progress = [];
        const id = a.sendRequest("/pull", null, { timeoutMs: 100, onProgress: (p) => progress.push(p) });
        await assert.rejects(within(a.responseFor(id), 3000), /no response within 100 ms/);
        assert.ok(Math.max(...progress) >= 0.5, "the first segment (half the response) arrived before the wait began");
        // The half-assembled response can never complete now (its request is
        // gone, so later segments are ignored): it is released at once, not
        // held until the link closes.
        assert.equal(a._splitAssemblies.size, 0, "the failed request's reassembly is released");
    } finally {
        Resource.MAX_EFFICIENT_SIZE = saved;
    }
});

// ── app.js waits on the link's receipt ────────────────────────────────────

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
function appMethod(signature, env) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const open = app.indexOf("{", start + signature.length);
    let depth = 0, close = -1;
    for (let i = open; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}" && --depth === 0) { close = i; break; }
    }
    const body = app.slice(open + 1, close).replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")")).split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params, `return (async () => {${body}})();`);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}
const quiet = { log() {}, warn() {}, error() {} };

test("app.js _rfedRequest resolves with a response that takes longer than its budget to transfer", async () => {
    const { a, b } = linkPair({ delay: (p) => (p.context === Packet.RESOURCE ? 25 : 0) });
    const page = bytes(150_000, 5);
    respondWith(b, () => page);
    const self = { _rfedLinkAvailable: () => true, _ensureRfedLink: async () => a };
    const rfedRequest = appMethod("async _rfedRequest(aspects, path, packedValue)", {
        RFED_LINK_PATHS: {}, rfedRequestTimeoutMs: () => 150, Buffer, console: quiet,
    })(self);
    const started = Date.now();
    const response = await within(rfedRequest(["link"], "/rfed/pull", MsgPack.pack(null)), 20_000, "_rfedRequest");
    assert.ok(Date.now() - started > 300);
    assert.ok(Buffer.from(response).equals(page));
});

test("app.js _rfedRequest rejects when no response starts within the budget", async () => {
    const { a } = linkPair();
    const self = { _rfedLinkAvailable: () => true, _ensureRfedLink: async () => a };
    const rfedRequest = appMethod("async _rfedRequest(aspects, path, packedValue)", {
        RFED_LINK_PATHS: {}, rfedRequestTimeoutMs: () => 60, Buffer, console: quiet,
    })(self);
    await assert.rejects(within(rfedRequest(["link"], "/rfed/pull", MsgPack.pack(null)), 2000), /\/rfed\/pull: no response within 60 ms/);
});

test("app.js _waitForResponse gives the response of a long transfer, and null for a failed request", async () => {
    const { a, b } = linkPair({ delay: (p) => (p.context === Packet.RESOURCE ? 25 : 0) });
    respondWith(b, (request) => (Buffer.from(request.data ?? []).length === 1 ? undefined : bytes(100_000)));
    const wait = appMethod("async _waitForResponse(link, requestId)", { Buffer, console: quiet })({});
    const id = a.sendRequest("/get", null, { timeoutMs: 150 });
    const blob = await within(wait(a, id), 20_000, "_waitForResponse");
    assert.ok(Buffer.from(blob).equals(bytes(100_000)));
    const unanswered = a.sendRequest("/get", Buffer.from([1]), { timeoutMs: 50 });
    assert.equal(await within(wait(a, unanswered), 2000, "_waitForResponse"), null);
});
