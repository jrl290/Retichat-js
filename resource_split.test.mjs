/**
 * Receiving a split (multi-segment) Resource.
 *
 * RNS/Resource.py sends anything over MAX_EFFICIENT_SIZE (1 MiB - 1) as
 * segments: separate Resources, each with its own hash, advertised one after
 * another as each is proved, sharing the first segment's hash as `o`
 * (original_hash) and carrying `i` (segment index) and `l` (segment count).
 * The receiver appends each segment to one file named by `o` and hands the
 * whole payload on only after segment l (Resource.py assemble()).
 *
 * Until 2026-09-30 this client refused every split advertisement, so a
 * response over 1 MiB (a /distro/pull page of several 256 KB blobs) was lost
 * whole. It now receives them; it still sends only single segments (it never
 * sends more than about 1 MB).
 *
 * Most tests lower Resource.MAX_EFFICIENT_SIZE so a split needs kilobytes,
 * not megabytes; the receiver's rules do not depend on the value. The
 * real-size case is in link_request_resource.test.mjs (a response page over
 * 1 MiB).
 *
 * Run: node --test resource_split.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import Link from "./lib/rns/link.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import { linkPair, once, settle } from "./test_link_pair.mjs";

const bytes = (n, k = 7) => Buffer.from(Array.from({ length: n }, (_, i) => (i * k) % 251));

/**
 * Send `data` from `link` as a split Resource, segment by segment, the way
 * RNS/Resource.py does: each segment is advertised when the previous one is
 * proved. `declaredSize` overrides the advertised total (`d`).
 */
export async function sendSplit(link, data, { requestId = null, isResponse = false, isRequest = false, declaredSize = null } = {}) {
    const segmentSize = Resource.MAX_EFFICIENT_SIZE;
    const total = Math.floor((data.length - 1) / segmentSize) + 1;
    let originalHash = null;
    for (let i = 1; i <= total; i++) {
        const segment = new Resource(link);
        segment.initiator = true;
        segment.segmentIndex = i;
        segment.totalSegments = total;
        segment.totalSize = declaredSize ?? data.length;
        segment.originalHash = originalHash;
        if (requestId) {
            segment.requestId = Buffer.from(requestId);
            segment.isResponse = isResponse;
            segment.isRequest = isRequest;
        }
        segment.prepareOutgoing(data.subarray((i - 1) * segmentSize, i * segmentSize));
        originalHash ??= segment.hash;
        await new Promise((resolve, reject) => {
            segment.once("concluded", resolve);
            segment.once("failed", reject);
            segment.advertise();
        });
    }
}

/** Run `fn` with a small MAX_EFFICIENT_SIZE. */
async function withSegmentSize(size, fn) {
    const saved = Resource.MAX_EFFICIENT_SIZE;
    Resource.MAX_EFFICIENT_SIZE = size;
    try { return await fn(); } finally { Resource.MAX_EFFICIENT_SIZE = saved; }
}

test("a split Resource arrives whole, once, after its last segment", () => withSegmentSize(5000, async () => {
    const { a, b } = linkPair();
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const delivered = [];
    const progress = [];
    b.on("resource", ({ data }) => delivered.push(data));
    b.on("resource_progress", ({ progress: p }) => progress.push(p));
    const payload = bytes(12_345, 3);

    await sendSplit(a, payload);
    await settle(5);

    assert.equal(delivered.length, 1, "one delivery for three segments");
    assert.ok(delivered[0].equals(payload), "the segments in order, byte for byte");
    assert.equal(b._splitAssemblies.size, 0, "nothing left held");
    assert.equal(b.incomingResources.length, 0);
    assert.ok(progress.every((p, i) => p >= 0 && p <= 1 && (i === 0 || p >= progress[i - 1])),
        `progress runs up across segments: ${progress.map((p) => p.toFixed(2))}`);
    assert.equal(progress.at(-1), 1);
}));

test("a later segment of a split Resource the link is not reassembling is refused", () => withSegmentSize(5000, async () => {
    const { a, b, wire } = linkPair();
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const segment = new Resource(a);
    segment.initiator = true;
    segment.segmentIndex = 2;
    segment.totalSegments = 2;
    segment.totalSize = 9000;
    segment.originalHash = Buffer.alloc(32, 0x5e);
    segment.prepareOutgoing(bytes(4000));
    const failed = once(segment, "failed");
    segment.advertise();
    assert.equal(await failed, "the peer rejected the resource", "refused with RCL");
    assert.equal(b.incomingResources.length, 0);
    assert.ok(wire.b.some((p) => p.context === Packet.RESOURCE_RCL));
}));

test("segments carrying more than the declared total are dropped, not delivered", () => withSegmentSize(5000, async () => {
    const { a, b } = linkPair();
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const delivered = [];
    b.on("resource", ({ data }) => delivered.push(data));
    // Two full segments (10000 bytes) advertised as 9900 in total.
    await sendSplit(a, bytes(10_000), { declaredSize: 9900 });
    await settle(5);
    assert.equal(delivered.length, 0);
    assert.equal(b._splitAssemblies.size, 0);
}));

test("a link that closes between segments drops the half-assembled Resource", () => withSegmentSize(5000, async () => {
    const { a, b } = linkPair();
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const first = new Resource(a);
    first.initiator = true;
    first.totalSegments = 2;
    first.totalSize = 9000;
    first.prepareOutgoing(bytes(5000));
    await new Promise((resolve, reject) => { first.once("concluded", resolve); first.once("failed", reject); first.advertise(); });
    assert.equal(b._splitAssemblies.size, 1, "segment 1 is held for segment 2");
    a.close();
    await settle(5);
    assert.equal(b.status, Link.CLOSED);
    assert.equal(b._splitAssemblies.size, 0);
}));
