/**
 * LXMF delivery links take a Resource only within LXMF's per-transfer limit.
 *
 * LXMF/LXMRouter.py sets every delivery link to ACCEPT_APP with
 * delivery_resource_advertised as the callback (LXMRouter.py:1959-1960,
 * 1977-1984): a Resource whose data size exceeds delivery_per_transfer_limit
 * (DELIVERY_LIMIT = 1000 KB, i.e. 1,000,000 bytes; LXMF-rust lxm_router.rs:290
 * and 4001-4015 the same) is rejected at its advertisement, before any part
 * is asked for. Until 2026-09-30 this client's delivery links were
 * ACCEPT_ALL: a peer could make the tab fetch and hold whatever it advertised.
 *
 * The gate governs bare data only. A Resource flagged as a request is taken
 * only where the destination has request handlers (RNS/Link.py:1036-1042),
 * and LXMF registers none on its delivery destination (LXMRouter.py:669-676
 * registers them on the propagation and control destinations), so on a
 * delivery link a request Resource is ignored, whatever size it declares.
 *
 * Run: node --test lxmf_delivery_limit.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import Destination from "./lib/rns/destination.js";
import Identity from "./lib/rns/identity.js";
import Link from "./lib/rns/link.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import EventEmitter from "./lib/rns/utils/events.js";
import Packet from "./lib/rns/packet.js";
import Cryptography from "./lib/rns/cryptography.js";
import { linkPair, once, sendSplit, settle, within } from "./test_link_pair.mjs";

const bytes = (n, k = 7) => Buffer.from(Array.from({ length: n }, (_, i) => (i * k) % 251));
const advertisementsFrom = (wire) => wire.filter((p) => p.context === Packet.RESOURCE_ADV);

/** `b` of a link pair, set up as an incoming LXMF delivery link. */
async function deliveryLink() {
    const pair = linkPair();
    const me = Identity.create();
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    new LXMRouter({ registerDestination: () => destination }, me);
    pair.b.accept = () => {};                     // already established here
    destination.emit("link_request", pair.b);
    await settle();
    return pair;
}

test("the limit is LXMF's 1000 KB, on the advertised data size", () => {
    assert.equal(LXMRouter.DELIVERY_LIMIT, 1000);
    assert.equal(LXMRouter.deliveryResourceAdvertised({ dataSize: 1_000_000 }), true, "at the limit: accepted (size > limit rejects)");
    assert.equal(LXMRouter.deliveryResourceAdvertised({ dataSize: 1_000_001 }), false);
    assert.equal(LXMRouter.deliveryResourceAdvertised({ dataSize: undefined }), false, "no size, no transfer");
});

test("a delivery link rejects a Resource over the limit at its advertisement", async () => {
    const { a, b, wire } = await deliveryLink();
    assert.equal(b.resourceStrategy, Link.ACCEPT_APP);
    await assert.rejects(within(a.sendResource(bytes(1_000_001)), 5000, "the oversized Resource"), /rejected/);
    assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_REQ).length, 0, "not one part was asked for");
    assert.equal(b.incomingResources.length, 0);
});

test("a delivery link takes a Resource within the limit", async () => {
    const { a, b } = await deliveryLink();
    const delivered = once(b, "resource");
    await within(a.sendResource(bytes(30_000)), 5000, "the Resource");
    assert.equal((await delivered).data.length, 30_000);
});

test("ACCEPT_APP: the callback sees the advertisement; a falsy answer or a throw rejects", async () => {
    const seen = [];
    for (const answer of [() => 0, () => { throw new Error("broken callback"); }, (adv) => { seen.push(adv); return 1; }]) {
        const { a, b } = linkPair();
        b.setResourceStrategy(Link.ACCEPT_APP);
        b.setResourceCallback(answer);
        const sending = a.sendResource(bytes(3000));
        if (answer.length === 0) {
            await assert.rejects(within(sending, 5000), /rejected/);
        } else {
            await within(sending, 5000);
        }
    }
    assert.equal(seen.length, 1);
    assert.equal(seen[0].dataSize, 3000, "d, the whole payload");
    assert.equal(seen[0].segmentIndex, 1);
    assert.equal(seen[0].totalSegments, 1);
    assert.ok(seen[0].transferSize > 3000 && Buffer.isBuffer(seen[0].hash));
});

test("a delivery link fetches nothing of a Resource flagged as a request, whatever size it declares", async () => {
    // Until 2026-09-30 a request flag walked any Resource past the size gate:
    // a 2.2 MB split request was fetched whole (110 part requests) and then
    // dropped, since nothing on a delivery link handles requests.
    const { a, b, wire } = await deliveryLink();
    const payload = bytes(2_200_000);
    const split = sendSplit(a, payload, { requestId: Cryptography.truncatedHash(payload), isRequest: true }).catch(() => {});
    const small = a.sendRequest("/lxmf/anything", bytes(2000));   // over the MDU: a request Resource
    await settle(60);
    assert.ok(advertisementsFrom(wire.a).length >= 2, "both request Resources were advertised");
    assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_REQ).length, 0, "not one part was asked for");
    assert.equal(wire.b.filter((p) => p.context === Packet.RESOURCE_RCL).length, 0, "ignored, not refused (RNS/Link.py)");
    assert.equal(b.incomingResources.length, 0);
    assert.equal(b._splitAssemblies.size, 0);
    a.close();
    await split;
    await assert.rejects(a.responseFor(small), /link closed|could not be sent|failed/);
});
