/**
 * Resource transfer tests.
 *
 * A link data packet carries at most 431 bytes. Before 2026-08, anything
 * larger threw ("Link payload of N bytes exceeds the link MDU"), so long
 * channel messages and long DMs could not be sent at all. RNS solves this
 * with the Resource protocol, which these tests exercise.
 *
 * The wire format is fixed by RNS 1.5.2 RNS/Resource.py and
 * Reticulum-rust/src/resource.rs. The advertisement layout, the map-hash
 * derivation, the request layout and the proof layout are all asserted
 * against those references here — if they drift, transfers to Python and Rust
 * nodes fail silently rather than loudly, so these assertions are the guard.
 *
 * 2026-09-30, parity with RNS 1.5.2: parts are cut at the reference SDU
 * (464, not 431), the timers read the link's RTT in milliseconds, a closing
 * link fails its Resources, a Resource on a link that is not ACTIVE fails at
 * once, hashmap updates are placed by segment, a re-sent advertisement is
 * ignored, a retry asks again for what is missing and shrinks the window,
 * the receiver's window is capped by the measured rate, the sender
 * re-advertises, and both ends report progress.
 *
 * Everything runs over two real Links joined in process (test_link_pair.mjs),
 * on virtual time (test_virtual_time.mjs): a watchdog's deadline (1.3 s for
 * an advertisement, 4 s for a part, at the pair's 50 ms RTT) and a test's
 * failure bound are reached only by the delays a test injects, never by the
 * machine being slow. Until 2026-09-30 those margins, and a 1 s bound on a
 * failure that must come at once, were all that kept a loaded machine (npm
 * test, the deploy gate, runs every file at once) from deciding a test.
 *
 * Run: node --test resource.test.mjs
 */

import assert from "node:assert/strict";
import test, { afterEach, beforeEach } from "node:test";

import Cryptography from "./lib/rns/cryptography.js";
import Destination from "./lib/rns/destination.js";
import Link from "./lib/rns/link.js";
import MsgPack from "./lib/rns/msgpack.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import Transport from "./lib/rns/transport.js";
import { linkPair, once, settle, within } from "./test_link_pair.mjs";
import { installVirtualTime } from "./test_virtual_time.mjs";

let clock = null;
beforeEach(() => { clock = installVirtualTime(); });
afterEach(() => { clock.uninstall(); clock = null; });

const bytes = (n, k = 7) => Buffer.from(Array.from({ length: n }, (_, i) => (i * k) % 251));
const advOf = (resource) => MsgPack.unpack(resource.packAdvertisement(0));
const get = (adv, k) => (adv instanceof Map ? adv.get(k) : adv[k]);
const withAdv = (adv, changes) => {
    const copy = new Map(adv instanceof Map ? adv : Object.entries(adv));
    for (const [k, v] of Object.entries(changes)) copy.set(k, v);
    return copy;
};

/** A receiver accepting bare data on `b`, resolving with the concluded payload. */
function receiveOn(b) {
    b.setResourceStrategy(Link.ACCEPT_ALL);
    return once(b, "resource").then(({ data }) => data);
}

// ── Wire format ───────────────────────────────────────────────────────────

test("parts are cut at the reference SDU: link MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE = 464", () => {
    assert.equal(Resource.SDU, 500 - 35 - 1);
    assert.equal(Resource.HASHMAP_MAX_LEN, 74, "the advertisement's hashmap still fits a 431-byte link packet");
    const { a } = linkPair();
    const resource = new Resource(a);
    resource.prepareOutgoing(bytes(9000));
    assert.equal(resource.totalParts, Math.ceil(resource.transferSize / 464),
        "n = ceil(t / sdu), which is how a Python receiver counts the parts (Resource.py accept)");
    for (const part of resource.parts.slice(0, -1)) assert.equal(part.length, 464);
});

test("the advertisement carries the keys the Python and Rust nodes read", () => {
    const { a } = linkPair();
    const resource = new Resource(a);
    resource.prepareOutgoing(bytes(1200, 3));
    const adv = advOf(resource);

    for (const key of ["t", "d", "n", "h", "r", "o", "i", "l", "q", "f", "m"]) {
        assert.ok(adv instanceof Map ? adv.has(key) : key in adv, `advertisement is missing key "${key}"`);
    }
    assert.equal(get(adv, "d"), 1200, "d is the uncompressed payload size");
    assert.equal(get(adv, "t"), resource.transferSize, "t is the encrypted transfer size");
    assert.equal(get(adv, "n"), resource.totalParts);
    assert.equal(Buffer.from(get(adv, "h")).length, 32, "h is a full 32 byte hash");
    assert.equal(Buffer.from(get(adv, "r")).length, 4, "r is a 4 byte random hash");
    assert.ok(Buffer.from(get(adv, "o")).equals(Buffer.from(get(adv, "h"))), "o equals h for a single segment");
    assert.equal(get(adv, "i"), 1, "segments are 1-indexed");
    assert.equal(get(adv, "l"), 1);
    assert.equal(get(adv, "f"), 0x01, "encrypted, not compressed/split/request/response/metadata");
    assert.equal(Buffer.from(get(adv, "m")).length, resource.totalParts * 4, "m holds one 4 byte map hash per part");
    assert.ok(resource.packAdvertisement(0).length <= Link.MDU, "the advertisement fits a single link packet");
});

test("the resource hash and proof are derived the way the reference does", () => {
    const { a } = linkPair();
    const data = Buffer.from("reference vectors matter", "utf8");
    const resource = new Resource(a);
    resource.prepareOutgoing(data);

    assert.ok(resource.hash.equals(Cryptography.fullHash(Buffer.concat([data, resource.randomHash]))),
        "hash = fullHash(data || randomHash)");
    assert.ok(resource.expectedProof.equals(Cryptography.fullHash(Buffer.concat([data, resource.hash]))),
        "proof = fullHash(data || hash)");
    assert.ok(resource.packets[0].mapHash.equals(
        Cryptography.fullHash(Buffer.concat([resource.parts[0], resource.randomHash])).slice(0, 4)),
        "mapHash = fullHash(part || randomHash)[0:4]");
});

test("the payload is encrypted once as a whole, then split", () => {
    const { a } = linkPair();
    const data = Buffer.alloc(2000, 0x7F);
    const resource = new Resource(a);
    resource.prepareOutgoing(data);

    const rejoined = Buffer.concat(resource.parts);
    assert.equal(rejoined.length, resource.transferSize);
    assert.ok(a.decrypt(rejoined).equals(Buffer.concat([resource.randomHash, data])),
        "the concatenated parts decrypt to randomHash || data");
    for (const part of resource.parts) assert.ok(part.length <= Resource.SDU);
});

test("a part map collision is mapped again under a new salt (Rust 42e1c0a, Resource.py:440-470)", async () => {
    const { a, b } = linkPair();
    const data = bytes(5000, 11);
    const resource = new Resource(a);
    resource.initiator = true;
    // Under the first salt every part maps to the same hash; under any other
    // salt the real map hash applies.
    let firstSalt = null;
    resource.getMapHash = function (part) {
        firstSalt ??= Buffer.from(this.randomHash);
        return this.randomHash.equals(firstSalt)
            ? Buffer.alloc(Resource.MAPHASH_LEN, 0xAA)
            : Resource.prototype.getMapHash.call(this, part);
    };
    resource.prepareOutgoing(data);

    assert.ok(firstSalt && !resource.randomHash.equals(firstSalt), "the second pass drew a new salt");
    assert.ok(resource.hash.equals(Cryptography.fullHash(Buffer.concat([data, resource.randomHash]))), "hash from the new salt");
    assert.ok(resource.expectedProof.equals(Cryptography.fullHash(Buffer.concat([data, resource.hash]))), "proof from the new hash");
    assert.ok(resource.originalHash.equals(resource.hash), "a first segment's original hash follows it");
    assert.equal(new Set(resource.packets.map((p) => p.mapHash.toString("hex"))).size, resource.totalParts, "no collision left");

    // And the peer takes it.
    const received = receiveOn(b);
    const sent = new Promise((resolve, reject) => { resource.once("concluded", resolve); resource.once("failed", reject); });
    resource.advertise();
    await sent;
    assert.ok((await received).equals(data));
});

test("a request names the resource and the parts it wants", () => {
    const { a, b } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(bytes(1000, 1));

    const receiver = Resource.accept(b, advOf(sender));
    receiver.clearTimer();

    const request = receiver.lastRequest;
    assert.equal(request[0], Resource.HASHMAP_IS_NOT_EXHAUSTED, "hashmap is complete for a small resource");
    assert.ok(request.slice(1, 33).equals(sender.hash), "the resource hash follows the flag byte");
    const wanted = request.slice(33);
    assert.equal(wanted.length / 4, Math.min(Resource.WINDOW, sender.totalParts), "a window of map hashes is requested");
    assert.ok(wanted.slice(0, 4).equals(sender.packets[0].mapHash), "the first requested hash is the first part");
    receiver.cancel("test over");
});

// ── The first advertisement (DISTRO-SYNC-PROOF-DESIGN.md §5.3(a)) ─────────

test("advertise() reports its first advertisement once, before it is handed to the link, by the hash of the packet the link sends; the watchdog's re-advertisements are not reported, and what is sent is unchanged", async () => {
    // James, 2026-10-10: a Resource upload whose first advertisement no
    // interface carried never left the device. The advertisement's send says
    // nothing of that (RNS/Resource.py __advertise_job ignores
    // Packet.send()), so the sender learns its hash first and the interface
    // says whether it went (app.js _uploadForDistro, _onPacketsLost).
    const { a, wire } = linkPair({ drop: () => true });
    const transmitted = [];
    const transmit = a._transmit.bind(a);
    a._transmit = (raw, ...rest) => {
        transmitted.push(Packet.fromBytes(Buffer.from(raw)).packetHash.toString("hex"));
        return transmit(raw, ...rest);
    };
    const reports = [];
    const sent = a.sendResource(bytes(3000, 3), {
        onFirstAdvertisement: (packetHash, resource) => reports.push({ hash: packetHash.toString("hex"), resource, before: transmitted.length }),
    });
    sent.catch(() => {});
    assert.equal(reports.length, 1, "reported once");
    assert.equal(reports[0].before, 0, "before the packet is handed to the link");
    assert.deepEqual(transmitted, [reports[0].hash], "the hash is the sent packet's, as the interface's loss report names it");
    assert.equal(wire.a[0].context, Packet.RESOURCE_ADV);
    const resource = reports[0].resource;
    assert.ok(resource instanceof Resource && resource.status === Resource.ADVERTISED && a.outgoingResources.includes(resource),
        "the Resource itself, advertised");

    // The watchdog re-advertises (the protocol's own retries): sent, not reported.
    resource.watchdog(Date.now() + 3_600_000);
    assert.equal(transmitted.length, 2, "re-advertised");
    assert.equal(wire.a[1].context, Packet.RESOURCE_ADV);
    assert.equal(reports.length, 1, "only the first is reported");
    resource.cancel("test over");
    await assert.rejects(sent);

    // Without the option the same Resource goes the same way.
    const plain = linkPair({ drop: () => true });
    const quiet = plain.a.sendResource(bytes(3000, 3));
    quiet.catch(() => {});
    assert.equal(plain.wire.a.length, 1);
    assert.equal(plain.wire.a[0].context, Packet.RESOURCE_ADV);
    assert.equal(plain.a.outgoingResources[0].onFirstAdvertisement, null);
    plain.a.outgoingResources[0].cancel("test over");
    await assert.rejects(quiet);
});

// ── Transfers ─────────────────────────────────────────────────────────────

test("a resource larger than a link packet transfers end to end", async () => {
    const { a, b } = linkPair();
    const payload = bytes(9000, 1);
    const received = receiveOn(b);
    const resource = await a.sendResource(payload);
    assert.ok(resource.totalParts > 1);
    assert.ok((await received).equals(payload), "the reassembled payload matches byte for byte");
    assert.equal(a.outgoingResources.length, 0);
    assert.equal(b.incomingResources.length, 0);
});

test("a transfer needing more than one hashmap segment completes, with every update sent twice", async () => {
    // Only 74 map hashes fit in an advertisement, so this forces hashmap
    // updates. The wire delivers every RESOURCE_HMU twice.
    const { a, b } = linkPair();
    const deliver = b.onPacket.bind(b);
    b.onPacket = (packet) => { deliver(packet); if (packet.context === Packet.RESOURCE_HMU) deliver(packet); };
    const payload = bytes(464 * 200, 7);
    const received = receiveOn(b);
    const resource = await a.sendResource(payload);
    assert.ok(resource.totalParts > Resource.HASHMAP_MAX_LEN * 2);
    assert.ok((await received).equals(payload));
});

test("a repeated hashmap update is placed by segment, not appended (Resource.py hashmap_update)", () => {
    const { a, b } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(bytes(464 * 300, 5));
    const receiver = Resource.accept(b, advOf(sender));
    const segment1 = sender.hashmapRaw.slice(74 * 4, 148 * 4);
    for (let i = 0; i < 2; i++) {
        receiver.waitingForHashmapUpdate = true;
        receiver.onHashmapUpdate(Buffer.concat([sender.hash, MsgPack.pack([1, segment1])]));
    }
    assert.equal(receiver.hashmap.length, sender.totalParts, "one slot per part");
    assert.equal(receiver.hashmapHeight, 148, "two segments known, however often the second arrived");
    for (let i = 0; i < 148; i++) {
        assert.ok(receiver.hashmap[i].equals(sender.packets[i].mapHash), `part ${i}'s map hash is at index ${i}`);
    }
    assert.equal(receiver.hashmap[148], null, "the repeat did not land after it");
    assert.equal(receiver.status, Resource.TRANSFERRING);
    receiver.cancel("test over");
});

test("a re-sent advertisement is ignored while that Resource transfers (Link.py has_incoming_resource)", async () => {
    const { a, b } = linkPair();
    const deliver = b.onPacket.bind(b);
    b.onPacket = (packet) => { deliver(packet); if (packet.context === Packet.RESOURCE_ADV) deliver(packet); };
    const seen = [];
    b.setResourceStrategy(Link.ACCEPT_ALL);
    b.on("resource", ({ data }) => seen.push(data));
    const payload = bytes(3000, 3);
    await a.sendResource(payload);
    await settle(5);
    assert.equal(seen.length, 1, "one transfer, one delivery");
    assert.ok(seen[0].equals(payload));
});

test("the same advertisement twice makes one incoming Resource", () => {
    const { a, b } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(bytes(3000));
    const first = Resource.accept(b, advOf(sender));
    assert.ok(first);
    assert.equal(Resource.accept(b, advOf(sender)), null, "ignored, not rejected");
    assert.equal(b.incomingResources.length, 1);
    first.cancel("test over");
});

test("the sender serves a requested hash from the collision-guard window, not the first match", () => {
    // Map hashes are unique only within COLLISION_GUARD_SIZE parts. Give
    // parts 0 and 250 the same one; a receiver past part 200 wants 250.
    const { a, wire } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.initiator = true;
    sender.getMapHash = function (part) {
        const i = this._mapIndex = (this._mapIndex ?? -1) + 1;
        return (i % 300 === 0 || i % 300 === 250) ? Buffer.alloc(4, 0xBB) : Resource.prototype.getMapHash.call(this, part);
    };
    sender.prepareOutgoing(bytes(464 * 300 - 100, 3));
    assert.ok(sender.packets[0].mapHash.equals(sender.packets[250].mapHash));
    sender.advertise();
    sender.receiverMinConsecutiveHeight = 200;
    sender.onRequest(Buffer.concat([Buffer.from([0]), sender.hash, Buffer.alloc(4, 0xBB)]));
    const parts = wire.a.filter((p) => p.context === Packet.RESOURCE);
    assert.equal(parts.length, 1);
    assert.ok(parts[0].data.equals(sender.parts[250]), "part 250, the one in the receiver's window");
    sender.cancel("test over");
});

test("a byte-identical repeat of a part request is ignored (Link.py req_hashlist)", () => {
    const { a, wire } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.initiator = true;
    sender.prepareOutgoing(bytes(3000));
    sender.advertise();
    const request = Buffer.concat([Buffer.from([0]), sender.hash, sender.packets[0].mapHash]);
    const packetHash = Buffer.alloc(32, 0x42);
    sender.onRequest(request, packetHash);
    sender.onRequest(request, packetHash);
    assert.equal(wire.a.filter((p) => p.context === Packet.RESOURCE).length, 1);
    sender.onRequest(request, Buffer.alloc(32, 0x43));
    assert.equal(wire.a.filter((p) => p.context === Packet.RESOURCE).length, 2, "a new request for the same part is served");
    sender.cancel("test over");
});

test("a lost part is asked for again: the retry names only what is missing and shrinks the window", async () => {
    let dropped = false;
    const { a, b } = linkPair({
        drop: (packet, from) => {
            if (from === "a" && packet.context === Packet.RESOURCE && !dropped && sender?.packets[1]?.raw.equals(packet.raw)) {
                dropped = true;
                return true;
            }
            return false;
        },
    });
    let sender = null;
    const received = receiveOn(b);
    const sending = new Promise((resolve) => {
        sender = new Resource(a);
        sender.initiator = true;
        sender.prepareOutgoing(bytes(464 * 20, 13));
        sender.once("concluded", resolve);
        sender.advertise();
    });
    await settle(20);
    const receiver = b.incomingResources[0];
    assert.ok(dropped, "part 1 was lost");
    assert.equal(receiver.outstandingParts, 1, "three of the first window's four parts arrived");
    assert.equal(receiver.window, 4);

    // The part timeout passes.
    receiver.watchdog(Date.now() + 60_000);
    const retry = receiver.lastRequest;
    assert.equal(retry[0], Resource.HASHMAP_IS_NOT_EXHAUSTED);
    assert.equal(retry.length, 1 + 32 + 4, "one map hash: parts already received are not asked for again");
    assert.ok(retry.slice(33, 37).equals(sender.packets[1].mapHash));
    assert.equal(receiver.window, 3, "the window shrinks by one");
    assert.ok(receiver.windowMax < Resource.WINDOW_MAX_SLOW, "and so does its ceiling");
    assert.equal(receiver.retriesLeft, Resource.MAX_RETRIES - 1);

    await sending;
    assert.ok((await received).equals(bytes(464 * 20, 13)));
});

/** Feed a receiver round by round, `roundMs` per round, returning its window after each. */
function windowsOverRounds(roundMs, rounds) {
    const { a, b } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(bytes(464 * 70, 3));
    const receiver = Resource.accept(b, advOf(sender));
    const windows = [receiver.window];
    for (let r = 0; r < rounds; r++) {
        receiver.reqSent = Date.now() - roundMs;
        receiver.reqResp = null;
        const wanted = receiver.lastRequest.slice(33);
        for (let i = 0; i < wanted.length / 4; i++) {
            const entry = sender.packets.find((p) => p.mapHash.equals(wanted.slice(i * 4, i * 4 + 4)));
            receiver.onPart(sender.parts[sender.packets.indexOf(entry)], entry.raw.length);
        }
        windows.push(receiver.window);
    }
    const result = { windows, windowMax: receiver.windowMax };
    receiver.cancel("test over");
    return result;
}

test("the receiver's window starts at WINDOW and grows one per round to WINDOW_MAX_SLOW on a slow link", () => {
    // About 1.9 KB per second: slower than RATE_FAST (50 kbps).
    const { windows, windowMax } = windowsOverRounds(1000, 9);
    assert.deepEqual(windows, [4, 5, 6, 7, 8, 9, 10, 10, 10, 10]);
    assert.equal(windowMax, Resource.WINDOW_MAX_SLOW);
});

test("a sustained fast rate lifts the ceiling to WINDOW_MAX_FAST; a very slow one lowers it", () => {
    const fast = windowsOverRounds(1, 12);
    assert.equal(fast.windowMax, Resource.WINDOW_MAX_FAST, "after FAST_RATE_THRESHOLD fast rounds");
    assert.ok(fast.windows.at(-1) > Resource.WINDOW_MAX_SLOW);

    const verySlow = windowsOverRounds(30_000, 4);   // about 60 bytes per second
    assert.equal(verySlow.windowMax, Resource.WINDOW_MAX_VERY_SLOW, "after VERY_SLOW_RATE_THRESHOLD very slow rounds");
});

// ── Timers read the link's RTT in milliseconds ────────────────────────────

test("timers read the link's RTT in milliseconds", () => {
    const { a, b } = linkPair({ rttMs: 1500, drop: () => true });
    const sender = new Resource(a);
    sender.initiator = true;
    sender.prepareOutgoing(bytes(3000));
    sender.advertise();
    assert.equal(sender.nextDeadline() - sender.advSent, 1500 * 6 + 1000,
        "advertisement: link rtt * traffic_timeout_factor + PROCESSING_GRACE, about 10 s (was 2.5 hours)");
    const receiver = Resource.accept(b, advOf(sender));
    assert.equal(receiver.partTimeoutMs(), 1500 * 6, "a lost part is asked for again after about 9 s");
    sender.cancel("test over");
    receiver.cancel("test over");
});

// ── The link's state ──────────────────────────────────────────────────────

test("a Resource on a link that is not ACTIVE fails at once and advertises nothing", async () => {
    // A failure that waited for a timer would move the virtual clock; how
    // long the machine takes does not.
    for (const status of [Link.CLOSED, Link.STALE, Link.PENDING]) {
        const { a, wire } = linkPair();
        a.status = status;
        // A PENDING link has no keys yet: nothing may be encrypted with it.
        if (status === Link.PENDING) a.derivedKey = null;
        const started = clock.now();
        await assert.rejects(a.sendResource(bytes(2000)), /link is not active/);
        assert.equal(clock.now() - started, 0, "at once, not when a timer runs out");
        assert.equal(wire.a.length, 0, `nothing on the wire from a ${status} link`);
        assert.equal(a.outgoingResources.length, 0);
    }
});

test("closing the link fails its Resources in both directions (Link.py link_closed, Rust 6e53dea)", async () => {
    // Parts never arrive, so the transfer is in flight when the link closes.
    const { a, b } = linkPair({ drop: (packet) => packet.context === Packet.RESOURCE });
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const sending = a.sendResource(bytes(5000));
    await settle(5);
    assert.equal(a.outgoingResources.length, 1);
    assert.equal(b.incomingResources.length, 1);
    const incoming = b.incomingResources[0];
    const incomingFailed = once(incoming, "failed");

    a.close();                                    // LINKCLOSE reaches b
    await assert.rejects(within(sending, 2000, "the sending Resource"), /link closed/);
    assert.equal(await within(incomingFailed, 2000, "the receiving Resource"), "link closed");
    assert.equal(b.status, Link.CLOSED);
    assert.equal(a.outgoingResources.length, 0);
    assert.equal(b.incomingResources.length, 0);
});

test("the sender re-advertises up to MAX_ADV_RETRIES times, then fails", async () => {
    const { a, wire } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.initiator = true;
    sender.prepareOutgoing(bytes(2000));
    const failed = once(sender, "failed");
    sender.advertise();
    const advs = () => wire.a.filter((p) => p.context === Packet.RESOURCE_ADV).length;
    assert.equal(advs(), 1);
    for (let i = 1; i <= Resource.MAX_ADV_RETRIES; i++) {
        sender.watchdog(Date.now() + i * 60_000);
        assert.equal(advs(), 1 + i, `re-advertisement ${i}`);
    }
    sender.watchdog(Date.now() + 3_600_000);
    assert.equal(await failed, "no response to the resource advertisement");
    assert.equal(advs(), 1 + Resource.MAX_ADV_RETRIES);
});

// ── Progress ──────────────────────────────────────────────────────────────

test("both ends report progress as a fraction of parts, and the link re-emits it", async () => {
    const { a, b } = linkPair();
    const sent = [], linkSent = [], linkReceived = [];
    a.on("resource_progress", ({ progress, initiator }) => { assert.equal(initiator, true); linkSent.push(progress); });
    b.on("resource_progress", ({ progress, initiator }) => { assert.equal(initiator, false); linkReceived.push(progress); });
    const received = receiveOn(b);
    await a.sendResource(bytes(464 * 30), { onProgress: (p) => sent.push(p) });
    await received;
    await settle(5);
    for (const series of [sent, linkSent, linkReceived]) {
        assert.ok(series.length >= 3, "several reports");
        assert.ok(series.every((p, i) => p >= 0 && p <= 1 && (i === 0 || p >= series[i - 1])), `non-decreasing in 0..1: ${series}`);
        assert.equal(series.at(-1), 1);
    }
});

// ── What the receiver refuses ─────────────────────────────────────────────

test("an advertisement whose part count disagrees with ceil(t/sdu) is rejected", async () => {
    const { a, b, wire } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(bytes(9000));
    const adv = advOf(sender);
    const n = get(adv, "n");
    for (const bad of [n + 1, n - 1, Math.ceil(get(adv, "t") / 431)]) {
        assert.equal(Resource.accept(b, withAdv(adv, { n: bad })), null, `n=${bad}`);
    }
    assert.equal(b.incomingResources.length, 0);
    assert.ok(wire.b.every((p) => p.context === Packet.RESOURCE_RCL), "each is refused with RCL");
});

test("compressed and metadata advertisements are rejected; a split one is accepted", () => {
    const { a, b } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(bytes(500));
    const adv = advOf(sender);
    for (const [flag, label] of [[0x02, "compressed"], [0x20, "metadata"]]) {
        assert.equal(new Resource(b).applyAdvertisement(withAdv(adv, { f: 0x01 | flag })), false, `${label} must be rejected`);
    }
    const segment = withAdv(adv, { f: 0x05, i: 1, l: 2, d: Resource.MAX_EFFICIENT_SIZE + 500 });
    assert.equal(new Resource(b).applyAdvertisement(segment), true, "segment 1 of 2");
    assert.equal(new Resource(b).applyAdvertisement(withAdv(segment, { l: 3 })), false, "l must match d");
    assert.equal(new Resource(b).applyAdvertisement(withAdv(segment, { i: 3 })), false, "i <= l");
});

test("a corrupted part is never delivered, and the receiver tells the sender", async () => {
    let corrupted = false;
    const { a, b } = linkPair();
    const deliver = b.onPacket.bind(b);
    b.onPacket = (packet) => {
        if (packet.context === Packet.RESOURCE && !corrupted) {
            corrupted = true;
            const data = Buffer.from(packet.data);
            data[0] ^= 0xFF;
            deliver({ ...packet, data, context: packet.context, raw: packet.raw });
            return;
        }
        deliver(packet);
    };
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const delivered = [];
    b.on("resource", (e) => delivered.push(e));
    const sending = a.sendResource(bytes(2000, 3));
    await settle(10);
    const receiver = b.incomingResources[0];
    // The tampered part matches no map hash; give up at once.
    receiver.retriesLeft = 0;
    receiver.watchdog(Date.now() + 60_000);
    await assert.rejects(sending, /rejected/, "the receiver's RCL fails the sender at once");
    await settle(5);
    assert.equal(delivered.length, 0);
});

test("the peer's proof is checked against the expected proof; a wrong one is ignored", async () => {
    const { a } = linkPair({ drop: () => true });
    const resource = new Resource(a);
    resource.initiator = true;
    resource.prepareOutgoing(Buffer.from("a payload worth proving", "utf8"));
    resource.advertise();
    let concluded = false;
    resource.once("concluded", () => { concluded = true; });
    resource.onProof(Buffer.concat([resource.hash, Buffer.alloc(32, 0xEE)]));
    await settle();
    assert.equal(concluded, false, "a wrong proof does not conclude (Resource.py validate_proof ignores it)");
    assert.equal(resource.status, Resource.ADVERTISED);
    resource.onProof(Buffer.concat([resource.hash, resource.expectedProof]));
    await settle();
    assert.equal(concluded, true, "the expected proof concludes the transfer");
});

test("a part belonging to another transfer does not disturb this one", () => {
    const { a, b } = linkPair({ drop: () => true });
    const sender = new Resource(a);
    sender.prepareOutgoing(Buffer.alloc(1000, 0x44));
    const receiver = Resource.accept(b, advOf(sender));
    const before = receiver.outstandingParts;
    assert.equal(receiver.onPart(Buffer.alloc(464, 0xFF)), false, "an unknown part is not claimed");
    assert.equal(receiver.outstandingParts, before, "the window is untouched");
    assert.equal(receiver.receivedCount, 0);
    receiver.cancel("test over");
});

test("the packet layer does not re-encrypt parts or proofs", () => {
    // RNS/Packet.py:195-201 exempts both: "A resource takes care of encryption
    // by itself". Encrypting a part again would make the receiver's map hashes
    // — computed over the ciphertext as sent — impossible to match.
    const payload = Buffer.from("payload", "utf8");
    const destination = { encrypt: () => Buffer.from("ENCRYPTED-BY-PACKET-LAYER", "utf8") };
    const pack = (context, packetType) => {
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = packetType;
        packet.transportType = Transport.BROADCAST;
        packet.context = context;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = destination;
        packet.destinationHash = Buffer.alloc(16, 0xAB);
        packet.destinationType = Destination.LINK;
        packet.data = payload;
        return packet.pack();
    };
    assert.ok(pack(Packet.RESOURCE, Packet.DATA).includes(payload), "resource parts go out as-is");
    assert.ok(pack(Packet.RESOURCE_PRF, Packet.PROOF).includes(payload), "resource proofs go out as-is");
    assert.ok(!pack(Packet.RESOURCE_ADV, Packet.DATA).includes(payload), "advertisements are still encrypted by the packet layer");
    assert.ok(!pack(Packet.RESOURCE_REQ, Packet.DATA).includes(payload), "part requests are still encrypted by the packet layer");
});
