/**
 * Resource transfer tests.
 *
 * A link data packet carries at most 431 bytes. Before this, anything larger
 * threw ("Link payload of N bytes exceeds the link MDU"), so long channel
 * messages and long DMs could not be sent at all. RNS solves this with the
 * Resource protocol, which these tests exercise.
 *
 * The wire format is fixed by Reticulum-master/RNS/Resource.py and
 * Reticulum-rust/src/resource.rs. The advertisement layout, the map-hash
 * derivation, the request layout and the proof layout are all asserted against
 * those references here — if they drift, transfers to Python and Rust nodes
 * fail silently rather than loudly, so these assertions are the guard.
 *
 * Run: node --test resource.test.mjs
 */

import assert from "node:assert/strict";
import test from "node:test";

import Cryptography from "./lib/rns/cryptography.js";
import Destination from "./lib/rns/destination.js";
import MsgPack from "./lib/rns/msgpack.js";
import Packet from "./lib/rns/packet.js";
import Resource from "./lib/rns/resource.js";
import Transport from "./lib/rns/transport.js";

/**
 * A stand-in for Link that records what would go on the wire. Encryption is a
 * reversible transform with the same 48-byte overhead and 16-byte block
 * alignment as the real token, so part counts match production.
 */
class FakeLink {
    constructor(name) {
        this.name = name;
        this.rtt = 0.05;
        this.hash = Buffer.alloc(16, 0xAB);
        this.attachedInterface = { name: "fake" };
        this.incomingResources = [];
        this.outgoingResources = [];
        this.sent = [];
        this.peer = null;
        this.destination = {
            rns: {
                sendData: (raw, iface) => this.onWire(raw, iface),
            },
        };
    }

    /**
     * Stands in for the link's token. Real link encryption chains blocks, so
     * repeated plaintext never yields repeated ciphertext; this keystream
     * reproduces that property, which the resource's map hashes rely on.
     */
    encrypt(data) {
        const padding = 16 - (data.length % 16);
        const padded = Buffer.concat([data, Buffer.alloc(padding, padding)]);
        const body = Buffer.from(padded.map((b, i) => b ^ ((i * 31 + 7) & 0xFF)));
        return Buffer.concat([Buffer.alloc(16, 0x11), body, Buffer.alloc(32, 0x22)]);
    }

    decrypt(data) {
        const body = data.slice(16, data.length - 32);
        const padded = Buffer.from(body.map((b, i) => b ^ ((i * 31 + 7) & 0xFF)));
        const padding = padded[padded.length - 1];
        return padded.slice(0, padded.length - padding);
    }

    // Resource builds packets through the link, but for the loopback we only
    // need the context and payload, so we hand back a marker object.
    newLinkPacket(context, data, packetType) {
        const link = this;
        return {
            context,
            data,
            packetType: packetType ?? Packet.DATA,
            pack() {
                return { context, data, packetType: packetType ?? Packet.DATA, from: link.name };
            },
        };
    }

    onWire(frame) {
        this.sent.push(frame);
        if(this.peer && !this.paused){
            this.peer.deliver(frame);
        }
    }

    /** Deliver a frame as the stack's Link.onPacket would. */
    deliver(frame) {
        const data = frame.data;
        if(frame.context === Packet.RESOURCE_ADV){
            Resource.accept(this, MsgPack.unpack(this.decrypt(data)));
        } else if(frame.context === Packet.RESOURCE){
            for(const resource of [...this.incomingResources]){
                if(resource.onPart(data)) break;
            }
        } else if(frame.context === Packet.RESOURCE_REQ){
            const request = this.decrypt(data);
            const offset = request[0] === Resource.HASHMAP_IS_EXHAUSTED ? 1 + Resource.MAPHASH_LEN : 1;
            const hash = request.slice(offset, offset + Resource.HASHLENGTH_IN_BYTES);
            this.outgoingResources.find((r) => r.hash.equals(hash))?.onRequest(request);
        } else if(frame.context === Packet.RESOURCE_HMU){
            const update = this.decrypt(data);
            const hash = update.slice(0, Resource.HASHLENGTH_IN_BYTES);
            this.incomingResources.find((r) => r.hash.equals(hash))?.onHashmapUpdate(update);
        } else if(frame.context === Packet.RESOURCE_PRF){
            const hash = data.slice(0, Resource.HASHLENGTH_IN_BYTES);
            this.outgoingResources.find((r) => r.hash.equals(hash))?.onProof(data);
        }
    }
}

function linkedPair() {
    const a = new FakeLink("a");
    const b = new FakeLink("b");
    a.peer = b;
    b.peer = a;
    // The receiver decrypts with the same transform in this harness.
    return [a, b];
}

/**
 * Watch a link for incoming resources. Must be installed before the transfer
 * starts, because a resource is removed from the link once it concludes.
 */
function captureIncoming(link, onAccept) {
    const holder = { accepted: null, concluded: null };
    const push = Array.prototype.push;
    link.incomingResources.push = function(resource) {
        holder.accepted = resource;
        resource.once("concluded", (r) => { holder.concluded = r; });
        onAccept?.(resource);
        return push.call(this, resource);
    };
    return holder;
}

/** The event emitter dispatches on a timer, so let it run. */
function tick() {
    return new Promise((resolve) => setTimeout(resolve, 0));
}

// The advertisement and request paths are encrypted by the packet layer in
// production; here Resource hands plaintext to the link, so wrap the send.
function encryptOnWire(link) {
    const original = link.onWire.bind(link);
    link.onWire = (frame) => {
        if(frame.context === Packet.RESOURCE || frame.context === Packet.RESOURCE_PRF){
            original(frame);
        } else {
            original({ ...frame, data: link.encrypt(frame.data) });
        }
    };
}

test("the part size matches the link MDU", () => {
    assert.equal(Resource.SDU, 431);
    assert.equal(Resource.HASHMAP_MAX_LEN, 74);
});

test("the advertisement carries the keys the Python and Rust nodes read", () => {
    const [a] = linkedPair();
    const resource = new Resource(a);
    resource.prepareOutgoing(Buffer.alloc(1200, 0x5A));

    const adv = MsgPack.unpack(resource.packAdvertisement(0));
    const get = (k) => (adv instanceof Map ? adv.get(k) : adv[k]);

    for(const key of ["t", "d", "n", "h", "r", "o", "i", "l", "q", "f", "m"]){
        assert.ok(adv instanceof Map ? adv.has(key) : key in adv, `advertisement is missing key "${key}"`);
    }

    assert.equal(get("d"), 1200, "d is the uncompressed payload size");
    assert.equal(get("t"), resource.transferSize, "t is the encrypted transfer size");
    assert.equal(get("n"), resource.totalParts);
    assert.equal(Buffer.from(get("h")).length, 32, "h is a full 32 byte hash");
    assert.equal(Buffer.from(get("r")).length, 4, "r is a 4 byte random hash");
    assert.ok(Buffer.from(get("o")).equals(Buffer.from(get("h"))), "o equals h for a single segment");
    assert.equal(get("i"), 1, "segments are 1-indexed");
    assert.equal(get("l"), 1);
    assert.equal(get("f"), 0x01, "encrypted, not compressed/split/request/response/metadata");
    assert.equal(Buffer.from(get("m")).length, resource.totalParts * 4, "m holds one 4 byte map hash per part");

    // The advertisement itself has to fit in a single link packet.
    assert.ok(resource.packAdvertisement(0).length <= 431);
});

test("the resource hash and proof are derived the way the reference does", () => {
    const [a] = linkedPair();
    const data = Buffer.from("reference vectors matter", "utf8");
    const resource = new Resource(a);
    resource.prepareOutgoing(data);

    assert.ok(
        resource.hash.equals(Cryptography.fullHash(Buffer.concat([data, resource.randomHash]))),
        "hash = fullHash(data || randomHash)",
    );
    assert.ok(
        resource.expectedProof.equals(Cryptography.fullHash(Buffer.concat([data, resource.hash]))),
        "proof = fullHash(data || hash)",
    );
    assert.ok(
        resource.packets[0].mapHash.equals(
            Cryptography.fullHash(Buffer.concat([resource.parts[0], resource.randomHash])).slice(0, 4),
        ),
        "mapHash = fullHash(part || randomHash)[0:4]",
    );
});

test("the payload is encrypted once as a whole, then split", () => {
    const [a] = linkedPair();
    const data = Buffer.alloc(2000, 0x7F);
    const resource = new Resource(a);
    resource.prepareOutgoing(data);

    const rejoined = Buffer.concat(resource.parts);
    assert.equal(rejoined.length, resource.transferSize);
    assert.ok(
        a.decrypt(rejoined).equals(Buffer.concat([resource.randomHash, data])),
        "the concatenated parts decrypt to randomHash || data",
    );
    for(const part of resource.parts){
        assert.ok(part.length <= Resource.SDU, "no part exceeds the link MDU");
    }
});

test("a request names the resource and the parts it wants", () => {
    const [a, b] = linkedPair();
    const sender = new Resource(a);
    sender.prepareOutgoing(Buffer.alloc(1000, 0x01));

    const receiver = new Resource(b);
    receiver.applyAdvertisement(MsgPack.unpack(sender.packAdvertisement(0)));
    receiver.requestNext();
    receiver.clearTimer();

    const request = receiver.lastRequest;
    assert.equal(request[0], Resource.HASHMAP_IS_NOT_EXHAUSTED, "hashmap is complete for a small resource");
    assert.ok(request.slice(1, 33).equals(sender.hash), "the resource hash follows the flag byte");

    const wanted = request.slice(33);
    assert.equal(wanted.length % 4, 0);
    assert.equal(wanted.length / 4, Math.min(Resource.WINDOW, sender.totalParts), "a window of map hashes is requested");
    assert.ok(wanted.slice(0, 4).equals(sender.packets[0].mapHash), "the first requested hash is the first part");
});

test("a resource larger than a link packet transfers end to end", async () => {
    const [a, b] = linkedPair();
    encryptOnWire(a);
    encryptOnWire(b);

    const payload = Buffer.from(Array.from({ length: 9000 }, (_, i) => i % 251));
    const incoming = captureIncoming(b);

    const resource = await Resource.send(a, payload);
    // The receiver proves the transfer before it announces its own conclusion,
    // so the sender resolves first.
    await tick();

    assert.ok(payload.length > 431, "the payload really was larger than a single link packet");
    assert.ok(resource.totalParts > 1);
    assert.ok(incoming.concluded, "the receiver concluded a resource");
    assert.ok(incoming.concluded.data.equals(payload), "the reassembled payload matches byte for byte");
});

test("a transfer needing more than one hashmap segment completes", async () => {
    const [a, b] = linkedPair();
    encryptOnWire(a);
    encryptOnWire(b);

    // Only 74 map hashes fit in an advertisement, so this forces hashmap updates.
    const payload = Buffer.from(Array.from({ length: 431 * 200 }, (_, i) => (i * 7) % 251));
    const incoming = captureIncoming(b);

    const resource = await Resource.send(a, payload);
    await tick();

    assert.ok(resource.totalParts > Resource.HASHMAP_MAX_LEN, "more parts than fit in one hashmap segment");
    assert.ok(incoming.concluded, "the receiver concluded a resource");
    assert.ok(incoming.concluded.data.equals(payload));
});

test("a corrupted part is rejected rather than delivered", async () => {
    const [a, b] = linkedPair();
    encryptOnWire(a);
    encryptOnWire(b);

    const payload = Buffer.from(Array.from({ length: 2000 }, (_, i) => (i * 3) % 251));

    let corrupted = false;
    const originalDeliver = b.deliver.bind(b);
    b.deliver = (frame) => {
        if(frame.context === Packet.RESOURCE && !corrupted){
            corrupted = true;
            const tampered = Buffer.from(frame.data);
            tampered[0] ^= 0xFF;
            originalDeliver({ ...frame, data: tampered });
            return;
        }
        originalDeliver(frame);
    };

    // Stop the receiver re-requesting so the test does not wait out the retries.
    const incoming = captureIncoming(b, (resource) => { resource.retriesLeft = 0; });

    await assert.rejects(Resource.send(a, payload));
    await tick();
    assert.equal(incoming.concluded, null, "a resource with a corrupted part is never concluded");
});

test("the peer's proof is verified against the expected proof", async () => {
    const [a] = linkedPair();
    const resource = new Resource(a);
    resource.prepareOutgoing(Buffer.from("a payload worth proving", "utf8"));

    let failed = null;
    resource.once("failed", (reason) => { failed = reason; });
    resource.onProof(Buffer.concat([resource.hash, Buffer.alloc(32, 0xEE)]));
    await tick();
    assert.ok(failed, "a wrong proof fails the transfer");

    const good = new Resource(a);
    good.prepareOutgoing(Buffer.from("a payload worth proving", "utf8"));
    let concluded = false;
    good.once("concluded", () => { concluded = true; });
    good.onProof(Buffer.concat([good.hash, good.expectedProof]));
    await tick();
    assert.equal(concluded, true, "the expected proof concludes the transfer");
});

test("advertisements we cannot handle are rejected, not mis-parsed", () => {
    const [a, b] = linkedPair();
    const sender = new Resource(a);
    sender.prepareOutgoing(Buffer.alloc(500, 0x02));

    for(const [flag, label] of [[0x02, "compressed"], [0x04, "split"], [0x20, "metadata"]]){
        const adv = MsgPack.unpack(sender.packAdvertisement(0));
        adv instanceof Map ? adv.set("f", 0x01 | flag) : (adv.f = 0x01 | flag);
        const resource = new Resource(b);
        assert.equal(resource.applyAdvertisement(adv), false, `${label} advertisements must be rejected`);
    }
});

test("a part belonging to another transfer does not disturb this one", () => {
    const [a, b] = linkedPair();
    const sender = new Resource(a);
    sender.prepareOutgoing(Buffer.alloc(1000, 0x44));

    const receiver = new Resource(b);
    receiver.applyAdvertisement(MsgPack.unpack(sender.packAdvertisement(0)));
    receiver.requestNext();
    receiver.clearTimer();

    const before = receiver.outstandingParts;
    assert.equal(receiver.onPart(Buffer.alloc(431, 0xFF)), false, "an unknown part is not claimed");
    assert.equal(receiver.outstandingParts, before, "the window is untouched");
    assert.equal(receiver.receivedCount, 0);
    receiver.clearTimer();
});

test("the packet layer does not re-encrypt parts or proofs", () => {
    // RNS/Packet.py:195-201 exempts both: "A resource takes care of encryption
    // by itself". Encrypting a part again would make the receiver's map hashes
    // — computed over the ciphertext as sent — impossible to match.
    const payload = Buffer.from("payload", "utf8");
    const destination = {
        encrypt: () => Buffer.from("ENCRYPTED-BY-PACKET-LAYER", "utf8"),
    };

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
    assert.ok(
        !pack(Packet.RESOURCE_ADV, Packet.DATA).includes(payload),
        "advertisements are still encrypted by the packet layer",
    );
    assert.ok(
        !pack(Packet.RESOURCE_REQ, Packet.DATA).includes(payload),
        "part requests are still encrypted by the packet layer",
    );
});
