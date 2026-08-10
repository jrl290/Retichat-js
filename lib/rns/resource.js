import Constants from "./constants.js";
import Cryptography from "./cryptography.js";
import EventEmitter from "./utils/events.js";
import MsgPack from "./msgpack.js";
import Packet from "./packet.js";

/**
 * Reticulum Resource transfer.
 *
 * A link data packet carries at most Link.MDU (431) bytes. Anything larger is
 * transferred as a Resource: the payload is encrypted as a whole, split into
 * MDU-sized parts, and advertised to the peer, which then pulls the parts it
 * is missing in windows and returns a proof once the reassembled data hashes
 * to the advertised value.
 *
 * Reference: Reticulum-master/RNS/Resource.py and Reticulum-rust/src/resource.rs.
 * The wire format is fixed by those implementations — every field name, length
 * and hash input below has to match them exactly or transfers to Python and
 * Rust nodes fail.
 *
 * Supported: single-segment, uncompressed transfers, in both directions.
 * Not supported: multi-segment split (payloads over 1 MiB), bzip2 compression,
 * metadata, and the Request/Response (`q`/`u`/`p`) variant. Advertisements
 * using those are rejected rather than mis-parsed.
 */
class Resource extends EventEmitter {

    // Protocol constants — see RNS/Resource.py.
    static WINDOW = 4;
    static WINDOW_MIN = 2;
    static WINDOW_MAX = 75;
    static WINDOW_FLEXIBILITY = 4;
    static MAPHASH_LEN = 4;
    static RANDOM_HASH_SIZE = 4;
    static HASHMAP_IS_NOT_EXHAUSTED = 0x00;
    static HASHMAP_IS_EXHAUSTED = 0xFF;
    static HASHLENGTH_IN_BYTES = 32;

    /** Part size. Python: `self.sdu = link.mdu or Resource.SDU`. */
    static SDU = Constants.LINK_MDU;

    /** Bytes of a packed advertisement that are not hashmap. RNS/Resource.py:1216. */
    static ADV_OVERHEAD = 134;
    static HASHMAP_MAX_LEN = Math.floor((Constants.LINK_MDU - Resource.ADV_OVERHEAD) / Resource.MAPHASH_LEN);
    static COLLISION_GUARD_SIZE = 2 * Resource.WINDOW_MAX + Resource.HASHMAP_MAX_LEN;

    // Largest payload we will send as a single-segment resource. Python splits
    // above this into multiple segments; we do not implement split, so we
    // refuse rather than emit something a peer would reassemble incorrectly.
    static MAX_EFFICIENT_SIZE = 1 * 1024 * 1024 - 1;

    // Statuses
    static NONE = 0x00;
    static ADVERTISED = 0x01;
    static TRANSFERRING = 0x02;
    static AWAITING_PROOF = 0x03;
    static ASSEMBLING = 0x04;
    static COMPLETE = 0x05;
    static FAILED = 0x06;
    static CORRUPT = 0x07;

    // Retransmission. A resource pulls missing parts, so a lost part is
    // re-requested rather than silently dropped — this is the protocol's own
    // recovery mechanism, not a workaround for a readiness bug.
    static PART_TIMEOUT_MS = 4000;
    static RTT_TIMEOUT_FACTOR = 6;
    static MAX_RETRIES = 8;
    static MAX_COLLISION_ATTEMPTS = 32;

    constructor(link) {
        super();
        this.link = link;
        this.status = Resource.NONE;
        this.initiator = false;

        this.hash = null;
        this.randomHash = null;
        this.expectedProof = null;
        this.data = null;

        this.sdu = Resource.SDU;
        this.totalParts = 0;
        this.parts = [];
        this.packets = [];
        this.hashmap = Buffer.alloc(0);
        this.hashmapHeight = 0;
        this.waitingForHashmapUpdate = false;

        this.window = Resource.WINDOW;
        this.windowMin = Resource.WINDOW_MIN;
        this.windowMax = Resource.WINDOW_MAX;
        this.consecutiveCompletedHeight = -1;
        this.outstandingParts = 0;
        this.receivedCount = 0;
        this.sentParts = 0;
        this.retriesLeft = Resource.MAX_RETRIES;
        this.timer = null;
    }

    // ---- Sending ----

    /**
     * Transfer data over a link as a resource.
     * @param link an established Link
     * @param data Buffer to transfer
     * @returns {Promise<Resource>} resolves when the peer has proved receipt
     */
    static send(link, data) {
        const resource = new Resource(link);
        resource.initiator = true;
        resource.prepareOutgoing(data);
        link.outgoingResources.push(resource);

        return new Promise((resolve, reject) => {
            resource.once("concluded", () => {
                resource.unregister();
                resolve(resource);
            });
            resource.once("failed", (reason) => {
                resource.unregister();
                reject(new Error(reason));
            });
            resource.advertise();
        });
    }

    prepareOutgoing(data) {
        if(data.length > Resource.MAX_EFFICIENT_SIZE){
            throw new Error(`Resource of ${data.length} bytes exceeds the single-segment limit of ${Resource.MAX_EFFICIENT_SIZE} bytes`);
        }

        this.uncompressedSize = data.length;

        let mapHashes;
        let parts;
        let encrypted;
        let attempts = 0;
        do {
            if(++attempts > Resource.MAX_COLLISION_ATTEMPTS){
                // Only reachable if the ciphertext repeats whole parts, which
                // real link encryption does not do. Failing beats spinning.
                throw new Error("could not build a collision-free resource hashmap");
            }
            this.randomHash = Cryptography.getRandomHash().slice(0, Resource.RANDOM_HASH_SIZE);

            // hash covers the plaintext payload plus the random hash; the proof
            // the receiver returns covers the payload plus that hash.
            this.hash = Cryptography.fullHash(Buffer.concat([data, this.randomHash]));
            this.expectedProof = Cryptography.fullHash(Buffer.concat([data, this.hash]));

            // The whole payload is link-encrypted once, then split. Part packets
            // are therefore not encrypted again at the packet layer.
            encrypted = this.link.encrypt(Buffer.concat([this.randomHash, data]));
            this.totalParts = Math.ceil(encrypted.length / this.sdu);

            parts = [];
            mapHashes = [];
            for(let i = 0; i < this.totalParts; i++){
                const part = encrypted.slice(i * this.sdu, Math.min((i + 1) * this.sdu, encrypted.length));
                parts.push(part);
                mapHashes.push(this.getMapHash(part));
            }
        } while(Resource.hasWindowCollision(mapHashes));

        this.transferSize = encrypted.length;
        this.parts = parts;
        this.hashmap = Buffer.concat(mapHashes);
        this.hashmapHeight = Math.ceil(this.totalParts / Resource.HASHMAP_MAX_LEN);
        this.packets = parts.map((part, i) => ({
            mapHash: mapHashes[i],
            raw: this.buildPartPacket(part),
            sent: false,
        }));
    }

    /**
     * Map hashes are truncated to 4 bytes, so two identical hashes inside the
     * receiver's search window would make those parts indistinguishable. Python
     * re-rolls the random hash until the window is collision-free.
     */
    static hasWindowCollision(mapHashes) {
        for(let i = 1; i < mapHashes.length; i++){
            for(let j = Math.max(0, i - Resource.COLLISION_GUARD_SIZE); j < i; j++){
                if(mapHashes[i].equals(mapHashes[j])) return true;
            }
        }
        return false;
    }

    getMapHash(data) {
        return Cryptography.fullHash(Buffer.concat([data, this.randomHash])).slice(0, Resource.MAPHASH_LEN);
    }

    advertise() {
        this.status = Resource.ADVERTISED;
        this.sendLinkPacket(Packet.RESOURCE_ADV, this.packAdvertisement(0));
        this.armTimer(() => this.fail("no response to resource advertisement"));
    }

    /** msgpack map, keys and types fixed by RNS/Resource.py ResourceAdvertisement. */
    packAdvertisement(segment) {
        const start = segment * Resource.HASHMAP_MAX_LEN;
        const end = Math.min((segment + 1) * Resource.HASHMAP_MAX_LEN, this.totalParts);

        const flags = 0x01; // encrypted; not compressed, split, request, response or metadata

        return MsgPack.pack(new Map([
            ["t", this.transferSize],
            ["d", this.uncompressedSize],
            ["n", this.totalParts],
            ["h", this.hash],
            ["r", this.randomHash],
            ["o", this.hash],
            ["i", 1],
            ["l", 1],
            ["q", null],
            ["f", flags],
            ["m", this.hashmap.slice(start * Resource.MAPHASH_LEN, end * Resource.MAPHASH_LEN)],
        ]));
    }

    /** Sender side: peer asked for a window of parts. */
    onRequest(requestData) {
        this.clearTimer();
        this.status = Resource.TRANSFERRING;

        const wantsMoreHashmap = requestData[0] === Resource.HASHMAP_IS_EXHAUSTED;
        const pad = wantsMoreHashmap ? 1 + Resource.MAPHASH_LEN : 1;
        const requested = requestData.slice(pad + Resource.HASHLENGTH_IN_BYTES);

        for(let i = 0; i < Math.floor(requested.length / Resource.MAPHASH_LEN); i++){
            const wanted = requested.slice(i * Resource.MAPHASH_LEN, (i + 1) * Resource.MAPHASH_LEN);
            const entry = this.packets.find((p) => p.mapHash.equals(wanted));
            if(entry){
                this.link.destination.rns.sendData(entry.raw, this.link.attachedInterface);
                if(!entry.sent){
                    entry.sent = true;
                    this.sentParts++;
                }
            }
        }

        if(wantsMoreHashmap){
            this.sendHashmapUpdate(requestData.slice(1, 1 + Resource.MAPHASH_LEN));
        }

        if(this.sentParts === this.packets.length){
            this.status = Resource.AWAITING_PROOF;
            this.armTimer(() => this.fail("peer never proved receipt of the resource"));
        } else {
            this.armTimer(() => this.fail("peer stopped requesting resource parts"));
        }
    }

    sendHashmapUpdate(lastMapHash) {
        const lastIndex = this.packets.map((p) => p.mapHash).findIndex((h) => h.equals(lastMapHash));
        if(lastIndex === -1){
            this.fail("hashmap update requested for an unknown part");
            return;
        }

        const partIndex = lastIndex + 1;
        const segment = partIndex % Resource.HASHMAP_MAX_LEN === 0
            ? partIndex / Resource.HASHMAP_MAX_LEN
            : Math.floor(lastIndex / Resource.HASHMAP_MAX_LEN) + 1;

        if(segment >= this.hashmapHeight){
            return;
        }

        const start = segment * Resource.HASHMAP_MAX_LEN;
        const end = Math.min((segment + 1) * Resource.HASHMAP_MAX_LEN, this.totalParts);
        const update = MsgPack.pack([segment, this.hashmap.slice(start * Resource.MAPHASH_LEN, end * Resource.MAPHASH_LEN)]);

        this.sendLinkPacket(Packet.RESOURCE_HMU, Buffer.concat([this.hash, update]));
    }

    /** Sender side: peer proved it reassembled the payload. */
    onProof(proofData) {
        if(proofData.length !== Resource.HASHLENGTH_IN_BYTES * 2){
            return;
        }
        if(!proofData.slice(Resource.HASHLENGTH_IN_BYTES).equals(this.expectedProof)){
            this.fail("resource proof did not match");
            return;
        }
        this.clearTimer();
        this.status = Resource.COMPLETE;
        this.emit("concluded", this);
    }

    // ---- Receiving ----

    /**
     * Accept an incoming resource advertisement.
     * @returns {Resource|null} null if the advertisement is one we cannot handle
     */
    static accept(link, advertisement) {
        const resource = new Resource(link);
        if(!resource.applyAdvertisement(advertisement)){
            resource.reject(advertisement);
            return null;
        }
        link.incomingResources.push(resource);
        resource.once("concluded", () => resource.unregister());
        resource.once("failed", () => resource.unregister());
        resource.requestNext();
        return resource;
    }

    unregister() {
        this.clearTimer();
        for(const list of [this.link.incomingResources, this.link.outgoingResources]){
            const index = list.indexOf(this);
            if(index !== -1) list.splice(index, 1);
        }
    }

    applyAdvertisement(advertisement) {
        const get = (key) => (advertisement instanceof Map ? advertisement.get(key) : advertisement[key]);

        const flags = Number(get("f") ?? 0);
        const compressed = (flags >> 1) & 0x01;
        const split = (flags >> 2) & 0x01;
        const hasMetadata = (flags >> 5) & 0x01;
        if(compressed || split || hasMetadata){
            console.warn(`[resource] rejecting advertisement with unsupported flags 0x${flags.toString(16)}`);
            return false;
        }

        this.encrypted = (flags & 0x01) === 0x01;
        this.hash = Buffer.from(get("h"));
        this.randomHash = Buffer.from(get("r"));
        this.transferSize = Number(get("t"));
        this.uncompressedSize = Number(get("d"));
        this.totalParts = Number(get("n"));
        this.hashmap = Buffer.from(get("m"));
        this.parts = new Array(this.totalParts).fill(null);
        this.status = Resource.TRANSFERRING;
        return true;
    }

    reject(advertisement) {
        const hash = advertisement instanceof Map ? advertisement.get("h") : advertisement?.h;
        if(hash){
            this.sendLinkPacket(Packet.RESOURCE_RCL, Buffer.from(hash));
        }
    }

    /** Receiver side: ask for the next window of missing parts. */
    requestNext() {
        if(this.status === Resource.FAILED || this.waitingForHashmapUpdate){
            return;
        }

        this.outstandingParts = 0;
        let exhausted = Resource.HASHMAP_IS_NOT_EXHAUSTED;
        const requested = [];

        let pn = Math.max(0, this.consecutiveCompletedHeight + 1);
        for(let searched = 0; searched < this.window; searched++){
            if(pn >= this.parts.length) break;
            if(this.parts[pn] === null){
                const idx = pn * Resource.MAPHASH_LEN;
                // We only hold map hashes for the segments advertised so far;
                // beyond that the sender has to send a hashmap update.
                if(idx + Resource.MAPHASH_LEN <= this.hashmap.length){
                    requested.push(this.hashmap.slice(idx, idx + Resource.MAPHASH_LEN));
                    this.outstandingParts++;
                } else {
                    exhausted = Resource.HASHMAP_IS_EXHAUSTED;
                }
            }
            pn++;
            if(this.outstandingParts >= this.window || exhausted === Resource.HASHMAP_IS_EXHAUSTED) break;
        }

        let prefix = Buffer.from([exhausted]);
        if(exhausted === Resource.HASHMAP_IS_EXHAUSTED){
            const lastIdx = Math.max(0, this.hashmapHeightReceived() - 1) * Resource.MAPHASH_LEN;
            prefix = Buffer.concat([prefix, this.hashmap.slice(lastIdx, lastIdx + Resource.MAPHASH_LEN)]);
            this.waitingForHashmapUpdate = true;
        }

        this.lastRequest = Buffer.concat([prefix, this.hash, ...requested]);
        this.sendLinkPacket(Packet.RESOURCE_REQ, this.lastRequest);
        this.armTimer(() => this.retryRequest());
    }

    hashmapHeightReceived() {
        return Math.floor(this.hashmap.length / Resource.MAPHASH_LEN);
    }

    retryRequest() {
        if(this.retriesLeft <= 0){
            this.fail("resource parts did not arrive");
            return;
        }
        this.retriesLeft--;
        this.sendLinkPacket(Packet.RESOURCE_REQ, this.lastRequest);
        this.armTimer(() => this.retryRequest());
    }

    /**
     * Receiver side: a part packet arrived. Part packets carry no resource
     * identifier, so every incoming resource on the link is offered the part
     * and identifies it by its map hash. A part we do not recognise belongs to
     * another transfer and must not disturb this one's window.
     *
     * @returns {boolean} whether the part belonged to this resource
     */
    onPart(partData) {
        const partHash = this.getMapHash(partData);

        let matched = -1;
        const start = Math.max(0, this.consecutiveCompletedHeight + 1);
        const searchEnd = Math.min(start + this.window, this.parts.length);
        for(let i = start; i < searchEnd; i++){
            const idx = i * Resource.MAPHASH_LEN;
            if(!this.hashmap.slice(idx, idx + Resource.MAPHASH_LEN).equals(partHash)) continue;
            if(this.parts[i] !== null) continue;
            matched = i;
            break;
        }

        if(matched === -1){
            return false;
        }

        this.clearTimer();
        this.parts[matched] = partData;
        this.receivedCount++;
        this.outstandingParts = Math.max(0, this.outstandingParts - 1);

        let cp = this.consecutiveCompletedHeight + 1;
        while(cp < this.parts.length && this.parts[cp] !== null){
            this.consecutiveCompletedHeight = cp;
            cp++;
        }
        this.emit("progress", this.receivedCount / this.totalParts);

        if(this.receivedCount === this.totalParts){
            this.assemble();
            return true;
        }

        if(this.outstandingParts === 0){
            if(this.window < this.windowMax){
                this.window++;
                if((this.window - this.windowMin) > (Resource.WINDOW_FLEXIBILITY - 1)){
                    this.windowMin++;
                }
            }
            this.requestNext();
        } else {
            this.armTimer(() => this.retryRequest());
        }
        return true;
    }

    /** Receiver side: the sender extended the hashmap. */
    onHashmapUpdate(payload) {
        const [, hashmap] = MsgPack.unpack(payload.slice(Resource.HASHLENGTH_IN_BYTES));
        const extension = Buffer.from(hashmap);
        // Segments arrive in order, each one appending to the map we hold.
        if(extension.length > 0){
            this.hashmap = Buffer.concat([this.hashmap, extension]);
        }
        this.waitingForHashmapUpdate = false;
        this.requestNext();
    }

    assemble() {
        this.clearTimer();
        this.status = Resource.ASSEMBLING;

        const stream = Buffer.concat(this.parts.map((p) => p ?? Buffer.alloc(0)));
        let data;
        try {
            data = this.encrypted ? this.link.decrypt(stream) : stream;
        } catch(e) {
            this.fail(`resource decryption failed: ${e.message}`);
            return;
        }

        data = data.slice(Resource.RANDOM_HASH_SIZE);

        if(!Cryptography.fullHash(Buffer.concat([data, this.randomHash])).equals(this.hash)){
            this.status = Resource.CORRUPT;
            this.fail("reassembled resource did not match the advertised hash");
            return;
        }

        this.data = data;
        this.status = Resource.COMPLETE;
        this.prove();
        this.emit("concluded", this);
    }

    prove() {
        const proof = Cryptography.fullHash(Buffer.concat([this.data, this.hash]));
        this.sendProofPacket(Buffer.concat([this.hash, proof]));
    }

    // ---- Packet plumbing ----

    buildPartPacket(part) {
        return this.link.newLinkPacket(Packet.RESOURCE, part).pack();
    }

    sendLinkPacket(context, data) {
        const raw = this.link.newLinkPacket(context, data).pack();
        this.link.destination.rns.sendData(raw, this.link.attachedInterface);
    }

    sendProofPacket(data) {
        const raw = this.link.newLinkPacket(Packet.RESOURCE_PRF, data, Packet.PROOF).pack();
        this.link.destination.rns.sendData(raw, this.link.attachedInterface);
    }

    /**
     * Parts are pulled, so a lost part has to be re-requested. The interval is
     * derived from the measured link RTT rather than being a fixed guess.
     */
    armTimer(onExpiry) {
        this.clearTimer();
        const rttMs = this.link.rtt ? this.link.rtt * 1000 : 0;
        const timeout = Math.max(Resource.PART_TIMEOUT_MS, Math.ceil(rttMs * Resource.RTT_TIMEOUT_FACTOR));
        this.timer = setTimeout(onExpiry, timeout);
    }

    clearTimer() {
        if(this.timer){
            clearTimeout(this.timer);
            this.timer = null;
        }
    }

    fail(reason) {
        this.clearTimer();
        if(this.status === Resource.FAILED) return;
        this.status = Resource.FAILED;
        console.warn(`[resource] ${reason}`);
        this.emit("failed", reason);
    }

}

export default Resource;
