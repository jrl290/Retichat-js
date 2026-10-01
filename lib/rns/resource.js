import Constants from "./constants.js";
import Cryptography from "./cryptography.js";
import EventEmitter from "./utils/events.js";
import MsgPack from "./msgpack.js";
import Packet from "./packet.js";

// Link.ACTIVE. link.js imports this module, so the value is repeated here
// rather than imported.
const LINK_ACTIVE = 0x02;

/**
 * Reticulum Resource transfer.
 *
 * A link data packet carries at most Link.MDU (431) bytes. Anything larger is
 * transferred as a Resource: the payload is encrypted as a whole, split into
 * parts, and advertised to the peer, which then pulls the parts it is missing
 * in windows and returns a proof once the reassembled data hashes to the
 * advertised value.
 *
 * Reference: RNS 1.5.2 RNS/Resource.py (the workspace .venv; Reticulum-master
 * is 1.1.3) and Reticulum-rust/src/resource.rs. The wire format is fixed by
 * those implementations — every field name, length and hash input below has
 * to match them exactly or transfers to Python and Rust nodes fail.
 *
 * Supported: uncompressed transfers in both directions, requests and
 * responses (`q`/`u`/`p`), and receiving a split (multi-segment) Resource.
 * The link reassembles the segments (link.js _incomingResourceConcluded).
 * Not supported: sending a split Resource (this client sends at most about
 * 1 MB, one segment), bzip2 compression, and metadata. Advertisements using
 * those are rejected rather than mis-parsed.
 *
 * Events: "progress" (fraction 0..1, as Resource.get_progress), "concluded"
 * (COMPLETE), "failed" (reason). Exactly one of the last two fires.
 *
 * DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30): a Resource's
 * total duration is not measured against 5 s, but from its advertisement on
 * it must show progress at least every QUIET_MS: a part received, a window
 * answered (the sender serving a request), a hashmap update, the proof. Every
 * Resource, sent or received, data, request or response, watches itself
 * (this.bulk, a BulkWatch, below): a silence longer than that is asserted and
 * logged as a §1 violation, once per silence, and its end is logged when
 * progress comes again. It never fails the transfer: the Resource's own
 * events (concluded, failed, cancelled, link closed) decide that. A
 * re-advertisement is not progress (the sender repeating itself is not the
 * transfer moving). Until 2026-10-01 only the Resources of a DM the web sent
 * were watched (lib/send_progress.js); the photos, files, rfed.link pushes,
 * /get responses, distro fan-out and channel publishes it moved were not.
 */

/**
 * DESIGN_PRINCIPLES §1, bulk transfers: the progress watch of one transfer.
 *
 * Event-driven bookkeeping: one timer, armed again from each progress event;
 * when it runs, nothing has moved since, and it asserts the silence, once.
 * An assertion timer, never a failure timer: nothing here changes the
 * transfer, whose own events end the watch (stop).
 *
 * The rule is a silence "longer than 5 seconds": exactly QUIET_MS is within
 * it (as the harness measures, test-harnesses resource_watch.mjs
 * resourceGaps), so the timer is armed for the first millisecond past it,
 * and one that runs early (a real timer can, by a millisecond) waits out the
 * rest.
 *
 * Every Resource has one (Resource.bulk), from its advertisement to its end.
 * A link reassembling a split Resource has one for each wait between a
 * segment's proof and the next segment's advertisement (link.js
 * _betweenSegments): the transfer is not over there, and no Resource is
 * running to watch it.
 */
class BulkWatch {

    /**
     * @param describe () => what the §1 lines call the transfer
     * @param state () => where it stands, for the violation line (or null)
     */
    constructor(describe, state = () => null) {
        this.describe = describe;
        this.state = state;
        this.startedAt = null;
        this.lastProgressAt = null;
        this.timer = null;
        // The silence it is in, if any, and every silence it has had:
        // { at, silentMs } (silentMs null while it lasts).
        this.silence = null;
        this.silences = [];
        this.ended = false;
    }

    /** The transfer starts: the advertisement sent or taken, or the wait for
     *  a split Resource's next segment begins. `startedAt` is when the whole
     *  transfer began, for the lines (default: now). */
    start(startedAt = null) {
        if(this.startedAt !== null || this.ended) return;
        const now = Date.now();
        this.startedAt = startedAt ?? now;
        this.lastProgressAt = now;
        this.arm(Resource.QUIET_MS + 1);
    }

    /** The transfer showed progress. Ends a silence, and says so. */
    progress() {
        if(this.startedAt === null || this.ended) return;
        const now = Date.now();
        if(this.silence){
            const silentMs = now - this.lastProgressAt;
            this.silence.silentMs = silentMs;
            this.silence = null;
            Resource.bulkLog.warn?.(`[§1] ${this.describe()}: progress again after ${(silentMs / 1000).toFixed(1)} s of silence`);
        }
        this.lastProgressAt = now;
        this.arm(Resource.QUIET_MS + 1);
    }

    arm(ms) {
        if(this.timer !== null) clearTimeout(this.timer);
        this.timer = setTimeout(() => this.check(), ms);
    }

    /** The timer ran out: more than QUIET_MS without progress is a violation. */
    check() {
        this.timer = null;
        if(this.ended || this.silence) return;
        const now = Date.now();
        const quietMs = now - this.lastProgressAt;
        if(quietMs <= Resource.QUIET_MS){
            this.arm(Resource.QUIET_MS + 1 - quietMs);
            return;
        }
        this.silence = { at: now, silentMs: null };
        this.silences.push(this.silence);
        const state = this.state();
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 (bulk transfers: no progress for over 5 s is a violation; it never fails the transfer)
        Resource.bulkLog.error?.(`[§1] VIOLATION ${this.describe()}: no progress for ${Resource.QUIET_MS / 1000} s `
            + `(${((now - this.startedAt) / 1000).toFixed(1)} s since it started${state ? `, ${state}` : ""}); `
            + "the Resource's own events decide its outcome");
    }

    /** The transfer ended (`how`): nothing more is watched. A silence it
     *  ended in is closed with its length. */
    stop(how) {
        if(this.ended) return;
        this.ended = true;
        if(this.timer !== null){
            clearTimeout(this.timer);
            this.timer = null;
        }
        if(this.silence){
            const silentMs = Date.now() - this.lastProgressAt;
            this.silence.silentMs = silentMs;
            this.silence = null;
            Resource.bulkLog.warn?.(`[§1] ${this.describe()}: ${how} after ${(silentMs / 1000).toFixed(1)} s of silence`);
        }
    }
}

class Resource extends EventEmitter {

    /** DESIGN_PRINCIPLES §1: the longest silence a moving transfer may have. */
    static QUIET_MS = 5_000;

    /** Where the §1 lines go: console (a test may put another log here). */
    static bulkLog = console;

    /** The §1 progress watch (a link watches the wait between segments with one). */
    static BulkWatch = BulkWatch;

    // Window control — RNS/Resource.py:59-100.
    static WINDOW = 4;
    static WINDOW_MIN = 2;
    static WINDOW_MAX_SLOW = 10;
    static WINDOW_MAX_VERY_SLOW = 4;
    static WINDOW_MAX_FAST = 75;
    static WINDOW_MAX = Resource.WINDOW_MAX_FAST;
    static FAST_RATE_THRESHOLD = Resource.WINDOW_MAX_SLOW - Resource.WINDOW - 2;
    static VERY_SLOW_RATE_THRESHOLD = 2;
    static RATE_FAST = (50 * 1000) / 8;        // bytes per second
    static RATE_VERY_SLOW = (2 * 1000) / 8;    // bytes per second
    static WINDOW_FLEXIBILITY = 4;

    static MAPHASH_LEN = 4;
    static RANDOM_HASH_SIZE = 4;
    static HASHMAP_IS_NOT_EXHAUSTED = 0x00;
    static HASHMAP_IS_EXHAUSTED = 0xFF;
    static HASHLENGTH_IN_BYTES = 32;

    /**
     * Part size. RNS 1.5.2 Resource.__init__: `if self.link.mtu: self.sdu =
     * self.link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` — 464 bytes on the
     * 500-byte MTU every link this client takes part in has (it signals no
     * MTU, and its proofs carry none). Parts are not encrypted per packet, so
     * the part is the whole payload of its packet. Rust does the same
     * (resource.rs, sdu from the link MTU). Until 2026-09-30 this was the
     * link MDU (431): a Python receiver, which counts parts as ceil(t/464),
     * dropped the advertisement whenever the two counts differed (t=896,
     * t=9008) or assembled a short stream.
     */
    static SDU = Constants.PACKET_MDU;

    /** Bytes of a packed advertisement that are not hashmap. RNS/Resource.py:1216. */
    static ADV_OVERHEAD = 134;
    static HASHMAP_MAX_LEN = Math.floor((Constants.LINK_MDU - Resource.ADV_OVERHEAD) / Resource.MAPHASH_LEN);
    static COLLISION_GUARD_SIZE = 2 * Resource.WINDOW_MAX + Resource.HASHMAP_MAX_LEN;

    // Largest single segment. Python and Rust split above this; this client
    // receives split Resources but sends only single segments.
    static MAX_EFFICIENT_SIZE = 1 * 1024 * 1024 - 1;
    static RESPONSE_MAX_GRACE_TIME = 10;

    // Timing — RNS/Resource.py:127-138 (seconds).
    static PROOF_TIMEOUT_FACTOR = 3;
    static MAX_RETRIES = 16;
    static MAX_ADV_RETRIES = 4;
    static SENDER_GRACE_TIME = 10.0;
    static PROCESSING_GRACE = 1.0;
    static PER_RETRY_DELAY = 0.5;
    static TRAFFIC_TIMEOUT_FACTOR = 6;         // Link.traffic_timeout_factor
    static PROOF_RETRIES = 3;                  // retries_left on AWAITING_PROOF

    // The receiver's part timeout. The reference derives it from its
    // expected in-flight rate (eifr, seeded from the link's establishment
    // cost, which this client does not track); here it is the larger of a
    // floor and RTT_TIMEOUT_FACTOR round trips, plus the reference's
    // PER_RETRY_DELAY for each retry already used.
    static PART_TIMEOUT_MS = 4000;
    static RTT_TIMEOUT_FACTOR = 6;
    static MAX_COLLISION_ATTEMPTS = 32;

    // Statuses — RNS/Resource.py:143-152.
    static NONE = 0x00;
    static QUEUED = 0x01;
    static ADVERTISED = 0x02;
    static TRANSFERRING = 0x03;
    static AWAITING_PROOF = 0x04;
    static ASSEMBLING = 0x05;
    static COMPLETE = 0x06;
    static FAILED = 0x07;
    static CORRUPT = 0x08;
    static REJECTED = 0x09;

    constructor(link) {
        super();
        this.link = link;
        this.status = Resource.NONE;
        this.initiator = false;

        this.hash = null;
        this.randomHash = null;
        this.originalHash = null;
        this.expectedProof = null;
        this.data = null;

        // RNS/Resource.py: a Resource may carry a link request or a response
        // instead of bare data. `request_id` rides in the advertisement as
        // `q`, with flag bit 3 (`u`) for a request and bit 4 (`p`) for a
        // response (ResourceAdvertisement.__init__). RNS/Link.py request()
        // sends a request larger than the MDU this way and handle_request()
        // its response; the receiver dispatches by these flags before any
        // resource strategy applies.
        this.requestId = null;
        this.isRequest = false;
        this.isResponse = false;

        // Segments of a split Resource (RNS/Resource.py: i, l, o).
        this.segmentIndex = 1;
        this.totalSegments = 1;
        this.split = false;
        this.totalSize = null;

        this.sdu = Resource.SDU;
        this.totalParts = 0;
        this.parts = [];
        this.sentParts = 0;
        this.receivedCount = 0;
        this.outstandingParts = 0;

        // Receiver: the map hash of each part, by part index, null until an
        // advertisement or hashmap update carries it.
        this.hashmap = [];
        this.hashmapHeight = 0;
        this.waitingForHashmapUpdate = false;
        this.consecutiveCompletedHeight = -1;

        // Sender: the packed parts and the whole map.
        this.packets = [];
        this.hashmapRaw = Buffer.alloc(0);
        this.receiverMinConsecutiveHeight = 0;
        this.reqHashlist = new Set();

        this.window = Resource.WINDOW;
        this.windowMax = Resource.WINDOW_MAX_SLOW;
        this.windowMin = Resource.WINDOW_MIN;
        this.windowFlexibility = Resource.WINDOW_FLEXIBILITY;
        this.maxRetries = Resource.MAX_RETRIES;
        this.maxAdvRetries = Resource.MAX_ADV_RETRIES;
        this.retriesLeft = this.maxRetries;

        // Round-trip and rate tracking (ms and bytes per second).
        this.rttMs = null;
        this.timeoutMs = null;
        this.advSent = 0;
        this.lastActivity = 0;
        this.lastPartSent = 0;
        this.reqSent = 0;
        this.reqSentBytes = 0;
        this.reqResp = null;
        this.rttRxdBytes = 0;
        this.rttRxdBytesAtPartReq = 0;
        this.reqRespRttRate = 0;
        this.reqDataRttRate = 0;
        this.fastRateRounds = 0;
        this.verySlowRateRounds = 0;

        this.timer = null;

        // §1 bulk-transfer watch, and what the app calls this transfer.
        this.label = null;
        this.bulk = new BulkWatch(() => this.describe(), () => `${(this.getProgress() * 100).toFixed(1)}% done`);
    }

    // ---- Sending ----

    /**
     * Transfer data over a link as a resource.
     * @param link an established Link
     * @param data Buffer to transfer
     * @param options { requestId, isRequest, isResponse, timeoutMs, onProgress,
     *   label (what the §1 lines call the transfer, e.g. "direct transfer of
     *   <message> to <conversation>") }
     * @returns {Promise<Resource>} resolves when the peer has proved receipt,
     *   rejects when the transfer fails (including at once on a link that is
     *   not ACTIVE)
     */
    static send(link, data, options = {}) {
        const resource = new Resource(link);
        resource.initiator = true;
        if(options.requestId){
            resource.requestId = Buffer.from(options.requestId);
            resource.isRequest = !!options.isRequest;
            resource.isResponse = !!options.isResponse;
        }
        if(options.timeoutMs != null){
            resource.timeoutMs = Number(options.timeoutMs);
        }
        if(typeof options.onProgress === "function"){
            resource.on("progress", options.onProgress);
        }
        if(options.label){
            resource.label = String(options.label);
        }
        const settled = new Promise((resolve, reject) => {
            resource.once("concluded", () => resolve(resource));
            resource.once("failed", (reason) => reject(new Error(reason)));
        });

        // RNS/Resource.py:529-545 ensure_link, before anything is built: a
        // Resource on a link that is not ACTIVE fails at once. Before
        // 2026-09-30 a Resource on a CLOSED link (which still held its key)
        // was built and advertised into the void, and its promise stayed
        // pending until a timer ran out.
        if(!resource.ensureLink()){
            return settled;
        }
        resource.prepareOutgoing(data);
        resource.advertise();
        return settled;
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
            // Every pass draws a new salt and recomputes everything derived
            // from it (RNS/Resource.py:440-470; Rust 42e1c0a): mapping again
            // under the same salt would collide again.
            this.randomHash = Cryptography.getRandomHash().slice(0, Resource.RANDOM_HASH_SIZE);

            // hash covers the plaintext payload plus the random hash; the proof
            // the receiver returns covers the payload plus that hash.
            this.hash = Cryptography.fullHash(Buffer.concat([data, this.randomHash]));
            this.expectedProof = Cryptography.fullHash(Buffer.concat([data, this.hash]));
            if(this.segmentIndex === 1 || !this.originalHash){
                this.originalHash = this.hash;
            }

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
        this.hashmapRaw = Buffer.concat(mapHashes);
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

    /** RNS/Resource.py __advertise_job. */
    advertise() {
        if(!this.ensureLink()) return;
        this.sendLinkPacket(Packet.RESOURCE_ADV, this.packAdvertisement(0));
        const now = Date.now();
        this.lastActivity = now;
        this.advSent = now;
        this.rttMs = null;
        this.status = Resource.ADVERTISED;
        this.retriesLeft = this.maxAdvRetries;
        if(!this.link.outgoingResources.includes(this)){
            this.link.outgoingResources.push(this);
        }
        this.bulk.start();
        this.scheduleWatchdog();
    }

    /** msgpack map, keys and types fixed by RNS/Resource.py ResourceAdvertisement. */
    packAdvertisement(segment) {
        const start = segment * Resource.HASHMAP_MAX_LEN;
        const end = Math.min((segment + 1) * Resource.HASHMAP_MAX_LEN, this.totalParts);
        const split = this.totalSegments > 1;

        // encrypted (bit 0); never compressed (1) or with metadata (5);
        // split (2) when there is more than one segment; request (3) and
        // response (4) when carrying one.
        const flags = 0x01 | ((split ? 1 : 0) << 2)
            | ((this.isRequest ? 1 : 0) << 3) | ((this.isResponse ? 1 : 0) << 4);

        return MsgPack.pack(new Map([
            ["t", this.transferSize],
            ["d", this.totalSize ?? this.uncompressedSize],
            ["n", this.totalParts],
            ["h", this.hash],
            ["r", this.randomHash],
            ["o", this.originalHash ?? this.hash],
            ["i", this.segmentIndex],
            ["l", this.totalSegments],
            ["q", this.requestId],
            ["f", flags],
            ["m", this.hashmapRaw.slice(start * Resource.MAPHASH_LEN, end * Resource.MAPHASH_LEN)],
        ]));
    }

    /**
     * Sender side: the peer asked for a window of parts
     * (RNS/Resource.py request()).
     * @param requestData the decrypted RESOURCE_REQ payload
     * @param packetHash the request packet's hash: a byte-identical repeat of
     *   a request already handled is ignored, "to avoid sequencing errors"
     */
    onRequest(requestData, packetHash = null) {
        if(this.status >= Resource.COMPLETE) return;
        if(packetHash){
            const key = Buffer.from(packetHash).toString("hex");
            if(this.reqHashlist.has(key)) return;
            this.reqHashlist.add(key);
        }

        const now = Date.now();
        if(this.rttMs === null){
            this.rttMs = now - this.advSent;
        }
        this.status = Resource.TRANSFERRING;
        this.retriesLeft = this.maxRetries;

        const wantsMoreHashmap = requestData[0] === Resource.HASHMAP_IS_EXHAUSTED;
        const pad = wantsMoreHashmap ? 1 + Resource.MAPHASH_LEN : 1;
        const requested = requestData.slice(pad + Resource.HASHLENGTH_IN_BYTES);
        const wanted = new Set();
        for(let i = 0; i < Math.floor(requested.length / Resource.MAPHASH_LEN); i++){
            wanted.add(requested.slice(i * Resource.MAPHASH_LEN, (i + 1) * Resource.MAPHASH_LEN).toString("hex"));
        }

        // Only within the collision guard window above the receiver's
        // consecutive height: map hashes are unique there and nowhere else.
        const searchStart = this.receiverMinConsecutiveHeight;
        const searchEnd = Math.min(searchStart + Resource.COLLISION_GUARD_SIZE, this.packets.length);
        for(let i = searchStart; i < searchEnd; i++){
            const entry = this.packets[i];
            if(!wanted.has(entry.mapHash.toString("hex"))) continue;
            if(!this.ensureLink()) return;
            this.link._transmit(entry.raw);
            if(!entry.sent){
                entry.sent = true;
                this.sentParts++;
            }
            this.lastActivity = Date.now();
            this.lastPartSent = this.lastActivity;
        }

        if(wantsMoreHashmap){
            if(!this.sendHashmapUpdate(requestData.slice(1, 1 + Resource.MAPHASH_LEN))) return;
        }

        if(this.sentParts === this.packets.length){
            this.status = Resource.AWAITING_PROOF;
            this.retriesLeft = Resource.PROOF_RETRIES;
        }
        this.reportProgress();
        this.scheduleWatchdog();
    }

    /** RNS/Resource.py request(), the wants_more_hashmap half. */
    sendHashmapUpdate(lastMapHash) {
        let partIndex = this.receiverMinConsecutiveHeight;
        const searchEnd = Math.min(partIndex + Resource.COLLISION_GUARD_SIZE, this.packets.length);
        for(let i = this.receiverMinConsecutiveHeight; i < searchEnd; i++){
            partIndex++;
            if(this.packets[i].mapHash.equals(lastMapHash)) break;
        }
        this.receiverMinConsecutiveHeight = Math.max(partIndex - 1 - Resource.WINDOW_MAX, 0);

        if(partIndex % Resource.HASHMAP_MAX_LEN !== 0){
            this.cancel("resource sequencing error: hashmap update requested off a segment boundary");
            return false;
        }
        const segment = partIndex / Resource.HASHMAP_MAX_LEN;
        const start = segment * Resource.HASHMAP_MAX_LEN;
        const end = Math.min((segment + 1) * Resource.HASHMAP_MAX_LEN, this.totalParts);
        const hashmap = this.hashmapRaw.slice(start * Resource.MAPHASH_LEN, end * Resource.MAPHASH_LEN);
        if(hashmap.length === 0){
            this.cancel("resource hashmap update requested past the last part");
            return false;
        }
        if(!this.ensureLink()) return false;
        this.sendLinkPacket(Packet.RESOURCE_HMU, Buffer.concat([this.hash, MsgPack.pack([segment, hashmap])]));
        this.lastActivity = Date.now();
        return true;
    }

    /** Sender side: peer proved it reassembled the payload. */
    onProof(proofData) {
        if(this.status >= Resource.COMPLETE) return;
        if(proofData.length !== Resource.HASHLENGTH_IN_BYTES * 2){
            return;
        }
        // RNS/Resource.py validate_proof ignores a proof that does not match.
        if(!proofData.slice(Resource.HASHLENGTH_IN_BYTES).equals(this.expectedProof)){
            return;
        }
        this.conclude();
    }

    // ---- Receiving ----

    /**
     * Accept an incoming resource advertisement (RNS/Resource.py accept()).
     * @param refusal optional object; when the advertisement is rejected,
     *   its `reason` is set to why (an ignored re-advertisement sets nothing)
     * @returns {Resource|null} null if the advertisement was rejected, or
     *   ignored because the same Resource is already transferring on the link
     */
    static accept(link, advertisement, refusal = null) {
        const resource = new Resource(link);
        if(!resource.applyAdvertisement(advertisement)){
            resource.reject(advertisement);
            if(refusal) refusal.reason = resource.refusalReason ?? "invalid advertisement";
            return null;
        }
        // RNS/Link.py has_incoming_resource: a re-sent advertisement (the
        // sender re-advertises when its first went unanswered) is ignored
        // while that Resource transfers, rather than transferred twice.
        if(link.incomingResources.some((r) => r.hash?.equals(resource.hash))){
            console.log(`[resource] ignoring advertisement for ${resource.hash.toString("hex").slice(0, 12)}: already transferring`);
            return null;
        }
        if(link.lastResourceWindow){
            resource.window = link.lastResourceWindow;
        }
        link.incomingResources.push(resource);
        const now = Date.now();
        resource.lastActivity = now;
        resource.startedTransferring = now;
        resource.bulk.start();
        resource.hashmapUpdate(0, resource.advertisedHashmap);
        return resource;
    }

    /**
     * Read an advertisement into this Resource, checking it against the
     * reference's invariants. @returns {boolean} false if it cannot be handled
     */
    applyAdvertisement(advertisement) {
        const get = (key) => (advertisement instanceof Map ? advertisement.get(key) : advertisement?.[key]);
        const reject = (why) => {
            console.warn(`[resource] rejecting advertisement: ${why}`);
            this.refusalReason = why;
            return false;
        };

        const flags = Number(get("f") ?? 0);
        const compressed = (flags >> 1) & 0x01;
        const hasMetadata = (flags >> 5) & 0x01;
        if(compressed || hasMetadata){
            return reject(`unsupported flags 0x${flags.toString(16)} (${compressed ? "compressed" : "metadata"})`);
        }

        const buf = (v, len) => {
            if(v === null || v === undefined) return null;
            const b = Buffer.from(v);
            return (len === undefined || b.length === len) ? b : null;
        };
        const int = (v) => (Number.isSafeInteger(Number(v)) ? Number(v) : NaN);

        this.hash = buf(get("h"), Resource.HASHLENGTH_IN_BYTES);
        this.randomHash = buf(get("r"), Resource.RANDOM_HASH_SIZE);
        this.originalHash = buf(get("o"), Resource.HASHLENGTH_IN_BYTES) ?? this.hash;
        if(!this.hash || !this.randomHash) return reject("malformed h or r");

        this.transferSize = int(get("t"));
        this.totalSize = int(get("d"));
        this.uncompressedSize = this.totalSize;
        const advertisedParts = int(get("n"));
        this.segmentIndex = int(get("i") ?? 1);
        this.totalSegments = int(get("l") ?? 1);
        if(!(this.transferSize > 0) || !(this.totalSize >= 0)) return reject("malformed t or d");
        // ResourceAdvertisement.unpack: "Invalid transfer size".
        if(this.transferSize > Resource.MAX_EFFICIENT_SIZE * 3) return reject(`transfer size ${this.transferSize} is too large`);

        // RNS/Resource.py accept(): total_parts = ceil(size / sdu). The
        // advertised count must agree; it sizes every array below.
        this.totalParts = Math.ceil(this.transferSize / this.sdu);
        if(advertisedParts !== this.totalParts){
            return reject(`n=${get("n")} parts does not match ceil(t=${this.transferSize} / ${this.sdu}) = ${this.totalParts}`);
        }

        // Segments: 1 <= i <= l, and l is what the declared total size needs
        // (RNS/Resource.py: total_segments = ((total_size-1) // MAX_EFFICIENT_SIZE) + 1).
        if(!(this.segmentIndex >= 1) || !(this.totalSegments >= 1) || this.segmentIndex > this.totalSegments){
            return reject(`segment ${get("i")} of ${get("l")}`);
        }
        this.split = this.totalSegments > 1;
        if(this.split && this.totalSegments !== Math.floor((this.totalSize - 1) / Resource.MAX_EFFICIENT_SIZE) + 1){
            return reject(`${this.totalSegments} segments for ${this.totalSize} bytes`);
        }

        const hashmap = buf(get("m"));
        if(!hashmap || hashmap.length < Resource.MAPHASH_LEN || hashmap.length % Resource.MAPHASH_LEN !== 0
            || hashmap.length / Resource.MAPHASH_LEN > Math.min(this.totalParts, Resource.HASHMAP_MAX_LEN)){
            return reject(`hashmap of ${hashmap?.length ?? 0} bytes for ${this.totalParts} parts`);
        }
        this.advertisedHashmap = hashmap;

        this.encrypted = (flags & 0x01) === 0x01;
        const requestId = get("q");
        this.requestId = requestId ? Buffer.from(requestId) : null;
        this.isRequest = !!this.requestId && ((flags >> 3) & 0x01) === 0x01;
        this.isResponse = !!this.requestId && ((flags >> 4) & 0x01) === 0x01;

        this.parts = new Array(this.totalParts).fill(null);
        this.hashmap = new Array(this.totalParts).fill(null);
        this.hashmapHeight = 0;
        this.status = Resource.TRANSFERRING;
        return true;
    }

    /** RNS/Resource.py reject(): tell the sender, by hash, that it is refused. */
    reject(advertisement) {
        const hash = advertisement instanceof Map ? advertisement.get("h") : advertisement?.h;
        if(hash){
            try {
                this.sendLinkPacket(Packet.RESOURCE_RCL, Buffer.from(hash));
            } catch(e) {
                console.warn(`[resource] could not send the rejection: ${e.message}`);
            }
        }
    }

    /** Receiver side: a RESOURCE_HMU arrived (RNS/Resource.py hashmap_update_packet). */
    onHashmapUpdate(payload) {
        if(this.status === Resource.FAILED || !this.waitingForHashmapUpdate) return;
        this.lastActivity = Date.now();
        this.retriesLeft = this.maxRetries;
        this.bulk.progress();
        let segment, hashmap;
        try {
            [segment, hashmap] = MsgPack.unpack(payload.slice(Resource.HASHLENGTH_IN_BYTES));
        } catch(e) {
            this.cancel("malformed hashmap update");
            return;
        }
        this.hashmapUpdate(Number(segment), hashmap ? Buffer.from(hashmap) : Buffer.alloc(0));
    }

    /**
     * Place a segment of map hashes at its index (RNS/Resource.py
     * hashmap_update: hashmap[i + segment * HASHMAP_MAX_LEN]). Until
     * 2026-09-30 updates were appended, so a repeated update shifted every
     * later hash and the transfer stalled.
     */
    hashmapUpdate(segment, hashmap) {
        if(this.status === Resource.FAILED) return;
        this.status = Resource.TRANSFERRING;
        const hashes = Math.floor(hashmap.length / Resource.MAPHASH_LEN);
        const base = segment * Resource.HASHMAP_MAX_LEN;
        if(hashes < 1){
            this.cancel("invalid hashmap update");
            return;
        }
        if(!Number.isSafeInteger(segment) || segment < 0 || base + hashes > this.totalParts){
            this.cancel(`hashmap update for segment ${segment} is outside the resource`);
            return;
        }
        for(let i = 0; i < hashes; i++){
            if(this.hashmap[base + i] === null) this.hashmapHeight++;
            this.hashmap[base + i] = hashmap.slice(i * Resource.MAPHASH_LEN, (i + 1) * Resource.MAPHASH_LEN);
        }
        this.waitingForHashmapUpdate = false;
        this.requestNext();
    }

    /**
     * Receiver side: ask for the next window of missing parts
     * (RNS/Resource.py request_next). Also what a retry sends: it is built
     * afresh from the parts still missing.
     */
    requestNext() {
        if(this.status === Resource.FAILED || this.waitingForHashmapUpdate){
            return;
        }

        this.outstandingParts = 0;
        let exhausted = Resource.HASHMAP_IS_NOT_EXHAUSTED;
        const requested = [];

        let found = 0;
        let pn = this.consecutiveCompletedHeight + 1;
        const searchEnd = Math.min(pn + this.window, this.parts.length);
        for(; pn < searchEnd; pn++){
            if(this.parts[pn] === null){
                const mapHash = this.hashmap[pn];
                if(mapHash !== null){
                    requested.push(mapHash);
                    this.outstandingParts++;
                    found++;
                } else {
                    exhausted = Resource.HASHMAP_IS_EXHAUSTED;
                }
            }
            if(found >= this.window || exhausted === Resource.HASHMAP_IS_EXHAUSTED) break;
        }

        let prefix = Buffer.from([exhausted]);
        if(exhausted === Resource.HASHMAP_IS_EXHAUSTED){
            // The last map hash held; segments fill in order, so it is the
            // last of the contiguous run from part 0.
            const lastMapHash = this.hashmap[this.hashmapHeight - 1];
            if(!lastMapHash){
                this.cancel("resource hashmap is not contiguous");
                return;
            }
            prefix = Buffer.concat([prefix, lastMapHash]);
            this.waitingForHashmapUpdate = true;
        }

        if(!this.ensureLink()) return;
        this.lastRequest = Buffer.concat([prefix, this.hash, ...requested]);
        const raw = this.sendLinkPacket(Packet.RESOURCE_REQ, this.lastRequest);
        const now = Date.now();
        this.lastActivity = now;
        this.reqSent = now;
        this.reqSentBytes = raw?.length ?? this.lastRequest.length;
        this.rttRxdBytesAtPartReq = this.rttRxdBytes;
        this.reqResp = null;
        this.scheduleWatchdog();
    }

    /**
     * Receiver side: a part packet arrived. Part packets carry no resource
     * identifier, so every incoming resource on the link is offered the part
     * and identifies it by its map hash. A part we do not recognise belongs to
     * another transfer and must not disturb this one's window.
     *
     * @param partData the part (the packet's payload)
     * @param rawLength the whole packet's length, for the rate measurement
     * @returns {boolean} whether the part belonged to this resource
     */
    onPart(partData, rawLength = partData.length) {
        if(this.status === Resource.FAILED || this.status >= Resource.ASSEMBLING) return false;
        const partHash = this.getMapHash(partData);

        let matched = -1;
        const start = this.consecutiveCompletedHeight + 1;
        const searchEnd = Math.min(start + this.window, this.parts.length);
        for(let i = start; i < searchEnd; i++){
            if(this.parts[i] !== null || this.hashmap[i] === null) continue;
            if(!this.hashmap[i].equals(partHash)) continue;
            matched = i;
            break;
        }
        if(matched === -1){
            return false;
        }

        const now = Date.now();
        this.lastActivity = now;
        this.retriesLeft = this.maxRetries;

        // The first part after a request: measure the round trip and the
        // request/response rate (RNS/Resource.py receive_part).
        if(this.reqResp === null){
            this.reqResp = now;
            const rtt = this.reqResp - this.reqSent;
            if(this.rttMs === null){
                this.rttMs = Number(this.link.rtt) || rtt;
            } else if(rtt < this.rttMs){
                this.rttMs = Math.max(this.rttMs - this.rttMs * 0.05, rtt);
            } else if(rtt > this.rttMs){
                this.rttMs = Math.min(this.rttMs + this.rttMs * 0.05, rtt);
            }
            if(rtt > 0){
                this.reqRespRttRate = (rawLength + this.reqSentBytes) / (rtt / 1000);
                if(this.reqRespRttRate > Resource.RATE_FAST && this.fastRateRounds < Resource.FAST_RATE_THRESHOLD){
                    this.fastRateRounds++;
                    if(this.fastRateRounds === Resource.FAST_RATE_THRESHOLD){
                        this.windowMax = Resource.WINDOW_MAX_FAST;
                    }
                }
            }
        }

        this.status = Resource.TRANSFERRING;
        this.parts[matched] = partData;
        this.rttRxdBytes += partData.length;
        this.receivedCount++;
        this.outstandingParts = Math.max(0, this.outstandingParts - 1);

        let cp = this.consecutiveCompletedHeight + 1;
        while(cp < this.parts.length && this.parts[cp] !== null){
            this.consecutiveCompletedHeight = cp;
            cp++;
        }
        this.reportProgress();

        if(this.receivedCount === this.totalParts){
            this.assemble();
            return true;
        }

        if(this.outstandingParts === 0){
            // The window grows by one per completed round, to window_max
            // (RNS/Resource.py receive_part), which the measured rate moves
            // between the very slow, slow and fast limits.
            if(this.window < this.windowMax){
                this.window++;
                if((this.window - this.windowMin) > (this.windowFlexibility - 1)){
                    this.windowMin++;
                }
            }
            if(this.reqSent !== 0){
                const rtt = now - this.reqSent;
                const transferred = this.rttRxdBytes - this.rttRxdBytesAtPartReq;
                if(rtt !== 0){
                    this.reqDataRttRate = transferred / (rtt / 1000);
                    this.rttRxdBytesAtPartReq = this.rttRxdBytes;
                    if(this.reqDataRttRate > Resource.RATE_FAST && this.fastRateRounds < Resource.FAST_RATE_THRESHOLD){
                        this.fastRateRounds++;
                        if(this.fastRateRounds === Resource.FAST_RATE_THRESHOLD){
                            this.windowMax = Resource.WINDOW_MAX_FAST;
                        }
                    }
                    if(this.fastRateRounds === 0 && this.reqDataRttRate < Resource.RATE_VERY_SLOW
                        && this.verySlowRateRounds < Resource.VERY_SLOW_RATE_THRESHOLD){
                        this.verySlowRateRounds++;
                        if(this.verySlowRateRounds === Resource.VERY_SLOW_RATE_THRESHOLD){
                            this.windowMax = Resource.WINDOW_MAX_VERY_SLOW;
                        }
                    }
                }
            }
            this.requestNext();
        } else {
            this.scheduleWatchdog();
        }
        return true;
    }

    assemble() {
        this.clearTimer();
        this.status = Resource.ASSEMBLING;

        const stream = Buffer.concat(this.parts);
        let data;
        try {
            data = this.encrypted ? this.link.decrypt(stream) : stream;
        } catch(e) {
            this.status = Resource.CORRUPT;
            this.cancel(`resource decryption failed: ${e.message}`);
            return;
        }

        data = data.slice(Resource.RANDOM_HASH_SIZE);

        if(!Cryptography.fullHash(Buffer.concat([data, this.randomHash])).equals(this.hash)){
            this.status = Resource.CORRUPT;
            this.cancel("reassembled resource did not match the advertised hash");
            return;
        }

        this.data = data;
        this.prove();
        this.conclude();
    }

    prove() {
        // RNS/Resource.py prove(): only on an ACTIVE link. The data is still
        // delivered if the proof cannot be sent (the reference concludes
        // COMPLETE either way).
        if(!this.link || this.link.status !== LINK_ACTIVE) return;
        const proof = Cryptography.fullHash(Buffer.concat([this.data, this.hash]));
        try {
            this.sendProofPacket(Buffer.concat([this.hash, proof]));
        } catch(e) {
            console.warn(`[resource] could not send the proof: ${e.message}`);
        }
    }

    // ---- Progress ----

    /** RNS/Resource.py get_progress(): fraction of parts, across segments. */
    getProgress() {
        if(this.status === Resource.COMPLETE && this.segmentIndex === this.totalSegments) return 1.0;
        const processed = this.initiator ? this.sentParts : this.receivedCount;
        if(!this.totalParts) return 0;
        if(!this.split){
            return Math.min(1.0, processed / this.totalParts);
        }
        const maxPartsPerSegment = Math.ceil(Resource.MAX_EFFICIENT_SIZE / this.sdu);
        const previouslyProcessed = (this.segmentIndex - 1) * maxPartsPerSegment;
        const factor = this.totalParts < maxPartsPerSegment ? maxPartsPerSegment / this.totalParts : 1;
        return Math.min(1.0, (previouslyProcessed + processed * factor) / (this.totalSegments * maxPartsPerSegment));
    }

    reportProgress() {
        this.bulk.progress();
        const progress = this.getProgress();
        this.emit("progress", progress);
        this.link?._onResourceProgress?.(this, progress);
    }

    // ---- DESIGN_PRINCIPLES §1, bulk transfers (this.bulk, BulkWatch) ----

    /** What the §1 lines call this transfer. */
    describe() {
        const kind = this.isRequest ? "request " : this.isResponse ? "response " : "";
        const segment = this.totalSegments > 1 ? ` segment ${this.segmentIndex}/${this.totalSegments}` : "";
        const what = `${this.initiator ? "sent" : "received"} ${kind}Resource `
            + `${this.hash ? this.hash.toString("hex").slice(0, 12) : "?"}${segment} `
            + `(${this.totalSize ?? this.uncompressedSize ?? "?"} B, link ${this.link?.hash ? this.link.hash.toString("hex").slice(0, 12) : "?"})`;
        return this.label ? `${this.label} (${what})` : what;
    }

    // ---- Watchdog (RNS/Resource.py __watchdog_job) ----

    /** The link's RTT in ms (Link.rtt is milliseconds on both sides). */
    linkRttMs() {
        return Number(this.link?.rtt) || 0;
    }

    /** The receiver's wait for outstanding parts before it asks again. */
    partTimeoutMs() {
        const rttMs = this.rttMs ?? this.linkRttMs();
        const retriesUsed = this.maxRetries - this.retriesLeft;
        return Math.max(Resource.PART_TIMEOUT_MS, Math.ceil(rttMs * Resource.RTT_TIMEOUT_FACTOR))
            + retriesUsed * Resource.PER_RETRY_DELAY * 1000;
    }

    /** When the watchdog next has something to decide, or null. */
    nextDeadline() {
        switch(this.status){
            case Resource.ADVERTISED: {
                // self.timeout = link.rtt * traffic_timeout_factor, or the
                // request's own timeout for a request sent as a Resource.
                const timeoutMs = this.timeoutMs ?? this.linkRttMs() * Resource.TRAFFIC_TIMEOUT_FACTOR;
                return this.advSent + timeoutMs + Resource.PROCESSING_GRACE * 1000;
            }
            case Resource.TRANSFERRING: {
                if(!this.initiator){
                    return this.lastActivity + this.partTimeoutMs();
                }
                let maxExtraWait = 0;
                for(let r = 0; r < Resource.MAX_RETRIES; r++) maxExtraWait += (r + 1) * Resource.PER_RETRY_DELAY;
                const rttMs = this.rttMs ?? this.linkRttMs();
                return this.lastActivity + rttMs * Resource.TRAFFIC_TIMEOUT_FACTOR * this.maxRetries
                    + (Resource.SENDER_GRACE_TIME + maxExtraWait) * 1000;
            }
            case Resource.AWAITING_PROOF: {
                const rttMs = this.rttMs ?? this.linkRttMs();
                return this.lastPartSent + rttMs * Resource.PROOF_TIMEOUT_FACTOR + Resource.SENDER_GRACE_TIME * 1000;
            }
            default:
                return null;
        }
    }

    scheduleWatchdog() {
        this.clearTimer();
        const deadline = this.nextDeadline();
        if(deadline === null) return;
        this.timer = setTimeout(() => this.watchdog(), Math.max(0, deadline - Date.now()));
    }

    /** One pass of the reference watchdog, run when a deadline passes. */
    watchdog(now = Date.now()) {
        this.clearTimer();
        const deadline = this.nextDeadline();
        if(deadline === null) return;
        if(now < deadline){
            this.scheduleWatchdog();
            return;
        }
        switch(this.status){
            case Resource.ADVERTISED:
                // Protocol-mandated retransmission (DESIGN_PRINCIPLES §3's
                // exception): the reference re-advertises max_adv_retries times.
                if(this.retriesLeft <= 0){
                    this.cancel("no response to the resource advertisement");
                    return;
                }
                this.retriesLeft--;
                if(!this.ensureLink()) return;
                this.sendLinkPacket(Packet.RESOURCE_ADV, this.packAdvertisement(0));
                this.lastActivity = now;
                this.advSent = now;
                break;
            case Resource.TRANSFERRING:
                if(this.initiator){
                    this.cancel("peer stopped requesting resource parts");
                    return;
                }
                if(this.retriesLeft <= 0){
                    this.cancel("resource parts did not arrive");
                    return;
                }
                // Timed out waiting for parts: shrink the window and ask
                // again for what is still missing (the request is rebuilt,
                // not replayed).
                if(this.window > this.windowMin){
                    this.window--;
                    if(this.windowMax > this.windowMin){
                        this.windowMax--;
                        if((this.windowMax - this.window) > (this.windowFlexibility - 1)){
                            this.windowMax--;
                        }
                    }
                }
                this.retriesLeft--;
                this.waitingForHashmapUpdate = false;
                this.requestNext();
                return;
            case Resource.AWAITING_PROOF:
                if(this.retriesLeft <= 0){
                    this.cancel("peer never proved receipt of the resource");
                    return;
                }
                // The reference asks the network cache for the proof here;
                // this client has no cache to ask, so it waits again, the
                // same number of times.
                this.retriesLeft--;
                this.lastPartSent = now;
                break;
        }
        this.scheduleWatchdog();
    }

    clearTimer() {
        if(this.timer){
            clearTimeout(this.timer);
            this.timer = null;
        }
    }

    // ---- Conclusion ----

    /** RNS/Resource.py ensure_link(): a Resource needs an ACTIVE link. */
    ensureLink() {
        if(!this.link || this.link.status !== LINK_ACTIVE){
            this.cancel(`link is not active (status ${this.link?.status})`);
            return false;
        }
        return true;
    }

    unregister() {
        this.clearTimer();
        if(!this.link) return;
        for(const list of [this.link.incomingResources, this.link.outgoingResources]){
            const index = list?.indexOf(this) ?? -1;
            if(index !== -1) list.splice(index, 1);
        }
    }

    conclude() {
        this.clearTimer();
        this.status = Resource.COMPLETE;
        if(!this.initiator && this.link){
            // RNS/Link.py resource_concluded: the next incoming Resource on
            // this link starts with this one's window.
            this.link.lastResourceWindow = this.window;
        }
        this.unregister();
        this.reportProgress();
        this.bulk.stop("concluded");
        // The link learns of an incoming Resource's end synchronously: it
        // reassembles split Resources and settles requests, and the next
        // segment's advertisement may already be on its way.
        if(!this.initiator) this.link?._incomingResourceConcluded?.(this);
        this.emit("concluded", this);
    }

    /**
     * RNS/Resource.py cancel(): FAILED, and the peer is told (ICL from the
     * sender, RCL from the receiver) while the link is still ACTIVE. On a
     * closing link nothing is sent.
     */
    cancel(reason = "cancelled") {
        if(this.status === Resource.COMPLETE || this.status === Resource.FAILED || this.status === Resource.REJECTED){
            return;
        }
        this.clearTimer();
        this.corrupt = this.status === Resource.CORRUPT;
        this.status = Resource.FAILED;
        this.bulk.stop(`failed: ${reason}`);
        if(this.hash && this.link && this.link.status === LINK_ACTIVE){
            try {
                this.sendLinkPacket(this.initiator ? Packet.RESOURCE_ICL : Packet.RESOURCE_RCL, this.hash);
            } catch(e) {
                console.warn(`[resource] could not send the cancel: ${e.message}`);
            }
        }
        this.unregister();
        console.warn(`[resource] ${reason}`);
        if(!this.initiator) this.link?._incomingResourceFailed?.(this, reason);
        this.emit("failed", reason);
    }

    /** RNS/Resource.py _rejected(): the receiver refused our Resource. */
    rejected() {
        if(!this.initiator || this.status >= Resource.COMPLETE) return;
        this.clearTimer();
        this.status = Resource.REJECTED;
        this.bulk.stop("rejected by the peer");
        this.unregister();
        console.warn("[resource] the peer rejected the resource");
        this.emit("failed", "the peer rejected the resource");
    }

    /** Kept for callers of the old name. */
    fail(reason) {
        this.cancel(reason);
    }

    // ---- Packet plumbing ----

    buildPartPacket(part) {
        return this.link.newLinkPacket(Packet.RESOURCE, part).pack();
    }

    sendLinkPacket(context, data) {
        const raw = this.link.newLinkPacket(context, data).pack();
        return this.link._transmit(raw);
    }

    sendProofPacket(data) {
        const raw = this.link.newLinkPacket(Packet.RESOURCE_PRF, data, Packet.PROOF).pack();
        return this.link._transmit(raw);
    }

}

export default Resource;
