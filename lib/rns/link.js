import { ed25519, x25519 } from "@noble/curves/ed25519";
import EventEmitter from "./utils/events.js";

import Destination from "./destination.js";
import Cryptography from "./cryptography.js";
import Constants from "./constants.js";
import Packet from "./packet.js";
import Transport from "./transport.js";
import Fernet from "./fernet.js";
import Identity from "./identity.js";
import MsgPack from "./msgpack.js";
import Resource from "./resource.js";

/**
 * Events emitted by a Link
 * - established: When the link has been established.
 * - recovered: When a STALE link hears from its peer and is ACTIVE again.
 *   It is the same link, not a new one, so "established" does not fire.
 * - packet: When a Packet has been received over the Link.
 * - close: When the Link has been closed.
 */
class Link extends EventEmitter {

    static KEYSIZE = 32;
    static ECPUBSIZE = 32 + 32;

    // Maximum plaintext payload that fits in a single link data packet.
    //
    // Reference: Reticulum-master/RNS/Link.py
    //   MDU = floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD)
    //               / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
    // with MTU=500, IFAC_MIN_SIZE=1, HEADER_MINSIZE=2+1+16=19,
    // TOKEN_OVERHEAD=48 (16B IV + 32B HMAC), AES128_BLOCKSIZE=16  =>  431.
    //
    // This is a protocol constant, NOT a tunable. Anything larger produces a
    // frame that exceeds the Reticulum MTU, which every conformant node will
    // reject (our PHP PostInterface answers HTTP 400 "packet too large" and
    // discards the whole exchange batch along with it). Payloads above this
    // must be sent as a Resource — see resource.js.
    static MDU = Constants.LINK_MDU;

    static PENDING = 0x00;
    static HANDSHAKE = 0x01;
    static ACTIVE = 0x02;
    static STALE = 0x03;
    static CLOSED = 0x04;

    static TIMEOUT = 0x01;
    static INITIATOR_CLOSED = 0x02;
    static DESTINATION_CLOSED = 0x03;

    // ── Keepalive / staleness, mirroring RNS/Link.py __watchdog_job ──────
    //
    // Values are the reference's (RNS/Link.py, Reticulum-rust/src/link.rs
    // KEEPALIVE_* / STALE_*). The interval is scaled from measured RTT so a
    // slow multi-hop path is not pinged as often as a LAN link:
    //
    //     keepalive  = clamp(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT),
    //                        KEEPALIVE_MIN, KEEPALIVE_MAX)
    //     stale_time = keepalive * STALE_FACTOR
    //
    // WHY THIS EXISTS. Until 2026-08-17 this client sent no keepalives at all.
    // On a quiet link the intermediate transport nodes' link tables expired
    // while the client still reported ACTIVE, so requests were accepted
    // locally and then vanished in transit with no error at either end —
    // measured that day as /rfed/pull burning its full 43-49s budget on links
    // a few minutes old while a freshly established link worked. The peer
    // (rfed) has always implemented the responder half: it bounces 0xFE for
    // every 0xFF it receives.
    static KEEPALIVE_MAX_RTT = 1.75;
    static KEEPALIVE_TIMEOUT_FACTOR = 4.0;
    static KEEPALIVE_MAX = 360.0;
    static KEEPALIVE_MIN = 5.0;
    static STALE_FACTOR = 2.0;
    static STALE_GRACE = 5.0;

    // Link establishment timeout, mirroring RNS/Link.py:
    //   establishment_timeout = Reticulum.get_first_hop_timeout(dest)
    //                         + ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, Transport.hops_to(dest))
    // with Reticulum.DEFAULT_PER_HOP_TIMEOUT = 6 (RNS/Reticulum.py:144) and
    // Link.ESTABLISHMENT_TIMEOUT_PER_HOP = DEFAULT_PER_HOP_TIMEOUT (RNS/Link.py:75).
    //
    // This is NOT a tunable for making establishment "work" — it exists so an
    // establishment attempt always reaches a terminal state. See
    // _startEstablishmentWatchdog().
    static DEFAULT_PER_HOP_TIMEOUT = 6;
    static ESTABLISHMENT_TIMEOUT_PER_HOP = 6;

    // This stack is an edge client with no path table, so it cannot call the
    // reference implementation's Transport.hops_to(). Callers that know the
    // hop count (destinations learn it from the announce that carried their
    // key) should pass it to establish(); otherwise assume a path spanning the
    // full browser -> php -> php peer -> post bridge -> backbone chain.
    static DEFAULT_ESTABLISHMENT_HOPS = 4;

    // Whether inbound resource advertisements are accepted on this link
    // (RNS/Link.py resource strategies). ACCEPT_APP asks the callback set
    // with setResourceCallback(), which sees the advertisement.
    static ACCEPT_NONE = 0x00;
    static ACCEPT_APP = 0x01;
    static ACCEPT_ALL = 0x02;

    // Requests — RNS/Link.py request() and RequestReceipt.
    //   timeout = rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125
    static TRAFFIC_TIMEOUT_FACTOR = 6;
    static RESPONSE_MAX_GRACE_TIME = 10;   // RNS/Resource.py, seconds
    static REQUEST_FAILED = 0x00;
    static REQUEST_SENT = 0x01;
    static REQUEST_DELIVERED = 0x02;
    static REQUEST_RECEIVING = 0x03;
    static REQUEST_READY = 0x04;
    static CONCLUDED_REQUESTS_KEPT = 64;

    /** RNS/Link.py request(): the default wait for a response, in ms. */
    static requestTimeoutMs(rttMs) {
        return (Number(rttMs) || 0) * Link.TRAFFIC_TIMEOUT_FACTOR + Link.RESPONSE_MAX_GRACE_TIME * 1.125 * 1000;
    }

    constructor() {
        super();
        this.incomingResources = [];
        this.outgoingResources = [];
        this.resourceStrategy = Link.ACCEPT_NONE;
        // RNS/Link.py last_resource_window: an incoming Resource starts with
        // the window the previous one ended on.
        this.lastResourceWindow = null;
        // Split Resources being reassembled, by original hash (hex): RNS
        // appends each segment to one file named by it (Resource.py assemble).
        this._splitAssemblies = new Map();
        // RNS/Link.py pending_requests: RequestReceipts awaiting a response.
        this.pendingRequests = [];
        // RNS/Destination.py max_request_size: the largest request Resource
        // (advertised data size d, in bytes) this link takes; null, the
        // reference default, takes any size.
        this.maxRequestSize = null;
        // Whether every data packet (context NONE) is proved as it arrives,
        // before anyone has looked at it: the reference's PROVE_ALL.
        // RNS/Link.py receive() proves one only by its destination's proof
        // strategy, whose default is PROVE_NONE (Destination.py). This
        // client's links have always proved every one, and every link but
        // an LXMF delivery link still does. LXMF leaves its delivery
        // destination at PROVE_NONE and proves a message itself
        // (LXMRouter.py delivery_packet), so LXMRouter turns this off on its
        // links and proves only a message it keeps: a message its privacy
        // filter drops is never proved, and a kept one is proved once, not
        // twice as until 2026-09-30.
        this.proveAll = true;
        // The last few concluded receipts, so responseFor() still answers
        // for a request that concluded before anyone asked (the reference
        // hands the caller the receipt object; this link hands out its id).
        this._concludedRequests = new Map();

        // Traffic times in ms since the epoch, 0 until the first one
        // (RNS/Link.py __init__: last_inbound, last_outbound, last_keepalive,
        // last_proof, last_data). The keepalive period starts at the reference
        // default and is rescaled from the RTT once the link is up.
        this.lastInbound = 0;
        this.lastOutbound = 0;
        this.lastKeepalive = 0;
        this.lastProof = 0;
        this.lastData = 0;
        this.keepalive = Link.KEEPALIVE_MAX;
        this.staleTime = Link.KEEPALIVE_MAX * Link.STALE_FACTOR;
    }

    establish(destination, hops = Link.DEFAULT_ESTABLISHMENT_HOPS) {

        this.initiator = true;
        this.status = Link.PENDING;
        this.destination = destination;
        this.attachedInterface = null;

        // generate private keys
        this.privateKeyBytes = Buffer.from(x25519.utils.randomPrivateKey());
        this.signaturePrivateKeyBytes = Buffer.from(ed25519.utils.randomPrivateKey());

        // get public keys. The signing key is Ed25519: the responder checks
        // this side's link-packet proofs with it (RNS/Link.py validate).
        // x25519.getPublicKey() of this key is a different point, and every
        // proof this side signed failed at the peer until 2026-09-30.
        this.publicKeyBytes = Buffer.from(x25519.getPublicKey(this.privateKeyBytes));
        this.signaturePublicKeyBytes = Buffer.from(ed25519.getPublicKey(this.signaturePrivateKeyBytes));

        // load peer keys from destination identity
        this.loadPeerKeysFromIdentity(destination.identity);

        if(this.initiator){

            // create link request data
            const requestData = Buffer.concat([
                this.publicKeyBytes,
                this.signaturePublicKeyBytes,
            ]);

            // create link request packet
            const packet = new Packet();
            packet.headerType = Packet.HEADER_1;
            packet.packetType = Packet.LINKREQUEST;
            packet.transportType = Transport.BROADCAST;
            packet.context = Packet.NONE;
            packet.contextFlag = Packet.FLAG_UNSET;
            packet.destination = destination;
            packet.destinationHash = destination.hash;
            packet.destinationType = destination.type;
            packet.data = requestData;
            const packed = packet.pack();

            // set link id
            this.setLinkId(packet);

            // register link in transport
            this.requestTime = Date.now();
            this.destination.rns.registerLink(this);

            this.establishmentTimeout = (Link.DEFAULT_PER_HOP_TIMEOUT
                + Link.ESTABLISHMENT_TIMEOUT_PER_HOP * Math.max(1, hops)) * 1000;
            this._startEstablishmentWatchdog();

            // The LINKREQUEST as an interface names it when it reports it
            // lost (PostInterface "lost": full packet hash, hex), and the
            // interfaces it goes to. See requestLost().
            this.requestPacketHash = packet.packetHash.toString("hex");
            this._requestInterfaces = new Set(this.destination.rns.interfaces ?? []);

            // fixme: only send on relevant interface
            // send link request (no attached interface yet: every interface)
            console.log(`Sending Link request ${this.hash.toString("hex")} to ${destination.hash.toString("hex")}`)
            this._transmit(packed);

        }

    }

    /**
     * Validates an incoming Link Request packet.
     * @param linkRequestPacket
     * @returns {boolean} true if the Link Request is valid.
     */
    validateLinkRequest(linkRequestPacket) {
        try {

            // ensure link proof data size is as expected
            // Python Reticulum may send more than 64 bytes in newer versions;
            // accept >= ECPUBSIZE and use the first 64
            if(!linkRequestPacket.data || linkRequestPacket.data.length < Link.ECPUBSIZE){
                console.log("link request validation failed: packet data too short (" + (linkRequestPacket.data?.length ?? 0) + " < " + Link.ECPUBSIZE + ")");
                return false;
            }

            this.initiator = false;
            this.status = Link.PENDING;
            this.destination = linkRequestPacket.destination;
            this.attachedInterface = linkRequestPacket.receivingInterface;

            // load peer keys
            const peerPublicKeyBytes = linkRequestPacket.data.slice(0, Link.ECPUBSIZE / 2);
            const peerSignaturePublicKeyBytes = linkRequestPacket.data.slice(Link.ECPUBSIZE / 2, Link.ECPUBSIZE)
            this.loadPeerKeys(peerPublicKeyBytes, peerSignaturePublicKeyBytes);

            // generate private key
            this.privateKeyBytes = Buffer.from(x25519.utils.randomPrivateKey());
            this.publicKeyBytes = Buffer.from(x25519.getPublicKey(this.privateKeyBytes));

            // load signature private key
            this.signaturePrivateKeyBytes = this.destination.identity.signaturePrivateKeyBytes;
            this.signaturePublicKeyBytes = this.destination.identity.signaturePublicKeyBytes;

            // set link id
            this.setLinkId(linkRequestPacket);

            // perform handshake
            this.handshake();

            return true;

        } catch(e) {
            console.log("link validation failed", e);
            return false;
        }
    }

    /**
     * Accepts a Link Request
     */
    accept() {

        // send proof of link establishment
        this.prove();

        this.requestTime = Date.now();
        this.destination.rns.registerLink(this);
        this.lastInbound = Date.now();
        // The keepalive watchdog of an accepted link starts in
        // onLinkRequestRtt(), when the initiator's RTT packet makes the link
        // ACTIVE (RNS/Link.py rtt_packet). This side never pings; the
        // watchdog makes a link that stops hearing its peer go STALE and
        // close, and the pong gate answers the initiator's pings.

        console.log(`Incoming link request ${this.hash.toString("hex")} accepted on (interface)`);

    }

    loadPeerKeys(peerPublicKeyBytes, peerSignaturePublicKeyBytes) {
        this.peerPublicKeyBytes = peerPublicKeyBytes;
        this.peerSignaturePublicKeyBytes = peerSignaturePublicKeyBytes;
    }

    loadPeerKeysFromIdentity(identity) {
        this.loadPeerKeys(identity.publicKeyBytes, identity.signaturePublicKeyBytes);
    }

    setLinkId(packet) {
        // Compute hashable part same as Python get_hashable_part()
        let hashablePart = packet.getHashablePart();
        
        // Strip MTU signalling bytes if present (Python compat).
        // Python link_id_from_lr_packet() does:
        //   if len(packet.data) > ECPUBSIZE:
        //       diff = len(packet.data) - ECPUBSIZE
        //       hashable_part = hashable_part[:-diff]
        if (packet.data && packet.data.length > Link.ECPUBSIZE) {
            const diff = packet.data.length - Link.ECPUBSIZE;
            hashablePart = hashablePart.slice(0, hashablePart.length - diff);
        }
        
        this.hash = Cryptography.truncatedHash(hashablePart);
    }

    validateProof(proofPacket) {
        try {

            console.log("[link] validateProof: status=" + this.status + " initiator=" + this.initiator + " dataLen=" + proofPacket.data.length);

            // do nothing if not in pending state
            if(this.status !== Link.PENDING){
                console.log("[link] validateProof FAIL: not pending");
                return;
            }

            // do nothing if not initiator
            if(!this.initiator){
                console.log("[link] validateProof FAIL: not initiator");
                return;
            }

            // ensure link proof data size is as expected
            const minLen = Identity.SIGLENGTH_IN_BYTES + Link.ECPUBSIZE / 2;
            if(proofPacket.data.length < minLen){
                console.log("[link] validateProof FAIL: data too short (" + proofPacket.data.length + " < " + minLen + ")");
                return;
            }

            // load peer keys (bytes 0-64 = sig, 64-96 = X25519 pub, 96+ = signalling)
            const peerPublicKeyBytes = proofPacket.data.slice(Identity.SIGLENGTH_IN_BYTES, Identity.SIGLENGTH_IN_BYTES + Link.ECPUBSIZE / 2);
            const peerSignaturePublicKeyBytes = this.destination.identity.signaturePublicKeyBytes;
            const signallingBytes = proofPacket.data.slice(Identity.SIGLENGTH_IN_BYTES + Link.ECPUBSIZE / 2);
            console.log("[link] validateProof: peerPub=" + peerPublicKeyBytes.toString("hex").slice(0,16) + "... sigPub=" + peerSignaturePublicKeyBytes.toString("hex").slice(0,16) + "... signalling=" + signallingBytes.length + "B");
            this.loadPeerKeys(peerPublicKeyBytes, peerSignaturePublicKeyBytes);

            // perform handshake
            this.handshake();
            console.log("[link] validateProof: handshake done, status=" + this.status);

            // signedData must match Rust: hash | pub | sigpub | signalling_bytes
            const signedData = Buffer.concat([
                this.hash,
                this.peerPublicKeyBytes,
                this.peerSignaturePublicKeyBytes,
                signallingBytes,
            ]);

            const signature = proofPacket.data.slice(0, Identity.SIGLENGTH_IN_BYTES);
            console.log("[link] validateProof: sig=" + signature.toString("hex").slice(0,16) + "... hash=" + this.hash.toString("hex").slice(0,16));

            // validate link proof signature
            if(!this.destination.identity.validate(signature, signedData)){
                console.log("[link] validateProof FAIL: invalid signature");
                return;
            }

            // ensure link is in handshake state
            if(this.status !== Link.HANDSHAKE){
                console.log("[link] validateProof FAIL: not handshake, status=" + this.status);
                return;
            }

            // update state
            this.rtt = Date.now() - this.requestTime;
            this.attachedInterface = proofPacket.receivingInterface;
            this.destination.rns.activateLink(this);
            this.lastProof = this.activatedAt;
            this._updateKeepalive();
            this._startKeepaliveWatchdog();

            console.log("[link] Link ESTABLISHED hash=" + this.hash.toString("hex").slice(0,12) + " rtt=" + this.rtt + "ms");

            // send rtt packet
            const rttData = MsgPack.pack(this.rtt / 1000);

            // create data packet
            const rttPacket = new Packet();
            rttPacket.hops = 0;
            rttPacket.headerType = Packet.HEADER_1;
            rttPacket.packetType = Packet.DATA;
            rttPacket.transportType = Transport.BROADCAST;
            rttPacket.context = Packet.LRRTT;
            rttPacket.contextFlag = Packet.FLAG_UNSET;
            rttPacket.destination = this;
            rttPacket.destinationHash = this.hash;//.slice(Constants.TRUNCATED_HASHLENGTH_IN_BYTES);
            rttPacket.destinationType = Destination.LINK;
            rttPacket.data = rttData;

            // pack packet
            const raw = rttPacket.pack();

            // send packet to attached interface. Counted as outbound, as the
            // reference's had_outbound() after rtt_packet.send(), so the
            // watchdog's quiet-outbound clock starts at activation.
            this._transmit(raw);

            // fire link established callback
            this.emit("established");

            // if self.rtt != None and self.establishment_cost != None and self.rtt > 0 and self.establishment_cost > 0:
            // self.establishment_rate = self.establishment_cost/self.rtt
            //
            // rtt_data = umsgpack.packb(self.rtt)
            // rtt_packet = RNS.Packet(self, rtt_data, context=RNS.Packet.LRRTT)
            // rtt_packet.send()
            // self.had_outbound()
            //
            // if self.callbacks.link_established != None:
            // thread = threading.Thread(target=self.callbacks.link_established, args=(self,))
            // thread.daemon = True
            // thread.start()

        } catch(e) {
            console.log("failed to validate link proof", e);
        }
    }

    handshake() {

        // prevent handshaking if link is not in pending state
        if(this.status !== Link.PENDING){
            console.log(`Handshake attempt on ${this.hash.toString("hex")} with invalid state ${this.status}`);
            return;
        }

        // update state
        this.status = Link.HANDSHAKE;

        // compute shared key
        this.sharedKey = Buffer.from(x25519.getSharedSecret(this.privateKeyBytes, this.peerPublicKeyBytes));

        // create derived key
        this.derivedKey = Cryptography.hkdf(64, this.sharedKey, this.hash);

    }

    prove() {

        // create data to sign
        const signedData = Buffer.concat([
            this.hash,
            this.publicKeyBytes,
            this.signaturePublicKeyBytes,
        ]);

        // sign data
        const signature = this.destination.identity.sign(signedData);

        // create proof data to send in packet
        const proofData = Buffer.concat([
            signature,
            this.publicKeyBytes,
        ]);

        // create data packet
        const packet = new Packet();
        // packet.hops = 0; // remote side checks expected hops and silently drops the packet if it doesn't match
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.PROOF;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.LRPROOF;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = proofData;

        // pack packet
        const raw = packet.pack();

        // send packet to attached interface
        this._transmit(raw);

    }

    encrypt(data) {
        const fernet = new Fernet(this.derivedKey);
        return fernet.encrypt(data);
    }

    decrypt(data) {
        const fernet = new Fernet(this.derivedKey);
        return fernet.decrypt(data);
    }

    sign(data) {
        return Buffer.from(ed25519.sign(data, this.signaturePrivateKeyBytes));
    }

    send(data) {

        // Refuse to emit an over-MTU frame. Python raises IOError from
        // Packet.pack() in the same situation (RNS/Packet.py). Failing here
        // gives the caller an accurate, immediate error instead of a frame
        // that is silently rejected downstream by the receiving node.
        // Payloads larger than this must be sent as a Resource, not a packet.
        if(data.length > Link.MDU){
            throw new Error(`Link payload of ${data.length} bytes exceeds the link MDU of ${Link.MDU} bytes`);
        }

        // create data packet
        const packet = this.newLinkPacket(Packet.NONE, data);

        // pack packet
        const raw = packet.pack();

        // send packet to attached interface
        this._transmit(raw);

        return packet;

    }

    /**
     * Put one packed link packet on the wire. Every packet this link sends,
     * and every packet its Resources send, goes through here, so the
     * watchdog's outbound clock sees all of it (RNS/Link.py had_outbound(),
     * called after every send). Before the link has an attached interface
     * (the link request) it goes to every interface.
     */
    _transmit(raw, isKeepalive = false) {
        // RNS/Packet.py send(): "Attempt to transmit over a closed link,
        // dropping packet".
        if(this.status === Link.CLOSED){
            console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} is closed; dropping an outbound packet`);
            return null;
        }
        this.destination.rns.sendData(raw, this.attachedInterface ?? null);
        this._hadOutbound(isKeepalive);
        return raw;
    }

    /** RNS/Link.py had_outbound(is_keepalive). */
    _hadOutbound(isKeepalive = false) {
        this.lastOutbound = Date.now();
        if (isKeepalive) {
            this.lastKeepalive = this.lastOutbound;
        } else {
            this.lastData = this.lastOutbound;
        }
    }

    /** Build a packet addressed to this link. */
    newLinkPacket(context, data, packetType) {
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = packetType ?? Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = context;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = data;
        return packet;
    }

    /** Accept inbound resource advertisements on this link. */
    setResourceStrategy(strategy) {
        this.resourceStrategy = strategy;
    }

    /**
     * For ACCEPT_APP: `callback(advertisement)` decides each bare-data
     * Resource before any part is requested; a truthy answer accepts it,
     * anything else (or a throw) rejects it (RCL). The advertisement is { dataSize (d, the whole
     * payload), transferSize (t), parts (n), hash, segmentIndex,
     * totalSegments } (RNS/Link.py set_resource_callback).
     */
    setResourceCallback(callback) {
        this.resourceCallback = callback;
    }

    /** Called by the stack when a RESOURCE_PRF proof packet arrives for this link. */
    onResourceProof(packet) {
        // RNS/Transport.py hands a RESOURCE_PRF to link.receive(), so it is
        // inbound traffic like any other (last_inbound, STALE recovery).
        if(this.status === Link.CLOSED) return;
        this._hadInbound(packet);
        const hash = packet.data.slice(0, Resource.HASHLENGTH_IN_BYTES);
        const resource = this.outgoingResources.find((r) => r.hash.equals(hash));
        if(resource){
            resource.onProof(packet.data);
        }
    }

    /**
     * Transfer a payload of any size over this link as a Resource.
     * @param options { onProgress(fraction) — the fraction of parts sent;
     *   label — what the Resource's §1 lines call the transfer }
     * @returns {Promise<Resource>} resolves once the peer proves receipt,
     *   rejects when the transfer fails or the link closes first
     */
    sendResource(data, options = {}) {
        return Resource.send(this, data, { onProgress: options.onProgress, label: options.label });
    }

    /**
     * Every Resource on this link reports progress here (the fraction of
     * parts sent or received, RNS/Resource.py get_progress), so the app can
     * follow a transfer by listening to the link's "resource_progress".
     */
    _onResourceProgress(resource, progress) {
        if(!resource.initiator && resource.isResponse && resource.requestId){
            const receipt = this._pendingRequest(resource.requestId);
            if(receipt){
                this._responseResourceProgress(receipt, resource);
            } else if(resource.status < Resource.COMPLETE){
                // RNS/Link.py response_resource_progress: the request it
                // answers has failed, so the transfer stops.
                resource.cancel("the request this response answers has failed");
                return;
            }
        }
        this.emit("resource_progress", { resource, progress, initiator: resource.initiator });
    }

    /**
     * Called by the stack when a PROOF (context NONE) addressed to this link
     * arrives: the peer proving a packet this side sent.
     *
     * RNS/Link.py counts a proved packet as hearing the peer: the watchdog's
     * "last heard" is max(last_inbound, last_proof, activated_at), and
     * Packet.validate_link_proof sets link.last_proof once the peer's
     * signature over the proved packet's hash checks out. Without it a link
     * that only sends (and is only proved) looks silent, goes STALE, and
     * closes: the peer's own pong gate skips the final ping because it has
     * been sending proofs.
     *
     * The reference validates against a receipt it holds for that packet;
     * this link keeps no receipts (the app matches proofs to messages), so it
     * checks the peer's link signature over the proved hash. Like the
     * reference (Transport.py:2725-2761, no link.receive() for these), a
     * proof does not bring a STALE link back: only inbound traffic does.
     */
    onPacketProof(packet) {
        if(this.status === Link.CLOSED || !this.peerSignaturePublicKeyBytes) return false;
        const data = packet.data;
        if(!data || data.length < 32 + 64) return false;
        let valid = false;
        try {
            valid = ed25519.verify(data.subarray(32, 96), data.subarray(0, 32), this.peerSignaturePublicKeyBytes);
        } catch(e) {
            valid = false;
        }
        if(valid){
            this.lastProof = Date.now();
        }
        return valid;
    }

    /**
     * Inbound bookkeeping shared by every packet the link hears
     * (RNS/Link.py __receive: last_inbound, last_data, STALE -> ACTIVE).
     *
     * Before 2026-08-17 lastInbound was written once, at accept(), and never
     * again — so once the watchdog existed it would have declared every
     * healthy link stale. It is refreshed before any handler can return.
     */
    _hadInbound(packet) {
        this.lastInbound = Date.now();
        if(packet?.context !== Packet.KEEPALIVE){
            this.lastData = this.lastInbound;
        }
        this._recoverIfStale();
    }

    _recoverIfStale() {
        if(this.status === Link.STALE){
            // The peer answered: recover rather than tear down. Matches the
            // Rust responder ("Mark active if stale") and Python's watchdog.
            this.status = Link.ACTIVE;
            this.staleSince = null;
            console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} recovered from STALE`);
            // The only STALE -> ACTIVE transition. Without an event, anything
            // that waits for ACTIVE had to wait for a teardown and a fresh
            // "established" that may never come.
            this.emit("recovered");
        }
    }

    /**
     * Called internally when a Packet has been received.
     * @param packet
     */
    onPacket(packet) {

        // do nothing if link closed
        if(this.status === Link.CLOSED){
            console.log("dropping packet received for closed link");
            return;
        }

        // RNS/Link.py:938 (1.5.2): an initiator ignores a ping entirely. Only
        // the initiator pings, so a 0xFF arriving here is not the peer
        // answering anything, and it must not refresh last_inbound or
        // recover a STALE link.
        if(this.initiator && packet.context === Packet.KEEPALIVE
            && packet.data?.length === 1 && packet.data[0] === 0xFF){
            return;
        }

        // Any inbound traffic proves the path is alive, which is what the
        // keepalive watchdog measures.
        this._hadInbound(packet);

        // KEEPALIVE travels unencrypted and MUST be handled before any
        // decrypt attempt — see the note in packet.js pack(). 0xFF is a ping
        // to answer; 0xFE is the pong, which needs nothing beyond the
        // lastInbound refresh above.
        if(packet.context === Packet.KEEPALIVE){
            const b = packet.data?.[0];
            // RNS/Link.py:1131-1135 (1.5.2): the responder answers only when
            // its own outbound has been quiet for a keepalive period, and the
            // pong counts as outbound. Anything it sent more recently already
            // told the initiator the link is alive.
            if(b === 0xFF && !this.initiator
                && Date.now() >= (this.lastOutbound || 0) + this.keepalive * 1000){
                try {
                    this._transmit(this.newLinkPacket(Packet.KEEPALIVE, Buffer.from([0xFE])).pack(), true);
                } catch(e) {
                    console.warn(`[link] keepalive reply failed: ${e.message}`);
                }
            }
            return;
        }

        // set link as packet destination
        packet.destination = this;

        // handle packet data for link
        if(packet.context === Packet.NONE) {

            // decrypt packet data
            const plaintext = this.decrypt(packet.data);

            // fire event
            this.emit("packet", {
                packet: packet,
                data: plaintext,
            });

            // Send proof back to the sender (see proveAll)
            if(this.proveAll){
                const proofSignature = this.sign(packet.packetHash);
                const proofData = Buffer.concat([packet.packetHash, proofSignature]);

                const proofPacket = new Packet();
                proofPacket.headerType = Packet.HEADER_1;
                proofPacket.packetType = Packet.PROOF;
                proofPacket.transportType = Transport.BROADCAST;
                proofPacket.context = Packet.NONE;
                proofPacket.contextFlag = Packet.FLAG_UNSET;
                proofPacket.destination = this;
                proofPacket.destinationHash = this.hash;
                proofPacket.destinationType = Destination.LINK;
                proofPacket.data = proofData;
                const proofRaw = proofPacket.pack();
                this._transmit(proofRaw);
            }

        }

        // handle link request rtt
        else if(packet.context === Packet.LRRTT){
            if(!this.initiator){
                this.onLinkRequestRtt(packet);
            }
        }

        // ---- Resource transfer (see resource.js) ----

        // an advertisement offers a payload too large for a single packet
        else if(packet.context === Packet.RESOURCE_ADV){
            let advertisement;
            try {
                advertisement = MsgPack.unpack(this.decrypt(packet.data));
            } catch(e) {
                console.warn("[resource] could not parse advertisement:", e.message);
                return;
            }
            // RNS/Link.py:1036-1066: a Resource flagged as a request or a
            // response is decided before, and regardless of, the resource
            // strategy — it is a link request or response that did not fit
            // one packet, and the strategy only governs bare data. Until
            // 2026-09-22 every advertisement went through the strategy and
            // concluded as bare data, so an rfed.link push larger than the
            // MDU was assembled, handed to the channel ingest under the wrong
            // path, and never answered — it fell to the deferred queue and
            // /channel/pull.
            const get = (key) => (advertisement instanceof Map ? advertisement.get(key) : advertisement?.[key]);
            const flags = Number(get("f") ?? 0);
            // ResourceAdvertisement.is_request / is_response: q plus flag bit
            // 3 (u) or bit 4 (p); a request is checked first, as there.
            const isRequest = !!get("q") && ((flags >> 3) & 0x01) === 0x01;
            const isResponse = !isRequest && !!get("q") && ((flags >> 4) & 0x01) === 0x01;

            // RNS/Link.py:1036-1042: a request Resource is taken only where
            // the destination has request handlers, and only within its
            // max_request_size. On this client a request handler is a
            // "request" listener on the link. Until 2026-09-30 every request
            // Resource was accepted, so a peer could flag any Resource as a
            // request (split, any declared size) and walk it past an LXMF
            // delivery link's size gate: the tab fetched and held all of it,
            // then dropped it, since nothing on a delivery link handles
            // requests. With no handler the reference neither accepts nor
            // refuses: the advertisement is ignored.
            if(isRequest){
                if(!this._handlesRequests()){
                    console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} ignored a request Resource: nothing on this link handles requests`);
                    return;
                }
                const size = Number(get("d"));
                if(this.maxRequestSize != null && !(size <= this.maxRequestSize)){
                    console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} rejected a request Resource of ${get("d")} bytes (max ${this.maxRequestSize})`);
                    new Resource(this).reject(advertisement);
                    return;
                }
                this._acceptResource(advertisement);
                return;
            }

            // RNS/Link.py:1044-1066: a response is accepted only for a
            // request this link is waiting on; anything else is ignored.
            // Once accepted, the request is RECEIVING and its timeout no
            // longer applies (response_resource_progress). A response this
            // link refuses fails its request now (response_rejected).
            if(isResponse){
                const receipt = this._pendingRequest(get("q"));
                if(!receipt){
                    console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} ignored a response Resource for no pending request`);
                    return;
                }
                const refusal = {};
                const resource = this._acceptResource(advertisement, refusal);
                if(resource){
                    this._responseResourceProgress(receipt, resource);
                } else if(refusal.reason){
                    this._responseRejected(receipt, refusal.reason);
                }
                return;
            }

            // Bare data: the resource strategy decides.
            if(this.resourceStrategy === Link.ACCEPT_NONE){
                return;
            }
            if(this.resourceStrategy === Link.ACCEPT_APP){
                let accepted = false;
                try {
                    accepted = !!this.resourceCallback?.({
                        dataSize: Number(get("d")),
                        transferSize: Number(get("t")),
                        parts: Number(get("n")),
                        hash: get("h") ? Buffer.from(get("h")) : null,
                        segmentIndex: Number(get("i") ?? 1),
                        totalSegments: Number(get("l") ?? 1),
                    });
                } catch(e) {
                    console.warn(`[link] resource callback failed: ${e.message}`);
                }
                if(!accepted){
                    new Resource(this).reject(advertisement);
                    return;
                }
            }
            this._acceptResource(advertisement);
        }

        // a resource part. Parts are not packet-encrypted — the resource
        // encrypts its payload as a whole before splitting it.
        else if(packet.context === Packet.RESOURCE){
            for(const resource of [...this.incomingResources]){
                if(resource.onPart(packet.data, packet.raw?.length ?? packet.data.length)) break;
            }
        }

        // the peer is pulling a window of parts from a resource we are sending
        else if(packet.context === Packet.RESOURCE_REQ){
            let request;
            try { request = this.decrypt(packet.data); } catch(e) { return; }
            const offset = request[0] === Resource.HASHMAP_IS_EXHAUSTED ? 1 + Resource.MAPHASH_LEN : 1;
            const hash = request.slice(offset, offset + Resource.HASHLENGTH_IN_BYTES);
            const resource = this.outgoingResources.find((r) => r.hash.equals(hash));
            if(resource){
                resource.onRequest(request, packet.packetHash);
            }
        }

        // the sender is extending the hashmap of a resource we are receiving
        else if(packet.context === Packet.RESOURCE_HMU){
            let update;
            try { update = this.decrypt(packet.data); } catch(e) { return; }
            const hash = update.slice(0, Resource.HASHLENGTH_IN_BYTES);
            const resource = this.incomingResources.find((r) => r.hash.equals(hash));
            if(resource){
                resource.onHashmapUpdate(update);
            }
        }

        // RNS/Link.py: the sender cancelled a Resource we are receiving
        // (ICL), or the receiver refused or cancelled one we are sending (RCL)
        else if(packet.context === Packet.RESOURCE_ICL || packet.context === Packet.RESOURCE_RCL){
            let plaintext;
            try { plaintext = this.decrypt(packet.data); } catch(e) { return; }
            const hash = plaintext.slice(0, Resource.HASHLENGTH_IN_BYTES);
            if(packet.context === Packet.RESOURCE_ICL){
                for(const resource of [...this.incomingResources]){
                    if(resource.hash?.equals(hash)) resource.cancel("the sender cancelled the resource");
                }
            } else {
                for(const resource of [...this.outgoingResources]){
                    if(resource.hash?.equals(hash)) resource.rejected();
                }
            }
        }

        // handle link identify (context=0xFB)
        //
        // Wire format is RAW bytes: public_key(64) || signature(64), signed
        // over link_id || public_key — RNS/Link.py:1036-1043, and our own
        // identify() sender below already emits exactly this. Until 2026-08-17
        // this receiver tried MsgPack.unpack on the plaintext instead, so
        // every conformant identify from a Python or Rust peer landed in the
        // catch below and was "ignored as malformed" — silently, which meant
        // any request a peer made on a link to this client that depended on
        // its identity was refused without anyone seeing why. Sender and
        // receiver in this same file disagreed about the format; the sender
        // was right.
        else if(packet.context === Packet.LINKIDENTIFY) {
            let plaintext;
            try { plaintext = this.decrypt(packet.data); } catch(e) {
                console.warn(`[link] identify decrypt failed on ${this.hash?.toString("hex").slice(0,12)}: ${e.message}`);
                return;
            }
            if (plaintext.length !== 128) {
                console.warn(`[link] identify ignored: ${plaintext.length} bytes, expected pubkey(64)||sig(64)`);
                return;
            }
            try {
                const peerPubKey = plaintext.slice(0, 64);
                const signature = plaintext.slice(64, 128);
                const signedData = Buffer.concat([this.hash, peerPubKey]);
                const peerIdentity = Identity.fromPublicKey(Buffer.from(peerPubKey));
                if (peerIdentity.validate(Buffer.from(signature), signedData)) {
                    this.remoteIdentity = peerIdentity;
                } else {
                    console.warn(`[link] identify signature invalid on ${this.hash?.toString("hex").slice(0,12)}`);
                }
            } catch(e) {
                console.warn(`[link] identify processing failed: ${e.message}`);
            }
        }

        // handle request (context=0x09)
        else if(packet.context === Packet.REQUEST) {
            let plaintext;
            try { plaintext = this.decrypt(packet.data); } catch(e) { return; }
            try {
                const parsed = MsgPack.unpack(plaintext);
                let requestId, path, data;
                if (Array.isArray(parsed) && parsed.length >= 3) {
                    if (typeof parsed[0] === 'number' && Buffer.isBuffer(parsed[1])) {
                        // Rust format: [timestamp, path_hash, data]
                        requestId = packet.getTruncatedHash();
                        path = parsed[1];
                        data = parsed[2];
                    } else {
                        // Legacy JS format: [requestId, path_string, data]
                        requestId = parsed[0];
                        path = parsed[1];
                        data = parsed[2];
                    }
                }
                this.emit("request", { requestId, path, data, packet });
            } catch(e) { /* ignore malformed */ }
        }

        // handle response (context=0x0A)
        else if(packet.context === Packet.RESPONSE) {
            let plaintext;
            try { plaintext = this.decrypt(packet.data); } catch(e) { return; }
            let requestId, responseData;
            try {
                [requestId, responseData] = MsgPack.unpack(plaintext);
            } catch(e) { return; /* malformed: RNS logs and drops it */ }
            this._handleResponse(requestId, responseData, { packet });
        }

        // handle link close
        else if(packet.context === Packet.LINKCLOSE){

            // decrypt link id from packet data and do nothing if it doesn't match this link
            const linkIdToClose = this.decrypt(packet.data);
            if(!this.hash.equals(linkIdToClose)){
                return;
            }

            // mark link as closed (RNS/Link.py teardown_packet)
            this.status = Link.CLOSED;
            this.closeReason = this.initiator ? Link.DESTINATION_CLOSED : Link.INITIATOR_CLOSED;
            this._linkClosed();

        }

    }

    /**
     * Everything that follows a link reaching CLOSED, whichever way it got
     * there: a LINKCLOSE from the peer, close(), the STALE timeout, or an
     * establishment that never completed (RNS/Link.py link_closed). The
     * caller sets status and closeReason first.
     */
    _linkClosed() {
        this._clearEstablishmentWatchdog();
        this._clearKeepaliveWatchdog();
        // A request still pending fails now, before its response Resource is
        // cancelled below (so it fails as "link closed"). In the reference
        // its timeout outlives the link (Transport's receipt, or the request
        // Resource's thread); here the close is the failure event, as in
        // Rust's link_closed.
        for(const receipt of [...this.pendingRequests]){
            this._failRequest(receipt, "the link closed before a response");
        }
        // RNS/Link.py link_closed(): every Resource in flight on the link is
        // cancelled, so its promise and callbacks settle now (FAILED)
        // instead of when a timer runs out. The link is already CLOSED, so
        // no cancel packets go out. (Rust 6e53dea did the same.)
        for(const resource of [...this.incomingResources, ...this.outgoingResources]){
            resource.cancel("link closed");
        }
        for(const key of [...this._splitAssemblies.keys()]){
            this._dropSplitAssembly(key, "link closed");
        }
        this.emit("close");
    }

    /**
     * RNS/Link.py __teardown_packet(): a LINKCLOSE carrying the link id,
     * encrypted like any link packet, so the peer drops its side at once
     * instead of waiting out its own stale timer. Not sent while PENDING
     * (there are no keys yet) or once CLOSED (teardown()'s guard).
     */
    _sendTeardownPacket() {
        if(this.status === Link.PENDING || this.status === Link.CLOSED) return;
        try {
            this._transmit(this.newLinkPacket(Packet.LINKCLOSE, this.hash).pack());
        } catch(e) {
            // A link that cannot encrypt cannot say goodbye; it still closes.
            console.warn(`[link] ${this.hash?.toString("hex").slice(0,12)} could not send LINKCLOSE: ${e.message}`);
        }
    }

    /**
     * Fail the link if establishment never completes.
     *
     * NEVER REMOVE. RNS/Link.py's __watchdog_job (line 772) does exactly this:
     * while the link is PENDING or HANDSHAKE, once
     * `request_time + establishment_timeout` has passed it sets
     * `status = CLOSED`, `teardown_reason = TIMEOUT` and calls `link_closed()`,
     * which fires the closed callbacks. Establishment is therefore guaranteed
     * to reach a terminal state.
     *
     * This stack was missing that transition, so a link whose LINKREQUEST was
     * lost in transit stayed PENDING forever and never emitted "close".
     * Anything awaiting establishment then waited forever, because the only
     * code that settles the establishment promise runs from the "established"
     * and "close" events.
     *
     * Observed in production: a browser's propagation LINKREQUEST was accepted
     * by its local PHP node but never arrived at the propagation node. The
     * link sat PENDING, the send awaiting it hung silently, and the caller's
     * retry loop — which is driven by that promise rejecting — never ran again,
     * so the client never recovered and no message was ever propagated.
     */
    _startEstablishmentWatchdog() {
        this._clearEstablishmentWatchdog();
        this._establishmentTimer = setTimeout(() => {
            this._establishmentTimer = null;
            if(this.status === Link.ACTIVE || this.status === Link.CLOSED){
                return;
            }
            console.log(`[link] establishment timed out for ${this.hash?.toString("hex")}`);
            this.status = Link.CLOSED;
            this.closeReason = Link.TIMEOUT;
            this._linkClosed();
        }, this.establishmentTimeout);
    }

    _clearEstablishmentWatchdog() {
        if(this._establishmentTimer){
            clearTimeout(this._establishmentTimer);
            this._establishmentTimer = null;
        }
    }

    /**
     * `iface` reports this link's LINKREQUEST lost: it will never leave
     * (PostInterface "lost" — the batch of a failed exchange, or a packet
     * handed to it while it was down). Reticulum calls this for
     * every link whose request is named in the report. Once every interface
     * the request went to has lost it, the attempt has failed, and it closes
     * now, as the establishment watchdog would close it (TIMEOUT), instead
     * of waiting out establishmentTimeout for an LRPROOF that cannot come.
     *
     * A departure from RNS, which waits establishment_timeout whatever
     * became of the request (RNS/Link.py __watchdog_job): the interface's
     * report is the deterministic failure event DESIGN_PRINCIPLES §1 asks
     * for ("name the OS return value, protocol message, or state
     * transition — not an elapsed time"), and the doomed attempt, in flight
     * for its whole timeout, would otherwise swallow the event that can
     * bring the link back — the exchange's return re-drives only a link
     * that is not already coming up. app-links fails an attempt that has no
     * usable interface at once, the same way (app-links/src/lib.rs
     * SendErr::NoUsableInterface, race_path; interface_online re-attempts
     * it). Whether a failed exchange's batch reached the node cannot be
     * known; an LRPROOF that still comes finds no pending link and is
     * dropped, as for any closed attempt, nothing re-sends the request (§3),
     * and the exchange's return ("up" after the "down" it marked) re-drives
     * the link.
     *
     * Only while PENDING: a link that has its proof does not depend on the
     * request any more. An interface that never reports loss (TCP,
     * WebSocket) keeps the attempt to its watchdog.
     *
     * Not for an exchange a check abandoned (`abandoned`: PostInterface
     * check() gave up on it when the page or its network came back: online,
     * visible, pageshow from the cache). That report does not
     * say the request never left: the node may have taken the batch, and
     * the exchange check() starts next may carry the LRPROOF. Nor is it a
     * failure: no "down" is marked, so no return follows to re-drive the
     * link. So the attempt waits for its LRPROOF or its establishment
     * timeout, as RNS waits. Until 2026-10-01 it closed at once, and an
     * LRPROOF that still came was dropped, leaving the link down until the
     * next event (review of 2026-09-30).
     */
    requestLost(iface, reason, { abandoned = false } = {}) {
        if(abandoned) return;
        if(!this.initiator || this.status !== Link.PENDING) return;
        if(!this._requestInterfaces?.delete(iface)) return;
        if(this._requestInterfaces.size > 0) return;
        console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} link request lost (${reason}) — establishment failed`);
        this.requestLostReason = reason;
        this.status = Link.CLOSED;
        this.closeReason = Link.TIMEOUT;
        this._linkClosed();
    }

    /**
     * Scale the keepalive interval from the measured RTT.
     * Mirrors RNS/Link.py __update_keepalive and Rust's update_keepalive().
     */
    _updateKeepalive() {
        const rttSecs = (Number(this.rtt) || 0) / 1000;
        const scaled = rttSecs * (Link.KEEPALIVE_MAX / Link.KEEPALIVE_MAX_RTT);
        this.keepalive = Math.max(
            Link.KEEPALIVE_MIN,
            Math.min(Link.KEEPALIVE_MAX, scaled),
        );
        this.staleTime = this.keepalive * Link.STALE_FACTOR;
    }

    /**
     * Decide what the watchdog does at time `now`, given link timings.
     * RNS/Link.py __watchdog_job, ACTIVE and STALE branches (1.5.2,
     * Link.py:743-766).
     *
     * Pure and static so the state machine is testable without timers, links
     * or sockets — the thing that actually went wrong here (no keepalives at
     * all) is a logic gap, and logic gaps belong in unit tests rather than in
     * a 60-second integration wait.
     *
     * All times in seconds. Returns `{ ping, next }`:
     *   ping — send a 0xFF keepalive now (initiator only), BEFORE applying next
     *   next — "idle"     nothing else to do
     *          "stale"    no inbound for staleTime: enter STALE, start grace
     *          "teardown" grace expired: the link is dead, tear it down
     */
    static keepaliveAction({
        now, lastInbound, lastProof, lastOutbound, lastKeepalive, activatedAt,
        keepalive, staleTime, initiator, status,
        staleSince = null, staleGrace = 0,
    }) {
        if (status === Link.STALE) {
            return { ping: false, next: (now >= staleSince + Math.max(1, staleGrace)) ? "teardown" : "idle" };
        }
        if (status !== Link.ACTIVE) {
            return { ping: false, next: "idle" };
        }
        // The latest of inbound, proof and activation is "last heard".
        const heard = Math.max(lastInbound || 0, lastProof || 0, activatedAt || 0);
        // Link.py:749: act when EITHER direction has been quiet for a
        // keepalive period. A link that only receives still pings, or the
        // peer (which hears nothing from it) times it out.
        if (now < heard + keepalive && now < (lastOutbound || 0) + keepalive) {
            return { ping: false, next: "idle" };
        }
        const stale = now >= heard + staleTime;             // Link.py:753
        // Link.py:750 pings when the last keepalive is a period old. On
        // entering STALE the initiator also sends a final keepalive, as the
        // reference's STALE_TIME contract states ("the link will be marked
        // as stale, and a final keep-alive packet will be sent"). The
        // reference meets that contract with a watchdog that sleeps from the
        // ping, so its period condition holds at the stale tick; this
        // watchdog ticks every second from when it started, and the literal
        // condition missed that tick by under a second about half the time.
        // The final keepalive is what lets a responder that skipped the
        // earlier ping (its pong gate) answer before the grace runs out.
        const ping = !!initiator && (stale || now >= (lastKeepalive || 0) + keepalive);
        return { ping, next: stale ? "stale" : "idle" };
    }

    /**
     * Run the keepalive/stale cycle. One timer per link, cleared on close.
     *
     * Only the INITIATOR pings; the responder answers when its own outbound
     * has been quiet (see the KEEPALIVE branch of onPacket). That asymmetry
     * is the reference's, and it matters here because this client is always
     * the initiator for its rfed and propagation links.
     */
    _startKeepaliveWatchdog() {
        this._clearKeepaliveWatchdog();
        const tick = () => {
            this._keepaliveTimer = null;
            if (this.status === Link.CLOSED) {
                return;
            }
            this._watchdogStep(Date.now());
            if (this.status !== Link.CLOSED) {
                this._keepaliveTimer = setTimeout(tick, 1000);
            }
        };
        this._keepaliveTimer = setTimeout(tick, 1000);
    }

    /** One watchdog pass at `nowMs`. Split from the timer so tests can drive it. */
    _watchdogStep(nowMs) {
        const s = (ms) => (ms || 0) / 1000;
        const action = Link.keepaliveAction({
            now: nowMs / 1000,
            lastInbound: s(this.lastInbound),
            lastProof: s(this.lastProof),
            lastOutbound: s(this.lastOutbound),
            lastKeepalive: s(this.lastKeepalive),
            activatedAt: s(this.activatedAt),
            keepalive: this.keepalive,
            staleTime: this.staleTime,
            initiator: this.initiator,
            status: this.status,
            staleSince: this.staleSince ? this.staleSince / 1000 : null,
            staleGrace: this.staleGrace || 0,
        });

        // The ping goes out before the link is marked STALE (Link.py:750-755).
        if (action.ping) {
            this._sendKeepalive();
        }
        if (action.next === "stale") {
            this.status = Link.STALE;
            this.staleSince = nowMs;
            this.staleGrace = ((Number(this.rtt) || 0) / 1000)
                * Link.KEEPALIVE_TIMEOUT_FACTOR + Link.STALE_GRACE;
            console.warn(`[link] ${this.hash?.toString("hex").slice(0,12)} went STALE `
                + `(no inbound for ${this.staleTime.toFixed(0)}s) — grace ${this.staleGrace.toFixed(0)}s`);
        } else if (action.next === "teardown") {
            // Link.py:761-766: send the teardown packet, then CLOSED with
            // reason TIMEOUT. Without the LINKCLOSE the peer kept this link
            // bound and pushed into it until its own stale timer ran out.
            console.warn(`[link] ${this.hash?.toString("hex").slice(0,12)} timed out after STALE — tearing down`);
            this._sendTeardownPacket();
            this.status = Link.CLOSED;
            this.closeReason = Link.TIMEOUT;
            this._linkClosed();
        }
        return action;
    }

    _clearKeepaliveWatchdog() {
        if(this._keepaliveTimer){
            clearTimeout(this._keepaliveTimer);
            this._keepaliveTimer = null;
        }
    }

    /** Send a single unencrypted 0xFF ping. The peer answers 0xFE. */
    _sendKeepalive() {
        try {
            this._transmit(this.newLinkPacket(Packet.KEEPALIVE, Buffer.from([0xFF])).pack(), true);
        } catch(e) {
            console.warn(`[link] keepalive send failed: ${e.message}`);
        }
    }

    /**
     * Called internally when a Link Request RTT packet has been received.
     * @param packet
     */
    onLinkRequestRtt(packet) {

        // measure round trip time
        this.measuredRtt = Date.now() - this.requestTime;

        // decrypt rtt data from packet
        const plaintext = this.decrypt(packet.data);
        if(!plaintext){
            return;
        }

        // unpack data: the initiator reports its RTT in seconds (RNS/Link.py
        // validate_proof packs self.rtt, a float of seconds; so does
        // validateProof() above). This link keeps rtt in milliseconds.
        const reportedRttMs = Number(MsgPack.unpack(plaintext)) * 1000;

        // update link rtt with the slowest of the two rtt values
        // (RNS/Link.py rtt_packet: max(measured_rtt, rtt)). Until 2026-09-30
        // the seconds went into Math.max unconverted, so the measured value
        // always won and a responder whose initiator had the longer RTT got
        // a shorter keepalive than the initiator, and went STALE first.
        this.rtt = Number.isFinite(reportedRttMs)
            ? Math.max(this.measuredRtt, reportedRttMs)
            : this.measuredRtt;

        // activate link
        this._clearEstablishmentWatchdog();
        this.destination.rns.activateLink(this);
        // Responder side: the link is live from here, so the keepalive cycle
        // starts now. This side never pings (keepaliveAction gates that on
        // `initiator`); the watchdog still runs so a responder link that stops
        // hearing from its peer goes STALE and is torn down rather than
        // lingering as a phantom ACTIVE.
        this._updateKeepalive();
        this._startKeepaliveWatchdog();

        // fire link established callback
        this.emit("established");

    }

    proveLinkPacket(packetToProve) {

        // sign the hash of the packet to prove
        const signature = this.sign(packetToProve.packetHash);

        // create explicit proof data (rns python stack doesn't use implicit for link packet proofs)
        const proofData = Buffer.concat([
            packetToProve.packetHash,
            signature,
        ]);

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.PROOF;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = proofData;

        // pack packet
        const raw = packet.pack();

        // send packet to attached interface
        this._transmit(raw);

    }

    /**
     * Identify this link to the remote peer.
     * Rust format: raw [public_key(64) || signature(64)] = 128 bytes.
     * Signed data: link_id(16) || public_key(64) — matches Rust.
     * Required before the propagation node will respond to /get requests.
     */
    identify(identity) {
        const pubKey = identity.getPublicKey();
        const signedData = Buffer.concat([this.hash, pubKey]);
        const sig = identity.sign(signedData);
        const data = Buffer.concat([pubKey, sig]);
        this._sendWithContext(data, Packet.LINKIDENTIFY);
    }

    /**
     * Accept an advertised Resource on this link. A later segment of a split
     * Resource is accepted only as the next segment of one this link is
     * reassembling (same original hash, same segment count); anything else
     * could only produce a partial payload, so it is refused.
     * @returns {Resource|null}
     */
    _acceptResource(advertisement, refusal = null) {
        const get = (key) => (advertisement instanceof Map ? advertisement.get(key) : advertisement?.[key]);
        const segmentIndex = Number(get("i") ?? 1);
        const totalSegments = Number(get("l") ?? 1);
        let assembly = null;
        if(totalSegments > 1 && segmentIndex > 1){
            const originalHash = get("o") ? Buffer.from(get("o")).toString("hex") : null;
            assembly = originalHash ? this._splitAssemblies.get(originalHash) : null;
            if(!assembly || assembly.nextSegment !== segmentIndex || assembly.totalSegments !== totalSegments){
                const why = `segment ${segmentIndex}/${totalSegments} of a split Resource this link is not reassembling`;
                console.warn(`[link] ${this.hash?.toString("hex").slice(0,12)} refused ${why}`);
                new Resource(this).reject(advertisement);
                if(refusal) refusal.reason = why;
                return null;
            }
        }
        const resource = Resource.accept(this, advertisement, refusal);
        // §1: the next segment is advertised and taken, so the wait for it
        // is over (_betweenSegments); its own Resource watches it from here.
        if(resource && assembly){
            assembly.wait?.stop(`segment ${segmentIndex}/${totalSegments} advertised`);
            assembly.wait = null;
        }
        return resource;
    }

    /** RNS/Link.py: `if self.destination.request_handlers` — here, a "request" listener. */
    _handlesRequests() {
        return (this.eventListenersMap.get("request")?.length ?? 0) > 0;
    }

    /**
     * An incoming Resource concluded (called synchronously by the Resource).
     * A segment of a split Resource is added to its reassembly; the last
     * segment hands the whole payload on, as Resource.py assemble() does once
     * segment_index == total_segments.
     */
    _incomingResourceConcluded(resource) {
        if(resource.totalSegments > 1){
            const key = resource.originalHash.toString("hex");
            let assembly = this._splitAssemblies.get(key);
            if(resource.segmentIndex === 1){
                // The same Resource sent again from its start: the old
                // reassembly (and its wait for a segment) is over.
                this._dropSplitAssembly(key, "sent again from segment 1");
                assembly = {
                    chunks: [], size: 0, nextSegment: 1,
                    totalSegments: resource.totalSegments, declaredSize: resource.totalSize,
                    // A response's reassembly dies with its request (_failRequest).
                    requestId: resource.isResponse && resource.requestId ? Buffer.from(resource.requestId) : null,
                    // §1: when the whole transfer began, and the watch on the
                    // wait for the next segment (_betweenSegments).
                    startedAt: resource.bulk?.startedAt ?? null,
                    wait: null,
                };
                this._splitAssemblies.set(key, assembly);
            }
            if(!assembly || assembly.nextSegment !== resource.segmentIndex){
                console.warn(`[link] segment ${resource.segmentIndex} concluded out of order; dropping the split Resource`);
                this._dropSplitAssembly(key, "dropped: its segments arrived out of order");
                this._incomingResourceDropped(resource, "a split Resource's segments arrived out of order");
                return;
            }
            assembly.chunks.push(resource.data);
            assembly.size += resource.data.length;
            assembly.nextSegment++;
            if(assembly.size > assembly.declaredSize){
                // The segments carry more than the advertised total: never
                // hold more than the sender declared.
                this._dropSplitAssembly(key, `dropped: over its declared ${assembly.declaredSize} bytes`);
                this._incomingResourceDropped(resource, `split Resource exceeded its declared ${assembly.declaredSize} bytes`);
                return;
            }
            if(resource.segmentIndex < resource.totalSegments){
                this._betweenSegments(resource, assembly);
                return;
            }
            this._dropSplitAssembly(key, "concluded");
            resource.data = Buffer.concat(assembly.chunks);
        }
        this._dispatchConcludedResource(resource);
    }

    /** An incoming Resource failed (called synchronously by the Resource). */
    _incomingResourceFailed(resource, reason) {
        if(resource.totalSegments > 1 && resource.originalHash){
            this._dropSplitAssembly(resource.originalHash.toString("hex"), `failed: ${reason}`);
        }
        this._incomingResourceDropped(resource, reason);
    }

    /**
     * A segment of a split Resource concluded and the next is awaited. For a
     * response, nothing is transferring until the next segment is
     * advertised, so the request waits for its response again and its
     * timeout applies. The reference leaves it RECEIVING, where no timeout
     * acts: a sender that never advertised the next segment would leave the
     * request pending for as long as the link lives.
     *
     * DESIGN_PRINCIPLES §1, bulk transfers: the split Resource is one
     * transfer from its first advertisement to its last proof (a
     * /distro/pull page of photos, a large /get), and the wait from this
     * segment's proof to the next segment's advertisement is part of it. No
     * Resource runs there to watch it, so the reassembly does, from the
     * proof until the next segment is taken (_acceptResource) or the
     * reassembly is dropped (_dropSplitAssembly: its request failed, the
     * link closed). Until 2026-10-01 that wait was not watched at all.
     */
    _betweenSegments(resource, assembly) {
        const key = resource.originalHash.toString("hex");
        const next = assembly.nextSegment;
        const total = assembly.totalSegments;
        const kind = resource.isRequest ? "request " : resource.isResponse ? "response " : "";
        const link = this.hash ? this.hash.toString("hex").slice(0, 12) : "?";
        assembly.wait = new Resource.BulkWatch(
            () => `received split ${kind}Resource ${key.slice(0, 12)} (${assembly.declaredSize} B, link ${link}), waiting for segment ${next}/${total}`,
            () => `${next - 1} of ${total} segments received`,
        );
        assembly.wait.start(assembly.startedAt);
        if(!resource.isResponse || !resource.requestId) return;
        const receipt = this._pendingRequest(resource.requestId);
        if(receipt) this._startResponseClock(receipt);
    }

    /** A split Resource's reassembly is over (`how`): released, and the
     *  watch on any wait for its next segment ended. */
    _dropSplitAssembly(key, how) {
        const assembly = this._splitAssemblies.get(key);
        if(!assembly) return;
        assembly.wait?.stop(how);
        assembly.wait = null;
        this._splitAssemblies.delete(key);
    }

    /**
     * An incoming Resource (or a split one's reassembly) ended without a
     * payload. A response that fails fails its request now (Rust parity).
     * The reference's response_resource_concluded calls request_timed_out,
     * which acts only on a DELIVERED request, and a request whose response
     * was transferring is RECEIVING, so it would never conclude.
     */
    _incomingResourceDropped(resource, reason) {
        if(!resource.isResponse || !resource.requestId) return;
        const receipt = this._pendingRequest(resource.requestId);
        if(receipt) this._failRequest(receipt, `the response transfer failed: ${reason}`);
    }

    /**
     * A concluded incoming Resource is one of three things (RNS/Link.py
     * request_resource_concluded, response_resource_concluded, and the
     * resource_concluded callback): a request, whose id is the truncated
     * hash of the packed request on both sides; a response, packed exactly
     * like a RESPONSE packet; or bare data.
     */
    _dispatchConcludedResource(resource) {
        const data = resource.data;
        if(resource.isRequest){
            let parsed;
            try { parsed = MsgPack.unpack(data); } catch(e) {
                console.warn(`[link] request resource on ${this.hash?.toString("hex").slice(0,12)} is not msgpack: ${e.message}`);
                return;
            }
            if(!Array.isArray(parsed) || parsed.length < 3){
                console.warn(`[link] request resource on ${this.hash?.toString("hex").slice(0,12)} is not [timestamp, path_hash, data]`);
                return;
            }
            const requestId = Cryptography.truncatedHash(data);
            this.emit("request", { requestId, path: parsed[1], data: parsed[2], resource });
        } else if(resource.isResponse){
            let parsed;
            try { parsed = MsgPack.unpack(data); } catch(e) {
                console.warn(`[link] response resource on ${this.hash?.toString("hex").slice(0,12)} is not msgpack: ${e.message}`);
                const receipt = this._pendingRequest(resource.requestId);
                if(receipt) this._failRequest(receipt, "the response was not msgpack");
                return;
            }
            if(!Array.isArray(parsed) || parsed.length < 2){
                console.warn(`[link] response resource on ${this.hash?.toString("hex").slice(0,12)} is not [request_id, response]`);
                const receipt = this._pendingRequest(resource.requestId);
                if(receipt) this._failRequest(receipt, "the response was not [request_id, response]");
                return;
            }
            this._handleResponse(parsed[0], parsed[1], { resource });
        } else {
            this.emit("resource", { resource, data });
        }
    }

    /**
     * RNS/Link.py request(): `if len(packed_request) <= self.mdu` the request
     * is one REQUEST packet, otherwise the same bytes go as a Resource flagged
     * as a request, whose id is the truncated hash of the packed request.
     *
     * Either way a RequestReceipt is registered before anything is sent
     * (DESIGN_PRINCIPLES §5: a response can never outrun the entry it is
     * matched to), and responseFor(requestId) settles with the response or
     * the failure. The "response" event still fires for a matched response.
     *
     * @param options { timeoutMs, onProgress(fraction), onDelivered() }
     *   onDelivered: called once, when the request becomes DELIVERED (the
     *   peer holds it and the response clock starts): at the send for a
     *   packet, at the peer's proof for a request Resource. Not called for a
     *   request that is answered or fails first.
     */
    _sendRequestPayload(requestPayload, options = {}) {
        if(this.status === Link.CLOSED){
            // RNS/Link.py request() returns False: the packet is dropped.
            throw new Error("the link is closed");
        }
        const timeoutMs = options.timeoutMs ?? Link.requestTimeoutMs(this.rtt);
        if(requestPayload.length <= Link.MDU){
            const packet = this.newLinkPacket(Packet.REQUEST, requestPayload);
            const raw = packet.pack();
            const requestId = packet.getTruncatedHash();
            const receipt = this._registerRequest(requestId, timeoutMs, options.onProgress, options.onDelivered);
            this._transmit(raw);
            // The wait for the response starts at the send. The reference's
            // timeout rides on the request packet's receipt, and when it
            // expires request_timed_out acts only on a DELIVERED request,
            // which a request sent as a packet never becomes: copied
            // literally, a lost request would never fail. So the budget runs
            // from the send until a response starts to arrive.
            this._startResponseClock(receipt);
            return requestId;
        }
        const requestId = Cryptography.truncatedHash(requestPayload);
        const receipt = this._registerRequest(requestId, timeoutMs, options.onProgress, options.onDelivered);
        let sending;
        try {
            sending = Resource.send(this, requestPayload, { requestId, isRequest: true, timeoutMs });
        } catch(e) {
            this._failRequest(receipt, `the request could not be sent: ${e.message}`);
            throw e;
        }
        // RNS/Link.py RequestReceipt.request_resource_concluded: the wait
        // for the response starts once the peer has proved the request.
        sending.then(
            () => this._requestResourceConcluded(receipt, true),
            (e) => this._requestResourceConcluded(receipt, false, e.message),
        );
        return requestId;
    }

    // ---- Request receipts (RNS/Link.py RequestReceipt) ----

    _registerRequest(requestId, timeoutMs, onProgress, onDelivered = null) {
        const receipt = {
            requestId: Buffer.from(requestId),
            timeoutMs,
            onProgress: typeof onProgress === "function" ? onProgress : null,
            onDelivered: typeof onDelivered === "function" ? onDelivered : null,
            status: Link.REQUEST_SENT,
            progress: 0,
            sentAt: Date.now(),
            timer: null,
        };
        receipt.promise = new Promise((resolve, reject) => {
            receipt.resolve = resolve;
            receipt.reject = reject;
        });
        // A request nobody waits on must not surface as an unhandled
        // rejection; responseFor() hands out the same promise.
        receipt.promise.catch(() => {});
        this.pendingRequests.push(receipt);
        return receipt;
    }

    _pendingRequest(requestId) {
        if(!requestId) return null;
        const id = Buffer.from(requestId);
        return this.pendingRequests.find((r) => r.requestId.equals(id)) ?? null;
    }

    /**
     * The request's response. Resolves with the response value; rejects when
     * the request fails: no response started within its timeout, the
     * request or its response failed to transfer, or the link closed.
     */
    responseFor(requestId) {
        const receipt = this._pendingRequest(requestId)
            ?? this._concludedRequests.get(Buffer.from(requestId ?? []).toString("hex"));
        if(!receipt){
            return Promise.reject(new Error(`no request ${Buffer.from(requestId ?? []).toString("hex").slice(0,12)} is pending on this link`));
        }
        return receipt.promise;
    }

    /** DELIVERED: the peer holds the request; the response timeout runs. */
    _startResponseClock(receipt) {
        if(receipt.status === Link.REQUEST_FAILED || receipt.status === Link.REQUEST_READY) return;
        receipt.status = Link.REQUEST_DELIVERED;
        // The first time only: between a split response's segments the
        // clock starts again, and the request was delivered long before.
        const onDelivered = receipt.onDelivered;
        receipt.onDelivered = null;
        if(onDelivered){
            try { onDelivered(); } catch(e) {
                console.warn(`[link] request ${receipt.requestId.toString("hex").slice(0,12)}: its delivered callback threw: ${e.message}`);
            }
        }
        if(receipt.timer) clearTimeout(receipt.timer);
        receipt.timer = setTimeout(() => {
            receipt.timer = null;
            // RNS/Link.py request_timed_out: only while DELIVERED.
            if(receipt.status === Link.REQUEST_DELIVERED){
                this._failRequest(receipt, `no response within ${Math.round(receipt.timeoutMs)} ms`);
            }
        }, receipt.timeoutMs);
    }

    _requestResourceConcluded(receipt, delivered, reason = "") {
        if(!this.pendingRequests.includes(receipt)) return;   // already answered or failed
        if(delivered){
            // Only a request still waiting for its proof starts the clock.
            // The Resource settles its promise a macrotask after the proof
            // was handled, and the response's advertisement can be handled
            // in between (PostInterface delivers a poll's batch in one
            // synchronous loop): the request is then RECEIVING, and putting
            // it back to DELIVERED with its timer running would fail a
            // response mid-transfer if its first part took longer than the
            // timeout. In wire order the proof came first and the
            // advertisement ended the wait, so there is nothing to start.
            if(receipt.status !== Link.REQUEST_SENT) return;
            this._startResponseClock(receipt);
        } else {
            this._failRequest(receipt, `sending the request as a Resource failed: ${reason}`);
        }
    }

    /**
     * RNS/Link.py response_resource_progress: the response is arriving, so
     * the request is RECEIVING and its timeout no longer applies; the
     * Resource's own watchdog bounds the transfer, and its failure fails
     * the request (_incomingResourceDropped).
     */
    _responseResourceProgress(receipt, resource) {
        if(receipt.status === Link.REQUEST_FAILED){
            resource.cancel("the request this response answers has failed");
            return;
        }
        receipt.status = Link.REQUEST_RECEIVING;
        if(receipt.timer){
            clearTimeout(receipt.timer);
            receipt.timer = null;
        }
        receipt.progress = resource.getProgress();
        receipt.onProgress?.(receipt.progress);
        this.emit("request_progress", { requestId: receipt.requestId, progress: receipt.progress });
    }

    /**
     * RNS/Link.py RequestReceipt.response_rejected (Link.py:1049-1052): this
     * link refused the response Resource (RCL), so no response is coming and
     * the request fails now, saying why. Until 2026-09-30 it waited out its
     * timeout and then reported "no response within N ms", which was false:
     * the response came and was refused. A request whose response is
     * already transferring (RECEIVING) is left to that transfer, as in the
     * reference. The reference acts only on DELIVERED; a request sent as a
     * Resource whose proof has not been handled yet (SENT) fails here too,
     * because the refused response is the only one its peer sends.
     */
    _responseRejected(receipt, reason) {
        if(receipt.status === Link.REQUEST_RECEIVING) return;
        this._failRequest(receipt, `the response was refused: ${reason}`);
    }

    /** RNS/Link.py handle_response: only for a pending request. */
    _handleResponse(requestId, data, { packet = null, resource = null } = {}) {
        const receipt = this._pendingRequest(requestId);
        if(!receipt){
            console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} ignored a response for no pending request`);
            return false;
        }
        this._concludeRequest(receipt);
        receipt.status = Link.REQUEST_READY;
        receipt.progress = 1.0;
        receipt.onProgress?.(1.0);
        receipt.resolve(data);
        this.emit("response", { requestId: receipt.requestId, data, packet, resource });
        return true;
    }

    _failRequest(receipt, reason) {
        if(!this.pendingRequests.includes(receipt)) return;
        this._concludeRequest(receipt);
        receipt.status = Link.REQUEST_FAILED;
        // A split response half reassembled for this request can never be
        // completed now (its later segments are ignored, as no request is
        // pending), so it is released here rather than held until the link
        // closes: on the long-lived rfed.link that was up to (l-1) x 1 MiB.
        for(const [key, assembly] of [...this._splitAssemblies]){
            if(assembly.requestId?.equals(receipt.requestId)) this._dropSplitAssembly(key, `its request failed: ${reason}`);
        }
        console.warn(`[link] request ${receipt.requestId.toString("hex").slice(0,12)} failed: ${reason}`);
        receipt.reject(new Error(reason));
    }

    _concludeRequest(receipt) {
        if(receipt.timer){
            clearTimeout(receipt.timer);
            receipt.timer = null;
        }
        const index = this.pendingRequests.indexOf(receipt);
        if(index !== -1) this.pendingRequests.splice(index, 1);
        this._concludedRequests.set(receipt.requestId.toString("hex"), receipt);
        while(this._concludedRequests.size > Link.CONCLUDED_REQUESTS_KEPT){
            this._concludedRequests.delete(this._concludedRequests.keys().next().value);
        }
    }

    /**
     * Send a request over the link (context=0x09).
     *
     * Rust/Python wire format: msgpack([timestamp_f64, path_hash(16), data])
     * where path_hash = truncated_hash(sha256(path_bytes)).
     *
     * request_id = truncated_hash(packet.hashable_part), matching Rust.
     * Returns the request_id so the caller can match the response.
     */
    sendRequest(path, data, options = {}) {
        const pathHash = Cryptography.truncatedHash(Buffer.from(path, "utf8"));
        const timestamp = Date.now() / 1000.0;
        const requestPayload = MsgPack.pack([timestamp, pathHash, data]);
        return this._sendRequestPayload(requestPayload, options);
    }

    /**
     * Send a request whose data is already encoded as one native msgpack value.
     * This avoids wrapping signed RFed arrays in a msgpack Binary envelope.
     *
     * `packedData` MUST be one complete msgpack value — the 0x93 below promises
     * the peer a three-element array, and packedData IS the third element. An
     * empty buffer is not a msgpack value: it produced a 28-byte request whose
     * parser died at end-of-buffer ("failed to fill whole buffer" in rfed's
     * log, 2026-08-17), and because that happened server-side after decrypt,
     * the client saw only a full-budget timeout. A request with no data is
     * msgpack nil (0xc0) — exactly what the Python reference sends for
     * request(path, data=None) (RNS/Link.py:493, umsgpack packs None as nil).
     */
    sendRequestPacked(path, packedData, options = {}) {
        if (!packedData || packedData.length === 0) {
            throw new Error(
                "sendRequestPacked: packedData must be one complete msgpack value; " +
                "for a request with no data send MsgPack.pack(null) (nil, 0xc0) " +
                "like the Python reference"
            );
        }
        const pathHash = Cryptography.truncatedHash(Buffer.from(path, "utf8"));
        const timestamp = Date.now() / 1000.0;
        const requestPayload = Buffer.concat([
            Buffer.from([0x93]),
            MsgPack.pack(timestamp),
            MsgPack.pack(pathHash),
            Buffer.from(packedData),
        ]);
        return this._sendRequestPayload(requestPayload, options);
    }

    /**
     * Send a response over the link (context=0x0A).
     * Rust/Python wire format: msgpack([Binary(request_id), response_value]).
     */
    sendResponse(requestId, responseData) {
        const responsePayload = MsgPack.pack([requestId, responseData]);
        // RNS/Link.py handle_request(): over the MDU the packed response goes
        // as a Resource flagged as a response, carrying the request id.
        if(responsePayload.length <= Link.MDU){
            this._sendWithContext(responsePayload, Packet.RESPONSE);
            return;
        }
        Resource.send(this, responsePayload, { requestId: Buffer.from(requestId), isResponse: true }).catch((e) => {
            console.warn(`[link] response resource for ${Buffer.from(requestId).toString("hex").slice(0,12)} failed: ${e.message}`);
        });
    }

    _sendWithContext(data, context) {
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = context;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = data;

        // packet.pack() handles link encryption and computes packetHash
        const raw = packet.pack();
        this._transmit(raw);
        return packet;
    }

    /**
     * Close the link and tell the other side (RNS/Link.py teardown()).
     */
    close() {

        // do nothing if link already closed
        if(this.status === Link.CLOSED){
            return;
        }

        // tell the peer, unless the link never got its keys
        this._sendTeardownPacket();

        // mark link as closed
        this.status = Link.CLOSED;
        this.closeReason = this.initiator ? Link.INITIATOR_CLOSED : Link.DESTINATION_CLOSED;
        this._linkClosed();

    }

}

export default Link;
