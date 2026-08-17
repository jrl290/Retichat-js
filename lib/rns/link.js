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

    // Whether inbound resource advertisements are accepted on this link.
    static ACCEPT_NONE = 0x00;
    static ACCEPT_ALL = 0x02;

    constructor() {
        super();
        this.incomingResources = [];
        this.outgoingResources = [];
        this.resourceStrategy = Link.ACCEPT_NONE;
    }

    establish(destination, hops = Link.DEFAULT_ESTABLISHMENT_HOPS) {

        this.initiator = true;
        this.status = Link.PENDING;
        this.destination = destination;
        this.attachedInterface = null;

        // generate private keys
        this.privateKeyBytes = Buffer.from(x25519.utils.randomPrivateKey());
        this.signaturePrivateKeyBytes = Buffer.from(ed25519.utils.randomPrivateKey());

        // get public keys
        this.publicKeyBytes = Buffer.from(x25519.getPublicKey(this.privateKeyBytes));
        this.signaturePublicKeyBytes = Buffer.from(x25519.getPublicKey(this.signaturePrivateKeyBytes));

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

            // fixme: only send on relevant interface
            // send link request
            console.log(`Sending Link request ${this.hash.toString("hex")} to ${destination.hash.toString("hex")}`)
            this.destination.rns.sendData(packed);

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
        // No keepalive watchdog on accepted links yet. (A stale note here used
        // to say `todo this.startWatchdog()` — no such method ever existed.
        // Do not confuse it with _startEstablishmentWatchdog(), which is real,
        // initiator-side, marked NEVER REMOVE, and only covers establishment.
        // Python's RNS/Link.py __watchdog_job also handles post-establishment
        // keepalive/stale teardown; that part is genuinely unimplemented here.)

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

            // send packet to attached interface
            this.destination.rns.sendData(raw, this.attachedInterface);

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
        this.destination.rns.sendData(raw, this.attachedInterface);

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
        this.destination.rns.sendData(raw, this.attachedInterface);

        return packet;

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

    /** Called by the stack when a RESOURCE_PRF proof packet arrives for this link. */
    onResourceProof(packet) {
        const hash = packet.data.slice(0, Resource.HASHLENGTH_IN_BYTES);
        const resource = this.outgoingResources.find((r) => r.hash.equals(hash));
        if(resource){
            resource.onProof(packet.data);
        }
    }

    /**
     * Transfer a payload of any size over this link as a Resource.
     * @returns {Promise<Resource>} resolves once the peer proves receipt
     */
    sendResource(data) {
        return Resource.send(this, data);
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

        // Any inbound traffic proves the path is alive, which is what the
        // keepalive watchdog measures. Before 2026-08-17 lastInbound was
        // written once, at accept(), and never again — so once the watchdog
        // existed it would have declared every healthy link stale. Refresh
        // FIRST, before any handler can return early.
        this.lastInbound = Date.now();
        if(this.status === Link.STALE){
            // The peer answered: recover rather than tear down. Matches the
            // Rust responder ("Mark active if stale") and Python's watchdog.
            this.status = Link.ACTIVE;
            this.staleSince = null;
            console.log(`[link] ${this.hash?.toString("hex").slice(0,12)} recovered from STALE`);
        }

        // KEEPALIVE travels unencrypted and MUST be handled before any
        // decrypt attempt — see the note in packet.js pack(). 0xFF is a ping
        // to answer; 0xFE is the pong, which needs nothing beyond the
        // lastInbound refresh above.
        if(packet.context === Packet.KEEPALIVE){
            const b = packet.data?.[0];
            if(b === 0xFF && !this.initiator){
                const reply = new Packet();
                reply.headerType = Packet.HEADER_1;
                reply.packetType = Packet.DATA;
                reply.transportType = Transport.BROADCAST;
                reply.context = Packet.KEEPALIVE;
                reply.contextFlag = Packet.FLAG_UNSET;
                reply.destination = this;
                reply.destinationHash = this.hash;
                reply.destinationType = Destination.LINK;
                reply.data = Buffer.from([0xFE]);
                try {
                    this.destination.rns.sendData(reply.pack(), this.attachedInterface);
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

            // Send proof back to the sender (required for LXMF delivery confirmation)
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
            this.destination.rns.sendData(proofRaw, this.attachedInterface);

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
            if(this.resourceStrategy === Link.ACCEPT_NONE){
                return;
            }
            let advertisement;
            try {
                advertisement = MsgPack.unpack(this.decrypt(packet.data));
            } catch(e) {
                console.warn("[resource] could not parse advertisement:", e.message);
                return;
            }
            const resource = Resource.accept(this, advertisement);
            if(resource){
                resource.once("concluded", () => this.emit("resource", { resource, data: resource.data }));
            }
        }

        // a resource part. Parts are not packet-encrypted — the resource
        // encrypts its payload as a whole before splitting it.
        else if(packet.context === Packet.RESOURCE){
            for(const resource of [...this.incomingResources]){
                if(resource.onPart(packet.data)) break;
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
                resource.onRequest(request);
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

        // either side cancelled a transfer
        else if(packet.context === Packet.RESOURCE_ICL || packet.context === Packet.RESOURCE_RCL){
            let hash;
            try { hash = this.decrypt(packet.data); } catch(e) { hash = packet.data; }
            for(const resource of [...this.incomingResources, ...this.outgoingResources]){
                if(resource.hash?.equals(hash?.slice(0, Resource.HASHLENGTH_IN_BYTES))){
                    resource.fail("peer cancelled the resource transfer");
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
            try {
                const [requestId, responseData] = MsgPack.unpack(plaintext);
                this.emit("response", { requestId, data: responseData, packet });
            } catch(e) { /* ignore malformed */ }
        }

        // handle link close
        else if(packet.context === Packet.LINKCLOSE){

            // decrypt link id from packet data and do nothing if it doesn't match this link
            const linkIdToClose = this.decrypt(packet.data);
            if(!this.hash.equals(linkIdToClose)){
                return;
            }

            // mark link as closed
            this.status = Link.CLOSED;
            this.closeReason = this.initiator ? Link.DESTINATION_CLOSED : Link.INITIATOR_CLOSED;
            this._clearEstablishmentWatchdog();
            this._clearKeepaliveWatchdog();

            // fire close event
            this.emit("close");

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
            this.emit("close");
        }, this.establishmentTimeout);
    }

    _clearEstablishmentWatchdog() {
        if(this._establishmentTimer){
            clearTimeout(this._establishmentTimer);
            this._establishmentTimer = null;
        }
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
     * Decide what the watchdog should do at time `now`, given link timings.
     *
     * Pure and static so the state machine is testable without timers, links
     * or sockets — the thing that actually went wrong here (no keepalives at
     * all) is a logic gap, and logic gaps belong in unit tests rather than in
     * a 60-second integration wait.
     *
     * All times in seconds. Returns one of:
     *   "idle"      — nothing due yet
     *   "keepalive" — send a 0xFF ping (initiator only)
     *   "stale"     — no inbound for staleTime; enter STALE and start grace
     *   "teardown"  — grace expired; the link is dead, tear it down
     */
    static keepaliveAction({
        now, lastInbound, lastKeepalive, activatedAt,
        keepalive, staleTime, initiator, status,
        staleSince = null, staleGrace = 0,
    }) {
        if (status === Link.STALE) {
            return (now >= staleSince + Math.max(1, staleGrace)) ? "teardown" : "idle";
        }
        if (status !== Link.ACTIVE) {
            return "idle";
        }
        // Python takes the latest of inbound/proof/activation as "last heard".
        const heard = Math.max(lastInbound || 0, activatedAt || 0);
        if (now < heard + keepalive) {
            return "idle";
        }
        // Staleness outranks pinging: once we are past staleTime with no
        // inbound, another ping cannot help.
        if (now >= heard + staleTime) {
            return "stale";
        }
        if (initiator && now >= (lastKeepalive || 0) + keepalive) {
            return "keepalive";
        }
        return "idle";
    }

    /**
     * Run the keepalive/stale cycle. One timer per link, cleared on close.
     *
     * Only the INITIATOR pings; the responder answers (rfed bounces 0xFE for
     * every 0xFF). That asymmetry is the reference's, and it matters here
     * because this client is always the initiator for its rfed and
     * propagation links.
     */
    _startKeepaliveWatchdog() {
        this._clearKeepaliveWatchdog();
        const tick = () => {
            if (this.status === Link.CLOSED) {
                this._clearKeepaliveWatchdog();
                return;
            }
            const now = Date.now() / 1000;
            const action = Link.keepaliveAction({
                now,
                lastInbound: (this.lastInbound || 0) / 1000,
                lastKeepalive: (this.lastKeepalive || 0) / 1000,
                activatedAt: (this.activatedAt || 0) / 1000,
                keepalive: this.keepalive,
                staleTime: this.staleTime,
                initiator: this.initiator,
                status: this.status,
                staleSince: this.staleSince ? this.staleSince / 1000 : null,
                staleGrace: this.staleGrace || 0,
            });

            if (action === "keepalive") {
                this._sendKeepalive();
            } else if (action === "stale") {
                this.status = Link.STALE;
                this.staleSince = Date.now();
                this.staleGrace = ((Number(this.rtt) || 0) / 1000)
                    * Link.KEEPALIVE_TIMEOUT_FACTOR + Link.STALE_GRACE;
                console.warn(`[link] ${this.hash?.toString("hex").slice(0,12)} went STALE `
                    + `(no inbound for ${this.staleTime.toFixed(0)}s) — grace ${this.staleGrace.toFixed(0)}s`);
            } else if (action === "teardown") {
                console.warn(`[link] ${this.hash?.toString("hex").slice(0,12)} timed out after STALE — tearing down`);
                this._clearKeepaliveWatchdog();
                this.status = Link.CLOSED;
                this.closeReason = Link.TIMEOUT;
                this.emit("close");
                return;
            }
            this._keepaliveTimer = setTimeout(tick, 1000);
        };
        this._keepaliveTimer = setTimeout(tick, 1000);
    }

    _clearKeepaliveWatchdog() {
        if(this._keepaliveTimer){
            clearTimeout(this._keepaliveTimer);
            this._keepaliveTimer = null;
        }
    }

    /** Send a single unencrypted 0xFF ping. The peer answers 0xFE. */
    _sendKeepalive() {
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.KEEPALIVE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = Buffer.from([0xFF]);
        try {
            const raw = packet.pack();
            this.destination.rns.sendData(raw, this.attachedInterface);
            this.lastKeepalive = Date.now();
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

        // unpack data
        const rtt = MsgPack.unpack(plaintext);

        // update link rtt with the slowest of the two rtt values
        this.rtt = Math.max(this.measuredRtt, rtt);

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
        this.destination.rns.sendData(raw, this.attachedInterface);

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
     * Send a request over the link (context=0x09).
     *
     * Rust/Python wire format: msgpack([timestamp_f64, path_hash(16), data])
     * where path_hash = truncated_hash(sha256(path_bytes)).
     *
     * request_id = truncated_hash(packet.hashable_part), matching Rust.
     * Returns the request_id so the caller can match the response.
     */
    sendRequest(path, data) {
        const pathHash = Cryptography.truncatedHash(Buffer.from(path, "utf8"));
        const timestamp = Date.now() / 1000.0;
        const requestPayload = MsgPack.pack([timestamp, pathHash, data]);
        const packet = this._sendWithContext(requestPayload, Packet.REQUEST);
        return packet.getTruncatedHash();
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
    sendRequestPacked(path, packedData) {
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
        const packet = this._sendWithContext(requestPayload, Packet.REQUEST);
        return packet.getTruncatedHash();
    }

    /**
     * Send a response over the link (context=0x0A).
     * Rust/Python wire format: msgpack([Binary(request_id), response_value]).
     */
    sendResponse(requestId, responseData) {
        const responsePayload = MsgPack.pack([requestId, responseData]);
        this._sendWithContext(responsePayload, Packet.RESPONSE);
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
        this.destination.rns.sendData(raw, this.attachedInterface);
        return packet;
    }

    /**
     * Send packet to tell other side of the Link we are closing it.
     */
    close() {

        // do nothing if link already closed
        if(this.status === Link.CLOSED){
            return;
        }

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.LINKCLOSE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = this.hash;

        // pack packet
        const raw = packet.pack();

        // send packet to attached interface
        this.destination.rns.sendData(raw, this.attachedInterface);

        // mark link as closed
        this.status = Link.CLOSED;
        this.closeReason = this.initiator ? Link.INITIATOR_CLOSED : Link.DESTINATION_CLOSED;
        this._clearEstablishmentWatchdog();
        this._clearKeepaliveWatchdog();

        // fire close event
        this.emit("close");

    }

}

export default Link;
