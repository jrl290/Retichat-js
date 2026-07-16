import { ed25519, x25519 } from "@noble/curves/ed25519";
import EventEmitter from "./utils/events.js";

import Destination from "./destination.js";
import Cryptography from "./cryptography.js";
import Packet from "./packet.js";
import Transport from "./transport.js";
import Fernet from "./fernet.js";
import Identity from "./identity.js";
import MsgPack from "./msgpack.js";

/**
 * Events emitted by a Link
 * - established: When the link has been established.
 * - packet: When a Packet has been received over the Link.
 * - close: When the Link has been closed.
 */
class Link extends EventEmitter {

    static KEYSIZE = 32;
    static ECPUBSIZE = 32 + 32;

    static PENDING = 0x00;
    static HANDSHAKE = 0x01;
    static ACTIVE = 0x02;
    // static STALE = 0x03;
    static CLOSED = 0x04;

    // static TIMEOUT = 0x01;
    static INITIATOR_CLOSED = 0x02;
    static DESTINATION_CLOSED = 0x03;

    constructor() {
        super();
    }

    establish(destination) {

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

            // todo start watchdog

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
        // todo this.startWatchdog();

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

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = data;

        // pack packet
        const raw = packet.pack();

        // send packet to attached interface
        this.destination.rns.sendData(raw, this.attachedInterface);

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

            // fire close event
            this.emit("close");

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
        this.destination.rns.activateLink(this);

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

        // fire close event
        this.emit("close");

    }

}

export default Link;
