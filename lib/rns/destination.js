import EventEmitter from "./utils/events.js";
import Constants from "./constants.js";
import Cryptography from "./cryptography.js";
import Packet from "./packet.js";
import Transport from "./transport.js";
import Identity from "./identity.js";
import Link from "./link.js";
import MsgPack from "./msgpack.js";

/**
 * Events emitted by a Destination
 * - link_request: When a request to establish a Link has been received.
 * - packet: When a Packet has been received over the Link.
 */
class Destination extends EventEmitter {

    // constants
    static SINGLE = 0x00;
    static GROUP = 0x01;
    static PLAIN = 0x02;
    static LINK = 0x03;
    static DESTINATION_TYPES = [this.SINGLE, this.GROUP, this.PLAIN, this.LINK];

    // directions
    static IN = 0x11;
    static OUT = 0x12;
    static DIRECTIONS = [this.IN, this.OUT];

    // How many ratchet keys a destination with ratchets keeps (RNS
    // Destination.RATCHET_COUNT), and the least time between two rotations,
    // in seconds (RNS Destination.RATCHET_INTERVAL).
    static RATCHET_COUNT = 512;
    static RATCHET_INTERVAL = 30 * 60;

    // How many of the older ratchets decryptSoon tries in one task before
    // the page runs again: about 16 to 30 ms of key exchanges.
    static RATCHETS_PER_TASK = 16;

    constructor(reticulum, identity, direction, type, appName, ...aspects) {

        super();

        this.rns = reticulum;
        this.identity = identity;
        this.direction = direction;
        this.type = type;
        this.appName = appName;
        this.aspects = aspects;

        this.name = Destination.expandName(identity, appName, ...aspects);
        const nameWithoutIdentity = Destination.expandName(null, appName, ...aspects);

        // generate the destination address hash
        this.hash = Destination.hash(this.identity, this.appName, ...aspects);
        this.nameHash = Cryptography.fullHash(nameWithoutIdentity).slice(0, Identity.NAME_HASH_LENGTH_IN_BYTES);

        // Ratchets (RNS Destination): this destination's ratchet private
        // keys, newest first, once enableRatchets() loaded them; null while
        // it has none. `ratchetStore` keeps them ({load(), save(blob)}), and
        // `ratchetsBlob` is the stored blob they were loaded from or last
        // saved as. `latestRatchetId` is the id of the ratchet the last
        // encrypt used, or that opened the last decrypt (null: the identity
        // key).
        this.ratchets = null;
        this.ratchetStore = null;
        this.ratchetsBlob = null;
        this.ratchetInterval = Destination.RATCHET_INTERVAL;
        this.retainedRatchets = Destination.RATCHET_COUNT;
        this.latestRatchetTime = null;
        this.latestRatchetId = null;
        this.ratchetsEnforced = false;

    }

    static expandName(identity, appName, ...aspects) {

        // Check input values and build name string
        if(appName.includes(".")){
            throw new Error("Dots can't be used in app names");
        }

        let name = appName;
        for(const aspect of aspects){
            if(aspect.includes(".")){
                throw new Error("Dots can't be used in aspects");
            }
            name += "." + aspect;
        }

        if(identity != null){
            name += "." + identity.hash.toString("hex");
        }

        return name;

    }

    static hash(identity, appName, ...aspects) {

        const fullName = Destination.expandName(null, appName, ...aspects);
        const nameHash = Cryptography.fullHash(fullName).slice(0, Identity.NAME_HASH_LENGTH_IN_BYTES);

        let addrHashMaterial = nameHash;
        if(identity != null){
            addrHashMaterial = Buffer.concat([addrHashMaterial, identity.hash]);
        }

        return Cryptography.fullHash(addrHashMaterial).slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);

    }

    static hashFromNameAndIdentity(fullName, identity) {
        const [ appName, ...aspects ] = fullName.split(".");
        return Destination.hash(identity, appName, ...aspects);
    }

    /**
     * A ratchet store that keeps the blob in memory only, for the tests:
     * nothing enables ratchets without a store (LXMRouter).
     * @returns {{load(): (Buffer|null), save(blob: Buffer): boolean}}
     */
    static memoryRatchetStore() {
        let blob = null;
        return {
            load: () => blob,
            save: (next) => { blob = Buffer.from(next); return true; },
        };
    }

    /**
     * The stored form of `ratchets`, byte for byte RNS 1.5.2's ratchet file
     * (Destination._persist_ratchets): msgpack({"signature": sign(packed),
     * "ratchets": packed}), packed = msgpack([32-byte private keys]),
     * newest first, signed by `identity`.
     * @returns {Buffer}
     */
    static packRatchets(identity, ratchets) {
        const packed = Buffer.from(MsgPack.pack(ratchets.map((ratchet) => Buffer.from(ratchet))));
        return Buffer.from(MsgPack.pack(new Map([
            ["signature", identity.sign(packed)],
            ["ratchets", packed],
        ])));
    }

    /**
     * The ratchets in a stored blob (packRatchets), once the signature is
     * checked against `identity` (RNS Destination._reload_ratchets). Throws
     * on a blob that does not parse, a signature that does not validate, or
     * a key that is not 32 bytes.
     * @returns {Buffer[]}
     */
    static unpackRatchets(identity, blob) {
        const persisted = MsgPack.unpack(Buffer.from(blob));
        if(!(persisted instanceof Map) || !persisted.has("signature") || !persisted.has("ratchets")){
            throw new Error("not a ratchet file");
        }
        const signature = persisted.get("signature");
        const packed = persisted.get("ratchets");
        if(!(signature instanceof Uint8Array) || !(packed instanceof Uint8Array)){
            throw new Error("not a ratchet file");
        }
        if(!identity.validate(signature, packed)){
            throw new Error("Invalid ratchet file signature");
        }
        const ratchets = MsgPack.unpack(Buffer.from(packed));
        if(!Array.isArray(ratchets) || ratchets.some((ratchet) => !(ratchet instanceof Uint8Array) || ratchet.length !== Identity.RATCHETSIZE_IN_BYTES)){
            throw new Error("the ratchets are not a list of 32-byte keys");
        }
        return ratchets.map((ratchet) => Buffer.from(ratchet));
    }

    /**
     * Enable ratchets on this destination (RNS Destination.enable_ratchets):
     * its announces then carry the newest ratchet, rotated at most every
     * RATCHET_INTERVAL, and what is encrypted to them is decrypted with
     * them. `store` keeps them ({load() → Buffer|null, save(blob) →
     * boolean}). The time of the last rotation is not stored, so the first
     * announce after a load rotates, as in RNS.
     * @returns {boolean} whether ratchets are enabled
     */
    enableRatchets(store) {
        if(!store){
            throw new Error(`No ratchet store given for ${this.name}`);
        }
        this.latestRatchetTime = 0;
        this.ratchetStore = store;
        this.reloadRatchets();
        return this.ratchets !== null;
    }

    /**
     * Load the stored ratchets (RNS Destination._reload_ratchets). None
     * stored: an empty list, stored at once. A stored blob that does not
     * parse or whose signature is not this identity's is refused, said, and
     * left where it is, never replaced: the ratchets stay as they were (none,
     * on the first load), as RNS refuses such a file.
     * @returns {boolean} whether the stored ratchets were loaded
     */
    reloadRatchets() {
        const destination = this.hash.toString("hex");
        let blob;
        try {
            blob = this.ratchetStore.load();
            if(blob == null){
                console.log(`[RATCHET] No ratchets stored for ${destination.slice(0, 8)}, starting a new list`);
                this.ratchets = [];
                if(!this.persistRatchets()){
                    this.ratchets = null;
                    return false;
                }
                return true;
            }
            this.ratchets = Destination.unpackRatchets(this.identity, blob);
            this.ratchetsBlob = Buffer.from(blob);
            return true;
        } catch(e) {
            console.error(`[RATCHET] The ratchets stored for ${destination.slice(0, 8)} could not be loaded (${e.message}). They are refused and left in storage, not replaced; ${this.ratchets === null ? "this destination has no ratchets until they are removed" : "the ratchets already loaded stay in use"}.`);
            return false;
        }
    }

    /**
     * Store the ratchets (RNS Destination._persist_ratchets).
     * @returns {boolean} whether the store kept them
     */
    persistRatchets() {
        const blob = Destination.packRatchets(this.identity, this.ratchets);
        let kept;
        try {
            kept = this.ratchetStore.save(blob) !== false;
        } catch(e) {
            kept = false;
        }
        if(kept){
            this.ratchetsBlob = blob;
        } else {
            console.error(`[RATCHET] Storage refused the ratchets of ${this.hash.toString("hex").slice(0, 8)}`);
        }
        return kept;
    }

    /**
     * Add a new ratchet when RATCHET_INTERVAL has passed since the last one
     * (RNS Destination.rotate_ratchets), keep the newest RATCHET_COUNT, and
     * store them. When storage refuses them the rotation is undone, so no
     * announce carries a ratchet that is not stored (RNS drops its ratchets
     * and fails the announce instead).
     * @param newRatchet the private key to add, generated when none is given
     *   (a test seam: cross-language vectors fix it)
     * @returns {boolean} false when the rotation was undone
     */
    rotateRatchets(newRatchet = null) {
        if(this.ratchets === null){
            throw new Error(`Cannot rotate ratchet on ${this.name}, ratchets are not enabled`);
        }
        const now = Date.now() / 1000;
        if(now > this.latestRatchetTime + this.ratchetInterval){
            const previous = this.ratchets;
            const previousTime = this.latestRatchetTime;
            this.ratchets = [Buffer.from(newRatchet ?? Identity.generateRatchet()), ...this.ratchets].slice(0, this.retainedRatchets);
            this.latestRatchetTime = now;
            if(!this.persistRatchets()){
                this.ratchets = previous;
                this.latestRatchetTime = previousTime;
                return false;
            }
        }
        return true;
    }

    /**
     * Refuse anything not encrypted to a ratchet (RNS
     * Destination.enforce_ratchets), only once ratchets are enabled.
     * @returns {boolean} whether enforcement is on
     */
    enforceRatchets() {
        if(this.ratchets === null){
            return false;
        }
        this.ratchetsEnforced = true;
        return true;
    }

    /**
     * Set the least time between two rotations, in seconds (RNS
     * Destination.set_ratchet_interval): RATCHET_INTERVAL unless set.
     * @returns {boolean} whether it was set (a whole number above 0)
     */
    setRatchetInterval(interval) {
        if(Number.isInteger(interval) && interval > 0){
            this.ratchetInterval = interval;
            return true;
        }
        return false;
    }

    /**
     * Encrypts data for this Destination (RNS Destination.encrypt): to the
     * ratchet it announced last when one is known (Identity.encryptFor).
     * @param data the data to encrypt
     * @returns {*}
     */
    encrypt(data) {

        // a plain destination does not encrypt its data
        if(this.type === Destination.PLAIN){
            return data;
        }

        // handle single destination type with known identity
        if(this.type === Destination.SINGLE && this.identity != null){
            return this.identity.encryptFor(this.hash, data, this);
        }

        throw new Error("Not Implemented");

    }

    /**
     * Decrypts data for this Destination (RNS Destination.decrypt), with its
     * ratchets when it has any. When they fail and the stored blob is not
     * the one loaded (another page stored newer ratchets), the stored ones
     * are loaded and tried once more, as RNS reloads its ratchet file; when
     * the blob is the same that would only repeat the same keys.
     * @param data the data to decrypt
     * @returns {Buffer|null} null when no key opens it
     */
    decrypt(data) {

        // a plain destination does not encrypt its data
        if(this.type === Destination.PLAIN){
            return data;
        }

        // handle single destination type with known identity
        if(this.type === Destination.SINGLE && this.identity != null){
            if(this.ratchets?.length > 0){
                const decrypted = this.decryptWith(data, this.ratchets);
                if(decrypted !== null){
                    return decrypted;
                }
                if(this.reloadChangedRatchets()){
                    return this.decryptWith(data, this.ratchets);
                }
                return null;
            }
            return this.decryptWith(data, null);
        }

        throw new Error("Not Implemented");

    }

    /**
     * Decrypts as decrypt() does, with the same keys in the same order, but
     * without holding the page while the older ratchets are tried. The
     * newest ratchet and the identity key, which open what peers send in the
     * common cases, are tried at once; only when neither does are the older
     * ratchets tried, RATCHETS_PER_TASK at a time, the page running between
     * two slices. A ciphertext no key opens costs up to 511 more key
     * exchanges, about half a second here, which in one piece would freeze
     * the page (DESIGN_PRINCIPLES §6); RNS runs the same scan on its
     * transport thread. When they all fail, the stored ratchets are reloaded
     * and tried once more as decrypt() does.
     * @returns {Buffer|null|Promise<Buffer|null>} the plaintext, or null when
     *   no key opens it: at once when the newest ratchet or the identity key
     *   decides, else a promise of it
     */
    decryptSoon(data) {
        if(this.type !== Destination.SINGLE || this.identity == null || !(this.ratchets?.length > 0)){
            return this.decrypt(data);
        }
        const decrypted = this.decryptWith(data, this.ratchets.slice(0, 1));
        return decrypted !== null ? decrypted : this.decryptOlder(data, this.ratchets.slice(1), true);
    }

    /**
     * Resolves in a later task, so the page runs in between. A timer would
     * do, but a hidden tab runs timers about once a second (Chrome: once a
     * minute after a few minutes hidden), which would stretch a scan of 511
     * ratchets to half a minute or half an hour; a MessageChannel message
     * is not throttled that way.
     */
    static nextTask() {
        if(typeof MessageChannel !== "function"){
            return new Promise((resolve) => setTimeout(resolve, 0));
        }
        return new Promise((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = () => {
                channel.port1.close();
                resolve();
            };
            channel.port2.postMessage(null);
        });
    }

    /** decryptSoon's older ratchets, a slice per task; then, once, the reloaded ones when the stored ratchets changed. */
    async decryptOlder(data, older, reload) {
        for(let i = 0; i < older.length; i += Destination.RATCHETS_PER_TASK){
            await Destination.nextTask();
            // the identity key was tried already, with the newest ratchet
            const decrypted = this.decryptWith(data, older.slice(i, i + Destination.RATCHETS_PER_TASK), true);
            if(decrypted !== null){
                return decrypted;
            }
        }
        if(reload && this.reloadChangedRatchets()){
            await Destination.nextTask();
            const decrypted = this.decryptWith(data, this.ratchets.slice(0, 1));
            return decrypted !== null ? decrypted : this.decryptOlder(data, this.ratchets.slice(1), false);
        }
        return null;
    }

    /**
     * After the ratchets failed: when the stored blob is not the one they
     * were loaded from or last saved as (another page stored newer ones),
     * load the stored ones, as RNS reloads its ratchet file when a decrypt
     * fails; when it is the same, that would only repeat the same keys.
     * @returns {boolean} whether other ratchets were loaded
     */
    reloadChangedRatchets() {
        let stored = null;
        try {
            stored = this.ratchetStore?.load() ?? null;
        } catch(e) {
            stored = null;
        }
        if(!stored || (this.ratchetsBlob && Buffer.from(stored).equals(this.ratchetsBlob))){
            return false;
        }
        console.log(`[RATCHET] Decryption with ratchets failed on ${this.hash.toString("hex").slice(0, 8)}; the stored ratchets changed, reloading them`);
        return this.reloadRatchets();
    }

    /**
     * Identity.decrypt with these ratchets, null when no key opens it;
     * `ratchetsOnly` leaves out the identity key, as enforcement does.
     */
    decryptWith(data, ratchets, ratchetsOnly = false) {
        try {
            return this.identity.decrypt(data, ratchets, this.ratchetsEnforced || ratchetsOnly, this);
        } catch(e) {
            return null;
        }
    }

    /**
     * Called internally when a Packet is received by this Destination.
     * @param packet
     */
    onPacket(packet) {

        // set destination on packet so prove will have access to it
        packet.destination = this;

        // handle incoming link requests
        if(packet.packetType === Packet.LINKREQUEST){
            this.onIncomingLinkRequest(packet);
            return;
        }

        // decrypt packet data. RNS Destination.receive hands its packet
        // callback only what it could decrypt, so a packet no key opens is
        // dropped here, unproved. One that needs the older ratchets is
        // handled once they were tried (decryptSoon), without holding the
        // packets after it.
        const handle = (plaintext) => {
            // the key that opened it, kept on the packet as RNS
            // Destination.receive keeps packet.ratchet_id: the listeners run
            // in a later task (emit), when another decrypt may have set
            // latestRatchetId since
            packet.ratchetId = this.latestRatchetId;
            if(plaintext === null){
                console.log(`[destination] A packet for ${this.hash.toString("hex").slice(0, 12)} could not be decrypted; dropped`);
                return;
            }

            // handle incoming data
            if(packet.packetType === Packet.DATA){
                this.emit("packet", {
                    packet: packet,
                    data: plaintext,
                });
            }
        };
        const plaintext = this.decryptSoon(packet.data);
        if(plaintext instanceof Promise){
            plaintext.then(handle).catch((e) => console.warn(`[destination] A packet for ${this.hash.toString("hex").slice(0, 12)} failed: ${e.message}`));
            return;
        }
        handle(plaintext);

    }

    /**
     * Called internally when this Destination receives an incoming Link Request.
     * @param packet
     */
    onIncomingLinkRequest(packet) {

        console.log("incoming link request", packet);

        // todo allow destination to enable/disable incoming link requests

        // create link from link request
        const link = new Link();
        if(!link.validateLinkRequest(packet)){
            return;
        }

        // fire link request event
        this.emit("link_request", link);

    }

    /**
     * Send an announce on all interfaces with the provided app data.
     * @param appDataBytes
     */
    announce(appDataBytes = null) {

        const { announceData, contextFlag } = this.buildAnnounceData(appDataBytes);

        // create announce packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.ANNOUNCE;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = contextFlag;
        packet.destinationHash = this.hash;
        packet.destinationType = this.type;
        packet.data = announceData;

        // pack packet
        const raw = packet.pack();

        // send packet to all interfaces
        this.rns.sendData(raw);

    }

    /**
     * Build the signed announce payload without transmitting it.
     *
     * Split out of announce() so a pre-signed announce can be handed to another
     * node to rebroadcast on this destination's behalf. Announces are the only
     * mechanism in Reticulum that distributes a public key, and only the holder
     * of the private key can sign one — so a node that stores messages for an
     * identity it has no key for (RFed distro) can only advertise it by
     * replaying bytes produced here.
     *
     * With ratchets enabled (enableRatchets) the ratchets are rotated when
     * due and the newest one's public key is carried, signed, with the
     * context flag set, and remembered as this destination's own (RNS
     * Destination.announce).
     *
     * @param appDataBytes
     * @param {{randomHash?: Buffer, newRatchet?: Buffer}} seams the 10-byte
     *   random hash, and the private key a due rotation adds: fixed in
     *   cross-language vectors only
     * @returns {{announceData: Buffer, contextFlag: number}}
     */
    buildAnnounceData(appDataBytes = null, { randomHash = null, newRatchet = null } = {}) {

        // Create the announce random hash: 5 random bytes followed by the
        // emission time in seconds as 5 big-endian bytes, matching
        // RNS Destination.announce().
        //
        // The trailing timestamp is NOT decorative. Transport nodes compare it
        // against the newest emission time they have recorded for the
        // destination to decide whether an announce carries fresh routing
        // information. Filling it with random bytes yields values centuries in
        // the future, after which every later announce looks stale and is
        // ignored forever — the destination's path can never be refreshed
        // again anywhere on the network.
        if(randomHash === null){
            const emitted = Math.floor(Date.now() / 1000);
            const emittedBytes = Buffer.alloc(5);
            emittedBytes.writeUIntBE(emitted, 0, 5);

            randomHash = Buffer.concat([
                Cryptography.getRandomHash().slice(0, 5),
                emittedBytes,
            ]);
        }

        let ratchet = Buffer.alloc(0);
        if(this.ratchets != null){
            this.rotateRatchets(newRatchet);
            if(this.ratchets.length > 0){
                ratchet = Identity.ratchetPublicBytes(this.ratchets[0]);
                Identity.rememberRatchet(this.hash, ratchet);
                console.log(`[RATCHET] announce dest=${this.hash.toString("hex").slice(0, 8)} ratchet=${Identity.ratchetId(ratchet).toString("hex")} count=${this.ratchets.length}`);
            }
        }

        // create signed data
        let signedData = Buffer.concat([
            this.hash,
            this.identity.getPublicKey(),
            this.nameHash,
            randomHash,
            ratchet,
        ]);

        // add app data to signed data if provided
        if(appDataBytes !== null){
            signedData = Buffer.concat([
                signedData,
                appDataBytes,
            ]);
        }

        // sign the data
        const signature = this.identity.sign(signedData);

        // create announce data
        let announceData = Buffer.concat([
            this.identity.getPublicKey(),
            this.nameHash,
            randomHash,
            ratchet,
            signature,
        ]);

        // add app data to announce data if provided
        if(appDataBytes !== null){
            announceData = Buffer.concat([
                announceData,
                appDataBytes,
            ]);
        }

        // set context flag if ratchet provided
        let contextFlag = Packet.FLAG_UNSET;
        if(ratchet.length > 0){
            contextFlag = Packet.FLAG_SET;
        }

        return { announceData, contextFlag };

    }

    /**
     * Send a data packet to this Destination.
     * @param data
     * @param viaTransportId
     */
    send(data, viaTransportId = null) {

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = this.type;
        packet.data = data;

        // fixme: remove viaTransportId, and send the packet to Transport class instead, which should find the path for us
        // packet should be sent via a transport node
        if(viaTransportId){
            packet.headerType = Packet.HEADER_2;
            packet.transportType = Transport.TRANSPORT;
            packet.transportId = viaTransportId; // Buffer.from("25ffd99be40b112a3a11294badae6d8f", "hex"); // Windows PC MeshChat
        }

        // pack packet
        const raw = packet.pack();

        // send packet to all interfaces
        this.rns.sendData(raw);

        // Return the packet hash so callers can match proofs back to messages
        return packet.packetHash;

    }

}

export default Destination;
