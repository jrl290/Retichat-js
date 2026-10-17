import { ed25519, x25519 } from "@noble/curves/ed25519";

import Constants from "./constants.js";
import Destination from "./destination.js";
import Cryptography from "./cryptography.js";
import Packet from "./packet.js";
import Transport from "./transport.js";
import Fernet from "./fernet.js";

class Identity {

    // X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
    static KEYSIZE_IN_BITS = 256 * 2;
    static KEYSIZE_IN_BYTES = this.KEYSIZE_IN_BITS / 8;

    // X.25519 ratchet key size in bits.
    static RATCHETSIZE_IN_BITS = 256;
    static RATCHETSIZE_IN_BYTES = this.RATCHETSIZE_IN_BITS / 8;

    // How long a ratchet a destination announced is used, in seconds (RNS
    // Identity.RATCHET_EXPIRY, 30 days). The newest one announced replaces it.
    static RATCHET_EXPIRY = 60 * 60 * 24 * 30;

    // length of identity name hashes
    static NAME_HASH_LENGTH_IN_BITS = 80;
    static NAME_HASH_LENGTH_IN_BYTES = this.NAME_HASH_LENGTH_IN_BITS / 8;

    /**
     * The ratchet each destination announced last, by destination hash (hex):
     * {ratchet: Buffer (32-byte X25519 public key), received: unix seconds}
     * (RNS Identity.known_ratchets). Every destination heard announcing one
     * is held here while the page runs.
     */
    static knownRatchets = new Map();

    /**
     * Where announced ratchets are kept across page loads, installed by
     * app.js (PeerRatchets); null keeps them in memory only, as under the
     * tests. RNS writes every one to disk; the page keeps only some (see
     * PeerRatchets for which and why):
     *   load(destHex) → {ratchet, received} | null
     *   remembered(destHex, entry): a destination announced a new ratchet
     *   encryptedTo(destHex, entry): this page encrypted to that ratchet
     */
    static ratchetStore = null;

    // Non-configurable constants
    // static FERNET_OVERHEAD           = RNS.Cryptography.Fernet.FERNET_OVERHEAD
    // static AES128_BLOCKSIZE          = 16          # In bytes
    // static HASHLENGTH                = 256         # In bits
    static SIGLENGTH_IN_BITS = this.KEYSIZE_IN_BITS;
    static SIGLENGTH_IN_BYTES = this.SIGLENGTH_IN_BITS / 8;

    constructor() {
        this.hash = null;
        this.publicKeyBytes = null;
        this.privateKeyBytes = null;
        this.signaturePublicKeyBytes = null;
        this.signaturePrivateKeyBytes = null;
    }

    /**
     * Load an Identity from the provided Public Key.
     * @param publicKeyBytes
     * @returns {Identity}
     */
    static fromPublicKey(publicKeyBytes) {
        const identity = new Identity();
        identity.loadPublicKey(publicKeyBytes);
        return identity;
    }

    /**
     * Load an Identity from the provided Private Key.
     * @param privateKeyBytes
     * @returns {Identity}
     */
    static fromPrivateKey(privateKeyBytes) {
        const identity = new Identity();
        identity.loadPrivateKey(privateKeyBytes);
        return identity;
    }

    /**
     * Create a new Identity with randomly generated keys.
     * @returns {Identity}
     */
    static create() {

        const identity = new Identity();

        // generate public key and private key
        const privateKeyBytes = x25519.utils.randomPrivateKey();
        const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);
        identity.publicKeyBytes = Buffer.from(publicKeyBytes);
        identity.privateKeyBytes = Buffer.from(privateKeyBytes);

        // generate signature public key and private key
        const signaturePrivateKeyBytes = ed25519.utils.randomPrivateKey();
        const signaturePublicKeyBytes = ed25519.getPublicKey(signaturePrivateKeyBytes);
        identity.signaturePublicKeyBytes = Buffer.from(signaturePublicKeyBytes);
        identity.signaturePrivateKeyBytes = Buffer.from(signaturePrivateKeyBytes);

        // update hashes
        identity.updateHashes();

        return identity;

    }

    /**
     * Called internally to update the Identity hashes.
     */
    updateHashes() {
        this.hash = Cryptography.truncatedHash(this.getPublicKey());
    }

    /**
     * Load a public key into the instance
     * @param {Buffer} publicKeyBytes - The public key as bytes.
     * @returns {boolean} True if the key was loaded, otherwise False.
     */
    loadPublicKey(publicKeyBytes) {
        try {
            // public key bytes contains 2 keys
            const data = Array.from(publicKeyBytes);
            this.publicKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));
            this.signaturePublicKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));
            this.updateHashes();
            return true;
        } catch(e) {
            console.log("Error while loading public key, the contained exception was", e);
            return false;
        }
    }

    /**
     * Load a private key into the instance
     * @param {Buffer} privateKeyBytes - The public key as bytes.
     * @returns {boolean} True if the key was loaded, otherwise False.
     */
    loadPrivateKey(privateKeyBytes) {
        try {

            // private key bytes contains 2 keys
            const data = Array.from(privateKeyBytes);
            this.privateKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));
            this.signaturePrivateKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));

            // load public keys
            this.publicKeyBytes = Buffer.from(x25519.getPublicKey(this.privateKeyBytes));
            this.signaturePublicKeyBytes = Buffer.from(ed25519.getPublicKey(this.signaturePrivateKeyBytes));

            // update hashes
            this.updateHashes();

            return true;

        } catch(e) {
            console.log("Error while loading private key, the contained exception was", e);
            return false;
        }
    }

    /**
     * Returns the Public Key for this Identity.
     * @returns {Buffer}
     */
    getPublicKey() {
        return Buffer.concat([
            this.publicKeyBytes,
            this.signaturePublicKeyBytes,
        ]);
    }

    /**
     * Returns the Private Key for this Identity.
     * @returns {Buffer}
     */
    getPrivateKey() {
        return Buffer.concat([
            this.privateKeyBytes,
            this.signaturePrivateKeyBytes,
        ]);
    }

    /**
     * Validates the signature of a signed message.
     * @param signature the signature to validate
     * @param data the data this signature is for
     * @returns {boolean}
     */
    validate(signature, data) {
        return ed25519.verify(signature, data, this.signaturePublicKeyBytes);
    }

    /**
     * Signs the provided data with this Identity's signature private key.
     * @param data
     * @returns {Buffer}
     */
    sign(data) {
        return Buffer.from(ed25519.sign(data, this.signaturePrivateKeyBytes));
    }

    /**
     * The id of a ratchet: the first 10 bytes of the SHA-256 of its public
     * key (RNS Identity._get_ratchet_id).
     * @param ratchetPublicKeyBytes
     * @returns {Buffer}
     */
    static ratchetId(ratchetPublicKeyBytes) {
        return Cryptography.fullHash(Buffer.from(ratchetPublicKeyBytes)).slice(0, Identity.NAME_HASH_LENGTH_IN_BYTES);
    }

    /** The X25519 public key of a ratchet private key (RNS Identity._ratchet_public_bytes). */
    static ratchetPublicBytes(ratchetPrivateKeyBytes) {
        return Buffer.from(x25519.getPublicKey(ratchetPrivateKeyBytes));
    }

    /** A new ratchet private key (RNS Identity._generate_ratchet). */
    static generateRatchet() {
        return Buffer.from(x25519.utils.randomPrivateKey());
    }

    /**
     * Remember the ratchet `destinationHash` announced (RNS
     * Identity._remember_ratchet), called once the whole announce validated
     * (Reticulum.onPacketReceived) and for a destination's own announce
     * (Destination.buildAnnounceData). A ratchet that differs from the one
     * known replaces it, with the time it was received; like RNS, nothing
     * checks that it is newer. The store is told (Identity.ratchetStore),
     * and keeps it if it keeps that destination.
     */
    static rememberRatchet(destinationHash, ratchet) {
        const key = Buffer.from(destinationHash).toString("hex");
        const known = Identity.knownRatchets.get(key);
        if(known && known.ratchet.equals(Buffer.from(ratchet))){
            return;
        }
        const entry = { ratchet: Buffer.from(ratchet), received: Date.now() / 1000 };
        Identity.knownRatchets.set(key, entry);
        try {
            Identity.ratchetStore?.remembered(key, entry);
        } catch(e) {
            console.warn(`[RATCHET] could not keep the ratchet of ${key.slice(0, 8)}: ${e.message}`);
        }
    }

    /**
     * The ratchet to encrypt to for `destinationHash`, or null (RNS
     * Identity.get_ratchet): the one remembered while the page runs, else
     * the one the store kept, if it was received less than RATCHET_EXPIRY
     * ago and is 32 bytes.
     * @returns {Buffer|null}
     */
    static getRatchet(destinationHash) {
        const key = Buffer.from(destinationHash).toString("hex");
        if(!Identity.knownRatchets.has(key)){
            let stored = null;
            try {
                stored = Identity.ratchetStore?.load(key) ?? null;
            } catch(e) {
                console.warn(`[RATCHET] could not load the ratchet of ${key.slice(0, 8)}: ${e.message}`);
            }
            if(stored && Date.now() / 1000 < stored.received + Identity.RATCHET_EXPIRY
                && stored.ratchet?.length === Identity.RATCHETSIZE_IN_BYTES){
                Identity.knownRatchets.set(key, { ratchet: Buffer.from(stored.ratchet), received: stored.received });
            }
        }
        return Identity.knownRatchets.get(key)?.ratchet ?? null;
    }

    /**
     * Encrypts `data` for `destinationHash`, a destination of this identity:
     * to the ratchet that destination announced last when one is known,
     * else to this identity's key (RNS Destination.encrypt). Every LXMF path
     * encrypts this way: the opportunistic packet (Destination.encrypt), the
     * propagated and the paper message (LXMessage.py pack: dest.encrypt).
     * When a ratchet is used its id is set on `ratchetIdReceiver`
     * (latestRatchetId), and the store keeps it (encryptedTo).
     * @returns {Buffer}
     */
    encryptFor(destinationHash, data, ratchetIdReceiver = null) {
        const key = Buffer.from(destinationHash).toString("hex");
        const ratchet = Identity.getRatchet(destinationHash);
        let used = "identity";
        if(ratchet){
            const ratchetId = Identity.ratchetId(ratchet);
            if(ratchetIdReceiver){
                ratchetIdReceiver.latestRatchetId = ratchetId;
            }
            used = ratchetId.toString("hex");
            try {
                Identity.ratchetStore?.encryptedTo(key, Identity.knownRatchets.get(key));
            } catch(e) {
                console.warn(`[RATCHET] could not keep the ratchet of ${key.slice(0, 8)}: ${e.message}`);
            }
        }
        console.log(`[RATCHET] encrypt dest=${key.slice(0, 8)} key=${used}`);
        return this.encrypt(data, ratchet);
    }

    /**
     * Encrypts information for the identity (RNS Identity.encrypt).
     * @param data the data to encrypt
     * @param ratchet the X25519 public key to encrypt to instead of this
     *   identity's: the ratchet its destination announced (encryptFor)
     * @param {{ephemeralPrivateKey?: Buffer, iv?: Buffer}} seams fixed in
     *   cross-language vectors only; random otherwise
     * @returns {Buffer}
     */
    encrypt(data, ratchet = null, { ephemeralPrivateKey = null, iv = null } = {}) {

        // generate an ephemeral private key
        const ephemeralPrivateKeyBytes = Buffer.from(ephemeralPrivateKey ?? x25519.utils.randomPrivateKey());
        const ephemeralPublicKeyBytes = Buffer.from(x25519.getPublicKey(ephemeralPrivateKeyBytes));

        const targetPublicKey = ratchet != null ? Buffer.from(ratchet) : this.publicKeyBytes;

        // compute shared key
        const sharedKey = Buffer.from(x25519.getSharedSecret(ephemeralPrivateKeyBytes, targetPublicKey));

        // create derived key
        const derivedKey = Cryptography.hkdf(64, sharedKey, this.hash);

        // encrypt plaintext using fernet
        const fernet = new Fernet(derivedKey);
        const cipherText = fernet.encrypt(data, iv);

        // create token
        const token = Buffer.concat([
            ephemeralPublicKeyBytes,
            cipherText,
        ]);

        return token;

    }

    /**
     * Decrypts information for the identity (RNS Identity.decrypt).
     *
     * With `ratchets` (a destination's ratchet private keys, newest first)
     * the newest is tried first, then this identity's key (skipped when
     * `enforceRatchets`), then the older ratchets. RNS tries every ratchet
     * before the identity key; only the right key passes the token's HMAC,
     * so both accept exactly the same ciphertexts, and this order keeps the
     * common cases (the newest ratchet, or a sender that knew no ratchet) at
     * one or two key exchanges instead of up to 513.
     *
     * `ratchetIdReceiver.latestRatchetId` is set to the id of the ratchet
     * that opened it, or null when it was the identity key (or nothing).
     * Throws when no key opens it (RNS returns None; every caller here
     * catches).
     * @param data the data to decrypt
     * @returns {Buffer}
     */
    decrypt(data, ratchets = null, enforceRatchets = false, ratchetIdReceiver = null) {

        if(data.length <= Identity.KEYSIZE_IN_BYTES / 2){
            throw new Error(`Cannot decrypt a token of only ${data.length} bytes`);
        }

        // parse peer public key and cipher text
        const peerPublicKeyBytes = data.slice(0, Identity.KEYSIZE_IN_BYTES / 2);
        const cipherText = data.slice(Identity.KEYSIZE_IN_BYTES / 2);

        // the keys to try, in order: null stands for this identity's key
        const keys = [];
        if(ratchets?.length > 0){
            keys.push(ratchets[0]);
        }
        if(!enforceRatchets){
            keys.push(null);
        }
        if(ratchets?.length > 1){
            keys.push(...ratchets.slice(1));
        }

        let failure = new Error(`Decryption with ratchet enforcement by ${this.hash?.toString("hex")} failed`);
        for(const ratchet of keys){
            try {

                // compute shared key
                const sharedKey = Buffer.from(x25519.getSharedSecret(ratchet ?? this.privateKeyBytes, peerPublicKeyBytes));

                // create derived key
                const derivedKey = Cryptography.hkdf(64, sharedKey, this.hash);

                // decrypt ciphertext using fernet
                const fernet = new Fernet(derivedKey);
                const plaintext = fernet.decrypt(cipherText);

                if(ratchetIdReceiver){
                    ratchetIdReceiver.latestRatchetId = ratchet ? Identity.ratchetId(Identity.ratchetPublicBytes(ratchet)) : null;
                }
                return plaintext;

            } catch(e) {
                failure = e;
            }
        }

        if(ratchetIdReceiver){
            ratchetIdReceiver.latestRatchetId = null;
        }
        throw failure;

    }

    /**
     * Prove that the provided Packet was received.
     * @param packetToProve
     */
    prove(packetToProve) {

        // sign the hash of the packet to prove
        const signature = this.sign(packetToProve.packetHash);

        // determine if we should use implicit or explicit proof
        let proofData;
        if(packetToProve.destination.rns.shouldUseImplicitProof){
            proofData = signature;
        } else {
            proofData = Buffer.concat([
                packetToProve.packetHash,
                signature,
            ]);
        }

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.PROOF;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = null;
        packet.destinationHash = packetToProve.packetHash.slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);
        packet.destinationType = Destination.SINGLE;
        packet.data = proofData;

        // pack packet
        const raw = packet.pack();

        // send packet to attached interface
        console.log(`[identity] Proof dispatched for received packet hash=${packetToProve.packetHash.toString('hex').slice(0,12)}...`);
        packetToProve.destination.rns.sendData(raw, packetToProve.attachedInterface);

    }

}

export default Identity;
