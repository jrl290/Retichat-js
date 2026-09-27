import Constants from "../constants.js";
import Cryptography from "../cryptography.js";
import MsgPack from "../msgpack.js";

import { GROUP_FIELDS } from "./lxmf.js";
import { decodePayload as decodeDisplayNamePayload } from "../../display_name.js";
import { listPrefix } from "../msgpack_raw.js";

class LXMessage {

    // Delivery methods and representations. Reference: LXMF/LXMessage.py.
    static OPPORTUNISTIC = 0x01;
    static DIRECT = 0x02;
    static PACKET = 0x01;
    static RESOURCE = 0x02;

    // Sizes of the packed message. Reference: LXMF/LXMessage.py 50-96.
    static DESTINATION_LENGTH = 16;
    static SIGNATURE_LENGTH = 64;
    static TIMESTAMP_SIZE = 8;
    static STRUCT_OVERHEAD = 8;
    static LXMF_OVERHEAD = 2 * this.DESTINATION_LENGTH + this.SIGNATURE_LENGTH + this.TIMESTAMP_SIZE + this.STRUCT_OVERHEAD;

    // A single packet to the destination carries at most 295 bytes of content
    // (the destination hash travels in the packet header, not the payload).
    static ENCRYPTED_PACKET_MDU = Constants.PACKET_ENCRYPTED_MDU + this.TIMESTAMP_SIZE;
    static ENCRYPTED_PACKET_MAX_CONTENT = this.ENCRYPTED_PACKET_MDU - this.LXMF_OVERHEAD + this.DESTINATION_LENGTH;

    // A single packet on a link carries at most 319 bytes of content; anything
    // larger travels as a Resource on the link.
    static LINK_PACKET_MDU = Constants.LINK_MDU;
    static LINK_PACKET_MAX_CONTENT = this.LINK_PACKET_MDU - this.LXMF_OVERHEAD;

    /**
     * Content size of a packed message, as the reference measures it for the
     * delivery decision: the msgpack payload without its timestamp and
     * structure overhead (LXMessage.py:388).
     * @param {Buffer} packed the non-opportunistic packing (destination hash first)
     */
    static contentSize(packed) {
        return packed.length - LXMessage.LXMF_OVERHEAD;
    }

    /**
     * Choose how a packed message reaches its destination, following
     * LXMessage.pack() (LXMessage.py:395-424) with no desired method: a
     * single packet to the destination when the content fits, otherwise a
     * link, and on the link a single packet when the content fits or a
     * Resource when it does not.
     * @param {Buffer} packed the non-opportunistic packing (destination hash first)
     * @returns {{method: number, representation: number}}
     */
    static deliveryPlan(packed) {
        const contentSize = LXMessage.contentSize(packed);
        if (contentSize <= LXMessage.ENCRYPTED_PACKET_MAX_CONTENT) {
            return { method: LXMessage.OPPORTUNISTIC, representation: LXMessage.PACKET };
        }
        if (contentSize <= LXMessage.LINK_PACKET_MAX_CONTENT) {
            return { method: LXMessage.DIRECT, representation: LXMessage.PACKET };
        }
        return { method: LXMessage.DIRECT, representation: LXMessage.RESOURCE };
    }

    constructor() {
        this.sourceHash = null;
        this.destinationHash = null;
        this.timestamp = null;
        this.title = null;
        this.content = null;
        this.fields = null;
        this.signatureValidated = false;
        this.unverifiedReason = null;
        this.displayName = null; // a received message's 0xD1 state (fromBytes)
    }

    // Why a message's signature is not validated. Reference: LXMessage.py
    // SOURCE_UNKNOWN / SIGNATURE_INVALID, the same values LXMF-rust reports
    // to the native apps as unverified_reason 1 and 2.
    static SOURCE_UNKNOWN = 0x01;
    static SIGNATURE_INVALID = 0x02;

    /**
     * The identity store, as RNS.Identity.recall is for the reference: an
     * lxmf.delivery source hash (Buffer) to the Identity that owns it, or
     * null when its key is not known. app.js installs the real one; until
     * then every source is unknown.
     */
    static recall = () => null;

    /**
     * The payload as it was signed. A fifth element (a stamp) is appended
     * after signing, so the reference drops it and re-packs the first four
     * before hashing (LXMessage.py unpack_from_bytes). Here the first four
     * are copied from the received bytes rather than decoded and re-packed
     * with msgpackr, which writes an integral float (a whole-second
     * timestamp) as an int and a uint64 as an int64 where umsgpack and rmpv
     * keep them: those stamped messages would fail as "invalid".
     */
    static signedPayload(packedPayload) {
        try {
            const prefix = listPrefix(packedPayload, 4);
            if (prefix) return Buffer.from(prefix);
        } catch (e) { /* not a readable list: hashed as it came */ }
        return Buffer.from(packedPayload);
    }

    /**
     * The LXMF message hash: SHA-256 over destination hash, source hash and
     * the msgpack payload as it was signed. Every receive path (the router's
     * packet and link paths, the propagated fetch) computes it here, so the
     * same message reaching this client two ways carries one hash and the
     * duplicate check sees it.
     */
    static hashOf(destinationHash, sourceHash, packedPayload) {
        return Cryptography.fullHash(Buffer.concat([
            Buffer.from(destinationHash),
            Buffer.from(sourceHash),
            LXMessage.signedPayload(packedPayload),
        ]));
    }

    /**
     * Validate a received message's signature exactly as the reference does
     * (LXMessage.py unpack_from_bytes):
     *   hashed_part = destination_hash + source_hash + packed_payload
     *   hash        = SHA-256(hashed_part)
     *   signed_part = hashed_part + hash
     * verified with the source's Ed25519 key from the identity store.
     * Returns { validated, unverifiedReason, hash }: unverifiedReason is
     * null when validated, SOURCE_UNKNOWN when the store has no key for the
     * source, SIGNATURE_INVALID when the key does not verify it (or the
     * check could not run, which never lets a name through).
     */
    static verify(destinationHash, sourceHash, signature, packedPayload, recall = LXMessage.recall) {
        const hashedPart = Buffer.concat([
            Buffer.from(destinationHash),
            Buffer.from(sourceHash),
            LXMessage.signedPayload(packedPayload),
        ]);
        const hash = Cryptography.fullHash(hashedPart);
        let identity = null;
        try {
            identity = recall(Buffer.from(sourceHash));
        } catch (e) {
            return { validated: false, unverifiedReason: LXMessage.SIGNATURE_INVALID, hash };
        }
        if (!identity) return { validated: false, unverifiedReason: LXMessage.SOURCE_UNKNOWN, hash };
        let valid = false;
        try {
            valid = identity.validate(Buffer.from(signature), Buffer.concat([hashedPart, hash])) === true;
        } catch (e) {
            valid = false;
        }
        return valid
            ? { validated: true, unverifiedReason: null, hash }
            : { validated: false, unverifiedReason: LXMessage.SIGNATURE_INVALID, hash };
    }

    /** "validated" | "unknown" | "invalid" — the three outcomes names follow
     *  (DISPLAY_NAMES.md §5.2). */
    get signatureState() {
        if (this.signatureValidated === true) return "validated";
        return this.unverifiedReason === LXMessage.SOURCE_UNKNOWN ? "unknown" : "invalid";
    }

    /**
     * Parse an LXMessage from source hash | signature | packed payload, and
     * validate its signature against the identity store. Without the
     * destination hash nothing can be validated and the message reports
     * SIGNATURE_INVALID.
     * @param data
     * @param destinationHash
     * @param recall the identity store (defaults to LXMessage.recall)
     * @returns {null|LXMessage}
     */
    static fromBytes(data, destinationHash = null, recall = LXMessage.recall) {
        try {

            // no data provided, unable to parse
            if(data == null || data.length === 0){
                return null;
            }

            // parse data
            const source = data.slice(0, 16);
            const signature = data.slice(16, 16 + 64);
            const packedPayload = data.slice(16 + 64);

            // unpack msgpack payload
            const unpacked = MsgPack.unpack(packedPayload);
            const timestamp = unpacked[0];
            const title = Buffer.from(unpacked[1] ?? []).toString();
            const content = Buffer.from(unpacked[2] ?? []).toString();
            const fields = unpacked[3];

            // create and return lxmf message
            const lxmfMessage = new LXMessage();
            lxmfMessage.destinationHash = destinationHash;
            lxmfMessage.sourceHash = source;
            lxmfMessage.signatureValidated = false;
            lxmfMessage.unverifiedReason = LXMessage.SIGNATURE_INVALID;
            if (destinationHash) {
                const check = LXMessage.verify(destinationHash, source, signature, packedPayload, recall);
                lxmfMessage.hash = check.hash;
                lxmfMessage.signatureValidated = check.validated;
                lxmfMessage.unverifiedReason = check.unverifiedReason;
            }
            lxmfMessage.timestamp = timestamp;
            lxmfMessage.title = title;
            lxmfMessage.content = content;
            lxmfMessage.fields = fields;
            // 0xD1 read from the payload bytes, not from `fields`: msgpackr
            // has already rewritten an invalid-UTF-8 str there (§3 rule 1).
            lxmfMessage.displayName = decodeDisplayNamePayload(packedPayload);
            return lxmfMessage;

        } catch(e) {
            console.log("failed to parse lxmf message from bytes", e);
            return null;
        }
    }

    /**
     * Packs the LXMessage to bytes for sending to a Destination.
     * @param identity the identity sending this message, which is used to sign it
     * @param opportunistic set to true if this message is being sent opportunistically
     * @returns {Buffer}
     */
    pack(identity, opportunistic = true) {

        // ensure fields is a Map, otherwise keys get converted from int to string...
        if(!(this.fields instanceof Map)){
            throw new Error("fields must be a Map instance");
        }

        // The timestamp, in seconds as a float, is stamped once: a message
        // that has one keeps it, as LXMessage.py pack() keeps it. The same
        // timestamp, title, content and fields from the same source to the
        // same destination is the same message with the same hash, which is
        // how a propagated copy stays the message it copies and the
        // recipient keeps one of the two. Until 2026-09-24 every pack()
        // stamped Date.now(), so a copy was always a new message.
        if (typeof this.timestamp !== "number") {
            this.timestamp = Date.now() / 1000;
        }

        // convert title and content to bytes
        const titleBytes = Buffer.from(this.title);
        const contentBytes = Buffer.from(this.content);

        // msgpack the payload
        const packedPayload = MsgPack.pack([
            this.timestamp,
            titleBytes,
            contentBytes,
            this.fields,
        ]);

        // hashed part
        const hashedPart = Buffer.concat([
            this.destinationHash,
            this.sourceHash,
            packedPayload,
        ]);

        // hash the data; kept as the message hash, as LXMessage.py pack() keeps it
        const hash = Cryptography.fullHash(hashedPart);
        this.hash = hash;

        // signed part
        const signedPart = Buffer.concat([
            hashedPart,
            hash,
        ]);

        // sign the data
        const signature = identity.sign(signedPart);

        // packed
        return Buffer.concat([
            opportunistic ? Buffer.alloc(0) : this.destinationHash, // opportunistic lxmf messages dont send destination in packed data
            this.sourceHash,
            signature,
            packedPayload,
        ]);

    }

    /**
     * Packs the LXMessage to an encrypted lxm:// uri that can be ingested by the destination.
     * The lxm uri could be encoded as a QR code and scanned by Sideband.
     * @param senderIdentity the identity sending this message, which is used to sign it
     * @param destinationIdentity the identity this message is being sent to, which is used to encrypt it
     * @returns {string} an lxm:// uri with the encrypted message data in url safe base64
     */
    toLxmUri(senderIdentity, destinationIdentity) {

        // pack this lxmf message
        const packed = this.pack(senderIdentity, false);
        const destinationHash = packed.slice(0, 16);
        const packedWithoutDestinationHash = packed.slice(16);

        // encrypt packed data: sourceHash + signature + packedPayload
        const encryptedData = destinationIdentity.encrypt(packedWithoutDestinationHash);

        // prepare data that will be base64 encoded
        const data = Buffer.concat([
            destinationHash,
            encryptedData,
        ]);

        // convert raw data buffer to url safe base64
        const base64EncodedBuffer = data.toString("base64")
            .replace(/\+/g, '-') // convert '+' to '-'
            .replace(/\//g, '_') // convert '/' to '_'
            .replace(/=+$/, ''); // remove trailing '='

        // format as lxm:// uri
        return `lxm://${base64EncodedBuffer}`;

    }

}

/**
 * Extract group metadata from LXMF message fields.
 * Returns null if not a group message, or { groupId, groupName, groupAction,
 * groupSender, members, relayFor, relaySeen, relayDone }.
 */
LXMessage.extractGroupFields = function(fields) {
    if (!fields || !(fields instanceof Map)) return null;
    const groupId = fields.get(GROUP_FIELDS.GROUP_ID);
    if (groupId == null) return null;

    const toString = (v) => {
        if (v == null) return null;
        if (v instanceof Uint8Array) return new TextDecoder().decode(v);
        return String(v);
    };
    const toBool = (v) => {
        if (v == null) return null;
        if (typeof v === 'boolean') return v;
        if (typeof v === 'number') return v !== 0;
        const s = String(v).toLowerCase();
        return s === 'true' || s === '1';
    };
    const toMembers = (v) => {
        if (!v) return [];
        const s = toString(v);
        if (!s) return [];
        return s.split(',').map(h => h.trim()).filter(h => h.length === 32);
    };
    const toMemberKeys = (v) => {
        const s = toString(v);
        if (!s) return new Map();
        const entries = s.split(',').map(entry => entry.trim()).filter(Boolean);
        const keys = new Map();
        for (const entry of entries) {
            const separator = entry.indexOf(':');
            if (separator < 0) continue;
            const hash = entry.slice(0, separator).toLowerCase();
            const publicKey = entry.slice(separator + 1);
            if (/^[0-9a-f]{32}$/.test(hash) && /^[A-Za-z0-9+/]{86}==$/.test(publicKey)) {
                keys.set(hash, publicKey);
            }
        }
        return keys;
    };

    return {
        groupId: toString(groupId),
        groupName: toString(fields.get(GROUP_FIELDS.GROUP_NAME)),
        groupAction: toString(fields.get(GROUP_FIELDS.GROUP_ACTION)),
        groupSender: toString(fields.get(GROUP_FIELDS.GROUP_SENDER)),
        members: toMembers(fields.get(GROUP_FIELDS.GROUP_MEMBERS)),
        relayFor: toString(fields.get(GROUP_FIELDS.GROUP_RELAY_FOR)),
        relaySeen: toMembers(fields.get(GROUP_FIELDS.GROUP_RELAY_SEEN)),
        relayDone: toBool(fields.get(GROUP_FIELDS.GROUP_RELAY_DONE)),
        memberKeys: toMemberKeys(fields.get(GROUP_FIELDS.GROUP_MEMBER_KEYS)),
    };
};

export default LXMessage;
