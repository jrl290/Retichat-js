import Constants from "../constants.js";
import Cryptography from "../cryptography.js";
import MsgPack from "../msgpack.js";

import { GROUP_FIELDS } from "./lxmf.js";

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
    }

    /**
     * The LXMF message hash: SHA-256 over destination hash, source hash and
     * the msgpack payload as it arrived. Every receive path (the router's
     * packet and link paths, the propagated fetch) computes it here, so the
     * same message reaching this client two ways carries one hash and the
     * duplicate check sees it.
     */
    static hashOf(destinationHash, sourceHash, packedPayload) {
        return Cryptography.fullHash(Buffer.concat([
            Buffer.from(destinationHash),
            Buffer.from(sourceHash),
            Buffer.from(packedPayload),
        ]));
    }

    /**
     * Parse an LXMessage from the provided data.
     * @param data
     * @returns {null|LXMessage}
     */
    static fromBytes(data, destinationHash = null) {
        try {

            // no data provided, unable to parse
            if(data == null || data.length === 0){
                return null;
            }

            // parse data
            const source = data.slice(0, 16);
            const signature = data.slice(16, 16 + 64);
            const packedPayload = data.slice(16 + 64);

            // todo validate signature

            // unpack msgpack payload
            const unpacked = MsgPack.unpack(packedPayload);
            const timestamp = unpacked[0];
            const title = unpacked[1].toString();
            const content = unpacked[2].toString();
            const fields = unpacked[3];

            // create and return lxmf message
            const lxmfMessage = new LXMessage();
            lxmfMessage.destinationHash = destinationHash;
            lxmfMessage.sourceHash = source;
            if (destinationHash) {
                lxmfMessage.hash = LXMessage.hashOf(destinationHash, source, packedPayload);
            }
            lxmfMessage.timestamp = timestamp;
            lxmfMessage.title = title;
            lxmfMessage.content = content;
            lxmfMessage.fields = fields;
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
