import Cryptography from "../cryptography.js";
import MsgPack from "../msgpack.js";

import { GROUP_FIELDS } from "./lxmf.js?v=20260726-keys2";

class LXMessage {

    constructor() {
        this.sourceHash = null;
        this.destinationHash = null;
        this.timestamp = null;
        this.title = null;
        this.content = null;
        this.fields = null;
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
                lxmfMessage.hash = Cryptography.fullHash(Buffer.concat([
                    Buffer.from(destinationHash),
                    source,
                    packedPayload,
                ]));
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

        // get current timestamp in seconds as float
        const timestampInSecondsAsFloat = Date.now() / 1000;

        // convert title and content to bytes
        const titleBytes = Buffer.from(this.title);
        const contentBytes = Buffer.from(this.content);

        // msgpack the payload
        const packedPayload = MsgPack.pack([
            timestampInSecondsAsFloat,
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

        // hash the data
        const hash = Cryptography.fullHash(hashedPart);

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
