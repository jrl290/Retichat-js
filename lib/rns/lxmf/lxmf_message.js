import Constants from "../constants.js";
import Cryptography from "../cryptography.js";
import MsgPack from "../msgpack.js";

import {
    readGroupEntry, readEntry, topLevel, readStatuses, keyIs, groupEntry, FIELD_RETICHAT, GROUP_ENTRIES,
    RF_GROUP_ID, RF_GROUP_MEMBERS, RF_GROUP_NAME, RF_GROUP_ACTION, RF_GROUP_SENDER,
    RF_GROUP_RELAY_SEEN, RF_GROUP_RELAY_FOR, RF_GROUP_RELAY_DONE, RF_GROUP_MEMBER_KEYS,
    RF_GROUP_STATUSES,
} from "../../retichat_field.js";
import { boundSenderKey } from "../../group_status.js";
import { inviteMembers } from "../../group_sync.js";
import { decodePayload as decodeDisplayNamePayload } from "../../display_name.js";
import { listPrefix, readHead, skipValue } from "../msgpack_raw.js";
import { refuseRepeatedKeys, isRefusal } from "../msgpack_keys.js";
import { attachmentsFromFields } from "./lxmf.js";

/** A group id as every client reads it (RFed SPEC §17.14): 32 hex characters. */
const HEX32 = /^[0-9a-fA-F]{32}$/;

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
        // A received message's group entries, read from its bytes
        // (fromBytes, groupFieldsOfPayload); null for one built here.
        this.groupFields = null;
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

    /** Whether `error` is a payload refused whole (decodePayload), already
     *  said once: msgpack_keys.js isRefusal, for the callers that have
     *  LXMessage at hand. */
    static isRefusal(error) {
        return isRefusal(error);
    }

    /** "validated" | "unknown" | "invalid" — the three outcomes names follow
     *  (DISPLAY_NAMES.md §5.2). */
    get signatureState() {
        if (this.signatureValidated === true) return "validated";
        return this.unverifiedReason === LXMessage.SOURCE_UNKNOWN ? "unknown" : "invalid";
    }

    /**
     * The packed LXMF payload [timestamp, title, content, fields, (stamp)]
     * decoded, with the attachments its fields carry (attachmentsFromFields).
     * Returns { timestamp, title, content, fields, attachments,
     * fieldsUnreadable }, title and content as bytes or str as they came.
     *
     * A payload that holds a map, at any depth, that repeats a key is
     * refused whole first, before any of it is decoded, as Python LXMF
     * refuses it (RFed SPEC §17.14 "Repeated keys"; James, 2026-10-11:
     * parity): this throws RefusedPayload (msgpack_keys.js isRefusal) after
     * one log line naming `what`. Every LXMF payload this client reads comes
     * here first: the direct path and the propagated messages (fromBytes)
     * and the distro path (app.js _handleDistroBlob).
     *
     * A fields map msgpack cannot decode (an unknown ext type, a count past
     * the end of the bytes) costs the fields, never the message: the first
     * three elements are read on their own (their bytes as sent, listPrefix)
     * and the message keeps its text with no fields, fieldsUnreadable set to
     * why. Android does the same since dcc3e46 and 702e5fb (LxmfFields
     * decodeOrEmpty). Until 2026-09-30 such a message was lost whole, and a
     * stranger can send one to a distro address. A payload whose first three
     * elements cannot be read throws, as before.
     */
    static decodePayload(packedPayload, what = "LXMF message") {
        refuseRepeatedKeys(packedPayload, what);
        let unpacked;
        let fieldsUnreadable = null;
        try {
            unpacked = MsgPack.unpack(packedPayload);
        } catch (e) {
            let head = null;
            try {
                head = listPrefix(packedPayload, 3);
            } catch (walkError) {
                throw e;
            }
            if (!head) throw e;
            unpacked = [...MsgPack.unpack(head), new Map()];
            fieldsUnreadable = e?.message || String(e);
        }
        if (!Array.isArray(unpacked) || unpacked.length < 3) {
            throw new Error("LXMF payload is not a list of at least three elements");
        }
        const fields = unpacked[3];
        return {
            timestamp: unpacked[0],
            title: unpacked[1],
            content: unpacked[2],
            fields,
            attachments: attachmentsFromFields(fields),
            fieldsUnreadable,
        };
    }

    /**
     * Parse an LXMessage from source hash | signature | packed payload, and
     * validate its signature against the identity store. Without the
     * destination hash nothing can be validated and the message reports
     * SIGNATURE_INVALID. Null when it cannot be parsed, or is refused
     * (unpackFromBytes).
     * @param data
     * @param destinationHash
     * @param recall the identity store (defaults to LXMessage.recall)
     * @returns {null|LXMessage}
     */
    static fromBytes(data, destinationHash = null, recall = LXMessage.recall) {
        // no data provided, unable to parse
        if(data == null || data.length === 0){
            return null;
        }
        try {
            return LXMessage.unpackFromBytes(data, destinationHash, recall);
        } catch(e) {
            // A refusal has said so once already (decodePayload).
            if (!isRefusal(e)) console.log("failed to parse lxmf message from bytes", e);
            return null;
        }
    }

    /**
     * fromBytes, throwing instead of returning null, as LXMessage.py
     * unpack_from_bytes raises: a payload that repeats a key throws
     * RefusedPayload (msgpack_keys.js isRefusal), already logged once, so a
     * caller that logs its own failures (the router) tells it apart and
     * does not say it again; anything else that cannot be parsed throws
     * its own error.
     * @returns {LXMessage}
     */
    static unpackFromBytes(data, destinationHash = null, recall = LXMessage.recall) {
        // no data provided, unable to parse
        if(data == null || data.length === 0){
            throw new Error("no LXMF data");
        }

        // parse data
        const source = data.slice(0, 16);
        const signature = data.slice(16, 16 + 64);
        const packedPayload = data.slice(16 + 64);

        // unpack msgpack payload (decodePayload: a payload that repeats
        // a key is refused whole; unreadable fields cost the fields, not
        // the message)
        const unpacked = LXMessage.decodePayload(packedPayload, `LXMF message from ${Buffer.from(source).toString("hex").slice(0, 12)}`);
        const timestamp = unpacked.timestamp;
        const title = Buffer.from(unpacked.title ?? []).toString();
        const content = Buffer.from(unpacked.content ?? []).toString();
        const fields = unpacked.fields;

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
        // An accept or leave carries its sender's own key (RFed-spec
        // Group.md, "Member statuses and keys"; group_status.js). It is
        // bound as an invite chunk's key is: it derives the lxmf.delivery
        // destination that is the entry's hash and the message's source.
        // senderKey is that key (a 64-byte Buffer) whenever one binds,
        // held already or not: a creator answers only an accept that
        // carries it. For a source this client holds no key for
        // (SOURCE_UNKNOWN) the signature is then checked under the
        // carried key, and the result is the message's signature as any
        // other check's: validated, or invalid when it does not verify.
        // A key that does not bind is no key: the message stays
        // unverifiable, as one that carried none.
        lxmfMessage.senderKey = null;
        // The group entries, read from the payload's bytes
        // (groupFieldsOfPayload, SPEC §17.14 "Repeated keys"), never
        // from msgpackr's `fields`: every reading of a received
        // message's group entries goes through them (groupInfo).
        const groupFields = LXMessage.groupFieldsOfPayload(packedPayload);
        lxmfMessage.groupFields = groupFields;
        const carried = LXMessage.carriedSenderKey(groupFields, source);
        if (carried) {
            lxmfMessage.senderKey = carried.getPublicKey();
            if (destinationHash && lxmfMessage.unverifiedReason === LXMessage.SOURCE_UNKNOWN) {
                const bound = LXMessage.verify(destinationHash, source, signature, packedPayload, () => carried);
                lxmfMessage.signatureValidated = bound.validated;
                lxmfMessage.unverifiedReason = bound.unverifiedReason;
            }
        }
        // What the signature covers, kept so that a check that could not
        // run (SOURCE_UNKNOWN: no key for the source yet) can be run once
        // the key is here (LXMessage.verify): app.js holds a group accept
        // or leave until then.
        lxmfMessage.signature = signature;
        lxmfMessage.packedPayload = packedPayload;
        lxmfMessage.timestamp = timestamp;
        lxmfMessage.title = title;
        lxmfMessage.content = content;
        lxmfMessage.fields = fields;
        // What the fields carry for the user to see (0x05, 0x06, 0x07),
        // and whether the fields could be read at all.
        lxmfMessage.attachments = unpacked.attachments;
        lxmfMessage.fieldsUnreadable = unpacked.fieldsUnreadable;
        // 0xD1 read from the payload bytes, not from `fields`: msgpackr
        // has already rewritten an invalid-UTF-8 str there (§3 rule 1).
        lxmfMessage.displayName = decodeDisplayNamePayload(packedPayload);
        return lxmfMessage;
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
 * groupSender, members, relayFor, relaySeen, relayDone, memberKeys }.
 *
 * Every entry is read by LXMF-rust/DISPLAY_NAMES.md §10 (retichat_field.js
 * readGroupEntry): from the Retichat field 0xD1 (keys 1-9) when it holds the
 * entry with its type, otherwise from the old top-level field 0xA0-0xA8, one
 * entry at a time. Types are strict, as on every other client: a str entry
 * is a msgpack str (bin is not), relay_done a msgpack bool. A message is a
 * group message when it has a group id; a Map at 0xD1 is never read as one.
 * An id of 32 hex characters is read lowercased, as every client reads it
 * (RFed SPEC §17.14; LXMessage.groupIdRefusal refuses a received message
 * whose GROUP_ID is anything else).
 * `statuses` is key 10 of the Retichat field (a `status`'s GROUP_STATUSES),
 * the array as decoded or null: it has no old field, so no other form is read.
 */
LXMessage.extractGroupFields = function(fields) {
    if (!fields || !(fields instanceof Map)) return null;
    const id = readGroupEntry(fields, RF_GROUP_ID);
    if (id == null) return null;
    const groupId = typeof id === "string" && HEX32.test(id) ? id.toLowerCase() : id;

    const toMembers = (s) => {
        if (!s) return [];
        return s.split(',').map(h => h.trim()).filter(h => h.length === 32);
    };
    const toMemberKeys = (s) => {
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
        groupId,
        groupName: readGroupEntry(fields, RF_GROUP_NAME),
        groupAction: readGroupEntry(fields, RF_GROUP_ACTION),
        groupSender: readGroupEntry(fields, RF_GROUP_SENDER),
        // The invite parser of every client (lib/group_sync.js
        // inviteMembers: trimmed of Unicode Zs and U+0009 only, 32 lowercase
        // hex, the first of each), so a list names D here exactly when it
        // does on the phones (GROUPS-DISTRO-DESIGN.md §9.3, §11.1 rule 4).
        // Until 2026-10-10 it was trim() and any 32 characters: a D wrapped
        // in a newline, or in uppercase, was listed here and not there.
        members: inviteMembers(readGroupEntry(fields, RF_GROUP_MEMBERS)),
        // The csv exactly as it came, which a D-group's accept sync carries
        // (GROUPS-DISTRO-DESIGN.md §10.2 `members`); null when none.
        membersCsv: typeof readGroupEntry(fields, RF_GROUP_MEMBERS) === "string" ? readGroupEntry(fields, RF_GROUP_MEMBERS) : null,
        relayFor: readGroupEntry(fields, RF_GROUP_RELAY_FOR),
        relaySeen: toMembers(readGroupEntry(fields, RF_GROUP_RELAY_SEEN)),
        relayDone: readGroupEntry(fields, RF_GROUP_RELAY_DONE),
        memberKeys: toMemberKeys(readGroupEntry(fields, RF_GROUP_MEMBER_KEYS)),
        statuses: readStatuses(fields),
    };
};

/**
 * The key an accept or leave carries for its own sender, once bound: the
 * Identity it loads as, or null for any other message, for one that carries
 * no entry for its source, and for one whose key does not derive the source
 * as an lxmf.delivery destination (group_status.js boundSenderKey).
 * `source` is the LXMF source (bytes).
 */
LXMessage.carriedSenderKey = function(fields, source) {
    if (!(fields instanceof Map)) return null;
    const group = LXMessage.extractGroupFields(fields);
    if (!group || (group.groupAction !== "accept" && group.groupAction !== "leave")) return null;
    return boundSenderKey(group.memberKeys, Buffer.from(source).toString("hex"));
};

/**
 * The JS value msgpackr gives the numeric map key at `pos` (`head` is
 * readHead's), or undefined for any other key: a number for every int width
 * but the two 64-bit ones, which msgpackr hands back as a BigInt, and a
 * number for a float. A key that is not numeric never matches an integer
 * field (retichat_field.js keyIs).
 */
function numericKey(b, pos, head) {
    const t = b[pos];
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
    if (t === 0xcf) return view.getBigUint64(pos + 1);
    if (t === 0xd3) return view.getBigInt64(pos + 1);
    if (head.kind === "int") return head.int;
    if (t === 0xca) return view.getFloat32(pos + 1);
    if (t === 0xcb) return view.getFloat64(pos + 1);
    return undefined;
}

/** What a group entry's value is when msgpackr cannot decode it (an ext of
 *  a type it does not know, inside the value or as the value): no str, no
 *  bool, no map and no array, so every typed reader takes it as an entry
 *  of the wrong type, and the entry is still there (a GROUP_ID of it still
 *  makes a group message, with no id). */
const UNDECODABLE = Object.freeze({ undecodable: true });

/** The value whose bytes are `b[from, to)`, decoded, or UNDECODABLE. */
function decodeValue(b, from, to) {
    try {
        return MsgPack.unpack(b.subarray(from, to));
    } catch {
        return UNDECODABLE;
    }
}

/**
 * The entries of the msgpack map at `pos` whose keys are one of the
 * integers `wanted`, decoded, in a Map shaped as msgpackr shapes one (its
 * keys as msgpackr gives them, in the order met). FIELD_RETICHAT, when
 * wanted, is the Map of its own entries whose keys are in `inner`, or null
 * when it is no map: a 0xD1 that is no map is ignored whole. Every other
 * entry is skipped by its length, unread, and a value msgpackr cannot decode
 * (an unknown ext) costs only itself (UNDECODABLE), never the map. null when
 * the value at `pos` is not a map.
 *
 * A map that repeats a key never reaches it from the parse: the payload is
 * refused whole first (decodePayload; RFed SPEC §17.14 "Repeated keys").
 * The router's look (peekGroupFields) runs before the parse; there a key's
 * first entry is taken, and the parse that follows refuses the payload.
 */
function pickEntries(b, pos, wanted, inner = []) {
    const head = readHead(b, pos);
    if (head.kind !== "map") return null;
    const picked = new Map();
    const taken = new Set();
    let at = head.end;
    for (let i = 0; i < head.count; i++) {
        const key = numericKey(b, at, readHead(b, at));
        const valueAt = skipValue(b, at);
        const end = skipValue(b, valueAt);
        const field = key === undefined ? undefined : wanted.find((w) => keyIs(key, w));
        if (field !== undefined && !taken.has(field)) {
            taken.add(field);
            picked.set(key, field === FIELD_RETICHAT ? pickEntries(b, valueAt, inner) : decodeValue(b, valueAt, end));
        }
        at = end;
    }
    return picked;
}

/** The fields map of a packed LXMF payload ([timestamp, title, content,
 *  fields, ...]): its offset, or null when the payload is no such list. */
function fieldsOffset(b) {
    const top = readHead(b, 0);
    if (top.kind !== "array" || top.count < 4) return null;
    let pos = top.end;
    for (let i = 0; i < 3; i++) pos = skipValue(b, pos);
    return pos;
}

/** The top-level fields that can hold a message's group id or action:
 *  the Retichat field 0xD1 (keys 1 and 4) and the old 0xA0 and 0xA3. */
const GROUP_PEEK_FIELDS = [FIELD_RETICHAT, groupEntry(RF_GROUP_ID).legacy, groupEntry(RF_GROUP_ACTION).legacy];

/** fields[0xFB], FIELD_CUSTOM_TYPE: where a distro marker is. */
const FIELD_CUSTOM_TYPE = 0xFB;
/** Every top-level field that can hold a group entry: the Retichat field
 *  0xD1 and the old 0xA0-0xA8, and 0xFB (the distro path's
 *  lib/group_sync.js groupEntriesOf reads no group entry beside a distro
 *  marker); and the group keys inside 0xD1, 1-9 and 10 (GROUP_STATUSES). */
const GROUP_FIELD_NUMBERS = [FIELD_RETICHAT, ...GROUP_ENTRIES.map((e) => e.legacy), FIELD_CUSTOM_TYPE];
const RETICHAT_GROUP_KEYS = [...GROUP_ENTRIES.map((e) => e.key), RF_GROUP_STATUSES];

/**
 * A received message's group entries, read from the bytes of its packed
 * payload ([timestamp, title, content, fields, ...]) and never from
 * msgpackr's decoding (RFed SPEC §17.14): a Map holding only the top-level
 * 0xA0-0xA8, 0xFB and the Retichat field 0xD1 (its keys 1-10), shaped as
 * msgpackr shapes a fields map, so every reader of group entries
 * (extractGroupFields, carriedSenderKey, lib/group_sync.js groupEntriesOf)
 * reads it as it reads the decoded fields. msgpackr refuses a whole map that
 * holds an ext of a type it does not know; LXMF-rust, the phones' unwrap
 * and lib/group_sync.js readGroupEntries (the distro path's classification)
 * skip the ext, so a message read from msgpackr's map would be a group
 * message there and none here. An empty Map when the payload has no fields
 * map or its bytes cannot be walked, as msgpackr then gives no fields. Read
 * after the parse has refused a payload that repeats a key (decodePayload).
 */
LXMessage.groupFieldsOfPayload = function(packedPayload) {
    try {
        const b = packedPayload instanceof Uint8Array ? packedPayload : Uint8Array.from(packedPayload ?? []);
        const pos = fieldsOffset(b);
        if (pos === null) return new Map();
        return pickEntries(b, pos, GROUP_FIELD_NUMBERS, RETICHAT_GROUP_KEYS) ?? new Map();
    } catch {
        return new Map();
    }
};

/**
 * RFed SPEC §17.14, the direct path: why a received message is refused for
 * its group id, or null. A GROUP_ID entry of any type in either form (key 1
 * of the Retichat field 0xD1 when that is a map, or the old 0xA0) makes it a
 * group message, and its id is read as the distro path reads it
 * (lib/group_sync.js readGroupEntries): a str of 32 hex characters, compared
 * and stored lowercased (extractGroupFields). A GROUP_ID that is anything
 * else (another length, not hex, a bin, an int, nil) refuses the message,
 * with a log line (LXMRouter.acceptsMessage): never a direct message, never
 * a group. Until 2026-10-11 a bin or int id made it a DM here, a str of any
 * other text made a group of that name, and an uppercase id another group
 * than the phones', which drop it and lowercase. A distro marker means
 * nothing here: the direct path classifies by the group id alone (the
 * distro path reads no group entry beside one). Read from the bytes, as
 * groupInfo reads them; a message built here from its fields.
 */
LXMessage.groupIdRefusal = function(message) {
    const fields = message?.groupFields instanceof Map ? message.groupFields : message?.fields;
    if (!(fields instanceof Map)) return null;
    const has = readEntry(fields, RF_GROUP_ID) !== undefined || topLevel(fields, groupEntry(RF_GROUP_ID).legacy) !== undefined;
    if (!has) return null;
    const id = readGroupEntry(fields, RF_GROUP_ID);
    return typeof id === "string" && HEX32.test(id) ? null : "its GROUP_ID is not a str of 32 hex characters";
};

/**
 * The group metadata (extractGroupFields) of `message`: for a received one
 * (LXMessage.fromBytes), from its group entries as its bytes hold them
 * (groupFields, groupFieldsOfPayload); for one built here, which has no
 * bytes yet and whose fields Map cannot repeat a key, from its fields. Every
 * receive path reads a message's group entries through this: the direct
 * path, the distro path, the privacy filter and a `status`'s elements
 * (app.js). null when it is no group message.
 */
LXMessage.groupInfo = function(message) {
    return LXMessage.extractGroupFields(message?.groupFields instanceof Map ? message.groupFields : message?.fields);
};

/**
 * The group id and action of a packed LXMF payload ([timestamp, title,
 * content, fields, ...]), read just far enough to tell, and nothing more:
 * for the privacy filter's look at a stranger's message (LXMRouter
 * acceptsSource), which must cost next to nothing when the answer is "drop".
 *
 * The payload is walked, not decoded (msgpack_raw.js): the timestamp, title
 * and content are skipped by their lengths, and so is every field but the
 * four entries that can carry these two (0xD1's keys 1 and 4, the old 0xA0
 * and 0xA3) — attachments, names, member lists and keys are never read.
 * Only those entries are decoded (pickEntries, as groupFieldsOfPayload reads
 * them), into a Map shaped as msgpackr would shape it, and read by
 * extractGroupFields, the same reader the full parse's group entries go
 * through (groupInfo), so the answer is the full parse's. A payload that
 * repeats a key is not looked for here: the parse refuses it.
 * Nothing is hashed, verified or kept. The router asks the filter again after the full parse
 * (acceptsMessage), so a message whose look and parse disagree costs a parse
 * and is still dropped unproved.
 *
 * @returns {{groupId: string, groupAction: string|null}|null} null when the
 *   payload carries no group id, or cannot be read.
 */
LXMessage.peekGroupFields = function(packedPayload) {
    try {
        const b = packedPayload instanceof Uint8Array ? packedPayload : Uint8Array.from(packedPayload ?? []);
        const pos = fieldsOffset(b);
        if (pos === null) return null;
        const fields = pickEntries(b, pos, GROUP_PEEK_FIELDS, [RF_GROUP_ID, RF_GROUP_ACTION]);
        const group = fields ? LXMessage.extractGroupFields(fields) : null;
        return group ? { groupId: group.groupId, groupAction: group.groupAction } : null;
    } catch {
        return null;
    }
};

export default LXMessage;
