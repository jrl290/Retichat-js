/**
 * RFed Channel protocol — pure JavaScript implementation.
 * Matches the Rust FFI in Retichat-ios/rust/retichat-ffi/src/lib.rs.
 *
 * Channel messages are LXMF payloads wrapped in a channel-specific
 * EC-encrypted envelope with a SOURCE-IDENTITY PRELUDE ("RTID" magic +
 * 64-byte sender public key) so receivers can validate signatures
 * without waiting for an LXMF announce.
 *
 * Wire format (send):
 *   [ ts_ms_be(8) | channel_id_hash(16) | EC_encrypted(prelude | lxmf_tail) ]
 *
 * Where:
 *   - ts_ms_be: LXMF timestamp as u64 big-endian ms (for local echo dedup)
 *   - channel_id_hash: channel identity hash (SHA256-derived, 16 bytes)
 *   - prelude: "RTID" (4 bytes) + sender_pub_key (64 bytes)
 *   - lxmf_tail: source_hash(16) | signature(64) | msgpack_payload
 *
 * On the wire, the 8-byte timestamp prefix is stripped — only
 * channel_id_hash | EC_encrypted(...) is sent.
 */

import Identity from "./identity.js";
import Destination from "./destination.js";
import Cryptography from "./cryptography.js";
import Constants from "./constants.js";
import MsgPack from "./msgpack.js";
import { Buffer } from "buffer";

/** "RTID" magic bytes for the SOURCE-IDENTITY PRELUDE. */
const RTID_MAGIC = Buffer.from("RTID", "ascii");  // 4 bytes

/** Length of the prelude: magic(4) + sender pub key(64) = 68 bytes. */
const PRELUDE_LEN = 4 + 64;

/** STAMP_EXPAND_ROUNDS = 16 — invariant per SPEC.md, forever. */
const STAMP_EXPAND_ROUNDS = 16;

/**
 * Derive a deterministic X25519+Ed25519 keypair from a channel name.
 * SPEC.md §1: seed = SHA-256(name) — single hash, same 32-byte seed
 * for both X25519 and Ed25519 private keys.
 */
function channelPrivateKeyBytes(name) {
    // SPEC.md §1: seed = SHA-256(name) → 32 bytes
    const seed = Cryptography.sha256(Buffer.from(name, "utf-8"));
    // Both X25519 and Ed25519 use the SAME seed.
    // RNS Identity.fromPrivateKey expects 64 bytes: first 32=X25519, last 32=Ed25519.
    return Buffer.concat([Buffer.from(seed), Buffer.from(seed)]);
}

/**
 * Create an Identity from a channel name.
 * Returns { identity, hash } where hash is the 16-byte identity hash.
 */
function channelIdentity(name) {
    const prvBytes = channelPrivateKeyBytes(name);
    const id = Identity.fromPrivateKey(prvBytes);
    return { identity: id, hash: id.hash };  // id.hash is the 16-byte truncated hash
}

/**
 * Derive the channel's `lxmf.delivery` destination hash.
 * This is the hash that the sender signs over in the LXMF message,
 * and that the receiver reconstructs before signature validation.
 */
function channelDeliveryHash(name) {
    const prvBytes = channelPrivateKeyBytes(name);
    const id = Identity.fromPrivateKey(prvBytes);
    return Destination.hash(id, "lxmf", "delivery");
}

/**
 * Pack a channel message for sending.
 *
 * @param {string} name - Channel name (e.g. "general")
 * @param {Identity} senderIdentity - Local identity
 * @param {string} content - Message content (UTF-8)
 * @returns {{ wire: Buffer, tsMs: number }} - wire payload (to send) + timestamp ms
 */
function channelLxmPack(name, senderIdentity, content) {
    // dest_hash = channel's lxmf.delivery hash (what sender signs over)
    const destHash = channelDeliveryHash(name);

    // Fix #1: source_hash = sender's lxmf.delivery DESTINATION hash,
    // NOT senderIdentity.hash (which is the identity hash).
    // Per SPEC.md: source_hash is truncated_hash(name_hash("lxmf.delivery") || identity_hash).
    const sourceHash = Destination.hash(senderIdentity, "lxmf", "delivery");
    const senderPubBytes = senderIdentity.getPublicKey();  // 64 bytes

    // Build LXMF payload: timestamp(8 f64) | title(0) | content | fields(empty map)
    const tsMs = Date.now();
    const tsSec = tsMs / 1000.0;
    const titleBytes = Buffer.alloc(0);
    const contentBytes = Buffer.from(content, "utf-8");
    const fields = new Map();

    const packedPayload = MsgPack.pack([tsSec, titleBytes, contentBytes, fields]);

    // hashed part: dest_hash | source_hash | packed_payload
    const hashedPart = Buffer.concat([destHash, sourceHash, packedPayload]);
    const hash = Cryptography.fullHash(hashedPart);

    // signed part: hashed_part | hash
    const signedPart = Buffer.concat([hashedPart, hash]);
    const signature = senderIdentity.sign(signedPart);

    // LXMF tail (non-opportunistic, matches iOS): source_hash(16) | sig(64) | payload
    // Per iOS Rust FFI: dest_hash is STRIPPED from the lxmf_tail before EC encryption.
    // The receiver reconstructs dest_hash from the channel name.
    const lxmfTail = Buffer.concat([sourceHash, signature, packedPayload]);

    // Prepend SOURCE-IDENTITY PRELUDE: RTID magic + sender pub key
    const preludePlusTail = Buffer.concat([RTID_MAGIC, senderPubBytes, lxmfTail]);

    // EC-encrypt with channel identity
    const { identity: chId } = channelIdentity(name);
    const encrypted = chId.encrypt(preludePlusTail);

    // Channel identity hash (routing label for RFed)
    const { hash: chIdHash } = channelIdentity(name);

    // Wire format: ts_ms_be(8) | channel_id_hash(16) | EC_encrypted(...)
    const tsBuf = Buffer.alloc(8);
    tsBuf.writeBigUInt64BE(BigInt(tsMs));
    const wire = Buffer.concat([tsBuf, chIdHash, encrypted]);

    // On the wire we strip the 8-byte timestamp prefix
    const wirePayload = Buffer.concat([chIdHash, encrypted]);

    return { wire: wirePayload, tsMs };
}

/**
 * Unpack a received channel message.
 *
 * @param {string} name - Channel name
 * @param {Buffer} data - Wire payload [channel_id_hash(16) | EC_encrypted(...)]
 * @returns {object|null} - { sourceHash, tsMs, content, title, senderPubKey } or null on error
 */
function channelLxmUnpack(name, data) {
    if (!data || data.length < 16 + 32) {
        console.warn("[channel] data too short for unpack");
        return null;
    }

    // EC-decrypt the tail
    const { identity: chId } = channelIdentity(name);
    const encrypted = data.slice(16);
    let decrypted;
    try {
        decrypted = chId.decrypt(encrypted);
    } catch(e) {
        console.warn("[channel] decrypt failed:", e.message);
        return null;
    }

    // Check RTID magic
    if (decrypted.length < PRELUDE_LEN ||
        !decrypted.slice(0, 4).equals(RTID_MAGIC)) {
        console.warn("[channel] missing RTID prelude — incompatible sender");
        return null;
    }

    // Extract sender public key (64 bytes after magic)
    const senderPubKey = decrypted.slice(4, PRELUDE_LEN);
    const lxmfTail = decrypted.slice(PRELUDE_LEN);

    if (lxmfTail.length < 16 + 64 + 4) {
        console.warn("[channel] LXMF tail too short");
        return null;
    }

    // LXMF tail (matches iOS): source_hash(16) | sig(64) | msgpack_payload
    // dest_hash is NOT in the tail — reconstructed below from channel name.
    const sourceHash = lxmfTail.slice(0, 16);
    const sig = lxmfTail.slice(16, 16 + 64);
    const packedPayload = lxmfTail.slice(16 + 64);

    // Reconstruct hashed part for signature validation:
    // dest_hash | source_hash | packed_payload
    const destHash = channelDeliveryHash(name);
    const hashedPart = Buffer.concat([destHash, sourceHash, packedPayload]);
    const hash = Cryptography.fullHash(hashedPart);
    const signedPart = Buffer.concat([hashedPart, hash]);

    // Verify signature using the sender's public key (from prelude)
    let sigValid = false;
    try {
        // Create a temporary identity from the public key to verify
        const senderId = Identity.fromPublicKey(senderPubKey);
        sigValid = senderId.validate(sig, signedPart);
    } catch(e) {
        console.warn("[channel] signature verification error:", e.message);
    }

    if (!sigValid) {
        console.warn("[channel] signature invalid");
        return null;
    }

    // Unpack the msgpack payload
    let payload;
    try {
        payload = MsgPack.unpack(packedPayload);
    } catch(e) {
        console.warn("[channel] msgpack unpack failed:", e.message);
        return null;
    }

    if (!Array.isArray(payload) || payload.length < 3) {
        console.warn("[channel] bad payload shape");
        return null;
    }

    const [tsSec, titleBin, contentBin, fieldsMap] = payload;
    const tsMs = Math.round((typeof tsSec === 'number' ? tsSec : 0) * 1000);
    const title = Buffer.from(titleBin || []).toString("utf-8");
    const content = Buffer.from(contentBin || []).toString("utf-8");

    return {
        sourceHash,
        tsMs,
        content,
        title,
        fields: fieldsMap instanceof Map ? fieldsMap : new Map(),
        senderPubKey,  // 64-byte raw pub key
        signatureValidated: true,
    };
}

/**
 * Compute a PoW stamp for a channel message.
 * Per SPEC.md stamp contract:
 *   transient_id = sha256(channel_hash(16) || inner_blob)  — the on-wire payload
 *   workblock    = sha256(transient_id), then 16 iterative SHA-256 rounds
 *   stamp        = 32-byte nonce where stamp_value >= cost
 *
 * @param {Buffer} wirePayload - On-wire payload [channel_hash(16) | EC_encrypted(...)]
 * @param {number} cost - Required leading zero bits from server
 * @returns {Promise<Buffer>} - 32-byte stamp, or null on failure
 */
async function channelComputeStamp(wirePayload, cost) {
    try {
        // Step 1: transient_id = sha256(payload)
        const transientId = Cryptography.sha256(wirePayload);

        // Step 2: match LXStamper::stamp_workblock exactly: hash the
        // transient ID once, then hash the 32-byte result for each round.
        let workblock = Cryptography.sha256(transientId);
        for (let n = 0; n < STAMP_EXPAND_ROUNDS; n++) {
            workblock = Cryptography.sha256(workblock);
        }

        // Step 3: mine a 32-byte stamp where sha256(workblock || stamp) has >= cost leading zero bits
        const target = cost;
        const nonceBytes = Buffer.alloc(16);
        for (let nonce = 0; nonce <= 1_000_000; nonce++) {
            nonceBytes.writeBigUInt64LE(BigInt(nonce), 0);
            nonceBytes.writeBigUInt64LE(0n, 8);
            const stamp = Cryptography.sha256(Buffer.concat([workblock, nonceBytes]));
            const hashInput = Buffer.concat([workblock, stamp]);
            const hash = Cryptography.sha256(hashInput);
            let leadingZeros = 0;
            for (let i = 0; i < hash.length; i++) {
                if (hash[i] === 0) { leadingZeros += 8; }
                else { leadingZeros += Math.clz32(hash[i]) - 24; break; }
            }
            if (leadingZeros >= target) {
                console.log(`[channel] 🔨 Stamp found after ${nonce + 1} attempts (${leadingZeros} leading zero bits, target ${target})`);
                return stamp;
            }
            if (nonce % 100 === 99) await new Promise(r => setTimeout(r, 0));
        }
        console.warn(`[channel] Stamp search exhausted at cost ${target}`);
        return null;
    } catch(e) {
        console.warn("[channel] Stamp computation error:", e.message);
        return null;
    }
}

/**
 * Derive the rfed.channel destination hash from the RFed node identity hash.
 */
function rfedChannelDestHash(rfedNodeHash) {
    const rfedIdBytes = Buffer.from(rfedNodeHash, "hex");
    return Destination.hash({hash: rfedIdBytes}, "rfed", "channel").toString("hex");
}

/**
 * Derive the rfed.channel.stream destination hash.
 */
function rfedChannelStreamDestHash(rfedNodeHash) {
    const rfedIdBytes = Buffer.from(rfedNodeHash, "hex");
    return Destination.hash({hash: rfedIdBytes}, "rfed", "channel", "stream").toString("hex");
}

/**
 * Derive the rfed.channel.pull destination hash.
 */
function rfedChannelPullDestHash(rfedNodeHash) {
    const rfedIdBytes = Buffer.from(rfedNodeHash, "hex");
    return Destination.hash({hash: rfedIdBytes}, "rfed", "channel", "pull").toString("hex");
}

/**
 * Derive the rfed.delivery destination hash (per-subscriber receive endpoint).
 * Per iOS: uses the USER's identity (not the RFed node's), so the hash is
 * Destination.hash(userIdentity, "rfed", "delivery").
 * @param {Identity} userIdentity — the local user's Identity
 */
function rfedDeliveryDestHash(userIdentity) {
    return Destination.hash(userIdentity, "rfed", "delivery").toString("hex");
}

export {
    channelIdentity,
    channelDeliveryHash,
    channelLxmPack,
    channelLxmUnpack,
    channelComputeStamp,
    rfedChannelDestHash,
    rfedChannelStreamDestHash,
    rfedChannelPullDestHash,
    rfedDeliveryDestHash,
};