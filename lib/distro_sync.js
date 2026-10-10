/**
 * The distro sync proof: RFed-rust SPEC.md §17.13, RFed-spec LXMFProp.md
 * §10.5, DISTRO-SYNC-PROOF-DESIGN.md §4 and §5 (approved by James,
 * 2026-10-10). The web's twin of LXMF-rust src/distro.rs sync_signed_bytes,
 * seal_for_sync, SyncClaim::for_sealed, verify_sync_claim and
 * sealed_upload, held to the same golden vector (LXMF-rust
 * tests/distro_sync_vectors.json; distro_sync.test.mjs).
 *
 * A device's own uploads to its distro D, the §17.11 sent copy and the
 * §17.12 membership message C (both kinds: James, 2026-10-10, Q1), are
 * sync. With D's private key the device proves that an upload is one, and
 * RFed then delivers it to D's connected devices and queues it for the rest
 * without waking them. The proof travels in the upload itself, as a third
 * element of the client's `lxmf.propagation` envelope:
 *
 *   [ timebase f64, [ lxmf_data ], { "rfed.distro.sync": [ claim ] } ]
 *   claim     = [ bin(16) id, bin(64) distro_pubkey, bin(64) sig ]
 *   lxmf_data = sealed | stamp(32)
 *   sealed    = D_hash(16) | D.encrypt(packed[16..])
 *   id        = SHA-256(sealed)[0..16]       (RFed's distro_message_id)
 *   sig       = D.sign("rfed.distro.sync" | 0x01 | D_hash | SHA-256(sealed))
 *
 * Every value is native msgpack (CHECK_THESE_THINGS_FIRST §11): bin for
 * bytes, a str key, arrays, and a native Map for the extension, never a
 * blob of msgpack packed beforehand and wrapped in bin. Without a claim the
 * envelope is LXMF's two-element [timebase, [lxmf_data]], as every upload
 * was before.
 *
 * The message is sealed once, when it is owed (app.js _sendDistroSentCopy,
 * _sendDistroChannelSync), and every upload of it carries the same sealed
 * bytes: only the stamp and the timebase are made again (app.js
 * _buildPropagationPacked). So a re-upload is byte-identical where it
 * matters, and RFed holds it under the same id and fans it out once. The
 * signature is made then because only then does the device hold D's
 * private key for certain: a sent copy stays owed to D after the device
 * gives D up.
 *
 * Which uploads carry the claim is the page's choice, not this file's: only
 * those to the configured RFed's own `lxmf.propagation` destination (design
 * §5.4, app.js _distroSyncProofGoes). LXMF ignores a Resource whose
 * envelope is not exactly two elements (LXMRouter.py), so a claim sent to
 * any other node would lose the message without a word.
 *
 * Nothing here touches a Node-only global at module load.
 */

import { Identity, Destination } from "./rns/reticulum.js";
import Cryptography from "./rns/cryptography.js";
import MsgPack from "./rns/msgpack.js";

/** The key of the sync proof in the upload's third element. */
export const DISTRO_SYNC_KEY = "rfed.distro.sync";
/** The version byte that follows the 16 ASCII bytes of the tag in the signed bytes. */
export const DISTRO_SYNC_VERSION = 0x01;
/** `tag(16) | version(1) | D_hash(16) | transient_id(32)`. */
export const DISTRO_SYNC_SIGNED_LEN = 65;
/** A claim's `id`: `transient_id[0..16]`. */
export const DISTRO_SYNC_ID_LEN = 16;

const DISTRO_SYNC_TAG = "rfed.distro.sync";
const DEST_HASH_LEN = 16;
const TRANSIENT_ID_LEN = 32;
const STAMP_LEN = 32;
// What follows the destination hash in a packed LXMF message before its
// payload: the source hash and the signature (LXMF-rust distro.rs).
const LXMF_HEADER_LEN = 16 + 64;
const PUBLIC_KEY_LEN = 64;
const SIGNATURE_LEN = 64;

const bytes = (b) => Buffer.from(b);

/** `transient_id = SHA-256(sealed)`: what the PN stamp is mined over, and what a sync signature covers. */
export function syncTransientId(sealed) {
    return Cryptography.fullHash(bytes(sealed));
}

/**
 * The 65 bytes D signs for a sync proof:
 * `"rfed.distro.sync" | 0x01 | D_hash | transient_id`. No other signature
 * D makes is 65 bytes that begin with this tag (design §4.2).
 */
export function syncSignedBytes(dHash, transientId) {
    if (dHash?.length !== DEST_HASH_LEN) throw new Error(`a destination hash is ${DEST_HASH_LEN} bytes, this is ${dHash?.length}`);
    if (transientId?.length !== TRANSIENT_ID_LEN) throw new Error(`a transient id is ${TRANSIENT_ID_LEN} bytes, this is ${transientId?.length}`);
    return Buffer.concat([Buffer.from(DISTRO_SYNC_TAG, "ascii"), Buffer.from([DISTRO_SYNC_VERSION]), bytes(dHash), bytes(transientId)]);
}

/**
 * Seal `packed`, an LXMF message D packed and signed to itself
 * (`D_hash | src | signature | payload`), for distro sync: encrypt it to D
 * once and sign the result with D's key. Returns `{ sealed, sig }`.
 *
 * Throws, with nothing made, when `identity` holds no private key, when
 * `packed` is too short to be an LXMF message or is not addressed to D, or
 * when the signature does not validate. The page then owes the message
 * without them, says so as an error, and builds it as before (design §5.1).
 */
export function sealForSync(identity, packed) {
    if (!identity?.privateKeyBytes?.length || !identity?.signaturePrivateKeyBytes?.length) {
        throw new Error("the distro identity has no private key: a sync proof needs D's signature");
    }
    const message = bytes(packed);
    if (message.length <= DEST_HASH_LEN + LXMF_HEADER_LEN) {
        throw new Error(`a packed LXMF message is longer than ${DEST_HASH_LEN + LXMF_HEADER_LEN} bytes, this is ${message.length}`);
    }
    const dHash = Destination.hash(identity, "lxmf", "delivery");
    if (!message.subarray(0, DEST_HASH_LEN).equals(dHash)) throw new Error("the packed message is not addressed to the distro");

    // Encrypted once: every upload of the entry carries these bytes.
    const sealed = Buffer.concat([dHash, identity.encrypt(message.subarray(DEST_HASH_LEN))]);
    const signed = syncSignedBytes(dHash, syncTransientId(sealed));
    const sig = identity.sign(signed);
    if (!identity.validate(sig, signed)) throw new Error("the sync signature does not validate with the distro's own key");
    return { sealed, sig };
}

/**
 * Why RFed would refuse `claim` for the message `sealed` (null when it
 * would not), LXMF-rust verify_sync_claim's three checks: the id is
 * `SHA-256(sealed)[0..16]`; the key's `lxmf.delivery` hash is the
 * message's destination, `sealed[0..16]`; and the signature is valid for
 * that key over the signed bytes. The reason is a fixed string.
 */
export function syncClaimRefusal(claim, sealed) {
    if (!Array.isArray(claim) || claim.length !== 3) return "not a claim";
    const [id, distroPubKey, sig] = claim.map((b) => (b instanceof Uint8Array ? bytes(b) : null));
    if (id?.length !== DISTRO_SYNC_ID_LEN || distroPubKey?.length !== PUBLIC_KEY_LEN || sig?.length !== SIGNATURE_LEN) return "not a claim";
    const message = bytes(sealed);
    if (message.length < DEST_HASH_LEN) return "message shorter than a destination hash";
    const transientId = syncTransientId(message);
    if (!id.equals(transientId.subarray(0, DISTRO_SYNC_ID_LEN))) return "id is not the message's";
    const dHash = message.subarray(0, DEST_HASH_LEN);
    const distro = Identity.fromPublicKey(distroPubKey);
    if (!Destination.hash(distro, "lxmf", "delivery").equals(dHash)) return "distro key is not the message's destination";
    let valid = false;
    try {
        valid = distro.validate(sig, syncSignedBytes(dHash, transientId));
    } catch {
        valid = false;
    }
    return valid ? null : "signature invalid";
}

/**
 * The claim for the sealed message `sealed`, from what the page kept with
 * the entry: D's public key `distroPubKey` (64 bytes) and the sync
 * signature `sig` (64): `[id, distroPubKey, sig]`, each a Buffer, so it
 * packs as bin. Throws when RFed would refuse it (syncClaimRefusal), so a
 * broken stored claim is never sent.
 */
export function syncClaimFor(sealed, distroPubKey, sig) {
    const claim = [syncTransientId(sealed).subarray(0, DISTRO_SYNC_ID_LEN), bytes(distroPubKey), bytes(sig)];
    const refused = syncClaimRefusal(claim, sealed);
    if (refused) throw new Error(`the sync claim is not this message's: ${refused}`);
    return claim;
}

/**
 * The upload of one sealed message to `lxmf.propagation`:
 * `lxmf_data = sealed | stamp`, the stamp mined over `SHA-256(sealed)` at
 * the node's cost. With `claim`, `[timebase, [lxmf_data], Map {"rfed.distro.sync" => [claim]}]`;
 * without, LXMF's `[timebase, [lxmf_data]]`. Throws when the stamp is not 32
 * bytes or RFed would refuse the claim (LXMF-rust sealed_upload).
 */
export function buildSealedUpload(sealed, stamp, claim = null, timebase = Date.now() / 1000) {
    const message = bytes(sealed);
    if (message.length <= DEST_HASH_LEN) throw new Error(`a sealed message is longer than ${DEST_HASH_LEN} bytes, this is ${message.length}`);
    if (stamp?.length !== STAMP_LEN) throw new Error(`a propagation stamp is ${STAMP_LEN} bytes, this is ${stamp?.length}`);
    const lxmfData = Buffer.concat([message, bytes(stamp)]);
    if (!claim) return MsgPack.pack([timebase, [lxmfData]]);
    const refused = syncClaimRefusal(claim, message);
    if (refused) throw new Error(`the sync claim is not this message's: ${refused}`);
    return MsgPack.pack([timebase, [lxmfData], new Map([[DISTRO_SYNC_KEY, [claim.map(bytes)]]])]);
}
