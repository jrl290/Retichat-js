/**
 * MEMBER STATUSES AND KEYS — RFed-spec Group.md, "Member statuses and keys
 * (2026-10-06)"; LXMF-rust/DISPLAY_NAMES.md §10 key 10. The pure half the
 * phones port: what an accept or leave carries, how that key is bound, and
 * what a message is worth by its signature. Which group a message is about,
 * who may send it and what it changes are app.js's (PrivacyFilter, GroupStore,
 * RnsClient); the packed messages a creator keeps and answers with are its.
 *
 * The sender's key. Every accept and leave (a decline is a leave) carries
 * GROUP_MEMBER_KEYS with exactly one entry, its sender's own
 * `hash:base64-public-key`, in the form an invite chunk uses. It is bound as
 * an invite chunk's key is: the key's lxmf.delivery destination must be the
 * entry's hash, and the entry's hash must be the message's LXMF source
 * (boundSenderKey).
 *
 * Verifying an accept or leave. Verified: its LXMF signature is valid under
 * its sender's key, one the receiver holds (an announce, an invite chunk) or
 * the one the message carries, once bound. LXMessage.fromBytes does it for
 * every message that reaches the app, so signatureState is "validated" for a
 * carried key as for a held one. Forged ("invalid"): the signature does not
 * verify under a held or a bound key. Unverifiable ("unknown"): no key held,
 * none carried, or the carried one does not bind.
 *
 * What it is worth (statusChangeVerdict): a verified message counts under the
 * group rules; a forged one is ignored; an unverifiable one counts until the
 * switch (GROUP_ENTRIES_IN_RETICHAT_FIELD, around 2026-10-26), exactly as the
 * phones count it, and from the switch is held until its sender's key arrives
 * (RnsClient._holdGroupStatusChange). James, 2026-10-06.
 *
 * No timers and no retries (DESIGN_PRINCIPLES.md §1, §3): nothing here waits.
 */
import { Buffer } from "buffer";
import Identity from "./rns/identity.js";
import Destination from "./rns/destination.js";

/** The longest payload of an accept or leave worth keeping or passing on, as
 *  GroupStore.HELD_PAYLOAD_LIMIT: a genuine one holds no content, so its
 *  payload (group id, action and sender, a name of at most 64 characters, a
 *  ticket) is a few hundred bytes. */
export const STATUS_PAYLOAD_LIMIT = 2048;

/** destination (16) + source (16) + signature (64). */
export const PACKED_HEADER_LENGTH = 96;

/** The longest packed accept or leave: a status element over this is
 *  skipped, and a creator keeps no copy of one. */
export const STATUS_PACKED_LIMIT = PACKED_HEADER_LENGTH + STATUS_PAYLOAD_LIMIT;

/**
 * One GROUP_MEMBER_KEYS entry, `hash:base64-public-key`: the form an invite
 * chunk uses (RnsClient._groupMemberKeys) and an accept or leave carries for
 * its own sender. `publicKeyHex` is the 64-byte public key as hex.
 */
export function senderKeyEntry(hash, publicKeyHex) {
    return `${hash}:${Buffer.from(publicKeyHex, "hex").toString("base64")}`;
}

/** The lxmf.delivery destination hash (hex) of the 64-byte `publicKey`. */
export function deliveryHashOf(publicKey) {
    return Destination.hash(Identity.fromPublicKey(Buffer.from(publicKey)), "lxmf", "delivery").toString("hex");
}

/**
 * The key a message carries for its own sender, when it binds: `memberKeys`
 * (LXMessage.extractGroupFields: hash to base64 key, every pair well formed)
 * has an entry for `source` (the LXMF source, hex), the key is 64 bytes, and
 * the lxmf.delivery destination it derives is `source`. An entry for any
 * other hash is not the sender's and is ignored, and so is one that does not
 * bind: the message is then as one that carried no key. Returns the Identity
 * the key loads as, or null.
 */
export function boundSenderKey(memberKeys, source) {
    const encoded = memberKeys instanceof Map && typeof source === "string" ? memberKeys.get(source.toLowerCase()) : undefined;
    if (typeof encoded !== "string") return null;
    try {
        const publicKey = Buffer.from(encoded, "base64");
        if (publicKey.length !== 64) return null;
        const identity = Identity.fromPublicKey(publicKey);
        return Destination.hash(identity, "lxmf", "delivery").toString("hex") === source.toLowerCase() ? identity : null;
    } catch {
        return null;
    }
}

/**
 * What an accept or leave is worth, from its signature state
 * (LXMessage.signatureState) and whether the switch has happened
 * (GROUP_ENTRIES_IN_RETICHAT_FIELD):
 *
 *   "validated"                    "count": under the group rules
 *   "invalid"                      "ignore": it is not its sender's
 *   "unknown", before the switch   "count": as the phones count it
 *   "unknown", from the switch     "hold": until its sender's key arrives
 *
 * Anything else (the router has not checked: null) is not counted.
 */
export function statusChangeVerdict(signature, switched) {
    if (signature === "validated") return "count";
    if (signature === "unknown") return switched ? "hold" : "count";
    return "ignore";
}

/**
 * The packed LXMF message of a received message, exactly as it was received:
 * destination (16) | source (16) | signature (64) | payload, the payload
 * with any stamp it came with. What a creator keeps of an accept or leave
 * and passes on in a `status`. Null when the message does not hold what its
 * signature covers (it was not parsed from bytes).
 */
export function packedMessage(message) {
    const { destinationHash, sourceHash, signature, packedPayload } = message ?? {};
    if (!destinationHash || !sourceHash || !signature || !packedPayload) return null;
    if (destinationHash.length !== 16 || sourceHash.length !== 16 || signature.length !== 64) return null;
    return Buffer.concat([Buffer.from(destinationHash), Buffer.from(sourceHash), Buffer.from(signature), Buffer.from(packedPayload)]);
}

/**
 * The packed message of a held accept or leave (GroupStore.hold: `dest` and
 * `signature` hex, `payload` base64 — the payload as signed, a stamp dropped —
 * and `src` hex): what a creator keeps once it counts.
 */
export function packedHeld(entry) {
    return Buffer.concat([
        Buffer.from(entry.dest, "hex"), Buffer.from(entry.src, "hex"),
        Buffer.from(entry.signature, "hex"), Buffer.from(entry.payload, "base64"),
    ]);
}
