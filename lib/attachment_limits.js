/**
 * What an outgoing message with attachments may weigh, checked in the
 * composer before anything is stored or sent, with a message that says which
 * limit and why.
 *
 * Every Retichat DM is sent direct and has its propagated copy behind it (or
 * goes propagated only, to a distro address), so both limits apply to it:
 *
 *   1. LXMF's delivery limit, 1,000,000 B of packed message
 *      (LXMRouter.DELIVERY_LIMIT, 1000 KB): the most any LXMF recipient takes,
 *      on every path. A direct Resource above it is refused at its
 *      advertisement (LXMRouter.py delivery_resource_advertised; this client
 *      too since e9979c8), and a recipient fetching from its propagation node
 *      asks only for messages within it (message_get_request's
 *      delivery_per_transfer_limit). Nothing larger reaches anyone.
 *   2. The propagation node's per-sync limit, from its announce
 *      ([3] per-transfer and [4] per-sync, in KB of 1000 B;
 *      LXMF.pn_announce_data_is_valid): the node refuses an upload whose
 *      Resource is larger (LXMRouter.py propagation_resource_advertised, and
 *      RFed-rust inbound_resource_callbacks, the same rule). The per-transfer
 *      limit is not the upload's: it binds the node's own sync to its peers
 *      (LXMPeer.sync, rfed plan_offer), and the reference client does not
 *      apply it to its own upload (LXMRouter.process_outbound, PROPAGATED).
 *      A message above it is still delivered to recipients of this node.
 *
 * Photos go at their original size (James, 2026-09-30): nothing is
 * downscaled, so a file over these limits is refused, honestly, in front of
 * the user.
 *
 * Nothing here touches a Node-only global at module load.
 */
import MsgPack from "./rns/msgpack.js";
import { FIELD_FILE_ATTACHMENTS, FIELD_TICKET } from "./rns/lxmf/lxmf.js";

/** iOS ConversationView's PhotosPicker maxSelectionCount. */
export const MAX_ATTACHMENTS = 5;

/** Destination, source and signature ahead of the msgpack payload. */
export const LXMF_PACKING_OVERHEAD = 16 + 16 + 64;

/** The most the Message Display Name adds (0xD1 {0: bin}): key 2, map 1,
 *  key 1, and at most 64 scalars of UTF-8 (display_name.js MAX_SCALARS),
 *  256 bytes, which takes a bin16 header (3: bin8 holds 255). Left out of
 *  the estimate's fields, so counted here. */
export const NAME_FIELD_MAX = 2 + 1 + 1 + 3 + 64 * 4;

/** What the propagation upload adds to the packed message (app.js
 *  _buildPropagationPacked): Identity.encrypt's ephemeral key 32, token IV
 *  16, HMAC 32 and PKCS7 padding up to 16; the stamp 32; msgpack
 *  [float64, [bin32]] 16. */
export const PROPAGATION_UPLOAD_OVERHEAD = 32 + 16 + 32 + 16 + 32 + 16;

/** Bytes in LXMF's units (KB and MB of 1000 B, as the limits are announced). */
export function formatSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1000) return `${n} B`;
    if (n < 1000 * 1000) return `${Math.round(n / 1000)} KB`;
    return `${(n / 1e6).toFixed(n < 10e6 ? 2 : 1)} MB`;
}

/**
 * The packed size of a DM carrying `content` and `attachments`
 * ([{name, bytes}]): the LXMF packing as app.js _sendPacket builds it, with
 * its ticket, plus the most the display name can add.
 */
export function estimatePackedSize(content, attachments, timestamp = Date.now() / 1000) {
    const fields = new Map([[FIELD_TICKET, "0".repeat(16)]]);
    if (attachments?.length) {
        fields.set(FIELD_FILE_ATTACHMENTS, attachments.map((a) => [String(a.name), a.bytes]));
    }
    const payload = MsgPack.pack([timestamp, new Uint8Array(0), new TextEncoder().encode(String(content ?? "")), fields]);
    return LXMF_PACKING_OVERHEAD + payload.length + NAME_FIELD_MAX;
}

/**
 * Why a DM of `packedSize` bytes with `count` attachments cannot be sent,
 * or null when it can. `deliveryLimit` is LXMF's (bytes); `perSyncKb` the
 * propagation node's announced per-sync limit, null while unknown.
 */
export function attachmentRefusal({ count = 0, packedSize, deliveryLimit, perSyncKb = null }) {
    if (count > MAX_ATTACHMENTS) {
        return `At most ${MAX_ATTACHMENTS} attachments go in one message.`;
    }
    if (packedSize > deliveryLimit) {
        return `This message would be ${formatSize(packedSize)}. An LXMF message can be at most `
            + `${formatSize(deliveryLimit)}, the most any recipient accepts; photos are sent at their original size, `
            + `so send fewer or smaller files.`;
    }
    const perSync = Number(perSyncKb);
    if (perSyncKb !== null && Number.isFinite(perSync) && perSync >= 0) {
        const upload = packedSize + PROPAGATION_UPLOAD_OVERHEAD;
        if (upload > perSync * 1000) {
            return `This message would be ${formatSize(upload)} to upload. Your propagation node takes at most `
                + `${formatSize(perSync * 1000)} at a time (its announced limit), so it could not hold the copy `
                + `that reaches the recipient when they are offline.`;
        }
    }
    return null;
}
