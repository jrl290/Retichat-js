import MsgPack from "../msgpack.js";
import { announceNameFromAppData, stripOwnHashSuffix } from "../../display_name.js";
import { FIELD_RETICHAT } from "../../retichat_field.js";
import { DISTRO_CHANNEL_TYPE, readChannelSync } from "../../channel_sync.js";

/** The OLD top-level fields of the group chat protocol, 0xA0-0xA8.
 *  LXMF-rust/DISPLAY_NAMES.md §10: group entries move to keys 1-9 of the
 *  Retichat field 0xD1. Read and write them only through retichat_field.js
 *  (readGroupEntry / applyGroupFields), which take either form; these
 *  numbers remain for that transition. */
export const GROUP_FIELDS = {
    GROUP_ID:       0xA0,  // groupId — 32-char hex
    GROUP_MEMBERS:  0xA1,  // groupMembers — comma-separated hex hashes (invite only)
    GROUP_NAME:     0xA2,  // groupName — UTF-8
    GROUP_ACTION:   0xA3,  // groupAction — "invite" | "accept" | "leave" | "relay_req" | "relay_done"
    GROUP_SENDER:   0xA4,  // groupSender — original sender hex (may differ from LXMF src)
    GROUP_RELAY_SEEN: 0xA5, // groupRelaySeen — comma-sep hashes already delivered
    GROUP_RELAY_FOR:  0xA6, // groupRelayFor — hash being relayed for
    GROUP_RELAY_DONE: 0xA7, // groupRelayDone — bool
    GROUP_MEMBER_KEYS: 0xA8, // groupMemberKeys — one hash:base64-public-key pair per invite chunk
};

/** LXMF/LXMF.py field numbers for what a message carries besides its text. */
export const FIELD_FILE_ATTACHMENTS = 0x05; // [[filename(str), data(bin)], ...]
export const FIELD_IMAGE = 0x06;            // [image_type(str), data(bin)]
export const FIELD_AUDIO = 0x07;            // [audio_mode(int), data(bin)]
export const FIELD_TICKET = 0x0C;

/** The extensions shown as an image: iOS Attachment.isImage (Models.swift
 *  246-251), the list Android shows inline as well. Anything else is a file. */
export const IMAGE_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp", "heic"];

const MIME_BY_EXTENSION = {
    jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif",
    webp: "image/webp", heic: "image/heic",
    pdf: "application/pdf", txt: "text/plain", json: "application/json", zip: "application/zip",
    ogg: "audio/ogg", opus: "audio/ogg", mp3: "audio/mpeg", m4a: "audio/mp4", wav: "audio/wav",
    mp4: "video/mp4", mov: "video/quicktime",
};

/** The lowercase extension of a filename, "" when it has none. */
export function extensionOf(name) {
    const s = String(name ?? "");
    const dot = s.lastIndexOf(".");
    return dot > 0 && dot < s.length - 1 ? s.slice(dot + 1).toLowerCase() : "";
}

/** A MIME type for a filename, by its extension. */
export function mimeForName(name) {
    return MIME_BY_EXTENSION[extensionOf(name)] ?? "application/octet-stream";
}

/** Whether a stored attachment is shown as an image: every FIELD_IMAGE,
 *  and a file whose name has one of iOS's image extensions. */
export function isImageAttachment({ name, field } = {}) {
    return field === FIELD_IMAGE || IMAGE_EXTENSIONS.includes(extensionOf(name));
}

/** LXMF/LXMF.py audio modes: Codec2 0x01-0x09, Opus (in OGG) 0x10-0x19. */
function audioFile(mode) {
    if (Number.isInteger(mode) && mode >= 0x10 && mode <= 0x19) return { name: "audio.ogg", mime: "audio/ogg" };
    if (Number.isInteger(mode) && mode >= 0x01 && mode <= 0x09) return { name: "audio.c2", mime: "application/octet-stream" };
    return { name: "audio.bin", mime: "application/octet-stream" };
}

const asBytes = (v) => (v instanceof Uint8Array ? v : null);
const asText = (v) => {
    if (typeof v === "string") return v;
    if (v instanceof Uint8Array) return new TextDecoder().decode(v);
    return null;
};

/**
 * The attachments a received message carries, from its decoded fields map:
 *   FIELD_FILE_ATTACHMENTS 0x05 = [[filename, data], ...] — what iOS and
 *     Android send (iOS LxmfFieldsDecoder, Android LxmfFields.kt
 *     getFileAttachments: a filename that is neither str nor bin is
 *     "attachment.bin", a pair whose data is not bin is skipped);
 *   FIELD_IMAGE 0x06 = [image_type, data] — Sideband and MeshChat; its name
 *     is the image type as sent ("png");
 *   FIELD_AUDIO 0x07 = [audio_mode, data] — offered as a file.
 * The web shows 0x06 and offers 0x07 although iOS and Android read only 0x05:
 * showing what the sender sent outranks parity (James, 2026-09-30).
 *
 * Returns [{name, mime, bytes, field}]. It never throws: an entry that is not
 * of that shape is skipped and counted in the list's `skipped` property (not
 * enumerable), and the message keeps everything else — a hostile fields map
 * costs the attachments, never the message (Android dcc3e46, 702e5fb).
 */
export function attachmentsFromFields(fields) {
    const out = [];
    let skipped = 0;
    if (fields instanceof Map) {
        try {
            if (fields.has(FIELD_FILE_ATTACHMENTS)) {
                const files = fields.get(FIELD_FILE_ATTACHMENTS);
                if (!Array.isArray(files)) {
                    skipped++;
                } else {
                    for (const entry of files) {
                        const bytes = Array.isArray(entry) && entry.length >= 2 ? asBytes(entry[1]) : null;
                        if (!bytes) { skipped++; continue; }
                        const name = asText(entry[0]) || "attachment.bin";
                        out.push({ name, mime: mimeForName(name), bytes, field: FIELD_FILE_ATTACHMENTS });
                    }
                }
            }
            if (fields.has(FIELD_IMAGE)) {
                const image = fields.get(FIELD_IMAGE);
                const bytes = Array.isArray(image) && image.length >= 2 ? asBytes(image[1]) : null;
                if (!bytes) {
                    skipped++;
                } else {
                    const type = (asText(image[0]) || "").trim();
                    const ext = type.toLowerCase().replace(/^image\//, "");
                    out.push({
                        name: type || "image",
                        // The type is the sender's string, so the MIME type
                        // comes from our own table of raster images and is
                        // never built from it: "svg+xml" made image/svg+xml,
                        // a document whose script runs on this page's origin
                        // (and reads the identity key) when the image is
                        // opened in a tab. An <img> decodes a raster image
                        // whatever its blob type, so nothing is lost.
                        mime: MIME_BY_EXTENSION[ext]?.startsWith("image/") ? MIME_BY_EXTENSION[ext] : "application/octet-stream",
                        bytes,
                        field: FIELD_IMAGE,
                    });
                }
            }
            if (fields.has(FIELD_AUDIO)) {
                const audio = fields.get(FIELD_AUDIO);
                const bytes = Array.isArray(audio) && audio.length >= 2 ? asBytes(audio[1]) : null;
                if (!bytes) {
                    skipped++;
                } else {
                    out.push({ ...audioFile(Number(audio[0])), bytes, field: FIELD_AUDIO });
                }
            }
        } catch (e) {
            // A Map whose accessors throw: what was read so far stands.
            skipped++;
        }
    }
    Object.defineProperty(out, "skipped", { value: skipped, enumerable: false });
    return out;
}

/** True when the fields carry 0x05, 0x06 or 0x07, whatever is in them
 *  (LXMF-rust distro.rs carries_attachment, 06c40e1). */
export function carriesAttachment(fields) {
    if (!(fields instanceof Map)) return false;
    return fields.has(FIELD_FILE_ATTACHMENTS) || fields.has(FIELD_IMAGE) || fields.has(FIELD_AUDIO);
}

class LXMF {

    static FIELD_FILE_ATTACHMENTS = FIELD_FILE_ATTACHMENTS;
    static FIELD_IMAGE = FIELD_IMAGE;
    static FIELD_AUDIO = FIELD_AUDIO;
    static FIELD_TICKET = FIELD_TICKET;

    /** See attachmentsFromFields. */
    static attachmentsFromFields(fields) {
        return attachmentsFromFields(fields);
    }

    /**
     * A delivery notification: a message with a ticket (0x0C), no content
     * and no attachment; the apps drop anything so flagged. The web sent
     * such a reply to every ticketed link message until 2026-10-01, never
     * one that parsed (lxmf_router.js handleLinkPayload: LXMF has no ticket
     * reply, it remembers the ticket). A message carrying 0x05, 0x06 or
     * 0x07 is always a message, never a notification, ticket or not: LXMF-rust distro.rs
     * is_delivery_notification since 06c40e1, where a captionless photo from
     * a sender that includes its ticket (LXMF include_ticket) vanished.
     */
    static isDeliveryNotification(fields, content) {
        if (!(fields instanceof Map) || !fields.has(FIELD_TICKET) || fields.get(FIELD_TICKET) == null) return false;
        if (content != null && String(content).length > 0) return false;
        return !carriesAttachment(fields);
    }

    /**
     * This client's own ticket in a fields map, or null. The web sends 8
     * random bytes as 16 lowercase hex characters, a msgpack str
     * (app.js _sendPacket), and a reply carries it back as it came; one
     * that comes back as 8 bytes of bin is read as their hex. Anything else
     * — the reference's [expires, ticket(16 bytes)] (LXMF include_ticket)
     * above all — is not one of ours and must never be looked up as one.
     */
    static webTicket(fields) {
        if (!(fields instanceof Map)) return null;
        const v = fields.get(FIELD_TICKET);
        if (typeof v === "string") return /^[0-9a-f]{16}$/.test(v) ? v : null;
        if (v instanceof Uint8Array && v.length === 8) {
            return Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
        }
        return null;
    }

    /** Upstream LXMF custom-field pair (LXMF.FIELD_CUSTOM_TYPE / _DATA). */
    static FIELD_CUSTOM_TYPE = 0xFB;
    static FIELD_CUSTOM_DATA = 0xFC;

    /** FIELD_CUSTOM_TYPE value marking a distro identity transfer; the
     *  private key (128-char hex) travels in FIELD_CUSTOM_DATA. RFed SPEC
     *  §17.9. Field 0x0D is upstream's FIELD_EVENT and is never used for this. */
    static DISTRO_TRANSFER_TYPE = "rfed.distro.transfer";

    /** Upstream LXMF.FIELD_CUSTOM_META, completing the custom-field triple. */
    static FIELD_CUSTOM_META = 0xFD;

    /** FIELD_CUSTOM_TYPE value marking a sent-message copy (RFed SPEC §17.11).
     *  A device that sends as its distro D also propagates a copy to D so the
     *  other devices of D see what "I" said: FIELD_CUSTOM_DATA is the
     *  recipient's address, FIELD_CUSTOM_META the sending device's own
     *  lxmf.delivery address. Same constant as LXMF-rust distro.rs
     *  DISTRO_SENT_TYPE, which the Android and iOS clients read. */
    static DISTRO_SENT_TYPE = "rfed.distro.sent";

    /** FIELD_CUSTOM_TYPE value marking a channel membership message (RFed
     *  SPEC §17.12): a device holding distro D that joins or leaves a channel
     *  by the user's own action sends one to D, and every sibling joins or
     *  leaves it too. FIELD_CUSTOM_DATA is [op, name, at_ms], FIELD_CUSTOM_META
     *  the sending device's own lxmf.delivery address (lib/channel_sync.js).
     *  The string SPEC §17.12's index gives LXMF-rust distro.rs as
     *  DISTRO_CHANNEL_TYPE, for the phones. */
    static DISTRO_CHANNEL_TYPE = DISTRO_CHANNEL_TYPE;

    /** supported_functionality entry marking an rfed distro address in its
     *  lxmf.delivery announce. RFed SPEC §17.10. */
    static SF_RFED_DISTRO = 0xD0;

    /** Field 0xD1, FIELD_RETICHAT (LXMF-rust/DISPLAY_NAMES.md §2.1, §10): a
     *  map whose key 0 is the display name and keys 1-9 the group entries.
     *  The retired 0x10 (FIELD_SENDER_NAME) is neither sent nor read. */
    static FIELD_RETICHAT = FIELD_RETICHAT;

    /**
     * The announce name in lxmf.delivery app_data (DISPLAY_NAMES.md §2.2,
     * §5.1): the first element of the 0.5.0+ list, or the whole of the
     * original raw format, cleaned (§3), "Anonymous Peer" as none. null when
     * the announce carries no name. With `destHash`, the announcing
     * destination's hash, the old web announce suffix is stripped (§5.4,
     * stripOwnHashSuffix): until 2026-09-23 the web announced "<name> (" +
     * the first 12 hex of that hash + ")".
     */
    static displayNameFromAppData(appData, destHash = null) {
        return stripOwnHashSuffix(announceNameFromAppData(appData), destHash);
    }

    /**
     * True iff the announce app_data is an LXMF 0.5.0+ list whose third
     * element (supported_functionality) is a list containing SF_RFED_DISTRO.
     * The announce is the only source of truth for "this is a distro".
     */
    static distroFromAppData(appData) {
        try {

            // ensure app data provided
            if(appData == null || appData.length === 0){
                return false;
            }

            // only the version 0.5.0+ list format can carry the flag
            if(!((appData[0] >= 0x90 && appData[0] <= 0x9f) || appData[0] === 0xdc)){
                return false;
            }

            const unpacked = MsgPack.unpack(appData);
            if(!Array.isArray(unpacked) || unpacked.length < 3) return false;
            const functionality = unpacked[2];
            if(!Array.isArray(functionality)) return false;
            return functionality.includes(LXMF.SF_RFED_DISTRO);

        } catch(e) {
            return false;
        }
    }

    /**
     * The distro private key (128-char hex) if these fields carry a distro
     * identity transfer, otherwise null. A transfer is recognised only by
     * FIELD_CUSTOM_TYPE == DISTRO_TRANSFER_TYPE; the key is FIELD_CUSTOM_DATA.
     * Values may arrive as msgpack str (string) or bin (Uint8Array).
     */
    static distroTransferKeyFromFields(fields) {
        if (!fields || !(fields instanceof Map)) return null;
        const decode = (v) => {
            if (v == null) return null;
            if (v instanceof Uint8Array) return new TextDecoder().decode(v);
            return String(v);
        };
        if (decode(fields.get(LXMF.FIELD_CUSTOM_TYPE)) !== LXMF.DISTRO_TRANSFER_TYPE) return null;
        return decode(fields.get(LXMF.FIELD_CUSTOM_DATA));
    }

    /**
     * The RFed SPEC §17.11 sent-copy marker, or null when these fields carry
     * none. A copy is recognised only by FIELD_CUSTOM_TYPE == DISTRO_SENT_TYPE.
     *
     * Returns { toHex, byHex } once the type matches, mirroring LXMF-rust
     * distro.rs sent_to / sent_by exactly so all three clients judge a copy
     * the same way:
     *   - toHex is FIELD_CUSTOM_DATA lowercased, and only when that is exactly
     *     32 hex characters; otherwise null. "Marker present, toHex null"
     *     is how a receiver tells a malformed copy (drop and log) from an
     *     unmarked message (today's behaviour).
     *   - byHex is FIELD_CUSTOM_META lowercased, "" when absent. It is not
     *     format-checked: a malformed one simply never equals this device's
     *     own address.
     * Values may arrive as msgpack str (string) or bin (Uint8Array), like
     * distroTransferKeyFromFields.
     */
    static distroSentCopyFromFields(fields) {
        if (!fields || !(fields instanceof Map)) return null;
        const decode = (v) => {
            if (v == null) return null;
            if (v instanceof Uint8Array) return new TextDecoder().decode(v);
            return String(v);
        };
        if (decode(fields.get(LXMF.FIELD_CUSTOM_TYPE)) !== LXMF.DISTRO_SENT_TYPE) return null;
        const to = (decode(fields.get(LXMF.FIELD_CUSTOM_DATA)) ?? "").toLowerCase();
        const by = (decode(fields.get(LXMF.FIELD_CUSTOM_META)) ?? "").toLowerCase();
        return {
            toHex: /^[0-9a-f]{32}$/.test(to) ? to : null,
            byHex: by,
        };
    }

    /**
     * The RFed SPEC §17.12 membership marker of a received message, read
     * from its packed payload bytes (lib/channel_sync.js readChannelSync):
     * null when it carries none; { byHex, sync: {op, name, atMs} | null,
     * problem } once FIELD_CUSTOM_TYPE is DISTRO_CHANNEL_TYPE, sync null when
     * FIELD_CUSTOM_DATA is unusable (dropped and logged, never shown). From
     * the bytes, not a decoded fields map, so an at_ms sent as a float is
     * refused here as LXMF-rust refuses it.
     */
    static distroChannelSyncFromPayload(packedPayload) {
        return readChannelSync(packedPayload);
    }

}

export default LXMF;
