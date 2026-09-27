import MsgPack from "../msgpack.js";
import { FIELD_DISPLAY_NAME, announceNameFromAppData } from "../../display_name.js";

/** LXMF custom field keys for group chat protocol.
 *  Matches Retichat iOS LxmfFields.swift field constants. */
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

class LXMF {

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

    /** supported_functionality entry marking an rfed distro address in its
     *  lxmf.delivery announce. RFed SPEC §17.10. */
    static SF_RFED_DISTRO = 0xD0;

    /** Field 0xD1, FIELD_DISPLAY_NAME (LXMF-rust/DISPLAY_NAMES.md §2.1).
     *  The retired 0x10 (FIELD_SENDER_NAME) is neither sent nor read. */
    static FIELD_DISPLAY_NAME = FIELD_DISPLAY_NAME;

    /**
     * The announce name in lxmf.delivery app_data (DISPLAY_NAMES.md §2.2,
     * §5.1): the first element of the 0.5.0+ list, or the whole of the
     * original raw format, cleaned (§3), "Anonymous Peer" as none. null when
     * the announce carries no name.
     */
    static displayNameFromAppData(appData) {
        return announceNameFromAppData(appData, (data) => MsgPack.unpack(data));
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

}

export default LXMF;
