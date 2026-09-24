import MsgPack from "../msgpack.js";

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

    /** supported_functionality entry marking an rfed distro address in its
     *  lxmf.delivery announce. RFed SPEC §17.10. */
    static SF_RFED_DISTRO = 0xD0;

    static displayNameFromAppData(appData) {
        try {

            // ensure app data provided
            if(appData == null || appData.length === 0){
                return null;
            }

            // version 0.5.0+ announce format
            if((appData[0] >= 0x90 && appData[0] <= 0x9f) || appData[0] === 0xdc){
                const [ displayName ] = MsgPack.unpack(appData);
                return displayName?.toString();
            }

            // original announce format
            return appData.toString();

        } catch(e) {
            console.log("failed to parse display name from app data", e);
            return null;
        }
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
     * Extract sender display name from LXMF message fields.
     * This is the preferred source — per-message, not broadcast.
     * Use this instead of displayNameFromAppData for privacy-preserving
     * name resolution.
     */
    static senderNameFromFields(fields) {
        try {
            if (!fields || !(fields instanceof Map)) return null;
            const val = fields.get(0x10);  // FIELD_SENDER_NAME
            if (val == null) return null;
            if (val instanceof Uint8Array) {
                return new TextDecoder().decode(val);
            }
            return String(val);
        } catch(e) {
            return null;
        }
    }

}

export default LXMF;
