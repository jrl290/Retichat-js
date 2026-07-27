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
