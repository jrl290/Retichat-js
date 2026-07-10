import MsgPack from "../msgpack.js";

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
