/**
 * What this device still owes its distro D: the messages it uploads for D
 * through the propagation node, each kept until the node proves it has it
 * (app.js RnsClient._oweDistro, _sendDistroOutbox, _uploadOwed).
 *
 *   - the RFed SPEC §17.12 membership message C, the newest action per
 *     channel only: a later join or leave of the same channel made on this
 *     device replaces the one still owed (its id is the channel's);
 *   - the §17.11 sent-copy of a message this device sent as D, one per
 *     message.
 *
 * Until 2026-10-03 both lived only in a promise waiting for the
 * propagation link (RnsClient._whenPropagationLinkUp, now gone). A device
 * that acted while the link was not up yet, or before the propagation
 * node's key was known, or whose tab stopped (taken over, reconnecting) or
 * closed first, lost the message without a word, and its siblings never
 * learned of the join or leave, or never showed the sent message. Now an
 * entry is written here before anything can yield, and leaves only when
 * the node proves the upload: it is sent when the user acts if the link is
 * up, and otherwise, or after an upload that was not proved, when the link
 * next comes up ("established", or "recovered" from STALE). Those two
 * events and the proof are the only triggers: no timer, no retry loop
 * (DESIGN_PRINCIPLES §3, §5).
 *
 * Each entry keeps its LXMF message as it was packed and signed by D when
 * the user acted, never packed again, so every upload of it is one and the
 * same message: a sibling that gets it twice (the node had an upload whose
 * proof never reached this tab) holds the second as a repeat (app.js
 * DistroSeen, by source and timestamp, and for C the message hash too).
 *
 * Read and written through `storage` on every use, so a tab that takes the
 * connection over from another sees what that one still owes. Entries are
 * plain JSON:
 *   { id, kind: "channel" | "sent", distro, packed, label, ... }
 * `distro` is D's lxmf.delivery hash (32 lowercase hex), `packed` the LXMF
 * message in base64, `label` what the log lines call it; "channel" entries
 * add { op, name, at }, "sent" entries { to }.
 *
 * Nothing here touches a Node-only global at module load.
 */

const OUTBOX_KEY = "distro_outbox_v1";

const HEX32 = /^[0-9a-f]{32}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** The id of channel `channelHash`'s membership message: one per channel. */
export const channelSyncEntryId = (channelHash) => `channel:${channelHash}`;

/** The id of a sent-copy, from its LXMF message's hash (hex). */
export const sentCopyEntryId = (messageHashHex) => `sent:${messageHashHex}`;

function isEntry(e) {
    return !!e && typeof e === "object"
        && typeof e.id === "string" && e.id.length > 0
        && (e.kind === "channel" || e.kind === "sent")
        && typeof e.distro === "string" && HEX32.test(e.distro)
        && typeof e.packed === "string" && BASE64.test(e.packed)
        && typeof e.label === "string";
}

export class DistroOutbox {
    /** `storage` is { get(key), set(key, value) } holding JSON values, as name_ledger.js takes. */
    constructor(storage) {
        this.storage = storage;
    }

    /** Every entry owed, oldest first. Anything stored that is not an entry is ignored. */
    list() {
        const rows = this.storage.get(OUTBOX_KEY);
        return Array.isArray(rows) ? rows.filter(isEntry) : [];
    }

    /** The entry owed under `id`, or null. */
    get(id) {
        return this.list().find((e) => e.id === id) ?? null;
    }

    /**
     * Owe `entry`. One already owed under its id (an earlier join or leave
     * of the same channel) is replaced, and the new one goes to the end.
     * Returns whether storage kept it: the page's storage drops a write it
     * cannot hold (app.js sSet, a full localStorage) without a word, so it
     * is read back.
     */
    put(entry) {
        if (!isEntry(entry)) throw new Error("not an entry the distro can be owed");
        const rows = this.list().filter((e) => e.id !== entry.id);
        rows.push(entry);
        this.storage.set(OUTBOX_KEY, rows);
        return this.get(entry.id)?.packed === entry.packed;
    }

    /**
     * The propagation node proved the upload of the message `packed`,
     * owed under `id` (or it is owed to a distro this device no longer
     * holds): it is owed no more. Only that message: one put under the
     * same id since (a later action on the channel) stays owed. Returns
     * true when an entry was dropped.
     */
    settle(id, packed) {
        const rows = this.list();
        const kept = rows.filter((e) => !(e.id === id && e.packed === packed));
        if (kept.length === rows.length) return false;
        this.storage.set(OUTBOX_KEY, kept);
        return true;
    }
}
