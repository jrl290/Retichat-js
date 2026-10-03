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
 * up, and otherwise when the link next comes up ("established", or
 * "recovered" from STALE). Those two events and the proof are the only
 * triggers: no timer, no retry loop (DESIGN_PRINCIPLES §5).
 *
 * An upload that was not proved (its packet reported lost, its link
 * closed, the connection stopped: the three events James's text names)
 * leaves the entry owed, and it is uploaded again when the link next comes
 * up. That second upload is a send retry, which DESIGN_PRINCIPLES §3
 * forbids but for the exceptions James decides; this is one he decided on
 * 2026-10-03 ("what a device owes its distro", §3; RFed SPEC §17.12 "On
 * the sending device"), and it covers these two messages only. It stays
 * on events, never a timer: the link's "established" or "recovered" after
 * the failure, never the failure itself, and never an earlier flush still
 * building (app.js _distroFlush). At most one upload of an entry is in
 * flight at a time: while one has left and is not decided, no flush
 * uploads it, on its link or on a new one that replaced that link while
 * it was STALE (app.js _distroOutboxInFlight). Being replaced decides
 * nothing; the old link's own close does, if no proof came first. Only the
 * newest action per channel is ever owed, so what goes again is never an
 * action the user has since undone.
 *
 * What a distro this device gives up was owed (D forgotten, or another
 * distro generated or imported) is dropped then, with a log line
 * (dropAllBut, from app.js RnsClient._dropOwedToOtherDistros): never kept
 * in case D comes back, never sent under another distro (§17.12).
 *
 * Each entry keeps its LXMF message as it was packed and signed by D when
 * the user acted, never packed again, so every upload of it is one and the
 * same message: a sibling that gets it twice (the node had an upload whose
 * proof never reached this tab) holds the second as a repeat (app.js
 * DistroSeen, by source and timestamp, and for C the message hash too).
 *
 * Read and written through `storage` on every use, so a tab that takes the
 * connection over from another sees what that one still owes. Storage that
 * refuses a write (a full localStorage: app.js sSet drops it without a
 * word) is found by reading the write back, and from then on this page
 * holds the outbox itself, the refused change included, so what the user
 * did last is what goes while the page is open. What storage still holds
 * is then cut down to what this page still owes, a write never larger than
 * what storage holds, so an entry replaced, proved or dropped never goes
 * from a later page either (_write). Entries are plain JSON:
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
    /**
     * `storage` is { get(key), set(key, value) } holding JSON values, as
     * name_ledger.js takes. `log` gets the line said when storage keeps an
     * entry that is owed no more (_write).
     */
    constructor(storage, { log = console } = {}) {
        this.storage = storage;
        this._log = log;
        // What this page owes, held here once storage refused a write
        // (_write); null while storage holds it all.
        this.held = null;
    }

    /** Every entry owed, oldest first. Anything stored that is not an entry is ignored. */
    list() {
        if (this.held) return [...this.held];
        return this._stored();
    }

    /** The entries storage holds, whatever this page holds. */
    _stored() {
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
     * Returns whether storage kept it.
     *
     * When storage refuses it, this page holds the outbox with the entry in
     * it, so it goes when the propagation link is up while the page is
     * open, and the one it replaced never goes from this page. The one it
     * replaced is taken out of storage too (_write), so a later page does
     * not send an action the user has since undone either; it gets
     * neither, and the refusal is said by the caller (app.js _oweDistro).
     * Until 2026-10-03 (review of 73a725d) the replaced entry stayed owed:
     * the user's join went to the siblings after the user had left.
     */
    put(entry) {
        if (!isEntry(entry)) throw new Error("not an entry the distro can be owed");
        const others = this.list().filter((e) => e.id !== entry.id);
        return this._write([...others, entry]);
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
        this._write(kept);
        return true;
    }

    /**
     * The distro this device holds is now `distro` (D's lxmf.delivery
     * hash), or none (null): every entry owed to another distro is owed no
     * more, and is dropped now (RFed SPEC §17.12 "On the sending device").
     * Returns the entries dropped, for the caller to say (app.js
     * RnsClient._dropOwedToOtherDistros).
     */
    dropAllBut(distro) {
        const rows = this.list();
        const dropped = rows.filter((e) => e.distro !== distro);
        if (dropped.length) this._write(rows.filter((e) => e.distro === distro));
        return dropped;
    }

    /**
     * Store `rows` as what is owed, and read it back: storage that kept it
     * is the outbox again. Storage that refused it leaves this page holding
     * `rows` (this.held), and what storage still holds is cut down to the
     * entries `rows` has. That write is never larger than what storage
     * holds, so a full localStorage takes it, and storage then holds
     * nothing this page has replaced, settled or dropped: a later page
     * never sends an action the user has since undone. Until 2026-10-03 it
     * wrote what this page held, less the replaced entry, which could be
     * larger than what storage held once the page held a refused entry; a
     * full storage refused it too and kept the replaced C for the next
     * page (SPEC §17.12 "Retichat-js departures"). Storage that refuses
     * even that write is said here: what it still holds that is owed no
     * more would go from a later page. Returns whether storage kept `rows`.
     */
    _write(rows) {
        this.storage.set(OUTBOX_KEY, rows);
        if (JSON.stringify(this.storage.get(OUTBOX_KEY)) === JSON.stringify(rows)) {
            this.held = null;
            return true;
        }
        this.held = rows;
        const owes = (e) => rows.some((r) => r.id === e.id && r.packed === e.packed);
        const stored = this._stored();
        const keep = stored.filter(owes);
        if (keep.length === stored.length) return false;
        this.storage.set(OUTBOX_KEY, keep);
        const left = this._stored().filter((e) => !owes(e));
        if (left.length) {
            this._log.error?.(`[distro] ✗ Storage refuses even a smaller write: it still holds ${left.map((e) => e.label).join(", ")}, `
                + "owed no more, which a later page would send");
        }
        return false;
    }
}
