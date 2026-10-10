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
 * "recovered" from STALE). Those two events, the exchange's return for an
 * upload that never left the device (below), and the proof are the only
 * triggers: no timer, no retry loop (DESIGN_PRINCIPLES §5).
 *
 * An upload that was not proved (its packet reported lost, its link
 * closed, the connection stopped) leaves the entry owed, and it is
 * uploaded again when the propagation link next comes up. That second
 * upload is a send retry, which DESIGN_PRINCIPLES §3 forbids but for the
 * exceptions James decides; this is one he decided on 2026-10-03 ("what a
 * device owes its distro", §3; RFed SPEC §17.12 "On the sending device"),
 * and it covers these two messages only. His rulings of that day:
 *   - the link comes up when a new propagation link is established, or a
 *     STALE one recovers when the node is heard from again;
 *   - an upload is never sent again on the strength of its own failure
 *     alone: a failure waits for the next coming-up, even when a flush is
 *     already running on the link that is up (UnprovedUploads below, held
 *     in app.js _distroUnproved; _propComingUps);
 *   - a STALE link replaced by a new one decides nothing, and keeps its
 *     grace for a late proof; when its own close then finds the upload not
 *     proved and a newer propagation link is up, that close is the event,
 *     and the entry goes once on the newer link (app.js _uploadOwed). The
 *     exchange's report that the upload's packet was lost counts the same
 *     as that close (James, 2026-10-04);
 *   - when the device forgets or replaces its distro, the membership
 *     messages it owed that distro are dropped; its sent-copies are still
 *     owed and still uploaded, to that distro;
 *   - an upload that never left the device, because no interface could
 *     carry it (the exchange refused its packet while down, or it was still
 *     queued when an exchange failed: PostInterface "lost", `unsent`), is not
 *     a failure: nothing was sent. It goes when the exchange is back, an
 *     event like the others (app.js _sendDistroNeverLeft, from
 *     _followExchange), as well as at the next coming-up, where a loss after
 *     the packet left still waits for the next coming-up, as above (James,
 *     2026-10-06: on staging a short network drop left the propagation link
 *     up, so no coming-up followed, and such an upload waited 35 s for an
 *     unrelated close). What is recorded for it is UnprovedUploads', below.
 * At most one upload of an entry is in flight at a time: while one has
 * left and is not decided, no flush uploads it, on its link or on a new one
 * that replaced that link while it was STALE (app.js _distroAttemptOpen).
 * Only the newest action per channel is ever owed, so what goes again is
 * never an action the user has since undone.
 *
 * The membership messages owed to a distro this device gives up (D
 * forgotten, or another distro generated or imported) are dropped then,
 * with a log line (dropMembershipNotFor, from app.js
 * RnsClient._dropMembershipOwedToOtherDistros): never kept in case D comes
 * back, never sent under another distro (§17.12). A sent-copy stays owed to
 * the distro it was made for: its entry carries that distro's public key
 * (`distroKey`), so it is encrypted to that distro and no other, and its
 * bytes are those packed and signed as that distro.
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
 *   { id, kind: "channel" | "sent", distro, distroKey, packed, label, ... }
 * `distro` is D's lxmf.delivery hash (32 lowercase hex), `distroKey` D's
 * public key (128 lowercase hex; absent from entries written before
 * 2026-10-03's review of 145ca2f), `packed` the LXMF message in base64,
 * `label` what the log lines call it; "channel" entries add
 * { op, name, at }, "sent" entries { to }. An entry owed since the distro
 * sync proof (RFed SPEC §17.13; DISTRO-SYNC-PROOF-DESIGN.md §5.1) also has
 * `sealed`, the message encrypted to the distro once when it was owed
 * (D_hash | D.encrypt(packed[16..])), and `syncSig`, D's signature over it
 * (lib/distro_sync.js), both base64, stored in the write that owes it so
 * every upload carries the same bytes and proof (app.js _uploadOwed). The
 * two come together, with `distroKey`, or not at all: an entry without them
 * (owed before, or one that could not be sealed) is built as before. The
 * proof is the entry's to carry, never what makes it one: a row whose pair
 * is broken (syncProofKept) is still owed, built as one without the pair,
 * and that is said; only its proof is lost, never the message.
 *
 * A stored row that is not an entry at all is said, once per page, and is
 * not sent; the next write of what is owed leaves it out (_stored).
 *
 * Nothing here touches a Node-only global at module load.
 */

const OUTBOX_KEY = "distro_outbox_v1";

const HEX32 = /^[0-9a-f]{32}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** The id of channel `channelHash`'s membership message: one per channel. */
export const channelSyncEntryId = (channelHash) => `channel:${channelHash}`;

/** The id of a sent-copy, from its LXMF message's hash (hex). */
export const sentCopyEntryId = (messageHashHex) => `sent:${messageHashHex}`;

/**
 * The distro sync proof kept with owed entry `e` (RFed SPEC §17.13):
 * "whole" when it carries `sealed` and `syncSig` both, as base64, with the
 * distro's key (`distroKey`); "none" when it carries neither (owed before
 * entries were sealed, or a message that could not be sealed); "broken"
 * otherwise (half of the pair, or a value that is not base64: a corrupted
 * or hand-edited row, or a writer that broke the pair). A broken proof
 * costs the proof alone, never the message: the row is still an entry, and
 * app.js _uploadOwed builds it as one owed before entries were sealed, and
 * says so. Until 2026-10-10 (review of Retichat-js 7b69904) a broken pair
 * made the row no entry: it was dropped without a word, and the next write
 * of the outbox erased the message from storage.
 */
export function syncProofKept(e) {
    if (e.sealed === undefined && e.syncSig === undefined) return "none";
    const whole = typeof e.sealed === "string" && BASE64.test(e.sealed)
        && typeof e.syncSig === "string" && BASE64.test(e.syncSig)
        && typeof e.distroKey === "string";
    return whole ? "whole" : "broken";
}

function isEntry(e) {
    return !!e && typeof e === "object"
        && typeof e.id === "string" && e.id.length > 0
        && (e.kind === "channel" || e.kind === "sent")
        && typeof e.distro === "string" && HEX32.test(e.distro)
        && (e.distroKey === undefined || (typeof e.distroKey === "string" && HEX128.test(e.distroKey)))
        && typeof e.packed === "string" && BASE64.test(e.packed)
        && typeof e.label === "string";
}

export class DistroOutbox {
    /**
     * `storage` is { get(key), set(key, value) } holding JSON values, as
     * name_ledger.js takes. `log` gets the line said when storage keeps an
     * entry that is owed no more (_write), and the one said for a stored
     * row that is not an entry (_stored).
     */
    constructor(storage, { log = console } = {}) {
        this.storage = storage;
        this._log = log;
        // What this page owes, held here once storage refused a write
        // (_write); null while storage holds it all.
        this.held = null;
        // The stored rows that are not entries this page has said (_stored).
        this._said = new Set();
    }

    /** Every entry owed, oldest first. Anything stored that is not an entry is ignored. */
    list() {
        if (this.held) return [...this.held];
        return this._stored();
    }

    /**
     * The entries storage holds, whatever this page holds. A stored row
     * that is not an entry (a corrupted or hand-edited one: no id, kind,
     * distro, message or label to send it by) is not sent, and the next
     * write leaves it out; that is said, once per page for each such row,
     * never silent.
     */
    _stored() {
        const rows = this.storage.get(OUTBOX_KEY);
        if (rows === null || rows === undefined) return [];
        if (!Array.isArray(rows)) {
            this._say(rows, "what storage holds of what is owed to the distro is not a list");
            return [];
        }
        const entries = rows.filter(isEntry);
        if (entries.length !== rows.length) {
            for (const row of rows.filter((r) => !isEntry(r))) {
                this._say(row, `storage holds a row of what is owed to the distro that is not an entry (${typeof row?.label === "string" ? row.label : typeof row?.id === "string" ? row.id : "no label"})`);
            }
        }
        return entries;
    }

    /** Says `what` about stored value `value`, once per page. */
    _say(value, what) {
        let key;
        try { key = JSON.stringify(value); } catch { key = String(value); }
        if (this._said.has(key)) return;
        this._said.add(key);
        this._log.error?.(`[distro] ✗ ${what}: it is not sent, and the next write of what is owed leaves it out`);
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
     * hash), or none (null): every membership message owed to another
     * distro is owed no more, and is dropped now (James, 2026-10-03; RFed
     * SPEC §17.12 "On the sending device"). Sent-copies are kept, whatever
     * distro they are owed to: each is still uploaded to its own. Returns
     * the entries dropped, for the caller to say (app.js
     * RnsClient._dropMembershipOwedToOtherDistros). Until 2026-10-03
     * (Retichat-js 3411e19, 145ca2f) this was dropAllBut, which dropped the
     * sent-copies too.
     */
    dropMembershipNotFor(distro) {
        const rows = this.list();
        const gone = (e) => e.kind === "channel" && e.distro !== distro;
        const dropped = rows.filter(gone);
        if (dropped.length) this._write(rows.filter((e) => !gone(e)));
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

/**
 * The messages owed to the distro whose last upload, or its build, was
 * decided not proved (its packet reported lost, its link closed, the
 * connection stopped, its build threw), each with the propagation link's
 * coming-up it was decided at (app.js RnsClient._propComingUps). A send
 * pass taken at a coming-up no later than that does not upload the
 * message, and the next coming-up does: an upload is never sent again on
 * the strength of its own failure alone (James, 2026-10-03;
 * DESIGN_PRINCIPLES §3, what a device owes its distro; app.js
 * _sendDistroOutbox, _unprovedSince, _uploadOwed).
 *
 * A record belongs to one message: the entry's id and the bytes packed
 * under it. One id (a channel's) may name several messages over time, a
 * join and then a leave, and the upload of each is decided on its own,
 * in any order: the older one's on the link it went on, which may close
 * long after the newer one's upload was reported lost. So each message
 * has its own record, and recording, reading or forgetting one never
 * replaces, reads or removes another's. Until 2026-10-04 (verifier of
 * Retichat-js 367b266, probe VR4-OW) the record was kept per id: the
 * older action's failure, decided after the newer action's, replaced the
 * newer one's record, and a send pass already under way uploaded the
 * newer message again at once on its own failure.
 *
 * What is recorded here is this page's alone (its coming-up counts start
 * at zero), so it lives in the page's memory, never in storage: a reload
 * starts with no record, and its first coming-up is the first link it
 * establishes, which sends everything owed.
 *
 * Apart from those failures, and held here so that forget() ends both, the
 * messages whose last upload never left the device (James, 2026-10-06; the
 * ruling above): nothing was sent, so that is no failure, no coming-up is
 * recorded for it, and a flush at a coming-up sends it like a message not
 * yet uploaded. The exchange's return sends it too (app.js
 * _sendDistroNeverLeft), and only while the record stands: an upload begun
 * for the message ends it (clearNeverLeft()), whatever becomes of that
 * upload, a loss being then a failure's record and waiting for the next
 * coming-up.
 */
export class UnprovedUploads {
    constructor() {
        // id → (packed → the coming-up the message's last failure was decided at)
        this._byId = new Map();
        // id → the packed messages whose last upload never left the device
        this._neverLeft = new Map();
    }

    /** The upload of the message `entry` ({ id, packed }) was decided not proved at coming-up `at`. */
    record(entry, at) {
        let messages = this._byId.get(entry.id);
        if (!messages) this._byId.set(entry.id, messages = new Map());
        messages.set(entry.packed, at);
    }

    /** The coming-up the last failure of the message `entry` was decided at, or undefined. */
    at(entry) {
        return this._byId.get(entry.id)?.get(entry.packed);
    }

    /** Whether the last failure of the message `entry` was decided at coming-up `comingUp` or later. */
    since(entry, comingUp) {
        const at = this.at(entry);
        return at !== undefined && at >= comingUp;
    }

    /**
     * The message `entry` is owed no more (proved, replaced by a later
     * action, dropped with its distro): its records go, the failure's and
     * the never-left one, and only its own.
     */
    forget(entry) {
        this.clearNeverLeft(entry);
        const messages = this._byId.get(entry.id);
        if (!messages?.delete(entry.packed)) return;
        if (messages.size === 0) this._byId.delete(entry.id);
    }

    /** How many messages have a failure record. */
    get size() {
        let size = 0;
        for (const messages of this._byId.values()) size += messages.size;
        return size;
    }

    /**
     * The last upload of the message `entry` never left the device: nothing
     * was sent, so it is no failure and no coming-up is recorded for it
     * (record() is for a failure, and is not called).
     */
    recordNeverLeft(entry) {
        let messages = this._neverLeft.get(entry.id);
        if (!messages) this._neverLeft.set(entry.id, messages = new Set());
        messages.add(entry.packed);
    }

    /** Whether the last upload of the message `entry` never left the device. */
    neverLeft(entry) {
        return this._neverLeft.get(entry.id)?.has(entry.packed) ?? false;
    }

    /**
     * An upload of the message `entry` begins: that its last one never left
     * decides nothing from now on. Only that message's own, as forget().
     */
    clearNeverLeft(entry) {
        const messages = this._neverLeft.get(entry.id);
        if (!messages?.delete(entry.packed)) return;
        if (messages.size === 0) this._neverLeft.delete(entry.id);
    }

    /** How many messages have a never-left record. */
    get neverLeftSize() {
        let size = 0;
        for (const messages of this._neverLeft.values()) size += messages.size;
        return size;
    }
}
