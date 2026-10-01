/**
 * Conversation order: the order a DM, group or channel lists its messages.
 *
 * By `timestamp` (ms), oldest first; messages with equal timestamps in the
 * order they were stored (arrival). iOS sorts a conversation by timestamp
 * (SortDescriptor(\.timestamp)), Android queries it ORDER BY timestamp ASC
 * (MessageDao, ChannelDao). Since 2026-09-30 (8e2481c) a received record
 * carries its sender's time (sentTimeMs), so a message pulled late (a
 * propagated /get, /distro/pull, a channel page) belongs under its own day,
 * among the messages of its time, not at the bottom where it arrived.
 *
 * The stores (app.js MsgStore, GroupMsgStore, ChannelMsgStore) keep their
 * records in this order, so every reader (the open chat, the chat list's
 * preview, the date markers) sees one order without sorting.
 *
 * Where a conversation is listed and which of its records a full store lets
 * go are separate questions. The stores keep 500 records a conversation
 * (localStorage's budget; iOS and Android keep every message: iOS fetches
 * pages of 50 to show, ChatRepository.messages, and Android deletes only by
 * id or a whole chat, MessageDao, ChannelDao). The cap lets go of the records
 * that arrived first, as it did before conversations were ordered by time,
 * not of the oldest by time: a message is proved to its sender, purged from
 * the node and marked seen (LxmfSeen) before it is stored, so one that
 * arrived late, older than everything held, would otherwise be let go by the
 * next late one, unseen and beyond recovery (review, 2026-10-01).
 */

/**
 * Store `record` in `records`, which are in conversation order: after every
 * record whose timestamp is not later than its own (so after equal ones),
 * before the later ones. A record whose timestamp is not a number goes at
 * the end, where it arrived, and one already stored without a number is
 * never passed over.
 *
 * `record` is stamped with `arrival`, one more than any record held has: the
 * order the conversation's records were stored in. A record with no
 * `arrival` was stored before stamps existed, when a conversation was kept in
 * arrival order, so it counts as arriving before every stamped one, in the
 * order it is listed.
 *
 * `limit` caps how many are kept: the records that arrived first go,
 * wherever they are listed, so never `record` itself, the last to arrive
 * (for any limit of 1 or more). Returns what the cap dropped, first arrived
 * first ([] when nothing was).
 * @param {Array<{timestamp?: number, arrival?: number}>} records changed in place
 * @param {{timestamp?: number, arrival?: number}} record
 * @param {number} [limit]
 * @returns {Array} the dropped records
 */
export function addInOrder(records, record, limit = Infinity) {
    let last = -1;
    for (const r of records) if (Number.isInteger(r?.arrival) && r.arrival > last) last = r.arrival;
    record.arrival = last + 1;

    let at = records.length;
    const t = record.timestamp;
    if (Number.isFinite(t)) {
        while (at > 0 && Number.isFinite(records[at - 1]?.timestamp) && records[at - 1].timestamp > t) at--;
    }
    records.splice(at, 0, record);

    const excess = records.length - limit;
    if (!(excess > 0)) return [];
    const arrived = (r) => (Number.isInteger(r?.arrival) ? r.arrival : -1);
    const dropped = records
        .map((r, listed) => ({ r, listed }))
        .sort((a, b) => arrived(a.r) - arrived(b.r) || a.listed - b.listed)
        .slice(0, excess)
        .map(({ r }) => r);
    const gone = new Set(dropped);
    let kept = 0;
    for (const r of records) if (!gone.has(r)) records[kept++] = r;
    records.length = kept;
    return dropped;
}
