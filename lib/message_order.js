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
 */

/**
 * Store `record` in `records`, which are in conversation order: after every
 * record whose timestamp is not later than its own (so after equal ones),
 * before the later ones. A record whose timestamp is not a number goes at
 * the end, where it arrived, and one already stored without a number is
 * never passed over.
 *
 * `limit` caps how many are kept: the oldest go, never `record` itself (a
 * message older than all `limit` held is still stored, at the top). Returns
 * what the cap dropped, oldest first ([] when nothing was).
 * @param {Array<{timestamp?: number}>} records changed in place
 * @param {{timestamp?: number}} record
 * @param {number} [limit]
 * @returns {Array} the dropped records
 */
export function addInOrder(records, record, limit = Infinity) {
    let at = records.length;
    const t = record?.timestamp;
    if (Number.isFinite(t)) {
        while (at > 0 && Number.isFinite(records[at - 1]?.timestamp) && records[at - 1].timestamp > t) at--;
    }
    records.splice(at, 0, record);
    const excess = records.length - limit;
    if (!(excess > 0)) return [];
    if (at >= excess) return records.splice(0, excess);
    // `record` is among the oldest: it stays, the next-oldest go.
    const dropped = records.splice(0, excess + 1).filter((r) => r !== record);
    records.unshift(record);
    return dropped;
}
