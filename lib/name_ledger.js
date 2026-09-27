/**
 * The persistent halves of LXMF-rust/DISPLAY_NAMES.md for the web client:
 *
 *   NameLedger          §4.1 — per (source, recipient), the digest of the
 *                       name last confirmed delivered and when.
 *   ChannelPostNames    §4.2 — per channel, what this client last included in
 *                       its own posts, and which senders it has seen there.
 *   ChannelSenderNames  §5.1 — per (channel, sender), the Channel Display
 *                       Name that sender's posts carry. Never a contact name.
 *
 * Each takes a storage adapter { get(key), set(key, value) } holding JSON
 * values (app.js passes sGet/sSet over localStorage), so the tests run them
 * over a Map. The pure rules they apply are in display_name.js.
 */

import { decide, decideChannelPost, stateDigest, acceptChannelName, EMPTY_DIGEST } from "./display_name.js";

const LEDGER_KEY = "name_ledger_v1";
const CHANNEL_POST_KEY = "channel_post_names_v1";
const CHANNEL_NAMES_KEY = "channel_sender_names_v1";

/** Most senders remembered per channel. One dropped is "not seen before"
 *  again, which only costs an extra inclusion of the name. */
const SENDERS_PER_CHANNEL = 2000;

export class NameLedger {
    constructor(storage) {
        this.storage = storage;
        this.rows = {};
        const stored = storage.get(LEDGER_KEY);
        if (stored && typeof stored === "object") this.rows = stored;
    }

    static key(source, recipient) {
        return `${String(source).toLowerCase()}:${String(recipient).toLowerCase()}`;
    }

    /** { digest, confirmedAt } in seconds, or null. */
    lookup(source, recipient) {
        const row = this.rows[NameLedger.key(source, recipient)];
        return row && typeof row.digest === "string" && Number.isFinite(row.confirmedAt) ? row : null;
    }

    /** §4.1: the name state for the next message from `source` to `recipient`. */
    decideFor(messageName, source, recipient, nowSecs) {
        return decide(messageName, this.lookup(source, recipient), nowSecs);
    }

    /** §4.1: a message carrying `state` reached DELIVERED. Absent records nothing. */
    recordDelivered(source, recipient, state, nowSecs) {
        const digest = stateDigest(state);
        if (digest === null || !source || !recipient) return false;
        this.rows[NameLedger.key(source, recipient)] = { digest, confirmedAt: nowSecs };
        this.storage.set(LEDGER_KEY, this.rows);
        return true;
    }
}

export class ChannelPostNames {
    constructor(storage) {
        this.storage = storage;
        this.channels = {};
        const stored = storage.get(CHANNEL_POST_KEY);
        if (stored && typeof stored === "object") this.channels = stored;
    }

    _entry(channel) {
        let entry = this.channels[channel];
        if (!entry) {
            entry = { lastDigest: null, lastIncludedAt: 0, lastNewSenderAt: 0, senders: [] };
            this.channels[channel] = entry;
        }
        if (!Array.isArray(entry.senders)) entry.senders = [];
        return entry;
    }

    /** §4.2: the name state for the next post to `channel`. */
    decide(channel, channelName, nowMs) {
        return decideChannelPost(channelName, this.channels[channel] ?? null, nowMs);
    }

    /**
     * A post from `sender` arrived in `channel`. A sender not seen before
     * makes the next own post carry the name (§4.2 rule 2). `ownHash` is
     * never counted: this client's own echo is not a new reader.
     */
    noteSender(channel, sender, ownHash, nowMs) {
        if (!sender || sender === ownHash) return false;
        const entry = this._entry(channel);
        if (entry.senders.includes(sender)) return false;
        entry.senders.push(sender);
        if (entry.senders.length > SENDERS_PER_CHANNEL) entry.senders.splice(0, entry.senders.length - SENDERS_PER_CHANNEL);
        entry.lastNewSenderAt = nowMs;
        this.storage.set(CHANNEL_POST_KEY, this.channels);
        return true;
    }

    /** §4.2: the post carrying `state`, decided at `decidedAtMs`, was handed
     *  to RFed. Absent records nothing. */
    recordIncluded(channel, state, decidedAtMs) {
        const digest = stateDigest(state);
        if (digest === null) return false;
        const entry = this._entry(channel);
        entry.lastDigest = digest;
        entry.lastIncludedAt = decidedAtMs;
        this.storage.set(CHANNEL_POST_KEY, this.channels);
        return true;
    }

    forget(channel) {
        delete this.channels[channel];
        this.storage.set(CHANNEL_POST_KEY, this.channels);
    }
}

export class ChannelSenderNames {
    constructor(storage) {
        this.storage = storage;
        this.channels = {};
        const stored = storage.get(CHANNEL_NAMES_KEY);
        if (stored && typeof stored === "object") this.channels = stored;
    }

    /** The stored { name, at } for (channel, sender), or null. Entries
     *  saved before the order rule are a bare name: its time is unknown, so
     *  any post that names or clears it is newer. A clear keeps its entry
     *  with a null name, so an older post cannot bring the name back. */
    entry(channel, sender) {
        const e = this.channels[channel]?.[sender];
        if (typeof e === "string") return { name: e, at: null };
        if (e && typeof e === "object") return { name: typeof e.name === "string" ? e.name : null, at: Number.isFinite(e.at) ? e.at : null };
        return null;
    }

    get(channel, sender) {
        return this.entry(channel, sender)?.name ?? null;
    }

    /** §5.2: an accepted post's 0xD1 sets or clears channelName for
     *  (channel, sender), unless a newer post has already set or cleared it
     *  (history pulled late). `postAtMs` is the post's timestamp; a newer
     *  post repeating the name or the clear advances it (acceptChannelName).
     *  Returns true when the stored name changed. */
    apply(channel, sender, field, postAtMs) {
        const current = this.entry(channel, sender);
        const next = acceptChannelName(current, field, postAtMs);
        if (next === null) return false;
        (this.channels[channel] ??= {})[sender] = next;
        this.storage.set(CHANNEL_NAMES_KEY, this.channels);
        return (current?.name ?? null) !== next.name;
    }

    forget(channel) {
        delete this.channels[channel];
        this.storage.set(CHANNEL_NAMES_KEY, this.channels);
    }
}

export { EMPTY_DIGEST };
