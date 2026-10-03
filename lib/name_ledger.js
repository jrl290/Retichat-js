/**
 * The persistent halves of LXMF-rust/DISPLAY_NAMES.md for the web client:
 *
 *   NameLedger          §4.1 — per (source, recipient), the digest of the
 *                       name last confirmed delivered and when.
 *   ChannelPostNames    §4.2 — per channel and posting identity, what this
 *                       client last included in its own posts; per channel,
 *                       which senders it has seen there.
 *   ChannelSenderNames  §5.1 — per (channel, sender), the Channel Display
 *                       Name that sender's posts carry. Never a contact name.
 *
 * Each takes a storage adapter { get(key), set(key, value) } holding JSON
 * values (app.js passes sGet/sSet over localStorage), so the tests run them
 * over a Map. The pure rules they apply are in display_name.js.
 */

import { decide, decideChannelPost, stateDigest, acceptChannelName, digestHex, EMPTY_DIGEST } from "./display_name.js";

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

    /**
     * A channel's entry: per channel, the senders seen in it and when one was
     * last new (rule 2); per posting identity (`posters`, keyed by its
     * lxmf.delivery hash: the distro when the device holds one, otherwise
     * the device, DISPLAY_NAMES.md §4.2), what this client last included in
     * its posts as that identity, { lastDigest, lastIncludedAt }. Readers
     * have never had a name from a new posting identity, so one this client
     * has no state for starts from none and its first post carries the name
     * (§4.2 "When the posting identity changes").
     */
    _entry(channel) {
        let entry = this.channels[channel];
        if (!entry || typeof entry !== "object") {
            entry = { lastNewSenderAt: 0, senders: [], posters: {} };
            this.channels[channel] = entry;
        }
        if (!Array.isArray(entry.senders)) entry.senders = [];
        if (!entry.posters || typeof entry.posters !== "object") entry.posters = {};
        return entry;
    }

    /** What this client last included in its posts to `channel` as
     *  `poster`: { lastDigest, lastIncludedAt } (ms), or null. */
    included(channel, poster) {
        const p = this.channels[channel]?.posters?.[poster];
        if (!p || typeof p !== "object" || typeof p.lastDigest !== "string") return null;
        return { lastDigest: p.lastDigest, lastIncludedAt: Number.isFinite(p.lastIncludedAt) ? p.lastIncludedAt : 0 };
    }

    /** §4.2: the name state for the next post to `channel` as `poster`. */
    decide(channel, poster, channelName, nowMs) {
        const included = this.included(channel, poster);
        return decideChannelPost(channelName, {
            lastDigest: included?.lastDigest ?? null,
            lastIncludedAt: included?.lastIncludedAt ?? 0,
            lastNewSenderAt: this.channels[channel]?.lastNewSenderAt ?? 0,
        }, nowMs);
    }

    /**
     * A post from `sender` arrived in `channel`. A sender not seen before
     * makes the next own post carry the name (§4.2 rule 2). `own`, the
     * user's own posting identities (this device's lxmf.delivery hash and
     * the distro's it holds; one hash or a list), are never counted: their
     * posts are the user's own, not a new reader's.
     */
    noteSender(channel, sender, own, nowMs) {
        const ownHashes = Array.isArray(own) ? own : [own];
        if (!sender || ownHashes.includes(sender)) return false;
        const entry = this._entry(channel);
        if (entry.senders.includes(sender)) return false;
        entry.senders.push(sender);
        if (entry.senders.length > SENDERS_PER_CHANNEL) entry.senders.splice(0, entry.senders.length - SENDERS_PER_CHANNEL);
        entry.lastNewSenderAt = nowMs;
        this.storage.set(CHANNEL_POST_KEY, this.channels);
        return true;
    }

    /** §4.2: the post `poster` signed, carrying `state`, decided at
     *  `decidedAtMs`, was handed to RFed. Absent records nothing. */
    recordIncluded(channel, poster, state, decidedAtMs) {
        const digest = stateDigest(state);
        if (digest === null || !poster) return false;
        this._entry(channel).posters[poster] = { lastDigest: digest, lastIncludedAt: decidedAtMs };
        this.storage.set(CHANNEL_POST_KEY, this.channels);
        return true;
    }

    /**
     * §4.2 "Learning from the channel": a post this client received in
     * `channel` whose source is its current posting identity `poster` (the
     * echo of its own post, or one a sibling device signed with the same
     * distro), after the key binding and the signature passed. Its key 0
     * (`field`, a display_name.js state) is recorded only when it is the
     * value this device would send now: its own Channel Display Name
     * `ownName` (the same digest), or a clear while `ownName` is unset; and
     * only when the post (at `postAtMs`) is later than what is recorded. Any
     * other post leaves the record as it was, so a device never records, and
     * so never clears, a name it does not hold. Returns true when recorded.
     *
     * The time recorded is the post's, as DISPLAY_NAMES.md §4.2 says, on
     * every client alike. 9f058e9 recorded min(post's time, this device's
     * clock) instead, so that a sibling whose clock runs ahead would not
     * hold back rule 2 (a new sender) and rule 3 (the 24-hour refresh) on
     * the devices that learn from it by as much as its lead. That only
     * delays a name, it never shows readers a false one, so the web keeps
     * to the spec text, which the phones build from (review of 9f058e9,
     * 2026-10-03); a change would be the spec's first.
     */
    learn(channel, poster, field, postAtMs, ownName) {
        if (!poster || !Number.isFinite(postAtMs)) return false;
        const included = this.included(channel, poster);
        if (postAtMs <= (included?.lastIncludedAt ?? 0)) return false;
        let digest = null;
        if (ownName) {
            if (field?.state === "name" && digestHex(field.name) === digestHex(ownName)) digest = digestHex(ownName);
        } else if (field?.state === "clear") {
            digest = EMPTY_DIGEST;
        }
        if (digest === null) return false;
        this._entry(channel).posters[poster] = { lastDigest: digest, lastIncludedAt: postAtMs };
        this.storage.set(CHANNEL_POST_KEY, this.channels);
        return true;
    }

    /**
     * Entries saved before 2026-10-03 hold one lastDigest and lastIncludedAt
     * per channel: this device's, the only posting identity a client had
     * then. They become `deviceHash`'s, once; a distro this device holds
     * starts from none (§4.2 "When the posting identity changes"). Without a
     * device hash nothing changes.
     */
    adoptLegacy(deviceHash) {
        if (!deviceHash) return false;
        let changed = false;
        for (const entry of Object.values(this.channels)) {
            if (!entry || typeof entry !== "object") continue;
            if (!("lastDigest" in entry) && !("lastIncludedAt" in entry)) continue;
            if (!entry.posters || typeof entry.posters !== "object") entry.posters = {};
            if (typeof entry.lastDigest === "string" && !entry.posters[deviceHash]) {
                entry.posters[deviceHash] = {
                    lastDigest: entry.lastDigest,
                    lastIncludedAt: Number.isFinite(entry.lastIncludedAt) ? entry.lastIncludedAt : 0,
                };
            }
            delete entry.lastDigest;
            delete entry.lastIncludedAt;
            changed = true;
        }
        if (changed) this.storage.set(CHANNEL_POST_KEY, this.channels);
        return changed;
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
     *  (channel, sender), unless a post at the same time or newer has
     *  already set or cleared it (history pulled late). `postAtMs` is the
     *  post's timestamp; a newer post repeating the name or the clear
     *  advances it (acceptChannelName). Returns true when the stored name
     *  changed. */
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
