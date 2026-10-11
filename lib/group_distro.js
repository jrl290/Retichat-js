/**
 * What a device of the distro D keeps for the groups that reach it through
 * D (RFed-rust SPEC.md §17.14; GROUPS-DISTRO-DESIGN.md §6.5, §9.1, §10.2),
 * client-local, nothing of it on the wire. Pure stores over a storage
 * adapter { get(key), set(key, value) } holding JSON values, as
 * name_ledger.js takes; app.js RnsClient keeps one of each.
 *
 * A `set` that returns false refused the write (app.js sSetKept: a full
 * localStorage); anything else kept it. A refused write is said, never
 * dropped silently (DESIGN_PRINCIPLES: every drop path speaks): each store
 * calls `onRefused(key, what)` (its options), or without one writes a log
 * line itself, naming its key and what it did not keep, and goes on with
 * what it holds in memory, for this page only. Until the review of
 * 96fffd9 app.js gave these stores sSet, which drops a refused write
 * without a word, so a held arrival, a `left` entry, a filtered id or a
 * sibling was lost at the next reload, unsaid.
 *
 *   HeldGroupArrivals  group traffic that reaches this device before it has
 *                      joined the group, held until it does (§6.5)
 *   FilteredInvites    the groups whose invite to D this device's privacy
 *                      filter dropped: their traffic is never held (§6.5)
 *   DistroLeftGroups   per D, the groups D left most recently: every G
 *                      carries them in `left` (§10.2)
 *   KnownSiblings      per D, the other devices of D this device has
 *                      learned from the 0xFD of D-signed syncs (§9.1)
 */

const HEX32 = /^[0-9a-f]{32}$/;
const isObject = (v) => !!v && typeof v === "object" && !Array.isArray(v);

/** Write `value` under `key` of `storage`; when storage refuses, say so
 *  (`onRefused`, else a log line) naming `what` was not kept. Returns
 *  whether it was kept. */
function persist(storage, key, value, onRefused, what) {
    if (storage.set(key, value) !== false) return true;
    if (onRefused) onRefused(key, what);
    else console.warn(`[distro] ⚠️ Storage refused a write of ${key}: ${what} is kept by this page only, and is lost when it closes`);
    return false;
}

/**
 * GROUPS-DISTRO-DESIGN.md §6.5. A message that reaches this device through
 * D for a group not joined here, when that is the sole reason it would be
 * dropped, is held here as the fan-out blob it came as, and fed to the
 * distro path again when the group becomes joined (app.js
 * _replayHeldGroupArrivals): ordering on a readiness event, never a retry
 * (DESIGN_PRINCIPLES §5). A held blob is never recorded as seen, so its
 * replay is judged as a new arrival.
 *
 * Each row: { blob (base64), groupId, src, hash, signature (hex),
 * validated, pending (the group was held pending here when the blob was
 * held, else not held at all), size (bytes) }, oldest first. Deduplicated
 * on (hash, signature): a copy with another signature never shadows one
 * already held, and a later copy whose signature validates replaces an
 * unverified one with the same hash.
 *
 * Bounds (counts and bytes, never a clock):
 *   - at most 64 blobs and 256 KiB in all;
 *   - at most 16 per group;
 *   - at most 8 per LXMF source other than D (a `post` G, source D,
 *     counts against its group only);
 *   - blobs for groups not held here: at most 16 in all, and such a blob
 *     never evicts a blob of a group held pending here;
 *   - a single blob over 64 KiB is never held.
 * A new blob that would pass a bound evicts the oldest blob of the source
 * holding the most blobs within that bound, from the class it may evict;
 * when nothing may be evicted it is refused. hold() returns every eviction
 * and refusal, naming the group, the source and the bound, for the caller's
 * log line, and `stored: false` when storage refused to keep a blob it
 * holds (held by this page only).
 */
export class HeldGroupArrivals {
    static KEY = "held_group_arrivals_v1";
    static MAX_BLOBS = 64;
    static MAX_BYTES = 256 * 1024;
    static PER_GROUP = 16;
    static PER_SOURCE = 8;
    static NOT_HELD = 16;
    static MAX_BLOB = 64 * 1024;

    constructor(storage, { onRefused = null } = {}) {
        this.storage = storage;
        this.onRefused = onRefused;
        const rows = storage.get(HeldGroupArrivals.KEY);
        this.rows = Array.isArray(rows) ? rows.filter((r) => isObject(r) && typeof r.blob === "string"
            && HEX32.test(r.groupId ?? "") && HEX32.test(r.src ?? "") && typeof r.hash === "string" && typeof r.signature === "string"
            && Number.isInteger(r.size)) : [];
    }

    /** Persist the rows; false (said) when storage refused them. */
    _save(what = "the held arrivals' latest change") {
        return persist(this.storage, HeldGroupArrivals.KEY, this.rows, this.onRefused, what);
    }

    /** The held rows, oldest first (copies). */
    list() {
        return this.rows.map((r) => ({ ...r }));
    }

    /** The held rows of group `groupId`, oldest first. */
    forGroup(groupId) {
        return this.rows.filter((r) => r.groupId === groupId).map((r) => ({ ...r }));
    }

    /**
     * Hold `arrival` { blob (Buffer/Uint8Array), groupId, src, hash,
     * signature (hex), validated, pending }; `dHex` is D, whose `post` G
     * counts against its group only. Returns { held, why, evicted } where
     * `evicted` lists { groupId, src, bound } for each blob it pushed out,
     * and `why` says what refused it (held false) or that it was held
     * already; with `stored: false` too when storage refused to keep the
     * blob held (said through onRefused): held by this page only.
     */
    hold(arrival, dHex) {
        const blob = Buffer.from(arrival.blob);
        const size = blob.length;
        const evicted = [];
        if (size > HeldGroupArrivals.MAX_BLOB) return { held: false, why: `it is ${size} bytes, over the ${HeldGroupArrivals.MAX_BLOB} a held blob may be`, evicted };
        const same = this.rows.find((r) => r.hash === arrival.hash && r.signature === arrival.signature);
        if (same) return { held: true, why: "it is held already", evicted };
        const row = {
            blob: blob.toString("base64"), groupId: arrival.groupId, src: arrival.src, hash: arrival.hash,
            signature: arrival.signature, validated: !!arrival.validated, pending: !!arrival.pending, size,
        };
        const unverified = arrival.validated ? this.rows.findIndex((r) => r.hash === arrival.hash && !r.validated) : -1;
        const answer = (result) => (this._save(`a held arrival for group ${row.groupId.slice(0, 8)} from ${row.src.slice(0, 12)}`) ? result : { ...result, stored: false });
        if (unverified >= 0) {
            this.rows[unverified] = row;
            return answer({ held: true, why: "it replaces an unverified copy of the same message", evicted });
        }
        // Which held blobs the new one may push out: a blob for a group not
        // held here never pushes out one of a group held pending here.
        const mayEvict = (r) => row.pending || !r.pending;
        const evictWithin = (within, bound) => {
            const candidates = this.rows.filter((r) => within(r) && mayEvict(r));
            if (candidates.length === 0) return false;
            const counts = new Map();
            for (const r of candidates) counts.set(r.src, (counts.get(r.src) ?? 0) + 1);
            const most = Math.max(...counts.values());
            const victim = candidates.find((r) => counts.get(r.src) === most);
            this.rows.splice(this.rows.indexOf(victim), 1);
            evicted.push({ groupId: victim.groupId, src: victim.src, bound });
            return true;
        };
        const bounds = [
            { name: `${HeldGroupArrivals.PER_GROUP} per group`, within: (r) => r.groupId === row.groupId, full: (n) => n >= HeldGroupArrivals.PER_GROUP },
            ...(row.src === dHex ? [] : [{ name: `${HeldGroupArrivals.PER_SOURCE} per source`, within: (r) => r.src === row.src, full: (n) => n >= HeldGroupArrivals.PER_SOURCE }]),
            ...(row.pending ? [] : [{ name: `${HeldGroupArrivals.NOT_HELD} for groups not held here`, within: (r) => !r.pending, full: (n) => n >= HeldGroupArrivals.NOT_HELD }]),
        ];
        for (const bound of bounds) {
            while (bound.full(this.rows.filter(bound.within).length)) {
                if (!evictWithin(bound.within, bound.name)) {
                    if (evicted.length) this._save("the held arrivals pushed out");
                    return { held: false, why: `the bound of ${bound.name} is reached, and nothing it holds may be pushed out for it`, evicted };
                }
            }
        }
        const total = { name: `${HeldGroupArrivals.MAX_BLOBS} blobs and ${HeldGroupArrivals.MAX_BYTES} bytes in all`, within: () => true };
        const bytes = () => this.rows.reduce((n, r) => n + r.size, 0);
        while (this.rows.length >= HeldGroupArrivals.MAX_BLOBS || bytes() + size > HeldGroupArrivals.MAX_BYTES) {
            if (!evictWithin(total.within, total.name)) {
                if (evicted.length) this._save("the held arrivals pushed out");
                return { held: false, why: `the bound of ${total.name} is reached, and nothing held may be pushed out for it`, evicted };
            }
        }
        this.rows.push(row);
        return answer({ held: true, why: null, evicted });
    }

    /** Stop holding the row `row` (replayed): only that one. */
    release(row) {
        const i = this.rows.findIndex((r) => r.hash === row.hash && r.signature === row.signature);
        if (i < 0) return false;
        this.rows.splice(i, 1);
        this._save(`the release of a held arrival for group ${row.groupId?.slice(0, 8)}`);
        return true;
    }

    /** Forget every blob held for group `groupId` (closed here). Returns the count. */
    forgetGroup(groupId) {
        const before = this.rows.length;
        this.rows = this.rows.filter((r) => r.groupId !== groupId);
        if (this.rows.length !== before) this._save(`forgetting what was held for group ${groupId.slice(0, 8)}`);
        return before - this.rows.length;
    }

    /** Forget everything held (the device gave its distro up). Returns the count. */
    forgetAll() {
        const n = this.rows.length;
        if (n) { this.rows = []; this._save(`forgetting the ${n} held arrival(s)`); }
        return n;
    }
}

/**
 * GROUPS-DISTRO-DESIGN.md §6.5: the group ids whose invite to D this
 * device's privacy filter dropped, at most 64, oldest forgotten first, like
 * the closed groups. Group traffic for an id here is never held: the filter
 * has already decided, and spends nothing more on that group (James,
 * 2026-09-28). An id leaves when the group becomes held here from a G.
 */
export class FilteredInvites {
    static KEY = "group_filtered_invites_v1";
    static LIMIT = 64;

    constructor(storage, { onRefused = null } = {}) {
        this.storage = storage;
        this.onRefused = onRefused;
        const ids = storage.get(FilteredInvites.KEY);
        this.ids = Array.isArray(ids) ? ids.filter((id) => typeof id === "string" && HEX32.test(id)).slice(-FilteredInvites.LIMIT) : [];
    }

    has(groupId) { return this.ids.includes(groupId); }

    add(groupId) {
        this.ids = this.ids.filter((id) => id !== groupId);
        this.ids.push(groupId);
        if (this.ids.length > FilteredInvites.LIMIT) this.ids = this.ids.slice(-FilteredInvites.LIMIT);
        persist(this.storage, FilteredInvites.KEY, this.ids, this.onRefused, `the filtered invite of group ${groupId.slice(0, 8)}`);
    }

    remove(groupId) {
        if (!this.has(groupId)) return false;
        this.ids = this.ids.filter((id) => id !== groupId);
        persist(this.storage, FilteredInvites.KEY, this.ids, this.onRefused, `group ${groupId.slice(0, 8)} leaving the filtered-invite set`);
        return true;
    }
}

/**
 * GROUPS-DISTRO-DESIGN.md §10.2: per D, the ids of the D-groups this device
 * holds as left by D, most recent first, at most 32: the user's own leaves
 * as D here, and every leave applied from a G or from another G's `left`.
 * Every G this device sends carries them, so a sibling that missed a leave G
 * learns it from the next one.
 */
export class DistroLeftGroups {
    static KEY = "group_distro_left_v1";
    static LIMIT = 32;

    constructor(storage, { onRefused = null } = {}) {
        this.storage = storage;
        this.onRefused = onRefused;
        const rows = storage.get(DistroLeftGroups.KEY);
        this.byDistro = isObject(rows) ? rows : {};
    }

    /** The ids D left, most recent first. */
    of(dHex) {
        const ids = this.byDistro[dHex];
        return Array.isArray(ids) ? ids.filter((id) => typeof id === "string" && HEX32.test(id)).slice(0, DistroLeftGroups.LIMIT) : [];
    }

    /** D left `groupId` (now, or learned now): it goes first. */
    record(dHex, groupId) {
        const ids = [groupId, ...this.of(dHex).filter((id) => id !== groupId)].slice(0, DistroLeftGroups.LIMIT);
        this.byDistro[dHex] = ids;
        persist(this.storage, DistroLeftGroups.KEY, this.byDistro, this.onRefused, `group ${groupId.slice(0, 8)} on the left list of distro ${String(dHex).slice(0, 8)}`);
    }
}

/**
 * GROUPS-DISTRO-DESIGN.md §9.1: per D, the other devices of D this device
 * has learned, never queried: the 0xFD of every D-signed sync it accepts
 * (§17.11 copies, §17.12 messages, §17.14 group syncs) that is not this
 * device. Persisted; dropped when D is given up, unless a group here still
 * has that D as its own address (§8.7).
 */
export class KnownSiblings {
    static KEY = "distro_siblings_v1";

    constructor(storage, { onRefused = null } = {}) {
        this.storage = storage;
        this.onRefused = onRefused;
        const rows = storage.get(KnownSiblings.KEY);
        this.byDistro = isObject(rows) ? rows : {};
    }

    of(dHex) {
        const list = this.byDistro[dHex];
        return Array.isArray(list) ? list.filter((h) => typeof h === "string" && HEX32.test(h)) : [];
    }

    has(dHex, hex) {
        return this.of(dHex).includes(hex);
    }

    /** Learn `hex` as a device of D. Returns whether it is new. */
    add(dHex, hex) {
        if (!HEX32.test(dHex ?? "") || !HEX32.test(hex ?? "") || this.has(dHex, hex)) return false;
        this.byDistro[dHex] = [...this.of(dHex), hex];
        persist(this.storage, KnownSiblings.KEY, this.byDistro, this.onRefused, `device ${hex.slice(0, 12)} of distro ${dHex.slice(0, 8)}`);
        return true;
    }

    /** Forget every distro but those in `keep`. Returns the distros dropped. */
    keepOnly(keep) {
        const dropped = Object.keys(this.byDistro).filter((d) => !keep.includes(d));
        if (!dropped.length) return [];
        for (const d of dropped) delete this.byDistro[d];
        persist(this.storage, KnownSiblings.KEY, this.byDistro, this.onRefused, `forgetting the devices of ${dropped.length} distro(s) given up`);
        return dropped;
    }
}
