/**
 * The transfers an outgoing message is waiting on — a Resource on the peer's
 * delivery link, the propagated copy's Resource on the propagation link — and
 * what they mean for the message: its progress, whether it may be failed, and
 * the 5-second rule for bulk transfers.
 *
 * Progress. While a message is SENDING, each Resource report sets its
 * progress to 0.10 + 0.90 x the Resource's fraction (LXMF/LXMessage.py
 * __update_transfer_progress; LXMF-rust 4125139), only ever upward: parallel
 * transfers of one message (the direct Resource and the propagated copy)
 * cannot pull the bar back, and a late report changes nothing.
 *
 * Outcome. A transfer that is moving decides itself: the Resource concludes
 * (the proof) or fails (its own watchdog, a refusal, the link closing). The
 * send ceiling defers to it (deferCeiling) and runs again once nothing of the
 * message is in flight. Until 2026-09-30 a flat 30 s ceiling failed a photo
 * whose Resource was still moving, and its late proof then flipped it to
 * delivered (Android 4b5bd9b, app-links 07bea51 had the same bug).
 *
 * Legs. A DM has two ways to be delivered: "direct" (the attempt on the
 * peer's delivery link) and "propagated" (the copy to the propagation node).
 * Each is open from its start until its proof or its failure (openLeg,
 * legFailed). When the last open one fails, nothing can deliver the message
 * any more, and that failure is the message's outcome, at once: not a timer's
 * 30 s later.
 *
 * DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30): a Resource's total
 * duration is not measured against 5 s; from the advertisement on it must
 * show progress at least every 5 s. A silence longer than that is a §1
 * violation, asserted and logged as one, and never used to fail the send.
 *
 * Nothing here touches a Node-only global at module load.
 */

export const PROGRESS_START = 0.10;
export const PROGRESS_SPAN = 0.90;
/** DESIGN_PRINCIPLES §1: the longest silence a moving transfer may have. */
export const QUIET_MS = 5_000;

/** Why a message failed when its propagated copy's upload did (the
 *  bubble's "Not sent: ..."). */
export function propagationFailure(error) {
    return `the upload to the propagation node failed (${error?.message || error || "no reason given"})`;
}

/** The message's progress for a Resource fraction (0..1). */
export function transferProgress(fraction) {
    const f = Number(fraction);
    const clamped = Number.isFinite(f) ? Math.min(1, Math.max(0, f)) : 0;
    return PROGRESS_START + PROGRESS_SPAN * clamped;
}

export class SendTransfers {

    constructor({
        now = () => Date.now(),
        setTimer = (fn, ms) => setTimeout(fn, ms),
        clearTimer = (id) => clearTimeout(id),
        quietMs = QUIET_MS,
        log = console,
    } = {}) {
        this._now = now;
        this._setTimer = setTimer;
        this._clearTimer = clearTimer;
        this._quietMs = quietMs;
        this._log = log;
        this._messages = new Map();
        this._seq = 0;
        /** Every §1 silence seen: {msgId, label, silentMs} (silentMs set on resume). */
        this.violations = [];
    }

    _entry(msgId) {
        let m = this._messages.get(msgId);
        if (!m) {
            m = { progress: null, transfers: new Set(), legs: new Set(), lastActivity: this._now(), deferred: null, settled: false };
            this._messages.set(msgId, m);
        }
        return m;
    }

    /** A transfer of message `msgId` started (its Resource is advertised),
     *  on `leg` ("direct" or "propagated"; see openLeg). */
    begin(msgId, label = "transfer", leg = null) {
        const m = this._entry(msgId);
        const t = this._now();
        const handle = { id: ++this._seq, msgId, label, leg, startedAt: t, lastActivityAt: t, timer: null, silence: null, ended: false };
        m.transfers.add(handle);
        m.lastActivity = t;
        this._watch(handle);
        return handle;
    }

    /**
     * The transfer reported `fraction` (Resource.get_progress). It is
     * activity whatever the value. Returns the message's new progress when
     * it rose, else null.
     */
    progress(handle, fraction) {
        if (!handle || handle.ended) return null;
        const m = this._messages.get(handle.msgId);
        if (!m) return null;
        const t = this._now();
        if (handle.silence) {
            handle.silence.silentMs = t - handle.lastActivityAt;
            this._log.warn?.(`[§1] ${handle.label}: progress again after ${(handle.silence.silentMs / 1000).toFixed(1)} s of silence`);
            handle.silence = null;
        }
        handle.lastActivityAt = t;
        m.lastActivity = t;
        this._watch(handle);
        if (m.settled) return null;
        const value = transferProgress(fraction);
        if (m.progress !== null && value <= m.progress) return null;
        m.progress = value;
        return value;
    }

    /** The transfer concluded (ok) or failed (with `error`). */
    end(handle, ok, error = null) {
        if (!handle || handle.ended) return;
        handle.ended = true;
        if (handle.timer !== null) this._clearTimer(handle.timer);
        handle.timer = null;
        const m = this._messages.get(handle.msgId);
        if (!m) return;
        m.transfers.delete(handle);
        m.lastActivity = this._now();
        if (m.transfers.size > 0) return;
        const deferred = m.deferred;
        m.deferred = null;
        if (m.settled) this._messages.delete(handle.msgId);
        if (deferred) deferred(ok, handle.leg, error);
    }

    /** True while a transfer of the message is in flight. */
    inFlight(msgId) {
        return (this._messages.get(msgId)?.transfers.size ?? 0) > 0;
    }

    /** Milliseconds since a transfer of the message last showed activity,
     *  or null when none is in flight. */
    quietFor(msgId) {
        const m = this._messages.get(msgId);
        if (!m || m.transfers.size === 0) return null;
        return this._now() - m.lastActivity;
    }

    /** The message's progress (0.10..1.0), or null before any transfer. */
    progressOf(msgId) {
        const m = this._messages.get(msgId);
        return m && !m.settled ? m.progress : null;
    }

    /**
     * The send ceiling ran out while a transfer was in flight: `run(ok, leg,
     * error)` runs once nothing of the message is in flight any more, with
     * whether the last transfer concluded, its leg, and why it failed. One
     * deferral per message; a later one replaces it.
     */
    deferCeiling(msgId, run) {
        this._entry(msgId).deferred = run;
    }

    /**
     * A way to deliver message `msgId` opened: `leg` is "direct" (from the
     * dispatch of the direct attempt) or "propagated" (from the start of
     * the copy to the propagation node, parked or not). It stays open until
     * the message's outcome (settle) or legFailed.
     */
    openLeg(msgId, leg) {
        this._entry(msgId).legs.add(leg);
    }

    /**
     * That way failed: the direct Resource or link failed; the propagated
     * Resource failed, or the node would not take the copy. True when it
     * was the last one open: nothing can deliver the message any more, so it
     * has failed, now. False while another is open, and for a message that
     * already has its outcome or opened none.
     */
    legFailed(msgId, leg) {
        const m = this._messages.get(msgId);
        if (!m || m.settled || !m.legs.has(leg)) return false;
        m.legs.delete(leg);
        return m.legs.size === 0;
    }

    /** The message reached its outcome: no more progress is reported, and
     *  it is forgotten once its transfers end. */
    settle(msgId) {
        const m = this._messages.get(msgId);
        if (!m) return;
        m.settled = true;
        m.deferred = null;
        if (m.transfers.size === 0) this._messages.delete(msgId);
    }

    _watch(handle) {
        if (handle.timer !== null) this._clearTimer(handle.timer);
        handle.timer = this._setTimer(() => this._silent(handle), this._quietMs);
    }

    _silent(handle) {
        handle.timer = null;
        if (handle.ended || handle.silence) return;
        handle.silence = { msgId: handle.msgId, label: handle.label, silentMs: null };
        this.violations.push(handle.silence);
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 (bulk transfers: no progress for 5 s is a violation; it never fails the send)
        this._log.error?.(`[§1] VIOLATION ${handle.label}: no progress for ${this._quietMs / 1000} s `
            + `(${((this._now() - handle.startedAt) / 1000).toFixed(1)} s since it started); the Resource's own events decide its outcome`);
    }
}
