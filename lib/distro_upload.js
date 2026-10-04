/**
 * The proof of an upload this device makes for its distro through the
 * propagation node: the RFed SPEC §17.11 sent-copy and the §17.12
 * membership message C (app.js _uploadForDistro, _uploadOwed).
 *
 * The user sees nothing of them, and an upload is never repeated here, on
 * a timer or on its own account: one that is not proved stays owed
 * (lib/distro_outbox.js) and is uploaded again when the propagation link
 * next comes up after the failure, that event being the trigger (or, for
 * an upload on a STALE link a newer one replaced, that link's close while
 * the newer link is up, or the exchange's report that its packet was
 * lost, which counts the same as that close: James, 2026-10-04). That
 * second upload is the retry DESIGN_PRINCIPLES §3 allows for these two
 * messages alone, by James's decision of 2026-10-03 (RFed SPEC §17.12 "On
 * the sending device"). But a queued packet is not a sent message
 * (CHECK_THESE_THINGS_FIRST §14). Until
 * 2026-10-03 (review of Retichat-js 69ff01e) each said "propagated", and
 * emitted its Harness event, the moment the packet was queued, with
 * nothing watching for the node's proof: a lost upload read as sent in the
 * log, and a staging stage reading the event would count it. Now an upload
 * that goes as one packet is sent when the propagation node proves the
 * packet; one that goes as a Resource, when the Resource is proved (its
 * progress has its own §1 watch, lib/rns/resource.js).
 *
 * DESIGN_PRINCIPLES §1: the node proves a packet it holds at once. At 5 s
 * with no proof the violation is logged, and a proof later than that is
 * logged with its time. Neither decides the upload: the proof does, or an
 * event that says the proof can no longer come, whichever is first: the
 * exchange's report that the packet was lost (RnsClient._onPacketsLost),
 * the close of the propagation link it went on, or the connection stopping
 * (RnsClient.disconnect; each cut()). A STALE link replaced by a new one
 * (RnsClient._establishPropagationLink) decides nothing (James,
 * 2026-10-03): the node may still prove the upload over it, and its own
 * close decides the rest. Until 2026-10-03 (review of Retichat-js
 * 9f058e9) neither the close nor disconnect() decided anything:
 * disconnect() dropped the proof's entry, so the upload stayed open, the
 * §1 watch said 5 s later that the proof or the exchange would decide it
 * though neither could, and the upload's end was never said. What was not
 * proved stays owed (lib/distro_outbox.js).
 *
 * Nothing here touches a Node-only global at module load.
 */

/** DESIGN_PRINCIPLES §1: the longest the propagation node may take to prove an upload packet. */
export const PROOF_LIVE_MS = 5_000;

export class DistroUploads {

    /**
     * `log` gets the §1 lines (console; a test may put another log here).
     * The timers are read when used, so a test's virtual clock applies.
     */
    constructor({ now = () => Date.now(), setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (t) => clearTimeout(t), log = console } = {}) {
        this._now = now;
        this._setTimer = setTimer;
        this._clearTimer = clearTimer;
        this._log = log;
        // Every upload not yet decided, for cut().
        this._open = new Set();
    }

    /**
     * An upload about to leave on the propagation link `link`, as one
     * packet (`how` "packet") or a Resource ("resource", whose progress has
     * its own §1 watch, lib/rns/resource.js, so left() is not called for
     * it); `label` is what the log lines call it. Returns the upload: its
     * `outcome` resolves with `{ waitedMs }` when it is proved and rejects
     * when it is lost, the first of the two deciding. `onLost`, when its
     * owner sets one, is told of the loss at once, in the task of the event
     * that decided it (lost()), where `outcome`'s handlers run only after
     * that task: what its owner records then is ordered before anything
     * that event's task does next (app.js _uploadOwed, which records the
     * propagation link's coming-up a failure was decided at).
     */
    track(label, link = null, how = "packet") {
        const upload = { label, link, how, leftAt: null, watch: null, settled: null, lateProof: false, onLateProof: null, onLost: null };
        upload.outcome = new Promise((resolve, reject) => { upload.resolve = resolve; upload.reject = reject; });
        // Fire-and-forget: nobody need be waiting when it is lost.
        upload.outcome.catch(() => {});
        this._open.add(upload);
        return upload;
    }

    /** The packet of `upload` went: the §1 clock starts. */
    left(upload) {
        if (upload.leftAt !== null || upload.settled) return;
        upload.leftAt = this._now();
        upload.watch = this._setTimer(() => {
            upload.watch = null;
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            this._log.error?.(`[distro] §1 VIOLATION: the propagation node has not proved ${upload.label} within `
                + `${PROOF_LIVE_MS / 1000} s of its upload; its proof, or the exchange's report that it was lost, decides it`);
        }, PROOF_LIVE_MS + 1);
    }

    _stopWatch(upload) {
        if (upload.watch !== null) {
            this._clearTimer(upload.watch);
            upload.watch = null;
        }
    }

    /**
     * The propagation node proved the packet of `upload`. True when this
     * decided it. A proof of one already decided lost (the exchange
     * reported its packet lost, and the node had it after all) decides
     * nothing, but it is the truth: it is logged, and `upload.onLateProof`,
     * when its owner set one, is told, so what it carried is owed no more.
     */
    proved(upload) {
        this._stopWatch(upload);
        const waitedMs = upload.leftAt === null ? 0 : this._now() - upload.leftAt;
        if (waitedMs > PROOF_LIVE_MS) {
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            this._log.error?.(`[distro] §1 VIOLATION: the propagation node proved ${upload.label} ${waitedMs} ms after `
                + `its upload (a late success is a failure)`);
        }
        if (upload.settled === "lost") {
            this._log.warn?.(`[distro] ${upload.label} was proved after all, after it was reported lost`);
            if (!upload.lateProof) {
                upload.lateProof = true;
                upload.onLateProof?.();
            }
            return false;
        }
        if (upload.settled) return false;
        upload.settled = "proved";
        this._open.delete(upload);
        upload.resolve({ waitedMs });
        return true;
    }

    /**
     * `upload` will never be proved: `why`. True when this decided it.
     * `upload.onLost` is told now, before this returns (track()).
     */
    lost(upload, why) {
        if (upload.settled) return false;
        this._stopWatch(upload);
        upload.settled = "lost";
        this._open.delete(upload);
        upload.reject(new Error(why));
        upload.onLost?.();
        return true;
    }

    /**
     * The proof of every upload not yet decided can no longer come, `why`:
     * the propagation link `link` closed (only its uploads), or with no
     * `link` the connection stopped (all of them).
     * Each is lost, its §1 watch stopped. A proof that comes all the same
     * is a late proof (proved()). Returns how many were cut.
     */
    cut(why, link = null) {
        let cut = 0;
        for (const upload of [...this._open]) {
            if (link !== null && upload.link !== link) continue;
            if (this.lost(upload, why)) cut++;
        }
        return cut;
    }
}
