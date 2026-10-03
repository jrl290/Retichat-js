/**
 * The proof of an upload this device makes for its distro through the
 * propagation node: the RFed SPEC §17.11 sent-copy and the §17.12
 * membership message C (app.js _uploadForDistro).
 *
 * Both are fire-and-forget: the user sees nothing of them and nothing is
 * sent again (DESIGN_PRINCIPLES §3). But a queued packet is not a sent
 * message (CHECK_THESE_THINGS_FIRST §14). Until 2026-10-03 (review of
 * Retichat-js 69ff01e) each said "propagated", and emitted its Harness
 * event, the moment the packet was queued, with nothing watching for the
 * node's proof: a lost upload read as sent in the log, and a staging stage
 * reading the event would count it. Now an upload that goes as one packet
 * is sent when the propagation node proves the packet; one that goes as a
 * Resource, when the Resource is proved (its progress has its own §1 watch,
 * lib/rns/resource.js).
 *
 * DESIGN_PRINCIPLES §1: the node proves a packet it holds at once. At 5 s
 * with no proof the violation is logged, and a proof later than that is
 * logged with its time. Neither decides the upload: the proof does, or the
 * exchange's report that the packet was lost (RnsClient._onPacketsLost),
 * whichever comes first.
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
    }

    /**
     * An upload about to leave as one packet; `label` is what the log lines
     * call it. Returns the upload: its `outcome` resolves with
     * `{ waitedMs }` when it is proved and rejects when it is lost, the
     * first of the two deciding.
     */
    track(label) {
        const upload = { label, leftAt: null, watch: null, settled: null };
        upload.outcome = new Promise((resolve, reject) => { upload.resolve = resolve; upload.reject = reject; });
        // Fire-and-forget: nobody need be waiting when it is lost.
        upload.outcome.catch(() => {});
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

    /** The propagation node proved the packet of `upload`. True when this decided it. */
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
            return false;
        }
        if (upload.settled) return false;
        upload.settled = "proved";
        upload.resolve({ waitedMs });
        return true;
    }

    /** `upload` will never be proved: `why`. True when this decided it. */
    lost(upload, why) {
        if (upload.settled) return false;
        this._stopWatch(upload);
        upload.settled = "lost";
        upload.reject(new Error(why));
        return true;
    }
}
