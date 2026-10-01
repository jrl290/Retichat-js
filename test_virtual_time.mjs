/**
 * Test support (not a test, not deployed): virtual time, for tests whose
 * subject is a clock: a request's response budget, a Resource's watchdog,
 * a delay on the in-process wire of test_link_pair.mjs.
 *
 * Such a test asks whether a budget runs out before some event. On the wall
 * clock the answer also depends on how fast the machine packs, encrypts and
 * hashes, and `npm test` (the deploy gate) runs every file at once: under
 * load a 100 ms budget ran out before an in-process response could start,
 * and link_request_resource.test.mjs went red at random (2026-09-30).
 *
 * While virtual time is installed:
 *   - a timer of more than 1 ms does not wait for the wall clock. It joins a
 *     virtual clock, and Date.now() reads that clock (new Date() and
 *     performance.now() still read the wall clock: lib/rns does not use
 *     them for its timers);
 *   - a timer of 0 or 1 ms (Node runs both after 1 ms: the EventEmitter's
 *     deferral, settle()) and setImmediate (the wire's delivery) run for
 *     real, and are counted;
 *   - the clock moves only when none of those is pending and every microtask
 *     has run, so when nothing but a timer could happen next. It then jumps
 *     to the earliest timer and runs that one alone, as a macrotask, as Node
 *     would after waiting for it. Timers due at the same time run in the
 *     order they were set.
 *
 * Work therefore takes no virtual time, however long it takes on the CPU: a
 * 150 ms budget runs out after the 150 ms of delays the test injected, or
 * never, and the order of events is still the event loop's own. A failure
 * bound (within()) is a virtual timer too, so a test that hangs fails as
 * soon as nothing else can happen, at the bound's virtual time.
 *
 * A livelock is a hang that keeps busy: two ends that exchange packets
 * forever over the in-process wire always have a delivery pending, so the
 * clock would never move and the bound would never be reached (on the wall
 * clock it was: Node runs a due timer between immediates). So the clock
 * counts the counted macrotasks that run without it moving. At
 * LIVELOCK_TURNS in a row (`livelockTurns`) it declares a livelock, says so
 * on stderr, and from then on drops every counted macrotask instead of
 * running it, until uninstall(): the loop stops, nothing is pending, and
 * the clock moves as it always does, so the test's bound is reached and
 * fails it. A test with no bound fails too: its promise can no longer
 * settle, and node:test fails a test whose event loop runs dry. uninstall()
 * then throws, so the test is red even if the loop would have ended by
 * itself, and the loop's macrotasks still queued are dropped as well, so it
 * does not outlive its test and keep the file's process alive. The count is
 * of macrotasks, not of milliseconds, so it does not depend on how loaded
 * the machine is.
 *
 * Async work the clock cannot count (file I/O, worker threads, WebCrypto)
 * must not be in flight while it is installed: the clock would move past
 * timers that such work should have beaten. setInterval is not supported
 * and throws, so a test cannot depend on one by accident.
 */

const real = {
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setImmediate: globalThis.setImmediate,
    clearImmediate: globalThis.clearImmediate,
    setInterval: globalThis.setInterval,
    now: Date.now,
};

/** Node runs a timer of less than 1 ms, or of more than this, after 1 ms. */
const TIMEOUT_MAX = 2 ** 31 - 1;

class VirtualTimer {
    constructor(id, at, fn, args) {
        this.id = id;
        this.at = at;
        this.fn = fn;
        this.args = args;
    }
    ref() { return this; }
    unref() { return this; }
    hasRef() { return true; }
    [Symbol.toPrimitive]() { return this.id; }
}

/**
 * Counted macrotasks that may run in a row without the clock moving before
 * the clock declares a livelock: about 35 times the suite's longest
 * legitimate run (2,909, a 1 MiB split response in
 * link_request_resource.test.mjs). Work that legitimately runs longer
 * without waiting for a timer passes a larger `livelockTurns`.
 */
export const LIVELOCK_TURNS = 100_000;

let installed = null;

/**
 * Install virtual time. Returns the clock: now() and elapsed() read it,
 * uninstall() puts the real timers and Date.now back and drops every
 * virtual timer still waiting (they belonged to the test), and throws if
 * the clock declared a livelock. `onLivelock(line)` is told when it does
 * (by default the line goes to stderr).
 */
export function installVirtualTime({ livelockTurns = LIVELOCK_TURNS, onLivelock = (line) => process.stderr.write(`${line}\n`) } = {}) {
    if (installed) throw new Error("virtual time is already installed");
    if (!(livelockTurns >= 1)) throw new Error(`livelockTurns must be at least 1, not ${livelockTurns}`);
    const start = real.now();
    const state = {
        now: start, seq: 0, timers: [], pending: 0, checkQueued: false, live: true,
        turns: 0,         // counted macrotasks run since the clock last moved
        livelock: null,   // once declared: { at: virtual ms, dropped: macrotasks not run }
    };
    const jobs = new WeakMap();   // real handle → counted job

    const queueCheck = () => {
        if (!state.live || state.checkQueued) return;
        state.checkQueued = true;
        real.setImmediate(check);
    };

    /** Runs as a real macrotask, after every microtask: the only place the clock moves. */
    function check() {
        state.checkQueued = false;
        if (!state.live || state.pending > 0 || state.timers.length === 0) return;
        let next = 0;
        for (let i = 1; i < state.timers.length; i++) {
            const t = state.timers[i];
            const n = state.timers[next];
            if (t.at < n.at || (t.at === n.at && t.id < n.id)) next = i;
        }
        const timer = state.timers.splice(next, 1)[0];
        if (timer.at > state.now) state.now = timer.at;
        state.turns = 0;
        try {
            timer.fn(...timer.args);
        } finally {
            queueCheck();
        }
    }

    /** The end of a counted real macrotask: run (`ran`), dropped or cleared. */
    const finish = (job, ran) => {
        if (job.done) return;
        job.done = true;
        state.pending--;
        if (ran && ++state.turns >= livelockTurns && !state.livelock && state.live) {
            state.livelock = { at: state.now - start, dropped: 0 };
            onLivelock(
                `⚠ test_virtual_time.mjs: livelock: ${livelockTurns} macrotasks ran one after another at ` +
                `${state.now - start} virtual ms without the clock moving (work that never waits for a timer); ` +
                "dropping every macrotask from here on: the loop stops, and the test fails at its bound or as never settling");
        }
        if (state.pending === 0) queueCheck();
    };

    const counted = (schedule, fn, args) => {
        const job = { done: false };
        state.pending++;
        const handle = schedule(() => {
            if (job.done) return;
            if (state.livelock) {
                state.livelock.dropped++;
                finish(job, false);
                return;
            }
            // Counted until its callback has returned: what it schedules is
            // counted before this job stops holding the clock.
            try {
                fn(...args);
            } finally {
                finish(job, true);
            }
        });
        jobs.set(handle, job);
        return handle;
    };

    globalThis.setTimeout = (fn, ms, ...args) => {
        const delay = Number(ms);
        if (!(delay > 1 && delay <= TIMEOUT_MAX)) {
            return counted((cb) => real.setTimeout(cb, 0), fn, args);
        }
        const timer = new VirtualTimer(++state.seq, state.now + delay, fn, args);
        state.timers.push(timer);
        queueCheck();
        return timer;
    };
    globalThis.clearTimeout = (handle) => {
        if (handle instanceof VirtualTimer) {
            const i = state.timers.indexOf(handle);
            if (i !== -1) state.timers.splice(i, 1);
            return;
        }
        const job = handle && typeof handle === "object" ? jobs.get(handle) : undefined;
        real.clearTimeout(handle);
        if (job) finish(job, false);
    };
    globalThis.setImmediate = (fn, ...args) => counted((cb) => real.setImmediate(cb), fn, args);
    globalThis.clearImmediate = (handle) => {
        const job = handle && typeof handle === "object" ? jobs.get(handle) : undefined;
        real.clearImmediate(handle);
        if (job) finish(job, false);
    };
    globalThis.setInterval = () => {
        throw new Error("setInterval under virtual time (test_virtual_time.mjs) is not supported");
    };
    Date.now = () => state.now;

    const clock = {
        now: () => state.now,
        /** Virtual milliseconds since installVirtualTime(). */
        elapsed: () => state.now - start,
        /** Virtual timers still waiting. */
        waiting: () => state.timers.length,
        /** Real macrotasks (setImmediate, 0 or 1 ms timers) queued and not yet run: the clock holds while any is. */
        pending: () => state.pending,
        /** The livelock, once declared: { at: its virtual ms, dropped: macrotasks not run since }; else null. */
        livelock: () => (state.livelock ? { ...state.livelock } : null),
        uninstall() {
            if (!state.live) return;
            state.live = false;
            state.timers.length = 0;
            globalThis.setTimeout = real.setTimeout;
            globalThis.clearTimeout = real.clearTimeout;
            globalThis.setImmediate = real.setImmediate;
            globalThis.clearImmediate = real.clearImmediate;
            globalThis.setInterval = real.setInterval;
            Date.now = real.now;
            installed = null;
            if (state.livelock) {
                throw new Error(
                    `virtual time: a livelock: ${livelockTurns} macrotasks ran one after another at ` +
                    `${state.livelock.at} virtual ms without the clock moving, so nothing waited for a timer; ` +
                    `${state.livelock.dropped} macrotask(s) were dropped after it. Work that legitimately runs ` +
                    "that long without waiting passes a larger livelockTurns to installVirtualTime().");
            }
        },
    };
    installed = clock;
    return clock;
}

/** installVirtualTime(options) for the test `t`, uninstalled when it ends. */
export function useVirtualTime(t, options) {
    const clock = installVirtualTime(options);
    t.after(() => clock.uninstall());
    return clock;
}
