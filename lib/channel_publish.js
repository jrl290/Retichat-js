/**
 * What a channel post this device publishes to its rfed shows: "sending"
 * until an event decides it, then "sent" or "failed". Each post is tracked
 * from before its publish can go until its outcome (ChannelPublishes below);
 * app.js RnsClient.sendChannelMessage feeds it the events and shows each
 * outcome (_setChannelPostStatus).
 *
 * "sent" means rfed has the post, and the event that says so is rfed's echo
 * of it: rfed fans every stored post out to every subscriber of its channel,
 * the publisher included (RFed-rust fanout.rs: no sender is left out), so
 * the post comes back to this device on whatever route rfed has to it (a
 * /delivery push on the bound rfed.link, the channel stream, an rfed.delivery
 * packet, a /channel/pull), and _handleChannelPacket knows it by its
 * (source, timestamp), the dedup key (Channel.md "Deduplication"). rfed
 * pushes it once it has checked the stamp and stored the blob
 * (destinations.rs ingest_send), so the echo also says rfed accepted it.
 * The packet's link proof does not: rfed proves a publish packet as it
 * arrives, before it looks at it (Reticulum-rust link.rs: prove_packet, then
 * the packet callback on a thread of its own; RNS/Link.py proves the same
 * way), so a proof says only that rfed received the bytes, and a post whose
 * stamp rfed refuses is proved all the same (Link.md: the packet form gets
 * no answer). The proof decides nothing here: it is noted, and a post that
 * fails says whether rfed had received it. An oversized post goes as a
 * Resource, whose proof says rfed holds every part; only then can rfed
 * ingest it, so its echo is waited for from that proof.
 *
 * iOS and Android show a channel post sent on the proof (AppLinks DELIVERED,
 * RfedChannelClient.trySend); this client waits for the echo, which the
 * proof only precedes by milliseconds (staging, 2026-10-01: proof +1594 ms,
 * echo +1597 ms, "accepted" +1604 ms after the send). It used to need both
 * (since 5a392b5), so a proof lost on its way back failed a post whose echo
 * had come: the echo implies the proof.
 *
 * "failed" is a definite failure: the publish never left (the link closed
 * first, its Resource failed), or the exchange lost its packet; or, as a
 * last resort, no echo within the ceiling (app.js rfedRequestTimeoutMs, the
 * link's request budget) from the moment the publish left. Nothing is sent
 * again (DESIGN_PRINCIPLES §3). An echo that comes after the post was failed
 * still makes it "sent": rfed has it, and saying otherwise would invite the
 * user to post it twice (the truth outranks the failure, as a late DM proof
 * does).
 *
 * DESIGN_PRINCIPLES §1: an echo later than 5 s after the publish left is a
 * late success, logged as a violation. It never fails the post.
 *
 * Until 2026-10-01 the outcome reached the store and never the screen:
 * "sent" was followed only by channel-send-complete, an event that appends
 * missing rows, so the bubble kept its "sending" dot until the chat was
 * rebuilt (staging, Retichat-js f56346c: the record "sent" 0.55 s and 1.6 s
 * after the send, the bubble "sending" 25 s later).
 *
 * Nothing here touches a Node-only global at module load.
 */

/** DESIGN_PRINCIPLES §1: the longest an echo may follow its publish. */
export const ECHO_LIVE_MS = 5_000;

export class ChannelPublishes {

    /**
     * `log` gets the §1 lines (console; a test may put another log here).
     * The timers are read when used, so a test's virtual clock applies.
     */
    constructor({ now = () => Date.now(), setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (t) => clearTimeout(t), log = console } = {}) {
        this._now = now;
        this._setTimer = setTimer;
        this._clearTimer = clearTimer;
        this._log = log;
        this._posts = new Map();
    }

    /**
     * Track the post whose echo is known by `key` ("<source hash hex>:<ts
     * ms>"), before its publish can go: an echo may come back before the
     * code that sent it runs again. `sent({waitedMs, late, proved})` and
     * `failed(why, {proved})` show its outcome: each is called at most once,
     * except that `sent` may follow `failed` (a late echo). Returns the
     * post: its `status`, and `outcome`, which resolves on "sent" and
     * rejects on "failed", whichever comes first.
     */
    track(key, { sent, failed }) {
        const post = { key, status: "sending", leftAt: null, provedAt: null, ceiling: null, sent, failed };
        post.outcome = new Promise((resolve, reject) => { post.resolve = resolve; post.reject = reject; });
        // Nobody may be waiting when it fails (the publish failed before it
        // left): the failure is shown by `failed`, not by an unhandled rejection.
        post.outcome.catch(() => {});
        this._posts.set(key, post);
        return post;
    }

    /**
     * The publish of `post` left: its packet went, or its Resource was
     * proved. The §1 clock and the ceiling (`ceilingMs`, the last resort)
     * start now. Returns the post's outcome.
     */
    left(post, ceilingMs) {
        if (post.status === "sending" && post.leftAt === null) {
            post.leftAt = this._now();
            post.ceiling = this._setTimer(() => {
                post.ceiling = null;
                this.failed(post, `rfed sent no echo of the post within ${Math.round(ceilingMs)} ms`);
            }, ceilingMs);
        }
        return post.outcome;
    }

    /** rfed's link proved the publish of `post`: it received the bytes. Not "sent". */
    proved(post) {
        if (post.provedAt === null) post.provedAt = this._now();
    }

    /**
     * rfed's echo of the post with this key arrived: rfed has it. True when
     * it was a post this tracks (and is now "sent"), false otherwise.
     */
    echoed(key) {
        const post = this._posts.get(key);
        if (!post) return false;
        this._posts.delete(key);
        if (post.ceiling !== null) {
            this._clearTimer(post.ceiling);
            post.ceiling = null;
        }
        const late = post.status === "failed";
        const waitedMs = post.leftAt === null ? 0 : this._now() - post.leftAt;
        post.status = "sent";
        if (waitedMs > ECHO_LIVE_MS) {
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            this._log.error?.(`[retichat] §1 VIOLATION: rfed's echo of channel post ${key.slice(0, 20)}… came ${waitedMs} ms after the publish left (a late success is a failure)`
                + (late ? "; it had been shown failed, and is now sent" : ""));
        }
        post.sent({ waitedMs, late, proved: post.provedAt !== null });
        post.resolve();
        return true;
    }

    /**
     * A definite failure of `post` (`why`), or the ceiling: a post still
     * "sending" is "failed". It stays tracked, so its echo, should it still
     * come, makes it "sent". True when this failed it.
     */
    failed(post, why) {
        if (post.status !== "sending") return false;
        if (post.ceiling !== null) {
            this._clearTimer(post.ceiling);
            post.ceiling = null;
        }
        post.status = "failed";
        const proved = post.provedAt !== null;
        post.failed(why, { proved });
        post.reject(new Error(proved ? `${why} (rfed received it: its proof came)` : why));
        return true;
    }

    /** The connection stopped: every post still "sending" fails (`why`),
     *  and nothing is tracked any more. */
    clear(why) {
        for (const post of [...this._posts.values()]) this.failed(post, why);
        this._posts.clear();
    }
}
