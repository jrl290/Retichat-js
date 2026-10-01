/**
 * What a channel post this device publishes to its rfed shows: "sending"
 * until an event decides it, then "sent" or "failed". Each post is tracked
 * from before its publish can go until its outcome (ChannelPublishes below);
 * app.js RnsClient.sendChannelMessage feeds it the events and shows each
 * outcome (_setChannelPostStatus).
 *
 * The post is published as the `/channel/publish` request on rfed.link
 * (RFed-spec/Link.md "/channel/publish — the one behavior change"), and
 * rfed's answer decides it: `[true, nil]` once rfed has checked the stamp,
 * stored the post and handed it to its fan-out; `[false, reason]` when it
 * refused it (`stamp_invalid`, `store_failed`, ...). RFed-rust answers from
 * the same ingest the packet form runs (destinations.rs ingest_send, then
 * publish_cb), a few milliseconds after it has the bytes, whatever the size
 * of the post: a post over the link MDU crosses as a request Resource
 * (RNS/Link.py request()), and the answer to it is still one packet.
 *
 * rfed's echo of the post says the same thing and decides it too, whichever
 * comes first: rfed fans every stored post out to every subscriber of its
 * channel, the publisher included (RFed-rust fanout.rs: no sender is left
 * out), so the post comes back to this device on whatever route rfed has to
 * it, and _handleChannelPacket knows it by its (source, timestamp), the
 * dedup key (Channel.md "Deduplication"). rfed only fans out a post it has
 * stored. A small post's echo comes a millisecond before the answer (rfed
 * pushes it before it answers); a large one's is a Resource of its own,
 * which concludes seconds after the answer, so it decides nothing there.
 *
 * Until 2026-10-01 (Retichat-js 2af0e9b) the echo alone decided, with the
 * publish a bare DATA packet or Resource on rfed.channel, as iOS and Android
 * still publish it. For a post of a few KB the echo is a bulk transfer back
 * from rfed (staging, 2026-10-01: 30 KB, the echo's Resource 8.8 s; 60 KB,
 * 15.7 s), so "sent" came long after rfed had the post, the ceiling showed
 * a 60 KB post failed while rfed's echo of it was still arriving, and the
 * §1 line counted that transfer's whole time against 5 s, which
 * DESIGN_PRINCIPLES §1 "Bulk transfers" rules out. The phones show a post
 * sent on rfed's link proof (AppLinks DELIVERED, RfedChannelClient.trySend),
 * which rfed sends as the bytes arrive, before it checks the stamp: a post
 * rfed refuses shows sent there.
 *
 * "failed" is a definite failure: the publish never left (the link closed
 * first, its request Resource failed), the exchange lost its packet, rfed
 * refused it (and said why); or, as a last resort, no answer within the
 * request's own budget (app.js rfedRequestTimeoutMs, RNS/Link.py
 * RequestReceipt), which runs from the moment rfed holds the request (the
 * packet sent, or the request Resource proved) and never while the request
 * Resource is still moving (§1 bulk transfers: its own events decide).
 * Nothing is sent again (DESIGN_PRINCIPLES §3). An echo, or an answer still
 * pending, that comes after the post was shown failed still makes it "sent":
 * rfed has it, and saying otherwise would invite the user to post it twice
 * (the truth outranks the failure). A connection that stops (app.js
 * disconnect(), a Settings save or a tab taken over) closes rfed.link, and
 * the link's close fails the publish request still pending (link.js
 * _linkClosed), so the post fails on that event and stays tracked like any
 * other: its echo, from the next connection's stream or pull, makes it
 * "sent". Until 2026-10-01 (2af0e9b) the stop failed it and forgot it, so
 * that echo was taken as a duplicate and the post stayed failed.
 *
 * DESIGN_PRINCIPLES §1: rfed must answer within 5 s of holding the request.
 * The clock starts when rfed holds it (left()), so it never counts the
 * request Resource's transfer; the answer is one packet. At 5 s without an
 * answer the violation is logged, and an answer later than that is logged
 * with its time. Neither fails the post. The echo is not timed: it is
 * rfed's delivery to this device, which may be a bulk transfer of its own,
 * whose progress its Resource watches (lib/rns/resource.js BulkWatch).
 *
 * Until 2026-10-01 the outcome reached the store and never the screen:
 * "sent" was followed only by channel-send-complete, an event that appends
 * missing rows, so the bubble kept its "sending" dot until the chat was
 * rebuilt (staging, Retichat-js f56346c: the record "sent" 0.55 s and 1.6 s
 * after the send, the bubble "sending" 25 s later).
 *
 * Nothing here touches a Node-only global at module load.
 */

/** DESIGN_PRINCIPLES §1: the longest rfed may take to answer a publish it holds. */
export const ANSWER_LIVE_MS = 5_000;

/** The path of the publish request on rfed.link (RFed-spec/Link.md). */
export const CHANNEL_PUBLISH_PATH = "/channel/publish";

/**
 * rfed's answer to /channel/publish, `[bool, str|nil]` (Link.md): null when
 * it accepted the post, else why not.
 */
export function publishRefusal(response) {
    if (Array.isArray(response) && response[0] === true) return null;
    if (Array.isArray(response) && response[0] === false) {
        return `rfed refused it (${typeof response[1] === "string" && response[1] ? response[1] : "no reason given"})`;
    }
    let shown;
    try { shown = JSON.stringify(response); } catch { shown = String(response); }
    return `rfed's answer was not [ok, reason]: ${String(shown).slice(0, 80)}`;
}

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
     * code that sent it runs again. `sent({via, late})` and `failed(why)`
     * show its outcome: each is called at most once, except that `sent` may
     * follow `failed` (an answer or an echo that came after the failure).
     * Returns the post: its `status`, and `outcome`, which resolves on
     * "sent" and rejects on "failed", whichever comes first.
     */
    track(key, { sent, failed }) {
        const post = { key, status: "sending", leftAt: null, watch: null, answered: false, sent, failed };
        post.outcome = new Promise((resolve, reject) => { post.resolve = resolve; post.reject = reject; });
        // Nobody may be waiting when it fails (the publish failed before it
        // left): the failure is shown by `failed`, not by an unhandled rejection.
        post.outcome.catch(() => {});
        this._posts.set(key, post);
        return post;
    }

    /**
     * rfed holds the publish of `post`: its request packet went, or its
     * request Resource was proved (the request's DELIVERED). The §1 clock
     * starts now.
     */
    left(post) {
        if (post.leftAt !== null || post.answered) return;
        post.leftAt = this._now();
        post.watch = this._setTimer(() => {
            post.watch = null;
            const state = post.status === "sent" ? "the post is sent: its echo came"
                : post.status === "failed" ? "the post is shown failed" : "the post is still sending";
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            this._log.error?.(`[retichat] §1 VIOLATION: rfed has not answered the publish of channel post ${post.key.slice(0, 20)}… `
                + `within ${ANSWER_LIVE_MS / 1000} s of holding it (${state}); its answer, or the request's own failure, decides it`);
        }, ANSWER_LIVE_MS + 1);
    }

    /** The publish request of `post` is over (answered, or failed): its §1 clock stops. */
    _concluded(post) {
        post.answered = true;
        if (post.watch !== null) {
            this._clearTimer(post.watch);
            post.watch = null;
        }
    }

    /**
     * rfed answered the publish of `post` (`response`, Link.md `[bool,
     * str|nil]`): it has the post, or it refused it. True when this decided it.
     */
    answered(post, response) {
        if (post.answered) return false;
        this._concluded(post);
        const waitedMs = post.leftAt === null ? 0 : this._now() - post.leftAt;
        if (waitedMs > ANSWER_LIVE_MS) {
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            this._log.error?.(`[retichat] §1 VIOLATION: rfed answered the publish of channel post ${post.key.slice(0, 20)}… `
                + `${waitedMs} ms after it held it (a late success is a failure)`);
        }
        const refusal = publishRefusal(response);
        return refusal === null ? this._sent(post, "rfed's answer") : this.failed(post, refusal);
    }

    /** The publish request of `post` failed (`why`: the link's own reason). */
    unanswered(post, why) {
        if (post.answered) return false;
        this._concluded(post);
        return this.failed(post, why);
    }

    /**
     * rfed's echo of the post with this key arrived: rfed has it. True when
     * it was a post this tracks (and is now "sent"), false otherwise.
     */
    echoed(key) {
        const post = this._posts.get(key);
        return post ? this._sent(post, "rfed's echo") : false;
    }

    _sent(post, via) {
        if (post.status === "sent") return false;
        this._posts.delete(post.key);
        const late = post.status === "failed";
        post.status = "sent";
        post.sent({ via, late });
        post.resolve();
        return true;
    }

    /**
     * A definite failure of `post` (`why`): a post still "sending" is
     * "failed". It stays tracked, so its echo or its answer, should either
     * still come, makes it "sent". True when this failed it.
     */
    failed(post, why) {
        if (post.status !== "sending") return false;
        post.status = "failed";
        post.failed(why);
        post.reject(new Error(why));
        return true;
    }
}
