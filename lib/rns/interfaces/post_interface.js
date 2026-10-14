/**
 * PostInterface — HTTP POST polling interface for Reticulum-php.
 *
 * Implements the rns.js Interface contract using the same POST exchange
 * protocol that your Reticulum-php node already speaks. No WebSocket,
 * no open ports, no Apache modules needed — just HTTP.
 *
 * The browser app POSTs raw RNS packets to the node's /v1/interfaces/exchange
 * endpoint and receives delivery packets in the response. Polls on the
 * idle_exchange_interval_ms returned by the node.
 *
 * Registration is signed (Reticulum-post REGISTRATION-STAGE1.md, "Stage 1:
 * browsers sign their registration", 2026-10-14): the interface asks the PHP
 * node for a challenge, signs its registration with its own identity key
 * (signRegistration), and decrypts the session token the PHP node answers
 * with, encrypted to that key (decryptSessionToken). A PHP node without
 * Stage 1 answers the challenge 404, the only answer on which this interface
 * registers the legacy way, unsigned (§3, §10): the same page runs on a node
 * with Stage 1 and on one without. Given only an identity hash (an app.js
 * older than Stage 1), it asks the challenge by that hash, registers the
 * legacy way on a 404 and otherwise stops, saying the page is out of date.
 *
 * Events (U6, CONNECTIVITY_READINESS.md, 2026-09-25):
 *   registered          a registration succeeded (a new session)
 *   up                  the first 200 exchange after a registration or a down
 *   down(reason)        an exchange or registration was rejected, answered
 *                       non-2xx, or aborted by the browser; once per failure
 *                       run, which only an "up" ends
 *   lost({packetHashes, reason, abandoned, unsent})
 *                       packets that will never leave: the batch of a failed
 *                       or abandoned exchange, and what a down interface
 *                       refused. Hashes are full packet hashes, hex.
 *                       abandoned is true for the batch of an exchange
 *                       check() gave up on: whether the node took it cannot
 *                       be known, and no "down" is marked for it.
 *                       unsent is the part of packetHashes that never went
 *                       into any request, so nothing of it was sent: what a
 *                       down or blocked interface refused, and what was
 *                       still queued when an exchange failed or the
 *                       interface was blocked. The rest, the batch of a
 *                       failed or abandoned exchange, may have reached the
 *                       node. A sender whose packet is in `unsent` may say
 *                       that nothing was sent (James, 2026-10-06: an upload
 *                       for the distro that never left the device is no
 *                       failure, RnsClient._onPacketsLost); every other
 *                       reader of "lost" treats all of packetHashes alike.
 *   stopped(reason)     the PHP node gave an answer after which no attempt
 *                       can succeed (REGISTRATION-STAGE1.md §10, "stops,
 *                       says why"): the interface ends as block() ends it,
 *                       reports its packets lost, and emits this exactly
 *                       once, whatever "down" said before. `reason` is a
 *                       sentence for a person, never the answer's error
 *                       code. Only a reload or a reconnect (a new
 *                       interface) asks the PHP node again.
 * Until 2026-09-25 only "registered" existed: a failed exchange was logged
 * and its batch dropped unseen, and the app showed online while it had
 * credentials.
 */
import Packet from "../packet.js";
import Interface from "./interface.js";

/** REGISTRATION-STAGE1.md §4.2: the domain every registration signs first. */
const REGISTER_DOMAIN = 'reticulum-post/register/v1';
const LOWER_HEX = /^[0-9a-f]+$/;
/** An `error` code as §10 writes them; anything else in that field is free text, never acted on or logged. */
const ERROR_CODE = /^[a-z0-9_]{1,64}$/;

const isLowerHex = (value, length) => typeof value === 'string' && value.length === length && LOWER_HEX.test(value);

/** §4.2: lp(x) = u16be(len(x)) || x. */
function lp(bytes) {
    if (bytes.length > 0xffff) throw new RangeError(`a signed field of ${bytes.length} bytes is longer than lp() can carry`);
    return Buffer.concat([Buffer.from([bytes.length >> 8, bytes.length & 0xff]), bytes]);
}

/** `value` (an integer from 0 to 2^53 - 1) as `width` bytes, big-endian: §4.2's u8, u32be and u64be. */
function uintBE(value, width) {
    if (!Number.isSafeInteger(value) || value < 0 || value >= 2 ** (8 * Math.min(width, 6.625))) {
        throw new RangeError(`${value} does not fit ${width} unsigned byte(s)`);
    }
    const out = Buffer.alloc(width);
    let rest = value;
    for (let i = width - 1; i >= 0; i--) {
        out[i] = rest % 256;
        rest = Math.floor(rest / 256);
    }
    return out;
}

/**
 * REGISTRATION-STAGE1.md §4.1 and §4.2: a browser's signed registration.
 * The one function that builds the signed bytes, from the values the body
 * carries, and the only received bytes it signs are the challenge's, in
 * their field, verbatim. A browser carries no transport and no peer, so the
 * last four fields are empty ("0000" each), and no address of the PHP node
 * is signed (James, 2026-10-14). Vectors: Reticulum-post
 * php/tests/vectors/registration_vectors.json, format 6
 * (registration_vectors.test.mjs).
 *
 * @param {object} identity   the RNS identity that registers (Identity: sign, getPublicKey)
 * @param {{name: string, bitrate: number, mtu: number, mode: number}} fields
 * @param {string} challenge  the PHP node's challenge, 96 lower-case hex, as it gave it
 * @returns {{body: object, signed: Buffer}} the register request's body, and the bytes its signature covers
 */
export function signRegistration(identity, { name, bitrate, mtu, mode }, challenge) {
    if (!isLowerHex(challenge, 96)) throw new TypeError("a challenge is 96 lower-case hex characters");
    const publicKey = identity.getPublicKey();
    const metadata = { client: 'rns-js', implementation: 'PostInterface', mode };
    const signed = Buffer.concat([
        lp(Buffer.from(REGISTER_DOMAIN, 'utf8')),
        lp(Buffer.from(challenge, 'hex')),
        lp(publicKey),
        lp(Buffer.from(name, 'utf8')),
        lp(uintBE(bitrate, 8)),
        lp(uintBE(mtu, 4)),
        lp(Buffer.from(metadata.client, 'utf8')),
        lp(uintBE(mode, 1)),
        lp(Buffer.alloc(0)),    // metadata.transport
        lp(Buffer.alloc(0)),    // metadata.peer_url
        lp(Buffer.alloc(0)),    // metadata.peer_interface_id
        lp(Buffer.alloc(0)),    // metadata.peer_session_token
    ]);
    const body = {
        name, bitrate, mtu, metadata,
        registration: {
            version: 1,
            public_key: publicKey.toString('hex'),
            challenge,
            signature: Buffer.from(identity.sign(signed)).toString('hex'),
        },
    };
    return { body, signed };
}

/**
 * REGISTRATION-STAGE1.md §5: the session token of a signed registration's
 * answer, `session_token_encrypted` decrypted with the browser's own
 * identity (RNS Identity.decrypt, no ratchet), or null when it does not
 * decrypt (an HMAC failure, a low-order key, a short blob) or its plaintext
 * is not 64 lower-case hex. There is never a plaintext token to fall back to.
 */
export function decryptSessionToken(identity, encryptedHex) {
    if (typeof encryptedHex !== 'string' || encryptedHex.length === 0 || encryptedHex.length % 2 !== 0
        || !LOWER_HEX.test(encryptedHex)) return null;
    let plaintext;
    try {
        plaintext = identity.decrypt(Buffer.from(encryptedHex, 'hex'));
    } catch (e) {
        return null;
    }
    if (!plaintext) return null;
    const token = Buffer.from(plaintext).toString('utf8');
    return isLowerHex(token, 64) ? token : null;
}

/** An answer of the PHP node after which this interface stops, saying `reason` (§10); `detail` is for the log. */
class Stop extends Error {
    constructor(reason, detail) {
        super(detail ?? reason);
        this.stopReason = reason;
    }
}

/** No protocol answer: a network failure, a 5xx, a 2xx that is not JSON, or (on an exchange) a 4xx §10 does not list. */
function failure(message, status = 0) {
    const err = new Error(message);
    err.status = status;
    return err;
}

/** A 4xx: the PHP node's answer to this request, not a failure to reach it. */
const isRefusal = (status) => status >= 400 && status < 500;

class PostInterface extends Interface {
    /** Upper bound on back-to-back exchanges before the idle poll interval applies. */
    static MAX_IMMEDIATE_EXCHANGES = 16;

    /**
     * The backoff before the next attempt (challenge, registration or
     * exchange) after a failure: a network failure, a 5xx, a 2xx that is not
     * JSON, or a 4xx on an exchange that REGISTRATION-STAGE1.md §10 does not
     * list. 2 s, twice as
     * long after each further failure, capped at 5 min; any success, an
     * exchange's 200 or a registration, resets it to 2 s. An online, visible
     * or pageshow event makes the next attempt at once (check()) and leaves
     * the backoff where it was, so a failure after it waits the next step.
     * A 401 is a protocol answer, not a failure: it registers again at
     * once. The answers that stop wait for nothing. James's decided
     * exception to DESIGN_PRINCIPLES §3 (2026-10-14, "the browser's next
     * attempt at its PHP node after a failure"; any success resets it,
     * James, 2026-10-14, so that separate drops over hours do not grow an
     * open tab's wait toward 5 min). The failure is still said: the
     * interface is down while it lasts. It replaces the fixed 5 s wait the
     * browser had before (RECONNECT_WAIT_MS, after the reference's
     * TCPClientInterface.RECONNECT_WAIT). It paces the next attempt; it
     * decides nothing, and no packet is re-sent after it.
     */
    static BACKOFF_FIRST_MS = 2_000;
    static BACKOFF_CAP_MS = 300_000;

    /**
     * DESIGN_PRINCIPLES §1: every challenge, registration and exchange, and
     * the keepalive goodbye, is a network send whose answer must come
     * within 5 s of the send (REGISTRATION-STAGE1.md §6). A later answer is
     * said, and still decides (_answered).
     */
    static ANSWER_LIVE_MS = 5_000;
    /** The clock _answered reads; tests replace it. */
    static now = () => Date.now();

    /** The sentences "stopped" says (REGISTRATION-STAGE1.md §8, §10). */
    static STOP_SUPERSEDED = "This identity connected from another tab or device. Reload to connect here.";
    static STOP_STALE_CHALLENGE = "Another registration of this identity got in first. Reload to connect here.";
    static STOP_DROPPED = "The PHP node dropped this connection as soon as it was made. Reload to connect.";
    static STOP_OUT_OF_DATE = "This page is out of date. Reload it to connect.";
    /** A token that does not decrypt, another identity hash, or an answer that is not the protocol's (§5). */
    static STOP_BAD_ANSWER = "The PHP node's answer to this connection could not be verified. Reload to connect.";
    /** A refusal whose answer carries no message for a person (a PHP node older than Stage 1). */
    static STOP_REFUSED = "The PHP node refused this connection. Reload to connect.";

    static BITRATE = 1000000;
    static MTU = 500;

    /**
     * @param {string} name       Human-readable name
     * @param {string} baseUrl    Base URL of the Reticulum-php node (e.g. https://example.com/reticulum)
     * @param {object|string} [identity]  The RNS identity that registers (signs and
     *                            decrypts: RnsClient passes IdMgr.id), or, from an
     *                            app.js older than Stage 1, only its hash (hex), which
     *                            cannot sign (see _registerWithHashOnly)
     * @param {number} [mode]     RNS interface mode (defaults to MODE_FULL = 1)
     */
    constructor(name, baseUrl, identity, mode) {
        super(name);
        this._baseUrl = baseUrl.replace(/\/$/, "");
        const signs = !!identity && typeof identity === 'object' && typeof identity.sign === 'function'
            && typeof identity.decrypt === 'function' && typeof identity.getPublicKey === 'function';
        this._identity = signs ? identity : null;
        this._identityHash = signs ? Buffer.from(identity.hash).toString('hex')
            : (typeof identity === 'string' && identity ? identity : null);
        this._mode = typeof mode === 'number' ? mode : Interface.MODE_FULL;
        this._interfaceId = null;
        this._sessionToken = null;
        this._outboundQueue = [];      // raw bytes queued for next exchange
        this._pendingAckIds = [];      // batch IDs to acknowledge
        this._pollTimer = null;
        this._pollIntervalMs = 1000;   // default, updated by node
        this._maxPacketBytes = 500;
        this._maxBatchPackets = 64;
        this._batchSeq = 0;
        this._running = false;
        this._exchangeInFlight = false;
        this._exchangePending = false;
        // true after a 200 exchange, false after a failure, null before
        // either and again after each registration (a session not yet proven).
        this._up = null;
        // "down" was emitted and no "up" since. Separate from _up: a
        // registration makes the interface carry packets again (_up null)
        // without ending the failure run the app was told about.
        this._downReported = false;
        // The next exchange is the first of the session a registration just
        // made. A 401 answering that one stops the interface (§7): the PHP
        // node dropped the session as soon as it was made.
        this._sessionFirstExchange = false;
        this._backoffMs = PostInterface.BACKOFF_FIRST_MS;   // what the next failure waits
        this._retryWaitMs = PostInterface.BACKOFF_FIRST_MS; // what the last failure waits
        this._abort = null;            // AbortController of the exchange in flight
        this._blocked = null;          // why block() stopped this interface for good
        this._stopped = null;          // why the PHP node's answer stopped it for good (_stop)
        this._checkRequested = false;  // check() asked for an exchange now
        this._pageHooks = null;
    }

    get isRegistered() {
        return this._interfaceId !== null && this._sessionToken !== null;
    }

    /** The last exchange succeeded. */
    get isUp() {
        return this._up === true;
    }

    /** The last exchange or registration failed, and nothing has succeeded since. */
    get isDown() {
        return this._up === false;
    }

    /** Why the PHP node's answer stopped this interface (the sentence "stopped" said), or null. */
    get stoppedReason() {
        return this._stopped;
    }

    /**
     * Register, then exchange and poll. Never rejects: a failed registration
     * is a down interface that registers again at the next exchange
     * opportunity (the backoff, or check()). Until 2026-09-25 this
     * awaited the first registration and rejected before polling started,
     * and nothing caught it (reticulum.js addInterface), so a page opened
     * offline stayed offline until it was reloaded.
     */
    async connect() {
        // A stopped interface stays stopped: "stopped" is said once, and a
        // reconnect is a new interface.
        if (this._stopped !== null) return;
        this._running = true;
        this._up = null;
        this._downReported = false;

        // Always register fresh — saved tokens go stale on reconnect.
        this._clearCredentials();
        this._hookPage();

        console.log(`[http-exchange] Starting exchange with ${this._baseUrl}`);
        await this._flushIfIdle();
    }

    /**
     * The page events this interface acts on, hooked once per interface and
     * unhooked by disconnect():
     *  - pagehide: tell the node the page is going away, so it stops holding
     *    our registration (and the local destinations behind it) until its
     *    stale timeout. pagehide is the one unload event browsers deliver
     *    reliably; the beacon is best effort and the node's timeout stays as
     *    the backstop for crashes and lost networks. Not when the page enters
     *    the back/forward cache (event.persisted): it may come back with this
     *    registration, and pageshow then checks it.
     *  - online, visibilitychange to visible, pageshow from the cache: the
     *    network may have changed under the page, so check() now.
     */
    _hookPage() {
        if (this._pageHooks || typeof window === 'undefined' || !window.addEventListener) return;
        this._pageHooks = [
            [window, 'pagehide', (event) => { if (!event?.persisted) this.goodbye(); }],
            [window, 'pageshow', (event) => { if (event?.persisted) this.check('pageshow'); }],
            [window, 'online', () => this.check('online')],
        ];
        if (typeof document !== 'undefined' && document.addEventListener) {
            this._pageHooks.push([document, 'visibilitychange', () => {
                if (document.visibilityState === 'visible') this.check('visible');
            }]);
        }
        for (const [target, type, listener] of this._pageHooks) target.addEventListener(type, listener);
    }

    _unhookPage() {
        for (const [target, type, listener] of this._pageHooks ?? []) target.removeEventListener(type, listener);
        this._pageHooks = null;
    }

    /**
     * POST /v1/interfaces/goodbye: the node marks this interface offline at
     * once and drops the local destinations and paths registered through it.
     * Sent as a text/plain beacon so it needs no CORS preflight and survives
     * page unload; falls back to a keepalive fetch where beacons are absent.
     * Idempotent, and the node's stale sweep still runs regardless. A
     * beacon has no answer to time (sendBeacon says only that the body was
     * queued), so the stale sweep is its backstop; the keepalive fetch gets
     * an answer, and it is held to §1 like every other request
     * (REGISTRATION-STAGE1.md §6).
     */
    goodbye() {
        if (!this.isRegistered) return false;
        const url = this._baseUrl + '/v1/interfaces/goodbye';
        const body = JSON.stringify({ interface_id: this._interfaceId, session_token: this._sessionToken });
        try {
            if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
                return navigator.sendBeacon(url, new Blob([body], { type: 'text/plain' }));
            }
            if (typeof fetch === 'function') {
                const sentAt = this._clock();
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 (the answer is timed: _answered)
                fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body, keepalive: true })
                    .then((resp) => this._answered('goodbye', sentAt, resp?.status), () => {});
                return true;
            }
        } catch (e) {
            console.warn('[http-exchange] goodbye failed:', e.message);
        }
        return false;
    }

    disconnect() {
        this.goodbye();
        this._running = false;
        this._unhookPage();
        // A registration still in flight is aborted: its session would
        // belong to no one. One the node already took never displaces the
        // tab that takes this identity over: that tab's challenge is made at
        // the count it moved, or its registration answered 409
        // stale_challenge and given one more round (REGISTRATION-STAGE1.md
        // §4.3); at a PHP node without Stage 1 it costs that tab a single
        // 401 and re-registration (D11). This interface never registers
        // again. An exchange in flight is left to land, because it may
        // carry a LINKCLOSE (RnsClient.disconnect() closes its links first);
        // nothing is taken from its answer (_doExchange), and the node hands
        // the unacknowledged delivery batch to the next session of this
        // identity, which reuses the interface row.
        if (!this.isRegistered) this._abort?.abort();
        if (this._pollTimer) {
            clearTimeout(this._pollTimer);
            this._pollTimer = null;
        }
    }

    /**
     * The page may not reach this exchange: its Content-Security-Policy
     * blocks the URL (RnsClient._checkSavedExchange), so the browser refuses
     * every request to it before it is sent. Stop for good, as disconnect()
     * does but with no goodbye (a blocked URL never registered), and carry
     * nothing from now on: what is queued, and every packet sent to this
     * interface after, is lost at once with `reason` (see _lose), as a down
     * interface's is, so a sender hears of it now instead of waiting on an
     * exchange that cannot happen. No "down" is emitted for it, and no
     * "stopped": the app says why itself. Until 2026-10-01 such an
     * interface kept asking every reconnect wait, each request refused by
     * the browser.
     */
    block(reason) {
        this._blocked = reason;
        this._running = false;
        this._unhookPage();
        this._abort?.abort();
        if (this._pollTimer) {
            clearTimeout(this._pollTimer);
            this._pollTimer = null;
        }
        this._up = false;
        const queued = this._outboundQueue.splice(0);
        this._lose(queued, reason, { unsent: queued });
    }

    /**
     * The network may have changed under the page (online, visible again,
     * restored from the back/forward cache): exchange now rather than on the
     * poll timer or the backoff, which is left where it was. An exchange in
     * flight may be waiting on a
     * connection that is gone, and a fetch has no deadline of its own, so
     * nothing else would ever end it (until 2026-09-25 one hung fetch stalled
     * all transport). It is aborted, its batch is lost (see _lose), and the
     * exchange started here decides up or down. A no-op after disconnect(),
     * block() or a stop.
     */
    check(reason) {
        if (!this._running) return;
        console.log(`[http-exchange] check (${reason})`);
        this._checkRequested = true;
        if (this._abort) {
            // The running cycle sees _checkRequested and exchanges again at once.
            this._abort.abort();
            return;
        }
        this._flushIfIdle();
    }

    /**
     * Queue raw packet data for the next exchange.
     * Triggers an immediate flush so UI-initiated sends don't wait for the poll timer.
     * Called by the rns.js stack.
     */
    sendData(data) {
        if (!data || data.length === 0) return;
        // The node rejects the ENTIRE exchange batch with HTTP 400 if any one
        // packet exceeds the limit it advertised at registration, so a single
        // oversized frame destroys every other packet queued alongside it.
        // Drop it here instead of poisoning the batch. Callers that build
        // link payloads are size-checked earlier (see Link.MDU).
        if (this._maxPacketBytes && data.length > this._maxPacketBytes) {
            console.error(`[http-exchange] Dropping ${data.length}B packet: node accepts at most ${this._maxPacketBytes}B`);
            return;
        }
        // A down interface carries nothing (as the reference's TCPInterface
        // process_outgoing writes only while online). The packet is lost now,
        // where its sender can see it, not queued for an exchange that may
        // never come (D3). Nothing of it was sent, and "lost" says so
        // (`unsent`).
        if (this._up === false) {
            this._lose([data], this._stopped ?? this._blocked ?? 'the exchange is down', { unsent: [data] });
            return;
        }
        this._outboundQueue.push(data);
        this._flushIfIdle();
    }

    /** Trigger an immediate exchange if one isn't already in flight. */
    async _flushIfIdle() {
        if (!this._running) return;
        if (this._exchangeInFlight) {
            this._exchangePending = true;
            return;
        }
        // Cancel the next scheduled poll so we don't double-fire
        if (this._pollTimer) {
            clearTimeout(this._pollTimer);
            this._pollTimer = null;
        }
        // Exchange again at once while there is work (queued packets, acks
        // to send, a flush requested mid-flight), but never more than
        // MAX_IMMEDIATE_EXCHANGES in a row: a node that keeps handing the
        // same unacknowledged batch back (2026-09-23, a SQLite node that
        // never numbered its packets) otherwise turns this into a tight loop
        // of ~40 exchanges a second, each replaying the same packets into
        // the stack. After the bound the idle poll interval applies.
        //
        // A failure ends the run: the next attempt comes after the backoff
        // (BACKOFF_FIRST_MS), or at once on check(). The exception is a 401,
        // which means the node is reachable and has forgotten the session:
        // register again at once (REGISTRATION-STAGE1.md §7). That is one
        // registration per 401, and a 401 on the first exchange of the
        // session just made stops the interface (_runExchange), so two
        // sessions fighting over one registration (two tabs, D11) cannot
        // spin here. An answer that stops the interface ends the run with
        // nothing armed.
        let immediate = 0;
        let outcome;
        do {
            this._exchangePending = false;
            this._checkRequested = false;
            outcome = await this._runExchange();
            immediate++;
        } while (this._running && immediate < PostInterface.MAX_IMMEDIATE_EXCHANGES && (
            outcome === 'session-lost' ||
            this._checkRequested ||
            (outcome === 'ok' && (
                this._exchangePending ||
                this._outboundQueue.length > 0 ||
                this._pendingAckIds.length > 0
            ))
        ));
        if (immediate >= PostInterface.MAX_IMMEDIATE_EXCHANGES && this._running) {
            console.warn(`[http-exchange] ${immediate} consecutive exchanges with work still pending — yielding to the poll interval (${this._pollIntervalMs}ms)`);
        }
        // Restart the poll timer from now, or wait out the backoff after a
        // failure. A run the bound ended on a 401 registers on the poll.
        if (this._running) {
            const wait = outcome === 'failed' ? this._retryWaitMs : this._pollIntervalMs;
            this._pollTimer = setTimeout(() => this._poll(), wait);
        }
    }

    async _poll() {
        if (!this._running) return;
        await this._flushIfIdle();
    }

    /**
     * One exchange opportunity: register first when there is no session,
     * then exchange. Never throws. Returns "ok", "failed", "aborted" (check()
     * gave up on it), "session-lost" (a 401: the node no longer knows the
     * session) or "stopped" (an answer after which nothing can succeed, §10).
     */
    async _runExchange() {
        if (this._exchangeInFlight) return 'failed';
        this._exchangeInFlight = true;
        const abort = new AbortController();
        this._abort = abort;
        const batch = { packets: [], ackIds: [], firstOfSession: false };
        try {
            if (!this.isRegistered) await this._register(abort.signal);
            await this._doExchange(abort.signal, batch);
            // Landed after disconnect(): the interface is gone, nothing to report.
            if (this._running) {
                // Any success resets the backoff (James, 2026-10-14).
                this._backoffMs = PostInterface.BACKOFF_FIRST_MS;
                this._markUp();
            }
            return 'ok';
        } catch (err) {
            // Failed after disconnect() (or aborted by it): nothing to report.
            if (!this._running) return 'failed';
            // The node never acknowledged these, so they are still owed.
            this._pendingAckIds.unshift(...batch.ackIds);
            // An answer that stops the interface decides, whatever came after it.
            if (err instanceof Stop) {
                this._stop(err.stopReason, err.message, batch.packets);
                return 'stopped';
            }
            if (abort.signal.aborted) {
                // check() gave up on this exchange; whether the node took the
                // batch is unknowable, and a re-send is a retry (§3). The
                // exchange check() starts next decides up or down, and may
                // carry the node's answers to it (Link.requestLost).
                this._lose(batch.packets, `exchange abandoned by a check`, { abandoned: true });
                return 'aborted';
            }
            if (err.status === 401 && batch.firstOfSession) {
                // REGISTRATION-STAGE1.md §7: one registration per 401, and
                // the first exchange of the session that registration made
                // was refused. Registering again would only have the PHP
                // node drop the next one too. At a PHP node without Stage 1
                // (a legacy session) the rule is the same.
                this._stop(PostInterface.STOP_DROPPED, 'the first exchange of a new session was answered 401', batch.packets);
                return 'stopped';
            }
            console.warn(`[http-exchange] Exchange failed:`, err.message);
            this._markDown(err.message);
            // What was queued behind the failed batch cannot leave either.
            // That part was in no request, so nothing of it was sent
            // (`unsent`); the batch itself may have reached the node.
            const queued = this._outboundQueue.splice(0);
            this._lose([...batch.packets, ...queued], err.message, { unsent: queued });
            if (err.status === 401) {
                // By its status alone (§7): today's match on the text
                // "Invalid interface credentials" is gone.
                console.log('[http-exchange] Session lost (401) — registering again at once');
                this._clearCredentials();
                return 'session-lost';
            }
            this._backOff();
            return 'failed';
        } finally {
            this._exchangeInFlight = false;
            if (this._abort === abort) this._abort = null;
        }
    }

    /** A failure: the next attempt waits the backoff's current step, and the step after doubles (BACKOFF_FIRST_MS). */
    _backOff() {
        this._retryWaitMs = this._backoffMs;
        this._backoffMs = Math.min(this._backoffMs * 2, PostInterface.BACKOFF_CAP_MS);
        console.warn(`[http-exchange] Next attempt in ${this._retryWaitMs / 1000} s, or at once when the page comes back online or into view`);
    }

    _markUp() {
        this._downReported = false;
        if (this._up === true) return;
        this._up = true;
        console.log(`[http-exchange] Exchange up`);
        this.emit('up');
    }

    _markDown(reason) {
        this._up = false;
        if (this._downReported) return;
        this._downReported = true;
        console.warn(`[http-exchange] Exchange down: ${reason}`);
        this.emit('down', reason);
    }

    /**
     * REGISTRATION-STAGE1.md §10, "stops, says why": the PHP node answered
     * so that no further attempt can succeed. The interface ends as block()
     * ends it (nothing is asked of the PHP node again, and every packet
     * given to it is lost at once, saying why), with no backoff; it emits
     * "stopped" with `reason`, a sentence for a person, exactly once; and
     * the packets it held, `packets` (the batch of the exchange so
     * answered) and the queue behind them, are reported lost. Its
     * credentials go too: a superseded or refused token is no one's, and a
     * goodbye with it would change nothing.
     */
    _stop(reason, detail, packets = []) {
        if (this._stopped !== null) return;
        this._stopped = reason;
        this._running = false;
        this._unhookPage();
        if (this._pollTimer) {
            clearTimeout(this._pollTimer);
            this._pollTimer = null;
        }
        this._up = false;
        this._clearCredentials();
        console.warn(`[http-exchange] Stopped (${detail}): ${reason}`);
        this.emit('stopped', reason);
        const queued = this._outboundQueue.splice(0);
        this._lose([...packets, ...queued], reason, { unsent: queued });
    }

    /**
     * Report packets that will never leave. Dropping them is parity (a TCP
     * interface that goes down drops what it cannot write); dropping them
     * unseen was the bug, because a DM in the batch then waited out the
     * 30 s ceiling as if it might still arrive.
     *
     * `unsent` is the part of `packets` that never went into any request
     * (the event's `unsent`): only the callers that know it pass it,
     * and a batch an exchange was carrying, or gave up on, never is.
     */
    _lose(packets, reason, { abandoned = false, unsent = [] } = {}) {
        if (packets.length === 0) return;
        const hashes = (raws) => {
            const found = [];
            for (const raw of raws) {
                try {
                    found.push(Packet.fromBytes(raw).packetHash.toString('hex'));
                } catch (e) {}
            }
            return found;
        };
        console.warn(`[http-exchange] ${packets.length} packet(s) lost: ${reason}`);
        this.emit('lost', { packetHashes: hashes(packets), reason, abandoned, unsent: hashes(unsent) });
    }

    // ---- Registration (REGISTRATION-STAGE1.md §3 to §5, §10) ----

    /**
     * Challenge, sign, register, decrypt: a signed registration
     * (signRegistration, decryptSessionToken). A 409 stale_challenge earns
     * one new challenge and one more registration, and only one: a second
     * stops the interface (§4.3, James, 2026-10-04: the registration this
     * page abandoned on a check() or a disconnect() that the PHP node still
     * completed, or another tab or device of this identity binding between
     * this challenge and this registration). A challenge answered 404 is a
     * PHP node without Stage 1, and only that registers the legacy way. A
     * network failure, a 5xx or a 2xx that is not JSON throws a failure (the
     * backoff); any other answer that does not end in a session stops the
     * interface, saying why: a 4xx (§10), a challenge for another identity,
     * a token that does not decrypt to this identity or another identity
     * hash (§5).
     */
    async _register(signal) {
        if (!this._identity) return this._registerWithHashOnly(signal);
        const publicKey = this._identity.getPublicKey().toString('hex');
        let staleRound = false;
        for (;;) {
            console.log(`[http-exchange] Registering interface "${this.name}" with ${this._baseUrl}: asking for a challenge`);
            const asked = await this._request('/v1/interfaces/challenge', { public_key: publicKey }, signal, 'challenge');
            this._throwIfGone();
            if (asked.status === 404) {
                console.log(`[http-exchange] The PHP node answered the challenge 404: it has no signed registration, so this interface registers the legacy way`);
                return this._registerLegacy(signal);
            }
            this._throwUnlessAnswered(asked, 'challenge');
            if (!asked.ok) throw new Stop(this._refusalReason(asked), this._describe('challenge', asked));
            if (!asked.json || typeof asked.json !== 'object') throw this._notJson('challenge', asked);
            const challenge = this._challengeFrom(asked.json);
            if (challenge === null) {
                throw new Stop(PostInterface.STOP_BAD_ANSWER, `the PHP node's answer to the challenge (HTTP ${asked.status}) is not a challenge for ${this._identityHash}`);
            }
            const { body } = signRegistration(this._identity,
                { name: this.name, bitrate: PostInterface.BITRATE, mtu: PostInterface.MTU, mode: this._mode }, challenge);
            const answer = await this._request('/v1/interfaces/register', body, signal, 'registration');
            this._throwIfGone();
            if (answer.status === 409 && answer.code === 'stale_challenge') {
                if (staleRound) throw new Stop(PostInterface.STOP_STALE_CHALLENGE, 'the registration was answered 409 stale_challenge twice');
                staleRound = true;
                console.log(`[http-exchange] The registration was answered 409 stale_challenge: asking for one new challenge and registering once more`);
                continue;
            }
            this._throwUnlessAnswered(answer, 'registration');
            if (!answer.ok) throw new Stop(this._refusalReason(answer), this._describe('registration', answer));
            if (!answer.json || typeof answer.json !== 'object') throw this._notJson('registration', answer);
            const session = this._sessionFrom(answer.json);
            if (session.problem) {
                throw new Stop(PostInterface.STOP_BAD_ANSWER, `the PHP node's answer to the registration (HTTP ${answer.status}): ${session.problem}`);
            }
            this._startSession(session.interfaceId, session.token, answer.json, 'signed');
            return;
        }
    }

    /**
     * An app.js older than Stage 1 gives this interface only its identity
     * hash, so it cannot sign (§10). It asks the challenge by that hash: a
     * 404 is a PHP node without Stage 1, where it registers the legacy way;
     * any other answer means the PHP node signs registrations and this page
     * cannot, so it stops. A network failure or a 5xx is no answer (the
     * backoff). The PHP node counts these challenges (`/health`'s
     * hash_only_challenges), so an old app.js served anywhere shows there.
     */
    async _registerWithHashOnly(signal) {
        console.log(`[http-exchange] Registering interface "${this.name}" with ${this._baseUrl}: this page gave no identity that signs, so it asks for a challenge by its identity hash`);
        const asked = await this._request('/v1/interfaces/challenge', { identity_hash: this._identityHash ?? '' }, signal, 'challenge');
        this._throwIfGone();
        if (asked.status === 404) return this._registerLegacy(signal);
        this._throwUnlessAnswered(asked, 'challenge');
        throw new Stop(PostInterface.STOP_OUT_OF_DATE, `the PHP node signs registrations (its challenge answered HTTP ${asked.status}) and this page cannot`);
    }

    /**
     * The legacy registration, unsigned, as before Stage 1: only at a PHP
     * node whose challenge answered 404. Its answer carries the session
     * token in plain text. A refusal stops the interface (§10); a network
     * failure, a 5xx or an answer without a session is a failure (the
     * backoff), as before.
     */
    async _registerLegacy(signal) {
        const answer = await this._request('/v1/interfaces/register', {
            name: this.name,
            bitrate: PostInterface.BITRATE,
            mtu: PostInterface.MTU,
            metadata: {
                client: 'rns-js',
                implementation: 'PostInterface',
                mode: this._mode,
                identity_hash: this._identityHash || '',
            },
        }, signal, 'registration');
        this._throwIfGone();
        if (isRefusal(answer.status)) throw new Stop(this._refusalReason(answer), this._describe('legacy registration', answer));
        this._throwUnlessAnswered(answer, 'registration');
        const json = answer.json;
        if (!json || typeof json.interface_id !== 'string' || json.interface_id === ''
            || typeof json.session_token !== 'string' || json.session_token === '') {
            throw failure(`the PHP node's answer to the registration (HTTP ${answer.status}) carries no session`, answer.status);
        }
        this._startSession(json.interface_id, json.session_token, json, 'legacy');
    }

    /** §3: the challenge in the PHP node's answer, or null when the answer is not a challenge for this identity. */
    _challengeFrom(json) {
        if (!json || typeof json !== 'object') return null;
        if (json.status !== 'challenge' || json.version !== 1) return null;
        if (json.identity_hash !== this._identityHash) return null;
        return isLowerHex(json.challenge, 96) ? json.challenge : null;
    }

    /**
     * §5: the session in a signed registration's answer, `{interfaceId,
     * token}`, or `{problem}`. The answer's identity hash MUST be this
     * identity's and its token MUST decrypt to 64 lower-case hex; a
     * plaintext `session_token` is never read.
     */
    _sessionFrom(json) {
        if (json.identity_hash !== this._identityHash) return { problem: 'it names another identity hash' };
        const interfaceId = json.interface_id;
        if (typeof interfaceId !== 'string' || interfaceId.length === 0 || interfaceId.length > 64) {
            return { problem: 'it has no interface id' };
        }
        const token = decryptSessionToken(this._identity, json.session_token_encrypted);
        if (token === null) return { problem: 'its session token does not decrypt to this identity' };
        return { interfaceId, token };
    }

    /** A registration succeeded: the new session, which carries packets again and is up on its first 200. */
    _startSession(interfaceId, token, json, how) {
        this._interfaceId = interfaceId;
        this._sessionToken = token;
        this._maxBatchPackets = json.max_batch_packets || 64;
        this._maxPacketBytes = json.max_packet_bytes || 500;
        this._pollIntervalMs = json.idle_exchange_interval_ms || 1000;
        this._up = null;
        this._sessionFirstExchange = true;
        // Any success resets the backoff (James, 2026-10-14).
        this._backoffMs = PostInterface.BACKOFF_FIRST_MS;

        // Never the token (REGISTRATION-STAGE1.md §11).
        console.log(`[http-exchange] Registered (${how}): ${this._interfaceId.slice(0,8)}... poll=${this._pollIntervalMs}ms`);

        this._saveCredentials();
        this.emit('registered');
    }

    /** Answered after disconnect(), block() or a stop: nothing of it is kept, and nothing more is asked. */
    _throwIfGone() {
        if (!this._running) throw new Error('answered after the interface stopped');
    }

    /** A status that is neither a 2xx nor a 4xx (a 5xx) on the challenge or a registration is a failure: the backoff. */
    _throwUnlessAnswered(answer, what) {
        if (answer.ok || isRefusal(answer.status)) return;
        throw failure(`the PHP node answered the ${what} HTTP ${answer.status}${answer.code ? ` ${answer.code}` : ''}`, answer.status);
    }

    /** What "stopped" says for a refusal: §10's sentence for its code, else the answer's message, never its code. */
    _refusalReason(answer) {
        if (answer.code === 'session_superseded') return PostInterface.STOP_SUPERSEDED;
        if (answer.code === 'stale_challenge') return PostInterface.STOP_STALE_CHALLENGE;
        return answer.message ?? PostInterface.STOP_REFUSED;
    }

    /**
     * A 2xx whose body is not JSON (a captive portal's page, a PHP error
     * page): no protocol answer, so a failure (the backoff), as an
     * exchange's always was. The excerpt logged has every run of 32 or more
     * hex digits cut out, so that no token, challenge or signature an error
     * page echoed reaches the log (REGISTRATION-STAGE1.md §11).
     */
    _notJson(what, answer) {
        const excerpt = answer.text.slice(0, 200).replace(/[0-9a-fA-F]{32,}/g, '[hex]');
        console.error(`[http-exchange] The PHP node's answer to the ${what} is not JSON (HTTP ${answer.status}, ${answer.length} bytes): ${excerpt}`);
        return failure(`the PHP node's answer to the ${what} is not JSON`, answer.status);
    }

    _describe(what, answer) {
        return `the PHP node answered the ${what} HTTP ${answer.status}${answer.code ? ` ${answer.code}` : ''}`;
    }

    async _doExchange(signal, batch) {
        if (!this.isRegistered) return;

        // Grab queued outbound packets. They are out of the queue from here
        // on; if the exchange fails, _runExchange reports them lost.
        const packets = this._outboundQueue.splice(0, this._maxBatchPackets);
        const ackIds = this._pendingAckIds.splice(0);
        batch.packets = packets;
        batch.ackIds = ackIds;

        const body = {
            interface_id: this._interfaceId,
            session_token: this._sessionToken,
            ack_batch_ids: ackIds,
            max_packets: this._maxBatchPackets,
            packets: packets.map(p => this._bytesToBase64(p)),
        };

        if (packets.length > 0) {
            body.batch_id = `web-${Date.now()}-${++this._batchSeq}`;
        }

        batch.firstOfSession = this._sessionFirstExchange;
        this._sessionFirstExchange = false;
        const answer = await this._request('/v1/interfaces/exchange', body, signal, 'exchange');

        // Landed after disconnect(): its packets reached the node, but its
        // delivery batch is left unacknowledged for the next session of this
        // identity (another tab's, after a takeover) rather than fed into a
        // stopped stack.
        if (!this._running) return;

        // §8: a newer signed registration of this identity replaced this
        // session. Newest wins: this one stops, saying so.
        if (answer.status === 409 && answer.code === 'session_superseded') {
            throw new Stop(PostInterface.STOP_SUPERSEDED, this._describe('exchange', answer));
        }
        // §7: Session lost, by its status alone. Any other answer that is
        // not a 200 is a failure, as before Stage 1.
        if (!answer.ok) throw failure(`HTTP ${answer.status}${answer.code ? ` ${answer.code}` : ''}`, answer.status);
        const resp = answer.json;
        if (!resp || typeof resp !== 'object') throw this._notJson('exchange', answer);

        // Process delivery packets
        const deliveryPackets = resp.delivery_packets || [];
        const deliveryBatchId = resp.delivery_batch_id || null;

        if (deliveryPackets.length > 0) {
            for (const pktBase64 of deliveryPackets) {
                if (typeof pktBase64 !== 'string' || pktBase64 === '') continue;
                const raw = this._base64ToBytes(pktBase64);
                if (!raw) continue;
                try {
                    this.processIncoming(raw);
                } catch (e) {
                    console.warn('[http-exchange] Failed to process incoming packet:', e.message);
                }
            }

            if (deliveryBatchId) {
                this._pendingAckIds.push(deliveryBatchId);
            }
        }

        // Update poll interval if the node changed it
        if (resp.idle_exchange_interval_ms && resp.idle_exchange_interval_ms !== this._pollIntervalMs) {
            this._pollIntervalMs = resp.idle_exchange_interval_ms;
            this._saveCredentials();
        }
    }

    /**
     * Process a deframed incoming packet.
     * Delegates to the rns.js stack.
     */
    processIncoming(data) {
        // Skip IFAC packets
        if ((data[0] & 0x80) === 0x80) {
            console.log('[http-exchange] IFAC packet received — skipping');
            return;
        }

        try {
            const packet = Packet.fromBytes(data);
            if (this.rns) {
                this.rns.onPacketReceived(packet, this);
            }
        } catch (e) {
            console.warn('[http-exchange] Failed to parse packet:', e.message);
        }
    }

    // ---- HTTP helpers ----

    /**
     * One POST to the PHP node, timed from its send to its answer
     * (_answered). Resolves with the answer, whatever its status: `{status,
     * ok, json, code, message, text, length}`, `json` the parsed body or
     * null, `code` its `error` when that is a code (§10), `message` its one
     * line for a person. Rejects only when there is no answer: a network
     * failure, or the AbortSignal every request carries, so that check(),
     * disconnect() and block() can end it.
     */
    async _request(path, body, signal, what) {
        const url = this._baseUrl + path;
        const sentAt = this._clock();
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal,
        });
        const text = await resp.text();
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 (the answer is timed: _answered)
        this._answered(what, sentAt, resp.status);
        let json = null;
        try {
            json = text ? JSON.parse(text) : null;
        } catch (e) {}
        const code = typeof json?.error === 'string' && ERROR_CODE.test(json.error) ? json.error : null;
        const message = typeof json?.message === 'string' && json.message.trim()
            ? json.message.replace(/\s+/g, ' ').trim().slice(0, 300) : null;
        return { status: resp.status, ok: resp.ok, json, code, message, text, length: text.length };
    }

    _clock() {
        return PostInterface.now();
    }

    /**
     * DESIGN_PRINCIPLES §1 for one request to the PHP node: its answer,
     * whatever its status, came `sentAt`'s distance after the send. Later
     * than 5 s is a violation, said here; the answer still decides, as any
     * answer does (REGISTRATION-STAGE1.md §6). Never a token, a challenge
     * or a signature in the line (§11).
     */
    _answered(what, sentAt, status) {
        const waitedMs = this._clock() - sentAt;
        if (waitedMs > PostInterface.ANSWER_LIVE_MS) {
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            console.error(`[http-exchange] §1 VIOLATION: the PHP node answered the ${what} (HTTP ${status}) ${waitedMs} ms after it was sent, more than ${PostInterface.ANSWER_LIVE_MS / 1000} s: something upstream is slow (the answer still decides)`);
        }
    }

    // ---- Base64 helpers (browser-native) ----

    _bytesToBase64(bytes) {
        // Convert Buffer/Uint8Array to base64 string
        const arr = new Uint8Array(bytes);
        let binary = '';
        for (let i = 0; i < arr.length; i++) {
            binary += String.fromCharCode(arr[i]);
        }
        return btoa(binary);
    }

    _base64ToBytes(b64) {
        try {
            const binary = atob(b64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return Buffer.from(bytes);
        } catch (e) {
            return null;
        }
    }

    // ---- Credential persistence ----

    _credentialKey() {
        const base = 'rns_exchange_creds';
        if (this._identityHash) {
            return base + '_' + this._identityHash.slice(0, 16);
        }
        return base;
    }

    _loadCredentials() {
        try {
            const raw = localStorage.getItem(this._credentialKey());
            if (raw) {
                const c = JSON.parse(raw);
                if (c.interfaceId && c.sessionToken) return c;
            }
        } catch (e) {}
        return null;
    }

    _saveCredentials() {
        try {
            localStorage.setItem(this._credentialKey(), JSON.stringify({
                interfaceId: this._interfaceId,
                sessionToken: this._sessionToken,
                baseUrl: this._baseUrl,
                maxBatchPackets: this._maxBatchPackets,
                maxPacketBytes: this._maxPacketBytes,
                pollIntervalMs: this._pollIntervalMs,
            }));
        } catch (e) {}
    }

    _clearCredentials() {
        this._interfaceId = null;
        this._sessionToken = null;
        try { localStorage.removeItem(this._credentialKey()); } catch (e) {}
    }
}

export default PostInterface;
