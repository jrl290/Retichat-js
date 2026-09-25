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
 * Events (U6, CONNECTIVITY_READINESS.md, 2026-09-25):
 *   registered          a registration succeeded (a new session)
 *   up                  the first 200 exchange after a registration or a down
 *   down(reason)        an exchange or registration was rejected, answered
 *                       non-2xx, or aborted by the browser; once per failure
 *                       run, which only an "up" ends
 *   lost({packetHashes, reason})
 *                       packets that will never leave: the batch of a failed
 *                       or abandoned exchange, and what a down interface
 *                       refused. Hashes are full packet hashes, hex.
 * Until 2026-09-25 only "registered" existed: a failed exchange was logged
 * and its batch dropped unseen, and the app showed online while it had
 * credentials.
 */
import Packet from "../packet.js";
import Interface from "./interface.js";

class PostInterface extends Interface {
    /** Upper bound on back-to-back exchanges before the idle poll interval applies. */
    static MAX_IMMEDIATE_EXCHANGES = 16;

    /**
     * The wait before the next attempt after a failed exchange or
     * registration: the reference's TCPClientInterface.RECONNECT_WAIT
     * (TCPInterface.py:80, 276), which applies while the network is up and
     * the peer is not. check() cuts it short on the events that say the page
     * may have its network back. It paces the next attempt; it decides
     * nothing, and no packet is re-sent after it.
     */
    static RECONNECT_WAIT_MS = 5000;

    /**
     * @param {string} name       Human-readable name
     * @param {string} baseUrl    Base URL of the Reticulum-php node (e.g. https://example.com/reticulum)
     * @param {string} [identityHash]  Optional identity hash to scope credentials
     * @param {number} [mode]     RNS interface mode (defaults to MODE_FULL = 1)
     */
    constructor(name, baseUrl, identityHash, mode) {
        super(name);
        this._baseUrl = baseUrl.replace(/\/$/, "");
        this._identityHash = identityHash || null;
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
        this._abort = null;            // AbortController of the exchange in flight
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

    /**
     * Register, then exchange and poll. Never rejects: a failed registration
     * is a down interface that registers again at the next exchange
     * opportunity (the reconnect wait, or check()). Until 2026-09-25 this
     * awaited the first registration and rejected before polling started,
     * and nothing caught it (reticulum.js addInterface), so a page opened
     * offline stayed offline until it was reloaded.
     */
    async connect() {
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
     * Idempotent, and the node's stale sweep still runs regardless.
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
                fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body, keepalive: true }).catch(() => {});
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
        // A registration still in flight is aborted: landing, it would rotate
        // the node's session token under the tab that takes this identity
        // over (D11). One the node already took costs that tab a single 401
        // and re-registration; this interface never registers again. An
        // exchange in flight is left to land, because it may
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
     * The network may have changed under the page (online, visible again,
     * restored from the back/forward cache): exchange now rather than on the
     * poll or reconnect timer. An exchange in flight may be waiting on a
     * connection that is gone, and a fetch has no deadline of its own, so
     * nothing else would ever end it (until 2026-09-25 one hung fetch stalled
     * all transport). It is aborted, its batch is lost (see _lose), and the
     * exchange started here decides up or down. A no-op after disconnect().
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
        // never come (D3).
        if (this._up === false) {
            this._lose([data], 'the exchange is down');
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
        // A failure ends the run: the next attempt comes after the reconnect
        // wait, or at once on check(). The exception is a 401, which means
        // the node is reachable and has forgotten the session: register
        // again at once, once per run, so two sessions fighting over one
        // registration (two tabs, D11) cannot spin here.
        let immediate = 0;
        let outcome;
        let reregistered = false;
        let again;
        do {
            this._exchangePending = false;
            this._checkRequested = false;
            outcome = await this._runExchange();
            immediate++;
            again = outcome === 'session-lost' && !reregistered;
            if (again) reregistered = true;
        } while (this._running && immediate < PostInterface.MAX_IMMEDIATE_EXCHANGES && (
            again ||
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
        // Restart the poll timer from now
        if (this._running) {
            const wait = outcome === 'ok' ? this._pollIntervalMs : PostInterface.RECONNECT_WAIT_MS;
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
     * gave up on it) or "session-lost" (a 401: the node no longer knows the
     * session).
     */
    async _runExchange() {
        if (this._exchangeInFlight) return 'failed';
        this._exchangeInFlight = true;
        const abort = new AbortController();
        this._abort = abort;
        const batch = { packets: [], ackIds: [] };
        try {
            if (!this.isRegistered) await this._register(abort.signal);
            await this._doExchange(abort.signal, batch);
            // Landed after disconnect(): the interface is gone, nothing to report.
            if (this._running) this._markUp();
            return 'ok';
        } catch (err) {
            // Failed after disconnect() (or aborted by it): nothing to report.
            if (!this._running) return 'failed';
            // The node never acknowledged these, so they are still owed.
            this._pendingAckIds.unshift(...batch.ackIds);
            if (abort.signal.aborted) {
                // check() gave up on this exchange; whether the node took the
                // batch is unknowable, and a re-send is a retry (§3). The
                // exchange check() starts next decides up or down.
                this._lose(batch.packets, `exchange abandoned by a check`);
                return 'aborted';
            }
            console.warn(`[http-exchange] Exchange failed:`, err.message);
            this._markDown(err.message);
            // What was queued behind the failed batch cannot leave either.
            this._lose([...batch.packets, ...this._outboundQueue.splice(0)], err.message);
            if (err.status === 401 || err.message?.includes('Invalid interface credentials')) {
                console.log('[http-exchange] Session lost — registering again');
                this._clearCredentials();
                return 'session-lost';
            }
            return 'failed';
        } finally {
            this._exchangeInFlight = false;
            if (this._abort === abort) this._abort = null;
        }
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
     * Report packets that will never leave. Dropping them is parity (a TCP
     * interface that goes down drops what it cannot write); dropping them
     * unseen was the bug, because a DM in the batch then waited out the
     * 30 s ceiling as if it might still arrive.
     */
    _lose(packets, reason) {
        if (packets.length === 0) return;
        const packetHashes = [];
        for (const raw of packets) {
            try {
                packetHashes.push(Packet.fromBytes(raw).packetHash.toString('hex'));
            } catch (e) {}
        }
        console.warn(`[http-exchange] ${packets.length} packet(s) lost: ${reason}`);
        this.emit('lost', { packetHashes, reason });
    }

    // ---- Registration ----

    async _register(signal) {
        console.log(`[http-exchange] Registering interface "${this.name}" with ${this._baseUrl}...`);
        const resp = await this._post('/v1/interfaces/register', {
            name: this.name,
            bitrate: 1000000,
            mtu: 500,
            metadata: {
                client: 'rns-js',
                implementation: 'PostInterface',
                mode: this._mode,
                identity_hash: this._identityHash || '',
            },
        }, signal);
        // Answered after disconnect() despite the abort: the session belongs
        // to no one, and nothing is kept, saved or announced.
        if (!this._running) throw new Error('Registered after disconnect');

        this._interfaceId = resp.interface_id;
        this._sessionToken = resp.session_token;
        this._maxBatchPackets = resp.max_batch_packets || 64;
        this._maxPacketBytes = resp.max_packet_bytes || 500;
        this._pollIntervalMs = resp.idle_exchange_interval_ms || 1000;
        // A new session carries packets again, and is up on its first 200.
        this._up = null;

        console.log(`[http-exchange] Registered: ${this._interfaceId.slice(0,8)}... token=${this._sessionToken.slice(0,12)}... poll=${this._pollIntervalMs}ms`);

        this._saveCredentials();
        this.emit('registered');
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

        const resp = await this._post('/v1/interfaces/exchange', body, signal);

        // Landed after disconnect(): its packets reached the node, but its
        // delivery batch is left unacknowledged for the next session of this
        // identity (another tab's, after a takeover) rather than fed into a
        // stopped stack.
        if (!this._running) return;

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

    /** Every request carries the exchange's AbortSignal, so check() and disconnect() can end it. */
    async _post(path, body, signal) {
        const url = this._baseUrl + path;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal,
        });

        if (!resp.ok) {
            const text = await resp.text().catch(() => '');
            const err = new Error(`HTTP ${resp.status}: ${text.slice(0, 200)}`);
            err.status = resp.status;
            throw err;
        }

        const text = await resp.text();
        try {
            return JSON.parse(text);
        } catch (e) {
            console.error('[http-exchange] JSON parse failed. Response text:', text.slice(0, 500));
            throw e;
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
