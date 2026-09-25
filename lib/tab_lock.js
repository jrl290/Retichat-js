/**
 * TabLock — one active tab per identity (D11, CONNECTIVITY_READINESS.md).
 *
 * James, 2026-09-25: "a pop-up saying another tab is active, and if
 * possible, a button that will defeat the other tab in order to load the new
 * tab." Two tabs of one identity register the same exchange interface, and
 * the node rotates the session token on every registration
 * (Reticulum-post request_interface_registry_trait.php), so each tab's
 * registration knocked the other's session out: a 401 ping-pong.
 *
 * The active tab holds a Web Lock named for the identity for as long as it
 * runs. A tab that cannot take the lock at once is not active. Taking over is
 * two steps, in this order: queue for the lock, then broadcast "takeover" on
 * a BroadcastChannel of the same name. The holder stops (onTakenOver), and
 * only then releases, so the lock manager hands the lock to the queued tab
 * after the holder has stopped exchanging. A holder that closes or crashes
 * releases it too. No clock decides anything. A tab left queued because its
 * broadcast went unheard asks again with takeOver(), which broadcasts again
 * from the same place in the queue.
 *
 * Without navigator.locks (Safari before 15.4, an insecure context), or where
 * it refuses the request (a sandboxed or opaque-origin document), a tab
 * cannot learn that another is active except by waiting for a reply that may
 * never come, which would be a timeout. The newest tab wins instead: it takes
 * over as it starts, and any other tab stops on its broadcast. Without
 * BroadcastChannel as well nothing can be arbitrated, and the tab runs
 * unguarded, as every tab did before.
 */
export class TabLock {
    /**
     * @param {string} name  lock and channel name, one per identity
     * @param {object} [options]
     * @param {LockManager|null} [options.locks]  defaults to navigator.locks; null for none
     * @param {typeof BroadcastChannel|null} [options.BroadcastChannel]  defaults to the global; null for none
     * @param {() => (void|Promise<void>)} [options.onTakenOver]  stop this tab; the lock is released after it returns
     */
    constructor(name, { locks, BroadcastChannel: Channel, onTakenOver } = {}) {
        this.name = name;
        this._locks = locks !== undefined ? locks : (globalThis.navigator?.locks ?? null);
        const ChannelClass = Channel !== undefined ? Channel : (globalThis.BroadcastChannel ?? null);
        this._channel = null;
        try {
            this._channel = ChannelClass ? new ChannelClass(name) : null;
        } catch (e) {
            console.warn("[tab] no BroadcastChannel:", e.message);
        }
        this._onTakenOver = onTakenOver ?? null;
        this._held = false;
        this._grant = null;     // { release } of the lock this tab holds, until release()
        this._waiting = null;   // a queued request, from takeOver()
        if (this._channel) this._channel.onmessage = (event) => this._onMessage(event.data);
    }

    /** This tab is the active tab. */
    get held() {
        return this._held;
    }

    /** takeOver() is queued for the lock and not yet granted it. */
    get waiting() {
        return this._waiting !== null;
    }

    /** Become the active tab if no other tab is. Resolves true when this tab holds the lock, false when another tab does. */
    tryAcquire() {
        if (!this._locks) return Promise.resolve(this._takeWithoutLocks());
        return this._request({ ifAvailable: true });
    }

    /**
     * "Use here": queue for the lock, then ask the active tab to let go.
     * Resolves true once this tab holds the lock, which is after the other
     * tab has stopped (or closed). Called again while queued, it asks again.
     */
    takeOver() {
        if (!this._locks) return Promise.resolve(this._takeWithoutLocks());
        if (this._held) return Promise.resolve(true);
        // Queued before the broadcast, so the holder's release hands the lock here.
        if (!this._waiting) {
            this._waiting = this._request({}).finally(() => { this._waiting = null; });
        }
        this._broadcast();
        return this._waiting;
    }

    /** Stop being the active tab; the next queued tab gets the lock. */
    release() {
        this._held = false;
        const grant = this._grant;
        this._grant = null;
        grant?.release();
    }

    /** Never rejects: a request the lock manager refuses falls back to the newest tab winning. */
    _request(options) {
        return new Promise((resolve) => {
            let grant = null;
            const granted = (lock) => {
                if (!lock) {
                    resolve(false);
                    return undefined;
                }
                this._held = true;
                resolve(true);
                // The lock is held until this promise settles: release().
                return new Promise((release) => { grant = { release }; this._grant = grant; });
            };
            let request;
            try {
                request = this._locks.request(this.name, options, granted);
            } catch (e) {
                request = Promise.reject(e);
            }
            Promise.resolve(request).then(
                () => { if (grant) this._ended(grant); },
                (error) => { if (grant) this._ended(grant); else resolve(this._refused(error)); },
            );
        });
    }

    /**
     * The request settled after it was granted. release() ends it on
     * purpose; anything else means the browser took the lock from this tab
     * (a steal, or any release this tab did not ask for), and another tab
     * may already hold it. This tab stops as if taken over.
     */
    _ended(grant) {
        if (this._grant !== grant) return;
        this._grant = null;
        if (!this._held) return;
        this._held = false;
        console.warn(`[tab] ${this.name} was taken from this tab`);
        this._onTakenOver?.();
    }

    /** navigator.locks exists but refused the request: as without it. */
    _refused(error) {
        console.warn(`[tab] Web Locks refused (${error?.message}): the newest tab wins`);
        this._locks = null;
        return this._takeWithoutLocks();
    }

    _takeWithoutLocks() {
        this._held = true;
        this._broadcast();
        return true;
    }

    _broadcast() {
        try {
            this._channel?.postMessage({ type: "takeover" });
        } catch (e) {
            console.warn("[tab] takeover broadcast failed:", e.message);
        }
    }

    async _onMessage(message) {
        if (message?.type !== "takeover" || !this._held) return;
        // Not held from here on, so a second takeover is ignored. Stop first,
        // release after: the tab taking over must never register while this
        // one still exchanges.
        this._held = false;
        try {
            await this._onTakenOver?.();
        } finally {
            this.release();
        }
    }
}

export default TabLock;
