export class GroupFallbackRegistry {
    constructor(
        setTimer = (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
        clearTimer = timer => globalThis.clearTimeout(timer),
    ) {
        this._setTimer = setTimer;
        this._clearTimer = clearTimer;
        this._entries = new Map();
    }

    schedule(key, delayMs, startFallback) {
        if (this._entries.has(key)) return false;
        const timer = this._setTimer(() => {
            if (!this._entries.delete(key)) return;
            startFallback();
        }, delayMs);
        this._entries.set(key, timer);
        return true;
    }

    prove(key) {
        const timer = this._entries.get(key);
        if (timer == null) return false;
        this._clearTimer(timer);
        this._entries.delete(key);
        return true;
    }

    clear() {
        for (const timer of this._entries.values()) this._clearTimer(timer);
        this._entries.clear();
    }
}

export class GroupDeliveryEvidence {
    constructor(memberHash) {
        this.memberHash = memberHash;
        this.settled = false;
        this.promise = new Promise(resolve => {
            this._resolve = resolve;
        });
    }

    fulfill(method) {
        if (this.settled) return false;
        this.settled = true;
        this._resolve({memberHash: this.memberHash, method});
        return true;
    }
}