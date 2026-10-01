/**
 * Where the web client keeps attachment bytes.
 *
 * Message records live in localStorage (app.js MsgStore), which cannot hold
 * photos: its quota is a few MB per origin, and app.js sSet swallows a failed
 * write, so one photo there would make every later save of that conversation
 * fail unseen. The bytes go to IndexedDB instead, one entry per attachment,
 * keyed "<message id>:<index>" (attachmentKey). The record keeps only
 * {key, name, mime, size, sha256, field, stored}.
 *
 * `stored` says where the bytes are, and the bubble says it when it is not
 * "persisted":
 *   "persisted" — written to IndexedDB;
 *   "session"   — IndexedDB is unavailable (private mode, blocked storage):
 *                 kept in this tab's memory, gone on reload;
 *   "failed"    — the IndexedDB write failed (quota): kept in memory for
 *                 this session too, with the error; never a silent loss.
 * The page boots and works without IndexedDB: open() falls back to memory.
 *
 * Backends are injected so the store can be tested without a browser: a
 * backend is {put(key, bytes), get(key), delete(key), clear()}, each async.
 * Nothing here touches a Node-only global at module load (the page loads it
 * as an ES module before app.js has set globalThis.Buffer).
 */

/** The key of attachment `index` of message `msgId`. */
export function attachmentKey(msgId, index) {
    return `${msgId}:${index}`;
}

/**
 * A backend that keeps everything in memory, for tests: `persistent` makes
 * it stand in for IndexedDB, `failPut` makes every write fail with it.
 */
export function memoryBackend({ persistent = false, failPut = null } = {}) {
    const data = new Map();
    return {
        persistent,
        data,
        async put(key, bytes) {
            if (failPut) throw new Error(failPut);
            data.set(key, new Uint8Array(bytes));
        },
        async get(key) { return data.has(key) ? data.get(key) : null; },
        async delete(key) { data.delete(key); },
        async clear() { data.clear(); },
    };
}

const DB_NAME = "retichat_attachments";
const STORE = "bytes";

const request = (req) => new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB request failed"));
});

/**
 * An IndexedDB backend, or a rejection when IndexedDB cannot be opened
 * (absent, private mode, blocked by the user's settings).
 */
export async function indexedDbBackend(idb = globalThis.indexedDB, name = DB_NAME) {
    if (!idb || typeof idb.open !== "function") throw new Error("IndexedDB is not available");
    const open = idb.open(name, 1);
    open.onupgradeneeded = () => {
        if (!open.result.objectStoreNames.contains(STORE)) open.result.createObjectStore(STORE);
    };
    const db = await request(open);
    const tx = (mode, run) => new Promise((resolve, reject) => {
        let result;
        const t = db.transaction(STORE, mode);
        t.oncomplete = () => resolve(result);
        t.onabort = () => reject(t.error ?? new Error("IndexedDB transaction aborted"));
        t.onerror = () => reject(t.error ?? new Error("IndexedDB transaction failed"));
        const req = run(t.objectStore(STORE));
        if (req) req.onsuccess = () => { result = req.result; };
    });
    return {
        persistent: true,
        put: (key, bytes) => tx("readwrite", (s) => s.put(bytes, key)),
        get: async (key) => {
            const v = await tx("readonly", (s) => s.get(key));
            if (v == null) return null;
            return v instanceof Uint8Array ? v : new Uint8Array(v);
        },
        delete: (key) => tx("readwrite", (s) => s.delete(key)),
        clear: () => tx("readwrite", (s) => s.clear()),
    };
}

export class AttachmentStore {

    /**
     * @param {Promise<object>|object|null} backend a backend, a promise of one
     *   (rejected: memory only), or null for memory only
     * @param {{warn?: Function}} options
     */
    constructor(backend = null, { warn = (...a) => console.warn(...a) } = {}) {
        this._warn = warn;
        // key -> bytes held in this tab: while a write is in flight, for the
        // session when nothing persists them, and while a send warms them.
        this._mem = new Map();
        this._pending = new Map();   // key -> promise of the put in flight
        this._warm = new Map();      // key -> count of warm() holds
        this.backendError = null;
        this._backend = Promise.resolve(backend).then(
            (b) => b ?? null,
            (e) => {
                this.backendError = e?.message || String(e);
                this._warn(`[attachments] IndexedDB is unavailable (${this.backendError}): attachments are kept for this session only`);
                return null;
            });
    }

    /** The store the page uses: IndexedDB when it opens, memory otherwise. */
    static open(idb = globalThis.indexedDB) {
        return new AttachmentStore(indexedDbBackend(idb));
    }

    /** Resolves to true when the bytes outlive the tab (IndexedDB opened). */
    async persistent() {
        const b = await this._backend;
        return !!b?.persistent;
    }

    /**
     * Keep `bytes` under `key`. The bytes are readable at once (peek, get)
     * and stay in memory until the write has landed. Resolves to
     * {stored: "persisted"|"session"|"failed", error}; never rejects.
     */
    put(key, bytes) {
        // A view into a larger buffer (an attachment is a slice of the
        // decrypted message) is copied out first: IndexedDB's structured
        // clone would otherwise store the whole buffer behind it.
        const tight = bytes instanceof Uint8Array && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
        const data = tight ? bytes : new Uint8Array(bytes);
        this._mem.set(key, data);
        const done = (async () => {
            const backend = await this._backend;
            if (!backend) return { stored: "session", error: this.backendError };
            try {
                await backend.put(key, data);
            } catch (e) {
                const error = e?.message || String(e);
                this._warn(`[attachments] could not save ${key} (${error}): kept for this session only`);
                return { stored: "failed", error };
            }
            if (this._pending.get(key) === done && !this._warm.has(key)) this._mem.delete(key);
            return { stored: backend.persistent ? "persisted" : "session", error: null };
        })();
        this._pending.set(key, done);
        done.finally(() => { if (this._pending.get(key) === done) this._pending.delete(key); });
        return done;
    }

    /** The bytes if this tab holds them in memory now, else null. Sync. */
    peek(key) {
        return this._mem.get(key) ?? null;
    }

    /** The bytes, from memory or the backend; null when nothing holds them. */
    async get(key) {
        const held = this._mem.get(key);
        if (held) return held;
        const backend = await this._backend;
        if (!backend) return null;
        try {
            return (await backend.get(key)) ?? null;
        } catch (e) {
            this._warn(`[attachments] could not read ${key}: ${e?.message || e}`);
            return null;
        }
    }

    /**
     * The bytes as they are kept: after any write in flight has landed, read
     * back from the backend when it holds them, else from memory. What a
     * test of the store compares (the attachment hook's sha256).
     */
    async readBack(key) {
        const pending = this._pending.get(key);
        if (pending) await pending;
        const backend = await this._backend;
        if (backend) {
            try {
                const v = await backend.get(key);
                if (v) return v;
            } catch (e) {
                this._warn(`[attachments] could not read ${key} back: ${e?.message || e}`);
            }
        }
        return this._mem.get(key) ?? null;
    }

    /**
     * Load `keys` into memory and hold them there until cool(keys), so a
     * synchronous send path can peek them. Resolves to the keys it could not
     * find.
     */
    async warm(keys) {
        const missing = [];
        for (const key of keys) {
            this._warm.set(key, (this._warm.get(key) ?? 0) + 1);
            const bytes = await this.get(key);
            if (bytes) this._mem.set(key, bytes);
            else missing.push(key);
        }
        return missing;
    }

    /** Release warm() holds; bytes the backend keeps leave memory. */
    async cool(keys) {
        const backend = await this._backend;
        for (const key of keys) {
            const n = (this._warm.get(key) ?? 1) - 1;
            if (n > 0) { this._warm.set(key, n); continue; }
            this._warm.delete(key);
            if (backend && !this._pending.has(key)) {
                // Only bytes the backend really holds may leave memory.
                let kept = null;
                try { kept = await backend.get(key); } catch (e) { kept = null; }
                if (kept && !this._warm.has(key)) this._mem.delete(key);
            }
        }
    }

    /** Delete these keys everywhere. Failures are reported, never swallowed. */
    async remove(keys) {
        const backend = await this._backend;
        const failed = [];
        for (const key of keys) {
            this._mem.delete(key);
            this._warm.delete(key);
            if (!backend) continue;
            try {
                await backend.delete(key);
            } catch (e) {
                failed.push(key);
                this._warn(`[attachments] could not delete ${key}: ${e?.message || e}`);
            }
        }
        return failed;
    }

    /** Delete every attachment (Reset All). */
    async clear() {
        this._mem.clear();
        this._warm.clear();
        const backend = await this._backend;
        if (backend) await backend.clear();
    }
}

/** The attachment keys of these message records (their stored metas). */
export function keysOf(records) {
    const keys = [];
    for (const r of records ?? []) {
        for (const a of r?.attachments ?? []) if (a?.key) keys.push(a.key);
    }
    return keys;
}
