/**
 * The object URLs the chat shows attachments through. Each is made for one
 * element (an <img>, a download link) and revoked once that element has left
 * the document: an object URL keeps its bytes alive until it is revoked, and a
 * chat that re-renders would otherwise hold every photo it ever showed.
 *
 * app.js sweeps after each render that can drop bubbles (render,
 * _rebuildDetail, a repainted row). The factories are injected for tests;
 * nothing here touches a browser global at module load.
 */
export class ObjectUrls {

    constructor({
        create = (blob) => URL.createObjectURL(blob),
        revoke = (url) => URL.revokeObjectURL(url),
        makeBlob = (bytes, type) => new Blob([bytes], { type: type || "application/octet-stream" }),
    } = {}) {
        this._create = create;
        this._revoke = revoke;
        this._makeBlob = makeBlob;
        this._live = new Map(); // url -> element
    }

    /** An object URL for `bytes`, owned by `element`. */
    attach(element, bytes, mime) {
        const url = this._create(this._makeBlob(bytes, mime));
        this._live.set(url, element);
        return url;
    }

    /** Revoke the URL now (its element is being replaced). */
    release(url) {
        if (!this._live.has(url)) return;
        this._live.delete(url);
        this._revoke(url);
    }

    /** Revoke every URL whose element is no longer in the document.
     *  Returns how many were revoked. */
    sweep() {
        let revoked = 0;
        for (const [url, element] of [...this._live]) {
            if (element?.isConnected) continue;
            this._live.delete(url);
            this._revoke(url);
            revoked++;
        }
        return revoked;
    }

    /** How many URLs are live. */
    get size() {
        return this._live.size;
    }
}
