/** The types an attachment's object URL may carry: images, audio and video,
 *  which a browser shows without running anything in them. */
export const INLINE_TYPES = new Set([
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/heic",
    "audio/ogg", "audio/mpeg", "audio/mp4", "audio/wav",
    "video/mp4", "video/quicktime",
]);

/** The blob type for an attachment's MIME type: itself when it is one of
 *  INLINE_TYPES, application/octet-stream (a download) for anything else. */
export function blobType(mime) {
    const type = String(mime ?? "").trim().toLowerCase();
    return INLINE_TYPES.has(type) ? type : "application/octet-stream";
}

/**
 * The object URLs the chat shows attachments through. Each is made for one
 * element (an <img>, a download link) and revoked once that element has left
 * the document: an object URL keeps its bytes alive until it is revoked, and a
 * chat that re-renders would otherwise hold every photo it ever showed.
 *
 * app.js sweeps after each render that can drop bubbles (render,
 * _rebuildDetail, a repainted row). The factories are injected for tests;
 * nothing here touches a browser global at module load.
 *
 * Every URL is typed by blobType: an object URL belongs to this page's
 * origin, and the bytes are a stranger's. Opened in a tab (the natural way to
 * see a photo at full size, or a middle-click on a download link), a blob
 * typed image/svg+xml or text/html is a document whose script runs as
 * retichat.com and can read the identity key in localStorage.
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

    /** An object URL for `bytes`, owned by `element`, typed by blobType. */
    attach(element, bytes, mime) {
        const url = this._create(this._makeBlob(bytes, blobType(mime)));
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
