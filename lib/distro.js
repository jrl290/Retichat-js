/**
 * DistroManager — Distro identity management for Retichat Web.
 *
 * A Distro identity is a shared LXMF identity that multiple devices use
 * to receive fanout messages. One device generates the identity and
 * shares it with others via encrypted LXMF transfer or QR code URI.
 *
 * URI format: rfed-distro-private-key://<128_hex_chars>
 *   - 64-byte private key (X25519_priv 32 || Ed25519_priv 32)
 *   - Public key is derived from private key on import
 *
 * Security model:
 *   - Private key never displayed to user
 *   - Stored in localStorage (browser secure storage)
 *   - Transferred encrypted via LXMF or ephemeral QR code
 */

import { Identity, Destination } from "./rns/reticulum.js";

const DISTRO_ID_KEY = "retichat_distro_identity";
// Named for what it carries. The old "rfed-distro-id://" read like a public
// identifier; this is the private key itself, and the scheme should say so.
const DISTRO_URI_SCHEME = "rfed-distro-private-key://";
const LEGACY_URI_SCHEME = "rfed-distro-id://";

const DistroManager = {
    _identity: null,
    _listeners: [],

    /**
     * Initialize from stored identity.
     */
    init() {
        const hex = localStorage.getItem(DISTRO_ID_KEY);
        if (hex && hex.length === 128) {
            try {
                this._identity = Identity.fromPrivateKey(globalThis.Buffer.from(hex, "hex"));
            } catch(e) {
                console.warn("[distro] Failed to load stored identity:", e);
                localStorage.removeItem(DISTRO_ID_KEY);
            }
        }
    },

    /**
     * Check if a distro identity is loaded.
     */
    get has() { return this._identity !== null; },

    /**
     * Get the distro identity hash (16 bytes hex).
     */
    get hash() { return this._identity?.hash?.toString("hex") ?? null; },

    /**
     * Get the distro identity public key (64 bytes hex).
     */
    get pubKey() { return this._identity?.getPublicKey()?.toString("hex") ?? null; },

    /**
     * Get the distro identity's lxmf.delivery destination hash.
     */
    get lxmfDeliveryHash() {
        if (!this._identity) return null;
        return Destination.hash(this._identity, "lxmf", "delivery").toString("hex");
    },

    /**
     * Generate a new distro identity.
     * Returns the identity hash.
     */
    generate() {
        this._identity = Identity.create();
        this._save();
        this._notify();
        return this.hash;
    },

    /**
     * Import a distro identity from a private key hex string.
     * @param {string} hex - 128 hex characters (64 bytes)
     * @returns {string} The identity hash
     */
    importHex(hex) {
        if (hex.length !== 128) {
            throw new Error("Private key must be exactly 128 hex characters");
        }
        this._identity = Identity.fromPrivateKey(globalThis.Buffer.from(hex, "hex"));
        this._save();
        this._notify();
        return this.hash;
    },

    /**
     * Import from a rfed-distro-private-key:// URI.
     * The legacy rfed-distro-id:// scheme is still accepted on import so a
     * key copied from an older build is not stranded.
     * @param {string} uri - The full URI
     * @returns {string} The identity hash
     */
    importUri(uri) {
        for (const scheme of [DISTRO_URI_SCHEME, LEGACY_URI_SCHEME]) {
            if (uri.startsWith(scheme)) return this.importHex(uri.slice(scheme.length));
        }
        throw new Error(`URI must start with ${DISTRO_URI_SCHEME}`);
    },

    /**
     * Export the identity as a rfed-distro-private-key:// URI.
     *
     * Not surfaced in the UI: device-to-device transfer goes over encrypted
     * LXMF (see _sendDistroViaLxmf). Kept for import round-tripping and for
     * the headless harness.
     * @returns {string} The URI
     */
    exportUri() {
        if (!this._identity) throw new Error("No distro identity");
        return DISTRO_URI_SCHEME + this.exportHex();
    },

    /**
     * Export the public contact as an lxma:// URI (public — share freely).
     *
     * The hash in an lxma:// URI is the *delivery destination* hash — that is
     * what a sender addresses packets to and what it feeds to `requestPath()`.
     * This used to emit the identity hash, which is a different value and
     * routes nowhere; senders who pasted it never reached the distro.
     *
     * @returns {string} The URI
     */
    exportLxmaUri() {
        if (!this._identity) throw new Error("No distro identity");
        const pubKey = this._identity.getPublicKey().toString("hex");
        return `lxma://${this.lxmfDeliveryHash}:${pubKey}`;
    },

    /**
     * Export the private key as hex.
     * @returns {string} 128 hex characters
     */
    exportHex() {
        if (!this._identity) throw new Error("No distro identity");
        const fullKey = globalThis.Buffer.concat([
            this._identity.privateKeyBytes,
            this._identity.signaturePrivateKeyBytes
        ]);
        return fullKey.toString("hex");
    },

    /**
     * Forget the current distro identity.
     */
    forget() {
        this._identity = null;
        localStorage.removeItem(DISTRO_ID_KEY);
        this._notify();
    },

    /**
     * Get the identity object for signing/encryption.
     * @returns {Identity}
     */
    get identity() { return this._identity; },

    /**
     * Register a callback for identity changes.
     */
    onChange(fn) {
        this._listeners.push(fn);
        fn(this.has ? { hash: this.hash, pubKey: this.pubKey } : null);
    },

    _notify() {
        const state = this.has ? { hash: this.hash, pubKey: this.pubKey } : null;
        this._listeners.forEach(fn => fn(state));
    },

    _save() {
        const fullKey = globalThis.Buffer.concat([
            this._identity.privateKeyBytes,
            this._identity.signaturePrivateKeyBytes
        ]);
        localStorage.setItem(DISTRO_ID_KEY, fullKey.toString("hex"));
    },
};

export default DistroManager;
