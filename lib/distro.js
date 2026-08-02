/**
 * DistroManager — Distro identity management for Retichat Web.
 *
 * A Distro identity is a shared LXMF identity that multiple devices use
 * to receive fanout messages. One device generates the identity and
 * shares it with others via encrypted LXMF transfer or QR code URI.
 *
 * URI format: rfed-distro-id://<128_hex_chars>
 *   - 64-byte private key (X25519_priv 32 || Ed25519_priv 32)
 *   - Public key is derived from private key on import
 *
 * Security model:
 *   - Private key never displayed to user
 *   - Stored in localStorage (browser secure storage)
 *   - Transferred encrypted via LXMF or ephemeral QR code
 */

import { Identity, Destination } from "./rns/reticulum.js?v=20260726-keys2";

const DISTRO_ID_KEY = "retichat_distro_identity";
const DISTRO_URI_SCHEME = "rfed-distro-id://";

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
                this._identity = Identity.fromPrivateKey(Buffer.from(hex, "hex"));
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
        this._identity = Identity.fromPrivateKey(Buffer.from(hex, "hex"));
        this._save();
        this._notify();
        return this.hash;
    },

    /**
     * Import from a rfed-distro-id:// URI.
     * @param {string} uri - The full URI
     * @returns {string} The identity hash
     */
    importUri(uri) {
        if (!uri.startsWith(DISTRO_URI_SCHEME)) {
            throw new Error(`URI must start with ${DISTRO_URI_SCHEME}`);
        }
        const hex = uri.slice(DISTRO_URI_SCHEME.length);
        return this.importHex(hex);
    },

    /**
     * Export the identity as a rfed-distro-id:// URI (private key — keep secret).
     * @returns {string} The URI
     */
    exportUri() {
        if (!this._identity) throw new Error("No distro identity");
        return DISTRO_URI_SCHEME + this.exportHex();
    },

    /**
     * Export the public contact as an lxma:// URI (public — share freely).
     * @returns {string} The URI
     */
    exportLxmaUri() {
        if (!this._identity) throw new Error("No distro identity");
        const pubKey = this._identity.getPublicKey().toString("hex");
        return `lxma://${this.hash}:${pubKey}`;
    },

    /**
     * Export the private key as hex.
     * @returns {string} 128 hex characters
     */
    exportHex() {
        if (!this._identity) throw new Error("No distro identity");
        const fullKey = Buffer.concat([
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
        const fullKey = Buffer.concat([
            this._identity.privateKeyBytes,
            this._identity.signaturePrivateKeyBytes
        ]);
        localStorage.setItem(DISTRO_ID_KEY, fullKey.toString("hex"));
    },
};

DistroManager.init();

export default DistroManager;
