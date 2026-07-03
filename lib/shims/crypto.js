/**
 * Browser-compatible shim for Node.js 'crypto' module.
 * Uses @noble/hashes (pure JS, synchronous) — already available via
 * the @noble/curves CDN import.
 *
 * API surface needed by rns.js:
 *   crypto.createHash('sha256' | 'sha512').update(data).digest()
 *   crypto.createHmac('sha256', key).update(data).digest()
 *   crypto.randomBytes(size)
 */

// These will be resolved by the import map to CDN
import { sha256, sha512 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import aesjs from "aes-js";

// ---- Hash wrapper matching Node.js crypto.Hash API ----
class Hash {
    constructor(algo) {
        this.algo = algo;
        this.data = new Uint8Array(0);
    }

    update(data) {
        const next = new Uint8Array(this.data.length + data.length);
        next.set(this.data, 0);
        next.set(typeof data === "string"
            ? new TextEncoder().encode(data)
            : new Uint8Array(data),
            this.data.length);
        this.data = next;
        return this;
    }

    digest() {
        const fn = this.algo === "sha256" ? sha256 : sha512;
        return Buffer.from(fn(this.data));
    }
}

// ---- Hmac wrapper ----
class Hmac {
    constructor(algo, key) {
        this.algo = algo;
        this.key = key;
        this.data = new Uint8Array(0);
    }

    update(data) {
        const next = new Uint8Array(this.data.length + data.length);
        next.set(this.data, 0);
        next.set(typeof data === "string"
            ? new TextEncoder().encode(data)
            : new Uint8Array(data),
            this.data.length);
        this.data = next;
        return this;
    }

    digest() {
        const fn = this.algo === "sha256" ? sha256 : sha512;
        return Buffer.from(hmac(fn, this.key, this.data));
    }
}

// ---- AES-CBC wrapper (for Fernet encryption) ----
class Cipheriv {
    constructor(algo, key, iv) {
        if (algo !== 'aes-128-cbc' && algo !== 'aes-256-cbc') {
            throw new Error(`Unsupported cipher algorithm: ${algo}`);
        }
        this.key = key;
        this.iv = iv;
        this.buf = Buffer.alloc(0);
        this._autoPadding = true;
    }

    update(data) {
        this.buf = Buffer.concat([this.buf, Buffer.from(data)]);
        return Buffer.alloc(0); // AES-CBC is block-based, return empty until final
    }

    final() {
        let data = this.buf;
        // Only pad if auto-padding is enabled (Fernet disables it because
        // it handles PKCS7 padding itself via PKCS7.pad/unpad).
        if (this._autoPadding) {
            const blockSize = 16;
            const padLen = blockSize - (data.length % blockSize);
            data = Buffer.concat([data, Buffer.alloc(padLen, padLen)]);
        }

        // AES-CBC encrypt
        const aesCbc = new aesjs.ModeOfOperation.cbc(
            new Uint8Array(this.key),
            new Uint8Array(this.iv)
        );
        const encrypted = aesCbc.encrypt(new Uint8Array(data));
        return Buffer.from(encrypted);
    }

    setAutoPadding(enabled) {
        this._autoPadding = !!enabled;
    }
}

class Decipheriv {
    constructor(algo, key, iv) {
        if (algo !== 'aes-128-cbc' && algo !== 'aes-256-cbc') {
            throw new Error(`Unsupported cipher algorithm: ${algo}`);
        }
        this.key = key;
        this.iv = iv;
        this.buf = Buffer.alloc(0);
        this._autoPadding = true;
    }

    update(data) {
        this.buf = Buffer.concat([this.buf, Buffer.from(data)]);
        return Buffer.alloc(0);
    }

    final() {
        const aesCbc = new aesjs.ModeOfOperation.cbc(
            new Uint8Array(this.key),
            new Uint8Array(this.iv)
        );
        const decrypted = aesCbc.decrypt(new Uint8Array(this.buf));

        // Only remove PKCS7 padding if auto-padding is enabled
        // (Fernet disables it because it handles padding itself).
        if (this._autoPadding) {
            const lastByte = decrypted[decrypted.length - 1];
            if (lastByte > 0 && lastByte <= 16) {
                return Buffer.from(decrypted.slice(0, decrypted.length - lastByte));
            }
        }
        return Buffer.from(decrypted);
    }

    setAutoPadding(enabled) {
        this._autoPadding = !!enabled;
    }
}

// ---- Module exports matching Node.js crypto ----

// Save reference to browser's native Web Crypto API before we shadow 'crypto'
const nativeCrypto = globalThis.crypto;

const crypto = {
    createHash(algo) {
        return new Hash(algo);
    },
    createHmac(algo, key) {
        return new Hmac(algo, key);
    },
    createCipheriv(algo, key, iv) {
        return new Cipheriv(algo, key, iv);
    },
    createDecipheriv(algo, key, iv) {
        return new Decipheriv(algo, key, iv);
    },
    randomBytes(size) {
        const buf = new Uint8Array(size);
        // Use the browser's native getRandomValues, not our own crypto object
        nativeCrypto.getRandomValues(buf);
        return Buffer.from(buf);
    },
};

export default crypto;
export const { createHash, createHmac, randomBytes } = crypto;
