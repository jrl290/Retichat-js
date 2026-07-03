import crypto from "crypto";
import PKCS7 from "./pkcs7.js";

class Fernet {

    static FERNET_OVERHEAD = 48;

    constructor(key) {
        if (!key) {
            throw new Error("Token key cannot be null");
        }

        if (key.length === 32) {
            // AES-128-CBC (legacy mode)
            this._mode = 'aes-128-cbc';
            this._signing_key = key.slice(0, 16);
            this._encryption_key = key.slice(16, 32);
        } else if (key.length === 64) {
            // AES-256-CBC (Python reference standard)
            this._mode = 'aes-256-cbc';
            this._signing_key = key.slice(0, 32);
            this._encryption_key = key.slice(32, 64);
        } else {
            throw new Error("Token key must be 32 or 64 bytes, not " + key.length);
        }
    }

    static generateKey() {
        return crypto.randomBytes(32);
    }

    verifyHmac(token) {
        if(token.length <= 32){
            throw new Error("Cannot verify HMAC on token of only " + token.length + " bytes");
        }
        const receivedHmac = token.slice(-32);
        const dataToSign = token.slice(0, -32);
        const expectedHmac = crypto.createHmac('sha256', this._signing_key).update(dataToSign).digest();
        return receivedHmac.equals(expectedHmac);
    }

    encrypt(data) {
        if(!Buffer.isBuffer(data)){
            throw new TypeError("Token plaintext input must be a Buffer");
        }
        const iv = crypto.randomBytes(16);
        const paddedData = PKCS7.pad(data);
        const cipher = crypto.createCipheriv(this._mode, this._encryption_key, iv);
        cipher.setAutoPadding(false);
        let ciphertext = cipher.update(paddedData);
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        const signedParts = Buffer.concat([iv, ciphertext]);
        const hmac = crypto.createHmac('sha256', this._signing_key).update(signedParts).digest();
        return Buffer.concat([signedParts, hmac]);
    }

    decrypt(token) {
        if(!Buffer.isBuffer(token)){
            throw new TypeError("Token must be a Buffer");
        }
        if(!this.verifyHmac(token)){
            throw new Error("Token HMAC was invalid");
        }
        const iv = token.slice(0, 16);
        const ciphertext = token.slice(16, -32);
        const decipher = crypto.createDecipheriv(this._mode, this._encryption_key, iv);
        decipher.setAutoPadding(false);
        let plaintext = decipher.update(ciphertext);
        plaintext = Buffer.concat([plaintext, decipher.final()]);
        return PKCS7.unpad(plaintext);
    }
}

export default Fernet;
