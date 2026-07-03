/**
 * DirectSocketsInterface — raw TCP connection via the Direct Sockets API.
 *
 * Chrome 120+ only. Enable:
 *   chrome://flags/#direct-sockets
 *
 * This eliminates the need for a WebSocket-to-TCP bridge. The browser opens
 * a raw TCP socket, handles HDLC framing, and speaks RNS directly to
 * standard TCP backbone servers.
 */
import Packet from "../packet.js";
import HDLC from "../framing/hdlc.js";
import Interface from "./interface.js";

class DirectSocketsInterface extends Interface {

    /**
     * @param {string} name    Human-readable name
     * @param {string} host    Backbone hostname or IP
     * @param {number} port    Backbone port (typically 4242 or 4965)
     */
    constructor(name, host, port) {
        super(name);
        this.host = host;
        this.port = port;
        this.socket = null;
        this._reader = null;
        this._reconnectDelay = 1000;
        this._reconnectMin = 1000;
        this._reconnectMax = 30000;
        this._shouldReconnect = true;
    }

    /**
     * Check whether the Direct Sockets API is available in this browser.
     * Requires: Chrome 120+ with chrome://flags/#direct-sockets enabled.
     */
    static isAvailable() {
        return typeof navigator !== "undefined" && "openTCPSocket" in navigator;
    }

    /**
     * Diagnose WHY Direct Sockets is unavailable. Returns a user-facing string.
     */
    static diagnose() {
        if (typeof navigator === "undefined") return "Not in a browser context";
        if (!("openTCPSocket" in navigator)) {
            return "navigator.openTCPSocket not found. Enable chrome://flags/#direct-sockets (not the worker/multicast ones — just #direct-sockets). Also try #enable-experimental-web-platform-features.";
        }
        if (location.protocol !== "https:" && location.hostname !== "localhost") {
            return "Direct Sockets requires HTTPS or localhost";
        }
        return "Available";
    }

    async connect() {
        const diag = DirectSocketsInterface.diagnose();
        if (!DirectSocketsInterface.isAvailable()) {
            console.error("[DirectSockets] API unavailable:", diag);
            console.error("[DirectSockets] Required: chrome://flags/#direct-sockets (no suffix) + chrome://flags/#enable-experimental-web-platform-features");
            return;
        }

        this._shouldReconnect = true;

        try {
            console.log(`[DirectSockets] Connecting to ${this.host}:${this.port}...`);
            this.socket = await navigator.openTCPSocket({
                remoteAddress: this.host,
                remotePort: this.port,
            });
            console.log(`[DirectSockets] ✓ Connected to ${this.name} (${this.host}:${this.port})`);
            this._reconnectDelay = this._reconnectMin;

            // Start the read loop
            this._startReadLoop();
        } catch (err) {
            console.error(`[DirectSockets] Connection to ${this.name} failed:`, err.message);
            if (err.message?.includes("permission") || err.message?.includes("denied")) {
                console.error("[DirectSockets] Permission denied. Make sure chrome://flags/#direct-sockets is enabled and you've relaunched Chrome.");
            }
            if (err.message?.includes("not defined") || err.message?.includes("is not a function")) {
                console.error("[DirectSockets] API not found. In Chrome flags, search for just 'direct-sockets' (no suffix). Also enable #enable-experimental-web-platform-features.");
            }
            this._scheduleReconnect();
        }
    }

    disconnect() {
        this._shouldReconnect = false;
        this._cleanup();
    }

    _cleanup() {
        if (this._reader) {
            try { this._reader.cancel(); } catch(e) {}
            this._reader = null;
        }
        if (this.socket) {
            try { this.socket.close(); } catch(e) {}
            this.socket = null;
        }
    }

    _scheduleReconnect() {
        if (!this._shouldReconnect) return;
        const delay = this._reconnectDelay;
        console.warn(`[DirectSockets] ${this.name}: reconnecting in ${(delay/1000).toFixed(1)}s...`);
        this._reconnectDelay = Math.min(this._reconnectDelay * 2, this._reconnectMax);
        setTimeout(() => this.connect(), delay);
    }

    async _startReadLoop() {
        if (!this.socket) return;

        try {
            this._reader = this.socket.readable.getReader();

            let frameBuf = [];
            let inFrame = false;

            while (true) {
                const { value, done } = await this._reader.read();
                if (done) break;
                if (!value || value.length === 0) continue;

                for (const byte of value) {
                    if (byte === HDLC.FLAG) {
                        if (inFrame && frameBuf.length > 0) {
                            try {
                                const payload = HDLC.unescape(Buffer.from(frameBuf));
                                this.processIncoming(payload);
                            } catch(e) {
                                console.warn("[DirectSockets] HDLC unescape error:", e.message);
                            }
                            frameBuf = [];
                        }
                        inFrame = true;
                    } else if (inFrame) {
                        frameBuf.push(byte);
                    }
                }
            }
        } catch (err) {
            // ReadableStream cancelled or network error — expected on close
            if (err.name !== "AbortError" && err.name !== "TypeError") {
                console.error(`[DirectSockets] ${this.name} read error:`, err.message);
            }
        } finally {
            this._cleanup();
            this._scheduleReconnect();
        }
    }

    sendData(data) {
        if (!this.socket) {
            console.warn(`[DirectSockets] ${this.name}: cannot send — socket not connected`);
            return;
        }

        try {
            // HDLC-frame the data: FLAG + escaped_data + FLAG
            const escaped = HDLC.escape(data);
            const framed = Buffer.concat([
                Buffer.from([HDLC.FLAG]),
                escaped,
                Buffer.from([HDLC.FLAG]),
            ]);

            const writer = this.socket.writable.getWriter();
            writer.write(framed);
            writer.releaseLock();
        } catch (err) {
            console.error(`[DirectSockets] ${this.name} send error:`, err.message);
        }
    }

    /**
     * Process a deframed incoming packet.
     * Skips IFAC packets, delegates valid RNS packets to the RNS stack.
     */
    processIncoming(data) {
        // Skip IFAC packets (bit 7 set on first byte)
        if ((data[0] & 0x80) === 0x80) {
            console.log("[DirectSockets] IFAC packet received — skipping");
            return;
        }

        try {
            const packet = Packet.fromBytes(data);
            if (this.rns) {
                this.rns.onPacketReceived(packet, this);
            }
        } catch(e) {
            console.warn("[DirectSockets] Failed to parse packet:", e.message);
        }
    }
}

export default DirectSocketsInterface;
