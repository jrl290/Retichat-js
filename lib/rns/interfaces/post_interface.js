/**
 * PostInterface — HTTP POST polling interface for Reticulum-php.
 *
 * Implements the rns.js Interface contract using the same POST exchange
 * protocol that your Reticulum-php node already speaks. No WebSocket,
 * no open ports, no Apache modules needed — just HTTP.
 *
 * The browser app POSTs raw RNS packets to the node's /v1/interfaces/exchange
 * endpoint and receives delivery packets in the response. Polls on the
 * idle_exchange_interval_ms returned by the node.
 */
import Packet from "../packet.js";
import Interface from "./interface.js";

class PostInterface extends Interface {

    /**
     * @param {string} name       Human-readable name
     * @param {string} baseUrl    Base URL of the Reticulum-php node (e.g. https://example.com/reticulum)
     * @param {string} [identityHash]  Optional identity hash to scope credentials
     * @param {number} [mode]     RNS interface mode (defaults to MODE_FULL = 1)
     */
    constructor(name, baseUrl, identityHash, mode) {
        super(name);
        this._baseUrl = baseUrl.replace(/\/$/, "");
        this._identityHash = identityHash || null;
        this._mode = typeof mode === 'number' ? mode : Interface.MODE_FULL;
        this._interfaceId = null;
        this._sessionToken = null;
        this._outboundQueue = [];      // raw bytes queued for next exchange
        this._pendingAckIds = [];      // batch IDs to acknowledge
        this._pollTimer = null;
        this._pollIntervalMs = 1000;   // default, updated by node
        this._maxPacketBytes = 500;
        this._maxBatchPackets = 64;
        this._batchSeq = 0;
        this._running = false;
    }

    get isRegistered() {
        return this._interfaceId !== null && this._sessionToken !== null;
    }

    async connect() {
        this._running = true;

        // Always register fresh — saved tokens go stale on reconnect.
        this._clearCredentials();
        await this._register();

        // Start polling
        console.log(`[http-exchange] Starting exchange poll every ${this._pollIntervalMs}ms`);
        this._poll();
    }

    disconnect() {
        this._running = false;
        if (this._pollTimer) {
            clearTimeout(this._pollTimer);
            this._pollTimer = null;
        }
    }

    /**
     * Queue raw packet data for the next exchange.
     * Called by the rns.js stack.
     */
    sendData(data) {
        if (!data || data.length === 0) return;
        console.log(`[http-exchange] Queuing outbound packet: ${data.length} bytes, first 8: ${Buffer.from(data.slice(0,8)).toString('hex')}`);
        this._outboundQueue.push(data);
    }

    // ---- Registration ----

    async _register() {
        console.log(`[http-exchange] Registering interface "${this.name}" with ${this._baseUrl}...`);
        const resp = await this._post('/v1/interfaces/register', {
            name: this.name,
            bitrate: 1000000,
            mtu: 500,
            metadata: {
                client: 'rns-js',
                implementation: 'PostInterface',
                mode: this._mode,
                identity_hash: this._identityHash || '',
            },
        });

        this._interfaceId = resp.interface_id;
        this._sessionToken = resp.session_token;
        this._maxBatchPackets = resp.max_batch_packets || 64;
        this._maxPacketBytes = resp.max_packet_bytes || 500;
        this._pollIntervalMs = resp.idle_exchange_interval_ms || 1000;

        console.log(`[http-exchange] Registered: ${this._interfaceId.slice(0,8)}... token=${this._sessionToken.slice(0,12)}... poll=${this._pollIntervalMs}ms`);

        this._saveCredentials();
    }

    // ---- Exchange loop ----

    async _poll() {
        if (!this._running) return;

        try {
            await this._doExchange();
        } catch (err) {
            console.warn(`[http-exchange] Exchange failed:`, err.message);
            // If auth failed, re-register
            if (err.message?.includes('401') || err.message?.includes('Invalid interface credentials')) {
                console.log('[http-exchange] Re-registering after auth failure...');
                this._clearCredentials();
                try {
                    await this._register();
                } catch (regErr) {
                    console.error('[http-exchange] Re-registration failed:', regErr.message);
                }
            }
        }

        if (this._running) {
            this._pollTimer = setTimeout(() => this._poll(), this._pollIntervalMs);
        }
    }

    async _doExchange() {
        if (!this.isRegistered) return;

        // Grab queued outbound packets
        const packets = this._outboundQueue.splice(0, this._maxBatchPackets);
        const ackIds = this._pendingAckIds.splice(0);

        const body = {
            interface_id: this._interfaceId,
            session_token: this._sessionToken,
            ack_batch_ids: ackIds,
            max_packets: this._maxBatchPackets,
            packets: packets.map(p => this._bytesToBase64(p)),
        };

        if (packets.length > 0) {
            body.batch_id = `web-${Date.now()}-${++this._batchSeq}`;
            console.log(`[http-exchange] Sending ${packets.length} outbound packet(s) in exchange`);
        }

        console.log(`[http-exchange] DEBUG exchange: iface=${this._interfaceId?.slice(0,12)} token=${this._sessionToken?.slice(0,12)}`);

        const resp = await this._post('/v1/interfaces/exchange', body);

        // Process delivery packets
        const deliveryPackets = resp.delivery_packets || [];
        const deliveryBatchId = resp.delivery_batch_id || null;

        if (deliveryPackets.length > 0) {
            for (const pktBase64 of deliveryPackets) {
                if (typeof pktBase64 !== 'string' || pktBase64 === '') continue;
                const raw = this._base64ToBytes(pktBase64);
                if (!raw) continue;
                try {
                    this.processIncoming(raw);
                } catch (e) {
                    console.warn('[http-exchange] Failed to process incoming packet:', e.message);
                }
            }

            if (deliveryBatchId) {
                this._pendingAckIds.push(deliveryBatchId);
            }
        }

        // Update poll interval if the node changed it
        if (resp.idle_exchange_interval_ms && resp.idle_exchange_interval_ms !== this._pollIntervalMs) {
            this._pollIntervalMs = resp.idle_exchange_interval_ms;
            this._saveCredentials();
        }
    }

    /**
     * Process a deframed incoming packet.
     * Delegates to the rns.js stack.
     */
    processIncoming(data) {
        // Skip IFAC packets
        if ((data[0] & 0x80) === 0x80) {
            console.log('[http-exchange] IFAC packet received — skipping');
            return;
        }

        try {
            const packet = Packet.fromBytes(data);            console.log(`[http-exchange] RX packet type=${packet.packetType} ctx=${packet.context} dst=${packet.destinationHash?.toString("hex")?.slice(0,12)}`);            if (this.rns) {
                this.rns.onPacketReceived(packet, this);
            }
        } catch (e) {
            console.warn('[http-exchange] Failed to parse packet:', e.message);
        }
    }

    // ---- HTTP helpers ----

    async _post(path, body) {
        const url = this._baseUrl + path;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!resp.ok) {
            const text = await resp.text().catch(() => '');
            throw new Error(`HTTP ${resp.status}: ${text.slice(0, 200)}`);
        }

        const text = await resp.text();
        try {
            return JSON.parse(text);
        } catch (e) {
            console.error('[http-exchange] JSON parse failed. Response text:', text.slice(0, 500));
            throw e;
        }
    }

    // ---- Base64 helpers (browser-native) ----

    _bytesToBase64(bytes) {
        // Convert Buffer/Uint8Array to base64 string
        const arr = new Uint8Array(bytes);
        let binary = '';
        for (let i = 0; i < arr.length; i++) {
            binary += String.fromCharCode(arr[i]);
        }
        return btoa(binary);
    }

    _base64ToBytes(b64) {
        try {
            const binary = atob(b64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return Buffer.from(bytes);
        } catch (e) {
            return null;
        }
    }

    // ---- Credential persistence ----

    _credentialKey() {
        const base = 'rns_exchange_creds';
        if (this._identityHash) {
            return base + '_' + this._identityHash.slice(0, 16);
        }
        return base;
    }

    _loadCredentials() {
        try {
            const raw = localStorage.getItem(this._credentialKey());
            if (raw) {
                const c = JSON.parse(raw);
                if (c.interfaceId && c.sessionToken) return c;
            }
        } catch (e) {}
        return null;
    }

    _saveCredentials() {
        try {
            localStorage.setItem(this._credentialKey(), JSON.stringify({
                interfaceId: this._interfaceId,
                sessionToken: this._sessionToken,
                baseUrl: this._baseUrl,
                maxBatchPackets: this._maxBatchPackets,
                maxPacketBytes: this._maxPacketBytes,
                pollIntervalMs: this._pollIntervalMs,
            }));
        } catch (e) {}
    }

    _clearCredentials() {
        this._interfaceId = null;
        this._sessionToken = null;
        try { localStorage.removeItem(this._credentialKey()); } catch (e) {}
    }
}

export default PostInterface;
