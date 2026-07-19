/**
 * Retichat Web — Standalone (zero-tooling) version.
 *
 * Drop the `standalone/` folder onto any static web server.
 * No npm, no build step, no Node.js required on the server.
 *
 * Dependencies resolved via import map in index.html:
 *   - @noble/curves, @noble/hashes, msgpackr → CDN (esm.sh)
 *   - buffer → CDN (esm.sh)
 *   - crypto, net, ws → local shims
 *   - rns.js → local copy in lib/rns/
 *
 * Matches Retichat UX:
 *   - Add Contact by entering a destination hash (no public peer directory)
 *   - Privacy filter: only accept messages from contacts you've added
 *   - Share your identity (destination hash) so others can add you
 */

// ---- Polyfills ----
import { Buffer } from "buffer";
globalThis.Buffer = Buffer;
globalThis.process = globalThis.process || { env: {}, versions: {} };

// ---- rns.js imports ----
import {
    Reticulum,
    Destination,
    Identity,
    Link,
    Packet,
    LXMessage,
    LXMRouter,
    LXMF,
    PostInterface,
} from "./lib/rns/reticulum.js";
import MsgPack from "./lib/rns/msgpack.js";

// =========================================================================
//  CONFIG
// =========================================================================
const DEFAULT_CONFIG = {
    // HTTP Exchange (Reticulum-php native) — primary transport.
    exchangeUrl: "https://retichat.com/reticulum",

    // RFed node identity hash. Used as the root for deriving propagation
    // and other capability destination hashes. Hidden default matches iOS.
    rfedNodeHash: "7e5ff856dc2aa0fbc9fc8831b62d2834",

    // Explicit LXMF propagation override. Empty = derive from RFed node hash.
    lxmfPropagationOverride: "",

    // Resolved propagation node (derived from RFed, or explicit override).
    // Filled at startup by resolvePropagationHash().
    propagationNodeHash: "",
    propagationNodePubKey: "",

    interfaceName: "Retichat Web",
    displayName: "Retichat Web",
    announceIntervalMs: 300000,
};
async function loadConfig() {
    const cfg = { ...DEFAULT_CONFIG };
    try {
        const resp = await fetch("./config.json");
        if (resp.ok) {
            const json = await resp.json();
            if (json.exchangeUrl) cfg.exchangeUrl = json.exchangeUrl;
            if (json.displayName) cfg.displayName = json.displayName;
            if (typeof json.announceIntervalMs === "number") cfg.announceIntervalMs = json.announceIntervalMs;
        }
    } catch(e) {}
    const savedExchangeUrl = sGet("exchangeUrl");
    if (savedExchangeUrl) cfg.exchangeUrl = savedExchangeUrl;
    const savedDisplayName = sGet("displayName");
    if (savedDisplayName) cfg.displayName = savedDisplayName;
    cfg.rfedNodeHash = sGet("rfedNodeHash") || DEFAULT_CONFIG.rfedNodeHash;
    cfg.lxmfPropagationOverride = sGet("lxmfPropagationOverride") || "";
    cfg.propagationNodePubKey = sGet("propagationNodePubKey") || "";
    return cfg;
}

// =========================================================================
//  STORE — localStorage helpers
// =========================================================================
const PFX = "retichat_";
function sGet(k) { try { const r = localStorage.getItem(PFX+k); return r ? JSON.parse(r) : null; } catch(e) { return null; } }
function sSet(k, v) { try { localStorage.setItem(PFX+k, JSON.stringify(v)); } catch(e) {} }

// =========================================================================
//  IDENTITY MANAGER
// =========================================================================
const ID_KEY = "identity_private_key";
const IdMgr = {
    _id: null,
    get has() { return this._id !== null; },
    get id() { return this._id; },
    get hash() { return this._id?.hash?.toString("hex") ?? null; },
    get shortHash() { const h = this.hash; return h ? h.slice(0,12) : null; },
    get pubKey() { return this._id?.getPublicKey()?.toString("hex") ?? null; },
    get privKey() {
        if (!this._id?.privateKeyBytes || !this._id?.signaturePrivateKeyBytes) return null;
        return Buffer.concat([this._id.privateKeyBytes, this._id.signaturePrivateKeyBytes]).toString("hex");
    },

    load() {
        const hex = sGet(ID_KEY);
        if (hex && hex.length === 128) {
            try { this._id = Identity.fromPrivateKey(Buffer.from(hex,"hex")); return true; }
            catch(e) { sSet(ID_KEY, null); }
        }
        return false;
    },
    create() {
        this._id = Identity.create();
        const fullKey = Buffer.concat([this._id.privateKeyBytes, this._id.signaturePrivateKeyBytes]);
        sSet(ID_KEY, fullKey.toString("hex"));
        return this._id;
    },
    importHex(hex) {
        this._id = Identity.fromPrivateKey(Buffer.from(hex,"hex"));
        sSet(ID_KEY, hex);
        return this._id;
    },
    forget() { this._id = null; sSet(ID_KEY, null); },
};

// =========================================================================
//  CONTACT STORE — only explicitly added contacts, not public peers
// =========================================================================
const ContactStore = {
    _contacts: new Map(),
    _listeners: [],

    init() {
        const data = sGet("contacts_v2");
        if (Array.isArray(data)) for (const c of data) this._contacts.set(c.destHash, c);
    },

    onChange(fn) { this._listeners.push(fn); fn(this.getAll()); },
    _notify() { const all = this.getAll(); this._listeners.forEach(fn => fn(all)); },

    /** Add a contact by destination hash. Returns the contact. */
    add(destHash) {
        destHash = destHash.toLowerCase().replace(/[^0-9a-f]/g, "");
        if (destHash.length !== 32) throw new Error("Destination hash must be exactly 32 hex characters");
        const existing = this._contacts.get(destHash);
        const contact = {
            destHash,
            displayName: existing?.displayName ?? "?" + destHash.slice(0,8),
            publicKey: existing?.publicKey ?? null,
            nameCustomized: existing?.nameCustomized ?? false,
            addedAt: existing?.addedAt ?? Date.now(),
            lastSeen: existing?.lastSeen ?? 0,
            reachable: existing?.reachable ?? null,  // null=unknown, true=direct proof received, false=offline
        };
        this._contacts.set(destHash, contact);
        this._save();
        this._notify();
        return contact;
    },

    /** Update contact info from an announce (display name, public key) */
    updateFromAnnounce(destHash, announce) {
        const c = this._contacts.get(destHash);
        if (!c) return;

        if (!c.nameCustomized && announce.appData) {
            try {
                const n = LXMF.displayNameFromAppData(announce.appData);
                if (n) c.displayName = n;
            } catch(e) {}
        }
        if (!c.publicKey && announce.identity) {
            c.publicKey = announce.identity.getPublicKey()?.toString("hex") ?? null;
        }
        c.lastSeen = Date.now();
        this._save();
        this._notify();
    },

    isContact(destHash) { return this._contacts.has(destHash); },

    setDisplayName(destHash, name) {
        const c = this._contacts.get(destHash);
        if (c) { c.displayName = name || ("?" + destHash.slice(0,8)); c.nameCustomized = true; this._save(); this._notify(); }
    },

    setReachable(destHash, reachable) {
        const c = this._contacts.get(destHash);
        if (c) { c.reachable = reachable; this._save(); }
    },

    /** Seconds to wait before propagating: 5 for online/unknown, 1 for offline. */
    propagationDelay(destHash) {
        const c = this._contacts.get(destHash);
        return (c && c.reachable === false) ? 1 : 5;
    },

    /** Reset all contacts' propagation timers to 5s (unknown state). */
    resetPropagationTimers() {
        for (const c of this._contacts.values()) {
            c.reachable = null;
        }
        this._save();
    },

    /** Bump lastSeen without triggering a re-render (caller handles that). */
    touch(destHash) {
        const c = this._contacts.get(destHash);
        if (c) { c.lastSeen = Date.now(); this._save(); }
    },

    remove(destHash) {
        this._contacts.delete(destHash);
        this._save();
        this._notify();
    },

    get(destHash) { return this._contacts.get(destHash) ?? null; },
    getAll() { return [...this._contacts.values()].sort((a,b) => b.lastSeen - a.lastSeen); },

    _save() { sSet("contacts_v2", [...this._contacts.values()]); },
};
ContactStore.init();

// =========================================================================
//  MESSAGE STORE
// =========================================================================
const MsgStore = {
    get(hash) { return sGet("msg_"+hash) ?? []; },
    add(hash, msg) {
        const msgs = this.get(hash);
        msgs.push({ id: Date.now().toString(36)+Math.random().toString(36).slice(2,8), timestamp: Date.now(), ...msg });
        if (msgs.length > 500) msgs.splice(0, msgs.length-500);
        sSet("msg_"+hash, msgs);
        return msgs[msgs.length-1];
    },
    updateStatus(hash, msgId, newStatus) {
        const msgs = this.get(hash);
        const m = msgs.find(x => x.id === msgId);
        if (m) { m.status = newStatus; sSet("msg_"+hash, msgs); }
        return m;
    },
    remove(hash) {
        sSet("msg_"+hash, []);
    },
    preview(hash) {
        const msgs = this.get(hash);
        if (!msgs.length) return null;
        const last = msgs[msgs.length-1];
        return (last.dir === "out" ? "You: " : "") + (last.content?.slice(0,60) ?? "");
    },
};

// =========================================================================
//  RNS CLIENT — with privacy filter
// =========================================================================
const RnsClient = {
    _rns: null, _lxmfRouter: null, _cfg: null,
    _status: "offline", _connType: "none", // "direct" | "websocket" | "none"
    _annTimer: null, _monTimer: null,
    _pendingTickets: new Map(),  // ticket → {contactHash, messageId}
    _pendingPacketHashes: new Map(),  // provedPacketHash (hex) → {contactHash, messageId}
    _pendingTimeouts: new Map(),  // messageId → timeoutId
    _onStatus: [], _onMsg: [],

    get status() { return this._status; },
    get connType() { return this._connType; },
    get ownHash() { return this._lxmfRouter?.destination?.hash?.toString("hex") ?? null; },
    get cfg() { return this._cfg || DEFAULT_CONFIG; },

    onStatus(fn) { this._onStatus.push(fn); },
    onMessage(fn) { this._onMsg.push(fn); },

    /** Update the delivery status of an outgoing message (e.g. "proved", "failed"). */
    updateMessageStatus(contactHash, msgId, newStatus) {
        MsgStore.updateStatus(contactHash, msgId, newStatus);
    },

    _setStatus(s, type) {
        if (type) this._connType = type;
        if (this._status === s) return;
        this._status = s;
        this._onStatus.forEach(fn => fn(s));
    },

    async connect() {
        if (!IdMgr.has) throw new Error("No identity");
        this._cfg = await loadConfig();

        // Resolve propagation node hash: explicit override, or derive from RFed.
        if (this._cfg.lxmfPropagationOverride) {
            this._cfg.propagationNodeHash = this._cfg.lxmfPropagationOverride;
        } else if (this._cfg.rfedNodeHash) {
            const rfedIdBytes = Buffer.from(this._cfg.rfedNodeHash, "hex");
            this._cfg.propagationNodeHash = Destination.hash({hash: rfedIdBytes}, "lxmf", "propagation").toString("hex");
        }
        console.log(`[retichat] Propagation node: ${this._cfg.propagationNodeHash.slice(0,12)}...`);

        // Reset all propagation timers to 5s on fresh open
        ContactStore.resetPropagationTimers();

        this._setStatus("connecting");

        this._rns = new Reticulum();

        // HTTP Exchange (Reticulum-php) — the only transport.
        if (!this._cfg.exchangeUrl) {
            this._setStatus("offline");
            throw new Error("No exchangeUrl configured. Set exchangeUrl in config.json.");
        }

        console.log("[rns] HTTP exchange →", this._cfg.exchangeUrl);
        const iface = new PostInterface(
            this._cfg.interfaceName,
            this._cfg.exchangeUrl,
            IdMgr.hash
        );
        this._rns.addInterface(iface);
        this._connType = "exchange";

        // Set up LXMF router
        this._lxmfRouter = new LXMRouter(this._rns, IdMgr.id);
        this._lxmfRouter.on("message", (lxmfMsg) => {
            const srcHash = lxmfMsg.sourceHash?.toString("hex");
            const content = lxmfMsg.content?.toString() ?? "";
            const title = lxmfMsg.title?.toString() ?? "";
            const ts = lxmfMsg.timestamp;

            // Log EVERY incoming message BEFORE the privacy filter
            console.log(`[retichat] 📥 RX message: src=${srcHash?.slice(0,12) ?? "???"}... title="${title.slice(0,40)}" content="${content.slice(0,80)}" ts=${ts} fields=${lxmfMsg.fields?.size ?? 0}`);
            console.log(`[retichat]   ownHash=${RnsClient.ownHash?.slice(0,12)} msg.destHash=${lxmfMsg.destinationHash?.toString("hex")?.slice(0,12)}`);

            if (!srcHash) return;

            // ---- Delivery notification (proof) ----
            // If the incoming message has FIELD_TICKET and empty content, it's a
            // delivery notification from a recipient proving they got our message.
            const FIELD_TICKET = 0x0C;
            const ticket = lxmfMsg.fields?.get(FIELD_TICKET);
            if (ticket && (!content || content.length === 0)) {
                const pending = this._pendingTickets.get(ticket);
                if (pending) {
                    this._pendingTickets.delete(ticket);
                    console.log(`[retichat] ✅ PROOF (LXMF) ticket=${ticket.slice(0,8)}... from ${srcHash.slice(0,12)}`);
                    if (pending.onProof) pending.onProof(pending.messageId);
                    else {
                        MsgStore.updateStatus(pending.contactHash, pending.messageId, "proved");
                        this._onMsg.forEach(fn => fn(lxmfMsg, srcHash));
                    }
                }
                return;
            }

            // Privacy filter — DISABLED for testing
            // if (!ContactStore.isContact(srcHash)) {
            //     console.log(`[rns] 🔒 Filtered: ${srcHash.slice(0,12)}... not in contact list`);
            //     return;
            // }

            // Auto-create contact for unknown senders so messages appear in UI
            if (!ContactStore.isContact(srcHash)) {
                console.log(`[rns] 📇 Auto-adding contact: ${srcHash.slice(0,12)}...`);
                ContactStore.add(srcHash);
            }

            // Update display name from per-message FIELD_SENDER_NAME (0x10).
            // This is privacy-preserving — only message recipients see it,
            // unlike the old broadcast announce approach.
            const senderName = LXMF.senderNameFromFields(lxmfMsg.fields);
            if (senderName) {
                const contact = ContactStore.get(srcHash);
                if (contact && !contact.nameCustomized && contact.displayName !== senderName) {
                    contact.displayName = senderName;
                    ContactStore._save();
                }
            }

            MsgStore.add(srcHash, { dir: "in", content, status: "delivered", srcHash });
            ContactStore.touch(srcHash);
            // Successfully received a message — reset propagation timer to 5s
            ContactStore.setReachable(srcHash, true);
            this._onMsg.forEach(fn => fn(lxmfMsg, srcHash));
        });

        // Listen for announces on lxmf.propagation — these arrive in response
        // to path requests and carry the propagation node's public key.
        // Do NOT add to contact store — the propagation node is infrastructure,
        // not a chat contact.
        this._rns.registerAnnounceHandler("lxmf.propagation", (event) => {
            const hash = event.announce.destinationHash.toString("hex");
            if (hash === this._cfg.propagationNodeHash && event.announce.identity) {
                const pk = event.announce.identity.getPublicKey()?.toString("hex") ?? "";
                if (pk) {
                    this._cfg.propagationNodePubKey = pk;
                    sSet("propagationNodePubKey", pk);
                    console.log(`[retichat] 📡 Learned propagation node pub key from announce: ${pk.slice(0,12)}...`);
                    // Now that we have the pub key, establish a persistent link
                    this._establishPropagationLink();
                }
            }
        });

        // Listen for announces on lxmf.delivery to enrich contacts
        this._rns.registerAnnounceHandler("lxmf.delivery", (event) => {
            const hash = event.announce.destinationHash.toString("hex");
            ContactStore.updateFromAnnounce(hash, event.announce);
        });

        // Listen for RNS-level delivery proofs (packet.prove() responses)
        this._rns.on("proof", (event) => {
            const provedHash = event.provedPacketHash?.toString("hex");
            if (!provedHash) return;
            console.log(`[retichat] PROOF lookup: provedHash=${provedHash.slice(0,12)}... pendingKeys=[${[...this._pendingPacketHashes.keys()].map(k=>k.slice(0,12)).join(",")}]`);
            const pending = this._pendingPacketHashes.get(provedHash);
            if (pending) {
                this._pendingPacketHashes.delete(provedHash);
                console.log(`[retichat] ✅ PROOF (RNS) for packet ${provedHash.slice(0,12)}...`);
                if (pending.onProof) pending.onProof(pending.messageId);
                else {
                    MsgStore.updateStatus(pending.contactHash, pending.messageId, "proved");
                    this._onMsg.forEach(fn => fn(null, pending.contactHash));
                }
                // Clear the failure timeout
                // Trigger a re-render so the status icon updates
                this._onMsg.forEach(fn => fn(null, pending.contactHash));
            }
        });

        // Periodic announce
        setTimeout(() => this._announce(), 3000);

        // Request a path to the propagation node so we learn its public key
        // and can send store-and-forward messages.
        if (this._cfg.propagationNodeHash) {
            setTimeout(() => {
                try {
                    this._rns.transport.requestPath(this._cfg.propagationNodeHash);
                    console.log(`[retichat] Path request sent for propagation node ${this._cfg.propagationNodeHash.slice(0,12)}...`);
                } catch(e) { console.warn("[retichat] Path request for propagation node failed:", e.message); }
            }, 4000);  // wait for interface registration + first announce
        }

        if (this._cfg.announceIntervalMs > 0) {
            this._annTimer = setInterval(() => this._announce(), this._cfg.announceIntervalMs);
        }

        // Status monitor — checks every 2s if any interface is ready
        this._monTimer = setInterval(() => {
            const ifaces = this._rns?.interfaces || [];
            let anyReady = false;
            for (const iface of ifaces) {
                // HTTP exchange: ready once registered
                if (iface.isRegistered) { anyReady = true; break; }
                // Direct Sockets / WebSocket
                const ws = iface.websocket || iface.socket;
                if (ws && (ws.readyState === 1 || (ws.readable && ws.writable))) { anyReady = true; break; }
            }
            if (anyReady && this._status !== "online") this._setStatus("online");
            else if (!anyReady && ifaces.length > 0 && this._status !== "offline") this._setStatus("offline");
        }, 2000);

        console.log(`[rns] Connecting via ${this._connType} (${(this._rns?.interfaces || []).length} interface(s))...`);
    },

    _announce() {
        if (!this._lxmfRouter) return;
        // Check if any interface is ready
        const ifaces = this._rns?.interfaces || [];
        const anyReady = ifaces.some(iface => {
            // HTTP exchange: always ready once registered
            if (iface.isRegistered) return true;
            // Direct Sockets / WebSocket: check socket state
            const ws = iface.websocket || iface.socket;
            return ws && (ws.readyState === 1 || (ws.readable && ws.writable));
        });
        if (!anyReady) {
            console.log("[rns] Skipping announce — no interface ready");
            return;
        }
        try {
            const ownShort = RnsClient.ownHash?.slice(0,12) ?? IdMgr.shortHash ?? "";
            const name = this._cfg.displayName + (ownShort ? ` (${ownShort})` : "");
            this._lxmfRouter.announce(Buffer.from(name));
        } catch(e) { console.warn("[rns] announce error", e.message); }
    },

    /** Build the propagation_packed wire format matching iOS/Rust.
     *  lxmfPacked = dest_hash(16) | source_hash(16) | sig(64) | msgpack_payload
     *  Returns: msgpack([timestamp_f64, [[dest_hash | EC_encrypted(rest) | stamp(32)]]])
     */
    async _buildPropagationPacked(lxmfPacked, peerPublicKeyHex) {
        const destHash = lxmfPacked.slice(0, 16);
        const rest = lxmfPacked.slice(16);  // source_hash | sig | payload
        const peerIdentity = Identity.fromPublicKey(Buffer.from(peerPublicKeyHex, "hex"));
        const encrypted = peerIdentity.encrypt(rest);
        let lxmfData = Buffer.concat([destHash, encrypted]);

        // Compute propagation stamp (PoW proof-of-work, matching iOS)
        const stamp = await this._computePropagationStamp(lxmfData);
        if (stamp) {
            lxmfData = Buffer.concat([lxmfData, stamp]);
            console.log(`[retichat] 🔨 Propagation stamp computed, appended 32B`);
        } else {
            console.warn(`[retichat] ⚠️ Stamp computation failed, sending without stamp (will be rejected by node)`);
        }

        // msgpack: [timestamp_f64, [binary_blob]]
        return MsgPack.pack([Date.now() / 1000, [lxmfData]]);
    },

    /** Compute a 32-byte PoW stamp for propagation.
     *  Returns a Promise that resolves to a 32-byte Buffer or null on failure.
     *  Target: >= 13 leading zero bits (rfed default cost=16, flex=3). */
    async _computePropagationStamp(lxmfData) {
        try {
            const { sha256 } = await import("@noble/hashes/sha256");
            const { hkdf } = await import("@noble/hashes/hkdf");

            // Step 1: transient_id = sha256(lxmfData)  (Identity.full_hash is single SHA256)
            const transientId = sha256(lxmfData);

            // Step 2: build workblock through 1000 HKDF expansion rounds.
            // Rust: salt = sha256(transientId || msgpack_uint(n))  (Identity.full_hash is single SHA256)
            //       hkdf = Hkdf::new(Some(&salt), transientId)
            //       hkdf.expand(&[], &mut derived)  → 256 bytes
            const EXPAND_ROUNDS = 1000;
            const EXPAND_BYTES = 256;
            const workblockParts = [];

            // MsgPack unsigned integer encoding (matching rmp::encode::write_uint)
            const msgpackUint = (n) => {
                if (n <= 127) return Buffer.from([n]);
                if (n <= 255) return Buffer.from([0xcc, n]);
                if (n <= 65535) { const b = Buffer.alloc(3); b[0] = 0xcd; b.writeUInt16BE(n, 1); return b; }
                const b = Buffer.alloc(5); b[0] = 0xce; b.writeUInt32BE(n, 1); return b;
            };

            for (let n = 0; n < EXPAND_ROUNDS; n++) {
                const saltInput = Buffer.concat([transientId, msgpackUint(n)]);
                const salt = sha256(saltInput);
                // HKDF: IKM=transientId, salt=salt, info="", length=256
                const expanded = hkdf(sha256, transientId, salt, '', EXPAND_BYTES);
                workblockParts.push(Buffer.from(expanded));
                if (n % 50 === 49) await new Promise(r => setTimeout(r, 0));
            }
            const workblock = Buffer.concat(workblockParts);

            // Step 3: mine a 32-byte stamp where sha256(workblock || stamp)
            // has >= 13 leading zero bits (stamp_valid uses Identity.full_hash = single SHA256)
            const TARGET_ZERO_BITS = 13;
            const STAMP_SIZE = 32;
            let attempts = 0;
            const stamp = Buffer.alloc(STAMP_SIZE);

            while (true) {
                crypto.getRandomValues(stamp);
                const hashInput = Buffer.concat([workblock, stamp]);
                const hash = sha256(hashInput);
                let leadingZeros = 0;
                for (let i = 0; i < hash.length; i++) {
                    if (hash[i] === 0) { leadingZeros += 8; }
                    else { leadingZeros += Math.clz32(hash[i]) - 24; break; }
                }
                attempts++;
                if (leadingZeros >= TARGET_ZERO_BITS) {
                    console.log(`[retichat] 🔨 Stamp found after ${attempts} attempts (${leadingZeros} leading zero bits)`);
                    return stamp;
                }
                if (attempts % 100 === 0) await new Promise(r => setTimeout(r, 0));
            }
        } catch (e) {
            console.warn("[retichat] Stamp computation error:", e.message);
            return null;
        }
    },

    /** Establish a persistent link to the propagation node so we can send
     *  store-and-forward messages. Matching iOS AppLinks::open_persistent. */
    _establishPropagationLink() {
        if (!this._cfg.propagationNodePubKey || !this._cfg.propagationNodeHash) return;

        // Already have an active link?
        if (this._propLink && this._propLink.status === Link.ACTIVE) return;

        const propIdentity = Identity.fromPublicKey(
            Buffer.from(this._cfg.propagationNodePubKey, "hex")
        );
        const propDest = this._rns.registerDestination(
            propIdentity,
            Destination.OUT,
            Destination.LINK,
            "lxmf",
            "propagation"
        );

        const link = new Link();
        this._propLink = link;

        link.on("established", () => {
            console.log(`[retichat] 🔗 Propagation link established, rtt=${link.rtt}ms`);
            // Flush any messages that missed the propagation window while
            // the link was still being established.
            this._flushPropagation();
            // Identify ourselves so the PN can authorize /get requests.
            // Small delay to let the link settle before sending.
            setTimeout(() => { link.identify(IdMgr.id); }, 1_000);
            // Pull any stored messages for us — after identify has propagated
            setTimeout(() => { this._fetchPropagatedMessages(); }, 5_000);
        });

        link.on("close", () => {
            console.log("[retichat] Propagation link closed");
            this._propLink = null;
        });

        link.establish(propDest);
        console.log(`[retichat] 🔗 Establishing propagation link to ${this._cfg.propagationNodeHash.slice(0,12)}...`);
    },

    /** Flush any pending messages that need propagation now that the link is up. */
    async _flushPropagation() {
        const link = this._propLink;
        if (!link || link.status !== Link.ACTIVE) return;

        // Track which messages we've already propagated to avoid double-sends
        if (!this._propagatedMsgIds) this._propagatedMsgIds = new Set();

        for (const [contactHash, msgs] of MsgStore._messages || []) {
            const contact = ContactStore.get(contactHash);
            if (!contact || !contact.publicKey) continue;
            for (const msg of msgs) {
                if (msg.dir !== "out" || msg.status !== "sending") continue;
                if (this._propagatedMsgIds.has(msg.id)) continue;
                this._propagatedMsgIds.add(msg.id);

                console.log(`[retichat] 📡 Flush propagation for ${contactHash.slice(0,8)} msg=${msg.id.slice(0,8)}`);

                // Build LXMF message addressed to the contact
                const contactPeerId = Identity.fromPublicKey(Buffer.from(contact.publicKey, "hex"));
                const contactDest = this._rns.registerDestination(contactPeerId, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
                const FIELD_TICKET = 0x0C;
                const ticket = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex");

                const lxmfMsg = new LXMessage();
                lxmfMsg.sourceHash = this._lxmfRouter.destination.hash;
                lxmfMsg.destinationHash = contactDest.hash;
                lxmfMsg.title = "";
                lxmfMsg.content = msg.content;
                lxmfMsg.fields = new Map();
                lxmfMsg.fields.set(FIELD_TICKET, ticket);
                // Non-opportunistic: dest_hash at offset 0 for propagation node to read
                const packed = lxmfMsg.pack(IdMgr.id, false);

                // Build and send propagation_packed
                try {
                    const propagationPacked = await this._buildPropagationPacked(packed, contact.publicKey);
                    const pkt = new Packet();
                    pkt.headerType = Packet.HEADER_1;
                    pkt.packetType = Packet.DATA;
                    pkt.transportType = 0;
                    pkt.context = Packet.NONE;
                    pkt.contextFlag = Packet.FLAG_UNSET;
                    pkt.destination = link;
                    pkt.destinationHash = link.hash;
                    pkt.destinationType = Destination.LINK;
                    pkt.data = propagationPacked;
                    const raw = pkt.pack();

                    const truncatedHex = pkt.packetHash.slice(0, 16).toString("hex");
                    this._pendingPacketHashes.set(truncatedHex, {
                        contactHash: contactHash,
                        messageId: msg.id,
                        onProof: (msgId) => {
                            MsgStore.updateStatus(contactHash, msgId, "propagated");
                            console.log(`[retichat] ✓ Propagation proof for ${contactHash.slice(0,8)}`);
                            this._onMsg.forEach(fn => fn(null, contactHash));
                        }
                    });

                    this._rns.sendData(raw, link.attachedInterface);
                    console.log(`[retichat] 📡 Flushed propagation for ${contactHash.slice(0,8)}`);
                } catch (e) {
                    console.warn(`[retichat] Propagation flush failed for ${contactHash.slice(0,8)}:`, e.message);
                }
            }
        }
    },

    /** Fetch propagated messages (called when propagation link establishes).
     *  Sends /get over the link to list, download, and purge stored messages. */
    async _fetchPropagatedMessages() {
        const link = this._propLink;
        if (!link || link.status !== Link.ACTIVE) return;
        if (this._propFetchInProgress) return;
        this._propFetchInProgress = true;

        try {
            if (!this._propSeenIds) this._propSeenIds = new Set();

            // ── Step 1: List pending message IDs ──
            console.log("[retichat] 📬 [1/4] Listing pending messages...");
            const listReqId = link.sendRequest("/get", [null, null]);
            const listResp = await this._waitForResponse(link, listReqId, 15000);

            if (listResp === null || listResp === undefined) {
                console.log("[retichat] 📬 [1/4] List timed out");
                this._propFetchInProgress = false; return;
            }
            if (typeof listResp === 'number') {
                const names = {0xF0:'NO_IDENTITY',0xF1:'NO_ACCESS',0xF3:'INVALID_KEY',0xF4:'INVALID_DATA'};
                console.log(`[retichat] 📬 [1/4] List error 0x${listResp.toString(16)} (${names[listResp]||'unknown'})`);
                this._propFetchInProgress = false; return;
            }
            if (!Array.isArray(listResp)) {
                console.log(`[retichat] 📬 [1/4] List unexpected type: ${typeof listResp}`, listResp);
                this._propFetchInProgress = false; return;
            }
            console.log(`[retichat] 📬 [1/4] ${listResp.length} pending, ids=${listResp.map(b=>Buffer.from(b).toString("hex").slice(0,8)).join(",")}`);
            const pendingIds = listResp;
            if (pendingIds.length === 0) {
                console.log("[retichat] 📬 [1/4] No pending messages");
                this._propFetchInProgress = false; return;
            }

            const newIds = pendingIds.filter(id => !this._propSeenIds.has(Buffer.from(id).toString("hex")));
            if (newIds.length === 0) {
                console.log("[retichat] 📬 All pending already seen");
                this._propFetchInProgress = false; return;
            }

            // ── Step 2+3: Download and decrypt one at a time (avoids MTU limits) ──
            const deliveredIds = [];
            const myDeliverHash = this._lxmfRouter?.destination?.hash;
            if (!myDeliverHash) {
                console.log("[retichat] 📬 No local delivery hash — cannot decrypt");
                this._propFetchInProgress = false; return;
            }

            for (const tid of newIds) {
                const tidHex = Buffer.from(tid).toString("hex").slice(0,8);
                console.log(`[retichat] 📬 [2/4] Downloading ${tidHex}...`);
                const blobResp = await this._waitForResponse(
                    link,
                    link.sendRequest("/get", [[tid], null]),
                    15000
                );
                if (!blobResp || !Array.isArray(blobResp) || blobResp.length === 0) {
                    console.log(`[retichat] 📬 [2/4] ${tidHex} download failed:`, typeof blobResp === 'number' ? `0x${blobResp.toString(16)}` : (blobResp ? `got ${blobResp.length||0} items` : 'timeout'));
                    continue;
                }
                const lxmfData = Buffer.from(blobResp[0]);
                console.log(`[retichat] 📬 [3/4] ${tidHex} blob ${lxmfData.length}B dest=${lxmfData.slice(0,16).toString("hex").slice(0,12)}`);

                if (lxmfData.length < 48) { console.log(`[retichat] 📬 [3/4] ${tidHex} too short`); continue; }
                const destHash = lxmfData.slice(0, 16);
                if (!destHash.equals(myDeliverHash)) { console.log(`[retichat] 📬 [3/4] ${tidHex} not for us`); continue; }

                try {
                    const decrypted = IdMgr.id.decrypt(lxmfData.slice(16));
                    if (!decrypted || decrypted.length < 80) { console.log(`[retichat] 📬 [3/4] ${tidHex} decrypt failed`); continue; }
                    const srcHash = decrypted.slice(0, 16);
                    const payloadBytes = decrypted.slice(80);

                    let payload;
                    try { payload = MsgPack.unpack(payloadBytes); } catch(e) { console.log(`[retichat] 📬 [3/4] ${tidHex} bad payload`); continue; }
                    if (!Array.isArray(payload) || payload.length < 3) { console.log(`[retichat] 📬 [3/4] ${tidHex} bad payload shape`); continue; }

                    const [ts, titleBin, contentBin, fieldsMap] = payload;
                    const content = Buffer.from(contentBin || []).toString();
                    console.log(`[retichat] 📬 [3/4] ✅ ${tidHex} from ${srcHash.toString("hex").slice(0,12)}: "${content.slice(0,60)}"`);

                    this._lxmfRouter.emit("message", {
                        sourceHash: srcHash, destinationHash: destHash,
                        title: Buffer.from(titleBin || []).toString(),
                        content, fields: fieldsMap, timestamp: ts,
                    });
                    this._propSeenIds.add(Buffer.from(tid).toString("hex"));
                    deliveredIds.push(tid);
                } catch(e) {
                    console.warn(`[retichat] 📬 [3/4] ${tidHex} exception:`, e.message);
                }
            }

            // ── Step 4: Purge delivered ──
            if (deliveredIds.length > 0) {
                console.log(`[retichat] 📬 [4/4] Purging ${deliveredIds.length} delivered...`);
                const haveReqId = link.sendRequest("/get", [null, deliveredIds]);
                await this._waitForResponse(link, haveReqId, 10000);
                console.log("[retichat] 📬 [4/4] Purge complete");
            } else {
                console.log("[retichat] 📬 [4/4] Nothing to purge");
            }
        } catch(e) {
            console.warn("[retichat] 📬 Fetch exception:", e.message, e.stack?.slice(0,200));
        } finally {
            this._propFetchInProgress = false;
        }
    },

    /** Wait for a response matching requestId on the given link. */
    _waitForResponse(link, requestId, timeoutMs) {
        return new Promise((resolve) => {
            const timer = setTimeout(() => { link.off("response", handler); resolve(null); }, timeoutMs);
            const handler = (resp) => {
                if (!resp.requestId || resp.requestId.length !== requestId.length) return;
                if (!Buffer.from(resp.requestId).equals(Buffer.from(requestId))) return;
                clearTimeout(timer);
                link.off("response", handler);
                resolve(resp.data);
            };
            link.on("response", handler);
        });
    },

    sendMessage(contact, content) {
        if (!this._rns || !this._lxmfRouter) throw new Error("Not connected");
        if (!contact.publicKey) throw new Error("No public key for this contact yet.");

        console.log(`[retichat] ✉️ SEND to ${contact.destHash.slice(0,12)}... content="${content.slice(0,60)}"`);

        // Create the outgoing message record
        ContactStore.touch(contact.destHash);
        const outMsg = MsgStore.add(contact.destHash, {
            dir: "out", content, status: "sending",
            srcHash: this.ownHash, destHash: contact.destHash,
        });

        // Send directly to the destination
        let directProofReceived = false;
        this._sendPacket(contact.destHash, contact.publicKey, content, outMsg.id,
            (msgId) => {
                // Direct proof callback
                directProofReceived = true;
                MsgStore.updateStatus(contact.destHash, msgId, "proved");
                ContactStore.setReachable(contact.destHash, true);
                console.log(`[retichat] ✅ Direct proof for ${contact.destHash.slice(0,8)}`);
                this._onMsg.forEach(fn => fn(null, contact.destHash));
            },
            (msgId) => {
                // Direct send error
                MsgStore.updateStatus(contact.destHash, msgId, "failed");
            }
        );

        // After propagation delay, if no direct proof, also send to propagation node
        const delaySec = ContactStore.propagationDelay(contact.destHash);
        setTimeout(async () => {
            if (directProofReceived) return;
            const link = this._propLink;
            if (!link || link.status !== Link.ACTIVE) {
                console.log(`[retichat] ⚠️ Propagation link not active, cannot propagate`);
                // Try to re-establish
                this._establishPropagationLink();
                return;
            }
            console.log(`[retichat] 📡 Propagating via link to ${this._cfg.propagationNodeHash.slice(0,12)}... (direct proof not received in ${delaySec}s)`);

            // Build LXMF message addressed to the contact's delivery destination
            const contactPeerId = Identity.fromPublicKey(Buffer.from(contact.publicKey, "hex"));
            const contactDest = this._rns.registerDestination(contactPeerId, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
            const FIELD_TICKET = 0x0C;
            const ticket = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex");

            const msg = new LXMessage();
            msg.sourceHash = this._lxmfRouter.destination.hash;
            msg.destinationHash = contactDest.hash;
            msg.title = "";
            msg.content = content;
            msg.fields = new Map();
            msg.fields.set(FIELD_TICKET, ticket);
            // Pack non-opportunistic so destinationHash is at offset 0.
            // The propagation node reads dest_hash in cleartext from lxmf_data[0..16]
            // to identify the final recipient.
            const packed = msg.pack(IdMgr.id, false);

            // Build propagation_packed: msgpack([timestamp, [[dest_hash | EC_encrypted(rest) | stamp]]])
            const propagationPacked = await this._buildPropagationPacked(packed, contact.publicKey);

            // Build a LINK-type DATA packet. Packet.pack() handles link encryption
            // via this.destination.encrypt(), so do NOT pre-encrypt here.
            const pkt = new Packet();
            pkt.headerType = Packet.HEADER_1;
            pkt.packetType = Packet.DATA;
            pkt.transportType = 0;  // BROADCAST
            pkt.context = Packet.NONE;
            pkt.contextFlag = Packet.FLAG_UNSET;
            pkt.destination = link;
            pkt.destinationHash = link.hash;
            pkt.destinationType = Destination.LINK;
            pkt.data = propagationPacked;
            const raw = pkt.pack();

            // Track packet hash for proof matching
            const truncatedHex = pkt.packetHash.slice(0, 16).toString("hex");
            this._pendingPacketHashes.set(truncatedHex, {
                contactHash: contact.destHash,
                messageId: outMsg.id,
                onProof: (msgId) => {
                    if (!directProofReceived) {
                        MsgStore.updateStatus(contact.destHash, msgId, "propagated");
                        console.log(`[retichat] ✓ Propagation proof for ${contact.destHash.slice(0,8)}`);
                        this._onMsg.forEach(fn => fn(null, contact.destHash));
                    }
                }
            });

            this._rns.sendData(raw, link.attachedInterface);

            // Mark as likely offline
            if (contact.reachable !== false) {
                ContactStore.setReachable(contact.destHash, false);
            }
        }, delaySec * 1000);

        // 30-second total timeout — mark as failed if no proof at all
        const timeoutId = setTimeout(() => {
            const msgs = MsgStore.get(contact.destHash);
            const msg = msgs.find(m => m.id === outMsg.id);
            if (msg && msg.status === "sending") {
                MsgStore.updateStatus(contact.destHash, outMsg.id, "failed");
                this._onMsg.forEach(fn => fn(null, contact.destHash));
            }
            this._pendingTimeouts.delete(outMsg.id);
        }, 30000);
        this._pendingTimeouts.set(outMsg.id, timeoutId);

        return outMsg;
    },

    /** Core packet send: packs, sends, tracks proof, calls back. */
    _sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError) {
        const peerId = Identity.fromPublicKey(Buffer.from(publicKeyHex, "hex"));
        const dest = this._rns.registerDestination(peerId, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

        const FIELD_TICKET = 0x0C;
        const ticket = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex");

        const msg = new LXMessage();
        msg.sourceHash = this._lxmfRouter.destination.hash;
        msg.destinationHash = dest.hash;
        msg.title = "";
        msg.content = content;
        msg.fields = new Map();
        msg.fields.set(FIELD_TICKET, ticket);
        const packed = msg.pack(IdMgr.id, true);

        this._pendingTickets.set(ticket, { contactHash, messageId, onProof });

        try {
            const sentPacketHash = dest.send(packed);
            if (sentPacketHash) {
                const truncatedHex = sentPacketHash.slice(0, 16).toString("hex");
                this._pendingPacketHashes.set(truncatedHex, { contactHash, messageId, onProof });
            }
        } catch (e) {
            this._pendingTickets.delete(ticket);
            if (onError) onError(messageId);
            throw e;
        }
    },

    disconnect() {
        if (this._annTimer) { clearInterval(this._annTimer); this._annTimer = null; }
        if (this._monTimer) { clearInterval(this._monTimer); this._monTimer = null; }
        this._pendingTickets.clear();
        this._pendingPacketHashes.clear();
        for (const tid of this._pendingTimeouts.values()) clearTimeout(tid);
        this._pendingTimeouts.clear();
        // Disconnect all interfaces
        if (this._rns?.interfaces) {
            for (const iface of this._rns.interfaces) {
                try { iface.disconnect?.(); } catch(e) {}
            }
        }
        this._rns = null; this._lxmfRouter = null;
        this._connType = "none";
        this._setStatus("offline");
    },

    async reconnect() { this.disconnect(); await this.connect(); },
};

// =========================================================================
//  UI HELPERS
// =========================================================================
function h(tag, a={}, ...kids) {
    const el = document.createElement(tag);
    const boolProps = new Set(['disabled', 'checked', 'readonly', 'selected', 'required', 'hidden']);
    for (const [k,v] of Object.entries(a)) {
        if (k === "className") el.className = v;
        else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
        else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
        else if (k === "htmlFor") el.setAttribute("for", v);
        else if (k === "innerHTML") el.innerHTML = v;
        else if (boolProps.has(k)) { el[k] = !!v; }
        else { el.setAttribute(k, v); }
    }
    for (const c of kids.flat()) { if (c == null || c === false) continue; el.appendChild(typeof c === "string" ? document.createTextNode(c) : c); }
    return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
function fmtTime(ts) { return new Date(ts).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}); }
function fmtDate(ts) {
    const d = new Date(ts);
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    if (isToday) return fmtTime(ts);
    const yesterday = new Date(now); yesterday.setDate(yesterday.getDate() - 1);
    if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
    return d.toLocaleDateString([], {month:"short", day:"numeric"});
}

/** Deterministic avatar color hue from a string (matches iOS avatarColorHue) */
function avatarHue(name) {
    let hash = 5381;
    for (let i = 0; i < name.length; i++) hash = ((hash * 33) ^ name.charCodeAt(i)) >>> 0;
    return (hash % 360);
}

// =========================================================================
//  APP STATE
// =========================================================================
const App = {
    root: document.getElementById("app"),
    state: {
        view: "onboarding",     // "onboarding" | "main"
        activeHash: null,        // destHash of open chat
        theme: "dark",           // "dark" | "light"
        searchQuery: "",
        showSettings: false,
        showAddContact: false,
        showShareId: false,
        showContactInfo: false,
        contactInfoHash: null,
        isWide: window.innerWidth >= 800,
    },
    _pathRequestedThisSession: new Set(),
    _savedFocus: null,  // { activeHash, cursorPos, value } for focus restoration

    // ===== LIFECYCLE =====

    async start() {
        // Restore theme
        const savedTheme = localStorage.getItem("retichat_theme");
        if (savedTheme === "light" || savedTheme === "dark") this.state.theme = savedTheme;
        document.documentElement.setAttribute("data-theme", this.state.theme);

        if (!IdMgr.load()) { this.state.view = "onboarding"; this.render(); return; }
        this.state.view = "main";
        this.render();
        try { await RnsClient.connect(); } catch(e) { console.error("RNS connect failed", e); }
        this._wire();
        this._listenResize();
    },

    _listenResize() {
        window.addEventListener("resize", () => {
            const wasWide = this.state.isWide;
            this.state.isWide = window.innerWidth >= 800;
            // Re-render if crossing the breakpoint
            if (wasWide !== this.state.isWide) {
                // If going narrow with a chat open, set the slide class before render
                if (!this.state.isWide && this.state.activeHash) {
                    document.body.classList.add("narrow-chat-open");
                }
                if (this.state.isWide) {
                    document.body.classList.remove("narrow-chat-open");
                }
                this.render();
            }
        });

        // Escape key closes any open modal
        window.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                if (this.state.showSettings || this.state.showAddContact || this.state.showShareId || this.state.showContactInfo) {
                    this.state.showSettings = false;
                    this.state.showAddContact = false;
                    this.state.showShareId = false;
                    this.state.showContactInfo = false;
                    this.render();
                }
            }
        });
    },

    // ===== FOCUS PRESERVATION =====
    // Saves composer state before a render that would destroy the DOM,
    // so we can restore focus afterward.
    _saveComposerFocus() {
        const ta = document.getElementById("composer-input");
        if (ta && document.activeElement === ta) {
            this._savedFocus = {
                activeHash: this.state.activeHash,
                cursorPos: ta.selectionStart,
                value: ta.value,
            };
        } else {
            this._savedFocus = null;
        }
    },

    _restoreComposerFocus() {
        const sf = this._savedFocus;
        if (!sf) return;
        // Only restore if we're still in the same chat
        if (this.state.activeHash !== sf.activeHash) { this._savedFocus = null; return; }
        const ta = document.getElementById("composer-input");
        if (ta) {
            // Restore the in-flight text and cursor position
            if (sf.value && ta.value !== sf.value) {
                ta.value = sf.value;
                ta.style.height = "auto";
                ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
            }
            ta.focus();
            if (sf.cursorPos !== undefined && sf.value === ta.value) {
                ta.setSelectionRange(sf.cursorPos, sf.cursorPos);
            }
        }
        this._savedFocus = null;
    },

    // ===== RENDER =====

    render() {
        this._saveComposerFocus();
        clear(this.root);
        if (this.state.view === "onboarding") {
            // Center the onboarding card in the viewport
            this.root.style.justifyContent = "center";
            this.root.style.alignItems = "center";
            this._renderOnboarding();
            return;
        }
        // Reset for two-panel layout
        this.root.style.justifyContent = "";
        this.root.style.alignItems = "";

        // ---- Wide layout: side-by-side sidebar + detail ----
        if (this.state.isWide) {
            this._renderWide();
        } else {
            // ---- Narrow layout: single column ----
            this._renderNarrow();
        }

        // ---- Modals (rendered as overlays) ----
        if (this.state.showSettings) this._renderSettingsModal();
        if (this.state.showAddContact) this._renderAddContactModal();
        if (this.state.showShareId) this._renderShareIdModal();
        if (this.state.showContactInfo) this._renderContactInfoModal();

        // Re-apply status dot after DOM rebuild (RNS status hasn't changed so listener won't fire)
        this._applyStatusDot();

        // Restore composer focus if it was active before render
        requestAnimationFrame(() => this._restoreComposerFocus());
    },

    /** Restore the status dot color after a render destroys the old DOM. */
    _applyStatusDot() {
        const dot = document.getElementById("status-dot");
        if (dot && RnsClient._status) {
            dot.className = `status-dot ${RnsClient._status}`;
        }
    },

    /** Wide layout: sidebar (left) + detail (right) */
    _renderWide() {
        // Clean up narrow state if we just crossed the breakpoint
        document.body.classList.remove("narrow-chat-open");
        this.root.append(
            h("div", { className: "sidebar" },
                this._buildSidebarContent(),
            ),
            h("div", { className: "detail" },
                this.state.activeHash
                    ? this._buildChatView()
                    : this._buildPlaceholder(),
            ),
        );
    },

    /** Narrow layout: show list or chat.
     *  `openChat()` / `closeChat()` manage the `narrow-chat-open` body class
     *  for slide transitions; here we just render the correct panel. */
    _renderNarrow() {
        if (this.state.activeHash) {
            this.root.append(
                h("div", { className: "sidebar hidden" }),
                h("div", { className: "detail" },
                    this._buildChatView(),
                ),
            );
        } else {
            this.root.append(
                h("div", { className: "sidebar" },
                    this._buildSidebarContent(),
                ),
                h("div", { className: "detail hidden" }),
            );
        }
    },

    // ===== SIDEBAR CONTENT =====

    _buildSidebarContent() {
        const contacts = ContactStore.getAll();
        const filtered = this.state.searchQuery
            ? contacts.filter(c => {
                const name = (c.displayName || "").toLowerCase();
                const hash = c.destHash.toLowerCase();
                const q = this.state.searchQuery.toLowerCase();
                return name.includes(q) || hash.includes(q);
            })
            : contacts;
        const hasContacts = contacts.length > 0;
        const connType = RnsClient.connType;

        const frag = document.createDocumentFragment();

        // Header
        frag.appendChild(
            h("div", { className: "sidebar-header" },
                h("span", { id: "status-dot", className: "status-dot" }),
                h("h1", {}, "Retichat"),
                h("button", { className: "icon-btn", title: "Share Identity",
                    onClick: () => { this.state.showShareId = true; this.render(); } }, "🔗"),
                h("button", { className: "icon-btn", title: "Settings",
                    onClick: () => { this.state.showSettings = true; this.render(); } }, "⚙"),
            ),
        );

        // Search bar
        frag.appendChild(
            h("div", { className: "search-bar" },
                h("span", { className: "search-icon" }, "🔍"),
                h("input", {
                    id: "search-input",
                    type: "text",
                    placeholder: "Search chats…",
                    value: this.state.searchQuery,
                    onInput: (e) => {
                        this.state.searchQuery = e.target.value;
                        this.render();
                    },
                }),
                h("button", {
                    className: "search-clear" + (this.state.searchQuery ? " visible" : ""),
                    onClick: () => { this.state.searchQuery = ""; this.render(); },
                }, "✕"),
            ),
        );

        // Contact list or empty state
        if (hasContacts && filtered.length === 0 && this.state.searchQuery) {
            frag.appendChild(
                h("div", { className: "empty-list" },
                    h("div", { className: "empty-icon" }, "🔍"),
                    h("h2", {}, "No results"),
                    h("p", {}, `No contacts match "${esc(this.state.searchQuery)}"`),
                ),
            );
        } else if (!hasContacts) {
            frag.appendChild(
                h("div", { className: "empty-list" },
                    h("div", { className: "empty-icon" }, "💬"),
                    h("h2", {}, "No conversations yet"),
                    h("p", {}, "Add a contact using the + button to start chatting privately over Reticulum."),
                    h("button", { className: "btn btn-primary", style: { marginTop: "8px" },
                        onClick: () => { this.state.showAddContact = true; this.render(); } },
                        "+ Add Contact"),
                ),
            );
        } else {
            frag.appendChild(
                h("div", { className: "contact-list" },
                    ...filtered.map(c => this._buildContactItem(c)),
                ),
            );
        }

        // FAB for adding contact
        if (hasContacts) {
            frag.appendChild(
                h("button", { className: "fab",
                    onClick: () => { this.state.showAddContact = true; this.render(); } }, "+"),
            );
        }

        return frag;
    },

    _buildContactItem(c) {
        const name = c.displayName || "?" + c.destHash.slice(0, 8);
        const preview = MsgStore.preview(c.destHash);
        const msgs = MsgStore.get(c.destHash);
        const lastTs = msgs.length > 0 ? msgs[msgs.length - 1].timestamp : c.lastSeen;
        const isActive = this.state.activeHash === c.destHash;
        const hue = avatarHue(name);

        return h("div", {
            className: "contact-item" + (isActive ? " active" : ""),
            onClick: () => this.openChat(c.destHash),
        },
            h("div", {
                className: "contact-avatar",
                style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
            }, name.charAt(0).toUpperCase()),
            h("div", { className: "contact-info" },
                h("div", { className: "contact-name" }, esc(name)),
                preview
                    ? h("div", { className: "contact-preview" }, esc(preview))
                    : h("div", { className: "contact-preview", style: { fontStyle: "italic" } }, "Tap to chat"),
            ),
            h("div", { className: "contact-meta" },
                h("div", { className: "contact-time" }, lastTs ? fmtDate(lastTs) : ""),
                !c.publicKey
                    ? h("span", { className: "contact-badge waiting" }, "⏳")
                    : null,
            ),
        );
    },

    // ===== DETAIL PANEL =====

    _buildPlaceholder() {
        return h("div", { className: "placeholder" },
            h("div", { className: "ph-icon" }, "💬"),
            h("h2", {}, "Select a conversation"),
            h("p", { style: { color: "var(--text-muted)", fontSize: "14px" } },
                "Choose a contact from the sidebar to start chatting."),
        );
    },

    _buildChatView() {
        const c = ContactStore.get(this.state.activeHash);
        if (!c) { this.state.activeHash = null; this.render(); return document.createDocumentFragment(); }
        const name = c.displayName || "?" + c.destHash.slice(0, 8);
        const msgs = MsgStore.get(c.destHash);
        const hue = avatarHue(name);

        return h("div", { className: "chat-view" },
            // Header
            h("div", { className: "chat-header" },
                h("button", { className: "back-btn",
                    onClick: () => this.closeChat() }, "←"),
                h("div", {
                    className: "header-avatar",
                    style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
                }, name.charAt(0).toUpperCase()),
                h("div", { className: "header-info",
                    onClick: () => { this.state.showContactInfo = true; this.state.contactInfoHash = c.destHash; this.render(); },
                    style: { cursor: "pointer" } },
                    h("div", { className: "header-name" }, esc(name)),
                    h("div", { className: "header-hash" },
                        c.destHash + (c.publicKey ? "" : " — waiting for public key…")),
                ),
                h("button", { className: "icon-btn", title: "Contact info",
                    onClick: () => { this.state.showContactInfo = true; this.state.contactInfoHash = c.destHash; this.render(); } }, "ℹ"),
            ),

            // Messages
            h("div", { className: "message-list", id: "msg-list" },
                ...(msgs.length === 0
                    ? []
                    : msgs.map(m => {
                        const isOwn = m.dir === "out";
                        const statusIcon = isOwn ? this._statusIcon(m.status) : "";
                        return h("div", { className: `msg-row ${isOwn ? "own" : "their"}`, "data-msg-id": m.id },
                            h("div", { className: "msg-bubble" },
                                esc(m.content),
                                h("div", { className: "msg-meta" },
                                    h("span", { className: "msg-time" }, fmtTime(m.timestamp)),
                                    statusIcon ? h("span", { className: `msg-status ${m.status}`, "data-msg-status": m.status }, statusIcon) : null,
                                ),
                            ),
                        );
                    })),
            ),

            // Composer
            h("div", { className: "composer" },
                h("textarea", {
                    id: "composer-input",
                    placeholder: c.publicKey ? "Message…" : "Waiting for public key…",
                    rows: 1,
                    disabled: !c.publicKey,
                    onKeydown: (e) => {
                        if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); this.sendMessage(); }
                    },
                    onInput: (e) => {
                        e.target.style.height = "auto";
                        e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
                    },
                }),
                h("button", {
                    className: "btn-send",
                    disabled: !c.publicKey,
                    onClick: () => this.sendMessage(),
                }, "➤"),
            ),
        );
    },

    // ===== ACTIONS =====

    openChat(hash) {
        this.state.activeHash = hash;
        this.state.showSettings = false;
        this.state.showAddContact = false;
        this.state.showShareId = false;
        this.state.showContactInfo = false;

        // Send a path request if we don't have this contact's public key yet
        const c = ContactStore.get(hash);
        if (c && !c.publicKey) {
            this._requestPathForContact(hash);
        }

        // On narrow: ensure narrow-chat-open is set before render so the
        // detail panel renders in its final (visible) position.
        if (!this.state.isWide) {
            document.body.classList.add("narrow-chat-open");
        }
        this.render();
        // Scroll to bottom after render
        requestAnimationFrame(() => this._scrollChatBottom());
    },

    /** Send a path request to discover the route to a destination.
     *  Only sends once per session per destination hash. */
    _requestPathForContact(destHash) {
        if (this._pathRequestedThisSession.has(destHash)) return;
        const transport = RnsClient._rns?.transport;
        if (!transport) return;
        try {
            transport.requestPath(destHash);
            this._pathRequestedThisSession.add(destHash);
            console.log(`[app] Path request sent for ${destHash.slice(0,12)}...`);
        } catch(e) {
            console.warn(`[app] Path request failed for ${destHash.slice(0,12)}...`, e.message);
        }
    },

    closeChat() {
        // On narrow devices, animate the detail panel sliding out before re-render
        if (!this.state.isWide && document.body.classList.contains("narrow-chat-open")) {
            document.body.classList.remove("narrow-chat-open");
            // Wait for the CSS transition to complete, then rebuild
            setTimeout(() => {
                this.state.activeHash = null;
                this.render();
            }, 300);
        } else {
            this.state.activeHash = null;
            this.render();
        }
    },

    sendMessage() {
        const ta = document.getElementById("composer-input");
        if (!ta) return;
        const content = ta.value.trim();
        if (!content) return;
        const c = ContactStore.get(this.state.activeHash);
        if (!c) return;
        try {
            RnsClient.sendMessage(c, content);
            ta.value = "";
            ta.style.height = "auto";
            this.render();
            requestAnimationFrame(() => {
                this._scrollChatBottom();
                document.getElementById("composer-input")?.focus();
            });
        } catch(e) { alert("Send failed: " + e.message); }
    },

    _scrollChatBottom() {
        const ml = document.getElementById("msg-list");
        if (ml) ml.scrollTop = ml.scrollHeight;
    },

    /** Returns the icon character for a given message status. */
    _statusIcon(status) {
        switch (status) {
            case "sending":     return "●";   // filled dot — awaiting proof
            case "propagated":  return "✓";   // single check — stored at propagation node
            case "proved":      return "✓✓";  // double check — direct proof received
            case "failed":      return "✗";   // cross — failed
            default:            return "";
        }
    },

    toggleTheme() {
        this.state.theme = this.state.theme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", this.state.theme);
        localStorage.setItem("retichat_theme", this.state.theme);
        // Update theme-color meta tag
        const mc = document.querySelector('meta[name="theme-color"]');
        if (mc) mc.content = this.state.theme === "dark" ? "#0F0F1A" : "#F2F3F7";
    },

    // ===== ONBOARDING =====

    _renderOnboarding() {
        this.root.appendChild(
            h("div", { className: "onboarding" },
                h("h1", {}, "🜃 Retichat Web"),
                h("p", { className: "subtitle" }, "Private chat over the Reticulum Network Stack"),
                h("div", { className: "settings-field", style: { marginBottom: "20px" } },
                    h("label", {}, "Create a new identity"),
                    h("button", { className: "btn btn-primary btn-block",
                        onClick: () => { IdMgr.create(); this._showIdCreated(); } },
                        "✨ Create New Identity"),
                ),
                h("div", { className: "form-divider" }, "or"),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "import-hex" }, "Import existing identity (hex private key)"),
                    h("textarea", {
                        id: "import-hex",
                        placeholder: "Paste 128-char hex private key…",
                        rows: 3,
                        style: { marginTop: "4px" },
                    }),
                    h("button", { className: "btn btn-secondary btn-block", style: { marginTop: "8px" },
                        onClick: () => this._importId() }, "📥 Import Identity"),
                ),
            )
        );
    },

    _importId() {
        const hex = this.root.querySelector("#import-hex")?.value?.trim();
        if (!hex || hex.length !== 128) { alert("Enter a valid 128-character hex private key."); return; }
        try { IdMgr.importHex(hex); this._showIdCreated(); } catch(e) { alert("Failed: " + e.message); }
    },

    _showIdCreated() {
        clear(this.root);
        this.root.appendChild(
            h("div", { className: "onboarding" },
                h("h1", {}, "✅ Identity Ready"),
                h("p", { className: "subtitle" }, "Save your private key somewhere safe!"),
                h("div", { className: "settings-field" },
                    h("label", {}, "Your identity hash (for backup only)"),
                    h("div", { className: "mono-value" }, IdMgr.hash ?? "???"),
                ),
                h("div", { className: "settings-field" },
                    h("label", {}, "Private key (save this!)"),
                    h("textarea", {
                        readonly: true,
                        rows: 3,
                        style: { background: "var(--warning-bg)", color: "var(--warning)" },
                    }, IdMgr.privKey ?? ""),
                ),
                h("button", { className: "btn btn-primary btn-block",
                    onClick: () => this._enterApp() }, "🚀 Enter Retichat"),
            )
        );
    },

    async _enterApp() {
        this.state.view = "main";
        this.render();
        try { await RnsClient.connect(); } catch(e) { console.error(e); }
        this._wire();
    },

    // ===== MODALS =====

    /** Settings modal — mirrors iOS SettingsView sections */
    _renderSettingsModal() {
        const cfg = RnsClient.cfg;
        const connType = RnsClient.connType;
        const connLabel = connType === "exchange" ? "HTTP Exchange"
            : connType === "direct" ? "Direct Sockets"
            : connType === "websocket" ? "WebSocket" : "None";

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showSettings = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });

        // Header
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "Settings"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showSettings = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });

        // ---- Profile section ----
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Profile"),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-name" }, "Display Name"),
                    h("input", { id: "cfg-name", type: "text", value: cfg.displayName || "" }),
                    h("div", { className: "field-hint" }, "Shown in your announces on the network."),
                ),
            ),
        );

        // ---- Theme section ----
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Appearance"),
                h("div", { className: "settings-row" },
                    h("span", { className: "row-label" },
                        this.state.theme === "dark" ? "🌙 Dark Mode" : "☀️ Light Mode"),
                    h("label", { className: "toggle" },
                        h("input", {
                            type: "checkbox",
                            checked: this.state.theme === "dark",
                            onChange: () => this.toggleTheme(),
                        }),
                        h("span", { className: "slider" }),
                    ),
                ),
            ),
        );

        // ---- Connection section ----
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Connection"),
                h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginBottom: "12px" } },
                    "Current: ", h("strong", {}, connLabel)),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-exchange" }, "HTTP Exchange URL"),
                    h("input", { id: "cfg-exchange", type: "text", value: cfg.exchangeUrl || "",
                        placeholder: "https://your-host.com/reticulum" }),
                    h("div", { className: "field-hint" },
                        "Uses HTTP POST polling — no WebSocket or open ports needed."),
                ),
            ),
        );

        // ---- RFed / Propagation section ----
        const derivedProp = (() => {
            try {
                const rfedBytes = Buffer.from(cfg.rfedNodeHash || DEFAULT_CONFIG.rfedNodeHash, "hex");
                return Destination.hash({hash: rfedBytes}, "lxmf", "propagation").toString("hex");
            } catch(e) { return ""; }
        })();
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "RFed & Propagation"),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-rfed" }, "RFed Node Identity Hash"),
                    h("input", { id: "cfg-rfed", type: "text",
                        value: cfg.rfedNodeHash || "",
                        placeholder: DEFAULT_CONFIG.rfedNodeHash }),
                    h("div", { className: "field-hint" },
                        "Root identity for deriving propagation, notify, and channel addresses."),
                ),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-prop-override" }, "LXMF Propagation Override"),
                    h("input", { id: "cfg-prop-override", type: "text",
                        value: cfg.lxmfPropagationOverride || "",
                        placeholder: derivedProp.slice(0,16) + "… (derived from RFed)" }),
                    h("div", { className: "field-hint" },
                        "Leave empty to derive from RFed node. Set explicitly for a custom propagation node."),
                ),
            ),
        );

        // ---- Actions ----
        body.appendChild(
            h("div", { className: "btn-row" },
                h("button", { className: "btn btn-primary",
                    onClick: () => this._saveSettings() }, "Save & Reconnect"),
                h("button", { className: "btn btn-danger",
                    onClick: () => this._resetAll() }, "Reset All"),
            ),
        );

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);

        // Focus the first input
        setTimeout(() => sheet.querySelector("input")?.focus(), 150);
    },

    async _saveSettings() {
        const exchangeUrl = document.getElementById("cfg-exchange")?.value?.trim();
        const name = document.getElementById("cfg-name")?.value?.trim();
        const rfedHash = document.getElementById("cfg-rfed")?.value?.trim();
        const propOverride = document.getElementById("cfg-prop-override")?.value?.trim();
        if (exchangeUrl !== undefined) { RnsClient._cfg.exchangeUrl = exchangeUrl; sSet("exchangeUrl", exchangeUrl); }
        if (name !== undefined) { RnsClient._cfg.displayName = name; sSet("displayName", name); }
        if (rfedHash !== undefined) { RnsClient._cfg.rfedNodeHash = rfedHash; sSet("rfedNodeHash", rfedHash); }
        if (propOverride !== undefined) { RnsClient._cfg.lxmfPropagationOverride = propOverride; sSet("lxmfPropagationOverride", propOverride); }
        try { await RnsClient.reconnect(); } catch(e) { console.error(e); }
        this.state.showSettings = false;
        this.render();
    },

    _resetAll() {
        if (confirm("Delete your identity and ALL messages? This cannot be undone.")) {
            IdMgr.forget(); localStorage.clear(); location.reload();
        }
    },

    /** Add Contact modal */
    _renderAddContactModal() {
        let inputValue = "";

        const doAdd = () => {
            const raw = inputValue.trim();
            if (!raw) { alert("Enter a destination hash."); return; }
            let hash = raw.toLowerCase().replace(/^lxmf:\/\/|^lxma:\/\//, "");
            const colonIdx = hash.indexOf(":");
            if (colonIdx > -1) hash = hash.substring(0, colonIdx);
            hash = hash.replace(/[^0-9a-f]/g, "");
            if (hash.length !== 32) {
                alert("Destination hash must be exactly 32 hex characters.\n\nGot: " + (hash || "(empty)") + " (" + hash.length + " chars)");
                return;
            }
            try {
                ContactStore.add(hash);
                this._requestPathForContact(hash);
                this.state.showAddContact = false;
                this.render();
            } catch(e) { alert(e.message); }
        };

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showAddContact = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "Add Contact"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showAddContact = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });
        body.appendChild(
            h("div", { className: "settings-field" },
                h("label", { htmlFor: "add-hash" }, "Destination hash (32 hex characters)"),
                h("input", {
                    id: "add-hash", type: "text",
                    placeholder: "e.g. a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                    onInput: (e) => { inputValue = e.target.value; },
                    onKeydown: (e) => { if (e.key === "Enter") doAdd(); },
                }),
                h("div", { className: "field-hint" },
                    "You can also paste an lxmf:// or lxma:// link from another Retichat user."),
            ),
            h("div", { className: "btn-row", style: { marginTop: "16px" } },
                h("button", { className: "btn btn-primary", onClick: doAdd }, "Add Contact"),
                h("button", { className: "btn btn-secondary",
                    onClick: () => { this.state.showAddContact = false; this.render(); } }, "Cancel"),
            ),
        );

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);

        setTimeout(() => document.getElementById("add-hash")?.focus(), 150);
    },

    /** Share Identity modal */
    _renderShareIdModal() {
        const hash = RnsClient.ownHash || IdMgr.hash || "???";
        const pubKey = IdMgr.pubKey ?? "";
        const lxmfLink = `lxmf://${hash}`;
        const lxmaLink = pubKey.length === 128 ? `lxma://${hash}:${pubKey}` : null;

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showShareId = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "🔗 Share Your Identity"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showShareId = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });

        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Destination Hash"),
                h("div", { className: "mono-value", style: { fontSize: "13px" } }, hash),
                h("button", { className: "btn btn-secondary btn-block", style: { marginTop: "8px" },
                    onClick: () => { navigator.clipboard.writeText(hash).catch(() => {}); } },
                    "📋 Copy Hash"),
            ),
        );

        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "LXMF Link"),
                h("div", { className: "mono-value", style: { fontSize: "13px" } }, lxmfLink),
                h("button", { className: "btn btn-secondary btn-block", style: { marginTop: "8px" },
                    onClick: () => { navigator.clipboard.writeText(lxmfLink).catch(() => {}); } },
                    "📋 Copy Link"),
            ),
        );

        if (lxmaLink) {
            body.appendChild(
                h("div", { className: "settings-section" },
                    h("h3", {}, "LXMA Link (with public key — preferred)"),
                    h("div", { className: "mono-value", style: { fontSize: "11px" } }, lxmaLink),
                    h("button", { className: "btn btn-primary btn-block", style: { marginTop: "8px" },
                        onClick: () => { navigator.clipboard.writeText(lxmaLink).catch(() => {}); } },
                        "📋 Copy Full Link"),
                ),
            );
        }

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);
    },

    /** Contact Info modal — edit name, delete chat */
    _renderContactInfoModal() {
        const c = ContactStore.get(this.state.contactInfoHash);
        if (!c) { this.state.showContactInfo = false; this.render(); return; }
        const name = c.displayName || "?" + c.destHash.slice(0, 8);
        const hue = avatarHue(name);

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showContactInfo = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "Contact Info"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showContactInfo = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });

        // Avatar + name header
        body.appendChild(
            h("div", { style: { display: "flex", alignItems: "center", gap: "14px", marginBottom: "20px" } },
                h("div", {
                    className: "contact-avatar",
                    style: { width: "52px", height: "52px", fontSize: "22px",
                        color: `hsl(${hue}, 50%, 65%)`,
                        background: `hsla(${hue}, 50%, 40%, 0.15)`,
                        borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
                }, name.charAt(0).toUpperCase()),
                h("div", { style: { flex: 1 } },
                    h("div", { style: { fontWeight: 700, fontSize: "17px" } }, esc(name)),
                    h("div", { style: { fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "2px" } },
                        c.destHash),
                ),
            ),
        );

        // Display Name (single editable field)
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Display Name"),
                h("div", { className: "settings-field" },
                    h("input", {
                        id: "ci-display-name",
                        type: "text",
                        value: name === ("?" + c.destHash.slice(0,8)) ? "" : name,
                        placeholder: name,
                    }),
                    h("div", { className: "field-hint" },
                        "A local name for this contact. Stored only on this device."),
                ),
            ),
        );

        // Public key status
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Public Key"),
                h("div", {
                    style: {
                        fontSize: "11px",
                        fontFamily: "var(--font-mono)",
                        color: c.publicKey ? "var(--success)" : "var(--warning)",
                        wordBreak: "break-all",
                    },
                }, c.publicKey || "Not received yet — messages cannot be sent until the contact comes online."),
            ),
        );

        // Actions
        body.appendChild(
            h("div", { className: "btn-row", style: { marginBottom: "8px" } },
                h("button", { className: "btn btn-primary",
                    onClick: () => this._saveContactInfo() }, "Save"),
            ),
        );

        // Delete button
        body.appendChild(
            h("div", { style: { marginTop: "8px" } },
                h("button", {
                    className: "btn btn-danger btn-block",
                    onClick: () => this._deleteContact(c),
                }, "🗑 Delete Conversation"),
            ),
        );

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);

        setTimeout(() => sheet.querySelector("input")?.focus(), 150);
    },

    _saveContactInfo() {
        const hash = this.state.contactInfoHash;
        if (!hash) return;
        const displayName = document.getElementById("ci-display-name")?.value?.trim();
        if (displayName) ContactStore.setDisplayName(hash, displayName);
        this.state.showContactInfo = false;
        this.render();
    },

    _deleteContact(c) {
        const name = c.displayName || c.destHash.slice(0,8);
        if (!confirm(`Delete conversation with "${name}" and all messages? This cannot be undone.`)) return;
        const hash = c.destHash;
        MsgStore.remove(hash);
        ContactStore.remove(hash);
        this.state.showContactInfo = false;
        if (this.state.activeHash === hash) this.state.activeHash = null;
        document.body.classList.remove("narrow-chat-open");
        this.render();
    },

    // ===== IN-PLACE DOM UPDATES =====
    // Avoid full re-renders for events not initiated by the user:
    // proofs, incoming messages, and contact list refreshes.
    // This preserves scroll position and composer focus.

    /** Append a single incoming message to the active chat view without re-rendering. */
    _appendMessageToDOM(msg, contactHash, contactName) {
        const ml = document.getElementById("msg-list");
        if (!ml) return false;
        const hue = avatarHue(contactName || contactHash?.slice(0,8));
        const isOwn = msg.dir === "out";
        const statusIcon = isOwn ? this._statusIcon(msg.status) : "";
        const row = h("div", { className: `msg-row ${isOwn ? "own" : "their"}`, "data-msg-id": msg.id },
            h("div", { className: "msg-bubble" },
                esc(msg.content),
                h("div", { className: "msg-meta" },
                    h("span", { className: "msg-time" }, fmtTime(msg.timestamp)),
                    statusIcon ? h("span", { className: `msg-status ${msg.status}`, "data-msg-status": msg.status }, statusIcon) : null,
                ),
            ),
        );
        ml.appendChild(row);
        return true;
    },

    /** Update a message status icon in-place without re-rendering.
     *  Finds the msg-row by data-msg-id and updates its status span. */
    _updateMsgStatusDOM(contactHash, msgId, newStatus) {
        const row = document.querySelector(`.msg-row[data-msg-id="${msgId}"]`);
        if (!row) return;
        // Remove old status span if present
        const oldStatus = row.querySelector(".msg-status");
        if (oldStatus) oldStatus.remove();
        // Add new status span
        const icon = this._statusIcon(newStatus);
        if (icon) {
            const meta = row.querySelector(".msg-meta");
            if (meta) {
                const span = document.createElement("span");
                span.className = `msg-status ${newStatus}`;
                span.setAttribute("data-msg-status", newStatus);
                span.textContent = icon;
                meta.appendChild(span);
            }
        }
    },

    // ===== REACTIVE WIRING =====

    _wire() {
        // Status dot updates
        RnsClient.onStatus(status => {
            const dot = document.getElementById("status-dot");
            if (dot) {
                dot.className = `status-dot ${status}`;
                dot.title = `RNS: ${status}`;
            }
        });

        // Incoming messages & proofs: update in-place when possible,
        // fall back to full re-render only when sidebar state changed.
        RnsClient.onMessage((msg, peerHash) => {
            if (this.state.view !== "main") return;
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId || this.state.showContactInfo) return;
            const inActiveChat = this.state.activeHash === peerHash;

            // Proof-only event (msg is null): update status icon in-place.
            // No re-render needed — the status change doesn't affect layout.
            if (!msg) {
                if (!inActiveChat) return; // status update for a non-visible chat — no-op
                // Find all outbound messages whose status may have changed and update them
                const msgs = MsgStore.get(peerHash);
                for (const m of msgs) {
                    if (m.dir !== "out") continue;
                    this._updateMsgStatusDOM(peerHash, m.id, m.status);
                }
                return;
            }

            // New message event: if in the active chat, append to DOM.
            // If in a different chat or the contact list, the sidebar needs
            // a refresh — do a full re-render (BUT only if we can't avoid it).
            if (inActiveChat) {
                // The msg argument is the LXMessage, not the MsgStore entry.
                // Grab the last (just-added) message from MsgStore.
                const msgs = MsgStore.get(peerHash);
                const lastMsg = msgs[msgs.length - 1];
                if (lastMsg && lastMsg.dir === "in") {
                    const c = ContactStore.get(peerHash);
                    const name = c?.displayName || "?" + (peerHash?.slice(0,8) ?? "");
                    const attached = this._appendMessageToDOM(lastMsg, peerHash, name);
                    if (attached) {
                        requestAnimationFrame(() => this._scrollChatBottom());
                        return;
                    }
                }
            }

            // Fallback: full re-render (user not in affected chat, or DOM append failed)
            this.render();
            if (inActiveChat) {
                requestAnimationFrame(() => this._scrollChatBottom());
            }
        });

        // Contact list changes — only re-render if not in an active chat.
        // When in a chat, the contact list is hidden behind the detail panel
        // and re-rendering would destroy the user's scroll position.
        ContactStore.onChange(() => {
            if (this.state.view !== "main") return;
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId || this.state.showContactInfo) return;
            // Only re-render if the user is on the contact list (no active chat).
            // When in a chat, skip — the contact list will refresh next time
            // the user navigates back.
            if (!this.state.activeHash) {
                this.render();
            }
        });
    },
};

App.start();

// =========================================================================
//  E2E TEST HELPERS — run in browser console: RetichatTest.help()
// =========================================================================
window.RetichatTest = {
    help() {
        console.log(`
RetichatTest commands:
  .state()        — show connection state, contacts, messages
  .contacts()     — list all contacts with public keys
  .messages(hash) — show messages for contact (or all if no hash)
  .send(hash,msg) — send a test message to contact hash
  .ping(hash)     — check if contact has public key
  .raw()          — dump raw RNS/LXMF internals
        `);
    },

    state() {
        const s = {
            status: RnsClient.status,
            connType: RnsClient.connType,
            ownHash: RnsClient.ownHash,
            lxmfDest: RnsClient._lxmfRouter?.destination?.hash?.toString("hex"),
            interface: RnsClient._rns?.interfaces?.[0]?._interfaceId?.slice(0,12),
            registered: RnsClient._rns?.interfaces?.[0]?.isRegistered,
            contacts: ContactStore.getAll().length,
        };
        console.table(s);
        return s;
    },

    contacts() {
        const all = ContactStore.getAll();
        const rows = all.map(c => ({
            destHash: c.destHash.slice(0,12) + '...',
            displayName: c.displayName,
            hasPublicKey: !!c.publicKey,
            pkPreview: c.publicKey?.slice(0,12) + '...' || 'NONE',
            lastSeen: c.lastSeen ? new Date(c.lastSeen).toLocaleString() : 'never',
        }));
        console.table(rows);
        return rows;
    },

    messages(hash) {
        if (hash) {
            const msgs = MsgStore.get(hash);
            console.log(`${msgs.length} messages for ${hash.slice(0,12)}...`);
            msgs.forEach(m => console.log(`  [${m.dir}] "${m.content?.slice(0,60)}" status=${m.status}`));
            return msgs;
        }
        const all = ContactStore.getAll();
        for (const c of all) {
            const msgs = MsgStore.get(c.destHash);
            if (msgs.length) {
                console.log(`--- ${c.displayName} (${c.destHash.slice(0,12)}...) : ${msgs.length} msgs ---`);
                msgs.slice(-3).forEach(m => console.log(`  [${m.dir}] "${m.content?.slice(0,60)}"`));
            }
        }
        return 'see console';
    },

    send(destHash, content) {
        destHash = destHash.toLowerCase().replace(/[^0-9a-f]/g, '');
        const contact = ContactStore.get(destHash);
        if (!contact) return `Contact ${destHash.slice(0,12)}... not found. Add it first.`;
        if (!contact.publicKey) return `No public key for ${destHash.slice(0,12)}.... Wait for announce.`;
        try {
            RnsClient.sendMessage(contact, content || 'E2E test ' + Date.now());
            return 'Sent — check console';
        } catch(e) {
            console.error('Send failed:', e.message);
            return 'Error: ' + e.message;
        }
    },

    ping(destHash) {
        destHash = destHash.toLowerCase().replace(/[^0-9a-f]/g, '');
        const c = ContactStore.get(destHash);
        if (!c) return { error: 'not a contact', hint: 'Add this destHash as a contact first' };
        return {
            destHash: c.destHash.slice(0,12) + '...',
            displayName: c.displayName,
            hasPublicKey: !!c.publicKey,
            publicKey: c.publicKey?.slice(0,12) + '...' || null,
            lastSeen: c.lastSeen ? new Date(c.lastSeen).toLocaleString() : 'never',
        };
    },

    raw() {
        const rns = RnsClient._rns;
        const lxmf = RnsClient._lxmfRouter;
        const iface = rns?.interfaces?.[0];
        const dests = rns?._destinations ? [...rns._destinations.keys()].map(k => k.slice(0,12) + '...') : [];
        console.log({
            ownHash: RnsClient.ownHash,
            lxmfDestHash: lxmf?.destination?.hash?.toString("hex")?.slice(0,12) + '...',
            lxmfDestType: lxmf?.destination?.type,
            lxmfDestDirection: lxmf?.destination?.direction,
            interfaceId: iface?._interfaceId?.slice(0,12) + '...',
            interfaceRegistered: iface?.isRegistered,
            pollIntervalMs: iface?._pollIntervalMs,
            outboundQueueLen: iface?._outboundQueue?.length ?? 0,
            registeredDests: dests.length,
            destHashes: dests.slice(0, 10),
        });
    },
};
console.log('[retichat] 🧪 RetichatTest helpers loaded. Type RetichatTest.help()');
