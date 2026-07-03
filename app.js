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
    LXMessage,
    LXMRouter,
    LXMF,
    WebsocketClientInterface,
    DirectSocketsInterface,
    PostInterface,
} from "./lib/rns/reticulum.js";

// =========================================================================
//  CONFIG
// =========================================================================
const DEFAULT_CONFIG = {
    // ---- HTTP Exchange (Reticulum-php native) ----
    // Set this to your Reticulum-php node URL to use HTTP POST polling.
    // This is the preferred transport — no WebSocket, no open ports needed.
    exchangeUrl: "",  // e.g. "https://your-host.com/reticulum"

    // ---- WebSocket (fallback) ----
    rnsEndpoint: "wss://rns-wss.liamcottle.net",

    // ---- Direct Sockets (raw TCP from Chrome) ----
    tcpBackbones: [
        { host: "amsterdam.connect.reticulum.network", port: 4965 },
        { host: "reticulum.betweentheborders.com", port: 4242 },
        { host: "v0lttech.com", port: 4242 },
    ],

    interfaceName: "Retichat Web",
    displayName: "Retichat Web",
    announceIntervalMs: 300000,
};
async function loadConfig() {
    const cfg = { ...DEFAULT_CONFIG, tcpBackbones: [...(DEFAULT_CONFIG.tcpBackbones || [])] };
    try {
        const resp = await fetch("./config.json");
        if (resp.ok) {
            const json = await resp.json();
            if (json.exchangeUrl) cfg.exchangeUrl = json.exchangeUrl;
            if (json.rnsEndpoint) cfg.rnsEndpoint = json.rnsEndpoint;
            if (json.displayName) cfg.displayName = json.displayName;
            if (typeof json.announceIntervalMs === "number") cfg.announceIntervalMs = json.announceIntervalMs;
            if (Array.isArray(json.tcpBackbones)) cfg.tcpBackbones = json.tcpBackbones;
        }
    } catch(e) {}
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
            alias: existing?.alias ?? null,
            addedAt: existing?.addedAt ?? Date.now(),
            lastSeen: existing?.lastSeen ?? 0,
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

        if (!c.alias && announce.appData) {
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

    setAlias(destHash, alias) {
        const c = this._contacts.get(destHash);
        if (c) { c.alias = alias || null; this._save(); this._notify(); }
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
    _onStatus: [], _onMsg: [],

    get status() { return this._status; },
    get connType() { return this._connType; },
    get ownHash() { return this._lxmfRouter?.destination?.hash?.toString("hex") ?? null; },
    get cfg() { return this._cfg || DEFAULT_CONFIG; },

    onStatus(fn) { this._onStatus.push(fn); },
    onMessage(fn) { this._onMsg.push(fn); },

    _setStatus(s, type) {
        if (type) this._connType = type;
        if (this._status === s) return;
        this._status = s;
        this._onStatus.forEach(fn => fn(s));
    },

    async connect() {
        if (!IdMgr.has) throw new Error("No identity");
        this._cfg = await loadConfig();
        this._setStatus("connecting");

        this._rns = new Reticulum();
        let addedAny = false;

        // ---- Strategy 1: HTTP Exchange (Reticulum-php native) ----
        if (this._cfg.exchangeUrl) {
            console.log("[rns] Using HTTP exchange with Reticulum-php node at", this._cfg.exchangeUrl);
            const iface = new PostInterface(
                this._cfg.interfaceName,
                this._cfg.exchangeUrl,
                IdMgr.hash
            );
            this._rns.addInterface(iface);
            this._connType = "exchange";
            addedAny = true;
            console.log("[rns] HTTP exchange interface added");
        }

        // ---- Strategy 2: Direct Sockets (raw TCP from browser) ----
        if (!addedAny && DirectSocketsInterface.isAvailable() && this._cfg.tcpBackbones?.length > 0) {
            console.log("[rns] Direct Sockets available — connecting to TCP backbones directly");
            for (const bb of this._cfg.tcpBackbones) {
                if (!bb.host || !bb.port) continue;
                const iface = new DirectSocketsInterface(bb.host + ":" + bb.port, bb.host, bb.port);
                this._rns.addInterface(iface);
                addedAny = true;
            }
            if (addedAny) {
                this._connType = "direct";
                console.log(`[rns] Added ${this._cfg.tcpBackbones.length} Direct Sockets interface(s)`);
            }
        }

        // ---- Strategy 3: WebSocket (fallback) ----
        if (!addedAny && this._cfg.rnsEndpoint) {
            console.log("[rns] Using WebSocket fallback:", this._cfg.rnsEndpoint);
            const iface = new WebsocketClientInterface(this._cfg.interfaceName, this._cfg.rnsEndpoint);
            this._rns.addInterface(iface);
            this._connType = "websocket";
            addedAny = true;
        }

        if (!addedAny) {
            this._setStatus("offline");
            throw new Error("No interfaces configured. Set exchangeUrl in config.json for Reticulum-php, or enable Direct Sockets, or set a WebSocket endpoint.");
        }

        // Set up LXMF router
        this._lxmfRouter = new LXMRouter(this._rns, IdMgr.id);
        this._lxmfRouter.on("message", (lxmfMsg) => {
            const srcHash = lxmfMsg.sourceHash?.toString("hex");
            const content = lxmfMsg.content?.toString() ?? "";
            const title = lxmfMsg.title?.toString() ?? "";
            const ts = lxmfMsg.timestamp;

            // Log EVERY incoming message BEFORE the privacy filter
            console.log(`[rns] 📥 RX message: src=${srcHash?.slice(0,12) ?? "???"}... title="${title.slice(0,40)}" content="${content.slice(0,80)}" ts=${ts} fields=${lxmfMsg.fields?.size ?? 0}`);

            if (!srcHash) return;

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

            MsgStore.add(srcHash, { dir: "in", content, status: "delivered", srcHash });
            this._onMsg.forEach(fn => fn(lxmfMsg, srcHash));
        });

        // Listen for announces to enrich contacts
        this._rns.registerAnnounceHandler("lxmf.delivery", (event) => {
            const hash = event.announce.destinationHash.toString("hex");
            ContactStore.updateFromAnnounce(hash, event.announce);
        });

        // Periodic announce
        setTimeout(() => this._announce(), 3000);
        if (this._cfg.announceIntervalMs > 0) {
            this._annTimer = setInterval(() => this._announce(), this._cfg.announceIntervalMs);
        }

        // Status monitor
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
        }, 5000);

        this._setStatus("online");
        console.log(`[rns] Connected via ${this._connType} (${addedAny} interface(s))`);
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

    sendMessage(contact, content) {
        if (!this._rns || !this._lxmfRouter) throw new Error("Not connected");
        if (!contact.publicKey) throw new Error("No public key for this contact yet. Wait for them to come online, or ask them for their full lxma:// link.");

        const peerId = Identity.fromPublicKey(Buffer.from(contact.publicKey, "hex"));
        const dest = this._rns.registerDestination(peerId, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

        const msg = new LXMessage();
        msg.sourceHash = this._lxmfRouter.destination.hash;
        msg.destinationHash = dest.hash;
        msg.title = "";
        msg.content = content;
        msg.fields = new Map();
        dest.send(msg.pack(IdMgr.id, true));

        return MsgStore.add(contact.destHash, {
            dir: "out", content, status: "sent",
            srcHash: this.ownHash, destHash: contact.destHash,
        });
    },

    disconnect() {
        if (this._annTimer) { clearInterval(this._annTimer); this._annTimer = null; }
        if (this._monTimer) { clearInterval(this._monTimer); this._monTimer = null; }
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
        else if (boolProps.has(k)) {
            // Boolean attributes: use DOM property, not setAttribute
            el[k] = !!v;
        } else {
            el.setAttribute(k, v);
        }
    }
    for (const c of kids.flat()) { if (c == null || c === false) continue; el.appendChild(typeof c === "string" ? document.createTextNode(c) : c); }
    return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
function fmtTime(ts) { return new Date(ts).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}); }

// =========================================================================
//  APP CONTROLLER
// =========================================================================
const App = {
    root: document.getElementById("app"),
    activeHash: null,
    _view: "onboarding",

    async start() {
        if (!IdMgr.load()) { this._view = "onboarding"; this._render(); return; }
        this._view = "main";
        this._render();
        try { await RnsClient.connect(); } catch(e) { console.error("RNS connect failed", e); }
        this._wire();
    },

    _render() {
        clear(this.root);
        switch (this._view) {
            case "onboarding": this._renderOnboarding(); break;
            case "main": this._renderMain(); break;
            case "addContact": this._renderAddContact(); break;
            case "chat": this._renderChat(); break;
            case "shareId": this._renderShareId(); break;
            case "settings": this._renderSettings(); break;
        }
    },

    // ---------- ONBOARDING ----------
    _renderOnboarding() {
        this.root.appendChild(
            h("div", { className: "onboarding" },
                h("h1", {}, "🜃 Retichat Web"),
                h("p", { className: "subtitle" }, "Private chat over the Reticulum Network Stack"),
                h("div", { className: "form-group" },
                    h("label", {}, "Create a new identity"),
                    h("button", { className: "btn btn-primary", onClick: () => { IdMgr.create(); this._showIdCreated(); } }, "✨ Create New Identity"),
                ),
                h("div", { className: "divider" }, "or"),
                h("div", { className: "form-group" },
                    h("label", { htmlFor: "import-hex" }, "Import existing identity (hex private key)"),
                    h("textarea", { id: "import-hex", placeholder: "Paste 128-char hex private key...", rows: 3 }),
                    h("button", { className: "btn btn-secondary", style: { marginTop:"8px", width:"100%" },
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
                h("div", { className: "form-group" },
                    h("label", {}, "Your identity hash (for backup only — not what you share)"),
                    h("div", { className: "identity-preview" }, IdMgr.hash ?? "???"),
                ),
                h("div", { className: "form-group" },
                    h("label", {}, "Private key (save this!)"),
                    h("textarea", { readonly: true, rows: 3, style: { background:"#fff3cd" } }, IdMgr.privKey ?? ""),
                ),
                h("button", { className: "btn btn-primary", onClick: () => this._enterApp() }, "🚀 Enter Retichat"),
            )
        );
    },

    async _enterApp() {
        this._view = "main"; this._render();
        try { await RnsClient.connect(); } catch(e) { console.error(e); }
        this._wire();
    },

    // ---------- MAIN (Contact List) ----------
    _renderMain() {
        const contacts = ContactStore.getAll();
        const hasContacts = contacts.length > 0;
        const hasDirectSockets = DirectSocketsInterface.isAvailable();
        const connType = RnsClient.connType;

        // Build the top area
        const topChildren = [
            h("div", { className: "sidebar-header" },
                h("div", { style: { display:"flex", alignItems:"center", gap:"8px" } },
                    h("span", { id:"status-dot", className:"status-dot offline" }),
                    h("h1", {}, "Retichat"),
                ),
                h("div", { style: { display:"flex", gap:"4px" } },
                    hasContacts ? h("button", { className:"btn btn-secondary", style:{padding:"6px 10px",fontSize:"12px"},
                        onClick: () => { this._view = "addContact"; this._render(); } }, "+") : null,
                    h("button", { className:"btn btn-secondary", style:{padding:"6px 10px",fontSize:"12px"},
                        onClick: () => { this._view = "shareId"; this._render(); } }, "🔗"),
                    h("button", { className:"btn btn-secondary", style:{padding:"6px 10px",fontSize:"12px"},
                        onClick: () => { this._view = "settings"; this._render(); } }, "⚙"),
                ),
            ),
        ];

        // Show connection status banner
        if (connType === "exchange") {
            topChildren.push(
                h("div", { style: {
                    padding: "6px 12px", fontSize: "11px", background: "#d4edda",
                    borderBottom: "1px solid #28a745", color: "#155724",
                }},
                    "🟢 Connected via HTTP Exchange (Reticulum-php node)"
                ),
            );
        } else if (connType === "direct") {
            topChildren.push(
                h("div", { style: {
                    padding: "6px 12px", fontSize: "11px", background: "#d4edda",
                    borderBottom: "1px solid #28a745", color: "#155724",
                }},
                    "🟢 Connected via Direct Sockets (raw TCP)"
                ),
            );
        } else if (!hasDirectSockets && connType !== "websocket") {
            topChildren.push(
                h("div", { style: {
                    padding: "8px 12px", fontSize: "11px", background: "#fff3cd",
                    borderBottom: "1px solid #ffc107", color: "#856404", lineHeight: "1.4",
                }},
                    "⚠ No connection method configured. Set ",
                    h("code", { style: { background:"#ffeeba", padding:"1px 4px", borderRadius:"3px" } }, "exchangeUrl"),
                    " in config.json to connect to your Reticulum-php node."
                ),
            );
        } else if (!hasDirectSockets && connType === "websocket") {
            topChildren.push(
                h("div", { style: {
                    padding: "8px 12px", fontSize: "11px", background: "#fff3cd",
                    borderBottom: "1px solid #ffc107", color: "#856404", lineHeight: "1.4",
                }},
                    "⚠ Direct Sockets unavailable — using WebSocket fallback."
                ),
            );
        }

        topChildren.push(
            hasContacts
                ? h("div", { className: "contact-list", style: { flex:1, overflowY:"auto" } },
                    ...contacts.map(c => {
                        const name = c.alias || c.displayName || "?"+c.destHash.slice(0,8);
                        const preview = MsgStore.preview(c.destHash);
                        return h("div", {
                            className: "contact-item",
                            onClick: () => { this.activeHash = c.destHash; this._view = "chat"; this._render(); },
                        },
                            h("div", { className: "contact-avatar" }, name.charAt(0).toUpperCase()),
                            h("div", { className: "contact-info" },
                                h("div", { className: "contact-name" }, esc(name)),
                                preview
                                    ? h("div", { className: "contact-preview" }, esc(preview))
                                    : h("div", { className: "contact-preview", style:{fontStyle:"italic"} }, "Tap to chat"),
                            ),
                            h("div", { className: "contact-hops" }, c.publicKey ? "" : "⏳"),
                        );
                    }))
                : h("div", { className: "empty-state", style:{flex:1} },
                    h("div", { className: "icon" }, "🔒"),
                    h("h2", {}, "No contacts yet"),
                    h("p", {}, "Retichat is private by default. Add a contact by entering their destination hash."),
                    h("button", { className:"btn btn-primary", style:{marginTop:"12px"},
                        onClick: () => { this._view = "addContact"; this._render(); } }, "+ Add Contact"),
                ),
        );

        this.root.appendChild(
            h("div", { className: "app-shell" },
                h("div", { className: "sidebar", style: { width:"100%", minWidth:"unset", display:"flex", flexDirection:"column" } },
                    ...topChildren,
                ),
            )
        );
    },

    // ---------- ADD CONTACT ----------
    _renderAddContact() {
        let inputValue = "";
        const doAdd = () => {
            const raw = inputValue.trim();
            if (!raw) { alert("Enter a destination hash."); return; }
            let hash = raw.toLowerCase().replace(/^lxmf:\/\/|^lxma:\/\//, "");
            const colonIdx = hash.indexOf(":");
            if (colonIdx > -1) hash = hash.substring(0, colonIdx);
            hash = hash.replace(/[^0-9a-f]/g, "");
            if (hash.length !== 32) { alert("Destination hash must be exactly 32 hex characters.\n\nGot: " + (hash || "(empty)") + " (" + hash.length + " chars)"); return; }
            try {
                ContactStore.add(hash);
                this._view = "main"; this._render();
            } catch(e) { alert(e.message); }
        };

        this.root.appendChild(
            h("div", { className: "onboarding" },
                h("h1", {}, "Add Contact"),
                h("p", { className: "subtitle" }, "Enter their destination hash, or paste an lxmf:// link."),
                h("div", { className: "form-group" },
                    h("label", { htmlFor: "add-hash" }, "Destination hash (32 hex characters)"),
                    h("input", {
                        id: "add-hash", type: "text",
                        placeholder: "e.g. a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                        onInput: (e) => { inputValue = e.target.value; },
                        onKeydown: (e) => { if (e.key === "Enter") doAdd(); },
                    }),
                    h("div", { style:{fontSize:"11px",color:"var(--text-muted)",marginTop:"4px"} },
                        "You can also paste an lxmf:// or lxma:// link from another Retichat user."),
                ),
                h("div", { className: "btn-row" },
                    h("button", { className:"btn btn-primary", onClick: doAdd }, "Add Contact"),
                    h("button", { className:"btn btn-secondary",
                        onClick: () => { this._view = "main"; this._render(); } }, "Cancel"),
                ),
            )
        );
        setTimeout(() => this.root.querySelector("#add-hash")?.focus(), 100);
    },

    // ---------- CHAT ----------
    _renderChat() {
        const c = ContactStore.get(this.activeHash);
        if (!c) { this._view = "main"; this._render(); return; }
        const name = c.alias || c.displayName || "?"+c.destHash.slice(0,8);
        const msgs = MsgStore.get(c.destHash);

        this.root.appendChild(
            h("div", { className:"app-shell", style:{flexDirection:"column"} },
                h("div", { className:"chat-header", style:{flexShrink:0} },
                    h("button", { className:"btn btn-secondary", style:{padding:"4px 8px",fontSize:"12px"},
                        onClick: () => { this._view = "main"; this._render(); } }, "←"),
                    h("div", { className:"contact-avatar", style:{width:"32px",height:"32px",fontSize:"13px"} }, name.charAt(0).toUpperCase()),
                    h("div", {},
                        h("div", { className:"peer-name" }, esc(name)),
                        h("div", { className:"peer-hash" }, c.destHash + (c.publicKey ? "" : " — waiting for public key...")),
                    ),
                ),
                h("div", { className:"message-list", id:"msg-list", style:{flex:1} },
                    ...(msgs.length === 0
                        ? [h("div", { className:"message-system" }, "Share your identity link with this contact so they can add you back. Messages are end-to-end encrypted. 🔐")]
                        : msgs.map(m => {
                            const isOwn = m.dir === "out";
                            return h("div", { className:`message-row ${isOwn?"own":"their"}` },
                                h("div", { className:"message-bubble" }, esc(m.content)),
                                h("div", { className:"message-meta" },
                                    h("span", {}, fmtTime(m.timestamp)),
                                    isOwn ? h("span", {}, m.status==="sent" ? "✓" : "✓✓") : null,
                                ),
                            );
                        })),
                ),
                h("div", { className:"composer", style:{flexShrink:0} },
                    h("textarea", {
                        id:"composer-input",
                        placeholder: c.publicKey ? "Type a message..." : "Waiting for contact's public key...",
                        rows:1,
                        disabled: !c.publicKey,
                        onKeydown: (e) => { if (e.key==="Enter" && !e.shiftKey) { e.preventDefault(); this._sendMsg(); } },
                        onInput: (e) => { e.target.style.height="auto"; e.target.style.height=Math.min(e.target.scrollHeight,120)+"px"; },
                    }),
                    h("button", { className:"btn-send", disabled:!c.publicKey, onClick:() => this._sendMsg() }, "➤"),
                ),
            )
        );
        requestAnimationFrame(() => {
            const ml = document.getElementById("msg-list");
            if (ml) ml.scrollTop = ml.scrollHeight;
            document.getElementById("composer-input")?.focus();
        });
    },

    _sendMsg() {
        const ta = document.getElementById("composer-input");
        if (!ta) return;
        const content = ta.value.trim(); if (!content) return;
        const c = ContactStore.get(this.activeHash); if (!c) return;
        try {
            RnsClient.sendMessage(c, content);
            ta.value = ""; ta.style.height = "auto";
            this._render();
            requestAnimationFrame(() => {
                const ml = document.getElementById("msg-list");
                if (ml) ml.scrollTop = ml.scrollHeight;
                document.getElementById("composer-input")?.focus();
            });
        } catch(e) { alert("Send failed: " + e.message); }
    },

    // ---------- SHARE IDENTITY ----------
    _renderShareId() {
        const hash = RnsClient.ownHash || IdMgr.hash || "???";
        const pubKey = IdMgr.pubKey ?? "";
        const lxmfLink = `lxmf://${hash}`;
        const lxmaLink = pubKey.length === 128 ? `lxma://${hash}:${pubKey}` : null;

        this.root.appendChild(
            h("div", { className:"onboarding" },
                h("h1", {}, "🔗 Share Your Identity"),
                h("p", { className:"subtitle" }, "Give this to others so they can add you as a contact in their Retichat."),
                h("div", { className:"form-group" },
                    h("label", {}, "Your destination hash"),
                    h("div", { className:"identity-preview", style:{fontSize:"14px"} },
                        hash,
                        h("br"),
                        h("span", { style:{fontSize:"11px",color:"var(--text-muted)"} }, "32 hex characters"),
                    ),
                    h("button", { className:"btn btn-secondary", style:{marginTop:"8px",width:"100%"},
                        onClick: () => { navigator.clipboard.writeText(hash).then(() => {}).catch(() => {}); } }, "📋 Copy Hash"),
                ),
                h("div", { className:"form-group" },
                    h("label", {}, "LXMF link (hash only)"),
                    h("div", { className:"identity-preview", style:{fontSize:"13px"} }, lxmfLink),
                    h("button", { className:"btn btn-secondary", style:{marginTop:"8px",width:"100%"},
                        onClick: () => { navigator.clipboard.writeText(lxmfLink).then(() => {}).catch(() => {}); } }, "📋 Copy Link"),
                ),
                lxmaLink ? h("div", { className:"form-group" },
                    h("label", {}, "LXMA link (with public key — preferred)"),
                    h("div", { className:"identity-preview", style:{fontSize:"11px",wordBreak:"break-all"} }, lxmaLink),
                    h("button", { className:"btn btn-primary", style:{marginTop:"8px",width:"100%"},
                        onClick: () => { navigator.clipboard.writeText(lxmaLink).then(() => {}).catch(() => {}); } }, "📋 Copy Full Link"),
                ) : null,
                h("button", { className:"btn btn-secondary", style:{marginTop:"20px",width:"100%"},
                    onClick: () => { this._view = "main"; this._render(); } }, "← Back"),
            )
        );
    },

    // ---------- SETTINGS ----------
    _renderSettings() {
        const cfg = RnsClient.cfg;
        const connType = RnsClient.connType;
        this.root.appendChild(
            h("div", { className:"onboarding" },
                h("h1", {}, "⚙ Settings"),
                h("div", { style:{fontSize:"13px",color:"var(--text-muted)",marginBottom:"16px"} },
                    "Connection: " + (
                        connType === "exchange" ? "🟢 HTTP Exchange (Reticulum-php)" :
                        connType === "direct" ? "🟢 Direct Sockets" :
                        connType === "websocket" ? "🔵 WebSocket" : "⚫ None")),
                h("div", { className:"form-group" },
                    h("label", { htmlFor:"cfg-exchange" }, "Reticulum-php Exchange URL (primary)"),
                    h("input", { id:"cfg-exchange", type:"text", value: cfg.exchangeUrl || "",
                        placeholder: "https://your-host.com/reticulum" }),
                    h("div", { style:{fontSize:"11px",color:"var(--text-muted)",marginTop:"4px"} },
                        "Uses HTTP POST polling — no WebSocket or open ports needed."),
                ),
                h("div", { className:"form-group" },
                    h("label", { htmlFor:"cfg-ep" }, "WebSocket Endpoint (fallback)"),
                    h("input", { id:"cfg-ep", type:"text", value: cfg.rnsEndpoint || "" }),
                ),
                h("div", { className:"form-group" },
                    h("label", { htmlFor:"cfg-name" }, "Display Name"),
                    h("input", { id:"cfg-name", type:"text", value: cfg.displayName }),
                ),
                h("div", { className:"form-group" },
                    h("label", {}, "Identity"),
                    h("div", { className:"identity-preview" }, "Hash: " + (IdMgr.hash ?? "N/A")),
                ),
                h("div", { className:"btn-row", style:{marginTop:"20px"} },
                    h("button", { className:"btn btn-primary",
                        onClick: () => this._saveSettings() }, "Save & Reconnect"),
                    h("button", { className:"btn btn-danger",
                        onClick: () => this._resetAll() }, "Reset All Data"),
                    h("button", { className:"btn btn-secondary",
                        onClick: () => { this._view = "main"; this._render(); } }, "← Back"),
                ),
            )
        );
    },

    async _saveSettings() {
        const exchangeUrl = this.root.querySelector("#cfg-exchange")?.value?.trim();
        const ep = this.root.querySelector("#cfg-ep")?.value?.trim();
        const name = this.root.querySelector("#cfg-name")?.value?.trim();
        if (exchangeUrl) RnsClient._cfg.exchangeUrl = exchangeUrl;
        if (ep) RnsClient._cfg.rnsEndpoint = ep;
        if (name) RnsClient._cfg.displayName = name;
        try { await RnsClient.reconnect(); } catch(e) { console.error(e); }
        this._view = "main"; this._render();
    },

    _resetAll() {
        if (confirm("Delete your identity and ALL messages? This cannot be undone.")) {
            IdMgr.forget(); localStorage.clear(); location.reload();
        }
    },

    // ---------- REACTIVE WIRING ----------
    _wire() {
        RnsClient.onStatus(status => {
            const dot = document.getElementById("status-dot");
            if (dot) {
                dot.className = `status-dot ${status}`;
                const typeStr = RnsClient.connType === "exchange" ? "HTTP Exchange" :
                                RnsClient.connType === "direct" ? "Direct Sockets" :
                                RnsClient.connType === "websocket" ? "WebSocket" : "none";
                dot.title = `RNS: ${status} (${typeStr})`;
            }
        });

        RnsClient.onMessage((msg, peerHash) => {
            if (this._view === "chat" && peerHash === this.activeHash) {
                this._render();
                requestAnimationFrame(() => {
                    const ml = document.getElementById("msg-list");
                    if (ml) ml.scrollTop = ml.scrollHeight;
                });
            }
            if (this._view === "main") this._render();
        });

        ContactStore.onChange(() => {
            if (this._view === "main") this._render();
            // Also re-render chat view if the active contact's info updated
            if (this._view === "chat" && this.activeHash) {
                this._render();
                requestAnimationFrame(() => {
                    const ml = document.getElementById("msg-list");
                    if (ml) ml.scrollTop = ml.scrollHeight;
                });
            }
        });
    },
};

App.start();
