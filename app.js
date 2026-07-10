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
    PostInterface,
} from "./lib/rns/reticulum.js";

// =========================================================================
//  CONFIG
// =========================================================================
const DEFAULT_CONFIG = {
    // HTTP Exchange (Reticulum-php native) — primary transport.
    // Announces flood through the PHP node to all interfaces including
    // PHP peer connections. Wake-driven between nodes.
    exchangeUrl: "https://retichat.com/reticulum",

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

            // Update display name from per-message FIELD_SENDER_NAME (0x10).
            // This is privacy-preserving — only message recipients see it,
            // unlike the old broadcast announce approach.
            const senderName = LXMF.senderNameFromFields(lxmfMsg.fields);
            if (senderName) {
                const contact = ContactStore.get(srcHash);
                if (contact && !contact.alias && contact.displayName !== senderName) {
                    contact.displayName = senderName;
                    ContactStore._save();
                }
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
        isWide: window.innerWidth >= 800,
    },
    _pathRequestedThisSession: new Set(),

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
                // On narrow, if we had a chat open, keep it
                this.render();
            }
        });

        // Escape key closes any open modal
        window.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                if (this.state.showSettings || this.state.showAddContact || this.state.showShareId) {
                    this.state.showSettings = false;
                    this.state.showAddContact = false;
                    this.state.showShareId = false;
                    this.render();
                }
            }
        });
    },

    // ===== RENDER =====

    render() {
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

        // Re-apply status dot after DOM rebuild (RNS status hasn't changed so listener won't fire)
        this._applyStatusDot();
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

    /** Narrow layout: show list or chat */
    _renderNarrow() {
        if (this.state.activeHash) {
            // Chat is open — show detail panel sliding in from right
            document.body.classList.add("narrow-chat-open");
            this.root.append(
                h("div", { className: "sidebar hidden" }),
                h("div", { className: "detail" },
                    this._buildChatView(),
                ),
            );
        } else {
            // Show sidebar
            document.body.classList.remove("narrow-chat-open");
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
                const name = (c.alias || c.displayName || "").toLowerCase();
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
        const name = c.alias || c.displayName || "?" + c.destHash.slice(0, 8);
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
        const name = c.alias || c.displayName || "?" + c.destHash.slice(0, 8);
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
                h("div", { className: "header-info" },
                    h("div", { className: "header-name" }, esc(name)),
                    h("div", { className: "header-hash" },
                        c.destHash + (c.publicKey ? "" : " — waiting for public key…")),
                ),
                h("button", { className: "icon-btn", title: "Contact info",
                    onClick: () => { /* future: contact info sheet */ } }, "ℹ"),
            ),

            // Messages
            h("div", { className: "message-list", id: "msg-list" },
                ...(msgs.length === 0
                    ? []
                    : msgs.map(m => {
                        const isOwn = m.dir === "out";
                        return h("div", { className: `msg-row ${isOwn ? "own" : "their"}` },
                            h("div", { className: "msg-bubble" },
                                esc(m.content),
                                h("div", { className: "msg-meta" },
                                    h("span", {}, fmtTime(m.timestamp)),
                                    isOwn ? h("span", {}, m.status === "sent" ? "✓" : "✓✓") : null,
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

        // Send a path request if we don't have this contact's public key yet
        // (first time opening this chat in the session)
        const c = ContactStore.get(hash);
        if (c && !c.publicKey) {
            this._requestPathForContact(hash);
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
        this.state.activeHash = null;
        document.body.classList.remove("narrow-chat-open");
        this.render();
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
        if (exchangeUrl !== undefined) { RnsClient._cfg.exchangeUrl = exchangeUrl; sSet("exchangeUrl", exchangeUrl); }
        if (name !== undefined) { RnsClient._cfg.displayName = name; sSet("displayName", name); }
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

        // Incoming messages: refresh the view (unless a modal is open)
        RnsClient.onMessage((msg, peerHash) => {
            if (this.state.view !== "main") return;
            // Don't disrupt open modals — they'll see updates when dismissed
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId) return;
            const inActiveChat = this.state.activeHash === peerHash;
            this.render();
            if (inActiveChat) {
                requestAnimationFrame(() => this._scrollChatBottom());
            }
        });

        // Contact list changes — only refresh if no modal is open
        ContactStore.onChange(() => {
            if (this.state.view !== "main") return;
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId) return;
            this.render();
        });
    },
};

App.start();
