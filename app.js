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
    GROUP_FIELDS,
    channelIdentity,
    channelLxmPack,
    channelLxmUnpack,
    channelComputeStamp,
    rfedDeliveryDestHash,
} from "./lib/rns/reticulum.js?v=20260809-destreg";
import MsgPack from "./lib/rns/msgpack.js";
import { GroupDeliveryEvidence, GroupFallbackRegistry } from "./lib/rns/group_fallback.js?v=20260726-2";
import DistroManager from "./lib/distro.js";

// Initialize DistroManager after Buffer polyfill is available
DistroManager.init();

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

    // RFed node public key — learned via announce. Used for DestinationType::Single
    // encryption when sending to rfed.node destinations per the spec.
    rfedNodePubKey: "",

    interfaceName: "Retichat Web",
    displayName: "Retichat Web",
    announceIntervalMs: 300000,
};
// RFed-over-PostInterface can require multiple one-second exchange cycles.
// Explicit implementation exception approved 2026-07-25.
const RFED_OPERATION_LIMIT_MS = 10_000;
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
    const savedInterfaceName = sGet("interfaceName");
    if (savedInterfaceName) cfg.interfaceName = savedInterfaceName;
    cfg.rfedNodeHash = sGet("rfedNodeHash") || DEFAULT_CONFIG.rfedNodeHash;
    cfg.lxmfPropagationOverride = sGet("lxmfPropagationOverride") || "";
    cfg.propagationNodePubKey = sGet("propagationNodePubKey") || "";
    cfg.rfedNodePubKey = sGet("rfedNodePubKey") || "";
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

function ownLxmfDestinationHash() {
    return IdMgr.has ? Destination.hash(IdMgr.id, "lxmf", "delivery").toString("hex") : null;
}

function shouldProcessGroupMessage(groupAction, inviterKnown, groupExists) {
    return groupAction === "invite" ? inviterKnown : groupExists;
}

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
    add(destHash, isDistro = false, publicKey = null) {
        destHash = destHash.toLowerCase().replace(/[^0-9a-f]/g, "");
        if (destHash.length !== 32) throw new Error("Destination hash must be exactly 32 hex characters");
        const existing = this._contacts.get(destHash);
        const contact = {
            destHash,
            displayName: existing?.displayName ?? ("?" + destHash.slice(0,8)),
            publicKey: existing?.publicKey ?? publicKey,
            nameCustomized: existing?.nameCustomized ?? false,
            addedAt: existing?.addedAt ?? Date.now(),
            lastSeen: existing?.lastSeen ?? 0,
            reachable: existing?.reachable ?? null,
            isDistro: existing?.isDistro ?? isDistro,
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

    /** Seconds to wait before propagating: 0 for distro, 5 for online/unknown, 1 for offline. */
    propagationDelay(destHash) {
        const c = this._contacts.get(destHash);
        if (c?.isDistro) return 0; // distro always goes via propagation immediately
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
//  HARNESS — in-memory observation surface for headless E2E drivers.
//  Never used by the UI; exists so tests never scrape the DOM or localStorage.
// =========================================================================
const Harness = {
    inbox: [],
    events: [],
    errors: [],
    _readyResolve: null,
    ready: null,

    recordInbound(peerHash, msg) {
        this.inbox.push({
            peerHash,
            srcHash: msg.srcHash ?? peerHash,
            content: msg.content ?? "",
            via: msg.via ?? "direct",
            timestamp: msg.timestamp,
            id: msg.id,
        });
        if (this.inbox.length > 500) this.inbox.splice(0, this.inbox.length - 500);
        this.event("rx", { via: msg.via ?? "direct", src: (msg.srcHash ?? peerHash).slice(0, 12), content: (msg.content ?? "").slice(0, 80) });
    },

    event(kind, detail) {
        this.events.push({ t: Date.now(), kind, detail });
        if (this.events.length > 2000) this.events.splice(0, this.events.length - 2000);
    },

    error(where, e) {
        this.errors.push({ t: Date.now(), where, message: e?.message ?? String(e) });
        this.event("error", { where, message: e?.message ?? String(e) });
    },

    /** Resolves once the RNS interface is registered and LXMF is listening. */
    markReady() { if (this._readyResolve) { this._readyResolve(); this._readyResolve = null; } },

    /** True once a message matching `marker` has arrived, optionally via a path. */
    received(marker, via) {
        return this.inbox.some(m => m.content.includes(marker) && (!via || m.via === via));
    },
};
Harness.ready = new Promise(resolve => { Harness._readyResolve = resolve; });
window.Harness = Harness;

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
        const stored = msgs[msgs.length-1];
        // In-memory mirror so headless harnesses can assert without reparsing localStorage.
        if (stored.dir === "in") Harness.recordInbound(hash, stored);
        return stored;
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
//  GROUP STORE — group chat state matching iOS GroupChatManager + ChatRepository
// =========================================================================
const GroupStore = {
    _groups: new Map(),  // groupId → { groupId, groupName, groupStatus, members: Map<memberHash, status>, lastActivity }
    _listeners: [],

    init() {
        const data = sGet("groups_v1");
        if (Array.isArray(data)) {
            for (const g of data) {
                const members = new Map();
                if (Array.isArray(g.members)) {
                    for (const m of g.members) members.set(m.hash, m.status);
                }
                this._groups.set(g.groupId, {
                    groupId: g.groupId,
                    groupName: g.groupName || "Group",
                    groupStatus: g.groupStatus || "active",
                    members,
                    lastActivity: g.lastActivity || 0,
                });
            }
        }
    },

    onChange(fn) { this._listeners.push(fn); fn(this.getAll()); },
    _notify() { const all = this.getAll(); this._listeners.forEach(fn => fn(all)); },

    /** Create a new group. Returns the group object. */
    create(groupName, memberHashes) {
        const groupId = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
        const ownHash = ownLxmfDestinationHash();
        const members = new Map();
        members.set(ownHash, "accepted");
        for (const h of memberHashes) {
            if (h !== ownHash) members.set(h, "invited");
        }
        const group = { groupId, groupName, groupStatus: "active", members, lastActivity: Date.now() };
        this._groups.set(groupId, group);
        this._save();
        this._notify();
        return group;
    },

    /** Handle an incoming group invite: create a pending group entry. */
    addPending(groupId, groupName, senderHash, memberHashes) {
        const existing = this._groups.get(groupId);
        if (existing) {
            // Duplicate pending invite: merge membership and preserve any
            // accepts already observed.
            const ms = existing.members;
            for (const h of memberHashes) {
                if (!ms.has(h)) ms.set(h, "invited");
            }
            ms.set(senderHash, "accepted");
            existing.lastActivity = Date.now();
            this._save();
            this._notify();
            return existing;
        }
        const members = new Map();
        for (const h of memberHashes) {
            members.set(h, "invited");
        }
        members.set(senderHash, "accepted");
        members.set(ownLxmfDestinationHash(), "invited");
        const group = { groupId, groupName, groupStatus: "pending", members, lastActivity: Date.now() };
        this._groups.set(groupId, group);
        this._save();
        this._notify();
        return group;
    },

    /** Accept a pending group invite. */
    accept(groupId) {
        const g = this._groups.get(groupId);
        if (!g) return;
        g.groupStatus = "active";
        g.members.set(ownLxmfDestinationHash(), "accepted");
        g.lastActivity = Date.now();
        this._save();
        this._notify();
    },

    /** Update a member's status. */
    updateMember(groupId, memberHash, status) {
        const g = this._groups.get(groupId);
        if (!g) return;
        g.members.set(memberHash, status);
        g.lastActivity = Date.now();
        this._save();
        this._notify();
    },

    /** Remove a group entirely (leave or decline). */
    remove(groupId) {
        this._groups.delete(groupId);
        this._save();
        this._notify();
    },

    get(groupId) { return this._groups.get(groupId) ?? null; },
    getAll() {
        return [...this._groups.values()]
            .sort((a, b) => b.lastActivity - a.lastActivity);
    },
    isGroupChat(id) { return this._groups.has(id); },
    isActiveGroup(id) {
        const g = this._groups.get(id);
        return g && g.groupStatus === "active";
    },

    migrateOwnMemberHash() {
        const legacyHash = IdMgr.hash;
        const deliveryHash = ownLxmfDestinationHash();
        if (!legacyHash || !deliveryHash || legacyHash === deliveryHash) return;
        let changed = false;
        for (const group of this._groups.values()) {
            if (!group.members.has(legacyHash)) continue;
            const status = group.members.get(legacyHash);
            group.members.delete(legacyHash);
            if (!group.members.has(deliveryHash)) group.members.set(deliveryHash, status);
            changed = true;
        }
        if (changed) this._save();
    },

    _save() {
        const arr = [];
        for (const g of this._groups.values()) {
            arr.push({
                groupId: g.groupId,
                groupName: g.groupName,
                groupStatus: g.groupStatus,
                members: [...g.members.entries()].map(([hash, status]) => ({ hash, status })),
                lastActivity: g.lastActivity,
            });
        }
        sSet("groups_v1", arr);
    },
};
GroupStore.init();

// =========================================================================
//  GROUP MESSAGE STORE — per-group messages
// =========================================================================
const GroupMsgStore = {
    get(groupId) { return sGet("gmsg_"+groupId) ?? []; },
    add(groupId, msg) {
        const msgs = this.get(groupId);
        msgs.push({ id: Date.now().toString(36)+Math.random().toString(36).slice(2,8), timestamp: Date.now(), ...msg });
        if (msgs.length > 500) msgs.splice(0, msgs.length-500);
        sSet("gmsg_"+groupId, msgs);
        return msgs[msgs.length-1];
    },
    updateStatus(groupId, msgId, newStatus) {
        const msgs = this.get(groupId);
        const m = msgs.find(x => x.id === msgId);
        if (m) { m.status = newStatus; sSet("gmsg_"+groupId, msgs); }
        return m;
    },
    addSystem(groupId, text) {
        return this.add(groupId, { dir: "system", content: text, status: "delivered" });
    },
    remove(groupId) {
        sSet("gmsg_"+groupId, []);
    },
    preview(groupId) {
        const msgs = this.get(groupId);
        if (!msgs.length) return null;
        const last = msgs[msgs.length-1];
        if (last.dir === "system") return last.content?.slice(0,60) ?? "";
        return (last.dir === "out" ? "You: " : "") + (last.content?.slice(0,60) ?? "");
    },
};

// =========================================================================
//  CHANNEL STORE — RFed channel subscriptions matching iOS ChannelEntity
// =========================================================================
const ChannelStore = {
    _channels: new Map(),  // channelName → { channelName, channelHash, rfedNodeHash, isSubscribed, stampCost, lastActivity }
    _listeners: [],

    init() {
        const data = sGet("channels_v1");
        if (Array.isArray(data)) {
            for (const ch of data) {
                this._channels.set(ch.channelName, {
                    channelName: ch.channelName,
                    channelHash: ch.channelHash || "",
                    rfedNodeHash: ch.rfedNodeHash || "",
                    isSubscribed: ch.isSubscribed ?? true,
                    stampCost: ch.stampCost ?? null,
                    lastActivity: ch.lastActivity || 0,
                });
            }
        }
    },

    onChange(fn) { this._listeners.push(fn); fn(this.getAll()); },
    _notify() { const all = this.getAll(); this._listeners.forEach(fn => fn(all)); },

    /** Join a channel — persist subscription.
     *  Channel hash = channel identity hash (SHA-256 of pub bundle)[0:16],
     *  which is the 16-byte prefix in the wire payload. Per SPEC.md §1. */
    join(channelName, rfedNodeHash) {
        // Channel hash = channelIdentity(name).hash — the identity hash,
        // which is what appears as the 16-byte routing prefix on the wire.
        const { hash: chIdHash } = channelIdentity(channelName);
        const channelHash = chIdHash.toString("hex");

        const ch = {
            channelName,
            channelHash,
            rfedNodeHash,
            isSubscribed: true,
            stampCost: null,
            lastActivity: Date.now(),
        };
        this._channels.set(channelName, ch);
        this._save();
        this._notify();
        return ch;
    },

    /** Leave a channel. */
    leave(channelName) {
        this._channels.delete(channelName);
        this._save();
        this._notify();
    },

    /** Update stamp cost from server. */
    setStampCost(channelName, cost) {
        const ch = this._channels.get(channelName);
        if (ch) { ch.stampCost = cost; this._save(); }
    },

    /** Touch last activity time. */
    touch(channelName) {
        const ch = this._channels.get(channelName);
        if (ch) { ch.lastActivity = Date.now(); this._save(); }
    },

    get(channelName) { return this._channels.get(channelName) ?? null; },
    getByHash(hash) {
        for (const ch of this._channels.values()) {
            if (ch.channelHash === hash) return ch;
        }
        return null;
    },
    getAll() {
        return [...this._channels.values()]
            .sort((a, b) => b.lastActivity - a.lastActivity);
    },

    _save() {
        const arr = [];
        for (const ch of this._channels.values()) {
            arr.push({ ...ch });
        }
        sSet("channels_v1", arr);
    },
};
ChannelStore.init();

// =========================================================================
//  CHANNEL MESSAGE STORE — per-channel messages
// =========================================================================
const ChannelMsgStore = {
    get(channelName) { return sGet("cmsg_"+channelName) ?? []; },
    add(channelName, msg) {
        const msgs = this.get(channelName);
        msgs.push({ id: Date.now().toString(36)+Math.random().toString(36).slice(2,8), timestamp: Date.now(), ...msg });
        if (msgs.length > 500) msgs.splice(0, msgs.length-500);
        sSet("cmsg_"+channelName, msgs);
        return msgs[msgs.length-1];
    },
    updateStatus(channelName, msgId, newStatus) {
        const msgs = this.get(channelName);
        const m = msgs.find(x => x.id === msgId);
        if (m) { m.status = newStatus; sSet("cmsg_"+channelName, msgs); }
        return m;
    },
    remove(channelName) {
        sSet("cmsg_"+channelName, []);
    },
    preview(channelName) {
        const msgs = this.get(channelName);
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
    _rfedLinks: new Map(),
    _rfedLinkPromises: new Map(),
    _rfedServiceReady: new Set(),
    _rfedServiceWaiters: new Map(),
    _rfedServicePathsRequested: false,
    _propagationPathRequested: false,
    _propagationInitialized: false,
    _propRetryTimer: null,
    _rfedOpenedChannelHashes: new Set(),
    _rfedPullState: new Map(),
    _rfedStampRefreshed: new Set(),
    _rfedSubscriptionPromises: new Map(),
    _rfedStreamPromises: new Map(),
    _rfedPendingEchoes: new Map(),
    _rfedSendChain: Promise.resolve(),
    _groupLinks: new Map(),
    _groupLinkPromises: new Map(),
    _groupPeerReady: new Set(),
    _groupPeerWaiters: new Map(),
    _groupPathsRequested: new Set(),
    _groupFallbacks: new GroupFallbackRegistry(),
    _propLinkPromise: null,
    _channelsInitialized: false,
    _channelsResubscribed: false,
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
        Harness.event("status", { status: s, connType: this._connType });
        if (s === "online") Harness.markReady();
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
        iface.on("registered", () => this._onExchangeRegistered());
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

            // ---- Distro identity transfer detection ----
            // Check for FIELD_DISTRO_ID (0x0D) BEFORE the ticket check.
            const FIELD_DISTRO_ID = 0x0D;
            const distroEncryptedHex = lxmfMsg.fields?.get(FIELD_DISTRO_ID);
            if (distroEncryptedHex) {
                this._handleDistroIdentityTransfer(lxmfMsg, srcHash, distroEncryptedHex);
                return;
            }

            // ---- Group message detection ----
            // Check for group fields BEFORE the ticket/epty-content check,
            // since group protocol messages carry content.
            const groupInfo = LXMessage.extractGroupFields(lxmfMsg.fields);
            if (groupInfo && groupInfo.groupId) {
                this._handleGroupMessage(lxmfMsg, srcHash, content, groupInfo);
                return;
            }

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

            MsgStore.add(srcHash, { dir: "in", content, status: "delivered", srcHash, via: "direct" });
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
                    // Defer link establishment — follow same pattern as channel init
                    this._initPropagation();
                }
            }
        });

        // Listen for announces on lxmf.delivery to enrich contacts
        this._rns.registerAnnounceHandler("lxmf.delivery", (event) => {
            const hash = event.announce.destinationHash.toString("hex");
            ContactStore.updateFromAnnounce(hash, event.announce);
            this._markGroupPeerReady(hash);
        });

        this._rns.registerAnnounceHandler("rfed.node", (event) => {
            this._catchRfedNodeAnnounce(event);
        });
        // Announce handlers that mark an rfed.* service "ready" when its
        // destination announces.  This MUST include distro.register (and the
        // other distro aspects): _registerDistro() -> _rfedRequest() ->
        // _ensureRfedLink(["distro","register"]) -> _waitForRfedService()
        // blocks until _rfedServiceReady contains "distro.register".  Without
        // the handler below, distro.register never became ready, so the
        // register request was never sent — the distro device never reached
        // the RFed.  (Bug found 2026-08-08: only channel* were subscribed.)
        for (const aspects of [
            ["channel"], ["channel", "stream"], ["channel", "pull"],
            ["distro", "register"], ["distro", "unregister"], ["distro", "list"],
        ]) {
            this._rns.registerAnnounceHandler(`rfed.${aspects.join(".")}`, (event) => {
                this._markRfedServiceReady(aspects, event);
            });
        }

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
            // Re-announce rfed.delivery alongside lxmf.delivery so the RFed's
            // path back to us stays fresh (the distro fanout + deferred flush
            // depend on it).  See _initChannels().
            if (this._rfedDeliveryDest) {
                try { this._rfedDeliveryDest.announce(); } catch(_) {}
            }
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
        if (this._propLinkPromise) return;

        const propIdentity = Identity.fromPublicKey(
            Buffer.from(this._cfg.propagationNodePubKey, "hex")
        );
        const propDest = this._rns.registerDestination(
            propIdentity,
            Destination.OUT,
            Destination.SINGLE,
            "lxmf",
            "propagation"
        );

        const link = new Link();
        this._propLink = link;
        this._propLinkPromise = new Promise((resolve, reject) => {
            this._propLinkResolve = resolve;
            this._propLinkReject = reject;
        });

        link.on("established", () => {
            console.log(`[retichat] 🔗 Propagation link established, rtt=${link.rtt}ms`);
            this._propLinkResolve?.(link);
            this._propLinkPromise = null;
            this._propLinkResolve = null;
            this._propLinkReject = null;
            // Flush any messages that missed the propagation window while
            // the link was still being established.
            this._flushPropagation();
            // Identify ourselves so the PN can authorize /get requests.
            // Small delay to let the link settle before sending.
            setTimeout(() => { link.identify(IdMgr.id); }, 1_000);
            // Pull any stored messages for us — after identify has propagated
            setTimeout(() => { this._fetchPropagatedMessages(); }, 5_000);
            // Also pull distro messages if we have a distro identity
            if (DistroManager.has) {
                setTimeout(() => { RnsClient._pullDistroMessages(); }, 7_000);
            }
        });

        link.on("close", () => {
            console.log("[retichat] Propagation link closed");
            this._propLinkReject?.(new Error("Propagation link closed before establishment"));
            this._propLinkPromise = null;
            this._propLinkResolve = null;
            this._propLinkReject = null;
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

        // Send directly to the destination (skip for distro — always use propagation)
        let directProofReceived = false;
        if (!contact.isDistro) {
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
        }

        // After propagation delay, if no direct proof, also send to propagation node
        const delaySec = ContactStore.propagationDelay(contact.destHash);
        setTimeout(async () => {
            if (directProofReceived) return;
            // Wait for the link instead of sampling its status. A distro send
            // always propagates, so it can reach this point while the link is
            // still being established (observed: B started its link 6s before
            // the send and was still handshaking), and dropping here loses the
            // message outright. _ensurePropagationLink() resolves on the
            // in-flight attempt rather than starting a competing one.
            let link;
            try {
                link = await this._ensurePropagationLink();
            } catch (e) {
                console.log(`[retichat] ⚠️ Propagation link unavailable, cannot propagate: ${e.message}`);
                return;
            }
            const reason = contact.isDistro ? "distro address" : `direct proof not received in ${delaySec}s`;
            console.log(`[retichat] 📡 Propagating via link to ${this._cfg.propagationNodeHash.slice(0,12)}... (${reason})`);

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

    // =========================================================================
    //  GROUP PROTOCOL — handle incoming group messages + send group operations
    // =========================================================================

    /** Handle incoming distro identity transfer (FIELD_DISTRO_ID). */
    _handleDistroIdentityTransfer(lxmfMsg, srcHash, privateKeyHex) {
        console.log(`[distro] 📥 Received distro identity transfer from ${srcHash.slice(0,12)}...`);
        try {
            if (!privateKeyHex || privateKeyHex.length !== 128) {
                console.warn(`[distro] Private key has wrong length: ${privateKeyHex?.length ?? 0}`);
                return;
            }
            const senderName = LXMF.senderNameFromFields(lxmfMsg.fields) || srcHash.slice(0,8);

            // Show custom modal instead of confirm() (which gets suppressed in background tabs)
            this._showDistroImportPrompt(senderName, privateKeyHex);
        } catch(e) {
            console.error(`[distro] Failed to import identity:`, e);
            this._showDistroImportError(e.message);
        }
    },

    /** Show a custom modal prompting the user to import a distro identity. */
    _showDistroImportPrompt(senderName, privateKeyHex) {
        const overlay = h("div", { className: "modal-overlay", style: { zIndex: 10000 } });
        const sheet = h("div", { className: "modal-sheet" });

        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "📥 Import Distro Identity"),
            ),
        );

        const body = h("div", { className: "modal-body" });
        body.appendChild(
            h("div", { className: "settings-section" },
                h("p", { style: { fontSize: "15px", lineHeight: "1.5" } },
                    `${senderName} sent you a distro identity.`),
                h("p", { style: { fontSize: "14px", color: "var(--text-muted)", lineHeight: "1.5" } },
                    "Importing it will allow this device to receive all messages sent to that identity."),
            ),
        );

        const doImport = () => {
            try {
                const hash = DistroManager.importHex(privateKeyHex);
                console.log(`[distro] ✅ Imported identity: ${hash}`);
                RnsClient._registerDistro();
                document.body.removeChild(overlay);
                this._showDistroImportSuccess(hash);
                this._onMsg.forEach(fn => fn(null, null));
            } catch(e) {
                document.body.removeChild(overlay);
                this._showDistroImportError(e.message);
            }
        };

        const doDecline = () => {
            console.log(`[distro] User declined import`);
            document.body.removeChild(overlay);
        };

        body.appendChild(
            h("div", { className: "btn-row", style: { marginTop: "20px" } },
                h("button", { className: "btn btn-primary", onClick: doImport }, "Import"),
                h("button", { className: "btn btn-secondary", onClick: doDecline }, "Decline"),
            ),
        );

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        document.body.appendChild(overlay);
    },

    _showDistroImportSuccess(hash) {
        const overlay = h("div", { className: "modal-overlay", style: { zIndex: 10000 },
            onClick: (e) => { if (e.target === overlay) document.body.removeChild(overlay); },
        });
        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "✅ Distro Identity Imported"),
            ),
        );
        const body = h("div", { className: "modal-body" });
        body.appendChild(
            h("div", { className: "settings-section" },
                h("div", { className: "mono-value", style: { fontSize: "13px" } }, hash),
                h("p", { style: { fontSize: "14px", color: "var(--text-muted)", marginTop: "12px" } },
                    "You can now receive distro messages on this device."),
            ),
        );
        body.appendChild(
            h("div", { className: "btn-row", style: { marginTop: "20px" } },
                h("button", { className: "btn btn-primary",
                    onClick: () => document.body.removeChild(overlay) }, "OK"),
            ),
        );
        sheet.appendChild(body);
        overlay.appendChild(sheet);
        document.body.appendChild(overlay);
    },

    _showDistroImportError(msg) {
        const overlay = h("div", { className: "modal-overlay", style: { zIndex: 10000 },
            onClick: (e) => { if (e.target === overlay) document.body.removeChild(overlay); },
        });
        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "❌ Import Failed"),
            ),
        );
        const body = h("div", { className: "modal-body" });
        body.appendChild(
            h("p", { style: { fontSize: "14px" } }, msg),
        );
        body.appendChild(
            h("div", { className: "btn-row", style: { marginTop: "20px" } },
                h("button", { className: "btn btn-primary",
                    onClick: () => document.body.removeChild(overlay) }, "OK"),
            ),
        );
        sheet.appendChild(body);
        overlay.appendChild(sheet);
        document.body.appendChild(overlay);
    },

    /** Handle an incoming group message (detected by GROUP_FIELDS.GROUP_ID). */
    _handleGroupMessage(lxmfMsg, srcHash, content, groupInfo) {
        const { groupId, groupName, groupAction, groupSender, members, relaySeen, memberKeys } = groupInfo;
        console.log(`[retichat] 👥 Group message: groupId=${groupId.slice(0,8)} action=${groupAction || "message"} from=${srcHash.slice(0,12)}`);

        const group = GroupStore.get(groupId);
        const actualSender = groupSender || srcHash;
        if (!shouldProcessGroupMessage(groupAction, ContactStore.isContact(srcHash), !!group)) {
            console.log(`[retichat] 👥 Dropped ${groupAction || "message"} for unknown group ${groupId.slice(0,8)}`);
            return;
        }
        if (!this._groupSeenIds) this._groupSeenIds = new Set();
        const dedupKey = lxmfMsg.hash?.toString("hex") ||
            `${groupId}:${actualSender}:${lxmfMsg.timestamp}:${groupAction || "message"}`;
        if (this._groupSeenIds.has(dedupKey)) {
            console.log(`[retichat] 👥 Group dedup ${dedupKey.slice(0,32)}...`);
            return;
        }
        this._groupSeenIds.add(dedupKey);
        if (this._groupSeenIds.size > 2000) {
            this._groupSeenIds = new Set([...this._groupSeenIds].slice(-1000));
        }

        switch (groupAction) {
            case "invite": {
                this._rememberGroupMemberKeys(memberKeys);
                // If we already have this group active, ignore
                if (group && group.groupStatus === "active") return;
                // Create pending group entry
                const senderName = LXMF.senderNameFromFields(lxmfMsg.fields) || srcHash.slice(0,8);
                GroupStore.addPending(groupId, groupName || "Group", srcHash, members || []);
                if (!group) GroupMsgStore.addSystem(groupId, `${senderName} invited you to "${groupName || "Group"}"`);
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));  // trigger UI refresh with groupId
                break;
            }
            case "accept": {
                if (!group) return;
                GroupStore.updateMember(groupId, actualSender, "accepted");
                const senderName = ContactStore.get(actualSender)?.displayName || actualSender.slice(0,8);
                GroupMsgStore.addSystem(groupId, `${senderName} joined the group`);
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));
                break;
            }
            case "leave": {
                if (!group) return;
                GroupStore.updateMember(groupId, actualSender, "left");
                const senderName = ContactStore.get(actualSender)?.displayName || actualSender.slice(0,8);
                GroupMsgStore.addSystem(groupId, `${senderName} left the group`);
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));
                break;
            }
            case "relay_req": {
                if (!group) return;
                this._performGroupRelay(
                    group,
                    content,
                    actualSender,
                    relaySeen || [],
                    srcHash
                );
                break;
            }
            case "relay_done": {
                console.log(`[retichat] 👥 Relay completed by ${srcHash.slice(0,8)} for ${groupId.slice(0,8)}`);
                break;
            }
            default: {
                // Regular group chat message
                if (!group) {
                    console.log(`[retichat] 👥 Group message for unknown group ${groupId.slice(0,8)}, ignoring`);
                    return;
                }

                const senderName = ContactStore.get(actualSender)?.displayName || actualSender.slice(0,12);
                const displayContent = content || "(empty)";
                GroupMsgStore.add(groupId, { dir: "in", content: displayContent, status: "delivered", srcHash: actualSender, senderName });
                // Update group last activity
                group.lastActivity = Date.now();
                GroupStore._save();
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));
                break;
            }
        }
    },

    /** Send a group chat message (fanout to all accepted members). */
    async sendGroupMessage(groupId, content) {
        const group = GroupStore.get(groupId);
        if (!group) throw new Error("Group not found");
        const ownHash = this.ownHash;

        // Add outgoing message to group store
        const outMsg = GroupMsgStore.add(groupId, { dir: "out", content, status: "sending", srcHash: ownHash });
        group.lastActivity = Date.now();
        GroupStore._save();

        const targets = [...group.members.entries()]
            .filter(([hash, status]) => hash !== ownHash && status === "accepted")
            .map(([hash]) => hash);
        const delivery = await this._fanoutGroupEnvelope(targets, content, {
            groupId,
            groupName: group.groupName,
            groupSender: ownHash,
        });

        if (delivery.fulfilled === delivery.total) {
            GroupMsgStore.updateStatus(groupId, outMsg.id, "sent");
        } else {
            GroupMsgStore.updateStatus(groupId, outMsg.id, "failed");
        }
        group.lastActivity = Date.now();
        GroupStore._save();
        this._onMsg.forEach(fn => fn(null, groupId));
        return outMsg;
    },

    /** Send group invites to all selected members. */
    async sendGroupInvites(groupId, groupName, memberHashes) {
        const ownHash = this.ownHash;
        const allMembers = [...new Set([...memberHashes, ownHash])];
        const membersStr = allMembers.join(",");
        const targets = allMembers.filter(hash => hash !== ownHash);
        const memberKeyEntries = this._groupMemberKeys(allMembers);
        await Promise.all(memberKeyEntries.map(groupMemberKey =>
            this._fanoutGroupEnvelope(targets, "", {
                groupId,
                groupName,
                groupMembers: membersStr,
                groupMemberKey,
                groupAction: "invite",
                groupSender: ownHash,
                suppressSenderName: true,
            })
        ));
    },

    /** Send accept to all group members. */
    async sendGroupAccept(groupId) {
        const group = GroupStore.get(groupId);
        if (!group) return;
        const ownHash = this.ownHash;

        const targets = [...group.members.keys()].filter(hash => hash !== ownHash);
        await this._fanoutGroupEnvelope(targets, "", {
            groupId,
            groupAction: "accept",
            groupSender: ownHash,
        });
    },

    /** Send leave to all accepted members. */
    async sendGroupLeave(groupId) {
        const group = GroupStore.get(groupId);
        if (!group) return;
        const ownHash = this.ownHash;

        const targets = [...group.members.entries()]
            .filter(([hash, status]) => hash !== ownHash && status === "accepted")
            .map(([hash]) => hash);
        await this._fanoutGroupEnvelope(targets, "", {
            groupId,
            groupAction: "leave",
            groupSender: ownHash,
        });
    },

    async sendGroupRelayRequest(groupId, content, originalSender, alreadySeen, relayerHash) {
        return this._sendGroupEnvelope(relayerHash, content, {
            groupId,
            groupAction: "relay_req",
            groupSender: originalSender,
            groupRelayFor: originalSender,
            groupRelaySeen: [...new Set(alreadySeen)].join(","),
        });
    },

    async _performGroupRelay(group, content, originalSender, alreadySeen, requester) {
        const ownHash = this.ownHash;
        const seen = new Set([...alreadySeen, requester, ownHash, originalSender]);
        const targets = [...group.members.entries()]
            .filter(([hash, status]) => status === "accepted" && !seen.has(hash))
            .map(([hash]) => hash);
        targets.forEach(hash => seen.add(hash));
        await this._fanoutGroupEnvelope(targets, content, {
            groupId: group.groupId,
            groupName: group.groupName,
            groupSender: originalSender,
            groupRelayFor: originalSender,
            groupRelaySeen: [...seen].join(","),
        });
        await this._sendGroupEnvelope(requester, "", {
            groupId: group.groupId,
            groupAction: "relay_done",
            groupSender: ownHash,
            groupRelayDone: true,
        });
    },

    async _fanoutGroupEnvelope(targets, content, fields) {
        const results = await Promise.allSettled(
            targets.map(target => this._sendGroupEnvelope(target, content, fields))
        );
        results.forEach((result, index) => {
            if (result.status === "rejected") {
                console.warn(`[retichat] 👥 Group send to ${targets[index].slice(0,8)} failed:`, result.reason?.message || result.reason);
            }
        });
        const fulfilled = results.filter(result => result.status === "fulfilled").length;
        return {
            fulfilled,
            total: targets.length,
            methods: results
                .filter(result => result.status === "fulfilled")
                .map(result => result.value.method),
        };
    },

    async _sendGroupEnvelope(memberHash, content, fields) {
        let contact = ContactStore.get(memberHash);
        if (!contact) contact = ContactStore.add(memberHash);
        if (!contact.publicKey) {
            this._requestGroupPeer(memberHash);
            await this._waitForGroupPeer(memberHash);
            contact = ContactStore.get(memberHash);
            if (!contact?.publicKey) {
                throw new Error(`No public key for group member ${memberHash.slice(0,8)}`);
            }
        }
        const identity = Identity.fromPublicKey(Buffer.from(contact.publicKey, "hex"));
        const dest = this._rns.registerDestination(
            identity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery"
        );

        const msg = new LXMessage();
        msg.sourceHash = this._lxmfRouter.destination.hash;
        msg.destinationHash = dest.hash;
        msg.title = "";
        msg.content = content;
        msg.fields = new Map();
        if (!fields.suppressSenderName) msg.fields.set(0x10, this._cfg.displayName || "Retichat Web");
        msg.fields.set(GROUP_FIELDS.GROUP_ID, fields.groupId);
        if (fields.groupMembers) msg.fields.set(GROUP_FIELDS.GROUP_MEMBERS, fields.groupMembers);
        if (fields.groupName) msg.fields.set(GROUP_FIELDS.GROUP_NAME, fields.groupName);
        if (fields.groupAction) msg.fields.set(GROUP_FIELDS.GROUP_ACTION, fields.groupAction);
        if (fields.groupSender) msg.fields.set(GROUP_FIELDS.GROUP_SENDER, fields.groupSender);
        if (fields.groupRelaySeen) msg.fields.set(GROUP_FIELDS.GROUP_RELAY_SEEN, fields.groupRelaySeen);
        if (fields.groupRelayFor) msg.fields.set(GROUP_FIELDS.GROUP_RELAY_FOR, fields.groupRelayFor);
        if (fields.groupRelayDone != null) msg.fields.set(GROUP_FIELDS.GROUP_RELAY_DONE, fields.groupRelayDone);
        if (fields.groupMemberKey) msg.fields.set(GROUP_FIELDS.GROUP_MEMBER_KEYS, fields.groupMemberKey);
        const packed = msg.pack(IdMgr.id, true);
        return this._deliverGroupEnvelope(
            memberHash,
            Buffer.concat([dest.hash, packed]),
            contact.publicKey
        );
    },

    _deliverGroupEnvelope(memberHash, fullLxmfBytes, publicKeyHex) {
        const deliveryKey = `${memberHash}:${crypto.randomUUID()}`;
        const evidence = new GroupDeliveryEvidence(memberHash);
        {
            let directProofKey = null;
            let propagationProofKey = null;
            const fulfill = method => {
                if (!evidence.fulfill(method)) return;
                this._groupFallbacks.prove(deliveryKey);
                if (directProofKey) this._pendingPacketHashes.delete(directProofKey);
                if (propagationProofKey) this._pendingPacketHashes.delete(propagationProofKey);
                console.log(`[retichat] 👥 Group delivery fulfilled for ${memberHash.slice(0,8)} via ${method}`);
            };

            this._groupFallbacks.schedule(deliveryKey, 5_000, async () => {
                try {
                    const propagationPacket = await this._sendGroupPropagationFallback(
                        fullLxmfBytes,
                        publicKeyHex,
                        memberHash,
                    );
                    if (evidence.settled) return;
                    propagationProofKey = propagationPacket.packetHash.slice(0, 16).toString("hex");
                    this._pendingPacketHashes.set(propagationProofKey, {
                        contactHash: memberHash,
                        messageId: propagationProofKey,
                        onProof: () => fulfill("propagation"),
                    });
                } catch (error) {
                    console.warn(`[retichat] 👥 Group propagation fallback failed for ${memberHash.slice(0,8)}:`, error.message);
                }
            }); // AppLinks Timer P parity — see DESIGN_PRINCIPLES.md §1
            this._ensureGroupLink(memberHash, publicKeyHex).then(({link, destination}) => {
                if (evidence.settled) return;
                if (fullLxmfBytes.length > Link.MDU) {
                    // Too large for one link packet, so it goes as a resource.
                    // The resource's own proof is the delivery evidence; there
                    // is no single packet hash to wait on.
                    link.sendResource(fullLxmfBytes)
                        .then(() => fulfill("direct"))
                        .catch(error => console.warn(`[retichat] 👥 Direct group resource failed for ${memberHash.slice(0,8)}:`, error.message));
                    return;
                }
                const packet = link.send(fullLxmfBytes);
                directProofKey = packet.packetHash.slice(0, 16).toString("hex");
                this._pendingPacketHashes.set(directProofKey, {
                    contactHash: memberHash,
                    messageId: directProofKey,
                    onProof: () => fulfill("direct"),
                });
            }).catch(error => {
                console.warn(`[retichat] 👥 Direct group delivery unavailable for ${memberHash.slice(0,8)}:`, error.message);
            });
        }
        return evidence.promise;
    },

    _groupMemberKeys(memberHashes) {
        return [...memberHashes].sort().map(hash => {
            const publicKey = hash === this.ownHash ? IdMgr.pubKey : ContactStore.get(hash)?.publicKey;
            if (!publicKey || !/^[0-9a-f]{128}$/i.test(publicKey)) {
                throw new Error(`Missing public key for group member ${hash.slice(0,8)}`);
            }
            return `${hash}:${Buffer.from(publicKey, "hex").toString("base64")}`;
        });
    },

    _rememberGroupMemberKeys(memberKeys) {
        for (const [hash, encodedPublicKey] of memberKeys || []) {
            try {
            const publicKey = Buffer.from(encodedPublicKey, "base64");
            if (publicKey.length !== 64) continue;
            const identity = Identity.fromPublicKey(publicKey);
                const derived = Destination.hash(identity, "lxmf", "delivery").toString("hex");
                if (derived !== hash) {
                    console.warn(`[retichat] 👥 Ignored mismatched member key for ${hash.slice(0,8)}`);
                    continue;
                }
                const contact = ContactStore.get(hash) || ContactStore.add(hash);
                contact.publicKey = publicKey.toString("hex");
            } catch (error) {
                console.warn(`[retichat] 👥 Ignored invalid member key for ${hash.slice(0,8)}:`, error.message);
            }
        }
        ContactStore._save();
    },

    async _sendGroupPropagationFallback(fullLxmfBytes, publicKeyHex, memberHash) {
        const link = await this._ensurePropagationLink();
        const propagationPacked = await this._buildPropagationPacked(fullLxmfBytes, publicKeyHex);
        const packet = link.send(propagationPacked);
        console.log(`[retichat] 👥 Group propagation fallback dispatched for ${memberHash.slice(0,8)} packet=${packet.packetHash.slice(0,6).toString("hex")}`);
        return packet;
    },

    _ensurePropagationLink() {
        if (this._propLink?.status === Link.ACTIVE) return Promise.resolve(this._propLink);
        if (!this._cfg.propagationNodePubKey || !this._cfg.propagationNodeHash) {
            return Promise.reject(new Error("Propagation node identity is not ready"));
        }
        this._establishPropagationLink();
        return this._propLinkPromise;
    },

    _markGroupPeerReady(memberHash) {
        const existing = this._groupLinks.get(memberHash);
        if (existing) {
            this._groupLinks.delete(memberHash);
            this._groupLinkPromises.delete(memberHash);
            try { existing.link.close(); } catch(e) {}
            console.log(`[retichat] 👥 Invalidated stale group link for ${memberHash.slice(0,12)} on fresh announce`);
        }
        this._groupPeerReady.add(memberHash);
        const waiters = this._groupPeerWaiters.get(memberHash) || [];
        this._groupPeerWaiters.delete(memberHash);
        waiters.forEach(waiter => waiter.resolve());
    },

    _waitForGroupPeer(memberHash) {
        if (this._groupPeerReady.has(memberHash)) return Promise.resolve();
        return new Promise((resolve, reject) => {
            const waiters = this._groupPeerWaiters.get(memberHash) || [];
            waiters.push({resolve, reject});
            this._groupPeerWaiters.set(memberHash, waiters);
        });
    },

    _requestGroupPeer(memberHash) {
        if (this._groupPathsRequested.has(memberHash)) return;
        this._groupPathsRequested.add(memberHash);
        this._rns.transport.requestPath(memberHash);
        console.log(`[retichat] 👥 Path request sent for group member ${memberHash.slice(0,12)}...`);
    },

    async _ensureGroupLink(memberHash, publicKeyHex) {
        const active = this._groupLinks.get(memberHash);
        if (active?.link?.status === Link.ACTIVE) return active;
        const pending = this._groupLinkPromises.get(memberHash);
        if (pending) return pending;

        const promise = (async () => {
            if (!this._groupPeerReady.has(memberHash)) {
                this._requestGroupPeer(memberHash);
                await this._waitForGroupPeer(memberHash);
            }

            const identity = Identity.fromPublicKey(Buffer.from(publicKeyHex, "hex"));
            const destination = this._rns.registerDestination(
                identity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery"
            );
            const link = new Link();
            const established = new Promise((resolve, reject) => {
                link.on("established", () => {
                    const value = {link, destination};
                    this._groupLinks.set(memberHash, value);
                    resolve(value);
                });
                link.on("close", () => {
                    this._groupLinks.delete(memberHash);
                    this._groupLinkPromises.delete(memberHash);
                    if (link.status !== Link.ACTIVE) reject(new Error("Group member link closed before establishment"));
                });
            });
            link.establish(destination);
            return established;
        })();
        this._groupLinkPromises.set(memberHash, promise);
        return promise;
    },

    async openGroupConversation(groupId) {
        const group = GroupStore.get(groupId);
        if (!group) return;
        const ownHash = this.ownHash;
        const links = [...group.members.keys()]
            .filter(hash => hash !== ownHash)
            .map(async hash => {
                let contact = ContactStore.get(hash);
                if (!contact) contact = ContactStore.add(hash);
                if (!contact.publicKey) {
                    this._requestGroupPeer(hash);
                    await this._waitForGroupPeer(hash);
                    contact = ContactStore.get(hash);
                }
                return contact?.publicKey ? this._ensureGroupLink(hash, contact.publicKey) : null;
            });
        await Promise.allSettled(links);
    },

    // =========================================================================
    //  CHANNEL PROTOCOL — RFed channel join/leave/send/receive
    // =========================================================================

    _getRfedDest(aspects) {
        const pubKeyHex = this._cfg.rfedNodePubKey;
        if (!pubKeyHex || pubKeyHex.length !== 128) {
            throw new Error("RFed node identity is not known yet");
        }
        const identity = Identity.fromPublicKey(Buffer.from(pubKeyHex, "hex"));
        if (identity.hash.toString("hex") !== this._cfg.rfedNodeHash) {
            throw new Error("RFed node public key does not match configured identity hash");
        }
        return this._rns.registerDestination(
            identity, Destination.OUT, Destination.SINGLE,
            "rfed", ...aspects
        );
    },

    _onExchangeRegistered() {
        this._announce();
        this._requestPropagationPath();
        if (!this._cfg.rfedNodeHash) return;
        const rfedIdBytes = Buffer.from(this._cfg.rfedNodeHash, "hex");
        const nodeHash = Destination.hash({hash: rfedIdBytes}, "rfed", "node").toString("hex");
        this._rns.transport.requestPath(nodeHash);
        console.log(`[retichat] Path request sent for rfed.node ${nodeHash.slice(0,12)}...`);
        this._requestRfedServicePaths();
        // Register distro identity if we have one
        if (DistroManager.has) {
            RnsClient._registerDistro();
        }
    },

    _requestRfedServicePaths() {
        if (this._rfedServicePathsRequested) return;
        if (!this._cfg.rfedNodeHash) return;
        this._rfedServicePathsRequested = true;
        // Derive the service destination hashes from the configured IDENTITY
        // HASH alone — do NOT gate this on rfedNodePubKey.
        //
        // NEVER REMOVE. An RNS destination hash is
        // sha256(sha256("rfed.<aspect>")[:10] + identity_hash)[:16]; the public
        // key is not part of it, and a path request only needs the hash. Gating
        // these requests on rfedNodePubKey created a deadlock in the bootstrap
        // graph: the pub key is only ever learned from an inbound rfed.*
        // announce, and a path request is the only thing that makes RFed emit
        // one on demand. A browser that started up between announces therefore
        // had no way to make progress and simply sat there — observed
        // 2026-08-09 01:12, where RFed had announced at 01:11 (restart) and the
        // client, opened at 01:12:12, waited out the whole 15-minute service
        // refresh interval with every distro call unusable.
        for (const aspects of [["channel"], ["channel", "stream"], ["channel", "pull"], ["distro", "register"]]) {
            const rfedIdBytes = Buffer.from(this._cfg.rfedNodeHash, "hex");
            const hash = Destination.hash({hash: rfedIdBytes}, "rfed", ...aspects).toString("hex");
            this._rns.transport.requestPath(hash);
            console.log(`[retichat] Path request sent for rfed.${aspects.join(".")} ${hash.slice(0,12)}...`);
        }
    },

    _requestPropagationPath() {
        if (this._propagationPathRequested || !this._cfg.propagationNodeHash) return;
        this._propagationPathRequested = true;
        try {
            this._rns.transport.requestPath(this._cfg.propagationNodeHash);
            console.log(`[retichat] Path request sent for propagation node ${this._cfg.propagationNodeHash.slice(0,12)}...`);
        } catch(e) {
            console.warn("[retichat] Path request for propagation node failed:", e.message);
        }
    },

    /** Initialize the persistent propagation link with retry.
     *  The LINKREQUEST can fail if path entries haven't propagated to all
     *  intermediate exchanges yet. Retry with exponential backoff until
     *  the link is established. Same pattern as _ensureRfedLink. */
    _initPropagation() {
        if (!this._cfg.propagationNodeHash || !this._cfg.propagationNodePubKey) return;
        if (this._propagationInitialized) return;
        this._propagationInitialized = true;
        console.log(`[retichat] 📡 Propagation service ready, retrying link until established...`);
        this._retryPropagationLink(2000);
    },

    /** Retry propagation link establishment with exponential backoff.
     *  Closes any stale PENDING link before creating a new one. */
    _retryPropagationLink(delayMs) {
        // Already active — done
        if (this._propLink?.status === Link.ACTIVE) return;

        // Clear any pending retry timer
        if (this._propRetryTimer) {
            clearTimeout(this._propRetryTimer);
            this._propRetryTimer = null;
        }

        // If there's an existing pending link that's never going to
        // complete, close it so we can start fresh.
        if (this._propLink && this._propLink.status !== Link.ACTIVE) {
            try { this._propLink.close(); } catch(e) {}
            this._propLink = null;
            this._propLinkPromise = null;
            this._propLinkResolve = null;
            this._propLinkReject = null;
        }

        console.log(`[retichat] 🔄 Establishing propagation link (retry in ${(delayMs/1000).toFixed(0)}s)...`);
        this._propRetryTimer = setTimeout(() => {
            this._propRetryTimer = null;
            this._ensurePropagationLink().then(() => {
                console.log(`[retichat] 🔗 Propagation link established via retry`);
            }).catch((e) => {
                const nextDelay = Math.min(delayMs * 2, 30000);
                console.warn(`[retichat] Propagation link retry failed: ${e.message}, next in ${(nextDelay/1000).toFixed(0)}s`);
                this._retryPropagationLink(nextDelay);
            });
        }, delayMs);
    },

    _markRfedServiceReady(aspects, event) {
        const identityHash = event.announce.identity?.hash?.toString("hex") ?? "";
        if (identityHash !== this._cfg.rfedNodeHash) return;
        // Harvest the RFed public key from ANY rfed.* announce, not just
        // rfed.node.
        //
        // NEVER REMOVE. Every rfed.* destination belongs to the SAME identity,
        // so every one of these announces carries the key we need, and the
        // identityHash check above has already proven it is the node we were
        // configured to trust (the announce signature was verified by the RNS
        // layer before we got here).
        //
        // Harvesting only from rfed.node made bootstrap depend on the rarest
        // announce on the wire: RFed publishes rfed.node at
        // `announce_interval_secs` (the live node is configured to 360
        // MINUTES) while every service destination refreshes every 15 min.
        // A browser that started up therefore sat with no rfedNodePubKey and
        // failed every distro/channel call with "RFed node identity is not
        // known yet" for up to six hours. The startup path request for
        // rfed.node cannot rescue it either — nothing in the mesh holds a path
        // for a destination that has not announced, so nobody answers.
        this._catchRfedNodeAnnounce(event);
        const key = aspects.join(".");
        this._rfedServiceReady.add(key);
        const waiters = this._rfedServiceWaiters.get(key) || [];
        this._rfedServiceWaiters.delete(key);
        waiters.forEach(waiter => waiter.resolve());
        if (key === "channel") {
            this._initChannels().catch(e => console.warn("[retichat] Channel init failed:", e.message));
        }
    },

    _waitForRfedService(aspects) {
        const key = aspects.join(".");
        if (this._rfedServiceReady.has(key)) return Promise.resolve();
        return new Promise((resolve, reject) => {
            const waiters = this._rfedServiceWaiters.get(key) || [];
            waiters.push({resolve, reject});
            this._rfedServiceWaiters.set(key, waiters);
        });
    },

    _ensureRfedLink(aspects) {
        const key = aspects.join(".");
        const active = this._rfedLinks.get(key);
        if (active?.status === Link.ACTIVE) return Promise.resolve(active);
        const pending = this._rfedLinkPromises.get(key);
        if (pending) return pending;
        if (!this._rfedServiceReady.has(key)) {
            return this._waitForRfedService(aspects).then(() => this._ensureRfedLink(aspects));
        }

        const destination = this._getRfedDest(aspects);
        const link = new Link();
        const startedAt = Date.now();
        let established = false;
        const promise = new Promise((resolve, reject) => {
            link.on("established", () => {
                if (established) return;
                established = true;
                if (Date.now() - startedAt > RFED_OPERATION_LIMIT_MS) {
                    link.close();
                    reject(new Error(`RFed ${key} link established after the 10-second limit`));
                    return;
                }
                link.identify(IdMgr.id);
                this._rfedLinks.set(key, link);
                console.log(`[retichat] RFed ${key} link active`);
                resolve(link);
            });
            link.on("packet", ({data}) => {
                if (key === "channel.stream") this._handleChannelPacket(data);
            });
            // A channel message too large for one link packet arrives as a
            // resource carrying the same payload.
            link.setResourceStrategy(Link.ACCEPT_ALL);
            link.on("resource", ({data}) => {
                if (key === "channel.stream") this._handleChannelPacket(data);
            });
            link.on("close", () => {
                if (this._rfedLinks.get(key) === link) this._rfedLinks.delete(key);
                this._rfedLinkPromises.delete(key);
                if (!established) reject(new Error(`RFed ${key} link closed before establishment`));
            });
        });
        this._rfedLinkPromises.set(key, promise);
        link.establish(destination);
        return promise;
    },

    async _rfedRequest(aspects, path, packedValue) {
        const link = await this._ensureRfedLink(aspects);
        return new Promise((resolve, reject) => {
            const startedAt = Date.now();
            let requestId = null;
            const responseHandler = (response) => {
                if (!requestId || !response.requestId) return;
                if (!Buffer.from(response.requestId).equals(Buffer.from(requestId))) return;
                link.off("response", responseHandler);
                link.off("close", closeHandler);
                if (Date.now() - startedAt > RFED_OPERATION_LIMIT_MS) {
                    reject(new Error(`${path} responded after the 10-second limit`));
                    return;
                }
                resolve(response.data);
            };
            const closeHandler = () => {
                link.off("response", responseHandler);
                reject(new Error(`${path} link closed before a response`));
            };
            link.on("response", responseHandler);
            link.on("close", closeHandler);
            try {
                requestId = link.sendRequestPacked(path, packedValue);
            } catch(e) {
                link.off("response", responseHandler);
                link.off("close", closeHandler);
                reject(e);
            }
        });
    },

    /** Initialize channel support: register rfed.delivery destination
     *  for incoming channel messages, and re-subscribe to saved channels. */
    /** Check if an announce is from our configured RFed node and store its pub key. */
    _catchRfedNodeAnnounce(event) {
        if (!event.announce.identity || !this._cfg.rfedNodeHash) return;
        const idHash = event.announce.identity.hash?.toString("hex") ?? "";
        if (idHash !== this._cfg.rfedNodeHash) return;
        const pk = event.announce.identity.getPublicKey()?.toString("hex") ?? "";
        if (pk && pk !== this._cfg.rfedNodePubKey) {
            this._cfg.rfedNodePubKey = pk;
            sSet("rfedNodePubKey", pk);
            console.log(`[retichat] 📡 Learned RFed node pub key from announce: ${pk.slice(0,12)}...`);
        }
        this._requestRfedServicePaths();
    },

    async _initChannels() {
        if (!this._cfg.rfedNodeHash) {
            console.log("[retichat] 📡 No RFed node configured, skipping channel init");
            return;
        }

        if (!this._cfg.rfedNodePubKey || this._cfg.rfedNodePubKey.length !== 128) return;
        if (!this._channelsInitialized) {
            const deliveryHash = rfedDeliveryDestHash(IdMgr.id);
            const deliveryDest = this._rns.registerDestination(
                IdMgr.id, Destination.IN, Destination.SINGLE, "rfed", "delivery"
            );
            deliveryDest.on("packet", ({data}) => this._handleChannelPacket(data));
            // ANNOUNCE rfed.delivery so the RFed learns a path back to us.
            // The distro fanout checks has_path(rfed.delivery) and the deferred
            // flush fires on an rfed.delivery announce — but we never announced
            // it, so fanout always deferred and the flush never fired (devices
            // never received fanned-out distro messages).  Announce now and on
            // the periodic _announce() cycle (see _announce()).
            this._rfedDeliveryDest = deliveryDest;
            try { deliveryDest.announce(); } catch(e) { console.warn("[retichat] rfed.delivery announce error", e.message); }
            this._channelsInitialized = true;
            console.log(`[retichat] 📡 Channel delivery dest registered+announced: ${deliveryHash.slice(0,12)}...`);
        }

        if (!this._channelsResubscribed) {
            this._channelsResubscribed = true;
            const subscriptions = ChannelStore.getAll()
                .filter(ch => ch.isSubscribed)
                .map(channel => this._ensureChannelSubscribed(channel));
            const results = await Promise.allSettled(subscriptions);
            results.forEach(result => {
                if (result.status === "rejected") {
                    console.warn("[retichat] Persisted channel subscription failed:", result.reason?.message || result.reason);
                }
            });
        }
        const openedChannels = ChannelStore.getAll().filter(channel =>
            this._rfedOpenedChannelHashes.has(channel.channelHash)
        );
        await Promise.all(openedChannels.map(channel => this._ensureChannelStreamConfigured(channel)));
    },

    /** Handle an incoming channel packet (DATA on rfed.delivery).
     *  Deduplicates by (sourceHash, tsMs) per the spec security requirements. */
    _handleChannelPacket(packetData) {
        try {
            const data = Buffer.from(packetData || []);
            if (!data || data.length < 16 + 32) return;

            // First 16 bytes are the channel identity hash (routing prefix)
            const channelIdPrefix = data.slice(0, 16).toString("hex");

            // Distro fanout arrives on this same rfed.delivery destination as
            // [ distro_lxmf_hash(16) | lxmf_blob ]. The PULL path carries the
            // bare lxmf_blob, so strip the extra routing prefix before unwrapping.
            if (DistroManager.has && channelIdPrefix === DistroManager.lxmfDeliveryHash) {
                Harness.event("distro-push", { distro: channelIdPrefix.slice(0, 12), bytes: data.length });
                this._handleDistroBlob(data.slice(0, 16), data.slice(16));
                return;
            }

            const ch = ChannelStore.getByHash(channelIdPrefix);
            if (!ch) {
                console.log(`[retichat] 📡 Channel blob for unknown channel ${channelIdPrefix.slice(0,12)}..., ignoring`);
                return;
            }

            // Unpack the channel message
            const result = channelLxmUnpack(ch.channelName, data);
            if (!result) {
                console.warn(`[retichat] 📡 Channel unpack failed for ${ch.channelName}`);
                return;
            }

            const { sourceHash, tsMs, content, senderPubKey } = result;
            const srcHashHex = sourceHash.toString("hex");

            // Dedup: track by (senderHash, tsMs) — per spec security requirements.
            // Server-echo of own sent messages and multi-subscriber fanout produce
            // duplicate deliveries.
            if (!this._chanSeenIds) this._chanSeenIds = new Set();
            const dedupKey = `${srcHashHex}:${tsMs}`;
            if (this._chanSeenIds.has(dedupKey)) {
                const pendingEcho = this._rfedPendingEchoes.get(dedupKey);
                if (pendingEcho) {
                    this._rfedPendingEchoes.delete(dedupKey);
                    pendingEcho.resolve();
                    console.log(`[retichat] 📡 Channel publish accepted by RFed: ${dedupKey.slice(0,20)}...`);
                }
                console.log(`[retichat] 📡 Channel dedup: already seen ${srcHashHex.slice(0,8)} ts=${tsMs}`);
                return;
            }
            this._chanSeenIds.add(dedupKey);
            // Cap the set size to prevent unbounded growth
            if (this._chanSeenIds.size > 2000) {
                const arr = [...this._chanSeenIds];
                this._chanSeenIds = new Set(arr.slice(-1000));
            }

            // Register sender identity from the RTID prelude
            if (senderPubKey && !ContactStore.isContact(srcHashHex)) {
                ContactStore.add(srcHashHex);
                const contact = ContactStore.get(srcHashHex);
                if (contact && !contact.publicKey) {
                    contact.publicKey = Buffer.from(senderPubKey).toString("hex");
                    ContactStore._save();
                }
            }

            // Insert message
            ChannelMsgStore.add(ch.channelName, {
                dir: "in", content, status: "delivered",
                srcHash: srcHashHex, senderName: srcHashHex.slice(0, 12),
            });
            ChannelStore.touch(ch.channelName);

            this._onMsg.forEach(fn => fn({kind: "channel-receive"}, ch.channelName));
            console.log(`[retichat] 📡 Channel message on #${ch.channelName}: "${content.slice(0,60)}" from ${srcHashHex.slice(0,12)}`);
        } catch(e) {
            console.warn("[retichat] 📡 Channel packet handler error:", e.message);
        }
    },

    /** Subscribe through the persistent legacy rfed.channel compatibility link. */
    async _subscribeChannel(channelName, rfedNodeHash) {
        const chHash = channelIdentity(channelName).hash;
        const pubKey = IdMgr.id.getPublicKey();
        const sig = IdMgr.id.sign(chHash);
        const subscribePayload = MsgPack.pack([chHash, pubKey, sig]);
        const response = await this._rfedRequest(["channel"], "/rfed/subscribe", subscribePayload);
        if (!Array.isArray(response) || response[0] !== true) {
            throw new Error(`RFed refused subscription to #${channelName}`);
        }
        ChannelStore.setStampCost(channelName, response[1] ?? null);
        console.log(`[retichat] 📡 Subscribed to #${channelName} (stamp=${response[1] ?? "none"})`);
        return response[1] ?? null;
    },

    _ensureChannelSubscribed(channel) {
        const key = channel.channelHash;
        const existing = this._rfedSubscriptionPromises.get(key);
        if (existing) return existing;
        const subscription = this._subscribeChannel(channel.channelName, channel.rfedNodeHash)
            .then(stampCost => {
                this._rfedStampRefreshed.add(key);
                return stampCost;
            });
        this._rfedSubscriptionPromises.set(key, subscription);
        return subscription;
    },

    /** Unsubscribe from a channel. */
    async _unsubscribeChannel(channelName, rfedNodeHash) {
        const chHash = channelIdentity(channelName).hash;
        const pubKey = IdMgr.id.getPublicKey();
        const sig = IdMgr.id.sign(chHash);
        const unsubscribePayload = MsgPack.pack([chHash, pubKey, sig]);
        const response = await this._rfedRequest(["channel"], "/rfed/unsubscribe", unsubscribePayload);
        if (response !== true) throw new Error(`RFed refused unsubscribe from #${channelName}`);
        console.log(`[retichat] 📡 Unsubscribed from #${channelName}`);
    },

    /** Register the distro identity with RFed so messages get fanned out. */
    async _registerDistro() {
        if (!DistroManager.has) {
            console.warn("[distro] No distro identity to register");
            return false;
        }
        // Coalesce concurrent registrations into ONE in-flight request.
        //
        // NEVER REMOVE. _registerDistro() has two independent callers that fire
        // within the same second of startup: _onExchangeRegistered() (automatic,
        // as soon as the exchange interface registers) and the UI/test entry
        // point RetichatTest.registerDistro(). Without this guard both build the
        // same payload and issue two /rfed/distro/register requests over the SAME
        // link, back to back. RFed then runs two registration callbacks
        // concurrently and both wedge — verified in production 2026-08-09
        // 00:56:54: two `[REQ] resolved path='/rfed/distro/register'` lines on
        // link 87448189... and NEITHER ever reached `[REQ] callback completed`,
        // so no response was ever sent and the client waited forever. Single
        // registrations on the same build complete in well under a second
        // (18:35:47, 18:38:38, 18:43:38 all logged `callback completed`).
        //
        // This is a duplicate-work bug, not a timing one: registering the same
        // device for the same distro twice is meaningless. Do not "fix" a slow
        // or missing response by retrying — that reproduces the exact condition
        // that wedges the server (DESIGN_PRINCIPLES.md Rule #1).
        if (this._registerDistroInFlight) return this._registerDistroInFlight;
        this._registerDistroInFlight = (async () => {
            try {
                const distroPubKey = DistroManager.identity.getPublicKey();
                const devicePubKey = IdMgr.id.getPublicKey();
                const sig = DistroManager.identity.sign(devicePubKey);
                const payload = MsgPack.pack([devicePubKey, distroPubKey, sig]);
                const response = await this._rfedRequest(["distro", "register"], "/rfed/distro/register", payload);
                if (response === true || (Array.isArray(response) && response[0] === true)) {
                    console.log(`[distro] ✅ Registered device with RFed (distro=${DistroManager.hash.slice(0,12)}...)`);
                    return true;
                } else {
                    console.warn(`[distro] RFed refused registration:`, response);
                    return false;
                }
            } catch(e) {
                console.error(`[distro] Registration failed:`, e);
                return false;
            } finally {
                this._registerDistroInFlight = null;
            }
        })();
        return this._registerDistroInFlight;
    },

    /** Unregister the distro identity from RFed. */
    async _unregisterDistro() {
        if (!DistroManager.has) return false;
        try {
            const distroPubKey = DistroManager.identity.getPublicKey();
            const devicePubKey = IdMgr.id.getPublicKey();
            const sig = DistroManager.identity.sign(devicePubKey);
            const payload = MsgPack.pack([devicePubKey, distroPubKey, sig]);
            const response = await this._rfedRequest(["distro", "unregister"], "/rfed/distro/unregister", payload);
            if (response === true) {
                console.log(`[distro] ✅ Unregistered device from RFed`);
                return true;
            }
            return false;
        } catch(e) {
            console.error(`[distro] Unregistration failed:`, e);
            return false;
        }
    },

    /** PULL deferred distro messages from RFed. */
    async _pullDistroMessages() {
        if (!DistroManager.has) return [];
        try {
            const response = await this._rfedRequest(["distro", "register"], "/rfed/pull", Buffer.alloc(0));
            if (!Array.isArray(response) || response.length < 2) return [];
            const [pairs, morePending] = response;
            const count = pairs?.length ?? 0;
            console.log(`[distro] 📬 PULL returned ${count} blob(s), more=${morePending}`);
            for (const pair of pairs || []) {
                if (!Array.isArray(pair) || pair.length < 2) continue;
                const [distroHash, blob] = pair;
                this._handleDistroBlob(distroHash, blob);
            }
            return pairs || [];
        } catch(e) {
            console.error(`[distro] PULL failed:`, e);
            return [];
        }
    },

    /** Handle a distro blob from PULL. */
    _handleDistroBlob(distroHash, blob) {
        try {
            const data = Buffer.from(blob);
            if (data.length < 48) return;
            // blob format: [dest_hash(16) | EC_encrypted(lxmf_data)]
            const destHash = data.slice(0, 16);
            const myLxmfHash = DistroManager.lxmfDeliveryHash;
            if (!destHash.equals(Buffer.from(myLxmfHash, "hex"))) {
                console.log(`[distro] Blob not for us: ${destHash.toString("hex").slice(0,12)}`);
                return;
            }
            // Decrypt with distro identity
            const decrypted = DistroManager.identity.decrypt(data.slice(16));
            if (!decrypted || decrypted.length < 80) return;
            const srcHash = decrypted.slice(0, 16);
            const payloadBytes = decrypted.slice(80);
            const payload = MsgPack.unpack(payloadBytes);
            if (!Array.isArray(payload) || payload.length < 3) return;
            const [ts, titleBin, contentBin, fieldsMap] = payload;
            const content = Buffer.from(contentBin || []).toString();
            const srcHashHex = srcHash.toString("hex");
            console.log(`[distro] 📥 Message from ${srcHashHex.slice(0,12)}: "${content.slice(0,60)}"`);
            // Auto-add contact and store message
            if (!ContactStore.isContact(srcHashHex)) {
                ContactStore.add(srcHashHex);
            }
            MsgStore.add(srcHashHex, { dir: "in", content, status: "delivered", srcHash: srcHashHex, via: "distro" });
            ContactStore.touch(srcHashHex);
            this._onMsg.forEach(fn => fn(null, srcHashHex));
        } catch(e) {
            console.error(`[distro] Failed to handle blob:`, e);
        }
    },

    async _configureChannelStream() {
        if (!this._channelsInitialized) return;
        const filters = ChannelStore.getAll()
            .filter(ch => ch.isSubscribed && this._rfedOpenedChannelHashes.has(ch.channelHash))
            .map(ch => Buffer.from(ch.channelHash, "hex"));
        if (filters.length === 0 && !this._rfedLinks.has("channel.stream")) return;

        const encodedFilters = MsgPack.pack(filters);
        const payload = MsgPack.pack([
            encodedFilters,
            IdMgr.id.getPublicKey(),
            IdMgr.id.sign(encodedFilters),
        ]);
        const response = await this._rfedRequest(
            ["channel", "stream"],
            "/rfed/channel/stream/open",
            payload
        );
        if (!Array.isArray(response) || response[0] !== true) {
            throw new Error(`RFed channel stream rejected: ${response?.[1] || "unknown"}`);
        }
        console.log(`[retichat] 📡 Channel stream configured for ${filters.length} channel(s)`);
    },

    async openChannel(channelName) {
        const channel = ChannelStore.get(channelName);
        if (!channel) return;
        this._rfedOpenedChannelHashes.add(channel.channelHash);
        await this._ensureChannelSubscribed(channel);
        const stream = this._ensureChannelStreamConfigured(channel);
        const pull = this._rfedPullState.has(channel.channelHash)
            ? Promise.resolve()
            : this.pullChannel(channelName);
        await Promise.all([stream, pull]);
    },

    _ensureChannelStreamConfigured(channel) {
        const key = channel.channelHash;
        this._rfedOpenedChannelHashes.add(key);
        const existing = this._rfedStreamPromises.get(key);
        if (existing) return existing;
        const configured = this._configureChannelStream();
        this._rfedStreamPromises.set(key, configured);
        return configured;
    },

    async pullChannel(channelName) {
        const channel = ChannelStore.get(channelName);
        if (!channel) return false;
        const key = channel.channelHash;
        const current = this._rfedPullState.get(key);
        if (current?.inFlight) return current.morePending !== false;
        this._rfedPullState.set(key, {inFlight: true, morePending: current?.morePending});
        this._onMsg.forEach(fn => fn({kind: "channel-pull-start"}, channelName));
        try {
            const response = await this._rfedRequest(
                ["channel", "pull"],
                "/rfed/pull",
                MsgPack.pack(Buffer.from(key, "hex"))
            );
            if (!Array.isArray(response) || !Array.isArray(response[0])) {
                throw new Error("Malformed RFed pull response");
            }
            for (const pair of response[0]) {
                if (!Array.isArray(pair) || pair.length !== 2) continue;
                this._handleChannelPacket(Buffer.concat([Buffer.from(pair[0]), Buffer.from(pair[1])]));
            }
            const morePending = response[1] === true;
            this._rfedPullState.set(key, {inFlight: false, morePending});
            return morePending;
        } catch(e) {
            this._rfedPullState.set(key, {inFlight: false, morePending: current?.morePending});
            throw e;
        } finally {
            this._onMsg.forEach(fn => fn({kind: "channel-pull-complete"}, channelName));
        }
    },

    /** Join a channel: persist + subscribe (queues if pub key unknown). */
    async joinChannel(channelName) {
        if (!this._cfg.rfedNodeHash) throw new Error("No RFed node configured");
        const existing = ChannelStore.get(channelName);
        if (existing && existing.isSubscribed) {
            console.log(`[retichat] 📡 Already in channel #${channelName}`);
            this.openChannel(channelName).catch(e => {
                console.warn(`[retichat] 📡 Channel activation failed for #${channelName}:`, e.message);
            });
            return existing;
        }

        const ch = ChannelStore.join(channelName, this._cfg.rfedNodeHash);
        ChannelMsgStore.add(channelName, {
            dir: "system", content: `You joined #${channelName}`,
            status: "delivered",
        });
        this._onMsg.forEach(fn => fn({kind: "channel-joined"}, channelName));

        (async () => {
            try {
                const stampCost = await this._ensureChannelSubscribed(ch);
                ChannelStore.setStampCost(channelName, stampCost);
                await this.openChannel(channelName);
                this._onMsg.forEach(fn => fn({kind: "channel-activated"}, channelName));
            } catch(e) {
                ChannelMsgStore.add(channelName, {
                    dir: "system",
                    content: `Channel connection failed: ${e.message}`,
                    status: "failed",
                });
                this._onMsg.forEach(fn => fn({kind: "channel-activation-failed"}, channelName));
                console.warn(`[retichat] 📡 Channel activation failed for #${channelName}:`, e.message);
            }
        })();

        return ch;
    },

    async leaveChannel(channelName) {
        const ch = ChannelStore.get(channelName);
        if (!ch) return;

        try { await this._unsubscribeChannel(channelName, ch.rfedNodeHash); } catch(e) {
            console.warn(`[retichat] 📡 Unsubscribe failed:`, e.message);
        }

        this._rfedOpenedChannelHashes.delete(ch.channelHash);
        this._rfedStreamPromises.delete(ch.channelHash);
        await this._configureChannelStream();
        ChannelMsgStore.remove(channelName);
        ChannelStore.leave(channelName);
        this._onMsg.forEach(fn => fn({kind: "channel-left"}, channelName));
    },

    /** Send a message to a channel. */
    async sendChannelMessage(channelName, content) {
        if (!IdMgr.has) throw new Error("No identity");

        // Add outgoing message optimistically
        const outMsg = ChannelMsgStore.add(channelName, {
            dir: "out", content, status: "sending",
            srcHash: IdMgr.hash,
        });
        ChannelStore.touch(channelName);
        this._onMsg.forEach(fn => fn({kind: "channel-send-pending"}, channelName));

        const previousSend = this._rfedSendChain;
        let releaseSend;
        this._rfedSendChain = new Promise(resolve => { releaseSend = resolve; });
        await previousSend;

        try {
            const ch = ChannelStore.get(channelName);
            if (!ch) throw new Error("Channel not found");
            await this._ensureChannelSubscribed(ch);
            await this._ensureChannelStreamConfigured(ch);

            // Pack the channel message
            const { wire, tsMs } = channelLxmPack(channelName, IdMgr.id, content);

            // Compute PoW stamp (only if server requires one)
            const stampCost = ChannelStore.get(channelName)?.stampCost;

            // Anything at or under the link MDU goes as a single data packet;
            // larger payloads go as an RNS Resource. Decide before mining the
            // stamp so the PoW is never burned on a send we cannot make.
            const stampBytes = (stampCost != null && stampCost > 0) ? 32 : 0;
            const oversized = wire.length + stampBytes > Link.MDU;

            let stamp = null;
            if (stampCost != null && stampCost > 0) {
                stamp = await channelComputeStamp(wire, stampCost);
                if (!stamp) throw new Error(`Could not compute required channel stamp at cost ${stampCost}`);
            }

            // Append stamp if available
            const finalPayload = stamp ? Buffer.concat([wire, stamp]) : wire;

            if (!this._chanSeenIds) this._chanSeenIds = new Set();
            const ownSourceHash = Destination.hash(IdMgr.id, "lxmf", "delivery").toString("hex");
            const echoKey = `${ownSourceHash}:${tsMs}`;
            this._chanSeenIds.add(echoKey);

            const link = await this._ensureRfedLink(["channel"]);
            const echoPromise = this._waitForRfedPublishEcho(echoKey, channelName);
            if (oversized) {
                // A resource has no single packet hash to prove against, so
                // the resource's own proof is the delivery evidence.
                await Promise.all([link.sendResource(finalPayload), echoPromise]);
            } else {
                const packet = link.send(finalPayload);
                await Promise.all([
                    this._waitForRfedPublishProof(packet, channelName, outMsg.id),
                    echoPromise,
                ]);
            }

            // Mark as sent
            ChannelMsgStore.updateStatus(channelName, outMsg.id, "sent");
            console.log(`[retichat] 📡 Channel message proved to #${channelName} (${finalPayload.length}B, stamp=${!!stamp}, resource=${oversized})`);
        } catch(e) {
            ChannelMsgStore.updateStatus(channelName, outMsg.id, "failed");
            console.warn(`[retichat] 📡 Channel send failed for #${channelName}:`, e.message);
            throw e;
        } finally {
            releaseSend();
            this._onMsg.forEach(fn => fn({kind: "channel-send-complete"}, channelName));
        }
        return outMsg;
    },

    _waitForRfedPublishProof(packet, channelName, messageId) {
        const proofKey = packet.packetHash.slice(0, 16).toString("hex");
        const startedAt = Date.now();
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this._pendingPacketHashes.delete(proofKey);
                reject(new Error(`No RFed publish proof for #${channelName} within 10 seconds`));
            }, RFED_OPERATION_LIMIT_MS);
            this._pendingPacketHashes.set(proofKey, {
                contactHash: channelName,
                messageId,
                onProof: () => {
                    clearTimeout(timer);
                    if (Date.now() - startedAt > RFED_OPERATION_LIMIT_MS) {
                        reject(new Error(`RFed publish proof for #${channelName} arrived after 10 seconds`));
                        return;
                    }
                    resolve();
                },
            });
        });
    },

    _waitForRfedPublishEcho(echoKey, channelName) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this._rfedPendingEchoes.delete(echoKey);
                reject(new Error(`No RFed stream acceptance for #${channelName} within 10 seconds`));
            }, RFED_OPERATION_LIMIT_MS);
            this._rfedPendingEchoes.set(echoKey, {
                resolve: () => {
                    clearTimeout(timer);
                    resolve();
                },
                reject: (error) => {
                    clearTimeout(timer);
                    reject(error);
                },
            });
        });
    },

    disconnect() {
        if (this._annTimer) { clearInterval(this._annTimer); this._annTimer = null; }
        if (this._monTimer) { clearInterval(this._monTimer); this._monTimer = null; }
        this._pendingTickets.clear();
        this._pendingPacketHashes.clear();
        for (const tid of this._pendingTimeouts.values()) clearTimeout(tid);
        this._pendingTimeouts.clear();
        for (const link of this._rfedLinks.values()) {
            try { link.close(); } catch(e) {}
        }
        this._rfedLinks.clear();
        this._rfedLinkPromises.clear();
        this._rfedServiceReady.clear();
        this._rfedServicePathsRequested = false;
        this._propagationPathRequested = false;
        for (const waiters of this._rfedServiceWaiters.values()) {
            waiters.forEach(waiter => waiter.reject(new Error("Disconnected before RFed service became reachable")));
        }
        this._rfedServiceWaiters.clear();
        this._rfedOpenedChannelHashes.clear();
        this._rfedPullState.clear();
        this._rfedStampRefreshed.clear();
        this._rfedSubscriptionPromises.clear();
        this._rfedStreamPromises.clear();
        for (const pendingEcho of this._rfedPendingEchoes.values()) {
            pendingEcho.reject?.(new Error("Disconnected before RFed stream acceptance"));
        }
        this._rfedPendingEchoes.clear();
        this._rfedSendChain = Promise.resolve();
        for (const entry of this._groupLinks.values()) {
            try { entry.link.close(); } catch(e) {}
        }
        this._groupLinks.clear();
        this._groupLinkPromises.clear();
        this._groupPeerReady.clear();
        for (const waiters of this._groupPeerWaiters.values()) {
            waiters.forEach(waiter => waiter.reject(new Error("Disconnected before group member became reachable")));
        }
        this._groupPeerWaiters.clear();
        this._groupPathsRequested.clear();
        this._groupFallbacks.clear();
        this._propLinkReject?.(new Error("Disconnected before propagation link became active"));
        this._propLinkPromise = null;
        this._propLinkResolve = null;
        this._propLinkReject = null;
        this._channelsInitialized = false;
        this._channelsResubscribed = false;
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
        showNewConversation: false,
        newConvTab: "direct",   // "direct" | "group" | "channel"
        channelVis: "public",   // "public" | "private"
        showGroupInfo: false,
        groupInfoId: null,
        showChannelInfo: false,
        channelInfoName: null,
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
        GroupStore.migrateOwnMemberHash();
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
                if (this.state.showSettings || this.state.showAddContact || this.state.showShareId ||
                    this.state.showContactInfo || this.state.showNewConversation || this.state.showGroupInfo ||
                    this.state.showChannelInfo) {
                    this.state.showSettings = false;
                    this.state.showAddContact = false;
                    this.state.showShareId = false;
                    this.state.showContactInfo = false;
                    this.state.showNewConversation = false;
                    this.state.showGroupInfo = false;
                    this.state.showChannelInfo = false;
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
        if (this.state.showNewConversation) this._renderNewConversationModal();
        if (this.state.showGroupInfo) this._renderGroupInfoModal();
        if (this.state.showChannelInfo) this._renderChannelInfoModal();

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
        const groups = GroupStore.getAll();
        const channels = ChannelStore.getAll();

        // Build unified chat entry list (contacts + groups + channels), sorted by last activity
        const entries = [];
        for (const c of contacts) {
            const msgs = MsgStore.get(c.destHash);
            const lastTs = msgs.length > 0 ? msgs[msgs.length-1].timestamp : c.lastSeen;
            entries.push({ type: "dm", id: c.destHash, name: c.displayName || "?" + c.destHash.slice(0,8),
                lastTs, data: c, preview: MsgStore.preview(c.destHash) });
        }
        for (const g of groups) {
            const msgs = GroupMsgStore.get(g.groupId);
            const lastTs = msgs.length > 0 ? msgs[msgs.length-1].timestamp : g.lastActivity;
            entries.push({ type: "group", id: g.groupId, name: g.groupName,
                lastTs, data: g, preview: GroupMsgStore.preview(g.groupId) });
        }
        for (const ch of channels) {
            const msgs = ChannelMsgStore.get(ch.channelName);
            const lastTs = msgs.length > 0 ? msgs[msgs.length-1].timestamp : ch.lastActivity;
            entries.push({ type: "channel", id: ch.channelName, name: "#" + ch.channelName,
                lastTs, data: ch, preview: ChannelMsgStore.preview(ch.channelName) });
        }
        entries.sort((a, b) => b.lastTs - a.lastTs);

        // Apply search filter
        const filtered = this.state.searchQuery
            ? entries.filter(e => {
                const name = e.name.toLowerCase();
                const id = e.id.toLowerCase();
                const q = this.state.searchQuery.toLowerCase();
                return name.includes(q) || id.includes(q);
            })
            : entries;
        const hasEntries = entries.length > 0;

        const frag = document.createDocumentFragment();

        // Header
        const ownHash = RnsClient.ownHash || ownLxmfDestinationHash();
        const abbreviatedHash = ownHash ? `${ownHash.slice(0, 12)}…` : "Identity unavailable";
        frag.appendChild(
            h("div", { className: "sidebar-header" },
                h("div", { className: "sidebar-brand" },
                    h("div", { className: "sidebar-title" },
                        h("span", { id: "status-dot", className: "status-dot" }),
                        h("h1", {}, "Retichat"),
                    ),
                    h("div", { className: "sidebar-identity" },
                        h("button", { className: "sidebar-hash", title: "Share Your Identity",
                            onClick: () => { this.state.showShareId = true; this.render(); } }, abbreviatedHash),
                        h("button", { className: "copy-hash-btn", title: "Copy LXMF hash",
                            disabled: !ownHash,
                            onClick: () => {
                                if (ownHash) navigator.clipboard.writeText(ownHash).catch(() => {});
                            } }, "⧉"),
                    ),
                ),
                h("div", { className: "sidebar-actions" },
                    h("button", { className: "icon-btn", title: "Settings",
                        onClick: () => { this.state.showSettings = true; this.render(); } }, "⚙"),
                    h("button", { className: "icon-btn", title: "Add",
                        onClick: () => { this.state.showNewConversation = true; this.state.newConvTab = "direct"; this.render(); } }, "+"),
                ),
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

        // Contact/Group list or empty state
        if (hasEntries && filtered.length === 0 && this.state.searchQuery) {
            frag.appendChild(
                h("div", { className: "empty-list" },
                    h("div", { className: "empty-icon" }, "🔍"),
                    h("h2", {}, "No results"),
                    h("p", {}, `No chats match "${esc(this.state.searchQuery)}"`),
                ),
            );
        } else if (!hasEntries) {
            frag.appendChild(
                h("div", { className: "empty-list" },
                    h("div", { className: "empty-icon" }, "💬"),
                    h("h2", {}, "No conversations yet"),
                    h("p", {}, "Add a contact or create a group to start chatting privately over Reticulum."),
                    h("div", { style: { display: "flex", gap: "8px", marginTop: "8px", justifyContent: "center" } },
                        h("button", { className: "btn btn-primary",
                            onClick: () => { this.state.showAddContact = true; this.render(); } },
                            "+ Add Contact"),
                        h("button", { className: "btn btn-secondary",
                            onClick: () => { this.state.showNewConversation = true; this.state.newConvTab = "group"; this.render(); } },
                            "👥 New Group"),
                    ),
                ),
            );
        } else {
            frag.appendChild(
                h("div", { className: "contact-list" },
                    ...filtered.map(e => {
                        if (e.type === "group") return this._buildGroupItem(e.data, e.preview, e.lastTs);
                        if (e.type === "channel") return this._buildChannelItem(e.data, e.preview, e.lastTs);
                        return this._buildContactItem(e.data);
                    }),
                ),
            );
        }

        return frag;
    },

    _buildGroupItem(g, preview, lastTs) {
        const name = g.groupName || "Group";
        const isActive = this.state.activeHash === g.groupId;
        const isPending = g.groupStatus === "pending";
        const hue = avatarHue(name);
        const memberCount = g.members?.size ?? 0;

        return h("div", {
            className: "contact-item" + (isActive ? " active" : ""),
            onClick: () => this.openChat(g.groupId),
        },
            h("div", {
                className: "contact-avatar",
                style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
            }, "👥"),
            h("div", { className: "contact-info" },
                h("div", { className: "contact-name" },
                    esc(name),
                    isPending ? h("span", { className: "contact-badge pending" }, "invite") : null,
                ),
                preview
                    ? h("div", { className: "contact-preview" }, esc(preview))
                    : h("div", { className: "contact-preview", style: { fontStyle: "italic" } },
                        `${memberCount} members`),
            ),
            h("div", { className: "contact-meta" },
                h("div", { className: "contact-time" }, lastTs ? fmtDate(lastTs) : ""),
            ),
        );
    },

    _buildChannelItem(ch, preview, lastTs) {
        const name = "#" + ch.channelName;
        const isActive = this.state.activeHash === ch.channelName;
        const hue = avatarHue(name);

        return h("div", {
            className: "contact-item" + (isActive ? " active" : ""),
            onClick: () => this.openChat(ch.channelName),
        },
            h("div", {
                className: "contact-avatar",
                style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
            }, "#"),
            h("div", { className: "contact-info" },
                h("div", { className: "contact-name" }, esc(name)),
                preview
                    ? h("div", { className: "contact-preview" }, esc(preview))
                    : h("div", { className: "contact-preview", style: { fontStyle: "italic" } },
                        "Channel"),
            ),
            h("div", { className: "contact-meta" },
                h("div", { className: "contact-time" }, lastTs ? fmtDate(lastTs) : ""),
            ),
        );
    },

    _buildContactItem(c) {
        const name = c.displayName || "?" + c.destHash.slice(0, 8);
        const preview = MsgStore.preview(c.destHash);
        const msgs = MsgStore.get(c.destHash);
        const lastTs = msgs.length > 0 ? msgs[msgs.length - 1].timestamp : c.lastSeen;
        const isActive = this.state.activeHash === c.destHash;
        const hue = avatarHue(name);
        const avatarText = name.charAt(0).toUpperCase();

        return h("div", {
            className: "contact-item" + (isActive ? " active" : ""),
            onClick: () => this.openChat(c.destHash),
        },
            h("div", {
                className: "contact-avatar",
                style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
            }, avatarText),
            h("div", { className: "contact-info" },
                h("div", { className: "contact-name" },
                    esc(name),

                ),
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
        // Check if this is a group chat
        if (GroupStore.isGroupChat(this.state.activeHash)) {
            return this._buildGroupChatView();
        }
        // Check if this is a channel
        if (ChannelStore.get(this.state.activeHash)) {
            return this._buildChannelChatView();
        }
        return this._buildDmChatView();
    },

    _buildDmChatView() {
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
                    : msgs.map(m => this._buildMsgBubble(m))),
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

    _buildGroupChatView() {
        const g = GroupStore.get(this.state.activeHash);
        if (!g) { this.state.activeHash = null; this.render(); return document.createDocumentFragment(); }
        const name = g.groupName || "Group";
        const msgs = GroupMsgStore.get(g.groupId);
        const hue = avatarHue(name);
        const isPending = g.groupStatus === "pending";
        const memberCount = g.members?.size ?? 0;

        return h("div", { className: "chat-view" },
            // Header
            h("div", { className: "chat-header" },
                h("button", { className: "back-btn",
                    onClick: () => this.closeChat() }, "←"),
                h("div", {
                    className: "header-avatar",
                    style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
                }, "👥"),
                h("div", { className: "header-info",
                    onClick: () => { this.state.showGroupInfo = true; this.state.groupInfoId = g.groupId; this.render(); },
                    style: { cursor: "pointer" } },
                    h("div", { className: "header-name" }, esc(name)),
                    h("div", { className: "header-hash" },
                        isPending ? "⏳ Pending invite" : `${memberCount} members`),
                ),
                h("button", { className: "icon-btn", title: "Group info",
                    onClick: () => { this.state.showGroupInfo = true; this.state.groupInfoId = g.groupId; this.render(); } }, "ℹ"),
            ),

            // Pending invite overlay (like iOS)
            ...(isPending ? [
                h("div", { className: "pending-invite-bar" },
                    h("div", { className: "pending-icon" }, "📩"),
                    h("div", { className: "pending-text" }, "You've been invited to this group"),
                    h("div", { style: { display: "flex", gap: "8px" } },
                        h("button", { className: "btn btn-primary btn-sm",
                            onClick: () => this._acceptGroupInvite(g.groupId) }, "Accept"),
                        h("button", { className: "btn btn-danger btn-sm",
                            onClick: () => this._declineGroupInvite(g.groupId) }, "Decline"),
                    ),
                ),
            ] : []),

            // Messages
            h("div", { className: "message-list", id: "msg-list" },
                ...(msgs.length === 0
                    ? [h("div", { className: "empty-chat" },
                        h("p", {}, isPending ? "Accept the invite to start chatting." : "No messages yet. Say hello!"))]
                    : msgs.map(m => {
                        if (m.dir === "system") {
                            return h("div", { className: "msg-row system", "data-msg-id": m.id },
                                h("div", { className: "system-msg" },
                                    h("span", { className: "msg-time" }, fmtTime(m.timestamp)),
                                    " ",
                                    esc(m.content),
                                ),
                            );
                        }
                        return this._buildMsgBubble(m);
                    })),
            ),

            // Composer (hidden for pending groups)
            ...(isPending ? [] : [
                h("div", { className: "composer" },
                    h("textarea", {
                        id: "composer-input",
                        placeholder: "Message…",
                        rows: 1,
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
                        onClick: () => this.sendMessage(),
                    }, "➤"),
                ),
            ]),
        );
    },

    /** Build a single message bubble (used by both DM and group views). */
    _buildMsgBubble(m) {
        const isOwn = m.dir === "out";
        const statusIcon = isOwn ? this._statusIcon(m.status) : "";
        return h("div", { className: `msg-row ${isOwn ? "own" : "their"}`, "data-msg-id": m.id },
            h("div", { className: "msg-bubble" },
                (!isOwn && m.senderName) ? h("div", { className: "msg-sender" }, esc(m.senderName)) : null,
                esc(m.content),
                h("div", { className: "msg-meta" },
                    h("span", { className: "msg-time" }, fmtTime(m.timestamp)),
                    statusIcon ? h("span", { className: `msg-status ${m.status}`, "data-msg-status": m.status }, statusIcon) : null,
                ),
            ),
        );
    },

    /** Channel conversation view */
    _buildChannelChatView() {
        const ch = ChannelStore.get(this.state.activeHash);
        if (!ch) { this.state.activeHash = null; this.render(); return document.createDocumentFragment(); }
        const name = "#" + ch.channelName;
        const msgs = ChannelMsgStore.get(ch.channelName);
        const hue = avatarHue(name);

        return h("div", { className: "chat-view" },
            // Header
            h("div", { className: "chat-header" },
                h("button", { className: "back-btn",
                    onClick: () => this.closeChat() }, "←"),
                h("div", {
                    className: "header-avatar",
                    style: { color: `hsl(${hue}, 50%, 65%)`, background: `hsla(${hue}, 50%, 40%, 0.15)`, borderColor: `hsla(${hue}, 50%, 65%, 0.2)` },
                }, "#"),
                h("div", { className: "header-info",
                    onClick: () => { this.state.showChannelInfo = true; this.state.channelInfoName = ch.channelName; this.render(); },
                    style: { cursor: "pointer" } },
                    h("div", { className: "header-name" }, esc(name)),
                    h("div", { className: "header-hash" }, `Channel · ${ch.channelHash.slice(0,12)}…`),
                ),
                h("button", { className: "icon-btn", title: "Channel info",
                    onClick: () => { this.state.showChannelInfo = true; this.state.channelInfoName = ch.channelName; this.render(); } }, "ℹ"),
            ),

            // Messages
            h("div", { className: "message-list", id: "msg-list" },
                ...(msgs.length === 0
                    ? [h("div", { className: "empty-chat" },
                        h("p", {}, "No messages yet. Be the first to speak!"))]
                    : msgs.map(m => {
                        if (m.dir === "system") {
                            return h("div", { className: "msg-row system", "data-msg-id": m.id },
                                h("div", { className: "system-msg" },
                                    h("span", { className: "msg-time" }, fmtTime(m.timestamp)),
                                    " ",
                                    esc(m.content),
                                ),
                            );
                        }
                        return this._buildMsgBubble({ ...m, senderName: m.senderName || (m.dir === "in" ? m.srcHash?.slice(0,12) : null) });
                    })),
            ),

            // Composer
            h("div", { className: "composer" },
                h("textarea", {
                    id: "composer-input",
                    placeholder: "Message #" + ch.channelName + "…",
                    rows: 1,
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
                    onClick: () => this.sendMessage(),
                }, "➤"),
            ),
        );
    },

    // ===== ACTIONS =====

    openChat(hash, activateChannel = true) {
        this.state.activeHash = hash;
        this.state.showSettings = false;
        this.state.showAddContact = false;
        this.state.showShareId = false;
        this.state.showContactInfo = false;
        this.state.showNewConversation = false;
        this.state.showGroupInfo = false;
        this.state.showChannelInfo = false;

        if (activateChannel && ChannelStore.get(hash)) {
            RnsClient.openChannel(hash).catch(e => console.warn("[retichat] Open channel failed:", e.message));
        }
        if (GroupStore.isGroupChat(hash)) {
            RnsClient.openGroupConversation(hash).catch(e => console.warn("[retichat] Open group failed:", e.message));
        }

        // For DMs: send a path request if we don't have this contact's public key yet
        if (!GroupStore.isGroupChat(hash)) {
            const c = ContactStore.get(hash);
            if (c && !c.publicKey) {
                this._requestPathForContact(hash);
            }
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

        const clearAndFocus = () => {
            ta.value = "";
            ta.style.height = "auto";
            this.render();
            requestAnimationFrame(() => {
                this._scrollChatBottom();
                document.getElementById("composer-input")?.focus();
            });
        };

        try {
            // Check if this is a group chat
            if (GroupStore.isGroupChat(this.state.activeHash)) {
                RnsClient.sendGroupMessage(this.state.activeHash, content).catch(e => {
                    console.warn("Group send failed:", e.message);
                });
                clearAndFocus();
                return;
            }
            // Check if this is a channel
            if (ChannelStore.get(this.state.activeHash)) {
                ta.value = "";
                ta.style.height = "auto";
                RnsClient.sendChannelMessage(this.state.activeHash, content).catch(e => {
                    console.warn("Channel send failed:", e.message);
                });
                requestAnimationFrame(() => {
                    this._scrollChatBottom();
                    document.getElementById("composer-input")?.focus();
                });
                return;
            }
            // DM
            const c = ContactStore.get(this.state.activeHash);
            if (!c) return;
            RnsClient.sendMessage(c, content);
            clearAndFocus();
        } catch(e) { alert("Send failed: " + e.message); }
    },

    _acceptGroupInvite(groupId) {
        const group = GroupStore.get(groupId);
        if (!group) return;
        const missingKeys = [...group.members.keys()].filter(hash =>
            hash !== RnsClient.ownHash && !ContactStore.get(hash)?.publicKey
        );
        if (missingKeys.length > 0) {
            alert(`Still receiving member keys (${group.members.size - missingKeys.length}/${group.members.size}).`);
            return;
        }
        GroupStore.accept(groupId);
        for (const memberHash of group.members.keys()) {
            if (memberHash === RnsClient.ownHash) continue;
            if (!ContactStore.isContact(memberHash)) ContactStore.add(memberHash);
            RnsClient._requestGroupPeer(memberHash);
        }
        GroupMsgStore.addSystem(groupId, `You joined "${group.groupName}"`);
        RnsClient.sendGroupAccept(groupId).catch(e => console.warn("Group accept send failed:", e.message));
        this.render();
    },

    _declineGroupInvite(groupId) {
        if (!confirm("Decline this group invite?")) return;
        GroupMsgStore.remove(groupId);
        GroupStore.remove(groupId);
        if (this.state.activeHash === groupId) this.state.activeHash = null;
        document.body.classList.remove("narrow-chat-open");
        this.render();
    },

    _leaveGroup(groupId) {
        if (!confirm("Leave this group? You won't receive future messages.")) return;
        RnsClient.sendGroupLeave(groupId).catch(e => console.warn("Group leave send failed:", e.message));
        GroupMsgStore.remove(groupId);
        GroupStore.remove(groupId);
        if (this.state.activeHash === groupId) this.state.activeHash = null;
        document.body.classList.remove("narrow-chat-open");
        this.render();
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
            case "sent":        return "✓";   // single check — published to RFed
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

        // ---- Distro section ----
        const distroState = DistroManager.has
            ? { hash: DistroManager.hash, pubKey: DistroManager.pubKey }
            : null;
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Distro Identity"),
                distroState
                    ? h("div", { className: "settings-field" },
                        h("div", { className: "mono-value", style: { fontSize: "13px", marginBottom: "8px" } },
                            distroState.hash),
                        h("div", { className: "field-hint", style: { marginBottom: "12px" } },
                            "Your distro identity is active. Messages sent to this identity will be fanned out to all registered devices."),
                        h("div", { className: "btn-row" },
                            h("button", { className: "btn btn-secondary",
                                onClick: () => this._showDistroShare() }, "📤 Share"),
                            h("button", { className: "btn btn-danger",
                                onClick: () => this._forgetDistro() }, "🗑 Forget"),
                        ),
                    )
                    : h("div", { className: "settings-field" },
                        h("div", { className: "field-hint", style: { marginBottom: "12px" } },
                            "Generate a distro identity to receive messages on multiple devices. All devices share the same identity and can decrypt the same messages."),
                        h("div", { className: "btn-row" },
                            h("button", { className: "btn btn-primary",
                                onClick: () => this._generateDistro() }, "✨ Generate"),
                            h("button", { className: "btn btn-secondary",
                                onClick: () => this._showDistroImport() }, "📥 Import"),
                        ),
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
                    h("label", { htmlFor: "cfg-rfed-pubkey" }, "RFed Node Public Key (128 hex)"),
                    h("input", { id: "cfg-rfed-pubkey", type: "text",
                        value: cfg.rfedNodePubKey || "",
                        placeholder: "Auto-learned from announce…" }),
                    h("div", { className: "field-hint" },
                        "Required for channel subscribe/unsubscribe. Learned automatically when the RFed node announces; set manually if needed."),
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
        const rfedPubKey = document.getElementById("cfg-rfed-pubkey")?.value?.trim();
        const propOverride = document.getElementById("cfg-prop-override")?.value?.trim();
        if (exchangeUrl !== undefined) { RnsClient._cfg.exchangeUrl = exchangeUrl; sSet("exchangeUrl", exchangeUrl); }
        if (name !== undefined) { RnsClient._cfg.displayName = name; sSet("displayName", name); }
        if (rfedHash !== undefined) { RnsClient._cfg.rfedNodeHash = rfedHash; sSet("rfedNodeHash", rfedHash); }
        if (rfedPubKey !== undefined) { RnsClient._cfg.rfedNodePubKey = rfedPubKey; sSet("rfedNodePubKey", rfedPubKey); }
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

    // ===== DISTRO IDENTITY MANAGEMENT =====

    _generateDistro() {
        if (!confirm("Generate a new distro identity? This will create a new shared identity for receiving messages on multiple devices.")) return;
        try {
            const hash = DistroManager.generate();
            console.log(`[distro] Generated new identity: ${hash}`);
            RnsClient._registerDistro();
            this.render();
        } catch(e) {
            alert("Failed to generate distro identity: " + e.message);
        }
    },

    _forgetDistro() {
        if (!confirm("Forget the current distro identity? You will no longer receive distro messages on this device. Other devices with the same identity are unaffected.")) return;
        RnsClient._unregisterDistro();
        DistroManager.forget();
        console.log("[distro] Identity forgotten");
        this.render();
    },

    _showDistroImport() {
        const uri = prompt("Paste the rfed-distro-id:// URI or 128-char hex private key:");
        if (!uri) return;
        try {
            const hash = DistroManager.importUri(uri.trim());
            console.log(`[distro] Imported identity: ${hash}`);
            RnsClient._registerDistro();
            this.render();
        } catch(e) {
            alert("Failed to import: " + e.message);
        }
    },

    _showDistroShare() {
        const uri = DistroManager.exportUri();
        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "📤 Share Distro Identity"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });

        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Distro Identity Hash"),
                h("div", { className: "mono-value", style: { fontSize: "13px" } }, DistroManager.hash),
                h("button", { className: "btn btn-secondary btn-block", style: { marginTop: "8px" },
                    onClick: () => { navigator.clipboard.writeText(DistroManager.hash).catch(() => {}); } },
                    "📋 Copy Hash"),
            ),
        );

        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Distro Contact (share with senders)"),
                h("div", { className: "field-hint", style: { marginBottom: "8px" } },
                    "Share this with anyone who wants to send you distro messages. It contains the public key only — safe to share openly."),
                h("div", { className: "mono-value", style: { fontSize: "11px", wordBreak: "break-all" } }, DistroManager.exportLxmaUri()),
                h("button", { className: "btn btn-primary btn-block", style: { marginTop: "8px" },
                    onClick: () => { navigator.clipboard.writeText(DistroManager.exportLxmaUri()).catch(() => {}); } },
                    "📋 Copy Contact URI"),
            ),
        );

        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Private Key (keep secret)"),
                h("div", { className: "field-hint", style: { marginBottom: "8px" } },
                    "⚠️ This contains the private key. Share it only with your own devices. Anyone with this key can read all distro messages."),
                h("div", { className: "mono-value", style: { fontSize: "11px", wordBreak: "break-all" } }, uri),
                h("button", { className: "btn btn-secondary btn-block", style: { marginTop: "8px" },
                    onClick: () => { navigator.clipboard.writeText(uri).catch(() => {}); } },
                    "📋 Copy Private Key URI"),
            ),
        );

        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Send via LXMF"),
                h("div", { className: "field-hint", style: { marginBottom: "8px" } },
                    "Send the identity encrypted to another Retichat user. They will be prompted to import it."),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "distro-lxmf-dest" }, "Recipient LXMF Address"),
                    h("input", { id: "distro-lxmf-dest", type: "text",
                        placeholder: "32-char hex destination hash" }),
                ),
                h("button", { className: "btn btn-primary btn-block", style: { marginTop: "8px" },
                    onClick: () => this._sendDistroViaLxmf() },
                    "📨 Send Encrypted Identity"),
            ),
        );

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);
    },

    _sendDistroViaLxmf() {
        const destHash = document.getElementById("distro-lxmf-dest")?.value?.trim();
        if (!destHash || destHash.length !== 32) {
            alert("Enter a valid 32-char destination hash");
            return;
        }
        const contact = ContactStore.get(destHash);
        if (!contact || !contact.publicKey) {
            alert("Contact not found or public key not yet received. Add the contact first and wait for their announce.");
            return;
        }
        if (!DistroManager.has) {
            alert("No distro identity to send");
            return;
        }

        // Build the payload: private key as hex (already encrypted by LXMF layer)
        const privateKeyHex = DistroManager.exportHex();

        // Build LXMF message with the private key in fields (LXMF encrypts the whole message)
        const recipientIdentity = Identity.fromPublicKey(Buffer.from(contact.publicKey, "hex"));
        const contactDest = RnsClient._rns.registerDestination(recipientIdentity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
        const FIELD_DISTRO_ID = 0x0D; // Custom field for distro identity transfer
        const msg = new LXMessage();
        msg.sourceHash = RnsClient._lxmfRouter.destination.hash;
        msg.destinationHash = contactDest.hash;
        msg.title = "Distro Identity";
        msg.content = "Import this distro identity to receive messages on all your devices.";
        msg.fields = new Map();
        msg.fields.set(FIELD_DISTRO_ID, privateKeyHex);
        const packed = msg.pack(IdMgr.id, true);

        // Send directly
        try {
            const sentPacketHash = contactDest.send(packed);
            if (sentPacketHash) {
                alert("Distro identity sent! The recipient will be prompted to import it.");
                console.log(`[distro] Sent identity to ${destHash.slice(0,12)}...`);
            } else {
                alert("Failed to send — no packet hash returned");
            }
        } catch(e) {
            alert("Failed to send: " + e.message);
            console.error("[distro] Send failed:", e);
        }
    },

    /** Add Contact modal */
    _renderAddContactModal() {
        let inputValue = "";

        const doAdd = () => {
            const raw = inputValue.trim();
            if (!raw) { alert("Enter a destination hash."); return; }
            let isDistro = false;
            let publicKey = null;
            let hash = raw.toLowerCase();

            // Parse lxma:// URI (contains public key)
            if (hash.startsWith("lxma://")) {
                isDistro = true;
                hash = hash.slice(7); // Remove "lxma://"
                const colonIdx = hash.indexOf(":");
                if (colonIdx > -1) {
                    publicKey = hash.slice(colonIdx + 1);
                    hash = hash.substring(0, colonIdx);
                }
            }
            // Parse lxmf:// URI (no public key)
            else if (hash.startsWith("lxmf://")) {
                hash = hash.slice(7); // Remove "lxmf://"
                const colonIdx = hash.indexOf(":");
                if (colonIdx > -1) hash = hash.substring(0, colonIdx);
            }

            hash = hash.replace(/[^0-9a-f]/g, "");
            if (hash.length !== 32) {
                alert("Destination hash must be exactly 32 hex characters.\n\nGot: " + (hash || "(empty)") + " (" + hash.length + " chars)");
                return;
            }
            try {
                ContactStore.add(hash, isDistro, publicKey);
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

    // ===== UNIFIED NEW CONVERSATION MODAL (matching iOS) =====

    /** Unified modal with segmented picker: Direct | Group | Channel */
    _renderNewConversationModal() {
        const tab = this.state.newConvTab || "direct";

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showNewConversation = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet nc-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "New Conversation"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showNewConversation = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body nc-form-body", id: "nc-form-body" });

        body.appendChild(
            h("div", { className: "segmented-picker" },
                ...[
                    { key: "direct", label: "Direct" },
                    { key: "group", label: "Group" },
                    { key: "channel", label: "Channel" },
                ].map(t => h("button", {
                    className: "seg-btn" + (tab === t.key ? " active" : ""),
                    "data-tab": t.key,
                    onClick: () => this._switchConvTab(t.key),
                }, t.label)),
            ),
        );

        // Pinned input area (name/hash field)
        const formTop = h("div", { id: "nc-form-top", className: "nc-form-top" });
        body.appendChild(formTop);
        // Scrollable content (contacts, members list)
        const formScroll = h("div", { id: "nc-form-scroll", className: "nc-form-scroll" });
        body.appendChild(formScroll);
        // Fixed footer with action button
        const formFooter = h("div", { id: "nc-form-footer", className: "nc-form-footer" });
        body.appendChild(formFooter);

        this._fillConvTab(tab, formTop, formScroll, formFooter);

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);
    },

    /** Switch conversation tab without closing/reopening the modal. */
    _switchConvTab(key) {
        this.state.newConvTab = key;
        const picker = document.querySelector(".segmented-picker");
        if (picker) {
            picker.querySelectorAll(".seg-btn").forEach(btn => {
                const isActive = btn.getAttribute("data-tab") === key;
                btn.className = "seg-btn" + (isActive ? " active" : "");
            });
        }
        const top = document.getElementById("nc-form-top");
        const scroll = document.getElementById("nc-form-scroll");
        const footer = document.getElementById("nc-form-footer");
        if (top && scroll && footer) {
            clear(top);
            clear(scroll);
            clear(footer);
            this._fillConvTab(key, top, scroll, footer);
            const input = top.querySelector("input") || scroll.querySelector("input");
            if (input) setTimeout(() => input.focus(), 100);
        }
    },

    /** Fill top, scroll, and footer for the given tab. */
    _fillConvTab(tab, top, scroll, footer) {
        switch (tab) {
            case "direct":  this._renderDirectForm(top, scroll, footer); break;
            case "group":   this._renderGroupForm(top, scroll, footer); break;
            case "channel": this._renderChannelForm(top, scroll, footer); break;
        }
    },

    /** Direct tab: hash input (top), contact list (scroll), Add button (footer). */
    _renderDirectForm(top, scroll, footer) {
        let inputValue = "";

        const doAdd = () => {
            const raw = inputValue.trim();
            if (!raw) return;
            let isDistro = false;
            let publicKey = null;
            let hash = raw.toLowerCase();

            // Parse lxma:// URI (contains public key)
            if (hash.startsWith("lxma://")) {
                isDistro = true;
                hash = hash.slice(7); // Remove "lxma://"
                const colonIdx = hash.indexOf(":");
                if (colonIdx > -1) {
                    publicKey = hash.slice(colonIdx + 1);
                    hash = hash.substring(0, colonIdx);
                }
            }
            // Parse lxmf:// URI (no public key)
            else if (hash.startsWith("lxmf://")) {
                hash = hash.slice(7); // Remove "lxmf://"
                const colonIdx = hash.indexOf(":");
                if (colonIdx > -1) hash = hash.substring(0, colonIdx);
            }

            hash = hash.replace(/[^0-9a-f]/g, "");
            if (hash.length !== 32) { alert("Destination hash must be exactly 32 hex characters."); return; }
            try {
                ContactStore.add(hash, isDistro, publicKey);
                this._requestPathForContact(hash);
                this.state.showNewConversation = false;
                this.render();
            } catch(e) { alert(e.message); }
        };

        top.appendChild(
            h("div", { className: "settings-field" },
                h("label", { htmlFor: "nc-direct-hash" }, "Destination Hash"),
                h("input", {
                    id: "nc-direct-hash", type: "text",
                    placeholder: "32-char hex hash or lxma:// URI…",
                    style: { fontFamily: "var(--font-mono)" },
                    onInput: (e) => { inputValue = e.target.value; },
                    onKeydown: (e) => { if (e.key === "Enter") doAdd(); },
                }),
                h("div", { className: "field-hint" }, "Paste a destination hash or lxmf:///lxma:// link."),
            ),
        );

        const contacts = ContactStore.getAll();
        if (contacts.length > 0) {
            scroll.appendChild(
                h("div", { className: "settings-section" },
                    h("h3", {}, "Contacts"),
                    ...contacts.map(c => h("div", {
                        className: "group-member-row",
                        style: { display: "flex", alignItems: "center", gap: "10px", padding: "8px 0", cursor: "pointer", borderBottom: "1px solid var(--border)" },
                        onClick: () => {
                            this.state.showNewConversation = false;
                            this.state.activeHash = c.destHash;
                            this.render();
                        },
                    },
                        h("div", { className: "contact-avatar", style: { width: "32px", height: "32px", fontSize: "14px", flexShrink: 0, color: `hsl(${avatarHue(c.displayName||c.destHash)}, 50%, 65%)`, background: `hsla(${avatarHue(c.displayName||c.destHash)}, 50%, 40%, 0.15)`, borderColor: `hsla(${avatarHue(c.displayName||c.destHash)}, 50%, 65%, 0.2)` } }, (c.displayName||"?")[0].toUpperCase()),
                        h("div", { style: { flex: 1 } },
                            h("div", { style: { fontSize: "14px", fontWeight: 500 } }, esc(c.displayName || "?" + c.destHash.slice(0,8))),
                            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" } }, c.destHash.slice(0,16) + "…"),
                        ),
                    )),
                ),
            );
        }

        footer.appendChild(
            h("button", { className: "btn btn-primary btn-block", onClick: doAdd }, "Add Contact"),
        );
    },

    /** Group tab: name input (top), member list (scroll), Create button (footer). */
    _renderGroupForm(top, scroll, footer) {
        let groupNameInput = "";

        const doCreate = () => {
            const name = groupNameInput.trim();
            if (!name) { alert("Enter a group name."); return; }
            const selected = [];
            scroll.querySelectorAll(".group-member-check:checked").forEach(cb => selected.push(cb.value));
            if (selected.length === 0) { alert("Select at least one member."); return; }
            const group = GroupStore.create(name, selected);
            GroupMsgStore.addSystem(group.groupId, `Group "${name}" created`);
            RnsClient.sendGroupInvites(group.groupId, name, selected)
                .catch(e => console.warn("Group invite send failed:", e.message));
            this.state.showNewConversation = false;
            this.openChat(group.groupId);
        };

        top.appendChild(
            h("div", { className: "settings-field" },
                h("label", { htmlFor: "nc-group-name" }, "Group Name"),
                h("input", {
                    id: "nc-group-name", type: "text",
                    placeholder: "e.g. Family, Work, Project…",
                    onInput: (e) => { groupNameInput = e.target.value; },
                    onKeydown: (e) => { if (e.key === "Enter") doCreate(); },
                }),
            ),
        );

        const contacts = ContactStore.getAll();
        scroll.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Members"),
                h("div", { className: "field-hint", style: { marginBottom: "8px" } }, "Select contacts to invite. You'll be added automatically."),
                ...(contacts.length === 0
                    ? [h("p", { style: { color: "var(--text-muted)", fontSize: "13px" } }, "No contacts yet. Add contacts first.")]
                    : contacts.map(c => h("label", { className: "group-member-row", style: { display: "flex", alignItems: "center", gap: "10px", padding: "8px 0", cursor: "pointer", borderBottom: "1px solid var(--border)" } },
                        h("input", { type: "checkbox", className: "group-member-check", value: c.destHash }),
                        h("div", { className: "contact-avatar", style: { width: "32px", height: "32px", fontSize: "14px", flexShrink: 0, color: `hsl(${avatarHue(c.displayName||c.destHash)}, 50%, 65%)`, background: `hsla(${avatarHue(c.displayName||c.destHash)}, 50%, 40%, 0.15)`, borderColor: `hsla(${avatarHue(c.displayName||c.destHash)}, 50%, 65%, 0.2)` } }, (c.displayName||"?")[0].toUpperCase()),
                        h("div", { style: { flex: 1 } },
                            h("div", { style: { fontSize: "14px", fontWeight: 500 } }, esc(c.displayName || "?" + c.destHash.slice(0,8))),
                            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" } }, c.destHash.slice(0,16) + "…"),
                        ),
                        c.publicKey ? null : h("span", { style: { fontSize: "11px", color: "var(--warning)" } }, "⏳"),
                    ))),
            ),
        );

        footer.appendChild(
            h("button", { className: "btn btn-primary btn-block", onClick: doCreate }, "Create Group"),
        );
    },

    /** Channel tab: sub-picker Public|Private + name input (top),
     *  info (scroll), Join button (footer). */
    _renderChannelForm(top, scroll, footer) {
        let channelNameInput = "public.";

        const rfedNodeHash = RnsClient.cfg?.rfedNodeHash || "";
        const hasRfed = rfedNodeHash.length === 32;
        const vis = this.state.channelVis || "public";

        const genPrivatePrefix = () => {
            return [...Array(8)].map(() => Math.floor(Math.random()*16).toString(16)).join('') + ".";
        };

        const applyPrefix = (mode) => {
            this.state.channelVis = mode;
            const inp = document.getElementById("nc-channel-name");
            if (!inp) return;
            // Preserve anything after the first dot segment
            const current = inp.value;
            const dotIdx = current.indexOf(".");
            const suffix = dotIdx >= 0 ? current.slice(dotIdx + 1) : "";
            if (mode === "public") {
                inp.value = suffix ? "public." + suffix : "public.";
            } else {
                const key = genPrivatePrefix();
                inp.value = suffix ? key + suffix : key;
            }
            channelNameInput = inp.value;
            // Update sub-picker buttons
            const subPicker = document.querySelector(".channel-vis-picker");
            if (subPicker) {
                subPicker.querySelectorAll(".seg-btn").forEach(btn => {
                    const isActive = btn.getAttribute("data-vis") === mode;
                    btn.className = "seg-btn" + (isActive ? " active" : "");
                });
            }
        };

        const doJoin = () => {
            const inp = document.getElementById("nc-channel-name");
            const name = (inp?.value || channelNameInput).trim();
            if (!name) { alert("Enter a channel name."); return; }
            RnsClient.joinChannel(name).then((channel) => {
                this.state.showNewConversation = false;
                this.openChat(channel.channelName, false);
            }).catch(e => alert("Failed to join channel: " + e.message));
        };

        // Channel name input
        top.appendChild(
            h("div", { className: "settings-field" },
                h("label", { htmlFor: "nc-channel-name" }, "Channel Name"),
                h("input", {
                    id: "nc-channel-name", type: "text",
                    value: "public.",
                    placeholder: "public.general…",
                    onInput: (e) => { channelNameInput = e.target.value; },
                    onKeydown: (e) => { if (e.key === "Enter") doJoin(); },
                }),
            ),
        );

        // Smaller Public | Private sub-picker below the input
        top.appendChild(
            h("div", { className: "segmented-picker segmented-picker-sm channel-vis-picker" },
                ...[
                    { vis: "public", label: "Public" },
                    { vis: "private", label: "Private" },
                ].map(t => h("button", {
                    className: "seg-btn" + (vis === t.vis ? " active" : ""),
                    "data-vis": t.vis,
                    onClick: () => applyPrefix(t.vis),
                }, t.label)),
            ),
        );

        if (hasRfed) {
            scroll.appendChild(
                h("div", { className: "settings-field" },
                    h("label", {}, "RFed Node"),
                    h("div", { style: { fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--text-muted)", wordBreak: "break-all" } }, rfedNodeHash),
                ),
            );
        }

        footer.appendChild(
            h("button", { className: "btn btn-primary btn-block", onClick: doJoin,
                disabled: !hasRfed, title: hasRfed ? "" : "Configure an RFed node in Settings first" },
                "Join / Create"),
        );
    },

    /** Group Info modal — shows members, allow accept/decline/leave */
    _renderGroupInfoModal() {
        const g = GroupStore.get(this.state.groupInfoId);
        if (!g) { this.state.showGroupInfo = false; this.render(); return; }
        const isPending = g.groupStatus === "pending";

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showGroupInfo = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, isPending ? "📩 Group Invite" : "👥 Group Info"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showGroupInfo = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });

        // Group name header
        body.appendChild(
            h("div", { style: { marginBottom: "16px" } },
                h("div", { style: { fontSize: "18px", fontWeight: 700 } }, esc(g.groupName || "Group")),
                h("div", { style: { fontSize: "12px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "4px" } },
                    `ID: ${g.groupId.slice(0,16)}…`),
            ),
        );

        // Pending actions
        if (isPending) {
            body.appendChild(
                h("div", { className: "btn-row", style: { marginBottom: "16px" } },
                    h("button", { className: "btn btn-primary",
                        onClick: () => { this.state.showGroupInfo = false; this.render(); this._acceptGroupInvite(g.groupId); } },
                        "✅ Accept Invite"),
                    h("button", { className: "btn btn-danger",
                        onClick: () => { this.state.showGroupInfo = false; this.render(); this._declineGroupInvite(g.groupId); } },
                        "❌ Decline"),
                ),
            );
        }

        // Members list
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, `Members (${g.members?.size ?? 0})`),
                ...[...g.members.entries()].map(([hash, status]) => {
                    const contact = ContactStore.get(hash);
                    const displayName = contact?.displayName || (hash === ownLxmfDestinationHash() ? "You" : hash.slice(0,12) + "…");
                    const statusLabel = status === "accepted" ? "" :
                        status === "invited" ? " ⏳" :
                        status === "left" ? " 🚪" : "";
                    return h("div", {
                        style: { display: "flex", alignItems: "center", gap: "10px", padding: "6px 0", borderBottom: "1px solid var(--border)" },
                    },
                        h("div", {
                            className: "contact-avatar",
                            style: { width: "28px", height: "28px", fontSize: "12px",
                                color: `hsl(${avatarHue(displayName)}, 50%, 65%)`,
                                background: `hsla(${avatarHue(displayName)}, 50%, 40%, 0.15)`,
                                borderColor: `hsla(${avatarHue(displayName)}, 50%, 65%, 0.2)` },
                        }, displayName.charAt(0).toUpperCase()),
                        h("div", { style: { flex: 1, fontSize: "13px" } },
                            esc(displayName) + statusLabel),
                        h("div", { style: { fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" } },
                            hash.slice(0,10) + "…"),
                    );
                }),
            ),
        );

        // Leave button (only for active groups)
        if (!isPending) {
            body.appendChild(
                h("div", { style: { marginTop: "16px" } },
                    h("button", { className: "btn btn-danger btn-block",
                        onClick: () => { this.state.showGroupInfo = false; this.render(); this._leaveGroup(g.groupId); } },
                        "🚪 Leave Group"),
                ),
            );
        }

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);
    },

    // ===== CHANNEL MODALS =====

    /** Channel Info modal */
    _renderChannelInfoModal() {
        const ch = ChannelStore.get(this.state.channelInfoName);
        if (!ch) { this.state.showChannelInfo = false; this.render(); return; }

        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) { this.state.showChannelInfo = false; this.render(); } },
        });

        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, "📡 Channel Info"),
                h("button", { className: "icon-btn",
                    onClick: () => { this.state.showChannelInfo = false; this.render(); } }, "✕"),
            ),
        );

        const body = h("div", { className: "modal-body" });

        // Channel name
        body.appendChild(
            h("div", { style: { marginBottom: "16px" } },
                h("div", { style: { fontSize: "18px", fontWeight: 700 } }, "#" + ch.channelName),
                h("div", { style: { fontSize: "12px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "4px", wordBreak: "break-all" } },
                    `Hash: ${ch.channelHash}`),
            ),
        );

        // Info
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Details"),
                h("div", { className: "settings-row" },
                    h("span", { className: "row-label" }, "RFed Node"),
                    h("span", { className: "row-value", style: { fontFamily: "var(--font-mono)", fontSize: "12px" } },
                        ch.rfedNodeHash?.slice(0,16) + "…" || "default"),
                ),
                h("div", { className: "settings-row" },
                    h("span", { className: "row-label" }, "Stamp Cost"),
                    h("span", { className: "row-value" },
                        ch.stampCost != null ? `${ch.stampCost} bits` : "default"),
                ),
            ),
        );

        // Leave button
        body.appendChild(
            h("div", { style: { marginTop: "16px" } },
                h("button", { className: "btn btn-danger btn-block",
                    onClick: () => {
                        if (!confirm(`Leave #${ch.channelName}?`)) return;
                        RnsClient.leaveChannel(ch.channelName).then(() => {
                            this.state.showChannelInfo = false;
                            if (this.state.activeHash === ch.channelName) this.state.activeHash = null;
                            document.body.classList.remove("narrow-chat-open");
                            this.render();
                        }).catch(e => alert("Failed: " + e.message));
                    } },
                    "🚪 Leave Channel"),
            ),
        );

        sheet.appendChild(body);
        overlay.appendChild(sheet);
        this.root.appendChild(overlay);
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
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId ||
                this.state.showContactInfo || this.state.showNewConversation || this.state.showGroupInfo ||
                this.state.showChannelInfo) return;
            const inActiveChat = this.state.activeHash === peerHash;

            // Proof-only event (msg is null): update status icon in-place.
            if (!msg) {
                if (!inActiveChat) return;
                // Update both DM, group, and channel messages
                if (GroupStore.isGroupChat(peerHash)) {
                    const msgs = GroupMsgStore.get(peerHash);
                    for (const m of msgs) {
                        if (m.dir !== "out") continue;
                        this._updateMsgStatusDOM(peerHash, m.id, m.status);
                    }
                } else if (ChannelStore.get(peerHash)) {
                    const msgs = ChannelMsgStore.get(peerHash);
                    for (const m of msgs) {
                        if (m.dir !== "out") continue;
                        this._updateMsgStatusDOM(peerHash, m.id, m.status);
                    }
                } else {
                    const msgs = MsgStore.get(peerHash);
                    for (const m of msgs) {
                        if (m.dir !== "out") continue;
                        this._updateMsgStatusDOM(peerHash, m.id, m.status);
                    }
                }
                return;
            }

            // New message or group/channel system message: full re-render
            this.render();
            if (inActiveChat) {
                requestAnimationFrame(() => this._scrollChatBottom());
            }
        });

        // Contact list changes — only re-render if not in an active chat.
        ContactStore.onChange(() => {
            if (this.state.view !== "main") return;
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId ||
                this.state.showContactInfo || this.state.showNewConversation || this.state.showGroupInfo ||
                this.state.showChannelInfo) return;
            if (!this.state.activeHash) {
                this.render();
            }
        });

        // Group list changes — same logic
        GroupStore.onChange(() => {
            if (this.state.view !== "main") return;
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId ||
                this.state.showContactInfo || this.state.showNewConversation || this.state.showGroupInfo ||
                this.state.showChannelInfo) return;
            if (!this.state.activeHash) {
                this.render();
            }
        });

        // Channel list changes — same logic
        ChannelStore.onChange(() => {
            if (this.state.view !== "main") return;
            if (this.state.showSettings || this.state.showAddContact || this.state.showShareId ||
                this.state.showContactInfo || this.state.showNewConversation || this.state.showGroupInfo ||
                this.state.showChannelInfo) return;
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
    // ---- Headless harness surface (see test-harnesses/distro-pipeline) ----
    // Everything below drives the real RnsClient; nothing touches the DOM.
    harness: Harness,
    get ready() { return Harness.ready; },
    get inbox() { return Harness.inbox; },
    get events() { return Harness.events; },
    get errors() { return Harness.errors; },

    /** Identity + destination hashes this node answers on. */
    identity() {
        return {
            identityHash: IdMgr.hash,
            publicKey: IdMgr.pubKey,
            lxmfDest: ownLxmfDestinationHash(),
            rfedDeliveryDest: IdMgr.has ? rfedDeliveryDestHash(IdMgr.id) : null,
            status: RnsClient.status,
            exchangeUrl: RnsClient._cfg?.exchangeUrl ?? null,
        };
    },

    /** Announce lxmf.delivery (and rfed.delivery once channels are up). */
    announce() { RnsClient._announce(); return true; },

    /** Register a peer's public key so we can address it without an announce.
     *  With no key supplied, request the path the way the UI add-contact flow
     *  does — otherwise the peer's key only arrives on its next scheduled
     *  announce, which can be minutes away. */
    addPeer(destHash, publicKeyHex) {
        destHash = destHash.toLowerCase().replace(/[^0-9a-f]/g, "");
        ContactStore.add(destHash, false, publicKeyHex || null);
        if (!publicKeyHex) App._requestPathForContact(destHash);
        return ContactStore.get(destHash);
    },

    /** True once a received message contains `marker` (optionally via "direct"|"distro"). */
    got(marker, via) { return Harness.received(marker, via); },

    // ---- Distro ----
    distro() {
        return {
            has: DistroManager.has,
            hash: DistroManager.has ? DistroManager.hash : null,
            pubKey: DistroManager.has ? DistroManager.pubKey : null,
            lxmfDeliveryHash: DistroManager.has ? DistroManager.lxmfDeliveryHash : null,
        };
    },
    async adoptDistro(privHex) {
        DistroManager.importHex(privHex);
        await RnsClient._registerDistro();
        return this.distro();
    },
    async generateDistro() {
        const hash = DistroManager.generate();
        await RnsClient._registerDistro();
        return { hash, privHex: DistroManager.exportHex(), ...this.distro() };
    },
    registerDistro() { return RnsClient._registerDistro(); },
    pullDistro() { return RnsClient._pullDistroMessages(); },

    help() {
        console.log(`
RetichatTest commands:
  .state()        — show connection state, contacts, messages
  .contacts()     — list all contacts with public keys
  .messages(hash) — show messages for contact (or all if no hash)
  .send(hash,msg) — send a test message to contact hash
  .ping(hash)     — check if contact has public key
  .raw()          — dump raw RNS/LXMF internals

Harness (headless):
  .ready          — promise resolving when the interface is online
  .identity()     — own identity + destination hashes
  .inbox          — received messages [{srcHash, content, via}]
  .got(marker)    — true if a message containing marker arrived
  .addPeer(h,pk)  — seed a peer's public key
  .distro()       — distro identity state
  .generateDistro() / .adoptDistro(privHex) / .pullDistro()
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
            lastSeenMs: c.lastSeen || 0,
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
