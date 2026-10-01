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
    channelIdentity,
    channelLxmPack,
    channelLxmUnpack,
    channelComputeStamp,
    rfedDeliveryDestHash,
} from "./lib/rns/reticulum.js";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import { GroupDeliveryEvidence, GroupFallbackRegistry } from "./lib/rns/group_fallback.js";
import DistroManager from "./lib/distro.js";
import { TabLock } from "./lib/tab_lock.js";
import {
    clean as cleanDisplayName,
    cleanAnnounce as cleanAnnounceName,
    decodePayload as decodeDisplayName,
    applyToFields as applyDisplayName,
    acceptMessageNameAt,
    contactName,
    channelPosterName,
    shortHash,
    migrateContact,
    migrateOwnDisplayName,
} from "./lib/display_name.js";
import { NameLedger, ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";
import { applyGroupFields } from "./lib/retichat_field.js";
import { AttachmentStore, attachmentKey, keysOf } from "./lib/attachment_store.js";
import { SendTransfers, propagationFailure } from "./lib/send_progress.js";
import { MAX_ATTACHMENTS, attachmentRefusal, estimatePackedSize, formatSize } from "./lib/attachment_limits.js";
import { ObjectUrls } from "./lib/object_urls.js";
import { FIELD_FILE_ATTACHMENTS, isImageAttachment, mimeForName } from "./lib/rns/lxmf/lxmf.js";
import {
    applyVisibility, filterChannelChars, initialChannelValue, pasteChannelName,
    regenerateRoot, typeChannelName, validateChannelName, visibilityHint,
    channelShareText, channelShareHint,
} from "./lib/channel_name.js";

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
    announceIntervalMs: 300000,
};
// RFed-over-PostInterface can require multiple one-second exchange cycles.
// Explicit implementation exception approved 2026-07-25.
// Timeouts follow RNS's own reference rather than a flat number.
//
// There used to be a single RFED_OPERATION_LIMIT_MS = 10_000 covering link
// establishment, request/response and publish proofs alike. It did not just
// bound the wait — it was applied *after* the fact, so a link that established
// in 12s was closed and a response that arrived in 11s was discarded. Work that
// had already succeeded was thrown away because it was slow, which on a polled
// multi-hop relay (one round trip ≈ 4.5s) meant the channel flow could not
// complete even when every hop was healthy.
//
// Link establishment is governed by Link.establishmentTimeout, which already
// mirrors RNS/Link.py:284 — get_first_hop_timeout + PER_HOP * max(1, hops).
// Nothing here may shorten it: the link's own close event is the failure.
//
// Request timeouts mirror RNS/Link.py:509:
//     timeout = rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125
// (RNS/Link.py:82 TRAFFIC_TIMEOUT_FACTOR = 6, RNS/Resource.py:117
// RESPONSE_MAX_GRACE_TIME = 10.)
const TRAFFIC_TIMEOUT_FACTOR = 6;
const RESPONSE_MAX_GRACE_MS = 10_000;

// ── RFed link recovery, ported from the reference LXMF propagation router ───
//
// Establishment over this transport fails sometimes: it is lossy enough that
// rfed's own §1 assert fires on link.establish taking 7-37s, and a single
// dropped LINKREQUEST or LRPROOF ends the attempt. Until 2026-08-17 a failed
// RFed link was terminal for the whole session — _ensureRfedLink rejected, the
// cached entry was dropped, and nothing ever drove the operation again. One
// lost packet silently cost distro registration and pull until a page reload,
// which is exactly the "sometimes it just doesn't work" report.
//
// The reference does NOT solve this with a retry loop (DESIGN_PRINCIPLES §3
// forbids one, and LXMRouter has none). It uses three pieces, ported here:
//
//   1. A state per link, not a silent boolean. LXMRouter.PR_* —
//      PR_LINK_ESTABLISHING / PR_LINK_ESTABLISHED / PR_LINK_FAILED /
//      PR_NO_PATH — so a failure is an inspectable state rather than a
//      swallowed rejection. RFED_LINK_* below are the same states.
//
//   2. A janitor that clears a CLOSED link so the next attempt starts clean:
//      LXMRouter.jobs() — `if outbound_propagation_link.status == CLOSED:
//      outbound_propagation_link = None` plus acknowledge_sync_completion(
//      failure_state=PR_LINK_FAILED). Our link close handler does the same.
//
//   3. Re-entry driven by an EVENT, never a timer. The reference records what
//      it wanted (wants_download_on_path_available_from/to, with
//      PR_PATH_TIMEOUT) and re-calls request_messages_from_propagation_node()
//      when the path appears — __request_messages_path_job. Our equivalent
//      event is the service announce, which proves the destination is
//      reachable again. _rfedPending records the wanted operation;
//      _markRfedServiceReady re-drives it. rfed re-announces its services
//      only every 6 hours (RFed-rust destinations.rs
//      SERVICE_REFRESH_INTERVAL_SECS, since b5ba134 on 2026-09-23; it was
//      15 minutes before), so an intent is re-driven by an announce only when
//      one comes early (rfed restarting) and otherwise expires
//      (RFED_PENDING_TIMEOUT_MS). The persistent links do not rely on it: the
//      exchange coming back and the page events re-drive them
//      (_onPageResume).
//
// So nothing re-attempts on a schedule. A failed operation waits for evidence
// that the service is back, exactly like the reference waits for a path.
// ── rfed.link: one link for all of RFed ──────────────────────────────────
//
// RFed-spec/Link.md. Every legacy destination is also reachable on the
// single `rfed.link` destination, addressed by request path instead of by
// destination hash: the aspect chain with `.` → `/`, plus the verb when the
// chain does not already name it. Payloads and responses are byte-identical;
// only the routing differs. This map is the client's copy of the node's
// `link_session::paths` table — NEVER rename an entry in place, a path is
// hashed into the wire request and a rename is a silent 404 against every
// deployed node.
//
// Migration (Link.md "Migration"): a node that has announced `rfed.link` gets
// every control-plane request on that one link; a node that has not gets the
// legacy per-aspect links, unchanged. So this client works against both.
const RFED_LINK_PATHS = {
    "channel:/rfed/subscribe":                "/channel/subscribe",
    "channel:/rfed/unsubscribe":              "/channel/unsubscribe",
    "channel.pull:/rfed/pull":                "/channel/pull",
    "channel.stream:/rfed/channel/stream/open": "/channel/stream/open",
    "distro.register:/rfed/distro/register":  "/distro/register",
    "distro.register:/rfed/distro/announce":  "/distro/announce",
    "distro.register:/rfed/pull":             "/distro/pull",
    "distro.unregister:/rfed/distro/unregister": "/distro/unregister",
    "distro.list:/rfed/distro/list":          "/distro/list",
};
// Node → client paths, pushed as REQUESTS on the bound link. The client's
// response is the node's delivery proof. Both delivery paths start with a
// 16-byte hash meaning different things: the PATH is the discriminator.
const RFED_LINK_PUSH_DELIVERY = "/delivery";
const RFED_LINK_PUSH_LXMF = "/lxmf/delivery";
const RFED_LINK_PUSH_NOTIFY = "/notify";
// A REQUEST carries truncated_hash(path), not the path (RNS/Link.py request()).
const RFED_LINK_PUSH_HASHES = {
    delivery: Cryptography.truncatedHash(Buffer.from(RFED_LINK_PUSH_DELIVERY, "utf8")).toString("hex"),
    lxmf:     Cryptography.truncatedHash(Buffer.from(RFED_LINK_PUSH_LXMF, "utf8")).toString("hex"),
    notify:   Cryptography.truncatedHash(Buffer.from(RFED_LINK_PUSH_NOTIFY, "utf8")).toString("hex"),
};

// The largest request rfed.link takes from the node: RNS
// Destination.max_request_size, which this link checks against a request
// Resource's advertised data size d (Link.maxRequestSize; RNS/Link.py:1036-1042).
// A push is the only request the node sends here (Link.md "Path map — node →
// client"), and the largest one a client must take is an /lxmf/delivery
// carrying a message at LXMF's delivery limit. rfed pushes the propagation
// form it stored (lxmf_propagation.rs dispatch_live_or_notify, distro.rs
// fan-out: stamp already stripped by validate_pn_stamps), inside the request
// Reticulum-rust builds (link.rs request(), as RNS/Link.py request()):
//
//   packed LXMF at LXMF's delivery limit (LXMRouter.DELIVERY_LIMIT KB)   1,000,000 B
//   propagation form: dest(16) | Identity.encrypt(packed[16:]), so        +     96 B
//     ephemeral X25519 key 32 + Token IV 16 + HMAC 32
//     + PKCS7 padding, at most 16
//   request envelope: msgpack [f64 timestamp, bin path hash, bin data]   +     33 B
//     (link_session.rs push_request encodes the payload as Binary):
//     fixarray 1 + f64 (0xcb) 9 + bin8 header 2 + path hash 16
//     + bin32 header 5
//   ----------------------------------------------------------------------------
//   RFED_LINK_MAX_REQUEST_SIZE                                           1,000,129 B
//
// Anything larger is refused at its advertisement (RCL) before a part is
// fetched, so a misbehaving node cannot make the tab hold a multi-MiB split
// push. The node's request then fails and the blob goes to the pull path
// (Link.md "The response is the delivery proof"), where it comes as a
// response, which this limit does not bound.
const LXMF_PROPAGATION_FORM_OVERHEAD = 32 + 16 + 32 + 16;
const RFED_PUSH_REQUEST_ENVELOPE = 1 + 9 + 2 + 16 + 5;
const RFED_LINK_MAX_REQUEST_SIZE = LXMRouter.DELIVERY_LIMIT * 1000
    + LXMF_PROPAGATION_FORM_OVERHEAD + RFED_PUSH_REQUEST_ENVELOPE;

const RFED_LINK_IDLE = "idle";
const RFED_LINK_ESTABLISHING = "establishing";
const RFED_LINK_ESTABLISHED = "established";
const RFED_LINK_FAILED = "link_failed";

// ── Persistent links: the app-links model (app-links/src/lib.rs 414-497) ────
//
// rfed.link (and the legacy rfed.channel.stream link) and the propagation
// link are held open while something is bound to them, like
// AppLinks::open_persistent on iOS and Android. When one that had been
// ESTABLISHED closes under us, it is re-opened once, straight away: a
// one-shot "reopen armed" flag is consumed on the close
// (handle_tracked_outbound_closed / consume_reconnect_arm) and armed again
// by the next successful establishment and by explicit events — any rfed.*
// announce, the page coming back online, becoming visible, or returning
// from the back/forward cache (Android ON_RESUME, iOS scenePhase .active),
// and the exchange coming back after it went down (PostInterface "up" after
// "down": app-links interface_online, lib.rs:1040). Those events also
// re-drive a link that is down (_onPageResume). A re-open that does not
// establish is parked for the service's next announce
// (_rfedDeferUntilAnnounce). No timers, no backoff (DESIGN_PRINCIPLES §3):
// each attempt follows an event.
//
// While the exchange is down no attempt starts at all (_exchangeIsDown): its
// LINKREQUEST would be lost at once (PostInterface.sendData), and the doomed
// attempt, in flight for its whole establishment timeout, would swallow the
// exchange's return, the one event that can bring the link back. This is
// app-links' "no usable interface" failure, which interface_online
// re-attempts.
//
// Only a close we did not ask for re-opens: TIMEOUT (the keepalive watchdog,
// or no answer at all) or DESTINATION_CLOSED (the node's LINKCLOSE). Every
// close this client makes is INITIATOR_CLOSED — disconnect() when another
// tab takes over, and the teardown after an identify refusal (0xF0/0xF1) —
// and never re-opens: a taken-over tab would take rfed's one binding per
// subscriber back from the active tab, and a refusal would become an
// establish, refuse, close loop.
//
// rfed.channel.stream is persistent for completeness: no mapped path opens
// it any more (RFED_LINK_PATHS sends every stream-open over rfed.link).
const RFED_PERSISTENT_KEYS = ["link", "channel.stream"];

// How long a pending operation stays eligible for re-driving, mirroring
// LXMRouter.PR_PATH_TIMEOUT, then it gives up rather than firing against a
// node that has genuinely gone away. Written when services re-announced
// every 15 min, so it spanned a few announce cycles; since 2026-09-23 they
// re-announce every 6 h (RFed-rust destinations.rs
// SERVICE_REFRESH_INTERVAL_SECS), so only an early announce (rfed
// restarting) re-drives an intent before it expires.
const RFED_PENDING_TIMEOUT_MS = 45 * 60 * 1000;

/** Reference request timeout for a link, in ms. `rtt` is measured at
 *  establishment; before that is known, fall back to the grace term alone. */
function rfedRequestTimeoutMs(link) {
    const rttMs = Number(link?.rtt) || 0;
    return rttMs * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_MS * 1.125;
}
async function loadConfig() {
    const cfg = { ...DEFAULT_CONFIG };
    let configDisplayName = null;
    try {
        const resp = await fetch("./config.json");
        if (resp.ok) {
            const json = await resp.json();
            if (json.exchangeUrl) cfg.exchangeUrl = json.exchangeUrl;
            // A node's config.json displayName was a default name for every
            // user of that node. There are no placeholder names any more
            // (DISPLAY_NAMES.md §1); it is read only to tell a pre-filled
            // legacy name from one the user typed (OwnNames.finishMigration).
            configDisplayName = typeof json.displayName === "string" ? json.displayName : null;
            if (typeof json.announceIntervalMs === "number") cfg.announceIntervalMs = json.announceIntervalMs;
        }
    } catch(e) {}
    const savedExchangeUrl = sGet("exchangeUrl");
    if (savedExchangeUrl) cfg.exchangeUrl = savedExchangeUrl;
    OwnNames.finishMigration(configDisplayName);
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

// Attachment bytes: IndexedDB, or this tab's memory when IndexedDB cannot be
// opened (lib/attachment_store.js). Never localStorage, which sSet above
// would fail silently on. A message record keeps only each attachment's
// {key, name, mime, size, sha256, field, stored}.
const Attachments = AttachmentStore.open();
// The object URLs the chat shows attachments through, revoked once their
// element has left the page (lib/object_urls.js; swept after each render).
const AttachmentUrls = new ObjectUrls();
/** Groups carry text only: every client's group relay (_performGroupRelay
 *  here, iOS GroupChatManager relay) forwards a message's content alone, so
 *  an attachment would never reach a member served through a relay. */
const GROUP_ATTACHMENT_REFUSAL = "Attachments can't be sent to a group: group messages that are relayed carry "
    + "text only, in every Retichat client, so some members would never get them. Send it in a direct chat.";

/** Delete the attachment bytes of message records that are going away (a
 *  conversation deleted, the oldest messages trimmed). A failed delete is
 *  reported, never swallowed. */
function discardAttachments(records) {
    const keys = keysOf(records);
    if (!keys.length) return;
    Attachments.remove(keys).then((failed) => {
        if (failed.length) console.error(`[attachments] ${failed.length} of ${keys.length} attachment(s) could not be deleted`);
    }, (e) => console.error("[attachments] deleting attachments failed:", e?.message || e));
}

// =========================================================================
//  OWN NAMES — LXMF-rust/DISPLAY_NAMES.md §1 and §6
//
//  Three independent names, all empty by default, none falling back to
//  another, and no placeholder ("Retichat Web"): unset means unset.
//    announce — Announce Display Name: public, in the lxmf.delivery announce
//               (device and distro).
//    message  — Message Display Name: field 0xD1 of messages, sent under the
//               name ledger (§4.1).
//    channel  — Channel Display Name: 0xD1 of channel posts (§4.2).
//  Each is cleaned (§3) when saved, so Settings shows exactly what goes out,
//  and a change takes effect at once, with no reconnect (§6).
// =========================================================================
const OwnNames = {
    announce: null,
    message: null,
    channel: null,
    _legacy: null,

    init() {
        // §3: the announce name is cleaned with the announce rules, so
        // "Anonymous Peer" (MeshChatX's and Columba's placeholder) is never
        // broadcast as a name: it is no name, as in LXMF-rust.
        this.announce = cleanAnnounceName(sGet("announceDisplayName"));
        this.channel = cleanDisplayName(sGet("channelDisplayName"));
        const message = sGet("messageDisplayName");
        const legacy = sGet("displayName");
        if (message === null && typeof legacy === "string") {
            // §5.4: the old display name becomes the Message Display Name.
            // Provisional until the node's config.json default is known
            // (finishMigration), which is dropped like "Retichat Web".
            this._legacy = legacy;
            this.message = migrateOwnDisplayName(legacy, null);
        } else {
            this.message = cleanDisplayName(message);
        }
    },

    /** §5.4: settle the legacy name once config.json has been read. The
     *  Settings field used to be pre-filled with "Retichat Web" or the
     *  node's default, so either one saved means nothing was typed. */
    finishMigration(configDefault) {
        if (this._legacy === null) return;
        this.message = migrateOwnDisplayName(this._legacy, configDefault);
        this._legacy = null;
        sSet("messageDisplayName", this.message ?? "");
        sSet("displayName", null);
    },

    setAnnounce(raw) {
        this.announce = cleanAnnounceName(raw ?? "");
        sSet("announceDisplayName", this.announce ?? "");
        RnsClient.applyAnnounceName();
        return this.announce;
    },

    setMessage(raw) {
        this.message = cleanDisplayName(raw ?? "");
        this._legacy = null;
        sSet("messageDisplayName", this.message ?? "");
        sSet("displayName", null);
        return this.message;
    },

    setChannel(raw) {
        this.channel = cleanDisplayName(raw ?? "");
        sSet("channelDisplayName", this.channel ?? "");
        return this.channel;
    },
};
OwnNames.init();

// The persistent name state of DISPLAY_NAMES.md §4.1, §4.2 and §5.1.
const nameStorage = { get: sGet, set: sSet };
const NameLedgerStore = new NameLedger(nameStorage);
const ChannelPostNamesStore = new ChannelPostNames(nameStorage);
const ChannelSenderNamesStore = new ChannelSenderNames(nameStorage);

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

/** iOS groupMessagePolicy (ChatRepository.swift:3066-3070), Android
 *  DeliveryPolicy.groupMessage: an invite is processed when its source
 *  passes the privacy filter (PrivacyFilter.allows), any other group
 *  message when the group exists here. */
function shouldProcessGroupMessage(groupAction, inviterAllowed, groupExists) {
    return groupAction === "invite" ? inviterAllowed : groupExists;
}

// =========================================================================
//  CONTACT STORE — the peers this client holds a row for
//
//  A row is either a contact the user has (added by hand, or a DM
//  conversation) or a hidden row (`hidden: true`) kept only to hold what
//  the client learned about a peer it has not added: a group member's or
//  channel poster's public key, and the names DISPLAY_NAMES.md §5.1 stores
//  for any sender, so group labels, member lists and system notices can
//  name them (as iOS and Android keep a plain contact row). Hidden rows are
//  never listed (chat list, contacts, group picker: audit L4); adding the
//  contact or a DM with it lists the row, names and key included.
//
//  Separately, a row is `allowlisted` or not: iOS ContactEntity.isAllowlisted,
//  Android ContactEntity.isAllowlisted. The privacy filter (PrivacyFilter)
//  keeps direct messages and group invites only from allowlisted rows. The
//  user allowlists a peer by adding it (Add Contact, New Conversation, an
//  lxma:// link), by sending it a DM, by creating or accepting a group with
//  it, and by an invite or accept it sends in a group (allow()). A row a
//  message created while the filter was off, a distro sender's and a distro
//  sent-copy recipient's are listed but not allowlisted, as iOS and Android
//  make a plain row for them. Listing and allowlisting are independent: a
//  group member is allowlisted and stays hidden.
// =========================================================================
const ContactStore = {
    _contacts: new Map(),
    _listeners: [],

    /**
     * Contacts hold the names of DISPLAY_NAMES.md §5.1: localName (the
     * user's own), messageName (from 0xD1, with messageNameAt, the LXMF
     * timestamp of the message that last set or cleared it), announceName
     * (from the contact's announce) and legacyName (migrated, origin
     * unknown). None is ever a placeholder; the label on screen is resolved
     * by name(). Records stored before 2026-09-27 had one displayName plus
     * nameCustomized, and the first three-slot build had no legacyName; both
     * are migrated as they load (§5.4).
     *
     * Rows stored before the privacy filter (2026-09-30) have no
     * `allowlisted`: a listed row becomes allowlisted, as Android's
     * migration allowlisted every existing contact (NamesMigration.kt:30-35,
     * the `1` of :99-106), so turning the filter on does not silently drop
     * the user's own contacts. A hidden row (a group member's, a channel
     * poster's, a name-only one) does not: it was never a contact.
     *
     * Consequence, open with James (2026-09-30): Android allowlisted every
     * row, group members' included, and the phones allowlist every member
     * of a group the user creates or accepts. A member of a group the user
     * held before this migration keeps a hidden, not allowlisted row here,
     * so its DMs are dropped (unproved) where a phone that accepted the
     * same group keeps them. Members of groups created or accepted from now
     * on are allowlisted (_acceptGroupInvite, group creation), as on the
     * phones.
     */
    init() {
        const data = sGet("contacts_v2");
        let migrated = false;
        if (Array.isArray(data)) for (const stored of data) {
            const c = migrateContact(stored);
            if ("displayName" in stored || "nameCustomized" in stored || !("localName" in stored) || !("legacyName" in stored)) migrated = true;
            if (!("allowlisted" in stored)) {
                c.allowlisted = !c.hidden && !c.nameOnly;
                migrated = true;
            }
            this._contacts.set(c.destHash, c);
        }
        if (migrated) this._save();
    },

    onChange(fn) { this._listeners.push(fn); fn(this.getAll()); },
    _notify() { const all = this.getAll(); this._listeners.forEach(fn => fn(all)); },

    /** Add a contact by destination hash. Returns the contact. Adding one
     *  that exists keeps everything it holds, names, key and allowlisting
     *  included, and lists a hidden row. It does not allowlist: a peer the
     *  user adds is also passed to allow(). */
    add(destHash, isDistro = false, publicKey = null) {
        return this._put(destHash, isDistro, publicKey, false);
    },

    /** iOS ensureAllowlistedContact (ChatRepository.swift:2984-3000),
     *  Android ensureAllowlistedContact (ChatRepository.kt:277-285): the
     *  privacy filter lets `destHash`'s DMs and invites through from now on.
     *  A peer with no row gets a hidden one (keep), and a name-only row is
     *  one no longer. Listing is left as it is. Returns the row. */
    allow(destHash) {
        const c = this.keep(destHash);
        if (c.allowlisted !== true) {
            c.allowlisted = true;
            this._save();
        }
        return c;
    },

    /** Whether the user allowlisted `destHash` (allow()). */
    allowlisted(destHash) { return this._contacts.get(destHash)?.allowlisted === true; },

    /** The row for a peer the user has not added (a group member, a channel
     *  poster): created hidden when there is none, returned as it is when
     *  there is one. Returns the row.
     *
     *  `nameOnly` marks a row created only to hold the name of a group
     *  sender the client had no row for (_handleGroupMessage). Until
     *  2026-09-30 such a row was the one row that never vouched for an
     *  invite; invites now need an allowlisted source (PrivacyFilter.allows),
     *  which a name-only row never is until allow() clears the mark. Keeping
     *  it for any other reason (its key as a member, a channel post, a send
     *  to it), or adding it, clears the mark, as those paths always created
     *  a row. */
    keep(destHash, publicKey = null, nameOnly = false) {
        const existing = this.get(destHash);
        if (!existing) return this._put(destHash, false, publicKey, true, nameOnly);
        if (existing.nameOnly && !nameOnly) {
            existing.nameOnly = false;
            this._save();
        }
        return existing;
    },

    _put(destHash, isDistro, publicKey, hidden, nameOnly = false) {
        destHash = destHash.toLowerCase().replace(/[^0-9a-f]/g, "");
        if (destHash.length !== 32) throw new Error("Destination hash must be exactly 32 hex characters");
        const existing = this._contacts.get(destHash);
        const contact = {
            destHash,
            localName: existing?.localName ?? null,
            messageName: existing?.messageName ?? null,
            messageNameAt: existing?.messageNameAt ?? null,
            announceName: existing?.announceName ?? null,
            legacyName: existing?.legacyName ?? null,
            publicKey: existing?.publicKey ?? publicKey,
            addedAt: existing?.addedAt ?? Date.now(),
            lastSeen: existing?.lastSeen ?? 0,
            reachable: existing?.reachable ?? null,
            isDistro: existing?.isDistro ?? isDistro,
            hidden,
            nameOnly,
            allowlisted: existing?.allowlisted === true,
        };
        this._contacts.set(destHash, contact);
        this._save();
        this._notify();
        return contact;
    },

    /** Update contact info from an announce (announce name, distro flag,
     *  public key). The announce name is replaced on every announce, and
     *  cleared by one that carries none (§5.1). */
    updateFromAnnounce(destHash, announce) {
        const c = this._contacts.get(destHash);
        if (!c) return;

        c.announceName = LXMF.displayNameFromAppData(announce.appData);
        // §5.1: an announce carrying a name replaces a migrated legacyName.
        if (c.announceName !== null) c.legacyName = null;
        // The lxmf.delivery announce is the source of truth for "distro"
        // (RFed SPEC §17.10): SF_RFED_DISTRO in supported_functionality.
        // No app_data says nothing, so leave the flag as it is.
        if (announce.appData && announce.appData.length > 0) {
            c.isDistro = LXMF.distroFromAppData(announce.appData);
        }
        if (!c.publicKey && announce.identity) {
            c.publicKey = announce.identity.getPublicKey()?.toString("hex") ?? null;
        }
        c.lastSeen = Date.now();
        this._save();
        this._notify();
    },

    /** A contact the user has: a listed row, not a hidden one. */
    isContact(destHash) {
        const c = this._contacts.get(destHash);
        return !!c && !c.hidden;
    },

    /** Any row, hidden or listed: a peer this client knows (its key, its
     *  names). */
    known(destHash) { return this._contacts.has(destHash); },

    /** The label every surface shows for `destHash` (§5.3):
     *  localName ?? messageName ?? announceName ?? 8-hex short hash. */
    name(destHash) { return contactName(this._contacts.get(destHash), destHash); },

    /** The name the contact provides, ignoring the user's own (§5.3 without
     *  localName): what the rename field falls back to when left empty. */
    providedName(destHash) {
        const c = this._contacts.get(destHash);
        return c?.messageName ?? c?.announceName ?? c?.legacyName ?? shortHash(destHash);
    },

    /** The user's own name for a contact (§5.1). Cleaned; an empty value
     *  clears it, so the provided name shows again. */
    setLocalName(destHash, raw) {
        const c = this._contacts.get(destHash);
        if (!c) return null;
        c.localName = cleanDisplayName(raw ?? "");
        this._save();
        this._notify();
        return c.localName;
    },

    /** Apply a received 0xD1 to the row's messageName under the §5.2 table
     *  and order rule: only from a message whose LXMF `timestamp` (seconds)
     *  is newer than messageNameAt, which an accepted one advances, a repeat
     *  included; accepting one drops legacyName (§5.1). Only rows that
     *  exist: a sender with none gets one (keep) where its message is
     *  processed. Returns true when the shown name may have changed. */
    acceptMessageName(destHash, field, signatureState, timestamp) {
        const c = this._contacts.get(destHash);
        if (!c) return false;
        const next = acceptMessageNameAt(c, field, signatureState, timestamp);
        if (next === null) return false;
        const changed = next.messageName !== (c.messageName ?? null) || (c.legacyName ?? null) !== null;
        Object.assign(c, next);
        this._save();
        if (changed) this._notify();
        return changed;
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
    /** Every row, hidden ones included: for work over stored conversations. */
    getAll() { return [...this._contacts.values()].sort((a,b) => b.lastSeen - a.lastSeen); },
    /** The user's contacts, for the surfaces that list them (chat list,
     *  contacts, group picker): hidden rows are left out. */
    listed() { return this.getAll().filter(c => !c.hidden); },

    _save() { sSet("contacts_v2", [...this._contacts.values()]); },
};
ContactStore.init();

/**
 * The identity store LXMF signatures are checked against (DISPLAY_NAMES.md
 * §7; the reference uses RNS.Identity.recall): this client's own device and
 * distro identities, and every contact's stored public key — but only a key
 * that produces the source hash as an lxmf.delivery destination, so a key
 * pasted or learned under the wrong hash never validates anything.
 */
function recallLxmfIdentity(sourceHash) {
    const hex = Buffer.from(sourceHash).toString("hex");
    if (IdMgr.has && hex === ownLxmfDestinationHash()) return IdMgr.id;
    if (DistroManager.has && hex === DistroManager.lxmfDeliveryHash) return DistroManager.identity;
    const publicKey = ContactStore.get(hex)?.publicKey;
    if (!publicKey || !/^[0-9a-f]{128}$/i.test(publicKey)) return null;
    const identity = Identity.fromPublicKey(Buffer.from(publicKey, "hex"));
    return Destination.hash(identity, "lxmf", "delivery").toString("hex") === hex ? identity : null;
}
LXMessage.recall = recallLxmfIdentity;

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
            // The LXMF message hash (lowercase hex), so a stage finds a
            // captionless message by what its sender printed.
            lxmfHash: msg.lxmfHash ?? null,
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
    // Called with the records a trim or a remove drops, so their attachment
    // bytes go with them (discardAttachments, wired after the stores).
    onDiscard: null,
    get(hash) { return sGet("msg_"+hash) ?? []; },
    add(hash, msg) {
        const msgs = this.get(hash);
        msgs.push({ id: Date.now().toString(36)+Math.random().toString(36).slice(2,8), timestamp: Date.now(), ...msg });
        if (msgs.length > 500) this.onDiscard?.(msgs.splice(0, msgs.length-500));
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
    /** Merge `changes` (status, waitFor, …) into a stored message and persist it. */
    update(hash, msgId, changes) {
        const msgs = this.get(hash);
        const m = msgs.find(x => x.id === msgId);
        if (m) { Object.assign(m, changes); sSet("msg_"+hash, msgs); }
        return m;
    },
    remove(hash) {
        this.onDiscard?.(this.get(hash));
        sSet("msg_"+hash, []);
    },
    preview(hash) {
        const msgs = this.get(hash);
        if (!msgs.length) return null;
        const last = msgs[msgs.length-1];
        return (last.dir === "out" ? "You: " : "") + (last.content?.slice(0,60) || attachmentPreview(last));
    },
};

/** What a distro message shows with neither text nor an attachment to show:
 *  a §17.11 sent-copy of a message that carried only attachments (copies are
 *  text only), or one whose attachments this client cannot read. iOS's words
 *  (RfedDistroClient.swift DistroMessageStore.unavailablePlaceholder). */
const DISTRO_ATTACHMENT_PLACEHOLDER = "[Attachment not available via the distro address]";

/** A captionless attachment's line in the chat list: "📎 name". */
function attachmentPreview(m) {
    const first = m?.attachments?.[0];
    if (!first) return "";
    const more = m.attachments.length > 1 ? ` +${m.attachments.length - 1}` : "";
    return `📎 ${first.name}${more}`;
}

// =========================================================================
//  DISTRO DEDUPE
//
//  A distro blob reaches this device on more than one path, and nothing
//  upstream guarantees it arrives once:
//    * live fanout as a DATA packet on rfed.delivery,
//    * the deferred-queue PULL we run on connect and after every register,
//    * a fresh fanout whenever an RFed node re-ingests the same blob from a
//      federation peer (the blob store dedupes, the fanout does not).
//  All of them carry the same LXMF message, so we key on the message itself —
//  (source hash, LXMF timestamp) — rather than on the bytes, which differ
//  between the live and PULL framings. The keys are persisted because a
//  reload must not re-admit blobs still sitting in a node's deferred queue.
// =========================================================================
const DistroSeen = {
    _keys: new Set(),
    _order: [],
    LIMIT: 500,

    init() {
        const stored = sGet("distro_seen");
        if (Array.isArray(stored)) {
            this._order = stored.slice(-this.LIMIT);
            this._keys = new Set(this._order);
        }
    },

    /** True if `key` has been handled before. Records it either way. */
    check(key) {
        if (this._keys.has(key)) return true;
        this._keys.add(key);
        this._order.push(key);
        if (this._order.length > this.LIMIT) {
            for (const k of this._order.splice(0, this._order.length - this.LIMIT)) {
                this._keys.delete(k);
            }
        }
        sSet("distro_seen", this._order);
        return false;
    },

    /** Un-record `key`: the blob was dropped, not kept, so a later copy of it
     *  is judged again rather than answered "already held". */
    forget(key) {
        if (!this._keys.delete(key)) return;
        this._order = this._order.filter(k => k !== key);
        sSet("distro_seen", this._order);
    },

    clear() { this._keys.clear(); this._order = []; sSet("distro_seen", []); },
};
DistroSeen.init();

// =========================================================================
//  LXMF MESSAGE DEDUPE
//
//  A DM whose direct delivery is not proved in time is also propagated, and
//  since 2026-09-24 the propagated copy is the same LXMF message — same
//  timestamp, title, content and fields, so the same message hash — from
//  every client (_propagateMessage here, LXMF-rust propagated_copy on
//  Android and iOS). A recipient can get both: direct, then from the node
//  on its next fetch. LXMF keeps one (LXMRouter.py has_message, LXMF-rust
//  lxmf_delivery), and so does this client: every message the router hands
//  over is keyed on its hash. Persisted, because the propagated copy of a
//  message received before a reload is still waiting on the node after it.
//  Bounded: the oldest hashes are dropped past LIMIT.
// =========================================================================
const LxmfSeen = {
    _keys: new Set(),
    _order: [],
    LIMIT: 2000,

    init() {
        const stored = sGet("lxmf_seen");
        if (Array.isArray(stored)) {
            this._order = stored.slice(-this.LIMIT);
            this._keys = new Set(this._order);
        }
    },

    /** True if the message hash `hashHex` has been handled before. Records it either way. */
    check(hashHex) {
        if (this._keys.has(hashHex)) return true;
        this._keys.add(hashHex);
        this._order.push(hashHex);
        if (this._order.length > this.LIMIT) {
            for (const k of this._order.splice(0, this._order.length - this.LIMIT)) {
                this._keys.delete(k);
            }
        }
        sSet("lxmf_seen", this._order);
        return false;
    },
};
LxmfSeen.init();

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
    /** Whether `memberHash` is in the member list of any group this client
     *  holds, pending or active, whatever its status. */
    hasMember(memberHash) {
        for (const g of this._groups.values()) if (g.members.has(memberHash)) return true;
        return false;
    },
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
//  PRIVACY FILTER — which received LXMF messages this client keeps
//
//  iOS: UserPreferences.filterStrangers (on by default), allowlistDecision
//  and groupMessagePolicy (ChatRepository.swift:3002-3070), applied in
//  handleIncomingMessage (:1947-1972). Android copies it exactly:
//  DeliveryPolicy.kt, applied in onMessageReceived (ChatRepository.kt
//  :1378-1394). With the filter on, a direct message is kept only from an
//  allowlisted contact (ContactStore.allow); a group invite only from an
//  allowlisted source; any other group message when its group exists here,
//  whoever sent it; a distro identity transfer is offered whoever sent it.
//  Off, everything is kept but group messages for a group this client does
//  not hold. Messages fanned out to the distro address are never filtered:
//  mail to the distro is mail to this person (iOS handleDistroMessage,
//  ChatRepository.swift:2049-2055; Android onDistroMessageReceived,
//  ChatRepository.kt:1436-1437), and _handleDistroBlob does not ask.
//
//  Where the decision is made differs from the phones, on purpose ("drop
//  costs nothing", James 2026-09-30): the LXMF router asks this filter
//  before it spends anything on a message (lib/rns/lxmf/lxmf_router.js
//  acceptsSource / acceptsMessage):
//    1. acceptsSource, on the decrypted bytes, before the proof and the
//       parse. It knows only the source, so it drops what no rule could
//       keep: a source that is neither allowlisted nor a member of a group
//       this client holds. That is the stranger, who then costs no proof,
//       no msgpack, no signature check, no ticket reply and no write.
//    2. acceptsMessage, after the parse and before the proof: the whole
//       rule above, for the sources step 1 let through.
//  A dropped message is never proved and never reaches the router's
//  listeners, so it records nothing, its 0xD1 name included (iOS applies
//  the name only once its policy accepts the message). A link Resource is
//  the exception to "no proof": the Resource protocol proves it on
//  assembly, before the source can be read.
//
//  Departures from iOS, forced by step 1 (the source is all it knows):
//  - a group message for a group this client holds, from a source that is
//    neither allowlisted nor in any group's member list here, is dropped
//    (iOS keeps it: groupMessagePolicy asks only whether the group exists).
//    Legitimate group traffic comes from members, whose hashes the invite
//    lists, so this is a member the local list does not have;
//  - a distro identity transfer from a device that is neither allowlisted
//    nor a co-member is dropped (iOS and Android offer it whoever sent
//    it). Add the sending device first, turn the filter off for the
//    transfer, or paste the key (Identity, Import).
// =========================================================================
const PrivacyFilter = {
    _on: true,

    /** On unless the user turned it off: iOS filterStrangers and Android
     *  filter_strangers both default to true (UserPreferences.swift:192-195). */
    init() { this._on = sGet("filterStrangers") !== false; },

    get on() { return this._on; },

    /** The Settings "Privacy filter" toggle: persisted, and applied to the
     *  next message at once (the router asks at every delivery), as
     *  Android's setCoreFilterStrangers. */
    set(on) {
        this._on = !!on;
        sSet("filterStrangers", this._on);
    },

    /** iOS allowlistDecision(...).isAllowed, Android DeliveryPolicy
     *  .allowlisted: a DM, or a group invite, from `srcHash` (hex) is kept
     *  when the filter is off, or when `srcHash` is an allowlisted row. */
    allows(srcHash) {
        return !this._on || ContactStore.allowlisted(srcHash);
    },

    /** Step 1, for the router (LXMRouter.acceptsSource): may a message from
     *  `sourceHash` (16 bytes, straight from the decrypted plaintext) be
     *  kept by any rule? */
    acceptsSource(sourceHash, path) {
        const src = Buffer.from(sourceHash).toString("hex");
        const accepted = this.allows(src) || GroupStore.hasMember(src);
        if (!accepted) Harness.event("privacy-drop", { src: src.slice(0, 12), path, at: "source" });
        return accepted;
    },

    /** Step 2, for the router (LXMRouter.acceptsMessage): is this parsed
     *  message kept? */
    acceptsMessage(lxmfMsg, path) {
        const src = Buffer.from(lxmfMsg.sourceHash ?? []).toString("hex");
        let accepted;
        if (LXMF.distroTransferKeyFromFields(lxmfMsg.fields) !== null) {
            // An offer the user answers, checked before the allowlist on iOS
            // (handleIncomingMessage, ChatRepository.swift:1926-1933) and
            // Android (onMessageReceived, ChatRepository.kt:1365-1373).
            accepted = true;
        } else {
            const group = LXMessage.extractGroupFields(lxmfMsg.fields);
            accepted = group?.groupId
                ? shouldProcessGroupMessage(group.groupAction, this.allows(src), GroupStore.get(group.groupId) !== null)
                : this.allows(src);
        }
        if (!accepted) Harness.event("privacy-drop", { src: src.slice(0, 12), path, at: "message" });
        return accepted;
    },
};
PrivacyFilter.init();

// =========================================================================
//  GROUP MESSAGE STORE — per-group messages
// =========================================================================
const GroupMsgStore = {
    // As MsgStore.onDiscard: the attachment bytes of dropped records go too.
    onDiscard: null,
    get(groupId) { return sGet("gmsg_"+groupId) ?? []; },
    add(groupId, msg) {
        const msgs = this.get(groupId);
        msgs.push({ id: Date.now().toString(36)+Math.random().toString(36).slice(2,8), timestamp: Date.now(), ...msg });
        if (msgs.length > 500) this.onDiscard?.(msgs.splice(0, msgs.length-500));
        sSet("gmsg_"+groupId, msgs);
        return msgs[msgs.length-1];
    },
    updateStatus(groupId, msgId, newStatus) {
        const msgs = this.get(groupId);
        const m = msgs.find(x => x.id === msgId);
        if (m) { m.status = newStatus; sSet("gmsg_"+groupId, msgs); }
        return m;
    },
    /** Merge `changes` (status, waitFor, …) into a stored message and persist it. */
    update(groupId, msgId, changes) {
        const msgs = this.get(groupId);
        const m = msgs.find(x => x.id === msgId);
        if (m) { Object.assign(m, changes); sSet("gmsg_"+groupId, msgs); }
        return m;
    },
    /** A system notice. `actor`, when given, is the hash of the member it
     *  is about: it is stored as a hash and named when shown
     *  (systemMessageText), never frozen into the text (DISPLAY_NAMES.md
     *  §5.3), so a name learned later, or a rename, reaches old notices. */
    addSystem(groupId, text, actor = null) {
        return this.add(groupId, actor
            ? { dir: "system", content: text, actor, status: "delivered" }
            : { dir: "system", content: text, status: "delivered" });
    },
    remove(groupId) {
        this.onDiscard?.(this.get(groupId));
        sSet("gmsg_"+groupId, []);
    },
    preview(groupId, systemText = (m) => m.content) {
        const msgs = this.get(groupId);
        if (!msgs.length) return null;
        const last = msgs[msgs.length-1];
        if (last.dir === "system") return systemText(last)?.slice(0,60) ?? "";
        return (last.dir === "out" ? "You: " : "") + (last.content?.slice(0,60) || attachmentPreview(last));
    },
    /** Notices stored before 2026-09-27 had the member's name frozen into the
     *  text ("?1a2b3c4d joined the group"). Give each one whose member can be
     *  identified an actor hash, so it is named when shown like a new one
     *  (§5.3). One pass per page load; a notice that cannot be matched to
     *  exactly one member keeps its text. */
    migrateLegacyNotices(groups, nameOf) {
        for (const g of groups) {
            const members = [...g.members.keys()];
            const msgs = this.get(g.groupId);
            let changed = false;
            for (const m of msgs) {
                if (m.dir !== "system" || m.actor) continue;
                const found = legacyNoticeActor(m.content, members, nameOf);
                if (!found) continue;
                m.actor = found.actor;
                m.content = found.content;
                changed = true;
            }
            if (changed) sSet("gmsg_"+g.groupId, msgs);
        }
    },
};
GroupMsgStore.migrateLegacyNotices(GroupStore.getAll(), (hash) => ContactStore.name(hash));
MsgStore.onDiscard = discardAttachments;
GroupMsgStore.onDiscard = discardAttachments;

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
    _annTimer: null,
    _rfedLinks: new Map(),
    _rfedLinkPromises: new Map(),
    _rfedServiceReady: new Set(),
    _rfedServiceWaiters: new Map(),
    // Per-aspect link state and the operation waiting on it, mirroring the
    // reference LXMF propagation router. See RFED_LINK_* and _rfedPending.
    _rfedLinkState: new Map(),
    _rfedPending: new Map(),
    _rfedServicePathsRequested: false,
    _propagationPathRequested: false,
    _propagationInitialized: false,
    // Persistent links (RFED_PERSISTENT_KEYS): the keys whose one-shot
    // re-open is armed, and the count of rfed.link establishments. A channel
    // is pulled once per rfed.link generation (_rfedPullState .gen), as
    // Android's rfedLinkGeneration and iOS's ConversationView do.
    _rfedReopenArmed: new Set(),
    _rfedLinkGeneration: 0,
    _propReopenArmed: false,
    _distroPullInFlight: null,
    _pageHooks: null,
    _rfedOpenedChannelHashes: new Set(),
    // channelHash → { inFlight, morePending, gen }: gen is the rfed.link
    // generation of the last pull that completed.
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
    _propLinkUpWaiters: [],      // _whenPropagationLinkUp: {resolve, reject}
    _channelsInitialized: false,
    _channelsResubscribed: false,
    _pendingTickets: new Map(),  // ticket → {contactHash, messageId}
    _pendingPacketHashes: new Map(),  // provedPacketHash (hex) → {contactHash, messageId, onProof?, dm?}
    _pendingTimeouts: new Map(),  // messageId → timeoutId
    // The initialization-complete signal (DESIGN_PRINCIPLES §5): false until
    // this connection's exchange interface has registered, reset by
    // disconnect(). A DM or group message sent before it is stored "queued"
    // (waitFor "init") and dispatched by _dispatchQueued() when it flips.
    _initialized: false,
    _onStatus: [], _onMsg: [],
    // The Resources an outgoing message waits on: its progress (0.10 + 0.90
    // x fraction), the send ceiling's deferral while one moves, and the §1
    // watch for bulk transfers (lib/send_progress.js).
    _sendTransfers: new SendTransfers(),
    _onSendProgress: [],      // (convHash, msgId, progress)
    _onAttachmentState: [],   // (convHash, msgId): an attachment's `stored` changed

    get status() { return this._status; },
    get connType() { return this._connType; },
    get ownHash() { return this._lxmfRouter?.destination?.hash?.toString("hex") ?? null; },

    /**
     * The identity outgoing messages are signed and addressed from.
     *
     * When a distro identity is loaded it wins, unconditionally. The point of a
     * distro is that it is *the* address for a person rather than for one of
     * their devices: replies then land on the distro and RFed fans them out to
     * every device, instead of stranding the conversation on whichever device
     * happened to send. Sending as the device would make the reply reachable on
     * that device only, which defeats the feature.
     *
     * Returns { identity, hash, isDistro }. `hash` is the lxmf.delivery hash
     * that recipients see as the source and reply to.
     */
    sendingIdentity() {
        if (DistroManager.has) {
            return {
                identity: DistroManager.identity,
                hash: DistroManager.lxmfDeliveryHash,
                isDistro: true,
            };
        }
        return { identity: IdMgr.id, hash: this.ownHash, isDistro: false };
    },
    /** The identity whose LXMF delivery hash is `srcHash`, if this client
     *  still holds it: the current sender, or the device under a distro. */
    _signerFor(srcHash) {
        const current = this.sendingIdentity();
        if (current.hash === srcHash) return current;
        if (srcHash && srcHash === this.ownHash) return { identity: IdMgr.id, hash: this.ownHash, isDistro: false };
        return null;
    },
    get cfg() { return this._cfg || DEFAULT_CONFIG; },

    onStatus(fn) { this._onStatus.push(fn); },
    onMessage(fn) { this._onMsg.push(fn); },
    onSendProgress(fn) { this._onSendProgress.push(fn); },
    onAttachmentState(fn) { this._onAttachmentState.push(fn); },

    /**
     * Keep the attachments a received (or sent) message carries: each one's
     * bytes go to the attachment store under "<msgId>:<index>", and the record
     * gets {key, name, mime, size, sha256, field, stored}. `found` is
     * LXMF.attachmentsFromFields's list (its `skipped` count of entries that
     * could not be read is kept too, and so is `fieldsUnreadable`, a fields
     * map that could not be decoded at all: the bubble says so). Called right
     * after the record is added and before anyone is told of it. `stored`
     * starts "saving" and becomes "persisted", "session" or "failed" when the
     * write lands; anything but "persisted" is shown on the bubble.
     * Returns the record as updated.
     */
    _keepAttachments(store, convHash, record, found, fieldsUnreadable = null) {
        const list = found ?? [];
        const metas = list.map((a, i) => ({
            key: attachmentKey(record.id, i),
            name: a.name,
            mime: a.mime,
            size: a.bytes.length,
            sha256: Cryptography.fullHash(a.bytes).toString("hex"),
            field: a.field,
            stored: "saving",
        }));
        const changes = {};
        if (metas.length) changes.attachments = metas;
        if (list.skipped) changes.attachmentsSkipped = list.skipped;
        if (fieldsUnreadable) changes.fieldsUnreadable = true;
        if (!Object.keys(changes).length) return record;
        const updated = store.update(convHash, record.id, changes) ?? Object.assign(record, changes);
        if (list.skipped || fieldsUnreadable) {
            console.warn(`[attachments] message ${record.id} kept without ${fieldsUnreadable ? "its fields (unreadable: " + fieldsUnreadable + ")" : list.skipped + " malformed attachment(s)"}`);
        }
        if (!metas.length) return updated;
        Promise.all(list.map((a, i) => Attachments.put(metas[i].key, a.bytes))).then((results) => {
            const current = store.get(convHash).find(m => m.id === record.id);
            if (!current?.attachments) return;   // deleted meanwhile
            const byKey = new Map(metas.map((m, i) => [m.key, results[i]]));
            let unsaved = false;
            const attachments = current.attachments.map((m) => {
                const r = byKey.get(m.key);
                if (!r) return m;
                if (r.stored !== "persisted") unsaved = true;
                return { ...m, stored: r.stored, ...(r.error ? { storeError: r.error } : {}) };
            });
            store.update(convHash, record.id, { attachments });
            if (unsaved) {
                console.warn(`[attachments] message ${record.id}: not saved to IndexedDB — kept for this session only`);
                this._onAttachmentState.forEach(fn => fn(convHash, record.id));
            }
        });
        return updated;
    },

    /** The stored record with id `msgId`, in a DM or a group: {store, convHash, record}. */
    _findRecord(msgId) {
        for (const c of ContactStore.getAll()) {
            const record = MsgStore.get(c.destHash).find(m => m.id === msgId);
            if (record) return { store: MsgStore, convHash: c.destHash, record };
        }
        for (const g of GroupStore.getAll()) {
            const record = GroupMsgStore.get(g.groupId).find(m => m.id === msgId);
            if (record) return { store: GroupMsgStore, convHash: g.groupId, record };
        }
        return null;
    },

    /**
     * The attachments of stored message `msgId`, each read back from where
     * the page keeps it (IndexedDB, or this tab's memory when it is
     * session-only): [{name, size, sha256, mime, field, stored}], [] for a
     * message with none. size and sha256 are of the bytes read back (null
     * when nothing holds them any more). The staging harness's hook
     * (test-harnesses/staging/lib/attach.mjs HOOK_CONTRACT).
     */
    async attachmentsFor(msgId) {
        const found = this._findRecord(msgId);
        const out = [];
        for (const meta of found?.record?.attachments ?? []) {
            const bytes = await Attachments.readBack(meta.key);
            out.push({
                name: meta.name,
                size: bytes ? bytes.length : null,
                sha256: bytes ? Cryptography.fullHash(bytes).toString("hex") : null,
                mime: meta.mime,
                field: meta.field,
                stored: meta.stored,
            });
        }
        return out;
    },

    /**
     * A Resource carrying message `msgId` (to `convHash`): sent on `link`,
     * its progress reported as the message's (_onSendProgress) and counted
     * as transfer activity (_sendTransfers), its end recorded. `label` is
     * its leg, "direct" or "propagated". Resolves or rejects as the Resource
     * does.
     */
    _sendWithProgress(link, data, convHash, msgId, label) {
        const transfer = this._sendTransfers.begin(msgId, `${label} transfer of ${msgId.slice(0, 8)} to ${convHash.slice(0, 8)}`, label);
        return link.sendResource(data, {
            onProgress: (fraction) => {
                const value = this._sendTransfers.progress(transfer, fraction);
                if (value !== null) this._onSendProgress.forEach(fn => fn(convHash, msgId, value));
            },
        }).then(
            (resource) => { this._sendTransfers.end(transfer, true); return resource; },
            (error) => { this._sendTransfers.end(transfer, false, error); throw error; });
    },

    /**
     * Why a DM with these attachments ([{name, bytes}]) cannot be sent, or
     * null (lib/attachment_limits.js): at most MAX_ATTACHMENTS, within LXMF's
     * delivery limit, and within what the propagation node announced it
     * holds in one upload. Checked before anything is stored.
     */
    attachmentRefusal(contact, content, attachments) {
        if (!attachments?.length) return null;
        return attachmentRefusal({
            count: attachments.length,
            packedSize: estimatePackedSize(content, attachments),
            deliveryLimit: LXMRouter.DELIVERY_LIMIT * 1000,
            perSyncKb: this._propagationLimits()?.perSyncKb ?? null,
        });
    },

    /** The FIELD_FILE_ATTACHMENTS value of an outgoing record, from the bytes
     *  this tab holds now (sync: _sendPacket packs in the same tick it is
     *  called). null for a record with none; throws when one is not held. */
    _attachmentFieldNow(record) {
        if (!record?.attachments?.length) return null;
        return record.attachments.map((meta) => {
            const bytes = Attachments.peek(meta.key);
            if (!bytes) throw new Error(`the attachment ${meta.name} is not in memory to send`);
            return [meta.name, bytes];
        });
    },

    /** As _attachmentFieldNow, reading the bytes from the store if need be.
     *  Rejects when the store no longer holds one (a session-only
     *  attachment after a reload). */
    async _attachmentField(record) {
        if (!record?.attachments?.length) return null;
        const field = [];
        for (const meta of record.attachments) {
            const bytes = await Attachments.get(meta.key);
            if (!bytes) throw new Error(`the attachment ${meta.name} is no longer held (it was kept for an earlier session only)`);
            field.push([meta.name, bytes]);
        }
        return field;
    },

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

    /**
     * What this connection takes from its exchange interface, hooked before
     * addInterface() connects it. Each event counts only while `iface` is
     * this connection's: one that lands after disconnect() belongs to the
     * stopped interface.
     */
    _followExchange(iface) {
        const current = () => this._rns?.interfaces?.includes(iface);
        iface.on("registered", () => {
            if (current()) this._onExchangeRegistered();
        });
        // The status dot follows the exchange itself (U6): "up" on its first
        // 200 after a registration or a failure, "down" on a failure. Until
        // 2026-09-25 a 2 s monitor showed online whenever the interface held
        // credentials, so a dead exchange stayed green.
        //
        // The exchange coming back ("up" after a "down", once it had been
        // up) is also an explicit event for the persistent links, the web's
        // interface up-edge (app-links interface_online, lib.rs:1040): an
        // outage long enough to time out rfed.link or the propagation link
        // leaves them down, and nothing else brings them back while the tab
        // stays visible and idle (rfed announces every 6 h). The
        // connection's first "up" is not one: that is initialization, which
        // the registration and the announces drive (§5).
        let wasUp = false;
        let wentDown = false;
        iface.on("up", () => {
            if (!current()) return;
            this._setStatus("online");
            const back = wasUp && wentDown;
            wasUp = true;
            wentDown = false;
            if (back) this._onPageResume("exchange back");
        });
        iface.on("down", () => {
            if (!current()) return;
            this._setStatus("offline");
            wentDown = true;
        });
        iface.on("lost", (lost) => {
            if (current()) this._onPacketsLost(lost);
        });
    },

    async connect() {
        if (!IdMgr.has) throw new Error("No identity");
        // D11: only the tab holding this identity's lock registers with the
        // exchange. A second registration rotates the node's session token
        // and knocks the other tab's session out.
        if (!ActiveTab.held) throw new Error("Retichat is active in another tab");
        this._cfg = await loadConfig();
        // Taken over while the config loaded: disconnect() has already run
        // and the lock is gone, so this connection must not start.
        if (!ActiveTab.held) return;

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
        this._followExchange(iface);
        this._rns.addInterface(iface);
        this._connType = "exchange";

        // Set up LXMF router, with the Announce Display Name its announces
        // carry (DISPLAY_NAMES.md §2.2; nil until the user sets one) and the
        // privacy filter, which it asks before it proves or parses anything
        // (PrivacyFilter). Given to the constructor, so no message can reach
        // the router before the filter is in place.
        this._lxmfRouter = new LXMRouter(this._rns, IdMgr.id, { filter: PrivacyFilter });
        this._lxmfRouter.setAnnounceName(OwnNames.announce);
        this._lxmfRouter.on("message", (lxmfMsg) => {
            const srcHash = lxmfMsg.sourceHash?.toString("hex");
            const content = lxmfMsg.content?.toString() ?? "";
            const title = lxmfMsg.title?.toString() ?? "";
            const ts = lxmfMsg.timestamp;

            // Every message here has passed the privacy filter: the router
            // asked PrivacyFilter before it proved or parsed it, and a
            // dropped one never reaches this handler.
            console.log(`[retichat] 📥 RX message: src=${srcHash?.slice(0,12) ?? "???"}... title="${title.slice(0,40)}" content="${content.slice(0,80)}" ts=${ts} fields=${lxmfMsg.fields?.size ?? 0}`);
            console.log(`[retichat]   ownHash=${RnsClient.ownHash?.slice(0,12)} msg.destHash=${lxmfMsg.destinationHash?.toString("hex")?.slice(0,12)}`);

            if (!srcHash) return;

            // ---- Duplicate message ----
            // The same LXMF message can arrive twice: direct, then as the
            // propagated copy fetched from the node (see LxmfSeen). The second
            // is dropped here, before anything reads it, or a transfer, a group
            // action, a proof or a bubble would run twice. A message without a
            // hash cannot be checked and is processed, never dropped.
            const lxmfHashHex = lxmfMsg.hash ? Buffer.from(lxmfMsg.hash).toString("hex") : null;
            if (!lxmfHashHex) {
                console.log(`[retichat] RX message from ${srcHash.slice(0,12)} has no LXMF hash — processed without the duplicate check`);
            } else if (LxmfSeen.check(lxmfHashHex)) {
                console.log(`[retichat] ↩︎ duplicate LXMF message ${lxmfHashHex.slice(0,12)} from ${srcHash.slice(0,12)} ignored`);
                Harness.event("lxmf-dup", { src: srcHash.slice(0, 12), hash: lxmfHashHex.slice(0, 12) });
                return;
            }

            // ---- Display name (field 0xD1) ----
            // DISPLAY_NAMES.md §5.2, on every path that yields an LXMF
            // message, group messages included: the name belongs to the LXMF
            // source (a relayed group message names the relayer, never
            // GROUP_SENDER), and whether it is taken depends on the
            // signature — validated sets or clears it, a source whose key is
            // not known yet only fills an empty name, an invalid signature
            // changes nothing. The message itself is kept either way, as the
            // reference and the native clients keep it. Only a message newer
            // than the one that last set or cleared the name counts (§5.2
            // order: a propagated copy can land after a later direct one).
            // A sender with no row yet gets one where its message is kept:
            // the DM below, a group message in _handleGroupMessage. The name
            // is taken after the privacy filter's decision, never before: the
            // router asks PrivacyFilter before this handler hears of a
            // message, so a dropped one records no name (iOS applies it only
            // once its policy accepts the message, ChatRepository.swift
            // handleIncomingMessage).
            const nameField = lxmfMsg.displayName; // read from the payload bytes by LXMessage.fromBytes
            const signatureState = lxmfMsg.signatureState ?? "invalid";
            if (!lxmfMsg.signatureValidated) {
                console.log(`[retichat] RX message from ${srcHash.slice(0,12)}: signature ${signatureState}`);
            }
            ContactStore.acceptMessageName(srcHash, nameField, signatureState, lxmfMsg.timestamp);

            // ---- Distro identity transfer detection ----
            // FIELD_CUSTOM_TYPE == "rfed.distro.transfer", key in
            // FIELD_CUSTOM_DATA (RFed SPEC §17.9). Checked BEFORE the ticket
            // check. Field 0x0D is upstream FIELD_EVENT and is not read.
            const distroKeyHex = LXMF.distroTransferKeyFromFields(lxmfMsg.fields);
            if (distroKeyHex !== null) {
                this._handleDistroIdentityTransfer(lxmfMsg, srcHash, distroKeyHex);
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
            // A ticket (0x0C), no content and no attachment: a recipient's
            // reply to the ticket one of our messages carried, proving it got
            // it (LXMF.isDeliveryNotification). A message that carries 0x05,
            // 0x06 or 0x07 is always a message, ticket or not (LXMF-rust
            // 06c40e1): until 2026-09-30 a captionless photo from a sender
            // that includes its ticket was taken for a notification and lost.
            // Only a ticket of ours (LXMF.webTicket) is looked up: the
            // reference's [expires, ticket] is never one.
            if (LXMF.isDeliveryNotification(lxmfMsg.fields, content)) {
                const ticket = LXMF.webTicket(lxmfMsg.fields);
                const pending = ticket ? this._pendingTickets.get(ticket) : null;
                if (pending) {
                    this._pendingTickets.delete(ticket);
                    console.log(`[retichat] ✅ PROOF (LXMF) ticket=${ticket.slice(0,8)}... from ${srcHash.slice(0,12)}`);
                    if (pending.onProof) pending.onProof(pending.messageId);
                    else {
                        MsgStore.updateStatus(pending.contactHash, pending.messageId, "proved");
                        this._onMsg.forEach(fn => fn(lxmfMsg, srcHash));
                    }
                } else {
                    console.log(`[retichat] delivery notification from ${srcHash.slice(0,12)} for a ticket that is not one we are waiting on — not stored`);
                }
                return;
            }

            // The privacy filter has let this DM through (PrivacyFilter): its
            // sender is allowlisted, or the filter is off. Either way the
            // conversation gets a listed row so it appears in the UI; a
            // hidden row (a group member's, a channel poster's) is listed
            // now that there is a conversation. A row made here is not
            // allowlisted (iOS and Android make a plain row for a sender
            // they accept), so a stranger let in while the filter was off is
            // dropped again once it is on, unless the user adds or answers
            // them.
            if (!ContactStore.isContact(srcHash)) {
                console.log(`[rns] 📇 Auto-adding contact: ${srcHash.slice(0,12)}...`);
                ContactStore.add(srcHash);
                // Its name, under the same §5.2 rule as above: a new contact
                // has no key yet, so the source is unknown and the name only
                // fills the empty slot. (A row that existed already took it
                // above; this same timestamp is then not newer, a no-op.)
                ContactStore.acceptMessageName(srcHash, nameField, signatureState, lxmfMsg.timestamp);
            }

            // Its attachments (0x05, 0x06, 0x07; LXMessage.fromBytes read them
            // on every path: direct packet, link packet, link Resource and
            // the propagated /get) go to the attachment store; a captionless
            // one keeps content "" and the bubble shows the attachment.
            const stored = MsgStore.add(srcHash, { dir: "in", content, status: "delivered", srcHash, via: "direct", lxmfHash: lxmfHashHex });
            if (lxmfMsg.attachments?.length || lxmfMsg.attachments?.skipped || lxmfMsg.fieldsUnreadable) {
                this._keepAttachments(MsgStore, srcHash, stored, lxmfMsg.attachments, lxmfMsg.fieldsUnreadable);
            }
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
                    // LXMF/LXMRouter.py get_outbound_propagation_cost(): the
                    // stamp cost is read from the node's announce, not assumed.
                    const costs = this._parsePropagationNodeAnnounce(event.announce.appData);
                    if (costs) {
                        this._cfg.propagationStampCost = costs.stampCost;
                        this._cfg.propagationStampFlexibility = costs.flexibility;
                        sSet("propagationStampCost", String(costs.stampCost));
                        sSet("propagationStampFlexibility", String(costs.flexibility));
                        console.log(`[retichat] 📡 Propagation node stamp cost ${costs.stampCost} (flexibility ${costs.flexibility}) from announce`);
                    }
                    // Its transfer limits, which bound an outgoing message
                    // with attachments (lib/attachment_limits.js).
                    const limits = this._parsePropagationNodeLimits(event.announce.appData);
                    if (limits) {
                        this._cfg.propagationLimits = limits;
                        sSet("propagationLimits", limits);
                        console.log(`[retichat] 📡 Propagation node limits: ${limits.perTransferKb} KB per transfer, ${limits.perSyncKb} KB per sync`);
                    }
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
            ["link"],
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

        // The page events that re-drive the persistent links (online,
        // visible, back from the back/forward cache). Unhooked by
        // disconnect(), so a stopped or taken-over tab drives nothing.
        this._hookPageLifecycle();

        console.log(`[rns] Connecting via ${this._connType} (${(this._rns?.interfaces || []).length} interface(s))...`);
    },

    /**
     * The page events that mean "the network or the user is back", hooked
     * once per connection: window "online", document "visibilitychange" to
     * visible, and "pageshow" from the back/forward cache (persisted). Each
     * one is an explicit event for the persistent links (_onPageResume):
     * Android pulls on ON_RESUME (ConversationScreen.kt:618-635) and
     * re-opens on a network change (ConnectionStateManager.kt:572-585); iOS
     * does both on scenePhase .active (RetichatApp.swift:281-310). A hidden
     * tab's timers are throttled, so its links may have died meanwhile.
     */
    _hookPageLifecycle() {
        if (this._pageHooks || typeof window === "undefined" || !window.addEventListener) return;
        this._pageHooks = [
            [window, "online", () => this._onPageResume("online")],
            [window, "pageshow", (event) => { if (event?.persisted) this._onPageResume("pageshow"); }],
        ];
        if (typeof document !== "undefined" && document.addEventListener) {
            this._pageHooks.push([document, "visibilitychange", () => {
                if (document.visibilityState === "visible") this._onPageResume("visible");
            }]);
        }
        for (const [target, type, listener] of this._pageHooks) target.addEventListener(type, listener);
    },

    _unhookPageLifecycle() {
        for (const [target, type, listener] of this._pageHooks ?? []) target.removeEventListener(type, listener);
        this._pageHooks = null;
    },

    /**
     * The page is back (online, visible, or restored from the cache), or
     * the exchange is (_followExchange): arm every persistent link's
     * one-shot re-open, re-drive the ones that are down, and collect what
     * the node deferred meanwhile on the ones that are up. A link that is
     * coming up, or STALE and waiting on its keepalive watchdog, is left
     * alone: its "established" pulls, and a second link would break rfed's
     * one binding per subscriber. Only the tab holding the identity does
     * anything.
     */
    _onPageResume(trigger) {
        if (!this._rns || !ActiveTab.held) return;
        console.log(`[retichat] Resume (${trigger}): re-arming the persistent links`);
        for (const key of RFED_PERSISTENT_KEYS) this._rfedReopenArmed.add(key);
        this._propReopenArmed = true;

        // The page came back while the exchange is still down (its own
        // check() on the same event decides): a pull on a link that is up
        // would lose its request, and while it waited out its timeout it
        // would take the place of the pull the exchange's return makes
        // (the in-flight guards); a re-drive would be refused. The return
        // (_followExchange) does all of it.
        if (this._exchangeIsDown()) {
            console.log(`[retichat] Resume (${trigger}): the exchange is down — its return re-drives and pulls`);
            return;
        }

        // rfed.link: pull the opened channels and the distro (Android
        // ON_RESUME, iOS scenePhase .active), or bring the link back, whose
        // "established" does the same (_onRfedLinkEstablished).
        const link = this._rfedLinks.get("link");
        if (link?.status === Link.ACTIVE) {
            this._pullOpenedChannels(trigger);
            if (DistroManager.has) this._pullDistroMessages();
        } else {
            this._redriveRfedLink("link", trigger);
        }

        // The propagation link: fetch what is stored for us (iOS
        // pollPropagationNode(force: true) on .active), or bring it back.
        if (this._propLink?.status === Link.ACTIVE) this._fetchPropagatedMessages();
        else this._redrivePropagationLink(trigger);
    },

    _announce() {
        if (!this._lxmfRouter) return;
        // Check if any interface is ready
        const ifaces = this._rns?.interfaces || [];
        const anyReady = ifaces.some(iface => {
            // HTTP exchange: ready once registered, unless its last exchange
            // failed (a down interface drops what it is given).
            if (iface.isRegistered) return !iface.isDown;
            // Direct Sockets / WebSocket: check socket state
            const ws = iface.websocket || iface.socket;
            return ws && (ws.readyState === 1 || (ws.readable && ws.writable));
        });
        if (!anyReady) {
            console.log("[rns] Skipping announce — no interface ready");
            return;
        }
        try {
            // [announce_name | nil, nil, []]: the Announce Display Name only
            // when the user has set one (DISPLAY_NAMES.md §2.2).
            this._lxmfRouter.announce();
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

    /**
     * The propagation node's announce (LXMF/LXMRouter.py
     * get_propagation_node_app_data, validated by LXMF.pn_announce_data_is_valid):
     * msgpack [legacy(false), timebase, node_state, per_transfer_limit,
     * per_sync_limit, [stamp_cost, flexibility, peering_cost], metadata].
     * Returns {stampCost, flexibility} or null when the data is not a valid
     * propagation-node announce.
     */
    _parsePropagationNodeAnnounce(appData) {
        if (!appData || appData.length === 0) return null;
        let data;
        try { data = MsgPack.unpack(Buffer.from(appData)); } catch (e) { return null; }
        if (!Array.isArray(data) || data.length < 7) return null;
        const costs = data[5];
        if (!Array.isArray(costs) || costs.length < 2) return null;
        const stampCost = Number(costs[0]);
        const flexibility = Number(costs[1]);
        if (!Number.isInteger(stampCost) || !Number.isInteger(flexibility) || stampCost < 0 || flexibility < 0) return null;
        return { stampCost, flexibility };
    },

    /**
     * The transfer limits in the propagation node's announce, in KB of
     * 1000 B: [3] per-transfer and [4] per-sync (LXMF/LXMRouter.py
     * get_propagation_node_app_data; LXMF.pn_announce_data_is_valid takes
     * int() of each). Returns {perTransferKb, perSyncKb} or null when the
     * data is not a valid propagation-node announce. What they bind is in
     * lib/attachment_limits.js: the node refuses an upload over per-sync.
     */
    _parsePropagationNodeLimits(appData) {
        if (!appData || appData.length === 0) return null;
        let data;
        try { data = MsgPack.unpack(Buffer.from(appData)); } catch (e) { return null; }
        if (!Array.isArray(data) || data.length < 7) return null;
        const kb = (v) => {
            const n = typeof v === "bigint" ? Number(v) : v;
            return typeof n === "number" && Number.isFinite(n) && n >= 0 ? Math.trunc(n) : null;
        };
        const perTransferKb = kb(data[3]);
        const perSyncKb = kb(data[4]);
        if (perTransferKb === null || perSyncKb === null) return null;
        return { perTransferKb, perSyncKb };
    },

    /** The propagation node's announced limits (_parsePropagationNodeLimits),
     *  from this session's announce or the last one stored; null while none
     *  has been heard. */
    _propagationLimits() {
        const known = this._cfg?.propagationLimits ?? sGet("propagationLimits");
        if (!known || typeof known !== "object") return null;
        const ok = (v) => Number.isFinite(v) && v >= 0;
        return ok(known.perTransferKb) && ok(known.perSyncKb) ? known : null;
    },

    /** The stamp target for a propagated message: the node's announced
     *  stamp cost (LXMF mines to the announced cost and the node accepts
     *  cost - flexibility). Until 2026-09-22 this was a hard-coded 13 -
     *  rfed's default cost 16 minus flexibility 3 - which only worked while
     *  the node's policy matched that guess. */
    _propagationStampTarget() {
        const known = this._cfg.propagationStampCost ?? sGet("propagationStampCost");
        // Number(null) is 0, which would mean "no work" for an unknown node.
        if (known !== null && known !== undefined && known !== "") {
            const cost = Number(known);
            if (Number.isInteger(cost) && cost >= 0) return cost;
        }
        return 16; // rfed's default policy, until the node's announce says otherwise
    },

    /** Compute a 32-byte PoW stamp for propagation.
     *  Returns a Promise that resolves to a 32-byte Buffer or null on failure.
     *  Target: the node's announced stamp cost (see _propagationStampTarget). */
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
            // has >= target leading zero bits (stamp_valid uses Identity.full_hash = single SHA256)
            const TARGET_ZERO_BITS = this._propagationStampTarget();
            if (TARGET_ZERO_BITS === 0) {
                console.log(`[retichat] 🔨 Propagation node stamp cost is 0 — no work required`);
                return Buffer.alloc(32);
            }
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
        // Nobody may be waiting on this attempt (_initPropagation starts it
        // and moves on), and disconnect() rejects it all the same: that must
        // not surface as an uncaught error, which it did on every takeover by
        // another tab while the link was coming up (2026-09-25). Callers of
        // _ensurePropagationLink still get the rejection.
        this._propLinkPromise.catch(() => {});

        let established = false;
        link.on("established", () => {
            established = true;
            console.log(`[retichat] 🔗 Propagation link established, rtt=${link.rtt}ms`);
            this._propLinkResolve?.(link);
            this._propLinkPromise = null;
            this._propLinkResolve = null;
            this._propLinkReject = null;
            const upWaiters = this._propLinkUpWaiters.splice(0);
            upWaiters.forEach(waiter => waiter.resolve(link));
            this._onPropagationLinkEstablished(link);
        });

        // A STALE link that hears from the PN again is ACTIVE without being
        // re-established (Link.onPacket), so "established" above never fires
        // for it. A §17.11 sent-copy that queued in _whenPropagationLinkUp
        // while it was STALE is released here, or it would wait for a teardown
        // and re-establishment that may never come, and die with the tab.
        link.on("recovered", () => {
            const upWaiters = this._propLinkUpWaiters;
            if (this._propLink !== link || link.status !== Link.ACTIVE) {
                // Events are delivered a tick late: the link may have been
                // replaced or closed since. The waiters stay queued for the
                // next link's "established".
                if (upWaiters.length) console.log(`[retichat] 🔗 Propagation link recovered but no longer current — ${upWaiters.length} waiter(s) stay queued`);
                return;
            }
            if (upWaiters.length) console.log(`[retichat] 🔗 Propagation link recovered from STALE — releasing ${upWaiters.length} waiter(s)`);
            upWaiters.splice(0).forEach(waiter => waiter.resolve(link));
        });

        link.on("close", () => {
            if (this._propLink !== link) {
                // A superseded link: a STALE one replaced by a new attempt
                // (this function overwrites _propLink), or one disconnect()
                // closed. The attempt and the link are the current link's;
                // the same guard as "recovered" above.
                console.log("[retichat] Superseded propagation link closed");
                return;
            }
            console.log("[retichat] Propagation link closed");
            this._propLinkReject?.(new Error("Propagation link closed before establishment"));
            this._propLinkPromise = null;
            this._propLinkResolve = null;
            this._propLinkReject = null;
            this._propLink = null;
            this._onPropagationLinkClosed(link, established);
        });

        link.establish(propDest);
        console.log(`[retichat] 🔗 Establishing propagation link to ${this._cfg.propagationNodeHash.slice(0,12)}...`);
    },

    /**
     * A new propagation link is up. Its re-open is armed again, and the work
     * that needs it runs in order, each step on the one before it
     * (DESIGN_PRINCIPLES §5), not on a clock:
     *   1. LINKIDENTIFY, so the node authorizes /get (LXMRouter.py
     *      request_messages_from_propagation_node: identify, then request);
     *      identify() puts it on the wire before it returns, and the /get
     *      below follows it on the same link;
     *   2. the copies parked while there was no link (_flushPropagation);
     *   3. /get: fetch what the node stores for us;
     *   4. once that has concluded, /distro/pull when this device holds a
     *      distro.
     * Until 2026-09-30 these ran on fixed 1 s, 5 s and 7 s timers ("to let
     * the link settle").
     */
    async _onPropagationLinkEstablished(link) {
        this._propReopenArmed = true;
        try {
            link.identify(IdMgr.id);
        } catch (e) {
            console.warn(`[retichat] Propagation link identify failed: ${e.message}`);
        }
        this._flushPropagation();
        await this._fetchPropagatedMessages();
        if (DistroManager.has) await this._pullDistroMessages();
    },

    /**
     * The current propagation link closed. One that had been established
     * and closed under us (TIMEOUT: the keepalive watchdog; or
     * DESTINATION_CLOSED: the node's LINKCLOSE) is re-opened once, if armed
     * (the app-links model, RFED_PERSISTENT_KEYS). Anything else waits for
     * an event: the node's next lxmf.propagation announce (_initPropagation),
     * the page or the exchange coming back (_onPageResume), or an upload
     * that needs the link (_ensurePropagationLink). The re-open goes through
     * _redrivePropagationLink, so it starts nothing while the exchange is
     * down; the exchange's return re-drives it. Until 2026-09-30 every close
     * started a timer loop that re-established the link, doubling from 4 s
     * to 30 s and never giving up: an application-level link retry
     * (DESIGN_PRINCIPLES §3).
     */
    _onPropagationLinkClosed(link, established) {
        if (!established) {
            console.log("[retichat] Propagation link attempt closed before establishment — the next lxmf.propagation announce, page resume or exchange return re-drives it");
            return;
        }
        const reason = link.closeReason;
        if (reason === Link.TIMEOUT) {
            console.error(`[retichat] Propagation link ${link.hash?.toString("hex").slice(0,12)} timed out (keepalive)`);
        }
        const unexpected = reason === Link.TIMEOUT || reason === Link.DESTINATION_CLOSED;
        if (!unexpected || !this._rns || !ActiveTab.held) {
            this._propReopenArmed = false;
            return;
        }
        if (!this._propReopenArmed) {
            console.log("[retichat] Propagation link closed; its re-open is not armed — waiting for the next announce or page resume");
            return;
        }
        this._propReopenArmed = false;
        console.log("[retichat] 🔁 Propagation link closed under us — re-opening it once");
        this._redrivePropagationLink("close");
    },

    /**
     * One attempt at the propagation link on an explicit event, when it is
     * down: not while one is up, STALE (its keepalive watchdog decides), or
     * coming up, and not while the exchange is down (_exchangeIsDown: the
     * exchange's return is the event then). Returns whether an attempt
     * started.
     */
    _redrivePropagationLink(trigger) {
        if (!this._rns || !ActiveTab.held) return false;
        if (!this._cfg?.propagationNodePubKey || !this._cfg?.propagationNodeHash) return false;
        if (this._propLink || this._propLinkPromise) return false;
        if (this._exchangeIsDown()) {
            console.log(`[retichat] Propagation link is down, and so is the exchange — its return re-drives the link (${trigger})`);
            return false;
        }
        console.log(`[retichat] 🔗 Propagation link is down — re-driving it (${trigger})`);
        this._establishPropagationLink();
        return true;
    },

    /**
     * Propagate the DMs whose propagated copy was parked because the link
     * was unavailable when their fallback fired (_propagateMessage: status
     * "queued", waitFor "propagation"). Runs from the link's "established"
     * handler. Parked records are persisted, so ones parked before a reload
     * go too. A record that was proved, propagated or failed meanwhile is
     * skipped, and one still "sending" is never touched: it is inside its
     * direct window or already being propagated by its own fallback, and a
     * second upload from here would deliver it twice.
     */
    async _flushPropagation() {
        const link = this._propLink;
        if (!link || link.status !== Link.ACTIVE) return;

        const parked = [];
        for (const contact of ContactStore.getAll()) {
            for (const msg of MsgStore.get(contact.destHash)) {
                if (msg.dir === "out" && msg.waitFor === "propagation") parked.push({ contact, msg });
            }
        }
        parked.sort((a, b) => a.msg.timestamp - b.msg.timestamp);
        for (const { contact, msg } of parked) {
            // Only while the link that fired "established" is up. Once it has
            // closed or been replaced, the rest stay parked for the next
            // "established": uploading them now would start a link attempt
            // per record (_propagateMessage), a retry loop (§3).
            if (this._propLink !== link || link.status !== Link.ACTIVE) {
                console.log(`[retichat] ⏳ Propagation link gone mid-flush — the remaining parked copies wait for the next one`);
                break;
            }
            // Re-read: a proof, or a flush from a later "established", may
            // have settled or claimed it while an earlier upload was mined.
            const stored = MsgStore.get(contact.destHash).find(m => m.id === msg.id);
            if (stored?.waitFor !== "propagation") continue;
            if (stored.status === "proved" || stored.status === "propagated" || stored.status === "failed") continue;
            // Claimed and persisted before the upload, so neither a second
            // "established" nor a reload can propagate it again.
            MsgStore.update(contact.destHash, msg.id, { status: "sending", waitFor: null });
            this._onMsg.forEach(fn => fn(null, contact.destHash));
            this._armSendCeiling(contact.destHash, msg.id);
            console.log(`[retichat] 📡 Flush propagation for ${contact.destHash.slice(0,8)} msg=${msg.id.slice(0,8)}`);
            try {
                await this._propagateMessage(contact, stored);
            } catch (e) {
                console.warn(`[retichat] Propagation flush failed for ${contact.destHash.slice(0,8)}:`, e.message);
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
            const listResp = await this._waitForResponse(link, listReqId);

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

                // A message this client had, delivered or dropped: the node
                // purges it. LXMF does the same with every message a /get
                // returns, whatever lxmf_propagation made of it
                // (LXMRouter.py message_get_response: haves).
                const had = () => {
                    this._propSeenIds.add(Buffer.from(tid).toString("hex"));
                    deliveredIds.push(tid);
                };
                try {
                    const decrypted = IdMgr.id.decrypt(lxmfData.slice(16));
                    if (!decrypted || decrypted.length < 80) { console.log(`[retichat] 📬 [3/4] ${tidHex} decrypt failed`); continue; }
                    // The privacy filter on the decrypted bytes, before any
                    // parse, as the router applies it on every direct path
                    // (LXMRouter.acceptsSource): a stranger's message was
                    // downloaded (its source is inside the ciphertext) but
                    // costs nothing more.
                    if (!this._lxmfRouter.acceptsSource(decrypted.subarray(0, 16), "propagated")) { had(); continue; }

                    // Parsed as the router parses the direct paths: the same
                    // hash, so a copy of one already received is recognised,
                    // and the same signature check against the identity store.
                    // fromBytes alone reads the payload: a fields map msgpack
                    // cannot decode costs the attachments, never the message
                    // (LXMessage.decodePayload). Until 2026-09-30 a msgpack
                    // pre-parse here threw on such a map first, so the
                    // message was lost, never purged, and downloaded again
                    // on every fetch.
                    const message = LXMessage.fromBytes(decrypted, destHash);
                    if (!message) { console.log(`[retichat] 📬 [3/4] ${tidHex} bad payload`); continue; }
                    if (!this._lxmfRouter.acceptsMessage(message, "propagated")) { had(); continue; }
                    console.log(`[retichat] 📬 [3/4] ✅ ${tidHex} from ${message.sourceHash.toString("hex").slice(0,12)}: "${message.content.slice(0,60)}"`);
                    this._lxmfRouter.emit("message", message);
                    had();
                } catch(e) {
                    console.warn(`[retichat] 📬 [3/4] ${tidHex} exception:`, e.message);
                }
            }

            // ── Step 4: Purge delivered ──
            if (deliveredIds.length > 0) {
                console.log(`[retichat] 📬 [4/4] Purging ${deliveredIds.length} delivered...`);
                const haveReqId = link.sendRequest("/get", [null, deliveredIds]);
                await this._waitForResponse(link, haveReqId);
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

    /** Wait for the response to a request sent on the given link; null if
     *  the request fails.
     *
     *  The link's request receipt owns the timeout (RNS/Link.py
     *  RequestReceipt): the reference budget scaled from the link's measured
     *  RTT (rfedRequestTimeoutMs's formula, RNS/Link.py:509) runs until a
     *  response starts to arrive. A response that arrives as a Resource
     *  stops it (RECEIVING), so a large /get is no longer thrown away half
     *  transferred; that transfer's failure, or the link closing, fails the
     *  request at once. Until 2026-09-30 a flat timer here kept running
     *  through the transfer. */
    async _waitForResponse(link, requestId) {
        try {
            return await link.responseFor(requestId);
        } catch (e) {
            console.log(`[retichat] request ${Buffer.from(requestId).toString("hex").slice(0, 12)}: ${e.message}`);
            return null;
        }
    },

    /**
     * Send a DM. The record is stored first, whatever the connection is
     * doing. Until initialization has finished (_initialized: this
     * connection's exchange interface has registered) there is nothing to
     * send it through — before connect(), during loadConfig(), after
     * disconnect() — so it is stored "queued" (waitFor "init") and
     * _dispatchQueued() sends it when the signal fires. It lives in
     * localStorage, so a reload keeps it and the next initialization sends
     * it. After initialization, one sent while the exchange is down is
     * stored "failed" and never sent. Returns the stored record.
     *
     * `attachments` ([{name, bytes}], at most MAX_ATTACHMENTS) go as
     * FIELD_FILE_ATTACHMENTS [[name, bytes], ...] at their original size,
     * as iOS and Android send them. Each one's MIME type is ours, from its
     * name (mimeForName), never one it came with: a picked file's type is
     * whatever the browser guessed (text/html for a .html), and an object
     * URL of that type opened in a tab runs as this page. A message over
     * its limits (attachmentRefusal) throws before anything is stored. Their
     * bytes go to the attachment store with the record, so the bubble shows
     * them and the propagated copy carries the same field.
     */
    sendMessage(contact, content, attachments = []) {
        if (!contact.publicKey) throw new Error("No public key for this contact yet.");
        const refusal = attachments.length ? this.attachmentRefusal(contact, content, attachments) : null;
        if (refusal) throw new Error(refusal);

        console.log(`[retichat] ✉️ SEND to ${contact.destHash.slice(0,12)}... content="${content.slice(0,60)}"${attachments.length ? ` attachments=${attachments.length}` : ""}`);

        // The user wrote to them, so their answer passes the privacy filter.
        // A departure from iOS and Android, asked for with the web's filter
        // (2026-09-30): neither phone allowlists on a send (iOS sendMessage,
        // ChatRepository.swift:1029; Android sendMessage, ChatRepository.kt
        // :507). They allowlist a chat the user starts (iOS createDirectChat
        // :2481, reached from New Chat, QR and links), which the web's Add
        // Contact and New Conversation do too. The difference: replying to
        // a sender kept while the filter was off allowlists it here, and not
        // on the phones.
        ContactStore.allow(contact.destHash);

        // Create the outgoing message record
        ContactStore.touch(contact.destHash);
        // Attachments are kept with the record whatever happens to it next
        // (queued, failed or sent): the bubble shows what the user sent.
        const withAttachments = (record) => attachments.length
            ? this._keepAttachments(MsgStore, contact.destHash, record, attachments.map(a => ({
                name: a.name, mime: mimeForName(a.name), bytes: a.bytes, field: FIELD_FILE_ATTACHMENTS,
            })))
            : record;
        if (!this._initialized) {
            const queued = MsgStore.add(contact.destHash, {
                dir: "out", content, status: "queued", waitFor: "init",
                srcHash: this.sendingIdentity().hash, destHash: contact.destHash,
            });
            // sSet swallows a failed write (storage full): a queued message
            // exists only in storage, so throw and keep it in the composer.
            if (!MsgStore.get(contact.destHash).some(m => m.id === queued.id)) {
                throw new Error("Could not store the message to send when connected (storage full?)");
            }
            console.log(`[retichat] ⏳ Queued for ${contact.destHash.slice(0,8)} until initialization finishes`);
            return withAttachments(queued);
        }
        // D3 (James, 2026-09-25): a send is an immediate act; "it should fail
        // in front of the user and be considered dead". Outside the
        // initialization hold above, a DM with no exchange to leave through
        // fails now, and nothing sends it later.
        if (this._exchangeIsDown()) {
            const failed = MsgStore.add(contact.destHash, {
                dir: "out", content, status: "failed",
                srcHash: this.sendingIdentity().hash, destHash: contact.destHash,
            });
            console.warn(`[retichat] ✗ Not sent to ${contact.destHash.slice(0,8)}: the exchange is down`);
            return withAttachments(failed);
        }
        const outMsg = withAttachments(MsgStore.add(contact.destHash, {
            dir: "out", content, status: "sending",
            srcHash: this.sendingIdentity().hash, destHash: contact.destHash,
        }));
        this._dispatchMessage(contact, outMsg);
        return outMsg;
    },

    /**
     * Dispatch a stored outgoing DM: the direct attempt, the §17.11
     * sent-copy, the propagation fallback and the 30 s ceiling. Runs once
     * per user message — from sendMessage once initialized, or from
     * _dispatchQueued for one queued before that.
     */
    _dispatchMessage(contact, outMsg) {
        const content = outMsg.content;
        // Signed as whoever sends it now, which a record queued before
        // connect() could not know.
        const signer = this.sendingIdentity();
        // DISPLAY_NAMES.md §4.1: whether this message carries the Message
        // Display Name (0xD1) is decided here, once, for the source it is
        // signed as, and kept on the record. The direct send (_sendPacket)
        // and the propagated copy (_propagateMessage) both read it from
        // there, so they carry identical bytes and one message hash — the
        // copy of a message the recipient already has is still a duplicate
        // (LxmfSeen).
        const lxmfName = this._decideMessageName(signer.hash, contact.destHash);
        MsgStore.update(contact.destHash, outMsg.id, { status: "sending", srcHash: signer.hash, lxmfName });
        if (outMsg.status !== "sending") this._onMsg.forEach(fn => fn(null, contact.destHash));

        // The propagated copy goes once: at once when the direct attempt
        // fails (as on Android and iOS, a DIRECT failure starts the copy and
        // is not the bubble's outcome), otherwise after the propagation delay
        // if no proof came. Until 2026-09-24 a direct failure showed the
        // message failed while its copy was still to go.
        let propagationStarted = false;
        const propagate = () => {
            if (propagationStarted) return;
            propagationStarted = true;
            this._propagateMessage(contact, outMsg).catch(error =>
                console.warn(`[retichat] ⚠️ Propagation for ${contact.destHash.slice(0,8)} failed:`, error.message));
        };

        // Send directly to the destination (skip for distro — always use propagation)
        let directDispatched = false;
        if (!contact.isDistro) {
            this._sendPacket(contact.destHash, contact.publicKey, content, outMsg.id,
                (msgId) => {
                    // Direct proof callback: the message is DELIVERED, so the
                    // name it carried is now known to the recipient (§4.1).
                    MsgStore.updateStatus(contact.destHash, msgId, "proved");
                    this._sendTransfers.settle(msgId);
                    this._recordNameDelivered(contact.destHash, msgId);
                    ContactStore.setReachable(contact.destHash, true);
                    console.log(`[retichat] ✅ Direct proof for ${contact.destHash.slice(0,8)}`);
                    this._onMsg.forEach(fn => fn(null, contact.destHash));
                },
                (msgId) => {
                    // Direct send error after the dispatch returned (the
                    // link or resource failed): the copy goes now, and is
                    // still to go. A copy that went earlier may have failed
                    // already: then nothing is left to deliver it, and this
                    // failure is its outcome now, not the ceiling's later.
                    // One that throws out of _sendPacket never left, and
                    // fails as before (see the §17.11 note below).
                    if (!directDispatched) { this._failSending(contact.destHash, msgId); return; }
                    const copyWentEarlier = propagationStarted;
                    propagate();
                    const nothingLeft = this._sendTransfers.legFailed(msgId, "direct");
                    if (copyWentEarlier && nothingLeft) this._failSending(contact.destHash, msgId);
                }
            );
            this._sendTransfers.openLeg(outMsg.id, "direct");
            directDispatched = true;
        }

        // RFed SPEC §17.11: a message sent AS the distro is also copied to the
        // distro, so every other device of the distro shows it as sent. Only
        // once M's dispatch has returned without throwing — a send that
        // throws never leaves, so siblings must not show it (Android sends
        // after messageSendViaAppLinks accepts M, iOS after M is submitted).
        // Once per user message: this function runs once per composer send
        // (directly, or from the queue), and neither the direct attempt, the
        // propagation fallback below nor _flushPropagation() comes back
        // through it, so a DIRECT attempt plus a propagated fallback of the
        // same message still yields ONE copy.
        // Fire-and-forget: the copy never touches outMsg's status.
        const sender = this.sendingIdentity();
        if (sender.isDistro && contact.destHash !== sender.hash) {
            this._sendDistroSentCopy(contact.destHash, "", content).catch(error => {
                console.warn(`[distro] ⚠️ Sent-copy to the distro for ${contact.destHash.slice(0,8)} failed:`, error.message);
                Harness.error("distro-sent-copy", error);
            });
        }

        // After the propagation delay with no direct proof, the copy goes to
        // the propagation node too — counting only time without transfer
        // activity: a direct Resource that keeps moving gets no copy, as
        // AppLinks Timer P (app-links 07bea51; Android 4b5bd9b, iOS 4744376).
        // Until 2026-09-30 a photo still moving direct got a second upload
        // of the whole attachment 5 s in. The delay is unchanged; what it
        // measures changed.
        const delayMs = ContactStore.propagationDelay(contact.destHash) * 1000;
        const fallback = () => {
            if (propagationStarted) return;
            const quiet = this._sendTransfers.quietFor(outMsg.id);
            if (quiet !== null && quiet < delayMs) {
                setTimeout(fallback, delayMs - quiet);
                return;
            }
            propagate();
        };
        setTimeout(fallback, delayMs);

        // The 30 s ceiling: failed if nothing proved or propagated it, unless
        // a transfer of it is still in flight (_armSendCeiling).
        this._armSendCeiling(contact.destHash, outMsg.id);
    },

    /**
     * Upload the propagated copy of a stored outgoing DM: from the fallback
     * timer in _dispatchMessage, and from _flushPropagation for a copy
     * parked earlier. Nothing goes once the message is proved, propagated
     * or failed (D3: a failed send is dead). With no link to upload on —
     * the node's identity is not known yet, or the attempt closed before
     * establishment — the copy is parked rather than dropped: "queued",
     * waitFor "propagation", persisted. The link's next "established"
     * uploads it, and the 30 s ceiling, which fails only "sending", leaves
     * it alone meanwhile.
     */
    async _propagateMessage(contact, outMsg) {
        const stored = () => MsgStore.get(contact.destHash).find(m => m.id === outMsg.id);
        // Gone, proved or propagated: nothing left to upload. Failed: the
        // user was shown it failed (a lost batch, _onPacketsLost), and a
        // copy now would be a re-send of a message they saw fail (D3).
        const settled = (m) => !m || m.status === "proved" || m.status === "propagated" || m.status === "failed";
        const park = (why) => {
            if (settled(stored())) return;
            MsgStore.update(contact.destHash, outMsg.id, { status: "queued", waitFor: "propagation" });
            console.log(`[retichat] ⏳ Propagation link unavailable (${why}) — ${contact.destHash.slice(0,8)} msg=${outMsg.id.slice(0,8)} parked until it is established`);
            this._onMsg.forEach(fn => fn(null, contact.destHash));
        };
        if (settled(stored())) return;
        // The copy is a way to deliver the message from here until its proof
        // or its failure (_propagationFailed), parked or not: a direct
        // failure while it waits for its link, its stamp or its upload sees
        // it still to go (legFailed in _dispatchMessage). Never opened for a
        // message already delivered or failed.
        this._sendTransfers.openLeg(outMsg.id, "propagated");
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
            park(e.message);
            return;
        }
        // A direct proof may have landed while the link came up.
        if (settled(stored())) return;
        const reason = contact.isDistro ? "distro address" : "no direct proof";
        console.log(`[retichat] 📡 Propagating via link to ${this._cfg.propagationNodeHash.slice(0,12)}... (${reason})`);

        // Build LXMF message addressed to the contact's delivery destination
        const contactPeerId = Identity.fromPublicKey(Buffer.from(contact.publicKey, "hex"));
        const contactDest = this._rns.registerDestination(contactPeerId, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");
        const FIELD_TICKET = 0x0C;
        // The copy is the direct message itself: its timestamp and ticket
        // from the record (_sendPacket), with the same title, content and
        // fields, give it the same LXMF hash, so a recipient that got the
        // direct message drops this one as a duplicate (LxmfSeen). Until
        // 2026-09-24 the copy had its own timestamp and ticket — a second
        // message — and a recipient that got both showed it twice. A record
        // never sent direct (a distro address) has neither and gets its own.
        // Signed by the identity the direct message was signed with: the
        // source is part of the hash, and a parked copy can wait across a
        // distro being imported or removed. If that identity is gone, the
        // copy is a new message from the current sender.
        const record = stored();
        const sender = this._signerFor(record.srcHash) ?? this.sendingIdentity();
        const sameMessage = sender.hash === record.srcHash;
        const ticket = (sameMessage && record.lxmfTicket) || Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex");

        const msg = new LXMessage();
        msg.sourceHash = Buffer.from(sender.hash, "hex");
        msg.destinationHash = contactDest.hash;
        if (sameMessage && typeof record.lxmfTimestamp === "number") msg.timestamp = record.lxmfTimestamp;
        msg.title = "";
        msg.content = outMsg.content;
        msg.fields = new Map();
        msg.fields.set(FIELD_TICKET, ticket);
        // The name decided for this message (_dispatchMessage), in the same
        // place as in _sendPacket, so the bytes are the same. A copy that is
        // a new message (the signer changed) gets its own decision, which
        // is never recorded: a propagated copy is never confirmed (§4.1).
        applyDisplayName(msg.fields, sameMessage
            ? record.lxmfName
            : this._decideMessageName(sender.hash, contact.destHash));
        // Its attachments, after the name as in _sendPacket, so the copy's
        // bytes and hash are the direct message's. Read from the attachment
        // store: a copy can go long after the send, or after a reload. One
        // whose bytes are gone (kept for an earlier session only) cannot be
        // the message the user sent, so it fails, saying why.
        if (record.attachments?.length) {
            let field;
            try {
                field = await this._attachmentField(record);
            } catch (e) {
                console.warn(`[retichat] ✗ Propagated copy of ${outMsg.id.slice(0,8)} to ${contact.destHash.slice(0,8)}: ${e.message}`);
                MsgStore.update(contact.destHash, outMsg.id, { sendError: e.message });
                this._failSending(contact.destHash, outMsg.id);
                return;
            }
            if (settled(stored())) return;
            msg.fields.set(FIELD_FILE_ATTACHMENTS, field);
        }
        // Pack non-opportunistic so destinationHash is at offset 0.
        // The propagation node reads dest_hash in cleartext from lxmf_data[0..16]
        // to identify the final recipient.
        const packed = msg.pack(sender.identity, false);

        // Build propagation_packed: msgpack([timestamp, [[dest_hash | EC_encrypted(rest) | stamp]]])
        const propagationPacked = await this._buildPropagationPacked(packed, contact.publicKey);
        // Mining the stamp yields, and can take seconds: a direct proof may
        // have landed, or the link closed, meanwhile. An upload onto a closed
        // link is never proved, so the copy is parked for the next one.
        if (settled(stored())) return;
        if (link.status !== Link.ACTIVE) {
            park("the link closed while the stamp was mined");
            return;
        }
        // The node refuses an upload over the per-sync limit it announces
        // (lib/attachment_limits.js). The composer checked an estimate; this
        // is the copy as built. Not uploaded: a direct attempt still open
        // decides; with none, the message has failed, now, with why.
        const perSyncKb = record.attachments?.length ? this._propagationLimits()?.perSyncKb : undefined;
        if (perSyncKb !== undefined && propagationPacked.length > perSyncKb * 1000) {
            const why = `the propagated copy is ${formatSize(propagationPacked.length)}, over the ${formatSize(perSyncKb * 1000)} the propagation node takes`;
            console.warn(`[retichat] ✗ ${outMsg.id.slice(0,8)} to ${contact.destHash.slice(0,8)}: ${why} — not uploaded`);
            this._propagationFailed(contact.destHash, outMsg.id, why);
            return;
        }
        const markPropagated = () => {
            // Delivery outranks everything: a direct proof keeps its ✓✓.
            if (stored()?.status === "proved") return;
            MsgStore.updateStatus(contact.destHash, outMsg.id, "propagated");
            this._sendTransfers.settle(outMsg.id);
            console.log(`[retichat] ✓ Propagation proof for ${contact.destHash.slice(0,8)}`);
            this._onMsg.forEach(fn => fn(null, contact.destHash));
        };
        // LXMF/LXMRouter.py propagation transfer: an upload that fits one
        // link packet is a packet, anything larger is a Resource on the
        // propagation link, and the resource's own proof is the evidence.
        // Until 2026-09-22 every upload was built as one packet, whose
        // pack() threw over the MDU inside the fallback timer — silently, so a
        // long message to a distro address never left the browser.
        if (propagationPacked.length > Link.MDU) {
            console.log(`[retichat] 📡 Propagation upload of ${propagationPacked.length} B exceeds the MDU — sending as a resource`);
            // Its progress is the message's (0.10 + 0.90 x fraction), and
            // while it moves the send ceiling waits for its end. Its failure
            // is the copy's (_propagationFailed).
            this._sendWithProgress(link, propagationPacked, contact.destHash, outMsg.id, "propagated")
                .then(markPropagated, (error) => {
                    console.warn(`[retichat] ⚠️ Propagation resource failed for ${contact.destHash.slice(0,8)}:`, error.message);
                    this._propagationFailed(contact.destHash, outMsg.id, propagationFailure(error));
                });
            if (contact.reachable !== false) {
                ContactStore.setReachable(contact.destHash, false);
            }
            return;
        }

        // A LINK-type DATA packet. Packet.pack() handles link encryption
        // via this.destination.encrypt(), so do NOT pre-encrypt here.
        const pkt = link.newLinkPacket(Packet.NONE, propagationPacked);
        const raw = pkt.pack();

        // Track packet hash for proof matching, before the packet can go
        // (DESIGN_PRINCIPLES §5: a proof never outruns its entry).
        const truncatedHex = pkt.packetHash.slice(0, 16).toString("hex");
        this._pendingPacketHashes.set(truncatedHex, {
            contactHash: contact.destHash,
            messageId: outMsg.id,
            onProof: markPropagated,
            dm: true,
        });

        // Through the link, like every other link send (RNS Packet.send on a
        // link: had_outbound), so the keepalive watchdog sees the outbound
        // and a CLOSED link drops it. Until 2026-09-30 this one went straight
        // to _rns.sendData: the link's outbound clock never moved, and it was
        // sent even on a closed link.
        if (link._transmit(raw) === null) {
            this._pendingPacketHashes.delete(truncatedHex);
            park("the link closed before the upload");
            return;
        }

        // Mark as likely offline
        if (contact.reachable !== false) {
            ContactStore.setReachable(contact.destHash, false);
        }
    },

    /**
     * DISPLAY_NAMES.md §4.1: the 0xD1 state of one outgoing message from
     * `sourceHex` to `recipientHex` — the Message Display Name when the
     * recipient has not had it confirmed in 30 days, an empty value once to
     * clear a name it has, otherwise nothing. Every outgoing DM, group and
     * group-control message goes through this, whatever its source (device
     * or distro); distro sent-copies and identity transfers, which go to
     * one's own devices, never do.
     */
    _decideMessageName(sourceHex, recipientHex) {
        return NameLedgerStore.decideFor(OwnNames.message, sourceHex, recipientHex, Math.floor(Date.now() / 1000));
    },

    /** §4.1: a DM reached DELIVERED; record the name it carried, if any. */
    _recordNameDelivered(contactHash, msgId) {
        const record = MsgStore.get(contactHash).find(m => m.id === msgId);
        if (!record?.srcHash) return;
        NameLedgerStore.recordDelivered(record.srcHash, contactHash, record.lxmfName, Math.floor(Date.now() / 1000));
    },

    /**
     * §2.2: a new Announce Display Name goes into the app_data of every
     * delivery destination at once. The device's next announce carries it;
     * the distro's announce is the one RFed replays, so it is handed over
     * again now.
     */
    applyAnnounceName() {
        this._lxmfRouter?.setAnnounceName(OwnNames.announce);
        if (DistroManager.has && this._initialized) {
            this._publishDistroAnnounce().catch(error =>
                console.warn("[distro] Re-publishing the distro announce with the new name failed:", error.message));
        }
    },

    /** The 30 s ceiling on a DM send: a record still "sending" when it
     *  expires has failed. Re-arming (a parked copy being flushed) replaces
     *  the earlier ceiling.
     *
     *  A Resource of the message still in flight when it expires decides
     *  instead (DESIGN_PRINCIPLES §1, bulk transfers): its proof delivers
     *  the message, its failure (its own watchdog, a refusal, the link
     *  closing) ends it. The ceiling waits for that end. A failed direct
     *  Resource has started the propagated copy, which gets the same 30 s
     *  from there. A failed propagated Resource leaves nothing to come, and
     *  the ceiling, already run out, fails the message at that failure. A
     *  moving transfer is never failed for its length, and a silence in it
     *  is logged as a §1 violation by _sendTransfers. Until 2026-09-30 a
     *  photo whose Resource was still moving was failed at 30 s, then shown
     *  delivered at its late proof. */
    _armSendCeiling(contactHash, msgId) {
        clearTimeout(this._pendingTimeouts.get(msgId));
        const timeoutId = setTimeout(() => {
            this._pendingTimeouts.delete(msgId);
            if (this._sendTransfers.inFlight(msgId)) {
                console.log(`[retichat] ⏳ ${msgId.slice(0,8)} to ${contactHash.slice(0,8)} is still transferring at the send ceiling — its transfer decides`);
                this._sendTransfers.deferCeiling(msgId, (ok, leg, error) => {
                    if (!ok && leg === "propagated") this._failSending(contactHash, msgId, propagationFailure(error));
                    else this._armSendCeiling(contactHash, msgId);
                });
                return;
            }
            this._failSending(contactHash, msgId);
        }, 30000);
        this._pendingTimeouts.set(msgId, timeoutId);
    },

    /** Fail a DM send that is still "sending", saying `why` when given.
     *  Anything else outranks the failure: a delivery (proved, propagated),
     *  or a copy parked for the propagation link ("queued"), which
     *  _flushPropagation still sends. Its ceiling has nothing left to do. */
    _failSending(contactHash, msgId, why = null) {
        const msg = MsgStore.get(contactHash).find(m => m.id === msgId);
        if (msg?.status !== "sending") return;
        clearTimeout(this._pendingTimeouts.get(msgId));
        this._pendingTimeouts.delete(msgId);
        if (why) MsgStore.update(contactHash, msgId, { sendError: why });
        MsgStore.updateStatus(contactHash, msgId, "failed");
        this._sendTransfers.settle(msgId);
        this._onMsg.forEach(fn => fn(null, contactHash));
    },

    /** The propagated copy of a DM failed: its Resource failed, or the node
     *  would not take it. Its reason goes on the record (shown if the
     *  message fails). A direct attempt still open decides the outcome; with
     *  none, nothing can deliver the message any more, and it fails now, on
     *  this event (DESIGN_PRINCIPLES §1, bulk transfers: the Resource's own
     *  events decide). Until 2026-09-30 only the 30 s ceiling failed it,
     *  so a distro send stayed "sending" after its upload had failed. */
    _propagationFailed(contactHash, msgId, why) {
        const msg = MsgStore.get(contactHash).find(m => m.id === msgId);
        if (msg?.status === "sending") MsgStore.update(contactHash, msgId, { sendError: why });
        if (this._sendTransfers.legFailed(msgId, "propagated")) this._failSending(contactHash, msgId);
    },

    /** True while this connection's exchange is down: its last exchange or
     *  registration failed and nothing has succeeded since (PostInterface
     *  isDown). Not while it is still starting, nor after a registration
     *  whose first exchange has yet to answer. */
    _exchangeIsDown() {
        return (this._rns?.interfaces ?? []).some(iface => iface.isDown === true);
    },

    /**
     * PostInterface "lost": an exchange failed (or a check abandoned it) and
     * took these packets with it, or they were sent while it was down. Until
     * 2026-09-25 they vanished unseen and a DM among them showed "sending"
     * until the 30 s ceiling. D3: a DM whose packet was lost fails now, in
     * front of the user, and nothing sends it again — a failed record is
     * settled for the propagated copy (_propagateMessage). The proof entry
     * stays: the node may have taken the batch before the exchange failed,
     * and a proof that still arrives is the truth and outranks the failure.
     * Link keepalives, proofs and requests are left to the link protocol.
     */
    _onPacketsLost({ packetHashes, reason }) {
        for (const packetHash of packetHashes) {
            const pending = this._pendingPacketHashes.get(packetHash.slice(0, 32));
            if (!pending?.dm) continue;
            const { contactHash, messageId } = pending;
            const msg = MsgStore.get(contactHash).find(m => m.id === messageId);
            if (msg?.status !== "sending") continue;
            clearTimeout(this._pendingTimeouts.get(messageId));
            this._pendingTimeouts.delete(messageId);
            MsgStore.updateStatus(contactHash, messageId, "failed");
            console.warn(`[retichat] ✗ DM ${messageId.slice(0,8)} to ${contactHash.slice(0,8)} failed: its packet was lost (${reason})`);
            Harness.event("dm-lost", { to: contactHash.slice(0, 12), id: messageId, reason });
            this._onMsg.forEach(fn => fn(null, contactHash));
        }
    },

    /**
     * Dispatch every message stored "queued" until initialization finished
     * (waitFor "init"): DMs and group messages, oldest first. Each record is
     * claimed — waitFor cleared and persisted — in the same tick it is
     * dispatched, so a second "registered" (a 401 re-registration) or a
     * reload mid-dispatch cannot send it twice. A DM whose contact has no
     * public key stays queued for the next initialization.
     *
     * A queued DM with attachments may hold them only in the attachment
     * store (it waited across a reload), and _sendPacket packs them
     * synchronously from memory. So when any is queued, the bytes of all of
     * them are read into memory first (Attachments.warm), and then every
     * queued message goes in one pass, in order, and the bytes are let go.
     * Until 2026-09-30 only those DMs waited for their bytes, so a text
     * queued after a photo was sent, and stamped, before it. One whose bytes
     * are gone (kept for an earlier session only) is not sent without them:
     * it fails, saying why.
     */
    _dispatchQueued() {
        const queued = [];
        const isQueued = (m) => m?.dir === "out" && m.status === "queued" && m.waitFor === "init";
        for (const contact of ContactStore.getAll()) {
            for (const msg of MsgStore.get(contact.destHash).filter(isQueued)) {
                queued.push({ msg, keys: (msg.attachments ?? []).map(a => a.key), dispatch: (missing) => {
                    if (!contact.publicKey) {
                        console.warn(`[retichat] ⏳ Queued message ${msg.id.slice(0,8)} to ${contact.destHash.slice(0,8)} stays queued: no public key for this contact yet`);
                        return;
                    }
                    // Re-read: another run may have claimed it while this
                    // one read the attachments.
                    if (!isQueued(MsgStore.get(contact.destHash).find(m => m.id === msg.id))) return;
                    const gone = (msg.attachments ?? []).filter(a => missing.has(a.key)).length;
                    if (gone) {
                        const why = `${gone === 1 ? "an attachment was" : "attachments were"} kept for an earlier session only and ${gone === 1 ? "is" : "are"} gone`;
                        console.warn(`[retichat] ✗ Queued message ${msg.id.slice(0,8)} to ${contact.destHash.slice(0,8)} not sent: ${why}`);
                        MsgStore.update(contact.destHash, msg.id, { status: "failed", waitFor: null, sendError: why });
                        this._onMsg.forEach(fn => fn(null, contact.destHash));
                        return;
                    }
                    MsgStore.update(contact.destHash, msg.id, { waitFor: null });
                    this._dispatchMessage(contact, msg);
                }});
            }
        }
        for (const group of GroupStore.getAll()) {
            for (const msg of GroupMsgStore.get(group.groupId).filter(isQueued)) {
                queued.push({ msg, keys: [], dispatch: () => {
                    if (!isQueued(GroupMsgStore.get(group.groupId).find(m => m.id === msg.id))) return;
                    GroupMsgStore.update(group.groupId, msg.id, { waitFor: null });
                    this._dispatchGroupMessage(group.groupId, msg).catch(error =>
                        console.warn(`[retichat] 👥 Queued group send to ${group.groupId.slice(0,8)} failed:`, error.message));
                }});
            }
        }
        if (!queued.length) return;
        console.log(`[retichat] ⏳ Initialization finished — dispatching ${queued.length} queued message(s)`);
        queued.sort((a, b) => a.msg.timestamp - b.msg.timestamp);
        const dispatchAll = (missing) => {
            for (const { msg, dispatch } of queued) {
                try {
                    dispatch(missing);
                } catch (error) {
                    console.warn(`[retichat] ⚠️ Queued message ${msg.id.slice(0,8)} failed to dispatch:`, error.message);
                    Harness.error("queued-dispatch", error);
                }
            }
        };
        const keys = queued.flatMap(q => q.keys);
        if (!keys.length) { dispatchAll(new Set()); return; }
        return Attachments.warm(keys)
            .then((missing) => dispatchAll(new Set(missing)))
            .finally(() => Attachments.cool(keys));
    },

    /**
     * Propagate the RFed SPEC §17.11 sent-copy of a message this device just
     * sent as the distro D to `recipientHex`: destination D, source D, signed
     * with D's key, title and content identical to the original, and
     *   0xFB FIELD_CUSTOM_TYPE = "rfed.distro.sent"
     *   0xFC FIELD_CUSTOM_DATA = the recipient's address (32 lowercase hex)
     *   0xFD FIELD_CUSTOM_META = this device's own lxmf.delivery address.
     * It goes PROPAGATED at once, like every distro-addressed message
     * (ContactStore.propagationDelay): RFed intercepts it on lxmf.propagation
     * and fans it out to every registered device of D, this one included —
     * _handleDistroBlob drops that echo by 0xFD. No ticket, so no delivery
     * notification comes back, and no bubble is created here. Mirrors the
     * Android and iOS send paths.
     */
    async _sendDistroSentCopy(recipientHex, title, content) {
        const distroHash = DistroManager.lxmfDeliveryHash;
        const deviceHash = this.ownHash;
        if (!DistroManager.has || !distroHash) return;
        // A message to the distro itself already reaches every device.
        if (recipientHex === distroHash) return;
        if (!deviceHash) throw new Error("own lxmf.delivery address unavailable for 0xFD");

        const msg = new LXMessage();
        msg.sourceHash = Buffer.from(distroHash, "hex");
        msg.destinationHash = Buffer.from(distroHash, "hex");
        msg.title = title;
        msg.content = content;
        msg.fields = new Map();
        msg.fields.set(LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_SENT_TYPE);
        msg.fields.set(LXMF.FIELD_CUSTOM_DATA, recipientHex.toLowerCase());
        msg.fields.set(LXMF.FIELD_CUSTOM_META, deviceHash.toLowerCase());
        // Non-opportunistic: the propagation node reads dest_hash (D) in
        // cleartext from offset 0 — that is how RFed recognises a distro.
        const packed = msg.pack(DistroManager.identity, false);
        const distroPubKey = DistroManager.pubKey;

        // Wait for the propagation link, never start it: when M's link comes
        // up is decided by M's own propagation timer, not by its copy. The
        // link's "established" handler runs _flushPropagation(), which
        // uploads only copies _propagateMessage parked (waitFor
        // "propagation") and never a record still "sending", so starting
        // the link no longer re-propagates M inside its direct window — the
        // double delivery this rule first guarded against. The link is kept
        // up by its persistent re-open, the node's announces
        // (_initPropagation) and page resumes, and by M's own propagation
        // timer, so the copy rides the next one.
        const link = await this._whenPropagationLinkUp(recipientHex);
        const propagationPacked = await this._buildPropagationPacked(packed, distroPubKey);
        const dispatched = (how) => {
            console.log(`[distro] 📤 Sent-copy for ${recipientHex.slice(0,8)} propagated to the distro as a ${how} (§17.11)`);
            Harness.event("distro-sent-copy", { to: recipientHex.slice(0, 12), how });
        };
        // Same size rule as every propagation upload (LXMF/LXMRouter.py).
        if (propagationPacked.length > Link.MDU) {
            console.log(`[distro] 📤 Sent-copy of ${propagationPacked.length} B for ${recipientHex.slice(0,8)} exceeds the MDU — sending as a resource`);
            await link.sendResource(propagationPacked);
            dispatched("resource");
            return;
        }
        link.send(propagationPacked);
        dispatched("packet");
    },

    /** Core packet send: packs, sends, tracks proof, calls back. */
    _sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError) {
        const peerId = Identity.fromPublicKey(Buffer.from(publicKeyHex, "hex"));
        const dest = this._rns.registerDestination(peerId, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

        const FIELD_TICKET = 0x0C;
        const ticket = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex");

        // Sign and address as the distro when one is loaded, so the recipient's
        // reply reaches every device rather than just this one.
        const sender = this.sendingIdentity();
        const msg = new LXMessage();
        msg.sourceHash = Buffer.from(sender.hash, "hex");
        msg.destinationHash = dest.hash;
        msg.title = "";
        msg.content = content;
        msg.fields = new Map();
        msg.fields.set(FIELD_TICKET, ticket);
        // DISPLAY_NAMES.md §4.1: the 0xD1 decided once for this message and
        // kept on its record (_dispatchMessage). None on a record without a
        // decision.
        const record = MsgStore.get(contactHash).find(m => m.id === messageId);
        applyDisplayName(msg.fields, record?.lxmfName);
        // Its attachments as FIELD_FILE_ATTACHMENTS [[name, bytes], ...], at
        // their original size, from the bytes this tab holds now (the send
        // put them there; _dispatchQueued warms a queued one's).
        if (record?.attachments?.length) {
            try {
                msg.fields.set(FIELD_FILE_ATTACHMENTS, this._attachmentFieldNow(record));
            } catch (e) {
                MsgStore.update(contactHash, messageId, { sendError: e.message });
                if (onError) onError(messageId);
                throw e;
            }
        }
        // The full packing: destination hash, source hash, signature, payload.
        // A packet to the destination sends it without the destination hash
        // (the packet header carries it); a link packet or Resource sends it
        // whole. Reference: LXMessage.py __as_packet / __as_resource.
        const packed = msg.pack(sender.identity, false);
        // LXMF's delivery limit, on the message as built (the composer
        // checked an estimate): no recipient takes more, on any path.
        if (record?.attachments?.length && packed.length > LXMRouter.DELIVERY_LIMIT * 1000) {
            const why = `This message is ${formatSize(packed.length)}; an LXMF message can be at most ${formatSize(LXMRouter.DELIVERY_LIMIT * 1000)}.`;
            MsgStore.update(contactHash, messageId, { sendError: why });
            if (onError) onError(messageId);
            throw new Error(why);
        }
        const plan = LXMessage.deliveryPlan(packed);
        // Kept on the record, so the propagated copy (_propagateMessage) —
        // one parked across a reload too — is rebuilt as this same message
        // with this same hash, and a recipient that gets both keeps one.
        MsgStore.update(contactHash, messageId, { lxmfTimestamp: msg.timestamp, lxmfTicket: ticket });

        this._pendingTickets.set(ticket, { contactHash, messageId, onProof });

        if (plan.method === LXMessage.DIRECT) {
            // Until 2026-09-23 every direct message left as one packet to the
            // destination whatever its size; the MTU check in Packet.pack() is
            // disabled, so a message over 295 bytes went out as an oversized
            // packet that every hop dropped without a word. LXMF sends those
            // over a link: a link packet up to 319 bytes of content, a
            // Resource above that.
            this._sendOverPeerLink(contactHash, publicKeyHex, packed, plan.representation, messageId, onProof, onError);
            return;
        }

        try {
            const sentPacketHash = dest.send(packed.subarray(LXMessage.DESTINATION_LENGTH));
            if (sentPacketHash) {
                const truncatedHex = sentPacketHash.slice(0, 16).toString("hex");
                this._pendingPacketHashes.set(truncatedHex, { contactHash, messageId, onProof, dm: true });
            }
        } catch (e) {
            this._pendingTickets.delete(ticket);
            if (onError) onError(messageId);
            throw e;
        }
    },

    /**
     * Deliver a packed LXMF message over a link to the peer's delivery
     * destination (LXMessage.DIRECT). The link is the same per-peer delivery
     * link group delivery uses. A link packet is proved like any packet and
     * matched in _pendingPacketHashes; a Resource is proved by its own
     * transfer, so its completion is the delivery evidence.
     */
    _sendOverPeerLink(contactHash, publicKeyHex, packed, representation, messageId, onProof, onError) {
        const fail = (what, error) => {
            console.warn(`[retichat] ⚠️ Direct ${what} to ${contactHash.slice(0,8)} failed:`, error.message);
            if (onError) onError(messageId);
        };
        this._ensureGroupLink(contactHash, publicKeyHex).then(({ link }) => {
            if (representation === LXMessage.RESOURCE) {
                console.log(`[retichat] ✉️ Direct message of ${packed.length} B to ${contactHash.slice(0,8)} exceeds the link MDU — sending as a resource`);
                // Its progress is the message's, and while it moves the
                // propagation fallback and the send ceiling wait for it.
                this._sendWithProgress(link, packed, contactHash, messageId, "direct")
                    .then(() => { if (onProof) onProof(messageId); })
                    .catch(error => fail("resource", error));
                return;
            }
            console.log(`[retichat] ✉️ Direct message of ${packed.length} B to ${contactHash.slice(0,8)} — sending as a link packet`);
            const packet = link.send(packed);
            const truncatedHex = packet.packetHash.slice(0, 16).toString("hex");
            this._pendingPacketHashes.set(truncatedHex, { contactHash, messageId, onProof, dm: true });
        }).catch(error => fail("link", error));
    },

    // =========================================================================
    //  GROUP PROTOCOL — handle incoming group messages + send group operations
    // =========================================================================

    /** Handle incoming distro identity transfer (FIELD_CUSTOM_TYPE "rfed.distro.transfer"). */
    _handleDistroIdentityTransfer(lxmfMsg, srcHash, privateKeyHex) {
        console.log(`[distro] 📥 Received distro identity transfer from ${srcHash.slice(0,12)}...`);
        try {
            if (!privateKeyHex || privateKeyHex.length !== 128) {
                console.warn(`[distro] Private key has wrong length: ${privateKeyHex?.length ?? 0}`);
                return;
            }
            // Named through the resolver (DISPLAY_NAMES.md §5.3): the user's
            // own name for the sender when there is one, and a 0xD1 only as
            // accepted under §5.2 — never the raw field, which anyone can
            // set to a known contact's name (audit M14).
            const senderName = ContactStore.name(srcHash);

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

    /** Handle an incoming group message (detected by its group id, key 1 of
     *  0xD1 or the old 0xA0: LXMessage.extractGroupFields). */
    _handleGroupMessage(lxmfMsg, srcHash, content, groupInfo) {
        const { groupId, groupName, groupAction, groupSender, members, relaySeen, memberKeys } = groupInfo;
        console.log(`[retichat] 👥 Group message: groupId=${groupId.slice(0,8)} action=${groupAction || "message"} from=${srcHash.slice(0,12)}`);

        const group = GroupStore.get(groupId);
        const actualSender = groupSender || srcHash;
        // iOS groupMessagePolicy: an invite only from a source the privacy
        // filter allows (an allowlisted contact while it is on; iOS
        // handleGroupInvite, ChatRepository.swift:2166-2171), anything else
        // only for a group this client holds. The router has already asked
        // the same (PrivacyFilter.acceptsMessage); asked again here so this
        // handler holds the rule on its own. Until 2026-09-30 any row but a
        // name-only one could invite, channel posters and every auto-added
        // stranger included.
        if (!shouldProcessGroupMessage(groupAction, PrivacyFilter.allows(srcHash), !!group)) {
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

        // DISPLAY_NAMES.md §5.2 for a sender this client holds no row for (a
        // member who joined after the invite, an accept from someone never
        // added): the router's handler could not store its 0xD1, so a hidden
        // row is kept for it now that the message is processed, and the name
        // taken by the same table. Group labels, the member list and system
        // notices then name it; the contact list does not show it.
        if (!ContactStore.known(srcHash) && srcHash !== (this.ownHash ?? ownLxmfDestinationHash())) {
            ContactStore.keep(srcHash, null, true);
            ContactStore.acceptMessageName(srcHash, lxmfMsg.displayName,
                lxmfMsg.signatureState ?? "invalid", lxmfMsg.timestamp);
        }

        switch (groupAction) {
            case "invite": {
                const verified = this._rememberGroupMemberKeys(memberKeys);
                // If we already have this group active, ignore
                if (group && group.groupStatus === "active") return;
                // The inviter, and each co-member the invite lists whose key
                // checked out, pass the privacy filter from now on: iOS
                // handleGroupInvite (ChatRepository.swift:2183-2191, 2220-2221),
                // Android handleGroupMessage (ChatRepository.kt:1545-1552,
                // 1596-1599).
                const listed = new Set([...(members || []), srcHash]);
                ContactStore.allow(srcHash);
                for (const hash of verified) if (listed.has(hash)) ContactStore.allow(hash);
                // Create pending group entry. The inviter is named when the
                // notice is shown, through the contact resolver: its 0xD1
                // was already taken under §5.2 above, and the raw field is
                // never shown as it arrived (audit M14).
                GroupStore.addPending(groupId, groupName || "Group", srcHash, members || []);
                if (!group) GroupMsgStore.addSystem(groupId, `invited you to "${groupName || "Group"}"`, srcHash);
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));  // trigger UI refresh with groupId
                break;
            }
            case "accept": {
                if (!group) return;
                GroupStore.updateMember(groupId, actualSender, "accepted");
                // A confirmed member passes the privacy filter: iOS
                // handleGroupAccept (ChatRepository.swift:2260-2264), Android
                // (ChatRepository.kt:1643-1646).
                if (actualSender !== (this.ownHash ?? ownLxmfDestinationHash())) ContactStore.allow(actualSender);
                GroupMsgStore.addSystem(groupId, "joined the group", actualSender);
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));
                break;
            }
            case "leave": {
                if (!group) return;
                GroupStore.updateMember(groupId, actualSender, "left");
                GroupMsgStore.addSystem(groupId, "left the group", actualSender);
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

                // The author (GROUP_SENDER, or the LXMF source) is stored as a
                // hash and named at render (groupSenderLabel), so the label follows
                // names learned later.
                // A group message's attachments are kept like a DM's (iOS
                // sends a group's attachments to each member,
                // ChatRepository.swift:1381-1432); a captionless one keeps
                // content "" and shows its attachment. Only a message with
                // neither is "(empty)".
                const found = lxmfMsg.attachments ?? [];
                const unreadable = found.skipped || lxmfMsg.fieldsUnreadable;
                const displayContent = content || (found.length || unreadable ? "" : "(empty)");
                const stored = GroupMsgStore.add(groupId, { dir: "in", content: displayContent, status: "delivered", srcHash: actualSender,
                    lxmfHash: lxmfMsg.hash ? Buffer.from(lxmfMsg.hash).toString("hex") : null });
                if (found.length || unreadable) this._keepAttachments(GroupMsgStore, groupId, stored, found, lxmfMsg.fieldsUnreadable);
                // Update group last activity
                group.lastActivity = Date.now();
                GroupStore._save();
                this._onMsg.forEach(fn => fn(lxmfMsg, groupId));
                break;
            }
        }
    },

    /** Send a group chat message (fanout to all accepted members). Before
     *  initialization has finished it is stored "queued" (waitFor "init"),
     *  like a DM, and _dispatchQueued() fans it out when the signal fires. */
    async sendGroupMessage(groupId, content) {
        const group = GroupStore.get(groupId);
        if (!group) throw new Error("Group not found");

        // Add outgoing message to group store
        const queued = !this._initialized;
        // D3: outside the initialization hold, a send with the exchange down
        // fails now and is never sent (see sendMessage).
        const down = !queued && this._exchangeIsDown();
        const outMsg = GroupMsgStore.add(groupId, queued
            ? { dir: "out", content, status: "queued", waitFor: "init", srcHash: this.ownHash }
            : { dir: "out", content, status: down ? "failed" : "sending", srcHash: this.ownHash });
        group.lastActivity = Date.now();
        GroupStore._save();
        if (queued) {
            if (!GroupMsgStore.get(groupId).some(m => m.id === outMsg.id)) {
                throw new Error("Could not store the group message to send when connected (storage full?)");
            }
            console.log(`[retichat] ⏳ Group message for ${groupId.slice(0,8)} queued until initialization finishes`);
            return outMsg;
        }
        if (down) {
            console.warn(`[retichat] ✗ Group message for ${groupId.slice(0,8)} not sent: the exchange is down`);
            return outMsg;
        }
        return this._dispatchGroupMessage(groupId, outMsg);
    },

    /** Fan a stored outgoing group message out to every accepted member. */
    async _dispatchGroupMessage(groupId, outMsg) {
        const group = GroupStore.get(groupId);
        if (!group) return outMsg;
        const ownHash = this.ownHash;
        GroupMsgStore.update(groupId, outMsg.id, { status: "sending", srcHash: ownHash });
        if (outMsg.status !== "sending") this._onMsg.forEach(fn => fn(null, groupId));

        const targets = [...group.members.entries()]
            .filter(([hash, status]) => hash !== ownHash && status === "accepted")
            .map(([hash]) => hash);
        const delivery = await this._fanoutGroupEnvelope(targets, outMsg.content, {
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
        let contact = ContactStore.keep(memberHash);
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
        // DISPLAY_NAMES.md §4.1: group messages and group control (invites
        // included) carry the Message Display Name under the same ledger as
        // DMs, per member. Recorded once this member's copy is delivered
        // directly; a propagated copy is never confirmed.
        const sourceHex = msg.sourceHash.toString("hex");
        const nameState = this._decideMessageName(sourceHex, memberHash);
        applyDisplayName(msg.fields, nameState);
        // DISPLAY_NAMES.md §10: the group entries, in the old top-level
        // fields 0xA0-0xA8 or in the Retichat field 0xD1 beside the name, as
        // GROUP_ENTRIES_IN_RETICHAT_FIELD selects (false until the switch).
        applyGroupFields(msg.fields, fields);
        const packed = msg.pack(IdMgr.id, true);
        return this._deliverGroupEnvelope(
            memberHash,
            Buffer.concat([dest.hash, packed]),
            contact.publicKey,
            () => NameLedgerStore.recordDelivered(sourceHex, memberHash, nameState, Math.floor(Date.now() / 1000)),
        );
    },

    _deliverGroupEnvelope(memberHash, fullLxmfBytes, publicKeyHex, onDelivered = null) {
        const deliveryKey = `${memberHash}:${crypto.randomUUID()}`;
        const evidence = new GroupDeliveryEvidence(memberHash);
        {
            let directProofKey = null;
            let propagationProofKey = null;
            const fulfill = method => {
                if (!evidence.fulfill(method)) return;
                if (method === "direct" && onDelivered) onDelivered();
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
                    if (propagationPacket === null) {
                        // A Resource upload resolves on its proof (see
                        // _sendGroupPropagationFallback).
                        fulfill("propagation");
                        return;
                    }
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

    /** Keep each member key that produces its hash as an lxmf.delivery
     *  destination. Returns the hashes whose keys checked out. */
    _rememberGroupMemberKeys(memberKeys) {
        // The member list includes this device. Its own hash is never a
        // contact: it would show as a "yourself" row in the chat list, the
        // contacts and the group picker (audit L4).
        const ownHash = this.ownHash ?? ownLxmfDestinationHash();
        const verified = [];
        for (const [hash, encodedPublicKey] of memberKeys || []) {
            if (hash === ownHash) continue;
            try {
            const publicKey = Buffer.from(encodedPublicKey, "base64");
            if (publicKey.length !== 64) continue;
            const identity = Identity.fromPublicKey(publicKey);
                const derived = Destination.hash(identity, "lxmf", "delivery").toString("hex");
                if (derived !== hash) {
                    console.warn(`[retichat] 👥 Ignored mismatched member key for ${hash.slice(0,8)}`);
                    continue;
                }
                const contact = ContactStore.keep(hash);
                contact.publicKey = publicKey.toString("hex");
                verified.push(hash);
            } catch (error) {
                console.warn(`[retichat] 👥 Ignored invalid member key for ${hash.slice(0,8)}:`, error.message);
            }
        }
        ContactStore._save();
        return verified;
    },

    /**
     * Returns the packet whose proof is the delivery evidence, or null when the
     * upload went as a Resource (over the MDU, LXMF/LXMRouter.py propagation
     * transfer) — in that case the Resource's own proof has already arrived
     * by the time this resolves.
     */
    async _sendGroupPropagationFallback(fullLxmfBytes, publicKeyHex, memberHash) {
        const link = await this._ensurePropagationLink();
        const propagationPacked = await this._buildPropagationPacked(fullLxmfBytes, publicKeyHex);
        if (propagationPacked.length > Link.MDU) {
            console.log(`[retichat] 👥 Group propagation fallback of ${propagationPacked.length} B exceeds the MDU — sending as a resource`);
            await link.sendResource(propagationPacked);
            return null;
        }
        const packet = link.send(propagationPacked);
        console.log(`[retichat] 👥 Group propagation fallback dispatched for ${memberHash.slice(0,8)} packet=${packet.packetHash.slice(0,6).toString("hex")}`);
        return packet;
    },

    /** The propagation link once it is ACTIVE, without starting it (unlike
     *  _ensurePropagationLink). Used by the §17.11 sent-copy, which must not
     *  change when the original message is propagated. Resolved by the
     *  link's "established" or "recovered" (STALE -> ACTIVE) handler,
     *  rejected by disconnect(). */
    _whenPropagationLinkUp(recipientHex) {
        if (this._propLink?.status === Link.ACTIVE) return Promise.resolve(this._propLink);
        if (!this._cfg.propagationNodePubKey || !this._cfg.propagationNodeHash) {
            return Promise.reject(new Error("Propagation node identity is not ready"));
        }
        console.log(`[distro] Sent-copy for ${recipientHex.slice(0,8)} waits for the propagation link (§17.11)`);
        return new Promise((resolve, reject) => this._propLinkUpWaiters.push({ resolve, reject }));
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
                let contact = ContactStore.keep(hash);
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
        // The first registration after connect() finishes initialization
        // (§5): messages sent before it were stored "queued" and go now. A
        // 401 re-registration fires "registered" again; the flag keeps that
        // from re-running the queue.
        if (!this._initialized) {
            this._initialized = true;
            this._dispatchQueued();
        }
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
        // client, opened at 01:12:12, waited out the whole service refresh
        // interval (then 15 minutes; 6 hours since 2026-09-23) with every
        // distro call unusable.
        for (const aspects of [["link"], ["channel"], ["channel", "stream"], ["channel", "pull"], ["distro", "register"]]) {
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

    /**
     * The configured propagation node announced (lxmf.propagation): the
     * reference's "path is available" moment, and an explicit event for the
     * persistent propagation link (app-links announce_received). Its re-open
     * is armed, and a link that is down gets one attempt. The LINKREQUEST
     * can fail while path entries are still spreading across the exchanges;
     * such an attempt is not retried on a timer, the next announce (or page
     * resume, or an upload that needs the link) makes the next one.
     */
    _initPropagation() {
        if (!this._cfg.propagationNodeHash || !this._cfg.propagationNodePubKey) return;
        this._propReopenArmed = true;
        if (!this._propagationInitialized) {
            this._propagationInitialized = true;
            console.log(`[retichat] 📡 Propagation service ready, establishing link...`);
        }
        this._redrivePropagationLink("announce");
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
        // MINUTES) while every service destination then refreshed every
        // 15 min (every 6 h too since 2026-09-23, RFed-rust
        // SERVICE_REFRESH_INTERVAL_SECS, so the startup path requests'
        // answers are what bring the key in practice).
        // A browser that started up therefore sat with no rfedNodePubKey and
        // failed every distro/channel call with "RFed node identity is not
        // known yet" for up to six hours. The startup path request for
        // rfed.node cannot rescue it either — nothing in the mesh holds a path
        // for a destination that has not announced, so nobody answers.
        this._catchRfedNodeAnnounce(event);
        const key = aspects.join(".");
        // An explicit event for the persistent links: the next close of one
        // that is up re-opens it once (app-links announce_received arms,
        // RFED_PERSISTENT_KEYS). A re-open that failed is parked below.
        for (const persistent of RFED_PERSISTENT_KEYS) this._rfedReopenArmed.add(persistent);
        this._rfedServiceReady.add(key);
        const waiters = this._rfedServiceWaiters.get(key) || [];
        this._rfedServiceWaiters.delete(key);
        waiters.forEach(waiter => waiter.resolve());
        if (key === "channel") {
            this._initChannels().catch(e => console.warn("[retichat] Channel init failed:", e.message));
        }
        // This announce is our proof the service is reachable again — the
        // reference's "path is available" moment. Anything that failed on a
        // dead link gets one shot at running now. Nothing is scheduled: no
        // announce, no re-drive.
        this._rfedRunPending(key);
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

    /**
     * Record an operation that could not run because its RFed link failed,
     * so the next announce for that service can re-drive it.
     *
     * This is the reference's wants_download_on_path_available_from/to/timeout
     * (LXMRouter.request_messages_from_propagation_node), which parks the
     * intent and lets __request_messages_path_job re-call the entry point once
     * a path exists. Same shape, different event: an announce is our proof
     * of reachability. rfed re-announces its services every 6 hours (15
     * minutes until 2026-09-23), so an intent outlives RFED_PENDING_TIMEOUT_MS
     * only when an announce comes early; the persistent links are re-driven
     * by the exchange and the page coming back as well (_onPageResume).
     *
     * One pending operation per aspect — re-driving the same intent twice is
     * duplicate work, not resilience (see the _registerDistro coalescing note).
     */
    _rfedDeferUntilAnnounce(key, label, run) {
        if (this._rfedPending.has(key)) return;
        this._rfedPending.set(key, {
            label,
            run,
            expiresAt: Date.now() + RFED_PENDING_TIMEOUT_MS,
        });
        console.warn(`[retichat] ⏳ ${label} deferred — waiting for the next `
            + `rfed.${key} announce to re-drive it (state=${this._rfedLinkState.get(key)})`);
    },

    /**
     * Re-drive whatever was waiting on this service, now that it has announced.
     * The reference's __request_messages_path_job tail: path available →
     * re-call; timed out → give up with a named failure state.
     */
    _rfedRunPending(key) {
        const pending = this._rfedPending.get(key);
        if (!pending) return;
        this._rfedPending.delete(key);
        if (Date.now() > pending.expiresAt) {
            console.warn(`[retichat] ⌛ ${pending.label} expired before rfed.${key} `
                + `announced again — not re-driving (reference: PR_NO_PATH)`);
            return;
        }
        console.log(`[retichat] 🔁 rfed.${key} announced — re-driving ${pending.label}`);
        Promise.resolve()
            .then(() => pending.run())
            .catch(e => console.warn(`[retichat] ${pending.label} failed again: ${e.message}`));
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
        this._rfedLinkState.set(key, RFED_LINK_ESTABLISHING);
        const promise = new Promise((resolve, reject) => {
            link.on("established", () => {
                if (established) return;
                established = true;
                // An established link is never rejected for being slow. The
                // deadline that matters is Link.establishmentTimeout (the RNS
                // reference, per hop); if that expires the link closes itself
                // and the close handler below rejects. Closing a link that just
                // came up only guarantees the next attempt starts from scratch.
                console.log(`[retichat] RFed ${key} link active after ${Date.now() - startedAt}ms (rtt=${link.rtt}ms)`);
                link.identify(IdMgr.id);
                this._rfedLinks.set(key, link);
                this._rfedLinkState.set(key, RFED_LINK_ESTABLISHED);
                console.log(`[retichat] RFed ${key} link active`);
                resolve(link);
                // Link.md "The client re-binds on every link": the bindings
                // and the pulls, after identify (above) and in order.
                if (RFED_PERSISTENT_KEYS.includes(key)) this._onRfedLinkEstablished(key, link);
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
            if (key === "link") {
                // The pushes this link takes are bounded before it exists: a
                // request Resource over RFED_LINK_MAX_REQUEST_SIZE is refused
                // at its advertisement (RNS Destination.max_request_size).
                link.maxRequestSize = RFED_LINK_MAX_REQUEST_SIZE;
                // Node → client pushes arrive as REQUESTS on the bound link
                // (Link.md "Path map — node → client"). Our response is the
                // node's delivery proof: an unanswered push goes to the
                // deferred queue and reaches us via /channel/pull — a change
                // of tier, not a loss. So answer only what was actually
                // handled. The path is the discriminator; both delivery
                // payloads start with a 16-byte hash meaning different things.
                link.on("request", ({requestId, path, data}) => {
                    this._onRfedLinkPush(link, requestId, path, data);
                });
            }
            link.on("close", () => {
                // The janitor, mirroring LXMRouter.jobs(): a CLOSED link is
                // cleared so the next attempt starts from scratch, and the
                // outcome is recorded as a state rather than vanishing.
                const current = this._rfedLinks.get(key) === link;
                if (current) this._rfedLinks.delete(key);
                // Only this link's own attempt: a late close of a link
                // disconnect() dropped (one still establishing is not closed
                // by it, and fails on its own timeout) must not touch the
                // newer attempt: forgetting it lets the next re-drive start a
                // second link beside it, and its state and bindings are not
                // this link's. disconnect() cleared all three itself.
                const own = this._rfedLinkPromises.get(key) === promise;
                if (own) {
                    // Link.md: the binding dies with the link. The
                    // channel-stream memo is per channel, not per link, so it
                    // must be dropped here or the next link never re-sends
                    // /channel/stream/open and every /delivery silently goes
                    // to the deferred queue.
                    if (key === "link" || key === "channel.stream") this._rfedStreamPromises.clear();
                    this._rfedLinkPromises.delete(key);
                    this._rfedLinkState.set(key, established ? RFED_LINK_IDLE : RFED_LINK_FAILED);
                }
                if (!established) reject(new Error(`RFed ${key} link closed before establishment`));
                // A persistent link that was up and closed under us is
                // re-opened once (RFED_PERSISTENT_KEYS). Not one that
                // disconnect() already dropped from _rfedLinks.
                else if (current && RFED_PERSISTENT_KEYS.includes(key)) this._onRfedLinkClosed(key, link);
            });
        });
        this._rfedLinkPromises.set(key, promise);
        link.establish(destination);
        return promise;
    },

    /** Something is bound to the persistent link `key`: opened channels
     *  (both keys) or a distro (rfed.link carries its push and its pull). */
    _rfedPersistentBound(key) {
        if (this._rfedOpenedChannelHashes.size > 0) return true;
        return key === "link" && DistroManager.has;
    },

    /**
     * A new persistent link is up (a new rfed.link generation). Its re-open
     * is armed again (app-links: reconnect_armed on each ACTIVE), and the
     * bindings the node dropped with the last link are sent again before
     * anything is pulled, so a post fanned out after a binding comes live
     * and one deferred before it comes in the pull (Link.md "The client
     * re-binds on every link", tiers 1 and 4):
     *   1. identify: already sent by the "established" handler;
     *   2. /propagation/stream/open (distro push) and /channel/stream/open
     *      for every opened channel;
     *   3. once both have answered, /channel/pull for every opened channel
     *      and /distro/pull when a distro exists (iOS and Android pull once
     *      per fresh rfed link: Android ConversationScreen.kt:603-615, iOS
     *      ConversationView.swift:596-612).
     */
    async _onRfedLinkEstablished(key, link) {
        this._rfedReopenArmed.add(key);
        if (key !== "link") {
            await this._rebindChannelStream().catch(e => console.warn(`[retichat] Channel stream re-bind failed: ${e.message}`));
            return;
        }
        this._rfedLinkGeneration++;
        await Promise.allSettled([this._bindRfedLinkForDistroPush(), this._rebindChannelStream()]);
        // Closed or replaced while the bindings were answered: the next
        // link's own "established" pulls.
        if (this._rfedLinks.get(key) !== link || link.status !== Link.ACTIVE) return;
        this._pullOpenedChannels("new rfed.link", this._rfedLinkGeneration);
        if (DistroManager.has) this._pullDistroMessages();
    },

    /**
     * A persistent link that had been established closed, and it was the
     * current one. Re-open it once when the close was not ours (TIMEOUT or
     * DESTINATION_CLOSED), this tab holds the identity, something is bound
     * to it, and its re-open is armed; the flag is consumed. See
     * RFED_PERSISTENT_KEYS.
     */
    _onRfedLinkClosed(key, link) {
        const reason = link.closeReason;
        const hex = link.hash?.toString("hex").slice(0, 12) ?? "?";
        if (reason === Link.TIMEOUT) {
            // Keepalives should keep an idle link up; a TIMEOUT close is
            // the defect of 2026-09-29, which the re-open must not hide.
            console.error(`[retichat] RFed ${key} link ${hex} timed out (keepalive)`);
        }
        if (reason !== Link.TIMEOUT && reason !== Link.DESTINATION_CLOSED) {
            // Ours: disconnect() (another tab took over) or an identify
            // refusal. Re-armed only by a new explicit event.
            this._rfedReopenArmed.delete(key);
            console.log(`[retichat] RFed ${key} link ${hex} closed by this client — not re-opened`);
            return;
        }
        if (!this._rns || !ActiveTab.held) return;
        if (!this._rfedPersistentBound(key)) {
            console.log(`[retichat] RFed ${key} link ${hex} closed; nothing is bound to it, so it is not re-opened`);
            return;
        }
        if (!this._rfedReopenArmed.has(key)) {
            console.log(`[retichat] RFed ${key} link ${hex} closed; its re-open is not armed — waiting for the next announce or page resume`);
            return;
        }
        this._rfedReopenArmed.delete(key);
        console.log(`[retichat] 🔁 RFed ${key} link ${hex} closed under us (reason ${reason}) — re-opening it once`);
        this._redriveRfedLink(key, "close");
    },

    /**
     * One attempt at the persistent link `key`, on an event: its close, an
     * announce that re-drives a parked re-open, or the page coming back. Not
     * while it is up, STALE (its keepalive watchdog decides) or coming up,
     * and only when this tab holds the identity and something is bound to
     * it. An attempt that closes before establishment is parked for the
     * service's next announce (_rfedDeferUntilAnnounce); nothing re-tries it
     * on a clock (DESIGN_PRINCIPLES §3). While the exchange is down nothing
     * starts (_exchangeIsDown): the exchange's return is the event then
     * (_followExchange). Returns whether it started one.
     */
    _redriveRfedLink(key, trigger) {
        if (!this._rns || !ActiveTab.held) return false;
        if (!this._rfedPersistentBound(key)) return false;
        if (this._rfedLinks.get(key)?.status === Link.ACTIVE) return false;
        if (this._rfedLinkPromises.has(key)) return false;
        if (this._exchangeIsDown()) {
            console.log(`[retichat] RFed ${key} link is down, and so is the exchange — its return re-drives the link (${trigger})`);
            return false;
        }
        console.log(`[retichat] 🔗 RFed ${key} link is down — re-driving it (${trigger})`);
        Promise.resolve()
            .then(() => this._ensureRfedLink(key.split(".")))
            .catch((e) => {
                console.warn(`[retichat] RFed ${key} link re-open failed: ${e.message}`);
                if (this._rfedLinkState.get(key) === RFED_LINK_FAILED) {
                    this._rfedDeferUntilAnnounce(key, `rfed.${key} re-open`, () => this._redriveRfedLink(key, "announce"));
                }
            });
        return true;
    },

    /**
     * /channel/stream/open once for every opened channel that has no binding
     * on the current link yet (the memo is cleared when a link closes). One
     * request carries the whole filter set (_configureChannelStream), so it
     * is sent once and shared, rather than once per channel.
     */
    _rebindChannelStream() {
        // Before _initChannels has run, _configureChannelStream sends
        // nothing; no memo is set then, so _initChannels binds them.
        if (!this._channelsInitialized) return Promise.resolve();
        const unbound = ChannelStore.getAll().filter(ch => ch.isSubscribed
            && this._rfedOpenedChannelHashes.has(ch.channelHash)
            && !this._rfedStreamPromises.has(ch.channelHash));
        if (unbound.length === 0) return Promise.resolve();
        const configured = this._configureChannelStream();
        for (const ch of unbound) this._rfedStreamPromises.set(ch.channelHash, configured);
        return configured;
    },

    /** /channel/pull every opened channel (one pull per channel at a time:
     *  pullChannel's in-flight guard). With `generation`, a channel already
     *  pulled on that rfed.link generation (openChannel got there first) is
     *  not pulled again; a page resume pulls them all, as Android's
     *  ON_RESUME does. */
    _pullOpenedChannels(trigger, generation = null) {
        for (const ch of ChannelStore.getAll()) {
            if (!ch.isSubscribed || !this._rfedOpenedChannelHashes.has(ch.channelHash)) continue;
            if (generation !== null && this._rfedPullState.get(ch.channelHash)?.gen === generation) continue;
            this.pullChannel(ch.channelName).catch(e =>
                console.warn(`[retichat] 📡 Channel pull for #${ch.channelName} (${trigger}) failed: ${e.message}`));
        }
    },

    /** The key of the link a request on (aspects, path) travels on: rfed.link
     *  for every mapped path (_rfedRequest), else the aspect's own. */
    _rfedLinkKeyFor(aspects, path) {
        return RFED_LINK_PATHS[`${aspects.join(".")}:${path}`] ? "link" : aspects.join(".");
    },

    /**
     * An identify refusal (0xF0 NO_IDENTITY, 0xF1 NO_ACCESS) on a pull: tear
     * down the link it came on, so the next one identifies afresh (Link.md
     * "Identify"; LXMRouter.py message_list_response). The close is ours
     * (INITIATOR_CLOSED), so nothing re-opens it, and its re-open is
     * disarmed: the next link comes from the next request or explicit event,
     * never from this close, or a refusal that repeats would be an
     * establish, refuse, close loop (DESIGN_PRINCIPLES §3).
     */
    _closeRefusedRfedLink(key, what) {
        this._rfedReopenArmed.delete(key);
        const link = this._rfedLinks.get(key);
        if (!link) return;
        console.warn(`[retichat] ${what}: tearing down the ${key} link — the next link re-identifies`);
        link.close();
    },

    /**
     * `/propagation/stream/open` on rfed.link: tell the node to push live
     * LXMF for this device's lxmf.delivery hash down this link. That is the
     * distro fan-out's first delivery tier; without it every fan-out goes to
     * the deferred queue and waits for the next /distro/pull — on staging,
     * 40 s later. Payload: `[bin(16 delivery_hash), pubkey, sign(hash)]`
     * (LXMFProp.md). Re-sent on every link (re)establishment, since the
     * binding lives on the link.
     */
    async _bindRfedLinkForDistroPush() {
        if (!DistroManager.has || !this._rfedLinkAvailable()) return;
        // Once per link: the binding lives on the link, and a second open on
        // the same one is refused as `already_open`.
        const link = this._rfedLinks.get("link");
        if (link && link._retichatDistroBound) return;
        if (link) link._retichatDistroBound = true; // claim before the round trip
        const deliveryHash = Destination.hash(IdMgr.id, "lxmf", "delivery");
        const payload = MsgPack.pack([deliveryHash, IdMgr.id.getPublicKey(), IdMgr.id.sign(deliveryHash)]);
        try {
            const response = await this._rfedRequest(["link"], "/propagation/stream/open", payload);
            if (!Array.isArray(response) || response[0] !== true) {
                if (link) link._retichatDistroBound = false;
                console.warn(`[retichat] rfed.link push binding refused: ${JSON.stringify(response)}`);
                return;
            }
            console.log("[retichat] rfed.link bound for live distro pushes");
        } catch (e) {
            if (link) link._retichatDistroBound = false;
            console.warn(`[retichat] rfed.link push binding failed: ${e.message}`);
        }
    },

    /** A push from the node on the rfed.link link. */
    _onRfedLinkPush(link, requestId, pathHash, data) {
        if (!requestId || !Buffer.isBuffer(pathHash)) {
            console.warn(`[retichat] rfed.link push with no request id or a non-binary path (${typeof pathHash}) — ignored`);
            return;
        }
        const hex = pathHash.toString("hex");
        console.log(`[retichat] rfed.link push path=${hex.slice(0, 12)} bytes=${data?.length ?? "?"}`);
        const payload = Buffer.isBuffer(data) ? data : (data instanceof Uint8Array ? Buffer.from(data) : null);
        // Link.md "The response is the delivery proof": true means we hold
        // the blob; false is a refusal the node records instead of deferring.
        if (hex === RFED_LINK_PUSH_HASHES.delivery) {
            if (!payload) { link.sendResponse(requestId, false); return; }
            link.sendResponse(requestId, this._handleChannelPacket(payload) === true);
        } else if (hex === RFED_LINK_PUSH_HASHES.notify) {
            // A wake: something was deferred for this device, and it is
            // collected with /distro/pull (SPEC §17.3 tier 3; Android
            // WakeWorker, iOS RfedDistroClient.pull). Acknowledged at once,
            // so the node does not count the wake as missed; the pull is
            // the pull's own request. Until 2026-09-30 it was acknowledged
            // and nothing was pulled.
            link.sendResponse(requestId, true);
            if (DistroManager.has) this._pullDistroMessages();
        } else if (hex === RFED_LINK_PUSH_HASHES.lxmf) {
            // A live LXMF push for this device's lxmf.delivery — for this
            // client that is a distro fan-out (the node's distro tier 1),
            // carrying the bare blob `[dest_hash(16) | encrypted]` that
            // /distro/pull would otherwise return. Same handler, same dedup.
            if (!payload || payload.length < 48) { link.sendResponse(requestId, false); return; }
            Harness.event("distro-link-push", { bytes: payload.length });
            link.sendResponse(requestId, this._handleDistroBlob(payload.slice(0, 16), payload) === true);
        } else {
            console.warn(`[retichat] unknown push path ${hex.slice(0, 12)} on rfed.link — not acknowledged`);
        }
    },

    /** True once the node has announced `rfed.link`. */
    _rfedLinkAvailable() {
        return this._rfedServiceReady.has("link");
    },

    async _rfedRequest(aspects, path, packedValue) {
        // Every mapped control request goes over the single rfed.link
        // (RFed-spec/Link.md: one link per subscriber; the legacy per-aspect
        // destinations are kept for pre-split clients, not for this one).
        // Until 2026-09-23 this raced the rfed.link announce against the
        // legacy aspect's and took whichever landed first, so on a node whose
        // rfed.link announce arrived a second later the client opened a
        // per-aspect link as well and held two links. Now it waits for the
        // rfed.link announce (path-requested at startup) - an event, not a
        // timer - and never falls back to a legacy link for a mapped path.
        const mapped = RFED_LINK_PATHS[`${aspects.join(".")}:${path}`];
        if (mapped) {
            if (!this._rfedLinkAvailable()) {
                await this._waitForRfedService(["link"]);
            }
            aspects = ["link"];
            path = mapped;
        }
        const link = await this._ensureRfedLink(aspects);
        const startedAt = Date.now();
        // Scaled from the link's measured RTT, per RNS/Link.py:509. The
        // link's request receipt owns the timer (RNS/Link.py RequestReceipt):
        // it runs until the response starts to arrive, and stops while a
        // response Resource transfers (a /distro/pull page of photos takes
        // far longer than the budget); a failed transfer or a closed link
        // fails the request at once. Before 2026-09-30 a flat timer here kept
        // running through the transfer and threw the page away.
        const timeoutMs = rfedRequestTimeoutMs(link);
        const requestId = link.sendRequestPacked(path, packedValue, { timeoutMs });
        try {
            const data = await link.responseFor(requestId);
            console.log(`[retichat] ${path} answered in ${Date.now() - startedAt}ms (budget ${Math.round(timeoutMs)}ms)`);
            return data;
        } catch (e) {
            throw new Error(`${path}: ${e.message} (rtt=${link.rtt}ms)`);
        }
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
            // Prove every packet RFed delivers here, as the native apps'
            // PROVE_ALL rfed.delivery does, so RFed counts a delivery only when
            // it is proved and queues and pushes the rest (RFed SPEC §7). Until
            // 2026-09-26 nothing was proved.
            deliveryDest.on("packet", ({packet, data}) => {
                try { packet.prove(); } catch (e) { console.warn("[retichat] rfed.delivery proof failed", e.message); }
                this._handleChannelPacket(data);
            });
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
    /**
     * Returns true when the blob was kept (stored, or already held), false
     * when it was dropped. Link.md "The response is the delivery proof": the
     * push acknowledgement must say what actually happened, so callers ack
     * only a true. Until 2026-09-22 every push was acknowledged, including
     * ones dropped for an unknown channel or a bad signature.
     */
    _handleChannelPacket(packetData) {
        try {
            const data = Buffer.from(packetData || []);
            if (!data || data.length < 16 + 32) return false;

            // First 16 bytes are the channel identity hash (routing prefix)
            const channelIdPrefix = data.slice(0, 16).toString("hex");

            // Distro fanout arrives on this same rfed.delivery destination as
            // [ distro_lxmf_hash(16) | lxmf_blob ]. The PULL path carries the
            // bare lxmf_blob, so strip the extra routing prefix before unwrapping.
            if (DistroManager.has && channelIdPrefix === DistroManager.lxmfDeliveryHash) {
                Harness.event("distro-push", { distro: channelIdPrefix.slice(0, 12), bytes: data.length });
                return this._handleDistroBlob(data.slice(0, 16), data.slice(16));
            }

            const ch = ChannelStore.getByHash(channelIdPrefix);
            if (!ch) {
                console.log(`[retichat] 📡 Channel blob for unknown channel ${channelIdPrefix.slice(0,12)}..., ignoring`);
                return false;
            }

            // Unpack the channel message. A post whose prelude key does not
            // bind to its claimed source, or whose signature fails, is
            // rejected there (DISPLAY_NAMES.md §2.3), before any key below
            // is remembered.
            const result = channelLxmUnpack(ch.channelName, data);
            if (!result) {
                console.warn(`[retichat] 📡 Channel unpack failed for ${ch.channelName}`);
                return false;
            }

            const { sourceHash, tsMs, content, senderPubKey, displayName } = result;
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
                return true; // already held
            }
            this._chanSeenIds.add(dedupKey);
            // Cap the set size to prevent unbounded growth
            if (this._chanSeenIds.size > 2000) {
                const arr = [...this._chanSeenIds];
                this._chanSeenIds = new Set(arr.slice(-1000));
            }

            // Register sender identity from the RTID prelude. The key is
            // bound to srcHashHex (checked in channelLxmUnpack), so it may
            // fill a contact's missing key; one already held is never
            // replaced from a channel post.
            // This device's own posts (fetched history, echoes) never make it
            // a contact of itself (audit L4).
            // A poster the user has not added gets a hidden row, never a
            // listed contact (audit L4).
            if (senderPubKey && srcHashHex !== ownLxmfDestinationHash()) {
                const contact = ContactStore.keep(srcHashHex);
                if (contact && !contact.publicKey) {
                    contact.publicKey = Buffer.from(senderPubKey).toString("hex");
                    ContactStore._save();
                }
            }

            // §5.2: the post's 0xD1 (reported only after the binding and the
            // signature passed) sets or clears this sender's Channel Display
            // Name in this channel. It never becomes the contact's name.
            // Only a post newer than the one that last set or cleared it
            // counts (§5.2 order), so history pulled late cannot undo it.
            ChannelSenderNamesStore.apply(ch.channelName, srcHashHex, displayName, tsMs);
            // §4.2 rule 2: a sender not seen here before means our next post
            // carries our Channel Display Name again.
            ChannelPostNamesStore.noteSender(ch.channelName, srcHashHex, ownLxmfDestinationHash(), Date.now());

            // Insert message. The sender is stored as a hash and labelled at
            // render (channelSenderLabel), so a name that arrives later
            // relabels earlier posts.
            ChannelMsgStore.add(ch.channelName, {
                dir: "in", content, status: "delivered",
                srcHash: srcHashHex,
            });
            ChannelStore.touch(ch.channelName);

            this._onMsg.forEach(fn => fn({kind: "channel-receive"}, ch.channelName));
            console.log(`[retichat] 📡 Channel message on #${ch.channelName}: "${content.slice(0,60)}" from ${srcHashHex.slice(0,12)}`);
            return true;
        } catch(e) {
            console.warn("[retichat] 📡 Channel packet handler error:", e.message);
            return false;
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
                    this._bindRfedLinkForDistroPush();
                console.log(`[distro] ✅ Registered device with RFed (distro=${DistroManager.hash.slice(0,12)}...)`);
                    // Registration must land first: RFed refuses an announce for
                    // a distro with no registered device, since it would be
                    // advertising a route it cannot serve.
                    await this._publishDistroAnnounce();
                    return true;
                } else {
                    console.warn(`[distro] RFed refused registration:`, response);
                    return false;
                }
            } catch(e) {
                console.error(`[distro] Registration failed:`, e);
                // A link that never established is transient on this transport
                // (one lost LINKREQUEST/LRPROOF ends the attempt). Park the
                // intent for the next rfed.distro.register announce rather
                // than leaving the device unregistered for the whole session.
                if (this._rfedLinkState.get("distro.register") === RFED_LINK_FAILED) {
                    this._rfedDeferUntilAnnounce(
                        "distro.register",
                        "distro registration",
                        () => this._registerDistro(),
                    );
                }
                return false;
            } finally {
                this._registerDistroInFlight = null;
            }
        })();
        return this._registerDistroInFlight;
    },

    /**
     * Hand RFed a pre-signed announce for the distro address so it can
     * rebroadcast it on the distro's behalf.
     *
     * Announces are the only mechanism in Reticulum that distributes a public
     * key, and only the private key holder can sign one. RFed is given the
     * distro *public* key at registration and nothing more, so it cannot mint
     * this itself — without it, no third-party client (MeshChat, Sideband) can
     * ever learn the distro key, and LXMF cannot even construct a propagated
     * message to an identity it has no key for.
     *
     * This device holds the distro private key, so it signs the announce here
     * and RFed replays the bytes verbatim — the same operation a transport node
     * performs when it answers a path request out of its announce cache.
     */
    async _publishDistroAnnounce() {
        if (!DistroManager.has) return false;
        try {
            const distroIdentity = DistroManager.identity;
            // Not registered with the Reticulum instance: this destination is
            // only a vehicle for building the announce bytes. Registering it
            // would make this browser claim inbound delivery for the distro.
            const distroDestination = new Destination(
                this._rns, distroIdentity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery",
            );
            // app_data = [announce_name, nil, [SF_RFED_DISTRO]] (RFed SPEC
            // §17.10, DISPLAY_NAMES.md §2.2): the Announce Display Name as bin
            // or nil when unset, no stamp cost, no compression claim — the
            // SF_RFED_DISTRO flag is how every reader recognises a distro
            // address.
            const distroAppData = MsgPack.pack([
                OwnNames.announce ? Buffer.from(OwnNames.announce, "utf8") : null,
                null,
                [LXMF.SF_RFED_DISTRO],
            ]);
            const { announceData, contextFlag } = distroDestination.buildAnnounceData(distroAppData);

            // value = flags(1) ‖ announceData; bit 0 signals a ratchet, which
            // shifts where the signature starts when RFed parses it.
            const flags = Buffer.from([contextFlag === Packet.FLAG_SET ? 0x01 : 0x00]);
            const value = Buffer.concat([flags, announceData]);

            const distroPubKey = distroIdentity.getPublicKey();
            const sig = distroIdentity.sign(value);
            const payload = MsgPack.pack([value, distroPubKey, sig]);

            const response = await this._rfedRequest(["distro", "register"], "/rfed/distro/announce", payload);
            if (response === true || (Array.isArray(response) && response[0] === true)) {
                console.log(`[distro] 📡 RFed is now announcing the distro address (${DistroManager.hash.slice(0,12)}...)`);
                return true;
            }
            console.warn(`[distro] RFed refused the pre-signed announce:`, response);
            return false;
        } catch(e) {
            console.error(`[distro] Announce publication failed:`, e);
            return false;
        }
    },

    /** Unregister the distro identity from RFed. */
    async _unregisterDistro() {        if (!DistroManager.has) return false;
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

    /**
     * PULL deferred distro messages from RFed. One pull at a time: a call
     * while one is in flight gets that pull's result (the rfed.link
     * "established", the propagation link, a /notify wake and the page
     * resuming can all ask at once). A page that says more is queued, and
     * brought something, is followed by one more pull when it has been
     * handled: the completed response is the event, never a timer.
     */
    async _pullDistroMessages() {
        if (!DistroManager.has) return [];
        if (this._distroPullInFlight) return this._distroPullInFlight;
        let again = false;
        const pull = (async () => {
            // The link this pull travels on (rfed.link for the mapped path).
            const linkKey = this._rfedLinkKeyFor(["distro", "register"], "/rfed/pull");
            try {
                // No request data → msgpack nil, per the Python reference
                // (request(path, data=None)). Buffer.alloc(0) here produced a
                // malformed 2-element request the server could not parse — see
                // sendRequestPacked's guard.
                const response = await this._rfedRequest(["distro", "register"], "/rfed/pull", MsgPack.pack(null));
                // PULL authenticates by link identity, so the server can
                // refuse with a bare LXMF error code — mirroring the reference
                // propagation node, LXMF/LXMRouter.py:1445. The reference
                // client's reaction (LXMRouter.py:1525) is to tear the link
                // down: LINKIDENTIFY is fire-and-forget, so a fresh link whose
                // identify precedes the next request is the recovery. The link
                // is the one the pull used — rfed.link since the migration;
                // until 2026-09-30 this closed "distro.register", which a
                // mapped pull never opens, so the refused link stayed up. No
                // auto-retry and no re-open (DESIGN_PRINCIPLES §3): the next
                // request or explicit event makes the next link.
                if (typeof response === "number") {
                    const names = {0xF0:"NO_IDENTITY",0xF1:"NO_ACCESS",0xF3:"INVALID_KEY",0xF4:"INVALID_DATA"};
                    console.warn(`[distro] 📬 PULL refused: 0x${response.toString(16)} (${names[response]||"unknown"})`);
                    if (response === 0xF0 || response === 0xF1) {
                        this._closeRefusedRfedLink(linkKey, "[distro] 📬 PULL refused (ref: LXMRouter.message_list_response)");
                    }
                    return [];
                }
                if (!Array.isArray(response) || response.length < 2) return [];
                const [pairs, morePending] = response;
                const count = pairs?.length ?? 0;
                console.log(`[distro] 📬 PULL returned ${count} blob(s), more=${morePending}`);
                for (const pair of pairs || []) {
                    if (!Array.isArray(pair) || pair.length < 2) continue;
                    const [distroHash, blob] = pair;
                    this._handleDistroBlob(distroHash, blob);
                }
                // A page that brought nothing is not followed, whatever it
                // says: pulling again would repeat the same answer.
                again = morePending === true && count > 0;
                return pairs || [];
            } catch(e) {
                console.error(`[distro] PULL failed:`, e);
                // The link never came up. On rfed.link the re-drive is parked
                // (its "established" pulls again); a legacy link parks the
                // pull itself.
                if (this._rfedLinkState.get(linkKey) === RFED_LINK_FAILED) {
                    if (linkKey === "link") {
                        this._rfedDeferUntilAnnounce(linkKey, "rfed.link re-open", () => this._redriveRfedLink(linkKey, "announce"));
                    } else {
                        this._rfedDeferUntilAnnounce(linkKey, "distro pull", () => this._pullDistroMessages());
                    }
                }
                return [];
            }
        })();
        this._distroPullInFlight = pull;
        try {
            return await pull;
        } finally {
            // Only its own entry: after a reconnect a newer pull may hold it.
            if (this._distroPullInFlight === pull) this._distroPullInFlight = null;
            if (again) {
                console.log("[distro] 📬 More is queued — pulling the next page");
                this._pullDistroMessages();
            }
        }
    },

    /**
     * Handle a distro blob (a push on rfed.link, the channel stream's distro
     * prefix, or /distro/pull). Returns true when this device keeps the
     * message the blob carries, or already holds it; false when the blob was
     * dropped: the push answers rfed with it (Link.md "The response is the
     * delivery proof"), so rfed is never told the web holds a blob it threw
     * away. A dropped blob is not recorded as seen, so a later copy of it is
     * judged again.
     */
    _handleDistroBlob(distroHash, blob) {
        try {
            const data = Buffer.from(blob);
            if (data.length < 48) return false;
            // blob format: [dest_hash(16) | EC_encrypted(lxmf_data)]
            const destHash = data.slice(0, 16);
            const myLxmfHash = DistroManager.lxmfDeliveryHash;
            if (!destHash.equals(Buffer.from(myLxmfHash, "hex"))) {
                console.log(`[distro] Blob not for us: ${destHash.toString("hex").slice(0,12)}`);
                return false;
            }
            // Decrypt with distro identity
            const decrypted = DistroManager.identity.decrypt(data.slice(16));
            if (!decrypted || decrypted.length < 80) return false;
            const srcHash = decrypted.slice(0, 16);
            const payloadBytes = decrypted.slice(80);
            // LXMessage.decodePayload: a fields map that cannot be decoded
            // costs the fields (and so the attachments), never the message
            // (Android 702e5fb: such a map from a stranger lost the text for
            // good, and every later copy was deduped as seen).
            const payload = LXMessage.decodePayload(payloadBytes);
            const { timestamp: ts, content: contentBin, fields: fieldsMap } = payload;
            const content = Buffer.from(contentBin || []).toString();
            const srcHashHex = srcHash.toString("hex");
            const found = payload.attachments;
            const unreadable = found.skipped || payload.fieldsUnreadable;

            // Idempotency: the same blob is delivered more than once (see
            // DistroSeen). Drop repeats before they reach the store, or the
            // conversation fills with duplicates of every message.
            const dedupKey = `${srcHashHex}:${ts}`;
            if (DistroSeen.check(dedupKey)) {
                Harness.event("distro-dup", { src: srcHashHex.slice(0, 12), ts });
                console.log(`[distro] ↩︎ duplicate, ignoring (${srcHashHex.slice(0,12)} ts=${ts})`);
                return true; // already held
            }
            // Nothing kept: un-record it, so a later copy is not answered
            // "already held" (see above), and tell the caller.
            const dropped = () => { DistroSeen.forget(dedupKey); return false; };

            // RFed SPEC §17.11 sent-message sync: another device of this
            // distro sent a message as the distro and propagated a copy here.
            // It is "me" talking, so it belongs in the conversation with the
            // recipient (0xFC) as an OUTGOING bubble, not as a message from
            // the distro address. Mirrors Retichat-android / Retichat-ios,
            // which read the same marker through distro.rs sent_to / sent_by.
            // Dedupe above already recorded it (same src:ts key as every
            // fan-out message), so a copy that arrives by stream and by PULL
            // is stored once, and an own echo stays dropped on re-delivery.
            const sentCopy = LXMF.distroSentCopyFromFields(fieldsMap);
            if (sentCopy) {
                // SPEC §17.11 receive rules, in order; the first drop ends it.
                // Rule 1, source.
                if (srcHashHex !== myLxmfHash) {
                    console.warn(`[distro] ⚠️ Sent-copy marker from ${srcHashHex.slice(0,12)}, not our distro — ignored (§17.11 rule 1)`);
                    return dropped();
                }
                // Rule 2, signature. Stored as "me", so the source must really
                // be the distro's key, not just its address: anyone can
                // encrypt to D's announced public key and claim source D.
                // LXMF signs dest | src | payload | SHA-256(dest | src | payload)
                // over the four-element payload; a fifth element (a stamp) is
                // appended after signing, so it is left out here as
                // LXMessage.unpack_from_bytes leaves it out
                // (LXMessage.signedPayload, from the received bytes).
                const hashedPart = Buffer.concat([destHash, srcHash, LXMessage.signedPayload(payloadBytes)]);
                const signature = decrypted.slice(16, 80);
                if (!DistroManager.identity.validate(signature, Buffer.concat([hashedPart, Cryptography.fullHash(hashedPart)]))) {
                    console.warn(`[distro] ⚠️ Sent-copy for ${sentCopy.toHex?.slice(0,12) ?? "?"} fails the distro signature — dropped (§17.11 rule 2)`);
                    return dropped();
                }
                // Rule 3, own echo.
                if (sentCopy.byHex === (this.ownHash ?? ownLxmfDestinationHash())) {
                    // Held: the copy is this device's own message, stored
                    // here when it was sent. It stays recorded as seen.
                    console.log(`[distro] ↩︎ own sent-copy echo for ${sentCopy.toHex?.slice(0,12) ?? "?"} — dropped (§17.11 rule 3)`);
                    return true;
                }
                // Rule 4, recipient: 32 hex and never D itself (no copy is
                // sent for a message to D; filing one would open a chat with
                // the distro address).
                if (!sentCopy.toHex || sentCopy.toHex === myLxmfHash) {
                    console.warn(`[distro] ⚠️ Sent-copy with a malformed 0xFC recipient from device ${sentCopy.byHex.slice(0,12) || "?"} — dropped (§17.11 rule 4)`);
                    return dropped();
                }
                const recipientHex = sentCopy.toHex;
                // No contact request and no stranger filter: this device's own
                // side of a conversation opens it. No notification either —
                // nobody is told about their own message.
                if (!ContactStore.isContact(recipientHex)) {
                    ContactStore.add(recipientHex);
                }
                // "sent", never "proved"/"delivered": this device holds no
                // evidence of delivery, only that the distro said it. §17.11
                // copies are text only (SPEC: "attachments are not copied"),
                // so a message that carried only attachments arrives empty:
                // it shows iOS's placeholder (ChatRepository.swift
                // handleDistroSentCopy), not an empty bubble. Attachments a
                // copy does carry are kept like any other.
                const placeholder = !content.trim() && !found.length && !unreadable;
                const record = MsgStore.add(recipientHex, {
                    dir: "out", content: placeholder ? DISTRO_ATTACHMENT_PLACEHOLDER : content, status: "sent",
                    srcHash: myLxmfHash, destHash: recipientHex, via: "distro",
                    timestamp: Number.isFinite(Number(ts)) ? Math.round(Number(ts) * 1000) : Date.now(),
                });
                const stored = found.length || unreadable
                    ? this._keepAttachments(MsgStore, recipientHex, record, found, payload.fieldsUnreadable)
                    : record;
                ContactStore.touch(recipientHex);
                console.log(`[distro] 📤 Synced sent message to ${recipientHex.slice(0,12)} from device ${sentCopy.byHex.slice(0,12)}: "${content.slice(0,60)}"`);
                Harness.event("distro-sent-sync", { to: recipientHex.slice(0, 12), by: sentCopy.byHex.slice(0, 12) });
                this._onMsg.forEach(fn => fn(stored, recipientHex));
                return true;
            }

            // Delivery notifications now arrive here too. Since we send as the
            // distro, the recipient's ticket reply is addressed to the distro
            // and reaches us fanned out rather than direct. It carries a ticket
            // and no content; storing it would post an empty bubble. One that
            // carries an attachment is a message (LXMF.isDeliveryNotification,
            // LXMF-rust 06c40e1), and only a ticket of ours is looked up
            // (LXMF.webTicket: the reference's [expires, ticket] never is).
            if (LXMF.isDeliveryNotification(fieldsMap, content)) {
                const ticket = LXMF.webTicket(fieldsMap);
                const pending = ticket ? this._pendingTickets.get(ticket) : null;
                if (pending) {
                    this._pendingTickets.delete(ticket);
                    console.log(`[distro] ✅ PROOF (LXMF via distro) ticket=${ticket.slice(0,8)}… from ${srcHashHex.slice(0,12)}`);
                    if (pending.onProof) pending.onProof(pending.messageId);
                    else MsgStore.updateStatus(pending.contactHash, pending.messageId, "proved");
                    this._onMsg.forEach(fn => fn(null, pending.contactHash));
                    return true; // its proof was taken
                }
                console.log(`[distro] delivery notification from ${srcHashHex.slice(0,12)} for a ticket that is not one we are waiting on — dropped`);
                return dropped();
            }

            console.log(`[distro] 📥 Message from ${srcHashHex.slice(0,12)}: "${content.slice(0,60)}"`);
            // Auto-add contact and store message. No privacy filter here:
            // mail to the distro is mail to this person (iOS
            // handleDistroMessage, Android onDistroMessageReceived). The row
            // is listed, not allowlisted, as the phones make a plain row
            // (ensureContact): a DM from the sender to this device's own
            // address still needs the user to add or answer them.
            if (!ContactStore.isContact(srcHashHex)) {
                ContactStore.add(srcHashHex);
            }
            // DISPLAY_NAMES.md §5.2 on the distro path too: the sender's 0xD1,
            // taken according to the LXMF signature, checked here exactly as
            // the router checks the direct paths (LXMessage.verify).
            const signature = LXMessage.verify(destHash, srcHash, decrypted.slice(16, 80), payloadBytes);
            const signatureState = signature.validated ? "validated"
                : signature.unverifiedReason === LXMessage.SOURCE_UNKNOWN ? "unknown" : "invalid";
            if (!signature.validated) console.log(`[distro] Message from ${srcHashHex.slice(0,12)}: signature ${signatureState}`);
            ContactStore.acceptMessageName(srcHashHex, decodeDisplayName(payloadBytes), signatureState, ts);
            // Its attachments, as on the direct path. With neither text nor
            // an attachment to show, iOS's placeholder stands in
            // (RfedDistroClient.swift DistroMessageStore.stored), not an
            // empty bubble.
            const placeholder = !content.trim() && !found.length && !unreadable;
            const record = MsgStore.add(srcHashHex, { dir: "in", content: placeholder ? DISTRO_ATTACHMENT_PLACEHOLDER : content,
                status: "delivered", srcHash: srcHashHex, via: "distro", lxmfHash: signature.hash.toString("hex") });
            const stored = found.length || unreadable
                ? this._keepAttachments(MsgStore, srcHashHex, record, found, payload.fieldsUnreadable)
                : record;
            ContactStore.touch(srcHashHex);
            // Pass the stored message, not null: listeners read a null `msg` as
            // a proof-only event and only repaint status ticks, so a distro
            // message used to land in storage without ever reaching the UI.
            this._onMsg.forEach(fn => fn(stored, srcHashHex));
            return true;
        } catch(e) {
            console.error(`[distro] Failed to handle blob:`, e);
            return false;
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
        // Once per rfed.link generation, not once per session: a link that
        // closed and re-opened pulls again (its "established" does, and so
        // does this). Until 2026-09-30 a channel was pulled at most once per
        // page load, so what the node deferred after that waited for a reload.
        const pulled = this._rfedPullState.get(channel.channelHash);
        const pull = pulled?.gen === this._rfedLinkGeneration && this._rfedLinkGeneration > 0
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

    /**
     * /channel/pull one channel: what the node deferred for this subscriber
     * on it (Channel.md /rfed/pull). One pull per channel at a time (the
     * in-flight guard). A page that says more is queued, and brought
     * something, is followed by one more pull once it has been handled: the
     * completed response is the event, never a timer. The rfed.link
     * generation of a completed pull is recorded (openChannel).
     */
    async pullChannel(channelName) {
        const channel = ChannelStore.get(channelName);
        if (!channel) return false;
        const key = channel.channelHash;
        const current = this._rfedPullState.get(key);
        if (current?.inFlight) return current.morePending !== false;
        this._rfedPullState.set(key, {inFlight: true, morePending: current?.morePending, gen: current?.gen});
        this._onMsg.forEach(fn => fn({kind: "channel-pull-start"}, channelName));
        let again = false;
        try {
            const response = await this._rfedRequest(
                ["channel", "pull"],
                "/rfed/pull",
                MsgPack.pack(Buffer.from(key, "hex"))
            );
            // Link.md "Identify": ERROR_NO_IDENTITY (0xF0) means the node saw no
            // LINKIDENTIFY on this link. Close it; the next link identifies
            // on it (same rule as /distro/pull). The close does not re-open
            // the link (_closeRefusedRfedLink).
            if (typeof response === "number") {
                const names = {0xF0:"NO_IDENTITY",0xF1:"NO_ACCESS",0xF3:"INVALID_KEY",0xF4:"INVALID_DATA"};
                console.warn(`[retichat] 📡 channel PULL refused: 0x${response.toString(16)} (${names[response]||"unknown"})`);
                if (response === 0xF0 || response === 0xF1) {
                    this._closeRefusedRfedLink(this._rfedLinkKeyFor(["channel", "pull"], "/rfed/pull"), "📡 channel PULL refused");
                }
                throw new Error(`channel pull refused: 0x${response.toString(16)}`);
            }
            if (!Array.isArray(response) || !Array.isArray(response[0])) {
                throw new Error("Malformed RFed pull response");
            }
            for (const pair of response[0]) {
                if (!Array.isArray(pair) || pair.length !== 2) continue;
                this._handleChannelPacket(Buffer.concat([Buffer.from(pair[0]), Buffer.from(pair[1])]));
            }
            const morePending = response[1] === true;
            this._rfedPullState.set(key, {inFlight: false, morePending, gen: this._rfedLinkGeneration});
            // A page that brought nothing is not followed, whatever it says:
            // pulling again would repeat the same answer.
            again = morePending && response[0].length > 0;
            return morePending;
        } catch(e) {
            this._rfedPullState.set(key, {inFlight: false, morePending: current?.morePending, gen: current?.gen});
            throw e;
        } finally {
            this._onMsg.forEach(fn => fn({kind: "channel-pull-complete"}, channelName));
            if (again) {
                console.log(`[retichat] 📡 More is queued for #${channelName} — pulling the next page`);
                this.pullChannel(channelName).catch(e =>
                    console.warn(`[retichat] 📡 Channel pull for #${channelName} failed: ${e.message}`));
            }
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
        ChannelSenderNamesStore.forget(channelName);
        ChannelPostNamesStore.forget(channelName);
        ChannelStore.leave(channelName);
        this._onMsg.forEach(fn => fn({kind: "channel-left"}, channelName));
    },

    /** Send a message to a channel. */
    async sendChannelMessage(channelName, content) {
        if (!IdMgr.has) throw new Error("No identity");

        // D3: a post with the exchange down fails now and is never sent
        // (see sendMessage).
        if (this._exchangeIsDown()) {
            const failed = ChannelMsgStore.add(channelName, {
                dir: "out", content, status: "failed",
                srcHash: IdMgr.hash,
            });
            ChannelStore.touch(channelName);
            console.warn(`[retichat] ✗ Post to #${channelName} not sent: the exchange is down`);
            this._onMsg.forEach(fn => fn({kind: "channel-send-complete"}, channelName));
            return failed;
        }

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

            // Pack the channel message, carrying the Channel Display Name
            // when the channel rule says so (DISPLAY_NAMES.md §4.2). It
            // never falls back to the Message Display Name.
            const nameDecidedAt = Date.now();
            const postName = ChannelPostNamesStore.decide(channelName, OwnNames.channel, nameDecidedAt);
            const { wire, tsMs } = channelLxmPack(channelName, IdMgr.id, content, postName);

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
            const echoPromise = this._waitForRfedPublishEcho(echoKey, channelName, link);
            if (oversized) {
                // A resource has no single packet hash to prove against, so
                // the resource's own proof is the delivery evidence.
                await Promise.all([link.sendResource(finalPayload), echoPromise]);
            } else {
                const packet = link.send(finalPayload);
                await Promise.all([
                    this._waitForRfedPublishProof(packet, channelName, outMsg.id, link),
                    echoPromise,
                ]);
            }

            // Mark as sent. RFed has the post, so what it carried is recorded
            // for the channel rule (§4.2).
            ChannelMsgStore.updateStatus(channelName, outMsg.id, "sent");
            ChannelPostNamesStore.recordIncluded(channelName, postName, nameDecidedAt);
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

    _waitForRfedPublishProof(packet, channelName, messageId, link) {
        const proofKey = packet.packetHash.slice(0, 16).toString("hex");
        const timeoutMs = rfedRequestTimeoutMs(link);
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this._pendingPacketHashes.delete(proofKey);
                reject(new Error(`No RFed publish proof for #${channelName} within ${Math.round(timeoutMs)}ms`));
            }, timeoutMs);
            this._pendingPacketHashes.set(proofKey, {
                contactHash: channelName,
                messageId,
                // A proof that arrives at all is a proof. Only the timer fails.
                onProof: () => { clearTimeout(timer); resolve(); },
            });
        });
    },

    _waitForRfedPublishEcho(echoKey, channelName, link) {
        const timeoutMs = rfedRequestTimeoutMs(link);
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this._rfedPendingEchoes.delete(echoKey);
                reject(new Error(`No RFed stream acceptance for #${channelName} within ${Math.round(timeoutMs)}ms`));
            }, timeoutMs);
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
        // A stopped tab (taken over by another, or reconnecting) re-drives
        // nothing: no page events, and no persistent link re-opens. The
        // links below close as INITIATOR_CLOSED, which never re-opens, and
        // _rfedLinks is cleared before their (deferred) close events run.
        this._unhookPageLifecycle();
        this._rfedReopenArmed.clear();
        this._propReopenArmed = false;
        this._distroPullInFlight = null;
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
        this._propLinkUpWaiters.splice(0).forEach(waiter => waiter.reject(new Error("Disconnected before propagation link became active")));
        this._propLinkPromise = null;
        this._propLinkResolve = null;
        this._propLinkReject = null;
        // The propagation link is bound to the interface being stopped. Left
        // in place, reconnect() would hand the old ACTIVE link to every
        // upload, and they would queue into a dead interface until it went
        // STALE. Nulled before close() so its "close" is a superseded one.
        const propLink = this._propLink;
        this._propLink = null;
        try { propLink?.close(); } catch(e) {}
        this._propagationInitialized = false;
        this._initialized = false;
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
/** One compact settings line: KEY | value (truncated, full text in the
 *  tooltip) | copy button. Clicking either the value or the button copies.
 *  Replaces the full-width bubble that every hash used to get. */
function kvRow(key, value, opts = {}) {
    const text = value ?? "";
    const usable = text !== "";
    const copyBtn = usable
        ? h("button", { className: "kv-copy", title: `Copy ${key.toLowerCase()}` }, "⧉")
        : null;
    const copy = () => {
        navigator.clipboard.writeText(text).catch(() => {});
        if (!copyBtn) return;
        copyBtn.classList.add("copied");
        copyBtn.textContent = "✓";
        setTimeout(() => { copyBtn.classList.remove("copied"); copyBtn.textContent = "⧉"; }, 1200);
    };
    if (copyBtn) copyBtn.addEventListener("click", copy);
    return h("div", { className: "kv-row" },
        h("div", { className: "kv-key" }, key),
        h("button", {
            className: "kv-val" + (usable ? "" : " muted"),
            title: usable ? text : "",
            disabled: !usable,
            onClick: () => { if (usable) copy(); },
        }, usable ? (opts.display ?? text) : (opts.empty ?? "—")),
        copyBtn,
    );
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

/** A system notice as shown: a notice about a member stores that member's
 *  hash (GroupMsgStore.addSystem) and names it now, through the resolver
 *  (DISPLAY_NAMES.md §5.3). Older notices carry their text only. */
/**
 * A pre-2026-09-27 system notice's frozen name, matched to one group member:
 * "<name> joined the group", "<name> left the group" or "<name> invited you
 * to …", where <name> was the member's old name, a "?hash8" placeholder, or 8/12 hex.
 * A hash form matches the member whose hash starts with it; a name matches
 * the member it resolves to today. Returns { actor, content } (the text
 * without the name) or null when not exactly one member matches.
 */
function legacyNoticeActor(content, memberHashes, nameOf) {
    const match = /^(.+?) (joined the group|left the group|invited you to ".*")$/s.exec(content ?? "");
    if (!match) return null;
    const [, who, rest] = match;
    const hex = /^\??([0-9a-f]{8,32})$/.exec(who);
    const candidates = hex
        ? memberHashes.filter(h => h.startsWith(hex[1]))
        : memberHashes.filter(h => nameOf(h) === who);
    return candidates.length === 1 ? { actor: candidates[0], content: rest } : null;
}

function systemMessageText(m) {
    return m.actor ? `${ContactStore.name(m.actor)} ${m.content}` : m.content;
}

/** The sender label of an incoming group message, resolved at render. */
function groupSenderLabel(m) {
    if (m.dir !== "in") return null;
    if (m.srcHash) return { label: ContactStore.name(m.srcHash), secondary: null };
    return m.senderName ? { label: m.senderName, secondary: null } : null;
}

/** The sender label of an incoming channel post (§5.3): the user's own name
 *  for the sender with the Channel Display Name beside it; else that channel
 *  name with the sender's short hash beside it; else the contact chain. */
function channelSenderLabel(channelName, m) {
    if (m.dir !== "in") return null;
    if (m.srcHash) {
        return channelPosterName(
            ChannelSenderNamesStore.get(channelName, m.srcHash),
            ContactStore.get(m.srcHash),
            m.srcHash,
        );
    }
    return m.senderName ? { label: m.senderName, secondary: null } : null;
}
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
//  ONE ACTIVE TAB PER IDENTITY (D11)
// =========================================================================
/**
 * Only one tab per identity connects; lib/tab_lock.js has the mechanism. A
 * tab that finds another active says so and offers "Use here". The tab it
 * takes over from stops, says it was opened in another tab, and offers the
 * same. RnsClient.connect() refuses without the lock, so no tab registers
 * with the exchange before it holds it.
 *
 * "Use here" reloads the page with a takeover flag in sessionStorage, and
 * the reloaded page takes over as it starts. The other tab may have changed
 * contacts, groups and messages since this one read them into memory, and a
 * reload reads every store again.
 */
const ActiveTab = {
    TAKEOVER_KEY: "retichat_takeover",
    _lock: null,
    _connect: null,
    _overlay: null,

    /** This tab holds the identity's lock (or runs where it cannot be arbitrated). */
    get held() { return this._lock?.held ?? false; },

    /** Run `connect` once this tab is the active tab for the identity. */
    async start(connect) {
        this._connect = connect;
        this._lock = new TabLock(`retichat:tab:${IdMgr.hash}`, { onTakenOver: () => this._takenOver() });
        let takeover = false;
        try {
            takeover = sessionStorage.getItem(this.TAKEOVER_KEY) === "1";
            sessionStorage.removeItem(this.TAKEOVER_KEY);
        } catch (e) {}
        if (takeover) this._show("taking-over");
        const held = takeover ? await this._lock.takeOver() : await this._lock.tryAcquire();
        if (!held) {
            console.log("[retichat] Retichat is active in another tab — this tab does not connect");
            Harness.event("tab", { state: "blocked" });
            this._show("blocked");
            return;
        }
        await this._activate();
    },

    /** The "Use here" button, in every state of the pop-up. */
    async useHere() {
        // Already queued for the lock ("Taking over…"): ask the active tab
        // again. Its first request can go unheard — two tabs pressed at once
        // and this one's reached the other before the lock did, or the
        // active tab never handled it — and only the active tab letting go
        // ends the wait.
        if (this._lock?.waiting) {
            this._lock.takeOver();
            return;
        }
        try {
            sessionStorage.setItem(this.TAKEOVER_KEY, "1");
            location.reload();
            return;
        } catch (e) {
            // No sessionStorage to carry the flag across a reload: take over in place.
        }
        this._show("taking-over");
        if (await this._lock.takeOver()) await this._activate();
    },

    async _activate() {
        this._hide();
        console.log("[retichat] This tab is the active tab for its identity");
        Harness.event("tab", { state: "active" });
        try { await this._connect(); } catch (e) { console.error("RNS connect failed", e); }
    },

    /** TabLock onTakenOver: stop exchanging before the lock is released. */
    _takenOver() {
        console.log("[retichat] Retichat was opened in another tab — stopping here");
        RnsClient.disconnect();
        Harness.event("tab", { state: "taken-over" });
        this._show("taken-over");
    },

    _show(kind) {
        // Every state keeps "Use here": while taking over it asks again (useHere).
        const [title, text] = {
            "blocked": ["Retichat is open in another tab",
                "Only one tab can be connected for this identity at a time. Use it here, and the other tab stops."],
            "taken-over": ["Retichat was opened in another tab",
                "This tab has stopped. Use it here, and the other tab stops instead."],
            "taking-over": ["Taking over from the other tab…",
                "Waiting for the other tab to stop. If nothing happens, press Use here again."],
        }[kind];
        this._hide();
        const body = h("div", { className: "modal-body" },
            h("p", { style: { fontSize: "15px", lineHeight: "1.5" } }, text),
            h("div", { className: "btn-row", style: { marginTop: "20px" } },
                h("button", { className: "btn btn-primary", onClick: () => this.useHere() }, "Use here")));
        this._overlay = h("div", { className: "modal-overlay", style: { zIndex: 10001 }, "data-tab-state": kind },
            h("div", { className: "modal-sheet", role: "alertdialog" },
                h("div", { className: "modal-header" }, h("h2", {}, title)),
                body));
        // The overlay covers the composer; keystrokes must not reach it either.
        document.activeElement?.blur?.();
        document.body.appendChild(this._overlay);
    },

    _hide() {
        this._overlay?.remove();
        this._overlay = null;
    },
};

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
        showIdentity: false,      // consolidated Device + Distro identity screen
        revealDeviceKey: false,   // private-key disclosure, reset on close
        revealDistroKey: false,
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
    // chat id -> attachments picked for the next message there: [{name, bytes, mime}]
    _pendingAttachments: new Map(),
    _fileInput: null,

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
        this._wire();
        this._listenResize();
        await ActiveTab.start(() => RnsClient.connect());
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
            if (e.key === "Escape" && this._closeAllModals()) this.render();
        });
    },

    /** Clear every modal flag. Returns true if anything was actually open, so
     *  callers can skip a needless render. */
    _closeAllModals() {
        const wasOpen = this.state.showSettings || this.state.showAddContact ||
            this.state.showIdentity || this.state.showContactInfo ||
            this.state.showNewConversation || this.state.showGroupInfo ||
            this.state.showChannelInfo;
        this.state.showSettings = false;
        this.state.showAddContact = false;
        this.state.showIdentity = false;
        this.state.revealDeviceKey = false;
        this.state.revealDistroKey = false;
        this.state.showContactInfo = false;
        this.state.showNewConversation = false;
        this.state.showGroupInfo = false;
        this.state.showChannelInfo = false;
        return wasOpen;
    },

    // ===== FOCUS PRESERVATION =====
    // Saves composer state before a render that would destroy the DOM,
    // so we can restore focus afterward.
    _saveComposerFocus() {
        const ta = document.getElementById("composer-input");
        if (!ta) { this._savedFocus = null; return; }
        // Capture the draft whether or not the composer holds focus — a half
        // typed message is just as easy to lose when the user has clicked away.
        this._savedFocus = {
            activeHash: this.state.activeHash,
            hadFocus: document.activeElement === ta,
            cursorPos: ta.selectionStart,
            value: ta.value,
        };
    },

    _restoreComposerFocus() {
        const sf = this._savedFocus;
        this._savedFocus = null;
        if (!sf) return;
        // Only restore if we're still in the same chat
        if (this.state.activeHash !== sf.activeHash) return;
        const ta = document.getElementById("composer-input");
        if (!ta) return;
        // Restore the in-flight text and cursor position
        if (sf.value && ta.value !== sf.value) {
            ta.value = sf.value;
            ta.style.height = "auto";
            ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
        }
        if (!sf.hadFocus) return;
        ta.focus();
        if (sf.cursorPos !== undefined && sf.value === ta.value) {
            ta.setSelectionRange(sf.cursorPos, sf.cursorPos);
        }
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
        if (this.state.showIdentity) this._renderIdentityModal();
        if (this.state.showContactInfo) this._renderContactInfoModal();
        if (this.state.showNewConversation) this._renderNewConversationModal();
        if (this.state.showGroupInfo) this._renderGroupInfoModal();
        if (this.state.showChannelInfo) this._renderChannelInfoModal();

        // Re-apply status dot after DOM rebuild (RNS status hasn't changed so listener won't fire)
        this._applyStatusDot();

        // The bubbles just replaced let go of their attachments' object URLs.
        AttachmentUrls.sweep();

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

    // ===== SELECTIVE UPDATES =====
    //
    // render() tears down and rebuilds the entire tree. Anything that can
    // arrive while the user is mid-conversation — an inbound DM, a distro
    // blob, an announce or path response that fills in a public key — must NOT
    // go through it, or the open chat is reset under the user's hands: scroll
    // jumps to the top, the list flashes, and any open modal disappears.
    // The helpers below repaint only the region that actually changed.

    /** Rebuild the sidebar in place. The detail pane and any open modal
     *  survive untouched; the search box keeps its value, caret and focus. */
    _refreshSidebar() {
        const sidebar = this.root.querySelector(".sidebar");
        if (!sidebar || sidebar.classList.contains("hidden")) return;

        const search = sidebar.querySelector("#search-input");
        const hadFocus = search && document.activeElement === search;
        const caret = hadFocus ? search.selectionStart : null;

        clear(sidebar);
        sidebar.appendChild(this._buildSidebarContent());
        this._applyStatusDot();

        if (hadFocus) {
            const next = sidebar.querySelector("#search-input");
            if (next) {
                next.focus();
                if (caret !== null) next.setSelectionRange(caret, caret);
            }
        }
    },

    /** Append to the open chat's message list any records that reached the
     *  store but aren't on screen yet.
     *
     *  Reads from the store rather than from the event payload: the `msg`
     *  argument handed to onMessage listeners is not consistent across senders
     *  (some pass the LXMF message, some the stored record, some null), and
     *  the DOM is the only reliable statement of what has already been shown.
     *
     *  Returns false when there is no open chat list to append to. */
    _syncOpenChatMessages() {
        const id = this.state.activeHash;
        if (!id) return false;
        const list = document.getElementById("msg-list");
        if (!list) return false;

        let records, build;
        if (GroupStore.isGroupChat(id)) {
            records = GroupMsgStore.get(id);
            build = (m) => m.dir === "system" ? this._buildSystemMsg(m) : this._buildMsgBubble(m, groupSenderLabel(m));
        } else if (ChannelStore.get(id)) {
            records = ChannelMsgStore.get(id);
            build = (m) => m.dir === "system"
                ? this._buildSystemMsg(m)
                : this._buildMsgBubble(m, channelSenderLabel(id, m));
        } else {
            records = MsgStore.get(id);
            build = (m) => this._buildMsgBubble(m);
        }

        const onScreen = new Set(
            [...list.querySelectorAll("[data-msg-id]")].map(el => el.getAttribute("data-msg-id"))
        );
        const missing = records.filter(m => !onScreen.has(m.id));
        if (missing.length === 0) return true;

        // Group and channel views seed an "empty-chat" placeholder — drop it
        // now that there is something real to show.
        list.querySelector(".empty-chat")?.remove();
        for (const m of missing) list.appendChild(build(m));
        return true;
    },

    /** Bring the open DM's header and composer in line with the contact store.
     *  This is what makes a path response visible: the announce fills in the
     *  public key, and the composer flips from disabled to enabled without the
     *  message list or the draft being touched. */
    _syncOpenChatChrome() {
        const id = this.state.activeHash;
        if (!id) return;
        if (GroupStore.isGroupChat(id) || ChannelStore.get(id)) {
            this._refreshNameLabels();
            return;
        }
        const c = ContactStore.get(id);
        if (!c) return;
        const view = this.root.querySelector(".detail .chat-view");
        if (!view) return;

        // The header follows a name that arrives while the chat is open
        // (a 0xD1, an announce, a rename): ContactStore notifies, this runs.
        const name = ContactStore.name(c.destHash);
        const nameEl = view.querySelector(".header-name");
        if (nameEl && nameEl.textContent !== name) nameEl.textContent = name;
        const avatarEl = view.querySelector(".header-avatar");
        const initial = name.charAt(0).toUpperCase();
        if (avatarEl && avatarEl.textContent !== initial) avatarEl.textContent = initial;

        const hashText = c.destHash + (c.publicKey ? "" : " — waiting for public key…");
        const hashEl = view.querySelector(".header-hash");
        if (hashEl && hashEl.textContent !== hashText) hashEl.textContent = hashText;

        const ta = view.querySelector("#composer-input");
        if (ta) {
            ta.disabled = !c.publicKey;
            ta.placeholder = c.publicKey ? "Message…" : "Waiting for public key…";
        }
        const send = view.querySelector(".btn-send");
        if (send) send.disabled = !c.publicKey;
        const attach = view.querySelector(".btn-attach");
        if (attach) attach.disabled = !c.publicKey;
    },

    /** Re-resolve the sender labels and system notices of the open group or
     *  channel in place: they are named at render (§5.3), so a name learned
     *  since — a 0xD1, an announce, a channel name, a rename — relabels the
     *  messages already on screen without rebuilding the list. */
    _refreshNameLabels() {
        const id = this.state.activeHash;
        const list = document.getElementById("msg-list");
        if (!id || !list) return;
        const isGroup = GroupStore.isGroupChat(id);
        const isChannel = !isGroup && !!ChannelStore.get(id);
        if (!isGroup && !isChannel) return;
        const records = new Map((isGroup ? GroupMsgStore.get(id) : ChannelMsgStore.get(id)).map(m => [m.id, m]));
        for (const row of list.querySelectorAll("[data-msg-id]")) {
            const m = records.get(row.getAttribute("data-msg-id"));
            if (!m) continue;
            if (m.dir === "system") {
                const text = row.querySelector(".system-text");
                const want = systemMessageText(m);
                if (text && text.textContent !== want) text.textContent = want;
                continue;
            }
            const el = row.querySelector(".msg-sender");
            const sender = isGroup ? groupSenderLabel(m) : channelSenderLabel(id, m);
            if (el && sender) el.replaceWith(this._buildSenderLabel(sender));
        }
    },

    /** Rebuild only the detail pane, keeping the composer draft and the scroll
     *  position. For structural changes an in-place patch can't express — a
     *  group invite being accepted, a channel subscription flipping. */
    _rebuildDetail() {
        const detail = this.root.querySelector(".detail");
        if (!detail || detail.classList.contains("hidden")) return;

        const list = document.getElementById("msg-list");
        const scrollTop = list ? list.scrollTop : null;
        const wasAtBottom = list
            ? (list.scrollHeight - list.scrollTop - list.clientHeight < 40)
            : true;

        this._saveComposerFocus();
        clear(detail);
        detail.appendChild(
            this.state.activeHash ? this._buildChatView() : this._buildPlaceholder()
        );

        const next = document.getElementById("msg-list");
        if (next && scrollTop !== null) {
            next.scrollTop = wasAtBottom ? next.scrollHeight : scrollTop;
        }
        AttachmentUrls.sweep();
        requestAnimationFrame(() => this._restoreComposerFocus());
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
        const contacts = ContactStore.listed();
        const groups = GroupStore.getAll();
        const channels = ChannelStore.getAll();

        // Build unified chat entry list (contacts + groups + channels), sorted by last activity
        const entries = [];
        for (const c of contacts) {
            const msgs = MsgStore.get(c.destHash);
            const lastTs = msgs.length > 0 ? msgs[msgs.length-1].timestamp : c.lastSeen;
            entries.push({ type: "dm", id: c.destHash, name: ContactStore.name(c.destHash),
                lastTs, data: c, preview: MsgStore.preview(c.destHash) });
        }
        for (const g of groups) {
            const msgs = GroupMsgStore.get(g.groupId);
            const lastTs = msgs.length > 0 ? msgs[msgs.length-1].timestamp : g.lastActivity;
            entries.push({ type: "group", id: g.groupId, name: g.groupName,
                lastTs, data: g, preview: GroupMsgStore.preview(g.groupId, systemMessageText) });
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

        // Header.
        //
        // One address, never two: whatever this client sends as. That is the
        // distro delivery address when a distro identity is loaded, and the
        // device's own delivery address otherwise — the same choice
        // RnsClient.sendingIdentity() makes, so what is on screen is what
        // recipients see and reply to.
        const distroLxmfHash = DistroManager.lxmfDeliveryHash;
        const shownHash = distroLxmfHash || RnsClient.ownHash || ownLxmfDestinationHash();
        const abbreviated = shownHash ? `${shownHash.slice(0, 12)}…` : "Identity unavailable";
        frag.appendChild(
            h("div", { className: "sidebar-header" },
                h("div", { className: "sidebar-brand" },
                    h("div", { className: "sidebar-title" },
                        h("span", { id: "status-dot", className: "status-dot" }),
                        h("h1", {}, "Retichat"),
                    ),
                    h("div", { className: "sidebar-identity" },
                        distroLxmfHash
                            ? h("span", { className: "distro-label" }, "distro")
                            : null,
                        h("button", { className: "sidebar-hash", title: "Open Identity",
                            onClick: () => { this.state.showIdentity = true; this.render(); } }, abbreviated),
                        h("button", { className: "copy-hash-btn",
                            title: distroLxmfHash ? "Copy distro delivery address" : "Copy delivery address",
                            disabled: !shownHash,
                            onClick: () => {
                                if (shownHash) navigator.clipboard.writeText(shownHash).catch(() => {});
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
                    h("p", {}, `No chats match "${this.state.searchQuery}"`),
                ),
            );
        } else if (!hasEntries) {
            frag.appendChild(
                h("div", { className: "empty-list" },
                    h("div", { className: "empty-icon" }, "💬"),
                    h("h2", {}, "No conversations yet"),
                    h("p", {}, "Add a contact or create a group to start chatting privately over Reticulum."),
                    // iOS ChatListView's empty list says the same.
                    PrivacyFilter.on
                        ? h("p", { className: "field-hint" },
                            "Privacy filter is on — only messages from contacts you've added will appear. Add contacts with + Add Contact, or turn the filter off in Settings.")
                        : null,
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
                    name,
                    isPending ? h("span", { className: "contact-badge pending" }, "invite") : null,
                ),
                preview
                    ? h("div", { className: "contact-preview" }, preview)
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
                h("div", { className: "contact-name" }, name),
                preview
                    ? h("div", { className: "contact-preview" }, preview)
                    : h("div", { className: "contact-preview", style: { fontStyle: "italic" } },
                        "Channel"),
            ),
            h("div", { className: "contact-meta" },
                h("div", { className: "contact-time" }, lastTs ? fmtDate(lastTs) : ""),
            ),
        );
    },

    _buildContactItem(c) {
        const name = ContactStore.name(c.destHash);
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
                h("div", { className: "contact-name" }, name),
                preview
                    ? h("div", { className: "contact-preview" }, preview)
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
        const name = ContactStore.name(c.destHash);
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
                    h("div", { className: "header-name" }, name),
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

            // Attachments waiting to go, and the composer's notices
            this._buildComposerExtras(c.destHash),

            // Composer
            h("div", { className: "composer" },
                h("button", {
                    className: "btn-attach",
                    title: "Attach files (sent at their original size)",
                    disabled: !c.publicKey,
                    onClick: () => this._pickAttachments(),
                }, "📎"),
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
                    h("div", { className: "header-name" }, name),
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
                    : msgs.map(m => m.dir === "system"
                        ? this._buildSystemMsg(m)
                        : this._buildMsgBubble(m, groupSenderLabel(m)))),
            ),

            // Composer (hidden for pending groups)
            ...(isPending ? [] : [
                this._buildComposerExtras(g.groupId),
                h("div", { className: "composer" },
                    // Shown, and it says why a group takes no attachment
                    // (GROUP_ATTACHMENT_REFUSAL).
                    h("button", {
                        className: "btn-attach",
                        title: "Groups carry text only",
                        onClick: () => this._pickAttachments(),
                    }, "📎"),
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

    /** Build a system notice row (group/channel views). */
    _buildSystemMsg(m) {
        return h("div", { className: "msg-row system", "data-msg-id": m.id },
            h("div", { className: "system-msg" },
                h("span", { className: "msg-time" }, fmtTime(m.timestamp)),
                " ",
                h("span", { className: "system-text" }, systemMessageText(m)),
            ),
        );
    },

    /** A sender label: the resolved name and, for a channel post, the grey
     *  secondary text beside it (§5.3): the Channel Display Name when the
     *  user has their own name for the sender, else the sender's short hash
     *  under a channel name. */
    _buildSenderLabel(sender) {
        const secondaryClass = sender.secondaryKind === "hash"
            ? "msg-sender-secondary msg-sender-hash" : "msg-sender-secondary";
        return h("div", { className: "msg-sender" },
            sender.label,
            sender.secondary ? h("span", { className: secondaryClass }, sender.secondary) : null,
        );
    },

    /** Build a single message bubble (DM, group and channel views). `sender`
     *  is the resolved label of an incoming group or channel message
     *  ({label, secondary}), null for DMs and own messages. */
    _buildMsgBubble(m, sender = null) {
        const isOwn = m.dir === "out";
        const statusIcon = isOwn ? this._statusIcon(m.status) : "";
        // A send in progress shows its transfer (0.10 + 0.90 x the Resource's
        // fraction), as iOS's bar does (4744376).
        const progress = isOwn && m.status === "sending" ? RnsClient._sendTransfers.progressOf(m.id) : null;
        return h("div", { className: `msg-row ${isOwn ? "own" : "their"}`, "data-msg-id": m.id },
            h("div", { className: "msg-bubble" },
                (!isOwn && sender) ? this._buildSenderLabel(sender) : null,
                this._buildAttachments(m),
                m.content,
                progress !== null ? this._buildProgressBar(progress) : null,
                isOwn && m.status === "failed" && m.sendError ? h("div", { className: "msg-attach-note" }, `Not sent: ${m.sendError}`) : null,
                h("div", { className: "msg-meta" },
                    h("span", { className: "msg-time" }, fmtTime(m.timestamp)),
                    statusIcon ? h("span", { className: `msg-status ${m.status}`, "data-msg-status": m.status }, statusIcon) : null,
                ),
            ),
        );
    },

    // ===== ATTACHMENTS =====

    /**
     * What a message carries besides its text: an inline image for a
     * FIELD_IMAGE and for a file with one of iOS's image extensions
     * (isImageAttachment), a download link with its name and size for
     * anything else (FIELD_AUDIO included). The bytes come from the
     * attachment store through an object URL, revoked once the bubble has
     * left the page (AttachmentUrls.sweep). Under them, what the user must
     * know: an attachment kept for this session only, one that could not be
     * saved, one that is gone, or attachments that could not be read.
     * null for a message with none of these.
     */
    _buildAttachments(m) {
        const list = m.attachments ?? [];
        const notes = [];
        if (list.some(a => a.stored === "session")) {
            notes.push("Kept for this session only: this browser is not keeping attachments.");
        }
        const failed = list.find(a => a.stored === "failed");
        if (failed) notes.push(`Not saved (${failed.storeError || "storage refused it"}): kept until this tab closes.`);
        if (m.attachmentsSkipped) {
            notes.push(`${m.attachmentsSkipped === 1 ? "An attachment" : `${m.attachmentsSkipped} attachments`} in this message could not be read.`);
        }
        if (m.fieldsUnreadable) notes.push("Part of this message could not be read.");
        if (!list.length && !notes.length) return null;
        return h("div", { className: "msg-attachments" },
            ...list.map(a => {
                const el = isImageAttachment(a)
                    ? h("img", { className: "msg-image", alt: a.name, title: `${a.name} · ${formatSize(a.size)}`, "data-attachment-key": a.key })
                    : this._attachmentLink(a);
                this._loadAttachment(el, a);
                return el;
            }),
            ...notes.map(text => h("div", { className: "msg-attach-note" }, text)),
        );
    },

    _attachmentLink(a) {
        return h("a", { className: "msg-file", download: a.name, title: a.name, "data-attachment-key": a.key },
            "📄 ", h("span", { className: "msg-file-name" }, a.name), ` · ${formatSize(a.size)}`);
    },

    /** Fill an attachment's element from the store once its bubble is on
     *  the page. An image the browser cannot decode (HEIC outside Safari)
     *  is offered as a file instead. Bytes that are gone say so. */
    _loadAttachment(el, a) {
        Attachments.get(a.key).then((bytes) => {
            if (!el.isConnected) return;
            if (!bytes) {
                el.replaceWith(h("div", { className: "msg-file gone", title: a.name },
                    `📄 ${a.name} · ${formatSize(a.size)} — no longer available (it was kept for that session only)`));
                return;
            }
            const url = AttachmentUrls.attach(el, bytes, a.mime);
            if (el.tagName === "IMG") {
                el.addEventListener("error", () => {
                    AttachmentUrls.release(url);
                    const link = this._attachmentLink(a);
                    el.replaceWith(link);
                    this._loadAttachment(link, a);
                }, { once: true });
                el.addEventListener("load", () => {
                    // Keep the newest message in view when an image above it
                    // grows the list.
                    const list = document.getElementById("msg-list");
                    if (list && list.scrollHeight - list.scrollTop - list.clientHeight < el.clientHeight + 80) {
                        list.scrollTop = list.scrollHeight;
                    }
                }, { once: true });
                el.src = url;
            } else {
                el.href = url;
            }
        }, (e) => console.warn(`[attachments] ${a.key} could not be shown:`, e?.message || e));
    },

    _buildProgressBar(progress) {
        return h("div", { className: "msg-progress", title: `${Math.round(progress * 100)}%` },
            h("span", { style: { width: `${Math.round(progress * 100)}%` } }));
    },

    /** A transfer of an outgoing message moved (RnsClient.onSendProgress):
     *  its bar follows, in place, while it is "sending". */
    _updateMsgProgressDOM(msgId, progress) {
        const row = document.querySelector(`.msg-row[data-msg-id="${msgId}"]`);
        if (!row) return;
        const status = row.querySelector(".msg-status")?.getAttribute("data-msg-status");
        if (status && status !== "sending") return;
        const bar = row.querySelector(".msg-progress");
        if (bar) {
            bar.title = `${Math.round(progress * 100)}%`;
            bar.firstChild.style.width = `${Math.round(progress * 100)}%`;
            return;
        }
        row.querySelector(".msg-meta")?.before(this._buildProgressBar(progress));
    },

    /** Rebuild one bubble of the open chat from the store (an attachment's
     *  storage changed), leaving the rest of the list alone. */
    _repaintMsgRow(convHash, msgId) {
        if (this.state.activeHash !== convHash) return;
        const row = document.querySelector(`.msg-row[data-msg-id="${msgId}"]`);
        if (!row) return;
        let m, sender = null;
        if (GroupStore.isGroupChat(convHash)) {
            m = GroupMsgStore.get(convHash).find(x => x.id === msgId);
            if (m) sender = groupSenderLabel(m);
        } else {
            m = MsgStore.get(convHash).find(x => x.id === msgId);
        }
        if (!m || m.dir === "system") return;
        row.replaceWith(this._buildMsgBubble(m, sender));
        AttachmentUrls.sweep();
    },

    /** The pending attachments and the notice line above a composer. */
    _buildComposerExtras(chatId) {
        const extras = h("div", { className: "composer-extras", id: "composer-extras" },
            h("div", { className: "composer-tray", id: "composer-tray" }),
            h("div", { className: "composer-notice", id: "composer-notice", role: "status" }),
        );
        this._fillComposerTray(extras.firstChild, chatId);
        return extras;
    },

    _fillComposerTray(tray, chatId) {
        clear(tray);
        for (const [i, a] of (this._pendingAttachments.get(chatId) ?? []).entries()) {
            tray.appendChild(h("span", { className: "attach-chip", title: a.name },
                h("span", { className: "attach-chip-name" }, `📎 ${a.name}`),
                ` · ${formatSize(a.bytes.length)}`,
                h("button", {
                    className: "attach-chip-remove", title: `Remove ${a.name}`,
                    onClick: () => {
                        const list = this._pendingAttachments.get(chatId) ?? [];
                        list.splice(i, 1);
                        if (!list.length) this._pendingAttachments.delete(chatId);
                        this._composerNotice("");
                        this._renderComposerTray(chatId);
                    },
                }, "×"),
            ));
        }
    },

    _renderComposerTray(chatId) {
        if (this.state.activeHash !== chatId) return;
        const tray = document.getElementById("composer-tray");
        if (tray) this._fillComposerTray(tray, chatId);
    },

    /** One line above the composer for why something cannot go; "" clears it. */
    _composerNotice(text) {
        const el = document.getElementById("composer-notice");
        if (el) el.textContent = text || "";
    },

    /** The paperclip: pick files for the open DM. A group takes none
     *  (GROUP_ATTACHMENT_REFUSAL). Several files at once, as iOS allows
     *  (up to MAX_ATTACHMENTS). */
    _pickAttachments() {
        const chatId = this.state.activeHash;
        if (!chatId) return;
        if (GroupStore.isGroupChat(chatId) || ChannelStore.get(chatId)) {
            this._composerNotice(GROUP_ATTACHMENT_REFUSAL);
            return;
        }
        if (!this._fileInput) {
            this._fileInput = h("input", { type: "file", multiple: "multiple", style: { display: "none" } });
            document.body.appendChild(this._fileInput);
        }
        const input = this._fileInput;
        input.value = "";
        input.onchange = () => {
            const files = [...(input.files ?? [])];
            input.value = "";
            this._addAttachments(chatId, files);
        };
        input.click();
    },

    /** Read picked files (async: the page never waits on them) into the
     *  chat's pending list, refusing what cannot go, with why. */
    async _addAttachments(chatId, files) {
        const pending = this._pendingAttachments.get(chatId) ?? [];
        const limit = LXMRouter.DELIVERY_LIMIT * 1000;
        const notices = [];
        for (const file of files) {
            if (pending.length >= MAX_ATTACHMENTS) {
                notices.push(`At most ${MAX_ATTACHMENTS} attachments go in one message.`);
                break;
            }
            if (file.size > limit) {
                notices.push(`${file.name} is ${formatSize(file.size)}: a message can be at most ${formatSize(limit)}, `
                    + `the most any recipient accepts, and files are sent at their original size.`);
                continue;
            }
            try {
                const bytes = new Uint8Array(await file.arrayBuffer());
                // No type from the browser (file.type): the record's MIME
                // type is ours, from the name (RnsClient.sendMessage).
                pending.push({ name: file.name || "attachment.bin", bytes });
            } catch (e) {
                notices.push(`${file.name} could not be read: ${e?.message || e}`);
            }
        }
        if (pending.length) this._pendingAttachments.set(chatId, pending);
        // The whole message, as it would go now.
        const contact = ContactStore.get(chatId);
        const draft = this.state.activeHash === chatId ? (document.getElementById("composer-input")?.value ?? "") : "";
        const refusal = contact && pending.length ? RnsClient.attachmentRefusal(contact, draft.trim(), pending) : null;
        if (refusal) notices.push(refusal);
        this._renderComposerTray(chatId);
        if (this.state.activeHash === chatId) this._composerNotice(notices.join(" "));
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
                    h("div", { className: "header-name" }, name),
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
                    : msgs.map(m => m.dir === "system"
                        ? this._buildSystemMsg(m)
                        : this._buildMsgBubble(m, channelSenderLabel(ch.channelName, m)))),
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
        this._closeAllModals();

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
        const chatId = this.state.activeHash;
        const attachments = this._pendingAttachments.get(chatId) ?? [];
        if (!content && !attachments.length) return;

        const clearAndFocus = () => {
            ta.value = "";
            ta.style.height = "auto";
            // Append the outgoing bubble in place instead of re-rendering, so
            // the chat doesn't flash and the composer keeps focus for the
            // next message.
            this._syncOpenChatMessages();
            this._refreshSidebar();
            requestAnimationFrame(() => {
                this._scrollChatBottom();
                document.getElementById("composer-input")?.focus();
            });
        };

        try {
            // Groups and channels carry text only.
            if (attachments.length && (GroupStore.isGroupChat(chatId) || ChannelStore.get(chatId))) {
                this._composerNotice(GROUP_ATTACHMENT_REFUSAL);
                return;
            }
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
            // DM. One over its limits is refused here, with why, and the
            // draft and attachments stay (attachmentRefusal).
            const c = ContactStore.get(this.state.activeHash);
            if (!c) return;
            const refusal = RnsClient.attachmentRefusal(c, content, attachments);
            if (refusal) { this._composerNotice(refusal); return; }
            RnsClient.sendMessage(c, content, attachments);
            if (attachments.length) {
                this._pendingAttachments.delete(chatId);
                this._renderComposerTray(chatId);
            }
            this._composerNotice("");
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
            // Members are kept (their key, their names), not listed as
            // contacts (audit L4), and pass the privacy filter: iOS
            // acceptGroupInvite (ChatRepository.swift:1543-1548), Android
            // (ChatRepository.kt:1772-1773).
            ContactStore.allow(memberHash);
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
            case "queued":      return "⏳";  // hourglass — waiting for initialization or the propagation link
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
        this._wire();
        await ActiveTab.start(() => RnsClient.connect());
    },

    // ===== MODALS =====

    /** Shell shared by Settings and Identity: overlay + sticky header + body.
     *  `onClose` runs on backdrop click and on the ✕ button. */
    _modalShell(title, onClose) {
        const overlay = h("div", { className: "modal-overlay",
            onClick: (e) => { if (e.target === overlay) onClose(); },
        });
        const sheet = h("div", { className: "modal-sheet" });
        sheet.appendChild(
            h("div", { className: "modal-header" },
                h("h2", {}, title),
                h("button", { className: "icon-btn", onClick: onClose }, "✕"),
            ),
        );
        const body = h("div", { className: "modal-body" });
        sheet.appendChild(body);
        overlay.appendChild(sheet);
        return { overlay, sheet, body };
    },

    /** Settings modal — configuration only. Everything to do with keys and
     *  addresses lives on the Identity screen, one row down. */
    _renderSettingsModal() {
        const cfg = RnsClient.cfg;
        const connType = RnsClient.connType;
        const connLabel = connType === "exchange" ? "HTTP Exchange"
            : connType === "direct" ? "Direct Sockets"
            : connType === "websocket" ? "WebSocket" : "None";

        const close = () => { this.state.showSettings = false; this.render(); };
        const { overlay, sheet, body } = this._modalShell("Settings", close);

        // ---- Identity (link into the consolidated screen) ----
        body.appendChild(
            h("button", { className: "nav-row",
                onClick: () => {
                    this.state.showSettings = false;
                    this.state.showIdentity = true;
                    this.render();
                } },
                h("span", {},
                    "Identity",
                    h("span", { className: "nav-sub" },
                        DistroManager.has ? "Device + distro addresses and keys" : "Device address and keys · no distro yet"),
                ),
                h("span", { className: "nav-chevron" }, "›"),
            ),
        );

        // ---- Names (DISPLAY_NAMES.md §6) ----
        // Three independent names, all empty by default. Each is cleaned and
        // takes effect as soon as the field is left (change event): no
        // reconnect, and the field then shows exactly what goes out.
        const nameField = (id, label, value, hint, save) => h("div", { className: "settings-field" },
            h("label", { htmlFor: id }, label),
            h("input", { id, type: "text", value: value ?? "", maxlength: "256",
                onChange: (e) => { e.target.value = save(e.target.value) ?? ""; } }),
            h("div", { className: "field-hint" }, hint),
        );
        body.appendChild(
            h("div", { className: "settings-section compact" },
                h("h3", {}, "Names"),
                nameField("cfg-announce-name", "Announce Display Name", OwnNames.announce,
                    "Public. Sent in your announces to the whole network, including other Reticulum apps. Leave empty to stay anonymous.",
                    (v) => OwnNames.setAnnounce(v)),
                nameField("cfg-message-name", "Message Display Name", OwnNames.message,
                    "Sent inside your messages, only to the people you message.",
                    (v) => OwnNames.setMessage(v)),
                nameField("cfg-channel-name", "Channel Display Name", OwnNames.channel,
                    "Shown on your channel posts. Anyone who can read a channel can see it. Leave empty to post without a name.",
                    (v) => OwnNames.setChannel(v)),
            ),
        );

        // ---- Privacy (iOS SettingsView privacySection, Android
        // SettingsScreen "Privacy" card: the same words) ----
        // Applied at once, like the theme: the router asks the filter at
        // every delivery.
        body.appendChild(
            h("div", { className: "settings-section compact" },
                h("h3", {}, "Privacy"),
                h("div", { className: "settings-row" },
                    h("span", { className: "row-label" }, "Privacy filter"),
                    h("label", { className: "toggle" },
                        h("input", {
                            id: "cfg-privacy-filter",
                            type: "checkbox",
                            checked: PrivacyFilter.on,
                            onChange: (e) => { PrivacyFilter.set(e.target.checked); },
                        }),
                        h("span", { className: "slider" }),
                    ),
                ),
                h("div", { className: "field-hint" },
                    "Only accept messages from contacts you have explicitly added"),
            ),
        );

        // ---- Appearance ----
        body.appendChild(
            h("div", { className: "settings-section compact" },
                h("h3", {}, "Appearance"),
                h("div", { className: "settings-row" },
                    h("span", { className: "row-label" },
                        this.state.theme === "dark" ? "🌙 Dark mode" : "☀️ Light mode"),
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

        // ---- Connection ----
        body.appendChild(
            h("div", { className: "settings-section compact" },
                h("div", { className: "section-head" },
                    h("h3", {}, "Connection"),
                    h("span", { className: "section-note" }, connLabel),
                ),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-exchange" }, "HTTP exchange URL"),
                    h("input", { id: "cfg-exchange", type: "text", value: cfg.exchangeUrl || "",
                        placeholder: "https://your-host.com/reticulum" }),
                    h("div", { className: "field-hint" },
                        "HTTP POST polling — no WebSocket or open ports needed."),
                ),
            ),
        );

        // ---- RFed / Propagation ----
        const derivedProp = (() => {
            try {
                const rfedBytes = Buffer.from(cfg.rfedNodeHash || DEFAULT_CONFIG.rfedNodeHash, "hex");
                return Destination.hash({hash: rfedBytes}, "lxmf", "propagation").toString("hex");
            } catch(e) { return ""; }
        })();
        body.appendChild(
            h("div", { className: "settings-section compact" },
                h("h3", {}, "RFed & Propagation"),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-rfed" }, "RFed node identity hash"),
                    h("input", { id: "cfg-rfed", type: "text",
                        value: cfg.rfedNodeHash || "",
                        placeholder: DEFAULT_CONFIG.rfedNodeHash }),
                    h("div", { className: "field-hint" },
                        "Root identity for propagation, notify and channel addresses."),
                ),
                h("div", { className: "settings-field" },
                    h("label", { htmlFor: "cfg-prop-override" }, "LXMF propagation override"),
                    h("input", { id: "cfg-prop-override", type: "text",
                        value: cfg.lxmfPropagationOverride || "",
                        placeholder: derivedProp.slice(0,16) + "… (derived)" }),
                    h("div", { className: "field-hint" },
                        "Leave empty to derive from the RFed node."),
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

        this.root.appendChild(overlay);

        // Focus the first input
        setTimeout(() => sheet.querySelector("input")?.focus(), 150);
    },

    // ===== IDENTITY SCREEN =====
    //
    // One screen for every address, key and share link. Device Identity (this
    // browser's own LXMF identity) and Distro Identity (the identity shared
    // with your other devices) are deliberately separate groups — they are
    // different keys with different sharing rules, and mixing them is how the
    // distro contact link ended up advertising the wrong address.

    /** Consolidated Device + Distro identity screen. */
    _renderIdentityModal() {
        const close = () => {
            this.state.showIdentity = false;
            this.state.revealDeviceKey = false;
            this.state.revealDistroKey = false;
            this.render();
        };
        const { overlay, body } = this._modalShell("Identity", close);
        // Distro first: it is the address this client sends as and the one
        // people are given, so it is what the user comes here to read. The
        // device identity is underlying detail.
        body.appendChild(this._buildDistroIdentitySection());
        body.appendChild(this._buildDeviceIdentitySection());
        this.root.appendChild(overlay);
    },

    /** This browser's own identity: what senders address, and the backup key. */
    _buildDeviceIdentitySection() {
        const deliveryHash = RnsClient.ownHash || ownLxmfDestinationHash();
        const pubKey = IdMgr.pubKey;
        const contactUri = (deliveryHash && pubKey?.length === 128)
            ? `lxma://${deliveryHash}:${pubKey}`
            : null;

        const section = h("div", { className: "settings-section compact" },
            h("div", { className: "section-head" },
                h("h3", {}, "Device Identity"),
                h("span", { className: "section-note" }, "This browser"),
            ),
            kvRow("Address", deliveryHash, { empty: "unavailable" }),
            kvRow("Identity", IdMgr.hash),
            kvRow("Public key", pubKey),
            kvRow("Contact", contactUri, { empty: "needs public key" }),
            h("div", { className: "field-hint" },
                "The contact link carries this device's delivery address and public key — safe to share."),
        );

        section.appendChild(
            h("div", { className: "btn-row" },
                h("button", { className: "btn btn-secondary btn-sm",
                    onClick: () => {
                        this.state.revealDeviceKey = !this.state.revealDeviceKey;
                        this.render();
                    } },
                    this.state.revealDeviceKey ? "🙈 Hide private key" : "🔑 Back up private key"),
            ),
        );

        if (this.state.revealDeviceKey) {
            const priv = IdMgr.privKey ?? "";
            section.appendChild(h("div", { className: "secret-warning" },
                "⚠️ Anyone holding this key is this device. Store it somewhere safe; never share it."));
            section.appendChild(h("div", { className: "secret-value" }, priv || "unavailable"));
            if (priv) {
                section.appendChild(
                    h("div", { className: "btn-row" },
                        h("button", { className: "btn btn-secondary btn-sm",
                            onClick: () => { navigator.clipboard.writeText(priv).catch(() => {}); } },
                            "⧉ Copy private key"),
                    ),
                );
            }
        }

        return section;
    },

    /** The shared multi-device identity. Separate group, separate key, and a
     *  contact link built from the *delivery* address rather than the identity
     *  hash — the identity hash routes nowhere. */
    _buildDistroIdentitySection() {
        const section = h("div", { className: "settings-section compact" });
        section.appendChild(
            h("div", { className: "section-head" },
                h("h3", {}, "Distro Identity"),
                h("span", { className: "section-note" },
                    DistroManager.has ? "Shared across your devices" : "Not configured"),
            ),
        );

        if (!DistroManager.has) {
            section.appendChild(h("div", { className: "field-hint" },
                "One LXMF address shared by all your devices. Anything sent to it is fanned out by RFed to every registered device."));
            section.appendChild(
                h("div", { className: "btn-row" },
                    h("button", { className: "btn btn-primary btn-sm",
                        onClick: () => this._generateDistro() }, "✨ Generate"),
                    h("button", { className: "btn btn-secondary btn-sm",
                        onClick: () => this._showDistroImport() }, "📥 Import"),
                ),
            );
            return section;
        }

        section.appendChild(kvRow("Address", DistroManager.lxmfDeliveryHash));
        section.appendChild(kvRow("Identity", DistroManager.hash));
        section.appendChild(kvRow("Public key", DistroManager.pubKey));
        section.appendChild(kvRow("Contact", DistroManager.exportLxmaUri()));
        section.appendChild(h("div", { className: "field-hint" },
            "Give senders the contact link. Address is where distro mail is delivered; identity is the key's own hash and is not routable."));

        section.appendChild(
            h("div", { className: "btn-row" },
                h("button", { className: "btn btn-secondary btn-sm",
                    onClick: () => {
                        this.state.revealDistroKey = !this.state.revealDistroKey;
                        this.render();
                    } },
                    this.state.revealDistroKey ? "✕ Cancel" : "📤 Add another device"),
                h("button", { className: "btn btn-danger btn-sm",
                    onClick: () => this._forgetDistro() }, "🗑 Forget"),
            ),
        );

        // Adding a device is a transfer, never a copy-paste. The key is sent
        // encrypted to the other device's LXMF delivery address and never
        // rendered — a private key on screen is one screenshot, one shoulder
        // or one clipboard manager away from being someone else's.
        if (this.state.revealDistroKey) {
            section.appendChild(
                h("div", { className: "settings-field", style: { marginTop: "12px" } },
                    h("label", { htmlFor: "distro-lxmf-dest" }, "Send to this device's LXMF address"),
                    h("input", { id: "distro-lxmf-dest", type: "text",
                        placeholder: "32-char hex delivery address" }),
                    h("div", { className: "field-hint" },
                        "Sent encrypted to that address; the device is prompted to accept. It must already be a contact with a known public key."),
                ),
            );
            section.appendChild(
                h("div", { className: "btn-row" },
                    h("button", { className: "btn btn-primary btn-sm",
                        onClick: () => this._sendDistroViaLxmf() }, "📨 Send identity"),
                ),
            );
        }

        return section;
    },

    async _saveSettings() {
        const exchangeUrl = document.getElementById("cfg-exchange")?.value?.trim();
        // The names apply on their own, when each field changes (§6); a
        // pending edit still in a focused field is applied here too.
        const names = [["cfg-announce-name", "setAnnounce"], ["cfg-message-name", "setMessage"], ["cfg-channel-name", "setChannel"]];
        for (const [id, setter] of names) {
            const el = document.getElementById(id);
            if (el) OwnNames[setter](el.value);
        }
        const rfedHash = document.getElementById("cfg-rfed")?.value?.trim();
        const propOverride = document.getElementById("cfg-prop-override")?.value?.trim();
        if (exchangeUrl !== undefined) { RnsClient._cfg.exchangeUrl = exchangeUrl; sSet("exchangeUrl", exchangeUrl); }
        // rfedNodePubKey is deliberately not editable: it is learned from the
        // node's own announce (_catchRfedNodeAnnounce), and a hand-entered value
        // that disagrees with the announce silently breaks channel subscribe.
        if (rfedHash !== undefined) { RnsClient._cfg.rfedNodeHash = rfedHash; sSet("rfedNodeHash", rfedHash); }
        if (propOverride !== undefined) { RnsClient._cfg.lxmfPropagationOverride = propOverride; sSet("lxmfPropagationOverride", propOverride); }
        try { await RnsClient.reconnect(); } catch(e) { console.error(e); }
        this.state.showSettings = false;
        this.render();
    },

    _resetAll() {
        if (confirm("Delete your identity and ALL messages? This cannot be undone.")) {
            // The attachment bytes (IndexedDB) go with the messages.
            const done = () => { IdMgr.forget(); localStorage.clear(); location.reload(); };
            Attachments.clear().then(done, (e) => {
                console.error("[attachments] could not delete the stored attachments:", e?.message || e);
                done();
            });
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
        const uri = prompt("Paste a rfed-distro-private-key:// URI or a 128-char hex private key:");
        if (!uri) return;
        try {
            // The prompt has always offered a bare hex key, but this only ever
            // called importUri(), which requires a scheme prefix and rejected it.
            const raw = uri.trim();
            const hash = /^[0-9a-fA-F]{128}$/.test(raw)
                ? DistroManager.importHex(raw.toLowerCase())
                : DistroManager.importUri(raw);
            console.log(`[distro] Imported identity: ${hash}`);
            RnsClient._registerDistro();
            this.render();
        } catch(e) {
            alert("Failed to import: " + e.message);
        }
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
        // Deliberately signed as this DEVICE, not as the distro: the recipient
        // is being handed the distro key and can only judge the offer by which
        // of their known contacts sent it. Signing as the distro would have the
        // key vouch for itself.
        const msg = new LXMessage();
        msg.sourceHash = RnsClient._lxmfRouter.destination.hash;
        msg.destinationHash = contactDest.hash;
        msg.title = "Distro Identity";
        msg.content = "Import this distro identity to receive messages on all your devices.";
        msg.fields = new Map();
        // RFed SPEC §17.9: upstream's custom-field pair, never 0x0D (FIELD_EVENT).
        msg.fields.set(LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_TRANSFER_TYPE);
        msg.fields.set(LXMF.FIELD_CUSTOM_DATA, privateKeyHex);
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
            let publicKey = null;
            let hash = raw.toLowerCase();

            // Parse lxma:// URI (contains public key). This carries a key
            // only — it is NOT a distro indicator; only the announce's
            // SF_RFED_DISTRO flag is (RFed SPEC §17.10).
            if (hash.startsWith("lxma://")) {
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
                // The user added it: listed and allowlisted (iOS
                // createDirectChat, Android addContact).
                ContactStore.add(hash, false, publicKey);
                ContactStore.allow(hash);
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

    /** Contact Info modal — edit name, delete chat */
    _renderContactInfoModal() {
        const c = ContactStore.get(this.state.contactInfoHash);
        if (!c) { this.state.showContactInfo = false; this.render(); return; }
        const name = ContactStore.name(c.destHash);
        const provided = ContactStore.providedName(c.destHash);
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
                    h("div", { style: { fontWeight: 700, fontSize: "17px" } }, name),
                    h("div", { style: { fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "2px" } },
                        c.destHash),
                ),
            ),
        );

        // Your own name for this contact (DISPLAY_NAMES.md §5.1). The field
        // holds only that name, never the one the contact provides — which is
        // the placeholder — so Save on an untouched field changes nothing, and
        // an emptied field clears the local name.
        body.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Your name for this contact"),
                h("div", { className: "settings-field" },
                    h("input", {
                        id: "ci-display-name",
                        type: "text",
                        maxlength: "256",
                        value: c.localName ?? "",
                        placeholder: provided,
                    }),
                    h("div", { className: "field-hint" },
                        "Stored only on this device. Leave empty to show the name they provide."),
                ),
            ),
        );

        // No public key panel: the key is not something to read or act on, and
        // the state that does matter — still waiting for it — is already on the
        // chat header and the disabled composer.

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
        const field = document.getElementById("ci-display-name");
        if (field) ContactStore.setLocalName(hash, field.value);
        this.state.showContactInfo = false;
        this.render();
    },

    _deleteContact(c) {
        const name = ContactStore.name(c.destHash);
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
            let publicKey = null;
            let hash = raw.toLowerCase();

            // Parse lxma:// URI (contains public key). This carries a key
            // only — it is NOT a distro indicator; only the announce's
            // SF_RFED_DISTRO flag is (RFed SPEC §17.10).
            if (hash.startsWith("lxma://")) {
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
                // The user added it: listed and allowlisted (iOS
                // createDirectChat, Android addContact).
                ContactStore.add(hash, false, publicKey);
                ContactStore.allow(hash);
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

        const contacts = ContactStore.listed();
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
                        h("div", { className: "contact-avatar", style: { width: "32px", height: "32px", fontSize: "14px", flexShrink: 0, color: `hsl(${avatarHue(ContactStore.name(c.destHash))}, 50%, 65%)`, background: `hsla(${avatarHue(ContactStore.name(c.destHash))}, 50%, 40%, 0.15)`, borderColor: `hsla(${avatarHue(ContactStore.name(c.destHash))}, 50%, 65%, 0.2)` } }, ContactStore.name(c.destHash).charAt(0).toUpperCase()),
                        h("div", { style: { flex: 1 } },
                            h("div", { style: { fontSize: "14px", fontWeight: 500 } }, ContactStore.name(c.destHash)),
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
            // Co-members pass the privacy filter: iOS createGroupChat
            // (ChatRepository.swift:2532-2536), Android (ChatRepository.kt:404-405).
            for (const hash of selected) ContactStore.allow(hash);
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

        const contacts = ContactStore.listed();
        scroll.appendChild(
            h("div", { className: "settings-section" },
                h("h3", {}, "Members"),
                h("div", { className: "field-hint", style: { marginBottom: "8px" } }, "Select contacts to invite. You'll be added automatically."),
                ...(contacts.length === 0
                    ? [h("p", { style: { color: "var(--text-muted)", fontSize: "13px" } }, "No contacts yet. Add contacts first.")]
                    : contacts.map(c => h("label", { className: "group-member-row", style: { display: "flex", alignItems: "center", gap: "10px", padding: "8px 0", cursor: "pointer", borderBottom: "1px solid var(--border)" } },
                        h("input", { type: "checkbox", className: "group-member-check", value: c.destHash }),
                        h("div", { className: "contact-avatar", style: { width: "32px", height: "32px", fontSize: "14px", flexShrink: 0, color: `hsl(${avatarHue(ContactStore.name(c.destHash))}, 50%, 65%)`, background: `hsla(${avatarHue(ContactStore.name(c.destHash))}, 50%, 40%, 0.15)`, borderColor: `hsla(${avatarHue(ContactStore.name(c.destHash))}, 50%, 65%, 0.2)` } }, ContactStore.name(c.destHash).charAt(0).toUpperCase()),
                        h("div", { style: { flex: 1 } },
                            h("div", { style: { fontSize: "14px", fontWeight: 500 } }, ContactStore.name(c.destHash)),
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

    /** Channel tab: name input + sub-picker Public|Private (top),
     *  info (scroll), Join button (footer).
     *
     *  One field holds the full "<root>.<name>". Public uses the root
     *  "public"; a private root defaults to 16 random hex characters
     *  (crypto.getRandomValues) and stays editable, so a shared private name
     *  can be typed or pasted whole. The rules live in lib/channel_name.js and
     *  match the iOS and Android forms. */
    _renderChannelForm(top, scroll, footer) {
        const rfedNodeHash = RnsClient.cfg?.rfedNodeHash || "";
        const hasRfed = rfedNodeHash.length === 32;
        const vis = this.state.channelVis || "public";
        const mode = () => this.state.channelVis || "public";

        let inp, hintEl, errorEl, regenBtn, joinBtn;
        // The field as the form last left it: typeChannelName compares an
        // input event's value with it to see what was typed where.
        let prevValue = "";

        /** Re-derive the hint, the error line and Join from the field. */
        const refresh = () => {
            if (!inp) return;
            const m = mode();
            const v = validateChannelName(inp.value, m);
            if (hintEl) hintEl.textContent = visibilityHint(m);
            if (errorEl) {
                // An untouched "public." or "<root>." needs no scolding.
                errorEl.textContent = v.ok || v.code === "name-empty" ? "" : v.error;
                errorEl.style.display = errorEl.textContent ? "" : "none";
            }
            if (regenBtn) regenBtn.style.display = m === "private" ? "" : "none";
            if (joinBtn) joinBtn.disabled = !hasRfed || !v.ok;
        };

        const setValue = (value, caret = value.length) => {
            inp.value = value;
            prevValue = value;
            try { inp.setSelectionRange(caret, caret); } catch (_) {}
            refresh();
        };

        const applyPrefix = (m) => {
            this.state.channelVis = m;
            if (inp) setValue(applyVisibility(inp.value, m));
            const subPicker = document.querySelector(".channel-vis-picker");
            if (subPicker) {
                subPicker.querySelectorAll(".seg-btn").forEach(btn => {
                    const isActive = btn.getAttribute("data-vis") === m;
                    btn.className = "seg-btn" + (isActive ? " active" : "");
                });
            }
            refresh();
        };

        const doJoin = () => {
            if (!inp) return;
            const v = validateChannelName(inp.value, mode());
            if (!v.ok) { refresh(); return; }
            RnsClient.joinChannel(v.name).then((channel) => {
                this.state.showNewConversation = false;
                this.openChat(channel.channelName, false);
            }).catch(e => alert("Failed to join channel: " + e.message));
        };

        inp = h("input", {
            id: "nc-channel-name", type: "text",
            value: initialChannelValue(vis),
            placeholder: vis === "private" ? "root.general…" : "public.general…",
            autocapitalize: "off", autocomplete: "off", spellcheck: "false",
            onInput: (e) => {
                // The character rule (letters, digits, "." and "-"), and a
                // "." typed into a Private name part moves its root out.
                const el = e.target;
                const caretFrom = el.selectionStart ?? el.value.length;
                const caret = filterChannelChars(el.value.slice(0, caretFrom)).length;
                const r = typeChannelName({ old: prevValue, value: el.value, caret, mode: mode() });
                if (r.value !== el.value) {
                    setValue(r.value, r.caret);
                } else {
                    prevValue = el.value;
                    refresh();
                }
            },
            onPaste: (e) => {
                const text = e.clipboardData?.getData("text");
                if (text == null) return;
                e.preventDefault();
                const el = e.target;
                const r = pasteChannelName({
                    value: el.value,
                    selStart: el.selectionStart,
                    selEnd: el.selectionEnd,
                    pasted: text,
                    mode: mode(),
                });
                setValue(r.value, r.caret);
            },
            onKeydown: (e) => { if (e.key === "Enter") doJoin(); },
        });
        // The value property, not only the attribute: setValue/refresh read it.
        inp.value = inp.getAttribute("value");
        prevValue = inp.value;

        // Channel name input
        top.appendChild(
            h("div", { className: "settings-field" },
                h("label", { htmlFor: "nc-channel-name" }, "Channel Name"),
                inp,
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

        hintEl = h("div", { className: "field-hint" }, visibilityHint(vis));
        errorEl = h("div", { className: "field-hint", style: { color: "var(--danger)", display: "none" } });
        regenBtn = h("button", {
            className: "btn btn-sm",
            style: { display: vis === "private" ? "" : "none", marginTop: "6px" },
            onClick: () => setValue(regenerateRoot(inp.value)),
        }, "Regenerate prefix");
        top.appendChild(h("div", {}, hintEl, errorEl, regenBtn));

        if (hasRfed) {
            scroll.appendChild(
                h("div", { className: "settings-field" },
                    h("label", {}, "RFed Node"),
                    h("div", { style: { fontSize: "12px", fontFamily: "var(--font-mono)", color: "var(--text-muted)", wordBreak: "break-all" } }, rfedNodeHash),
                ),
            );
        }

        joinBtn = h("button", { className: "btn btn-primary btn-block", onClick: doJoin,
            disabled: true, title: hasRfed ? "" : "Configure an RFed node in Settings first" },
            "Join / Create");
        footer.appendChild(joinBtn);
        refresh();
    },

    /** Group Info modal — shows members, allow accept/decline/leave */
    /** A Group Info member row's label (§5.3): the resolver, "You" for this device. */
    _groupMemberLabel(hash) {
        return hash === ownLxmfDestinationHash() ? "You" : ContactStore.name(hash);
    },

    _paintMemberAvatar(avatar, name) {
        avatar.textContent = name.charAt(0).toUpperCase();
        avatar.style.color = `hsl(${avatarHue(name)}, 50%, 65%)`;
        avatar.style.background = `hsla(${avatarHue(name)}, 50%, 40%, 0.15)`;
        avatar.style.borderColor = `hsla(${avatarHue(name)}, 50%, 65%, 0.2)`;
    },

    /** Relabel the open Group Info modal's member rows in place when a name
     *  arrives (a 0xD1, an announce, a rename) while it is open (§5.3). */
    _refreshGroupInfoNames() {
        if (!this.state.showGroupInfo) return;
        for (const row of this.root.querySelectorAll(".modal-sheet [data-member-hash]")) {
            const name = this._groupMemberLabel(row.getAttribute("data-member-hash"));
            const label = row.querySelector(".member-name");
            if (!label || label.textContent === name) continue;
            label.textContent = name;
            const avatar = row.querySelector(".member-avatar");
            if (avatar) this._paintMemberAvatar(avatar, name);
        }
    },

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
                h("div", { style: { fontSize: "18px", fontWeight: 700 } }, g.groupName || "Group"),
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
                    const displayName = this._groupMemberLabel(hash);
                    const statusLabel = status === "accepted" ? "" :
                        status === "invited" ? " ⏳" :
                        status === "left" ? " 🚪" : "";
                    const avatar = h("div", {
                        className: "contact-avatar member-avatar",
                        style: { width: "28px", height: "28px", fontSize: "12px" },
                    });
                    this._paintMemberAvatar(avatar, displayName);
                    return h("div", {
                        "data-member-hash": hash,
                        style: { display: "flex", alignItems: "center", gap: "10px", padding: "6px 0", borderBottom: "1px solid var(--border)" },
                    },
                        avatar,
                        h("div", { style: { flex: 1, fontSize: "13px" } },
                            h("span", { className: "member-name" }, displayName), statusLabel),
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

        // Channel name. The full "<root>.<name>" is how a channel is shared
        // (for a private channel it is the invite), so it is shown whole and
        // selectable, with Copy and Share; the hash cannot be joined by and
        // stays secondary. Rules: lib/channel_name.js channelShareText/Hint.
        const fullName = channelShareText(ch.channelName);
        const copyBtn = h("button", { className: "btn btn-secondary btn-sm channel-copy-name",
            title: "Copy the full channel name" }, "⧉ Copy name");
        copyBtn.addEventListener("click", () => {
            navigator.clipboard.writeText(fullName).then(() => {
                copyBtn.classList.add("copied");
                copyBtn.textContent = "✓ Copied";
                setTimeout(() => { copyBtn.classList.remove("copied"); copyBtn.textContent = "⧉ Copy name"; }, 1200);
            }).catch(() => alert("Could not copy. Select the name and copy it instead."));
        });
        const shareBtn = typeof navigator.share === "function"
            ? h("button", { className: "btn btn-secondary btn-sm channel-share-name",
                title: "Share the full channel name",
                onClick: () => { navigator.share({ text: fullName }).catch(() => {}); } }, "↗ Share")
            : null;
        body.appendChild(
            h("div", { style: { marginBottom: "16px" } },
                h("div", { className: "channel-full-name" }, fullName),
                h("div", { className: "channel-share-hint" }, channelShareHint(fullName)),
                h("div", { className: "btn-row channel-name-actions" }, copyBtn, shareBtn),
                h("div", { style: { fontSize: "12px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "8px", wordBreak: "break-all" } },
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
    // (Message rows are appended by _syncOpenChatMessages, above.)

    /** Update a message status icon in-place without re-rendering.
     *  Finds the msg-row by data-msg-id and updates its status span. */
    _updateMsgStatusDOM(contactHash, msgId, newStatus, record = null) {
        const row = document.querySelector(`.msg-row[data-msg-id="${msgId}"]`);
        if (!row) return;
        // A send's bar goes once it is no longer sending, and a failed one
        // says why when it knows.
        if (newStatus !== "sending") row.querySelector(".msg-progress")?.remove();
        if (newStatus === "failed" && record?.sendError && !row.querySelector(".msg-send-error")) {
            row.querySelector(".msg-meta")?.before(h("div", { className: "msg-attach-note msg-send-error" }, `Not sent: ${record.sendError}`));
        }
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

        // Incoming messages & proofs. Everything here is a targeted DOM patch:
        // a full render() would reset the open chat (scroll, draft, in-flight
        // interaction) and tear down any open modal, which is exactly what the
        // user notices when a distro message or a path response lands.
        RnsClient.onMessage((msg, peerHash) => {
            if (this.state.view !== "main") return;
            const inActiveChat = this.state.activeHash === peerHash;

            // Proof-only event (msg is null): update status icons in place.
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
                        this._updateMsgStatusDOM(peerHash, m.id, m.status, m);
                    }
                }
                return;
            }

            // New message (DM, distro, group or channel): append the bubbles
            // that aren't on screen yet and repaint the sidebar for preview
            // and ordering. Both are safe with a modal open, so unlike before
            // a message arriving mid-dialog is no longer dropped from the UI.
            const appended = this._syncOpenChatMessages();
            // A channel post can carry a new Channel Display Name for a
            // sender whose earlier posts are on screen.
            if (inActiveChat) this._refreshNameLabels();
            this._refreshSidebar();
            if (inActiveChat && appended) {
                requestAnimationFrame(() => this._scrollChatBottom());
            }
        });

        // A send's transfer moved: its bar follows, in the open chat only.
        RnsClient.onSendProgress((convHash, msgId, progress) => {
            if (this.state.view !== "main" || this.state.activeHash !== convHash) return;
            this._updateMsgProgressDOM(msgId, progress);
        });

        // An attachment could not be saved to IndexedDB: its bubble says so.
        RnsClient.onAttachmentState((convHash, msgId) => {
            if (this.state.view !== "main") return;
            this._repaintMsgRow(convHash, msgId);
        });

        // Contact list changes — announces and path responses land here. The
        // open chat keeps its message list and draft; only the header line and
        // the composer's enabled state follow the newly learned public key.
        ContactStore.onChange(() => {
            if (this.state.view !== "main") return;
            this._refreshSidebar();
            this._syncOpenChatChrome();
            this._refreshGroupInfoNames();
        });

        // Group list changes — membership and invite state are structural, so
        // the open group chat is rebuilt (draft and scroll preserved).
        GroupStore.onChange(() => {
            if (this.state.view !== "main") return;
            this._refreshSidebar();
            if (this.state.activeHash && GroupStore.isGroupChat(this.state.activeHash)) {
                this._rebuildDetail();
            }
        });

        // Channel list changes — same logic
        ChannelStore.onChange(() => {
            if (this.state.view !== "main") return;
            this._refreshSidebar();
            if (this.state.activeHash && ChannelStore.get(this.state.activeHash)) {
                this._rebuildDetail();
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

    /** The live App and RnsClient, for the one class of assertion the
     *  harness surface above cannot make: that an arriving message actually
     *  reaches the screen, and does so without rebuilding the open chat. */
    app: App,
    client: RnsClient,

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
        // As the Add Contact flow does: listed and allowlisted, so the
        // privacy filter (on by default) keeps the peer's messages.
        ContactStore.add(destHash, false, publicKeyHex || null);
        ContactStore.allow(destHash);
        if (!publicKeyHex) App._requestPathForContact(destHash);
        return ContactStore.get(destHash);
    },

    /** The privacy filter (Settings "Privacy filter"): with no argument,
     *  whether it is on; with a boolean, turn it on or off (persisted, as
     *  the toggle does) and return the new state. A stage that needs a
     *  stranger's message kept turns it off first; debug.html?privacy=0
     *  does it before the page boots. Drops are recorded as Harness events
     *  of kind "privacy-drop" ({src, path, at: "source"|"message"}). */
    privacyFilter(on) {
        if (on !== undefined) PrivacyFilter.set(on);
        return PrivacyFilter.on;
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

    // ---- Attachments (test-harnesses/staging/lib/attach.mjs HOOK_CONTRACT) ----
    // client.attachmentsFor(msgId) reads each attachment of a stored message
    // back from the attachment store: [{name, size, sha256, mime, field}].
    /** One /get fetch from the propagation node, as a user's pull. */
    fetchPropagated() { return RnsClient._fetchPropagatedMessages(); },

    // ---- One active tab (D11) ----
    /** "active" when this tab holds the identity's lock, else "inactive". */
    tab() { return ActiveTab.held ? "active" : "inactive"; },
    /** Press "Use here" (reloads the page, which then takes over). */
    useHere() { return ActiveTab.useHere(); },

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
  .inbox          — received messages [{srcHash, content, via, id, lxmfHash}]
  .client.attachmentsFor(msgId) — a message's attachments, read back from storage
  .fetchPropagated() — one /get fetch from the propagation node
  .got(marker)    — true if a message containing marker arrived
  .addPeer(h,pk)  — add a peer (allowlisted), optionally with its public key
  .privacyFilter([on]) — read, or turn on/off, the privacy filter
  .distro()       — distro identity state
  .generateDistro() / .adoptDistro(privHex) / .pullDistro()
  .tab()          — "active" | "inactive" (one active tab per identity)
  .useHere()      — take over from the active tab (reloads this one)
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
            exchange: RnsClient._rns?.interfaces?.[0]?.isUp ? "up" : RnsClient._rns?.interfaces?.[0]?.isDown ? "down" : "starting",
            tab: ActiveTab.held ? "active" : "inactive",
            contacts: ContactStore.getAll().length,
            // Link state per RFed aspect, and anything parked waiting for the
            // next announce. A failed link used to be invisible; this is the
            // reference's PR_* state made inspectable.
            rfedLinks: Object.fromEntries(RnsClient._rfedLinkState),
            rfedPending: [...RnsClient._rfedPending.keys()],
        };
        console.table(s);
        return s;
    },

    contacts() {
        const all = ContactStore.getAll();
        const rows = all.map(c => ({
            destHash: c.destHash.slice(0,12) + '...',
            displayName: ContactStore.name(c.destHash),
            localName: c.localName, messageName: c.messageName, announceName: c.announceName,
            legacyName: c.legacyName, hidden: !!c.hidden, nameOnly: !!c.nameOnly,
            allowlisted: c.allowlisted === true,
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
                console.log(`--- ${ContactStore.name(c.destHash)} (${c.destHash.slice(0,12)}...) : ${msgs.length} msgs ---`);
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
            const stored = RnsClient.sendMessage(contact, content || 'E2E test ' + Date.now());
            if (stored.status === 'queued') return 'Queued — sends when initialization finishes';
            if (stored.status === 'failed') return 'Failed — the exchange is down';
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
            displayName: ContactStore.name(c.destHash),
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
