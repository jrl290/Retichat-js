/**
 * Test support (not a test, not deployed): web clients that talk to each
 * other in one process, over the real shipped code, for the group statuses
 * and keys tests (RFed-spec Group.md, "Member statuses and keys").
 *
 * A client (`groupClient`) is what connect() builds, as far as groups go:
 * the real LXMRouter given the real PrivacyFilter, the real message handler
 * behind it, the real _handleGroupMessage and the methods it calls, and the
 * real send path (sendGroupInvites, sendGroupAccept, sendGroupLeave,
 * sendGroupStatus, _fanoutGroupEnvelope, _sendGroupEnvelope,
 * _deliverGroupEnvelope), over the real ContactStore, GroupStore,
 * GroupMsgStore, PrivacyFilter and MsgStore, extracted from app.js and
 * compiled over stubs (test_app_source.mjs). Stubbed at the edge only: a
 * link to a member records the bytes it is given (`sent`) instead of
 * transmitting them, and the transport records each path request.
 * `network(...)` carries what one client sent to the client it is for, as an
 * opportunistic packet, and each side signs, verifies and decides for real.
 *
 * `switched` is the page before (false) or after (true) the switch, around
 * 2026-10-26 (GROUP_ENTRIES_IN_RETICHAT_FIELD): the form group entries are
 * sent in, and whether an unverifiable accept or leave counts or is held.
 *
 * Nothing here waits on a clock: delivery is a microtask or a macrotask
 * round (settle), never a timer that decides a result.
 */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, { GROUP_FIELDS } from "./lib/rns/lxmf/lxmf.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Link from "./lib/rns/link.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { GroupDeliveryEvidence } from "./lib/rns/group_fallback.js";
import Cryptography from "./lib/rns/cryptography.js";
import * as DN from "./lib/display_name.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { applyGroupFields } from "./lib/retichat_field.js";
import { senderKeyEntry } from "./lib/group_status.js";
import { NameLedger } from "./lib/name_ledger.js";
import { app, build, compile, constValue, fn, memoryStorage, messageHandler, GROUP_STATUS_METHODS, groupStatusEnv } from "./test_app_source.mjs";
import { settle } from "./test_link_pair.mjs";

export { settle, GROUP_FIELDS, LXMessage, Identity, Destination };

export const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
export const hex = (b) => Buffer.from(b).toString("hex");
export const quiet = { log() {}, warn() {}, error() {} };

/** A top-level function of app.js, compiled over `env`, with its own parameter list. */
export function appFunction(name, env) {
    const m = app.match(new RegExp(`\\nfunction ${name}\\(([^)]*)\\)`));
    assert.ok(m, `function ${name} is missing from app.js`);
    return fn(name, m[1], env);
}

/** shouldProcessGroupMessage as app.js defines it, over groupTrustsSource and
 *  GROUP_ACTIONS_THAT_RELAY. */
export function groupRule() {
    const groupTrustsSource = appFunction("groupTrustsSource", {});
    const GROUP_ACTIONS_THAT_RELAY = constValue("GROUP_ACTIONS_THAT_RELAY");
    return { groupTrustsSource, GROUP_ACTIONS_THAT_RELAY,
        shouldProcessGroupMessage: appFunction("shouldProcessGroupMessage", { groupTrustsSource, GROUP_ACTIONS_THAT_RELAY }) };
}

let clock = Date.now() / 1000;
/** A received message's packing from `from` to `to`, signed by `signer`
 *  (`from` unless a forger says otherwise): destination | source | signature
 *  | payload. A fixed `timestamp` makes it reproducible. */
export function lxm(from, to, content, fields = new Map(), { signer = from, timestamp = null, title = "" } = {}) {
    const m = new LXMessage();
    m.timestamp = timestamp ?? (clock += 1);
    m.sourceHash = Buffer.from(typeof from === "string" ? from : lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(typeof to === "string" ? to : lxmfHash(to), "hex");
    m.title = title;
    m.content = content;
    m.fields = fields;
    return m.pack(signer, false);
}

/** One group control message's fields, in the old top-level form (what a
 *  build from before the switch sends) with the entries given. */
export function oldFields(entries) {
    const f = GROUP_FIELDS;
    const names = { id: f.GROUP_ID, members: f.GROUP_MEMBERS, name: f.GROUP_NAME, action: f.GROUP_ACTION, sender: f.GROUP_SENDER, keys: f.GROUP_MEMBER_KEYS };
    return new Map(Object.entries(entries).filter(([, v]) => v != null).map(([k, v]) => [names[k], v]));
}

/** The same entries in the Retichat field 0xD1 (keys 1-9, ascending), what a
 *  build after the switch sends. */
export function newFields(entries) {
    const keys = { id: 1, members: 2, name: 3, action: 4, sender: 5, keys: 9 };
    const map = new Map(Object.entries(entries).filter(([, v]) => v != null).map(([k, v]) => [keys[k], v]).sort((a, b) => a[0] - b[0]));
    return new Map([[0xD1, map]]);
}

/**
 * A web client. `identity`/`me` is its identity (made when none is given);
 * `storage` is the localStorage it runs over (a reload is another client over
 * the same storage); `filter` is the Settings "Privacy filter" switch;
 * `switched` is the page after the switch; `name` the Message Display Name.
 */
export function groupClient({ me = Identity.create(), storage = memoryStorage(), filter = false, switched = false, name = null, creates = true } = {}) {
    const { sGet, sSet } = storage;
    if (filter && sGet("filterStrangers") === null) sSet("filterStrangers", true);
    const own = lxmfHash(me);
    const pubKey = me.getPublicKey().toString("hex");
    const events = [];
    const Harness = { recordInbound() {}, event: (kind, detail) => events.push({ kind, detail }), error() {} };
    const ContactStore = build("ContactStore", {
        sGet, sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    const GroupStore = build("GroupStore", {
        sGet, sSet, Buffer, crypto: globalThis.crypto, Date, IdMgr: { hash: null }, ownLxmfDestinationHash: () => own,
    });
    GroupStore.init();
    const PrivacyFilter = build("PrivacyFilter", {
        sGet, sSet, ContactStore, GroupStore, Harness, LXMF, LXMessage, Buffer, ...groupRule(),
    });
    PrivacyFilter.init();
    const MsgStore = build("MsgStore", { sGet, sSet, Harness, Date });
    const GroupMsgStore = build("GroupMsgStore", { sGet, sSet, Date, ContactStore });

    const recall = appFunction("recallLxmfIdentity", {
        Buffer, Identity, Destination, IdMgr: { has: true, id: me }, ownLxmfDestinationHash: () => own,
        DistroManager: { has: false }, ContactStore,
    });
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    const router = new LXMRouter({ registerDestination: () => destination }, me, { filter: PrivacyFilter });

    // What the transport edge records.
    const paths = [], sent = [], proofs = [], relays = [];
    class WireLink {
        static ACTIVE = Link.ACTIVE;
        static MDU = Link.MDU;
        constructor() { this.status = 0; this.handlers = new Map(); }
        on(event, handler) { this.handlers.set(event, handler); }
        establish(dest) {
            this.to = dest.hash.toString("hex");
            this.status = Link.ACTIVE;
            queueMicrotask(() => this.handlers.get("established")?.());
        }
        // The proof of what a link carried comes when the network delivers it
        // (network.pump): the packet's proof, or the Resource's own.
        send(bytes) {
            const packetHash = Cryptography.fullHash(bytes);
            const key = packetHash.slice(0, 16).toString("hex");
            sent.push({ to: this.to, bytes: Buffer.from(bytes), via: "packet", prove: () => self._pendingPacketHashes.get(key)?.onProof?.() });
            return { packetHash };
        }
        sendResource(bytes) {
            return new Promise((resolve) => sent.push({ to: this.to, bytes: Buffer.from(bytes), via: "resource", prove: resolve }));
        }
        close() {}
    }
    const fallbacks = [];
    const self = {
        get ownHash() { return this._lxmfRouter?.destination?.hash?.toString("hex") ?? null; },
        _lxmfRouter: router,
        _rns: {
            transport: { requestPath: (hash) => paths.push(hash) },
            registerDestination: (identity) => ({ hash: Destination.hash(identity, "lxmf", "delivery") }),
        },
        _onMsg: [], _pendingTickets: new Map(),
        _groupPathsRequested: new Set(), _groupPeerReady: new Set(), _groupPeerWaiters: new Map(),
        _groupLinks: new Map(), _groupLinkPromises: new Map(), _pendingPacketHashes: new Map(),
        _groupFallbacks: { schedule: (key) => { fallbacks.push(key.slice(0, key.indexOf(":"))); return true; }, prove() {} },
        _performGroupRelay: (...a) => { relays.push(a); },
        _handleDistroIdentityTransfer() {},
        _keepAttachments() {},
    };

    const receiveEnv = {
        GroupStore, GroupMsgStore, ContactStore, PrivacyFilter, console: quiet, Date, Buffer, LXMessage, Harness,
        sentTimeMs, ownLxmfDestinationHash: () => own, Identity, Destination,
        ...groupStatusEnv({ GROUP_ENTRIES_IN_RETICHAT_FIELD: switched }),
    };
    for (const signature of [
        "_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)", ...GROUP_STATUS_METHODS,
        "_rememberGroupMemberKeys(memberKeys)",
    ]) self[signature.replace(/^async /, "").split("(")[0]] = compile(signature, receiveEnv)(self);

    const sendEnv = {
        GroupStore, ContactStore, console: quiet, Identity, Destination, Buffer, LXMessage, Date, Harness,
        Link: WireLink, GroupDeliveryEvidence, applyGroupFields: (fields, group) => applyGroupFields(fields, group, switched),
        applyDisplayName: DN.applyToFields, IdMgr: { id: me, pubKey }, senderKeyEntry,
        NameLedgerStore: new NameLedger({ get: sGet, set: sSet }), OwnNames: { message: name },
        crypto: globalThis.crypto, ownLxmfDestinationHash: () => own,
    };
    for (const signature of [
        "async sendGroupInvites(groupId, groupName, memberHashes)", "async sendGroupAccept(groupId)", "async sendGroupLeave(groupId)",
        "async sendGroupStatus(groupId, memberHash)", "_ownGroupMemberKey()", "_groupMemberKeys(memberHashes)",
        "async _fanoutGroupEnvelope(targets, content, fields)", "async _sendGroupEnvelope(memberHash, content, fields)",
        "_deliverGroupEnvelope(memberHash, fullLxmfBytes, publicKeyHex, onDelivered = null)",
        "_decideMessageName(sourceHex, recipientHex)", "_requestGroupPeer(memberHash)", "_waitForGroupPeer(memberHash)",
        "_markGroupPeerReady(memberHash)", "async _ensureGroupLink(memberHash, publicKeyHex)",
    ]) self[signature.replace(/^async /, "").split("(")[0]] = compile(signature, sendEnv)(self);

    // The user's own acts, as the page runs them.
    const alerts = [];
    const page = { state: { activeHash: null }, render() {} };
    const pageEnv = {
        GroupStore, ContactStore, GroupMsgStore, console: quiet, RnsClient: self, confirm: () => true,
        alert: (m) => alerts.push(m), document: { body: { classList: { remove() {} } } },
    };
    for (const signature of ["_acceptGroupInvite(groupId)", "_declineGroupInvite(groupId)", "_leaveGroup(groupId)", "_quitGroup(groupId, how)"]) {
        page[signature.slice(0, signature.indexOf("("))] = compile(signature, pageEnv)(page);
    }

    const seen = new Set();
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: (h) => (seen.has(h) ? true : (seen.add(h), false)) }, Harness, console: quiet,
        RnsClient: { ownHash: own }, LXMF, LXMessage, ContactStore, MsgStore, decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self);
    const emitted = [];
    router.on("message", (m) => { emitted.push(m); handle(m); });

    const client = {
        me, own, pubKey, storage, switched, filter, name,
        ContactStore, GroupStore, GroupMsgStore, PrivacyFilter, MsgStore, Harness, events,
        router, destination, self, page, alerts, paths, sent, proofs, relays, fallbacks, emitted, recall,
        /** Deliver `packed` (a full packing, destination first) as an
         *  opportunistic packet: signatures are checked against this
         *  client's identity store. */
        async receive(packed) {
            LXMessage.recall = recall;
            destination.emit("packet", { data: packed.subarray(16), packet: { prove: () => proofs.push(packed) } });
            await settle();
        },
        /** Hold `other`'s key, as a contact with it would. */
        know(other) {
            const hash = other.own ?? lxmfHash(other);
            const publicKey = other.pubKey ?? other.getPublicKey().toString("hex");
            const row = ContactStore.keep(hash, publicKey);
            if (!row.publicKey) { row.publicKey = publicKey; ContactStore._save(); }      // a row kept without a key gets it
            return client;
        },
        /** Every peer is reachable: a path is known for each hash given. */
        reachable(...hashes) {
            for (const h of hashes) self._markGroupPeerReady(h.own ?? h);
            return client;
        },
        /** The status of member `hash` in group `groupId` as this client holds it. */
        status: (groupId, hash) => GroupStore.get(groupId)?.members.get(hash),
        /** The group's system notices, [text, actor]. */
        notices: (groupId) => GroupMsgStore.get(groupId).filter((m) => m.dir === "system").map((m) => [m.content, m.actor ?? null]),
        held: () => GroupStore.heldChanges().map((e) => [e.src, e.action]),
        /** Another client over the same storage, as after a reload. */
        reload: (options = {}) => groupClient({ me, storage, filter, switched, name, ...options }),
        /** The messages sent, as their recipient parses them (no keys needed). */
        decoded: (from = 0) => sent.slice(from).map(({ to, bytes, via }) =>
            ({ to, via, bytes, message: LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16), () => me) })),
    };
    return client;
}

/**
 * The clients on one network: what one sends (its `sent`) is delivered to the
 * client it is addressed to, as an opportunistic packet. Nothing is
 * delivered until a pump says so, so a test decides what arrives, and when:
 *   pump(from, { to, skip })  deliver what `from` has sent and not yet
 *                             delivered, in order: to `to` only when given,
 *                             never to those in `skip`; the rest stays queued.
 *   drop(from, { to })        discard what `from` has queued (for `to`, when
 *                             given): it never arrives.
 *   run()                     pump everyone until nothing new is sent
 *                             (answers included).
 * pump and run return what was delivered, [recipient hash, bytes].
 */
export function network(...clients) {
    const byHash = new Map(clients.map((c) => [c.own, c]));
    const cursor = new Map(clients.map((c) => [c, 0]));
    const queued = new Map(clients.map((c) => [c, []]));
    const collect = (from) => {
        while (cursor.get(from) < from.sent.length) {
            queued.get(from).push(from.sent[cursor.get(from)]);
            cursor.set(from, cursor.get(from) + 1);
        }
    };
    const wanted = (entry, to, skip) => (!to || entry.to === (to.own ?? to)) && !skip.some((s) => (s.own ?? s) === entry.to);
    return {
        byHash,
        queue: (from) => (collect(from), queued.get(from).slice()),
        async pump(from, { to = null, skip = [] } = {}) {
            await settle();
            collect(from);
            const delivered = [];
            const rest = [];
            for (const entry of queued.get(from)) {
                const target = byHash.get(entry.to);
                if (!target || !wanted(entry, to, skip)) { rest.push(entry); continue; }
                await target.receive(entry.bytes);
                entry.prove?.();
                delivered.push([entry.to, entry.bytes]);
            }
            queued.set(from, rest);
            await settle();
            return delivered;
        },
        drop(from, { to = null } = {}) {
            collect(from);
            queued.set(from, queued.get(from).filter((entry) => !wanted(entry, to, [])));
        },
        async run(limit = 30) {
            for (let i = 0; i < limit; i++) {
                let moved = 0;
                for (const c of clients) moved += (await this.pump(c)).length;
                if (moved === 0) return;
            }
            throw new Error("the network did not settle");
        },
    };
}
