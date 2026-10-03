/**
 * CHANNELS AND THE DISTRO — RFed-rust SPEC.md §17.12, RFed-spec/Channel.md
 * "Distro holders", LXMF-rust/DISPLAY_NAMES.md §4.2 (James, 2026-10-03).
 *
 * Until then (Retichat-js 24d83e6) the web signed every channel post with
 * the device, so a post made on the user's phone showed on the laptop as a
 * stranger's, each device had to join each channel itself, and rfed's echo
 * of an own post, pulled after a reload, was stored a second time as an
 * incoming post. Now:
 *   1. a device holding distro D signs its posts as D; subscribing, the
 *      stream and pulls stay the device's;
 *   2. a post from the device or from D is the user's own: stored as
 *      outgoing and "sent", no contact row, never counted as a sender, and
 *      every post is deduplicated by (source, timestamp) against what is
 *      stored, across reloads;
 *   3. the user's join or leave goes to D's other devices as one membership
 *      message C, and each applies it with its own device key, in the order
 *      §17.12 rule 5 gives;
 *   4. the Channel Display Name rule keeps its state per posting identity
 *      and learns from D's posts only the value the device would send.
 *
 * Everything runs the shipped method bodies from app.js (test_app_source.mjs)
 * over the real stores (ChannelStore, ChannelMsgStore, DistroSeen built from
 * app.js; ChannelPostNames, ChannelSenderNames, ChannelMembership from lib/),
 * with real identities, the real channel envelope, real LXMF packing and
 * real encryption. RFed is played at its seams: a post's /channel/publish
 * is taken and answered, and its fan-out handed to each device's
 * _handleChannelPacket; C's propagation upload is taken and its distro
 * fan-out handed to each device's _handleDistroBlob. Several devices of one
 * distro share nothing but those hand-offs.
 * distro_channels_page.test.mjs runs the real page.
 *
 * Run: node --test distro_channels.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Cryptography from "./lib/rns/cryptography.js";
import MsgPack from "./lib/rns/msgpack.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import { readHead, skipValue } from "./lib/rns/msgpack_raw.js";
import { channelLxmPack, channelLxmUnpack, channelIdentity, channelComputeStamp } from "./lib/rns/rfed_channel.js";
import { ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";
import * as DN from "./lib/display_name.js";
import { sentTimeMs } from "./lib/day_markers.js";
import { ChannelPublishes, CHANNEL_PUBLISH_PATH } from "./lib/channel_publish.js";
import {
    ChannelMembership, DISTRO_CHANNEL_TYPE, channelSyncDisposition, channelSyncFields, joinNameAccepted,
    readChannelSync, supersedes,
} from "./lib/channel_sync.js";
import { DistroUploads } from "./lib/distro_upload.js";
import { DistroOutbox, channelSyncEntryId, sentCopyEntryId } from "./lib/distro_outbox.js";
import { app, build, compile, install, methodBody, memoryStorage } from "./test_app_source.mjs";

const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const quiet = { log() {}, warn() {}, error() {} };
const RFED = "ab".repeat(16);
const CH = "public.distro";
const H = 3_600_000;

/** Every macrotask queued before this one has run: the fire-and-forget
 *  sends (C, a post's "sent") have finished their hops. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

/** The clock app.js reads (Date.now), set by the test. With `tick`, every
 *  read moves it on by 1 ms, as a real clock moves between two reads. */
function fakeClock(t, start = 1_790_000_000_000, { tick = false } = {}) {
    const real = Date.now;
    const clock = { now: start };
    Date.now = tick ? () => clock.now++ : () => clock.now;
    t.after(() => { Date.now = real; });
    return clock;
}

/** A LINK-type packet as Link.newLinkPacket builds it: `pack()` gives the
 *  bytes the fake link transmits, and its hash is the upload's own. */
const linkPacket = (data) => ({ packetHash: Cryptography.fullHash(Buffer.from(data)), pack: () => Buffer.from(data) });

/** _onPacketsLost, whose parameter is destructured, compiled by hand. */
function installPacketsLost(self, env) {
    const body = methodBody("_onPacketsLost({ packetHashes, reason })").replaceAll("this.", "self.");
    const names = Object.keys(env);
    const f = new Function(...names, "self", "arg", `const { packetHashes, reason } = arg; ${body}`);
    self._onPacketsLost = (arg) => f(...names.map((n) => env[n]), self, arg);
}

/**
 * One device: its own identity and storage, the shipped methods, and, when
 * `distro` is given, that distro held. `ownName` is its Channel Display
 * Name. RFed is played at the seams (see the header); `holdUnsubscribe`
 * keeps each /rfed/unsubscribe unanswered until `release()`. The
 * propagation link is up from the start unless `linkUp` is false;
 * `establish()` brings a new one up (its "established" handler's
 * _sendDistroOutbox), `closeLink()` takes the current one down (its "close"
 * handler's cut). A page reload is a second device() on the same `me` and
 * `storage`.
 */
function device(distro, { label = "device", ownName = null, resubscribed = true, holdUnsubscribe = false, proofs = "auto",
    linkUp = true, me = Identity.create(), storage = memoryStorage() } = {}) {
    const { sGet, sSet } = storage;
    const names = { get: sGet, set: sSet };
    const events = [];
    const ui = [];
    const contacts = new Set();
    const Harness = {
        event: (kind, detail) => events.push({ kind, detail }),
        error: (where, e) => events.push({ kind: "error", detail: { where, message: e?.message ?? String(e) } }),
    };
    const ChannelStore = build("ChannelStore", { sGet, sSet, channelIdentity });
    ChannelStore.init();
    const ChannelMsgStore = build("ChannelMsgStore", { sGet, sSet });
    const DistroSeen = build("DistroSeen", { sGet, sSet });
    DistroSeen.init();
    const DistroManager = { has: false, identity: null, lxmfDeliveryHash: null, pubKey: null };
    const hold = (identity) => Object.assign(DistroManager, identity
        ? { has: true, identity, lxmfDeliveryHash: lxmfHash(identity), pubKey: identity.getPublicKey().toString("hex") }
        : { has: false, identity: null, lxmfDeliveryHash: null, pubKey: null });
    hold(distro);
    const logged = [];      // the error and warn lines of the shipped code
    const log = {
        log() {},
        warn: (...args) => logged.push(["warn", args.join(" ")]),
        error: (...args) => logged.push(["error", args.join(" ")]),
    };
    const env = {
        Buffer, Destination, Cryptography, MsgPack, LXMessage, LXMF, Link: { MDU: 100_000, ACTIVE: 0x02, CLOSED: 0x04 },
        Packet: { NONE: 0x00 }, console: log,
        IdMgr: { has: true, id: me, hash: me.hash.toString("hex") },
        DistroManager, DistroSeen, Harness,
        ContactStore: { keep: (h) => { contacts.add(h); return { publicKey: null }; }, _save() {}, touch() {}, acceptMessageName() {} },
        MsgStore: { add: () => assert.fail("no direct message here"), get: () => [] },
        ChannelStore, ChannelMsgStore,
        ChannelSenderNamesStore: new ChannelSenderNames(names), ChannelPostNamesStore: new ChannelPostNames(names),
        ChannelMembershipStore: new ChannelMembership(names),
        DistroOutboxStore: new DistroOutbox(names), channelSyncEntryId, sentCopyEntryId,
        channelIdentity, channelLxmPack, channelLxmUnpack, channelComputeStamp, channelSyncFields, channelSyncDisposition,
        CHANNEL_PUBLISH_PATH, OwnNames: { channel: ownName },
        ownLxmfDestinationHash: () => lxmfHash(me), sentTimeMs, decodeDisplayName: DN.decodePayload,
        rfedRequestTimeoutMs: () => 10_000,
    };
    const uploads = [];     // the LXMF packing of each C this device propagated
    const requests = [];    // [path, payload] to rfed, in the order sent
    const published = [];   // each post's /channel/publish payload: channel_hash | blob
    const held = [];
    // The §1 watch's timers, run by the test (fireTimers), never by a clock.
    const timers = [];
    // The propagation link C goes on: the node proves each upload packet at
    // once (`proofs: "auto"`), or when the test says (`prove()`).
    const proofKeys = [];
    const propagationLink = (name = "link") => ({
        name, status: 0x02, sent: [],
        newLinkPacket: (context, data) => linkPacket(data),
        _transmit(raw) {
            if (this.status === 0x04) return null;
            this.sent.push(Buffer.from(raw));
            uploads.push(Buffer.from(raw));
            const key = Cryptography.fullHash(Buffer.from(raw)).subarray(0, 16).toString("hex");
            proofKeys.push(key);
            if (proofs === "auto") queueMicrotask(() => prove(key));
            return raw;
        },
        sendResource: async (d) => { uploads.push(Buffer.from(d)); },
        close() { this.status = 0x04; },
    });
    /** The propagation node's proof of the upload packet `key` (the
     *  proof handler, RnsClient.connect's "proof" listener). */
    const prove = (key = proofKeys.at(-1)) => {
        const pending = self._pendingPacketHashes.get(key);
        if (!pending) return false;
        self._pendingPacketHashes.delete(key);
        pending.onProof?.(pending.messageId);
        return true;
    };
    const self = {
        ownHash: lxmfHash(me),
        _cfg: { rfedNodeHash: RFED },
        _channelsResubscribed: resubscribed, _channelsInitialized: false,
        _rfedSubscriptionPromises: new Map(), _rfedUnsubscribes: new Map(), _rfedStampRefreshed: new Set(),
        _rfedOpenedChannelHashes: new Set(), _rfedStreamPromises: new Map(),
        _pendingTickets: new Map(), _pendingPacketHashes: new Map(), _pendingTimeouts: new Map(),
        _distroUploads: new DistroUploads({
            now: () => Date.now(), log,
            setTimer: (fn, ms) => { const timer = { fn, ms, cleared: false }; timers.push(timer); return timer; },
            clearTimer: (timer) => { timer.cleared = true; },
        }),
        _onMsg: [(m, peer) => ui.push({ kind: m?.kind ?? null, synced: m?.synced ?? null, peer })],
        _channelPublishes: new ChannelPublishes(), _rfedSendChain: Promise.resolve(),
        _rfedRequest: async (aspects, path, payload) => {
            requests.push([path, MsgPack.unpack(payload)]);
            if (path === "/rfed/unsubscribe" && holdUnsubscribe) await new Promise((resolve) => held.push(resolve));
            return path === "/rfed/subscribe" ? [true, null] : true;
        },
        _configureChannelStream: async () => {},
        openChannel: async () => {},
        // Every propagation link this device had, oldest first; _propLink
        // is the current one.
        _propLinks: [], _propLink: null, _distroOutboxInFlight: new Map(),
        _buildPropagationPacked: async (packed) => packed,
        _exchangeIsDown: () => false,
        _ensureChannelStreamConfigured: async () => {},
        _rfedLinkAvailable: () => true,
        _ensureRfedLink: async () => ({
            sendRequestPacked: (path, packed, options) => {
                assert.equal(path, "/channel/publish");
                published.push(Buffer.from(MsgPack.unpack(packed)));
                options?.onDelivered?.();
                return Buffer.alloc(16, published.length);
            },
            responseFor: () => Promise.resolve([true, null]),
        }),
    };
    install(self, env, [
        "sendingIdentity()",
        "async sendChannelMessage(channelName, content)",
        "_setChannelPostStatus(channelName, msgId, status)",
        "_handleChannelPacket(packetData)",
        "async joinChannel(channelName)",
        "async leaveChannel(channelName)",
        "_leaveChannelHere(ch, synced = false)",
        "_ensureChannelSubscribed(channel)",
        "async _subscribeChannel(channelName, rfedNodeHash)",
        "async _unsubscribeChannel(channelName, rfedNodeHash)",
        "_syncChannelMembership(op, ch)",
        "_sendDistroChannelSync(op, ch, atMs)",
        "async _sendDistroSentCopy(recipientHex, title, content)",
        "_oweDistro(entry)",
        "async _sendDistroOutbox(link, trigger)",
        "async _uploadOwed(link, entry)",
        "_stillOwed(entry)",
        "_dropOwedToOtherDistros()",
        "_distroOwedOutcome(entry, how, error)",
        "_uploadForDistro(link, propagationPacked, label)",
        "_handleDistroBlob(distroHash, blob)",
        "_handleDistroChannelSync(marker, facts)",
        "_applyDistroChannelSync(change, byHex)",
    ]);
    installPacketsLost(self, env);
    /** A new propagation link is up: what is owed goes on it, as the link's
     *  "established" handler (_onPropagationLinkEstablished) sends it. */
    const establish = async (name = `link${self._propLinks.length + 1}`) => {
        const link = propagationLink(name);
        self._propLinks.push(link);
        self._propLink = link;
        await self._sendDistroOutbox(link, "established");
        return link;
    };
    /** The current propagation link closes, as its "close" handler takes
     *  it: no proof can come over it, so its open uploads are cut. */
    const closeLink = () => {
        const link = self._propLink;
        link.status = 0x04;
        self._propLink = null;
        self._distroUploads.cut("the propagation link closed before the propagation node proved it", link);
        return link;
    };
    if (linkUp) {
        self._propLink = propagationLink("link1");
        self._propLinks.push(self._propLink);
    }
    return {
        label, me, hash: lxmfHash(me), self, env, storage, ChannelStore, ChannelMsgStore, DistroManager, hold,
        uploads, requests, published, events, ui, contacts, logged, timers, proofKeys, prove, establish, closeLink,
        makeLink: propagationLink,
        /** What this device still owes the distro (lib/distro_outbox.js). */
        owed: () => env.DistroOutboxStore.list().map((e) => (e.kind === "channel" ? [e.kind, e.op, e.name, e.at] : [e.kind, e.to])),
        sentEvents: () => events.filter((e) => e.kind === "distro-channel-sync-sent").map((e) => [e.detail.op, e.detail.channel]),
        /** Run the §1 watch's timers that are due and not cleared. */
        fireTimers: () => timers.splice(0).filter((timer) => !timer.cleared).forEach((timer) => timer.fn()),
        release: () => held.splice(0).forEach((resolve) => resolve()),
        channels: () => ChannelStore.getAll().map((c) => c.channelName).sort(),
        record: (name) => env.ChannelMembershipStore.get(channelIdentity(name).hash.toString("hex")),
        syncEvents: () => events.filter((e) => e.kind === "distro-channel-sync").map((e) => e.detail.result),
    };
}

/** RFed's distro fan-out of one propagated LXMF packing to `devices`, in
 *  that order: each gets [D | D-encrypted(src | sig | payload)]. Returns
 *  what each _handleDistroBlob answered. */
function fanOut(distro, packed, devices) {
    const D = Buffer.from(lxmfHash(distro), "hex");
    const blob = Buffer.concat([D, distro.encrypt(Buffer.from(packed).subarray(16))]);
    return devices.map((d) => d.self._handleDistroBlob(null, blob));
}

/** RFed's channel fan-out of a post to `devices`. */
const deliver = (wire, devices) => devices.map((d) => d.self._handleChannelPacket(wire));

/** A membership message as any client could build it: `fields` as given,
 *  source `source`'s address, signed by `signer`, to D. */
function craftC(distro, { fields, source = distro, signer = source, timestampMs = Date.now(), content = "" }) {
    const msg = new LXMessage();
    msg.sourceHash = Buffer.from(lxmfHash(source), "hex");
    msg.destinationHash = Buffer.from(lxmfHash(distro), "hex");
    msg.title = "";
    msg.content = content;
    msg.fields = fields;
    msg.timestamp = timestampMs / 1000;
    return msg.pack(signer, false);
}

/** The raw msgpack heads of a packed LXMF message's fields, by key. */
function rawFields(packed) {
    const b = Buffer.from(packed).subarray(96);
    const top = readHead(b, 0);
    let pos = top.end;
    for (let i = 0; i < 3; i++) pos = skipValue(b, pos);
    const map = readHead(b, pos);
    pos = map.end;
    const out = new Map();
    for (let i = 0; i < map.count; i++) {
        const key = readHead(b, pos);
        pos = skipValue(b, pos);
        out.set(key.int, { at: pos, head: readHead(b, pos), bytes: b.subarray(pos, skipValue(b, pos)) });
        pos = skipValue(b, pos);
    }
    return out;
}

// ═════════════════════════════════════════════════════════════════════════
//  lib/channel_sync.js — the membership message's form and rules 4 and 5
// ═════════════════════════════════════════════════════════════════════════

test("C's fields: an empty 0x0C, the type, [op, name, at_ms] as a native array with an integer time, the sending device", () => {
    const device = "AB".repeat(16);
    const fields = channelSyncFields("join", "public.tea", 1_790_000_000_123, device);
    assert.deepEqual([...fields.keys()], [0x0C, 0xFB, 0xFC, 0xFD]);
    const packed = Buffer.from(MsgPack.pack(fields));
    // The bytes: an empty bin, a str, an array of three, a str.
    const b = packed;
    const heads = [];
    let pos = readHead(b, 0).end;
    for (let i = 0; i < 4; i++) {
        const key = readHead(b, pos);
        pos = skipValue(b, pos);
        heads.push([key.int, readHead(b, pos)]);
        pos = skipValue(b, pos);
    }
    const [ticket, type, data, meta] = heads.map(([, h]) => h);
    assert.deepEqual([ticket.kind, ticket.raw.length], ["bin", 0], "0x0C an empty bin (c4 00), never nil or a str");
    assert.deepEqual([type.kind, Buffer.from(type.raw).toString()], ["str", DISTRO_CHANNEL_TYPE]);
    assert.deepEqual([data.kind, data.count], ["array", 3], "0xFC a native array, never a bin of packed msgpack");
    let p = data.end;
    const op = readHead(b, p); p = skipValue(b, p);
    const name = readHead(b, p); p = skipValue(b, p);
    const at = readHead(b, p);
    assert.deepEqual([op.kind, Buffer.from(op.raw).toString(), name.kind, Buffer.from(name.raw).toString()], ["str", "join", "str", "public.tea"]);
    assert.deepEqual([at.kind, at.int], ["int", 1_790_000_000_123], "at_ms an integer: a JS number above 32 bits would go as a float 64");
    assert.deepEqual([meta.kind, Buffer.from(meta.raw).toString()], ["str", device.toLowerCase()]);
    for (const [args, why] of [[["rejoin", "public.x", 1, device], "op"], [["join", "", 1, device], "name"],
        [["join", "public.x", -1, device], "negative at_ms"], [["join", "public.x", 1.5, device], "fractional at_ms"],
        [["join", "public.x", 1, "nope"], "device address"]]) {
        assert.throws(() => channelSyncFields(...args), Error, why);
    }
});

test("readChannelSync: a usable marker, from str or bin, with any integer width; elements after the third ignored", () => {
    const enc = (s) => new TextEncoder().encode(s);
    const payload = (fields) => Buffer.from(MsgPack.pack([1.5, Buffer.alloc(0), Buffer.alloc(0), fields]));
    const by = "cd".repeat(16);
    assert.deepEqual(readChannelSync(payload(channelSyncFields("leave", "4cdc4115.tea", 42, by))),
        { byHex: by, sync: { op: "leave", name: "4cdc4115.tea", atMs: 42 }, problem: null });
    const bin = new Map([[0xFB, enc(DISTRO_CHANNEL_TYPE)], [0xFC, [enc("join"), enc("public.tea"), 7, "extra"]], [0xFD, enc(by.toUpperCase())]]);
    assert.deepEqual(readChannelSync(payload(bin)), { byHex: by, sync: { op: "join", name: "public.tea", atMs: 7 }, problem: null });
    const noMeta = new Map([[0xFB, DISTRO_CHANNEL_TYPE], [0xFC, ["join", "public.tea", 2n ** 40n]]]);
    assert.deepEqual(readChannelSync(payload(noMeta)), { byHex: "", sync: { op: "join", name: "public.tea", atMs: 2 ** 40 }, problem: null });
});

test("readChannelSync: no marker for other types and other shapes; an unusable 0xFC is a marker with no change", () => {
    const payload = (fields) => Buffer.from(MsgPack.pack([1.5, Buffer.alloc(0), Buffer.alloc(0), fields]));
    assert.equal(readChannelSync(payload(new Map([[0xFB, "rfed.distro.sent"], [0xFC, ["join", "public.x", 1]]]))), null);
    assert.equal(readChannelSync(payload(new Map([[0xFC, ["join", "public.x", 1]]]))), null);
    assert.equal(readChannelSync(payload(new Map())), null);
    assert.equal(readChannelSync(Buffer.from(MsgPack.pack([1.5, Buffer.alloc(0), Buffer.alloc(0)]))), null);
    assert.equal(readChannelSync(Buffer.from([0xc1])), null);
    assert.equal(readChannelSync("not bytes"), null);

    const unusable = (data, why) => {
        const r = readChannelSync(payload(new Map([[0xFB, DISTRO_CHANNEL_TYPE], [0xFC, data], [0xFD, "ee".repeat(16)]])));
        assert.equal(r.sync, null, why);
        assert.equal(r.byHex, "ee".repeat(16), why);
        assert.equal(typeof r.problem, "string", why);
    };
    // CHECK_THESE_THINGS_FIRST.md §11: the array packed and wrapped in a bin.
    unusable(Buffer.from(MsgPack.pack(["join", "public.x", 1])), "0xFC as a bin holding packed msgpack");
    unusable(Date.now(), "a scalar 0xFC");
    unusable(["join", "public.x"], "two elements");
    unusable(["rejoin", "public.x", 1], "an op that is neither join nor leave");
    unusable([1, "public.x", 1], "an op that is not text");
    unusable(["join", "", 1], "an empty name");
    unusable(["join", Buffer.from([0xff, 0xfe]), 1], "a name that is not UTF-8");
    unusable(["join", "public.x", -5], "a negative at_ms");
    // msgpackr packs this ms time as a float 64 (cb): an integer to JS, a
    // float to LXMF-rust, which refuses it. Refused here too, from the bytes.
    unusable(["join", "public.x", 1_790_000_000_000], "an at_ms sent as a float");
    unusable(["join", "public.x", 1.5], "a fractional at_ms");
    unusable(["join", "public.x", null], "a nil at_ms");
    assert.equal(readChannelSync(payload(new Map([[0xFB, DISTRO_CHANNEL_TYPE]]))).problem, "it carries no 0xFC");
});

/** A C payload whose at_ms is the 64-bit `value` (a BigInt) written as
 *  `type`: 0xd3 (int 64, as the web writes it) or 0xcf (uint 64, as rmpv and
 *  umsgpack write it). msgpackr writes the placeholder as int 64. */
function payloadAt(value, type) {
    const placeholder = 0x7fff_ffff_ffff_ffffn;
    const fields = new Map([[0xFB, DISTRO_CHANNEL_TYPE], [0xFC, ["join", "public.tea", placeholder]], [0xFD, "cd".repeat(16)]]);
    const b = Buffer.from(MsgPack.pack([1.5, Buffer.alloc(0), Buffer.alloc(0), fields]));
    const at = b.indexOf(Buffer.from("d37fffffffffffffff", "hex"));
    assert.notEqual(at, -1);
    b[at] = type;
    b.writeBigUInt64BE(value, at + 1);
    return b;
}

test("readChannelSync: at_ms is an integer from 0 to 2^53 − 1 in any integer encoding; from 2^53 up it is no at_ms (§17.12 rule 4)", () => {
    const INT64 = 0xd3, UINT64 = 0xcf;
    const atMs = (value, type) => readChannelSync(payloadAt(value, type));
    // The same value from the web (int 64) and from a phone (uint 64) is one action.
    assert.deepEqual(atMs(1_790_000_000_123n, INT64), atMs(1_790_000_000_123n, UINT64));
    assert.equal(atMs(1_790_000_000_123n, UINT64).sync.atMs, 1_790_000_000_123, "uint 64, as rmpv writes it");
    assert.equal(atMs(2n ** 53n - 1n, UINT64).sync.atMs, 2 ** 53 - 1, "2^53 − 1 as uint 64");
    assert.equal(atMs(2n ** 53n - 1n, INT64).sync.atMs, 2 ** 53 - 1, "2^53 − 1 as int 64");
    // Review of a448e98: these were read, rounded (2^53 + 1 as 2^53), and
    // applied, where the phones keep them exact; a join at 2^53 + 1 and a
    // leave at 2^53 were then ordered one way here and the other there.
    for (const [value, type, why] of [[2n ** 53n, UINT64, "2^53 as uint 64"], [2n ** 53n + 1n, UINT64, "2^53 + 1 as uint 64"],
        [2n ** 53n, INT64, "2^53 as int 64"], [2n ** 53n + 1n, INT64, "2^53 + 1 as int 64"], [2n ** 64n - 1n, UINT64, "2^64 − 1"],
        [2n ** 64n - 1n, INT64, "−1 as int 64"]]) {
        const r = atMs(value, type);
        assert.deepEqual([r.sync, r.problem], [null, "its at_ms is not an integer from 0 to 2^53 − 1"], why);
    }
});

test("rule 4: a C whose at_ms is above 2^53 − 1 is dropped, whatever its encoding, and never applied", (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const b = device(distro);
    const typed = (at) => new Map([[0x0C, Buffer.alloc(0)], [0xFB, DISTRO_CHANNEL_TYPE], [0xFC, ["join", "public.tea", at]], [0xFD, "cc".repeat(16)]]);
    let ts = Date.now();
    assert.deepEqual(fanOut(distro, craftC(distro, { fields: typed(2n ** 53n + 1n), timestampMs: ++ts }), [b]), [false]);
    assert.deepEqual(fanOut(distro, craftC(distro, { fields: typed(2n ** 63n + 5n), timestampMs: ++ts }), [b]), [false], "uint 64");
    assert.deepEqual(b.channels(), []);
    assert.equal(b.record("public.tea"), null, "nothing recorded for rule 5 either");
    assert.deepEqual(b.events.filter((e) => e.kind === "distro-channel-sync").map((e) => e.detail.rule), [4, 4]);
    assert.deepEqual(fanOut(distro, craftC(distro, { fields: typed(2n ** 53n - 1n), timestampMs: ++ts }), [b]), [true]);
    assert.deepEqual(b.channels(), ["public.tea"], "2^53 − 1 is applied");
});

test("joinNameAccepted: exactly the names the New Channel form joins", () => {
    for (const ok of ["public.tea", "public.tea-time.2", "4cdc4115.nametest-096499", "0123456789abcdef.x", "public.café"]) {
        assert.equal(joinNameAccepted(ok), true, ok);
    }
    for (const no of ["public.Test", "Test", "My Channel", "public.", ".tea", "public..tea", "public.tea.", " public.tea",
        "public.tea ", "public.my channel", "PUBLIC.tea", "public.café", "", null, 7]) {
        assert.equal(joinNameAccepted(no), false, String(no));
    }
});

test("supersedes: a later time wins; at an equal time a leave replaces a join, never the other way", () => {
    assert.equal(supersedes({ op: "join", atMs: 5 }, null), true);
    assert.equal(supersedes({ op: "join", atMs: 6 }, { op: "leave", at: 5 }), true);
    assert.equal(supersedes({ op: "leave", atMs: 4 }, { op: "join", at: 5 }), false);
    assert.equal(supersedes({ op: "leave", atMs: 5 }, { op: "join", at: 5 }), true);
    assert.equal(supersedes({ op: "join", atMs: 5 }, { op: "leave", at: 5 }), false);
    assert.equal(supersedes({ op: "join", atMs: 5 }, { op: "join", at: 5 }), false);
    assert.equal(supersedes({ op: "leave", atMs: 5 }, { op: "leave", at: 5 }), false);
});

test("the disposition takes rules 1-5 in order: the first that drops ends it", () => {
    const own = "aa".repeat(16), other = "bb".repeat(16);
    const marker = (op, name, atMs, byHex = other) => ({ byHex, sync: { op, name, atMs }, problem: null });
    const facts = (extra = {}) => ({ fromDistro: true, signedByDistro: true, ownDeviceHex: own,
        channelHashOf: (n) => `hash:${n}`, recordOf: () => null, ...extra });
    assert.deepEqual(channelSyncDisposition(marker("join", "public.x", 1, own), facts({ fromDistro: false, signedByDistro: false })),
        { verdict: "drop", rule: 1, reason: "its source is not this device's distro" }, "rule 1 before rule 3");
    assert.equal(channelSyncDisposition(marker("join", "public.x", 1, own), facts({ signedByDistro: false })).rule, 2, "rule 2 before rule 3");
    assert.deepEqual(channelSyncDisposition({ byHex: own, sync: null, problem: "x" }, facts()), { verdict: "echo" }, "rule 3 before rule 4");
    assert.deepEqual(channelSyncDisposition({ byHex: other, sync: null, problem: "bad" }, facts()), { verdict: "drop", rule: 4, reason: "bad" });
    assert.equal(channelSyncDisposition(marker("join", "public.Test", 1), facts()).rule, 4, "a join held to the join rules");
    assert.deepEqual(channelSyncDisposition(marker("leave", "public.Test", 1), facts()),
        { verdict: "apply", op: "leave", name: "public.Test", atMs: 1, channelHash: "hash:public.Test" }, "a leave is not");
    const stale = channelSyncDisposition(marker("join", "public.x", 4), facts({ recordOf: (h) => (h === "hash:public.x" ? { op: "leave", at: 5 } : null) }));
    assert.equal(stale.verdict, "stale");
    assert.deepEqual(stale.recorded, { op: "leave", at: 5 });
});

test("ChannelMembership: the user's action is stamped after any record held, and the record persists", () => {
    const storage = memoryStorage();
    const names = { get: storage.sGet, set: storage.sSet };
    const log = new ChannelMembership(names);
    assert.equal(log.stampLocal("c1", "join", 1000), 1000, "no record: the clock");
    assert.equal(log.stampLocal("c1", "leave", 2000), 2000, "a later clock");
    log.record("c1", "join", 9_000);
    assert.equal(log.stampLocal("c1", "leave", 2500), 9_001, "a clock behind the record: one more than it");
    assert.deepEqual(new ChannelMembership(names).get("c1"), { op: "leave", at: 9_001 }, "persisted");
    assert.equal(new ChannelMembership(names).get("c2"), null);
});

// ═════════════════════════════════════════════════════════════════════════
//  1. Posting identity: the distro signs; the device subscribes
// ═════════════════════════════════════════════════════════════════════════

test("a device holding a distro posts as the distro: source, prelude key and signature are D's; the record and the echo key too", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    const post = await a.self.sendChannelMessage(CH, "as the distro");
    const wire = a.published[0];
    const unpacked = channelLxmUnpack(CH, wire);
    assert.equal(unpacked.sourceHash.toString("hex"), lxmfHash(distro), "the post's source is D");
    assert.equal(Buffer.from(unpacked.senderPubKey).toString("hex"), distro.getPublicKey().toString("hex"), "D's key in the prelude");
    assert.equal(unpacked.signatureValidated, true, "signed by D (channelLxmUnpack checks it)");
    const [record] = a.ChannelMsgStore.get(CH).filter((m) => m.dir === "out");
    assert.deepEqual([record.srcHash, record.timestamp, record.status], [lxmfHash(distro), unpacked.tsMs, "sent"],
        "the record holds the post's identity: D and the timestamp it was packed with");
    assert.equal(post.id, record.id);
    // rfed's echo of it: dropped against the record (in memory, then stored).
    assert.equal(a.self._handleChannelPacket(wire), true);
    assert.equal(a.ChannelMsgStore.get(CH).filter((m) => m.dir !== "system").length, 1, "no second bubble");
});

test("rfed's echo of a post as the distro, before rfed answers, makes it sent: the echo key is the posting identity's", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    a.self._ensureRfedLink = async () => ({
        sendRequestPacked: (path, packed, options) => {
            a.published.push(Buffer.from(MsgPack.unpack(packed)));
            options?.onDelivered?.();
            return Buffer.alloc(16, 1);
        },
        responseFor: () => new Promise(() => {}),   // rfed's answer has not come
    });
    let outcome = null;
    a.self.sendChannelMessage(CH, "echoed first").then(() => { outcome = "sent"; }, (e) => { outcome = e.message; });
    await settle();
    assert.equal(outcome, null);
    assert.deepEqual(deliver(a.published[0], [a]), [true]);
    await settle();
    assert.equal(outcome, "sent", "the post's own publish is decided by the echo");
    assert.equal(a.ChannelMsgStore.get(CH).find((m) => m.dir === "out").status, "sent");
    assert.equal(a.ChannelMsgStore.get(CH).filter((m) => m.dir !== "system").length, 1);

    // The echo key gone from memory (the set keeps the last 1000 of 2000
    // once full) while the publish is still tracked: the stored post decides
    // it all the same, so it cannot be failed later by the request's budget.
    let second = null;
    Date.now = ((n) => () => n)(Date.now() + 1000);
    a.self.sendChannelMessage(CH, "echoed after a busy pull").then(() => { second = "sent"; }, (e) => { second = e.message; });
    await settle();
    a.self._chanSeenIds = new Set();
    assert.deepEqual(deliver(a.published[1], [a]), [true]);
    await settle();
    assert.equal(second, "sent");
    assert.equal(a.self._channelPublishes._posts.size, 0, "nothing left tracked");
});

test("without a distro the device posts as itself, and a distro taken up later makes the next post D's", async (t) => {
    const clock = fakeClock(t);
    const a = device(null);
    a.ChannelStore.join(CH, RFED);
    await a.self.sendChannelMessage(CH, "as the device");
    assert.equal(channelLxmUnpack(CH, a.published[0]).sourceHash.toString("hex"), a.hash);
    const distro = Identity.create();
    a.hold(distro);
    clock.now += 1000;
    await a.self.sendChannelMessage(CH, "as the distro now");
    assert.equal(channelLxmUnpack(CH, a.published[1]).sourceHash.toString("hex"), lxmfHash(distro));
});

test("subscribing, unsubscribing and the stream stay the device's: RFed keys a subscriber by its key", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    const ch = a.ChannelStore.join(CH, RFED);
    await a.self._ensureChannelSubscribed(ch);
    await a.self._leaveChannelHere(ch);
    const [[subPath, sub], [unsubPath, unsub]] = a.requests;
    assert.deepEqual([subPath, unsubPath], ["/rfed/subscribe", "/rfed/unsubscribe"]);
    for (const [, key, sig] of [sub, unsub]) {
        assert.equal(Buffer.from(key).toString("hex"), a.me.getPublicKey().toString("hex"), "the device's key, never D's");
        assert.ok(a.me.validate(Buffer.from(sig), channelIdentity(CH).hash), "signed by the device");
    }
    // The stream's signature and the link's identify: the device's identity
    // only, never the distro's or the posting identity.
    for (const sig of ["async _configureChannelStream()", "async _subscribeChannel(channelName, rfedNodeHash)",
        "async _unsubscribeChannel(channelName, rfedNodeHash)"]) {
        const body = methodBody(sig);
        assert.match(body, /IdMgr\.id\.getPublicKey\(\)/, sig);
        assert.doesNotMatch(body, /DistroManager|sendingIdentity/, sig);
    }
});

// ═════════════════════════════════════════════════════════════════════════
//  2. Own posts and deduplication
// ═════════════════════════════════════════════════════════════════════════

test("a sibling's post as the distro is the user's own: outgoing and sent, no contact row, not counted as a sender", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { ownName: "Ann" });
    const b = device(distro);
    for (const d of [a, b]) d.ChannelStore.join(CH, RFED);
    await a.self.sendChannelMessage(CH, "first, with my name");
    clock.now += 1000;
    const sibling = channelLxmPack(CH, distro, "from the phone", DN.ABSENT, Date.now());
    assert.equal(a.self._handleChannelPacket(sibling.wire), true);
    const posts = a.ChannelMsgStore.get(CH).filter((m) => m.dir !== "system");
    assert.deepEqual(posts.map((m) => [m.dir, m.content, m.status, m.srcHash, m.timestamp]), [
        ["out", "first, with my name", "sent", lxmfHash(distro), posts[0].timestamp],
        ["out", "from the phone", "sent", lxmfHash(distro), sibling.tsMs],
    ], "the user's bubble, \"sent\" (it came from RFed), never \"delivered\"");
    assert.equal(a.contacts.size, 0, "no contact row for the distro");
    assert.deepEqual(a.events.filter((e) => e.kind === "channel-own-post").map((e) => e.detail.via), ["distro"]);
    // §4.2 rule 2: a sibling is no new reader, so the next post does not
    // carry the name again.
    clock.now += 1000;
    await a.self.sendChannelMessage(CH, "second");
    assert.equal(channelLxmUnpack(CH, a.published[1]).displayName.state, "absent");
    // The same post again (stream, then pull): stored once.
    assert.equal(a.self._handleChannelPacket(sibling.wire), true);
    assert.equal(a.ChannelMsgStore.get(CH).filter((m) => m.content === "from the phone").length, 1);
});

test("a post this device signed with its own key before it held the distro is its own too; D's posts are another's once D is given up", (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    const old = channelLxmPack(CH, a.me, "from before the distro", DN.ABSENT, Date.now() - 5000);
    assert.equal(a.self._handleChannelPacket(old.wire), true);
    assert.equal(a.ChannelMsgStore.held(CH, a.hash, old.tsMs)?.dir, "out", "this device's own address");
    a.hold(null);
    const later = channelLxmPack(CH, distro, "D, after this device gave it up", DN.nameState("Dee"), Date.now());
    assert.equal(a.self._handleChannelPacket(later.wire), true);
    const record = a.ChannelMsgStore.held(CH, lxmfHash(distro), later.tsMs);
    assert.deepEqual([record.dir, record.status], ["in", "delivered"], "another poster's");
    assert.ok(a.contacts.has(lxmfHash(distro)));
});

test("rfed's echo of an own post after a reload is dropped against the stored post, which it makes sent; never a second, incoming bubble", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    // The post went; the tab was reloaded before rfed answered.
    a.self._ensureRfedLink = async () => ({
        sendRequestPacked: (path, packed, options) => {
            a.published.push(Buffer.from(MsgPack.unpack(packed)));
            options?.onDelivered?.();
            return Buffer.alloc(16, 1);
        },
        responseFor: () => new Promise(() => {}),
    });
    a.self.sendChannelMessage(CH, "posted before the reload");
    await settle();
    assert.equal(a.published.length, 1);
    assert.equal(a.ChannelMsgStore.get(CH).find((m) => m.dir === "out").status, "sending");
    // The reload: this tab's memory is new, its storage is not.
    a.self._chanSeenIds = new Set();
    a.self._channelPublishes = new ChannelPublishes();
    clock.now += 60_000;
    // rfed's echo, deferred and pulled now.
    assert.equal(a.self._handleChannelPacket(a.published[0]), true);
    const posts = a.ChannelMsgStore.get(CH).filter((m) => m.dir !== "system");
    assert.deepEqual(posts.map((m) => [m.dir, m.status]), [["out", "sent"]], "one bubble, the user's, sent: RFed holds it");
    assert.ok(a.ui.some((e) => e.kind === null && e.peer === CH), "the bubble is told of its status");
});

test("a stranger's post pulled again after a reload is stored once", (t) => {
    fakeClock(t);
    const a = device(null);
    a.ChannelStore.join(CH, RFED);
    const stranger = Identity.create();
    const post = channelLxmPack(CH, stranger, "hello", DN.ABSENT, Date.now() - 1000);
    assert.equal(a.self._handleChannelPacket(post.wire), true);
    a.self._chanSeenIds = new Set();
    assert.equal(a.self._handleChannelPacket(post.wire), true, "held");
    assert.equal(a.ChannelMsgStore.get(CH).length, 1);
});

test("ChannelMsgStore keeps one post per (source, timestamp), and two posts of this device never share one", async (t) => {
    const clock = fakeClock(t);
    const a = device(null);
    a.ChannelStore.join(CH, RFED);
    const first = a.ChannelMsgStore.add(CH, { dir: "in", content: "x", status: "delivered", srcHash: "aa", timestamp: 5 });
    assert.equal(a.ChannelMsgStore.add(CH, { dir: "in", content: "x again", status: "delivered", srcHash: "aa", timestamp: 5 }).id, first.id);
    a.ChannelMsgStore.add(CH, { dir: "in", content: "y", status: "delivered", srcHash: "bb", timestamp: 5 });
    a.ChannelMsgStore.add(CH, { dir: "system", content: "You joined", status: "delivered" });
    a.ChannelMsgStore.add(CH, { dir: "system", content: "You joined", status: "delivered" });
    assert.deepEqual(a.ChannelMsgStore.get(CH).map((m) => m.content), ["x", "y", "You joined", "You joined"]);
    // Two posts in one millisecond: the second takes the next one.
    await Promise.all([a.self.sendChannelMessage(CH, "one"), a.self.sendChannelMessage(CH, "two")]);
    const ts = a.published.map((w) => channelLxmUnpack(CH, w).tsMs);
    assert.deepEqual(ts, [clock.now, clock.now + 1]);
    assert.deepEqual(a.ChannelMsgStore.get(CH).filter((m) => m.dir === "out").map((m) => [m.content, m.status]), [["one", "sent"], ["two", "sent"]]);
});

// The record's identity is the one the post is packed with (review of
// 69ff01e, 2026-10-03): ChannelMsgStore.add stamps its own Date.now() on a
// record that has none, which is another millisecond whenever the
// next-free-millisecond loop moved on or the clock did, and every other test
// here freezes the clock.

test("two posts in one millisecond, then a reload: rfed's echo of each is dropped against its record", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    await Promise.all([a.self.sendChannelMessage(CH, "one"), a.self.sendChannelMessage(CH, "two")]);
    assert.equal(a.published.length, 2);
    // The reload: memory is new, storage is not; rfed's echoes are pulled.
    a.self._chanSeenIds = new Set();
    a.self._channelPublishes = new ChannelPublishes();
    for (const wire of a.published) assert.equal(a.self._handleChannelPacket(wire), true);
    const posts = a.ChannelMsgStore.get(CH).filter((m) => m.dir !== "system");
    assert.deepEqual(posts.map((m) => [m.content, m.dir, m.status]), [["one", "out", "sent"], ["two", "out", "sent"]],
        "two bubbles, each the user's, sent");
});

test("with a clock that moves between reads, an own post's record keeps the timestamp it is packed with, and its echo after a reload is dropped", async (t) => {
    fakeClock(t, 1_790_000_000_000, { tick: true });
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    await a.self.sendChannelMessage(CH, "one");
    const [record] = a.ChannelMsgStore.get(CH).filter((m) => m.dir === "out");
    assert.deepEqual([record.srcHash, record.timestamp], [lxmfHash(distro), channelLxmUnpack(CH, a.published[0]).tsMs]);
    a.self._chanSeenIds = new Set();
    a.self._channelPublishes = new ChannelPublishes();
    assert.equal(a.self._handleChannelPacket(a.published[0]), true);
    assert.deepEqual(a.ChannelMsgStore.get(CH).filter((m) => m.dir !== "system").map((m) => [m.content, m.dir, m.status]),
        [["one", "out", "sent"]], "one bubble");
});

test("a post that fails with the exchange down takes an identity of its own, the next free millisecond, and keeps it", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.ChannelStore.join(CH, RFED);
    await a.self.sendChannelMessage(CH, "sent");
    a.self._exchangeIsDown = () => true;
    await a.self.sendChannelMessage(CH, "failed");
    a.self._exchangeIsDown = () => false;
    await a.self.sendChannelMessage(CH, "sent again");
    const D = lxmfHash(distro);
    const own = () => a.ChannelMsgStore.get(CH).filter((m) => m.dir === "out")
        .map((m) => [m.content, m.status, m.srcHash === D ? "D" : m.srcHash, m.timestamp - clock.now]);
    assert.deepEqual(own(), [["sent", "sent", "D", 0], ["failed", "failed", "D", 1], ["sent again", "sent", "D", 2]],
        "one identity each: the failed post holds the millisecond it took");
    assert.deepEqual(a.published.map((w) => channelLxmUnpack(CH, w).tsMs - clock.now), [0, 2]);
    // A reload, and rfed's echoes pulled: each lands on its own record.
    a.self._chanSeenIds = new Set();
    a.self._channelPublishes = new ChannelPublishes();
    for (const wire of a.published) assert.equal(a.self._handleChannelPacket(wire), true);
    assert.deepEqual(own(), [["sent", "sent", "D", 0], ["failed", "failed", "D", 1], ["sent again", "sent", "D", 2]],
        "nothing stored twice, and the failed post stays failed");
});

// ═════════════════════════════════════════════════════════════════════════
//  4. The Channel Display Name rule across the distro's devices
//     (DISPLAY_NAMES.md §9, "Posting as the distro": the four tests)
// ═════════════════════════════════════════════════════════════════════════

/** Devices A and B holding one distro, and reader R, all in CH. `post(d,
 *  text)` posts from d and fans it out to all three; returns the name
 *  state the post carried. */
function threeInAChannel(t, { aName, bName }) {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { label: "A", ownName: aName });
    const b = device(distro, { label: "B", ownName: bName });
    const r = device(null, { label: "R" });
    for (const d of [a, b, r]) d.ChannelStore.join(CH, RFED);
    const post = async (d, text) => {
        clock.now += 60_000;
        await d.self.sendChannelMessage(CH, text);
        const wire = d.published.at(-1);
        assert.deepEqual(deliver(wire, [a, b, r]), [true, true, true]);
        return channelLxmUnpack(CH, wire).displayName;
    };
    const readerSees = () => r.env.ChannelSenderNamesStore.get(CH, lxmfHash(distro));
    return { a, b, r, post, readerSees, clock, distro };
}

test("§4.2: a device with no name never clears its sibling's name, and the reader keeps it", async (t) => {
    const { a, b, post, readerSees } = threeInAChannel(t, { aName: "Ann", bName: null });
    const sent = [];
    for (let i = 0; i < 3; i++) {
        sent.push(["A", (await post(a, `a${i}`)).state, readerSees()]);
        sent.push(["B", (await post(b, `b${i}`)).state, readerSees()]);
    }
    assert.deepEqual(sent, [
        ["A", "name", "Ann"], ["B", "absent", "Ann"],
        ["A", "absent", "Ann"], ["B", "absent", "Ann"],
        ["A", "absent", "Ann"], ["B", "absent", "Ann"],
    ]);
});

test("§4.2: two devices with the same name include it once within 24 hours", async (t) => {
    const { a, b, post, readerSees } = threeInAChannel(t, { aName: "Ann", bName: "Ann" });
    const states = [];
    for (let i = 0; i < 3; i++) {
        states.push((await post(a, `a${i}`)).state);
        states.push((await post(b, `b${i}`)).state);
    }
    assert.deepEqual(states, ["name", "absent", "absent", "absent", "absent", "absent"]);
    assert.equal(readerSees(), "Ann");
});

test("§4.2: two devices with different names include theirs on their own triggers, not on every post", async (t) => {
    const { a, b, post, readerSees, clock } = threeInAChannel(t, { aName: "Ann", bName: "Bob" });
    const sent = [];
    for (let i = 0; i < 3; i++) {
        sent.push(["A", (await post(a, `a${i}`)).state, readerSees()]);
        sent.push(["B", (await post(b, `b${i}`)).state, readerSees()]);
    }
    assert.deepEqual(sent, [
        ["A", "name", "Ann"], ["B", "name", "Bob"],
        ["A", "absent", "Bob"], ["B", "absent", "Bob"],
        ["A", "absent", "Bob"], ["B", "absent", "Bob"],
    ], "each device's first post as D carries its name; after that neither repeats it");
    // A trigger of A's own, the 24-hour refresh, brings Ann back.
    clock.now += 24 * H;
    assert.deepEqual([(await post(a, "a day later")).state, readerSees()], ["name", "Ann"]);
});

test("§4.2: when both devices have unset their names, one clear is sent", async (t) => {
    const { a, b, post, readerSees } = threeInAChannel(t, { aName: "Ann", bName: "Ann" });
    await post(a, "a0");
    await post(b, "b0");
    a.env.OwnNames.channel = null;
    b.env.OwnNames.channel = null;
    const states = [];
    for (let i = 1; i < 4; i++) {
        states.push((await post(a, `a${i}`)).state);
        states.push((await post(b, `b${i}`)).state);
    }
    assert.deepEqual(states, ["clear", "absent", "absent", "absent", "absent", "absent"]);
    assert.equal(readerSees(), null, "the reader shows D with no channel name");
});

test("§4.2: a device that has a name never learns a sibling's clear: it keeps its record and does not repeat its name", async (t) => {
    const { a, b, post, readerSees } = threeInAChannel(t, { aName: "Ann", bName: "Ann" });
    assert.deepEqual([(await post(a, "a0")).state, (await post(b, "b0")).state], ["name", "absent"]);
    // A's name is unset: A clears it once (rule: unset after including).
    a.env.OwnNames.channel = null;
    assert.deepEqual([(await post(a, "a1")).state, readerSees()], ["clear", null]);
    // B still holds "Ann". A's clear is not what B would send (§4.2 "a clear
    // while it has one"), so B's record stays "Ann", and B's next post is
    // decided on B's own triggers alone: none has fired.
    assert.equal(b.env.ChannelPostNamesStore.included(CH, lxmfHash(b.DistroManager.identity)).lastDigest, DN.digestHex("Ann"));
    assert.deepEqual([(await post(b, "b1")).state, readerSees()], ["absent", null],
        "D's posts show no channel name until a device's own trigger includes one");
});

// DISPLAY_NAMES.md §4.2 records "the post's time". 9f058e9 recorded
// min(post's time, this device's clock) instead; the review of 9f058e9
// (2026-10-03) put the web back on the spec text, which the phones build
// from: a sibling's clock running ahead delays a name by its lead, and
// never shows readers a false one.
test("§4.2: what is learned is recorded at the post's time, as the spec says, even when the sibling's clock runs ahead", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const b = device(distro, { label: "B", ownName: "Ann" });
    b.ChannelStore.join(CH, RFED);
    const D = lxmfHash(distro);
    // B included "Ann" an hour ago.
    clock.now -= H;
    await b.self.sendChannelMessage(CH, "an hour ago");
    clock.now += H;
    assert.equal(channelLxmUnpack(CH, b.published[0]).displayName.state, "name");
    // Sibling A, its clock 10 minutes ahead, posts "Ann" now: B learns it,
    // at the post's time.
    const t0 = clock.now;
    const aheadBy = 10 * 60_000;
    const fromA = channelLxmPack(CH, distro, "from A", DN.nameState("Ann"), t0 + aheadBy);
    assert.equal(b.self._handleChannelPacket(fromA.wire), true);
    assert.deepEqual(b.env.ChannelPostNamesStore.included(CH, D), { lastDigest: DN.digestHex("Ann"), lastIncludedAt: t0 + aheadBy },
        "the post's time (DISPLAY_NAMES §4.2), not this device's clock");
    // So a reader B has never seen, posting 2 minutes later by B's clock,
    // is counted from that time: B's next post carries no name yet.
    clock.now = t0 + 2 * 60_000;
    assert.equal(b.self._handleChannelPacket(channelLxmPack(CH, Identity.create(), "hello", DN.ABSENT, clock.now).wire), true);
    clock.now = t0 + 3 * 60_000;
    await b.self.sendChannelMessage(CH, "within A's lead");
    assert.deepEqual(channelLxmUnpack(CH, b.published.at(-1)).displayName, DN.ABSENT);
    // A reader new after that time is rule 2's, as for any post.
    clock.now = t0 + aheadBy + 60_000;
    assert.equal(b.self._handleChannelPacket(channelLxmPack(CH, Identity.create(), "hi", DN.ABSENT, clock.now).wire), true);
    clock.now += 1;
    await b.self.sendChannelMessage(CH, "to the newcomer");
    assert.deepEqual(channelLxmUnpack(CH, b.published.at(-1)).displayName, DN.nameState("Ann"));

    // The unit: the post's time, whatever this device's clock reads.
    const storage = memoryStorage();
    const posts = new ChannelPostNames({ get: storage.sGet, set: storage.sSet });
    assert.equal(posts.learn(CH, D, DN.nameState("Ann"), 500, "Ann"), true);
    assert.equal(posts.included(CH, D).lastIncludedAt, 500);
    assert.equal(posts.learn(CH, D, DN.nameState("Ann"), 2_000, "Ann"), true);
    assert.equal(posts.included(CH, D).lastIncludedAt, 2_000);
    assert.doesNotMatch(methodBody("_handleChannelPacket(packetData)"), /ChannelPostNamesStore\.learn\([^)]*Date\.now\(\)/,
        "learn is not handed this device's clock");
});

test("§4.2: the rule's state is per posting identity, and what the device included before 2026-10-03 becomes the device's", (t) => {
    fakeClock(t);
    const storage = memoryStorage();
    const names = { get: storage.sGet, set: storage.sSet };
    storage.sSet("channel_post_names_v1", { [CH]: { lastDigest: DN.digestHex("Ann"), lastIncludedAt: Date.now() - 1000,
        lastNewSenderAt: 0, senders: ["ff".repeat(16)] } });
    const posts = new ChannelPostNames(names);
    assert.equal(posts.adoptLegacy("dd".repeat(16)), true);
    assert.equal(posts.adoptLegacy("dd".repeat(16)), false, "once");
    assert.equal(posts.decide(CH, "dd".repeat(16), "Ann", Date.now()).state, "absent", "the device's own state carried over");
    assert.equal(posts.decide(CH, "d1".repeat(16), "Ann", Date.now()).state, "name", "a distro starts from none: readers never had its name");
    assert.deepEqual(new ChannelPostNames(names).channels[CH].senders, ["ff".repeat(16)], "the senders seen are kept");
    assert.equal("lastDigest" in new ChannelPostNames(names).channels[CH], false);
});

test("§4.2: learning takes only a post later than the record, and only for the posting identity it came from", async (t) => {
    const clock = fakeClock(t);
    const storage = memoryStorage();
    const posts = new ChannelPostNames({ get: storage.sGet, set: storage.sSet });
    const D = "d1".repeat(16);
    posts.recordIncluded(CH, D, DN.nameState("Ann"), 100);
    assert.equal(posts.learn(CH, D, DN.CLEAR, 50, null), false, "an older post, pulled late, is not what readers last got");
    assert.equal(posts.learn(CH, D, DN.CLEAR, 100, null), false, "nor one at the same time");
    assert.equal(posts.included(CH, D).lastDigest, DN.digestHex("Ann"));
    assert.equal(posts.learn(CH, D, DN.CLEAR, 150, null), true);
    assert.deepEqual(posts.included(CH, D), { lastDigest: DN.EMPTY_DIGEST, lastIncludedAt: 150 });
    assert.equal(posts.learn(CH, D, DN.ABSENT, 200, null), false, "a post with no key 0 tells nothing");

    // In the app: this device's own post from before it held D, carrying its
    // name, says nothing about what readers had from D.
    const distro = Identity.create();
    const a = device(distro, { ownName: "Ann" });
    a.ChannelStore.join(CH, RFED);
    const old = channelLxmPack(CH, a.me, "as the device, named", DN.nameState("Ann"), Date.now() - 1000);
    assert.equal(a.self._handleChannelPacket(old.wire), true);
    clock.now += 1000;
    await a.self.sendChannelMessage(CH, "first as D");
    assert.deepEqual(channelLxmUnpack(CH, a.published[0]).displayName, DN.nameState("Ann"), "D's first post carries the name");
});

test("§4.2: the page gives the state saved before 2026-10-03 to this device once its identity is loaded", () => {
    const start = methodBody("async start()");
    const load = start.indexOf("if (!IdMgr.load())");
    const adopt = start.indexOf("ChannelPostNamesStore.adoptLegacy(ownLxmfDestinationHash());");
    assert.ok(load !== -1 && adopt > load, "after the identity is loaded");
    assert.ok(adopt < start.indexOf("ActiveTab.start("), "before anything connects or posts");
});

// ═════════════════════════════════════════════════════════════════════════
//  3. Membership sync (§17.12)
// ═════════════════════════════════════════════════════════════════════════

test("the user's join sends one C to the distro: D to D, signed by D, the marker, no title, content or name", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    await a.self.joinChannel("public.tea");
    await settle();
    assert.equal(a.uploads.length, 1, "one message per change");
    const packed = a.uploads[0];
    const D = lxmfHash(distro);
    assert.deepEqual([packed.subarray(0, 16).toString("hex"), packed.subarray(16, 32).toString("hex")], [D, D]);
    const payload = packed.subarray(96);
    const hashed = Buffer.concat([packed.subarray(0, 32), payload]);
    assert.ok(distro.validate(packed.subarray(32, 96), Buffer.concat([hashed, Cryptography.fullHash(hashed)])), "signed by D");
    const [, title, content, fields] = MsgPack.unpack(payload);
    assert.deepEqual([Buffer.from(title).length, Buffer.from(content).length], [0, 0]);
    assert.deepEqual([...fields.keys()], [0x0C, 0xFB, 0xFC, 0xFD], "no 0xD1: a message to one's own devices carries no name");
    assert.deepEqual(readChannelSync(payload), { byHex: a.hash, sync: { op: "join", name: "public.tea", atMs: clock.now }, problem: null });
    const raw = rawFields(packed);
    assert.equal(raw.get(0xFC).head.kind, "array");
    // Clients older than §17.12 take C for a delivery notification and drop it.
    assert.equal(LXMF.isDeliveryNotification(fields, ""), true);
    assert.deepEqual(a.record("public.tea"), { op: "join", at: clock.now }, "recorded for rule 5");
    assert.deepEqual(a.events.filter((e) => e.kind === "distro-channel-sync-sent").map((e) => [e.detail.op, e.detail.how]), [["join", "packet"]]);
});

// C is sent once the propagation node has it (review of 69ff01e,
// 2026-10-03; CHECK_THESE_THINGS_FIRST §14): until then the log said
// "propagated" and the Harness event fired when the packet was queued.

test("C is said sent when the propagation node proves its upload, never when the packet is queued", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel("public.tea");
    await settle();
    assert.equal(a.uploads.length, 1, "uploaded");
    const sent = () => a.events.filter((e) => e.kind === "distro-channel-sync-sent").map((e) => [e.detail.op, e.detail.how]);
    assert.deepEqual(sent(), [], "not sent while unproved");
    assert.equal(a.self._pendingPacketHashes.has(a.proofKeys[0]), true, "its proof is waited for");
    assert.equal(a.prove(), true);
    await settle();
    assert.deepEqual(sent(), [["join", "packet"]]);
    assert.deepEqual(a.logged, [], "a proof in time is no §1 violation");
    assert.equal(a.timers.length, 1);
    assert.equal(a.timers[0].cleared, true, "the §1 watch stopped at the proof");
});

test("C whose packet the exchange lost is reported lost, never said sent, not sent again on that link, and still owed: it goes once when the link next comes up", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    a.ChannelStore.join("public.tea", RFED);
    await a.self.leaveChannel("public.tea");
    await settle();
    assert.equal(a.uploads.length, 1);
    a.self._onPacketsLost({ packetHashes: [Cryptography.fullHash(a.uploads[0]).toString("hex")], reason: "the exchange failed" });
    await settle();
    assert.deepEqual(a.sentEvents(), []);
    assert.deepEqual(a.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]),
        [["distro-channel-sync", "its packet was lost (the exchange failed)"]]);
    assert.equal(a.uploads.length, 1, "no second upload of its own accord (DESIGN_PRINCIPLES §3)");
    assert.deepEqual(a.channels(), [], "the leave stands here whatever became of C");
    assert.deepEqual(a.owed(), [["channel", "leave", "public.tea", clock.now]], "still owed: the node never proved it");
    // The link coming up is the event that sends it, once, the same message.
    await a.establish();
    assert.equal(a.uploads.length, 2);
    assert.deepEqual(a.uploads[1], a.uploads[0], "the LXMF message packed when the user acted, not a new one");
    assert.equal(a.prove(), true);
    await settle();
    assert.deepEqual(a.sentEvents(), [["leave", "public.tea"]]);
    assert.deepEqual(a.owed(), [], "proved: owed no more");
});

test("a proof that comes after C was reported lost is the truth: C is owed no more and does not go again", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel("public.tea");
    await settle();
    a.self._onPacketsLost({ packetHashes: [Cryptography.fullHash(a.uploads[0]).toString("hex")], reason: "the exchange failed" });
    await settle();
    assert.equal(a.owed().length, 1);
    // The node had it after all: its proof still comes.
    assert.equal(a.prove(), true);
    await settle();
    assert.ok(a.logged.some(([level, line]) => level === "warn" && line.includes("proved after all")));
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["join", "public.tea"]], "said sent: the node has it");
    await a.establish();
    assert.equal(a.uploads.length, 1, "nothing goes again");
});

test("§1: 5 s with no proof of C is said then, and a proof after that is logged with its time; neither decides it", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel("public.tea");
    await settle();
    assert.deepEqual(a.timers.map((timer) => timer.ms), [5_001]);
    a.fireTimers();
    assert.deepEqual(a.logged.map(([level, line]) => [level, /§1 VIOLATION: the propagation node has not proved the join of #public\.tea/.test(line)]),
        [["error", true]]);
    assert.deepEqual(a.events.filter((e) => e.kind === "distro-channel-sync-sent"), [], "said, not decided");
    clock.now += 6_000;
    a.prove();
    await settle();
    assert.ok(a.logged.some(([level, line]) => level === "error" && line.includes("proved the join of #public.tea (§17.12) 6000 ms after its upload")),
        "a late success is a failure, and logged as one");
    assert.deepEqual(a.events.filter((e) => e.kind === "distro-channel-sync-sent").map((e) => e.detail.op), ["join"], "the proof decides it");
});

test("a propagation link that went down while C was built: nothing left, C stays owed, and goes once on the next link", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    let mined = 0;
    a.self._buildPropagationPacked = async (packed) => {
        if (mined++ === 0) a.closeLink();   // closed while the first stamp was mined
        return packed;
    };
    await a.self.joinChannel("public.tea");
    await settle();
    assert.deepEqual(a.self._propLinks.map((l) => [l.name, l.status, l.sent.length]), [["link1", 0x04, 0]], "never onto a closed link");
    assert.deepEqual(a.events.filter((e) => e.kind === "error"), [], "nothing left, so nothing was lost");
    assert.equal(a.owed().length, 1);
    await a.establish();
    await settle();
    assert.deepEqual(a.self._propLinks.map((l) => [l.name, l.status, l.sent.length]), [["link1", 0x04, 0], ["link2", 0x02, 1]]);
    assert.deepEqual(a.sentEvents(), [["join", "public.tea"]]);
    assert.deepEqual(a.owed(), []);
});

test("C over the link MDU goes as a Resource, sent when the Resource is proved", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    a.env.Link.MDU = 10;
    let proveResource;
    a.self._propLink.sendResource = (d) => {
        a.uploads.push(Buffer.from(d));
        return new Promise((resolve) => { proveResource = resolve; });
    };
    await a.self.joinChannel("public.tea");
    await settle();
    assert.equal(a.uploads.length, 1);
    assert.deepEqual(a.self._propLinks.map((l) => l.sent.length), [0], "no packet");
    const sent = () => a.events.filter((e) => e.kind === "distro-channel-sync-sent").map((e) => e.detail.how);
    assert.deepEqual(sent(), [], "not while the Resource moves");
    proveResource();
    await settle();
    assert.deepEqual(sent(), ["resource"]);
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.timers, [], "a Resource has no 5 s proof watch: its progress has its own (§1, bulk transfers)");
});

// ─────────────────────────────────────────────────────────────────────────
// What the distro is owed is never lost before it leaves (review of
// 9f058e9, 2026-10-03). Until then C, and the §17.11 sent-copy, waited in
// memory for the propagation link (_whenPropagationLinkUp): rejected at once
// when the propagation node's key was not known yet, rejected by
// disconnect() (a tab taken over, a settings reconnect), gone with a closed
// tab, so a sibling never learned of the join or leave. Now each is written
// to lib/distro_outbox.js when the user acts and kept until the propagation
// node proves it; the link coming up ("established", "recovered") sends
// what is owed. No timer, no retry loop.
// ─────────────────────────────────────────────────────────────────────────

/** The real disconnect() over a device's state: what a takeover by another
 *  tab, or a settings reconnect, runs. */
function disconnectOf(d) {
    Object.assign(d.self, {
        _annTimer: null, _unhookPageLifecycle() {}, _rfedReopenArmed: new Set(), _rfedLinks: new Map(), _rfedLinkPromises: new Map(),
        _rfedServiceReady: new Set(), _rfedServiceWaiters: new Map(), _groupLinks: new Map(), _groupLinkPromises: new Map(),
        _groupPeerReady: new Set(), _groupPeerWaiters: new Map(), _groupPathsRequested: new Set(), _groupFallbacks: new Map(),
        _rfedPullState: new Map(), _rns: null, _setStatus() {},
    });
    return compile("disconnect()", { clearInterval() {}, clearTimeout() {}, console: quiet })(d.self);
}

test("with no propagation link up (not yet, or the node's key not yet known), C is owed, kept in storage, and goes when the link is established", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false, proofs: "manual" });
    await a.self.joinChannel("public.tea");
    await settle();
    assert.equal(a.uploads.length, 0, "no link: nothing left, and no link was started");
    assert.deepEqual(a.owed(), [["channel", "join", "public.tea", clock.now]]);
    assert.equal(a.storage.data.has("distro_outbox_v1"), true, "in storage, not only in this page's memory");
    assert.deepEqual(a.events.filter((e) => e.kind === "error"), [], "nothing failed: it waits for its event");
    await a.establish();
    assert.equal(a.uploads.length, 1);
    assert.deepEqual(readChannelSync(a.uploads[0].subarray(96)).sync, { op: "join", name: "public.tea", atMs: clock.now });
    assert.deepEqual(a.owed(), [["channel", "join", "public.tea", clock.now]], "owed until the node proves it");
    a.prove();
    await settle();
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["join", "public.tea"]]);
});

test("a later join or leave of a channel replaces the C still owed for it: only the newest action goes", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false });
    const b = device(distro);
    b.ChannelStore.join(CH, RFED);
    await a.self.joinChannel(CH);
    clock.now += 10;
    await a.self.leaveChannel(CH);
    clock.now += 10;
    await a.self.joinChannel("public.other");
    clock.now += 10;
    await a.self.joinChannel(CH);
    await settle();
    assert.deepEqual(a.owed(), [["channel", "join", "public.other", clock.now - 10], ["channel", "join", CH, clock.now]]);
    await a.establish();
    await settle();
    assert.deepEqual(a.uploads.map((u) => readChannelSync(u.subarray(96)).sync.op + " " + readChannelSync(u.subarray(96)).sync.name),
        ["join public.other", `join ${CH}`], "one message per channel, the newest action");
    assert.deepEqual(a.owed(), []);
    fanOut(distro, a.uploads[0], [b]);
    fanOut(distro, a.uploads[1], [b]);
    await settle();
    assert.deepEqual(b.channels(), [CH, "public.other"].sort());
});

test("a C replaced while its upload is built is not sent: only the newest action for the channel goes", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    // Building an upload (its stamp) yields; these are released by hand.
    const building = [];
    a.self._buildPropagationPacked = (packed) => new Promise((resolve) => building.push(() => resolve(packed)));
    await a.self.joinChannel(CH);
    clock.now += 10;
    await a.self.leaveChannel(CH);
    assert.equal(building.length, 2, "both being built");
    building.splice(0).forEach((release) => release());
    await settle();
    assert.deepEqual(a.uploads.map((u) => readChannelSync(u.subarray(96)).sync.op), ["leave"], "the join was replaced before it left");
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["leave", CH]]);
});

test("an earlier C's proof leaves the later action for the same channel owed", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel(CH);
    clock.now += 10;
    await a.self.leaveChannel(CH);
    await settle();
    assert.equal(a.uploads.length, 2, "each goes at once on the link that is up");
    assert.equal(a.prove(a.proofKeys[0]), true, "the join is proved");
    await settle();
    assert.deepEqual(a.owed(), [["channel", "leave", CH, clock.now]], "the leave is still owed");
    assert.equal(a.prove(a.proofKeys[1]), true);
    await settle();
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["join", CH], ["leave", CH]]);
});

test("the link coming up again sends nothing twice: what is already uploading on it is left to its proof", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel(CH);
    await settle();
    assert.equal(a.uploads.length, 1);
    // The same link heard from the node again ("recovered") before the proof.
    await a.self._sendDistroOutbox(a.self._propLink, "recovered");
    assert.equal(a.uploads.length, 1, "uploading already");
    a.prove();
    await settle();
    assert.deepEqual(a.owed(), []);
});

test("a flush whose link goes down leaves the rest owed and unbuilt, for the next link", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false });
    await a.self.joinChannel(CH);
    await a.self.joinChannel("public.other");
    let built = 0;
    a.self._buildPropagationPacked = async (packed) => {
        if (built++ === 0) a.closeLink();   // the link goes while the first is built
        return packed;
    };
    await a.establish();
    await settle();
    assert.deepEqual([built, a.uploads.length, a.owed().length], [1, 0, 2], "the second is not even built (no stamp mined for nothing)");
    await a.establish();
    await settle();
    assert.deepEqual([built, a.uploads.length, a.owed().length], [3, 2, 0]);
});

test("an upload built for a link that is no longer the propagation link does not go on it, whatever its status says", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    const old = a.self._propLink;
    let release;
    a.self._buildPropagationPacked = (packed) => new Promise((resolve) => { release = () => resolve(packed); });
    await a.self.joinChannel(CH);
    // disconnect() let go of it (a close that threw leaves it ACTIVE).
    a.self._propLink = null;
    release();
    await settle();
    assert.equal(old.status, 0x02);
    assert.deepEqual([a.uploads.length, a.owed().length], [0, 1]);
});

test("storage that cannot keep what is owed (a full localStorage) is said, and C still goes on the link that is up", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const real = memoryStorage();
    // app.js sSet drops a write localStorage refuses without a word.
    const full = { data: real.data, sGet: real.sGet, sSet: (k, v) => { if (k !== "distro_outbox_v1") real.sSet(k, v); } };
    const a = device(distro, { storage: full });
    await a.self.joinChannel(CH);
    await settle();
    assert.deepEqual(a.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]),
        [["distro-channel-sync", `the join of #${CH} (§17.12) could not be kept in storage`]]);
    assert.ok(a.logged.some(([level, line]) => level === "error" && line.includes("could not be kept in storage")));
    assert.equal(a.uploads.length, 1, "it still goes: this page holds it");
    await settle();
    assert.deepEqual(a.sentEvents(), [["join", CH]]);
});

/** What each upload of `d` carried: "op name" for a C, "sent-copy" for a
 *  §17.11 copy. */
const carried = (d) => d.uploads.map((u) => {
    const sync = readChannelSync(Buffer.from(u).subarray(96))?.sync;
    return sync ? `${sync.op} ${sync.name}` : "sent-copy";
});

/** Each build `d` makes (each mines a stamp), by what it carries, the first
 *  held until `release()`. */
function holdFirstBuild(d) {
    const built = [];
    let release = null;
    d.self._buildPropagationPacked = (packed) => {
        const sync = readChannelSync(Buffer.from(packed).subarray(96))?.sync;
        built.push(sync ? `${sync.op} ${sync.name}` : "sent-copy");
        if (built.length > 1) return Promise.resolve(packed);
        return new Promise((resolve) => { release = () => resolve(packed); });
    };
    return { built, release: () => release() };
}

/** Storage that refuses a write of the outbox larger than what it holds, as
 *  a full localStorage does (app.js sSet drops it without a word), once
 *  `full.on` is set. A smaller write (an entry dropped) is taken. */
function fullStorage() {
    const real = memoryStorage();
    const full = {
        on: false, data: real.data, sGet: real.sGet,
        sSet: (k, v) => {
            if (full.on && k === "distro_outbox_v1" && JSON.stringify(v).length > (real.data.get(k)?.length ?? 0)) return;
            real.sSet(k, v);
        },
    };
    return full;
}

test("storage that refuses the C replacing one owed: the user's newer action goes while the page is open, the one it replaced never goes, and a later page sends neither", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const storage = fullStorage();
    const a = device(distro, { storage, linkUp: false });
    const b = device(distro);
    await a.self.joinChannel(CH);
    storage.on = true;                    // localStorage is full now
    clock.now += 10;
    await a.self.leaveChannel(CH);
    await settle();
    assert.deepEqual(a.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]),
        [["distro-channel-sync", `the leave of #${CH} (§17.12) could not be kept in storage`]]);
    assert.deepEqual(a.owed(), [["channel", "leave", CH, clock.now]], "this page holds the leave; the join it replaced is owed no more");
    assert.deepEqual(device(distro, { me: a.me, storage, linkUp: false }).owed(), [],
        "a page loaded now (the tab closed) sends neither: storage was written without the join");
    await a.establish();
    await settle();
    // Review of 73a725d: the join stayed owed under the channel's id and
    // went, after the user had left.
    assert.deepEqual(carried(a), [`leave ${CH}`]);
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["leave", CH]]);
    for (const upload of a.uploads) fanOut(distro, upload, [b]);
    await settle();
    assert.deepEqual([a.channels(), b.channels()], [[], []], "the sibling never joins a channel the user left");
});

test("storage that refuses the C replacing one owed, with the link up: it goes at once, and the earlier C's proof does not bring that one back", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const storage = fullStorage();
    const a = device(distro, { storage, proofs: "manual" });
    await a.self.joinChannel(CH);
    await settle();
    storage.on = true;
    clock.now += 10;
    await a.self.leaveChannel(CH);
    await settle();
    // Review of 73a725d: the join still stored under the channel's id was
    // taken for a later action, and the leave was never sent.
    assert.deepEqual(carried(a), [`join ${CH}`, `leave ${CH}`]);
    assert.equal(a.prove(a.proofKeys[0]), true, "the join is proved");
    await settle();
    assert.deepEqual(a.owed(), [["channel", "leave", CH, clock.now]]);
    assert.equal(a.prove(a.proofKeys[1]), true);
    await settle();
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["join", CH], ["leave", CH]]);
});

test("what a flush listed is checked again before it is built: a C replaced and proved meanwhile is neither built nor sent", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false });
    const R = "0123456789abcdef0123456789abcdef";
    await a.self._sendDistroSentCopy(R, "", "sent while the link was down");
    clock.now += 10;
    await a.self.joinChannel(CH);
    const hold = holdFirstBuild(a);
    const flush = a.establish();          // lists [the sent-copy, the join]; the sent-copy's stamp is mined
    await settle();
    clock.now += 10;
    await a.self.leaveChannel(CH);        // the link is up: the leave goes at once, and is proved
    await settle();
    assert.deepEqual(carried(a), [`leave ${CH}`]);
    hold.release();
    await flush;
    await settle();
    // Review of 73a725d: the join was mined and went last, after the leave,
    // and the Harness said the join was sent last.
    assert.deepEqual(carried(a), [`leave ${CH}`, "sent-copy"]);
    assert.deepEqual(hold.built, ["sent-copy", `leave ${CH}`], "no stamp mined for the join");
    assert.deepEqual(a.sentEvents(), [["leave", CH]]);
    assert.deepEqual(a.owed(), []);
});

test("two flushes on one link (established, then recovered while the first is still built): what the second proved, the first neither builds nor sends again", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false, proofs: "manual" });
    await a.self.joinChannel(CH);
    await a.self.joinChannel("public.other");
    const hold = holdFirstBuild(a);
    const flush = a.establish();          // lists [CH, public.other]; CH's stamp is mined
    await settle();
    // The same link, STALE and heard from again: CH is in flight on it, so
    // only public.other goes, and is proved.
    await a.self._sendDistroOutbox(a.self._propLink, "recovered");
    assert.deepEqual(carried(a), ["join public.other"]);
    assert.equal(a.prove(), true);
    await settle();
    hold.release();
    await flush;
    await settle();
    // Review of 73a725d: public.other was mined and went a second time.
    assert.deepEqual(carried(a), ["join public.other", `join ${CH}`]);
    assert.deepEqual(hold.built, [`join ${CH}`, "join public.other"]);
    assert.equal(a.prove(), true);
    await settle();
    assert.deepEqual(a.owed(), []);
});

test("a C proved while it is built again (the node had the upload whose loss was reported) is not sent again", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel(CH);
    await settle();
    a.self._onPacketsLost({ packetHashes: [Cryptography.fullHash(a.uploads[0]).toString("hex")], reason: "the exchange failed" });
    await settle();
    const hold = holdFirstBuild(a);
    const flush = a.self._sendDistroOutbox(a.self._propLink, "recovered");
    await settle();
    assert.deepEqual(hold.built, [`join ${CH}`], "still owed, so built again");
    assert.equal(a.prove(a.proofKeys[0]), true, "the node had the first upload after all");
    await settle();
    assert.deepEqual(a.owed(), []);
    hold.release();
    await flush;
    await settle();
    // Review of 73a725d: nothing owed under its id was taken for a write
    // storage had refused, and it went again.
    assert.equal(a.uploads.length, 1);
    assert.deepEqual(a.sentEvents(), [["join", CH]]);
});

test("a distro given up while a flush builds: nothing owed to it is sent, nor built with the new distro's key", async (t) => {
    fakeClock(t);
    const d1 = Identity.create();
    const d2 = Identity.create();
    const a = device(d1, { linkUp: false });
    await a.self.joinChannel(CH);
    await a.self.joinChannel("public.other");
    const hold = holdFirstBuild(a);
    const flush = a.establish();          // lists both, owed to D1; CH's stamp is mined
    await settle();
    a.hold(d2);                           // the user imports another distro meanwhile
    hold.release();
    await flush;
    await settle();
    assert.equal(a.uploads.length, 0, "nothing owed to D1 went once D2 was held");
    assert.deepEqual(hold.built, [`join ${CH}`], "and public.other was never built for D2's key");
    await a.establish();                  // the next flush drops them, saying so
    assert.deepEqual([a.uploads.length, a.owed().length], [0, 0]);
});

test("a newer C made while the link is STALE mines nothing then, and goes on 'recovered' although the older C for the channel is still in flight on that link", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    let built = 0;
    a.self._buildPropagationPacked = async (packed) => { built++; return packed; };
    await a.self.joinChannel(CH);
    await settle();
    const link = a.self._propLink;
    link.status = 0x03;                   // STALE
    clock.now += 10;
    await a.self.leaveChannel(CH);
    await settle();
    assert.deepEqual([built, a.uploads.length], [1, 1], "nothing built or sent on a STALE link");
    link.status = 0x02;                   // the node is heard again: "recovered"
    await a.self._sendDistroOutbox(link, "recovered");
    await settle();
    assert.deepEqual(carried(a), [`join ${CH}`, `leave ${CH}`], "the join's upload on this link holds back only the join");
    a.prove(a.proofKeys[0]);
    a.prove(a.proofKeys[1]);
    await settle();
    assert.deepEqual(a.owed(), []);
});

test("an upload whose link went STALE while it was built goes when that link recovers", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    const link = a.self._propLink;
    const hold = holdFirstBuild(a);
    await a.self.joinChannel(CH);
    link.status = 0x03;                   // STALE while the stamp is mined
    hold.release();
    await settle();
    assert.equal(a.uploads.length, 0, "nothing onto a STALE link");
    assert.deepEqual(a.events.filter((e) => e.kind === "error"), [], "nothing left, so nothing was lost");
    link.status = 0x02;
    await a.self._sendDistroOutbox(link, "recovered");
    await settle();
    assert.deepEqual(carried(a), [`join ${CH}`]);
});

test("an upload whose build failed is said, stays owed, and goes when the link next comes up, a recovery included", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    const link = a.self._propLink;
    const build = a.self._buildPropagationPacked;
    a.self._buildPropagationPacked = async () => { throw new Error("the stamp could not be made"); };
    await a.self.joinChannel(CH);
    await settle();
    assert.deepEqual(a.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]),
        [["distro-channel-sync", "the stamp could not be made"]]);
    assert.equal(a.owed().length, 1);
    a.self._buildPropagationPacked = build;
    await a.self._sendDistroOutbox(link, "recovered");
    await settle();
    assert.deepEqual(carried(a), [`join ${CH}`]);
});

test("a flush whose link goes STALE while one is built mines nothing more; the rest go when it recovers", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false });
    await a.self.joinChannel(CH);
    await a.self.joinChannel("public.other");
    let built = 0;
    a.self._buildPropagationPacked = async (packed) => {
        if (built++ === 0) a.self._propLink.status = 0x03;    // STALE, still the propagation link
        return packed;
    };
    const link = await a.establish();
    await settle();
    assert.deepEqual([built, a.uploads.length, a.owed().length], [1, 0, 2], "no stamp mined for a link that is not up");
    link.status = 0x02;
    await a.self._sendDistroOutbox(link, "recovered");
    await settle();
    assert.deepEqual([built, a.uploads.length, a.owed().length], [3, 2, 0]);
});

test("the tab closes before the link comes up: the next page sends the C still owed, once", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false });
    a.ChannelStore.join(CH, RFED);
    await a.self.leaveChannel(CH);
    await settle();
    assert.equal(a.uploads.length, 0);
    const owed = a.owed();
    assert.deepEqual(owed, [["channel", "leave", CH, clock.now]]);
    // Reloaded: the same identity and storage, a new page.
    const again = device(distro, { me: a.me, storage: a.storage, linkUp: false });
    assert.deepEqual(again.owed(), owed);
    await again.establish();
    await settle();
    assert.equal(again.uploads.length, 1);
    assert.deepEqual(readChannelSync(again.uploads[0].subarray(96)), { byHex: a.hash, sync: { op: "leave", name: CH, atMs: clock.now }, problem: null });
    assert.deepEqual(again.owed(), []);
});

test("disconnect() decides every upload still waiting for its proof, with no §1 line and a Harness error for each; what they carried stays owed and the next connection sends it", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel(CH);
    await a.self._sendDistroSentCopy("0123456789abcdef0123456789abcdef", "", "sent as the distro");
    await settle();
    assert.equal(a.uploads.length, 2, "both left");
    assert.equal(a.self._pendingPacketHashes.size, 2);
    disconnectOf(a)();
    await settle();
    // Review of 9f058e9: the proofs' entries were dropped and the uploads
    // left open, so the §1 watch said, 5 s on, that the proof or the
    // exchange would decide them, though neither could, and nothing ever
    // said they had ended.
    a.fireTimers();
    assert.deepEqual(a.logged.filter(([level]) => level === "error"), [], "no §1 line: nobody waits for those proofs now");
    assert.deepEqual(a.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]), [
        ["distro-channel-sync", "the connection stopped before the propagation node proved it"],
        ["distro-sent-copy", "the connection stopped before the propagation node proved it"],
    ]);
    assert.deepEqual(a.sentEvents(), []);
    assert.equal(a.self._distroOutboxInFlight.size, 0);
    assert.deepEqual(a.owed(), [["channel", "join", CH, Date.now()], ["sent", "0123456789abcdef0123456789abcdef"]]);
    // The next connection: its propagation link comes up.
    await a.establish();
    await settle();
    assert.equal(a.uploads.length, 4);
    assert.deepEqual(a.uploads.slice(2), a.uploads.slice(0, 2), "the same two messages");
    for (const key of a.proofKeys.slice(2)) a.prove(key);
    await settle();
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["join", CH]]);
    assert.deepEqual(a.events.filter((e) => e.kind === "distro-sent-copy").map((e) => e.detail.how), ["packet"]);
});

test("a C that went twice (the first upload's proof was cut) is one message to a sibling: the second is held as a repeat", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    const b = device(distro);
    await a.self.joinChannel(CH);
    await settle();
    a.closeLink();                           // the node had it; its proof never came back
    await a.establish();
    await settle();
    assert.equal(a.uploads.length, 2);
    assert.deepEqual(fanOut(distro, a.uploads[0], [b]), [true]);
    assert.deepEqual(fanOut(distro, a.uploads[1], [b]), [true]);
    await settle();
    assert.deepEqual(b.syncEvents(), ["joined"], "applied once");
    assert.equal(b.events.filter((e) => e.kind === "distro-dup").length, 1, "the second is a repeat of the first");
});

test("a sent-copy that went twice is shown once on a sibling", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    const b = device(distro);
    const stored = [];
    b.env.MsgStore = { add: (peer, record) => { stored.push([peer, record.content]); return record; }, get: () => [] };
    const R = "0123456789abcdef0123456789abcdef";
    await a.self._sendDistroSentCopy(R, "", "hello from the phone");
    await settle();
    a.closeLink();
    await a.establish();
    await settle();
    assert.equal(a.uploads.length, 2);
    fanOut(distro, a.uploads[0], [b]);
    fanOut(distro, a.uploads[1], [b]);
    assert.deepEqual(stored, [[R, "hello from the phone"]], "one bubble, not two");
});

test("the propagation link closing before the proof decides the upload lost, with no §1 line; C goes once on the next link", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    a.ChannelStore.join(CH, RFED);
    await a.self.leaveChannel(CH);
    await settle();
    a.closeLink();
    await settle();
    a.fireTimers();
    assert.deepEqual(a.logged.filter(([level]) => level === "error"), []);
    assert.deepEqual(a.events.filter((e) => e.kind === "error").map((e) => e.detail.message),
        ["the propagation link closed before the propagation node proved it"]);
    assert.equal(a.owed().length, 1);
    await a.establish();
    a.prove();
    await settle();
    assert.equal(a.uploads.length, 2);
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.sentEvents(), [["leave", CH]]);
});

test("what is owed to a distro this device no longer holds is dropped, saying so, and never sent to the one it holds now", async (t) => {
    fakeClock(t);
    const d1 = Identity.create();
    const d2 = Identity.create();
    const a = device(d1, { linkUp: false });
    await a.self.joinChannel(CH);
    a.hold(d2);
    await a.self.joinChannel("public.other");
    await a.establish();
    a.prove();
    await settle();
    assert.equal(a.uploads.length, 1, "only the C made for D2");
    assert.equal(a.uploads[0].subarray(0, 16).toString("hex"), lxmfHash(d2));
    assert.deepEqual(a.owed(), []);
    assert.ok(a.logged.some(([level, line]) => level === "warn" && line.includes(`owed to ${lxmfHash(d1).slice(0, 8)}, a distro this device no longer holds`)));
    // With no distro held at all, nothing goes, and what was owed is
    // dropped, saying so. Review of a448e98: it was kept, and went if D was
    // imported again.
    const b = device(d1, { linkUp: false });
    await b.self.joinChannel(CH);
    b.hold(null);
    await b.establish();
    assert.deepEqual([b.uploads.length, b.owed().length], [0, 0]);
    assert.ok(b.logged.some(([level, line]) => level === "warn" && line.includes(`the join of #${CH} (§17.12) was owed to ${lxmfHash(d1).slice(0, 8)}`)));
    b.hold(d1);
    await b.establish();
    assert.equal(b.uploads.length, 0, "D held again: nothing goes");
});

/** The Harness errors `d` raised, [where, message]. */
const errorsOf = (d) => d.events.filter((e) => e.kind === "error").map((e) => [e.detail.where, e.detail.message]);

/** `d` gives up its distro or takes `identity` instead: DistroManager's
 *  change, then its onChange listener, as the page registers it (pinned
 *  below and in distro_channels_page.test.mjs). */
function changeDistro(d, identity) {
    d.hold(identity);
    d.self._dropOwedToOtherDistros();
}

test("the page drops what is owed to a distro it gives up on every change of the distro held, and once at load", () => {
    // DistroManager.onChange runs its listener at once and on every
    // generate, import and forget (lib/distro.js _notify).
    assert.match(app, /\nDistroManager\.onChange\(\(\) => RnsClient\._dropOwedToOtherDistros\(\)\);\n/);
    assert.ok(app.indexOf("\nDistroManager.onChange(") > app.indexOf("\nconst RnsClient = {"), "after RnsClient is defined");
    assert.match(methodBody("async _sendDistroOutbox(link, trigger)"), /^\s*try \{[^]*?this\._dropOwedToOtherDistros\(\);\s*const owed = DistroOutboxStore\.list\(\);/,
        "and before each flush lists what is owed");
});

test("RFed SPEC §17.12: a join owed with the link down, D given up (said), D imported again and the link up: nothing goes, and the sibling never joins a channel the user left", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false });
    const b = device(distro);
    await a.self.joinChannel(CH);
    assert.equal(a.owed().length, 1);
    changeDistro(a, null);
    assert.deepEqual(a.owed(), [], "dropped when D was given up");
    assert.deepEqual(a.logged, [["warn", `[distro] ⚠️ the join of #${CH} (§17.12) was owed to ${lxmfHash(distro).slice(0, 8)}, a distro this device no longer holds — dropped, never sent (§17.12)`]]);
    assert.equal(device(distro, { me: a.me, storage: a.storage, linkUp: false }).owed().length, 0, "not in storage either");
    clock.now += 60_000;
    await a.self.leaveChannel(CH);           // with no distro: recorded, no C
    changeDistro(a, distro);                 // D imported again
    await a.establish();
    await settle();
    // Review of a448e98: the join was kept while no distro was held and
    // went now; the sibling joined a channel this device had left.
    assert.equal(a.uploads.length, 0);
    for (const upload of a.uploads) fanOut(distro, upload, [b]);
    assert.deepEqual([a.channels(), b.channels()], [[], []]);
});

test("D replaced by another distro and then taken again with no link up in between: what was owed to D is dropped at the first change and never sent", async (t) => {
    fakeClock(t);
    const d1 = Identity.create();
    const d2 = Identity.create();
    const a = device(d1, { linkUp: false });
    await a.self.joinChannel(CH);
    await a.self._sendDistroSentCopy("0123456789abcdef0123456789abcdef", "", "sent as D1");
    changeDistro(a, d2);
    assert.deepEqual(a.owed(), []);
    assert.equal(a.logged.filter(([level, line]) => level === "warn" && line.includes("a distro this device no longer holds — dropped")).length, 2,
        "one line for each, the sent-copy too");
    changeDistro(a, d1);
    await a.establish();
    assert.equal(a.uploads.length, 0, "nothing for D1, nor for D2");
});

/**
 * `d`'s propagation link lifecycle run by the shipped
 * _establishPropagationLink, over links the test drives: `attempt()` makes
 * one as the page does (it replaces a STALE one), PENDING until `up(link)`
 * delivers its "established" (whose handler sends what is owed, as
 * _onPropagationLinkEstablished does); `close(link)` delivers its "close".
 */
function shippedLinks(d) {
    class TestLink {
        static PENDING = 0x00;
        static ACTIVE = 0x02;
        static STALE = 0x03;
        static CLOSED = 0x04;
        constructor() {
            Object.assign(this, d.makeLink(`link${d.self._propLinks.length + 1}`));
            this.status = TestLink.PENDING;
            this.listeners = new Map();
            d.self._propLinks.push(this);
        }
        on(event, fn) { this.listeners.set(event, [...(this.listeners.get(event) ?? []), fn]); }
        emit(event) { for (const fn of this.listeners.get(event) ?? []) fn(); }
        establish() {}
    }
    Object.assign(d.self, {
        _cfg: { ...d.self._cfg, propagationNodePubKey: Identity.create().getPublicKey().toString("hex"), propagationNodeHash: "b".repeat(32) },
        _rns: { registerDestination: () => ({}) },
        _propLinkPromise: null,
        _onPropagationLinkEstablished: (link) => d.self._sendDistroOutbox(link, "established"),
        _onPropagationLinkClosed() {},
    });
    const establishLink = compile("_establishPropagationLink()", { Identity, Buffer, Destination, Link: TestLink, console: quiet })(d.self);
    return {
        attempt: () => { establishLink(); return d.self._propLink; },
        up: async (link) => { link.status = TestLink.ACTIVE; link.emit("established"); await settle(); },
        close: async (link) => { link.status = TestLink.CLOSED; link.emit("close"); await settle(); },
    };
}

test("a STALE propagation link replaced by a new one decides the upload still waiting on it: C goes again on the new link only once that one is decided, and one sibling applies it once", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false, proofs: "manual" });
    const b = device(distro);
    const links = shippedLinks(a);
    const first = links.attempt();
    await links.up(first);
    await a.self.joinChannel(CH);
    await settle();
    assert.deepEqual(first.sent.length, 1, "uploaded on the link that is up");
    // Its proof's entry (the two uploads are one packing here, so the
    // second's would take its key).
    const firstProof = a.self._pendingPacketHashes.get(a.proofKeys[0]);
    first.status = 0x03;                  // STALE: nothing heard for staleTime
    const second = links.attempt();       // a DM's propagation (_ensurePropagationLink) replaces it
    assert.notEqual(second, first);
    await settle();
    // Review of a448e98 (PROBE S1): the upload on the replaced link stayed
    // open, and the new link's "established" uploaded the join again while
    // it was: two uploads of one C at once.
    assert.deepEqual(errorsOf(a), [["distro-channel-sync", "the propagation link it went on was replaced before the propagation node proved it"]]);
    assert.ok(a.logged.some(([level, line]) => level === "warn" && line.includes("still owed: it goes when the propagation link is next up")));
    assert.equal(a.owed().length, 1, "not proved, so still owed");
    await links.up(second);
    assert.deepEqual([first.sent.length, second.sent.length], [1, 1], "uploaded again on the new link (DESIGN_PRINCIPLES §3, the distro exception)");
    assert.equal(a.prove(a.proofKeys[1]), true);
    await settle();
    assert.deepEqual(a.owed(), []);
    // The old link's watchdog tears it down: there is nothing left on it to
    // decide, and nothing more is said.
    await links.close(first);
    assert.equal(errorsOf(a).length, 1);
    // The node had the first upload after all: its proof comes late, over
    // the old link.
    firstProof.onProof(firstProof.messageId);
    await settle();
    assert.deepEqual([a.uploads.length, a.owed().length], [2, 0]);
    assert.deepEqual(a.sentEvents(), [["join", CH], ["join", CH]], "each proof said, the late one too");
    for (const upload of a.uploads) fanOut(distro, upload, [b]);
    await settle();
    assert.deepEqual(b.syncEvents(), ["joined"], "applied once");
});

test("an upload cut after a later action replaced its C, or after its distro was given up, is not said to be owed and raises no error", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { proofs: "manual" });
    await a.self.joinChannel(CH);
    await settle();
    clock.now += 10;
    await a.self.leaveChannel(CH);        // replaces the join, which is in flight
    await settle();
    assert.deepEqual(carried(a), [`join ${CH}`, `leave ${CH}`]);
    a.closeLink();
    await settle();
    // Review of a448e98 (PROBE S2): the join's cut said "still owed: it
    // goes when the propagation link is next up" and raised the error too,
    // though nothing was owed for it.
    assert.deepEqual(errorsOf(a), [["distro-channel-sync", "the propagation link closed before the propagation node proved it"]], "the leave's alone");
    const stillOwed = a.logged.filter(([, line]) => line.includes("still owed"));
    assert.equal(stillOwed.length, 1);
    assert.match(stillOwed[0][1], /the leave of/);
    await a.establish();
    assert.deepEqual(carried(a), [`join ${CH}`, `leave ${CH}`, `leave ${CH}`]);

    // The distro given up while C's upload waits for its proof.
    const c = device(distro, { proofs: "manual" });
    await c.self.joinChannel(CH);
    await settle();
    changeDistro(c, null);
    c.closeLink();
    await settle();
    assert.deepEqual(errorsOf(c), []);
    assert.equal(c.logged.filter(([, line]) => line.includes("still owed")).length, 0);
});

test("the §17.11 sent-copy is owed the same way: made with no link up, it goes when the link comes up and is owed until proved", async (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { linkUp: false, proofs: "manual" });
    const R = "0123456789abcdef0123456789abcdef";
    await a.self._sendDistroSentCopy(R, "", "while the link was down");
    assert.deepEqual(a.owed(), [["sent", R]]);
    assert.equal(a.uploads.length, 0);
    await a.establish();
    assert.equal(a.uploads.length, 1);
    const [, , content, fields] = MsgPack.unpack(a.uploads[0].subarray(96));
    assert.deepEqual([Buffer.from(content).toString(), fields.get(0xFB), fields.get(0xFC), fields.get(0xFD)],
        ["while the link was down", LXMF.DISTRO_SENT_TYPE, R, a.hash]);
    a.prove();
    await settle();
    assert.deepEqual(a.owed(), []);
    assert.deepEqual(a.events.filter((e) => e.kind === "distro-sent-copy").map((e) => e.detail), [{ to: R.slice(0, 12), how: "packet" }]);
});

test("a sibling applies C with its own key; the sender's echo changes nothing; nothing is sent back", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { label: "A" });
    const b = device(distro, { label: "B" });
    const c = device(distro, { label: "C", resubscribed: false });
    await a.self.joinChannel("public.tea");
    await settle();
    assert.deepEqual(fanOut(distro, a.uploads[0], [a, b, c]), [true, true, true]);
    await settle();
    assert.deepEqual([a.channels(), b.channels(), c.channels()], [["public.tea"], ["public.tea"], ["public.tea"]]);
    assert.deepEqual(a.syncEvents(), ["echo"]);
    assert.deepEqual(b.syncEvents(), ["joined"]);
    const subscribe = b.requests.find(([path]) => path === "/rfed/subscribe");
    assert.equal(Buffer.from(subscribe[1][1]).toString("hex"), b.me.getPublicKey().toString("hex"), "B subscribes with its own key");
    assert.deepEqual(c.requests, [], "C, whose stored channels are not yet subscribed, leaves it to that subscription (no retry)");
    assert.deepEqual([b.uploads.length, c.uploads.length], [0, 0], "applying sends nothing: nothing loops");
    assert.deepEqual(b.ChannelMsgStore.get("public.tea"), [], "no notice, no alert: the channel simply appears");
    assert.deepEqual(b.record("public.tea"), { op: "join", at: clock.now });
    // The same C again (live, then pulled): held.
    assert.deepEqual(fanOut(distro, a.uploads[0], [b]), [true]);
    assert.ok(b.events.some((e) => e.kind === "distro-dup"));

    // The leave, made on B: A and C leave, their posts and names go.
    clock.now += 1000;
    a.ChannelMsgStore.add("public.tea", { dir: "in", content: "kept until the leave", status: "delivered", srcHash: "ee", timestamp: 1 });
    await b.self.leaveChannel("public.tea");
    await settle();
    assert.equal(b.uploads.length, 1);
    assert.deepEqual(fanOut(distro, b.uploads[0], [a, b, c]), [true, true, true]);
    await settle();
    assert.deepEqual([a.channels(), b.channels(), c.channels()], [[], [], []]);
    assert.deepEqual(a.ChannelMsgStore.get("public.tea"), []);
    assert.ok(a.requests.some(([path, p]) => path === "/rfed/unsubscribe" && Buffer.from(p[1]).equals(a.me.getPublicKey())));
    assert.deepEqual(a.ui.filter((e) => e.kind === "channel-left").map((e) => e.synced), [true], "the open chat is told it is a sibling's");
    assert.deepEqual([a.uploads.length, c.uploads.length], [1, 0]);
});

test("no C for a join of a channel already listed, nor from a device that holds no distro (whose action is still recorded)", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    await a.self.joinChannel("public.tea");
    await a.self.joinChannel("public.tea");
    await settle();
    assert.equal(a.uploads.length, 1);
    const lone = device(null);
    await lone.self.joinChannel("public.tea");
    clock.now += 5;
    await lone.self.leaveChannel("public.tea");
    await settle();
    assert.equal(lone.uploads.length, 0);
    assert.deepEqual(lone.record("public.tea"), { op: "leave", at: clock.now });
    // Only the user's own join and leave send one.
    for (const sig of ["async joinChannel(channelName)", "async leaveChannel(channelName)"]) {
        assert.equal((methodBody(sig).match(/_syncChannelMembership\(/g) || []).length, 1, sig);
    }
    for (const sig of ["_applyDistroChannelSync(change, byHex)", "_leaveChannelHere(ch, synced = false)", "async _initChannels()",
        "_handleDistroChannelSync(marker, facts)", "async openChannel(channelName)"]) {
        assert.doesNotMatch(methodBody(sig), /_syncChannelMembership|_sendDistroChannelSync/, sig);
    }
});

test("rules 1-3: a C from another source, or claiming D without D's signature, is dropped; this device's own is an echo", (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const b = device(distro);
    const stranger = Identity.create();
    const fields = () => channelSyncFields("join", "public.bait", Date.now(), "cc".repeat(16));
    assert.deepEqual(fanOut(distro, craftC(distro, { fields: fields(), source: stranger }), [b]), [false], "rule 1");
    assert.deepEqual(fanOut(distro, craftC(distro, { fields: fields(), source: distro, signer: stranger }), [b]), [false], "rule 2");
    assert.deepEqual(b.channels(), [], "a stranger cannot make the user's devices join a channel");
    assert.deepEqual(b.events.filter((e) => e.kind === "distro-channel-sync").map((e) => e.detail.rule), [1, 2]);
    const echo = craftC(distro, { fields: channelSyncFields("join", "public.bait", Date.now() + 1, b.hash) });
    assert.deepEqual(fanOut(distro, echo, [b]), [true], "rule 3: held, recorded as seen");
    assert.deepEqual(b.channels(), []);
    assert.equal(b.record("public.bait"), null);
});

test("rule 4: an unusable C is dropped, and C is never taken for a message", (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const b = device(distro);
    const typed = (data) => new Map([[0x0C, Buffer.alloc(0)], [0xFB, DISTRO_CHANNEL_TYPE], [0xFC, data], [0xFD, "cc".repeat(16)]]);
    let ts = Date.now();
    for (const data of [Buffer.from(MsgPack.pack(["join", "public.x", 1])), ["join", "public.x", Date.now()], ["part", "public.x", 1n],
        ["join", "public.X", 1n], ["join", "Test", 1n]]) {
        assert.deepEqual(fanOut(distro, craftC(distro, { fields: typed(data), timestampMs: ++ts }), [b]), [false], JSON.stringify(String(data)));
    }
    assert.deepEqual(b.channels(), []);
    assert.deepEqual(b.events.filter((e) => e.kind === "distro-channel-sync").map((e) => e.detail.rule), [4, 4, 4, 4, 4]);
});

test("a dropped C is not kept as seen: a second copy is judged again and dropped again, never answered as held", (t) => {
    fakeClock(t);
    const distro = Identity.create();
    const b = device(distro);
    const fields = new Map([[0x0C, Buffer.alloc(0)], [0xFB, DISTRO_CHANNEL_TYPE], [0xFC, ["join", "Test", 1n]], [0xFD, "cc".repeat(16)]]);
    const packed = craftC(distro, { fields });
    // The same blob, live and then pulled: rfed is told "not held" both times.
    assert.deepEqual(fanOut(distro, packed, [b]), [false]);
    assert.deepEqual(fanOut(distro, packed, [b]), [false]);
    assert.deepEqual(b.syncEvents(), ["dropped", "dropped"]);
    assert.equal(b.events.some((e) => e.kind === "distro-dup"), false);
});

test("rule 4: a leave of a channel joined before the name rules is applied; a join of that name is dropped", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    const b = device(distro);
    for (const d of [a, b]) d.ChannelStore.join("public.Test", RFED);
    clock.now += 1000;
    await a.self.leaveChannel("public.Test");
    await settle();
    assert.deepEqual(fanOut(distro, a.uploads[0], [b]), [true]);
    assert.deepEqual(b.channels(), [], "left on every device");
    clock.now += 1000;
    await a.self.joinChannel("public.Test");
    await settle();
    assert.deepEqual(fanOut(distro, a.uploads[1], [b]), [false], "today's join refuses the name");
    assert.deepEqual(b.channels(), []);
});

test("rule 5: a device that took a sibling's leave, its clock 10 minutes behind, joins after it, and every device ends joined", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { label: "A" });
    const b = device(distro, { label: "B" });
    const c = device(distro, { label: "C" });
    for (const d of [a, b, c]) d.ChannelStore.join(CH, RFED);
    await a.self.leaveChannel(CH);              // A's clock: 12:00
    await settle();
    fanOut(distro, a.uploads[0], [a, b, c]);
    await settle();
    assert.deepEqual([a.channels(), b.channels(), c.channels()], [[], [], []]);
    const aLeftAt = clock.now;
    clock.now = aLeftAt - 9 * 60_000;            // B's clock, 10 minutes slow, a minute later
    await b.self.joinChannel(CH);
    await settle();
    assert.equal(readChannelSync(b.uploads[0].subarray(96)).sync.atMs, aLeftAt + 1, "stamped after the leave it holds");
    fanOut(distro, b.uploads[0], [a, b, c]);
    await settle();
    assert.deepEqual([a.channels(), b.channels(), c.channels()], [[CH], [CH], [CH]], "the later action wins everywhere");
});

test("rule 5: a join and a leave at one time leave every device left, in either order", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { label: "A" });
    const b = device(distro, { label: "B" });
    const c = device(distro, { label: "C" });
    const d = device(distro, { label: "D" });
    for (const x of [b, c, d]) x.ChannelStore.join(CH, RFED);
    const T = clock.now;
    await a.self.joinChannel(CH);               // A joins at T
    await b.self.leaveChannel(CH);              // B leaves at T, before either has the other's
    await settle();
    assert.deepEqual([readChannelSync(a.uploads[0].subarray(96)).sync.atMs, readChannelSync(b.uploads[0].subarray(96)).sync.atMs], [T, T]);
    const join = a.uploads[0], leave = b.uploads[0];
    // Their LXMF timestamps are one and the same too: two messages still.
    for (const x of [a, b]) fanOut(distro, join, [x]), fanOut(distro, leave, [x]);
    fanOut(distro, join, [c]); fanOut(distro, leave, [c]);
    fanOut(distro, leave, [d]); fanOut(distro, join, [d]);
    await settle();
    assert.deepEqual([a, b, c, d].map((x) => x.channels()), [[], [], [], []]);
    assert.deepEqual([a, b, c, d].map((x) => x.record(CH)), [a, b, c, d].map(() => ({ op: "leave", at: T })));
});

test("rule 5: concurrent actions end in one state everywhere, the one with the larger time (12:00 leave, 12:05 join stamped 11:55)", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { label: "A" });
    const b = device(distro, { label: "B" });
    const c = device(distro, { label: "C" });
    for (const x of [a, c]) x.ChannelStore.join(CH, RFED);
    const noon = clock.now;
    await a.self.leaveChannel(CH);              // A: 12:00
    clock.now = noon - 5 * 60_000;              // B, ten minutes slow, at 12:05
    await b.self.joinChannel(CH);
    await settle();
    fanOut(distro, b.uploads[0], [a, b, c]);
    fanOut(distro, a.uploads[0], [a, b, c]);
    await settle();
    assert.deepEqual([a, b, c].map((x) => x.channels()), [[], [], []], "every device ends left: the larger time");
    // The other order of arrival, on a fourth device that held it.
    const d = device(distro, { label: "D" });
    d.ChannelStore.join(CH, RFED);
    fanOut(distro, a.uploads[0], [d]);
    fanOut(distro, b.uploads[0], [d]);
    await settle();
    assert.deepEqual(d.channels(), []);
});

test("rule 6: a join of a listed channel and a leave of one not listed change nothing but the record", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    const b = device(distro);
    b.ChannelStore.join(CH, RFED);
    await a.self.joinChannel(CH);
    await settle();
    clock.now += 1;
    // A leave of a channel B never held (A held it under a name B never saw).
    const leave = craftC(distro, { fields: channelSyncFields("leave", "public.never-here", Date.now(), a.hash) });
    const before = b.requests.length;
    fanOut(distro, a.uploads[0], [b]);
    fanOut(distro, leave, [b]);
    await settle();
    assert.deepEqual(b.channels(), [CH]);
    assert.equal(b.requests.length, before, "no subscription and no unsubscription");
    assert.deepEqual(b.syncEvents(), ["recorded", "recorded"]);
    assert.deepEqual(b.record("public.never-here"), { op: "leave", at: clock.now });
});

test("a leave, then a join of the same channel in one connection: unsubscribed first, then subscribed again", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro);
    const b = device(distro, { holdUnsubscribe: true });
    for (const x of [a, b]) x.ChannelStore.join(CH, RFED);
    await b.self._ensureChannelSubscribed(b.ChannelStore.get(CH));
    await a.self.leaveChannel(CH);
    clock.now += 1000;
    await a.self.joinChannel(CH);
    await settle();
    fanOut(distro, a.uploads[0], [b]);
    fanOut(distro, a.uploads[1], [b]);
    await settle();
    assert.deepEqual(b.channels(), [CH], "listed again at once");
    assert.deepEqual(b.requests.map(([path]) => path), ["/rfed/subscribe", "/rfed/unsubscribe"],
        "the new subscription waits for the leave's unsubscribe, still unanswered");
    b.release();
    await settle();
    await settle();
    assert.deepEqual(b.requests.map(([path]) => path), ["/rfed/subscribe", "/rfed/unsubscribe", "/rfed/subscribe"],
        "then subscribes again: the leave forgot the old subscription");
    assert.equal(b.self._rfedUnsubscribes.size, 0);
});

test("the user's own leave and join of one channel in one connection also subscribes again", async (t) => {
    fakeClock(t);
    const a = device(null);
    await a.self.joinChannel(CH);
    await settle();
    await a.self.leaveChannel(CH);
    await a.self.joinChannel(CH);
    await settle();
    assert.deepEqual(a.requests.map(([path]) => path), ["/rfed/subscribe", "/rfed/unsubscribe", "/rfed/subscribe"]);
});

// A sibling's leave runs this device's own leave clean-up (§17.12 rule 6:
// "remove … its posts and its names"), _leaveChannelHere. The review of
// 9f058e9 found three of its parts pinned by no test: forgetting the
// channel's sender names, forgetting this device's own-name state (§4.2),
// and dropping the channel's stream memo.

test("a sibling's leave forgets the channel's sender names and this device's own-name state: after a re-join the name goes again", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const D = lxmfHash(distro);
    const a = device(distro, { label: "A" });
    const b = device(distro, { label: "B", ownName: "Ann" });
    for (const d of [a, b]) d.ChannelStore.join(CH, RFED);
    await b.self.sendChannelMessage(CH, "first, with the name");
    assert.deepEqual(channelLxmUnpack(CH, b.published[0]).displayName, DN.nameState("Ann"));
    const sam = Identity.create();
    const samHash = lxmfHash(sam);
    clock.now += 1000;
    assert.equal(b.self._handleChannelPacket(channelLxmPack(CH, sam, "hi", DN.nameState("Sam"), clock.now).wire), true);
    assert.equal(b.env.ChannelSenderNamesStore.get(CH, samHash), "Sam");
    assert.equal(b.env.ChannelPostNamesStore.included(CH, D)?.lastDigest, DN.digestHex("Ann"));

    clock.now += 1000;
    await a.self.leaveChannel(CH);
    fanOut(distro, a.uploads[0], [b]);
    await settle();
    assert.deepEqual(b.channels(), []);
    assert.equal(b.env.ChannelSenderNamesStore.get(CH, samHash), null, "the channel's sender names go with it");
    assert.equal(b.env.ChannelSenderNamesStore.entry(CH, samHash), null);
    assert.equal(b.env.ChannelPostNamesStore.included(CH, D), null, "and what B included in it");

    // Joined again, by A: B's first post carries the name, as a first post
    // in a channel does (§4.2 rule 1); readers who came after the leave
    // have never had it.
    clock.now += 1000;
    await a.self.joinChannel(CH);
    fanOut(distro, a.uploads[1], [b]);
    await settle();
    assert.deepEqual(b.channels(), [CH]);
    clock.now += 1000;
    await b.self.sendChannelMessage(CH, "back again");
    assert.deepEqual(channelLxmUnpack(CH, b.published.at(-1)).displayName, DN.nameState("Ann"));
});

test("a sibling's leave drops the channel's stream memo: joined again and opened in the same connection, the stream is set up with it again", async (t) => {
    const clock = fakeClock(t);
    const distro = Identity.create();
    const a = device(distro, { label: "A" });
    const b = device(distro, { label: "B" });
    for (const d of [a, b]) d.ChannelStore.join(CH, RFED);
    const key = channelIdentity(CH).hash.toString("hex");
    // The real stream set-up: /rfed/channel/stream/open with the filter set.
    Object.assign(b.self, { _channelsInitialized: true, _rfedLinks: new Map([["channel.stream", {}]]) });
    install(b.self, b.env, ["async _configureChannelStream()", "_ensureChannelStreamConfigured(channel)"]);
    const streams = [];
    const rfed = b.self._rfedRequest;
    b.self._rfedRequest = async (aspects, path, payload) => {
        if (path !== "/rfed/channel/stream/open") return rfed(aspects, path, payload);
        streams.push(MsgPack.unpack(Buffer.from(MsgPack.unpack(payload)[0])).map((h) => Buffer.from(h).toString("hex")));
        return [true];
    };
    await b.self._ensureChannelStreamConfigured(b.ChannelStore.get(CH));   // B opens it
    assert.deepEqual(streams, [[key]]);

    clock.now += 1000;
    await a.self.leaveChannel(CH);
    fanOut(distro, a.uploads[0], [b]);
    await settle();
    assert.deepEqual(streams, [[key], []], "the stream is set up without it");
    assert.equal(b.self._rfedStreamPromises.has(key), false, "and its memo is gone");

    clock.now += 1000;
    await a.self.joinChannel(CH);
    fanOut(distro, a.uploads[1], [b]);
    await settle();
    await b.self._ensureChannelStreamConfigured(b.ChannelStore.get(CH));   // B opens it again
    assert.deepEqual(streams, [[key], [], [key]], "set up with it again, not answered from the old memo");
});
