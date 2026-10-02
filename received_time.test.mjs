/**
 * A RECEIVED MESSAGE CARRIES THE TIME ITS SENDER SENT IT — review of
 * 505d0ed: the web stored every incoming record at Date.now(), the time it
 * arrived, so a DM or distro message sent on Monday and pulled on Wednesday,
 * or channel history pulled late, sat under "Today" with Wednesday's time,
 * where iOS and Android show it under Monday (they store the LXMF or post
 * timestamp: iOS ChatRepository.swift handleIncomingMessage,
 * handleDistroMessage, handleGroupChatMessage, RfedChannelClient.swift
 * `timestamp: Double(tsMs)`; Android ChatRepository.kt
 * `timestamp = (timestamp * 1000).toLong()`, RfedChannelClient.kt
 * `timestamp = result.timestampMs`). The date marker, the bubble's time and
 * the sidebar's order all read the record's `timestamp`.
 *
 * These run the real shipped code: connect()'s router message handler,
 * _handleGroupMessage, _handleChannelPacket and _handleDistroBlob cut out of
 * app.js (test_app_source.mjs), over the real MsgStore, GroupMsgStore,
 * ChannelMsgStore and ContactStore, with real LXMF packing and encryption,
 * and lib/day_markers.js for real. The chat list follows: a conversation is
 * placed and dated by its latest message (lastMessageTime), so one pulled
 * late does not pull it down, as iOS keeps the larger time.
 *
 * Run: node --test received_time.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Cryptography from "./lib/rns/cryptography.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, { GROUP_FIELDS } from "./lib/rns/lxmf/lxmf.js";
import { channelLxmPack, channelLxmUnpack } from "./lib/rns/rfed_channel.js";
import * as DN from "./lib/display_name.js";
import { ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";
import { ChannelPublishes } from "./lib/channel_publish.js";
import { dayMarkers, lastMessageTime, sentTimeMs } from "./lib/day_markers.js";
import { build, compile, constValue, memoryStorage, messageHandler } from "./test_app_source.mjs";

const quiet = { log() {}, warn() {}, error() {} };
const Harness = { recordInbound() {}, event() {}, error() {} };
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const DAY_MS = 86_400_000;

/** Sent two days and a few hours before now, in Unix seconds with a fraction. */
const twoDaysAgo = () => (Date.now() - 2 * DAY_MS - 3 * 3_600_000) / 1000 + 0.25;

/** The full packing (destination | source | signature | payload) of a message
 *  `from` sends at `seconds`. */
function lxm(from, toHash, content, fields, seconds) {
    const m = new LXMessage();
    m.timestamp = seconds;
    m.sourceHash = Buffer.from(lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(toHash, "hex");
    m.title = "";
    m.content = content;
    m.fields = fields;
    return m.pack(from, false);
}

/** What a page keeps: the real stores over memory. */
function page() {
    const storage = memoryStorage();
    const ContactStore = build("ContactStore", {
        sGet: storage.sGet, sSet: storage.sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    return {
        storage, ContactStore,
        MsgStore: build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date }),
        GroupMsgStore: build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date }),
        ChannelMsgStore: build("ChannelMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date }),
    };
}

/** The marker the record would get as the only message in its list, now. */
const markerOf = (record) => dayMarkers([record.timestamp], {
    now: Date.now(), timeZone: "UTC", locale: "en-US",
})[0];

test("sentTimeMs: the LXMF timestamp in ms; a message with no usable time keeps the time it arrived", () => {
    assert.equal(sentTimeMs(1_790_000_000.25, 5), 1_790_000_000_250);
    assert.equal(sentTimeMs(1_790_000_000.0004, 5), 1_790_000_000_000, "rounded to the ms");
    assert.equal(sentTimeMs(4_102_444_800, 5), 4_102_444_800_000, "a sender's clock ahead is shown as it is");
    for (const none of [undefined, null, NaN, Infinity, -Infinity, 0, -1, "1790000000", true]) {
        assert.equal(sentTimeMs(none, 5), 5, `${String(none)}: arrival time, never 1970 or NaN`);
    }
    const before = Date.now();
    const arrived = sentTimeMs(undefined);
    assert.ok(arrived >= before && arrived <= Date.now(), "now, when no arrival time is given");
});

test("a direct (or propagated) message pulled two days late is stored, and marked, at the time it was sent", () => {
    const me = Identity.create(), alice = Identity.create();
    const p = page();
    const self = { _onMsg: [], _pendingTickets: new Map(), _handleGroupMessage() {}, _handleDistroIdentityTransfer() {} };
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness, console: quiet,
        RnsClient: { ownHash: lxmfHash(me) }, LXMF, LXMessage, ContactStore: p.ContactStore, MsgStore: p.MsgStore,
        decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self);
    const sent = twoDaysAgo();
    const packed = lxm(alice, lxmfHash(me), "sent on Monday", new Map(), sent);
    handle(LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16)));
    const [rec] = p.MsgStore.get(lxmfHash(alice));
    assert.equal(rec.content, "sent on Monday");
    assert.equal(rec.timestamp, Math.round(sent * 1000), "the sender's time, not the arrival time");
    assert.notEqual(markerOf(rec), "Today");
    assert.notEqual(markerOf(rec), "Yesterday");
});

test("a group message is stored at the time its sender sent it", () => {
    const me = Identity.create(), bob = Identity.create();
    const p = page();
    const G = "9".repeat(32);
    const groups = new Map([[G, { groupId: G, groupName: "G", members: new Map(), lastActivity: 0 }]]);
    const self = { _onMsg: [] };
    const handleGroup = compile("_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)", {
        GroupStore: { getAll: () => [...groups.values()], get: (id) => groups.get(id) ?? null, memberStatus: () => undefined,
            isClosed: () => false, heldChanges: () => [], _save() {} },
        GroupMsgStore: p.GroupMsgStore, ContactStore: p.ContactStore, console: quiet, Date, Buffer, LXMF, sentTimeMs,
        ownLxmfDestinationHash: () => lxmfHash(me),
        // The group rule is not what this tests: it lets the plain post
        // through, and the post is its source's own (privacy_filter.test.mjs
        // pins the rule and GROUP_SENDER).
        PrivacyFilter: { groupAccepts: () => true, groupMember: (group, src) => src },
    })(self);
    const sent = twoDaysAgo();
    const packed = lxm(bob, lxmfHash(me), "to the group", new Map([[GROUP_FIELDS.GROUP_ID, G]]), sent);
    const m = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16));
    handleGroup(m, lxmfHash(bob), "to the group", LXMessage.extractGroupFields(m.fields));
    const [rec] = p.GroupMsgStore.get(G);
    assert.equal(rec.content, "to the group");
    assert.equal(rec.timestamp, Math.round(sent * 1000));
    assert.notEqual(markerOf(rec), "Today");
});

test("a channel post pulled late is stored at the time its poster sent it", () => {
    const me = Identity.create(), carol = Identity.create();
    const p = page();
    const CHANNEL = "public.times";
    const names = { get: p.storage.sGet, set: p.storage.sSet };
    const handlePost = compile("_handleChannelPacket(packetData)", {
        Buffer, DistroManager: { has: false }, Harness, console: quiet, channelLxmUnpack, ContactStore: p.ContactStore,
        ChannelStore: { getByHash: () => ({ channelName: CHANNEL }), touch() {} },
        ChannelMsgStore: p.ChannelMsgStore, ownLxmfDestinationHash: () => lxmfHash(me), sentTimeMs,
        ChannelSenderNamesStore: new ChannelSenderNames(names), ChannelPostNamesStore: new ChannelPostNames(names),
    })({ _channelPublishes: new ChannelPublishes(), _onMsg: [] });
    // channelLxmPack stamps a post with the clock: the poster's, two days ago.
    const realNow = Date.now;
    const postedAt = Math.round(twoDaysAgo() * 1000);
    Date.now = () => postedAt;
    let post;
    try { post = channelLxmPack(CHANNEL, carol, "history", DN.ABSENT); } finally { Date.now = realNow; }
    assert.equal(post.tsMs, postedAt, "(fixture) the post is stamped two days ago");
    assert.equal(handlePost(post.wire), true);
    const [rec] = p.ChannelMsgStore.get(CHANNEL);
    assert.equal(rec.content, "history");
    assert.equal(rec.timestamp, postedAt, "the post's time, not the pull's");
    assert.notEqual(markerOf(rec), "Today");
});

test("a message pulled from the distro late, and a sibling's sent-copy, keep the time they were sent", () => {
    const device = Identity.create(), distro = Identity.create(), dave = Identity.create();
    const p = page();
    const D = lxmfHash(distro);
    const handleBlob = compile("_handleDistroBlob(distroHash, blob)", {
        DistroManager: { identity: distro, lxmfDeliveryHash: D },
        MsgPack, Buffer, DistroSeen: build("DistroSeen", { sGet: p.storage.sGet, sSet: p.storage.sSet }), Harness,
        ContactStore: p.ContactStore, MsgStore: p.MsgStore, LXMF, Cryptography, LXMessage,
        decodeDisplayName: DN.decodePayload, ownLxmfDestinationHash: () => lxmfHash(device), console: quiet,
        DISTRO_ATTACHMENT_PLACEHOLDER: constValue("DISTRO_ATTACHMENT_PLACEHOLDER"), sentTimeMs,
    })({ ownHash: lxmfHash(device), _pendingTickets: new Map(), _onMsg: [] });
    const blob = (packed) => Buffer.concat([Buffer.from(D, "hex"), distro.encrypt(packed.subarray(16))]);

    const sent = twoDaysAgo();
    assert.equal(handleBlob(null, blob(lxm(dave, D, "via the distro", new Map(), sent))), true);
    const [rec] = p.MsgStore.get(lxmfHash(dave));
    assert.equal(rec.dir, "in");
    assert.equal(rec.timestamp, Math.round(sent * 1000));
    assert.notEqual(markerOf(rec), "Today");

    const R = "0123456789abcdef0123456789abcdef";
    const marker = new Map([[0xFB, "rfed.distro.sent"], [0xFC, R], [0xFD, "fedcba9876543210fedcba9876543210"]]);
    const copySent = sent + 60;
    assert.equal(handleBlob(null, blob(lxm(distro, D, "from my phone", marker, copySent))), true);
    const [copy] = p.MsgStore.get(R);
    assert.equal(copy.dir, "out");
    assert.equal(copy.timestamp, Math.round(copySent * 1000), "a sent-copy too, by the same rule");
});

// ── the chat list ───────────────────────────────────────────────────────────

test("lastMessageTime: the latest record's time, not the last stored; the fallback with none", () => {
    assert.equal(lastMessageTime([], 7), 7);
    assert.equal(lastMessageTime([{ timestamp: 30 }, { timestamp: 50 }, { timestamp: 10 }], 7), 50,
        "a message pulled late (10, stored last) does not date the conversation back");
    assert.equal(lastMessageTime([{ timestamp: 30 }, { timestamp: undefined }, { timestamp: NaN }], 7), 30);
    assert.equal(lastMessageTime([{}, { timestamp: null }], 7), 7, "no usable time at all: the fallback");
});

test("the chat list orders and dates a conversation by its latest message, so a late arrival does not sink it", () => {
    const now = Date.now();
    const A = "a".repeat(32), B = "b".repeat(32), G = "9".repeat(32), C = "news";
    const records = {
        [A]: [{ id: "a1", dir: "in", timestamp: now - 3_600_000, content: "an hour ago" }],
        // B's newest message, then one sent two days ago that arrived after it.
        [B]: [{ id: "b1", dir: "in", timestamp: now - 600_000, content: "ten minutes ago" },
              { id: "b2", dir: "in", timestamp: now - 2 * DAY_MS, content: "pulled late" }],
        [G]: [{ id: "g1", dir: "in", timestamp: now - 300_000 }, { id: "g2", dir: "in", timestamp: now - 3 * DAY_MS }],
        [C]: [{ id: "c1", dir: "in", timestamp: now - 1_200_000 }, { id: "c2", dir: "in", timestamp: now - 4 * DAY_MS }],
    };
    const h = (tag, attrs, ...kids) => ({ tag, attrs: attrs ?? {}, kids: kids.flat().filter((k) => k != null) });
    const frag = { kids: [], appendChild(c) { this.kids.push(c); return c; } };
    const env = {
        h, document: { createDocumentFragment: () => frag }, navigator: {}, PrivacyFilter: { on: false },
        DistroManager: {}, RnsClient: { ownHash: "e".repeat(32) }, ownLxmfDestinationHash: () => "e".repeat(32),
        ContactStore: { chats: () => [{ destHash: A, lastSeen: 1 }, { destHash: B, lastSeen: 1 }], name: (x) => x.slice(0, 1) },
        GroupStore: { getAll: () => [{ groupId: G, groupName: "G", lastActivity: 1 }] },
        ChannelStore: { getAll: () => [{ channelName: C, lastActivity: 1 }] },
        MsgStore: { get: (x) => records[x], preview: (x) => records[x].at(-1).content },
        GroupMsgStore: { get: (x) => records[x], preview: () => "" }, ChannelMsgStore: { get: (x) => records[x], preview: () => "" },
        systemMessageText: () => "", lastMessageTime,
    };
    const self = {
        state: { searchQuery: "" }, _buildContactItem: (c) => c.destHash,
        _buildGroupItem: (g) => g.groupId, _buildChannelItem: (ch) => ch.channelName,
    };
    const sidebar = compile("_buildSidebarContent()", env)(self)();
    const list = sidebar.kids.find((k) => k.attrs.className === "contact-list");
    assert.deepEqual(list.kids, [G, B, C, A],
        "by each one's latest message (5, 10, 20 and 60 minutes ago), whatever arrived last");

    const shown = [];
    const item = compile("_buildContactItem(c)", {
        h, ContactStore: env.ContactStore, MsgStore: env.MsgStore, avatarHue: () => 0, lastMessageTime,
        fmtDate: (ts) => { shown.push(ts); return String(ts); },
    })({ state: {}, openChat() {} });
    item({ destHash: B, publicKey: "k" });
    assert.deepEqual(shown, [now - 600_000], "and its time is the latest message's, not the late one's");
});
