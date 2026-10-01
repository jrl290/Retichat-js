/**
 * CONVERSATION ORDER — a DM, group or channel lists its messages by
 * timestamp, equal timestamps in arrival order, as iOS
 * (SortDescriptor(\.timestamp)) and Android (MessageDao / ChannelDao
 * ORDER BY timestamp ASC) do. Received records carry their sender's time
 * since 8e2481c, so a message pulled late goes in among the messages of its
 * time, under its own day's date marker, not at the bottom where it arrived.
 *
 *   - lib/message_order.js addInOrder, the one rule the three stores use;
 *   - the real MsgStore, GroupMsgStore and ChannelMsgStore (app.js);
 *   - connect()'s router message handler storing a DM pulled late;
 *   - _syncOpenChatMessages and _holdView (app.js) over a fake DOM with a
 *     layout: a late row goes in at its place under its own date marker, the
 *     reader's view stays put (at the bottom it stays at the bottom), only a
 *     row new at the bottom asks to be followed down, and a channel's rows go
 *     in under its "Load earlier messages" control, which leads the list.
 *
 * Run: node --test message_order.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import * as DN from "./lib/display_name.js";
import { addInOrder } from "./lib/message_order.js";
import { dayMarkers, sentTimeMs } from "./lib/day_markers.js";
import { build, fn, install, memoryStorage, messageHandler, methodBody } from "./test_app_source.mjs";

const quiet = { log() {}, warn() {}, error() {} };
const Harness = { recordInbound() {}, event() {}, error() {} };
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const HOUR = 3_600_000;
const NOON = Date.UTC(2026, 8, 30, 12);          // Wednesday 2026-09-30 12:00 UTC
const CTX = { now: NOON, timeZone: "UTC", locale: "en-US" };
const ids = (records) => records.map((r) => r.id);

// ── the rule ────────────────────────────────────────────────────────────────

test("addInOrder: by timestamp, equal timestamps in the order they came, a late one among those of its time", () => {
    const r = [];
    for (const [id, timestamp] of [["b", 20], ["d", 40], ["a", 10], ["c", 30], ["c2", 30], ["e", 50], ["a2", 10]]) {
        assert.deepEqual(addInOrder(r, { id, timestamp }), [], "nothing dropped without a limit");
    }
    assert.deepEqual(ids(r), ["a", "a2", "b", "c", "c2", "d", "e"]);

    // No usable time: where it arrived, and never passed over.
    addInOrder(r, { id: "x" });
    addInOrder(r, { id: "y", timestamp: NaN });
    addInOrder(r, { id: "z", timestamp: 35 });
    assert.deepEqual(ids(r), ["a", "a2", "b", "c", "c2", "d", "e", "x", "y", "z"],
        "z stops at y: a record with no time is never passed over");
});

test("addInOrder: a limit drops the oldest, never the record being added", () => {
    const r = [{ id: "a", timestamp: 10 }, { id: "b", timestamp: 20 }, { id: "c", timestamp: 30 }];
    assert.deepEqual(ids(addInOrder(r, { id: "d", timestamp: 40 }, 3)), ["a"]);
    assert.deepEqual(ids(r), ["b", "c", "d"]);
    assert.deepEqual(ids(addInOrder(r, { id: "bb", timestamp: 25 }, 3)), ["b"]);
    assert.deepEqual(ids(r), ["bb", "c", "d"]);
    // Older than every record held: it is kept, at the top, and the next-oldest go.
    assert.deepEqual(ids(addInOrder(r, { id: "old", timestamp: 1 }, 3)), ["bb"]);
    assert.deepEqual(ids(r), ["old", "c", "d"]);
    const many = [1, 2, 3, 4].map((t) => ({ id: `m${t}`, timestamp: t * 10 }));
    assert.deepEqual(ids(addInOrder(many, { id: "first", timestamp: 0 }, 2)), ["m1", "m2", "m3"]);
    assert.deepEqual(ids(many), ["first", "m4"]);
});

// ── the stores ──────────────────────────────────────────────────────────────

function stores() {
    const storage = memoryStorage();
    return {
        storage,
        MsgStore: build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date }),
        GroupMsgStore: build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date }),
        ChannelMsgStore: build("ChannelMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date }),
    };
}

test("MsgStore, GroupMsgStore and ChannelMsgStore keep conversation order; add returns the record it stored", () => {
    const s = stores();
    for (const [store, key] of [[s.MsgStore, "peer"], [s.GroupMsgStore, "group"], [s.ChannelMsgStore, "chan"]]) {
        store.add(key, { dir: "in", content: "Monday", timestamp: NOON - 48 * HOUR });
        store.add(key, { dir: "out", content: "today", timestamp: NOON });
        const late = store.add(key, { dir: "in", content: "Tuesday, pulled late", timestamp: NOON - 24 * HOUR });
        store.add(key, { dir: "in", content: "today too", timestamp: NOON });
        assert.deepEqual(store.get(key).map((m) => m.content), ["Monday", "Tuesday, pulled late", "today", "today too"], key);
        assert.equal(late.content, "Tuesday, pulled late", `${key}: add returns the late record, not the last one`);
        assert.equal(store.get(key)[1].id, late.id);
        if (store.preview) assert.match(store.preview(key, () => ""), /today too/, `${key}: the preview is the latest`);
    }
});

test("the 500 cap drops the oldest by time, and their attachments with them (onDiscard)", () => {
    const s = stores();
    const discarded = [];
    s.MsgStore.onDiscard = (records) => discarded.push(...records.map((m) => m.content));
    for (let i = 0; i < 500; i++) s.MsgStore.add("p", { dir: "in", content: `m${i}`, timestamp: NOON + i * 1000 });
    s.MsgStore.add("p", { dir: "in", content: "late", timestamp: NOON - HOUR });
    assert.deepEqual(discarded, ["m0"], "the oldest other than the one added");
    const kept = s.MsgStore.get("p");
    assert.equal(kept.length, 500);
    assert.deepEqual(kept.slice(0, 2).map((m) => m.content), ["late", "m1"]);
    s.MsgStore.add("p", { dir: "in", content: "new", timestamp: NOON + 600_000 });
    assert.deepEqual(discarded, ["m0", "late"], "then the late one is the oldest");
});

test("a DM pulled late (router handler) is stored at its sent time, among the messages of its time", () => {
    const me = Identity.create(), alice = Identity.create();
    const storage = memoryStorage();
    const ContactStore = build("ContactStore", {
        sGet: storage.sGet, sSet: storage.sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });
    const self = { _onMsg: [], _pendingTickets: new Map(), _handleGroupMessage() {}, _handleDistroIdentityTransfer() {} };
    const handle = messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness, console: quiet,
        RnsClient: { ownHash: lxmfHash(me) }, LXMF, LXMessage, ContactStore, MsgStore,
        decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self);
    const deliver = (content, seconds) => {
        const m = new LXMessage();
        m.timestamp = seconds;
        m.sourceHash = Buffer.from(lxmfHash(alice), "hex");
        m.destinationHash = Buffer.from(lxmfHash(me), "hex");
        m.title = "";
        m.content = content;
        m.fields = new Map();
        const packed = m.pack(alice, false);
        handle(LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16)));
    };
    const now = Date.now() / 1000;
    deliver("an hour ago", now - 3600);
    deliver("just now", now);
    deliver("two days ago, pulled late", now - 2 * 86400);
    deliver("ten minutes ago, pulled late", now - 600);
    assert.deepEqual(MsgStore.get(lxmfHash(alice)).map((m) => m.content),
        ["two days ago, pulled late", "an hour ago", "ten minutes ago, pulled late", "just now"]);
});

// ── the open chat: a fake DOM with a layout ─────────────────────────────────

const LIST_TOP = 100;
/** Heights: a row 40 (+20 under a date marker), the load control 30 (0 when hidden), the empty notice 50. */
class El {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parent = null;
        this.attrs = {};
        this.listeners = {};
        this.style = {};
        this.className = "";
        this._scrollTop = 0;
        this.clientHeight = 0;
        const self = this;
        this.classList = {
            contains: (c) => self.className.split(" ").includes(c),
            add: (c) => { if (!self.classList.contains(c)) self.className = `${self.className} ${c}`.trim(); },
            remove: (c) => { self.className = self.className.split(" ").filter((x) => x && x !== c).join(" "); },
        };
    }
    appendChild(c) { if (c && typeof c === "object") c.parent = this; this.children.push(c); return c; }
    insertBefore(c, ref) {
        c.parent = this;
        const i = ref ? this.children.indexOf(ref) : -1;
        if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
        return c;
    }
    after(c) { const list = this.parent.children; c.parent = this.parent; list.splice(list.indexOf(this) + 1, 0, c); }
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    get id() { return this.attrs.id ?? ""; }
    get firstChild() { return this.children[0] ?? null; }
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
    set textContent(v) { this.children = [{ textContent: String(v) }]; }
    querySelectorAll(selector) {
        assert.equal(selector, "[data-msg-id]");
        return this.children.filter((c) => c instanceof El && "data-msg-id" in c.attrs);
    }
    querySelector(selector) {
        assert.equal(selector, ".empty-chat");
        return this.children.find((c) => c instanceof El && c.classList.contains("empty-chat")) ?? null;
    }
    // layout
    get height() {
        if (this.classList.contains("hidden")) return 0;
        if ("data-msg-id" in this.attrs) return 40 + (this.classList.contains("has-day-marker") ? 20 : 0);
        if (this.classList.contains("load-more")) return 30;
        if (this.classList.contains("empty-chat")) return 50;
        return 0;
    }
    get scrollHeight() { return this.children.reduce((sum, c) => sum + (c.height ?? 0), 0); }
    get scrollTop() { return this._scrollTop; }
    set scrollTop(v) { this._scrollTop = Math.max(0, Math.min(v, this.scrollHeight - this.clientHeight)); }
    getBoundingClientRect() {
        if (!this.parent || !(this.parent instanceof El) || this.parent.tagName === "BODY") {
            return { top: LIST_TOP, bottom: LIST_TOP + this.clientHeight };
        }
        const list = this.parent;
        let offset = 0;
        for (const c of list.children) { if (c === this) break; offset += c.height ?? 0; }
        const top = LIST_TOP + offset - list.scrollTop;
        return { top, bottom: top + this.height };
    }
}
const document0 = { createElement: (tag) => new El(tag), createTextNode: (text) => ({ textContent: text }) };
const h = fn("h", "tag, a={}, ...kids", { document: document0 });
const row = (m) => h("div", { className: "msg-row their", "data-msg-id": m.id }, h("div", { className: "msg-bubble" }, m.content ?? ""));
const rowIds = (list) => list.querySelectorAll("[data-msg-id]").map((r) => r.getAttribute("data-msg-id"));
const markerOf = (r) => (r.firstChild?.className === "day-marker" ? r.firstChild.textContent : null);
const rowById = (list, id) => list.querySelectorAll("[data-msg-id]").find((r) => r.getAttribute("data-msg-id") === id);

/** The open chat `kind` ("dm" | "channel") over `records`, its list built as the views build it. */
function openChat(records, { kind = "dm", clientHeight = 200, loadMore = null } = {}) {
    const stores = { list: null };
    const self = { state: { view: "main", activeHash: kind === "channel" ? "news" : "d".repeat(32) } };
    install(self, {
        h, document: { ...document0, getElementById: (id) => (id === "msg-list" ? stores.list : null) },
        dayMarkers, deviceDayContext: () => ({ ...CTX }),
        GroupStore: { isGroupChat: () => false },
        ChannelStore: { get: (id) => (kind === "channel" && id === "news" ? { channelName: "news" } : null) },
        MsgStore: { get: () => records }, GroupMsgStore: { get: () => [] }, ChannelMsgStore: { get: () => records },
        channelSenderLabel: () => null,
    }, ["_syncOpenChatMessages()", "_holdView(list, rows)", "_applyDayMarkers(list, records)", "_setDayMarker(row, label)"]);
    self._buildMsgBubble = (m) => row(m);
    self._buildSystemMsg = (m) => row(m);
    const kids = records.length ? records.map(row) : [h("div", { className: "empty-chat" })];
    if (loadMore) kids.unshift(loadMore);
    stores.list = self._applyDayMarkers(h("div", { className: "message-list", id: "msg-list" }, ...kids), records);
    stores.list.clientHeight = clientHeight;
    new El("body").appendChild(stores.list);
    return { self, list: stores.list };
}

/** n records an hour apart, the last at NOON. */
const day = (n, prefix = "m") => Array.from({ length: n }, (_, i) => ({ id: `${prefix}${i}`, dir: "in", content: `${prefix}${i}`, timestamp: NOON - (n - 1 - i) * HOUR }));

test("a late message goes in at its place, under its own day's marker, and does not ask to be followed down", () => {
    const records = [
        { id: "mon", dir: "in", timestamp: NOON - 48 * HOUR },
        { id: "wed1", dir: "out", timestamp: NOON - HOUR },
        { id: "wed2", dir: "in", timestamp: NOON },
    ];
    const { self, list } = openChat(records);
    assert.deepEqual(list.querySelectorAll("[data-msg-id]").map(markerOf), ["Monday, September 28", "Today", null]);

    // Tuesday's, pulled late: stored in order (the store's job), shown in order.
    records.splice(1, 0, { id: "tue", dir: "in", timestamp: NOON - 24 * HOUR });
    assert.equal(self._syncOpenChatMessages(), false, "nothing new at the bottom: the reader is not moved there");
    assert.deepEqual(rowIds(list), ["mon", "tue", "wed1", "wed2"]);
    assert.deepEqual(list.querySelectorAll("[data-msg-id]").map(markerOf), ["Monday, September 28", "Yesterday", "Today", null]);

    // One of today's, later than all: at the bottom, and followed down.
    records.push({ id: "wed3", dir: "in", timestamp: NOON + 1000 });
    assert.equal(self._syncOpenChatMessages(), true);
    assert.deepEqual(rowIds(list), ["mon", "tue", "wed1", "wed2", "wed3"]);

    // Nothing missing: nothing moves, nothing to follow.
    assert.equal(self._syncOpenChatMessages(), false);
    assert.deepEqual(rowIds(list), ["mon", "tue", "wed1", "wed2", "wed3"]);

    // Several at once, one of them first of all.
    records.unshift({ id: "sun", dir: "in", timestamp: NOON - 72 * HOUR });
    records.splice(4, 0, { id: "wed1b", dir: "in", timestamp: NOON - HOUR });
    assert.equal(self._syncOpenChatMessages(), false);
    assert.deepEqual(rowIds(list), ["sun", "mon", "tue", "wed1", "wed1b", "wed2", "wed3"]);
    assert.equal(list.children.length, 7, "one row per message");
});

test("the reader scrolled up keeps what they are looking at when a late message goes in above it", () => {
    const records = day(12);                    // 12 rows, 40 high, the first under a marker (+20): 500 high
    const { self, list } = openChat(records);
    list.scrollTop = 200;                       // reading the middle: rows m4.. in view
    const reading = rowById(list, "m5");
    const before = reading.getBoundingClientRect().top;

    records.splice(2, 0, { id: "late", dir: "in", content: "late", timestamp: records[1].timestamp + 1 });
    assert.equal(self._syncOpenChatMessages(), false);
    assert.equal(rowById(list, "late").getBoundingClientRect().bottom <= LIST_TOP, true, "(fixture) it went in above the view");
    assert.equal(reading.getBoundingClientRect().top, before, "the row being read has not moved");
    assert.equal(list.scrollTop, 240, "the list scrolled by the new row's height");

    // A day earlier than all: the marker moves to it, and the view still holds.
    records.unshift({ id: "older", dir: "in", content: "older", timestamp: NOON - 30 * HOUR });
    self._syncOpenChatMessages();
    assert.equal(reading.getBoundingClientRect().top, before, "still where it was");
    assert.equal(markerOf(rowById(list, "older")), "Yesterday");
    assert.equal(markerOf(rowById(list, "m0")), "Today");
});

test("the reader at the bottom stays at the bottom when a late message goes in above", () => {
    const records = day(12);
    const { self, list } = openChat(records);
    list.scrollTop = list.scrollHeight;
    assert.equal(list.scrollTop, list.scrollHeight - list.clientHeight, "(fixture) at the bottom");
    records.splice(9, 0, { id: "late", dir: "in", content: "late", timestamp: records[8].timestamp + 1 });
    assert.equal(self._syncOpenChatMessages(), false);
    assert.equal(rowIds(list)[9], "late");
    assert.equal(list.scrollTop, list.scrollHeight - list.clientHeight, "still at the bottom");
});

test("a channel's rows go in under its \"Load earlier messages\" control, which leads the list", () => {
    const control = () => h("div", { className: "load-more", id: "channel-load-more" }, h("button", {}, "Load earlier messages"));
    // An empty channel: the notice goes, the first post goes under the control.
    const empty = [];
    const a = openChat(empty, { kind: "channel", loadMore: control() });
    empty.push({ id: "p1", dir: "in", timestamp: NOON - HOUR });
    assert.equal(a.self._syncOpenChatMessages(), true);
    assert.deepEqual(a.list.children.map((c) => c.id || c.getAttribute("data-msg-id")), ["channel-load-more", "p1"]);

    // A page of earlier posts: above what was shown, under the control,
    // and the reader at the top keeps reading where they were.
    const records = day(10, "p");
    const b = openChat(records, { kind: "channel", loadMore: control() });
    b.list.scrollTop = 0;
    const reading = rowById(b.list, "p0");
    const before = reading.getBoundingClientRect().top;
    records.unshift(
        { id: "e1", dir: "in", timestamp: NOON - 30 * HOUR },
        { id: "e2", dir: "in", timestamp: NOON - 29 * HOUR },
    );
    assert.equal(b.self._syncOpenChatMessages(), false, "earlier history does not pull the reader down");
    assert.equal(b.list.children[0].id, "channel-load-more", "the control still leads the list");
    assert.deepEqual(rowIds(b.list).slice(0, 3), ["e1", "e2", "p0"]);
    assert.equal(reading.getBoundingClientRect().top, before, "the first post shown before stays in view where it was");

    // The views: the channel's control is the list's first item.
    assert.match(methodBody("_buildChannelChatView()"),
        /this\._applyDayMarkers\(h\("div", \{ className: "message-list", id: "msg-list" \},\n\s+this\._buildChannelLoadMore\(ch\.channelName\),\n/);
    assert.match(methodBody("_buildChannelLoadMore(channelName)"), /inFlight \? "Loading…" : "Load earlier messages"/, "the phones' words");
});
