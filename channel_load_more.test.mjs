/**
 * CHANNEL PAGING BY HAND — "Load more messages".
 *
 * RFed-spec/Channel.md /rfed/pull: "Client should display a 'load more'
 * control if more_pending == true". Android and iOS page channel history by
 * hand ("Load earlier messages": ConversationScreen.kt:739-760,
 * ConversationView.swift:478-507). Until 2026-09-30 the web followed
 * more_pending on its own, one pull per completed non-empty page, and had no
 * control. Now:
 *   - a channel is pulled one page per explicit open and once per new
 *     rfed.link (rfed_link_recovery.test.mjs), and one page per click;
 *   - the control, under the open channel's messages, appears once the node
 *     has said it holds more, says "Loading…" while a pull runs, and follows
 *     the pull's start and completion in place;
 *   - /distro/pull, which is message delivery and not history, still
 *     follows more_pending on its own.
 *
 * The real shipped bodies from app.js (pullChannel, channelPullState,
 * _buildChannelLoadMore, _syncChannelLoadMore, the onMessage listener,
 * _pullDistroMessages) run over a small fake DOM and a scripted node.
 *
 * Run: node --test channel_load_more.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import { app as source, compile, constValue, fn, install } from "./test_app_source.mjs";

// ── a fake DOM, just enough for h(), getElementById and replaceWith ─────────

class El {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parent = null;
        this.attrs = {};
        this.listeners = {};
        this.style = {};
        this.className = "";
        this.disabled = false;
    }
    appendChild(c) { if (c && typeof c === "object") c.parent = this; this.children.push(c); return c; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    get id() { return this.attrs.id ?? ""; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    click() { if (!this.disabled) for (const f of this.listeners.click ?? []) f(); }
    replaceWith(other) {
        const list = this.parent.children;
        list[list.indexOf(this)] = other;
        other.parent = this.parent;
        this.parent = null;
    }
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
    find(test) {
        for (const c of this.children) {
            if (!(c instanceof El)) continue;
            if (test(c)) return c;
            const below = c.find(test);
            if (below) return below;
        }
        return null;
    }
}
const page = new El("body");
const document = {
    createElement: (tag) => new El(tag),
    createTextNode: (text) => ({ textContent: text }),
    getElementById: (id) => page.find((e) => e.id === id),
};
const h = fn("h", "tag, a={}, ...kids", { document });
const settle = async () => { for (let i = 0; i < 3; i++) await new Promise((r) => setImmediate(r)); };

/** The body of `RnsClient.onMessage((msg, peerHash) => {…})` in App, compiled over `env`. */
function onMessageListener(env) {
    const marker = "RnsClient.onMessage((msg, peerHash) => {";
    const start = source.indexOf(marker);
    assert.notEqual(start, -1, "the UI's onMessage listener is missing from app.js");
    let depth = 0;
    const open = start + marker.length - 1;
    for (let i = open; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}" && --depth === 0) {
            const body = source.slice(open + 1, i).replaceAll("this.", "self.");
            const names = Object.keys(env);
            const f = new Function(...names, "self", "msg", "peerHash", body);
            return (self) => (msg, peerHash) => f(...names.map((n) => env[n]), self, msg, peerHash);
        }
    }
    throw new Error("could not brace-match the onMessage listener");
}

const CHANNEL = { channelName: "general", channelHash: Buffer.from("general".padEnd(16, "_")).toString("hex"), isSubscribed: true };
const ChannelStore = { get: (name) => (name === CHANNEL.channelName ? CHANNEL : null), getAll: () => [CHANNEL] };
const post = (n) => [Buffer.from(CHANNEL.channelHash, "hex"), Buffer.from(`post-${n}`)];

/**
 * The open channel "general": the real RnsClient pull bodies over a node that
 * answers each /channel/pull when the test says, and the real App control
 * and listener. `ui` records what the listener did besides the control.
 */
function openChannel() {
    page.children = [];
    const requests = [];
    const handled = [];
    const client = {
        _rfedPullState: new Map(), _rfedLinkGeneration: 1, _onMsg: [],
        _rfedRequest: (aspects, path, payload) => new Promise((resolve) => requests.push({ path, payload, answer: resolve })),
        _handleChannelPacket: (data) => { handled.push(Buffer.from(data).subarray(16).toString()); return true; },
        _rfedLinkKeyFor: () => "link",
        _closeRefusedRfedLink() {},
    };
    install(client, { ChannelStore, MsgPack, Buffer, console: { log() {}, warn() {} } },
        ["async pullChannel(channelName)", "channelPullState(channelName)"]);

    const ui = [];
    const app = {
        state: { view: "main", activeHash: CHANNEL.channelName },
        _checkDayTurn() {},
        _syncOpenChatMessages: () => { ui.push("sync messages"); return true; },
        _refreshNameLabels: () => ui.push("labels"),
        _refreshSidebar: () => ui.push("sidebar"),
        _scrollChatBottom: () => ui.push("scroll"),
    };
    const warnings = [];
    install(app, { h, document, RnsClient: client, ChannelStore, console: { warn: (...a) => warnings.push(a.join(" ")) } },
        ["_buildChannelLoadMore(channelName)", "_syncChannelLoadMore()"]);
    client._onMsg.push(onMessageListener({
        GroupStore: { isGroupChat: () => false }, ChannelStore, ChannelMsgStore: { get: () => [] }, MsgStore: { get: () => [] },
        requestAnimationFrame: (f) => f(),
    })(app));

    // The channel view: its list, then the control, then the composer.
    page.appendChild(h("div", { className: "message-list", id: "msg-list" }));
    page.appendChild(app._buildChannelLoadMore(CHANNEL.channelName));
    page.appendChild(h("div", { className: "composer" }));
    const control = () => document.getElementById("channel-load-more");
    const button = () => control().find((e) => e.tagName === "BUTTON");
    return { client, app, requests, handled, ui, warnings, control, button };
}

test("the control appears once the node says it holds more, pulls one page per click, and says Loading… meanwhile", async () => {
    const v = openChannel();
    assert.ok(v.control(), "the slot is in the channel view");
    assert.match(v.control().className, /\bhidden\b/, "nothing is known yet: no control");
    assert.equal(v.button(), null);

    // The open's pull (openChannel): one page, and the node holds more.
    const opening = v.client.pullChannel(CHANNEL.channelName);
    assert.equal(v.requests.length, 1);
    assert.match(v.control().className, /\bhidden\b/, "still nothing known while the first page comes");
    v.requests[0].answer([[post(1)], true]);
    assert.equal(await opening, true);
    await settle();
    assert.deepEqual(v.handled, ["post-1"]);
    assert.equal(v.requests.length, 1, "nothing pulls the next page on its own");
    assert.doesNotMatch(v.control().className, /\bhidden\b/);
    assert.equal(v.button().textContent, "Load more messages");
    assert.equal(v.button().disabled, false);

    // A click: the next page, and the control says so until it is answered.
    v.button().click();
    assert.equal(v.requests.length, 2, "one /channel/pull per click");
    assert.equal(v.requests[1].path, "/rfed/pull");
    assert.deepEqual(MsgPack.unpack(v.requests[1].payload), Buffer.from(CHANNEL.channelHash, "hex"), "for this channel");
    assert.equal(v.button().textContent, "Loading…");
    assert.equal(v.button().disabled, true, "no second click while it runs");
    v.button().click();
    v.client.pullChannel(CHANNEL.channelName);
    assert.equal(v.requests.length, 2, "nor a second pull");

    // The last page.
    v.requests[1].answer([[post(2)], false]);
    await settle();
    assert.deepEqual(v.handled, ["post-1", "post-2"]);
    assert.match(v.control().className, /\bhidden\b/, "the node holds no more: the control goes");
    assert.equal(v.requests.length, 2);
    assert.deepEqual(v.warnings, []);
});

test("a pull that fails leaves the control as the last answer left it, ready for another click", async () => {
    const v = openChannel();
    const first = v.client.pullChannel(CHANNEL.channelName);
    v.requests[0].answer([[post(1)], true]);
    await first;
    await settle();
    v.client._rfedRequest = async () => { throw new Error("/channel/pull: the link closed before a response"); };
    v.button().click();
    await settle();
    assert.equal(v.button().textContent, "Load more messages");
    assert.equal(v.button().disabled, false);
    assert.equal(v.warnings.length, 1, "the failure is logged");
});

test("a pull's start and completion repaint only the open channel's control: not the list, the sidebar or the scroll", async () => {
    const v = openChannel();
    const pull = v.client.pullChannel(CHANNEL.channelName);
    v.requests[0].answer([[], true]);
    await pull;
    await settle();
    assert.deepEqual(v.ui, [], "the posts a pull brings repaint the list with their own event (channel-receive)");
    assert.equal(v.button().textContent, "Load more messages");

    // Another chat is open: its view is left alone.
    v.app.state.activeHash = "someone else";
    const before = v.control();
    v.client._rfedPullState.clear();
    v.client._onMsg[0]({ kind: "channel-pull-complete" }, CHANNEL.channelName);
    assert.equal(v.control(), before);

    // A post still goes through the message path.
    v.app.state.activeHash = CHANNEL.channelName;
    v.client._onMsg[0]({ kind: "channel-receive" }, CHANNEL.channelName);
    assert.deepEqual(v.ui, ["sync messages", "labels", "sidebar", "scroll"]);
});

test("/distro/pull still drains on its own, one pull per non-empty page; /channel/pull takes one page", async () => {
    // The distro pull is message delivery, not history: the device must get
    // every message the node deferred for it without a click.
    const requests = [];
    const answers = [[[["d".repeat(32), Buffer.alloc(64)]], true], [[["d".repeat(32), Buffer.alloc(64)]], true], [[], true]];
    const self = {
        _distroPullInFlight: null, _rfedLinkState: new Map(),
        _rfedRequest: async (aspects, path) => { requests.push(`${aspects.join(".")}:${path}`); return answers.shift(); },
        _handleDistroBlob: () => true, _rfedLinkKeyFor: () => "link",
        _closeRefusedRfedLink() {}, _rfedDeferUntilAnnounce() {}, _redriveRfedLink() {},
    };
    install(self, {
        DistroManager: { has: true }, MsgPack, console: { log() {}, warn() {}, error() {} },
        RFED_LINK_FAILED: constValue("RFED_LINK_FAILED"),
    }, ["async _pullDistroMessages()"]);
    await self._pullDistroMessages();
    await settle();
    assert.deepEqual(requests, ["distro.register:/rfed/pull", "distro.register:/rfed/pull", "distro.register:/rfed/pull"],
        "two pages that said more, each followed; the empty one that also said more is not");

    const v = openChannel();
    const pull = v.client.pullChannel(CHANNEL.channelName);
    v.requests[0].answer([[post(1)], true]);
    await pull;
    await settle();
    assert.equal(v.requests.length, 1, "the same answer for a channel waits for the user");
});
