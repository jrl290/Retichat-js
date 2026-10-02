/**
 * A MESSAGE'S LINE BREAKS (James, 2026-10-02: "It looks like the web chat
 * strips out newline characters ... lets correct that").
 *
 * The text kept its line breaks all the way: composer, send paths, LXMF and
 * channel packing, unpacking, the stores. Two places lost them:
 *   - the bubble put the text in .msg-bubble as a bare text node, under
 *     white-space: normal, so each line break was drawn as a space;
 *   - on a phone the return key sent the message, and a phone's keyboard
 *     has no Shift+Return, so no line break could be typed.
 * Now the bubble's text is a .msg-text element (white-space: pre-wrap) and
 * on a touch-first device the return key breaks the line (lib/message_text.js).
 *
 * This file pins each link of the chain under Node: the display rule, the
 * Enter rule, the bubble, the composers, the send paths, the codecs, the
 * stylesheet. message_newlines_page.test.mjs checks the drawn result in
 * Chromium (`npm run test:full`).
 *
 * Run: node --test message_newlines.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { bubbleText, enterSends, TOUCH_FIRST } from "./lib/message_text.js";
import { clean as cleanDisplayName } from "./lib/display_name.js";
import { emptyInvalidStrs } from "./lib/rns/msgpack.js";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import { channelLxmPack, channelLxmUnpack } from "./lib/rns/rfed_channel.js";
import { app, compile, fn, install, methodBody } from "./test_app_source.mjs";

const MULTI = "line one\nline two\r\nline three";

// ── the display rule ────────────────────────────────────────────────────────

test("bubbleText keeps every line break, reads CR LF and a lone CR as one break each, and trims both ends only", () => {
    assert.equal(bubbleText("a\nb"), "a\nb");
    assert.equal(bubbleText(MULTI), "line one\nline two\nline three");
    assert.equal(bubbleText("a\rb"), "a\nb", "a lone CR (classic Mac) is a break, not a space");
    assert.equal(bubbleText("a\n\n\nb"), "a\n\n\nb", "blank lines inside are kept");
    assert.equal(bubbleText("a  \tb"), "a  \tb", "spaces inside are kept");
    assert.equal(bubbleText("\n\n  a\nb  \n\n"), "a\nb", "white space at either end is not shown, as iOS stores a received message");
    assert.equal(bubbleText(" \r\n\t"), "");
    assert.equal(bubbleText(""), "");
    assert.equal(bubbleText(null), "");
    assert.equal(bubbleText(undefined), "");
});

// ── the Enter rule ──────────────────────────────────────────────────────────

test("enterSends: with a keyboard Enter sends and Shift+Enter breaks the line; on a touch-first device the return key always breaks it; an IME's Enter never sends", () => {
    const key = (over) => ({ key: "Enter", shiftKey: false, isComposing: false, ...over });
    assert.equal(enterSends(key(), false), true);
    assert.equal(enterSends(key({ shiftKey: true }), false), false);
    assert.equal(enterSends(key({ isComposing: true }), false), false);
    assert.equal(enterSends(key(), true), false, "a phone's return key breaks the line");
    assert.equal(enterSends(key({ shiftKey: true }), true), false);
    assert.equal(enterSends(key({ key: "a" }), false), false);
    assert.equal(TOUCH_FIRST, "(hover: none) and (pointer: coarse)");
});

// ── the bubble, over a small fake DOM ───────────────────────────────────────

class El {
    constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.style = {}; this.className = ""; }
    appendChild(c) { this.children.push(c); return c; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    addEventListener() {}
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
    all(test) {
        const out = [];
        const walk = (n) => { for (const c of n.children ?? []) if (c instanceof El) { if (test(c)) out.push(c); walk(c); } };
        walk(this);
        return out;
    }
}
const document = { createElement: (tag) => new El(tag), createTextNode: (text) => ({ textContent: text }) };
const h = fn("h", "tag, a={}, ...kids", { document });
const byClass = (root, name) => root.all((e) => e.className.split(" ").includes(name));

function bubbles() {
    const self = {
        _statusIcon: () => "●",
        _buildAttachments: () => null,
    };
    return install(self, {
        h, bubbleText, fmtTime: () => "12:00", RnsClient: { _sendTransfers: { progressOf: () => null } },
    }, ["_buildMsgBubble(m, sender = null)", "_buildSenderLabel(sender)", "_buildProgressBar(progress)"]);
}

test("the bubble holds the text in a .msg-text element of its own, line breaks in it, between the sender label and the meta line; the record is not touched", () => {
    const app = bubbles();
    const m = { id: "m1", dir: "in", content: MULTI, timestamp: 0, status: "delivered" };
    const row = app._buildMsgBubble(m, { label: "Alice", secondary: null });
    const [bubble] = byClass(row, "msg-bubble");
    assert.deepEqual(bubble.children.map((c) => c.className), ["msg-sender", "msg-text", "msg-meta"],
        "the text is an element, never a bare text node in the bubble");
    const [text] = byClass(row, "msg-text");
    assert.equal(text.tagName, "DIV");
    assert.equal(text.textContent, "line one\nline two\nline three");
    assert.equal(m.content, MULTI, "the stored text is not rewritten");

    const own = app._buildMsgBubble({ id: "m2", dir: "out", content: "a\nb", timestamp: 0, status: "sent" });
    assert.equal(byClass(own, "msg-text")[0].textContent, "a\nb");
});

test("a message with no text (a captionless attachment, or only white space) has no .msg-text", () => {
    const app = bubbles();
    for (const content of ["", " \n\r\n ", undefined]) {
        const row = app._buildMsgBubble({ id: "m", dir: "in", content, timestamp: 0 });
        assert.equal(byClass(row, "msg-text").length, 0, JSON.stringify(content));
        assert.equal(byClass(row, "msg-meta").length, 1);
    }
});

test("the bubble builder shows the text through bubbleText in .msg-text, never as a bare text node; the DM, group and channel views build their bubbles with it", () => {
    // DM, group, channel, the in-place append and the repaint all call it.
    const builders = app.match(/this\._buildMsgBubble\(/g) ?? [];
    assert.ok(builders.length >= 5, `found ${builders.length}`);
    const body = methodBody("_buildMsgBubble(m, sender = null)");
    assert.match(body, /const text = bubbleText\(m\.content\);/);
    assert.match(body, /h\("div", \{ className: "msg-text" \}, text\)/);
    assert.doesNotMatch(body, /^\s*m\.content,\s*$/m, "no bare text node");
});

// ── the composers ───────────────────────────────────────────────────────────

test("every composer's keydown goes through _composerKeydown, and nothing else sends on Enter", () => {
    const composers = app.match(/id: "composer-input"/g) ?? [];
    const wired = app.match(/onKeydown: \(e\) => this\._composerKeydown\(e\)/g) ?? [];
    assert.equal(composers.length, 3, "DM, group and channel");
    assert.equal(wired.length, composers.length, "each composer textarea uses the shared rule");
    assert.doesNotMatch(app, /e\.key === "Enter" && !e\.shiftKey\) \{ e\.preventDefault\(\); this\.sendMessage\(\)/,
        "no composer keeps its own Enter rule");
});

test("_composerKeydown: Enter sends on a desktop; Shift+Enter, a phone's return key and an IME's Enter leave the line break to the textarea", () => {
    let coarse = false;
    const window = { matchMedia: (q) => ({ matches: q === TOUCH_FIRST && coarse }) };
    const sent = [];
    const self = { sendMessage: () => sent.push(1) };
    install(self, { window, enterSends, TOUCH_FIRST }, ["_composerKeydown(e)"]);
    const press = (over) => {
        const e = { key: "Enter", shiftKey: false, isComposing: false, prevented: false, ...over };
        e.preventDefault = () => { e.prevented = true; };
        self._composerKeydown(e);
        return e.prevented;
    };
    assert.equal(press(), true); assert.equal(sent.length, 1);
    assert.equal(press({ shiftKey: true }), false); assert.equal(sent.length, 1);
    assert.equal(press({ isComposing: true }), false); assert.equal(sent.length, 1);
    coarse = true;
    assert.equal(press(), false, "a phone: the return key breaks the line"); assert.equal(sent.length, 1);
    // A browser without matchMedia is treated as having a keyboard.
    const bare = { sendMessage: () => sent.push(2) };
    install(bare, { window: {}, enterSends, TOUCH_FIRST }, ["_composerKeydown(e)"]);
    const e = { key: "Enter", shiftKey: false, isComposing: false, preventDefault() {} };
    bare._composerKeydown(e);
    assert.deepEqual(sent, [1, 2]);
});

// ── App.sendMessage: the composer's text, line breaks inside it, to each send path ──

function sendFrom(value, kind) {
    const calls = [];
    const ta = { value, style: {} };
    const pending = () => ({ catch() {} });
    const env = {
        document: { getElementById: (id) => (id === "composer-input" ? ta : null) },
        requestAnimationFrame: () => {},
        alert: (m) => { throw new Error(m); },
        console,
        GROUP_ATTACHMENT_REFUSAL: "no",
        GroupStore: { isGroupChat: () => kind === "group" },
        ChannelStore: { get: () => (kind === "channel" ? { channelName: "c" } : null) },
        ContactStore: { get: () => ({ destHash: "d" }) },
        RnsClient: {
            attachmentRefusal: () => null,
            sendMessage: (c, content) => calls.push(["dm", content]),
            sendGroupMessage: (g, content) => { calls.push(["group", content]); return pending(); },
            sendChannelMessage: (c, content) => { calls.push(["channel", content]); return pending(); },
        },
    };
    const self = {
        state: { activeHash: "chat" }, _pendingAttachments: new Map(),
        _syncOpenChatMessages() {}, _refreshSidebar() {}, _scrollChatBottom() {}, _composerNotice() {}, _renderComposerTray() {},
    };
    install(self, env, ["sendMessage()"]);
    self.sendMessage();
    return { calls, ta };
}

test("the composer's text goes to the DM, group and channel send paths with its line breaks, trimmed at both ends only", () => {
    for (const kind of ["dm", "group", "channel"]) {
        const { calls, ta } = sendFrom("\n  first line\n\nthird line\r\nfourth  \n", kind);
        assert.deepEqual(calls, [[kind, "first line\n\nthird line\r\nfourth"]], kind);
        assert.equal(ta.value, "", `${kind}: the composer is cleared`);
    }
});

// ── the codecs: what is sent is what is received ────────────────────────────

const TEXT = "first\nsecond\r\n\nfourth\twith tab\n";
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery");

test("LXMF (DM, group envelope): the content's line breaks survive pack and unpack byte for byte", () => {
    const alice = Identity.create(), bob = Identity.create();
    const m = new LXMessage();
    m.sourceHash = lxmfHash(alice);
    m.destinationHash = lxmfHash(bob);
    m.title = "";
    m.content = TEXT;
    m.fields = new Map();
    const bytes = m.pack(alice, false);
    const back = LXMessage.fromBytes(bytes.subarray(16), bytes.subarray(0, 16), () => alice);
    assert.equal(back.content, TEXT);
    assert.equal(back.signatureValidated, true);
});

test("the distro path (LXMessage.decodePayload) and the msgpack UTF-8 guard keep a multi-line text as it came", () => {
    const payload = MsgPack.pack([1700000000, Buffer.alloc(0), Buffer.from(TEXT, "utf8"), new Map()]);
    assert.equal(emptyInvalidStrs(payload), payload, "valid text: the same bytes, untouched");
    const asStr = MsgPack.pack([1700000000, "", "ünï\ncödé\r\n", new Map()]);
    assert.equal(emptyInvalidStrs(asStr), asStr, "a str with line breaks and non-ASCII is valid UTF-8 and kept");
    const decoded = LXMessage.decodePayload(payload);
    assert.equal(Buffer.from(decoded.content).toString(), TEXT, "as app.js _handleDistroBlob decodes it");
    assert.equal(Buffer.from(LXMessage.decodePayload(asStr).content).toString(), "ünï\ncödé\r\n");
});

test("a channel post's line breaks survive channelLxmPack and channelLxmUnpack", () => {
    const sender = Identity.create();
    const { wire } = channelLxmPack("newlines", sender, TEXT);
    const post = channelLxmUnpack("newlines", wire);
    assert.ok(post, "unpacked");
    assert.equal(post.content, TEXT);
});

test("display-name cleaning still makes a name one line, and is never given message content", () => {
    assert.equal(cleanDisplayName("Ann\nMarie"), "Ann Marie", "names stay one line (DISPLAY_NAMES.md §3 rule 2)");
    // Every cleaner call in app.js is on a name source, never on a message's content.
    const calls = app.match(/clean(?:Display|Announce)Name\(([^)]*)\)/g) ?? [];
    assert.ok(calls.length > 0);
    for (const c of calls) assert.doesNotMatch(c, /content/, c);
});

// ── the stylesheet ──────────────────────────────────────────────────────────

const css = readFileSync(new URL("./style.css", import.meta.url), "utf8");
/** The declarations of the rule whose selector is exactly `selector`. */
function rule(selector) {
    const at = css.search(new RegExp(`(^|\\n)${selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\{`));
    assert.notEqual(at, -1, `${selector} is missing from style.css`);
    const open = css.indexOf("{", at);
    return css.slice(open + 1, css.indexOf("}", open));
}

test("style.css: .msg-text keeps line breaks and wraps a long word; the chat-list preview stays one line", () => {
    assert.match(rule(".msg-text"), /white-space:\s*pre-wrap;/);
    assert.match(rule(".msg-text"), /overflow-wrap:\s*anywhere;/);
    assert.match(rule(".contact-preview"), /white-space:\s*nowrap;/, "a preview's line breaks are drawn as spaces, on one line");
    assert.match(rule(".contact-preview"), /text-overflow:\s*ellipsis;/);
    assert.doesNotMatch(rule(".msg-bubble"), /white-space/, "the bubble's other parts (sender, attachments, meta) keep the default");
});
