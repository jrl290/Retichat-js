/**
 * GROUP UI RULINGS — what the web shows for a group, after James's rulings of
 * 2026-10-11 (GROUPS-DISTRO-DESIGN.md §8.7, the start-up):
 *
 *   - UI text never describes an internal state, and the only new text is the
 *     former-distro text, word for word, shown with "Delete from this device";
 *   - while the start has not finished (RnsClient.connect() has not built
 *     the client), Accept, Decline, Leave, Delete from this device and
 *     Create are greyed, with no text, and a post waits like a DM's; once
 *     built they work while the exchange is down, as before;
 *   - a post refused after Send says nothing, and its draft stays in the
 *     composer; an accept, decline or leave refused says nothing either;
 *   - the distro changing (imported, generated, forgotten) draws an open
 *     group chat again, its draft kept.
 *
 * These run App's own views and handlers, cut out of app.js
 * (test_app_source.mjs), over a real client's stores and RnsClient
 * (test_group_net.mjs) and a small fake DOM.
 *
 * Run: node --test group_ui_rulings.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { compile, install, fn, methodBody } from "./test_app_source.mjs";
import { groupClient, lxmfHash, quiet, Identity } from "./test_group_net.mjs";

// ── a small fake DOM ───────────────────────────────────────────────────────

class El {
    constructor(tag) {
        this.tagName = String(tag).toUpperCase();
        this.children = [];
        this.attrs = {};
        this.listeners = {};
        this.style = {};
        this.className = "";
        this.parent = null;
        this._text = "";
        this.classList = { add() {}, remove() {}, contains: () => false };
    }
    appendChild(c) { c.parent = this; this.children.push(c); return c; }
    append(...cs) { for (const c of cs) this.appendChild(c); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    /** "[attribute]" or ".class:checked" only: every element under this one that matches. */
    querySelectorAll(selector) {
        const attr = /^\[([\w-]+)\]$/.exec(selector);
        const checked = /^\.([\w-]+):checked$/.exec(selector);
        assert.ok(attr || checked, `selector ${selector} is not one this fake DOM knows`);
        return attr ? this.all((e) => e !== this && attr[1] in e.attrs)
            : this.all((e) => e !== this && e.className.split(" ").includes(checked[1]) && e.checked === true);
    }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
    *walk() { yield this; for (const c of this.children) yield* c.walk(); }
    all(pred) { return [...this.walk()].filter(pred); }
    find(pred) { return this.all(pred)[0] ?? null; }
    fire(type, event = {}) { for (const f of this.listeners[type] ?? []) f({ target: this, key: event.key, preventDefault() {}, ...event }); }
}
const document = {
    createElement: (tag) => new El(tag),
    createTextNode: (text) => { const t = new El("#text"); t._text = String(text); return t; },
    createDocumentFragment: () => new El("#fragment"),
    getElementById: () => null,
    body: new El("body"),
};
const h = fn("h", "tag, a={}, ...kids", { document });
const buttons = (root) => root.all((e) => e.tagName === "BUTTON");
const button = (root, text) => buttons(root).find((e) => e.textContent === text) ?? null;
/** Every button's label and whether it is greyed, in order. */
const offered = (root) => buttons(root).map((b) => [b.textContent, b.disabled === true]);

// ── the user, a D-group, and App's views over them ─────────────────────────

/** The user's device holding distro D, in group `id` created by C, listing
 *  M and D (its own address D): pending, or joined when `joined`. */
function dGroup({ joined = false } = {}) {
    const Did = Identity.create(), D = lxmfHash(Did);
    const Cid = Identity.create(), Mid = Identity.create();
    const C = lxmfHash(Cid), M = lxmfHash(Mid);
    const u = groupClient({ distro: Did });
    u.know(Cid).know(Mid);                               // every member's key here: an accept can go
    const id = "5e".repeat(16);
    u.GroupStore.addPending(id, "G", C, [C, M, D], D);
    if (joined) u.GroupStore.accept(id);
    return { u, Did, D, C, M, id };
}

/** App, with its group views and acts compiled from app.js over `u`. */
function appOf(u, chat) {
    const notices = [];
    const composer = { el: null };
    const env = {
        h, document: { ...document, getElementById: (id) => (id === "composer-input" ? composer.el : null) },
        GroupStore: u.GroupStore, GroupMsgStore: u.GroupMsgStore, ContactStore: u.ContactStore, ChannelStore: { get: () => null },
        RnsClient: u.self, DistroManager: u.DistroManager, avatarHue: () => 0, groupSenderLabel: () => "",
        alert: (m) => assert.fail(`alert: ${m}`), confirm: (m) => assert.fail(`confirm: ${m}`), console: quiet,
        requestAnimationFrame: (f) => f(), GROUP_ATTACHMENT_REFUSAL: "text only", AttachmentUrls: { sweep() {} },
    };
    const self = {
        state: { activeHash: chat, showGroupInfo: false, groupInfoId: chat, showNewConversation: true },
        root: new El("div"), renders: 0, opened: [], _pendingAttachments: new Map(), _keptDrafts: new Map(),
        render() { this.renders++; }, openChat(id) { this.opened.push(id); }, closeChat() {},
        _applyDayMarkers: (list) => list, _buildSystemMsg: () => h("div"), _buildMsgBubble: () => h("div"),
        _buildComposerExtras: () => h("div"), _composerKeydown() {}, _pickAttachments() {},
        _groupMemberLabel: (hash) => hash.slice(0, 8), _paintMemberAvatar() {},
        _composerNotice: (t) => notices.push(t), _syncOpenChatMessages() {}, _refreshSidebar() {}, _scrollChatBottom() {},
        _renderComposerTray() {},
    };
    install(self, env, [
        "_buildGroupChatView()", "_renderGroupInfoModal()", "_renderGroupForm(top, scroll, footer)", "sendMessage()",
        "_groupActionsReady()", "_syncGroupActions()", "_saveComposerFocus()", "_restoreComposerFocus()",
    ]);
    /** The group chat as drawn now, in the detail pane (root). */
    self.chat = () => { self.root = new El("div"); self.root.appendChild(self._buildGroupChatView()); return self.root; };
    /** The group info sheet as drawn now. */
    self.info = () => { self.root = new El("div"); self._renderGroupInfoModal(); return self.root; };
    /** The New Conversation group form as drawn now: { top, scroll, footer }. */
    self.form = () => {
        const top = new El("div"), scroll = new El("div"), footer = new El("div");
        self.root = new El("div");
        self.root.append(top, scroll, footer);
        self._renderGroupForm(top, scroll, footer);
        return { top, scroll, footer };
    };
    /** The composer, holding `text`. */
    self.type = (text) => { composer.el = { value: text, style: {}, selectionStart: text.length, focus() {} }; return composer.el; };
    self.noComposer = () => { composer.el = null; };
    return Object.assign(self, { notices, composer });
}

/** The start not finished: connect() has not built the client (its router),
 *  so the exchange has not registered either. */
function starting(u) {
    u.router ??= u.self._lxmfRouter;
    u.self._lxmfRouter = null;
    u.self._initialized = false;
}
/** The start finished: the client built (the exchange may still be down). */
function started(u) {
    u.self._lxmfRouter = u.router ?? u.self._lxmfRouter;
}

const FORMER = (D) => `This group uses your distro address ${D.slice(0, 8)}…, which is no longer on this device. ` +
    "New messages in it don't reach this device, and you can't post, join or leave from here. Import that distro again to use the group here.";

// ── the former-distro text, word for word ──────────────────────────────────

test("a D-group whose distro is no longer here says exactly James's words, the address its first 8 hex and \"…\", straight apostrophes, with \"Delete from this device\" in the chat and in the group info", () => {
    for (const joined of [false, true]) {
        const { u, D, id } = dGroup({ joined });
        u.DistroManager.set(null);
        const text = u.self.groupFormerDistroText(u.GroupStore.get(id));
        assert.equal(text, FORMER(D));
        assert.ok(!/[‘’]/.test(text) && text.includes(`${D.slice(0, 8)}…,`), "U+2026 after 8 hex; no curly apostrophe");
        const page = appOf(u, id);
        const chat = page.chat();
        assert.ok(chat.textContent.includes(FORMER(D)), "the chat shows it");
        assert.deepEqual(offered(chat).filter(([t]) => t !== "←" && t !== "ℹ"), [["Delete from this device", false]],
            "its one act; no accept, decline, composer or send");
        const info = page.info();
        assert.ok(info.textContent.includes(FORMER(D)), "the group info shows it");
        assert.deepEqual(offered(info).filter(([t]) => t !== "✕"), [["Delete from this device", false]], "and only that act");
        // A replacing distro is no different.
        u.DistroManager.set(Identity.create());
        assert.equal(u.self.groupFormerDistroText(u.GroupStore.get(id)), FORMER(D));
    }
});

// ── refusals say nothing ───────────────────────────────────────────────────

test("an accept, decline or leave refused for a distro no longer here says nothing (no alert, no question), changes nothing, and draws the group again", () => {
    for (const joined of [false, true]) {
        const { u, id } = dGroup({ joined });
        u.DistroManager.set(null);
        const before = u.page.renders ?? 0;
        if (!joined) {
            u.page._acceptGroupInvite(id);
            u.page._declineGroupInvite(id);
        } else {
            u.page._leaveGroup(id);
        }
        assert.deepEqual([u.alerts, u.confirms], [[], []], "no text at all");
        assert.equal(u.GroupStore.get(id).groupStatus, joined ? "active" : "pending", "nothing changed");
        assert.equal(u.GroupStore.isClosed(id), false);
        assert.equal(u.page.renders - before, joined ? 1 : 2, "drawn again, so the chat shows why");
    }
});

test("a post refused after Send (the group's distro is no longer here) says nothing and leaves the draft in the composer; with the distro here the draft is sent and cleared", async () => {
    const { u, Did, id } = dGroup({ joined: true });
    const page = appOf(u, id);
    u.DistroManager.set(null);
    const ta = page.type("  the draft  ");
    page.sendMessage();
    assert.equal(ta.value, "  the draft  ", "the draft stays, as typed");
    assert.deepEqual(page.notices, [], "no notice");
    assert.deepEqual(u.GroupMsgStore.get(id).filter((m) => m.dir === "out"), [], "nothing stored to send");
    u.DistroManager.set(Did);
    page.sendMessage();
    assert.equal(ta.value, "", "sent: cleared");
    assert.deepEqual(u.GroupMsgStore.get(id).filter((m) => m.dir === "out").map((m) => m.content), ["the draft"]);
});

// ── the start-up: greyed, no text ──────────────────────────────────────────

test("until the start finishes, Accept, Decline, Leave, Delete from this device and Create are greyed with no text, in the chat, the group info and the group form; once it finishes they are offered in place", () => {
    const pending = dGroup();
    const joined = dGroup({ joined: true });
    const former = dGroup({ joined: true });
    former.u.DistroManager.set(null);
    for (const g of [pending, joined, former]) starting(g.u);

    const views = [];
    const p = appOf(pending.u, pending.id);
    const pChat = p.chat();
    assert.deepEqual(offered(pChat).filter(([t]) => t === "Accept" || t === "Decline"), [["Accept", true], ["Decline", true]]);
    views.push([p, pChat, ["Accept", "Decline"]]);
    const pInfo = appOf(pending.u, pending.id);
    const pSheet = pInfo.info();
    assert.deepEqual(offered(pSheet).filter(([t]) => /Accept|Decline/.test(t)), [["✅ Accept Invite", true], ["❌ Decline", true]]);
    views.push([pInfo, pSheet, ["✅ Accept Invite", "❌ Decline"]]);
    const j = appOf(joined.u, joined.id);
    const jSheet = j.info();
    assert.deepEqual(offered(jSheet).filter(([t]) => /Leave/.test(t)), [["🚪 Leave Group", true]]);
    views.push([j, jSheet, ["🚪 Leave Group"]]);
    const jChat = appOf(joined.u, joined.id);
    const jComposer = jChat.chat();
    assert.ok(buttons(jComposer).some((b) => b.className === "btn-send" && !b.disabled), "the composer stays: a post waits like a DM's");
    for (const view of ["chat", "info"]) {
        const f = appOf(former.u, former.id);
        const root = f[view]();
        assert.deepEqual(offered(root).filter(([t]) => t === "Delete from this device"), [["Delete from this device", true]], view);
        views.push([f, root, ["Delete from this device"]]);
    }
    const c = appOf(joined.u, null);
    const { footer } = c.form();
    assert.deepEqual(offered(footer), [["Create Group", true]]);
    views.push([c, c.root, ["Create Group"]]);

    // Greyed is seen: a disabled button is drawn faded and takes no pointer.
    assert.match(readFileSync(new URL("./style.css", import.meta.url), "utf8"), /\n\.btn:disabled \{ opacity: 0\.5; cursor: default; pointer-events: none; \}/);
    // Nothing greyed says why: the texts are the ones shown when offered.
    const texts = (root) => root.textContent;
    const greyedTexts = views.map(([, root]) => texts(root));

    for (const g of [pending, joined, former]) started(g.u);         // the exchange not registered yet: no matter
    for (const [page, root, labels] of views) {
        page.root = root;
        page._syncGroupActions();
        for (const label of labels) assert.equal(button(root, label).disabled, false, `${label}: offered once the start has finished`);
    }
    assert.deepEqual(views.map(([, root]) => texts(root)), greyedTexts, "the same words greyed or not");
    // And greyed again while a restart has not finished.
    for (const g of [pending, joined, former]) starting(g.u);
    for (const [page, root, labels] of views) {
        page.root = root;
        page._syncGroupActions();
        for (const label of labels) assert.equal(button(root, label).disabled, true, `${label}: greyed again`);
    }
});

test("until the start finishes the acts themselves do nothing and say nothing: accept, decline, leave, delete from this device, and create (the button or Enter in the name)", () => {
    const pending = dGroup();
    starting(pending.u);
    pending.u.page._acceptGroupInvite(pending.id);
    pending.u.page._declineGroupInvite(pending.id);
    assert.equal(pending.u.GroupStore.get(pending.id).groupStatus, "pending");

    const joined = dGroup({ joined: true });
    starting(joined.u);
    joined.u.page._leaveGroup(joined.id);
    assert.equal(joined.u.GroupStore.isClosed(joined.id), false);

    const former = dGroup({ joined: true });
    former.u.DistroManager.set(null);
    starting(former.u);
    former.u.page._deleteGroupFromDevice(former.id);
    assert.ok(former.u.GroupStore.get(former.id), "still here");

    for (const g of [pending, joined, former]) assert.deepEqual([g.u.alerts, g.u.confirms, g.u.sent.length], [[], [], 0], "no text, nothing sent");

    const c = appOf(joined.u, null);
    const contact = Identity.create();
    joined.u.ContactStore.add(lxmfHash(contact), false, contact.getPublicKey().toString("hex"));
    const groupsBefore = joined.u.GroupStore.getAll().length;
    const { top, scroll, footer } = c.form();
    const box = scroll.find((e) => e.className === "group-member-check");
    assert.ok(box, "a contact to pick");
    box.checked = true;
    const name = top.find((e) => e.attrs.id === "nc-group-name");
    name.fire("input", { target: { value: "New" } });
    name.fire("keydown", { key: "Enter" });
    button(footer, "Create Group").fire("click");
    assert.equal(joined.u.GroupStore.getAll().length, groupsBefore, "no group created");
    assert.deepEqual(c.opened, []);
});

test("the start finishing is the client being built, not the exchange answering: connect() tells the page once it has built the client, and with the exchange down the acts are offered and work, as before", () => {
    const connect = methodBody("async connect()");
    const built = connect.indexOf("this._lxmfRouter = new LXMRouter(");
    const hooked = connect.indexOf("this._hookPageLifecycle();", built);
    const told = connect.indexOf("this._onStatus.forEach(fn => fn(this._status));", hooked);
    const last = connect.indexOf("console.log(`[rns] Connecting via", told);
    assert.ok(built > 0 && hooked > built && told > hooked && last > told, "told after the client is built, its last act before the closing line");
    assert.doesNotMatch(connect.slice(connect.indexOf("this._lxmfRouter = new LXMRouter(")), /\bawait\b/, "nothing awaited after the router");
    assert.match(methodBody("_wire()"), /RnsClient\.onStatus\(\(\) => \{[^}]*this\._syncGroupActions\(\);/);
    assert.match(methodBody("_groupActionsReady()"), /^\s*return RnsClient\._lxmfRouter != null;\s*$/);

    // Built, the exchange down (never registered): offered, and the accept works.
    const { u, id } = dGroup();
    u.self._initialized = false;
    const page = appOf(u, id);
    assert.deepEqual(offered(page.chat()).filter(([t]) => t === "Accept" || t === "Decline"), [["Accept", false], ["Decline", false]]);
    u.page._acceptGroupInvite(id);
    assert.equal(u.GroupStore.get(id).groupStatus, "active");
});

// ── the distro changing draws an open group chat again, its draft kept ─────

test("the distro changing draws the open group chat again (and the group info when open); a draft whose composer gives way to the former-distro text comes back with the composer", () => {
    const wire = methodBody("_wire()");
    assert.match(wire, /DistroManager\.onChange\(\(\) => \{[\s\S]*?GroupStore\.isGroupChat\(this\.state\.activeHash\)[\s\S]*?this\._rebuildDetail\(\);[\s\S]*?\}\);/);

    const { u, Did, id } = dGroup({ joined: true });
    const page = appOf(u, id);
    page.type("half typed");
    page._saveComposerFocus();
    u.DistroManager.set(null);
    page.noComposer();                                   // the rebuilt chat has the former-distro bar, no composer
    page._restoreComposerFocus();
    assert.equal(page._keptDrafts.get(id), "half typed", "kept for the chat");
    u.DistroManager.set(Did);
    page._saveComposerFocus();                           // no composer: nothing to save
    const back = page.type("");                          // the composer is back, empty
    page._restoreComposerFocus();
    assert.equal(back.value, "half typed", "the draft is back in it");
    assert.equal(page._keptDrafts.has(id), false, "once");
});

test("a post written before the start finishes waits like a DM's (queued, the draft sent and cleared); when the start finishes and the group's distro is gone it is shown failed, as a DM that cannot go, and nothing is sent", async () => {
    const { u, id } = dGroup({ joined: true });
    starting(u);
    const page = appOf(u, id);
    const ta = page.type("early");
    page.sendMessage();
    assert.equal(ta.value, "", "taken, as a DM's");
    const [queued] = u.GroupMsgStore.get(id).filter((m) => m.dir === "out");
    assert.deepEqual([queued.content, queued.status, queued.waitFor], ["early", "queued", "init"]);
    u.DistroManager.set(null);
    started(u);
    u.self._initialized = true;
    await u.self._dispatchGroupMessage(id, queued);
    assert.equal(u.GroupMsgStore.get(id).find((m) => m.id === queued.id).status, "failed");
    assert.deepEqual([u.sent.length, u.propagated.length, u.alerts], [0, 0, []]);
});
