/**
 * A CONTACT IS ONLY WHAT THE USER ADDS; EVERYTHING ELSE IS A CONVERSATION OR
 * NOTHING (James, 2026-10-02, after retichat.com showed channel posters as
 * "Tap to chat" contacts: "You don't need to clean up anything. Just prevent
 * adding contacts that aren't explicitly added. The group and channel member
 * messages are only accepted by association.")
 *
 *   - A contact (a listed ContactStore row) is made only by the user: Add
 *     Contact, New Conversation (a hash, an lxmf:// or lxma:// link), "Add
 *     contact" on a conversation's contact-info sheet, and the harness's
 *     RetichatTest.addPeer; all through App._addContact, the one caller of
 *     ContactStore.add. It shows in the chat list with "Tap to chat" until
 *     there is a message (iOS createDirectChat, Android getOrCreateDirectChat
 *     show an empty preview), in the New Conversation list and in the group
 *     picker.
 *   - A stranger's DM (the web's filter is off by default), a distro message
 *     and a distro sent copy keep a hidden row: a CONVERSATION, shown in the
 *     chat list with its preview (never "Tap to chat", even for a message
 *     with no text and no attachment), and nowhere that offers contacts.
 *   - Channel posters and group members are accepted by association: a
 *     hidden row (key, names), shown nowhere. Allowlisting (accepting a
 *     group, the user's own DM) lists nothing.
 *   - Deleting a conversation that is no contact keeps the hidden row (the
 *     key a group still checks signatures with); deleting a contact's
 *     removes the contact, as before.
 *   - No clean-up: a row stored without the `hidden` key by an older build
 *     stays a contact.
 *
 * These run the real shipped code: ContactStore, MsgStore, GroupStore,
 * GroupMsgStore, ChannelMsgStore and PrivacyFilter over one storage; the
 * real LXMRouter with the real message handler and _handleGroupMessage
 * behind it; _handleDistroBlob; _handleChannelPacket with real channel wire
 * bytes; _acceptGroupInvite; and the chat list, the New Conversation form,
 * the group picker, Add Contact and the contact-info sheet, built by their
 * own methods over a small fake DOM.
 *
 * Run: node --test contacts_explicit.test.mjs
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
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { channelLxmPack, channelLxmUnpack } from "./lib/rns/rfed_channel.js";
import * as DN from "./lib/display_name.js";
import { ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";
import { ChannelPublishes } from "./lib/channel_publish.js";
import { lastMessageTime, sentTimeMs } from "./lib/day_markers.js";
import { settle } from "./test_link_pair.mjs";
import { app, build, compile, constValue, fn, install, methodBody, memoryStorage, messageHandler, objectLiteral } from "./test_app_source.mjs";

const CHANNEL = "public.general";
const quiet = { log() {}, warn() {}, error() {} };
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const keyHex = (identity) => identity.getPublicKey().toString("hex");
const appFunction = (name, env) => fn(name, app.match(new RegExp(`\\nfunction ${name}\\(([^)]*)\\)`))[1], env);
const short = (hash) => DN.shortHash(hash);

/** The group trust rule as app.js defines it. */
function groupRule() {
    const groupTrustsSource = appFunction("groupTrustsSource", {});
    const GROUP_ACTIONS_THAT_RELAY = constValue("GROUP_ACTIONS_THAT_RELAY");
    return { groupTrustsSource, GROUP_ACTIONS_THAT_RELAY,
        shouldProcessGroupMessage: appFunction("shouldProcessGroupMessage", { groupTrustsSource, GROUP_ACTIONS_THAT_RELAY }) };
}

// ── a page: the stores, the receive paths, the screens ─────────────────────

/** The stores a page load builds, over `storage`. The privacy filter is the
 *  web's default (off) unless `filter` says otherwise. */
function page({ me = Identity.create(), storage = memoryStorage(), filter = null } = {}) {
    const { sGet, sSet } = storage;
    if (filter !== null) sSet("filterStrangers", filter);
    const Harness = { recordInbound() {}, event() {}, error() {} };
    const own = () => lxmfHash(me);
    const ContactStore = build("ContactStore", {
        sGet, sSet, LXMF, Date,
        migrateContact: DN.migrateContact, contactName: DN.contactName, shortHash: DN.shortHash,
        cleanDisplayName: DN.clean, acceptMessageNameAt: DN.acceptMessageNameAt,
    });
    ContactStore.init();
    const GroupStore = build("GroupStore", {
        sGet, sSet, Buffer, crypto: globalThis.crypto, Date, IdMgr: { hash: null }, ownLxmfDestinationHash: own,
        RnsClient: { ownHash: own() }, PrivacyFilter: {},
    });
    GroupStore.init();
    const PrivacyFilter = build("PrivacyFilter", { sGet, sSet, ContactStore, GroupStore, Harness, LXMF, LXMessage, Buffer, ...groupRule() });
    PrivacyFilter.init();
    const MsgStore = build("MsgStore", { sGet, sSet, Harness, Date, attachmentPreview: appFunction("attachmentPreview", {}) });
    const GroupMsgStore = build("GroupMsgStore", { sGet, sSet, Date, MsgStore });
    const ChannelMsgStore = build("ChannelMsgStore", { sGet, sSet, Date, MsgStore });
    const p = { me, own, storage, Harness, ContactStore, GroupStore, PrivacyFilter, MsgStore, GroupMsgStore, ChannelMsgStore };
    p.dm = receiver(p);
    p.ui = screens(p);
    return p;
}

/** The router as connect() builds it (with the privacy filter), the real
 *  message handler behind it and the real group handler behind that.
 *  Returns deliver(packed): an opportunistic packet, settled. */
function receiver(p) {
    LXMessage.recall = appFunction("recallLxmfIdentity", {
        Buffer, Identity, Destination, IdMgr: { has: true, id: p.me }, ownLxmfDestinationHash: p.own,
        DistroManager: { has: false }, ContactStore: p.ContactStore,
    });
    const destination = new EventEmitter();
    destination.hash = Destination.hash(p.me, "lxmf", "delivery");
    const router = new LXMRouter({ registerDestination: () => destination }, p.me, { filter: p.PrivacyFilter });
    const self = { ownHash: p.own(), _onMsg: [], _pendingTickets: new Map(), _performGroupRelay() {}, _handleDistroIdentityTransfer() {} };
    install(self, {
        GroupStore: p.GroupStore, GroupMsgStore: p.GroupMsgStore, ContactStore: p.ContactStore, PrivacyFilter: p.PrivacyFilter,
        console: quiet, Date, Buffer, LXMessage, Harness: p.Harness, sentTimeMs, ownLxmfDestinationHash: p.own, Identity, Destination,
    }, [
        "_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)",
        "_applyGroupStatusChange(groupId, src, action, event = null)",
        "_holdGroupStatusChange(lxmfMsg, groupId, src, action)",
        "_decideHeldGroupChanges()",
        "_rememberGroupMemberKeys(memberKeys)",
    ]);
    router.on("message", messageHandler({
        Buffer, LxmfSeen: { check: () => false }, Harness: p.Harness, console: quiet,
        RnsClient: { ownHash: p.own() }, LXMF, LXMessage, ContactStore: p.ContactStore, MsgStore: p.MsgStore,
        decodeDisplayName: DN.decodePayload, sentTimeMs,
    })(self));
    p.rns = self;
    return async (packed) => {
        destination.emit("packet", { data: packed.subarray(16), packet: { prove() {} } });
        await settle();
    };
}

/** _handleDistroBlob for a page holding distro identity `distro`: hand it an
 *  LXMF message (full packing) addressed to the distro. */
function distroOf(p, distro = Identity.create()) {
    const handle = compile("_handleDistroBlob(distroHash, blob)", {
        DistroManager: { identity: distro, lxmfDeliveryHash: lxmfHash(distro) },
        MsgPack, Buffer, DistroSeen: { check: () => false, forget() {} }, Harness: p.Harness,
        ContactStore: p.ContactStore, MsgStore: p.MsgStore, LXMF, Cryptography, LXMessage, decodeDisplayName: DN.decodePayload,
        ownLxmfDestinationHash: p.own, console: quiet, sentTimeMs,
        DISTRO_ATTACHMENT_PLACEHOLDER: constValue("DISTRO_ATTACHMENT_PLACEHOLDER"),
    })({ ownHash: p.own(), _pendingTickets: new Map(), _onMsg: [] });
    const D = lxmfHash(distro);
    return { distro, D, deliver: (packed) => handle(null, Buffer.concat([Buffer.from(D, "hex"), distro.encrypt(packed.subarray(16))])) };
}

/** _handleChannelPacket over the page's stores: hand it a channel post's wire bytes. */
function channelOf(p) {
    return compile("_handleChannelPacket(packetData)", {
        Buffer, DistroManager: { has: false }, Harness: p.Harness, console: quiet, channelLxmUnpack, ContactStore: p.ContactStore,
        ChannelStore: { getByHash: () => ({ channelName: CHANNEL }), touch() {} }, ChannelMsgStore: p.ChannelMsgStore,
        ownLxmfDestinationHash: p.own, sentTimeMs,
        ChannelSenderNamesStore: new ChannelSenderNames({ get: p.storage.sGet, set: p.storage.sSet }),
        ChannelPostNamesStore: new ChannelPostNames({ get: p.storage.sGet, set: p.storage.sSet }),
    })({ _onMsg: [], _channelPublishes: new ChannelPublishes() });
}

// An hour ago and on, a second a message: sent before anything the user
// writes now, so a conversation's order is the order of this test.
let clock = Date.now() / 1000 - 3600;
/** A full LXMF packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content, fields = new Map()) {
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = Buffer.from(lxmfHash(from), "hex");
    m.destinationHash = Buffer.from(toHash, "hex");
    m.title = "";
    m.content = content;
    m.fields = fields;
    return m.pack(from, false);
}

// ── the screens, over a small fake DOM ─────────────────────────────────────

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
    /** The DOM's appendChild takes one node and drops any other silently
     *  (the Add Contact modal lost its buttons that way until 2026-10-02):
     *  here a second one fails the test. */
    appendChild(c, ...more) {
        assert.equal(more.length, 0, "appendChild takes one node; the DOM drops the rest");
        c.parent = this;
        this.children.push(c);
        return c;
    }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    replaceWith(next) { next.parent = this.parent; this.parent.children[this.parent.children.indexOf(this)] = next; }
    querySelector() { return null; }
    querySelectorAll() { return []; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
    *walk() { yield this; for (const c of this.children) yield* c.walk(); }
    all(pred) { return [...this.walk()].filter(pred); }
    find(pred) { return this.all(pred)[0] ?? null; }
    fire(type, event = {}) { for (const f of this.listeners[type] ?? []) f({ target: this, preventDefault() {}, ...event }); }
}
const document = {
    createElement: (tag) => new El(tag),
    createTextNode: (text) => { const t = new El("#text"); t._text = String(text); return t; },
    createDocumentFragment: () => new El("#fragment"),
    getElementById: () => null,
    body: new El("body"),
};
const h = fn("h", "tag, a={}, ...kids", { document });
const classed = (name) => (e) => e.className.split(" ").includes(name);
const button = (root, text) => root.find((e) => e.tagName === "BUTTON" && e.textContent === text);

/** App's own methods for the screens this is about, over the page's stores. */
function screens(p) {
    const paths = [];
    const env = {
        h, document, navigator: {}, ContactStore: p.ContactStore, MsgStore: p.MsgStore, GroupStore: p.GroupStore,
        ChannelStore: { getAll: () => [], get: () => null }, GroupMsgStore: p.GroupMsgStore, ChannelMsgStore: p.ChannelMsgStore,
        avatarHue: appFunction("avatarHue", {}), fmtDate: String, lastMessageTime, systemMessageText: (m) => m.content,
        DistroManager: { has: false, lxmfDeliveryHash: null }, RnsClient: { ownHash: p.own() }, ownLxmfDestinationHash: p.own,
        PrivacyFilter: p.PrivacyFilter, alert: (m) => assert.fail(`alert: ${m}`), setTimeout: () => {}, confirm: () => true,
    };
    const self = {
        state: { searchQuery: "", activeHash: null, showContactInfo: false, contactInfoHash: null, showAddContact: false, showNewConversation: false },
        root: new El("div"), paths, render() {}, openChat() {},
        _requestPathForContact: (hash) => paths.push(hash),
        _buildGroupItem: (g) => h("div", { className: "group-item" }, g.groupName),
        _buildChannelItem: () => h("div", { className: "channel-item" }),
    };
    install(self, env, [
        "_addContact(destHash, publicKey = null)",
        "_buildSidebarContent()",
        "_buildContactItem(c)",
        "_renderAddContactModal()",
        "_renderDirectForm(top, scroll, footer)",
        "_renderGroupForm(top, scroll, footer)",
        "_renderContactInfoModal()",
        "_deleteContact(c)",
    ]);
    /** RetichatTest.addPeer, as the harness calls it. */
    self.addPeer = compile("addPeer(destHash, publicKeyHex)", { ContactStore: p.ContactStore, App: self })({});
    return self;
}

/** The chat list's DM rows: [{name, preview}], the preview's text or null. */
function chatList(p) {
    return p.ui._buildSidebarContent().all(classed("contact-item")).map((e) => ({
        name: e.find(classed("contact-name")).textContent,
        preview: e.find(classed("contact-preview"))?.textContent ?? null,
    }));
}
const chatNames = (p) => chatList(p).map((r) => r.name);
/** The New Conversation form's "Contacts": each row's hash prefix (16 hex). */
function contactsScreen(p) {
    const scroll = new El("div");
    p.ui._renderDirectForm(new El("div"), scroll, new El("div"));
    return scroll.all(classed("group-member-row")).map((r) => r.textContent.match(/[0-9a-f]{16}…/)[0].slice(0, 16));
}
/** The group picker's members: each checkbox's hash. */
function groupPicker(p) {
    const scroll = new El("div");
    p.ui._renderGroupForm(new El("div"), scroll, new El("div"));
    return scroll.all(classed("group-member-check")).map((c) => c.attrs.value);
}
/** Everything the user is shown about `hash` outside the chat list. */
const offered = (p, hash) => ({ contacts: contactsScreen(p).includes(hash.slice(0, 16)), picker: groupPicker(p).includes(hash) });
/** The contact-info sheet for `hash`, drawn. */
function infoSheet(p, hash) {
    p.ui.root = new El("div");
    p.ui.state.contactInfoHash = hash;
    p.ui.state.showContactInfo = true;
    p.ui._renderContactInfoModal();
    return p.ui.root;
}
/** The user typing `text` into the field with this id, then pressing the button. */
function typeAndPress(root, id, text, label) {
    root.find((e) => e.attrs.id === id).fire("input", { target: { value: text } });
    button(root, label).fire("click");
}

// ── conversations that are no contacts ─────────────────────────────────────

test("a stranger's DM with the filter off is a conversation in the chat list, with its preview; not a contact, not offered anywhere", async () => {
    const p = page();
    assert.equal(p.PrivacyFilter.on, false, "the web's default");
    const stranger = Identity.create(), S = lxmfHash(stranger);
    await p.dm(lxm(stranger, p.own(), "hello from nowhere"));

    const row = p.ContactStore.get(S);
    assert.deepEqual([row.hidden, row.allowlisted, p.ContactStore.isContact(S)], [true, false, false], "a hidden row, not allowlisted");
    assert.deepEqual(chatList(p), [{ name: short(S), preview: "hello from nowhere" }], "the conversation, shown by its last message");
    assert.deepEqual(offered(p, S), { contacts: false, picker: false }, "not in the New Conversation list or the group picker");
    assert.deepEqual(p.ContactStore.listed(), []);

    // Its key arrives (an announce), and the user writes back: allowlisted
    // (the web's departure, sendMessage), still no contact.
    p.ContactStore.updateFromAnnounce(S, { appData: null, identity: stranger });
    const send = compile("sendMessage(contact, content, attachments = [])", { ContactStore: p.ContactStore, MsgStore: p.MsgStore, console: quiet })({
        _initialized: false, sendingIdentity: () => ({ hash: p.own() }),
    });
    send(p.ContactStore.get(S), "hello back");
    assert.deepEqual([p.ContactStore.allowlisted(S), p.ContactStore.get(S).hidden], [true, true], "allowlisting lists nothing");
    assert.deepEqual(chatList(p), [{ name: short(S), preview: "You: hello back" }]);
    assert.deepEqual(offered(p, S), { contacts: false, picker: false });

    // A reload shows the same.
    const again = page({ me: p.me, storage: p.storage });
    assert.deepEqual([chatNames(again), offered(again, S)], [[short(S)], { contacts: false, picker: false }]);
});

test("a distro message and a distro sent copy are conversations, not contacts", () => {
    const p = page();
    const d = distroOf(p);
    const sender = Identity.create(), S = lxmfHash(sender);
    assert.equal(d.deliver(lxm(sender, d.D, "to your distro")), true);
    assert.deepEqual([p.ContactStore.get(S).hidden, p.ContactStore.allowlisted(S)], [true, false]);

    // Another device of this distro wrote to R and propagated its copy here.
    const R = lxmfHash(Identity.create());
    const copy = new Map([[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_SENT_TYPE], [LXMF.FIELD_CUSTOM_DATA, R], [LXMF.FIELD_CUSTOM_META, "fe".repeat(16)]]);
    assert.equal(d.deliver(lxm(d.distro, d.D, "sent on the phone", copy)), true);
    assert.equal(p.ContactStore.get(R).hidden, true, "the recipient of the user's own message is no contact either");

    assert.deepEqual(chatList(p).sort((a, b) => a.name.localeCompare(b.name)),
        [{ name: short(S), preview: "to your distro" }, { name: short(R), preview: "You: sent on the phone" }]
            .sort((a, b) => a.name.localeCompare(b.name)));
    assert.deepEqual([offered(p, S), offered(p, R)], [{ contacts: false, picker: false }, { contacts: false, picker: false }]);
});

test("a channel post lists nothing anywhere: the poster's hidden row holds its key, with the filter off and on", async () => {
    for (const filter of [null, true]) {
        const p = page({ filter });
        const poster = Identity.create(), P = lxmfHash(poster);
        assert.equal(channelOf(p)(channelLxmPack(CHANNEL, poster, "hi all", DN.nameState("Pseud")).wire), true);
        p.ContactStore.updateFromAnnounce(P, { appData: MsgPack.pack([Buffer.from("Poster"), null]), identity: poster });
        const row = p.ContactStore.get(P);
        assert.deepEqual([row.hidden, row.allowlisted, row.publicKey], [true, false, keyHex(poster)], "kept by association");
        assert.deepEqual(chatList(p), [], "no chat-list entry, no 'Tap to chat'");
        assert.deepEqual(offered(p, P), { contacts: false, picker: false });
        assert.deepEqual(chatList(page({ me: p.me, storage: p.storage })), [], "nor after a reload");
    }
});

test("a group invite and the user's accept keep every member by association: allowed, never listed; a member's DM is a conversation", async () => {
    const p = page();
    // Fay is a contact the user added (her key from her lxma:// link); she
    // invites the user to a group with Bob, whose key the invite carries.
    const fay = Identity.create(), bob = Identity.create(), F = lxmfHash(fay), B = lxmfHash(bob);
    p.ui._addContact(F, keyHex(fay));
    const G = "9".repeat(32);
    await p.dm(lxm(fay, p.own(), "", new Map([[GROUP_FIELDS.GROUP_ID, G], [GROUP_FIELDS.GROUP_ACTION, "invite"],
        [GROUP_FIELDS.GROUP_NAME, "Walkers"], [GROUP_FIELDS.GROUP_MEMBERS, `${F},${B},${p.own()}`],
        [GROUP_FIELDS.GROUP_MEMBER_KEYS, `${B}:${bob.getPublicKey().toString("base64")}`]])));
    assert.equal(p.GroupStore.get(G)?.groupStatus, "pending", "the invite arrived");
    assert.deepEqual([p.ContactStore.get(B).hidden, p.ContactStore.get(B).publicKey], [true, keyHex(bob)], "Bob's key, hidden");

    // The user accepts (the real _acceptGroupInvite): every member allowed.
    compile("_acceptGroupInvite(groupId)", {
        GroupStore: p.GroupStore, ContactStore: p.ContactStore, GroupMsgStore: p.GroupMsgStore, console: quiet,
        RnsClient: { ownHash: p.own(), _decideHeldGroupChanges() {}, _requestGroupPeer() {}, sendGroupAccept: async () => {} },
        alert: (m) => assert.fail(m),
    })({ render() {} })(G);
    assert.equal(p.GroupStore.get(G).groupStatus, "active");
    assert.deepEqual([p.ContactStore.allowlisted(B), p.ContactStore.get(B).hidden], [true, true], "allowed, still hidden");

    // Bob posts in the group: still nowhere.
    await p.dm(lxm(bob, p.own(), "hi group", new Map([[GROUP_FIELDS.GROUP_ID, G]])));
    assert.equal(p.GroupMsgStore.get(G).some((m) => m.content === "hi group"), true);
    assert.deepEqual(chatList(p), [{ name: short(F), preview: "Tap to chat" }], "only Fay, the contact (the group is its own row)");
    assert.deepEqual(offered(p, B), { contacts: false, picker: false });
    assert.deepEqual([contactsScreen(p), groupPicker(p)], [[F.slice(0, 16)], [F]], "Fay is offered, Bob is not");

    // With the filter on, Bob's DM passes (allowed by the accept) and is a
    // conversation, not a contact.
    p.PrivacyFilter.set(true);
    await p.dm(lxm(bob, p.own(), "psst"));
    assert.deepEqual(p.MsgStore.get(B).map((m) => m.content), ["psst"]);
    assert.equal(p.ContactStore.get(B).hidden, true);
    assert.deepEqual(chatList(p).find((r) => r.name === short(B)), { name: short(B), preview: "psst" });
    assert.deepEqual(offered(p, B), { contacts: false, picker: false });
});

// ── what the user adds ─────────────────────────────────────────────────────

test("Add Contact, New Conversation (a hash, lxmf:// or lxma:// link) and addPeer list a contact, allowlisted, with 'Tap to chat'", () => {
    const p = page();
    const [a, b, c, d] = [Identity.create(), Identity.create(), Identity.create(), Identity.create()];
    const [A, B, C, D] = [a, b, c, d].map(lxmfHash);

    p.ui.state.showAddContact = true;
    p.ui._renderAddContactModal();
    typeAndPress(p.ui.root, "add-hash", A.toUpperCase(), "Add Contact");
    assert.equal(p.ui.state.showAddContact, false, "the modal closes");

    const form = () => { const top = new El("div"), footer = new El("div"); p.ui._renderDirectForm(top, new El("div"), footer); return { top, footer }; };
    for (const link of [`lxma://${B}:${keyHex(b)}`, `lxmf://${C}`]) {
        const f = form();
        f.top.find((e) => e.attrs.id === "nc-direct-hash").fire("input", { target: { value: link } });
        button(f.footer, "Add Contact").fire("click");          // the form's footer holds its button
    }
    p.ui.addPeer(D, keyHex(d));

    for (const X of [A, B, C, D]) {
        const row = p.ContactStore.get(X);
        assert.deepEqual([row.hidden, row.allowlisted], [false, true], X);
        assert.deepEqual(offered(p, X), { contacts: true, picker: true }, X);
    }
    assert.equal(p.ContactStore.get(B).publicKey, keyHex(b), "the lxma:// link's key");
    assert.deepEqual(p.ui.paths.sort(), [A, B, C].sort(), "a path asked for each the user added (addPeer with a key asks none)");
    assert.deepEqual(chatList(p).map((r) => r.preview), ["Tap to chat", "Tap to chat", "Tap to chat", "Tap to chat"],
        "a contact with no message yet: iOS and Android show the chat with an empty preview");
});

test("adding someone the client already holds keeps their conversation and key: the contact shows its last message", async () => {
    const p = page();
    const stranger = Identity.create(), S = lxmfHash(stranger);
    await p.dm(lxm(stranger, p.own(), "remember me?"));
    p.ContactStore.get(S).publicKey = keyHex(stranger);
    p.ui._addContact(S);
    assert.deepEqual([p.ContactStore.isContact(S), p.ContactStore.get(S).publicKey], [true, keyHex(stranger)]);
    assert.deepEqual(chatList(p), [{ name: short(S), preview: "remember me?" }]);
    assert.deepEqual(offered(p, S), { contacts: true, picker: true });
});

test("'Add contact' on a conversation's contact-info sheet makes it a contact; a contact's sheet has none", async () => {
    const p = page();
    const stranger = Identity.create(), S = lxmfHash(stranger);
    await p.dm(lxm(stranger, p.own(), "hi"));
    const sheet = infoSheet(p, S);
    assert.match(sheet.find((e) => e.attrs.id === "ci-add-contact").textContent, /Not in your contacts\./);
    const name = sheet.find((e) => e.attrs.id === "ci-display-name");
    button(sheet, "Add contact").fire("click");
    assert.deepEqual([p.ContactStore.isContact(S), p.ContactStore.allowlisted(S)], [true, true], "listed and allowlisted, as Add Contact does");
    assert.deepEqual(p.ui.paths, [S], "its path asked for");
    assert.deepEqual(offered(p, S), { contacts: true, picker: true });
    assert.equal(sheet.find((e) => e.attrs.id === "ci-add-contact").textContent, "Added to your contacts.", "the button gives way to a line");
    assert.equal(sheet.find((e) => e.attrs.id === "ci-display-name"), name, "the rest of the sheet stays, a typed name with it");
    assert.equal(button(sheet, "Add contact"), null);

    assert.equal(infoSheet(p, S).find((e) => e.attrs.id === "ci-add-contact"), null, "a contact's sheet offers no 'Add contact'");
});

// ── the chat list's rows ───────────────────────────────────────────────────

test("a conversation never shows 'Tap to chat', not even for a message with no text and no attachment; a contact's shows it only with no message", async () => {
    const p = page();
    const stranger = Identity.create(), S = lxmfHash(stranger);
    await p.dm(lxm(stranger, p.own(), ""));
    assert.equal(p.MsgStore.get(S).length, 1, "stored");
    assert.equal(p.MsgStore.preview(S), "", "nothing to preview");
    assert.deepEqual(chatList(p), [{ name: short(S), preview: "" }], "an empty preview, never 'Tap to chat'");

    const friend = Identity.create(), F = lxmfHash(friend);
    p.ui._addContact(F, keyHex(friend));
    assert.deepEqual(chatList(p).find((r) => r.name === short(F)).preview, "Tap to chat");
    await p.dm(lxm(friend, p.own(), ""));
    assert.deepEqual(chatList(p).find((r) => r.name === short(F)).preview, "", "a contact with a message: its preview, empty or not");
    assert.equal(chatList(p).some((r) => r.preview === "Tap to chat"), false);
});

test("deleting a conversation that is no contact keeps the hidden row (a group still needs the key); deleting a contact's removes the contact", async () => {
    const p = page();
    const member = Identity.create(), M = lxmfHash(member);
    p.ContactStore.keep(M, keyHex(member));
    p.ContactStore.allow(M);                       // a member of a group the user accepted
    await p.dm(lxm(member, p.own(), "a DM"));
    assert.deepEqual(chatNames(p), [short(M)]);
    p.ui._deleteContact(p.ContactStore.get(M));
    assert.deepEqual(p.MsgStore.get(M), [], "the conversation is gone");
    const row = p.ContactStore.get(M);
    assert.deepEqual([row?.hidden, row?.publicKey, row?.allowlisted], [true, keyHex(member), true], "the row stays as it was");
    assert.deepEqual(chatList(p), [], "and leaves the chat list");

    // "Add contact" then "Delete Conversation" on the same sheet: a contact now.
    await p.dm(lxm(member, p.own(), "again"));
    const sheet = infoSheet(p, M);
    button(sheet, "Add contact").fire("click");
    button(sheet, "🗑 Delete Conversation").fire("click");
    assert.equal(p.ContactStore.get(M), null, "a contact goes with its conversation, as before");

    const friend = lxmfHash(Identity.create());
    p.ui._addContact(friend);
    p.ui._deleteContact(p.ContactStore.get(friend));
    assert.equal(p.ContactStore.get(friend), null);
});

// ── no clean-up ────────────────────────────────────────────────────────────

test("no clean-up: a row an older build stored without the hidden key stays a contact, 'Tap to chat' and all; a post from it changes nothing", () => {
    const storage = memoryStorage();
    const poster = Identity.create(), P = lxmfHash(poster);
    // As 7af5969 stored a channel poster it listed by itself.
    storage.sSet("contacts_v2", [{ destHash: P, displayName: `?${P.slice(0, 8)}`, publicKey: null, nameCustomized: false,
        addedAt: 1, lastSeen: 1, reachable: null, isDistro: false }]);
    const p = page({ storage });
    assert.equal("hidden" in p.ContactStore.get(P), false, "nothing writes the flag in");
    assert.deepEqual(chatList(p), [{ name: short(P), preview: "Tap to chat" }]);
    assert.deepEqual(offered(p, P), { contacts: true, picker: true });
    assert.equal(channelOf(p)(channelLxmPack(CHANNEL, poster, "still here", DN.nameState("Pseud")).wire), true);
    assert.deepEqual([p.ContactStore.isContact(P), chatList(p).length], [true, 1], "keep() leaves a contact a contact");
});

// ── the source: one way in ─────────────────────────────────────────────────

test("a contact is made only by the user: ContactStore.add has one caller, _addContact, and only the user's acts call that", () => {
    const occurrences = (text, needle) => text.split(needle).length - 1;
    assert.equal(occurrences(app, "ContactStore.add("), 1, "one call of ContactStore.add in app.js");
    assert.equal(occurrences(methodBody("_addContact(destHash, publicKey = null)"), "ContactStore.add("), 1, "... in _addContact");

    // The user's acts: Add Contact, New Conversation, the contact-info
    // sheet's "Add contact", and RetichatTest.addPeer standing in for them.
    const explicit = ["_renderAddContactModal()", "_renderDirectForm(top, scroll, footer)", "_renderContactInfoModal()", "addPeer(destHash, publicKeyHex)"];
    const calls = /\b(?:this|App)\._addContact\(/g;
    const inExplicit = explicit.map((s) => (methodBody(s).match(calls) ?? []).length);
    assert.ok(inExplicit.every((n) => n === 1), `each calls it once: ${inExplicit}`);
    assert.equal((app.match(calls) ?? []).length, inExplicit.reduce((a, b) => a + b), "and nothing else does");

    // Inside the store, only add() stores a row unhidden; nothing anywhere
    // writes the flag but _row.
    const store = objectLiteral("ContactStore");
    assert.deepEqual([...store.matchAll(/this\._put\(([^)]*)\)/g)].map((m) => m[1]),
        ["destHash, isDistro, publicKey, false", "destHash, false, publicKey, true, nameOnly"], "add() and keep()");
    assert.doesNotMatch(app, /\.hidden\s*=(?!=)/, "no assignment to a row's flag");
    assert.doesNotMatch(app, /\bhidden:\s*(?:false|0|null)\b/, "no row literal written unhidden");

    // The surfaces: the chat list shows chats(), the two that offer contacts listed().
    assert.match(methodBody("_buildSidebarContent()"), /ContactStore\.chats\(\(hash\) => MsgStore\.get\(hash\)\.length > 0\)/);
    for (const s of ["_renderDirectForm(top, scroll, footer)", "_renderGroupForm(top, scroll, footer)"]) {
        assert.match(methodBody(s), /const contacts = ContactStore\.listed\(\);/, s);
    }
});
