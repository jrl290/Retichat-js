/**
 * REGRESSION GUARD — the page coming back re-drives the persistent links.
 *
 * Android pulls an open channel on every ON_RESUME (ConversationScreen.kt
 * 618-635) and re-opens its links on a network change
 * (ConnectionStateManager.kt onNetworkReconnect); iOS re-opens the rfed link,
 * syncs the propagation node and pulls the distro on scenePhase .active
 * (RetichatApp.swift 281-310). Until 2026-09-30 the web client did none of
 * it: a tab that came back online or visible after its links died (hidden
 * tabs' timers are throttled) got nothing until the next reload.
 *
 * RnsClient hooks window "online", document "visibilitychange" to visible
 * and "pageshow" from the back/forward cache once per connection, and
 * disconnect() unhooks them. Each is an explicit event (_onPageResume): it
 * arms every persistent link's one-shot re-open, re-drives a link that is
 * down, and pulls on one that is up. Only the tab holding the identity does
 * anything.
 *
 * The exchange coming back after it went down is the same event
 * (_followExchange), the web's interface up-edge (app-links
 * interface_online): without it an outage long enough to time the links out
 * left a visible, idle tab without them, since rfed announces every 6 h.
 * While the exchange is down nothing is re-driven (_exchangeIsDown).
 *
 * These run the real shipped method bodies from app.js against stubs.
 * Run: node --test page_resume.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Link from "./lib/rns/link.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

function extractMethod(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const open = app.indexOf("{", start + signature.length);
    let depth = 0;
    for (let i = open; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}" && --depth === 0) return app.slice(open + 1, i);
    }
    throw new Error(`could not brace-match ${signature}`);
}

function compile(signature, env) {
    const body = extractMethod(signature).replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
        .split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params, body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

const RFED_PERSISTENT_KEYS = new Function(`return ${/\nconst RFED_PERSISTENT_KEYS = (\[[^\]]*\]);/.exec(app)[1]};`)();
const quiet = { log() {}, warn() {}, error() {} };

/** A page: window and document as event targets, the document's visibility settable. */
function makePage() {
    const window = new EventTarget();
    const document = new EventTarget();
    document.visibilityState = "hidden";
    const pageshow = (persisted) => Object.assign(new Event("pageshow"), { persisted });
    return { window, document, pageshow };
}

function makeHooks(page) {
    const resumes = [];
    const self = { _pageHooks: null, _onPageResume: (trigger) => resumes.push(trigger) };
    const env = { window: page.window, document: page.document };
    self._hookPageLifecycle = compile("_hookPageLifecycle()", env)(self);
    self._unhookPageLifecycle = compile("_unhookPageLifecycle()", env)(self);
    return { self, resumes };
}

test("online, visible and a return from the back/forward cache each resume the page, once per event", () => {
    const page = makePage();
    const { self, resumes } = makeHooks(page);
    self._hookPageLifecycle();
    self._hookPageLifecycle(); // a second connect() must not hook twice

    page.window.dispatchEvent(new Event("online"));
    assert.deepEqual(resumes, ["online"]);

    page.document.visibilityState = "hidden";
    page.document.dispatchEvent(new Event("visibilitychange"));
    assert.deepEqual(resumes, ["online"], "going hidden is not a resume");
    page.document.visibilityState = "visible";
    page.document.dispatchEvent(new Event("visibilitychange"));
    assert.deepEqual(resumes, ["online", "visible"]);

    page.window.dispatchEvent(page.pageshow(false));
    assert.deepEqual(resumes, ["online", "visible"], "a fresh load is not a resume: connect() is running");
    page.window.dispatchEvent(page.pageshow(true));
    assert.deepEqual(resumes, ["online", "visible", "pageshow"]);

    self._unhookPageLifecycle();
    page.window.dispatchEvent(new Event("online"));
    page.document.dispatchEvent(new Event("visibilitychange"));
    page.window.dispatchEvent(page.pageshow(true));
    assert.equal(resumes.length, 3, "a stopped connection hears nothing");
    assert.equal(self._pageHooks, null);
});

test("without a window (Node, a worker) nothing is hooked", () => {
    const self = { _pageHooks: null };
    compile("_hookPageLifecycle()", { window: undefined, document: undefined })(self)();
    assert.equal(self._pageHooks, null);
});

test("connect() hooks the page events and disconnect() unhooks them", () => {
    assert.match(extractMethod("async connect()"), /this\._hookPageLifecycle\(\);/);
    assert.match(extractMethod("disconnect()"), /this\._unhookPageLifecycle\(\);/);
});

/** _onPageResume over recorded stubs. */
function makeResume({ rfedLink = null, propLink = null, distro = true, held = true, connected = true, exchangeDown = false } = {}) {
    const calls = [];
    const self = {
        _rns: connected ? {} : null,
        _exchangeIsDown: () => exchangeDown,
        _rfedLinks: new Map(rfedLink ? [["link", rfedLink]] : []),
        _rfedReopenArmed: new Set(),
        _propReopenArmed: false,
        _propLink: propLink,
        _pullChannelOnScreen: (trigger) => calls.push(`pull channel on screen (${trigger})`),
        _pullDistroMessages: () => calls.push("pull distro"),
        _redriveRfedLink: (key, trigger) => calls.push(`redrive ${key} (${trigger})`),
        _fetchPropagatedMessages: () => calls.push("fetch propagated"),
        _redrivePropagationLink: (trigger) => calls.push(`redrive propagation (${trigger})`),
    };
    const env = { ActiveTab: { held }, DistroManager: { has: distro }, Link, RFED_PERSISTENT_KEYS, console: quiet };
    self._onPageResume = compile("_onPageResume(trigger)", env)(self);
    return { self, calls };
}

test("a resume with the links up pulls: the channel on screen, the distro, and the propagation node", () => {
    const { self, calls } = makeResume({ rfedLink: { status: Link.ACTIVE }, propLink: { status: Link.ACTIVE } });
    self._onPageResume("visible");
    assert.deepEqual(calls, ["pull channel on screen (visible)", "pull distro", "fetch propagated"]);
    assert.deepEqual([...self._rfedReopenArmed].sort(), [...RFED_PERSISTENT_KEYS].sort(), "every persistent link's re-open is armed");
    assert.equal(self._propReopenArmed, true);
});

test("a resume with the links down re-drives them; their \"established\" pulls", () => {
    const { self, calls } = makeResume({ rfedLink: null, propLink: null });
    self._onPageResume("online");
    assert.deepEqual(calls, ["redrive link (online)", "redrive propagation (online)"]);

    // A STALE rfed.link is not up: the re-drive decides (it leaves a STALE
    // or establishing link to its own watchdog).
    const stale = makeResume({ rfedLink: { status: Link.STALE }, propLink: { status: Link.STALE } });
    stale.self._onPageResume("pageshow");
    assert.deepEqual(stale.calls, ["redrive link (pageshow)", "redrive propagation (pageshow)"]);
});

test("no distro, no distro pull", () => {
    const { self, calls } = makeResume({ rfedLink: { status: Link.ACTIVE }, propLink: { status: Link.ACTIVE }, distro: false });
    self._onPageResume("visible");
    assert.deepEqual(calls, ["pull channel on screen (visible)", "fetch propagated"]);
});

test("a resume while the exchange is still down arms the links and does nothing else; the exchange's return does the rest", () => {
    // A pull sent now would lose its request (PostInterface.sendData) and,
    // in flight until its timeout, take the place of the pull the return
    // makes (the in-flight guards).
    const up = makeResume({ rfedLink: { status: Link.ACTIVE }, propLink: { status: Link.ACTIVE }, exchangeDown: true });
    up.self._onPageResume("online");
    assert.deepEqual(up.calls, [], "no pull on the links that are still up");
    assert.deepEqual([...up.self._rfedReopenArmed].sort(), [...RFED_PERSISTENT_KEYS].sort(), "but the event arms their re-open");
    assert.equal(up.self._propReopenArmed, true);

    const down = makeResume({ exchangeDown: true });
    down.self._onPageResume("visible");
    assert.deepEqual(down.calls, [], "and no re-drive of the ones that are down");
});

test("a tab without the lock, or a stopped connection, does nothing on resume", () => {
    const blocked = makeResume({ held: false });
    blocked.self._onPageResume("visible");
    assert.deepEqual(blocked.calls, [], "another tab owns the identity");
    assert.equal(blocked.self._rfedReopenArmed.size, 0, "and nothing is armed");

    const stopped = makeResume({ connected: false });
    stopped.self._onPageResume("online");
    assert.deepEqual(stopped.calls, []);
});

test("every page event pulls the channel on screen only, not every channel opened this session (Android ON_RESUME, iOS .active)", () => {
    // Android pulls on ON_RESUME from the channel's own screen
    // (ConversationScreen.kt:618-635), iOS from its channel view: a channel
    // opened earlier and left is pulled when it is opened again. Until
    // 2026-10-01 each event pulled every channel opened this session.
    const rows = ["alpha", "beta", "gamma", "left"].map((name) => ({
        channelName: name, channelHash: Buffer.from(name.padEnd(16, "_")).toString("hex"), isSubscribed: name !== "left" }));
    const ChannelStore = { get: (name) => rows.find((r) => r.channelName === name) ?? null, getAll: () => rows };
    const pulls = [];
    const screen = { name: "beta" };
    const self = {
        _rns: {},
        _exchangeIsDown: () => false,
        _rfedLinks: new Map([["link", { status: Link.ACTIVE }]]),
        _rfedReopenArmed: new Set(),
        _propReopenArmed: false,
        _propLink: null,
        _rfedOpenedChannelHashes: new Set(rows.filter((r) => r.channelName !== "gamma").map((r) => r.channelHash)),
        _rfedPullState: new Map(),
        channelOnScreen: () => screen.name,
        pullChannel: async (name) => { pulls.push(name); },
        _pullDistroMessages: () => {},
        _redrivePropagationLink: () => {},
    };
    const env = { ActiveTab: { held: true }, DistroManager: { has: false }, Link, RFED_PERSISTENT_KEYS, ChannelStore, console: quiet };
    self._pullChannelOnScreen = compile("_pullChannelOnScreen(trigger, generation = null)", env)(self);
    self._onPageResume = compile("_onPageResume(trigger)", env)(self);

    for (const trigger of ["visible", "online", "pageshow", "exchange back"]) self._onPageResume(trigger);
    assert.deepEqual(pulls, ["beta", "beta", "beta", "beta"], "beta, on screen, once per event; alpha, opened earlier, never");

    pulls.length = 0;
    for (const [name, why] of [[null, "no channel on screen (a DM or the chat list)"], ["gamma", "a channel never opened"],
        ["left", "a channel left (not subscribed)"], ["nosuch", "a name that is no channel"]]) {
        screen.name = name;
        self._onPageResume("visible");
        assert.deepEqual(pulls, [], why);
    }

    // The UI says which channel is on screen: the open chat, when it is a channel.
    assert.match(extractMethod("_wire()"),
        /RnsClient\.channelOnScreen = \(\) => \(this\.state\.activeHash && ChannelStore\.get\(this\.state\.activeHash\) \? this\.state\.activeHash : null\);/);
});

/** _followExchange over a stand-in exchange that emits as PostInterface does. */
function makeExchange() {
    const listeners = new Map();
    const iface = { on: (type, fn) => listeners.set(type, [...(listeners.get(type) ?? []), fn]) };
    const emit = (type, arg) => (listeners.get(type) ?? []).forEach((fn) => fn(arg));
    const statuses = [];
    const resumes = [];
    const self = {
        _rns: { interfaces: [iface] },
        _setStatus: (s) => statuses.push(s),
        _onExchangeRegistered() {},
        _onPacketsLost() {},
        _onPageResume: (trigger) => resumes.push(trigger),
    };
    compile("_followExchange(iface)", {})(self)(iface);
    return { self, emit, statuses, resumes };
}

test("the exchange coming back resumes the persistent links; its first \"up\" is initialization", () => {
    const x = makeExchange();
    x.emit("up");
    assert.deepEqual(x.resumes, [], "the connection's first up: the registration and the announces drive the start (§5)");
    x.emit("down", "fetch failed");
    assert.deepEqual(x.resumes, [], "going down re-drives nothing");
    x.emit("up");
    assert.deepEqual(x.resumes, ["exchange back"], "back after an outage: the web's interface up-edge (app-links interface_online)");
    assert.deepEqual(x.statuses, ["online", "offline", "online"], "the status dot still follows the exchange");
    x.emit("up");
    assert.deepEqual(x.resumes, ["exchange back"], "an up with no down before it is not a return");
    x.emit("down", "a");
    x.emit("down", "b");
    x.emit("up");
    assert.deepEqual(x.resumes, ["exchange back", "exchange back"], "one resume per return");

    // A page opened offline: its first up follows a down, and is still initialization.
    const offline = makeExchange();
    offline.emit("down", "offline");
    offline.emit("up");
    assert.deepEqual(offline.resumes, []);

    // An interface disconnect() stopped is no longer this connection's.
    const stopped = makeExchange();
    stopped.emit("up");
    stopped.emit("down", "x");
    stopped.self._rns = null;
    stopped.emit("up");
    assert.deepEqual(stopped.resumes, []);
});

test("the resume path schedules nothing", () => {
    for (const signature of ["_hookPageLifecycle()", "_unhookPageLifecycle()", "_onPageResume(trigger)", "_followExchange(iface)"]) {
        assert.doesNotMatch(extractMethod(signature), /setTimeout|setInterval/, `${signature}: events, never a clock`);
    }
});
