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
function makeResume({ rfedLink = null, propLink = null, distro = true, held = true, connected = true } = {}) {
    const calls = [];
    const self = {
        _rns: connected ? {} : null,
        _rfedLinks: new Map(rfedLink ? [["link", rfedLink]] : []),
        _rfedReopenArmed: new Set(),
        _propReopenArmed: false,
        _propLink: propLink,
        _pullOpenedChannels: (trigger) => calls.push(`pull channels (${trigger})`),
        _pullDistroMessages: () => calls.push("pull distro"),
        _redriveRfedLink: (key, trigger) => calls.push(`redrive ${key} (${trigger})`),
        _fetchPropagatedMessages: () => calls.push("fetch propagated"),
        _redrivePropagationLink: (trigger) => calls.push(`redrive propagation (${trigger})`),
    };
    const env = { ActiveTab: { held }, DistroManager: { has: distro }, Link, RFED_PERSISTENT_KEYS, console: quiet };
    self._onPageResume = compile("_onPageResume(trigger)", env)(self);
    return { self, calls };
}

test("a resume with the links up pulls: the opened channels, the distro, and the propagation node", () => {
    const { self, calls } = makeResume({ rfedLink: { status: Link.ACTIVE }, propLink: { status: Link.ACTIVE } });
    self._onPageResume("visible");
    assert.deepEqual(calls, ["pull channels (visible)", "pull distro", "fetch propagated"]);
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
    assert.deepEqual(calls, ["pull channels (visible)", "fetch propagated"]);
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

test("the resume path schedules nothing", () => {
    for (const signature of ["_hookPageLifecycle()", "_unhookPageLifecycle()", "_onPageResume(trigger)"]) {
        assert.doesNotMatch(extractMethod(signature), /setTimeout|setInterval/, `${signature}: events, never a clock`);
    }
});
