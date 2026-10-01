/**
 * A SAVED EXCHANGE URL THE PAGE'S POLICY BLOCKS IS SAID AT LOAD.
 *
 * Settings refuses an exchange URL the page's Content-Security-Policy would
 * block (a71c32a, exchange_url_policy.test.mjs). One saved before that, or
 * edited in storage, still left the page offline with nothing to say why:
 * the browser refuses each request to it before it is sent, and the status
 * dot only turned red. Now, as the page connects, a saved exchange URL other
 * than the node's own is checked with the same check Settings makes
 * (PagePolicy, lib/connect_policy.js), alongside the connection
 * (RnsClient._checkSavedExchange): nothing waits on it. The browser's own
 * refusal of a request to the exchange, the securitypolicyviolation event
 * it fires on the document, is heard too, for any exchange URL
 * (RnsClient._watchExchangeRefusal), so a blocked one is found even when
 * the page's server never answers the policy read. Whichever comes first,
 * a blocked one has
 * its interface stopped (PostInterface.block: never asked again), the
 * status is "blocked", and the page says so where it shows the connection
 * status, under the status dot ("This exchange is blocked by the page's
 * security policy; change it in Settings.", with a button to Settings,
 * whose exchange field then says why). The client behind it is built as
 * for any URL, so the page works as it does while the exchange is down (an
 * invite can be accepted). Changing the URL in Settings reconnects, and the
 * line goes.
 *
 * Until 2026-10-01 (review of e48ede8) connect() awaited the check first:
 * a blocked URL returned before the router was built, so an accept said
 * keys were missing or threw halfway, and a policy read the page's server
 * never answered kept even an allowed exchange from ever being asked.
 *
 * The node's own URL (config.json, or the default) is never checked: it is
 * served beside the policy, and deploy.sh's boot gate fails on any
 * violation. A policy that cannot be read decides nothing: the saved URL
 * stays connected, unchecked, and the console says so. A read that has not
 * answered in 5 s is a §1 failure, said then. Until 2026-10-01 (b9f525a) a
 * blocked saved URL whose policy read went unanswered was said nowhere,
 * its interface asking again every reconnect wait, each request refused.
 *
 * These run the real shipped code from app.js (loadConfig, PagePolicy,
 * RnsClient.connect up to its router, _checkSavedExchange,
 * _watchExchangeRefusal, _exchangeIsBlocked, App._applyStatusDot, h) over
 * stubs. Three tests (RETICHAT_BOOT_TESTS=1, as deploy.sh runs the suite)
 * load the real page in Chromium under the .htaccess policy.
 * PostInterface.block is in exchange_truth.test.mjs; how a violation is
 * read (exchangeRefusalFromViolation), against Chromium's own events, in
 * exchange_url_policy.test.mjs.
 *
 * Run: node --test exchange_url_at_load.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { exchangeUrlRefusal, exchangeRefusalFromViolation } from "./lib/connect_policy.js";
import { Identity, Destination } from "./lib/rns/reticulum.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { app, build, compile, constValue, fn, methodBody } from "./test_app_source.mjs";

const htaccess = readFileSync(new URL("./.htaccess", import.meta.url), "utf8");
const POLICY = htaccess.match(/^\s*Header\s+(?:always\s+)?set\s+Content-Security-Policy\s+"([^"]+)"\s*$/m)[1];
const PAGE = "https://retichat.com/";
const BLOCKED = "https://other-node.example/reticulum";       // a host the policy names nowhere
const ALLOWED = "https://selectivesubconscious.com/reticulum"; // a production exchange it names
const NOTICE = "This exchange is blocked by the page's security policy; change it in Settings.";

/** A response as fetch gives it: a status and its headers. */
const response = (status, headers = {}) => ({
    ok: status >= 200 && status < 300, status,
    headers: new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
    body: { cancel: async () => {} },
    json: async () => JSON.parse(headers["x-json"] ?? "{}"),
});
const servedWithPolicy = () => response(200, { "Content-Security-Policy": POLICY });

/** The real PagePolicy over a page at `href` served by `serve`; what it
 *  warns goes to `warnings`, what it says as an error to `errors`. Its
 *  timers are captured (`timers`) and fired by hand. */
function pagePolicy(serve, href = PAGE, warnings = [], errors = []) {
    const fetched = [];
    const timers = [];
    const PagePolicy = build("PagePolicy", {
        fetch: async (url, init) => { fetched.push([url, init?.cache]); return serve(url, init); },
        location: { href }, exchangeUrlRefusal, Date,
        setTimeout: (fn, ms) => { const timer = { fn, ms, cleared: false }; timers.push(timer); return timer; },
        clearTimeout: (timer) => { if (timer) timer.cleared = true; },
        console: { log() {}, error: (m) => errors.push(m), warn: (m) => warnings.push(m) },
    });
    return { PagePolicy, fetched, warnings, errors, timers };
}

// ── PagePolicy.blockedReason ───────────────────────────────────────────────

test("PagePolicy.blockedReason: the reason the served policy blocks a saved exchange, null for one it allows; an unreadable policy decides nothing and says so", async () => {
    const p = pagePolicy(servedWithPolicy);
    const reason = await p.PagePolicy.blockedReason(BLOCKED);
    assert.equal(reason, exchangeUrlRefusal(BLOCKED, POLICY, PAGE), "the check Settings makes (lib/connect_policy.js)");
    assert.match(reason, /The exchange https:\/\/other-node\.example\/reticulum is not among them/);
    assert.doesNotMatch(reason, /Not saved/, "nothing was being saved");
    assert.equal(await p.PagePolicy.blockedReason(ALLOWED), null);
    assert.deepEqual(p.fetched, [[PAGE, "no-store"]], "the policy read once, from the page's own URL, past the cache");
    assert.match(await p.PagePolicy.exchangeRefusal(BLOCKED), /is not among them.* Not saved\.$/, "Settings, after it: the same reason, and no second read");
    assert.equal(p.fetched.length, 1);

    for (const fail of [() => { throw new TypeError("Failed to fetch"); }, () => response(500)]) {
        const q = pagePolicy(fail);
        assert.equal(await q.PagePolicy.blockedReason(BLOCKED), null, "unread, the policy decides nothing");
        assert.match(q.warnings[0], /^\[retichat\] Could not read this page's Content-Security-Policy \((Failed to fetch|HTTP 500)\): the saved exchange URL https:\/\/other-node\.example\/reticulum is used unchecked$/);
    }

    const local = pagePolicy(() => response(200, {}), "http://127.0.0.1:8000/");
    assert.equal(await local.PagePolicy.blockedReason("http://127.0.0.1:8080"), null, "a page served with no policy blocks nothing");
});

test("PagePolicy.header: a read its server has not answered in 5 s is a §1 failure, said then; one answered in time says nothing", async () => {
    // DESIGN_PRINCIPLES.md §1: a fetch has no deadline, so a read never
    // answered would otherwise never be heard of. It decides nothing.
    const hung = pagePolicy(() => new Promise(() => {}));
    hung.PagePolicy.header();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(hung.timers.map((x) => [x.ms, x.cleared]), [[5000, false]], "armed as the read starts");
    assert.deepEqual(hung.errors, []);
    hung.timers[0].fn();
    assert.equal(hung.errors.length, 1);
    assert.match(hung.errors[0], /§1: this page's own server has not answered the read of its Content-Security-Policy in 5 s/);

    for (const serve of [servedWithPolicy, () => { throw new TypeError("Failed to fetch"); }]) {
        const answered = pagePolicy(serve);
        await answered.PagePolicy.header().catch(() => {});
        assert.deepEqual(answered.timers.map((x) => [x.ms, x.cleared]), [[5000, true]], "cleared by the answer, or the failure");
        assert.deepEqual(answered.errors, []);
    }
});

// ── loadConfig: which URL is the saved one ─────────────────────────────────

/** The real loadConfig over `stored` (localStorage as sGet sees it) and a
 *  node whose config.json says `nodeUrl` (null: no config.json). */
function loadConfigOver(stored, nodeUrl) {
    const start = app.indexOf("\nasync function loadConfig() {");
    assert.notEqual(start, -1, "async function loadConfig() is missing from app.js");
    const open = app.indexOf("{", start);
    let depth = 0, close = open;
    for (; close < app.length; close++) {
        if (app[close] === "{") depth++;
        else if (app[close] === "}" && --depth === 0) break;
    }
    const env = {
        DEFAULT_CONFIG: constValue("DEFAULT_CONFIG"),
        fetch: async () => (nodeUrl ? response(200, { "x-json": JSON.stringify({ exchangeUrl: nodeUrl }) }) : response(404)),
        sGet: (k) => stored[k] ?? null,
        OwnNames: { finishMigration() {} },
    };
    return new Function(...Object.keys(env), `return (async () => {${app.slice(open + 1, close)}})();`)(...Object.values(env));
}

test("loadConfig marks the exchange URL as saved only when one saved in this browser differs from the node's own", async () => {
    const DEFAULT_EXCHANGE = constValue("DEFAULT_CONFIG").exchangeUrl;
    const node = "https://selectivesubconscious.com/reticulum";
    for (const [stored, nodeUrl, url, saved] of [
        [{}, node, node, false],                                                 // nothing saved: the node's
        [{}, null, DEFAULT_EXCHANGE, false],                                     // nor a config.json: the default
        [{ exchangeUrl: node }, node, node, false],                              // saved by any Save, unchanged
        [{ exchangeUrl: DEFAULT_EXCHANGE }, null, DEFAULT_EXCHANGE, false],
        [{ exchangeUrl: BLOCKED }, node, BLOCKED, true],                          // the user's own
        [{ exchangeUrl: BLOCKED }, null, BLOCKED, true],
        [{ exchangeUrl: `${node}/` }, node, `${node}/`, true],                   // another spelling is checked (and allowed)
    ]) {
        const cfg = await loadConfigOver(stored, nodeUrl);
        assert.deepEqual([cfg.exchangeUrl, cfg.exchangeUrlSaved], [url, saved], JSON.stringify({ stored, nodeUrl }));
    }
});

// ── RnsClient.connect and _checkSavedExchange ───────────────────────────────

/**
 * The real RnsClient.connect() up to its LXMF router (as tab_lock.test.mjs
 * runs it), with the real _checkSavedExchange and PagePolicy over `serve`,
 * and a config whose exchange URL is `exchangeUrl`, saved or the node's.
 * `duringRead(self)` runs as the policy is read (a disconnect meanwhile).
 * The check is awaited unless `awaitCheck` is false. The real
 * _watchExchangeRefusal and _exchangeIsBlocked hear the page's document
 * (`doc`): `doc.fire(event)` dispatches a securitypolicyviolation to its
 * listeners, `doc.listeners` holds them.
 */
async function runConnect({ exchangeUrl, saved, serve = servedWithPolicy, duringRead = null, awaitCheck = true }) {
    const made = [];
    const statuses = [];
    const events = [];
    const warnings = [];
    const blocks = [];
    const STOP = new Error("the LXMF router is being built (the test stops here)");
    let self;
    const p = pagePolicy(async (...a) => {
        duringRead?.(self);
        return serve(...a);
    }, PAGE, warnings);
    const Harness = { event: (kind, detail) => events.push([kind, detail]) };
    const console = { log() {}, error() {}, warn: (m) => warnings.push(m) };
    const doc = documentHeard();
    let listenersAtAdd = null;
    const env = {
        IdMgr: { has: true, hash: "ab".repeat(16) },
        ActiveTab: { held: true },
        loadConfig: async () => ({ lxmfPropagationOverride: "b".repeat(32), exchangeUrl, exchangeUrlSaved: saved, interfaceName: "Retichat Web" }),
        Harness, console,
        ContactStore: { resetPropagationTimers() {} },
        Reticulum: class { constructor() { this.interfaces = []; made.push("Reticulum"); } addInterface(i) { listenersAtAdd = doc.listeners.length; this.interfaces.push(i); made.push("addInterface"); } },
        PostInterface: class { constructor(name, url) { made.push(`PostInterface ${url}`); } on() {} block(reason) { blocks.push(reason); } },
        LXMRouter: class { constructor() { made.push("LXMRouter"); throw STOP; } },
        PrivacyFilter: {},
        OutboundTickets: {},
    };
    self = { exchangeBlocked: "stale", _setStatus(s) { statuses.push(s); }, _followExchange() {} };
    self._checkSavedExchange = compile("async _checkSavedExchange(iface, exchangeUrl)", { PagePolicy: p.PagePolicy })(self);
    self._watchExchangeRefusal = compile("_watchExchangeRefusal(iface, exchangeUrl)", { document: doc, location: { href: PAGE }, exchangeRefusalFromViolation })(self);
    self._exchangeIsBlocked = compile("_exchangeIsBlocked(iface, exchangeUrl, reason, found)", { Harness, console })(self);
    // Everything connect() does up to the router is synchronous once the
    // config is loaded (a settled promise here), so by the next macrotask it
    // has returned or thrown, unless it waits on something outside it (the
    // policy read): then the outcome is PENDING, and the test fails at once
    // instead of hanging.
    const outcome = await Promise.race([
        compile("async connect()", env)(self)().catch((e) => e),
        new Promise((resolve) => setImmediate(() => resolve(PENDING))),
    ]);
    const atReturn = { made: [...made], statuses: [...statuses], blocks: [...blocks] };
    if (awaitCheck) await self._exchangeCheck;
    return { made, statuses, events, warnings, blocks, outcome, STOP, self, atReturn, fetched: p.fetched, doc, listenersAtAdd };
}
const PENDING = Symbol("connect() still waiting");

/** A document as _watchExchangeRefusal uses it: its securitypolicyviolation
 *  listeners, and `fire(event)` to dispatch one to them. */
function documentHeard() {
    const listeners = [];
    return {
        listeners,
        addEventListener(type, fn) { assert.equal(type, "securitypolicyviolation"); listeners.push(fn); },
        removeEventListener(type, fn) { assert.equal(type, "securitypolicyviolation"); const i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); },
        fire(event) { for (const fn of [...listeners]) fn(event); },
    };
}

/** The securitypolicyviolation Chromium fires on the document when it
 *  refuses PostInterface's first request to `exchangeUrl` under POLICY
 *  (as exchange_url_policy.test.mjs records them). */
const refusal = (exchangeUrl, over = {}) => ({ blockedURI: `${exchangeUrl}/v1/interfaces/register`, effectiveDirective: "connect-src",
    violatedDirective: "connect-src", disposition: "enforce", originalPolicy: POLICY, ...over });

test("connect(): with a saved exchange URL the page's policy blocks, the client is built as for any URL, and the check alongside stops the interface; the status is \"blocked\" and the reason kept", async () => {
    const run = await runConnect({ exchangeUrl: BLOCKED, saved: true });
    assert.equal(run.outcome, run.STOP, "connect() went on to the router");
    assert.deepEqual(run.made, ["Reticulum", `PostInterface ${BLOCKED}`, "addInterface", "LXMRouter"],
        "the client is built whatever the check finds: the page stays usable as while the exchange is down (an accept needs RnsClient.ownHash)");
    assert.deepEqual(run.atReturn.blocks, [], "nothing waited on the check");
    assert.deepEqual(run.blocks, ["the exchange URL is blocked by this page's Content-Security-Policy"], "then its interface is stopped, saying why");
    assert.deepEqual(run.statuses, ["connecting", "blocked"]);
    assert.equal(run.self.exchangeBlocked, exchangeUrlRefusal(BLOCKED, POLICY, PAGE), "the reason, for Settings");
    assert.deepEqual(run.events, [["exchange-blocked", { exchangeUrl: BLOCKED, found: "policy" }]], "the harness hears of it, and how it was found");
    assert.match(run.warnings[0], /^\[retichat\] The exchange URL https:\/\/other-node\.example\/reticulum is blocked by this page's Content-Security-Policy \(found by reading the policy\): its interface is stopped\. This page's/);
    assert.deepEqual(run.fetched, [[PAGE, "no-store"]], "the policy read once");
});

test("connect(): nothing waits on the policy read: one the page's server never answers holds back neither the exchange nor the router, and decides nothing", async () => {
    const never = await runConnect({ exchangeUrl: ALLOWED, saved: true, serve: () => new Promise(() => {}), awaitCheck: false });
    assert.equal(never.outcome, never.STOP, "connect() went on to the router while the read hangs");
    assert.deepEqual(never.made, ["Reticulum", `PostInterface ${ALLOWED}`, "addInterface", "LXMRouter"], "the exchange's interface added: it is asked at once");
    assert.deepEqual(never.fetched, [[PAGE, "no-store"]], "the read was started");
    const pending = Symbol("pending");
    assert.equal(await Promise.race([never.self._exchangeCheck, new Promise((resolve) => setImmediate(() => resolve(pending)))]), pending, "and is still out");
    assert.deepEqual([never.statuses, never.blocks, never.self.exchangeBlocked], [["connecting"], [], null], "nothing stopped, nothing said");
});

test("connect(): an allowed saved URL is left connected; the node's own URL is never checked; an unreadable policy decides nothing; a check that lands after a disconnect stops nothing", async () => {
    const allowed = await runConnect({ exchangeUrl: ALLOWED, saved: true });
    assert.equal(allowed.outcome, allowed.STOP);
    assert.deepEqual(allowed.made, ["Reticulum", `PostInterface ${ALLOWED}`, "addInterface", "LXMRouter"]);
    assert.deepEqual([allowed.statuses, allowed.blocks, allowed.self.exchangeBlocked], [["connecting"], [], null], "nothing blocked, and a stale reason cleared");
    assert.equal(allowed.fetched.length, 1, "checked");

    // The node's own URL, even one the policy would block, is not checked:
    // no read of the page, no check at all.
    const own = await runConnect({ exchangeUrl: BLOCKED, saved: false });
    assert.equal(own.outcome, own.STOP);
    assert.deepEqual([own.fetched, own.statuses, own.blocks, own.self._exchangeCheck], [[], ["connecting"], [], null], "no policy read at all");

    const unread = await runConnect({ exchangeUrl: BLOCKED, saved: true, serve: () => { throw new TypeError("Failed to fetch"); } });
    assert.equal(unread.outcome, unread.STOP, "connected to, as before the check");
    assert.deepEqual([unread.statuses, unread.blocks, unread.self.exchangeBlocked], [["connecting"], [], null]);
    assert.match(unread.warnings[0], /used unchecked$/);

    // Disconnected while the policy was read (Settings saved another URL,
    // another tab took over): the connection the check was for is gone.
    const replaced = await runConnect({ exchangeUrl: BLOCKED, saved: true, duringRead: (self) => { self._rns = null; } });
    assert.deepEqual([replaced.blocks, replaced.statuses, replaced.events, replaced.self.exchangeBlocked], [[], ["connecting"], [], null],
        "not this check's to stop: nothing blocked, nothing said");

    // Where it starts: once the interface is added, before the router, and
    // not awaited; a disconnect (a reconnect from Settings, a takeover)
    // forgets the reason and the check.
    const connect = methodBody("async connect()");
    const check = connect.indexOf("this._checkSavedExchange(iface, this._cfg.exchangeUrl)");
    assert.ok(connect.indexOf("this._rns.addInterface(iface);") < check && check < connect.indexOf("new LXMRouter("));
    assert.equal(own.listenersAtAdd, 1, "the browser's refusal is heard from before the interface's first request");
    assert.doesNotMatch(connect, /\bawait\s+[^;]*(_checkSavedExchange|PagePolicy|_exchangeCheck)/);
    assert.match(methodBody("disconnect()"), /this\._exchangeRefusalWatch\?\.\(\);\n\s+this\._exchangeRefusalWatch = null;\n\s+this\.exchangeBlocked = null;\n\s+this\._exchangeCheck = null;\n\s+this\._setStatus\("offline"\);/);
});

test("connect(): the browser's refusal of the exchange, a securitypolicyviolation on the document, stops its interface and says so while the policy read is never answered; nothing else does, and it counts once", async () => {
    // The case the policy read cannot close: the page's server never
    // answers it. Until 2026-10-01 the page then sat offline with nothing
    // said, its interface asking again every reconnect wait.
    const run = await runConnect({ exchangeUrl: BLOCKED, saved: true, serve: () => new Promise(() => {}), awaitCheck: false });
    assert.equal(run.outcome, run.STOP, "connect() went on to the router");
    assert.equal(run.listenersAtAdd, 1, "heard from before the interface's first request");
    // Violations that are not this exchange refused: a report-only policy,
    // another URL, another directive, another exchange.
    run.doc.fire(refusal(BLOCKED, { disposition: "report" }));
    run.doc.fire(refusal(BLOCKED, { blockedURI: "https://esm.sh/msgpackr" }));
    run.doc.fire(refusal(BLOCKED, { effectiveDirective: "img-src", violatedDirective: "img-src" }));
    run.doc.fire(refusal(ALLOWED));
    assert.deepEqual([run.statuses, run.blocks, run.events, run.self.exchangeBlocked], [["connecting"], [], [], null], "none of them stops anything");

    run.doc.fire(refusal(BLOCKED));
    assert.deepEqual(run.blocks, ["the exchange URL is blocked by this page's Content-Security-Policy"], "its interface is stopped");
    assert.deepEqual(run.statuses, ["connecting", "blocked"], "and the page says so (the line under the status dot)");
    assert.equal(run.self.exchangeBlocked, exchangeUrlRefusal(BLOCKED, POLICY, PAGE), "Settings' words, from the policy the event carries");
    assert.deepEqual(run.events, [["exchange-blocked", { exchangeUrl: BLOCKED, found: "violation" }]]);
    assert.match(run.warnings.at(-1), /^\[retichat\] The exchange URL https:\/\/other-node\.example\/reticulum is blocked by this page's Content-Security-Policy \(the browser refused a request to it\): its interface is stopped\. This page's/);
    const pending = Symbol("pending");
    assert.equal(await Promise.race([run.self._exchangeCheck, new Promise((resolve) => setImmediate(() => resolve(pending)))]), pending, "while the read is still out");

    // Once per connection: a second refusal (the goodbye beacon, another
    // request) changes nothing.
    run.doc.fire(refusal(BLOCKED, { blockedURI: `${BLOCKED}/v1/interfaces/exchange` }));
    assert.deepEqual([run.blocks.length, run.events.length, run.statuses], [1, 1, ["connecting", "blocked"]]);
});

test("connect(): whichever finds the blocked exchange first, the policy read or the browser's refusal, stops it; the other changes nothing", async () => {
    // The refusal first, then the read answers.
    let answer;
    const first = await runConnect({ exchangeUrl: BLOCKED, saved: true, serve: () => new Promise((resolve) => { answer = resolve; }), awaitCheck: false });
    first.doc.fire(refusal(BLOCKED));
    answer(servedWithPolicy());
    await first.self._exchangeCheck;
    assert.deepEqual([first.blocks.length, first.events.map(([, d]) => d.found), first.statuses], [1, ["violation"], ["connecting", "blocked"]]);

    // The read first (awaited), then the refusal.
    const second = await runConnect({ exchangeUrl: BLOCKED, saved: true });
    second.doc.fire(refusal(BLOCKED));
    assert.deepEqual([second.blocks.length, second.events.map(([, d]) => d.found), second.statuses], [1, ["policy"], ["connecting", "blocked"]]);
});

test("connect(): the node's own URL is never read against the policy, but the browser's refusal of it is still heard and said", async () => {
    const own = await runConnect({ exchangeUrl: BLOCKED, saved: false });
    assert.deepEqual([own.fetched, own.self._exchangeCheck], [[], null], "no policy read");
    assert.equal(own.listenersAtAdd, 1);
    own.doc.fire(refusal(BLOCKED));
    assert.deepEqual([own.blocks.length, own.statuses, own.events], [1, ["connecting", "blocked"], [["exchange-blocked", { exchangeUrl: BLOCKED, found: "violation" }]]]);
    assert.equal(own.self.exchangeBlocked, exchangeUrlRefusal(BLOCKED, POLICY, PAGE));
});

test("_watchExchangeRefusal: one listener per connection; disconnect() or the next connection's hook removes it; a refusal heard for a connection that has ended stops nothing", async () => {
    const run = await runConnect({ exchangeUrl: BLOCKED, saved: true });
    // A refusal of the previous connection's exchange lands after it ended
    // (Settings saved another URL): not this listener's to act on.
    const ended = await runConnect({ exchangeUrl: BLOCKED, saved: false });
    const iface = ended.self._rns.interfaces[0];
    ended.self._rns = null;
    ended.doc.fire(refusal(BLOCKED));
    assert.deepEqual([ended.blocks, ended.statuses, ended.self.exchangeBlocked], [[], ["connecting"], null], "nothing stopped, nothing said");

    // The next connection's hook replaces the old one; unhooking leaves none.
    assert.equal(run.doc.listeners.length, 1);
    run.self._watchExchangeRefusal(iface, ALLOWED);
    assert.equal(run.doc.listeners.length, 1, "the earlier one removed");
    run.self._exchangeRefusalWatch();
    assert.equal(run.doc.listeners.length, 0, "and disconnect() removes the last (its unhook line is checked above)");
});

test("a down or up the interface emitted before it was found blocked, heard after, leaves the status \"blocked\"; for an exchange not blocked they move it as before", async () => {
    // PostInterface emits each event after a setTimeout, so the "down" of
    // the first request the browser refused can be heard after the
    // refusal's securitypolicyviolation stopped the interface. Until
    // 2026-10-01 that down turned "blocked" back to "offline", and the
    // line under the status dot went (seen in Chromium, where the event
    // usually lands first).
    for (const blocked of [true, false]) {
        const statuses = [];
        const Harness = { event: (kind, detail) => { if (kind === "status") statuses.push(detail.status); }, markReady() {} };
        const iface = new EventEmitter();
        iface.block = () => {};
        const self = { _rns: { interfaces: [iface] }, _status: "connecting", _connType: "exchange", _onStatus: [], exchangeBlocked: null,
            _onExchangeRegistered() {}, _onPacketsLost() {}, _onPageResume() {} };
        self._setStatus = compile("_setStatus(s, type)", { Harness })(self);
        self._exchangeIsBlocked = compile("_exchangeIsBlocked(iface, exchangeUrl, reason, found)", { Harness, console: { warn() {} } })(self);
        compile("_followExchange(iface)", {})(self)(iface);

        iface.emit("down", "Failed to fetch");          // the refused first request: heard on the next macrotask
        if (blocked) self._exchangeIsBlocked(iface, BLOCKED, "why", "violation");
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));
        assert.equal(self._status, blocked ? "blocked" : "offline", blocked ? "the late down leaves it blocked" : "down: offline, as before");
        iface.emit("up");
        await new Promise((resolve) => setTimeout(resolve, 0));
        assert.equal(self._status, blocked ? "blocked" : "online", blocked ? "and so does a late up" : "up: online, as before");
        assert.deepEqual(statuses, blocked ? ["blocked"] : ["offline", "online"]);
    }
});

// ── where the page shows it ────────────────────────────────────────────────

class El {
    constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.style = {}; this.className = ""; this.title = ""; }
    appendChild(c) { this.children.push(c); return c; }
    removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
    get firstChild() { return this.children[0] ?? null; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    click() { for (const f of this.listeners.click ?? []) f(); }
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
}

test("the line under the status dot: while the status is \"blocked\" it says so and opens Settings; otherwise it is empty, and the dot says the status", () => {
    const dot = new El("span"), banner = new El("div");
    const document = {
        createElement: (tag) => new El(tag),
        createTextNode: (text) => ({ textContent: text }),
        getElementById: (id) => ({ "status-dot": dot, "exchange-blocked": banner })[id] ?? null,
    };
    const h = fn("h", "tag, a={}, ...kids", { document });
    const clear = fn("clear", "el", {});
    const RnsClient = { _status: "blocked" };
    const self = { state: { showSettings: false, settingsFocus: null }, renders: 0, render() { this.renders++; } };
    const apply = compile("_applyStatusDot()", { document, h, clear, RnsClient, EXCHANGE_BLOCKED_NOTICE: constValue("EXCHANGE_BLOCKED_NOTICE") })(self);

    apply();
    assert.equal(constValue("EXCHANGE_BLOCKED_NOTICE"), NOTICE);
    assert.equal(dot.className, "status-dot blocked");
    assert.equal(dot.title, NOTICE);
    assert.equal(banner.textContent, `${NOTICE} Open Settings`);
    const button = banner.children.find((c) => c instanceof El);
    button.click();
    assert.deepEqual([self.state.showSettings, self.state.settingsFocus, self.renders], [true, "cfg-exchange", 1], "its button opens Settings on the exchange field");

    apply();
    assert.equal(banner.children.length, 2, "applied again (every render): said once");

    for (const status of ["offline", "connecting", "online"]) {
        RnsClient._status = status;
        apply();
        assert.deepEqual([dot.className, dot.title, banner.children.length], [`status-dot ${status}`, `RNS: ${status}`, 0], status);
    }

    // Its place: right under the sidebar header, which holds the dot; and
    // the status listener and every render apply it.
    const sidebar = methodBody("_buildSidebarContent()");
    const header = sidebar.indexOf('h("div", { className: "sidebar-header" },');
    const line = sidebar.indexOf('frag.appendChild(h("div", { id: "exchange-blocked", className: "conn-banner none", role: "status" }));');
    assert.ok(header > 0 && line > header && line < sidebar.indexOf("// Search bar"), "between the header and the search bar");
    assert.match(methodBody("_wire()"), /RnsClient\.onStatus\(\(\) => \{\n\s+this\._checkDayTurn\(\);\n\s+this\._applyStatusDot\(\);\n\s+\}\);/);
    assert.match(methodBody("render()"), /this\._applyStatusDot\(\);/);
    const css = readFileSync(new URL("./style.css", import.meta.url), "utf8");
    assert.match(css, /#exchange-blocked:empty \{ display: none; \}/, "empty, it takes no room");
    assert.match(css, /\.status-dot\.blocked \{ background: var\(--danger\); \}/);
});

test("Settings opens on the field it was opened for, once, on its own focus timer; else on its first input", () => {
    // The modal focuses a field 150 ms after it opens. A field the opener
    // focused itself was taken back by that timer (to the first input, the
    // Announce Display Name), so the opener names the field
    // (state.settingsFocus) and the modal's timer focuses it.
    const modal = methodBody("_renderSettingsModal()");
    const from = modal.indexOf("const focusId = this.state.settingsFocus;");
    const to = modal.indexOf("150);", from) + "150);".length;
    assert.ok(from > 0 && to > from && modal.slice(to).trim() === "", "the modal's last statements");
    assert.equal((modal.match(/\.focus\(/g) ?? []).length, 1, "the one focus in Settings");
    assert.match(modal, /h\("input", \{ id: "cfg-exchange", type: "text"/, "the field it names exists");
    const focusLines = new Function("self", "sheet", "setTimeout", modal.slice(from, to).replaceAll("this.", "self."));

    const focused = [];
    const field = (id) => ({ id, focus: () => focused.push(id) });
    const sheet = { querySelector: (sel) => (sel === "input" ? field("cfg-announce-name") : sel.startsWith("#") ? field(sel.slice(1)) : null) };
    const open = (state) => {
        const timers = [];
        focusLines({ state }, sheet, (fn, ms) => timers.push([fn, ms]));
        assert.deepEqual(timers.map(([, ms]) => ms), [150]);
        timers[0][0]();
    };
    const state = { settingsFocus: "cfg-exchange" };
    open(state);
    assert.deepEqual(focused, ["cfg-exchange"], "opened from the blocked line: the exchange field");
    assert.equal(state.settingsFocus, null, "once");
    open(state);
    assert.deepEqual(focused, ["cfg-exchange", "cfg-announce-name"], "opened again (the gear, a re-render): the first input, as before");
});

// ── the real page, in Chromium ─────────────────────────────────────────────

const BOOT_TESTS = process.env.RETICHAT_BOOT_TESTS === "1";
const chromiumTest = BOOT_TESTS ? test
    : (name, fn) => test(name, { skip: "RETICHAT_BOOT_TESTS is not 1: run `npm run test:full` (deploy.sh always does)" }, fn);

/** Playwright's Chromium, or null when the test was skipped for want of it. */
async function launchChromium(t) {
    let chromium;
    try {
        ({ chromium } = createRequire(new URL("../test-harnesses/distro-pipeline/package.json", import.meta.url))("playwright"));
    } catch {
        t.skip("no Playwright in ../test-harnesses/distro-pipeline");
        return null;
    }
    try {
        return await chromium.launch({ headless: true, args: ["--disable-dev-shm-usage"] });
    } catch (e) {
        if (/Executable doesn't exist/i.test(e?.message ?? "")) { t.skip("Playwright has no Chromium installed"); return null; }
        throw e;
    }
}

/**
 * The page from this directory, index.html with the nodes' policy, and a
 * config.json naming an exchange on this server ('self') that answers 503,
 * as deploy.sh's boot gate serves it. With `holdPolicyRead`, every request
 * for index.html that is not the navigation (PagePolicy's read of the
 * policy) is held unanswered; `policyReadHeld` resolves when the first one
 * arrives. connect() starts that read after it has added its interface, so
 * the read can reach this server after the exchange has answered, or after
 * the browser has refused the interface's first request: a test waits for
 * it (readArrives) before it says the read is held. Until 2026-10-01 they
 * asserted it at once, and under the full suite's load one run in two or
 * five failed with "while the policy read is still held" (0, not 1).
 */
async function servePage({ holdPolicyRead = false } = {}) {
    const ROOT = fileURLToPath(new URL(".", import.meta.url));
    const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" };
    const exchangeHits = [];
    const held = [];
    let readHeld;
    const policyReadHeld = new Promise((resolve) => { readHeld = resolve; });
    const server = createServer(async (req, res) => {
        const path = new URL(req.url, "http://x").pathname;
        if (path === "/config.json") {
            res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" })
                .end(JSON.stringify({ exchangeUrl: `http://127.0.0.1:${server.address().port}/no-exchange` }));
            return;
        }
        if (path.startsWith("/no-exchange")) { exchangeHits.push(path); res.writeHead(503).end(); return; }
        const file = join(ROOT, path.endsWith("/") ? `${path}index.html` : path);
        if (holdPolicyRead && file.endsWith("index.html") && req.headers["sec-fetch-mode"] !== "navigate") { held.push(res); readHeld(); return; }
        try {
            const body = await readFile(file);
            res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store",
                ...(file.endsWith("index.html") ? { "content-security-policy": POLICY } : {}) }).end(body);
        } catch {
            res.writeHead(404).end();
        }
    });
    await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
    return {
        origin: `http://127.0.0.1:${server.address().port}`, exchangeHits, held, policyReadHeld,
        close() { held.forEach((r) => r.destroy()); server.close(); },
    };
}

/**
 * A new page at `origin` with `seed` in its storage (retichat_<key>: JSON)
 * at its first load. Only `origin` and esm.sh (the importmap) are
 * reachable; anything else is blocked in the browser (`elsewhere`). Every
 * securitypolicyviolation is recorded in window.__violations.
 */
async function openPage(browser, origin, seed) {
    const context = await browser.newContext({ serviceWorkers: "block" });
    const elsewhere = [];
    await context.route("**/*", (route) => {
        const u = new URL(route.request().url());
        if (u.origin === origin || (u.protocol === "https:" && u.hostname === "esm.sh")) return route.continue();
        elsewhere.push(route.request().url());
        return route.abort("blockedbyclient");
    });
    await context.addInitScript((seed) => {
        if (!sessionStorage.getItem("seeded")) {
            for (const [k, v] of Object.entries(seed)) localStorage.setItem(`retichat_${k}`, JSON.stringify(v));
            sessionStorage.setItem("seeded", "1");
        }
        window.__violations = [];
        window.addEventListener("securitypolicyviolation", (e) => window.__violations.push(`${e.effectiveDirective} ${e.blockedURI}`), true);
    }, seed);
    const page = await context.newPage();
    const pageErrors = [], dialogs = [], consoleLines = [];
    page.on("pageerror", (e) => pageErrors.push(e.message));
    page.on("dialog", (d) => { dialogs.push(d.message()); d.accept().catch(() => {}); });
    page.on("console", (m) => consoleLines.push(`${m.type()}: ${m.text()}`.slice(0, 240)));
    /** A page condition, failing the test with `what` (and the page's last
     *  console lines) if it does not hold within 10 s. */
    const until = (what, condition, arg = null) => page.waitForFunction(condition, arg, { timeout: 10_000 }).catch((e) => {
        throw new Error(`${what}: not within 10 s (${e.message.split("\n")[0]})\n${consoleLines.slice(-25).join("\n")}`);
    });
    return { context, page, pageErrors, dialogs, elsewhere, until };
}

/** servePage's `policyReadHeld`: the page's policy read reaching its server,
 *  within 10 s (a test-failure bound only, never a pass path). */
function readArrives(policyReadHeld) {
    let timer;
    const bound = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("the page's policy read never reached its server within 10 s")), 10_000); });
    return Promise.race([policyReadHeld, bound]).finally(() => clearTimeout(timer));
}

const OWN_KEY = "11".repeat(64);
const deliveryHash = (id) => Destination.hash(id, "lxmf", "delivery").toString("hex");

chromiumTest("the real page under the .htaccess policy: a saved exchange it blocks is said under the status dot and never asked again; the page still works (an invite is accepted); changing it in Settings clears it", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePage();
    const { origin, exchangeHits } = served;
    try {
        // An identity, so the page opens on its main view; the exchange URL a
        // build before a71c32a let the user save; and an invite waiting from
        // an allowlisted contact, every member's key held.
        const id = (byte) => Identity.fromPrivateKey(Buffer.from(byte.repeat(64), "hex"));
        const [own, inviter, other] = [id("11"), id("22"), id("33")];
        const row = (who, allowlisted) => ({ destHash: deliveryHash(who), publicKey: who.getPublicKey().toString("hex"), hidden: true, allowlisted,
            localName: null, messageName: null, messageNameAt: null, announceName: null, legacyName: null, isDistro: false });
        const GID = "ab".repeat(16);
        const { context, page, pageErrors, dialogs, elsewhere, until } = await openPage(browser, origin, {
            identity_private_key: OWN_KEY,
            exchangeUrl: BLOCKED,
            groupMembersAllowlisted: 2,
            contacts_v2: [row(inviter, true), row(other, false)],
            groups_v1: [{ groupId: GID, groupName: "Pending G", groupStatus: "pending", lastActivity: Date.now(),
                members: [{ hash: deliveryHash(inviter), status: "accepted" }, { hash: deliveryHash(other), status: "invited" },
                    { hash: deliveryHash(own), status: "invited" }] }],
        });
        await page.goto(`${origin}/index.html`);

        const banner = page.locator("#exchange-blocked");
        await until("the line under the status dot", (notice) => document.getElementById("exchange-blocked")?.textContent.startsWith(notice), NOTICE);
        assert.equal(await banner.textContent(), `${NOTICE} Open Settings`);
        // Read in one step in the page: a sidebar refresh replaces the element.
        const shown = () => page.evaluate(() => {
            const el = document.getElementById("exchange-blocked");
            return [getComputedStyle(el).display, el.getBoundingClientRect().height > 0];
        });
        assert.deepEqual(await shown(), ["block", true], "on screen");
        assert.equal(await page.locator("#status-dot").getAttribute("class"), "status-dot blocked");
        const state = () => page.evaluate(() => {
            const s = window.RetichatTest.state();
            return { status: s.status, blocked: !!s.exchangeBlocked, exchange: s.exchange, ownHash: s.ownHash };
        });
        assert.deepEqual(await state(), { status: "blocked", blocked: true, exchange: "down", ownHash: deliveryHash(own) },
            "the debug surface says it too; the client is built (its own hash is known)");
        // The interface's first request was refused by the browser before it
        // was sent (the one violation a blocked saved URL costs a page load);
        // the check then stopped it, so it is never asked again.
        await until("the browser's refusal of the interface's first request", () => window.__violations.length > 0);
        const violations = await page.evaluate(() => window.__violations);
        assert.ok(violations.length >= 1 && violations.every((v) => /^connect-src https:\/\/other-node\.example\b/.test(v)),
            `only the blocked exchange, refused by the browser: ${JSON.stringify(violations)}`);
        assert.deepEqual(exchangeHits, [], "no exchange was reached");
        // The network "comes back": a running interface would ask again at
        // once (PostInterface.check), and be refused again. A stopped one
        // does not (checked below, after the steps that follow).
        await page.evaluate(() => window.dispatchEvent(new Event("online")));

        // The page works as it does while the exchange is down: the invite is
        // accepted. Until 2026-10-01 the client had no router here, and the
        // accept said "Still receiving member keys (2/3)" and did nothing.
        await page.locator(".contact-item", { hasText: "Pending G" }).first().click();
        await page.getByRole("button", { name: "Accept", exact: true }).first().click();
        await until("the group joined", (gid) => JSON.parse(localStorage.getItem("retichat_groups_v1")).find((g) => g.groupId === gid)?.groupStatus === "active", GID);
        const joined = await page.evaluate(([gid, other]) => ({
            allowlisted: JSON.parse(localStorage.getItem("retichat_contacts_v2")).find((c) => c.destHash === other)?.allowlisted,
            system: JSON.parse(localStorage.getItem(`retichat_gmsg_${gid}`) ?? "[]").map((m) => m.content),
        }), [GID, deliveryHash(other)]);
        assert.deepEqual(joined, { allowlisted: true, system: ['You joined "Pending G"'] }, "joined, every member allowed");
        assert.deepEqual([dialogs, pageErrors], [[], []], "no complaint, no error");

        // Its button opens Settings, where the field says why.
        // Settings focuses its field on its own timer, and only then: until
        // that, the body has the focus (the button went with the re-render).
        await banner.getByRole("button", { name: "Open Settings" }).click();
        await until("Settings on the exchange field", () => document.activeElement?.id === "cfg-exchange");
        const refusal = page.locator("#cfg-exchange-refusal");
        assert.match(await refusal.textContent(), /^This page's Content-Security-Policy lets it connect only to .*The exchange https:\/\/other-node\.example\/reticulum is not among them/);
        assert.equal(await page.locator("#cfg-exchange").inputValue(), BLOCKED);

        // The user changes it to the node's own exchange and saves: the page
        // reconnects, and the line goes (the exchange answers 503: offline).
        await page.fill("#cfg-exchange", `${origin}/no-exchange`);
        await page.getByRole("button", { name: "Save & Reconnect" }).click();
        await until("the line cleared", () => document.getElementById("exchange-blocked")?.textContent === "");
        assert.deepEqual(await shown(), ["none", false], "and, empty, takes no room");
        // The new connection's interface reports its exchange down (the 503),
        // so the exchange it was given was asked.
        await until("the new exchange reported down", () => window.RetichatTest.state().exchange === "down" && window.RetichatTest.state().status === "offline");
        assert.ok(exchangeHits.length > 0, "the exchange it was given was asked");
        assert.equal(await page.locator("#status-dot").getAttribute("class"), "status-dot offline");
        assert.deepEqual(await page.evaluate(() => window.__violations), violations, "no violation since: the blocked interface never asked again");

        // Reloaded with the node's own URL saved, nothing is said.
        await page.reload();
        await until("the reloaded page's status", () => /status-dot (connecting|offline|online)/.test(document.getElementById("status-dot")?.className));
        assert.equal(await banner.textContent(), "", "no line for an exchange the policy allows");
        assert.deepEqual(await page.evaluate(() => window.__violations), [], "and no violation");
        assert.deepEqual(pageErrors, []);
        assert.deepEqual(elsewhere, [], "nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});

chromiumTest("the real page: a policy read the page's server never answers holds nothing back; a saved exchange the policy allows is asked at once, and nothing is said", async (t) => {
    // Until 2026-10-01 connect() awaited the read: a server that answered
    // the page but held this read kept the page offline, its exchange never
    // asked, with no line.
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePage({ holdPolicyRead: true });
    const { origin, exchangeHits, held, policyReadHeld } = served;
    try {
        // Saved: the node's own exchange in another spelling (a trailing
        // slash), which the policy allows ('self') and loadConfig counts as
        // saved, so the page reads the policy for it.
        const { context, page, pageErrors, elsewhere, until } = await openPage(browser, origin, {
            identity_private_key: OWN_KEY,
            exchangeUrl: `${origin}/no-exchange/`,
        });
        await page.goto(`${origin}/index.html`);
        await until("its exchange asked, and reported down (503)", () => window.RetichatTest.state().exchange === "down" && window.RetichatTest.state().status === "offline");
        assert.ok(exchangeHits.length > 0, "the exchange was asked");
        await readArrives(policyReadHeld);
        assert.equal(held.length, 1, "while the policy read is still held");
        assert.equal(await page.evaluate(() => window.RetichatTest.state().ownHash), deliveryHash(Identity.fromPrivateKey(Buffer.from(OWN_KEY, "hex"))),
            "and the client is built (its LXMF router: its own hash is known)");
        assert.equal(await page.locator("#exchange-blocked").textContent(), "", "nothing said: nothing is known to be blocked");
        assert.deepEqual(await page.evaluate(() => [window.__violations, !!window.RetichatTest.state().exchangeBlocked]), [[], false]);
        assert.deepEqual([pageErrors, elsewhere], [[], []]);
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});

chromiumTest("the real page: a saved exchange the policy blocks is said from the browser's refusal alone while the page's server never answers the policy read; the interface is stopped at that first refusal, and Settings says why", async (t) => {
    // The case the policy read cannot close (b9f525a's last open one): the
    // read is held, so only the browser's securitypolicyviolation, fired
    // when it refuses the interface's first request, can say it. Until
    // 2026-10-01 the page sat offline here, the dot red, nothing said, its
    // interface asking again every reconnect wait (5 s), each refused.
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePage({ holdPolicyRead: true });
    const { origin, exchangeHits, held, policyReadHeld } = served;
    try {
        const { context, page, pageErrors, elsewhere, until } = await openPage(browser, origin, {
            identity_private_key: OWN_KEY,
            exchangeUrl: BLOCKED,
        });
        await page.goto(`${origin}/index.html`);
        await until("the line under the status dot", (notice) => document.getElementById("exchange-blocked")?.textContent.startsWith(notice), NOTICE);
        await readArrives(policyReadHeld);
        assert.equal(held.length, 1, "while the policy read is still held");
        const state = () => page.evaluate(() => {
            const s = window.RetichatTest.state();
            return { status: s.status, exchangeBlocked: s.exchangeBlocked, exchange: s.exchange, ownHash: s.ownHash };
        });
        const s = await state();
        assert.deepEqual([s.status, s.exchange, s.ownHash], ["blocked", "down", deliveryHash(Identity.fromPrivateKey(Buffer.from(OWN_KEY, "hex")))],
            "blocked, its interface stopped, the client built");
        assert.match(s.exchangeBlocked, /^This page's Content-Security-Policy lets it connect only to .*The exchange https:\/\/other-node\.example\/reticulum is not among them/,
            "the reason, from the policy the browser's event carries");
        assert.equal(await page.locator("#status-dot").getAttribute("class"), "status-dot blocked");

        // Stopped at the first refusal: the network "coming back" asks
        // nothing more, so the one violation stays the only one.
        await page.evaluate(() => window.dispatchEvent(new Event("online")));
        await page.locator("#exchange-blocked").getByRole("button", { name: "Open Settings" }).click();
        await until("Settings on the exchange field", () => document.activeElement?.id === "cfg-exchange");
        assert.equal(await page.locator("#cfg-exchange-refusal").textContent(), s.exchangeBlocked, "Settings says why");
        const violations = await page.evaluate(() => window.__violations);
        assert.deepEqual(violations, [`connect-src ${BLOCKED}/v1/interfaces/register`], "one refusal, of the first request; none since");
        assert.equal(held.length, 1, "the read is still held");
        assert.deepEqual([exchangeHits, pageErrors, elsewhere], [[], [], []], "no exchange reached, no error, nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});
