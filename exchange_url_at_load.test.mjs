/**
 * A SAVED EXCHANGE URL THE PAGE'S POLICY BLOCKS IS SAID AT LOAD.
 *
 * Settings refuses an exchange URL the page's Content-Security-Policy would
 * block (a71c32a, exchange_url_policy.test.mjs). One saved before that, or
 * edited in storage, still left the page offline with nothing to say why:
 * the browser refuses each request to it before it is sent, and the status
 * dot only turned red. Now, as the page loads, a saved exchange URL other
 * than the node's own is checked with the same check Settings makes
 * (PagePolicy, lib/connect_policy.js) before anything connects (§5). A
 * blocked one is not connected to: the status is "blocked", and the page
 * says so where it shows the connection status, under the status dot ("This
 * exchange is blocked by the page's security policy; change it in
 * Settings.", with a button to Settings, whose exchange field then says
 * why). Changing it in Settings reconnects, and the line goes.
 *
 * The node's own URL (config.json, or the default) is never checked: it is
 * served beside the policy, and deploy.sh's boot gate fails on any
 * violation. A policy that cannot be read decides nothing: the saved URL is
 * connected to as before, and the console says it is unchecked.
 *
 * These run the real shipped code from app.js (loadConfig, PagePolicy,
 * RnsClient.connect up to its interface, App._applyStatusDot, h) over
 * stubs. One test (RETICHAT_BOOT_TESTS=1, as deploy.sh runs the suite)
 * loads the real page in Chromium under the .htaccess policy.
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
import { exchangeUrlRefusal } from "./lib/connect_policy.js";
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
 *  warns goes to `warnings`. */
function pagePolicy(serve, href = PAGE, warnings = []) {
    const fetched = [];
    const PagePolicy = build("PagePolicy", {
        fetch: async (url, init) => { fetched.push([url, init?.cache]); return serve(url, init); },
        location: { href }, exchangeUrlRefusal, Date,
        console: { log() {}, error() {}, warn: (m) => warnings.push(m) },
    });
    return { PagePolicy, fetched, warnings };
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

// ── RnsClient.connect ──────────────────────────────────────────────────────

/**
 * The real RnsClient.connect() up to its exchange interface (as
 * tab_lock.test.mjs runs it), with the real PagePolicy over `serve` and a
 * config whose exchange URL is `exchangeUrl`, saved or the node's.
 */
async function runConnect({ exchangeUrl, saved, serve = servedWithPolicy, takenOverWhileChecking = false }) {
    const made = [];
    const statuses = [];
    const events = [];
    const warnings = [];
    const STOP = new Error("the interface exists (the test stops here)");
    const activeTab = { held: true };
    const p = pagePolicy(async (...a) => {
        if (takenOverWhileChecking) activeTab.held = false;   // _takenOver() ran meanwhile
        return serve(...a);
    }, PAGE, warnings);
    const env = {
        IdMgr: { has: true, hash: "ab".repeat(16) },
        ActiveTab: activeTab,
        loadConfig: async () => ({ lxmfPropagationOverride: "b".repeat(32), exchangeUrl, exchangeUrlSaved: saved, interfaceName: "Retichat Web" }),
        PagePolicy: p.PagePolicy,
        Harness: { event: (kind, detail) => events.push([kind, detail]) },
        console: { log() {}, error() {}, warn: (m) => warnings.push(m) },
        ContactStore: { resetPropagationTimers() {} },
        Reticulum: class { constructor() { this.interfaces = []; made.push("Reticulum"); } addInterface(i) { this.interfaces.push(i); made.push("addInterface"); } },
        PostInterface: class { constructor(name, url) { made.push(`PostInterface ${url}`); } on() {} },
        LXMRouter: class { constructor() { throw STOP; } },
        PrivacyFilter: {},
        OutboundTickets: {},
    };
    const self = { exchangeBlocked: "stale", _setStatus(s) { statuses.push(s); }, _followExchange() {} };
    let outcome;
    try {
        outcome = await compile("async connect()", env)(self)();
    } catch (e) {
        outcome = e;
    }
    return { made, statuses, events, warnings, outcome, STOP, self, fetched: p.fetched };
}

test("connect(): a saved exchange URL the page's policy blocks is not connected to; the status is \"blocked\" and the reason kept", async () => {
    const run = await runConnect({ exchangeUrl: BLOCKED, saved: true });
    assert.equal(run.outcome, undefined, "it stops there, quietly");
    assert.deepEqual(run.made, [], "no Reticulum, no interface: nothing is sent to an exchange the browser would refuse");
    assert.deepEqual(run.statuses, ["blocked"]);
    assert.equal(run.self.exchangeBlocked, exchangeUrlRefusal(BLOCKED, POLICY, PAGE), "the reason, for Settings");
    assert.deepEqual(run.events, [["exchange-blocked", { exchangeUrl: BLOCKED }]], "the harness hears of it");
    assert.match(run.warnings[0], /^\[retichat\] Not connecting: the saved exchange URL https:\/\/other-node\.example\/reticulum is blocked by this page's Content-Security-Policy\. This page's/);
    assert.deepEqual(run.fetched, [[PAGE, "no-store"]], "the policy read before anything connects");
});

test("connect(): an allowed saved URL connects; the node's own URL is never checked; an unreadable policy decides nothing; a tab taken over while it checks stops", async () => {
    const allowed = await runConnect({ exchangeUrl: ALLOWED, saved: true });
    assert.equal(allowed.outcome, allowed.STOP);
    assert.deepEqual(allowed.made, ["Reticulum", `PostInterface ${ALLOWED}`, "addInterface"]);
    assert.deepEqual([allowed.statuses, allowed.self.exchangeBlocked], [["connecting"], null], "nothing blocked, and a stale reason cleared");
    assert.equal(allowed.fetched.length, 1, "checked first");

    // The node's own URL, even one the policy would block, is not checked:
    // no read of the page, and it connects.
    const own = await runConnect({ exchangeUrl: BLOCKED, saved: false });
    assert.equal(own.outcome, own.STOP);
    assert.deepEqual([own.fetched, own.statuses], [[], ["connecting"]], "no policy read at all");

    const unread = await runConnect({ exchangeUrl: BLOCKED, saved: true, serve: () => { throw new TypeError("Failed to fetch"); } });
    assert.equal(unread.outcome, unread.STOP, "connected to, as before the check");
    assert.deepEqual([unread.statuses, unread.self.exchangeBlocked], [["connecting"], null]);
    assert.match(unread.warnings[0], /used unchecked$/);

    const takenOver = await runConnect({ exchangeUrl: BLOCKED, saved: true, takenOverWhileChecking: true });
    assert.equal(takenOver.outcome, undefined);
    assert.deepEqual([takenOver.made, takenOver.statuses, takenOver.events], [[], [], []], "the other tab has the identity: nothing here");

    // The check comes before the connection's first step, and a disconnect
    // (a reconnect from Settings, a takeover) forgets the reason.
    const connect = methodBody("async connect()");
    assert.ok(connect.indexOf("PagePolicy.blockedReason(this._cfg.exchangeUrl)") < connect.indexOf("ContactStore.resetPropagationTimers()"));
    assert.match(methodBody("disconnect()"), /this\.exchangeBlocked = null;\n\s+this\._setStatus\("offline"\);/);
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

chromiumTest("the real page under the .htaccess policy: a saved exchange it blocks is said under the status dot, never asked for, and changing it in Settings clears it", async (t) => {
    let chromium;
    try {
        ({ chromium } = createRequire(new URL("../test-harnesses/distro-pipeline/package.json", import.meta.url))("playwright"));
    } catch {
        return t.skip("no Playwright in ../test-harnesses/distro-pipeline");
    }
    let browser;
    try {
        browser = await chromium.launch({ headless: true, args: ["--disable-dev-shm-usage"] });
    } catch (e) {
        if (/Executable doesn't exist/i.test(e?.message ?? "")) return t.skip("Playwright has no Chromium installed");
        throw e;
    }
    // The page from this directory, index.html with the nodes' policy, and
    // a config.json naming an exchange on this server ('self') that answers
    // 503, as deploy.sh's boot gate serves it. Only this server and esm.sh
    // (the importmap) are reachable; anything else is blocked in the browser.
    const ROOT = fileURLToPath(new URL(".", import.meta.url));
    const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" };
    const exchangeHits = [];
    const server = createServer(async (req, res) => {
        const path = new URL(req.url, "http://x").pathname;
        if (path === "/config.json") {
            res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" })
                .end(JSON.stringify({ exchangeUrl: `http://127.0.0.1:${server.address().port}/no-exchange` }));
            return;
        }
        if (path.startsWith("/no-exchange")) { exchangeHits.push(path); res.writeHead(503).end(); return; }
        try {
            const file = join(ROOT, path.endsWith("/") ? `${path}index.html` : path);
            const body = await readFile(file);
            res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store",
                ...(file.endsWith("index.html") ? { "content-security-policy": POLICY } : {}) }).end(body);
        } catch {
            res.writeHead(404).end();
        }
    });
    await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
    const origin = `http://127.0.0.1:${server.address().port}`;
    try {
        const context = await browser.newContext({ serviceWorkers: "block" });
        const elsewhere = [];
        await context.route("**/*", (route) => {
            const u = new URL(route.request().url());
            if (u.origin === origin || (u.protocol === "https:" && u.hostname === "esm.sh")) return route.continue();
            elsewhere.push(route.request().url());
            return route.abort("blockedbyclient");
        });
        await context.addInitScript(({ blocked }) => {
            // An identity, so the page opens on its main view, and the
            // exchange URL a build before a71c32a let the user save.
            if (!sessionStorage.getItem("seeded")) {
                localStorage.setItem("retichat_identity_private_key", JSON.stringify("11".repeat(64)));
                localStorage.setItem("retichat_exchangeUrl", JSON.stringify(blocked));
                sessionStorage.setItem("seeded", "1");
            }
            window.__violations = [];
            window.addEventListener("securitypolicyviolation", (e) => window.__violations.push(`${e.effectiveDirective} ${e.blockedURI}`), true);
        }, { blocked: BLOCKED });
        const page = await context.newPage();
        const pageErrors = [];
        page.on("pageerror", (e) => pageErrors.push(e.message));
        const consoleLines = [];
        page.on("console", (m) => consoleLines.push(`${m.type()}: ${m.text()}`.slice(0, 240)));
        /** A page condition, failing the test with `what` (and the page's last
         *  console lines) if it does not hold within 10 s. */
        const until = (what, condition, arg = null) => page.waitForFunction(condition, arg, { timeout: 10_000 }).catch((e) => {
            throw new Error(`${what}: not within 10 s (${e.message.split("\n")[0]})\n${consoleLines.slice(-25).join("\n")}`);
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
        assert.deepEqual(await page.evaluate(() => [window.RetichatTest.state().status, !!window.RetichatTest.state().exchangeBlocked]), ["blocked", true],
            "the debug surface says it too");
        assert.deepEqual(await page.evaluate(() => window.__violations), [], "the blocked exchange was never asked for");
        assert.deepEqual(exchangeHits, [], "nor any exchange");

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
        await until("the new exchange reported down", () => window.RetichatTest.state().exchange === "down");
        assert.ok(exchangeHits.length > 0, "the exchange it was given was asked");
        assert.equal(await page.locator("#status-dot").getAttribute("class"), "status-dot offline");
        assert.deepEqual(await page.evaluate(() => window.__violations), [], "no violation");

        // Reloaded with the node's own URL saved, nothing is said.
        await page.reload();
        await until("the reloaded page's status", () => /status-dot (connecting|offline|online)/.test(document.getElementById("status-dot")?.className));
        assert.equal(await banner.textContent(), "", "no line for an exchange the policy allows");
        assert.deepEqual(pageErrors, []);
        assert.deepEqual(elsewhere, [], "nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        server.close();
    }
});
