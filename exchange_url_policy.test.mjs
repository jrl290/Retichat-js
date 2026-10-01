/**
 * SETTINGS REFUSES AN EXCHANGE THE PAGE'S POLICY WOULD BLOCK.
 *
 * The page is served with a Content-Security-Policy (.htaccess, on
 * index.html) whose connect-src names this origin, the production nodes'
 * exchanges and esm.sh. An exchange URL on any other host typed in Settings
 * used to be saved, and then every request to it was refused by the
 * browser before it was sent: the page sat offline with nothing to say why.
 * Now Save refuses it, says why under the field, and saves nothing
 * (App._saveSettings, PagePolicy, lib/connect_policy.js).
 *
 * The allowed origins are never restated: the page reads the header it is
 * served with (a fetch of its own URL), which the nodes build from the
 * .htaccess line, and these tests run the rules against that line itself.
 * A page served with no policy (a local server) refuses nothing.
 *
 * One test asks Chromium itself (RETICHAT_BOOT_TESTS=1, as deploy.sh runs
 * the suite): under the .htaccess policy, with its hosts renamed to .invalid
 * ones so nothing leaves this machine, the browser lets through exactly the
 * exchanges these rules allow, and each it refuses is told to the page in a
 * securitypolicyviolation event that exchangeRefusalFromViolation reads as
 * that exchange's refusal, in the words Settings gives
 * (RnsClient._watchExchangeRefusal, exchange_url_at_load.test.mjs).
 *
 * Run: node --test exchange_url_policy.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { connectSourceLists, exchangeUrlRefusal, exchangeRefusalFromViolation, isExchangeRequest, sourceListAllows, EXCHANGE_PATHS } from "./lib/connect_policy.js";
import { app, build, compile, methodBody } from "./test_app_source.mjs";

const htaccess = readFileSync(new URL("./.htaccess", import.meta.url), "utf8");
/** The policy the nodes send with index.html: the .htaccess line, read as
 *  the boot gate reads it. */
const POLICY = htaccess.match(/^\s*Header\s+(?:always\s+)?set\s+Content-Security-Policy\s+"([^"]+)"\s*$/m)[1];
const PAGES = ["https://retichat.com/", "https://selectivesubconscious.com/retichat/", "https://selectivesubconscious.com/retichat/index.html"];
const DEFAULT_EXCHANGE = app.match(/const DEFAULT_CONFIG = \{[\s\S]*?exchangeUrl: "([^"]+)"/)[1];
const quiet = { log() {}, warn() {}, error() {} };

test("under the nodes' policy: their exchanges and the page's own origin are allowed; any other host, port or scheme is refused, saying why", () => {
    const [connect] = connectSourceLists(POLICY);
    assert.ok(connect.includes("'self'"), "(the policy's connect-src, read from .htaccess)");
    // Every exchange connect-src names (a path source), with and without
    // the trailing "/", and the fallback config: from every production page.
    const exchanges = connect.filter((s) => /^https:\/\/[^/]+\/.+\/$/.test(s));
    assert.ok(exchanges.length >= 2, "the production nodes' exchanges");
    for (const page of PAGES) {
        for (const url of [...exchanges, ...exchanges.map((e) => e.slice(0, -1)), DEFAULT_EXCHANGE]) {
            assert.equal(exchangeUrlRefusal(url, POLICY, page), null, `${url} from ${page}`);
        }
        // 'self': the node serving the page, by a relative or absolute URL.
        const origin = new URL(page).origin;
        for (const url of ["/reticulum", "./x/reticulum", `${origin}/anything/at/all`]) {
            assert.equal(exchangeUrlRefusal(url, POLICY, page), null, `${url} from ${page} ('self')`);
        }
    }

    const refusal = exchangeUrlRefusal("https://example.com/reticulum", POLICY, "https://retichat.com/");
    assert.match(refusal, /^This page's Content-Security-Policy lets it connect only to this page's own origin \(https:\/\/retichat\.com\), /);
    assert.match(refusal, /https:\/\/retichat\.com\/reticulum\/, https:\/\/selectivesubconscious\.com\/reticulum\/, https:\/\/esm\.sh\. /,
        "it names what the policy allows, as the policy says it");
    assert.match(refusal, /The exchange https:\/\/example\.com\/reticulum is not among them, so the browser would refuse every request to it and the page would stay offline\.$/);
    assert.doesNotMatch(refusal, /saved/i, "saving is Settings' to speak of (PagePolicy.exchangeRefusal); the page at load uses the same reason");
    assert.equal(exchangeUrlRefusal("http://[::1", POLICY, "https://retichat.com/"), "\"http://[::1\" is not a URL.");

    for (const [url, page] of [
        ["http://127.0.0.1:8080", "https://retichat.com/"],                                       // the local node, from a production page
        ["https://other-node.example/reticulum", "https://selectivesubconscious.com/retichat/"],  // a host no source names
        ["http://retichat.com/reticulum", "https://selectivesubconscious.com/retichat/"],        // https only, and no 'self' upgrade off this host
        ["https://retichat.com:8443/reticulum", "https://retichat.com/"],                        // another port
        ["https://retichat.com/elsewhere", "https://selectivesubconscious.com/retichat/"],       // a production host outside its exchange path
        ["https://retichat.com/reticulum2", "https://selectivesubconscious.com/retichat/"],      // "/reticulum/" is a segment prefix, not a string one
        ["wss://retichat.com/reticulum", "https://selectivesubconscious.com/retichat/"],
    ]) {
        assert.match(exchangeUrlRefusal(url, POLICY, page) ?? "", /is not among them/, `${url} from ${page}`);
    }
});

test("a page served with no policy refuses nothing: a local server and its local exchange", () => {
    for (const header of [null, undefined, "", "   "]) {
        assert.equal(exchangeUrlRefusal("http://127.0.0.1:8080", header, "http://127.0.0.1:8000/index.html"), null);
        assert.equal(exchangeUrlRefusal("https://anywhere.example/x", header, "http://localhost:8000/"), null);
    }
    // A policy that does not restrict connections: no connect-src, no default-src.
    assert.equal(exchangeUrlRefusal("https://anywhere.example/x", "script-src 'self'; object-src 'none'", "https://a.example/"), null);
});

test("the requests checked are the ones PostInterface makes: the base without a trailing \"/\", then each path", () => {
    const iface = readFileSync(new URL("./lib/rns/interfaces/post_interface.js", import.meta.url), "utf8");
    assert.match(iface, /this\._baseUrl = baseUrl\.replace\(\/\\\/\$\/, ""\);/);
    const used = [...iface.matchAll(/'(\/v1\/interfaces\/[a-z]+)'/g)].map((m) => m[1]);
    assert.deepEqual([...new Set(used)].sort(), [...EXCHANGE_PATHS].sort(), "every path PostInterface requests, and only those");
    // An exact path source allows the one URL it names: no exchange fits it.
    assert.match(exchangeUrlRefusal("https://n.example/reticulum", "connect-src https://n.example/reticulum", "https://p.example/") ?? "", /not among/);
    assert.equal(exchangeUrlRefusal("https://n.example/reticulum", "connect-src https://n.example/reticulum/", "https://p.example/"), null);
    // Every one of them is checked: a policy naming each request exactly is
    // enough, and one that leaves any of them out, whichever, is refused.
    const exact = (paths) => `connect-src ${paths.map((path) => `https://n.example/reticulum${path}`).join(" ")}`;
    assert.equal(exchangeUrlRefusal("https://n.example/reticulum", exact(EXCHANGE_PATHS), "https://p.example/"), null);
    for (const missing of EXCHANGE_PATHS) {
        const policy = exact(EXCHANGE_PATHS.filter((path) => path !== missing));
        assert.match(exchangeUrlRefusal("https://n.example/reticulum", policy, "https://p.example/") ?? "", /not among/, `without ${missing}`);
    }
});

test("a securitypolicyviolation names the exchange when its URL is one of the requests PostInterface makes there, as fetch resolves it and CSP reports it", () => {
    const page = "https://p.example/retichat/";
    for (const base of ["https://n.example/reticulum", "https://n.example/reticulum/", "  https://n.example/reticulum/  "]) {
        for (const path of EXCHANGE_PATHS) {
            assert.equal(isExchangeRequest(`https://n.example/reticulum${path}`, base, page), true, `${JSON.stringify(base)} ${path}`);
        }
    }
    // A relative exchange URL resolves against the page, as fetch does it.
    assert.equal(isExchangeRequest("https://p.example/reticulum/v1/interfaces/register", "/reticulum", page), true);
    assert.equal(isExchangeRequest("https://p.example/retichat/x/v1/interfaces/exchange", "./x", page), true);
    // CSP reports a URL without its fragment; one given with it still matches.
    assert.equal(isExchangeRequest("https://n.example/reticulum/v1/interfaces/goodbye#f", "https://n.example/reticulum", page), true);
    // Anything else is not the exchange's: another path, host, port or
    // scheme, the base alone, an origin only (a redirect's target, as CSP
    // reports it), a keyword CSP reports for inline code, nothing at all.
    for (const blocked of ["https://n.example/reticulum/v1/interfaces/registers", "https://n.example/reticulum/v1/interfaces",
        "https://n.example/reticulum", "https://n.example/other/v1/interfaces/register", "https://m.example/reticulum/v1/interfaces/register",
        "https://n.example:8443/reticulum/v1/interfaces/register", "http://n.example/reticulum/v1/interfaces/register",
        "https://n.example", "https://n.example/", "inline", "eval", "", undefined, null]) {
        assert.equal(isExchangeRequest(blocked, "https://n.example/reticulum", page), false, String(blocked));
    }
    assert.equal(isExchangeRequest("https://n.example/reticulum/v1/interfaces/register", "not a url at all", "not a page"), false);
});

test("exchangeRefusalFromViolation: the browser refusing the exchange under a policy it enforces gives the reason Settings gives; any other violation gives nothing", () => {
    const page = "https://retichat.com/";
    const exchange = "https://other-node.example/reticulum";
    const refused = (over = {}) => ({ blockedURI: `${exchange}/v1/interfaces/register`, effectiveDirective: "connect-src", violatedDirective: "connect-src",
        disposition: "enforce", originalPolicy: POLICY, ...over });
    // The reason is exchangeUrlRefusal's for the policy the event carries.
    assert.equal(exchangeRefusalFromViolation(refused(), exchange, page), exchangeUrlRefusal(exchange, POLICY, page));
    assert.match(exchangeRefusalFromViolation(refused(), exchange, page), /The exchange https:\/\/other-node\.example\/reticulum is not among them/);
    for (const path of EXCHANGE_PATHS) {
        assert.notEqual(exchangeRefusalFromViolation(refused({ blockedURI: `${exchange}${path}` }), `${exchange}/`, page), null, path);
    }
    // Not the exchange's refusal: a report-only policy refuses nothing;
    // another directive is no connection; another URL is not this exchange.
    for (const [what, event] of [
        ["report-only", refused({ disposition: "report" })],
        ["no disposition", refused({ disposition: undefined })],
        ["img-src", refused({ effectiveDirective: "img-src", violatedDirective: "img-src" })],
        ["script-src", refused({ effectiveDirective: "script-src-elem" })],
        ["another URL", refused({ blockedURI: "https://esm.sh/x" })],
        ["inline code", refused({ blockedURI: "inline", effectiveDirective: "script-src-elem" })],
        ["no event", null],
    ]) {
        assert.equal(exchangeRefusalFromViolation(event, exchange, page), null, what);
    }
    assert.equal(exchangeRefusalFromViolation(refused(), "https://retichat.com/reticulum", page), null, "another exchange's refusal is not this one's");
    // Should these rules allow what the browser refused (a source they read
    // otherwise), the reason is the event's own facts, not silence.
    const policy = "connect-src https://other-node.example/reticulum/";
    assert.equal(exchangeUrlRefusal(exchange, policy, page), null, "(the rules allow it)");
    assert.equal(exchangeRefusalFromViolation(refused({ originalPolicy: policy }), exchange, page),
        `The browser refused the request to ${exchange}/v1/interfaces/register under this page's Content-Security-Policy ("${policy}"), so the page would stay offline.`);
});

test("CSP Level 3 matching: default-src stands in, every policy must allow, 'none', schemes, wildcards, ports, paths, 'self' upgrades", () => {
    const page = new URL("https://p.example/app/");
    const allows = (sources, url, self = page) => sourceListAllows(sources, new URL(url), self);
    assert.deepEqual(connectSourceLists("default-src 'self'; connect-src https://a.example; connect-src https://b.example"), [["https://a.example"]],
        "connect-src, the first of a repeated directive");
    assert.deepEqual(connectSourceLists("default-src 'self' https://a.example; img-src *"), [["'self'", "https://a.example"]], "default-src stands in");
    assert.deepEqual(connectSourceLists("connect-src https://a.example, connect-src https://b.example"), [["https://a.example"], ["https://b.example"]]);
    assert.match(exchangeUrlRefusal("https://a.example/x", "connect-src https://a.example, connect-src https://b.example", page.href) ?? "",
        /not among/, "two policies: each must allow it");
    assert.equal(allows(["'none'"], "https://p.example/x"), false);
    assert.equal(allows([], "https://p.example/x"), false);
    assert.equal(allows(["https:"], "https://q.example/x"), true);
    assert.equal(allows(["https:"], "http://q.example/x"), false);
    assert.equal(allows(["http:"], "https://q.example/x"), true, "http: allows its upgrade");
    assert.equal(allows(["*"], "https://q.example:9/x"), true);
    assert.equal(allows(["*.a.example"], "https://b.a.example/x"), true);
    assert.equal(allows(["*.a.example"], "https://a.example/x"), false, "a wildcard is for subdomains only");
    assert.equal(allows(["https://a.example:*"], "https://a.example:9/x"), true);
    assert.equal(allows(["https://a.example:443"], "https://a.example/x"), true, "the scheme's default port");
    assert.equal(allows(["https://a.example"], "https://a.example:444/x"), false);
    assert.equal(allows(["a.example"], "https://a.example/x"), true, "no scheme: the page's");
    assert.equal(allows(["a.example"], "http://a.example/x"), false);
    assert.equal(allows(["http://a.example"], "https://a.example/x"), true, "http:// allows its upgrade to https");
    assert.equal(allows(["https://a.example/r/"], "https://a.example/r"), true, "a path ending in / covers its own segment");
    assert.equal(allows(["https://a.example/r/"], "https://a.example/r/v1/x"), true);
    assert.equal(allows(["https://a.example/r/"], "https://a.example/rr/x"), false);
    assert.equal(allows(["https://a.example/r%20s/"], "https://a.example/r s/x"), true, "segments compared percent-decoded");
    assert.equal(allows(["'self'"], "https://p.example/x"), true);
    assert.equal(allows(["'self'"], "wss://p.example/x"), true, "'self' from https: wss too");
    assert.equal(allows(["'self'"], "http://p.example/x"), false, "but never down to http");
    assert.equal(allows(["'self'"], "https://p.example/x", new URL("http://p.example/")), true, "from an http page: its https upgrade");
    assert.equal(allows(["'self'"], "https://p.example:8443/x"), false);
    for (const keyword of ["'unsafe-inline'", "'nonce-abc'", "'sha256-abc='", "'strict-dynamic'"]) {
        assert.equal(allows([keyword], "https://p.example/x"), false, keyword);
    }
});

// ── the page: PagePolicy and Save ──────────────────────────────────────────

/** A response as fetch gives it: a status and its headers. */
const response = (status, headers = {}) => ({
    ok: status >= 200 && status < 300, status,
    headers: new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
    body: { cancel: async () => {} },
});

/** The real PagePolicy and _saveSettings over a page at `href`, served by
 *  `serve(request)` (a response, or a throw for no answer). */
function settingsPage({ href = "https://retichat.com/", current = "https://retichat.com/reticulum", serve }) {
    const fetched = [];
    const fetch = async (url, init) => { fetched.push([url, init]); return serve(url, init); };
    const location = { href };
    const PagePolicy = build("PagePolicy", { fetch, location, exchangeUrlRefusal, console: quiet, Date });
    const elements = {
        "cfg-exchange": { value: "" },
        "cfg-exchange-refusal": { textContent: "" },
    };
    const saved = [];
    const reconnects = [];
    const RnsClient = { _cfg: { exchangeUrl: current }, reconnect: async () => { reconnects.push(RnsClient._cfg.exchangeUrl); } };
    const self = { state: { showSettings: true }, renders: 0, render() { this.renders++; } };
    const save = compile("async _saveSettings()", {
        document: { getElementById: (id) => elements[id] ?? null },
        PagePolicy, RnsClient, OwnNames: {}, sSet: (k, v) => saved.push([k, v]), console: quiet,
    })(self);
    /** Type `url` into the field and press Save. */
    const enter = async (url) => { elements["cfg-exchange"].value = url; await save(); };
    return { enter, fetched, saved, reconnects, self, refusal: () => elements["cfg-exchange-refusal"].textContent, RnsClient };
}

test("Save refuses an exchange the served policy would block: nothing saved, no reconnect, the reason under the field; an allowed one is saved", async () => {
    const page = settingsPage({ serve: () => response(200, { "Content-Security-Policy": POLICY }) });
    await page.enter("https://example.com/reticulum");
    assert.match(page.refusal(), /^This page's Content-Security-Policy lets it connect only to .*The exchange https:\/\/example\.com\/reticulum is not among them.*Not saved\.$/);
    assert.deepEqual(page.saved, [], "nothing saved");
    assert.deepEqual(page.reconnects, [], "no reconnect");
    assert.equal(page.self.state.showSettings, true, "Settings stays open, showing why");
    assert.equal(page.RnsClient._cfg.exchangeUrl, "https://retichat.com/reticulum", "the connection keeps its exchange");
    assert.deepEqual(page.fetched.map(([url, init]) => [url, init?.cache]), [["https://retichat.com/", "no-store"]],
        "the policy read from the page's own URL, past the cache");

    await page.enter("https://selectivesubconscious.com/reticulum");
    assert.deepEqual(page.saved.find(([k]) => k === "exchangeUrl"), ["exchangeUrl", "https://selectivesubconscious.com/reticulum"]);
    assert.deepEqual(page.reconnects, ["https://selectivesubconscious.com/reticulum"]);
    assert.equal(page.self.state.showSettings, false, "saved and closed");
    assert.equal(page.fetched.length, 1, "the header is read once per page load");

    // The field unchanged: nothing to check, whatever it holds.
    const same = settingsPage({ current: "http://127.0.0.1:8080", serve: () => response(200, { "Content-Security-Policy": POLICY }) });
    await same.enter("http://127.0.0.1:8080");
    assert.deepEqual([same.fetched.length, same.reconnects.length], [0, 1], "an unchanged URL is not checked");
});

test("Save on a page served with no policy (a local server) refuses nothing", async () => {
    const page = settingsPage({ href: "http://127.0.0.1:8000/index.html", current: "http://127.0.0.1:8080", serve: () => response(200, {}) });
    await page.enter("http://127.0.0.1:8081");
    assert.equal(page.refusal(), "");
    assert.deepEqual(page.reconnects, ["http://127.0.0.1:8081"]);
});

test("a policy that cannot be read decides nothing: the change is refused with that reason, and the next Save reads again", async () => {
    let answer = () => { throw new TypeError("Failed to fetch"); };
    const page = settingsPage({ serve: () => answer() });
    await page.enter("https://selectivesubconscious.com/reticulum");
    assert.match(page.refusal(), /^Could not check the exchange URL against this page's Content-Security-Policy: the page's own server did not answer \(Failed to fetch\)\. Not saved\.$/);
    assert.deepEqual([page.saved, page.reconnects], [[], []]);

    answer = () => response(404, {});
    await page.enter("https://selectivesubconscious.com/reticulum");
    assert.match(page.refusal(), /\(HTTP 404\)\. Not saved\.$/, "not a 2xx: Apache sets the header on successful responses only");
    assert.deepEqual(page.reconnects, []);

    answer = () => response(200, { "Content-Security-Policy": POLICY });
    await page.enter("https://selectivesubconscious.com/reticulum");
    assert.deepEqual(page.reconnects, ["https://selectivesubconscious.com/reticulum"], "read again, and allowed");
    assert.equal(page.fetched.length, 3);
});

test("the Settings field: the refusal shows under it, and editing it clears it", () => {
    const modal = methodBody("_renderSettingsModal()");
    assert.match(modal, /h\("div", \{ className: "field-error", id: "cfg-exchange-refusal", role: "alert" \}, RnsClient\.exchangeBlocked\)/,
        "empty, or, when Settings opens on a saved URL the page found blocked, why (exchange_url_at_load.test.mjs)");
    assert.match(modal, /id: "cfg-exchange", type: "text"[\s\S]{0,200}onInput: \(\) => \{ const el = document\.getElementById\("cfg-exchange-refusal"\); if \(el\) el\.textContent = ""; \}/);
    const css = readFileSync(new URL("./style.css", import.meta.url), "utf8");
    assert.match(css, /\.settings-field \.field-error:empty \{ display: none; \}/);
    // The check comes first in Save: a refused URL saves nothing at all.
    const save = methodBody("async _saveSettings()");
    assert.ok(save.indexOf("PagePolicy.exchangeRefusal(exchangeUrl)") < save.indexOf("OwnNames[setter]"), "before anything is saved");
    assert.match(app, /\nimport \{ exchangeUrlRefusal, exchangeRefusalFromViolation \} from "\.\/lib\/connect_policy\.js";\n/);
});

// ── against Chromium's own enforcement ─────────────────────────────────────

const BOOT_TESTS = process.env.RETICHAT_BOOT_TESTS === "1";
const chromiumTest = BOOT_TESTS ? test
    : (name, fn) => test(name, { skip: "RETICHAT_BOOT_TESTS is not 1: run `npm run test:full` (deploy.sh always does)" }, fn);

chromiumTest("Chromium lets through exactly the exchanges these rules allow, under the .htaccess policy (its hosts renamed .invalid)", async (t) => {
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
    // The nodes' policy with every host renamed: the same sources, paths and
    // schemes, and no request can reach a real host.
    const RENAME = [["https://retichat.com/", "https://node-a.invalid/"], ["https://selectivesubconscious.com/", "https://node-b.invalid/"],
        ["https://esm.sh", "https://cdn.invalid"]];
    let policy = POLICY;
    for (const [from, to] of RENAME) {
        assert.ok(policy.includes(from), `(the policy names ${from})`);
        policy = policy.replaceAll(from, to);
    }
    assert.doesNotMatch(policy, /https?:\/\/(?![a-z-]+\.invalid)/, "every host renamed");
    const bases = ["https://node-a.invalid/reticulum", "https://node-b.invalid/reticulum/", "/reticulum", "https://node-a.invalid/elsewhere",
        "https://node-a.invalid/reticulum2", "https://node-a.invalid:8443/reticulum", "https://other.invalid/reticulum", "http://node-a.invalid/reticulum",
        "http://127.0.0.1:8080", "https://cdn.invalid/x"];
    try {
        for (const pageUrl of ["https://node-a.invalid/", "https://node-b.invalid/retichat/"]) {
            const context = await browser.newContext({ serviceWorkers: "block" });
            const reached = [];
            await context.route("**/*", (route) => {
                const url = route.request().url();
                if (url === pageUrl) {
                    return route.fulfill({ status: 200, contentType: "text/html", headers: { "content-security-policy": policy },
                        body: "<!DOCTYPE html><title>policy</title>" });
                }
                reached.push(url);
                return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
            });
            const page = await context.newPage();
            await page.goto(pageUrl);
            // What the page hears of each refusal (RnsClient._watchExchangeRefusal).
            await page.evaluate(() => {
                window.__violations = [];
                document.addEventListener("securitypolicyviolation", (e) => window.__violations.push({ blockedURI: e.blockedURI,
                    effectiveDirective: e.effectiveDirective, disposition: e.disposition, originalPolicy: e.originalPolicy }));
            });
            const refusedUrls = new Map();   // each URL Chromium refused -> the base it is a request of
            for (const base of bases) {
                const want = exchangeUrlRefusal(base, policy, pageUrl) === null;
                const urls = EXCHANGE_PATHS.map((path) => new URL(base.replace(/\/$/, "") + path, pageUrl).href);
                const outcomes = await page.evaluate(async (list) => Promise.all(list.map((u) =>
                    fetch(u, { method: "POST", body: "{}" }).then(() => "sent", () => "refused"))), urls);
                assert.deepEqual(outcomes, urls.map(() => (want ? "sent" : "refused")),
                    `${base} from ${pageUrl}: the rules say ${want ? "allowed" : "refused"}, Chromium ${outcomes.join("/")}`);
                if (!want) for (const u of urls) refusedUrls.set(u, base);
            }
            // Each refusal is told to the page, once, and read as the refusal
            // of exactly the exchange it is a request of, with Settings' words.
            await page.waitForFunction((n) => window.__violations.length >= n, refusedUrls.size, { timeout: 10_000 });
            const violations = await page.evaluate(() => window.__violations);
            assert.deepEqual(violations.map((v) => v.blockedURI).sort(), [...refusedUrls.keys()].sort(), "one event per refused request");
            for (const v of violations) {
                const base = refusedUrls.get(v.blockedURI);
                assert.deepEqual([v.effectiveDirective, v.disposition, v.originalPolicy], ["connect-src", "enforce", policy]);
                assert.equal(exchangeRefusalFromViolation(v, base, pageUrl), exchangeUrlRefusal(base, policy, pageUrl), `${v.blockedURI} read for ${base}`);
                for (const other of bases.filter((b) => b !== base && !EXCHANGE_PATHS.some((path) => new URL(b.replace(/\/$/, "") + path, pageUrl).href === v.blockedURI))) {
                    assert.equal(exchangeRefusalFromViolation(v, other, pageUrl), null, `${v.blockedURI} is not ${other}'s`);
                }
            }
            assert.ok(reached.every((u) => new URL(u).hostname.endsWith(".invalid")), `only .invalid hosts were asked for: ${reached}`);
            await context.close();
        }
    } finally {
        await browser.close();
    }
});
