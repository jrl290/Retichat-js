/**
 * OPENING A PENDING GROUP'S CHAT SENDS NOTHING FOR ITS MEMBERS, IN THE REAL
 * PAGE.
 *
 * James's group trust rule (2026-10-01): the members an invite lists are
 * allowed only once the user accepts it. Until then the web client asked,
 * as soon as the user opened a pending group's chat (App.openChat ->
 * RnsClient.openGroupConversation), for the path of every listed member and
 * opened a link to each. Now opening it asks nothing of them; the accept
 * does, and opening a joined group's chat still does
 * (privacy_filter.test.mjs runs the same code over stubs).
 *
 * This loads the real page in Chromium under the nodes' .htaccess policy,
 * from a local server that is also its exchange: a stand-in for
 * Reticulum-php's /v1/interfaces API (register, exchange, goodbye) that
 * answers with nothing to deliver and keeps every packet the page sends.
 * A path request carries the hash it asks for in the clear, and a link
 * request or a packet to a member carries the member's destination hash
 * in its header, so a member's hash in the bytes the page sent is
 * something asked of, or sent to, that member.
 *
 * It runs only with RETICHAT_BOOT_TESTS=1 (`npm run test:full`; deploy.sh
 * always sets it), as the other Chromium tests do.
 *
 * Run: RETICHAT_BOOT_TESTS=1 node --test pending_group_page.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Identity, Destination } from "./lib/rns/reticulum.js";

const htaccess = readFileSync(new URL("./.htaccess", import.meta.url), "utf8");
const POLICY = htaccess.match(/^\s*Header\s+(?:always\s+)?set\s+Content-Security-Policy\s+"([^"]+)"\s*$/m)[1];

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
 * config.json naming the exchange on this server ('self', which the policy
 * allows). The exchange registers the page, answers each exchange with
 * nothing to deliver, and keeps what it was sent: `exchanges` counts the
 * exchange requests, `packets` holds every packet in them (raw bytes), and
 * `afterExchanges(n)` resolves once n more exchange requests have come.
 */
async function servePageAndExchange() {
    const ROOT = fileURLToPath(new URL(".", import.meta.url));
    const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" };
    const packets = [];
    const waiters = [];
    let exchanges = 0;
    const json = (res, body) => res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
    const server = createServer(async (req, res) => {
        const path = new URL(req.url, "http://x").pathname;
        if (path === "/config.json") { json(res, { exchangeUrl: `http://127.0.0.1:${server.address().port}/exchange` }); return; }
        if (path.startsWith("/exchange/")) {
            let body = "";
            for await (const chunk of req) body += chunk;
            if (path === "/exchange/v1/interfaces/register") {
                json(res, { interface_id: "f".repeat(32), session_token: "e".repeat(64), max_batch_packets: 64, max_packet_bytes: 500, idle_exchange_interval_ms: 100 });
                return;
            }
            if (path === "/exchange/v1/interfaces/exchange") {
                for (const p of JSON.parse(body).packets ?? []) packets.push(Buffer.from(p, "base64"));
                exchanges++;
                for (const w of waiters.splice(0)) if (exchanges >= w.at) w.resolve(); else waiters.push(w);
                json(res, { delivery_packets: [], delivery_batch_id: null, idle_exchange_interval_ms: 100 });
                return;
            }
            res.writeHead(200).end();
            return;
        }
        const file = join(ROOT, path.endsWith("/") ? `${path}index.html` : path);
        try {
            const data = await readFile(file);
            res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store",
                ...(file.endsWith("index.html") ? { "content-security-policy": POLICY } : {}) }).end(data);
        } catch {
            res.writeHead(404).end();
        }
    });
    await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
    return {
        origin: `http://127.0.0.1:${server.address().port}`, packets,
        afterExchanges: (n) => new Promise((resolve) => waiters.push({ at: exchanges + n, resolve })),
        close() { server.close(); },
    };
}

/** A failure bound for a test step: `promise`, or a failure naming `what`
 *  if it has not settled in 10 s. Never a way to pass. */
function within(promise, what) {
    let timer;
    const bound = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${what}: not within 10 s`)), 10_000); });
    return Promise.race([promise, bound]).finally(() => clearTimeout(timer));
}

const deliveryHash = (id) => Destination.hash(id, "lxmf", "delivery").toString("hex");
const id = (byte) => Identity.fromPrivateKey(Buffer.from(byte.repeat(64), "hex"));

chromiumTest("the real page: opening a pending group's chat sends nothing that names its members; opening a joined group's chat still asks for its member, and the user's accept asks for the pending group's members", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePageAndExchange();
    const { origin, packets, afterExchanges } = served;
    try {
        // An invite waiting from an allowlisted contact (I), listing O, whose
        // key is held (hidden, not allowlisted); and a group already joined
        // with M, allowlisted, never asked for.
        const [own, inviter, other, joined] = [id("11"), id("22"), id("33"), id("44")];
        const [ME, I, O, M] = [own, inviter, other, joined].map(deliveryHash);
        const row = (who, allowlisted) => ({ destHash: deliveryHash(who), publicKey: who.getPublicKey().toString("hex"), hidden: true, allowlisted,
            localName: null, messageName: null, messageNameAt: null, announceName: null, legacyName: null, isDistro: false });
        const PENDING = "ab".repeat(16), JOINED = "cd".repeat(16);
        const context = await browser.newContext({ serviceWorkers: "block" });
        const elsewhere = [];
        await context.route("**/*", (route) => {
            const u = new URL(route.request().url());
            if (u.origin === origin || (u.protocol === "https:" && u.hostname === "esm.sh")) return route.continue();
            elsewhere.push(route.request().url());
            return route.abort("blockedbyclient");
        });
        await context.addInitScript((seed) => {
            if (sessionStorage.getItem("seeded")) return;
            for (const [k, v] of Object.entries(seed)) localStorage.setItem(`retichat_${k}`, JSON.stringify(v));
            sessionStorage.setItem("seeded", "1");
        }, {
            identity_private_key: "11".repeat(64),
            groupMembersAllowlisted: 2,
            contacts_v2: [row(inviter, true), row(other, false), row(joined, true)],
            groups_v1: [
                { groupId: PENDING, groupName: "Pending G", groupStatus: "pending", lastActivity: 2,
                    members: [{ hash: I, status: "accepted" }, { hash: O, status: "invited" }, { hash: ME, status: "invited" }] },
                { groupId: JOINED, groupName: "Joined J", groupStatus: "active", lastActivity: 1,
                    members: [{ hash: M, status: "accepted" }, { hash: ME, status: "accepted" }] },
            ],
        });
        const page = await context.newPage();
        const pageErrors = [], dialogs = [];
        page.on("pageerror", (e) => pageErrors.push(e.message));
        page.on("dialog", (d) => { dialogs.push(d.message()); d.accept().catch(() => {}); });
        /** Which of `hashes` the page has sent a packet naming. */
        const named = (...hashes) => hashes.filter((h) => packets.some((p) => p.includes(Buffer.from(h, "hex"))));
        /** Resolves once the page has sent a packet naming every one of
         *  `hashes`, looking after each exchange; fails after 10 s. */
        const untilNamed = (what, ...hashes) => {
            let failed = false;
            return within((async () => {
                while (!failed && named(...hashes).length < hashes.length) await afterExchanges(1);
            })(), what).catch((e) => { failed = true; throw e; });
        };

        await page.goto(`${origin}/index.html`);
        await within(page.waitForFunction(() => window.RetichatTest?.state().status === "online", null, { timeout: 0 }), "the page online on its exchange");
        assert.equal(await page.evaluate(() => window.RetichatTest.state().ownHash), ME);
        await untilNamed("the page's own announce", ME);

        // The user opens the pending group's chat. Anything it asked of the
        // members was queued as the click ran, and goes in the exchange that
        // follows the one in flight: two more exchanges carry it.
        await page.locator(".contact-item", { hasText: "Pending G" }).first().click();
        await page.locator(".pending-invite-bar").waitFor();
        await within(afterExchanges(2), "two exchanges after the chat opened");
        await within(afterExchanges(1), "and one more");
        assert.deepEqual(named(I, O), [], "nothing names the inviter or the listed member: no path request, no link");

        // A joined group's chat is opened as before: its member's path asked.
        assert.deepEqual(named(M), [], "M not asked for until his group's chat is opened");
        await page.locator(".contact-item", { hasText: "Joined J" }).first().click();
        await untilNamed("the joined group's member asked for", M);

        // The user accepts the invite: now the members are asked for (paths,
        // then the accept sent to each).
        await page.locator(".contact-item", { hasText: "Pending G" }).first().click();
        await page.getByRole("button", { name: "Accept", exact: true }).first().click();
        await untilNamed("the pending group's members asked for once the user accepts", I, O);
        assert.equal(await page.evaluate((gid) => JSON.parse(localStorage.getItem("retichat_groups_v1")).find((g) => g.groupId === gid).groupStatus, PENDING), "active");
        assert.deepEqual([dialogs, pageErrors, elsewhere], [[], [], []], "no complaint, no error, nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});

chromiumTest("the real page: declining a pending invite sends the user's leave, as leaving does (James, 2026-10-02): every listed member is asked for, the inviter and the one still invited alike, and the group is closed at once", async (t) => {
    // privacy_filter.test.mjs runs the same code over stubs and checks the
    // message itself; here the real page, on the user's click. The stand-in
    // exchange answers no path request, so what shows is each member's
    // path asked, the first step of the leave's delivery to it.
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePageAndExchange();
    const { origin, packets, afterExchanges } = served;
    try {
        const [own, inviter, other, gone] = [id("11"), id("22"), id("33"), id("55")];
        const [ME, I, O, X] = [own, inviter, other, gone].map(deliveryHash);
        const row = (who, allowlisted) => ({ destHash: deliveryHash(who), publicKey: who.getPublicKey().toString("hex"), hidden: true, allowlisted,
            localName: null, messageName: null, messageNameAt: null, announceName: null, legacyName: null, isDistro: false });
        const PENDING = "ef".repeat(16);
        const context = await browser.newContext({ serviceWorkers: "block" });
        const elsewhere = [];
        await context.route("**/*", (route) => {
            const u = new URL(route.request().url());
            if (u.origin === origin || (u.protocol === "https:" && u.hostname === "esm.sh")) return route.continue();
            elsewhere.push(route.request().url());
            return route.abort("blockedbyclient");
        });
        // An invite from an allowlisted contact (I), listing O (key held,
        // not allowlisted, not answered) and X (who declined before).
        await context.addInitScript((seed) => {
            if (sessionStorage.getItem("seeded")) return;
            for (const [k, v] of Object.entries(seed)) localStorage.setItem(`retichat_${k}`, JSON.stringify(v));
            sessionStorage.setItem("seeded", "1");
        }, {
            identity_private_key: "11".repeat(64),
            groupMembersAllowlisted: 2,
            contacts_v2: [row(inviter, true), row(other, false), row(gone, false)],
            groups_v1: [
                { groupId: PENDING, groupName: "Pending G", groupStatus: "pending", lastActivity: 2,
                    members: [{ hash: I, status: "accepted" }, { hash: O, status: "invited" }, { hash: X, status: "left" }, { hash: ME, status: "invited" }] },
            ],
        });
        const page = await context.newPage();
        const pageErrors = [], dialogs = [];
        page.on("pageerror", (e) => pageErrors.push(e.message));
        page.on("dialog", (d) => { dialogs.push(d.message()); d.accept().catch(() => {}); });
        const named = (...hashes) => hashes.filter((h) => packets.some((p) => p.includes(Buffer.from(h, "hex"))));
        const untilNamed = (what, ...hashes) => {
            let failed = false;
            return within((async () => {
                while (!failed && named(...hashes).length < hashes.length) await afterExchanges(1);
            })(), what).catch((e) => { failed = true; throw e; });
        };

        await page.goto(`${origin}/index.html`);
        await within(page.waitForFunction(() => window.RetichatTest?.state().status === "online", null, { timeout: 0 }), "the page online on its exchange");
        await untilNamed("the page's own announce", ME);
        await page.locator(".contact-item", { hasText: "Pending G" }).first().click();
        await page.locator(".pending-invite-bar").waitFor();
        await within(afterExchanges(2), "two exchanges after the chat opened");
        assert.deepEqual(named(I, O, X), [], "opening the invite asks nothing of anyone");

        // The user declines.
        await page.getByRole("button", { name: "Decline", exact: true }).first().click();
        assert.deepEqual(dialogs, ["Decline this group invite? You won't be able to join this group later."]);
        const stored = (key) => page.evaluate((k) => JSON.parse(localStorage.getItem(`retichat_${k}`)), key);
        assert.equal((await stored("groups_v1")).some((g) => g.groupId === PENDING), false, "the group is gone at once");
        assert.deepEqual(await stored("groups_closed_v1"), [[PENDING, "rejected"]], "and recorded as declined");
        await untilNamed("the leave on its way to the inviter and to the member still invited", I, O);
        await within(afterExchanges(2), "two more exchanges");
        assert.deepEqual(named(X), [], "nothing for X, who declined before");
        assert.equal(await page.locator(".contact-item", { hasText: "Pending G" }).count(), 0, "not offered any more");
        assert.deepEqual([pageErrors, elsewhere], [[], []], "no error, nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});
