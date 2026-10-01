/**
 * A CHANNEL POST'S BUBBLE FOLLOWS ITS STATUS, IN THE REAL PAGE.
 *
 * 2026-10-01, James after the retichat.com deploy: "Channels don't seem to
 * update their chat send indicator when a message successfully hits the
 * rfed node." On the private staging chain (Retichat-js f56346c) a post
 * through the composer was proved by rfed at +1596 ms and echoed at
 * +1597 ms, its record went "sent" at +1604 ms, and its bubble still showed
 * the "sending" dot 25 s later (the same for a second post: record "sent"
 * at +551 ms). The status reached the store, never the screen.
 *
 * This loads the real page (index.html, app.js, the nodes' policy) in
 * Chromium on a stand-in exchange, opens a channel and posts through the
 * composer, as a user does. rfed is played at the page's own seams: the
 * rfed.channel link is a stand-in that keeps what is published, rfed's
 * proof goes through the page's own proof handler (Reticulum "proof"), and
 * rfed's echo through _handleChannelPacket, the handler every route of
 * rfed's fan-out ends in. The bubble is read from the DOM:
 *   - proof then echo, as on staging: the bubble says "sent" as the echo is
 *     handled (on f56346c it stays "sending");
 *   - an exchange that lost the publish: "failed" at once, and rfed's echo
 *     after that makes it "sent" (no other event follows it);
 *   - a record whose status changed with no event of its own: the next
 *     message event brings its bubble in line.
 * channel_send_status.test.mjs runs the same code under Node.
 *
 * It runs only with RETICHAT_BOOT_TESTS=1 (`npm run test:full`; deploy.sh
 * always sets it), as the other Chromium tests do.
 *
 * Run: RETICHAT_BOOT_TESTS=1 node --test channel_send_status_page.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { channelIdentity } from "./lib/rns/rfed_channel.js";

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

/** The page from this directory, index.html with the nodes' policy, and a
 *  config.json naming an exchange on this server that registers the page
 *  and answers each exchange with nothing to deliver. */
async function servePageAndExchange() {
    const ROOT = fileURLToPath(new URL(".", import.meta.url));
    const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" };
    const json = (res, body) => res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
    const server = createServer(async (req, res) => {
        const path = new URL(req.url, "http://x").pathname;
        if (path === "/config.json") { json(res, { exchangeUrl: `http://127.0.0.1:${server.address().port}/exchange` }); return; }
        if (path.startsWith("/exchange/")) {
            for await (const chunk of req) void chunk;
            if (path === "/exchange/v1/interfaces/register") {
                json(res, { interface_id: "f".repeat(32), session_token: "e".repeat(64), max_batch_packets: 64, max_packet_bytes: 500, idle_exchange_interval_ms: 100 });
                return;
            }
            if (path === "/exchange/v1/interfaces/exchange") {
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
    return { origin: `http://127.0.0.1:${server.address().port}`, close() { server.close(); } };
}

/** A failure bound for a test step: `promise`, or a failure naming `what`
 *  if it has not settled in 10 s. Never a way to pass. */
function within(promise, what) {
    let timer;
    const bound = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${what}: not within 10 s`)), 10_000); });
    return Promise.race([promise, bound]).finally(() => clearTimeout(timer));
}

const CH = "public.indicator";

chromiumTest("the real page: a channel post's bubble says sent when rfed's echo comes, failed when the exchange lost it, and follows its record on every message event", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePageAndExchange();
    const { origin } = served;
    try {
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
            channels_v1: [{ channelName: CH, channelHash: channelIdentity(CH).hash.toString("hex"), rfedNodeHash: "aa".repeat(16),
                isSubscribed: true, stampCost: null, lastActivity: 3 }],
            [`cmsg_${CH}`]: [{ id: "seeded", dir: "out", content: "posted earlier", status: "sending", timestamp: Date.now() - 60_000 }],
        });
        const page = await context.newPage();
        const pageErrors = [], dialogs = [];
        page.on("pageerror", (e) => pageErrors.push(e.message));
        page.on("dialog", (d) => { dialogs.push(d.message()); d.accept().catch(() => {}); });

        await page.goto(`${origin}/index.html`);
        await within(page.waitForFunction(() => window.RetichatTest?.state().status === "online", null, { timeout: 0 }), "the page online on its exchange");

        // rfed, at the page's seams: subscribed, the stream bound, and an
        // rfed.channel link that keeps each publish (its packet hash too).
        await page.evaluate((ch) => {
            const c = window.RetichatTest.client;
            window.__published = [];
            c._ensureChannelSubscribed = async () => null;
            c._ensureChannelStreamConfigured = async () => {};
            c.openChannel = async () => {};
            c._ensureRfedLink = async () => ({
                rtt: 100,
                send(payload) {
                    const packetHash = Buffer.alloc(32, window.__published.length + 1);
                    window.__published.push({ payload: Buffer.from(payload), packetHash });
                    return { packetHash };
                },
            });
            window.RetichatTest.app.openChat(ch);
        }, CH);
        const statusOf = (text) => page.evaluate((txt) => {
            const row = [...document.querySelectorAll(".msg-row[data-msg-id]")].find((r) => r.textContent.includes(txt));
            return row ? (row.querySelector(".msg-status")?.getAttribute("data-msg-status") ?? "(none)") : "(no bubble)";
        }, text);
        const post = async (text) => {
            const n = await page.evaluate(() => window.__published.length);
            await page.locator("#composer-input").fill(text);
            await page.locator("#composer-input").press("Enter");
            await within(page.waitForFunction((k) => window.__published.length > k, n, { timeout: 0 }), `"${text}" published`);
            return n;
        };
        /** rfed proves publish `i` (the page's own proof handler) and the page has taken it. */
        const prove = (i) => within(page.evaluate((k) => new Promise((resolve) => {
            const c = window.RetichatTest.client;
            const key = window.__published[k].packetHash.subarray(0, 16).toString("hex");
            c._rns.emit("proof", { provedPacketHash: window.__published[k].packetHash.subarray(0, 16) });
            const check = () => (c._pendingPacketHashes.has(key) ? setTimeout(check, 10) : resolve());
            check();
        }), i), `the proof of publish ${i} handled`);
        /** rfed's echo of publish `i`: its fan-out to this subscriber, the post as published (no stamp here). */
        const echo = (i) => page.evaluate((k) => window.RetichatTest.client._handleChannelPacket(window.__published[k].payload), i);

        // 1. Proof, then echo, as on staging.
        const first = await post("first post");
        assert.equal(await statusOf("first post"), "sending");
        await prove(first);
        assert.equal(await statusOf("first post"), "sending", "rfed's proof alone is not sent");
        assert.equal(await echo(first), true);
        assert.equal(await statusOf("first post"), "sent", "the bubble says sent as rfed's echo is handled");

        // 2. The exchange lost the publish: failed now; rfed's echo after it: sent.
        const second = await post("second post");
        await page.evaluate((k) => window.RetichatTest.client._onPacketsLost({
            packetHashes: [window.__published[k].packetHash.toString("hex")], reason: "HTTP 502" }), second);
        assert.equal(await statusOf("second post"), "failed", "a lost publish fails the post at once");
        assert.equal(await echo(second), true);
        assert.equal(await statusOf("second post"), "sent", "rfed had it after all: the bubble follows");

        // 3. A record whose status changed without an event of its own: the
        // next message event (here a post received) brings its bubble in line.
        assert.equal(await statusOf("posted earlier"), "sending");
        await page.evaluate((ch) => {
            const key = `retichat_cmsg_${ch}`;
            const records = JSON.parse(localStorage.getItem(key));
            records.find((m) => m.id === "seeded").status = "failed";
            localStorage.setItem(key, JSON.stringify(records));
            window.RetichatTest.client._onMsg.forEach((fn) => fn({ kind: "channel-receive" }, ch));
        }, CH);
        assert.equal(await statusOf("posted earlier"), "failed");

        assert.deepEqual([dialogs, pageErrors, elsewhere], [[], [], []], "no complaint, no error, nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});
