/**
 * CHANNELS AND THE DISTRO, IN THE REAL PAGE — RFed-rust SPEC.md §17.12,
 * RFed-spec/Channel.md "Distro holders" (James, 2026-10-03).
 *
 * The page (index.html, app.js, the nodes' policy) in Chromium on a
 * stand-in exchange, holding a distro D and two channels, one of them open:
 *   - a post the user made as D on another device is the user's own bubble,
 *     "sent", with no sender label (on 24d83e6 a stranger's bubble, labelled
 *     with the device's hash);
 *   - a join made on another device puts the channel in the chat list, and
 *     a leave made there takes the open channel away and closes its chat;
 *   - the Leave button sends the user's leave to the distro as one
 *     membership message, and a post made here is signed as D.
 * rfed is played at the page's own seams: rfed.link and the propagation
 * link are stand-ins that keep what the page sends, and rfed's fan-out goes
 * through _handleChannelPacket and _handleDistroBlob, the handlers every
 * route of it ends in. distro_channels.test.mjs runs the same code under Node.
 *
 * It runs only with RETICHAT_BOOT_TESTS=1 (`npm run test:full`; deploy.sh
 * always sets it), as the other Chromium tests do.
 *
 * Run: RETICHAT_BOOT_TESTS=1 node --test distro_channels_page.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import { channelIdentity, channelLxmPack, channelLxmUnpack } from "./lib/rns/rfed_channel.js";
import { ABSENT } from "./lib/display_name.js";
import { channelSyncFields, readChannelSync } from "./lib/channel_sync.js";

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

const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");
const OPEN = "public.open-here";
const OTHER = "public.also-here";
const ELSEWHERE = "public.joined-elsewhere";
const SIBLING = "5b".repeat(16);   // another device of the distro

/** A membership message from the sibling, as RFed fans it out: D | D-encrypted. */
function siblingC(distro, op, name, atMs) {
    const msg = new LXMessage();
    msg.sourceHash = Buffer.from(lxmfHash(distro), "hex");
    msg.destinationHash = Buffer.from(lxmfHash(distro), "hex");
    msg.title = "";
    msg.content = "";
    msg.fields = channelSyncFields(op, name, atMs, SIBLING);
    msg.timestamp = atMs / 1000;
    const packed = msg.pack(distro, false);
    return Buffer.concat([packed.subarray(0, 16), distro.encrypt(packed.subarray(16))]).toString("hex");
}

chromiumTest("the real page: a sibling's post is the user's own bubble; a sibling's join and leave change the list and close the open chat; Leave and a post go out as the distro", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePageAndExchange();
    const { origin } = served;
    const distro = Identity.create();
    const D = lxmfHash(distro);
    const distroHex = Buffer.concat([distro.privateKeyBytes, distro.signaturePrivateKeyBytes]).toString("hex");
    try {
        const context = await browser.newContext({ serviceWorkers: "block" });
        const elsewhere = [];
        await context.route("**/*", (route) => {
            const u = new URL(route.request().url());
            if (u.origin === origin || (u.protocol === "https:" && u.hostname === "esm.sh")) return route.continue();
            elsewhere.push(route.request().url());
            return route.abort("blockedbyclient");
        });
        const channel = (name, lastActivity) => ({ channelName: name, channelHash: channelIdentity(name).hash.toString("hex"),
            rfedNodeHash: "aa".repeat(16), isSubscribed: true, stampCost: null, lastActivity });
        await context.addInitScript(([seed, distroKey]) => {
            if (sessionStorage.getItem("seeded")) return;
            for (const [k, v] of Object.entries(seed)) localStorage.setItem(`retichat_${k}`, JSON.stringify(v));
            localStorage.setItem("retichat_distro_identity", distroKey);
            sessionStorage.setItem("seeded", "1");
        }, [{
            identity_private_key: "22".repeat(64),
            channels_v1: [channel(OPEN, 3), channel(OTHER, 2)],
        }, distroHex]);
        const page = await context.newPage();
        const pageErrors = [], dialogs = [];
        page.on("pageerror", (e) => pageErrors.push(e.message));
        page.on("dialog", (d) => { dialogs.push(d.message()); d.accept().catch(() => {}); });

        await page.goto(`${origin}/index.html`);
        await within(page.waitForFunction(() => window.RetichatTest?.state().status === "online", null, { timeout: 0 }), "the page online on its exchange");
        assert.equal(await page.evaluate(() => window.RetichatTest.distro().lxmfDeliveryHash), D, "(fixture) the page holds the distro");
        assert.equal(await page.evaluate(() => window.RetichatTest.channelPoster()), D, "it posts as the distro");

        // rfed, at the page's seams.
        await page.evaluate(() => {
            const c = window.RetichatTest.client;
            window.__published = [];
            window.__uploads = [];
            window.__requests = [];
            c._ensureChannelSubscribed = async () => null;
            c._ensureChannelStreamConfigured = async () => {};
            c._configureChannelStream = async () => {};
            c.openChannel = async () => {};
            c._rfedRequest = async (aspects, path) => { window.__requests.push(path); return path === "/rfed/subscribe" ? [true, null] : true; };
            c._rfedLinkAvailable = () => true;
            c._ensureRfedLink = async () => ({
                rtt: 100,
                sendRequestPacked(path, packed, options) {
                    window.__published.push({ path, packed: Buffer.from(packed) });
                    options?.onDelivered?.();
                    return Buffer.alloc(16, window.__published.length);
                },
                responseFor: () => Promise.resolve([true, null]),
            });
            // The propagation link, up: an upload packet is transmitted and
            // the node proves it at once (what the distro is owed stays owed
            // until the proof, _uploadOwed).
            const propagationLink = {
                status: 0x02,
                newLinkPacket: (context, data) => ({ packetHash: Buffer.alloc(32, window.__uploads.length + 1), pack: () => Buffer.from(data) }),
                _transmit(raw) {
                    window.__uploads.push(Buffer.from(raw).toString("hex"));
                    const key = Buffer.alloc(16, window.__uploads.length).toString("hex");
                    setTimeout(() => {
                        const pending = c._pendingPacketHashes.get(key);
                        c._pendingPacketHashes.delete(key);
                        pending?.onProof(pending.messageId);
                    }, 0);
                    return raw;
                },
            };
            c._propLink = propagationLink;
            c._buildPropagationPacked = async (packed) => packed;
        });
        /** The channels the chat list shows. */
        const sidebar = () => page.evaluate(() => [...document.querySelectorAll(".sidebar *")]
            .map((e) => (e.childNodes.length === 1 && e.firstChild.nodeType === 3 ? e.textContent : ""))
            .filter((s) => s.startsWith("#public.")).sort());
        assert.deepEqual(await sidebar(), [`#${OTHER}`, `#${OPEN}`]);
        await page.evaluate((ch) => window.RetichatTest.app.openChat(ch), OPEN);
        await within(page.locator("#composer-input").waitFor({ state: "attached", timeout: 0 }), "the open channel's composer");

        // 1. The user's post from the phone, as D, through rfed's fan-out.
        const fromPhone = channelLxmPack(OPEN, distro, "posted on my phone", ABSENT, Date.now() - 2000);
        assert.equal(await page.evaluate((hex) => window.RetichatTest.client._handleChannelPacket(Buffer.from(hex, "hex")), fromPhone.wire.toString("hex")), true);
        const bubble = await page.evaluate((txt) => {
            const row = [...document.querySelectorAll(".msg-row[data-msg-id]")].find((r) => r.textContent.includes(txt));
            return row ? { own: row.classList.contains("own"), their: row.classList.contains("their"), label: !!row.querySelector(".msg-sender"),
                status: row.querySelector(".msg-status")?.getAttribute("data-msg-status") ?? null } : null;
        }, "posted on my phone");
        assert.deepEqual(bubble, { own: true, their: false, label: false, status: "sent" }, "the user's own bubble, sent, under no label");

        // 2. A post made here goes out as D.
        await page.locator("#composer-input").fill("posted on the laptop");
        await page.locator("#composer-input").press("Enter");
        await within(page.waitForFunction(() => window.__published.length === 1, null, { timeout: 0 }), "the post published");
        const published = Buffer.from(await page.evaluate(() => window.__published[0].packed.toString("hex")), "hex");
        const header = { 0xc4: 2, 0xc5: 3, 0xc6: 5 }[published[0]];
        assert.equal(channelLxmUnpack(OPEN, published.subarray(header)).sourceHash.toString("hex"), D, "signed as the distro");

        // 3. A join made on the phone: the channel is listed here.
        assert.equal(await page.evaluate((hex) => window.RetichatTest.client._handleDistroBlob(null, Buffer.from(hex, "hex")),
            siblingC(distro, "join", ELSEWHERE, Date.now())), true);
        assert.deepEqual(await sidebar(), [`#${OTHER}`, `#${ELSEWHERE}`, `#${OPEN}`].sort());
        assert.equal(await page.evaluate(() => window.RetichatTest.app.state.activeHash), OPEN, "the open chat stays open");

        // 4. A leave of the open channel made on the phone: gone, and its chat closed.
        assert.equal(await page.evaluate((hex) => window.RetichatTest.client._handleDistroBlob(null, Buffer.from(hex, "hex")),
            siblingC(distro, "leave", OPEN, Date.now() + 1)), true);
        await within(page.waitForFunction(() => !document.querySelector("#composer-input"), null, { timeout: 0 }), "the open chat closed");
        assert.equal(await page.evaluate(() => window.RetichatTest.app.state.activeHash), null);
        assert.deepEqual(await sidebar(), [`#${OTHER}`, `#${ELSEWHERE}`].sort());
        assert.ok((await page.evaluate(() => window.__requests)).includes("/rfed/unsubscribe"), "unsubscribed here, with this device's key");
        assert.deepEqual(await page.evaluate(() => window.__uploads.length), 0, "applying the phone's changes sent nothing back");

        // 5. The Leave button: the user's own leave, sent to the distro.
        await page.evaluate((ch) => { const app = window.RetichatTest.app; app.openChat(ch); app.state.showChannelInfo = true; app.state.channelInfoName = ch; app.render(); }, OTHER);
        await page.getByText("Leave Channel").click();
        await within(page.waitForFunction(() => window.__uploads.length === 1, null, { timeout: 0 }), "the leave sent to the distro");
        const upload = Buffer.from(await page.evaluate(() => window.__uploads[0]), "hex");
        assert.equal(upload.subarray(0, 16).toString("hex"), D, "to the distro");
        assert.deepEqual(readChannelSync(upload.subarray(96))?.sync?.op, "leave");
        assert.equal(readChannelSync(upload.subarray(96)).sync.name, OTHER);
        assert.deepEqual(await sidebar(), [`#${ELSEWHERE}`]);
        // Said sent once the propagation node proved it (_uploadForDistro).
        await within(page.waitForFunction(() => window.Harness.events.some((e) => e.kind === "distro-channel-sync-sent"), null, { timeout: 0 }),
            "the leave proved by the propagation node");
        assert.deepEqual(await page.evaluate(() => window.Harness.events.filter((e) => e.kind === "distro-channel-sync-sent").map((e) => [e.detail.op, e.detail.how])),
            [["leave", "packet"]]);
        assert.deepEqual(await page.evaluate(() => window.RetichatTest.distroOwed()), [], "proved: owed no more");

        assert.deepEqual([dialogs, pageErrors, elsewhere], [[`Leave #${OTHER}?`], [], []], "the Leave confirmation only; no error; nothing left this machine but esm.sh");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});
