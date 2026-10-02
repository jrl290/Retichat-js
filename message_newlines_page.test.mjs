/**
 * A MESSAGE'S LINE BREAKS, DRAWN IN THE REAL PAGE (James, 2026-10-02: "It
 * looks like the web chat strips out newline characters").
 *
 * The text kept its line breaks everywhere but on screen: the bubble drew
 * each one as a space, and on a phone the return key sent the message, so
 * none could be typed (message_newlines.test.mjs has the chain under Node).
 * This loads the real page in Chromium under the nodes' .htaccess policy
 * (style-src 'self': no inline style attribute) and checks what is drawn:
 *   - a DM and a group message that arrive over the exchange as LXMF
 *     packets, line breaks, a CR LF and an indented first line in them, are
 *     stored byte for byte and drawn line by line, indentation kept;
 *   - a stored message of three lines, CR LF in one, is three lines in a
 *     DM, a group and a channel bubble;
 *   - one typed with Shift+Enter is sent and stored with its line breaks and
 *     drawn as three lines in each;
 *   - a word too long for the bubble wraps inside it;
 *   - each chat-list preview is one line;
 *   - copying a bubble's text copies its line breaks;
 *   - on a phone the return key breaks the line and the send button sends.
 * The page's exchange is a stand-in on this server (no node is contacted)
 * that hands the page the packets a test gives it; the page's modules come
 * from esm.sh, as in production. A channel post reaches the page over an
 * rfed link, which the stand-in does not speak: message_newlines.test.mjs
 * runs the shipped channel handler on a real post instead.
 *
 * It runs only with RETICHAT_BOOT_TESTS=1 (`npm run test:full`; deploy.sh
 * always sets it), as the other Chromium tests do.
 *
 * Run: RETICHAT_BOOT_TESTS=1 node --test message_newlines_page.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Identity, Destination, Packet, LXMessage, GROUP_FIELDS } from "./lib/rns/reticulum.js";
import Transport from "./lib/rns/transport.js";

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

/** The page from this directory, index.html under the nodes' policy, and a
 *  stand-in exchange that registers the page and delivers the packets given
 *  to deliver() (base64), each once, on its next exchange. */
async function servePage() {
    const queued = [];
    const ROOT = fileURLToPath(new URL(".", import.meta.url));
    const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json" };
    const json = (res, body) => res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
    const server = createServer(async (req, res) => {
        const path = new URL(req.url, "http://x").pathname;
        if (path === "/config.json") { json(res, { exchangeUrl: `http://127.0.0.1:${server.address().port}/exchange` }); return; }
        if (path.startsWith("/exchange/")) {
            for await (const _ of req);
            if (path === "/exchange/v1/interfaces/register") {
                json(res, { interface_id: "f".repeat(32), session_token: "e".repeat(64), max_batch_packets: 64, max_packet_bytes: 500, idle_exchange_interval_ms: 100 });
                return;
            }
            if (path === "/exchange/v1/interfaces/exchange") {
                json(res, { delivery_packets: queued.splice(0), delivery_batch_id: null, idle_exchange_interval_ms: 100 });
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
    return { origin: `http://127.0.0.1:${server.address().port}`, deliver: (b64) => queued.push(b64), close() { server.close(); } };
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

/** The opportunistic LXMF packet `from` sends to `to`, as a node hands it
 *  on: a DATA packet to `to`'s lxmf.delivery, encrypted to its key,
 *  carrying the message without its destination hash. Base64. */
function lxmfPacket(from, to, content, fields = new Map()) {
    const m = new LXMessage();
    m.timestamp = Date.now() / 1000;
    m.sourceHash = Destination.hash(from, "lxmf", "delivery");
    m.destinationHash = Destination.hash(to, "lxmf", "delivery");
    m.title = "";
    m.content = content;
    m.fields = fields;
    const packed = m.pack(from, false);
    const p = new Packet();
    p.headerType = Packet.HEADER_1;
    p.packetType = Packet.DATA;
    p.transportType = Transport.BROADCAST;
    p.context = Packet.NONE;
    p.contextFlag = Packet.FLAG_UNSET;
    p.destination = { encrypt: (data) => to.encrypt(data) };
    p.destinationHash = m.destinationHash;
    p.destinationType = Destination.SINGLE;
    p.data = packed.subarray(LXMessage.DESTINATION_LENGTH);
    return p.pack().toString("base64");
}

const RECEIVED = "line one\nline two\r\nline three";
const SHOWN = "line one\nline two\nline three";
const LONG_WORD = "x".repeat(400);
const GID = "ab".repeat(16);
const CHANNEL = "newlines";

/** The localStorage a user with Alice as a contact, a group with her and a
 *  channel has, each holding a three-line message from her. */
function seed() {
    const [own, alice] = [id("11"), id("22")];
    const [ME, A] = [own, alice].map(deliveryHash);
    const at = Date.now() - 60_000;
    return {
        A, ME,
        storage: {
            identity_private_key: "11".repeat(64),
            groupMembersAllowlisted: 2,
            contacts_v2: [{ destHash: A, publicKey: alice.getPublicKey().toString("hex"), hidden: false, allowlisted: true,
                localName: "Alice", messageName: null, messageNameAt: null, announceName: null, legacyName: null, isDistro: false }],
            [`msg_${A}`]: [
                { id: "dm-in", dir: "in", content: RECEIVED, status: "delivered", timestamp: at },
                { id: "dm-long", dir: "in", content: `${LONG_WORD}\nshort`, status: "delivered", timestamp: at + 1 },
            ],
            groups_v1: [{ groupId: GID, groupName: "Gee", groupStatus: "active", lastActivity: at,
                members: [{ hash: A, status: "accepted" }, { hash: ME, status: "accepted" }] }],
            [`gmsg_${GID}`]: [{ id: "group-in", dir: "in", content: RECEIVED, status: "delivered", srcHash: A, timestamp: at }],
            channels_v1: [{ channelName: CHANNEL, channelHash: "", rfedNodeHash: "cd".repeat(16), isSubscribed: true, lastActivity: at }],
            [`cmsg_${CHANNEL}`]: [{ id: "channel-in", dir: "in", content: RECEIVED, status: "delivered", srcHash: A, timestamp: at }],
        },
    };
}

/** A context on the served page with `storage` seeded once, nothing but the
 *  page's origin and esm.sh reachable, and every complaint kept. */
async function openPage(browser, origin, storage, options = {}) {
    const context = await browser.newContext({ serviceWorkers: "block", ...options });
    const elsewhere = [];
    await context.route("**/*", (route) => {
        const u = new URL(route.request().url());
        if (u.origin === origin || (u.protocol === "https:" && u.hostname === "esm.sh")) return route.continue();
        elsewhere.push(route.request().url());
        return route.abort("blockedbyclient");
    });
    await context.addInitScript((seeded) => {
        // Every CSP violation, inline style attributes included.
        window.__cspViolations = [];
        document.addEventListener("securitypolicyviolation", (e) => window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`));
        if (sessionStorage.getItem("seeded")) return;
        for (const [k, v] of Object.entries(seeded)) localStorage.setItem(`retichat_${k}`, JSON.stringify(v));
        sessionStorage.setItem("seeded", "1");
    }, storage);
    const page = await context.newPage();
    const pageErrors = [], dialogs = [];
    page.on("pageerror", (e) => pageErrors.push(e.message));
    page.on("dialog", (d) => { dialogs.push(d.message()); d.dismiss().catch(() => {}); });
    await page.goto(`${origin}/index.html`);
    await within(page.waitForFunction(() => window.RetichatTest?.state().status === "online", null, { timeout: 0 }), "the page online on its exchange");
    const complaints = async () => ({ pageErrors, dialogs, elsewhere, csp: await page.evaluate(() => window.__cspViolations) });
    return { context, page, complaints };
}

/** How an element is drawn: its rendered text and its number of lines (the
 *  distinct tops of the boxes its text is laid out in). */
const drawn = (locator) => locator.evaluate((el) => {
    const range = document.createRange();
    range.selectNodeContents(el);
    return { text: el.innerText, lines: new Set([...range.getClientRects()].map((r) => Math.round(r.top))).size };
});

/** The stored records of a conversation. */
const stored = (page, key) => page.evaluate((k) => JSON.parse(localStorage.getItem(`retichat_${k}`)), key);

chromiumTest("the real page: a message's line breaks are drawn in DM, group and channel bubbles, stored and sent with Shift+Enter; a long word wraps; previews stay one line; a copy keeps the breaks", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePage();
    try {
        const { A, storage } = seed();
        const { context, page, complaints } = await openPage(browser, served.origin, storage, { viewport: { width: 1280, height: 800 } });
        await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: served.origin });

        // Each chat-list preview is one line, its line breaks drawn as spaces.
        for (const name of ["Alice", "Gee", `#${CHANNEL}`]) {
            const preview = page.locator(".contact-item", { hasText: name }).first().locator(".contact-preview");
            const p = await drawn(preview);
            assert.equal(p.lines, 1, `${name}: the preview is one line`);
            assert.doesNotMatch(p.text, /\n/, `${name}: no line break in the preview`);
        }

        const chats = [
            { name: "Alice", key: `msg_${A}`, received: "dm-in" },
            { name: "Gee", key: `gmsg_${GID}`, received: "group-in" },
            { name: `#${CHANNEL}`, key: `cmsg_${CHANNEL}`, received: "channel-in" },
        ];
        for (const chat of chats) {
            await page.locator(".contact-item", { hasText: chat.name }).first().click();
            const received = page.locator(`.msg-row[data-msg-id="${chat.received}"] .msg-text`);
            await within(received.waitFor(), `${chat.name}: the stored message's bubble`);
            assert.deepEqual(await drawn(received), { text: SHOWN, lines: 3 }, `${chat.name}: the stored message is three lines`);

            // Typed with Shift+Enter, sent with Enter.
            const composer = page.locator("#composer-input");
            await composer.click();
            await page.keyboard.type("first");
            await page.keyboard.press("Shift+Enter");
            await page.keyboard.type("second");
            await page.keyboard.press("Shift+Enter");
            await page.keyboard.type("third");
            assert.equal(await composer.inputValue(), "first\nsecond\nthird", `${chat.name}: Shift+Enter breaks the line`);
            await page.keyboard.press("Enter");
            const sent = page.locator(".msg-row.own .msg-text", { hasText: "first" });
            await within(sent.waitFor(), `${chat.name}: the sent bubble`);
            assert.deepEqual(await drawn(sent), { text: "first\nsecond\nthird", lines: 3 }, `${chat.name}: the sent message is three lines`);
            assert.equal(await page.locator("#composer-input").inputValue(), "", `${chat.name}: the composer is cleared`);
            const out = (await stored(page, chat.key)).filter((m) => m.dir === "out");
            assert.deepEqual(out.map((m) => m.content), ["first\nsecond\nthird"], `${chat.name}: stored as typed`);
            assert.equal((await stored(page, chat.key)).find((m) => m.id === chat.received).content, RECEIVED,
                `${chat.name}: the stored record is not rewritten`);
        }

        // A word longer than the bubble wraps inside it.
        await page.locator(".contact-item", { hasText: "Alice" }).first().click();
        const long = page.locator('.msg-row[data-msg-id="dm-long"]');
        await within(long.waitFor(), "the long word's bubble");
        const fit = await long.evaluate((row) => {
            const bubble = row.querySelector(".msg-bubble"), list = document.getElementById("msg-list");
            return { overflow: bubble.scrollWidth - bubble.clientWidth, right: bubble.getBoundingClientRect().right - list.getBoundingClientRect().right,
                rowShare: row.getBoundingClientRect().width / list.clientWidth, text: row.querySelector(".msg-text").innerText };
        });
        assert.equal(fit.text, `${LONG_WORD}\nshort`);
        assert.ok(fit.overflow <= 0, `nothing overflows the bubble (${fit.overflow}px)`);
        assert.ok(fit.right <= 0, `the bubble stays inside the list (${fit.right}px)`);
        assert.ok(fit.rowShare <= 0.76, `the row keeps its 75% (${fit.rowShare})`);

        // Copying a bubble's text copies its line breaks.
        await page.locator('.msg-row[data-msg-id="dm-in"] .msg-text').evaluate((el) => {
            const range = document.createRange();
            range.selectNodeContents(el);
            getSelection().removeAllRanges();
            getSelection().addRange(range);
        });
        assert.equal(await page.evaluate(() => getSelection().toString()), SHOWN, "the selection reads as drawn");
        await page.keyboard.press("ControlOrMeta+C");
        assert.equal(await page.evaluate(() => navigator.clipboard.readText()), SHOWN, "the clipboard holds the line breaks");

        // Multi-line text pasted into the composer keeps its line breaks.
        await page.evaluate(() => navigator.clipboard.writeText("pasted one\npasted two"));
        await page.locator("#composer-input").click();
        await page.keyboard.press("ControlOrMeta+V");
        assert.equal(await page.locator("#composer-input").inputValue(), "pasted one\npasted two");

        assert.deepEqual(await complaints(), { pageErrors: [], dialogs: [], elsewhere: [], csp: [] },
            "no error, no dialog, nothing left this machine but esm.sh, no CSP violation");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});

/** Sent untrimmed (as Android sends): an indented first line, a CR LF,
 *  an indented third line and a trailing line break. */
const WIRE = "  indented first\nline two\r\n    line three\n";
const WIRE_SHOWN = "  indented first\nline two\n    line three";

chromiumTest("the real page: a DM and a group message arriving over the exchange are stored as they came and drawn line by line, the first line's indentation kept", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePage();
    try {
        const { A, storage } = seed();
        const [own, alice] = [id("11"), id("22")];
        const { context, page, complaints } = await openPage(browser, served.origin, storage, { viewport: { width: 1280, height: 800 } });
        const arrivals = [
            { name: "Alice", key: `msg_${A}`, fields: new Map() },
            { name: "Gee", key: `gmsg_${GID}`, fields: new Map([[GROUP_FIELDS.GROUP_ID, GID]]) },
        ];
        const seeded = ["dm-in", "dm-long", "group-in"];
        for (const chat of arrivals) {
            served.deliver(lxmfPacket(alice, own, WIRE, chat.fields));
            // The page's own receive path: exchange, transport, router,
            // connect()'s handler (and _handleGroupMessage), the store.
            const arrived = await within(page.waitForFunction(([k, old]) =>
                (JSON.parse(localStorage.getItem(`retichat_${k}`)) ?? []).find((m) => m.dir === "in" && !old.includes(m.id)) ?? null,
            [chat.key, seeded], { timeout: 0 }), `${chat.name}: the message from the exchange stored`);
            const rec = await arrived.jsonValue();
            assert.equal(rec.content, WIRE, `${chat.name}: stored byte for byte`);

            await page.locator(".contact-item", { hasText: chat.name }).first().click();
            const bubble = page.locator(`.msg-row[data-msg-id="${rec.id}"] .msg-text`);
            await within(bubble.waitFor(), `${chat.name}: its bubble`);
            assert.deepEqual(await drawn(bubble), { text: WIRE_SHOWN, lines: 3 },
                `${chat.name}: three lines, the first and third indented as sent`);
        }
        assert.deepEqual(await complaints(), { pageErrors: [], dialogs: [], elsewhere: [], csp: [] },
            "no error, no dialog, nothing left this machine but esm.sh, no CSP violation");
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});

chromiumTest("the real page on a phone: the return key breaks the line instead of sending, and the send button sends the message with its line breaks", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    const served = await servePage();
    try {
        const { A, storage } = seed();
        const { context, page, complaints } = await openPage(browser, served.origin, storage,
            { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
        assert.equal(await page.evaluate(() => matchMedia("(hover: none) and (pointer: coarse)").matches), true, "a touch-first device");

        await page.locator(".contact-item", { hasText: "Alice" }).first().click();
        const composer = page.locator("#composer-input");
        await within(composer.waitFor(), "the DM's composer");
        await composer.tap();
        await page.keyboard.type("one");
        await page.keyboard.press("Enter");
        await page.keyboard.type("two");
        assert.equal(await composer.inputValue(), "one\ntwo", "the return key broke the line");
        assert.equal((await stored(page, `msg_${A}`)).filter((m) => m.dir === "out").length, 0, "and sent nothing");

        await page.locator(".btn-send").tap();
        const sent = page.locator(".msg-row.own .msg-text", { hasText: "one" });
        await within(sent.waitFor(), "the sent bubble");
        assert.deepEqual(await drawn(sent), { text: "one\ntwo", lines: 2 });
        assert.deepEqual((await stored(page, `msg_${A}`)).filter((m) => m.dir === "out").map((m) => m.content), ["one\ntwo"]);
        assert.deepEqual(await drawn(page.locator('.msg-row[data-msg-id="dm-in"] .msg-text')), { text: SHOWN, lines: 3 });
        assert.deepEqual(await complaints(), { pageErrors: [], dialogs: [], elsewhere: [], csp: [] });
        await context.close();
    } finally {
        await browser.close();
        served.close();
    }
});
