/**
 * REGRESSION GUARD — the exchange tells the truth and always recovers (U6).
 *
 * CONNECTIVITY_READINESS.md §15 and U6, 2026-09-25. Until then PostInterface:
 *   - spliced the outbound batch out of the queue before the fetch and
 *     swallowed the failure, so the batch was lost without a word and a DM in
 *     it showed "sending" until the 30 s ceiling;
 *   - emitted only "registered": the status dot showed online whenever the
 *     interface held credentials, a dead exchange included;
 *   - rejected connect() on a failed first registration before polling
 *     started, and nothing caught it (reticulum.js addInterface), so a page
 *     opened offline never recovered without a reload;
 *   - stopped for good after a 401 whose re-registration failed;
 *   - gave its fetches no AbortSignal, so one hung fetch stalled all transport;
 *   - said goodbye on pagehide even when the page went into the back/forward
 *     cache.
 * D3 (James, 2026-09-25): a send "should fail in front of the user and be
 * considered dead" — a DM whose packet was lost fails at once and is never
 * sent again, and a DM, group message or channel post sent while the
 * exchange is down fails at once.
 * James, 2026-10-06 (DESIGN_PRINCIPLES §3, what a device owes its distro): an
 * upload for the distro that never left the device, because the exchange
 * could not carry its packet, is no failure and goes when the exchange is
 * back; one lost after it left still waits for the propagation link's next
 * coming-up. The last tests run that over the real PostInterface and the
 * real _followExchange (the staging case: a short drop, the propagation link
 * still up). James, 2026-10-10 (DISTRO-SYNC-PROOF-DESIGN.md §5.3(a)): the
 * same holds for an upload that goes as a Resource, whose first
 * advertisement the exchange never sent; once that has left, the
 * Resource's own failure decides. Those run a real Resource over a real
 * propagation link (test_link_pair.mjs) whose packets the exchange carries.
 *
 * The real PostInterface runs against a scripted node (a fake fetch). The app
 * tests run the real shipped method bodies from app.js: the DM path over a
 * real Reticulum, real LXMF packing and the real MsgStore; group and channel
 * sends over their real stores; the status dot through the real
 * _followExchange and _setStatus. No clock decides a result: timers are
 * captured and fired by hand.
 *
 * Run: node --test exchange_truth.test.mjs
 */
import { SendTransfers } from "./lib/send_progress.js";
import { addInOrder } from "./lib/message_order.js";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import { Reticulum, Identity, Destination, LXMessage, Link, Packet, Resource } from "./lib/rns/reticulum.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";
import Cryptography from "./lib/rns/cryptography.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import { DistroUploads } from "./lib/distro_upload.js";
import { DistroOutbox, UnprovedUploads, channelSyncEntryId, sentCopyEntryId, syncProofKept } from "./lib/distro_outbox.js";
import { applyToFields as applyDisplayName, ABSENT } from "./lib/display_name.js";
import { linkPair } from "./test_link_pair.mjs";
import { sealForSync } from "./lib/distro_sync.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

// ── Harness ────────────────────────────────────────────────────────────────

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const tick = () => new Promise((resolve) => realSetTimeout(resolve, 0));

/** Wait (a few macrotasks at most) for `probe` to return something truthy. A failure mechanism only. */
async function eventually(probe, what) {
    for (let i = 0; i < 100; i++) {
        const value = probe();
        if (value) return value;
        await tick();
    }
    throw new Error(`never happened: ${what}`);
}

/**
 * Timers of 0 ms (the EventEmitter's deferral) run for real; every other
 * timer is captured and fired by hand.
 */
function fakeTimers(t) {
    const timers = [];
    globalThis.setTimeout = (fn, ms, ...args) => {
        if (!ms) return realSetTimeout(fn, 0, ...args);
        const timer = { fn, ms, cleared: false, fired: false };
        timers.push(timer);
        return timer;
    };
    globalThis.clearTimeout = (timer) => {
        if (timer && typeof timer === "object" && "cleared" in timer) timer.cleared = true;
        else realClearTimeout(timer);
    };
    t.after(() => { globalThis.setTimeout = realSetTimeout; globalThis.clearTimeout = realClearTimeout; });
    return {
        timers,
        /** The one armed timer. */
        armed() {
            const armed = timers.filter((x) => !x.cleared && !x.fired);
            assert.equal(armed.length, 1, `one armed timer, got ${armed.map((x) => x.ms)}`);
            return armed[0];
        },
        fire(timer) { timer.fired = true; timer.fn(); },
    };
}

/**
 * A scripted Reticulum-php node: every request waits for the test to answer
 * it. With `honourAbort: false` an abort does not end the request, as when
 * the answer was already on its way.
 */
function fakeNode(t, { honourAbort = true } = {}) {
    const requests = [];
    globalThis.fetch = (url, options) => new Promise((resolve, reject) => {
        const request = {
            path: new URL(url).pathname.replace(/^\/reticulum/, ""),
            body: JSON.parse(options.body),
            signal: options.signal,
            settled: false,
            respond(status, json = {}) {
                if (request.settled) return;
                request.settled = true;
                resolve({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(json) });
            },
            fail(message = "Failed to fetch") {
                if (request.settled) return;
                request.settled = true;
                reject(new TypeError(message));
            },
        };
        options.signal?.addEventListener("abort", () => {
            if (request.settled || !honourAbort) return;
            request.settled = true;
            reject(new DOMException("The operation was aborted.", "AbortError"));
        });
        requests.push(request);
    });
    t.after(() => { delete globalThis.fetch; });
    return {
        requests,
        /** The next unanswered request to `path` (without the /v1/interfaces prefix). */
        pending: (path) => eventually(
            () => requests.find((r) => !r.settled && r.path === `/v1/interfaces/${path}`),
            `a ${path} request`),
        count: (path) => requests.filter((r) => r.path === `/v1/interfaces/${path}`).length,
    };
}

const REGISTERED = {
    interface_id: "1".repeat(32), session_token: "2".repeat(32),
    idle_exchange_interval_ms: 1000, max_batch_packets: 64, max_packet_bytes: 500,
};

function record(iface) {
    const events = [];
    for (const kind of ["registered", "up", "down", "lost"]) {
        iface.on(kind, (detail) => events.push({ kind, detail }));
    }
    return {
        events,
        kinds: () => events.map((e) => e.kind),
        lost: () => events.filter((e) => e.kind === "lost").map((e) => e.detail),
    };
}

// PostInterface narrates every exchange; keep the test output readable.
const quiet = (t) => {
    const { log, warn, error } = console;
    console.log = () => {}; console.warn = () => {}; console.error = () => {};
    t.after(() => Object.assign(console, { log, warn, error }));
};

/** connect(), register, first exchange answered 200: an interface that is up. */
async function upInterface(t, node, clock) {
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    const seen = record(iface);
    t.after(() => iface.disconnect());
    const started = iface.connect();
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await started;
    await eventually(() => seen.kinds().includes("up"), "up");
    assert.equal(clock.armed().ms, 1000, "polls on the node's idle interval");
    return { iface, seen };
}

/** A raw packet as the stack hands it to sendData, and its full hash. */
function rawPacket(fill) {
    const raw = Buffer.concat([Buffer.from([0x00, 0x00]), Buffer.alloc(16, fill), Buffer.from([0x00]), Buffer.alloc(40, fill)]);
    return { raw, hash: Packet.fromBytes(raw).packetHash.toString("hex") };
}

// ── The exchange ───────────────────────────────────────────────────────────

test("a rejected exchange emits one down, and the next 200 one up", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, seen } = await upInterface(t, node, clock);
    assert.deepEqual(seen.kinds(), ["registered", "up"]);
    assert.equal(iface.isUp, true);

    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => seen.kinds().includes("down"), "down");
    assert.match(seen.events.find((e) => e.kind === "down").detail, /Failed to fetch/, "down carries its reason");
    assert.equal(iface.isDown, true);
    assert.equal(clock.armed().ms, PostInterface.RECONNECT_WAIT_MS, "after a failure, the reference's reconnect wait");
    assert.equal(PostInterface.RECONNECT_WAIT_MS, 5000, "TCPInterface.py RECONNECT_WAIT");

    // Still down: no second down.
    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(503, { error: "busy" });
    await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the next attempt armed");
    assert.equal(seen.kinds().filter((k) => k === "down").length, 1, "one down per failure run, not one per attempt");

    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => seen.kinds().at(-1) === "up", "up again");
    assert.deepEqual(seen.kinds(), ["registered", "up", "down", "up"]);
    assert.equal(clock.armed().ms, 1000, "back on the idle interval");
});

test("a failed first registration leaves the interface down, and it registers again", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    const seen = record(iface);
    t.after(() => iface.disconnect());

    // The page was opened offline.
    const started = iface.connect();
    (await node.pending("register")).fail();
    await started; // does not reject: nothing would catch it (reticulum.js addInterface)
    await eventually(() => seen.kinds().includes("down"), "down");
    assert.equal(iface.isDown, true);
    const wait = clock.armed();
    assert.equal(wait.ms, PostInterface.RECONNECT_WAIT_MS);

    // After the reconnect wait it registers again, and fails again quietly.
    clock.fire(wait);
    (await node.pending("register")).fail();
    await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the next attempt armed");

    // The network comes back: "online" does not wait out the timer.
    iface.check("online");
    assert.equal(clock.timers.filter((x) => !x.cleared && !x.fired).length, 0, "the reconnect wait is cut short");
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => seen.kinds().at(-1) === "up", "up");
    assert.deepEqual(seen.kinds(), ["down", "registered", "up"]);
    assert.equal(node.count("register"), 3);
});

test("a 401 whose re-registration fails keeps the interface going", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, seen } = await upInterface(t, node, clock);

    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(401, { error: "Invalid interface credentials" });
    // The session is lost, the node is not: it registers again at once.
    (await node.pending("register")).fail();
    await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the next attempt armed");
    assert.equal(iface.isDown, true);
    assert.equal(iface.isRegistered, false);

    // Until 2026-09-25 nothing came after this.
    clock.fire(clock.armed());
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => seen.kinds().at(-1) === "up", "up");
    assert.deepEqual(seen.kinds(), ["registered", "up", "down", "registered", "up"]);
});

test("a 401 re-registers once per run, so two sessions fighting cannot spin", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    await upInterface(t, node, clock);

    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(401, {});
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(401, {});
    await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the next attempt armed");
    assert.equal(node.count("register"), 2, "one re-registration, then the reconnect wait");
    assert.equal(clock.armed().ms, PostInterface.RECONNECT_WAIT_MS);
});

test("a 401, a new session, then a failed exchange: one down until an up", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, seen } = await upInterface(t, node, clock);

    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(401, {});
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).fail();
    await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the next attempt armed");
    assert.equal(iface.isDown, true, "the state says down");
    assert.deepEqual(seen.kinds(), ["registered", "up", "down", "registered"],
        "the new session did not end the failure run the app was told about");

    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => seen.kinds().at(-1) === "up", "up");
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => seen.kinds().at(-1) === "down", "a new run, a new down");
    assert.deepEqual(seen.kinds(), ["registered", "up", "down", "registered", "up", "down"]);
});

test("check() aborts a hung exchange, loses its batch and exchanges at once", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, seen } = await upInterface(t, node, clock);

    const a = rawPacket(0xa1);
    iface.sendData(a.raw);
    const hung = await node.pending("exchange");
    assert.equal(hung.body.packets.length, 1);
    assert.ok(hung.signal, "every exchange carries an AbortSignal");

    // Never answered: only an event can end it.
    iface.check("visible");
    assert.equal(hung.signal.aborted, true);
    const fresh = await node.pending("exchange");
    assert.notEqual(fresh, hung, "a new exchange, at once, without a timer");
    await eventually(() => seen.lost().length === 1, "the abandoned batch reported");
    assert.deepEqual(seen.lost()[0].packetHashes, [a.hash]);
    assert.equal(seen.lost()[0].abandoned, true,
        "as abandoned: the node may have taken it, so a link attempt keeps waiting for its LRPROOF (Link.requestLost)");
    assert.deepEqual(seen.lost()[0].unsent, [], "and so none of it is said never to have been sent: it was in a request");
    assert.deepEqual(fresh.body.packets, [], "the abandoned packet is not re-sent");

    fresh.respond(200, {});
    await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the poll armed");
    assert.equal(seen.kinds().includes("down"), false, "the check's own exchange decides; it answered 200");
    assert.equal(iface.isUp, true);
});

test("check() during a registration registers again at once", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    iface.connect();
    const hung = await node.pending("register");
    iface.check("online");
    assert.equal(hung.signal.aborted, true);
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => iface.isUp, "up");
    assert.equal(clock.armed().ms, 1000);
});

test("a failed exchange loses its batch and the queue behind it, and a down interface loses what it is given", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, seen } = await upInterface(t, node, clock);

    const a = rawPacket(0xa1);
    const b = rawPacket(0xb2);
    iface.sendData(a.raw);
    const exchange = await node.pending("exchange");
    iface.sendData(b.raw); // queued behind the batch in flight
    exchange.fail();
    await eventually(() => seen.lost().length === 1, "lost");
    assert.deepEqual(seen.lost()[0].packetHashes, [a.hash, b.hash]);
    assert.equal(seen.lost()[0].abandoned, false, "a failed exchange's report is not an abandoned one");
    assert.deepEqual(seen.lost()[0].unsent, [b.hash],
        "what was queued behind the batch went into no request, so nothing of it was sent; the batch itself may have reached the node");
    assert.equal(seen.kinds().indexOf("down") < seen.kinds().indexOf("lost"), true, "down, then what it lost");

    const requestsBefore = node.requests.length;
    const c = rawPacket(0xc3);
    iface.sendData(c.raw);
    await eventually(() => seen.lost().length === 2, "lost at once");
    assert.deepEqual(seen.lost()[1], { packetHashes: [c.hash], reason: "the exchange is down", abandoned: false, unsent: [c.hash] },
        "refused while down: nothing of it was sent");
    assert.equal(node.requests.length, requestsBefore, "nothing is sent for it");

    // The next attempt re-sends none of them (a re-send is a retry, §3).
    clock.fire(clock.armed());
    const next = await node.pending("exchange");
    assert.deepEqual(next.body.packets, [], "no lost packet is re-sent");
});

test("the batch acknowledgements of a failed exchange go with the next one", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface } = await upInterface(t, node, clock);
    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(200, { delivery_packets: [Buffer.alloc(40, 1).toString("base64")], delivery_batch_id: "b-1" });
    const acking = await node.pending("exchange");
    assert.deepEqual(acking.body.ack_batch_ids, ["b-1"]);
    acking.fail();
    await eventually(() => iface.isDown, "down");
    clock.fire(clock.armed());
    assert.deepEqual((await node.pending("exchange")).body.ack_batch_ids, ["b-1"]);
});

test("the page: no goodbye into the back/forward cache; pageshow, online and visible check the exchange", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const page = new EventTarget();
    const doc = Object.assign(new EventTarget(), { visibilityState: "visible" });
    globalThis.window = page;
    globalThis.document = doc;
    t.after(() => { delete globalThis.window; delete globalThis.document; });
    const { iface } = await upInterface(t, node, clock);
    const pageEvent = (type, persisted) => Object.assign(new Event(type), { persisted });

    page.dispatchEvent(pageEvent("pagehide", true));
    await tick();
    assert.equal(node.count("goodbye"), 0, "a cached page may come back with this registration");
    page.dispatchEvent(pageEvent("pagehide", false));
    await tick();
    assert.equal(node.count("goodbye"), 1, "a page going away says goodbye");

    for (const [target, event] of [
        [page, pageEvent("pageshow", true)],
        [page, new Event("online")],
        [doc, new Event("visibilitychange")],
    ]) {
        const poll = clock.armed();
        target.dispatchEvent(event);
        assert.equal(poll.cleared, true, `${event.type}: the poll timer is not waited out`);
        (await node.pending("exchange")).respond(200, {});
        await eventually(() => clock.timers.some((x) => !x.cleared && !x.fired), "the poll armed");
    }

    const exchanges = node.count("exchange");
    page.dispatchEvent(pageEvent("pageshow", false)); // a fresh load, not a restore
    doc.visibilityState = "hidden";
    doc.dispatchEvent(new Event("visibilitychange"));
    await tick();
    assert.equal(node.count("exchange"), exchanges, "neither is a reason to check");

    iface.disconnect();
    page.dispatchEvent(new Event("online"));
    await tick();
    assert.equal(node.count("exchange"), exchanges, "a stopped interface is unhooked");
});

test("disconnect() lets the exchange in flight land, and takes nothing from it", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, seen } = await upInterface(t, node, clock);
    const fed = [];
    iface.processIncoming = (raw) => fed.push(raw);

    // RnsClient.disconnect() closes its links, then the interface.
    const linkClose = rawPacket(0xd4);
    iface.sendData(linkClose.raw);
    const inFlight = await node.pending("exchange");
    const before = seen.events.length;
    iface.disconnect();
    assert.equal(inFlight.signal.aborted, false, "the LINKCLOSE it carries still reaches the node");
    assert.equal(inFlight.body.packets.length, 1);

    inFlight.respond(200, { delivery_packets: [Buffer.alloc(40, 1).toString("base64")], delivery_batch_id: "b-9" });
    await tick(); await tick();
    assert.deepEqual(fed, [], "a stopped stack is fed nothing; the node hands the batch to the next session");
    assert.deepEqual(iface._pendingAckIds, [], "and nothing acknowledges it");
    assert.equal(seen.events.length, before, "no up, no down, no lost: the interface is gone");
    assert.equal(clock.timers.filter((x) => !x.cleared && !x.fired).length, 0, "no poll after disconnect");
    assert.equal(node.count("exchange"), 2, "and no exchange after it");

    // The first exchange of a new session, landing after disconnect(): no "up".
    const fresh = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    const freshSeen = record(fresh);
    fresh.connect();
    (await node.pending("register")).respond(200, REGISTERED);
    const first = await node.pending("exchange");
    fresh.disconnect();
    first.respond(200, {});
    await tick(); await tick();
    assert.deepEqual(freshSeen.kinds(), ["registered"], "a stopped interface is never reported up");
});

test("disconnect() aborts a registration in flight, and one answered anyway is not kept", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    for (const honourAbort of [true, false]) {
        const node = fakeNode(t, { honourAbort });
        const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
        const seen = record(iface);
        iface.connect();
        const registering = await node.pending("register");
        iface.disconnect();
        assert.equal(registering.signal.aborted, true, "it would rotate the token under the tab taking over");
        registering.respond(200, REGISTERED); // ignored once aborted, unless the answer was on its way
        await tick(); await tick();
        assert.equal(iface.isRegistered, false, `honourAbort ${honourAbort}: the session belongs to no one`);
        assert.deepEqual(seen.kinds(), [], `honourAbort ${honourAbort}: nothing reported`);
        assert.equal(node.count("exchange"), 0, `honourAbort ${honourAbort}: nothing exchanged`);
        assert.equal(clock.timers.filter((x) => !x.cleared && !x.fired).length, 0);
    }
});

test("block(): an exchange the page's policy blocks is never asked again, and what is sent through it is lost at once, saying why, whichever lands first", async (t) => {
    // RnsClient._checkSavedExchange, 2026-10-01: the browser refuses every
    // request to such a URL before it is sent. Until then the interface kept
    // asking on the reconnect wait, each request refused again.
    quiet(t);
    const clock = fakeTimers(t);
    const REASON = "the exchange URL is blocked by this page's Content-Security-Policy";
    for (const refusedFirst of [true, false]) {
        const node = fakeNode(t);
        const iface = new PostInterface("Retichat Web", "https://other-node.example/reticulum", "ab".repeat(16));
        const seen = record(iface);
        iface.connect();
        const registering = await node.pending("register");
        if (refusedFirst) {
            // The browser's refusal lands before the check's answer.
            registering.fail();
            await eventually(() => seen.kinds().includes("down"), "down");
            assert.equal(clock.armed().ms, PostInterface.RECONNECT_WAIT_MS, "the next attempt was armed");
            iface.block(REASON);
        } else {
            iface.block(REASON);
            assert.equal(registering.signal.aborted, true, "the request in flight is ended");
            await tick(); await tick();
        }
        const label = refusedFirst ? "refused, then blocked" : "blocked first";
        assert.equal(clock.timers.filter((x) => !x.cleared && !x.fired).length, 0, `${label}: no attempt armed`);
        assert.deepEqual(seen.kinds(), refusedFirst ? ["down"] : [], `${label}: block() emits no down of its own`);
        assert.equal(iface.isDown, true, `${label}: down`);

        const a = rawPacket(0xa1);
        iface.sendData(a.raw);
        await eventually(() => seen.lost().length === 1, "lost at once");
        assert.deepEqual(seen.lost()[0], { packetHashes: [a.hash], reason: REASON, abandoned: false, unsent: [a.hash] },
            `${label}: lost at once, saying why, and nothing of it was sent`);
        iface.check("online");
        iface.check("visible");
        await tick(); await tick();
        assert.equal(node.requests.length, 1, `${label}: nothing is asked of it again, a check included`);
        assert.equal(clock.timers.filter((x) => !x.cleared && !x.fired).length, 0);
    }
});

test("what was still queued when a registration fails, or when the page's policy blocks the exchange, went into no request: it is reported unsent", async (t) => {
    // James, 2026-10-06 (DESIGN_PRINCIPLES §3, what a device owes its
    // distro): the sender of an upload for the distro whose packet is in
    // `unsent` may say that nothing was sent, which is no failure.
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);

    // A registration that fails takes the packets queued behind it: none was sent.
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();
    const registering = await node.pending("register");
    const queued = rawPacket(0xd4);
    iface.sendData(queued.raw);
    registering.fail();
    await eventually(() => seen.lost().length === 1, "lost");
    assert.deepEqual(seen.lost()[0], { packetHashes: [queued.hash], reason: "Failed to fetch", abandoned: false, unsent: [queued.hash] });
    assert.equal(node.count("exchange"), 0, "and no request ever carried it");
    iface.disconnect();

    // block() drops what is queued, and none of it was sent either; the exchange in flight carries nothing.
    const blocked = await upInterface(t, fakeNode(t), clock);
    blocked.iface.check("online");
    const queuedAtBlock = rawPacket(0xe5);
    blocked.iface.sendData(queuedAtBlock.raw);
    blocked.iface.block("the exchange URL is blocked by this page's Content-Security-Policy");
    await eventually(() => blocked.seen.lost().length === 1, "lost at once");
    assert.deepEqual(blocked.seen.lost()[0].packetHashes, [queuedAtBlock.hash]);
    assert.deepEqual(blocked.seen.lost()[0].unsent, [queuedAtBlock.hash]);
});

// ── A DM whose packet is lost (app.js) ─────────────────────────────────────

function braceMatch(from, label) {
    const bodyStart = app.indexOf("{", from);
    let depth = 0;
    for (let i = bodyStart; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}") {
            depth--;
            if (depth === 0) return [bodyStart, i];
        }
    }
    throw new Error(`could not brace-match ${label}`);
}

function extractMethod(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const [open, close] = braceMatch(start + signature.length, signature);
    return app.slice(open + 1, close);
}

function extractObject(name) {
    const start = app.indexOf(`\nconst ${name} = {`);
    assert.notEqual(start, -1, `${name} is missing from app.js`);
    const [open, close] = braceMatch(start, name);
    return app.slice(open, close + 1);
}

function compile(signature, env) {
    const body = extractMethod(signature).replaceAll("this.", "self.");
    const inner = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")")).trim();
    // A destructured parameter ({ a, b }) is bound from a plain one.
    const destructured = inner.startsWith("{");
    const params = destructured ? ["__arg"] : inner.split(",").map((p) => p.trim()).filter(Boolean);
    const prelude = destructured ? `const ${inner} = __arg;` : "";
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params,
        signature.startsWith("async ") ? `${prelude} return (async () => {${body}})();` : `${prelude}${body}`);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

const methodName = (signature) => signature.replace(/^async /, "").split("(")[0];
const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery").toString("hex");

const DM_METHODS = [
    "sendMessage(contact, content, attachments = [])", "_dispatchMessage(contact, outMsg)",
    "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
    "async _propagateMessage(contact, outMsg)", "_signerFor(srcHash)",
    "_armSendCeiling(contactHash, msgId)", "_failSending(contactHash, msgId, why = null)",
    "_exchangeIsDown()", "_onPacketsLost({ packetHashes, reason, unsent = [] })",
];

/** The real DM send path from app.js over a real Reticulum whose one interface is `iface`. */
function makeDmClient(iface) {
    const data = new Map();
    const sGet = (k) => (data.has(k) ? JSON.parse(data.get(k)) : null);
    const sSet = (k, v) => data.set(k, JSON.stringify(v));
    const events = [];
    const Harness = { recordInbound() {}, event: (kind, detail) => events.push({ kind, detail }), error() {} };
    const MsgStore = new Function("sGet", "sSet", "Harness", "addInOrder", `return ${extractObject("MsgStore")};`)(sGet, sSet, Harness, addInOrder);
    const appTimers = [];
    const cleared = [];
    const propagationLinks = [];
    const env = {
        MsgStore, Harness, console: { log() {}, warn() {}, error() {} },
        ContactStore: { touch() {}, setReachable() {}, propagationDelay: () => 5, allow() {} },
        setTimeout: (fn, ms) => { const timer = { fn, ms }; appTimers.push(timer); return timer; },
        clearTimeout: (timer) => { if (timer !== undefined) cleared.push(timer); },
        Identity, Buffer, Destination, LXMessage, Link, Packet, crypto: globalThis.crypto,
        DistroManager: { has: false }, IdMgr: { id: me }, applyDisplayName,
    };
    const rns = new Reticulum();
    const self = {
        _rns: rns, _initialized: true, _onMsg: [],
        _decideMessageName: () => ABSENT, _recordNameDelivered() {},
        _pendingTimeouts: new Map(), _pendingPacketHashes: new Map(), _pendingTickets: new Map(),
        _sendTransfers: new SendTransfers(),
        _cfg: { propagationNodeHash: "b".repeat(32) },
        sendingIdentity: () => ({ identity: me, hash: lxmfHash(me), isDistro: false }),
        _ensurePropagationLink: async () => { propagationLinks.push(1); throw new Error("no propagation link in this test"); },
    };
    for (const signature of DM_METHODS) self[methodName(signature)] = compile(signature, env)(self);
    iface.on("lost", (lost) => self._onPacketsLost(lost));
    return { self, rns, MsgStore, events, appTimers, cleared, propagationLinks };
}

const me = Identity.create();
const peer = Identity.create();
const alice = { destHash: lxmfHash(peer), publicKey: peer.getPublicKey().toString("hex"), isDistro: false };

test("a DM whose packet is lost with a failed exchange fails at once and is never sent again", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    const c = makeDmClient(iface);
    const seen = record(iface);
    c.rns.addInterface(iface); // connects
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => iface.isUp, "up");

    const msg = c.self.sendMessage(alice, "hello over a dying exchange");
    assert.equal(msg.status, "sending");
    const carrying = await node.pending("exchange");
    assert.equal(carrying.body.packets.length, 1, "the DM left in this batch");
    const fallback = c.appTimers.find((x) => x.ms === 5000);
    const ceiling = c.appTimers.find((x) => x.ms === 30000);
    assert.ok(fallback && ceiling, "the propagation fallback and the 30 s ceiling are armed");

    carrying.fail();
    await eventually(() => c.MsgStore.get(alice.destHash)[0].status === "failed", "the DM failed");
    assert.equal(seen.lost().length, 1);
    assert.ok(c.cleared.includes(ceiling), "at once: its ceiling is cleared, not waited out");
    assert.ok(c.events.some((e) => e.kind === "dm-lost" && e.detail.id === msg.id));
    const proofKey = seen.lost()[0].packetHashes[0].slice(0, 32);
    assert.ok(c.self._pendingPacketHashes.get(proofKey)?.dm, "a proof that still arrives can still be matched");

    // The propagation fallback comes due: a failed DM is dead (D3).
    await fallback.fn();
    await tick();
    assert.equal(c.propagationLinks.length, 0, "no propagated copy of a message the user saw fail");
    assert.equal(c.MsgStore.get(alice.destHash)[0].status, "failed");

    // Nor does the next exchange carry it.
    clock.fire(clock.armed());
    assert.deepEqual((await node.pending("exchange")).body.packets, []);
});

test("a DM sent while the exchange is down fails at once and sends nothing", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    const c = makeDmClient(iface);
    c.rns.addInterface(iface);
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => iface.isUp, "up");
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => iface.isDown, "down");

    const requests = node.requests.length;
    const msg = c.self.sendMessage(alice, "sent into a dead exchange");
    assert.equal(msg.status, "failed", "shown failed at once");
    assert.deepEqual(c.MsgStore.get(alice.destHash).map((m) => m.status), ["failed"]);
    assert.equal(c.appTimers.length, 0, "no fallback, no ceiling: nothing will send it");
    await tick();
    assert.equal(node.requests.length, requests, "nothing left the browser");
});

// ── Group messages and channel posts while the exchange is down (app.js) ───

/** An interface whose first registration failed: down. */
async function downInterface(t, node) {
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    iface.connect();
    (await node.pending("register")).fail();
    await eventually(() => iface.isDown, "down");
    return iface;
}

function memoryStorage() {
    const data = new Map();
    return {
        sGet: (k) => (data.has(k) ? JSON.parse(data.get(k)) : null),
        sSet: (k, v) => data.set(k, JSON.stringify(v)),
    };
}

/** The real sendGroupMessage over the real GroupMsgStore; the fan-out is recorded, not run. */
function makeGroupClient(iface) {
    const { sGet, sSet } = memoryStorage();
    const GroupMsgStore = new Function("sGet", "sSet", "addInOrder", `return ${extractObject("GroupMsgStore")};`)(sGet, sSet, addInOrder);
    const group = { groupId: "9".repeat(32), groupName: "G", members: new Map() };
    const env = {
        GroupMsgStore, GroupStore: { get: (id) => (id === group.groupId ? group : null), _save() {} },
        console: { log() {}, warn() {}, error() {} },
    };
    const dispatched = [];
    const self = {
        _rns: { interfaces: [iface] }, _initialized: true, ownHash: "a".repeat(32), _onMsg: [],
        _dispatchGroupMessage: async (groupId, outMsg) => { dispatched.push(outMsg); return outMsg; },
    };
    for (const signature of ["async sendGroupMessage(groupId, content)", "_exchangeIsDown()"]) {
        self[methodName(signature)] = compile(signature, env)(self);
    }
    return { self, group, GroupMsgStore, dispatched };
}

/** The real sendChannelMessage over the real ChannelMsgStore; anything past the down check stops at the subscription. */
function makeChannelClient(iface) {
    const { sGet, sSet } = memoryStorage();
    const ChannelMsgStore = new Function("sGet", "sSet", "addInOrder", `return ${extractObject("ChannelMsgStore")};`)(sGet, sSet, addInOrder);
    const channel = { channelName: "general", channelHash: "c".repeat(32) };
    const me = Identity.create();
    const env = {
        ChannelMsgStore, IdMgr: { has: true, id: me, hash: me.hash.toString("hex") }, DistroManager: { has: false }, Destination,
        ChannelStore: { get: (name) => (name === channel.channelName ? channel : null), touch() {} },
        console: { log() {}, warn() {}, error() {} },
    };
    const subscribing = [];
    const notified = [];
    const self = {
        _rns: { interfaces: [iface] }, _rfedSendChain: Promise.resolve(),
        _onMsg: [(event, name) => notified.push({ kind: event?.kind, name })],
        _ensureChannelSubscribed: async (ch) => { subscribing.push(ch); throw new Error("sent on (test stops here)"); },
    };
    for (const signature of ["async sendChannelMessage(channelName, content)", "_exchangeIsDown()", "_setChannelPostStatus(channelName, msgId, status)",
        "sendingIdentity()"]) {
        self[methodName(signature)] = compile(signature, env)(self);
    }
    return { self, channel, ChannelMsgStore, subscribing, notified };
}

test("a group message sent while the exchange is down fails at once and is not fanned out", async (t) => {
    quiet(t);
    fakeTimers(t);
    const node = fakeNode(t);
    const c = makeGroupClient(await downInterface(t, node));
    const stored = await c.self.sendGroupMessage(c.group.groupId, "into a dead exchange");
    assert.equal(stored.status, "failed", "shown failed at once");
    assert.deepEqual(c.GroupMsgStore.get(c.group.groupId).map((m) => m.status), ["failed"]);
    assert.equal(c.dispatched.length, 0, "nothing fans it out, now or later");
});

test("a group message sent while the exchange is up is fanned out (control)", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface } = await upInterface(t, node, clock);
    const c = makeGroupClient(iface);
    await c.self.sendGroupMessage(c.group.groupId, "over a live exchange");
    assert.deepEqual(c.dispatched.map((m) => m.status), ["sending"]);
});

test("a channel post sent while the exchange is down fails at once and is not sent", async (t) => {
    quiet(t);
    fakeTimers(t);
    const node = fakeNode(t);
    const c = makeChannelClient(await downInterface(t, node));
    const stored = await c.self.sendChannelMessage(c.channel.channelName, "into a dead exchange");
    assert.equal(stored.status, "failed", "shown failed at once");
    assert.deepEqual(c.ChannelMsgStore.get(c.channel.channelName).map((m) => m.status), ["failed"]);
    assert.equal(c.subscribing.length, 0, "nothing goes toward the channel");
    assert.deepEqual(c.notified, [{ kind: "channel-send-complete", name: "general" }], "the composer is released");
});

test("a channel post sent while the exchange is up goes on toward the channel (control)", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface } = await upInterface(t, node, clock);
    const c = makeChannelClient(iface);
    await assert.rejects(c.self.sendChannelMessage(c.channel.channelName, "over a live exchange"), /test stops here/);
    assert.equal(c.subscribing.length, 1);
});

// ── The app follows the exchange (app.js) ──────────────────────────────────

test("the app follows the exchange: the dot on up and down, lost packets to the DM path, its return to the persistent links, nothing from a stopped interface", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    const statuses = [];
    const env = {
        Harness: { event: (kind, detail) => { if (kind === "status") statuses.push(detail.status); }, markReady() {} },
    };
    const self = { _rns: { interfaces: [iface] }, _status: "connecting", _connType: "exchange", _onStatus: [] };
    const registered = [];
    const lost = [];
    self._onExchangeRegistered = () => registered.push(1);
    self._onPacketsLost = (detail) => lost.push(detail);
    const resumes = [];
    self._onPageResume = (trigger) => resumes.push(trigger);
    const distroReturns = [];
    self._sendDistroNeverLeft = (trigger) => distroReturns.push(trigger);
    self._setStatus = compile("_setStatus(s, type)", env)(self);
    compile("_followExchange(iface)", env)(self)(iface);

    iface.connect();
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => self._status === "online", "online on up");
    assert.equal(registered.length, 1, "the registration initializes the connection");
    assert.deepEqual(resumes, [], "the first up is initialization, not a return");
    assert.deepEqual(distroReturns, [], "and sends nothing owed to the distro");

    clock.fire(clock.armed());
    const failing = await node.pending("exchange");
    const dm = rawPacket(0xe5);
    iface.sendData(dm.raw); // queued behind the exchange in flight
    failing.fail();
    await eventually(() => self._status === "offline", "offline on down");
    await eventually(() => lost.length === 1, "lost packets reach the DM path");
    assert.deepEqual(lost[0].packetHashes, [dm.hash]);

    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => self._status === "online", "online again on up");
    assert.deepEqual(statuses, ["online", "offline", "online"], "credentials alone never made it green");
    assert.deepEqual(resumes, ["exchange back"],
        "the exchange's return re-drives the persistent links (app-links interface_online)");
    assert.deepEqual(distroReturns, ["exchange back"],
        "and sends what is owed to the distro and never left the device while it was down (James, 2026-10-06)");

    // disconnect() replaced the interface: its events are no longer this connection's.
    self._rns = { interfaces: [] };
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => iface.isDown, "down");
    await tick(); await tick();
    assert.deepEqual(statuses, ["online", "offline", "online"], "a stopped interface does not move the dot");
    assert.deepEqual(resumes, ["exchange back"], "nor re-drive anything");
    assert.deepEqual(distroReturns, ["exchange back"], "nor send anything for the distro");

    assert.match(extractMethod("async connect()"), /this\._followExchange\(iface\);\s*this\._rns\.addInterface\(iface\);/,
        "hooked before addInterface() connects it");
    assert.doesNotMatch(app, /_monTimer/, "the credential monitor is gone");
});

// ── An upload owed to the distro, over the real exchange (app.js) ──────────
//
// James, 2026-10-06: on staging a short network drop left an Android phone's
// propagation link up, the owed upload attempted during the drop never left
// the device, and no coming-up followed, so it waited 35 s for an unrelated
// link close. The web has the same chain: the exchange refuses a packet sent
// while it is down, reports it lost, and the page treated it as a loss.

const DISTRO_METHODS = [
    "_followExchange(iface)", "_setStatus(s, type)", "_exchangeIsDown()", "_onPacketsLost({ packetHashes, reason, unsent = [] })",
    "async _sendDistroSentCopy(recipientHex, title, content)", "_sealForDistroSync(packed, label)", "_distroSyncProofGoes(link)",
    "_oweDistro(entry)", "async _sendDistroOutbox(link, trigger)",
    "async _sendDistroNeverLeft(trigger)", "_distroAttemptOpen(entry, link)", "_unprovedSince(entry, comingUp)",
    "async _uploadOwed(link, entry, comingUp = null)", "_stillOwed(entry)", "_dropMembershipOwedToOtherDistros()",
    "_distroOwedOutcome(entry, how, error, goesNow = false)", "_distroOwedNeverLeft(entry, error)",
    "_uploadForDistro(link, propagationPacked, label)",
];

const R = "0123456789abcdef0123456789abcdef";

/**
 * The real distro-outbox path from app.js over the real PostInterface `iface`:
 * the propagation link is a stand-in whose packets go through
 * iface.sendData, so the exchange itself refuses, queues, carries or loses
 * them, and its events reach the page through the real _followExchange.
 */
function makeDistroClient(iface, { link: realLink = null } = {}) {
    const { sGet, sSet } = memoryStorage();
    const distro = Identity.create();
    const events = [];
    const resumes = [];
    const Harness = {
        event: (kind, detail) => events.push({ kind, detail }),
        error: (where, e) => events.push({ kind: "error", detail: { where, message: e.message } }),
        markReady() {},
    };
    const quietLog = { log() {}, warn() {}, error() {} };
    const watches = [];     // the §1 watch's timers, which this test's clock never runs
    const uploadOf = new Map();  // a packet's hash → the propagation upload it carries
    let made = 0;
    // `realLink`: this device's end of a real propagation link (resourceLink), whose uploads over the MDU go as real Resources.
    const link = realLink ?? {
        status: Link.ACTIVE,
        newLinkPacket: (context, data) => {
            const raw = rawPacket(0x30 + made++).raw;
            uploadOf.set(Packet.fromBytes(raw).packetHash.toString("hex"), Buffer.from(data));
            return { packetHash: Packet.fromBytes(raw).packetHash, pack: () => raw };
        },
        _transmit: (raw) => { iface.sendData(raw); return raw; },
        sendResource: async () => { throw new Error("no Resource in this test"); },
    };
    const env = {
        Harness, console: quietLog, Buffer, Cryptography, LXMessage, LXMF, Packet: { NONE: 0x00 }, Link: { MDU: realLink ? Link.MDU : 100_000, ACTIVE: Link.ACTIVE },
        DistroManager: { has: true, identity: distro, lxmfDeliveryHash: lxmfHash(distro), pubKey: distro.getPublicKey().toString("hex") },
        DistroOutboxStore: new DistroOutbox({ get: sGet, set: sSet }), sentCopyEntryId, channelSyncEntryId, ActiveTab: { held: true },
        sealForSync, syncProofKept, Destination,
    };
    const self = {
        ownHash: lxmfHash(me), _rns: { interfaces: [iface] }, _status: "connecting", _connType: "exchange", _onStatus: [],
        _pendingPacketHashes: new Map(), _distroOutboxInFlight: new Map(), _propComingUps: 0, _distroUnproved: new UnprovedUploads(),
        _distroUploads: new DistroUploads({
            log: quietLog,
            setTimer: (fn, ms) => { const timer = { fn, ms, cleared: false }; watches.push(timer); return timer; },
            clearTimer: (timer) => { timer.cleared = true; },
        }),
        _propLink: link, _buildPropagationPacked: async (packed) => packed,
        _onExchangeRegistered() {}, _onPageResume: (trigger) => resumes.push(trigger),
    };
    for (const signature of DISTRO_METHODS) self[methodName(signature)] = compile(signature, env)(self);
    return {
        self, env, link, events, resumes, watches, uploadOf,
        errors: () => events.filter((e) => e.kind === "error"),
        sentCopies: () => events.filter((e) => e.kind === "distro-sent-copy"),
        owed: () => env.DistroOutboxStore.list(),
        /** What the exchange has carried to the node so far: every upload packet in a request, by hash. */
        carried: (node) => node.requests.filter((r) => r.path === "/v1/interfaces/exchange")
            .flatMap((r) => (r.body.packets ?? []).map((b64) => Packet.fromBytes(Buffer.from(b64, "base64")).packetHash.toString("hex")))
            .filter((hash) => uploadOf.has(hash)),
        /** The node proves the upload whose packet has this hash (the proof handler's entry). */
        prove: (hash) => {
            const key = hash.slice(0, 32);
            const pending = self._pendingPacketHashes.get(key);
            if (!pending) return false;
            self._pendingPacketHashes.delete(key);
            pending.onProof?.(pending.messageId);
            return true;
        },
    };
}

/** An interface the page follows from its first request (so its first "up" is initialization), registered and up, with the distro client over it. */
async function upWithDistroClient(t, node, clock) {
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    const c = makeDistroClient(iface);
    c.self._followExchange(iface);
    iface.connect();
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => c.self._status === "online", "online on up");
    assert.equal(clock.armed().ms, 1000, "polls on the node's idle interval");
    return { iface, c };
}

/** The network drops: the poll that comes due fails, and the page has heard the exchange go down. */
async function dropExchange(c, iface, node, clock) {
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => iface.isDown && c.self._status === "offline", "down");
}

/** The network is back: the next attempt (the reconnect wait is cut short by check() on the browser's "online") is answered, and the page hears "up". */
async function returnExchange(c, iface, node, clock, { check = false } = {}) {
    if (check) iface.check("online");
    else clock.fire(clock.armed());
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => c.self._status === "online", "online again on up");
}

test("the staging case: a short drop with the propagation link still up; the upload owed during it never left, is no failure, and goes when the exchange answers again, once", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, c } = await upWithDistroClient(t, node, clock);
    await dropExchange(c, iface, node, clock);
    assert.equal(c.link.status, Link.ACTIVE, "the propagation link never went STALE and never closed");

    // The user sends as the distro during the drop: the sent-copy is owed and attempted at once on the link that is up.
    await c.self._sendDistroSentCopy(R, "", "sent during the drop");
    await eventually(() => c.self._distroUnproved.neverLeftSize === 1, "the exchange said nothing of it was sent");
    const [entry] = c.owed();
    assert.deepEqual(c.carried(node), [], "nothing reached the node");
    assert.deepEqual(c.errors(), [], "and it is no failure: the Harness hears none");
    assert.equal(c.self._distroUnproved.neverLeft(entry), true);
    assert.deepEqual([c.self._distroUnproved.size, c.self._propComingUps], [0, 0], "no failure recorded, and no coming-up since");
    assert.equal(c.owed().length, 1, "still owed");
    assert.deepEqual(c.watches.filter((w) => !w.cleared), [], "no §1 watch is left for a packet nobody sent");
    assert.deepEqual(c.resumes, [], "and the page has not resumed anything");

    // Timers decide nothing: the reconnect attempts come and the network is still down.
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await tick(); await tick();
    assert.deepEqual(c.carried(node), [], "no timer sends it");
    assert.equal(c.self._distroUnproved.neverLeftSize, 1);

    // The network is back, the exchange answers: that is the event.
    await returnExchange(c, iface, node, clock);
    assert.deepEqual(c.resumes, ["exchange back"], "the return re-drives the persistent links as before");
    const carrying = await node.pending("exchange");
    const hashes = (request) => request.body.packets.map((b64) => Packet.fromBytes(Buffer.from(b64, "base64")).packetHash.toString("hex"));
    assert.equal(carrying.body.packets.length, 1, "the owed upload left in this exchange");
    const [hash] = hashes(carrying);
    assert.deepEqual(c.uploadOf.get(hash), Buffer.from(entry.packed, "base64"), "the LXMF message packed when the user acted, not a new one");
    carrying.respond(200, {});
    await eventually(() => c.self._distroUnproved.neverLeftSize === 0, "an upload of it has begun");

    // Its proof makes it owed no more; the next return sends nothing.
    assert.equal(c.prove(hash), true);
    await eventually(() => c.sentCopies().length === 1, "proved: said sent");
    assert.deepEqual(c.owed(), []);
    assert.deepEqual(c.errors(), []);
    await dropExchange(c, iface, node, clock);
    await returnExchange(c, iface, node, clock);
    await tick(); await tick();
    assert.deepEqual(c.carried(node), [hash], "nothing more went: it was proved");
    assert.deepEqual(c.resumes, ["exchange back", "exchange back"]);
});

test("the browser's \"online\" does not send it, and the exchange's answer to the check it makes does: the return is the interface's, never the window's", async (t) => {
    // PostInterface hooks the window's "online" to check(); the page's own
    // listener of it re-arms the links (_onPageResume) and, while the
    // exchange is down, does nothing more. The upload goes when the exchange
    // answers, not when the browser says it has a network.
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, c } = await upWithDistroClient(t, node, clock);
    await dropExchange(c, iface, node, clock);
    await c.self._sendDistroSentCopy(R, "", "sent during the drop");
    await eventually(() => c.self._distroUnproved.neverLeftSize === 1, "never left");

    // "online": the check is an exchange attempt now. It fails: the network is not really back, and nothing is sent.
    iface.check("online");
    (await node.pending("exchange")).fail();
    await tick(); await tick();
    assert.deepEqual([c.carried(node), c.resumes, c.self._distroUnproved.neverLeftSize], [[], [], 1]);
    // "online" again, and this time the exchange answers: now it goes.
    await returnExchange(c, iface, node, clock, { check: true });
    const carrying = await node.pending("exchange");
    assert.equal(carrying.body.packets.length, 1, "it left with the exchange's return");
    carrying.respond(200, {});
});

test("an upload that left in a batch the exchange then failed is a loss: it does not go when the exchange answers again, and goes at the propagation link's next coming-up", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, c } = await upWithDistroClient(t, node, clock);

    // Sent while the exchange is up: it is in the batch an exchange is carrying when the network drops.
    await c.self._sendDistroSentCopy(R, "", "in a batch that failed");
    const carrying = await node.pending("exchange");
    assert.equal(carrying.body.packets.length, 1, "it left");
    const [hash] = c.carried(node);
    carrying.fail();
    await eventually(() => c.errors().length === 1, "reported lost");
    assert.deepEqual(c.errors().map((e) => [e.detail.where, e.detail.message]),
        [["distro-sent-copy", "its packet was lost (Failed to fetch)"]], "a loss after the packet left is a failure, and reported");
    const [entry] = c.owed();
    assert.equal(c.self._distroUnproved.neverLeft(entry), false, "not a packet that never left");
    assert.equal(c.self._distroUnproved.at(entry), 0, "recorded at the coming-up it was decided at");

    // The exchange answers again: nothing is retried on a failure.
    await returnExchange(c, iface, node, clock);
    await tick(); await tick();
    assert.equal(node.requests.at(-1).body.packets.length, 0, "no upload went with the exchange's return");
    clock.fire(clock.armed());
    const next = await node.pending("exchange");
    assert.deepEqual(next.body.packets, [], "nor on the next poll: a failure waits for a coming-up");
    next.respond(200, {});
    await tick(); await tick();
    assert.deepEqual(c.carried(node), [hash], "only the first upload ever left");
    assert.equal(c.owed().length, 1, "still owed");

    // The propagation link's next coming-up sends it.
    await c.self._sendDistroOutbox(c.link, "established");
    const again = await node.pending("exchange");
    assert.equal(again.body.packets.length, 1, "the coming-up sent it");
    again.respond(200, {});
    const [, second] = c.carried(node);
    assert.equal(c.prove(second), true);
    await eventually(() => c.sentCopies().length === 1, "proved");
    assert.deepEqual(c.owed(), []);
});

test("an upload queued behind a failed batch went into no request: it never left, and goes when the exchange answers again", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, c } = await upWithDistroClient(t, node, clock);
    // An exchange is in flight (the idle poll, carrying nothing) when the user acts: the upload is queued behind it.
    clock.fire(clock.armed());
    const poll = await node.pending("exchange");
    assert.equal(poll.body.packets.length, 0);
    await c.self._sendDistroSentCopy(R, "", "queued behind a batch that failed");
    await eventually(() => c.self._distroUploads._open.size === 1, "the upload was handed to the exchange");
    poll.fail();
    await eventually(() => c.self._distroUnproved.neverLeftSize === 1, "the exchange said it went into no request");
    assert.deepEqual([c.carried(node), c.errors(), c.self._distroUnproved.size], [[], [], 0], "nothing sent, no failure, none recorded");

    await returnExchange(c, iface, node, clock);
    const carrying = await node.pending("exchange");
    assert.equal(carrying.body.packets.length, 1, "it goes at the return");
    carrying.respond(200, {});
});

test("an upload for the distro is the only reader of `unsent`: a DM queued behind a failed batch fails at once, as ever (D3)", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    const c = makeDmClient(iface);
    const seen = record(iface);
    c.rns.addInterface(iface);
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => iface.isUp, "up");
    clock.fire(clock.armed());
    const poll = await node.pending("exchange");
    const msg = c.self.sendMessage(alice, "queued behind a batch that is about to fail");
    assert.equal(msg.status, "sending");
    poll.fail();
    await eventually(() => c.MsgStore.get(alice.destHash)[0].status === "failed", "the DM failed at once");
    assert.deepEqual(seen.lost()[0].unsent, [seen.lost()[0].packetHashes[0]], "its packet was never sent, and the interface says so");
    assert.ok(c.events.some((e) => e.kind === "dm-lost" && e.detail.id === msg.id), "and the DM path treats it as lost, nothing sends it again");
});

// ── An upload owed to the distro that goes as a Resource (app.js) ──────────
//
// James, 2026-10-10 (DISTRO-SYNC-PROOF-DESIGN.md §5.3(a), under his ruling
// of 2026-10-06): a Resource upload whose first advertisement no interface
// could carry never left the device. It is no failure, the Resource is
// cancelled on this device and the propagation link kept, and it goes at the
// exchange's return like a packet that never left. Once its first
// advertisement has left, the Resource's own retries and failure decide, as
// before (ruling of 2026-10-04). Every sent copy over the link MDU is a
// Resource today, and with the sync proof every upload for the distro is.

/**
 * A real propagation link (test_link_pair.mjs): this device's end `a` sends
 * through the exchange `iface`, and the node's end `b` takes every Resource;
 * what `b` sends back reaches `a` directly, as the node's answers would.
 */
function resourceLink(iface) {
    const { a, b } = linkPair();
    a.destination = { rns: { sendData: (raw) => iface.sendData(raw) } };
    b.setResourceStrategy(Link.ACCEPT_ALL);
    const received = [];
    b.on("resource", ({ data }) => received.push(Buffer.from(data)));
    return { a, b, received };
}

/** The node takes the packets an exchange carries: each goes to the link's far end `b`, as linkPair's wire routes it. */
function toNode(b, request) {
    for (const b64 of request.body.packets ?? []) {
        const packet = Packet.fromBytes(Buffer.from(b64, "base64"));
        if (packet.packetType === Packet.DATA) b.onPacket(packet);
        else if (packet.packetType === Packet.PROOF && packet.context === Packet.RESOURCE_PRF) b.onResourceProof(packet);
        else if (packet.packetType === Packet.PROOF) b.onPacketProof(packet);
    }
}

/** Answer every exchange (handing what it carries to `b` unless `deliver` is false) until `done()`. A failure mechanism only. */
async function carryUntil(node, b, done, what, { deliver = true } = {}) {
    for (let i = 0; i < 400 && !done(); i++) {
        const request = node.requests.find((r) => !r.settled && r.path === "/v1/interfaces/exchange");
        if (request) {
            request.respond(200, {});
            if (deliver) toNode(b, request);
        }
        await tick();
    }
    assert.ok(done(), `never happened: ${what}`);
}

/** The hashes of the packets one exchange carries, by context. */
const carriedContexts = (request) => (request.body.packets ?? []).map((b64) => Packet.fromBytes(Buffer.from(b64, "base64")).context);

/** Over the link MDU, so the upload of its sent copy goes as a Resource. */
const LONG = "a sent copy over the link MDU, so its upload is a Resource: ".padEnd(900, "x");

async function upWithResourceClient(t, node) {
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", "ab".repeat(16));
    t.after(() => iface.disconnect());
    const { a, b, received } = resourceLink(iface);
    const c = makeDistroClient(iface, { link: a });
    c.self._followExchange(iface);
    iface.connect();
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => c.self._status === "online", "online on up");
    return { iface, c, a, b, received };
}

test("the staging case for a Resource upload: its first advertisement never left in a short drop, so the upload never left: no failure, the Resource cancelled on this device and the link kept, and it goes when the exchange answers again, at once and once (James, 2026-10-10)", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, c, a, b, received } = await upWithResourceClient(t, node);
    await dropExchange(c, iface, node, clock);

    // The user sends as the distro during the drop: its sent copy is over the MDU, so the upload is a Resource.
    await c.self._sendDistroSentCopy(R, "", LONG);
    const [entry] = c.owed();
    assert.ok(Buffer.from(entry.packed, "base64").length > Link.MDU, "a Resource upload");
    await eventually(() => c.self._distroUnproved.neverLeftSize === 1, "the exchange said its first advertisement went into no request");
    assert.equal(c.self._distroUnproved.neverLeft(entry), true, "decided never left");
    assert.deepEqual([c.self._distroUnproved.size, c.self._propComingUps], [0, 0], "no failure recorded, and no coming-up since");
    assert.deepEqual(c.errors(), [], "no failure: the Harness hears none");
    assert.equal(a.status, Link.ACTIVE, "the propagation link is kept");
    assert.deepEqual(a.outgoingResources, [], "the Resource was cancelled on this device");
    assert.equal(c.self._pendingPacketHashes.size, 0, "and its advertisement's entry went with it");

    // The Resource's rejection (its cancel) comes later, and decides nothing: DistroUploads decided it once.
    await tick(); await tick(); await tick();
    assert.deepEqual([c.self._distroUnproved.neverLeftSize, c.self._distroUnproved.size, c.errors()], [1, 0, []],
        "its rejection is no loss and no failure");
    assert.equal(c.self._distroUploads._open.size, 0, "the upload is decided");
    assert.deepEqual(received, [], "nothing reached the node");
    assert.deepEqual(clock.timers.filter((x) => !x.cleared && !x.fired).map((x) => x.ms), [PostInterface.RECONNECT_WAIT_MS],
        "the Resource's own timers went with it: only the exchange's reconnect wait is armed");

    // The exchange answers again: that is the event. The upload goes in the next exchange, before any timer fires: no 35 s wait.
    await returnExchange(c, iface, node, clock);
    const fired = clock.timers.filter((x) => x.fired).length;
    const carrying = await node.pending("exchange");
    assert.deepEqual(carriedContexts(carrying), [Packet.RESOURCE_ADV], "a new Resource's first advertisement left with the exchange's return");
    assert.equal(c.self._distroUnproved.neverLeftSize, 0, "an upload of it has begun");
    await carryUntil(node, b, () => received.length === 1 && c.sentCopies().length === 1, "the node took it, and it was proved");
    assert.equal(clock.timers.filter((x) => x.fired).length, fired, "no timer was fired for it: the return sent it");
    assert.deepEqual(received[0], Buffer.from(entry.packed, "base64"), "the LXMF message packed when the user acted, once");
    assert.deepEqual([c.owed(), c.errors(), c.self._distroUnproved.size, c.self._distroUnproved.neverLeftSize], [[], [], 0, 0], "owed no more");
});

test("a Resource upload whose first advertisement left: a loss report for it decides nothing, and the Resource's own failure is a loss that waits for the propagation link's next coming-up, never the exchange's return (ruling of 2026-10-04)", async (t) => {
    quiet(t);
    const clock = fakeTimers(t);
    const node = fakeNode(t);
    const { iface, c, a, b, received } = await upWithResourceClient(t, node);

    // Sent while the exchange is up: its first advertisement is in the batch an exchange is carrying when the network drops.
    await c.self._sendDistroSentCopy(R, "", LONG);
    const [entry] = c.owed();
    const carrying = await node.pending("exchange");
    assert.deepEqual(carriedContexts(carrying), [Packet.RESOURCE_ADV], "its first advertisement left");
    const [resource] = a.outgoingResources;
    carrying.fail();
    await eventually(() => iface.isDown && c.self._status === "offline", "down");
    await tick(); await tick();
    // The exchange reported the advertisement lost, not unsent: it may have reached the node. That decides nothing.
    assert.deepEqual([c.errors(), c.self._distroUnproved.size, c.self._distroUnproved.neverLeftSize], [[], 0, 0],
        "no failure and no never-left: the loss report for an advertisement that left decides nothing");
    assert.equal(c.self._distroUploads._open.size, 1, "the upload is still open");
    assert.equal(resource.status, Resource.ADVERTISED, "the Resource goes on: its own retries decide");
    assert.equal(c.self._pendingPacketHashes.size, 1, "its first advertisement is still tracked");

    // The exchange answers again: nothing goes for it (it did not never leave), and the Resource is untouched.
    await returnExchange(c, iface, node, clock, { check: true });
    await carryUntil(node, b, () => true, "the return's exchange answered", { deliver: false });
    assert.equal(resource.status, Resource.ADVERTISED);
    assert.equal(a.outgoingResources.length, 1, "no second upload: one Resource");

    // The node never answers: the Resource re-advertises (the protocol's own retries, carried but not delivered here) and fails.
    let now = Date.now();
    for (let i = 0; i < 20 && resource.status === Resource.ADVERTISED; i++) {
        now += 3_600_000;
        resource.watchdog(now);
        await carryUntil(node, b, () => !node.requests.some((r) => !r.settled && r.path === "/v1/interfaces/exchange"), "re-advertisement carried", { deliver: false });
    }
    assert.equal(resource.status, Resource.FAILED, "the Resource failed by its own retries");
    await eventually(() => c.errors().length === 1, "decided lost");
    assert.match(c.errors()[0].detail.message, /^its Resource failed \(no response to the resource advertisement\)$/, "a loss, and reported");
    assert.deepEqual([c.self._distroUnproved.neverLeft(entry), c.self._distroUnproved.at(entry)], [false, 0],
        "a failure recorded at the coming-up it was decided at, not a never-left");
    assert.equal(c.self._pendingPacketHashes.size, 0, "its advertisement's entry went with the Resource");
    assert.equal(a.status, Link.ACTIVE, "the link is kept");

    // The exchange's return sends nothing for a failure.
    await dropExchange(c, iface, node, clock);
    await returnExchange(c, iface, node, clock);
    await carryUntil(node, b, () => true, "answered", { deliver: false });
    assert.equal(a.outgoingResources.length, 0, "nothing went at the exchange's return");
    assert.deepEqual(received, []);

    // The propagation link's next coming-up sends it, and the node takes it.
    await c.self._sendDistroOutbox(a, "established");
    await carryUntil(node, b, () => received.length === 1 && c.sentCopies().length === 1, "uploaded again at the coming-up, and proved");
    assert.deepEqual(received[0], Buffer.from(entry.packed, "base64"));
    assert.deepEqual([c.owed(), c.self._distroUnproved.size], [[], 0], "owed no more");
});
