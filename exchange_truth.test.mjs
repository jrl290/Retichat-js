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
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import { Reticulum, Identity, Destination, LXMessage, Link, Packet } from "./lib/rns/reticulum.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";

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
    assert.equal(seen.kinds().indexOf("down") < seen.kinds().indexOf("lost"), true, "down, then what it lost");

    const requestsBefore = node.requests.length;
    const c = rawPacket(0xc3);
    iface.sendData(c.raw);
    await eventually(() => seen.lost().length === 2, "lost at once");
    assert.deepEqual(seen.lost()[1], { packetHashes: [c.hash], reason: "the exchange is down" });
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
    "sendMessage(contact, content)", "_dispatchMessage(contact, outMsg)",
    "_sendPacket(contactHash, publicKeyHex, content, messageId, onProof, onError)",
    "async _propagateMessage(contact, outMsg)", "_signerFor(srcHash)",
    "_armSendCeiling(contactHash, msgId)", "_failSending(contactHash, msgId)",
    "_exchangeIsDown()", "_onPacketsLost({ packetHashes, reason })",
];

/** The real DM send path from app.js over a real Reticulum whose one interface is `iface`. */
function makeDmClient(iface) {
    const data = new Map();
    const sGet = (k) => (data.has(k) ? JSON.parse(data.get(k)) : null);
    const sSet = (k, v) => data.set(k, JSON.stringify(v));
    const events = [];
    const Harness = { recordInbound() {}, event: (kind, detail) => events.push({ kind, detail }), error() {} };
    const MsgStore = new Function("sGet", "sSet", "Harness", `return ${extractObject("MsgStore")};`)(sGet, sSet, Harness);
    const appTimers = [];
    const cleared = [];
    const propagationLinks = [];
    const env = {
        MsgStore, Harness, console: { log() {}, warn() {}, error() {} },
        ContactStore: { touch() {}, setReachable() {}, propagationDelay: () => 5 },
        setTimeout: (fn, ms) => { const timer = { fn, ms }; appTimers.push(timer); return timer; },
        clearTimeout: (timer) => { if (timer !== undefined) cleared.push(timer); },
        Identity, Buffer, Destination, LXMessage, Link, Packet, crypto: globalThis.crypto,
        DistroManager: { has: false }, IdMgr: { id: me },
    };
    const rns = new Reticulum();
    const self = {
        _rns: rns, _initialized: true, _onMsg: [],
        _pendingTimeouts: new Map(), _pendingPacketHashes: new Map(), _pendingTickets: new Map(),
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
    const GroupMsgStore = new Function("sGet", "sSet", `return ${extractObject("GroupMsgStore")};`)(sGet, sSet);
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
    const ChannelMsgStore = new Function("sGet", "sSet", `return ${extractObject("ChannelMsgStore")};`)(sGet, sSet);
    const channel = { channelName: "general", channelHash: "c".repeat(32) };
    const env = {
        ChannelMsgStore, IdMgr: { has: true, hash: "a".repeat(32) },
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
    for (const signature of ["async sendChannelMessage(channelName, content)", "_exchangeIsDown()"]) {
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

test("the app follows the exchange: the dot on up and down, lost packets to the DM path, nothing from a stopped interface", async (t) => {
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
    self._setStatus = compile("_setStatus(s, type)", env)(self);
    compile("_followExchange(iface)", env)(self)(iface);

    iface.connect();
    (await node.pending("register")).respond(200, REGISTERED);
    (await node.pending("exchange")).respond(200, {});
    await eventually(() => self._status === "online", "online on up");
    assert.equal(registered.length, 1, "the registration initializes the connection");

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

    // disconnect() replaced the interface: its events are no longer this connection's.
    self._rns = { interfaces: [] };
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => iface.isDown, "down");
    await tick(); await tick();
    assert.deepEqual(statuses, ["online", "offline", "online"], "a stopped interface does not move the dot");

    assert.match(extractMethod("async connect()"), /this\._followExchange\(iface\);\s*this\._rns\.addInterface\(iface\);/,
        "hooked before addInterface() connects it");
    assert.doesNotMatch(app, /_monTimer/, "the credential monitor is gone");
});
