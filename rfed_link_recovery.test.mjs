// REGRESSION GUARD — do not delete, do not weaken.
//
// A failed RFed link must not be terminal for the session.
//
// Establishment over this transport fails sometimes — it is lossy enough that
// rfed's own §1 assert fires on link.establish taking 7-37s, and one dropped
// LINKREQUEST or LRPROOF ends the attempt. Until 2026-08-17 that was permanent:
// _ensureRfedLink rejected, the cached link was dropped, and nothing ever drove
// the operation again, so a single lost packet silently cost distro
// registration and pull until the page was reloaded. Verified against the live
// node that day: rfed received, accepted and proved these link requests
// normally, and concurrent links to several of its destinations established
// fine — so the loss is ordinary transient packet loss, not a bug to be
// designed around.
//
// The recovery is ported from the reference LXMF propagation router and is
// deliberately NOT a retry loop (DESIGN_PRINCIPLES §3 forbids one, and
// LXMRouter has none):
//
//   - a state per link, like LXMRouter.PR_*, so failure is inspectable
//   - a janitor clearing CLOSED links, like LXMRouter.jobs()
//   - re-entry driven by an EVENT — the reference re-calls
//     request_messages_from_propagation_node() when a path appears
//     (__request_messages_path_job); we re-drive when the service announces
//     (every 6 hours since RFed-rust b5ba134, 2026-09-23; 15 minutes before),
//     and the persistent links also when the exchange or the page comes back
//
// These tests run the real shipped methods against stubs.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const appSource = await readFile(new URL("./app.js", import.meta.url), "utf8");

function extractMethod(signature) {
    const start = appSource.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const bodyStart = appSource.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < appSource.length; i++) {
        if (appSource[i] === "{") depth++;
        else if (appSource[i] === "}") {
            depth--;
            if (depth === 0) return appSource.slice(bodyStart + 1, i);
        }
    }
    throw new Error(`could not brace-match ${signature}`);
}

/** A stub carrying the real _rfedDeferUntilAnnounce / _rfedRunPending bodies. */
function makeClient({ now = 1_000_000 } = {}) {
    const deferBody = extractMethod("_rfedDeferUntilAnnounce(key, label, run)");
    const runBody = extractMethod("_rfedRunPending(key)");
    const warnings = [];
    const self = {
        _rfedPending: new Map(),
        _rfedLinkState: new Map(),
        _now: now,
    };
    const console_ = {
        warn: (...a) => warnings.push(a.join(" ")),
        log: () => {},
    };
    const TIMEOUT = 45 * 60 * 1000;
    self._rfedDeferUntilAnnounce = new Function(
        "key", "label", "run", "self", "console", "Date", "RFED_PENDING_TIMEOUT_MS",
        deferBody.replaceAll("this.", "self."),
    ).bind(null);
    self._rfedRunPending = new Function(
        "key", "self", "console", "Date",
        runBody.replaceAll("this.", "self."),
    ).bind(null);
    return {
        self, warnings,
        defer: (k, l, r) => self._rfedDeferUntilAnnounce(k, l, r, self, console_, { now: () => self._now }, TIMEOUT),
        run: (k) => self._rfedRunPending(k, self, console_, { now: () => self._now }),
    };
}

test("a failed operation is parked, not lost", () => {
    const c = makeClient();
    let ran = 0;
    c.defer("distro.register", "distro registration", () => { ran++; });
    assert.equal(c.self._rfedPending.size, 1, "the intent must be recorded");
    assert.equal(ran, 0, "parking must not run it immediately");
});

test("the service announce re-drives the parked operation exactly once", async () => {
    const c = makeClient();
    let ran = 0;
    c.defer("distro.register", "distro registration", () => { ran++; });
    c.run("distro.register");
    // run() is dispatched through Promise.resolve() on purpose: a throwing
    // operation must not break the announce handler that re-drove it.
    await Promise.resolve();
    assert.equal(ran, 1, "the announce must re-drive it");
    c.run("distro.register");
    await Promise.resolve();
    assert.equal(ran, 1, "a second announce must not run it again — the intent is consumed");
});

test("only one intent is held per aspect", async () => {
    const c = makeClient();
    let first = 0, second = 0;
    c.defer("distro.register", "registration", () => { first++; });
    c.defer("distro.register", "pull", () => { second++; });
    assert.equal(c.self._rfedPending.size, 1);
    c.run("distro.register");
    await Promise.resolve();
    assert.equal(first, 1, "the first intent wins");
    assert.equal(second, 0, "re-driving the same intent twice is duplicate work, not resilience");
});

test("an expired intent is dropped rather than fired late", () => {
    const c = makeClient();
    let ran = 0;
    c.defer("distro.register", "distro registration", () => { ran++; });
    c.self._now += 46 * 60 * 1000; // past RFED_PENDING_TIMEOUT_MS
    c.run("distro.register");
    assert.equal(ran, 0, "past the timeout the reference gives up (PR_NO_PATH)");
    assert.equal(c.self._rfedPending.size, 0, "and the intent is cleared");
});

test("an announce for an unrelated service does nothing", () => {
    const c = makeClient();
    let ran = 0;
    c.defer("distro.register", "distro registration", () => { ran++; });
    c.run("channel");
    assert.equal(ran, 0);
    assert.equal(c.self._rfedPending.size, 1, "the distro intent must still be waiting");
});

// ── Structural guarantees ────────────────────────────────────────────────

test("link close records a state instead of silently dropping the link", () => {
    const ensure = extractMethod("_ensureRfedLink(aspects)");
    assert.match(ensure, /_rfedLinkState\.set\(key, RFED_LINK_ESTABLISHING\)/,
        "establishment must be an observable state");
    assert.match(ensure, /_rfedLinkState\.set\(key, RFED_LINK_ESTABLISHED\)/,
        "success must be an observable state");
    assert.match(ensure, /_rfedLinkState\.set\(key, established \? RFED_LINK_IDLE : RFED_LINK_FAILED\)/,
        "close must record whether the link ever established — the janitor step " +
        "from LXMRouter.jobs()");
});

test("re-driving is event-driven, never scheduled", () => {
    const defer = extractMethod("_rfedDeferUntilAnnounce(key, label, run)");
    const run = extractMethod("_rfedRunPending(key)");
    for (const [name, body] of [["_rfedDeferUntilAnnounce", defer], ["_rfedRunPending", run]]) {
        assert.doesNotMatch(body, /setTimeout|setInterval/,
            `${name} must not schedule anything — DESIGN_PRINCIPLES §3 forbids ` +
            `retry loops, and the reference re-drives on the path-available ` +
            `event, not on a timer`);
    }
});

test("the announce handler re-drives pending work", () => {
    const handler = extractMethod("_markRfedServiceReady(aspects, event)");
    assert.match(handler, /_rfedRunPending\(key\)/,
        "the service announce is our path-available event and must re-drive");
});

test("distro registration and pull both park on a failed link", () => {
    for (const sig of ["async _registerDistro()", "async _pullDistroMessages()"]) {
        const body = extractMethod(sig);
        assert.match(body, /_rfedDeferUntilAnnounce\(/,
            `${sig} must park its intent when the link failed, or one lost ` +
            `packet costs the feature for the whole session`);
        assert.match(body, /RFED_LINK_FAILED/,
            `${sig} must only park on an establishment failure, not on every error`);
    }
});

// ── Persistent rfed.link: re-open once when it closes under us ────────────
//
// The keepalive defect of 2026-09-29 had an app half: after an established
// rfed.link closed, nothing re-opened it and nothing pulled again, so every
// post rfed deferred for this subscriber waited for a page reload. The fix
// ports the app-links persistent model (app-links/src/lib.rs 414-497): a
// one-shot "reopen armed" flag, consumed when an established link closes
// under us and armed again by the next establishment and by explicit events;
// a re-open that fails is parked for the service's announce. Every new
// rfed.link identifies, re-binds, and then pulls. These run the real shipped
// method bodies over the real Link class, with only the wire handshake
// skipped; any app-level setTimeout/setInterval on these paths fails them.

import Link from "./lib/rns/link.js";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import { Buffer } from "node:buffer";

/** `const NAME = <expr>;` from app.js, evaluated over `env`. */
function extractConst(name, env = {}) {
    const match = new RegExp(`\\nconst ${name} = ([\\s\\S]*?);\\n`).exec(appSource);
    assert.ok(match, `${name} is missing from app.js`);
    const names = Object.keys(env);
    return new Function(...names, `return (${match[1]});`)(...names.map((n) => env[n]));
}

const LXMF_PROPAGATION_FORM_OVERHEAD = extractConst("LXMF_PROPAGATION_FORM_OVERHEAD");
const RFED_PUSH_REQUEST_ENVELOPE = extractConst("RFED_PUSH_REQUEST_ENVELOPE");
const APP_CONSTS = {
    RFED_LINK_PATHS: extractConst("RFED_LINK_PATHS"),
    RFED_PERSISTENT_KEYS: extractConst("RFED_PERSISTENT_KEYS"),
    RFED_LINK_IDLE: extractConst("RFED_LINK_IDLE"),
    RFED_LINK_ESTABLISHING: extractConst("RFED_LINK_ESTABLISHING"),
    RFED_LINK_ESTABLISHED: extractConst("RFED_LINK_ESTABLISHED"),
    RFED_LINK_FAILED: extractConst("RFED_LINK_FAILED"),
    RFED_PENDING_TIMEOUT_MS: extractConst("RFED_PENDING_TIMEOUT_MS"),
    RFED_LINK_MAX_REQUEST_SIZE: extractConst("RFED_LINK_MAX_REQUEST_SIZE",
        { LXMRouter, LXMF_PROPAGATION_FORM_OVERHEAD, RFED_PUSH_REQUEST_ENVELOPE }),
};

/** A real method body, `this.` read as `self.`, its free names from env. */
function compileMethod(signature, env) {
    const body = extractMethod(signature).replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
        .split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params,
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

const PERSISTENT_METHODS = [
    "_ensureRfedLink(aspects)", "_rfedPersistentBound(key)", "async _onRfedLinkEstablished(key, link)",
    "_onRfedLinkClosed(key, link)", "_redriveRfedLink(key, trigger)", "_rebindChannelStream()",
    "_pullOpenedChannels(trigger, generation = null)", "_rfedLinkKeyFor(aspects, path)", "_closeRefusedRfedLink(key, what)",
    "_rfedDeferUntilAnnounce(key, label, run)", "_rfedRunPending(key)", "_onPageResume(trigger)",
    "async pullChannel(channelName)", "async openChannel(channelName)", "_exchangeIsDown()",
    "_registerOwedDistro(trigger)",
];

/**
 * Let the link events and the promise chains after them run. Each listener
 * is a setTimeout 0 (utils/events.js), which Node runs no earlier than 1 ms
 * later, so every round waits for a timer queued after them.
 */
const settle = async (rounds = 4) => {
    for (let i = 0; i < rounds; i++) {
        await new Promise((r) => setTimeout(r, 0));
        await new Promise((r) => setImmediate(r));
    }
};

/**
 * A stub RnsClient carrying the real persistent-link bodies. Every link it
 * creates is a real Link whose establish() only records the attempt.
 * `channels` are subscribed channels; `opened` the ones opened this session.
 */
function makePersistent({ channels = ["general"], opened = channels, distro = false, held = true } = {}) {
    const links = [];
    class OfflineLink extends Link {
        constructor() { super(); links.push(this); }
        establish(destination) {
            this.initiator = true;
            this.status = Link.PENDING;
            this.destination = destination;
            this.hash = Buffer.alloc(16, links.length);
        }
        identify(identity) { (this.identified ??= []).push(identity); }
    }
    const log = { log: [], warn: [], error: [] };
    const console_ = {
        log: (...a) => log.log.push(a.join(" ")),
        warn: (...a) => log.warn.push(a.join(" ")),
        error: (...a) => log.error.push(a.join(" ")),
    };
    const channelRows = channels.map((name) => ({ channelName: name, channelHash: Buffer.from(name.padEnd(16, "_")).toString("hex"), isSubscribed: true }));
    const ChannelStore = {
        getAll: () => channelRows,
        get: (name) => channelRows.find((c) => c.channelName === name) ?? null,
    };
    const ActiveTab = { held };
    const DistroManager = { has: distro };
    const noTimers = () => assert.fail("no timer may be started on the persistent-link paths (DESIGN_PRINCIPLES §3)");
    const env = {
        ...APP_CONSTS, Link: OfflineLink, IdMgr: { id: { name: "me" } }, ActiveTab, DistroManager, ChannelStore,
        MsgPack, Buffer, Date, console: console_, setTimeout: noTimers, setInterval: noTimers,
    };
    const calls = [];
    // The connection's one exchange interface; a test takes it down.
    const exchange = { isDown: false };
    const self = {
        _rns: { interfaces: [exchange] },
        _cfg: { rfedNodeHash: "c".repeat(32) },
        _rfedLinks: new Map(),
        _rfedLinkPromises: new Map(),
        _rfedLinkState: new Map(),
        _rfedPending: new Map(),
        _rfedServiceReady: new Set(["link", "channel", "channel.stream", "channel.pull", "distro.register"]),
        _rfedReopenArmed: new Set(),
        _rfedLinkGeneration: 0,
        _distroRegistrationOwed: null,
        _rfedOpenedChannelHashes: new Set(channelRows.filter((c) => opened.includes(c.channelName)).map((c) => c.channelHash)),
        _rfedPullState: new Map(),
        _rfedStreamPromises: new Map(),
        _channelsInitialized: true,
        _propLink: null,
        _onMsg: [],
        _getRfedDest: (aspects) => ({ rns: { registerLink() {}, sendData: () => {} }, aspects }),
        _onRfedLinkPush: () => {},
        _handleChannelPacket: () => true,
        // What the new link sends, recorded; each answers at once unless a
        // test holds it.
        _configureChannelStream: async () => { calls.push("stream-open"); },
        _bindRfedLinkForDistroPush: async () => { calls.push("distro-bind"); },
        _rfedRequest: async (aspects, path) => { calls.push(`request ${aspects.join(".")}:${path}`); return [[], false]; },
        _pullDistroMessages: async () => { calls.push("distro-pull"); return []; },
        _fetchPropagatedMessages: () => { calls.push("prop-fetch"); },
        _redrivePropagationLink: () => { calls.push("prop-redrive"); },
    };
    for (const signature of PERSISTENT_METHODS) {
        self[signature.replace(/^async /, "").split("(")[0]] = compileMethod(signature, env)(self);
    }
    /** Complete the handshake of `link` (Link.validateProof's outcome). */
    const establish = async (link) => {
        link.status = Link.ACTIVE;
        link.emit("established");
        await settle();
    };
    /** Close `link` the way the watchdog (TIMEOUT) or the peer's LINKCLOSE (DESTINATION_CLOSED) does. */
    const closeUnder = async (link, reason) => {
        link.status = Link.CLOSED;
        link.closeReason = reason;
        link._linkClosed();
        await settle();
    };
    /** A connected client whose rfed.link is up. */
    const up = async () => {
        const pending = self._ensureRfedLink(["link"]);
        await establish(links.at(-1));
        await pending;
        return links.at(-1);
    };
    return { self, links, calls, log, env, exchange, ActiveTab, DistroManager, channelRows, establish, closeUnder, up };
}

test("an established rfed.link that closes under us re-opens exactly once", async () => {
    const c = makePersistent();
    const first = await c.up();
    assert.equal(c.self._rfedReopenArmed.has("link"), true, "armed by the establishment");

    await c.closeUnder(first, Link.TIMEOUT);
    assert.equal(c.links.length, 2, "one re-open, on the close event");
    assert.equal(c.links[1].status, Link.PENDING);
    assert.equal(c.self._rfedReopenArmed.has("link"), false, "the one-shot flag is consumed");
    assert.ok(c.log.error.some((l) => /timed out/.test(l)), "a TIMEOUT close is logged as an error, so the re-open does not hide it");

    // The re-open never establishes (a lost LINKREQUEST): nothing re-tries it.
    await c.closeUnder(c.links[1], Link.TIMEOUT);
    assert.equal(c.links.length, 2, "a failed re-open is not retried");
    assert.equal(c.self._rfedPending.get("link")?.label, "rfed.link re-open", "it is parked for the next rfed.link announce");

    // The announce re-drives it, once.
    c.self._rfedRunPending("link");
    await settle();
    assert.equal(c.links.length, 3);
    c.self._rfedRunPending("link");
    await settle();
    assert.equal(c.links.length, 3, "the parked intent is consumed");

    // That one establishes (armed again) and is closed by the node: one more.
    await c.establish(c.links[2]);
    await c.closeUnder(c.links[2], Link.DESTINATION_CLOSED);
    assert.equal(c.links.length, 4, "a LINKCLOSE from the node re-opens it once too");
    await c.closeUnder(c.links[3], Link.TIMEOUT);
    assert.equal(c.links.length, 4);
});

test("a close this client made never re-opens the link", async () => {
    const c = makePersistent();
    const link = await c.up();
    link.close(); // INITIATOR_CLOSED: disconnect(), or a refusal teardown
    await settle();
    assert.equal(link.closeReason, Link.INITIATOR_CLOSED);
    assert.equal(c.links.length, 1, "not re-opened");
    assert.equal(c.self._rfedReopenArmed.has("link"), false, "and disarmed until an explicit event");
});

test("a tab that lost the lock, or a disconnected client, re-opens nothing", async () => {
    // TabLock takeover: ActiveTab._takenOver runs disconnect(), which clears
    // _rfedLinks before the close events run, and the lock is gone.
    const taken = makePersistent();
    const link = await taken.up();
    taken.ActiveTab.held = false;
    await taken.closeUnder(link, Link.TIMEOUT);
    assert.equal(taken.links.length, 1, "another tab owns the identity: it must keep rfed's one binding");

    const stopped = makePersistent();
    const old = await stopped.up();
    stopped.self._rfedLinks.clear(); // disconnect()
    await stopped.closeUnder(old, Link.TIMEOUT);
    assert.equal(stopped.links.length, 1, "a link disconnect() dropped is not the current one");

    const gone = makePersistent();
    const last = await gone.up();
    gone.self._rns = null;
    await gone.closeUnder(last, Link.TIMEOUT);
    assert.equal(gone.links.length, 1);
});

test("a link nothing is bound to is not re-opened", async () => {
    const c = makePersistent({ opened: [], distro: false });
    const link = await c.up();
    await c.closeUnder(link, Link.TIMEOUT);
    assert.equal(c.links.length, 1, "no opened channel and no distro: nothing needs the link");
    const withDistro = makePersistent({ opened: [], distro: true });
    await withDistro.closeUnder(await withDistro.up(), Link.TIMEOUT);
    assert.equal(withDistro.links.length, 2, "a distro's push and pull ride on rfed.link");
});

test("an identify refusal on a pull does not loop: the next link waits for an explicit event", async () => {
    const c = makePersistent();
    c.self._rfedRequest = async (aspects, path) => { c.calls.push(`request ${path}`); return 0xF0; };
    const first = await c.up();
    // The new link's pull was refused: the link is torn down (Link.md
    // "Identify"), as the close this client makes.
    assert.ok(c.calls.includes("request /rfed/pull"), "the new link pulled");
    assert.equal(first.status, Link.CLOSED);
    assert.equal(first.closeReason, Link.INITIATOR_CLOSED);
    assert.equal(c.links.length, 1, "no establish, refuse, close loop");
    assert.equal(c.self._rfedReopenArmed.has("link"), false);

    // A new explicit event (the page becomes visible): exactly one new link,
    // whose own refusal again ends there.
    c.self._onPageResume("visible");
    await settle();
    assert.equal(c.links.length, 2, "one attempt for the event");
    await c.establish(c.links[1]);
    await settle();
    assert.equal(c.links[1].status, Link.CLOSED);
    assert.equal(c.links.length, 2, "and nothing after its refusal");
});

test("a new rfed.link re-sends the stream open, then pulls the opened channels and the distro", async () => {
    const c = makePersistent({ channels: ["alpha", "beta", "gamma"], opened: ["alpha", "beta"], distro: true });
    const gates = [];
    const held = (name) => async () => { c.calls.push(name); await new Promise((resolve) => gates.push(resolve)); };
    c.self._configureChannelStream = held("stream-open");
    c.self._bindRfedLinkForDistroPush = held("distro-bind");
    c.self.pullChannel = async (name) => { c.calls.push(`pull #${name}`); return false; };

    const first = await c.up();
    assert.deepEqual(first.identified, [{ name: "me" }], "identified first");
    assert.deepEqual(c.calls, ["distro-bind", "stream-open"],
        "both bindings, one /channel/stream/open for the whole filter set, and no pull before they are answered");
    gates.splice(0).forEach((open) => open());
    await settle();
    assert.deepEqual(c.calls.slice(2), ["pull #alpha", "pull #beta", "distro-pull"],
        "then every opened channel (not gamma, which was never opened) and the distro");
    assert.equal(c.self._rfedLinkGeneration, 1);

    // The link dies and is re-opened: the node dropped the bindings with it.
    c.calls.length = 0;
    await c.closeUnder(first, Link.TIMEOUT);
    await c.establish(c.links[1]);
    assert.deepEqual(c.calls, ["distro-bind", "stream-open"], "re-bound on the new link (Link.md: the client re-binds on every link)");
    // openChannel pulled alpha on this new link while the bindings were
    // answered: once per generation, so the link does not pull it again.
    c.self._rfedPullState.set(c.channelRows[0].channelHash, { inFlight: false, morePending: false, gen: 2 });
    gates.splice(0).forEach((open) => open());
    await settle();
    assert.deepEqual(c.calls.slice(2), ["pull #beta", "distro-pull"], "and pulled again, each channel once per link");
    assert.equal(c.self._rfedLinkGeneration, 2);
});

test("a new link that closes while its bindings are answered pulls nothing; the next one does", async () => {
    const c = makePersistent({ distro: true });
    let release;
    c.self._configureChannelStream = async () => { c.calls.push("stream-open"); await new Promise((r) => { release = r; }); };
    const first = await c.up();
    await c.closeUnder(first, Link.TIMEOUT);
    release();
    await settle();
    assert.equal(c.calls.filter((x) => x.startsWith("request") || x === "distro-pull").length, 0,
        "the pulls belong to the link that is up");
    // The re-opened link establishes: its own bindings, then its pulls.
    await c.establish(c.links[1]);
    release();
    await settle();
    assert.deepEqual(c.calls.filter((x) => x.startsWith("request") || x === "distro-pull"),
        ["request channel.pull:/rfed/pull", "distro-pull"]);
});

test("every explicit open pulls one page; a new rfed.link pulls each opened channel once more", async () => {
    // Android and iOS pull when the channel screen opens (their per-screen
    // generation guard starts empty on each open) and once per new rfed
    // link while it is open (ConversationScreen.kt:603-615,
    // ConversationView.swift:596-612).
    const c = makePersistent({ channels: ["general"], opened: [] });
    const pulls = [];
    c.self._ensureChannelSubscribed = async () => {};
    c.self._ensureChannelStreamConfigured = async () => {};
    c.self.pullChannel = async (name) => { pulls.push(name); };
    const hash = c.channelRows[0].channelHash;
    c.self._rfedLinkGeneration = 1;
    c.self._rfedPullState.set(hash, { inFlight: false, morePending: false, gen: 1 });
    await c.self.openChannel("general");
    await c.self.openChannel("general");
    assert.deepEqual(pulls, ["general", "general"], "one page on each open, though this link pulled it already");

    pulls.length = 0;
    c.self._rfedOpenedChannelHashes.add(hash);
    c.self._pullOpenedChannels("new rfed.link", 1);
    assert.deepEqual(pulls, [], "a link that has pulled it (an open got there first) does not pull it again");
    c.self._pullOpenedChannels("new rfed.link", 2);
    assert.deepEqual(pulls, ["general"], "a new link pulls it once");
});

test("a channel pull is one at a time and one page: more_pending is recorded for \"Load more messages\", never followed", async () => {
    // Channel.md /rfed/pull: the client shows a "load more" control while
    // more_pending is true; Android and iOS page channel history by hand.
    // Until 2026-09-30 the web followed more_pending on its own and drained
    // the whole deferred queue.
    const c = makePersistent({ channels: ["general"] });
    c.self.channelPullState = compileMethod("channelPullState(channelName)", c.env)(c.self);
    const [row] = c.channelRows;
    const channelHash = Buffer.from(row.channelHash, "hex");
    const page = (n) => [[channelHash, Buffer.from(`post-${n}`)]];
    const answers = [[page(1), true], [page(2), false]];
    let release;
    c.self._rfedRequest = async (aspects, path) => {
        c.calls.push(`request ${path}`);
        if (!release) await new Promise((r) => { release = r; });
        return answers.shift();
    };
    const handled = [];
    c.self._handleChannelPacket = (data) => { handled.push(Buffer.from(data).subarray(16).toString()); return true; };
    const events = [];
    c.self._onMsg.push((ev, name) => events.push(`${ev.kind} ${name}`));
    c.self._rfedLinkGeneration = 3;
    assert.deepEqual(c.self.channelPullState("general"), { inFlight: false, morePending: false }, "nothing known before a pull");

    const first = c.self.pullChannel("general");
    const second = c.self.pullChannel("general");
    assert.deepEqual(c.self.channelPullState("general"), { inFlight: true, morePending: false });
    await settle();
    assert.equal(c.calls.length, 1, "a pull while one is in flight sends nothing");
    release();
    assert.equal(await first, true, "the node holds more");
    await second;
    await settle();
    assert.equal(c.calls.length, 1, "and nothing pulls it on its own: the next page is the user's");
    assert.deepEqual(handled, ["post-1"]);
    assert.deepEqual(c.self.channelPullState("general"), { inFlight: false, morePending: true }, "what the control shows");
    assert.equal(c.self._rfedPullState.get(row.channelHash).gen, 3, "the generation it was pulled on");
    assert.deepEqual(events, ["channel-pull-start general", "channel-pull-complete general"]);

    // "Load more messages": the next page, which is the last.
    assert.equal(await c.self.pullChannel("general"), false);
    await settle();
    assert.equal(c.calls.length, 2);
    assert.deepEqual(handled, ["post-1", "post-2"]);
    assert.deepEqual(c.self.channelPullState("general"), { inFlight: false, morePending: false });

    // A pull that fails leaves what the last completed one said.
    c.self._rfedPullState.set(row.channelHash, { inFlight: false, morePending: true, gen: 3 });
    c.self._rfedRequest = async () => { throw new Error("/channel/pull: the link closed before a response"); };
    await assert.rejects(c.self.pullChannel("general"));
    assert.deepEqual(c.self.channelPullState("general"), { inFlight: false, morePending: true });
});

test("rfed.link refuses a push larger than a message at LXMF's delivery limit, and takes one that size", async () => {
    // The arithmetic of RFED_LINK_MAX_REQUEST_SIZE, rebuilt from real bytes:
    // a packed LXMF of exactly LXMF's delivery limit, in the propagation form
    // rfed pushes (dest | Identity.encrypt(rest)), inside the request rfed
    // builds (rmpv: fixarray, f64 timestamp, bin(16) path hash, bin(data)).
    const limit = LXMRouter.DELIVERY_LIMIT * 1000;
    assert.equal(limit, 1_000_000);
    const recipient = Identity.create();
    const packed = Buffer.alloc(limit, 7);
    const blob = Buffer.concat([packed.subarray(0, 16), recipient.encrypt(packed.subarray(16))]);
    assert.equal((limit - 16) % 16, 0, "a whole number of blocks: PKCS7 adds a full block, the most it adds");
    assert.equal(blob.length, limit + LXMF_PROPAGATION_FORM_OVERHEAD, "32 key + 16 IV + 32 HMAC + 16 padding");
    const f64 = Buffer.alloc(9); f64[0] = 0xcb; f64.writeDoubleBE(Date.now() / 1000, 1);
    const bin32 = Buffer.alloc(5); bin32[0] = 0xc6; bin32.writeUInt32BE(blob.length, 1);
    const request = Buffer.concat([Buffer.from([0x93]), f64, Buffer.from([0xc4, 16]), Buffer.alloc(16, 1), bin32, blob]);
    assert.equal(request.length, APP_CONSTS.RFED_LINK_MAX_REQUEST_SIZE, "the largest legitimate push, to the byte");
    assert.equal(APP_CONSTS.RFED_LINK_MAX_REQUEST_SIZE, 1_000_129);

    // Every rfed.link carries it from before its first packet; other links
    // keep the reference default (no limit), as they take no requests.
    const c = makePersistent();
    c.self._ensureRfedLink(["link"]);
    assert.equal(c.links[0].maxRequestSize, 1_000_129);
    c.self._ensureRfedLink(["channel"]);
    assert.equal(c.links[1].maxRequestSize, null);
});

test("an exchange outage that times out rfed.link: nothing starts while it is down, and its return re-opens the link once and pulls", async () => {
    // Review of 2026-09-30: the re-open after the TIMEOUT went out while the
    // exchange was down, its LINKREQUEST was lost (PostInterface.sendData),
    // and the failed attempt was parked for an rfed.link announce that comes
    // every 6 h, while the intent expires in 45 min. A visible, idle tab
    // then got no live channel or distro pushes until the user did something.
    const c = makePersistent({ distro: true });
    // The exchange as PostInterface presents it: isDown, and "up"/"down" events.
    const iface = new EventTarget();
    iface.on = (type, fn) => iface.addEventListener(type, () => fn());
    c.self._rns.interfaces = [iface];
    const exchange = (up) => {
        iface.isDown = !up;
        iface.dispatchEvent(new Event(up ? "up" : "down"));
    };
    Object.assign(c.self, { _setStatus() {}, _onExchangeRegistered() {}, _onPacketsLost() {} });
    compileMethod("_followExchange(iface)", c.env)(c.self)(iface);
    exchange(true); // the connection's first "up"

    const first = await c.up();
    c.calls.length = 0;
    exchange(false);
    c.self._onPageResume("visible"); // the link is still up, the exchange is not
    await settle();
    assert.deepEqual(c.calls, [], "no pull whose request the down exchange would lose");
    await c.closeUnder(first, Link.TIMEOUT); // the keepalive watchdog
    assert.equal(c.links.length, 1, "no LINKREQUEST into a down exchange: it would be lost, and the doomed attempt would swallow the exchange's return");
    assert.equal(c.self._rfedPending.has("link"), false, "and nothing parked for an announce hours away");
    assert.ok(c.log.log.some((l) => /so is the exchange/.test(l)), "it says why");

    // The page comes online first; the exchange is still down (its own check() decides).
    c.self._onPageResume("online");
    await settle();
    assert.equal(c.links.length, 1, "still nothing while it is down");

    exchange(true); // the exchange is back
    await settle();
    assert.equal(c.links.length, 2, "one re-open on the exchange's return");
    exchange(true);
    await settle();
    assert.equal(c.links.length, 2, "an up with no down before it is not a return");
    await c.establish(c.links[1]);
    assert.deepEqual(c.calls.filter((x) => !x.startsWith("prop-")),
        ["distro-bind", "stream-open", "request channel.pull:/rfed/pull", "distro-pull"],
        "the new link re-binds, then pulls what the node deferred during the outage");
    assert.equal(c.self._rfedReopenArmed.has("link"), true, "and is armed for its own next close");
});

test("a late close of an attempt disconnect() dropped leaves the newer attempt, its state and its bindings alone", async () => {
    // disconnect() clears _rfedLinks and _rfedLinkPromises but closes only
    // the links in _rfedLinks: one still establishing fails later, on its
    // own establishment timeout, possibly after reconnect() started the next.
    const disconnect = (c) => { c.self._rfedLinks.clear(); c.self._rfedLinkPromises.clear(); c.self._rfedStreamPromises.clear(); };

    const c = makePersistent();
    c.self._ensureRfedLink(["link"]).catch(() => {});
    disconnect(c);
    const next = c.self._ensureRfedLink(["link"]);
    await c.closeUnder(c.links[0], Link.TIMEOUT); // the dropped attempt times out
    assert.equal(c.self._rfedLinkPromises.get("link"), next, "the newer attempt is still the one in flight");
    assert.equal(c.self._rfedLinkState.get("link"), APP_CONSTS.RFED_LINK_ESTABLISHING, "and its state is its own");
    assert.equal(c.self._redriveRfedLink("link", "online"), false, "so an event starts no second link beside it");
    assert.equal(c.links.length, 2);
    await c.establish(c.links[1]);
    assert.equal(await next, c.links[1]);

    // The newer link is up and bound when the dropped one times out.
    const b = makePersistent();
    b.self._ensureRfedLink(["link"]).catch(() => {});
    disconnect(b);
    const live = await b.up();
    const channelHash = b.channelRows[0].channelHash;
    assert.ok(b.self._rfedStreamPromises.has(channelHash), "the live link bound the opened channel");
    await b.closeUnder(b.links[0], Link.TIMEOUT);
    assert.equal(b.self._rfedLinks.get("link"), live);
    assert.equal(b.self._rfedLinkState.get("link"), APP_CONSTS.RFED_LINK_ESTABLISHED);
    assert.ok(b.self._rfedStreamPromises.has(channelHash),
        "its binding memo is kept: dropping it would re-send /channel/stream/open on a link that holds the binding");
    assert.equal(b.links.length, 2, "and nothing re-opens");
});

test("a distro pull that fails on a dead rfed.link parks the link's re-open, and the link that brings back pulls the distro", async () => {
    const c = makePersistent({ opened: [], distro: true });
    Object.assign(c.self, { _distroPullInFlight: null, _handleDistroBlob: () => true });
    // The mapped /distro/pull travels on rfed.link (RFED_LINK_PATHS).
    c.self._rfedRequest = async (aspects, path) => {
        await c.self._ensureRfedLink(["link"]);
        c.calls.push(`request ${aspects.join(".")}:${path}`);
        return [[], false];
    };
    c.self._pullDistroMessages = compileMethod("async _pullDistroMessages()", c.env)(c.self);

    const pull = c.self._pullDistroMessages();
    assert.equal(c.links.length, 1);
    await c.closeUnder(c.links[0], Link.TIMEOUT); // the LINKREQUEST or its proof was lost
    assert.deepEqual(await pull, []);
    assert.equal(c.self._rfedLinkState.get("link"), APP_CONSTS.RFED_LINK_FAILED);
    assert.equal(c.self._rfedPending.get("link")?.label, "rfed.link re-open",
        "the link's re-open is parked, whose \"established\" pulls the distro");
    assert.equal(c.self._rfedPending.has("distro.register"), false, "not a pull parked under a key no mapped pull fails on");

    c.self._rfedRunPending("link"); // the rfed.link announce
    await settle();
    assert.equal(c.links.length, 2, "one attempt");
    await c.establish(c.links[1]);
    assert.deepEqual(c.calls.filter((x) => x.startsWith("request")), ["request distro.register:/rfed/pull"],
        "the new link pulls the distro");
});

// ── The distro registration rides on rfed.link ────────────────────────────
//
// /rfed/distro/register is a mapped path: it travels on rfed.link, whose
// state is keyed "link". Until 2026-09-30 _registerDistro parked itself only
// when "distro.register" had FAILED, a state no mapped request sets, so a
// registration that failed on a dead rfed.link was lost for the session.
// Now the link's re-open is parked (the one intent per key the pull and the
// persistent link park too), and a registration not yet answered yes is
// owed: every new rfed.link sends it once, until one is answered yes (iOS
// and Android re-register on their register link's next ACTIVE edge).

const DISTRO_A = "a1".repeat(16);
const DISTRO_B = "b2".repeat(16);

/**
 * The real _registerDistro on a makePersistent client holding a distro.
 * Each /rfed/distro/register travels on rfed.link (opening it if need be)
 * and is answered from `answers`: true, false (a refusal), or "lost" (the
 * link closes under it, as the keepalive watchdog closes it).
 */
function withRegistration(c, { hash = DISTRO_A } = {}) {
    Object.assign(c.DistroManager, {
        has: true, hash,
        identity: { getPublicKey: () => Buffer.alloc(64, 1), sign: () => Buffer.alloc(64, 2) },
    });
    c.env.IdMgr.id.getPublicKey = () => Buffer.alloc(64, 3);
    const answers = [];
    const gates = [];
    c.self._registerDistroInFlight = null;
    c.self._rfedRequest = async (aspects, path) => {
        const link = await c.self._ensureRfedLink(["link"]);
        const on = c.links.indexOf(link);
        if (path !== "/rfed/distro/register") { c.calls.push(`request ${path} on ${on}`); return [[], false]; }
        c.calls.push(`register ${c.DistroManager.hash.slice(0, 2)} on ${on}`);
        if (gates.length) await gates.shift();
        const answer = answers.shift();
        if (answer === "lost") {
            await c.closeUnder(link, Link.TIMEOUT);
            throw new Error(`${path}: the link closed before a response`);
        }
        return answer;
    };
    c.self._publishDistroAnnounce = async () => { c.calls.push("distro-announce"); return true; };
    c.self._registerDistro = compileMethod("async _registerDistro()", c.env)(c.self);
    return { answers, gates, registers: () => c.calls.filter((x) => x.startsWith("register")) };
}

test("a distro registration that fails on a dead rfed.link parks the link's re-open, and every new rfed.link sends it once until it is answered yes", async () => {
    const c = makePersistent({ opened: [], distro: true });
    const r = withRegistration(c);

    // Startup: the registration opens rfed.link, whose LINKREQUEST is lost.
    const first = c.self._registerDistro();
    assert.equal(c.links.length, 1);
    await c.closeUnder(c.links[0], Link.TIMEOUT);
    assert.equal(await first, false);
    assert.equal(c.self._rfedLinkState.get("link"), APP_CONSTS.RFED_LINK_FAILED);
    assert.equal(c.self._rfedPending.get("link")?.label, "rfed.link re-open",
        "the link the request travels on is parked for its announce");
    assert.equal(c.self._rfedPending.has("distro.register"), false, "not a key no mapped request fails on");
    assert.equal(c.self._distroRegistrationOwed, DISTRO_A, "and the registration is owed");
    assert.deepEqual(r.registers(), [], "nothing was sent");

    // The rfed.link announce brings the link back; the node refuses.
    r.answers.push(false);
    c.self._rfedRunPending("link");
    await settle();
    assert.equal(c.links.length, 2, "one attempt");
    await c.establish(c.links[1]);
    assert.deepEqual(r.registers(), ["register a1 on 1"], "the new link sends the owed registration, once");
    assert.equal(c.self._distroRegistrationOwed, DISTRO_A, "a refusal leaves it owed: never sent again at once (§3)");

    // The node closes that link: re-opened once; the request is lost with it.
    r.answers.push("lost");
    await c.closeUnder(c.links[1], Link.DESTINATION_CLOSED);
    assert.equal(c.links.length, 3);
    await c.establish(c.links[2]);
    await settle();
    assert.deepEqual(r.registers(), ["register a1 on 1", "register a1 on 2"]);
    assert.equal(c.links.length, 4, "the link it was lost with was re-opened once");
    assert.equal(c.self._distroRegistrationOwed, DISTRO_A);

    // The next link: answered yes, before anything is pulled.
    r.answers.push(true);
    c.calls.length = 0;
    await c.establish(c.links[3]);
    assert.deepEqual(r.registers(), ["register a1 on 3"]);
    const at = (x) => c.calls.indexOf(x);
    assert.ok(at("register a1 on 3") < at("distro-announce") && at("distro-announce") < at("distro-pull"),
        `registered, then the pre-signed announce, and only then the distro pull: ${c.calls}`);
    assert.equal(c.self._distroRegistrationOwed, null, "answered yes: nothing owed");

    // Every later link: nothing to register.
    c.calls.length = 0;
    await c.closeUnder(c.links[3], Link.TIMEOUT);
    await c.establish(c.links[4]);
    assert.deepEqual(r.registers(), [], "registered once is registered");
    assert.ok(c.calls.includes("distro-pull"), "the new link still pulls");
});

test("a registration for another distro, asked for while one is in flight, goes after it; a forgotten distro owes nothing", async () => {
    const c = makePersistent({ opened: [], distro: true });
    const r = withRegistration(c, { hash: DISTRO_A });
    await c.up();
    c.calls.length = 0;
    let release;
    r.gates.push(new Promise((resolve) => { release = resolve; }));
    r.answers.push(true, true);
    const a = c.self._registerDistro();
    await settle();
    c.DistroManager.hash = DISTRO_B; // imported while A's registration is in flight
    const b = c.self._registerDistro();
    const b2 = c.self._registerDistro(); // a second caller for B
    await settle();
    assert.deepEqual(r.registers(), ["register a1 on 0"], "never two registrations at once on one link");
    r.answers.length = 0;
    r.answers.push(true, false); // A is answered yes, B is refused
    release();
    assert.equal(await a, true);
    await settle();
    assert.equal(await b, false, "B's caller is answered by B's own registration, not told A's yes");
    assert.equal(await b2, false);
    assert.deepEqual(r.registers(), ["register a1 on 0", "register b2 on 0"], "B goes once A is answered, once for both callers");
    assert.equal(c.self._distroRegistrationOwed, DISTRO_B, "refused: B is still owed");

    // Owed for a distro that is then forgotten: the next link sends nothing.
    c.DistroManager.has = false;
    c.calls.length = 0;
    await c.closeUnder(c.links[0], Link.TIMEOUT);
    assert.equal(c.links.length, 1, "nothing is bound to the link any more");
    c.DistroManager.has = true;
    c.DistroManager.hash = DISTRO_A; // another distro, never asked for
    c.self._redriveRfedLink("link", "visible");
    await settle();
    await c.establish(c.links[1]);
    assert.deepEqual(r.registers(), [], "nothing of the forgotten distro is owed");
    assert.equal(c.self._distroRegistrationOwed, null);
});

// ── A reconnect: each connection registers for itself ─────────────────────
//
// reconnect() is disconnect() + connect() (Settings > Save; a tab that took
// over and gave the identity back). Review of 2026-09-30: disconnect() left
// the stopped connection's registration in flight, so the next connection's
// own (_onExchangeRegistered) joined it and was never sent. The stopped one
// waited on an rfed.link attempt of the stopped interface (disconnect()
// closes only established links, and a stopped PostInterface reports
// nothing lost), failed on that attempt's own timeout, and nothing was owed
// any more: no later rfed.link of the new connection registered.

/** The real disconnect() over a makePersistent client. */
function disconnectFor(c) {
    Object.assign(c.self, {
        _annTimer: null, _unhookPageLifecycle() {}, _pendingTickets: new Map(), _pendingPacketHashes: new Map(),
        _pendingTimeouts: new Map(), _rfedServiceWaiters: new Map(), _rfedStampRefreshed: new Set(),
        _rfedSubscriptionPromises: new Map(), _rfedPendingEchoes: new Map(), _groupLinks: new Map(),
        _groupLinkPromises: new Map(), _groupPeerReady: new Set(), _groupPeerWaiters: new Map(),
        _groupPathsRequested: new Set(), _groupFallbacks: new Map(), _propLinkUpWaiters: [], _setStatus() {},
    });
    return compileMethod("disconnect()", { ...c.env, clearInterval() {}, clearTimeout() {} })(c.self);
}

/** connect() as far as these paths read it: a new exchange, the rfed.link announce heard. */
function connectAgain(c) {
    c.self._rns = { interfaces: [{ isDown: false }] };
    c.self._rfedServiceReady.add("link");
}

test("a reconnect while the registration waits for its rfed.link: the new connection sends its own, once", async () => {
    const c = makePersistent({ opened: [], distro: true });
    const r = withRegistration(c);
    // Startup: the registration opens rfed.link, which is still coming up.
    const old = c.self._registerDistro();
    await settle();
    assert.equal(c.links.length, 1);
    assert.equal(c.links[0].status, Link.PENDING);

    disconnectFor(c)();
    connectAgain(c);
    r.answers.push(true);
    const fresh = c.self._registerDistro(); // _onExchangeRegistered
    assert.notEqual(fresh, old, "not joined to the stopped connection's registration");
    assert.equal(c.self._distroRegistrationOwed, DISTRO_A, "owed by the new connection until it is answered yes");
    await settle();
    assert.equal(c.links.length, 2, "on the new connection's own rfed.link");
    await c.establish(c.links[1]);
    assert.equal(await fresh, true);
    assert.deepEqual(r.registers(), ["register a1 on 1"]);
    assert.equal(c.self._distroRegistrationOwed, null);

    // The stopped connection's attempt fails on its own timeout.
    await c.closeUnder(c.links[0], Link.TIMEOUT);
    assert.equal(await old, false);
    assert.equal(c.self._rfedLinks.get("link"), c.links[1], "the new connection's link is untouched");
    assert.equal(c.self._rfedPending.has("link"), false, "and nothing is parked for it");
    assert.deepEqual(r.registers(), ["register a1 on 1"], "registered once");
});

test("a stopped connection's registration that ends after the reconnect touches nothing of the new one", async () => {
    // Answered yes after disconnect(): no push binding and no distro
    // announce on the new connection, which has not registered yet.
    const c = makePersistent({ opened: [], distro: true });
    const r = withRegistration(c);
    await c.up();
    c.calls.length = 0;
    let release;
    r.gates.push(new Promise((resolve) => { release = resolve; }));
    r.answers.push(true);
    const old = c.self._registerDistro();
    await settle();
    assert.deepEqual(r.registers(), ["register a1 on 0"]);
    disconnectFor(c)();
    connectAgain(c);
    await settle();
    c.calls.length = 0;
    release();
    assert.equal(await old, true, "its caller is told what the node answered");
    await settle();
    assert.deepEqual(c.calls, [], "and the new connection is left to register, bind and announce for itself");
    assert.equal(c.self._registerDistroInFlight, null);

    // A caller for another distro, joined to a registration of the stopped
    // connection: answered false, and nothing is sent for it on the new one.
    const d = makePersistent({ opened: [], distro: true });
    const s = withRegistration(d);
    await d.up();
    let releaseA;
    s.gates.push(new Promise((resolve) => { releaseA = resolve; }));
    s.answers.push(true);
    const a = d.self._registerDistro();
    await settle();
    d.DistroManager.hash = DISTRO_B;
    let b = "unanswered";
    d.self._registerDistro().then((answer) => { b = answer; });
    disconnectFor(d)();
    connectAgain(d);
    releaseA();
    assert.equal(await a, true);
    await settle();
    assert.equal(b, false, "the connection it was asked on is gone");
    assert.equal(d.links.length, 1, "no rfed.link is opened for it on the new connection");
    assert.deepEqual(s.registers(), ["register a1 on 0"], "B is the new connection's to register (_onExchangeRegistered)");
    assert.equal(d.self._registerDistroInFlight, null);

    // Failed after the reconnect: what it parks is decided by the stopped
    // connection's link, not by the new connection's rfed.link state.
    const e = makePersistent({ opened: [], distro: true });
    withRegistration(e);
    const stale = e.self._registerDistro();
    await settle();
    disconnectFor(e)();
    connectAgain(e);
    e.self._ensureRfedLink(["link"]).catch(() => {}); // the new connection's first attempt (a channel send's)
    await e.closeUnder(e.links[1], Link.TIMEOUT);       // fails, and its caller fails in front of the user
    assert.equal(e.self._rfedLinkState.get("link"), APP_CONSTS.RFED_LINK_FAILED);
    await e.closeUnder(e.links[0], Link.TIMEOUT);       // the stopped connection's attempt times out
    assert.equal(await stale, false);
    assert.equal(e.self._rfedPending.has("link"), false, "the stopped connection's registration parks nothing on the new one");
    assert.equal(e.self._distroRegistrationOwed, null, "and owes nothing on it");
});

test("the persistent-link paths schedule nothing", () => {
    for (const signature of PERSISTENT_METHODS.concat(["_hookPageLifecycle()", "_unhookPageLifecycle()", "async _pullDistroMessages()", "_followExchange(iface)"])) {
        assert.doesNotMatch(extractMethod(signature), /setTimeout|setInterval/,
            `${signature}: a re-open or a pull follows an event, never a clock (DESIGN_PRINCIPLES §3)`);
    }
});
