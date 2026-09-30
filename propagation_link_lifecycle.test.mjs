/**
 * REGRESSION GUARD — the propagation link is persistent without a retry loop.
 *
 * Until 2026-09-30 every close of the propagation link started
 * _retryPropagationLink: a setTimeout loop that doubled from 4 s to 30 s and
 * never gave up, an application-level link retry (DESIGN_PRINCIPLES §3); the
 * 09-29 stage_android log shows it re-linking an idle link the keepalive
 * defect had killed. And once the link was up, identify, the /get fetch and
 * the distro pull ran on fixed 1 s, 5 s and 7 s timers "to let the link
 * settle" (§5: an order on a clock, not on events).
 *
 * Now it follows the app-links persistent model, as rfed.link does
 * (app-links/src/lib.rs 414-497; iOS AppLinks::open_persistent): a link that
 * had been established and closes under us (TIMEOUT, DESTINATION_CLOSED) is
 * re-opened once, the flag armed again by the next establishment and by
 * explicit events; an attempt that fails waits for the next event — the
 * node's lxmf.propagation announce (_initPropagation), the page coming back,
 * or an upload that needs the link. After establishment: identify, then
 * /get, then /distro/pull, each on the one before.
 *
 * These run the real shipped method bodies from app.js over the real Link
 * class (only the wire handshake skipped). Any app-level timer on these
 * paths fails them.
 *
 * Run: node --test propagation_link_lifecycle.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import Link from "./lib/rns/link.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

function extractMethod(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const open = app.indexOf("{", start + signature.length);
    let depth = 0;
    for (let i = open; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}" && --depth === 0) return app.slice(open + 1, i);
    }
    throw new Error(`could not brace-match ${signature}`);
}

function compile(signature, env) {
    const body = extractMethod(signature).replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
        .split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params,
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

const LIFECYCLE = [
    "_establishPropagationLink()", "_ensurePropagationLink()", "async _onPropagationLinkEstablished(link)",
    "_onPropagationLinkClosed(link, established)", "_redrivePropagationLink(trigger)", "_initPropagation()",
    "_exchangeIsDown()",
];

/** Link events are a setTimeout 0 per listener (Node: ≥ 1 ms); wait past them and their promise chains. */
const settle = async (rounds = 4) => {
    for (let i = 0; i < rounds; i++) {
        await new Promise((r) => setTimeout(r, 0));
        await new Promise((r) => setImmediate(r));
    }
};

function makeClient({ distro = true } = {}) {
    const links = [];
    const order = [];
    class OfflineLink extends Link {
        constructor() { super(); links.push(this); }
        establish(destination) { this.initiator = true; this.status = Link.PENDING; this.destination = destination; }
        identify() { order.push("identify"); }
    }
    const node = Identity.create();
    const ActiveTab = { held: true };
    const noTimers = () => assert.fail("no timer may be started on the propagation link's lifecycle (DESIGN_PRINCIPLES §3, §5)");
    const env = {
        Link: OfflineLink, Identity, Buffer, Destination, IdMgr: { id: {} }, DistroManager: { has: distro }, ActiveTab,
        RnsClient: {}, console: { log() {}, warn() {}, error() {} }, setTimeout: noTimers, setInterval: noTimers,
    };
    let fetched;
    // The connection's one exchange interface; a test takes it down.
    const exchange = { isDown: false };
    const self = {
        _rns: { interfaces: [exchange], registerDestination: () => ({ rns: { registerLink() {}, sendData() {} } }) },
        _cfg: { propagationNodePubKey: node.getPublicKey().toString("hex"), propagationNodeHash: "b".repeat(32) },
        _propLink: null, _propLinkPromise: null, _propLinkUpWaiters: [], _propagationInitialized: false, _propReopenArmed: false,
        _flushPropagation: () => { order.push("flush"); },
        // /get takes its time: the distro pull must wait for it, not for a clock.
        _fetchPropagatedMessages: () => { order.push("fetch"); return new Promise((resolve) => { fetched = resolve; }); },
        _pullDistroMessages: async () => { order.push("distro pull"); return []; },
    };
    for (const signature of LIFECYCLE) self[signature.replace(/^async /, "").split("(")[0]] = compile(signature, env)(self);
    const establish = async (link) => { link.status = Link.ACTIVE; link.emit("established"); await settle(); };
    const closeUnder = async (link, reason) => { link.status = Link.CLOSED; link.closeReason = reason; link._linkClosed(); await settle(); };
    return { self, links, order, exchange, ActiveTab, establish, closeUnder, finishFetch: () => fetched?.() };
}

test("no backoff loop remains", () => {
    assert.doesNotMatch(app, /_retryPropagationLink/, "the retry loop is gone");
    assert.doesNotMatch(app, /_propRetryTimer/, "and its timer");
    for (const signature of LIFECYCLE) {
        assert.doesNotMatch(extractMethod(signature), /setTimeout|setInterval/, `${signature}: events, never a clock`);
    }
});

test("after establishment: identify, then /get, then /distro/pull, each on the one before", async () => {
    const c = makeClient();
    c.self._initPropagation(); // the node's lxmf.propagation announce
    assert.equal(c.links.length, 1);
    await c.establish(c.links[0]);
    assert.deepEqual(c.order, ["identify", "flush", "fetch"], "identify first; the fetch follows it on the same link");
    await settle();
    assert.deepEqual(c.order, ["identify", "flush", "fetch"], "the distro pull waits for the fetch to conclude");
    c.finishFetch();
    await settle();
    assert.deepEqual(c.order, ["identify", "flush", "fetch", "distro pull"]);

    const none = makeClient({ distro: false });
    none.self._initPropagation();
    await none.establish(none.links[0]);
    none.finishFetch();
    await settle();
    assert.deepEqual(none.order, ["identify", "flush", "fetch"], "no distro, no distro pull");
});

test("an established propagation link that closes under us re-opens exactly once; a failed attempt waits for an event", async () => {
    const c = makeClient();
    c.self._initPropagation();
    await c.establish(c.links[0]);
    assert.equal(c.self._propReopenArmed, true, "armed by the establishment");

    await c.closeUnder(c.links[0], Link.TIMEOUT);
    assert.equal(c.links.length, 2, "one re-open, on the close event");
    assert.equal(c.self._propReopenArmed, false, "the one-shot flag is consumed");

    // The re-open never establishes: nothing re-tries it, on a timer or otherwise.
    await c.closeUnder(c.links[1], Link.TIMEOUT);
    assert.equal(c.links.length, 2, "a failed attempt is not retried");
    assert.equal(c.self._propLink, null);

    // The node's next announce re-drives it, once.
    c.self._initPropagation();
    assert.equal(c.links.length, 3);
    c.self._initPropagation();
    assert.equal(c.links.length, 3, "not while that attempt is in flight");

    // Established again, then closed by the node (LINKCLOSE): re-opened once.
    await c.establish(c.links[2]);
    await c.closeUnder(c.links[2], Link.DESTINATION_CLOSED);
    assert.equal(c.links.length, 4);
});

test("a propagation link closed by this client, or in a tab without the lock, is not re-opened", async () => {
    const ours = makeClient();
    ours.self._initPropagation();
    await ours.establish(ours.links[0]);
    await ours.closeUnder(ours.links[0], Link.INITIATOR_CLOSED);
    assert.equal(ours.links.length, 1);

    const taken = makeClient();
    taken.self._initPropagation();
    await taken.establish(taken.links[0]);
    taken.ActiveTab.held = false;
    await taken.closeUnder(taken.links[0], Link.TIMEOUT);
    assert.equal(taken.links.length, 1, "another tab owns the identity");
    taken.self._initPropagation();
    assert.equal(taken.links.length, 1, "and an announce does not start one either");
});

test("a STALE propagation link is left to its keepalive watchdog by the announce", async () => {
    const c = makeClient();
    c.self._initPropagation();
    await c.establish(c.links[0]);
    c.links[0].status = Link.STALE;
    c.self._initPropagation();
    assert.equal(c.links.length, 1, "it either recovers or times out, and a TIMEOUT re-opens it");
});

test("while the exchange is down the propagation link is not re-opened; the exchange's return re-drives it once", async () => {
    // The re-open after a TIMEOUT caused by an exchange outage would send its
    // LINKREQUEST into the down exchange (PostInterface.sendData loses it),
    // and the doomed attempt, in flight for its establishment timeout,
    // would swallow the exchange's return; the next lxmf.propagation
    // announce is 6 h away. So nothing starts until the exchange is back.
    const c = makeClient();
    c.self._initPropagation();
    await c.establish(c.links[0]);
    c.exchange.isDown = true;
    await c.closeUnder(c.links[0], Link.TIMEOUT);
    assert.equal(c.links.length, 1, "no LINKREQUEST into a down exchange");
    assert.equal(c.self._propReopenArmed, false, "the close consumed its one re-open");
    assert.equal(c.self._redrivePropagationLink("online"), false, "a page event while it is still down starts nothing either");

    c.exchange.isDown = false;
    assert.equal(c.self._redrivePropagationLink("exchange back"), true, "the exchange's return (_onPageResume) re-drives it");
    assert.equal(c.links.length, 2);
    assert.equal(c.self._redrivePropagationLink("exchange back"), false, "one attempt at a time");
    await c.establish(c.links[1]);
    assert.equal(c.self._propReopenArmed, true);
});
