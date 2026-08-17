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
//     (__request_messages_path_job); we re-drive when the service announces,
//     since rfed re-announces every service every 15 minutes
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
