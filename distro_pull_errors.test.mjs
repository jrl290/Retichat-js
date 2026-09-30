// REGRESSION GUARD — do not delete, do not weaken.
//
// /rfed/pull is the one rfed request authenticated by link identity, so the
// server can refuse it with a bare msgpack integer error code — LXMF
// reference codes (LXMF/LXMPeer.py): 0xF0 NO_IDENTITY, 0xF1 NO_ACCESS.
// The reference client's reaction (LXMF/LXMRouter.py:1525
// message_list_response) is to TEAR THE LINK DOWN: LINKIDENTIFY is
// fire-and-forget, so a fresh link whose identify precedes the next request
// is the recovery. No in-place retry (DESIGN_PRINCIPLES §3).
//
// Until 2026-08-17 the server sent nothing at all for an unidentified pull
// and this client had no numeric-response branch, so a refusal was
// indistinguishable from a dead node: a silent 43-49s timeout per attempt.
//
// This runs the real shipped _pullDistroMessages body against stubs.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import MsgPack from "./lib/rns/msgpack.js";

const appSource = await readFile(new URL("./app.js", import.meta.url), "utf8");

function extractMethod(source, signature, label) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from ${label}`);
    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
            depth--;
            if (depth === 0) return source.slice(bodyStart + 1, i);
        }
    }
    throw new Error(`could not brace-match ${signature} in ${label}`);
}

/** The object literal of a top-level `const NAME = { … };` in app.js. */
function extractConst(name) {
    const start = appSource.indexOf(`\nconst ${name} = {`);
    assert.notEqual(start, -1, `${name} is missing from app.js`);
    const open = appSource.indexOf("{", start);
    let depth = 0;
    for (let i = open; i < appSource.length; i++) {
        if (appSource[i] === "{") depth++;
        else if (appSource[i] === "}" && --depth === 0) return appSource.slice(open, i + 1);
    }
    throw new Error(`could not brace-match ${name}`);
}

const RFED_LINK_PATHS = new Function(`return ${extractConst("RFED_LINK_PATHS")};`)();

/** A real app.js method body, `this.` read as `self.`, its free names from env. */
function compile(signature, env) {
    const body = extractMethod(appSource, signature, "app.js").replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
        .split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params,
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

const quiet = { log() {}, warn() {}, error() {} };

/**
 * The real _pullDistroMessages over the real _rfedLinkKeyFor and
 * _closeRefusedRfedLink. `responses` are answered in turn; each request
 * waits for `gate()` when one is given.
 */
function makePull({ response, responses = [response], gate = null }) {
    const closed = [];
    const requests = [];
    const handled = [];
    // The pull travels on rfed.link (RFED_LINK_PATHS maps it there); a
    // stray legacy link is never touched.
    const rfedLink = { close: () => closed.push("link") };
    const legacy = { close: () => closed.push("distro.register") };
    const env = { DistroManager: { has: true }, MsgPack, Buffer, RFED_LINK_PATHS, RFED_LINK_FAILED: "link_failed", console: quiet };
    const self = {
        _rfedRequest: async (aspects, path) => {
            requests.push(`${aspects.join(".")}:${path}`);
            if (gate) await gate();
            return responses[Math.min(requests.length, responses.length) - 1];
        },
        _rfedLinks: new Map([["link", rfedLink], ["distro.register", legacy]]),
        _rfedLinkState: new Map(),
        _rfedReopenArmed: new Set(["link"]),
        _distroPullInFlight: null,
        _handleDistroBlob: (hash, blob) => { handled.push(Buffer.from(blob).toString()); return true; },
    };
    for (const signature of ["async _pullDistroMessages()", "_rfedLinkKeyFor(aspects, path)", "_closeRefusedRfedLink(key, what)"]) {
        self[signature.replace(/^async /, "").split("(")[0]] = compile(signature, env)(self);
    }
    return { run: () => self._pullDistroMessages(), closed, requests, handled, self };
}

test("PULL refused with NO_IDENTITY tears the link down, reference-style", async () => {
    const { run, closed, self } = makePull({ response: 0xF0 });
    const result = await run();
    assert.deepEqual(result, [], "a refusal yields no messages");
    assert.deepEqual(closed, ["link"],
        "the link the pull came on — rfed.link — must be torn down so the " +
        "next link re-identifies (LXMF/LXMRouter.py:1525). Until 2026-09-30 " +
        "this closed the legacy distro.register link, which a mapped pull " +
        "never uses, and the refused rfed.link stayed up");
    assert.equal(self._rfedReopenArmed.has("link"), false,
        "and its one-shot re-open is disarmed: a refusal must not become an " +
        "establish, refuse, close loop (DESIGN_PRINCIPLES §3)");
});

test("PULL refused with NO_ACCESS also tears the link down", async () => {
    const { run, closed, self } = makePull({ response: 0xF1 });
    await run();
    assert.deepEqual(closed, ["link"]);
    assert.equal(self._rfedReopenArmed.has("link"), false);
});

test("other numeric errors are surfaced without teardown", async () => {
    const { run, closed } = makePull({ response: 0xF4 });
    const result = await run();
    assert.deepEqual(result, [], "no messages on error");
    assert.deepEqual(closed, [],
        "INVALID_DATA is a client bug, not an identity race — tearing the " +
        "link down would not help and costs a re-establishment");
});

test("a served empty page is not treated as an error", async () => {
    const { run, closed } = makePull({ response: [[], false] });
    const result = await run();
    assert.deepEqual(result, [], "empty page yields no messages");
    assert.deepEqual(closed, [], "a successful response must not close the link");
});

// ── One pull at a time; more_pending is followed on the response ────────────

test("a pull asked for while one is in flight is that pull, not a second request", async () => {
    let release;
    const { self, requests } = makePull({
        responses: [[[[Buffer.alloc(16), Buffer.from("blob-1")]], false]],
        gate: () => new Promise((resolve) => { release = resolve; }),
    });
    const first = self._pullDistroMessages();
    const second = self._pullDistroMessages();
    await new Promise((r) => setImmediate(r));
    assert.equal(requests.length, 1, "one /distro/pull on the wire");
    release();
    const [a, b] = await Promise.all([first, second]);
    assert.equal(a.length, 1);
    assert.deepEqual(b, a, "the second caller gets the first pull's page");
    assert.equal(self._distroPullInFlight, null, "the guard is released when the pull ends");
});

test("a page that says more is queued is followed by one more pull, once it has been handled", async () => {
    const { self, requests, handled } = makePull({
        responses: [
            [[[Buffer.alloc(16), Buffer.from("page-1")]], true],
            [[[Buffer.alloc(16), Buffer.from("page-2")]], false],
        ],
    });
    await self._pullDistroMessages();
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    assert.equal(requests.length, 2, "more_pending: exactly one follow-up");
    assert.deepEqual(handled, ["page-1", "page-2"], "each page handled, in order");
});

test("a page that brought nothing is not followed, whatever it says", async () => {
    // Finite answers, so that code which did follow would stop and show it.
    const { self, requests } = makePull({ responses: [[[], true], [[], false]] });
    await self._pullDistroMessages();
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    assert.equal(requests.length, 1, "an empty page with more_pending would repeat the same answer forever");
});

test("the distro pull path schedules nothing", () => {
    const body = extractMethod(appSource, "async _pullDistroMessages()", "app.js");
    assert.doesNotMatch(body, /setTimeout|setInterval/, "the follow-up is on the response, never on a clock");
});
