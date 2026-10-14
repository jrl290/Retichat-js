/**
 * DESIGN_PRINCIPLES §1 for every request to the PHP node (the challenge,
 * the registration, the exchange and the keepalive goodbye): its answer
 * must come within 5 s of its send (Reticulum-post REGISTRATION-STAGE1.md
 * §6). A request with no answer 5 s after it was sent is said, once, as a
 * §1 violation, and an answer that comes later is said with its time: a
 * late success is a failure. The watch decides nothing: the answer, or the
 * request's own failure (the network's, or check()'s abort), decides the
 * request, and a stop ends every watch.
 *
 * Until 2026-10-14 only an answer was timed (PostInterface._answered, when
 * its text arrived), so a request never answered, or one check() aborted,
 * was never said (the review of stage1-sign).
 *
 * A real PostInterface over the scripted PHP node of test_stage1_node.mjs,
 * on virtual time (test_virtual_time.mjs): a wait is exactly the delay a
 * test injects. The model is request_response_rule.test.mjs, the same rule
 * for a request on a link.
 *
 * Run: node --test post_interface_answer_rule.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import PostInterface from "./lib/rns/interfaces/post_interface.js";
import { signingInterface, stage1Node } from "./test_stage1_node.mjs";
import { useVirtualTime } from "./test_virtual_time.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** `promise`, or a failure once `ms` virtual ms have passed. */
function within(promise, ms, label) {
    let timer;
    const bound = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} did not happen within ${ms} ms`)), ms); });
    return Promise.race([promise, bound]).finally(() => clearTimeout(timer));
}

/** Virtual time, and the §1 lines PostInterface writes, each with the virtual ms it was written at; the rest of its console kept quiet. */
function setUp(t) {
    const clock = useVirtualTime(t);
    const lines = [];
    const { log, warn, error } = console;
    const keep = (...args) => {
        const text = args.map(String).join(" ");
        if (text.startsWith("[§1] VIOLATION")) lines.push({ at: clock.elapsed(), text });
    };
    console.log = keep; console.warn = keep; console.error = keep;
    t.after(() => Object.assign(console, { log, warn, error }));
    return { clock, lines };
}

/**
 * The PHP node: it answers every request at once, as it would, but the
 * first request to `path`, which `script(request)` handles (its send time
 * is `request.sentAt`).
 */
function nodeWith(t, clock, path, script) {
    let first = true;
    const node = stage1Node(t, {
        onRequest(request) {
            if (first && request.path === `/v1/interfaces/${path}`) {
                first = false;
                request.sentAt = clock.elapsed();
                script(request, node);
                return;
            }
            node.serve(request);
        },
    });
    return node;
}

/** A signing interface, connected, and its first "up". */
function connected(t) {
    const iface = signingInterface();
    t.after(() => iface.disconnect());
    const up = new Promise((resolve) => iface.once("up", resolve));
    iface.connect();
    return { iface, up: within(up, 60_000, "up") };
}

const NO_ANSWER = (what) => `[§1] VIOLATION the ${what} request to the PHP node: no answer 5 s after it was sent; its answer, or its own failure, decides it`;
const LATE = (what, status, ms) => `[§1] VIOLATION the ${what} request to the PHP node: answered (HTTP ${status}) ${ms} ms after it was sent (a late success is a failure)`;

/** Each request, by its path and the name its lines give it. */
const REQUESTS = [["challenge", "challenge"], ["register", "registration"], ["exchange", "exchange"], ["goodbye", "goodbye"]];

/**
 * Connect over a PHP node whose first request to `path` `script` handles;
 * for the goodbye, send one once the interface is up (a browser without
 * sendBeacon sends it as a keepalive fetch). Then let 20 s pass, so that
 * any watch still armed would have run.
 */
async function run(t, clock, path, script) {
    const node = nodeWith(t, clock, path, script);
    const { iface, up } = connected(t);
    await up;
    if (path === "goodbye") {
        assert.equal(typeof globalThis.navigator?.sendBeacon, "undefined", "(this runtime has no sendBeacon)");
        assert.equal(iface.goodbye(), true);
    }
    await sleep(20_000);
    const request = node.requests.find((r) => r.sentAt !== undefined);
    assert.ok(request, `a ${path} request was sent`);
    return { node, iface, request };
}

test("an answer 5 s after its send is not said; exactly 5 s is within the rule", async (t) => {
    for (const [path, what] of REQUESTS) {
        await t.test(what, async (t) => {
            const { clock, lines } = setUp(t);
            const { request } = await run(t, clock, path, (r, node) => setTimeout(() => node.serve(r), 5_000));
            assert.equal(request.answered.status, 200);
            assert.deepEqual(lines, []);
        });
    }
});

test("no answer 5 s after its send is said once, at 5 s; the answer after it is said with its time, and still decides", async (t) => {
    for (const [path, what] of REQUESTS) {
        await t.test(what, async (t) => {
            const { clock, lines } = setUp(t);
            const { iface, request } = await run(t, clock, path, (r, node) => setTimeout(() => node.serve(r), 6_500));
            assert.deepEqual(lines, [
                { at: request.sentAt + 5_001, text: NO_ANSWER(what) },
                { at: request.sentAt + 6_500, text: LATE(what, 200, 6_500) },
            ], "the first millisecond past 5 s, then the answer with its time");
            assert.equal(request.answered.status, 200);
            assert.equal(iface.isUp, true, "a late success decides nothing else: it is said");
        });
    }
});

test("a request that fails or is aborted before 5 s leaves no line: its own failure decided it", async (t) => {
    for (const [how, end] of [["aborted by check()", (iface) => iface.check("online")], ["failed on the network", (iface, r) => r.fail()]]) {
        await t.test(how, async (t) => {
            const { clock, lines } = setUp(t);
            let iface = null;
            const node = nodeWith(t, clock, "challenge", (r) => setTimeout(() => end(iface, r), 3_000));
            const made = connected(t);
            iface = made.iface;
            await made.up;
            await sleep(20_000);
            assert.equal(node.count("challenge"), 2, "the challenge after it connected");
            assert.deepEqual(lines, []);
        });
    }
});

test("a request aborted, or failed, 7 s after its send was said once, at 5 s; its end adds nothing", async (t) => {
    for (const [how, end] of [["aborted by check()", (iface) => iface.check("online")], ["failed on the network", (iface, r) => r.fail()]]) {
        await t.test(how, async (t) => {
            const { clock, lines } = setUp(t);
            let iface = null;
            const node = nodeWith(t, clock, "challenge", (r) => setTimeout(() => end(iface, r), 7_000));
            const made = connected(t);
            iface = made.iface;
            await made.up;
            await sleep(20_000);
            assert.equal(node.count("challenge"), 2, "the challenge after it connected");
            assert.deepEqual(lines, [{ at: 5_001, text: NO_ANSWER("challenge") }]);
        });
    }
});

test("a stop ends every watch: a goodbye still in flight when the PHP node supersedes the session is not said", async (t) => {
    const { clock, lines } = setUp(t);
    const node = nodeWith(t, clock, "goodbye", () => {});   // the goodbye is never answered
    const { iface, up } = connected(t);
    await up;
    const stopped = within(new Promise((resolve) => iface.once("stopped", resolve)), 60_000, "stopped");
    assert.equal(iface.goodbye(), true);
    const sentAt = clock.elapsed();
    node.supersede(iface._identityHash);   // the next poll's exchange is answered 409 session_superseded (§8)
    assert.equal(await stopped, PostInterface.STOP_SUPERSEDED);
    assert.ok(clock.elapsed() < sentAt + 5_000, "stopped before the goodbye's 5 s");
    await sleep(20_000);
    assert.deepEqual(lines, [], "no line for the goodbye");
    assert.equal(node.requests.find((r) => r.sentAt !== undefined).settled, false, "the goodbye was never answered");
});
