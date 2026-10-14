/**
 * REGRESSION GUARD — the browser backs off from its PHP node.
 *
 * Reticulum-post REGISTRATION-STAGE1.md §10 and §14's
 * post_interface_backoff.test.mjs; DESIGN_PRINCIPLES §3's decided exception
 * (James, 2026-10-14: "Back off 2 s to 5 min", and "Any success resets it").
 * After a failure (a network failure, a 5xx, a 2xx that is not JSON, or a
 * 4xx on an exchange that §10 does not list), on the challenge, the
 * registration or an exchange, the next attempt comes after 2 s, twice as
 * long after each further failure, capped at 300 s; any success, an
 * exchange's 200 or a registration, resets it to 2 s. An online, visible or
 * pageshow event makes the next attempt at once and leaves the backoff where
 * it was. A 401 registers again at once and leaves it too. The answers that
 * stop wait for nothing. Until Stage 1 every wait was a fixed 5 s
 * (RECONNECT_WAIT_MS).
 *
 * The real PostInterface against the scripted PHP node of
 * test_stage1_node.mjs; its timers are captured and fired by hand.
 *
 * Run: node --test post_interface_backoff.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Identity } from "./lib/rns/reticulum.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";
import { captureConsole, eventually, fakePage, fakeTimers, record, signingInterface, stage1Node, tick, upSigned } from "./test_stage1_node.mjs";

const S = 1000;
const STEPS = [2, 4, 8, 16, 32, 64, 128, 256, 300, 300].map((s) => s * S);

/** The next attempt is armed `ms` from now and is the only timer; fire it. */
async function waitsThenFires(clock, ms, label) {
    const wait = await clock.next(`${label}: the next attempt armed`);
    assert.equal(wait.ms, ms, `${label}: waits ${ms / S} s`);
    clock.fire(wait);
}

function signing(t) {
    const iface = signingInterface();
    t.after(() => iface.disconnect());
    return { iface, seen: record(iface) };
}

test("the backoff: 2 s, doubling, capped at 5 min, as decided", () => {
    assert.equal(PostInterface.BACKOFF_FIRST_MS, 2 * S);
    assert.equal(PostInterface.BACKOFF_CAP_MS, 300 * S);
    assert.equal(PostInterface.RECONNECT_WAIT_MS, undefined, "the fixed 5 s wait is gone");
});

test("consecutive failures on the challenge wait 2, 4, 8 … s before the next attempt, capped at 300 s, and each attempt asks once", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, seen } = signing(t);
    iface.connect();
    for (const ms of STEPS) {
        (await node.pending("challenge")).fail();
        await waitsThenFires(clock, ms, `challenge failure, ${ms / S} s`);
    }
    await node.pending("challenge");
    assert.equal(node.count("challenge"), STEPS.length + 1, "one request per attempt: nothing is sent again in between");
    assert.deepEqual(seen.kinds(), ["down"], "one down for the whole failure run: the status dot shows offline while it lasts");
    assert.equal(iface.isDown, true);
});

test("failures on the challenge and the registration share one backoff: a network failure, a 5xx, a 2xx that is not JSON", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, seen } = signing(t);
    iface.connect();

    (await node.pending("challenge")).fail();
    await waitsThenFires(clock, 2 * S, "challenge: network failure");
    (await node.pending("challenge")).respond(503, { error: "busy", message: "Busy." });
    await waitsThenFires(clock, 4 * S, "challenge: 503");
    (await node.pending("challenge")).respondText(200, "<html>Sign in to the hotel Wi-Fi</html>");
    await waitsThenFires(clock, 8 * S, "challenge: a 200 that is not JSON (a captive portal's page)");
    await node.serveNext("challenge");
    (await node.pending("register")).fail();
    await waitsThenFires(clock, 16 * S, "registration: network failure");
    await node.serveNext("challenge");
    (await node.pending("register")).respond(502, {});
    await waitsThenFires(clock, 32 * S, "registration: 502");
    await node.serveNext("challenge");
    (await node.pending("register")).respondText(200, "Fatal error: out of memory");
    await waitsThenFires(clock, 64 * S, "registration: a 200 that is not JSON");
    assert.deepEqual(seen.stopped(), [], "none of them stops");
    assert.deepEqual(seen.kinds(), ["down"]);

    await node.serveNext("challenge");
    await node.serveNext("register");
    await node.serveNext("exchange");
    await eventually(() => seen.kinds().at(-1) === "up", "up");
    assert.equal(clock.armed().ms, 1000, "then the idle poll");
});

test("failures on an exchange: a network failure, a 5xx, a 2xx that is not JSON, and a 4xx that §10 does not list each take the next step", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, events } = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    const failures = [
        ["network failure", (r) => r.fail()],
        ["503", (r) => r.respond(503, { error: "busy" })],
        ["a 200 that is not JSON", (r) => r.respondText(200, "<html>portal</html>")],
        ["404", (r) => r.respond(404, { error: "not_found" })],
        ["400", (r) => r.respond(400, { error: "bad_request", message: "No." })],
        ["429", (r) => r.respond(429, {})],
        ["409 with another code", (r) => r.respond(409, { error: "conflict" })],
        ["403", (r) => r.respond(403, { error: "forbidden" })],
    ];
    let ms = 2 * S;
    for (const [label, answer] of failures) {
        answer(await node.pending("exchange"));
        await waitsThenFires(clock, ms, `exchange: ${label}`);
        ms *= 2;
    }
    assert.deepEqual(events.stopped(), [], "an exchange's unlisted 4xx is a failure, not a stop");
    assert.equal(node.count("register"), 1, "and none registers again");
    assert.deepEqual(events.kinds(), ["registered", "up", "down"]);
    assert.equal(iface.isRegistered, true, "the session is kept");
});

test("a successful registration resets the wait to 2 s", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, seen } = signing(t);
    iface.connect();
    for (const ms of [2, 4, 8].map((s) => s * S)) {
        (await node.pending("challenge")).fail();
        await waitsThenFires(clock, ms, `challenge failure, ${ms / S} s`);
    }
    await node.serveNext("challenge");
    await node.serveNext("register");
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 2 * S, "the first exchange after the registration fails: 2 s, not 16 s");
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 4 * S, "and then the next step");
    assert.deepEqual(seen.kinds(), ["down", "registered"], "still down: the registration did not end the failure run the app was told about");
    await node.serveNext("exchange");
    await eventually(() => iface.isUp, "up");
});

test("a successful exchange resets the wait to 2 s", async (t) => {
    // James, 2026-10-14 ("Any success resets it"): after a network drop the
    // session is still valid, so the next attempt is an exchange; were only
    // a registration to reset the wait, separate drops over hours would grow
    // an open tab's wait toward 5 min.
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, events } = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    for (const ms of [2, 4, 8].map((s) => s * S)) {
        (await node.pending("exchange")).fail();
        await waitsThenFires(clock, ms, `exchange failure, ${ms / S} s`);
    }
    await node.serveNext("exchange");
    await eventually(() => events.kinds().at(-1) === "up", "up again");
    await waitsThenFires(clock, 1000, "the idle poll");
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 2 * S, "a later drop waits 2 s, not 16 s");
    assert.equal(node.count("register"), 1, "no registration in all this: the session was valid throughout");
    assert.equal(iface.isRegistered, true);
});

test("online, visible and pageshow each make the next attempt at once and leave the backoff where it was", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const page = fakePage(t);
    const node = stage1Node(t);
    const { iface, events } = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 2 * S, "first failure");
    (await node.pending("exchange")).fail();
    const waiting = await clock.next();
    assert.equal(waiting.ms, 4 * S);

    let ms = 8 * S;
    for (const [label, event] of [["online", page.online], ["visible", page.visible], ["pageshow", () => page.pageshow(true)]]) {
        const armed = clock.live()[0];
        event();
        assert.equal(armed.cleared, true, `${label}: the backoff is not waited out`);
        (await node.pending("exchange")).fail();
        const next = await clock.next(`${label}: the next attempt armed`);
        assert.equal(next.ms, ms, `${label}: a failure after it waits the next step (${ms / S} s), not 2 s again`);
        ms *= 2;
    }

    // Neither a fresh load's pageshow nor a hidden page is a reason to attempt.
    const exchanges = node.count("exchange");
    page.pageshow(false);
    page.document.visibilityState = "hidden";
    page.document.dispatchEvent(new Event("visibilitychange"));
    await tick(); await tick();
    assert.equal(node.count("exchange"), exchanges);
    assert.equal(clock.live()[0].cleared, false);

    // The attempt one of them makes can succeed, and that resets it.
    page.online();
    await node.serveNext("exchange");
    await eventually(() => events.kinds().at(-1) === "up", "up");
    await waitsThenFires(clock, 1000, "the idle poll");
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 2 * S, "reset by that success");
    assert.equal(iface.isDown, true);
});

test("a 401 registers again at once, with no backoff, and leaves the backoff where it was", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, events, hash } = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 2 * S, "first failure");
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 4 * S, "second failure");

    node.forget(hash);
    assert.equal(node.serve(await node.pending("exchange")).status, 401);
    const asked = await node.pending("challenge");
    assert.equal(clock.live().length, 0, "registers again at once: nothing armed");
    asked.fail();
    await waitsThenFires(clock, 8 * S, "a failure after the 401 waits the next step: the 401 neither waited nor reset it");
    await node.serveNext("challenge");
    await node.serveNext("register");
    await node.serveNext("exchange");
    await eventually(() => events.kinds().at(-1) === "up", "up");
    assert.equal(clock.armed().ms, 1000);
    assert.equal(iface.isUp, true);
});

test("terminal codes stop with no backoff, whatever the backoff had reached", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);

    // After failures on the challenge, the registration is refused.
    let node = stage1Node(t);
    let { iface, seen } = signing(t);
    iface.connect();
    for (const ms of [2, 4].map((s) => s * S)) {
        (await node.pending("challenge")).fail();
        await waitsThenFires(clock, ms, `challenge failure, ${ms / S} s`);
    }
    await node.serveNext("challenge");
    (await node.pending("register")).respond(403, { error: "bad_registration_signature", message: "The registration's signature does not verify." });
    await eventually(() => seen.stopped().length === 1, "stopped");
    await tick(); await tick();
    assert.equal(clock.live().length, 0, "the stop waits for nothing");

    // After failures on an exchange, the session is superseded.
    node = stage1Node(t);
    const up = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await waitsThenFires(clock, 2 * S, "exchange failure");
    node.supersede(up.hash);
    await node.serveNext("exchange");
    await eventually(() => up.events.stopped().length === 1, "stopped");
    await tick(); await tick();
    assert.equal(clock.live().length, 0, "the stop waits for nothing");
    assert.deepEqual(up.events.stopped(), [PostInterface.STOP_SUPERSEDED]);
});
