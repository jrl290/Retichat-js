/**
 * REGRESSION GUARD — the browser signs its registration (Stage 1).
 *
 * Reticulum-post REGISTRATION-STAGE1.md (revision 3, 2026-10-14), §14's
 * post_interface_signed.test.mjs. Until Stage 1 PostInterface registered
 * unsigned, with only its identity hash, and read the session token in plain
 * text from the answer: anyone who knew a hash could take over its
 * registration. Now it asks a challenge (§3), signs its registration with
 * its identity key (§4), decrypts the token the PHP node encrypted to that
 * key (§5), and acts on the answers of §7, §8 and §10: one more round after
 * 409 stale_challenge, a 401 registers again at once, and the answers after
 * which nothing can succeed stop it, saying why ("stopped"). A challenge
 * answered 404 (a PHP node without Stage 1) is the only answer on which it
 * registers the legacy way. Every request is held to DESIGN_PRINCIPLES §1
 * (§6), and nothing secret reaches the log (§11).
 *
 * The real PostInterface runs against a scripted PHP node with its own
 * Stage 1 code (test_stage1_node.mjs). The backoff is
 * post_interface_backoff.test.mjs's; the page's side, exchange_stopped.test.mjs's.
 *
 * Run: node --test post_interface_signed.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import { Identity } from "./lib/rns/reticulum.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";
import {
    SUPERSEDED_MESSAGE, captureConsole, eventually, fakePage, fakeTimers, rawPacket, record, signedBytesOf,
    signingInterface, stage1Node, testClock, tick, upSigned,
} from "./test_stage1_node.mjs";

const source = await readFile(new URL("./lib/rns/interfaces/post_interface.js", import.meta.url), "utf8");
const URL_BASE = "https://node.example/reticulum";
const LEGACY_METADATA = (hash) => ({ client: "rns-js", implementation: "PostInterface", mode: 1, identity_hash: hash });

/** The interface stopped, once, saying `reason`, with nothing armed and nothing more asked of the PHP node. */
async function assertStopped(seen, iface, clock, node, reason, label) {
    await eventually(() => seen.stopped().length > 0, `${label}: stopped`);
    await tick(); await tick();
    assert.deepEqual(seen.stopped(), [reason], `${label}: stopped once, saying why`);
    assert.equal(iface.stoppedReason, reason, label);
    assert.equal(clock.live().length, 0, `${label}: no backoff, nothing armed`);
    assert.equal(iface.isDown, true, `${label}: it carries nothing`);
    const asked = node.requests.length;
    iface.check("online");
    iface.check("visible");
    iface.disconnect();
    await tick(); await tick();
    assert.equal(node.requests.length, asked, `${label}: nothing more is asked of the PHP node, a check, a disconnect or a goodbye included`);
    assert.deepEqual(seen.stopped(), [reason], `${label}: still once`);
}

// ── The constructor: the hash third, the identity in the options ───────────

test("the third argument is the identity's hash, a string, or null, never the identity; an options.identity of another hash throws", () => {
    // A PostInterface older than Stage 1 sends its third argument to the PHP
    // node (metadata.identity_hash): an identity there carries its private
    // keys, so a page that passes one must fail here, at once.
    const identity = Identity.create();
    const hash = identity.hash.toString("hex");
    const make = (third, mode, options) => () => new PostInterface("Retichat Web", URL_BASE, third, mode, options);
    for (const [third, label] of [[identity, "the identity"], [identity.hash, "its hash as bytes"], [undefined, "undefined"], [42, "a number"]]) {
        assert.throws(make(third), TypeError, `${label} third throws`);
        assert.throws(make(third, undefined, { identity }), TypeError, `${label} third throws, even with options.identity`);
    }
    assert.throws(make("ab".repeat(16), undefined, { identity }), /options\.identity's hash is not the identity hash/, "another identity's hash");
    assert.throws(make(null, undefined, { identity }), /options\.identity's hash is not the identity hash/, "no hash, with an identity");
    assert.throws(make(hash, undefined, { identity: { hash: identity.hash } }), /not an RNS identity that signs/, "not an identity");

    // Accepted: a hash alone (an app.js older than Stage 1), null, and the hash with its identity.
    assert.equal(make(hash)()._identity, null);
    assert.equal(make(hash)()._identityHash, hash);
    assert.equal(make(null)()._identityHash, null);
    const signing = make(hash, undefined, { identity })();
    assert.equal(signing._identity, identity);
    assert.equal(signing._identityHash, hash);
    assert.equal(make(hash, 1, {})()._identity, null);
});

// ── Challenge, sign, decrypt ───────────────────────────────────────────────

test("challenge, sign, decrypt: the registration is signed over §4.2's bytes, the token is the one the PHP node encrypted, and no secret is logged", async (t) => {
    const lines = captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const identity = Identity.create();
    const hash = identity.hash.toString("hex");
    const iface = signingInterface(identity);
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();

    const asked = await node.pending("challenge");
    assert.deepEqual(asked.body, { public_key: identity.getPublicKey().toString("hex") }, "the challenge is asked by the public key");
    const { json: challenge } = node.serve(asked);

    const registering = await node.pending("register");
    const body = registering.body;
    assert.deepEqual(Object.keys(body), ["name", "bitrate", "mtu", "metadata", "registration"]);
    assert.deepEqual([body.name, body.bitrate, body.mtu], ["Retichat Web", 1000000, 500]);
    assert.deepEqual(body.metadata, { client: "rns-js", implementation: "PostInterface", mode: 1 },
        "only signed metadata (and `implementation`): no identity_hash, no transport, no peer");
    assert.deepEqual(Object.keys(body.registration), ["version", "public_key", "challenge", "signature"]);
    assert.equal(body.registration.version, 1);
    assert.equal(body.registration.public_key, identity.getPublicKey().toString("hex"));
    assert.equal(body.registration.challenge, challenge.challenge, "the challenge, verbatim");
    assert.equal(identity.validate(Buffer.from(body.registration.signature, "hex"), signedBytesOf(body)), true,
        "signed over §4.2's bytes, as the PHP node rebuilds them from the body");

    const { json: answer } = node.serve(registering);
    assert.equal("session_token" in answer, false, "a signed registration's answer has no plaintext token (§5)");
    const exchanging = await node.pending("exchange");
    const row = node.rows.get(hash);
    assert.equal(row.count, 1, "the registration moved the row's count (§4.4)");
    assert.equal(exchanging.body.interface_id, answer.interface_id);
    assert.equal(exchanging.body.session_token, row.token, "the token the PHP node encrypted, decrypted");
    node.serve(exchanging);
    await eventually(() => seen.kinds().includes("up"), "up");
    assert.deepEqual(seen.kinds(), ["registered", "up"]);
    assert.equal(clock.armed().ms, 1000, "polls on the node's idle interval");

    // §11: never a token, a challenge or a signature in a log line.
    for (const [what, secret] of [["the session token", row.token], ["the challenge", challenge.challenge],
        ["the signature", body.registration.signature], ["the encrypted token", answer.session_token_encrypted]]) {
        assert.equal(lines.some((line) => line.text.includes(secret)), false, `${what} is in no log line`);
    }
    assert.ok(lines.some((line) => /Registered \(signed\): [0-9a-f]{8}\.\.\./.test(line.text)), "the interface id, 8 hex");
});

test("409 stale_challenge: one new challenge and one more registration, which connects", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge", "exchange"] });
    const identity = Identity.create();
    const iface = signingInterface(identity);
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();

    const first = await node.pending("register");
    node.supersede(identity.hash.toString("hex")); // another tab or device binds between this challenge and this registration
    assert.equal(node.serve(first).json.error, "stale_challenge");
    const second = await node.pending("register");
    assert.notEqual(second.body.registration.challenge, first.body.registration.challenge, "a new challenge, at the count that moved");
    assert.equal(node.serve(second).status, 200);
    await eventually(() => seen.kinds().includes("up"), "up");
    assert.deepEqual(seen.stopped(), [], "no stop");
    assert.deepEqual([node.count("challenge"), node.count("register")], [2, 2]);
    assert.deepEqual(seen.kinds(), ["registered", "up"], "no down: the extra round is the protocol, not a failure");
    assert.equal(clock.armed().ms, 1000);
});

test("409 stale_challenge twice: the interface stops with its own text, with no backoff", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge"] });
    const identity = Identity.create();
    const hash = identity.hash.toString("hex");
    const iface = signingInterface(identity);
    const seen = record(iface);
    iface.connect();

    for (let round = 0; round < 2; round++) {
        const registering = await node.pending("register");
        node.supersede(hash);
        assert.equal(node.serve(registering).json.error, "stale_challenge");
    }
    await assertStopped(seen, iface, clock, node, PostInterface.STOP_STALE_CHALLENGE, "two stale challenges");
    assert.equal(PostInterface.STOP_STALE_CHALLENGE, "Another registration of this identity got in first. Reload to connect here.");
    assert.deepEqual([node.count("challenge"), node.count("register"), node.count("exchange")], [2, 2, 0]);
});

test("the extra round is the interface's until a registration succeeds: 409, then a 503 or an abort, then the next attempt's 409 stops", async (t) => {
    // Until the review of stage1-sign (2026-10-14) the extra round was one
    // attempt's: a 503 or an abort in it, then the next attempt's 409,
    // earned a second, and so on for every failure in between.
    const STALE = { error: "stale_challenge", message: "The challenge is no longer valid; ask for a new one." };
    const ends = [
        ["a 503", async (iface, node, clock) => {
            (await node.pending("challenge")).respond(503, { error: "busy", message: "Busy." });
            const wait = await clock.next("the backoff armed");
            assert.equal(wait.ms, PostInterface.BACKOFF_FIRST_MS, "a 503 in the extra round backs off");
            clock.fire(wait);
        }],
        ["an abort", async (iface, node) => {
            await node.pending("challenge");
            iface.check("online");   // aborts it; the next attempt is at once
        }],
    ];
    for (const [label, end] of ends) {
        await t.test(label, async (t) => {
            captureConsole(t);
            const clock = fakeTimers(t);
            const node = stage1Node(t);
            const iface = signingInterface();
            const seen = record(iface);
            iface.connect();
            node.serve(await node.pending("challenge"));
            (await node.pending("register")).respond(409, STALE);   // the extra round is taken
            await end(iface, node, clock);
            node.serve(await node.pending("challenge"));
            (await node.pending("register")).respond(409, STALE);
            await assertStopped(seen, iface, clock, node, PostInterface.STOP_STALE_CHALLENGE, `409, ${label}, 409`);
            assert.deepEqual([node.count("challenge"), node.count("register")], [3, 2], "one extra round in all");
        });
    }
});

test("a registration that succeeds gives the extra round back: a 409 after it, and after a 401, earns its own", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge", "exchange"] });
    const identity = Identity.create();
    const hash = identity.hash.toString("hex");
    const iface = signingInterface(identity);
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();
    for (const round of ["the first registration", "the registration after a 401"]) {
        const registering = await node.pending("register");
        node.supersede(hash);
        assert.equal(node.serve(registering).json.error, "stale_challenge", round);
        assert.equal(node.serve(await node.pending("register")).status, 200, `${round}: its extra round connects`);
        await eventually(() => iface.isUp, `${round}: up`);
        if (round === "the first registration") {
            node.forget(hash);   // the next exchange is answered 401: it registers again, at once
            clock.fire(await clock.next("the poll armed"));
        }
    }
    assert.deepEqual(seen.stopped(), []);
    assert.equal(node.count("register"), 4);
});

test("a registration abandoned by check() that binds between the new challenge and the new registration still connects, with no stop", async (t) => {
    // §4.3: the page gave up on it, the PHP node completed it anyway, after
    // the page's next challenge was made: that registration's 409 earns the
    // one more round, and the round connects.
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge", "exchange"] });
    const identity = Identity.create();
    const iface = signingInterface(identity);
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();

    const abandoned = await node.pending("register");
    iface.check("online");
    assert.equal(abandoned.signal.aborted, true, "the check ends the registration in flight");
    const again = await node.pending("register");   // its challenge was made at count 0
    assert.equal(node.serve(abandoned).status, 200, "the abandoned registration reaches the PHP node anyway and binds (count 0 → 1)");
    assert.equal(node.serve(again).json.error, "stale_challenge");
    const third = await node.pending("register");
    assert.equal(node.serve(third).status, 200);
    await eventually(() => seen.kinds().includes("up"), "up");
    assert.deepEqual(seen.stopped(), [], "no stop");
    assert.deepEqual([node.count("challenge"), node.count("register")], [3, 3]);
    assert.equal(node.rows.get(identity.hash.toString("hex")).count, 2);
    assert.equal(clock.armed().ms, 1000);
});

// ── Superseded (§8) ────────────────────────────────────────────────────────

test("Superseded: the interface stops with §8's message, reports what it held lost, and sends nothing more", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, events, hash } = await upSigned(t, node, clock);

    node.supersede(hash); // another tab or device of this identity connected: newest wins
    const a = rawPacket(0xa1);
    const b = rawPacket(0xb2);
    iface.sendData(a.raw);
    const exchanging = await node.pending("exchange");
    assert.equal(exchanging.body.packets.length, 1);
    iface.sendData(b.raw); // queued behind the exchange in flight
    assert.equal(node.serve(exchanging).json.error, "session_superseded");

    await eventually(() => events.lost().length === 1, "lost");
    assert.deepEqual(events.stopped(), [PostInterface.STOP_SUPERSEDED]);
    assert.equal(PostInterface.STOP_SUPERSEDED, SUPERSEDED_MESSAGE, "§8's message");
    assert.deepEqual(events.lost()[0], { packetHashes: [a.hash, b.hash], reason: SUPERSEDED_MESSAGE, abandoned: false, unsent: [b.hash] },
        "the batch it carried and the queue behind it, saying why; only the queue went into no request");
    assert.deepEqual(events.kinds(), ["registered", "up", "stopped", "lost"], "stopped, then what it lost; no down");

    const c = rawPacket(0xc3);
    const asked = node.requests.length;
    iface.sendData(c.raw);
    await eventually(() => events.lost().length === 2, "lost at once");
    assert.deepEqual(events.lost()[1], { packetHashes: [c.hash], reason: SUPERSEDED_MESSAGE, abandoned: false, unsent: [c.hash] });
    assert.equal(node.requests.length, asked, "nothing is sent for it");
    assert.equal(iface.isRegistered, false, "the superseded token is no one's");
    await assertStopped(events, iface, clock, node, SUPERSEDED_MESSAGE, "superseded");
    assert.equal(node.count("goodbye"), 0, "no goodbye with a superseded token");
});

test("a tab superseded twice while hidden, woken by \"visible\", stops with §8's message and never registers", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const page = fakePage(t);
    const node = stage1Node(t);
    const { iface, events, hash } = await upSigned(t, node, clock);
    node.supersede(hash);
    node.supersede(hash);
    page.visible();
    await node.serveNext("exchange");
    await assertStopped(events, iface, clock, node, PostInterface.STOP_SUPERSEDED, "woken by visible");
    assert.deepEqual([node.count("challenge"), node.count("register")], [1, 1], "it never registers again");
});

// ── Stops (§10) ────────────────────────────────────────────────────────────

test("terminal codes stop with no backoff, each saying the PHP node's message, never its code", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const cases = [
        ["challenge", 400, "bad_challenge_request"],
        ["challenge", 429, "too_many"],          // a 4xx §10 does not list, on the challenge: stops, says why
        ["register", 400, "bad_registration"],
        ["register", 400, "unsigned_metadata"],
        ["register", 400, "identity_hash_mismatch"],
        ["register", 400, "unknown_client"],
        ["register", 400, "transit_mode_not_allowed"],
        ["register", 400, "metadata_not_allowed"],
        ["register", 403, "bad_registration_signature"],
        ["register", 403, "identity_requires_signature"],
        ["register", 403, "signature_required"],
        ["register", 404, "not_found"],          // only the challenge's 404 means "no Stage 1"
    ];
    for (const [where, status, code] of cases) {
        const label = `${where} ${status} ${code}`;
        const node = stage1Node(t, { auto: where === "register" ? ["challenge"] : [] });
        const iface = signingInterface();
        const seen = record(iface);
        iface.connect();
        const message = `The PHP node says no (${label}).`;
        (await node.pending(where)).respond(status, { error: code, message });
        await assertStopped(seen, iface, clock, node, message, label);
        assert.equal(seen.kinds().includes("down"), false, `${label}: a stop is no down`);
        assert.equal(node.count("exchange"), 0, label);
        assert.equal(node.count("register"), where === "register" ? 1 : 0, `${label}: never the legacy registration`);
    }

    // A refusal without a message for a person: the interface's own sentence, never the code.
    const node = stage1Node(t, { auto: ["challenge"] });
    const iface = signingInterface();
    const seen = record(iface);
    iface.connect();
    (await node.pending("register")).respond(400, { error: "bad_registration" });
    await assertStopped(seen, iface, clock, node, PostInterface.STOP_REFUSED, "no message");
    assert.doesNotMatch(PostInterface.STOP_REFUSED, /bad_registration/);
});

test("each stop emits \"stopped\" once: after a network failure then 409 Superseded, and after a 401 then two 409 stale_challenge", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);

    // A network failure (down, the backoff), then Superseded.
    let node = stage1Node(t);
    let up = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    (await node.pending("exchange")).fail();
    await eventually(() => up.iface.isDown, "down");
    node.supersede(up.hash);
    clock.fire(await clock.next());
    await node.serveNext("exchange");
    await assertStopped(up.events, up.iface, clock, node, PostInterface.STOP_SUPERSEDED, "failure, then superseded");
    assert.deepEqual(up.events.kinds(), ["registered", "up", "down", "stopped"], "down said once, for the failure; the stop says the rest, once");

    // A 401 (the PHP node forgot the session), then two stale challenges.
    node = stage1Node(t, { auto: ["challenge"] });
    up = await upSigned(t, node, clock);
    node.forget(up.hash);
    clock.fire(clock.armed());
    await node.serveNext("exchange"); // 401
    for (let round = 0; round < 2; round++) {
        const registering = await node.pending("register");
        node.supersede(up.hash);
        assert.equal(node.serve(registering).json.error, "stale_challenge");
    }
    await assertStopped(up.events, up.iface, clock, node, PostInterface.STOP_STALE_CHALLENGE, "401, then two stale challenges");
    assert.deepEqual(up.events.kinds(), ["registered", "up", "down", "stopped"]);
});

// ── The legacy registration, only after a challenge 404 ───────────────────

test("a challenge answered 404 (a PHP node without Stage 1) leads to the legacy registration, and only that", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { stage1: false });
    const identity = Identity.create();
    const hash = identity.hash.toString("hex");
    const iface = signingInterface(identity);
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();

    assert.equal(node.serve(await node.pending("challenge")).status, 404);
    const registering = await node.pending("register");
    assert.deepEqual(registering.body, { name: "Retichat Web", bitrate: 1000000, mtu: 500, metadata: LEGACY_METADATA(hash) },
        "today's unsigned registration, by identity hash");
    const { json: answer } = node.serve(registering);
    const exchanging = await node.pending("exchange");
    assert.equal(exchanging.body.session_token, answer.session_token, "the legacy answer's token, in plain text");
    node.serve(exchanging);
    await eventually(() => seen.kinds().includes("up"), "up");
    assert.deepEqual(seen.kinds(), ["registered", "up"]);
    assert.equal(clock.armed().ms, 1000);
});

// ── Session lost (§7) ──────────────────────────────────────────────────────

test("a 401 registers again, signed, at once; a 401 on that new session's first exchange stops", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface, events, hash } = await upSigned(t, node, clock);

    node.forget(hash);
    clock.fire(clock.armed());
    assert.equal(node.serve(await node.pending("exchange")).status, 401);
    const asked = await node.pending("challenge");
    assert.equal(clock.live().length, 0, "at once: no backoff");
    node.serve(asked);
    const registering = await node.pending("register");
    assert.ok(registering.body.registration, "signed");
    node.serve(registering);
    const first = await node.pending("exchange");
    assert.equal(first.body.session_token, node.rows.get(hash).token, "the new session");
    first.respond(401, { error: "unauthorized", message: "Unknown interface or session." }); // dropped as soon as it was made
    await assertStopped(events, iface, clock, node, PostInterface.STOP_DROPPED, "401 on the new session's first exchange");
    assert.equal(PostInterface.STOP_DROPPED, "The PHP node dropped this connection as soon as it was made. Reload to connect.");
    assert.deepEqual([node.count("challenge"), node.count("register")], [2, 2], "one registration per 401");
    assert.deepEqual(events.kinds(), ["registered", "up", "down", "registered", "stopped"]);
});

test("a 401 acts on the status alone, whatever the answer's text", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge", "register"] });
    const { iface, events } = await upSigned(t, node, clock);
    clock.fire(clock.armed());
    (await node.pending("exchange")).respond(401, { error: "Something else entirely" });
    await node.serveNext("exchange");
    await eventually(() => iface.isUp && events.kinds().at(-1) === "up", "up again");
    assert.equal(node.count("register"), 2, "registered again");
    assert.doesNotMatch(source, /\.includes\(['"]Invalid interface credentials['"]\)/, "today's match on the text is gone");
});

// ── The answer (§5) ────────────────────────────────────────────────────────

test("a token that does not decrypt to this identity, or an answer naming another identity hash, stops; a plaintext token is never read", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const stranger = Identity.create();
    const encryptedTo = (identity, text) => identity.encrypt(Buffer.from(text, "utf8")).toString("hex");
    const cases = [
        ["encrypted to another identity", (a) => ({ ...a, session_token_encrypted: encryptedTo(stranger, "a".repeat(64)) })],
        ["one ciphertext bit flipped (HMAC)", (a) => {
            const blob = Buffer.from(a.session_token_encrypted, "hex");
            blob[60] ^= 0x01;
            return { ...a, session_token_encrypted: blob.toString("hex") };
        }],
        ["not 64 lower-case hex", (a, identity) => ({ ...a, session_token_encrypted: encryptedTo(identity, "A".repeat(64)) })],
        ["a short token", (a, identity) => ({ ...a, session_token_encrypted: encryptedTo(identity, "a".repeat(32)) })],
        ["another identity hash", (a) => ({ ...a, identity_hash: stranger.hash.toString("hex") })],
        ["a plaintext token instead", (a) => {
            const { session_token_encrypted, ...rest } = a;
            return { ...rest, session_token: "b".repeat(64) };
        }],
        ["a plaintext token beside one that does not decrypt", (a) => ({ ...a, session_token: "b".repeat(64),
            session_token_encrypted: encryptedTo(stranger, "b".repeat(64)) })],
    ];
    for (const [label, alter] of cases) {
        const node = stage1Node(t, { auto: ["challenge"] });
        const identity = Identity.create();
        const iface = signingInterface(identity);
        const seen = record(iface);
        iface.connect();
        const registering = await node.pending("register");
        const real = node.serve({ ...registering, respond() {} }); // the PHP node's own answer, kept from the browser
        registering.respond(200, alter(real.json, identity));
        await assertStopped(seen, iface, clock, node, PostInterface.STOP_BAD_ANSWER, label);
        assert.equal(node.count("exchange"), 0, `${label}: no exchange with it`);
        assert.equal(iface.isRegistered, false, label);
    }

    // A challenge for another identity is no challenge for this one.
    const node = stage1Node(t);
    const iface = signingInterface();
    const seen = record(iface);
    iface.connect();
    (await node.pending("challenge")).respond(200, { status: "challenge", version: 1, identity_hash: stranger.hash.toString("hex"), challenge: "c".repeat(96) });
    await assertStopped(seen, iface, clock, node, PostInterface.STOP_BAD_ANSWER, "a challenge for another identity");
    assert.equal(node.count("register"), 0);
});

// ── A page with only a hash (an app.js older than Stage 1) ────────────────

test("a page that gives only an identity hash registers the legacy way on a challenge 404, and otherwise stops: out of date", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const hash = "ab".repeat(16);

    // A PHP node without Stage 1.
    let node = stage1Node(t, { stage1: false });
    let iface = new PostInterface("Retichat Web", URL_BASE, hash);
    let seen = record(iface);
    iface.connect();
    const asked = await node.pending("challenge");
    assert.deepEqual(asked.body, { identity_hash: hash }, "it asks by its hash");
    node.serve(asked);
    const registering = await node.pending("register");
    assert.deepEqual(registering.body.metadata, LEGACY_METADATA(hash));
    node.serve(registering);
    await node.serveNext("exchange");
    await eventually(() => iface.isUp, "up");
    iface.disconnect();

    // A PHP node with Stage 1: this page cannot sign.
    node = stage1Node(t);
    iface = new PostInterface("Retichat Web", URL_BASE, hash);
    seen = record(iface);
    iface.connect();
    assert.equal(node.serve(await node.pending("challenge")).status, 200);
    await assertStopped(seen, iface, clock, node, PostInterface.STOP_OUT_OF_DATE, "a Stage 1 node's challenge");
    assert.equal(PostInterface.STOP_OUT_OF_DATE, "This page is out of date. Reload it to connect.");
    assert.equal(node.hashOnlyChallenges, 1, "the PHP node counts it (/health's hash_only_challenges)");
    assert.equal(node.count("register"), 0, "never the legacy registration");

    // Any answer but a 404 says the same; a 5xx is no answer (the backoff).
    for (const [status, stops] of [[400, true], [403, true], [200, true], [503, false]]) {
        node = stage1Node(t);
        iface = new PostInterface("Retichat Web", URL_BASE, hash);
        seen = record(iface);
        iface.connect();
        (await node.pending("challenge")).respond(status, status === 200 ? {} : { error: "x", message: "no" });
        if (stops) {
            await assertStopped(seen, iface, clock, node, PostInterface.STOP_OUT_OF_DATE, `challenge ${status}`);
        } else {
            assert.equal((await clock.next()).ms, PostInterface.BACKOFF_FIRST_MS, `challenge ${status}: the backoff`);
            assert.deepEqual(seen.stopped(), []);
            iface.disconnect();
        }
        assert.equal(node.count("register"), 0, `challenge ${status}: never the legacy registration`);
    }

    // No hash at all: the same.
    node = stage1Node(t);
    iface = new PostInterface("Retichat Web", URL_BASE, null);
    seen = record(iface);
    iface.connect();
    assert.equal(node.serve(await node.pending("challenge")).status, 400);
    await assertStopped(seen, iface, clock, node, PostInterface.STOP_OUT_OF_DATE, "no identity at all");
});

test("a page with only a hash behind a captive portal: a 2xx that is not JSON is no answer, so it backs off, and is not stopped", async (t) => {
    // Until the review of stage1-sign (2026-10-14) the portal's page stopped
    // it for good, "out of date".
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { stage1: false });
    const iface = new PostInterface("Retichat Web", URL_BASE, "ab".repeat(16));
    const seen = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();
    (await node.pending("challenge")).respondText(200, "<html><body>Sign in to use this Wi-Fi.</body></html>");
    const wait = await clock.next("the backoff armed");
    assert.equal(wait.ms, PostInterface.BACKOFF_FIRST_MS, "the backoff, as for any 2xx that is not JSON");
    assert.deepEqual(seen.stopped(), [], "not stopped: the portal is not the PHP node");
    assert.equal(iface.isDown, true, "down while it lasts");

    // Past the portal, the PHP node itself (without Stage 1) answers the challenge 404.
    clock.fire(wait);
    assert.equal(node.serve(await node.pending("challenge")).status, 404);
    node.serve(await node.pending("register"));
    node.serve(await node.pending("exchange"));
    await eventually(() => iface.isUp, "up, registered the legacy way");
    assert.deepEqual(seen.stopped(), []);
});

// ── §6: every request held to DESIGN_PRINCIPLES §1 ─────────────────────────

test("§6's assertions: an answer later than 5 s is a §1 violation, said once per request with its time and no secret, and still decides; the keepalive goodbye included", async (t) => {
    const lines = captureConsole(t);
    const clock = fakeTimers(t);
    const time = testClock(t);
    const node = stage1Node(t);
    const identity = Identity.create();
    const iface = signingInterface(identity);
    const seen = record(iface);
    t.after(() => iface.disconnect());
    // The watch's own line (no answer 5 s after the send) runs on virtual
    // time in post_interface_answer_rule.test.mjs; here its timers are
    // captured apart (fakeTimers) and only the late answer's line is said.
    const violations = () => lines.filter((line) => line.level === "error" && line.text.startsWith("[§1] VIOLATION"));
    const late = (what, status, ms) => new RegExp(`^\\[§1\\] VIOLATION the ${what} request to the PHP node: answered \\(HTTP ${status}\\) ${ms} ms after it was sent \\(a late success is a failure\\)$`);

    iface.connect();
    const asked = await node.pending("challenge");
    time.advance(5_001);
    const { json: challenge } = node.serve(asked);
    const registering = await node.pending("register");
    time.advance(6_000);
    node.serve(registering);
    const exchanging = await node.pending("exchange");
    time.advance(5_000); // exactly 5 s: in time
    node.serve(exchanging);
    await eventually(() => iface.isUp, "each late answer still decided: up");
    assert.equal(violations().length, 2);
    assert.match(violations()[0].text, late("challenge", 200, 5001));
    assert.match(violations()[1].text, late("registration", 200, 6000));
    assert.deepEqual(clock.watches(), [], "each answer ended its request's watch");

    // A late failure is said, and decides: down.
    clock.fire(clock.armed());
    const slow = await node.pending("exchange");
    time.advance(7_000);
    slow.respond(503, { error: "busy", message: "Busy." });
    await eventually(() => iface.isDown, "down");
    assert.equal(violations().length, 3);
    assert.match(violations()[2].text, late("exchange", 503, 7000));
    clock.fire(await clock.next());
    node.serve(await node.pending("exchange"));
    await eventually(() => iface.isUp, "up again");

    // The keepalive goodbye, where the browser has no sendBeacon.
    assert.equal(typeof globalThis.navigator?.sendBeacon, "undefined", "(this runtime has no sendBeacon)");
    assert.equal(iface.goodbye(), true);
    const goodbye = await node.pending("goodbye");
    assert.equal(goodbye.keepalive, true);
    time.advance(9_000);
    assert.equal(node.serve(goodbye).status, 200, "the goodbye is answered, late");
    await eventually(() => violations().length === 4, "the goodbye's violation");
    assert.match(violations()[3].text, late("goodbye", 200, 9000));
    assert.deepEqual(clock.watches(), [], "the goodbye's answer ended its watch");

    const row = node.rows.get(identity.hash.toString("hex"));
    for (const secret of [row.token, challenge.challenge, registering.body.registration.signature]) {
        assert.equal(violations().some((line) => line.text.includes(secret)), false, "no secret in a §1 line");
    }
    assert.deepEqual(seen.stopped(), []);

    // Both §1 lines (the watch's and the late answer's) carry the
    // principles' comment, and every request goes through both.
    const marked = source.match(/\/\/ NEVER REMOVE EVER — see DESIGN_PRINCIPLES\.md §1\n\s+console\.error\(`\[§1\] VIOLATION/g) ?? [];
    assert.equal(marked.length, 2, "the watch's line and the late answer's");
    assert.equal((source.match(/console\.error\(`\[§1\] VIOLATION/g) ?? []).length, 2, "every §1 line is marked");
    assert.equal([...source.matchAll(/\bawait fetch\(|\bfetch\(url/g)].length, 2, "one fetch for every request, and the keepalive goodbye's");
    assert.match(source, /const watch = this\._watch\(what\);\n\s+let resp;/, "every request is watched from its send");
    assert.match(source, /const watch = this\._watch\('goodbye'\);\n\s+sent\.then\(\(resp\) => \{\n\s+this\._unwatch\(watch\);\n\s+this\._answered\('goodbye', sentAt, resp\?\.status\);\n\s+\}, \(\) => this\._unwatch\(watch\)\);/,
        "the keepalive goodbye too");
});

test("an answer that is not JSON is logged with its hex runs cut out before the excerpt is cut: a run crossing the 200th character logs no hex", async (t) => {
    // §11: no token, challenge or signature an error page echoes reaches the
    // log. Cut to 200 characters first (until the review of stage1-sign,
    // 2026-10-14), this run's first 10 digits were logged: too short, by
    // then, to be cut out.
    const lines = captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const iface = signingInterface();
    t.after(() => iface.disconnect());
    iface.connect();
    const page = `${"x".repeat(190)}${"a1".repeat(32)}${"y".repeat(40)}`;   // 64 hex digits from the 191st character
    (await node.pending("challenge")).respondText(200, page);
    assert.equal((await clock.next("the backoff armed")).ms, PostInterface.BACKOFF_FIRST_MS);
    const logged = lines.filter((line) => line.text.includes("is not JSON (HTTP"));
    assert.equal(logged.length, 1, "the one line with the excerpt");
    assert.match(logged[0].text, /\(HTTP 200, 294 bytes\): x{190}\[hex\]y{5}$/, "the run cut out, then the first 200 characters");
    assert.doesNotMatch(logged[0].text, /[0-9a-fA-F]{8,}/, "no hex of the run");
});

test("a beacon goodbye has no answer to time: the stale sweep is its backstop", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t);
    const { iface } = await upSigned(t, node, clock);
    const beacons = [];
    const original = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: { sendBeacon: (url, blob) => { beacons.push(url); return true; } }, configurable: true });
    t.after(() => Object.defineProperty(globalThis, "navigator", original));
    assert.equal(iface.goodbye(), true);
    assert.deepEqual(beacons, [`${URL_BASE}/v1/interfaces/goodbye`]);
    assert.equal(node.count("goodbye"), 0, "no fetch beside the beacon");
});
