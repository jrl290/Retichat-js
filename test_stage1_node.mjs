/**
 * A scripted PHP node for the browser's Stage 1 tests
 * (Reticulum-post REGISTRATION-STAGE1.md: post_interface_signed.test.mjs,
 * post_interface_backoff.test.mjs, exchange_stopped.test.mjs).
 *
 * It keeps the state the PHP node keeps and answers as §3 to §8 say, by its
 * own code, not the browser's: a stateless HMAC challenge over the row's
 * registration count (§3), the signed bytes rebuilt from the received body
 * and the signature checked with RNS Identity.validate (§4.2, §4.3), the
 * session token encrypted to the registering key with RNS Identity.encrypt
 * (§5), and the session checks of the exchange and the goodbye (§7, §8).
 * With `stage1: false` it is a PHP node without Stage 1: the challenge is
 * answered 404 and only the legacy registration exists.
 *
 * Every request waits for the test, which answers it as this node would
 * (`node.serve(request)`) or with any status and body (`request.respond`),
 * or fails it as the network would (`request.fail`); `auto` names the paths
 * served as soon as they are asked. No clock decides anything: the timers
 * PostInterface arms are captured and fired by hand (fakeTimers), and the
 * clock its §1 assertions read is the test's (testClock).
 */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { Identity, Packet } from "./lib/rns/reticulum.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
export const tick = () => new Promise((resolve) => realSetTimeout(resolve, 0));

/** Wait (a few macrotasks at most) for `probe` to return something truthy. A failure mechanism only. */
export async function eventually(probe, what) {
    for (let i = 0; i < 200; i++) {
        const value = probe();
        if (value) return value;
        await tick();
    }
    throw new Error(`never happened: ${what}`);
}

/** Timers of 0 ms (the EventEmitter's deferral) run for real; every other timer is captured and fired by hand. */
export function fakeTimers(t) {
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
    const live = () => timers.filter((x) => !x.cleared && !x.fired);
    return {
        timers,
        live,
        /** The one armed timer. */
        armed() {
            assert.equal(live().length, 1, `one armed timer, got ${live().map((x) => x.ms)}`);
            return live()[0];
        },
        /** Wait until a timer is armed, and return it (the only one). */
        async next(what = "the next attempt armed") {
            await eventually(() => live().length > 0, what);
            return this.armed();
        },
        fire(timer) { timer.fired = true; timer.fn(); },
    };
}

/** The clock PostInterface's §1 assertions read (PostInterface.now), moved by hand. */
export function testClock(t) {
    let now = 1_000_000;
    const real = PostInterface.now;
    PostInterface.now = () => now;
    t.after(() => { PostInterface.now = real; });
    return { advance(ms) { now += ms; } };
}

/** Every console line PostInterface writes, kept and not printed: [{ level, text }]. */
export function captureConsole(t) {
    const lines = [];
    const { log, warn, error } = console;
    const keep = (level) => (...args) => lines.push({ level, text: args.map(String).join(" ") });
    console.log = keep("log"); console.warn = keep("warn"); console.error = keep("error");
    t.after(() => Object.assign(console, { log, warn, error }));
    return lines;
}

/** The page's events PostInterface hooks (window, document), on stand-ins. */
export function fakePage(t) {
    const window = new EventTarget();
    const document = Object.assign(new EventTarget(), { visibilityState: "visible" });
    globalThis.window = window;
    globalThis.document = document;
    t.after(() => { delete globalThis.window; delete globalThis.document; });
    return {
        window, document,
        online: () => window.dispatchEvent(new Event("online")),
        visible: () => { document.visibilityState = "visible"; document.dispatchEvent(new Event("visibilitychange")); },
        pageshow: (persisted = true) => window.dispatchEvent(Object.assign(new Event("pageshow"), { persisted })),
    };
}

export const SUPERSEDED_MESSAGE = "This identity connected from another tab or device. Reload to connect here.";

// ── The node's own Stage 1 code ────────────────────────────────────────────

const CHALLENGE_DOMAIN = Buffer.from("reticulum-post/challenge/v1", "ascii");
const REGISTER_DOMAIN = Buffer.from("reticulum-post/register/v1", "ascii");
const SIGNED_METADATA = ["client", "mode", "transport", "peer_url", "peer_interface_id", "peer_session_token"];
const hex = (value, length) => typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
const lp = (bytes) => Buffer.concat([Buffer.from([bytes.length >> 8, bytes.length & 0xff]), bytes]);
const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const refusal = (status, error, message) => ({ status, json: { error, message } });

/** §4.2, rebuilt from a received body. */
export function signedBytesOf(body) {
    const m = body.metadata;
    const r = body.registration;
    return Buffer.concat([
        lp(REGISTER_DOMAIN), lp(Buffer.from(r.challenge, "hex")), lp(Buffer.from(r.public_key, "hex")),
        lp(Buffer.from(body.name, "utf8")), lp(u64be(body.bitrate)), lp(u32be(body.mtu)), lp(Buffer.from(m.client, "utf8")),
        lp(Buffer.from([m.mode])), lp(Buffer.from(m.transport ?? "", "utf8")), lp(Buffer.from(m.peer_url ?? "", "utf8")),
        lp(Buffer.from(m.peer_interface_id ?? "", "utf8")), lp(Buffer.from(m.peer_session_token ?? "", "utf8")),
    ]);
}

/**
 * The scripted PHP node, answering every fetch PostInterface makes. Options:
 * `stage1` (default true): a node with Stage 1; false answers the challenge 404.
 * `auto`: the paths (without /v1/interfaces/) served at once, or true for all.
 * `honourAbort` (default true): false lets an aborted request still be served, as when its answer was on its way.
 */
export function stage1Node(t, { stage1 = true, auto = [], honourAbort = true } = {}) {
    const secret = randomBytes(32);
    const rows = new Map();          // identity hash (hex) → { count, interfaceId, token, signed }
    const byInterface = new Map();   // interface id → row
    const requests = [];
    const autoPaths = auto === true ? null : new Set(auto);
    let hashOnlyChallenges = 0;

    const mac = (H, count, nonce) => createHmac("sha256", secret).update(Buffer.concat([CHALLENGE_DOMAIN, H, u64be(count), nonce])).digest();

    function challenge(body) {
        if (!stage1) return { status: 404, json: { error: "not_found" } };
        const keys = Object.keys(body ?? {});
        let H;
        if (keys.length === 1 && hex(body.public_key, 128)) H = Identity.fromPublicKey(Buffer.from(body.public_key, "hex")).hash;
        else if (keys.length === 1 && hex(body.identity_hash, 32)) { H = Buffer.from(body.identity_hash, "hex"); hashOnlyChallenges++; }
        else return refusal(400, "bad_challenge_request", "A challenge request carries exactly one public key or identity hash, in lower-case hex.");
        const nonce = randomBytes(16);
        const count = rows.get(H.toString("hex"))?.count ?? 0;
        return { status: 200, json: { status: "challenge", version: 1, identity_hash: H.toString("hex"),
            challenge: Buffer.concat([nonce, mac(H, count, nonce)]).toString("hex") } };
    }

    function bind(H, token, signed) {
        const key = H.toString("hex");
        let row = rows.get(key);
        if (!row) {
            row = { count: 0, interfaceId: randomBytes(16).toString("hex"), token: null, signed };
            rows.set(key, row);
            byInterface.set(row.interfaceId, row);
        }
        row.token = token;
        row.signed = row.signed || signed;
        if (signed) row.count++;
        return row;
    }

    function register(body) {
        const settings = { idle_exchange_interval_ms: 1000, max_batch_packets: 64, max_packet_bytes: 500 };
        if (!body?.registration) {
            // A legacy registration (§4.6): its claimed identity, unproven.
            const claim = body?.metadata?.identity_hash;
            if (stage1 && hex(claim, 32) && rows.get(claim)?.signed) {
                return refusal(403, "identity_requires_signature", "This identity has signed its registration here; reload the page to connect.");
            }
            const token = randomBytes(32).toString("hex");
            const row = bind(Buffer.from(hex(claim, 32) ? claim : randomBytes(16).toString("hex"), "hex"), token, false);
            return { status: 200, json: { status: "registered", interface_id: row.interfaceId, session_token: token, ...settings } };
        }
        if (!stage1) return { status: 400, json: { error: "Invalid registration" } };
        const r = body.registration;
        const m = body.metadata ?? {};
        // §4.3, in its order.
        if (Object.keys(r).sort().join() !== "challenge,public_key,signature,version" || r.version !== 1
            || !hex(r.challenge, 96) || !hex(r.public_key, 128) || !hex(r.signature, 128)
            || typeof body.name !== "string" || body.name === "" || !Number.isInteger(body.bitrate) || !Number.isInteger(body.mtu)
            || !Number.isInteger(m.mode) || m.mode < 1 || m.mode > 7 || typeof m.client !== "string" || m.client === "") {
            return refusal(400, "bad_registration", "The registration is malformed.");
        }
        if (Object.keys(m).some((k) => !SIGNED_METADATA.includes(k) && k !== "implementation" && k !== "identity_hash")) {
            return refusal(400, "unsigned_metadata", "The registration carries metadata its signature does not cover.");
        }
        const publicKey = Buffer.from(r.public_key, "hex");
        const identity = Identity.fromPublicKey(publicKey);
        const H = identity.hash;
        if (m.identity_hash !== undefined && m.identity_hash !== H.toString("hex")) {
            return refusal(400, "identity_hash_mismatch", "The registration's identity hash is not its public key's.");
        }
        if (m.client !== "rns-js") return refusal(400, "unknown_client", "This client cannot register here.");
        if (![1, 2, 4, 7].includes(m.mode)) return refusal(400, "transit_mode_not_allowed", "A browser cannot register in a transit mode.");
        if (["transport", "peer_url", "peer_interface_id", "peer_session_token"].some((k) => m[k] !== undefined && m[k] !== null && m[k] !== "")) {
            return refusal(400, "metadata_not_allowed", "A browser's registration carries no transport and no peer.");
        }
        if (!identity.validate(Buffer.from(r.signature, "hex"), signedBytesOf(body))) {
            return refusal(403, "bad_registration_signature", "The registration's signature does not verify.");
        }
        const received = Buffer.from(r.challenge, "hex");
        const count = rows.get(H.toString("hex"))?.count ?? 0;
        if (!timingSafeEqual(mac(H, count, received.subarray(0, 16)), received.subarray(16))) {
            return refusal(409, "stale_challenge", "The challenge is no longer valid; ask for a new one.");
        }
        const token = randomBytes(32).toString("hex");
        const encrypted = identity.encrypt(Buffer.from(token, "utf8")).toString("hex");
        const row = bind(H, token, true);
        return { status: 200, json: { status: "registered", interface_id: row.interfaceId, identity_hash: H.toString("hex"),
            session_token_encrypted: encrypted, ...settings } };
    }

    /** §7, §8: the session check of /exchange and /goodbye. */
    function session(body) {
        const row = byInterface.get(body?.interface_id);
        if (!row) return refusal(401, "unauthorized", "Unknown interface or session.");
        if (body.session_token === row.token) return null;
        if (row.signed) return refusal(409, "session_superseded", SUPERSEDED_MESSAGE);
        return refusal(401, "unauthorized", "Unknown interface or session.");
    }

    function answerFor(path, body) {
        switch (path) {
            case "/v1/interfaces/challenge": return challenge(body);
            case "/v1/interfaces/register": return register(body);
            case "/v1/interfaces/exchange": return session(body) ?? { status: 200, json: { delivery_packets: [], idle_exchange_interval_ms: 1000 } };
            case "/v1/interfaces/goodbye": return session(body) ?? { status: 200, json: { status: "ok" } };
            default: return { status: 404, json: { error: "not_found" } };
        }
    }

    globalThis.fetch = (url, options) => new Promise((resolve, reject) => {
        const request = {
            path: new URL(url).pathname.replace(/^\/reticulum/, ""),
            body: JSON.parse(options.body),
            signal: options.signal,
            keepalive: options.keepalive === true,
            settled: false,
            answered: null,
            respond(status, json = {}) {
                if (request.settled) return;
                request.settled = true;
                request.answered = { status, json };
                resolve({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(json) });
            },
            respondText(status, text) {
                if (request.settled) return;
                request.settled = true;
                request.answered = { status, text };
                resolve({ ok: status >= 200 && status < 300, status, text: async () => text });
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
        if (node.isAuto(request.path.replace("/v1/interfaces/", ""))) node.serve(request);
    });
    t.after(() => { delete globalThis.fetch; });

    const node = {
        requests,
        rows,
        get hashOnlyChallenges() { return hashOnlyChallenges; },
        /** The next unanswered request to `path` (without the /v1/interfaces/ prefix). */
        pending: (path) => eventually(() => requests.find((r) => !r.settled && r.path === `/v1/interfaces/${path}`), `a ${path} request`),
        count: (path) => requests.filter((r) => r.path === `/v1/interfaces/${path}`).length,
        /** This path is served as soon as it is asked. */
        isAuto: (path) => autoPaths === null || autoPaths.has(path),
        /** Process `request` as this node would, its state changed whether or not the browser still waits for it, and answer it. */
        serve(request) {
            const answer = answerFor(request.path, request.body);
            request.respond(answer.status, answer.json);
            return answer;
        },
        /** Serve the next request to `path`. */
        async serveNext(path) {
            return node.serve(await node.pending(path));
        },
        /**
         * Another tab or device of the identity with this hash registers,
         * signed, and binds: the row's count moves, so every challenge made
         * before is stale (§3), and its token is replaced, so the session
         * that held it is superseded (§4.4, §8).
         */
        supersede(identityHashHex) {
            bind(Buffer.from(identityHashHex, "hex"), randomBytes(32).toString("hex"), true);
        },
        /** The PHP node forgets the session (its stale sweep, a reset): the next exchange gets 401 (§7). */
        forget(identityHashHex) {
            const row = rows.get(identityHashHex);
            assert.ok(row, "a row to forget");
            byInterface.delete(row.interfaceId);
            rows.delete(identityHashHex);
        },
    };
    return node;
}

/** connect() a signing PostInterface over `node` and serve it until its first exchange is answered: an interface that is up. */
export async function upSigned(t, node, clock, { identity = Identity.create(), name = "Retichat Web" } = {}) {
    const iface = new PostInterface(name, "https://node.example/reticulum", identity);
    const events = record(iface);
    t.after(() => iface.disconnect());
    iface.connect();
    for (const path of ["challenge", "register", "exchange"]) {
        if (!node.isAuto(path)) await node.serveNext(path);
    }
    await eventually(() => iface.isUp && events.kinds().includes("up"), "up");
    assert.equal((await clock.next("the poll armed")).ms, 1000, "polls on the node's idle interval");
    return { iface, identity, events, hash: identity.hash.toString("hex") };
}

/** A raw packet as the stack hands it to sendData, and its full hash. */
export function rawPacket(fill) {
    const raw = Buffer.concat([Buffer.from([0x00, 0x00]), Buffer.alloc(16, fill), Buffer.from([0x00]), Buffer.alloc(40, fill)]);
    return { raw, hash: Packet.fromBytes(raw).packetHash.toString("hex") };
}

/** Every event the interface emits, in order. */
export function record(iface) {
    const events = [];
    for (const kind of ["registered", "up", "down", "lost", "stopped"]) {
        iface.on(kind, (detail) => events.push({ kind, detail }));
    }
    return {
        events,
        kinds: () => events.map((e) => e.kind),
        lost: () => events.filter((e) => e.kind === "lost").map((e) => e.detail),
        stopped: () => events.filter((e) => e.kind === "stopped").map((e) => e.detail),
    };
}
