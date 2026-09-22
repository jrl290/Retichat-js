/**
 * The client tells the node when its page goes away.
 *
 * Until 2026-09-22 nothing left the browser on close; the node only learned
 * an interface was gone from silence (interface_stale_after_seconds, 300 s on
 * retichat.com), and a closed tab kept capturing direct delivery for its
 * destinations that whole time. goodbye() posts /v1/interfaces/goodbye as a
 * text/plain beacon (no CORS preflight, survives unload); connect() hooks it
 * to pagehide; disconnect() sends it too. The stale sweep stays as backstop.
 *
 * Run: node --test goodbye_beacon.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./lib/rns/interfaces/post_interface.js", import.meta.url), "utf8");

function method(sig) {
    const start = source.indexOf(`\n    ${sig} {`);
    assert.notEqual(start, -1, `${sig} missing`);
    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") { depth--; if (depth === 0) return source.slice(bodyStart + 1, i); }
    }
    throw new Error(`could not brace-match ${sig}`);
}

function makeGoodbye(self, env) {
    const body = method("goodbye()").replaceAll("this.", "self.");
    const fn = new Function("self", "navigator", "fetch", "Blob", "console", body);
    return () => fn(self, env.navigator, env.fetch, env.Blob ?? globalThis.Blob, console);
}

test("goodbye sends the interface credentials as a text/plain beacon", async () => {
    const sent = [];
    const navigator = { sendBeacon: (url, blob) => { sent.push({ url, blob }); return true; } };
    const self = { isRegistered: true, _baseUrl: "https://node.example/reticulum", _interfaceId: "iface1", _sessionToken: "tok1" };
    assert.equal(makeGoodbye(self, { navigator, fetch: undefined })(), true);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].url, "https://node.example/reticulum/v1/interfaces/goodbye");
    assert.equal(sent[0].blob.type, "text/plain", "text/plain needs no CORS preflight during unload");
    assert.deepEqual(JSON.parse(await sent[0].blob.text()), { interface_id: "iface1", session_token: "tok1" });
});

test("goodbye is a no-op before registration and falls back to a keepalive fetch", () => {
    const calls = [];
    const fetch = (url, opts) => { calls.push({ url, opts }); return Promise.resolve(); };
    const unregistered = { isRegistered: false, _baseUrl: "https://n/r", _interfaceId: null, _sessionToken: null };
    assert.equal(makeGoodbye(unregistered, { navigator: {}, fetch })(), false);
    assert.equal(calls.length, 0);
    const registered = { isRegistered: true, _baseUrl: "https://n/r", _interfaceId: "i", _sessionToken: "t" };
    assert.equal(makeGoodbye(registered, { navigator: {}, fetch })(), true);
    assert.equal(calls[0].opts.keepalive, true, "the fallback must outlive the page");
});

test("connect hooks goodbye to pagehide once, and disconnect sends it", () => {
    assert.match(method("async connect()"), /addEventListener\('pagehide', this\._goodbyeHook\)/);
    assert.match(method("async connect()"), /if \(!this\._goodbyeHook/, "hooked once, not per reconnect");
    assert.match(method("disconnect()"), /this\.goodbye\(\)/);
});
