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

function makePull({ response }) {
    const body = extractMethod(appSource, "async _pullDistroMessages()", "app.js");
    const closed = [];
    const link = { close: () => closed.push("distro.register") };
    const self = {
        _rfedRequest: async () => response,
        _rfedLinks: new Map([["distro.register", link]]),
        _handleDistroBlob: () => { throw new Error("must not handle blobs on a refusal"); },
    };
    const DistroManager = { has: true };
    const fn = new Function(
        "DistroManager", "MsgPack", "Buffer", "self",
        `return (async () => {${body.replaceAll("this.", "self.")}})();`,
    );
    return { run: () => fn(DistroManager, MsgPack, Buffer, self), closed };
}

test("PULL refused with NO_IDENTITY tears the link down, reference-style", async () => {
    const { run, closed } = makePull({ response: 0xF0 });
    const result = await run();
    assert.deepEqual(result, [], "a refusal yields no messages");
    assert.deepEqual(closed, ["distro.register"],
        "the link must be torn down so the next pull re-establishes and " +
        "re-identifies (LXMF/LXMRouter.py:1525)");
});

test("PULL refused with NO_ACCESS also tears the link down", async () => {
    const { run, closed } = makePull({ response: 0xF1 });
    await run();
    assert.deepEqual(closed, ["distro.register"]);
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
