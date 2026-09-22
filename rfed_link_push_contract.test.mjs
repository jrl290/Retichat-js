/**
 * REGRESSION GUARD — RFed-spec/Link.md, node → client contract.
 *
 *  - "The response is the delivery proof": a push is acknowledged with
 *    msgpack true only when the client holds the blob; a dropped push gets
 *    false. Until 2026-09-22 every /delivery and /lxmf/delivery push was
 *    acknowledged after the handler returned, including ones dropped for an
 *    unknown channel, a bad signature or a wrong destination.
 *  - "Identify": ERROR_NO_IDENTITY on /channel/pull closes the link so the
 *    next pull re-identifies (as /distro/pull already did).
 *  - "The binding dies with the link": the client must re-send
 *    /channel/stream/open on its next link, so the per-channel memo of that
 *    request is dropped when the link closes.
 *
 * app.js cannot be imported under Node; these read the source.
 * Run: node --test rfed_link_push_contract.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./app.js", import.meta.url), "utf8");

function method(name) {
    let start = source.indexOf(`\n    ${name}(`);
    if (start === -1) start = source.indexOf(`\n    async ${name}(`);
    assert.notEqual(start, -1, `${name} missing`);
    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") { depth--; if (depth === 0) return source.slice(bodyStart + 1, i); }
    }
    throw new Error(`could not brace-match ${name}`);
}

test("a push is acknowledged with the handler's verdict, never unconditionally", () => {
    const body = method("_onRfedLinkPush");
    assert.doesNotMatch(body, /\n\s+this\._handle(ChannelPacket|DistroBlob)\([^\n]*\);\n\s+link\.sendResponse\(requestId, true\)/,
        "an unconditional true after a handler call is the old behaviour");
    assert.match(body, /link\.sendResponse\(requestId, this\._handleChannelPacket\(payload\) === true\)/);
    assert.match(body, /link\.sendResponse\(requestId, this\._handleDistroBlob\(.*?\) === true\)/);
});

test("the push handlers report whether the blob was kept", () => {
    for (const name of ["_handleChannelPacket", "_handleDistroBlob"]) {
        const body = method(name);
        assert.doesNotMatch(body, /\n\s+return;\n/, `${name}: a bare return hides the verdict`);
        assert.match(body, /return true/, `${name}: must report a kept blob`);
        assert.match(body, /return false/, `${name}: must report a dropped blob`);
    }
});

test("a refused channel pull (ERROR_NO_IDENTITY) closes the link", () => {
    const body = method("pullChannel");
    assert.match(body, /typeof response === "number"/, "numeric error codes must be recognised, not treated as malformed");
    assert.match(body, /response === 0xF0/);
    assert.match(body, /\.close\(\)/, "the link is torn down so the next pull re-identifies");
});

test("channel stream bindings are dropped when the link that held them closes", () => {
    // The rfed.link close handler is the one with the janitor comment.
    const start = source.indexOf("The janitor, mirroring LXMRouter.jobs()");
    assert.notEqual(start, -1);
    const closeHandler = source.slice(start, start + 1200);
    assert.match(closeHandler, /_rfedStreamPromises\.clear\(\)/);
});
