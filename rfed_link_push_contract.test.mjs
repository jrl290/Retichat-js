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
 *  - "The client re-binds on every link": a new rfed.link's "established"
 *    re-sends /propagation/stream/open and /channel/stream/open for the
 *    opened channels, and only then pulls (2026-09-30).
 *  - A /notify wake runs /distro/pull (SPEC §17.3 tier 3).
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
    // The link it came on (rfed.link for the mapped path), torn down so the
    // next link re-identifies, and disarmed so the close does not re-open it.
    assert.match(body, /this\._closeRefusedRfedLink\(this\._rfedLinkKeyFor\(\["channel", "pull"\], "\/rfed\/pull"\)/);
    const close = method("_closeRefusedRfedLink");
    assert.match(close, /this\._rfedReopenArmed\.delete\(key\)/);
    assert.match(close, /link\.close\(\)/, "the link is torn down so the next pull re-identifies");
});

test("channel stream bindings are dropped when the link that held them closes", () => {
    // The rfed.link close handler is the one with the janitor comment.
    const start = source.indexOf("The janitor, mirroring LXMRouter.jobs()");
    assert.notEqual(start, -1);
    const end = source.indexOf("this._rfedLinkPromises.set(key, promise);", start);
    assert.notEqual(end, -1);
    const closeHandler = source.slice(start, end);
    // The link's own attempt only: a late close of a link disconnect()
    // dropped must not drop the bindings of the link that replaced it
    // (rfed_link_recovery.test.mjs runs both cases).
    assert.match(closeHandler, /if \(own\) \{[^}]*_rfedStreamPromises\.clear\(\)/);
});

test("a new rfed.link re-binds the channel stream, from its established handler", () => {
    // _ensureRfedLink's "established" handler hands every persistent link to
    // _onRfedLinkEstablished, which re-binds before it pulls.
    const ensure = method("_ensureRfedLink");
    assert.match(ensure, /link\.identify\(IdMgr\.id\);[\s\S]*resolve\(link\);[\s\S]*this\._onRfedLinkEstablished\(key, link\)/,
        "identify first, then the bindings and pulls");
    const established = method("_onRfedLinkEstablished");
    const rebind = established.indexOf("this._rebindChannelStream()");
    const pull = established.indexOf("this._pullOpenedChannels(");
    assert.notEqual(rebind, -1, "the channel stream is re-bound on every new link");
    assert.match(established, /this\._bindRfedLinkForDistroPush\(\)/, "and the distro push");
    assert.ok(rebind < pull, "bindings before pulls");
    assert.match(established, /await Promise\.allSettled\(\[this\._bindRfedLinkForDistroPush\(\), this\._rebindChannelStream\(\)\]\)/,
        "the pulls wait for both bindings to be answered");
});

test("a /notify wake is acknowledged and runs /distro/pull", () => {
    const body = method("_onRfedLinkPush");
    const notify = body.slice(body.indexOf("RFED_LINK_PUSH_HASHES.notify"), body.indexOf("RFED_LINK_PUSH_HASHES.lxmf"));
    assert.match(notify, /link\.sendResponse\(requestId, true\);[\s\S]*this\._pullDistroMessages\(\)/);
});
