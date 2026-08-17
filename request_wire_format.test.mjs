// REGRESSION GUARD — do not delete, do not weaken.
//
// A link REQUEST is msgpack [timestamp, path_hash(16), data] — three elements,
// always (RNS/Link.py:493: request(path, data=None) packs None as nil).
// sendRequestPacked() writes a hardcoded 0x93 array-3 header and then splices
// the caller's pre-encoded msgpack value in as the third element.
//
// On 2026-08-17 the distro PULL called it with Buffer.alloc(0). Zero bytes is
// not a msgpack value, so the wire carried an array-3 header with only two
// elements. rfed decrypted it fine and then died in the parser:
//
//   [REQ] handle_request_packet: request_id=6817bf55... plaintext_len=28
//   [Error] [REQ] msgpack parse FAILED: I/O error while reading marker byte:
//           failed to fill whole buffer
//
// No response is sent for an unparseable request (matches the Python
// reference), so the client burned its full RTT-scaled budget — ~43-49s per
// pull — and the failure looked identical to a dead node. PULL was the only
// request with no payload, which is why every other request worked and this
// one "regressed". The clients that pull successfully all send nil (0xc0).
//
// This test runs the real shipped sendRequestPacked body against stubs, so it
// tests behaviour rather than the text of the file.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import MsgPack from "./lib/rns/msgpack.js";

const linkSource = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");

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

function makeSendRequestPacked(captured) {
    const body = extractMethod(linkSource, "sendRequestPacked(path, packedData)", "link.js");
    // Stub the collaborators the body touches.
    const Cryptography = {
        truncatedHash: (b) => Buffer.alloc(16, 0xab),
    };
    const Packet = { REQUEST: 0x09 };
    const self = {
        _sendWithContext(data, context) {
            captured.payload = data;
            captured.context = context;
            return { getTruncatedHash: () => Buffer.alloc(16, 0xcd) };
        },
    };
    const fn = new Function(
        "path", "packedData", "Cryptography", "MsgPack", "Packet", "Buffer",
        body.replaceAll("this.", "self.").replace(/^/, "const self = arguments[6];\n"),
    );
    return (path, packedData) => fn(path, packedData, Cryptography, MsgPack, Packet, Buffer, self);
}

test("sendRequestPacked emits a parseable three-element request for nil data", () => {
    const captured = {};
    const send = makeSendRequestPacked(captured);
    send("/rfed/pull", MsgPack.pack(null));

    assert.equal(captured.context, 0x09, "must send with REQUEST context");
    const payload = captured.payload;
    assert.equal(payload[0], 0x93, "wire starts with an array-3 header");

    // The whole point: the payload must decode as msgpack WITHOUT running out
    // of buffer, and must contain exactly three elements.
    const decoded = MsgPack.unpack(payload);
    assert.equal(decoded.length, 3, "request must carry three elements");
    assert.equal(decoded[2], null, "empty request data is nil, like Python's data=None");
});

test("sendRequestPacked refuses an empty buffer instead of emitting a truncated request", () => {
    const captured = {};
    const send = makeSendRequestPacked(captured);
    assert.throws(
        () => send("/rfed/pull", Buffer.alloc(0)),
        /msgpack value|MsgPack\.pack\(null\)/,
        "an empty buffer is not a msgpack value and must be rejected loudly — " +
        "sent to the wire it becomes a malformed request the server can only " +
        "drop, which the client experiences as a silent full-budget timeout",
    );
    assert.equal(captured.payload, undefined, "nothing may reach the wire");
});

test("the distro pull call site sends nil, not an empty buffer", async () => {
    const appSource = await readFile(new URL("./app.js", import.meta.url), "utf8");
    const pullStart = appSource.indexOf("async _pullDistroMessages()");
    assert.notEqual(pullStart, -1, "_pullDistroMessages present");
    const window = appSource.slice(pullStart, pullStart + 1500);
    assert.match(
        window,
        /"\/rfed\/pull", MsgPack\.pack\(null\)/,
        "the pull request must send msgpack nil (0xc0) as its data",
    );
    assert.doesNotMatch(
        window,
        /"\/rfed\/pull", Buffer\.alloc\(0\)/,
        "Buffer.alloc(0) has regressed back into the pull call site",
    );
});
