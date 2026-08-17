// REGRESSION GUARD — do not delete, do not weaken.
//
// LINKIDENTIFY wire format is RAW bytes: public_key(64) || signature(64),
// signature over link_id || public_key. That is the Python reference
// (RNS/Link.py:1036-1043), the Rust implementation
// (Reticulum-rust/src/link.rs handle_linkidentify_packet), and this file's
// own identify() SENDER.
//
// Until 2026-08-17 this file's RECEIVER disagreed with its own sender: it
// tried MsgPack.unpack on the plaintext and validated the signature over the
// bare link hash. Every conformant identify from a Python or Rust peer landed
// in a catch labelled "ignore malformed identify" — so a peer that identified
// on a link to this client was never recognised, and any identity-gated
// request it then made was refused with no trace on either side. The same
// class of silent-drop that hid the /rfed/pull failures (see
// request_wire_format.test.mjs).

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const linkSource = await readFile(new URL("./lib/rns/link.js", import.meta.url), "utf8");

function branchOf(source, marker, label) {
    const start = source.indexOf(marker);
    assert.notEqual(start, -1, `${label} branch is missing`);
    // Take the branch through to the next `else if(packet.context`
    const end = source.indexOf("else if(packet.context", start + marker.length);
    return source.slice(start, end === -1 ? source.length : end);
}

function methodOf(source, signature, label) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from ${label}`);
    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") {
            depth--;
            if (depth === 0) return source.slice(start, i + 1);
        }
    }
    throw new Error(`could not brace-match ${signature} in ${label}`);
}

test("identify sender emits raw pubkey||sig, signed over link_id||pubkey", () => {
    const sender = methodOf(linkSource, "identify(identity)", "link.js");
    assert.match(sender, /Buffer\.concat\(\[this\.hash, pubKey\]\)/,
        "signature must cover link_id || public_key");
    assert.match(sender, /Buffer\.concat\(\[pubKey, sig\]\)/,
        "wire payload must be raw pubkey || sig");
    assert.doesNotMatch(sender, /MsgPack\.pack/,
        "identify is raw bytes, never msgpack");
});

test("identify receiver parses the same raw format the sender emits", () => {
    const receiver = branchOf(
        linkSource,
        "else if(packet.context === Packet.LINKIDENTIFY)",
        "LINKIDENTIFY receiver",
    );
    assert.doesNotMatch(receiver, /MsgPack\.unpack/,
        "the receiver has regressed to msgpack-decoding identify — the wire " +
        "is raw pubkey(64)||sig(64) (RNS/Link.py:1036) and this client's own " +
        "sender emits exactly that");
    assert.match(receiver, /slice\(0, 64\)/, "must take pubkey from bytes 0..64");
    assert.match(receiver, /slice\(64, 128\)/, "must take signature from bytes 64..128");
    assert.match(receiver, /Buffer\.concat\(\[this\.hash, peerPubKey\]\)/,
        "must validate over link_id || public_key, not the bare link hash");
    assert.match(receiver, /console\.warn/,
        "malformed or invalid identifies must be logged, never swallowed — " +
        "silent drops in this pipeline cost hours (see rfed.log 2026-08-17)");
});
