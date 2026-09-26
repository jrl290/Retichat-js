// The rfed.delivery packet handler proves every packet (2026-09-26).
//
// RFed counts an rfed.delivery packet delivered only when it is proved, and
// queues and pushes the rest (RFed SPEC §7). The native apps prove with
// PROVE_ALL; this client proves in its handler. Until 2026-09-26 nothing
// proved, so every such packet was one RFed could not confirm.
//
// As in proof_dispatch.test.mjs, the shipped handler is lifted out of app.js
// and run against stubs: app.js cannot be imported under Node.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./app.js", import.meta.url), "utf8");

function deliveryHandler(self) {
    const marker = 'deliveryDest.on("packet", ';
    const start = source.indexOf(marker);
    assert.notEqual(start, -1, "the rfed.delivery packet handler is missing from app.js");
    const fnStart = start + marker.length;
    let depth = 0;
    for (let i = fnStart; i < source.length; i++) {
        if (source[i] === "(" || source[i] === "{") depth++;
        else if (source[i] === ")" || source[i] === "}") {
            if (depth === 0) {
                const arrow = source.slice(fnStart, i);
                // An arrow function takes `this` from where it is made.
                return new Function(`return function () { return (${arrow}); }`)().call(self);
            }
            depth--;
        }
    }
    throw new Error("could not brace-match the rfed.delivery handler");
}

test("every rfed.delivery packet is proved, and handled", () => {
    const handled = [];
    const handler = deliveryHandler({ _handleChannelPacket: (data) => handled.push(data) });
    let proofs = 0;
    handler({ packet: { prove: () => proofs++ }, data: Buffer.from("blob") });
    assert.equal(proofs, 1);
    assert.deepEqual(handled.map(String), ["blob"]);
});

test("a proof that fails to send does not lose the packet", () => {
    const handled = [];
    const handler = deliveryHandler({ _handleChannelPacket: (data) => handled.push(data) });
    const warn = console.warn;
    console.warn = () => {};
    try {
        handler({ packet: { prove: () => { throw new Error("no interface"); } }, data: Buffer.from("blob") });
    } finally {
        console.warn = warn;
    }
    assert.equal(handled.length, 1);
});
