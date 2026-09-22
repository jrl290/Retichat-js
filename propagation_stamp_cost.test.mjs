/**
 * The propagation stamp target comes from the node's announce.
 *
 * LXMF/LXMRouter.py get_outbound_propagation_cost() reads pn_config[5][0]
 * from the propagation node's announce data, which LXMF.pn_announce_data_is_valid
 * requires to be the 7-element [legacy, timebase, state, transfer_limit,
 * sync_limit, [stamp_cost, flexibility, peering_cost], metadata]. Until
 * 2026-09-22 this client mined to a hard-coded 13 bits (rfed's default 16
 * minus flexibility 3), which only worked while the node's policy matched
 * that guess.
 *
 * app.js cannot be imported under Node, so the two methods are lifted from
 * source and run against stubs. Run: node --test propagation_stamp_cost.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import MsgPack from "./lib/rns/msgpack.js";

const source = await readFile(new URL("./app.js", import.meta.url), "utf8");

function extractMethod(signature) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}") { depth--; if (depth === 0) return source.slice(bodyStart + 1, i); }
    }
    throw new Error(`could not brace-match ${signature}`);
}

function lift(signature, self, globals) {
    const params = signature.slice(signature.indexOf("(") + 1, signature.indexOf(")")).split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(globals);
    const fn = new Function(...params, ...names, "self", extractMethod(signature).replaceAll("this.", "self."));
    return (...args) => fn(...args, ...names.map((n) => globals[n]), self);
}

const announce = (stampCost, flexibility, extra = {}) => MsgPack.pack([
    false, 1790000000, true, 256, 1024, [stampCost, flexibility, 18], new Map([[0, Buffer.from("staging")]]),
]);

test("a valid propagation-node announce yields its stamp cost and flexibility", () => {
    const parse = lift("_parsePropagationNodeAnnounce(appData)", {}, { MsgPack, Buffer, Number });
    assert.deepEqual(parse(announce(16, 3)), { stampCost: 16, flexibility: 3 });
    assert.deepEqual(parse(announce(0, 0)), { stampCost: 0, flexibility: 0 }, "a zero cost is a valid answer, not a missing one");
});

test("announce data that LXMF would reject yields null", () => {
    const parse = lift("_parsePropagationNodeAnnounce(appData)", {}, { MsgPack, Buffer, Number });
    assert.equal(parse(null), null);
    assert.equal(parse(Buffer.alloc(0)), null);
    assert.equal(parse(Buffer.from("not msgpack")), null);
    // Six elements: a deprecated LXMF version (pn_announce_data_is_valid: len < 7).
    assert.equal(parse(MsgPack.pack([false, 1, true, 256, 1024, [16, 3, 18]])), null);
    assert.equal(parse(MsgPack.pack([false, 1, true, 256, 1024, "costs", new Map()])), null, "stamp costs must be a list");
});

test("the stamp target is the announced cost, with rfed's default when nothing is known", () => {
    const stored = {};
    const sGet = (k) => stored[k] ?? null;
    const target = (cfg) => lift("_propagationStampTarget()", { _cfg: cfg }, { sGet, Number })();
    assert.equal(target({ propagationStampCost: 12 }), 12);
    assert.equal(target({ propagationStampCost: 0 }), 0, "an announced zero cost means no work");
    stored.propagationStampCost = "9"; // persisted across reloads as a JSON string
    assert.equal(target({}), 9);
    delete stored.propagationStampCost;
    assert.equal(target({}), 16, "rfed's default policy until the announce arrives");
});
