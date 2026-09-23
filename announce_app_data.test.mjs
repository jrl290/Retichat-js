/**
 * REGRESSION GUARD — the lxmf.delivery announce app_data.
 *
 * LXMF 1.1 announces `[display_name, stamp_cost, supported_functionality]`
 * and senders read SF_COMPRESSION from the third element to decide whether a
 * Resource may be compressed. This client cannot decompress, and names must
 * not be announced (DESIGN_PRINCIPLES.md), so it must announce
 * `[nil, nil, []]`. Until 2026-09-23 it announced the display name and short
 * hash as raw bytes, which peers read as "supports compression": a phone's
 * 650-character message arrived as a compressed Resource and was rejected.
 *
 * Run: node --test announce_app_data.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import MsgPack from "./lib/rns/msgpack.js";

const router = await readFile(new URL("./lib/rns/lxmf/lxmf_router.js", import.meta.url), "utf8");
const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

test("the router announces [nil, nil, []] and nothing else", () => {
    const start = router.indexOf("    announce() {");
    assert.notEqual(start, -1, "announce() takes no name");
    const body = router.slice(start, router.indexOf("\n    }", start));
    assert.match(body, /MsgPack\.pack\(\[null, null, \[\]\]\)/, "app_data is [nil, nil, []]");
    assert.doesNotMatch(body, /displayName|Buffer\.from\(/, "no name bytes in the announce");
    const packed = MsgPack.pack([null, null, []]);
    const back = MsgPack.unpack(packed);
    assert.equal(back.length, 3);
    assert.equal(back[0], null); assert.equal(back[1], null);
    assert.deepEqual(Array.from(back[2]), [], "empty supported-functionality list: no SF_COMPRESSION");
});

test("app.js no longer passes a name to the announce", () => {
    assert.doesNotMatch(app, /_lxmfRouter\.announce\(Buffer/, "the name is gone from the announce call");
    assert.match(app, /_lxmfRouter\.announce\(\)/);
});
