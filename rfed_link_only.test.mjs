/**
 * REGRESSION GUARD — a mapped control request never opens a legacy link.
 *
 * RFed-spec/Link.md: one link per subscriber; the legacy per-aspect
 * destinations exist for pre-split clients only. Until 2026-09-23
 * _rfedRequest raced the rfed.link announce against the legacy aspect's and
 * took whichever landed first, so on a freshly started node whose rfed.link
 * announce arrived a second later the client registered over a
 * rfed.distro.register link AND then bound rfed.link, holding two links
 * (stage_browser on the private staging chain). It must wait for rfed.link.
 *
 * app.js cannot be imported under Node (browser importmap), so this reads the
 * source of _rfedRequest.
 *
 * Run: node --test rfed_link_only.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./app.js", import.meta.url), "utf8");

function body(signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} not found`);
    let i = source.indexOf("{", start), depth = 0;
    for (; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}" && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`could not brace-match ${signature}`);
}

test("a mapped path waits for the rfed.link announce and is sent on rfed.link", () => {
    const fn = body("async _rfedRequest(aspects, path, packedValue)");
    const decision = fn.slice(0, fn.indexOf("_ensureRfedLink"));
    assert.match(decision, /RFED_LINK_PATHS\[/, "the mapping table decides which paths are control requests");
    assert.match(decision, /_waitForRfedService\(\["link"\]\)/, "it waits for the rfed.link announce");
    assert.doesNotMatch(decision, /Promise\.race/, "no race against the legacy aspect's announce");
    assert.doesNotMatch(decision, /_waitForRfedService\(aspects\)/, "a mapped path never waits for, or uses, the legacy aspect");
    assert.match(decision, /aspects = \["link"\];\s*path = mapped;/, "the request is rewritten onto rfed.link");
});
