/**
 * REGRESSION GUARD — a propagated message larger than one link packet.
 *
 * LXMF/LXMRouter.py's propagation transfer sends an upload that fits the link
 * MDU as one packet and anything larger as a Resource on the propagation
 * link. Until 2026-09-22 both upload sites in app.js (the live send and the
 * deferred flush) built one Packet unconditionally; Packet.pack() threw over
 * the MDU inside a timer callback, so a long message to a distro address
 * (which always propagates) never left the browser and nothing was logged.
 * Found by test-harnesses/staging/stage_large.mjs.
 *
 * app.js cannot be imported under Node (its module graph needs the browser
 * importmap), so this reads the source: every propagation upload site must
 * branch on Link.MDU to link.sendResource() before it builds a Packet.
 *
 * Run: node --test propagation_upload_mdu.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("./app.js", import.meta.url), "utf8");

/** Every place the app builds a propagation upload from `_buildPropagationPacked`. */
function uploadSites() {
    const sites = [];
    let from = 0;
    for (;;) {
        const i = source.indexOf("await this._buildPropagationPacked(", from);
        if (i === -1) break;
        sites.push(i);
        from = i + 1;
    }
    return sites;
}

test("all four propagation upload sites exist", () => {
    assert.equal(uploadSites().length, 4, "the live send path, the deferred flush path, the group fallback, and the RFed SPEC §17.11 distro sent-copy");
});

test("each propagation upload sends over the MDU as a Resource, before any packet is built", () => {
    for (const site of uploadSites()) {
        // The window between building the upload and building/sending a packet.
        const candidates = ["new Packet()", "link.send(propagationPacked)"]
            .map((needle) => source.indexOf(needle, site))
            .filter((i) => i !== -1);
        assert.ok(candidates.length > 0, `site at ${site}: no packet path found after it`);
        const window = source.slice(site, Math.min(...candidates));
        assert.match(window, /propagationPacked\.length > Link\.MDU/, `site at ${site}: no MDU branch before the packet`);
        assert.match(window, /link\.sendResource\(propagationPacked\)/, `site at ${site}: the over-MDU branch must use link.sendResource`);
        // The branch must leave the packet path: return in the send path, the group
        // fallback and the §17.11 sent-copy, continue in the flush loop.
        assert.match(window, /\n\s+(return( null)?|continue);\n/, `site at ${site}: the Resource branch must not fall through to the packet`);
    }
});
