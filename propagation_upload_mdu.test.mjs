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
 * branch on Link.MDU to link.sendResource() before it builds a Packet. The
 * distro's two uploads (the §17.11 sent-copy and the §17.12 membership
 * message) hand their packing to _uploadForDistro, which branches the same
 * way (2026-10-03).
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
    // The live send path and the deferred flush both upload a DM's copy
    // through _propagateMessage, so one site covers both.
    assert.equal(uploadSites().length, 4, "the DM propagated copy (_propagateMessage), the group fallback, the RFed SPEC §17.11 "
        + "distro sent-copy and the §17.12 channel membership message");
});

/** Where a packet of the upload is built or sent, or the upload is handed
 *  to _uploadForDistro, after `from`. */
const PACKET_PATHS = ["new Packet()", "link.send(propagationPacked)", "link.newLinkPacket(Packet.NONE, propagationPacked)"];
const HANDOFF = "this._uploadForDistro(";

/** The source of the method with this exact signature. */
function method(signature) {
    const start = source.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const open = source.indexOf("{", start + signature.length);
    let depth = 0;
    for (let i = open; i < source.length; i++) {
        if (source[i] === "{") depth++;
        else if (source[i] === "}" && --depth === 0) return source.slice(open, i + 1);
    }
    throw new Error(`could not brace-match ${signature}`);
}

/** The over-MDU branch comes before the packet path in `window`, uses
 *  link.sendResource (or _sendWithProgress, which hands it the upload and
 *  reports its progress), and leaves the packet path. */
function assertResourceFirst(window, where) {
    assert.match(window, /propagationPacked\.length > Link\.MDU/, `${where}: no MDU branch before the packet`);
    assert.match(window, /link\.sendResource\(propagationPacked\)|this\._sendWithProgress\(link, propagationPacked,/,
        `${where}: the over-MDU branch must use link.sendResource`);
    assert.match(window, /\n\s+return( null| "resource")?;\n/, `${where}: the Resource branch must not fall through to the packet`);
}

test("each propagation upload sends over the MDU as a Resource, before any packet is built", () => {
    for (const site of uploadSites()) {
        // The window between building the upload and building/sending a
        // packet, or handing it to _uploadForDistro (the §17.11 sent-copy
        // and the §17.12 membership message, since 2026-10-03), which
        // makes the same branch itself.
        const next = [...PACKET_PATHS, HANDOFF]
            .map((needle) => ({ needle, at: source.indexOf(needle, site) }))
            .filter(({ at }) => at !== -1)
            .sort((x, y) => x.at - y.at)[0];
        assert.ok(next, `site at ${site}: no packet path found after it`);
        if (next.needle === HANDOFF) continue;
        assertResourceFirst(source.slice(site, next.at), `site at ${site}`);
    }
    // _uploadForDistro: the branch, before its packet.
    const upload = method("async _uploadForDistro(link, recipientHex, propagationPacked, label)");
    const packetAt = Math.min(...PACKET_PATHS.map((needle) => upload.indexOf(needle)).filter((i) => i !== -1));
    assert.ok(Number.isFinite(packetAt), "_uploadForDistro builds a packet");
    assertResourceFirst(upload.slice(0, packetAt), "_uploadForDistro");
});

test("the distro's uploads are the two that hand their packing to _uploadForDistro", () => {
    const handoffs = [];
    for (let i = source.indexOf(HANDOFF); i !== -1; i = source.indexOf(HANDOFF, i + 1)) handoffs.push(i);
    // The method each hand-off is in: the last method header before it.
    const owner = (at) => [...source.slice(0, at).matchAll(/\n    (?:async )?([_A-Za-z]\w*)\([^)\n]*\) \{/g)].at(-1)?.[1];
    assert.deepEqual(handoffs.map(owner).sort(), ["_sendDistroChannelSync", "_sendDistroSentCopy"]);
});
