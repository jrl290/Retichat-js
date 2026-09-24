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
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";

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

/*
 * DISTRO FLAG AND TRANSFER FIELDS — RFed SPEC §17.10 / §17.9.
 *
 * A distro address is recognised only by SF_RFED_DISTRO (0xD0) in the
 * supported_functionality list of its lxmf.delivery announce, whose app_data
 * is exactly [nil, nil, [0xD0]]. An lxma://hash:pubkey link carries a key and
 * nothing more. The identity transfer uses upstream's FIELD_CUSTOM_TYPE /
 * FIELD_CUSTOM_DATA pair; 0x0D is upstream FIELD_EVENT and is never used.
 */

test("distroFromAppData is true only for SF_RFED_DISTRO in the third element", () => {
    assert.equal(LXMF.SF_RFED_DISTRO, 0xD0);
    assert.equal(LXMF.distroFromAppData(MsgPack.pack([null, null, [0xD0]])), true);
    assert.equal(LXMF.distroFromAppData(MsgPack.pack(["name", 8, [0x01, 0xD0]])), true, "alongside other flags");
    assert.equal(LXMF.distroFromAppData(MsgPack.pack([null, null, []])), false);
    assert.equal(LXMF.distroFromAppData(MsgPack.pack([null, null, [0]])), false);
    assert.equal(LXMF.distroFromAppData(MsgPack.pack([null, null])), false, "short list");
    assert.equal(LXMF.distroFromAppData(MsgPack.pack([null, null, 0xD0])), false, "third element not a list");
    assert.equal(LXMF.distroFromAppData(Buffer.from("Alice")), false, "original raw-bytes format");
    assert.equal(LXMF.distroFromAppData(Buffer.alloc(0)), false);
    assert.equal(LXMF.distroFromAppData(undefined), false);
    assert.equal(LXMF.distroFromAppData(null), false);
});

test("the distro announce carries no display name", () => {
    assert.equal(LXMF.displayNameFromAppData(MsgPack.pack([null, null, [0xD0]])) ?? null, null);
});

test("_publishDistroAnnounce signs [nil, nil, [SF_RFED_DISTRO]] as its app_data", () => {
    const start = app.indexOf("async _publishDistroAnnounce() {");
    assert.notEqual(start, -1);
    const body = app.slice(start, app.indexOf("\n    },", start));
    assert.match(body, /MsgPack\.pack\(\[null, null, \[LXMF\.SF_RFED_DISTRO\]\]\)/);
    assert.doesNotMatch(body, /buildAnnounceData\(null\)/, "the announce must carry the flag");
});

test("an lxma:// link does not make a contact a distro", () => {
    assert.doesNotMatch(app, /isDistro = true/, "nothing infers isDistro from the link format");
    const updater = app.slice(app.indexOf("updateFromAnnounce(destHash, announce) {"));
    assert.match(updater.slice(0, 1500), /LXMF\.distroFromAppData\(announce\.appData\)/,
        "the announce is the source of truth");
});

test("the identity transfer uses the custom field pair, never 0x0D", () => {
    assert.equal(LXMF.FIELD_CUSTOM_TYPE, 0xFB);
    assert.equal(LXMF.FIELD_CUSTOM_DATA, 0xFC);
    assert.equal(LXMF.DISTRO_TRANSFER_TYPE, "rfed.distro.transfer");
    assert.doesNotMatch(app, /FIELD_DISTRO_ID|fields\.(get|set)\(0x0D/i);

    const key = "ab".repeat(64);
    const sent = new Map([[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_TRANSFER_TYPE], [LXMF.FIELD_CUSTOM_DATA, key]]);
    const received = MsgPack.unpack(MsgPack.pack(sent));
    assert.equal(LXMF.distroTransferKeyFromFields(received), key);

    // A peer may send msgpack bin rather than str.
    const asBin = new Map([
        [LXMF.FIELD_CUSTOM_TYPE, Buffer.from(LXMF.DISTRO_TRANSFER_TYPE)],
        [LXMF.FIELD_CUSTOM_DATA, Buffer.from(key)],
    ]);
    assert.equal(LXMF.distroTransferKeyFromFields(MsgPack.unpack(MsgPack.pack(asBin))), key);

    assert.equal(LXMF.distroTransferKeyFromFields(new Map([[0x0D, key]])), null, "0x0D is FIELD_EVENT, not a transfer");
    assert.equal(LXMF.distroTransferKeyFromFields(new Map([[LXMF.FIELD_CUSTOM_TYPE, "other"], [LXMF.FIELD_CUSTOM_DATA, key]])), null);
    assert.equal(LXMF.distroTransferKeyFromFields(null), null);
});
