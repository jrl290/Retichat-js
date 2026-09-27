/**
 * REGRESSION GUARD — the lxmf.delivery announce app_data.
 *
 * LXMF 1.1 announces `[display_name, stamp_cost, supported_functionality]`
 * and senders read SF_COMPRESSION from the third element to decide whether a
 * Resource may be compressed. This client cannot decompress, so the third
 * element is always an empty list. Until 2026-09-23 it announced the display
 * name and short hash as raw bytes, which peers read as "supports
 * compression": a phone's 650-character message arrived as a compressed
 * Resource and was rejected.
 *
 * The first element is the Announce Display Name (LXMF-rust/DISPLAY_NAMES.md
 * §2.2): bin when the user has set one, nil otherwise — `[announce_name |
 * nil, nil, []]`, and `[announce_name | nil, nil, [0xD0]]` for the distro.
 * Nothing personal is announced unless the user fills in that public field.
 *
 * Run: node --test announce_app_data.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import EventEmitter from "./lib/rns/utils/events.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

function makeRouter() {
    const announced = [];
    const destination = new EventEmitter();
    destination.hash = Buffer.alloc(16, 7);
    destination.announce = (appData) => announced.push(Buffer.from(appData));
    const router = new LXMRouter({ registerDestination: () => destination }, { hash: Buffer.alloc(16) });
    return { router, announced };
}

test("the router announces [nil, nil, []] while no Announce Display Name is set", () => {
    const { router, announced } = makeRouter();
    router.announce();
    assert.equal(announced.length, 1);
    assert.equal(announced[0].toString("hex"), "93c0c090", "exactly [nil, nil, []]");
    const back = MsgPack.unpack(announced[0]);
    assert.equal(back.length, 3);
    assert.equal(back[0], null); assert.equal(back[1], null);
    assert.deepEqual(Array.from(back[2]), [], "empty supported-functionality list: no SF_COMPRESSION");
});

test("with an Announce Display Name the first element is that name as bin, at once", () => {
    const { router, announced } = makeRouter();
    router.setAnnounceName("Alice");
    router.announce();
    const packed = announced[0];
    assert.equal(packed.toString("hex"), "93c405416c696365c090", "[bin \"Alice\", nil, []]");
    assert.equal(LXMF.displayNameFromAppData(packed), "Alice", "upstream readers see the name");
    router.setAnnounceName(null);
    router.announce();
    assert.equal(announced[1].toString("hex"), "93c0c090", "cleared: the next announce is anonymous again");
    router.setAnnounceName("");
    router.announce();
    assert.equal(announced[2].toString("hex"), "93c0c090", "an empty name is no name");
});

test("app.js hands the router the Announce Display Name, and only that name", () => {
    assert.doesNotMatch(app, /_lxmfRouter\.announce\(Buffer/, "no name passed to announce() itself");
    assert.match(app, /_lxmfRouter\.announce\(\)/);
    assert.match(app, /this\._lxmfRouter\.setAnnounceName\(OwnNames\.announce\);/, "set before the first announce");
    const apply = app.slice(app.indexOf("\n    applyAnnounceName() {"));
    assert.match(apply.slice(0, 600), /this\._lxmfRouter\?\.setAnnounceName\(OwnNames\.announce\)/, "a change applies at once");
    assert.doesNotMatch(app, /setAnnounceName\(OwnNames\.(message|channel)\)/, "never the message or channel name");
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

test("an unnamed distro announce carries no display name", () => {
    assert.equal(LXMF.displayNameFromAppData(MsgPack.pack([null, null, [0xD0]])), null);
});

/** The real _publishDistroAnnounce, capturing the app_data it signs. */
async function distroAppData(announceName) {
    const body = app.slice(app.indexOf("{", app.indexOf("\n    async _publishDistroAnnounce() {")) + 1);
    let depth = 1, end = 0;
    for (let i = 0; i < body.length; i++) {
        if (body[i] === "{") depth++;
        else if (body[i] === "}" && --depth === 0) { end = i; break; }
    }
    let captured = null;
    class Destination {
        static OUT = 1; static SINGLE = 1;
        buildAnnounceData(appData) { captured = Buffer.from(appData); return { announceData: Buffer.alloc(8), contextFlag: 0 }; }
    }
    const identity = { getPublicKey: () => Buffer.alloc(64), sign: () => Buffer.alloc(64) };
    const env = {
        DistroManager: { has: true, identity, hash: "d".repeat(32) },
        Destination, Packet: { FLAG_SET: 1 }, MsgPack, Buffer, LXMF,
        OwnNames: { announce: announceName }, console: { log() {}, warn() {}, error() {} },
    };
    const self = { _rns: {}, _rfedRequest: async () => true };
    const fn = new Function(...Object.keys(env), "self", `return (async () => {${body.slice(0, end).replaceAll("this.", "self.")}})();`);
    assert.equal(await fn(...Object.values(env), self), true);
    return captured;
}

test("_publishDistroAnnounce signs [announce_name | nil, nil, [SF_RFED_DISTRO]]", async () => {
    const unnamed = await distroAppData(null);
    assert.equal(unnamed.toString("hex"), "93c0c091ccd0", "[nil, nil, [0xD0]]");
    assert.equal(LXMF.distroFromAppData(unnamed), true);
    const named = await distroAppData("Alice");
    assert.equal(named.toString("hex"), "93c405416c696365c091ccd0", "[bin \"Alice\", nil, [0xD0]]");
    assert.equal(LXMF.distroFromAppData(named), true, "still recognised as a distro");
    assert.equal(LXMF.displayNameFromAppData(named), "Alice");
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
