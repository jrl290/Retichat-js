/**
 * ATTACHMENT FIELDS — what a received LXMF message carries besides its text,
 * read on every path through one decoder (lib/rns/lxmf/lxmf.js
 * attachmentsFromFields, LXMessage.decodePayload).
 *
 *   FIELD_FILE_ATTACHMENTS 0x05 = [[filename, data], ...]   iOS, Android
 *   FIELD_IMAGE            0x06 = [image_type, data]        Sideband, MeshChat
 *   FIELD_AUDIO            0x07 = [audio_mode, data]        offered as a file
 *
 * The decoder never throws: an entry of the wrong shape is skipped and
 * counted, and a fields map msgpack cannot decode at all costs the fields,
 * never the message (Android dcc3e46, 702e5fb). Parity: iOS Models.swift
 * Attachment.isImage (the image extensions), Android LxmfFields.kt
 * getFileAttachments (a filename of neither str nor bin is
 * "attachment.bin"; data that is not bin is skipped).
 *
 * Run: node --test attachments_fields.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMF, {
    attachmentsFromFields, carriesAttachment, isImageAttachment, mimeForName, IMAGE_EXTENSIONS,
    FIELD_FILE_ATTACHMENTS, FIELD_IMAGE, FIELD_AUDIO, FIELD_TICKET,
} from "./lib/rns/lxmf/lxmf.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Cryptography from "./lib/rns/cryptography.js";
import { channelIdentity, channelDeliveryHash, channelLxmUnpack } from "./lib/rns/rfed_channel.js";

const bytes = (n, fill = 7) => Buffer.alloc(n, fill);
const shape = (list) => list.map(({ name, mime, bytes: b, field }) => ({ name, mime, size: b.length, field }));

test("the field numbers are LXMF's", () => {
    assert.deepEqual([FIELD_FILE_ATTACHMENTS, FIELD_IMAGE, FIELD_AUDIO, FIELD_TICKET], [0x05, 0x06, 0x07, 0x0C]);
    assert.deepEqual([LXMF.FIELD_FILE_ATTACHMENTS, LXMF.FIELD_IMAGE, LXMF.FIELD_AUDIO], [0x05, 0x06, 0x07]);
});

test("0x05: every [filename, data] pair, the filename as str or bin, as iOS and Android send them", () => {
    const fields = new Map([[0x05, [
        ["photo_1727712345.jpg", bytes(3000, 1)],
        [Buffer.from("notes.pdf"), bytes(10, 2)],
        ["IMG.HEIC", bytes(5, 3)],
    ]]]);
    const got = attachmentsFromFields(fields);
    assert.deepEqual(shape(got), [
        { name: "photo_1727712345.jpg", mime: "image/jpeg", size: 3000, field: 5 },
        { name: "notes.pdf", mime: "application/pdf", size: 10, field: 5 },
        { name: "IMG.HEIC", mime: "image/heic", size: 5, field: 5 },
    ]);
    assert.equal(got.skipped, 0);
    assert.ok(got[0].bytes.equals(bytes(3000, 1)), "the bytes as sent, not a copy of something else");
});

test("0x06: [image_type, data], named by its type; 0x07: [audio_mode, data], a file", () => {
    const got = attachmentsFromFields(new Map([
        [0x06, ["png", bytes(64)]],
        [0x07, [0x10, bytes(32)]],
    ]));
    assert.deepEqual(shape(got), [
        { name: "png", mime: "image/png", size: 64, field: 6 },
        { name: "audio.ogg", mime: "audio/ogg", size: 32, field: 7 },
    ]);
    assert.deepEqual(shape(attachmentsFromFields(new Map([[0x06, ["jpg", bytes(1)]]]))), [{ name: "jpg", mime: "image/jpeg", size: 1, field: 6 }]);
    assert.deepEqual(shape(attachmentsFromFields(new Map([[0x06, [Buffer.from("webp"), bytes(1)]]]))), [{ name: "webp", mime: "image/webp", size: 1, field: 6 }]);
    assert.deepEqual(shape(attachmentsFromFields(new Map([[0x07, [0x04, bytes(1)]]]))), [{ name: "audio.c2", mime: "application/octet-stream", size: 1, field: 7 }],
        "Codec2 (LXMF AM_CODEC2_*) is raw frames: a file to download");
});

test("0x06's MIME type is never built from the sender's image type: anything but our raster images is a download", () => {
    // image/svg+xml opened in a tab is a document whose script runs on the
    // page's origin and reads the identity key (review of adee619).
    for (const type of ["svg+xml", "image/svg+xml", "SVG+XML", " image/SVG+xml ", "html", "text/html", "xhtml+xml", "bmp", ""]) {
        const [a] = attachmentsFromFields(new Map([[0x06, [type, bytes(8)]]]));
        assert.equal(a.mime, "application/octet-stream", JSON.stringify(type));
        assert.equal(a.field, 6, "still an image to try in an <img>");
    }
    for (const [type, mime] of [["png", "image/png"], ["image/png", "image/png"], ["JPEG", "image/jpeg"], ["gif", "image/gif"], ["heic", "image/heic"]]) {
        assert.equal(attachmentsFromFields(new Map([[0x06, [type, bytes(8)]]]))[0].mime, mime, type);
    }
});

test("a malformed entry is skipped and counted; the rest of the message, and its good entries, survive", () => {
    const fields = new Map([
        [0x05, [
            ["good.png", bytes(4)],
            ["no-data"],                     // too short
            ["text-data.png", "not bytes"],  // data must be bin (Android: skipped)
            [42, bytes(2)],                  // a filename of neither str nor bin (Android: "attachment.bin")
            "not a pair",
        ]],
        [0x06, ["png"]],                     // no data
        [0x07, [0x10, "str"]],               // data not bin
        [0xD1, new Map([[0, Buffer.from("Name")]])],
    ]);
    const got = attachmentsFromFields(fields);
    assert.deepEqual(shape(got), [
        { name: "good.png", mime: "image/png", size: 4, field: 5 },
        { name: "attachment.bin", mime: "application/octet-stream", size: 2, field: 5 },
    ]);
    assert.equal(got.skipped, 5);
    assert.deepEqual(Object.keys(got), ["0", "1"], "skipped is not an enumerable entry");
});

test("a hostile fields map costs nothing but its attachments: the decoder never throws", () => {
    for (const fields of [null, undefined, 5, "x", [], {}, new Map(), new Map([[0x05, null]]), new Map([[0x05, 7]]),
        new Map([[0x05, new Map()]]), new Map([[0x06, null]]), new Map([[0x07, {}]])]) {
        const got = attachmentsFromFields(fields);
        assert.deepEqual([...got], []);
    }
    assert.equal(attachmentsFromFields(new Map([[0x05, 7]])).skipped, 1, "a 0x05 that is not a list counts as unreadable");
    const throwing = new Map([[0x05, []]]);
    throwing.get = () => { throw new Error("hostile accessor"); };
    assert.deepEqual([...attachmentsFromFields(throwing)], []);
    assert.equal(attachmentsFromFields(throwing).skipped, 1);
});

test("an image is a FIELD_IMAGE, or a file with one of iOS's image extensions; anything else is a file", () => {
    assert.deepEqual(IMAGE_EXTENSIONS, ["jpg", "jpeg", "png", "gif", "webp", "heic"], "iOS Attachment.isImage");
    for (const name of ["a.jpg", "b.JPEG", "c.png", "d.gif", "e.webp", "f.HEIC"]) {
        assert.equal(isImageAttachment({ name, field: 5 }), true, name);
    }
    for (const name of ["a.pdf", "b.ogg", "c", "png", "d.jpg.zip", ".png"]) {
        assert.equal(isImageAttachment({ name, field: 5 }), false, name);
    }
    assert.equal(isImageAttachment({ name: "anything", field: 6 }), true, "0x06 is shown whatever its type");
    assert.equal(isImageAttachment({ name: "audio.ogg", field: 7 }), false, "0x07 is offered as a file");
    assert.equal(mimeForName("x.unknown"), "application/octet-stream");
});

test("carriesAttachment: 0x05, 0x06 or 0x07 present, whatever is in it (LXMF-rust 06c40e1)", () => {
    assert.equal(carriesAttachment(new Map([[0x05, []]])), true);
    assert.equal(carriesAttachment(new Map([[0x06, null]])), true);
    assert.equal(carriesAttachment(new Map([[0x07, 1]])), true);
    assert.equal(carriesAttachment(new Map([[0x0C, "0123456789abcdef"], [0xD1, new Map()]])), false);
    assert.equal(carriesAttachment(null), false);
});

// ── through the wire: LXMessage.fromBytes on every router path ─────────────

const lxmfHash = (identity) => Destination.hash(identity, "lxmf", "delivery");
let clock = 1_790_000_000;

function packed(from, to, content, fields) {
    const m = new LXMessage();
    m.timestamp = (clock += 1);
    m.sourceHash = lxmfHash(from);
    m.destinationHash = lxmfHash(to);
    m.title = "";
    m.content = content;
    m.fields = fields;
    return m.pack(from, false);
}

/** A full packing whose fields map (element 3) is replaced by `rawFields`. */
function packedWithRawFields(from, to, content, rawFields) {
    const head = MsgPack.pack([(clock += 1), Buffer.alloc(0), Buffer.from(content)]);
    const payload = Buffer.concat([Buffer.from([0x94]), head.subarray(1), rawFields]);
    const dest = lxmfHash(to);
    const src = lxmfHash(from);
    const hashedPart = Buffer.concat([dest, src, payload]);
    const signature = from.sign(Buffer.concat([hashedPart, LXMessage.hashOf(dest, src, payload)]));
    return Buffer.concat([dest, src, signature, payload]);
}

test("fromBytes reads a message's attachments, whatever path brought it", () => {
    const from = Identity.create(), to = Identity.create();
    const photo = bytes(5000, 9);
    const p = packed(from, to, "", new Map([[0x0C, "0123456789abcdef"], [0x05, [["cat.png", photo]]]]));
    const recall = (h) => (h.equals(lxmfHash(from)) ? from : null);
    const m = LXMessage.fromBytes(p.subarray(16), p.subarray(0, 16), recall);
    assert.equal(m.content, "");
    assert.equal(m.signatureValidated, true);
    assert.deepEqual(shape(m.attachments), [{ name: "cat.png", mime: "image/png", size: 5000, field: 5 }]);
    assert.ok(Buffer.from(m.attachments[0].bytes).equals(photo));
    assert.equal(m.fieldsUnreadable, null);
});

test("Android's reviewed hostile map {1: ext(0, dd 7f ff ff ff), 2: 3, 4: 5} keeps the text", () => {
    // DistroAttachmentsTest (Android 702e5fb): fields gwHHBQDdf////wIDBAU=.
    const from = Identity.create(), to = Identity.create();
    const p = packedWithRawFields(from, to, "hello, keep this text", Buffer.from("gwHHBQDdf////wIDBAU=", "base64"));
    const recall = (h) => (h.equals(lxmfHash(from)) ? from : null);
    const m = LXMessage.fromBytes(p.subarray(16), p.subarray(0, 16), recall);
    assert.ok(m, "the message survives");
    assert.equal(m.content, "hello, keep this text");
    assert.equal(m.signatureValidated, true, "signed over the bytes as sent");
    assert.deepEqual([...m.attachments], []);
});

test("a fields map msgpack cannot decode at all costs the fields and is said to, never the message", () => {
    // msgpackr throws "Unknown extension" on an ext type it has no reader for;
    // until 2026-09-30 fromBytes then returned null and the message was lost.
    const from = Identity.create(), to = Identity.create();
    const unknownExt = Buffer.from([0x82, 0x05, 0xd4, 0x01, 0x00, 0x01, 0x02]);   // {5: ext(1, 00), 1: 2}
    assert.throws(() => MsgPack.unpack(Buffer.concat([Buffer.from([0x91]), unknownExt])), /extension/i, "the premise: msgpackr refuses it");
    const p = packedWithRawFields(from, to, "the text stays", unknownExt);
    const recall = (h) => (h.equals(lxmfHash(from)) ? from : null);
    const m = LXMessage.fromBytes(p.subarray(16), p.subarray(0, 16), recall);
    assert.ok(m, "kept");
    assert.equal(m.content, "the text stays");
    assert.equal(m.signatureValidated, true);
    assert.deepEqual([...m.fields.keys()], [], "no fields");
    assert.match(m.fieldsUnreadable, /extension/i, "and the reason is kept for the bubble");
    assert.ok(m.hash.equals(LXMessage.hashOf(p.subarray(0, 16), p.subarray(16, 32), p.subarray(96))), "the hash of the bytes as sent");
});

test("a payload whose text cannot be read is still no message", () => {
    // decodePayload falls back only past the third element.
    const bad = Buffer.from([0x94, 0xcb, 0, 0, 0, 0, 0, 0, 0, 0, 0xc4, 0x00, 0xd4, 0x01, 0x00, 0x80]);
    assert.throws(() => LXMessage.decodePayload(bad));
    assert.throws(() => LXMessage.decodePayload(Buffer.from([0xc1])));
});

// ── field keys as the phones read them (RFed SPEC §17.14) ──────────────────
//
// LXMF-rust (key_is, as_u64), Android (LxmfFields.readMap) and iOS (readKey)
// read a field number from a msgpack integer of any width, and never from a
// float. msgpackr gives an integral float key as the number it equals and a
// 64-bit integer key as a BigInt, so until 2026-10-11 the web read float 5.0
// as an attachment and missed uint 64 5.

/** Key `k` (0..127) in each integer encoding a sender may choose. */
const INTEGER_KEYS = {
    "positive fixint": (k) => [k],
    "uint 8": (k) => [0xcc, k],
    "uint 16": (k) => [0xcd, 0, k],
    "uint 32": (k) => [0xce, 0, 0, 0, k],
    "uint 64": (k) => [0xcf, 0, 0, 0, 0, 0, 0, 0, k],
    "int 8": (k) => [0xd0, k],
    "int 16": (k) => [0xd1, 0, k],
    "int 32": (k) => [0xd2, 0, 0, 0, k],
    "int 64": (k) => [0xd3, 0, 0, 0, 0, 0, 0, 0, k],
};
/** Key `k` as a float, which is no field on either phone. */
const FLOAT_KEYS = {
    "float 32": (k) => { const b = Buffer.alloc(5); b[0] = 0xca; b.writeFloatBE(k, 1); return [...b]; },
    "float 64": (k) => { const b = Buffer.alloc(9); b[0] = 0xcb; b.writeDoubleBE(k, 1); return [...b]; },
};
/** A fields map of the entries [key bytes, value] given, the values packed as msgpackr packs them. */
const rawMap = (entries) => Buffer.concat([Buffer.from([0x80 | entries.length]),
    ...entries.flatMap(([k, v]) => [Buffer.from(k), Buffer.from(MsgPack.pack(v))])]);
const WEB = "0123456789abcdef";
const recallOf = (from) => (h) => (h.equals(lxmfHash(from)) ? from : null);
const receive = (from, to, content, fieldsBytes) => {
    const p = packedWithRawFields(from, to, content, fieldsBytes);
    return LXMessage.fromBytes(p.subarray(16), p.subarray(0, 16), recallOf(from));
};
const ATTACHMENT_FIELDS = [[0x05, [["a.png", bytes(20, 5)]]], [0x06, ["png", bytes(20, 6)]], [0x07, [0x10, bytes(20, 7)]]];

test("attachments 0x05, 0x06 and 0x07 are read under an integer key of any width, uint 64 and int 64 included, and never under a float key, as both phones read them", () => {
    const from = Identity.create(), to = Identity.create();
    for (const [name, key] of Object.entries(INTEGER_KEYS)) {
        for (const [field, value] of ATTACHMENT_FIELDS) {
            const m = receive(from, to, "", rawMap([[key(field), value]]));
            assert.deepEqual(m.attachments.map((a) => a.field), [field], `${name} ${field}`);
            assert.deepEqual([...m.fields.keys()], [field], `${name} ${field}: the key is the number`);
            assert.equal(LXMessage.decodePayload(packedWithRawFields(from, to, "", rawMap([[key(field), value]])).subarray(96)).attachments.length, 1);
        }
    }
    for (const [name, key] of Object.entries(FLOAT_KEYS)) {
        for (const [field, value] of ATTACHMENT_FIELDS) {
            const m = receive(from, to, "text", rawMap([[key(field), value]]));
            assert.equal(m.content, "text", "the message stays");
            assert.deepEqual([...m.attachments], [], `${name} ${field}.0 is no field`);
            assert.equal(m.attachments.skipped, 0, "nor a field that could not be read");
            assert.deepEqual([...m.fields.keys()], [], `${name}: no entry under a float key`);
            assert.equal(carriesAttachment(m.fields), false);
        }
    }
});

test("the ticket 0x0C: a delivery notification and the web's own ticket are read under an integer key of any width and never under a float key; an attachment under a uint 64 key keeps a ticketed message a message", () => {
    const from = Identity.create(), to = Identity.create();
    for (const [name, key] of Object.entries(INTEGER_KEYS)) {
        const m = receive(from, to, "", rawMap([[key(0x0C), WEB]]));
        assert.equal(LXMF.isDeliveryNotification(m.fields, m.content), true, name);
        assert.equal(LXMF.webTicket(m.fields), WEB, name);
        // A captionless photo whose attachment key is this width, the ticket a fixint (LXMF-rust 06c40e1).
        const photo = receive(from, to, "", rawMap([[[0x0C], WEB], [key(0x05), [["p.jpg", bytes(9)]]]]));
        assert.equal(LXMF.isDeliveryNotification(photo.fields, photo.content), false, `${name}: a photo, not a notification`);
        assert.equal(photo.attachments.length, 1);
    }
    for (const [name, key] of Object.entries(FLOAT_KEYS)) {
        const m = receive(from, to, "", rawMap([[key(0x0C), WEB]]));
        assert.equal(LXMF.isDeliveryNotification(m.fields, m.content), false, `${name} 12.0 is no ticket`);
        assert.equal(LXMF.webTicket(m.fields), null, name);
    }
});

test("the router remembers a ticket [expires, ticket] under an integer key of any width, and none under a float key", () => {
    const from = Identity.create(), to = Identity.create();
    const ticket = [Date.now() / 1000 + 3600, bytes(16, 4)];
    const remembers = (fieldsBytes) => {
        const router = { outboundTickets: new Map() };
        const m = receive(from, to, "hi", fieldsBytes);
        assert.equal(m.signatureValidated, true);
        return LXMRouter.prototype.rememberTicket.call(router, m) && router.outboundTickets.size === 1;
    };
    for (const [name, key] of Object.entries(INTEGER_KEYS)) assert.equal(remembers(rawMap([[key(0x0C), ticket]])), true, name);
    for (const [name, key] of Object.entries(FLOAT_KEYS)) assert.equal(remembers(rawMap([[key(0x0C), ticket]])), false, name);
});

test("a channel post's fields are keyed the same way (channelLxmUnpack)", () => {
    const sender = Identity.create();
    const post = (fieldsBytes) => {
        const payload = Buffer.concat([Buffer.from("94cb41daab8c00000000c400c40178", "hex"), fieldsBytes]);
        const sourceHash = lxmfHash(sender);
        const hashedPart = Buffer.concat([channelDeliveryHash("general"), sourceHash, payload]);
        const signature = sender.sign(Buffer.concat([hashedPart, Cryptography.fullHash(hashedPart)]));
        const { identity, hash } = channelIdentity("general");
        const data = Buffer.concat([hash, identity.encrypt(Buffer.concat([Buffer.from("RTID"), sender.getPublicKey(), sourceHash, signature, payload]))]);
        const saved = { log: console.log, warn: console.warn };
        console.log = console.warn = () => {};
        try { return channelLxmUnpack("general", data); } finally { Object.assign(console, saved); }
    };
    for (const [name, key] of Object.entries(INTEGER_KEYS)) {
        const got = post(rawMap([[key(0x05), [["a.png", bytes(4)]]]]));
        assert.equal(got?.content, "x", name);
        assert.deepEqual([...got.fields.keys()], [0x05], name);
    }
    for (const [name, key] of Object.entries(FLOAT_KEYS)) {
        assert.deepEqual([...post(rawMap([[key(0x05), [["a.png", bytes(4)]]]])).fields.keys()], [], name);
    }
});

test("every other key is kept as it was: a 64-bit key past 2^53 stays a BigInt (no field), a negative one is its number, a str or bin key is msgpackr's; two NaN keys, one key in a JS Map, cost nothing else", () => {
    const from = Identity.create(), to = Identity.create();
    const m = receive(from, to, "", rawMap([
        [[0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 1],
        [[0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 2],
        [[0xa1, 0x35], 3],                                                   // the str "5"
        [[0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0], 4],
        [[0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0], 5],
        [[0xcf, 0, 0, 0, 0, 0, 0, 0, 0x05], [["a.png", bytes(3)]]],
    ]));
    assert.deepEqual([...m.fields.entries()].map(([k, v]) => [typeof k, String(k), Array.isArray(v) ? "list" : v]),
        [["bigint", "18446744073709551615", 1], ["number", "-1", 2], ["string", "5", 3], ["number", "5", "list"]]);
    assert.deepEqual(m.attachments.map((a) => a.name), ["a.png"]);
    assert.equal(m.fieldsUnreadable, null);
});

// ── the page loads these modules before app.js sets globalThis.Buffer ───────

test("the attachment modules load without Node-only globals (the \"Buffer is not defined\" class)", () => {
    const root = fileURLToPath(new URL("./", import.meta.url));
    const script = `
        delete globalThis.Buffer;
        delete globalThis.process?.binding;
        for (const m of ["./lib/attachment_store.js", "./lib/send_progress.js", "./lib/object_urls.js",
                         "./lib/attachment_limits.js", "./lib/rns/lxmf/lxmf.js"]) {
            await import(m);
        }
        console.log("loaded");`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { cwd: root, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /loaded/);
});
