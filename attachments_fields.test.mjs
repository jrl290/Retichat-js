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
