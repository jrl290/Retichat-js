/**
 * A PHOTO LEAVES WITHOUT WHERE IT WAS TAKEN (James, 2026-10-05: no photo
 * leaves with GPS location, whatever its format). lib/photo_metadata.js
 * withoutLocation(bytes), on every attachment RnsClient.sendMessage sends
 * (attachments_send.test.mjs pins that). Attachments go at their original
 * size (James, 2026-09-30), so nothing is re-encoded: only the metadata that
 * can carry a location goes, every other byte is kept.
 *
 *   JPEG: the GPS IFD leaves EXIF (pointer dropped, its bytes zeroed in
 *   place), Orientation and the rest of EXIF stay, in both byte orders; XMP,
 *   extended XMP, IPTC (APP13) and every APPn a decoder does not need go;
 *   the EXIF thumbnail is cleaned in its place; after EOI only the images an
 *   MPF index lists stay, cleaned, the index rewritten. The tables and scans
 *   are untouched.
 *   PNG: eXIf loses its GPS IFD (CRC recomputed), XMP and the text chunks
 *   that carry EXIF, IPTC or a location go, IDAT is untouched.
 *   WebP: EXIF loses its GPS IFD, XMP goes, the VP8X flags and the RIFF size
 *   follow, the VP8 data is untouched.
 *   Malformed input never throws and never keeps GPS: an EXIF block that
 *   cannot be parsed goes whole, a file cut at any length is safe.
 *   Anything else comes back as given.
 *
 * The photos are built around real images (test_photos.mjs), with sentinel
 * text in every piece of metadata that must go.
 * photo_metadata_decode.test.mjs decodes the results in Chromium.
 *
 * Run: node --test photo_metadata.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { withoutLocation } from "./lib/photo_metadata.js";
import {
    BASE_JPEG, PROGRESSIVE_JPEG, THUMB_JPEG, VP8_CHUNK, SENTINEL, TAG, PNG_PIXELS,
    sentinelsIn, tiffBlock, readTiff, numberOf, gpsEntries,
    segment, exifSegment, xmpSegment, extendedXmpSegment, iptcSegment, iccSegment, adobeSegment, comSegment,
    goproSegment, c2paSegment, duckySegment, isoGainMapSegment, mpfSegment, mpfEntries, gainMapJpeg,
    jpegWith, imageDataOf, jpegSegments, appSegmentNames, exifOf,
    png, pngChunk, pngChunks, pngScanlines, textChunk, XMP_PACKET,
    webp, riffChunk, webpChunks,
} from "./test_photos.mjs";

/** withoutLocation's result, which must be bytes, as a Buffer view. */
function clean(bytes) {
    const out = withoutLocation(bytes);
    assert.ok(out instanceof Uint8Array, `bytes back, not ${out}`);
    return Buffer.from(out.buffer, out.byteOffset, out.length);
}

const segmentsOf = (bytes, marker) => jpegSegments(bytes).segments.filter((s) => s.marker === marker);

/** Every position where `a` and `b` (the same length) differ. */
function differences(a, b) {
    assert.equal(a.length, b.length);
    const at = [];
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) at.push(i);
    return at;
}

// ── JPEG ────────────────────────────────────────────────────────────────────

for (const le of [true, false]) {
    test(`JPEG, ${le ? "little" : "big"}-endian EXIF: the GPS IFD goes, Orientation and the rest of EXIF stay, the image data is untouched`, () => {
        const exif = tiffBlock({ le });
        const kept = [iccSegment(), comSegment(), adobeSegment()];
        const input = jpegWith([exifSegment(exif.block), xmpSegment(), extendedXmpSegment(), iptcSegment(), kept[0], kept[1],
            goproSegment(), c2paSegment(), duckySegment(), segment(0xE1, "QVCI\0", SENTINEL.xmp), kept[2]]);
        assert.deepEqual(sentinelsIn(input).sort(), [SENTINEL.gps, SENTINEL.xmp, SENTINEL.extendedXmp, SENTINEL.iptc, SENTINEL.gopro, SENTINEL.c2pa, SENTINEL.ducky].sort());

        const out = clean(input);
        assert.deepEqual(sentinelsIn(out), [], "no GPS, XMP, IPTC or vendor block is left anywhere");
        assert.deepEqual(appSegmentNames(out), ["E0:JFIF", "E1:Exif", "E2:ICC_PROFILE", "FE", "EE:Adobe"],
            "XMP, extended XMP, APP13, GoPro's APP6, C2PA's APP11, Ducky's APP12 and an unknown APP1 went; JFIF, EXIF, ICC, COM and Adobe stayed");
        for (const [i, marker] of [[0, 0xE2], [1, 0xFE], [2, 0xEE]]) {
            assert.ok(segmentsOf(out, marker)[0].payload.equals(kept[i].subarray(4)), `the ${marker.toString(16)} segment byte for byte`);
        }
        assert.ok(out.subarray(2, 20).equals(BASE_JPEG.subarray(2, 20)), "APP0 JFIF byte for byte");
        assert.ok(out.subarray(out.length - imageDataOf(BASE_JPEG).length).equals(imageDataOf(BASE_JPEG)), "tables, scan and EOI byte for byte");
        assert.equal(jpegSegments(out).end, out.length, "it parses to its EOI, and nothing follows");

        // EXIF: the same length, Orientation and everything else readable.
        const tiff = exifOf(out);
        assert.equal(tiff.length, exif.block.length, "in place: every offset in the block still holds");
        const read = readTiff(tiff);
        assert.equal(read.le, le);
        assert.equal(numberOf(read.ifd0.get(TAG.Orientation), le), 6, "Orientation kept: the photo stays upright");
        assert.equal(read.ifd0.get(TAG.Make).value.toString("latin1"), "Retichat Test Camera\0");
        assert.equal(read.exif.get(TAG.DateTimeOriginal).value.toString("latin1"), "2026:10:05 12:00:00\0");
        assert.equal(read.ifd0.has(TAG.GPSInfo), false, "no GPSInfo pointer");
        assert.equal(read.gps, undefined);
        // Only IFD0's entries (one fewer) and the GPS IFD with its values changed.
        const ifd0End = exif.at.ifd0 + 2 + 12 * 5 + 4;
        for (const i of differences(exif.block, tiff)) {
            assert.ok((i >= exif.at.ifd0 && i < ifd0End) || i >= exif.at.gps, `byte ${i} changed outside IFD0 and the GPS IFD`);
        }
        assert.ok(tiff.subarray(exif.at.gps).every((b) => b === 0), "the GPS IFD and its values are zeros");

        assert.equal(withoutLocation(out), out, "nothing is left to remove: the same object comes back");
    });
}

test("progressive JPEG: metadata between its scans goes too, every table and scan is kept", () => {
    const base = jpegWith([exifSegment(tiffBlock().block)], { base: PROGRESSIVE_JPEG });
    const firstScanEnd = jpegSegments(base).segments.find((s) => s.marker === "scan").end;
    const input = Buffer.concat([base.subarray(0, firstScanEnd), xmpSegment(), iptcSegment(), comSegment("between scans"), base.subarray(firstScanEnd)]);
    const out = clean(input);
    assert.deepEqual(sentinelsIn(out), []);
    const imageParts = (bytes) => jpegSegments(bytes).segments.filter((s) => !(s.marker >= 0xE0 && s.marker <= 0xEF))
        .map((s) => Buffer.from(bytes).subarray(s.start, s.end).toString("hex"));
    assert.deepEqual(imageParts(out), imageParts(input), "every table, scan header, scan and COM, in order, byte for byte");
    assert.equal(jpegSegments(input).segments.filter((s) => s.marker === "scan").length, 10);
    assert.equal(numberOf(readTiff(exifOf(out)).ifd0.get(TAG.Orientation), true), 6);
});

test("the EXIF thumbnail is cleaned where it is: its own GPS and XMP go, it stays a JPEG of the length IFD1 gives", () => {
    const thumbnail = jpegWith([exifSegment(tiffBlock({ exif: false, orientation: 1, gps: gpsEntries(SENTINEL.thumbGps) }).block), xmpSegment()], { base: THUMB_JPEG });
    const exif = tiffBlock({ le: false, thumbnail });
    const out = clean(jpegWith([exifSegment(exif.block)]));
    assert.deepEqual(sentinelsIn(out), []);
    const tiff = exifOf(out);
    const read = readTiff(tiff);
    assert.equal(numberOf(read.ifd0.get(TAG.Orientation), false), 6);
    const offset = numberOf(read.ifd1.get(TAG.ThumbnailOffset), false);
    const length = numberOf(read.ifd1.get(TAG.ThumbnailLength), false);
    assert.equal(offset, exif.at.thumbnail, "where it was");
    assert.equal(length, thumbnail.length - xmpSegment().length, "shorter by its XMP, and IFD1 says so");
    const thumb = tiff.subarray(offset, offset + length);
    assert.equal(jpegSegments(thumb).end, length, "a JPEG that ends at its EOI");
    assert.deepEqual(appSegmentNames(thumb), ["E0:JFIF", "E1:Exif"]);
    assert.equal(readTiff(exifOf(thumb)).ifd0.has(TAG.GPSInfo), false);
    assert.ok(thumb.subarray(length - imageDataOf(THUMB_JPEG).length).equals(imageDataOf(THUMB_JPEG)), "its image data byte for byte");
    assert.ok(tiff.subarray(offset + length, offset + thumbnail.length).every((b) => b === 0), "the room it freed is zeros");
});

test("after EOI: a trailer goes (a motion photo's video, Samsung's trailer)", () => {
    const input = jpegWith([exifSegment(tiffBlock().block)], { trailer: `\0\0\0\x18ftypmp42 SEFH ${SENTINEL.trailer} SEFT` });
    const out = clean(input);
    assert.deepEqual(sentinelsIn(out), []);
    assert.equal(jpegSegments(out).end, out.length, "it ends at its EOI");
    assert.ok(out.subarray(out.length - imageDataOf(BASE_JPEG).length).equals(imageDataOf(BASE_JPEG)));
});

test("an MPF index keeps its images: each cleaned, the index rewritten to where they now are; what lies between and after goes", () => {
    const { bytes, gainMap } = gainMapJpeg();
    const before = mpfEntries(bytes);
    assert.ok(bytes.subarray(before.base + before.images[1].offset, before.base + before.images[1].offset + 2).equals(Buffer.from([0xFF, 0xD8])));
    const out = clean(bytes);
    assert.deepEqual(sentinelsIn(out), [], "no GPS in the photo or its gain map, no XMP, no video, no trailer");
    assert.deepEqual(appSegmentNames(out), ["E0:JFIF", "E1:Exif", "E2:MPF", "E2:urn:iso:std:iso:ts:21496:-1"]);
    const primaryEnd = jpegSegments(out).end;
    const { base, images } = mpfEntries(out);
    assert.equal(images[0].size, primaryEnd, "the photo's own entry: its new length");
    assert.equal(images[0].offset, 0);
    assert.equal(base + images[1].offset, primaryEnd, "the gain map right after the photo: the video between went");
    assert.equal(base + images[1].offset + images[1].size, out.length, "and the trailer after it went");
    const map = out.subarray(base + images[1].offset);
    assert.equal(jpegSegments(map).end, map.length, "the gain map is a JPEG that ends where its entry says");
    assert.deepEqual(appSegmentNames(map), ["E0:JFIF", "E1:Exif", "E2:urn:iso:std:iso:ts:21496:-1"], "its XMP went, its ISO 21496-1 parameters stayed");
    assert.equal(readTiff(exifOf(map)).ifd0.has(TAG.GPSInfo), false);
    assert.ok(map.subarray(map.length - imageDataOf(THUMB_JPEG).length).equals(imageDataOf(THUMB_JPEG)), "its image data byte for byte");
    assert.ok(gainMap.length > map.length);
    assert.equal(withoutLocation(out), out, "nothing is left to remove");
});

test("an MPF index that does not describe the file goes, and with it everything after EOI", () => {
    for (const entries of [
        [{ size: 1, offset: 0 }, { size: 400, offset: 99_999 }],                // past the end
        [{ size: 1, offset: 0 }, { size: 40, offset: 10 }],                     // inside the photo
        [{ size: 1, offset: 5 }],                                               // the photo's own entry not at 0
    ]) {
        const input = jpegWith([exifSegment(tiffBlock().block), mpfSegment(entries)], { trailer: `\xFF\xD8\xFF ${SENTINEL.trailer}` });
        const out = clean(input);
        assert.deepEqual(appSegmentNames(out), ["E0:JFIF", "E1:Exif"], JSON.stringify(entries));
        assert.equal(jpegSegments(out).end, out.length);
        assert.deepEqual(sentinelsIn(out), []);
    }
});

// ── PNG ─────────────────────────────────────────────────────────────────────

for (const [le, header] of [[true, ""], [false, ""], [true, "Exif\0\0"]]) {
    test(`PNG, ${le ? "little" : "big"}-endian eXIf${header ? " behind \"Exif\\0\\0\"" : ""}: the GPS IFD goes and Orientation stays (CRC anew); XMP, raw profiles, location text, C2PA and pre-standard EXIF go; IDAT is untouched`, () => {
        const exif = tiffBlock({ le });
        const comment = textChunk("tEXt", "Comment", "a comment the user wrote");
        const time = pngChunk("tIME", Buffer.from([7, 234, 10, 5, 12, 0, 0]));
        const physical = pngChunk("pHYs", Buffer.from([0, 0, 0x0B, 0x13, 0, 0, 0x0B, 0x13, 1]));
        const input = png({
            before: [
                pngChunk("eXIf", Buffer.concat([Buffer.from(header, "latin1"), exif.block])),
                textChunk("iTXt", "XML:com.adobe.xmp", XMP_PACKET),
                textChunk("zTXt", "Raw profile type exif", `\nexif\n  40\n${SENTINEL.rawProfile}`),
                textChunk("tEXt", "Raw profile type iptc", `\niptc\n  40\n${SENTINEL.iptc}`),
                textChunk("tEXt", "GPSLocation", SENTINEL.location),
                textChunk("iTXt", "Location", SENTINEL.location),
                comment, time, physical,
                pngChunk("exIf", tiffBlock({ gps: gpsEntries(SENTINEL.thumbGps) }).block),
                pngChunk("caBX", SENTINEL.c2pa),
                pngChunk("prVW", SENTINEL.vendor),
            ],
            trailer: SENTINEL.trailer,
        });
        const out = clean(input);
        assert.deepEqual(sentinelsIn(out), []);
        const chunks = pngChunks(out);                                      // every CRC checked, nothing after IEND
        assert.deepEqual(chunks.map((c) => c.type), ["IHDR", "eXIf", "tEXt", "tIME", "pHYs", "IDAT", "IEND"],
            "XMP, raw profiles, location text, exIf, caBX and a vendor's chunk went");
        for (const [i, chunk] of [[2, comment], [3, time], [4, physical]]) assert.ok(pngChunk(chunks[i].type, chunks[i].data).equals(chunk), `${chunks[i].type} byte for byte`);
        assert.ok(pngScanlines(out).equals(PNG_PIXELS), "IDAT inflates to the very scanlines");
        assert.ok(chunks[5].data.equals(pngChunks(png()).find((c) => c.type === "IDAT").data), "IDAT byte for byte");
        const data = chunks[1].data;
        assert.equal(data.length, header.length + exif.block.length, "eXIf keeps its length");
        assert.equal(data.subarray(0, header.length).toString("latin1"), header);
        const read = readTiff(data.subarray(header.length));
        assert.equal(numberOf(read.ifd0.get(TAG.Orientation), le), 6, "Orientation kept: browsers rotate a PNG by it");
        assert.equal(read.ifd0.has(TAG.GPSInfo), false);
        assert.equal(read.exif.get(TAG.DateTimeOriginal).value.toString("latin1"), "2026:10:05 12:00:00\0");
        assert.equal(withoutLocation(out), out, "nothing is left to remove");
    });
}

// ── WebP ────────────────────────────────────────────────────────────────────

for (const header of ["", "Exif\0\0"]) {
    test(`WebP${header ? ", EXIF behind \"Exif\\0\\0\"" : ""}: the GPS IFD leaves EXIF and Orientation stays; XMP goes with its VP8X flag; the RIFF size follows; the VP8 data is untouched`, () => {
        const exif = tiffBlock();
        const input = webp([riffChunk("EXIF", Buffer.concat([Buffer.from(header, "latin1"), exif.block])), riffChunk("XMP ", XMP_PACKET), riffChunk("ZZZZ", SENTINEL.vendor)]);
        assert.equal(webpChunks(input).flags, 0x08 | 0x04);
        const out = clean(input);
        assert.deepEqual(sentinelsIn(out), []);
        const { flags, chunks } = webpChunks(out);                          // the RIFF size is the file's, every chunk fits
        assert.deepEqual(chunks.map((c) => c.fourcc), ["VP8X", "VP8 ", "EXIF"], "XMP and a chunk no decoder reads went");
        assert.equal(flags, 0x08, "the EXIF flag stays, the XMP flag is cleared");
        assert.ok(chunks[1].raw.equals(VP8_CHUNK), "the VP8 chunk byte for byte");
        assert.ok(chunks[0].data.subarray(1).equals(webpChunks(input).chunks[0].data.subarray(1)), "the canvas size untouched");
        const read = readTiff(chunks[2].data.subarray(header.length));
        assert.equal(numberOf(read.ifd0.get(TAG.Orientation), true), 6);
        assert.equal(read.ifd0.has(TAG.GPSInfo), false);
        assert.equal(withoutLocation(out), out, "nothing is left to remove");
    });
}

test("WebP: an EXIF chunk that cannot be parsed goes, with its VP8X flag; bytes after the RIFF go", () => {
    const bad = Buffer.concat([Buffer.from("XX*\0", "latin1"), tiffBlock().block.subarray(4)]);
    const input = Buffer.concat([webp([riffChunk("EXIF", bad), riffChunk("XMP ", XMP_PACKET)]), Buffer.from(SENTINEL.trailer)]);
    const out = clean(input);
    assert.deepEqual(sentinelsIn(out), []);
    const { flags, chunks } = webpChunks(out);
    assert.deepEqual(chunks.map((c) => c.fourcc), ["VP8X", "VP8 "]);
    assert.equal(flags, 0);
});

// ── malformed input ─────────────────────────────────────────────────────────

/** A TIFF block with the GPS sentinel in it, changed by `f`. */
function changed(f, options = {}) {
    const t = tiffBlock(options);
    const b = Buffer.from(t.block);
    f(b, t);
    return b;
}

/** In a JPEG, a PNG and a WebP: the EXIF that leaves, or null when none does. */
function exifLeaving(block) {
    const jpeg = clean(jpegWith([exifSegment(block), comSegment()]));
    assert.ok(jpeg.subarray(jpeg.length - imageDataOf(BASE_JPEG).length).equals(imageDataOf(BASE_JPEG)), "JPEG image data kept");
    const p = clean(png({ before: [pngChunk("eXIf", block)] }));
    const w = clean(webp([riffChunk("EXIF", block)]));
    for (const out of [jpeg, p, w]) assert.deepEqual(sentinelsIn(out), []);
    const inPng = pngChunks(p).find((c) => c.type === "eXIf")?.data ?? null;
    const { flags, chunks } = webpChunks(w);
    const inWebp = chunks.find((c) => c.fourcc === "EXIF")?.data ?? null;
    assert.equal(flags, inWebp ? 0x08 : 0, "the VP8X EXIF flag says whether EXIF is there");
    return { jpeg: exifOf(jpeg), png: inPng, webp: inWebp };
}

test("an EXIF block that cannot be parsed goes whole, in a JPEG, a PNG and a WebP", () => {
    const cases = {
        "no byte order mark": changed((b) => b.write("XX", 0, "latin1")),
        "not 42": changed((b) => b.writeUInt16LE(43, 2)),
        "IFD0 past the end": changed((b) => b.writeUInt32LE(b.length + 100, 4)),
        "IFD0 cut by the end": changed((b, { at }) => b.writeUInt16LE(5000, at.ifd0)),
        "the Exif IFD cut by the end": changed((b, { at }) => b.writeUInt16LE(5000, at.exif)),
        "an Exif IFD pointer that is text": changed((b, { entry }) => b.writeUInt16LE(2, entry.ifd0[TAG.ExifIFD] + 2)),
        "a block of 6 bytes": Buffer.from("II*\0\b\0", "latin1"),
    };
    for (const [why, bad] of Object.entries(cases)) {
        assert.deepEqual(exifLeaving(bad), { jpeg: null, png: null, webp: null }, why);
    }
});

test("a GPS IFD that cannot be read: its pointer goes, every byte no IFD references becomes zero, Orientation stays", () => {
    const cases = {
        "the GPS IFD cut by the end": changed((b, { at }) => b.writeUInt16LE(5000, at.gps)),
        "a GPS value past the end": changed((b, { entry }) => b.writeUInt32LE(b.length - 4, entry.gps[TAG.GPSLatitude] + 8)),
        "a GPS entry of no type": changed((b, { at }) => b.writeUInt16LE(99, at.gps + 2 + 2)),
        "a GPSInfo pointer that is text": changed((b, { entry }) => b.writeUInt16LE(2, entry.ifd0[TAG.GPSInfo] + 2)),
        "a GPSInfo pointer of two values": changed((b, { entry }) => b.writeUInt32LE(2, entry.ifd0[TAG.GPSInfo] + 4)),
        "a GPSInfo pointer past the end": changed((b, { entry }) => b.writeUInt32LE(b.length + 64, entry.ifd0[TAG.GPSInfo] + 8)),
        "the block cut inside the GPS IFD": tiffBlock().block.subarray(0, tiffBlock().at.gps + 30),
    };
    for (const [why, bad] of Object.entries(cases)) {
        for (const [format, tiff] of Object.entries(exifLeaving(bad))) {
            const read = readTiff(tiff);
            assert.equal(read.ifd0.has(TAG.GPSInfo), false, `${format}, ${why}`);
            assert.equal(numberOf(read.ifd0.get(TAG.Orientation), true), 6, `${format}, ${why}`);
            assert.equal(read.exif.get(TAG.DateTimeOriginal).value.toString("latin1"), "2026:10:05 12:00:00\0", `${format}, ${why}`);
            assert.ok(tiff.subarray(tiffBlock().at.gps).every((x) => x === 0), `${format}, ${why}: where the GPS IFD was is zeros`);
        }
    }
});

test("GPS a naive stripper left behind without its pointer goes too, and so do segments a wrong APP1 length swallowed", () => {
    // The GPSInfo entry taken out of IFD0 and nothing else: the GPS IFD is still in the block.
    const orphan = changed((b, { at, entry }) => {
        const gps = entry.ifd0[TAG.GPSInfo];
        b.copy(b, gps, gps + 12, at.ifd0 + 2 + 12 * 5 + 4);
        b.writeUInt16LE(4, at.ifd0);
    });
    assert.deepEqual(readTiff(orphan).gps, undefined);
    assert.ok(orphan.includes(SENTINEL.gps), "the coordinates are still in it");
    for (const [format, tiff] of Object.entries(exifLeaving(orphan))) {
        assert.equal(numberOf(readTiff(tiff).ifd0.get(TAG.Orientation), true), 6, format);
    }
    // APP1's length runs over the XMP and IPTC segments after it.
    const exif = exifSegment(tiffBlock().block);
    const swallowed = jpegWith([exif, xmpSegment(), iptcSegment()]);
    swallowed.writeUInt16BE(exif.length - 2 + xmpSegment().length + iptcSegment().length, 22);
    assert.deepEqual(appSegmentNames(swallowed), ["E0:JFIF", "E1:Exif"]);
    const out = clean(swallowed);
    assert.deepEqual(sentinelsIn(out), []);
    assert.deepEqual(appSegmentNames(out), ["E0:JFIF", "E1:Exif"]);
    assert.equal(numberOf(readTiff(exifOf(out)).ifd0.get(TAG.Orientation), true), 6);
    assert.ok(out.subarray(out.length - imageDataOf(BASE_JPEG).length).equals(imageDataOf(BASE_JPEG)));
});

test("XMP and IPTC written into EXIF (XMLPacket, IPTC-NAA, ImageResources) go with GPS; an uncompressed thumbnail's strips stay", () => {
    const strips = Buffer.alloc(24, 0x5A);
    const block = tiffBlock({ le: false, strips, ifd0Extra: [
        [TAG.XMLPacket, 7, XMP_PACKET],
        [TAG.IPTCNAA, 7, `\x1C\x02\x5A\0\x14${SENTINEL.iptc}`],
        [TAG.ImageResources, 7, `8BIM\x04\x04\0\0\0\0\0\x14${SENTINEL.location}`],
    ] }).block;
    for (const [format, tiff] of Object.entries(exifLeaving(block))) {
        const read = readTiff(tiff);
        for (const tag of [TAG.XMLPacket, TAG.IPTCNAA, TAG.ImageResources, TAG.GPSInfo]) assert.equal(read.ifd0.has(tag), false, `${format} ${tag}`);
        assert.equal(numberOf(read.ifd0.get(TAG.Orientation), false), 6, format);
        assert.equal(read.ifd0.get(TAG.Make).value.toString("latin1"), "Retichat Test Camera\0", format);
        const offset = numberOf(read.ifd1.get(TAG.StripOffsets), false);
        assert.ok(tiff.subarray(offset, offset + strips.length).equals(strips), `${format}: the strip bytes as they were`);
    }
});

test("an IFD chain that loops is followed once", () => {
    const thumbnail = jpegWith([], { base: THUMB_JPEG });
    const { block, at } = tiffBlock({ thumbnail });
    const b = Buffer.from(block);
    b.writeUInt32LE(at.ifd0, at.ifd1 + 2 + 12 * 3);                       // IFD1's next is IFD0
    const out = clean(jpegWith([exifSegment(b)]));
    assert.deepEqual(sentinelsIn(out), []);
    assert.equal(numberOf(readTiff(exifOf(out)).ifd0.get(TAG.Orientation), true), 6);
});

test("a JPEG whose structure breaks never throws and keeps no GPS", () => {
    const gps = exifSegment(tiffBlock().block);
    const longer = Buffer.from(gps);
    longer.writeUInt16BE(0xFFF0, 2);                                        // an EXIF length past the end of the file
    const cases = {
        "the EXIF segment runs past the end": Buffer.concat([BASE_JPEG.subarray(0, 20), longer]),
        "a segment length under 2": Buffer.concat([BASE_JPEG.subarray(0, 20), Buffer.from([0xFF, 0xE1, 0x00, 0x01]), gps, imageDataOf(BASE_JPEG)]),
        "a file cut inside its EXIF": jpegWith([gps]).subarray(0, 20 + 200),
        "bytes that are no segment": jpegWith([gps, Buffer.from(`garbage ${SENTINEL.location} `, "latin1")]),
        "a second SOI": jpegWith([gps, Buffer.from([0xFF, 0xD8]), xmpSegment()]),
    };
    for (const [why, input] of Object.entries(cases)) {
        assert.deepEqual(sentinelsIn(clean(input)), [], why);
    }
    // Garbage between segments goes, as a decoder skips it; the rest stays.
    const skipped = clean(cases["bytes that are no segment"]);
    assert.equal(jpegSegments(skipped).end, skipped.length);
    assert.ok(skipped.subarray(skipped.length - imageDataOf(BASE_JPEG).length).equals(imageDataOf(BASE_JPEG)));
    // A photo cut in its scan (no EOI) is cleaned and keeps what it has.
    const exif = tiffBlock();
    const cut = clean(jpegWith([exifSegment(exif.block), xmpSegment()]).subarray(0, -40));
    const kept = imageDataOf(BASE_JPEG).subarray(0, -40);
    assert.ok(cut.subarray(0, 20).equals(BASE_JPEG.subarray(0, 20)));
    const cleanedExif = exifOf(clean(jpegWith([exifSegment(exif.block)])));
    assert.equal(readTiff(cleanedExif).ifd0.has(TAG.GPSInfo), false);
    assert.ok(cut.subarray(20, cut.length - kept.length).equals(exifSegment(cleanedExif)), "its EXIF, cleaned, and no XMP");
    assert.ok(cut.subarray(cut.length - kept.length).equals(kept), "the tables and the scan as far as it goes");
});

test("a PNG or WebP whose structure breaks keeps no GPS: a chunk that runs over the rest goes with it, image data cut short stays", () => {
    const gps = pngChunk("eXIf", tiffBlock().block);
    const p = png({ before: [gps] });
    const ihdrTooLong = Buffer.from(p);
    ihdrTooLong.writeUInt32BE(13 + gps.length, 8);                         // IHDR's length runs over eXIf
    assert.equal(clean(ihdrTooLong).length, 8, "nothing after the signature can be delimited");
    const hugeIhdr = Buffer.from(p);
    hugeIhdr.writeUInt32BE(0x7FFFFFF0, 8);
    assert.deepEqual(sentinelsIn(clean(hugeIhdr)), []);
    const xmpAfter = png({ before: [gps], after: [textChunk("iTXt", "XML:com.adobe.xmp", XMP_PACKET)] });
    const cutIdat = clean(xmpAfter.subarray(0, xmpAfter.indexOf("IDAT") + 20));
    assert.deepEqual(sentinelsIn(cutIdat), []);
    assert.ok(cutIdat.subarray(-16).equals(xmpAfter.subarray(xmpAfter.indexOf("IDAT") + 4, xmpAfter.indexOf("IDAT") + 20)), "an IDAT cut short keeps what it has");
    const idatTooLong = Buffer.from(xmpAfter);
    idatTooLong.writeUInt32BE(0x00FFFFFF, xmpAfter.indexOf("IDAT") - 4);   // the file ends in IEND: not cut, a wrong length
    assert.deepEqual(sentinelsIn(clean(idatTooLong)), [], "an IDAT whose length runs over the XMP after it goes with it");

    const w = webp([riffChunk("EXIF", tiffBlock().block), riffChunk("XMP ", XMP_PACKET)]);
    const vp8xTooLong = Buffer.from(w);
    vp8xTooLong.writeUInt32LE(10 + VP8_CHUNK.length, 16);                  // VP8X's size runs over the VP8 chunk
    assert.deepEqual(sentinelsIn(clean(vp8xTooLong)), []);
    assert.equal(clean(vp8xTooLong).length, 12, "nothing after the RIFF header can be delimited");
    const cutVp8 = clean(w.subarray(0, 12 + 18 + 40));
    assert.ok(cutVp8.subarray(12 + 18).equals(VP8_CHUNK.subarray(0, 40)), "a VP8 chunk cut short keeps what it has");
    const vp8TooLong = Buffer.from(w);
    vp8TooLong.writeUInt32LE(0x00FFFFFF, 12 + 18 + 4);                     // past the RIFF itself: not cut, a wrong size
    assert.deepEqual(sentinelsIn(clean(vp8TooLong)), [], "a VP8 chunk whose size runs over EXIF and XMP goes with them");
});

test("cut at every length, a JPEG, a PNG and a WebP never throw and never keep GPS", () => {
    const photos = {
        jpeg: jpegWith([exifSegment(tiffBlock({ thumbnail: jpegWith([exifSegment(tiffBlock({ exif: false, gps: gpsEntries(SENTINEL.thumbGps) }).block)], { base: THUMB_JPEG }) }).block), xmpSegment(), iptcSegment()]),
        mpf: gainMapJpeg().bytes,
        png: png({ before: [pngChunk("eXIf", tiffBlock().block), textChunk("iTXt", "XML:com.adobe.xmp", XMP_PACKET)] }),
        webp: webp([riffChunk("EXIF", tiffBlock().block), riffChunk("XMP ", XMP_PACKET)]),
    };
    for (const [name, photo] of Object.entries(photos)) {
        for (let n = 1; n <= photo.length; n++) {
            const out = withoutLocation(photo.subarray(0, n));
            assert.ok(out instanceof Uint8Array, `${name} cut at ${n}: bytes back`);
            assert.deepEqual(sentinelsIn(out), [], `${name} cut at ${n}`);
        }
    }
});

test("bytes changed at random never make it throw or fail", () => {
    let seed = 0x5EED;
    const random = (n) => {
        seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
        return seed % n;
    };
    const photos = [gpsJpegWithThumbnail(), gainMapJpeg().bytes, jpegWith([exifSegment(tiffBlock().block)], { base: PROGRESSIVE_JPEG }),
        png({ before: [pngChunk("eXIf", tiffBlock().block)] }), webp([riffChunk("EXIF", tiffBlock({ le: false }).block), riffChunk("XMP ", XMP_PACKET)])];
    for (const photo of photos) {
        for (let round = 0; round < 1500; round++) {
            const bytes = Buffer.from(photo);
            for (let k = 1 + random(4); k > 0; k--) bytes[random(bytes.length)] = random(256);
            assert.ok(withoutLocation(bytes) instanceof Uint8Array, `round ${round}`);
        }
    }
});

function gpsJpegWithThumbnail() {
    const thumbnail = jpegWith([exifSegment(tiffBlock({ exif: false, gps: gpsEntries(SENTINEL.thumbGps) }).block)], { base: THUMB_JPEG });
    return jpegWith([exifSegment(tiffBlock({ thumbnail }).block), xmpSegment(), iptcSegment()]);
}

test("a failure inside returns null, never an exception: the caller then does not send the file", () => {
    class Failing extends Uint8Array {
        indexOf() { throw new Error("boom"); }
    }
    const photo = jpegWith([exifSegment(tiffBlock().block)]);
    const failing = new Failing(photo.length);
    failing.set(photo);
    assert.equal(withoutLocation(failing), null);
});

// ── as given ────────────────────────────────────────────────────────────────

test("a GIF, a HEIC, a PDF or anything else comes back as the very object given", () => {
    for (const bytes of [
        Buffer.from("GIF89a\x10\x00\x08\x00\x80\x00\x00", "latin1"),
        Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypheic\0\0\0\0mif1heic", "latin1")]),
        Buffer.from("%PDF-1.7\n", "latin1"),
        Buffer.alloc(600_000, 7),
        new Uint8Array(0),
        Buffer.from([0xFF, 0xD8]),
        Buffer.from("RIFF\0\0\0\0WAVEfmt ", "latin1"),
    ]) {
        assert.equal(withoutLocation(bytes), bytes);
    }
    for (const value of [null, undefined, "IMG_0001.jpg", new ArrayBuffer(8)]) assert.equal(withoutLocation(value), value);
});

test("a photo with nothing to remove comes back as the very object given", () => {
    const noGps = jpegWith([exifSegment(tiffBlock({ gps: null }).block), iccSegment(), isoGainMapSegment(), adobeSegment(), comSegment()]);
    for (const bytes of [BASE_JPEG, PROGRESSIVE_JPEG, THUMB_JPEG, noGps, png(), png({ before: [pngChunk("eXIf", tiffBlock({ gps: null }).block)] }),
        webp([]), webp([riffChunk("EXIF", tiffBlock({ gps: null }).block)]), Buffer.concat([Buffer.from("RIFF\x5a\0\0\0WEBP", "latin1"), VP8_CHUNK])]) {
        assert.equal(withoutLocation(bytes), bytes);
    }
});
