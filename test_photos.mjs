/**
 * Test support (not a test, not deployed): photos with their location in
 * them, built byte by byte around real images, and readers that take a
 * result apart again (photo_metadata.test.mjs, photo_metadata_decode.test.mjs,
 * attachments_send.test.mjs). The readers are written here, apart from
 * lib/photo_metadata.js, so they check it rather than repeat it.
 *
 * The images are real: a 16x8 baseline JPEG (4:2:0), the same picture as a
 * progressive JPEG (ten scans, Huffman tables between them) and an 8x4 JPEG
 * for EXIF thumbnails, each made by ImageMagick 7 (libjpeg-turbo, -strip: a
 * JFIF APP0 and nothing else), and a 16x8 lossy WebP (VP8) made by
 * `cwebp -metadata none`. The PNG is made here, with zlib. Every piece of
 * metadata put around them is written here, with sentinel text in it that
 * must never leave.
 */
import { Buffer } from "node:buffer";
import { crc32, deflateSync, inflateSync } from "node:zlib";

const b64 = (s) => Buffer.from(s.replace(/\s+/g, ""), "base64");

/** 16x8, baseline, 4:2:0: SOI, APP0 JFIF (bytes 2-19), tables, one scan, EOI. */
export const BASE_JPEG = b64(`
/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMU
FRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
FBQUFBQUFBT/wAARCAAIABADASIAAhEBAxEB/8QAFgABAQEAAAAAAAAAAAAAAAAAAAYH/8QAIRAAAAQFBQAAAAAAAAAAAAAAAAYR
EgECBBRhExUxQ6H/xAAVAQEBAAAAAAAAAAAAAAAAAAAEB//EACARAAEEAgEFAAAAAAAAAAAAAAECAwURACEGBBMxUaH/2gAMAwEA
AhEDEQA/AMaNh9lM1qlLa6D+17lTEE49E/uWQAXdrgUCygIQzoezf02cPE8nkYTo0R8crttIukizVkqOySdkk+c//9k=`);

/** The same picture, progressive: ten scans with Huffman tables between them. */
export const PROGRESSIVE_JPEG = b64(`
/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMU
FRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
FBQUFBQUFBT/wgARCAAIABADAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAABQb/xAAXAQADAQAAAAAAAAAAAAAAAAADBAUG
/9oADAMBAAIQAxAAAAGMqiPa1v8A/8QAFxAAAwEAAAAAAAAAAAAAAAAAAAQTFP/aAAgBAQABBQJt/SUP/8QAHxEAAAUEAwAAAAAA
AAAAAAAAAAMFERIBExZhMUFR/9oACAEDAQE/AUE0tCuQNlNum4fdfRk2x//EAB0RAAECBwAAAAAAAAAAAAAAAAADEQECBhIWYYH/
2gAIAQIBAT8BQpedN74vwxzR/8QAGRAAAQUAAAAAAAAAAAAAAAAAAhAREiJh/9oACAEBAAY/AhrFtT//xAAYEAACAwAAAAAAAAAA
AAAAAAABEBFRYf/aAAgBAQABPyEG/tK//9oADAMBAAIAAwAAABD7/8QAGhEAAgIDAAAAAAAAAAAAAAAAABFBYXGR8P/aAAgBAwEB
PxC8xg3DwOWf/8QAGREAAgMBAAAAAAAAAAAAAAAAETEBEEFh/9oACAECAQE/ENcQED7Lp//EABsQAAIBBQAAAAAAAAAAAAAAAAAR
oQEhMWFx/9oACAEBAAE/ELIk8tUWJOj/2Q==`);

/** 8x4, baseline: the EXIF thumbnail. */
export const THUMB_JPEG = b64(`
/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYn
KSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo
KCgoKCgoKCj/wAARCAAEAAgDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAf/xAAaEAEAAQUAAAAAAAAAAAAAAAAAAQYX
VaHR/8QAFQEBAQAAAAAAAAAAAAAAAAAAAwX/xAAcEQACAAcAAAAAAAAAAAAAAAAAAQIEEhRRU5H/2gAMAwEAAhEDEQA/AJ5dqrch
qegINjLa4eIWp5P/2Q==`);

/** 16x8 lossy WebP, simple format: RIFF, WEBP, one "VP8 " chunk. */
const BASE_WEBP = b64(`
UklGRloAAABXRUJQVlA4IE4AAADwAQCdASoQAAgAAUAmJbACdLoAArdtOAAAyPgGR+3G6AWnmU/xNrhNT3NNLv9Ef+pZ/fh//5Ln
H/Umf/SAP9P+ID+FR+2I/nMmrWGAAAA=`);
/** Its "VP8 " chunk, header and all: the image data a WebP keeps. */
export const VP8_CHUNK = BASE_WEBP.subarray(12);

/** Text that must never leave, one per kind of metadata. */
export const SENTINEL = {
    gps: "GPS-SENTINEL-37.7749N-122.4194W",
    thumbGps: "THUMB-GPS-SENTINEL",
    xmp: "XMP-SENTINEL-Lisbon",
    extendedXmp: "EXTENDED-XMP-SENTINEL",
    iptc: "IPTC-SENTINEL-Lisbon",
    gopro: "GPMF-GPS5-SENTINEL",
    c2pa: "C2PA-SENTINEL",
    ducky: "DUCKY-SENTINEL",
    trailer: "TRAILER-SENTINEL-MCC-268",
    location: "LOCATION-SENTINEL-Lisbon",
    rawProfile: "RAW-PROFILE-SENTINEL",
    vendor: "VENDOR-CHUNK-SENTINEL",
};

/** Whether any sentinel is anywhere in `bytes` (latin1, so every byte). */
export function sentinelsIn(bytes) {
    const text = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).toString("latin1");
    return Object.values(SENTINEL).filter((s) => text.includes(s));
}

const asBuffer = (bytes) => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length);
const bytesOf = (part) => (typeof part === "string" ? Buffer.from(part, "latin1") : Buffer.from(part));

// ── TIFF (EXIF's) ───────────────────────────────────────────────────────────

export const TAG = {
    Make: 0x010F, Orientation: 0x0112, XResolution: 0x011A, Compression: 0x0103, StripOffsets: 0x0111, StripByteCounts: 0x0117,
    XMLPacket: 0x02BC, IPTCNAA: 0x83BB, ImageResources: 0x8649,
    ExifIFD: 0x8769, GPSInfo: 0x8825, InteropIFD: 0xA005,
    ThumbnailOffset: 0x0201, ThumbnailLength: 0x0202,
    ExposureTime: 0x829A, DateTimeOriginal: 0x9003,
    GPSVersionID: 0x0000, GPSLatitudeRef: 0x0001, GPSLatitude: 0x0002, GPSLongitudeRef: 0x0003,
    GPSLongitude: 0x0004, GPSAltitude: 0x0006, GPSProcessingMethod: 0x001B,
};
const BYTE = 1, ASCII = 2, SHORT = 3, LONG = 4, RATIONAL = 5, UNDEFINED = 7;

function encode(type, value, le) {
    const out = [];
    const put = (v, n) => {
        for (let i = 0; i < n; i++) out.push((v >>> (8 * (le ? i : n - 1 - i))) & 0xFF);
    };
    if (type === ASCII) return { bytes: Buffer.from(value + "\0", "latin1"), count: value.length + 1 };
    if (type === BYTE || type === UNDEFINED) return { bytes: bytesOf(value), count: bytesOf(value).length };
    if (type === SHORT) value.forEach((v) => put(v, 2));
    else if (type === LONG) value.forEach((v) => put(v, 4));
    else if (type === RATIONAL) value.forEach(([n, d]) => { put(n, 4); put(d, 4); });
    else throw new Error(`type ${type}`);
    return { bytes: Buffer.from(out), count: value.length };
}

/** The GPS IFD a phone writes: where, and how high, with a sentinel. */
export const gpsEntries = (sentinel = SENTINEL.gps) => [
    [TAG.GPSVersionID, BYTE, [2, 3, 0, 0]],
    [TAG.GPSLatitudeRef, ASCII, "N"],
    [TAG.GPSLatitude, RATIONAL, [[37, 1], [46, 1], [2934, 100]]],
    [TAG.GPSLongitudeRef, ASCII, "W"],
    [TAG.GPSLongitude, RATIONAL, [[122, 1], [25, 1], [960, 100]]],
    [TAG.GPSAltitude, RATIONAL, [[52, 1]]],
    [TAG.GPSProcessingMethod, UNDEFINED, "ASCII\0\0\0" + sentinel],
];
export const GPS_ENTRIES = gpsEntries();

/**
 * An EXIF TIFF block in byte order `le`: IFD0 (Make, Orientation,
 * XResolution, and pointers to the Exif and GPS IFDs), the Exif IFD
 * (exposure, date), the GPS IFD and IFD1 with a JPEG thumbnail when one is
 * given, each followed by its values. Returns the block and where things are
 * in it: `at.ifd0`, `at.exif`, `at.gps`, `at.ifd1`, `at.thumbnail`, and
 * `entry[name][tag]`, the position of each entry.
 */
export function tiffBlock({ le = true, orientation = 6, gps = GPS_ENTRIES, thumbnail = null, strips = null, exif = true, ifd0Extra = [] } = {}) {
    const ifds = [];
    const ifd0 = [[TAG.Make, ASCII, "Retichat Test Camera"], [TAG.Orientation, SHORT, [orientation]], [TAG.XResolution, RATIONAL, [[72, 1]]], ...ifd0Extra];
    if (exif) ifd0.push([TAG.ExifIFD, LONG, "exif"]);
    if (gps) ifd0.push([TAG.GPSInfo, LONG, "gps"]);
    ifds.push(["ifd0", ifd0]);
    if (exif) ifds.push(["exif", [[TAG.ExposureTime, RATIONAL, [[1, 120]]], [TAG.DateTimeOriginal, ASCII, "2026:10:05 12:00:00"]]]);
    if (gps) ifds.push(["gps", gps]);
    if (thumbnail) ifds.push(["ifd1", [[TAG.Compression, SHORT, [6]], [TAG.ThumbnailOffset, LONG, "thumbnail"], [TAG.ThumbnailLength, LONG, [thumbnail.length]]]]);
    else if (strips) ifds.push(["ifd1", [[TAG.Compression, SHORT, [1]], [TAG.StripOffsets, LONG, "thumbnail"], [TAG.StripByteCounts, LONG, [strips.length]]]]);
    thumbnail ??= strips;

    // Lay out: header, then each IFD and its values, then the thumbnail.
    const at = {};
    const entry = {};
    let pos = 8;
    const laid = ifds.map(([name, entries]) => {
        const sorted = [...entries].sort((a, b) => a[0] - b[0]);
        at[name] = pos;
        entry[name] = {};
        pos += 2 + 12 * sorted.length + 4;
        const encoded = sorted.map(([tag, type, value]) => {
            const e = typeof value === "string" && type === LONG ? { bytes: null, count: 1, ref: value } : encode(type, value, le);
            if (e.bytes && e.bytes.length > 4) {
                e.valueAt = pos;
                pos += e.bytes.length + (e.bytes.length & 1);
            }
            return { tag, type, ...e };
        });
        return { name, encoded };
    });
    if (thumbnail) {
        at.thumbnail = pos;
        pos += thumbnail.length;
    }
    const block = Buffer.alloc(pos);
    const u16 = (o, v) => (le ? block.writeUInt16LE(v, o) : block.writeUInt16BE(v, o));
    const u32 = (o, v) => (le ? block.writeUInt32LE(v, o) : block.writeUInt32BE(v, o));
    block.write(le ? "II" : "MM", 0, "latin1");
    u16(2, 42);
    u32(4, at.ifd0);
    for (const { name, encoded } of laid) {
        const base = at[name];
        u16(base, encoded.length);
        encoded.forEach((e, k) => {
            const p = base + 2 + 12 * k;
            entry[name][e.tag] = p;
            u16(p, e.tag);
            u16(p + 2, e.type);
            u32(p + 4, e.count);
            if (e.ref) u32(p + 8, at[e.ref]);
            else if (e.valueAt !== undefined) {
                u32(p + 8, e.valueAt);
                e.bytes.copy(block, e.valueAt);
            } else e.bytes.copy(block, p + 8);
        });
        u32(base + 2 + 12 * encoded.length, name === "ifd0" && at.ifd1 ? at.ifd1 : 0);
    }
    if (thumbnail) Buffer.from(thumbnail).copy(block, at.thumbnail);
    return { block, at, entry, le };
}

/**
 * A TIFF block read back: its byte order and each IFD reachable from IFD0
 * (ifd0, exif, gps, ifd1) as a Map of tag to {type, count, value}, where
 * value is the entry's value bytes. Throws when it cannot be read.
 */
export function readTiff(bytes) {
    const b = asBuffer(bytes);
    const le = b.toString("latin1", 0, 2) === "II";
    if (!le && b.toString("latin1", 0, 2) !== "MM") throw new Error("not a TIFF header");
    const u16 = (o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
    const u32 = (o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
    if (u16(2) !== 42) throw new Error("not TIFF");
    const sizes = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    const read = (at) => {
        const map = new Map();
        const n = u16(at);
        for (let k = 0; k < n; k++) {
            const p = at + 2 + 12 * k;
            const type = u16(p + 2);
            const count = u32(p + 4);
            const size = sizes[type] * count;
            const valueAt = size > 4 ? u32(p + 8) : p + 8;
            if (valueAt + size > b.length) throw new Error(`tag ${u16(p)} runs past the block`);
            map.set(u16(p), { type, count, value: b.subarray(valueAt, valueAt + size) });
        }
        return { map, next: u32(at + 2 + 12 * n) };
    };
    const ifd0 = read(u32(4));
    const out = { le, ifd0: ifd0.map };
    if (ifd0.map.has(TAG.ExifIFD)) out.exif = read(u32Value(ifd0.map.get(TAG.ExifIFD), le)).map;
    if (ifd0.map.has(TAG.GPSInfo)) out.gps = read(u32Value(ifd0.map.get(TAG.GPSInfo), le)).map;
    if (ifd0.next) out.ifd1 = read(ifd0.next).map;
    return out;
}

const u32Value = (e, le) => (le ? e.value.readUInt32LE(0) : e.value.readUInt32BE(0));

/** A SHORT or LONG entry's (first) value. */
export function numberOf(entry, le) {
    if (entry.type === SHORT) return le ? entry.value.readUInt16LE(0) : entry.value.readUInt16BE(0);
    return u32Value(entry, le);
}

// ── JPEG ────────────────────────────────────────────────────────────────────

/** A marker segment: FF, marker, length, then the parts. */
export function segment(marker, ...parts) {
    const payload = Buffer.concat(parts.map(bytesOf));
    const head = Buffer.from([0xFF, marker, 0, 0]);
    head.writeUInt16BE(payload.length + 2, 2);
    return Buffer.concat([head, payload]);
}

export const exifSegment = (block, header = "Exif\0\0") => segment(0xE1, header, block);

export const XMP_PACKET = `<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:exif="http://ns.adobe.com/exif/1.0/" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/" exif:GPSLatitude="37,46.489N" exif:GPSLongitude="122,25.16W" photoshop:City="${SENTINEL.xmp}"/></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`;

export const xmpSegment = (packet = XMP_PACKET) => segment(0xE1, "http://ns.adobe.com/xap/1.0/\0", Buffer.from(packet, "utf8"));

/** An extended XMP segment: namespace, GUID, full length, offset, part. */
export function extendedXmpSegment() {
    const part = Buffer.from(`<rdf:Description photoshop:State="${SENTINEL.extendedXmp}"/>`, "utf8");
    const sizes = Buffer.alloc(8);
    sizes.writeUInt32BE(part.length, 0);
    sizes.writeUInt32BE(0, 4);
    return segment(0xE1, "http://ns.adobe.com/xmp/extension/\0", "0123456789ABCDEF0123456789ABCDEF", sizes, part);
}

/** APP13: a Photoshop IRB holding IPTC City (2:90) and Country (2:101). */
export function iptcSegment() {
    const dataset = (n, text) => Buffer.concat([Buffer.from([0x1C, 0x02, n, 0, text.length]), Buffer.from(text, "latin1")]);
    const iptc = Buffer.concat([dataset(90, SENTINEL.iptc), dataset(101, "Portugal")]);
    const size = Buffer.alloc(4);
    size.writeUInt32BE(iptc.length, 0);
    const pad = iptc.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0);
    return segment(0xED, "Photoshop 3.0\0", "8BIM", Buffer.from([0x04, 0x04, 0, 0]), size, iptc, pad);
}

/** APP2 ICC_PROFILE, chunk 1 of 1 (a stand-in profile body). */
export const iccSegment = () => segment(0xE2, "ICC_PROFILE\0", Buffer.from([1, 1]), Buffer.alloc(128, 0x11));
/** APP14 Adobe: version 100, no flags, transform 1 (YCbCr). */
export const adobeSegment = () => segment(0xEE, "Adobe", Buffer.from([0, 100, 0, 0, 0, 0, 1]));
export const comSegment = (text = "a comment the user wrote") => segment(0xFE, text);
/** GoPro's APP6: GPMF, with a GPS5 stream. */
export const goproSegment = () => segment(0xE6, "GoPro\0", "DEVC", Buffer.from([0, 0, 0, 0]), "GPS5", SENTINEL.gopro);
/** APP11: a JUMBF box holding a C2PA manifest. */
export const c2paSegment = () => segment(0xEB, "JP", Buffer.from([0, 1, 0, 0, 0, 1]), "jumb", "c2pa", SENTINEL.c2pa);
/** APP12 Ducky (Photoshop's Save for Web). */
export const duckySegment = () => segment(0xEC, "Ducky", Buffer.from([0, 1, 0, 0, 0, 0x50]), SENTINEL.ducky);

/** `base` (a JPEG with its JFIF APP0 at bytes 2-19) with `segments` after
 *  its APP0 and `trailer` after its EOI. */
export function jpegWith(segments, { base = BASE_JPEG, trailer = null } = {}) {
    return Buffer.concat([base.subarray(0, 20), ...segments.map(bytesOf), base.subarray(20), ...(trailer ? [bytesOf(trailer)] : [])]);
}

/** The bytes of a JPEG after its APP0: the tables, the scans and EOI. */
export const imageDataOf = (base) => base.subarray(20);

/**
 * A JPEG's segments read back, strictly: SOI, segments whose lengths hold,
 * the entropy-coded data after each SOS (as {marker: "scan"}), EOI. Returns
 * {segments, end} (end: just after EOI). Throws on anything else.
 */
export function jpegSegments(bytes, from = 0) {
    const b = asBuffer(bytes);
    if (b[from] !== 0xFF || b[from + 1] !== 0xD8) throw new Error("no SOI");
    const segments = [];
    let pos = from + 2;
    for (;;) {
        if (pos + 2 > b.length || b[pos] !== 0xFF) throw new Error(`no marker at ${pos}`);
        const marker = b[pos + 1];
        if (marker === 0xD9) {
            segments.push({ marker, start: pos, end: pos + 2 });
            return { segments, end: pos + 2 };
        }
        if (pos + 4 > b.length) throw new Error(`a segment cut at ${pos}`);
        const end = pos + 2 + b.readUInt16BE(pos + 2);
        if (end > b.length) throw new Error(`segment ${marker.toString(16)} at ${pos} runs past the end`);
        segments.push({ marker, start: pos, end, payload: b.subarray(pos + 4, end) });
        pos = end;
        if (marker === 0xDA) {
            let i = pos;
            for (;;) {
                i = b.indexOf(0xFF, i);
                if (i < 0 || i + 1 >= b.length) throw new Error("a scan with no end");
                const next = b[i + 1];
                if (next === 0x00 || (next >= 0xD0 && next <= 0xD7)) { i += 2; continue; }
                break;
            }
            segments.push({ marker: "scan", start: pos, end: i });
            pos = i;
        }
    }
}

/** The APPn segments of a JPEG, as "E1:Exif", "E2:ICC_PROFILE", "FE" (COM)... */
export function appSegmentNames(bytes) {
    return jpegSegments(bytes).segments
        .filter((s) => (s.marker >= 0xE0 && s.marker <= 0xEF) || s.marker === 0xFE)
        .map((s) => {
            const id = s.payload.toString("latin1", 0, Math.min(s.payload.length, 40)).split("\0")[0];
            return s.marker === 0xFE ? "FE" : `${s.marker.toString(16).toUpperCase()}:${id}`;
        });
}

/** The TIFF block of the first EXIF APP1 in a JPEG, or null. */
export function exifOf(bytes) {
    const seg = jpegSegments(bytes).segments.find((s) => s.marker === 0xE1 && s.payload.toString("latin1", 0, 5) === "Exif\0");
    return seg ? seg.payload.subarray(6) : null;
}

/** A JPEG with a GPS EXIF (and orientation 6), XMP and IPTC: what a phone's photo carries. */
export const gpsJpeg = ({ le = true } = {}) => jpegWith([exifSegment(tiffBlock({ le }).block), xmpSegment(), iptcSegment()]);

/** APP2 ISO 21496-1: an HDR gain map's parameters (a stand-in body). */
export const isoGainMapSegment = () => segment(0xE2, "urn:iso:std:iso:ts:21496:-1\0", Buffer.from([0, 0, 0, 0]));

/** APP2 MPF (CIPA DC-007), big-endian: an MP index IFD (version, number of
 *  images, MP entries) and the entries [{size, offset}], 16 bytes each. */
export function mpfSegment(entries) {
    const head = Buffer.alloc(8 + 2 + 3 * 12 + 4);
    head.write("MM", 0, "latin1");
    head.writeUInt16BE(42, 2);
    head.writeUInt32BE(8, 4);
    head.writeUInt16BE(3, 8);
    const put = (k, tag, type, count, value) => {
        const p = 10 + 12 * k;
        head.writeUInt16BE(tag, p);
        head.writeUInt16BE(type, p + 2);
        head.writeUInt32BE(count, p + 4);
        if (typeof value === "string") head.write(value, p + 8, "latin1");
        else head.writeUInt32BE(value, p + 8);
    };
    put(0, 0xB000, UNDEFINED, 4, "0100");
    put(1, 0xB001, LONG, 1, entries.length);
    put(2, 0xB002, UNDEFINED, 16 * entries.length, head.length);
    const table = Buffer.alloc(16 * entries.length);
    entries.forEach(({ size, offset, attribute = 0 }, i) => {
        table.writeUInt32BE(attribute, 16 * i);
        table.writeUInt32BE(size, 16 * i + 4);
        table.writeUInt32BE(offset, 16 * i + 8);
    });
    return segment(0xE2, "MPF\0", head, table);
}

/** The MP entries of a JPEG's MPF segment, and where its offsets count from. */
export function mpfEntries(bytes) {
    const seg = jpegSegments(bytes).segments.find((s) => s.marker === 0xE2 && s.payload.toString("latin1", 0, 4) === "MPF\0");
    if (!seg) return null;
    const base = seg.start + 4 + 4;
    const p = seg.payload.subarray(4);
    const count = p.readUInt16BE(8);
    let entries = null;
    let n = 0;
    for (let k = 0; k < count; k++) {
        const e = 10 + 12 * k;
        if (p.readUInt16BE(e) === 0xB001) n = p.readUInt32BE(e + 8);
        if (p.readUInt16BE(e) === 0xB002) entries = p.readUInt32BE(e + 8);
    }
    return {
        base,
        images: Array.from({ length: n }, (_, i) => ({ size: p.readUInt32BE(entries + 16 * i + 4), offset: p.readUInt32BE(entries + 16 * i + 8) })),
    };
}

/**
 * An Ultra HDR-like photo: the primary JPEG (GPS EXIF, an MPF index, then
 * XMP after the index, so dropping it moves what the index points at), a
 * motion photo's video between it and its gain map, the gain map (a JPEG
 * with its own GPS EXIF, XMP and ISO 21496-1 parameters), and a trailer
 * after that. Returns the bytes and the gain map as built.
 */
export function gainMapJpeg() {
    const gainMap = jpegWith([exifSegment(tiffBlock({ exif: false, orientation: 1, gps: gpsEntries(SENTINEL.thumbGps) }).block),
        xmpSegment(`<x:xmpmeta xmlns:x="adobe:ns:meta/" hdrgm:Version="1.0" photoshop:City="${SENTINEL.xmp}"/>`), isoGainMapSegment()],
    { base: THUMB_JPEG });
    const video = Buffer.concat([Buffer.from("\0\0\0\x18ftypmp42", "latin1"), Buffer.from(`moov udta \xA9xyz +37.7749-122.4194/ ${SENTINEL.trailer}`, "latin1")]);
    const tail = Buffer.from(`SEFH ${SENTINEL.trailer} SEFT`, "latin1");
    const build = (entries) => jpegWith([exifSegment(tiffBlock().block), mpfSegment(entries), xmpSegment(), isoGainMapSegment()]);
    const draft = build([{ size: 0, offset: 0 }, { size: 0, offset: 0 }]);
    const base = jpegSegments(draft).segments.find((s) => s.marker === 0xE2 && s.payload.toString("latin1", 0, 4) === "MPF\0").start + 8;
    const primary = build([{ size: draft.length, offset: 0, attribute: 0x20030000 }, { size: gainMap.length, offset: draft.length + video.length - base }]);
    return { bytes: Buffer.concat([primary, video, gainMap, tail]), gainMap, primary };
}

// ── PNG ─────────────────────────────────────────────────────────────────────

export const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

export function pngChunk(type, data = Buffer.alloc(0)) {
    const body = Buffer.concat([Buffer.from(type, "latin1"), bytesOf(data)]);
    const head = Buffer.alloc(4);
    head.writeUInt32BE(body.length - 4, 0);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body), 0);
    return Buffer.concat([head, body, crc]);
}

/** 16x8 RGB, every row filter 0: the scanlines IDAT holds. */
export const PNG_PIXELS = Buffer.concat(Array.from({ length: 8 }, (_, y) => Buffer.concat([
    Buffer.from([0]),
    Buffer.from(Array.from({ length: 16 }, (_, x) => [x * 16, y * 32, x < 4 && y < 4 ? 255 : 64]).flat()),
])));

/** A real 16x8 PNG with `before` chunks between IHDR and IDAT, `after`
 *  chunks between IDAT and IEND, and `trailer` after IEND. */
export function png({ before = [], after = [], trailer = null } = {}) {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(16, 0);
    ihdr.writeUInt32BE(8, 4);
    ihdr.set([8, 2, 0, 0, 0], 8);
    return Buffer.concat([
        PNG_SIGNATURE, pngChunk("IHDR", ihdr), ...before, pngChunk("IDAT", deflateSync(PNG_PIXELS)), ...after, pngChunk("IEND"),
        ...(trailer ? [bytesOf(trailer)] : []),
    ]);
}

/** A PNG's chunks read back, strictly: the signature, each chunk's CRC,
 *  IHDR first, IEND last and nothing after it. Throws on anything else. */
export function pngChunks(bytes) {
    const b = asBuffer(bytes);
    if (!b.subarray(0, 8).equals(PNG_SIGNATURE)) throw new Error("no PNG signature");
    const chunks = [];
    let pos = 8;
    while (pos < b.length) {
        if (pos + 12 > b.length) throw new Error(`a chunk cut at ${pos}`);
        const size = b.readUInt32BE(pos);
        const type = b.toString("latin1", pos + 4, pos + 8);
        const end = pos + 12 + size;
        if (end > b.length) throw new Error(`${type} runs past the end`);
        if (crc32(b.subarray(pos + 4, pos + 8 + size)) !== b.readUInt32BE(pos + 8 + size)) throw new Error(`${type}: bad CRC`);
        chunks.push({ type, data: b.subarray(pos + 8, pos + 8 + size) });
        pos = end;
        if (type === "IEND" && pos !== b.length) throw new Error("bytes after IEND");
    }
    if (chunks[0]?.type !== "IHDR" || chunks.at(-1)?.type !== "IEND") throw new Error("IHDR first, IEND last");
    return chunks;
}

/** What a PNG's IDAT inflates to: its scanlines. */
export const pngScanlines = (bytes) => inflateSync(Buffer.concat(pngChunks(bytes).filter((c) => c.type === "IDAT").map((c) => c.data)));

/** A PNG text chunk: tEXt keyword\0text, zTXt keyword\0\0deflated, iTXt keyword\0\0\0\0\0text. */
export function textChunk(type, keyword, text) {
    if (type === "tEXt") return pngChunk(type, Buffer.concat([bytesOf(keyword + "\0"), bytesOf(text)]));
    if (type === "zTXt") return pngChunk(type, Buffer.concat([bytesOf(keyword + "\0\0"), deflateSync(Buffer.from(text, "latin1"))]));
    return pngChunk(type, Buffer.concat([bytesOf(keyword + "\0\0\0\0\0"), Buffer.from(text, "utf8")]));
}

// ── WebP ────────────────────────────────────────────────────────────────────

export function riffChunk(fourcc, data) {
    const body = bytesOf(data);
    const head = Buffer.alloc(8);
    head.write(fourcc, 0, "latin1");
    head.writeUInt32LE(body.length, 4);
    return Buffer.concat([head, body, body.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0)]);
}

/** An extended WebP: VP8X (canvas 16x8, flags for what follows), the VP8
 *  image, then `chunks` (EXIF, XMP...), with the RIFF size right. */
export function webp(chunks = [], { flags = null } = {}) {
    const fourccs = chunks.map((c) => c.toString("latin1", 0, 4));
    const vp8x = Buffer.alloc(10);
    vp8x[0] = flags ?? ((fourccs.includes("EXIF") ? 0x08 : 0) | (fourccs.includes("XMP ") ? 0x04 : 0));
    vp8x.writeUIntLE(15, 4, 3);
    vp8x.writeUIntLE(7, 7, 3);
    const body = Buffer.concat([Buffer.from("WEBP"), riffChunk("VP8X", vp8x), VP8_CHUNK, ...chunks]);
    const head = Buffer.alloc(8);
    head.write("RIFF", 0, "latin1");
    head.writeUInt32LE(body.length, 4);
    return Buffer.concat([head, body]);
}

/** A WebP's chunks read back, strictly: the RIFF size is the file's, every
 *  chunk and its pad fit exactly. Returns {flags, chunks: [{fourcc, data}]}. */
export function webpChunks(bytes) {
    const b = asBuffer(bytes);
    if (b.toString("latin1", 0, 4) !== "RIFF" || b.toString("latin1", 8, 12) !== "WEBP") throw new Error("not a WebP");
    if (b.readUInt32LE(4) !== b.length - 8) throw new Error(`RIFF size ${b.readUInt32LE(4)} for ${b.length - 8} bytes`);
    const chunks = [];
    let pos = 12;
    while (pos < b.length) {
        if (pos + 8 > b.length) throw new Error(`a chunk cut at ${pos}`);
        const size = b.readUInt32LE(pos + 4);
        const end = pos + 8 + size + (size & 1);
        if (end > b.length) throw new Error("a chunk runs past the end");
        chunks.push({ fourcc: b.toString("latin1", pos, pos + 4), data: b.subarray(pos + 8, pos + 8 + size), raw: b.subarray(pos, end) });
        pos = end;
    }
    const vp8x = chunks.find((c) => c.fourcc === "VP8X");
    return { flags: vp8x ? vp8x.data[0] : null, chunks };
}
