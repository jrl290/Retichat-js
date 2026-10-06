/**
 * A photo leaves without where it was taken (James, 2026-10-05: no photo
 * leaves with GPS location, whatever its format). Attachments go at their
 * original size (James, 2026-09-30), so nothing is decoded or re-encoded:
 * withoutLocation(bytes) removes the metadata that can carry a location and
 * keeps every other byte as picked, the image data above all. What it does
 * not read, it does not keep: a part of a photo it cannot parse goes whole.
 *
 * JPEG (SOI, segments, scans, EOI):
 *   - EXIF (APP1 "Exif"): the GPS IFD goes. Its pointer (GPSInfo, tag
 *     0x8825) leaves every IFD that holds one, and so do XMP and IPTC put in
 *     the TIFF block (tags 0x02BC, 0x83BB, 0x8649); then every byte no IFD
 *     left references becomes zero, the GPS IFD and its values among them,
 *     in place: the block keeps its length, so every other offset in it
 *     still holds, and the rest is kept, Orientation (0x0112) above all, so a
 *     receiver that rotates by it shows the photo upright, as before. GPS a
 *     naive stripper left behind without its pointer goes the same way. The
 *     thumbnail (IFD1) is a JPEG of its own and is cleaned the same way,
 *     where it is. An EXIF block that cannot be parsed goes whole.
 *   - XMP (APP1 "http://ns.adobe.com/xap/1.0/" and its extension segments)
 *     goes: it repeats the GPS (exif:GPSLatitude) and adds place names
 *     (photoshop:City, Iptc4xmpCore:Location). So does every other APP1.
 *   - IPTC (APP13, Photoshop) goes: City, Sub-location, Province/State and
 *     Country.
 *   - Every other APPn goes as well, but those a decoder needs to show the
 *     picture: APP0 JFIF, APP2 ICC_PROFILE (colour), APP2 MPF (where the
 *     embedded images are), APP2 ISO 21496-1 (an HDR gain map's parameters)
 *     and APP14 Adobe (colour transform). The others are vendor blobs this
 *     does not read, and some carry location: GoPro's APP6 (GPMF) holds GPS
 *     tracks, a C2PA manifest (APP11) EXIF with GPS.
 *   - After EOI, only the images the MPF index lists (an HDR gain map, a
 *     depth map) are kept, each cleaned as the photo is, and the index is
 *     rewritten to where they now are. Anything else there goes: a motion
 *     photo's video, Samsung's trailer (which names the network's country).
 *   The tables, the scans and COM segments are kept byte for byte. Bytes
 *   between segments that are no marker go, as a decoder skips them, and so
 *   do segments of a reserved marker, which no decoder reads.
 *
 * PNG (chunks): eXIf is cleaned as EXIF above, its CRC recomputed, and goes
 * whole when it cannot be parsed (a browser rotates a PNG by its eXIf, so
 * it is kept when it can be). Every tEXt, zTXt and iTXt whose keyword is
 * XMP's ("XML:com.adobe.xmp"), an ImageMagick raw profile ("Raw profile type
 * exif", "... iptc", "... xmp", "... 8bim") or names EXIF, XMP, IPTC, GPS or
 * a location goes; other text stays. Of the other ancillary chunks only
 * those in PNG_KEPT stay: the rest are what this does not read (a C2PA
 * manifest, caBX, pre-standard EXIF, exIf and zxIf, among them), and a
 * decoder skips them too. Critical chunks stay. Bytes after IEND go.
 *
 * WebP (RIFF): EXIF is cleaned as above, and goes whole (its VP8X flag
 * cleared) when it cannot be parsed; "XMP " goes and its VP8X flag is
 * cleared, and so does every chunk but the picture's own (WEBP_KEPT); the
 * RIFF size is rewritten. Bytes after the RIFF go.
 *
 * A chunk or segment whose length does not fit cannot be delimited, and
 * neither can anything after it: it goes with the rest, but for image data
 * cut short (a photo whose end is missing still shows what it has).
 *
 * Anything else (GIF, HEIC, AVIF, TIFF, a video, a document) is returned as
 * given: HEIC and AVIF can carry the same EXIF GPS and XMP, and are not
 * handled here.
 *
 * A file that needs no change comes back as the very object given. Nothing
 * here throws: a failure inside returns null, and the caller must not send
 * the file then. Nothing touches a Node-only global.
 */

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));

const JPEG_START = [0xFF, 0xD8, 0xFF];
const PNG_SIGNATURE = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const PNG_IEND = [0, 0, 0, 0, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
const RIFF = ascii("RIFF");
const WEBP = ascii("WEBP");

const JFIF = ascii("JFIF\0");
const EXIF = ascii("Exif\0");                       // and one more byte, 0 by the standard
const ICC_PROFILE = ascii("ICC_PROFILE\0");
const ISO_GAIN_MAP = ascii("urn:iso:std:iso:ts:21496:-1\0");
const MPF = ascii("MPF\0");
const ADOBE = ascii("Adobe");

/** How deep images inside images are cleaned (the photo is 0, its EXIF
 *  thumbnail or an MPF image 1, a thumbnail's thumbnail 2); an EXIF block
 *  deeper than this goes whole. */
const MAX_DEPTH = 2;

const GPS_INFO = 0x8825;
const EXIF_IFD = 0x8769;
const INTEROP_IFD = 0xA005;
const THUMBNAIL_OFFSET = 0x0201;
const THUMBNAIL_LENGTH = 0x0202;
const STRIP_OFFSETS = 0x0111;
const STRIP_BYTE_COUNTS = 0x0117;
/** The EXIF entries that leave, with what they point to: GPSInfo (the GPS
 *  IFD), and XMLPacket (XMP), IPTC-NAA and Photoshop's ImageResources
 *  (IPTC), which some writers put in the TIFF block instead of APP1/APP13. */
const DROPPED_TAGS = new Set([GPS_INFO, 0x02BC, 0x83BB, 0x8649]);
/** Bytes per value of TIFF types 1-13 (BYTE, ASCII, SHORT, LONG, RATIONAL,
 *  SBYTE, UNDEFINED, SSHORT, SLONG, SRATIONAL, FLOAT, DOUBLE, IFD). */
const TYPE_SIZE = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];

/** WebP VP8X flags (libwebp WebPFeatureFlags). */
const WEBP_EXIF_FLAG = 0x08;
const WEBP_XMP_FLAG = 0x04;
/** The WebP chunks kept as they are, besides the first VP8X (EXIF is kept
 *  cleaned): the picture, its alpha, animation and colour profile. */
const WEBP_KEPT = new Set(["VP8 ", "VP8L", "ALPH", "ANIM", "ANMF", "ICCP"]);
/** Of those, the image data: kept even when cut short. */
const WEBP_IMAGE_DATA = new Set(["VP8 ", "VP8L", "ALPH", "ANMF"]);

/** The PNG ancillary chunks kept as they are (eXIf is kept cleaned, a text
 *  chunk unless its keyword names location metadata): what decoders use to
 *  show the picture (colour, transparency, density, animation, Apple's iDOT)
 *  and the registered ones that cannot say where. Critical chunks are all
 *  kept. */
const PNG_KEPT = new Set(["cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "cICP", "mDCV", "mDCv", "cLLI", "cLLi", "bKGD", "hIST", "tRNS",
    "pHYs", "sPLT", "tIME", "acTL", "fcTL", "fdAT", "oFFs", "pCAL", "sCAL", "sTER", "gIFg", "iDOT"]);
/** PNG image data: kept even when cut short. */
const PNG_IMAGE_DATA = new Set(["IDAT", "fdAT"]);

/** A PNG text chunk keyword that names metadata which can carry location. */
const PNG_LOCATION_KEYWORD = /^xml:com\.adobe\.xmp$|^raw profile type |exif|xmp|iptc|gps|geo|locat|latitude|longitude/i;

/**
 * `bytes` as they may leave: a JPEG, PNG or WebP without the metadata that
 * can carry where it was taken, anything else as given. The same object when
 * nothing changes, a new Uint8Array when something does, and null when it is
 * one of those formats and something failed inside (do not send it then).
 */
export function withoutLocation(bytes) {
    if (!(bytes instanceof Uint8Array)) return bytes;
    try {
        let edits;
        if (startsWith(bytes, JPEG_START)) edits = jpegEdits(bytes, 0);
        else if (startsWith(bytes, PNG_SIGNATURE)) edits = pngEdits(bytes);
        else if (startsWith(bytes, RIFF) && startsWith(bytes, WEBP, 8)) edits = webpEdits(bytes);
        else return bytes;
        return applyEdits(bytes, edits);
    } catch {
        return null;
    }
}

// ── bytes ───────────────────────────────────────────────────────────────────

function startsWith(bytes, prefix, at = 0, end = bytes.length) {
    if (at < 0 || at + prefix.length > end) return false;
    for (let i = 0; i < prefix.length; i++) if (bytes[at + i] !== prefix[i]) return false;
    return true;
}

function reader(bytes, littleEndian) {
    return littleEndian ? {
        u16: (o) => bytes[o] | (bytes[o + 1] << 8),
        u32: (o) => (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0,
    } : {
        u16: (o) => (bytes[o] << 8) | bytes[o + 1],
        u32: (o) => ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0,
    };
}

function writer(bytes, littleEndian) {
    const put = (o, v, n) => {
        for (let i = 0; i < n; i++) bytes[o + (littleEndian ? i : n - 1 - i)] = (v >>> (8 * i)) & 0xFF;
    };
    return { u16: (o, v) => put(o, v, 2), u32: (o, v) => put(o, v, 4) };
}

/** A plain Uint8Array copy of [start, end) (Buffer#slice would be a view). */
function copyOf(bytes, start = 0, end = bytes.length) {
    const out = new Uint8Array(end - start);
    out.set(bytes.subarray(start, end));
    return out;
}

const latin1 = (bytes, start, end) => String.fromCharCode(...bytes.subarray(start, end));

/**
 * `bytes` with `edits` made: each {start, end} is dropped, each {start, end,
 * replace} overwritten by `replace`, which is exactly as long. Returns
 * `bytes` itself when there is nothing to do.
 */
function applyEdits(bytes, edits) {
    if (!edits.length) return bytes;
    edits.sort((a, b) => a.start - b.start);
    let length = bytes.length;
    let from = 0;
    for (const e of edits) {
        if (e.start < from || e.end < e.start || e.end > bytes.length) throw new Error("edits overlap or overrun");
        if (e.replace) {
            if (e.replace.length !== e.end - e.start) throw new Error("a replacement changes the length");
        } else {
            length -= e.end - e.start;
        }
        from = e.end;
    }
    const out = new Uint8Array(length);
    let src = 0;
    let dst = 0;
    for (const e of edits) {
        out.set(bytes.subarray(src, e.start), dst);
        dst += e.start - src;
        if (e.replace) {
            out.set(e.replace, dst);
            dst += e.replace.length;
        }
        src = e.end;
    }
    out.set(bytes.subarray(src), dst);
    return out;
}

/** Where position `p` of the input lands once `edits` are made. */
function newPosition(edits, p) {
    let dropped = 0;
    for (const e of edits) if (!e.replace && e.end <= p) dropped += e.end - e.start;
    return p - dropped;
}

// ── EXIF (a TIFF block) ─────────────────────────────────────────────────────

/**
 * An EXIF TIFF block without GPS, as a copy of the same length (so every
 * offset in it still holds): every entry of DROPPED_TAGS leaves its IFD, the
 * other entries moving up; then every byte that no IFD left in it references
 * becomes zero, and so does everything a dropped entry pointed to. That takes
 * the GPS IFD however it lies, GPS a naive stripper left behind without its
 * pointer, and a segment a wrong length swallowed: the block keeps what its
 * structure says is in it, and nothing else. The
 * thumbnail is cleaned in its place. `tiff` itself when there is nothing to
 * do; null when the block cannot be parsed (the caller then drops it whole).
 *
 * A pass is made again on what it gives until nothing changes: in a broken
 * block, what a dropped entry pointed to can overlap an IFD that is kept,
 * and the values that IFD pointed to are then referenced by nothing. A block
 * that has not settled after four passes goes whole.
 */
function tiffWithoutGps(tiff, depth) {
    let current = tiff;
    for (let pass = 0; pass < 4; pass++) {
        const next = tiffPass(current, depth);
        if (next === null || next === current) return next;
        current = next;
    }
    return null;
}

/** One pass of tiffWithoutGps. */
function tiffPass(tiff, depth) {
    const layout = tiffLayout(tiff);
    if (!layout) return null;
    let thumbnail = null;
    if (layout.thumbnail) {
        const { start, end } = layout.thumbnail;
        const original = tiff.subarray(start, end);
        const clean = applyEdits(original, jpegEdits(original, depth + 1));
        if (clean !== original) thumbnail = clean;
    }
    const referenced = new Uint8Array(tiff.length);
    for (const [start, end] of layout.keep) referenced.fill(1, start, end);
    const dropping = layout.ifds.some((ifd) => ifd.drop.length);
    const stray = tiff.some((b, i) => b !== 0 && !referenced[i]);
    if (!dropping && !stray && !thumbnail) return tiff;

    const out = copyOf(tiff);
    const r = reader(tiff, layout.le);
    const w = writer(out, layout.le);
    // The dropped entries leave their IFDs: the others move up, the next-IFD
    // offset follows them.
    for (const ifd of layout.ifds) {
        if (!ifd.drop.length) continue;
        let p = ifd.at + 2;
        for (let k = 0; k < ifd.count; k++) {
            if (ifd.drop.includes(k)) continue;
            const e = ifd.at + 2 + 12 * k;
            out.set(tiff.subarray(e, e + 12), p);
            p += 12;
        }
        const next = ifd.at + 2 + 12 * ifd.count;
        out.set(tiff.subarray(next, next + 4), p);
        w.u16(ifd.at, ifd.count - ifd.drop.length);
    }
    // What nothing references becomes zeros (the freed entries among it), and
    // so does what the dropped entries pointed to, wherever it lies.
    for (let i = 0; i < out.length; i++) if (!referenced[i]) out[i] = 0;
    for (const [start, end] of layout.wipe) out.fill(0, start, end);
    // The thumbnail, cleaned, where it was; its length entry says how long.
    if (thumbnail) {
        const { start, end, ifd } = layout.thumbnail;
        out.set(thumbnail, start);
        out.fill(0, start + thumbnail.length, end);
        const o = reader(out, layout.le);
        for (let k = 0; k < o.u16(ifd); k++) {
            const e = ifd + 2 + 12 * k;
            if (o.u16(e) !== THUMBNAIL_LENGTH) continue;
            if (o.u16(e + 2) === 3) w.u16(e + 8, thumbnail.length);
            else w.u32(e + 8, thumbnail.length);
        }
    }
    // What leaves must parse, with nothing of DROPPED_TAGS left in it.
    const check = tiffLayout(out);
    if (!check || check.ifds.some((ifd) => ifd.drop.length)) return null;
    return out;
}

/**
 * A TIFF block's structure, as far as EXIF has one: the IFDs reachable from
 * IFD0 (its chain, the Exif and Interoperability IFDs), the entries of
 * DROPPED_TAGS in each, the ranges the block keeps once those are gone (the
 * header, each IFD, each other entry's value, the IFD1 thumbnail or strips),
 * the ranges what the dropped entries point to occupy (`wipe`: the GPS IFD
 * and its values, XMP, IPTC), and the IFD1 thumbnail when it is a JPEG
 * inside the block. null when it cannot be parsed: a bad header, an IFD0
 * outside the block, an IFD the block's end cuts, or an Exif or
 * Interoperability pointer that is not one. An IFD that lies wholly outside
 * the block is not in it, and is passed over; so is a value.
 */
function tiffLayout(t) {
    const len = t.length;
    if (len < 8) return null;
    let le;
    if (t[0] === 0x49 && t[1] === 0x49) le = true;
    else if (t[0] === 0x4D && t[1] === 0x4D) le = false;
    else return null;
    const { u16, u32 } = reader(t, le);
    if (u16(2) !== 42) return null;

    const pointer = (e) => {
        const type = u16(e + 2);
        if (u32(e + 4) !== 1) return null;
        if (type === 3) return u16(e + 8);
        if (type === 4 || type === 13) return u32(e + 8);
        return null;
    };
    /** Where an entry's value lies outside the entry, or null. */
    const valueRange = (e) => {
        const type = u16(e + 2);
        if (!(type >= 1 && type <= 13)) return null;
        const size = TYPE_SIZE[type] * u32(e + 4);
        if (size <= 4) return null;
        const at = u32(e + 8);
        return at >= 8 && at + size <= len ? [at, at + size] : null;
    };
    /** A SHORT or LONG entry's values. */
    const numbers = (e) => {
        const type = u16(e + 2);
        const count = u32(e + 4);
        const size = type === 3 ? 2 : type === 4 ? 4 : 0;
        if (!size || count > len) return [];
        const at = count * size <= 4 ? e + 8 : u32(e + 8);
        if (at + count * size > len) return [];
        return Array.from({ length: count }, (_, i) => (size === 2 ? u16(at + 2 * i) : u32(at + 4 * i)));
    };
    const ifds = [];
    const keep = [[0, 8]];
    const wipe = [];
    let thumbnail = null;
    const seen = new Set();
    const queue = [{ at: u32(4), kind: "ifd0" }];
    while (queue.length) {
        const { at, kind } = queue.shift();
        if (seen.has(at)) continue;
        seen.add(at);
        if (at < 8 || at + 2 > len) {
            if (kind === "ifd0") return null;
            continue;
        }
        const count = u16(at);
        const next = at + 2 + 12 * count;
        if (next + 4 > len) return null;
        const ifd = { at, count, drop: [] };
        let thumbOffset = null;
        let thumbLength = null;
        let strips = null;
        let stripLengths = null;
        for (let k = 0; k < count; k++) {
            const e = at + 2 + 12 * k;
            const tag = u16(e);
            if (DROPPED_TAGS.has(tag)) {
                ifd.drop.push(k);
                if (tag === GPS_INFO) {
                    const g = pointer(e);
                    if (g !== null) wipe.push(...gpsRanges(t, le, g));
                } else {
                    const range = valueRange(e);
                    if (range) wipe.push(range);
                }
                continue;
            }
            const range = valueRange(e);
            if (range) keep.push(range);
            if (tag === EXIF_IFD && kind !== "exif" && kind !== "interop") {
                const p = pointer(e);
                if (p === null) return null;
                queue.push({ at: p, kind: "exif" });
            } else if (tag === INTEROP_IFD && kind === "exif") {
                const p = pointer(e);
                if (p === null) return null;
                queue.push({ at: p, kind: "interop" });
            } else if (kind === "ifd1" && tag === THUMBNAIL_OFFSET) {
                thumbOffset = pointer(e);
            } else if (kind === "ifd1" && tag === THUMBNAIL_LENGTH) {
                thumbLength = pointer(e);
            } else if (tag === STRIP_OFFSETS) {
                strips = numbers(e);
            } else if (tag === STRIP_BYTE_COUNTS) {
                stripLengths = numbers(e);
            }
        }
        keep.push([at, at + 2 + 12 * (count - ifd.drop.length) + 4]);
        ifds.push(ifd);
        if (kind === "ifd0" || kind === "ifd1" || kind === "chain") {
            const following = u32(next);
            if (following) queue.push({ at: following, kind: kind === "ifd0" ? "ifd1" : "chain" });
        }
        if (thumbOffset !== null && thumbLength && thumbOffset >= 8 && thumbOffset + thumbLength <= len) {
            keep.push([thumbOffset, thumbOffset + thumbLength]);
            if (t[thumbOffset] === 0xFF && t[thumbOffset + 1] === 0xD8) {
                thumbnail = { start: thumbOffset, end: thumbOffset + thumbLength, ifd: at };
            }
        }
        if (strips && stripLengths && strips.length === stripLengths.length) {
            strips.forEach((s, i) => {
                if (s >= 8 && s + stripLengths[i] <= len) keep.push([s, s + stripLengths[i]]);
            });
        }
    }
    return { le, ifds, keep, wipe, thumbnail };
}

/** The ranges a GPS IFD at `at` and its values occupy in `t`, as far as
 *  they are in it and can be read. */
function gpsRanges(t, le, at) {
    const len = t.length;
    if (at < 8 || at + 2 > len) return [];
    const { u16, u32 } = reader(t, le);
    const count = u16(at);
    const ranges = [[at, Math.min(len, at + 2 + 12 * count + 4)]];
    for (let k = 0; k < count && at + 2 + 12 * (k + 1) <= len; k++) {
        const e = at + 2 + 12 * k;
        const type = u16(e + 2);
        if (!(type >= 1 && type <= 13)) continue;
        const size = TYPE_SIZE[type] * u32(e + 4);
        const value = u32(e + 8);
        if (size > 4 && value >= 8 && value + size <= len) ranges.push([value, value + size]);
    }
    return ranges;
}

// ── JPEG ────────────────────────────────────────────────────────────────────

const DROP = "drop";

/**
 * The edits that clean the JPEG in `bytes` (SOI at 0), at `depth` (0 the
 * photo, deeper an image inside it, which keeps no MPF and nothing after its
 * EOI).
 */
function jpegEdits(bytes, depth) {
    const len = bytes.length;
    const edits = [];
    let mpf = null;
    let imageEnd = len;
    let pos = 2;
    while (pos < len) {
        if (bytes[pos] !== 0xFF) {
            // Not a marker: bytes a decoder skips to the next one.
            const next = nextMarker(bytes, pos);
            edits.push({ start: pos, end: next });
            pos = next;
            continue;
        }
        let m = pos;
        while (m + 1 < len && bytes[m + 1] === 0xFF) m++;          // fill bytes
        if (m + 1 >= len) {
            edits.push({ start: pos, end: len });
            break;
        }
        const code = bytes[m + 1];
        const body = m + 2;
        if (code === 0x00) {
            const next = nextMarker(bytes, body);
            edits.push({ start: pos, end: next });
            pos = next;
            continue;
        }
        if (code === 0xD9) {                                        // EOI
            imageEnd = body;
            break;
        }
        if (code === 0xD8) {                                        // a second SOI: nothing after it is this image
            edits.push({ start: pos, end: len });
            break;
        }
        if (code === 0x01 || (code >= 0xD0 && code <= 0xD7)) {     // TEM, RSTn: no length
            pos = body;
            continue;
        }
        const end = body + 2 <= len ? body + ((bytes[body] << 8) | bytes[body + 1]) : -1;
        if (end < body + 2 || end > len) {
            // A length that does not fit: nothing after it can be delimited.
            edits.push({ start: pos, end: len });
            break;
        }
        if (code === 0xDA) {                                        // SOS: the entropy-coded data follows
            pos = scanEnd(bytes, end);
            continue;
        }
        if (code < 0xC0 || code === 0xC8) {                         // reserved: no decoder reads it
            edits.push({ start: pos, end });
            pos = end;
            continue;
        }
        if (code >= 0xE0 && code <= 0xEF) {
            const verdict = appSegment(code, bytes, body + 2, end, depth, mpf === null);
            if (verdict === DROP) edits.push({ start: pos, end });
            else if (verdict?.edit) edits.push(verdict.edit);
            else if (verdict?.mpf) mpf = { ...verdict.mpf, start: pos, end };
        }
        pos = end;
    }

    if (mpf) {
        const listed = mpfImages(bytes, mpf, imageEnd);
        if (listed) {
            let cursor = imageEnd;
            for (const image of listed.images) {
                if (image.start > cursor) edits.push({ start: cursor, end: image.start });
                for (const e of jpegEdits(bytes.subarray(image.start, image.end), depth + 1)) {
                    edits.push({ ...e, start: e.start + image.start, end: e.end + image.start });
                }
                cursor = image.end;
            }
            if (cursor < len) edits.push({ start: cursor, end: len });
            const patch = mpfPatch(bytes, mpf, listed, imageEnd, edits);
            if (patch) edits.push(patch);
            return edits;
        }
        // An index that does not describe this file goes, with what follows.
        edits.push({ start: mpf.start, end: mpf.end });
    }
    if (imageEnd < len) edits.push({ start: imageEnd, end: len });
    return edits;
}

/** The first marker at or after `i` outside entropy-coded data (an FF not
 *  followed by 00), or the end. */
function nextMarker(bytes, i) {
    const len = bytes.length;
    for (;;) {
        i = bytes.indexOf(0xFF, i);
        if (i < 0) return len;
        let j = i + 1;
        while (j < len && bytes[j] === 0xFF) j++;
        if (j >= len) return len;
        if (bytes[j] !== 0x00) return i;
        i = j + 1;
    }
}

/** Where the entropy-coded data starting at `i` ends: the first marker that
 *  is not a stuffed FF 00 or a restart marker, or the end. */
function scanEnd(bytes, i) {
    const len = bytes.length;
    for (;;) {
        i = bytes.indexOf(0xFF, i);
        if (i < 0) return len;
        let j = i + 1;
        while (j < len && bytes[j] === 0xFF) j++;
        if (j >= len) return len;
        const b = bytes[j];
        if (b !== 0x00 && !(b >= 0xD0 && b <= 0xD7)) return i;
        i = j + 1;
    }
}

/** What becomes of an APPn segment whose payload is [payload, end). */
function appSegment(code, bytes, payload, end, depth, mpfFree) {
    if (code === 0xE0) return startsWith(bytes, JFIF, payload, end) ? null : DROP;
    if (code === 0xE1) {
        if (depth > MAX_DEPTH || !startsWith(bytes, EXIF, payload, end) || payload + 6 > end) return DROP;
        const tiff = bytes.subarray(payload + 6, end);
        const clean = tiffWithoutGps(tiff, depth);
        if (!clean) return DROP;
        return clean === tiff ? null : { edit: { start: payload + 6, end, replace: clean } };
    }
    if (code === 0xE2) {
        if (startsWith(bytes, ICC_PROFILE, payload, end) || startsWith(bytes, ISO_GAIN_MAP, payload, end)) return null;
        if (depth === 0 && mpfFree && startsWith(bytes, MPF, payload, end)) {
            const mpf = parseMpf(bytes, payload, end);
            return mpf ? { mpf } : DROP;
        }
        return DROP;
    }
    if (code === 0xEE) return startsWith(bytes, ADOBE, payload, end) ? null : DROP;
    return DROP;
}

/** An MPF index (CIPA DC-007): its byte order, the MP header it counts
 *  offsets from, and where its MP entries are. null when it cannot be read. */
function parseMpf(bytes, payload, end) {
    const base = payload + 4;
    if (base + 8 > end) return null;
    let le;
    if (bytes[base] === 0x49 && bytes[base + 1] === 0x49) le = true;
    else if (bytes[base] === 0x4D && bytes[base + 1] === 0x4D) le = false;
    else return null;
    const { u16, u32 } = reader(bytes, le);
    if (u16(base + 2) !== 42) return null;
    const ifd = base + u32(base + 4);
    if (ifd + 2 > end) return null;
    const n = u16(ifd);
    if (ifd + 2 + 12 * n > end) return null;
    let count = null;
    let entries = null;
    let length = null;
    for (let k = 0; k < n; k++) {
        const e = ifd + 2 + 12 * k;
        const tag = u16(e);
        if (tag === 0xB001 && u16(e + 2) === 4 && u32(e + 4) === 1) count = u32(e + 8);
        else if (tag === 0xB002 && u16(e + 2) === 7) {
            length = u32(e + 4);
            entries = base + u32(e + 8);
        }
    }
    if (!count || entries === null || length !== 16 * count || entries + length > end) return null;
    return { base, le, entries, count };
}

/** The images an MPF index lists after the photo's EOI, in file order, or
 *  null when the index does not describe this file. */
function mpfImages(bytes, mpf, imageEnd) {
    const { u32 } = reader(bytes, mpf.le);
    let first = null;
    const images = [];
    for (let i = 0; i < mpf.count; i++) {
        const at = mpf.entries + 16 * i;
        const size = u32(at + 4);
        const offset = u32(at + 8);
        if (i === 0) {
            if (offset !== 0) return null;
            first = { at, size };
            continue;
        }
        if (size === 0) continue;
        const start = mpf.base + offset;
        const end = start + size;
        if (offset === 0 || start < imageEnd || end > bytes.length || bytes[start] !== 0xFF || bytes[start + 1] !== 0xD8) return null;
        images.push({ at, start, end });
    }
    images.sort((a, b) => a.start - b.start);
    for (let i = 1; i < images.length; i++) if (images[i].start < images[i - 1].end) return null;
    return { first, images };
}

/** The MP entries rewritten for where the photo ends and its images are once
 *  `edits` are made, or null when they do not change. */
function mpfPatch(bytes, mpf, listed, imageEnd, edits) {
    const at = (p) => newPosition(edits, p);
    const start = mpf.entries;
    const end = start + 16 * mpf.count;
    const block = copyOf(bytes, start, end);
    const w = writer(block, mpf.le);
    if (listed.first.size === imageEnd) w.u32(listed.first.at - start + 4, at(imageEnd));
    for (const image of listed.images) {
        w.u32(image.at - start + 4, at(image.end) - at(image.start));
        w.u32(image.at - start + 8, at(image.start) - at(mpf.base));
    }
    for (let i = 0; i < block.length; i++) if (block[i] !== bytes[start + i]) return { start, end, replace: block };
    return null;
}

// ── PNG ─────────────────────────────────────────────────────────────────────

function pngEdits(bytes) {
    const len = bytes.length;
    const { u32 } = reader(bytes, false);
    const edits = [];
    let pos = PNG_SIGNATURE.length;
    while (pos < len) {
        const size = pos + 12 <= len ? u32(pos) : -1;
        const type = size >= 0 ? latin1(bytes, pos + 4, pos + 8) : "";
        const data = pos + 8;
        const next = data + size + 4;
        // Not a chunk (or one cut short) cannot be delimited, and nothing after
        // it can: it goes with the rest, but for image data cut short, which
        // still shows what it has. A file that ends in IEND was not cut: its
        // image data's length is wrong, and it would take what follows.
        if (!/^[A-Za-z]{4}$/.test(type) || next > len || (type === "IHDR" && size !== 13)) {
            const cut = next > len && PNG_IMAGE_DATA.has(type) && !startsWith(bytes, PNG_IEND, len - PNG_IEND.length);
            if (!cut) edits.push({ start: pos, end: len });
            break;
        }
        const verdict = pngChunk(type, bytes, data, data + size);
        if (verdict === DROP) edits.push({ start: pos, end: next });
        else if (verdict) edits.push({ start: data, end: next, replace: verdict });
        pos = next;
        if (type === "IEND") {
            if (pos < len) edits.push({ start: pos, end: len });
            break;
        }
    }
    return edits;
}

/** What becomes of a PNG chunk: null to keep it, DROP, or its data and CRC
 *  anew. */
function pngChunk(type, bytes, data, end) {
    if (!(type.charCodeAt(0) & 0x20)) return null;                  // critical: the picture itself
    if (type === "eXIf") {
        // A TIFF block, behind EXIF's JPEG header when a writer put one there.
        const tiffAt = startsWith(bytes, EXIF, data, end) ? data + 6 : data;
        const tiff = bytes.subarray(tiffAt, end);
        const clean = tiffWithoutGps(tiff, 0);
        if (!clean) return DROP;
        if (clean === tiff) return null;
        const chunk = new Uint8Array(end - data + 4);
        chunk.set(bytes.subarray(data, tiffAt), 0);
        chunk.set(clean, tiffAt - data);
        const crc = crc32(chunk, 0, end - data, crc32(bytes, data - 4, data));
        writer(chunk, false).u32(end - data, crc);
        return chunk;
    }
    if (type === "tEXt" || type === "zTXt" || type === "iTXt") {
        const nul = bytes.subarray(data, Math.min(end, data + 80)).indexOf(0);
        if (nul < 1) return DROP;                                   // no keyword to go by
        return PNG_LOCATION_KEYWORD.test(latin1(bytes, data, data + nul)) ? DROP : null;
    }
    return PNG_KEPT.has(type) ? null : DROP;
}

let CRC_TABLE = null;

/** CRC-32 (ISO 3309, as PNG uses it) of [start, end), continuing `previous`
 *  (a finished CRC) when given. */
function crc32(bytes, start, end, previous = 0) {
    if (!CRC_TABLE) {
        CRC_TABLE = new Uint32Array(256);
        for (let n = 0; n < 256; n++) {
            let c = n;
            for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
            CRC_TABLE[n] = c >>> 0;
        }
    }
    let c = (previous ^ 0xFFFFFFFF) >>> 0;
    for (let i = start; i < end; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
}

// ── WebP ────────────────────────────────────────────────────────────────────

function webpEdits(bytes) {
    const len = bytes.length;
    const { u32 } = reader(bytes, true);
    const edits = [];
    const riffSize = u32(4);
    const riffEnd = 8 + riffSize;
    const end = Math.min(len, riffEnd);
    let pos = 12;
    let vp8x = -1;
    let exifKept = 0;
    let exifDropped = 0;
    let xmpDropped = 0;
    while (pos < end) {
        const fourcc = pos + 8 <= end ? latin1(bytes, pos, pos + 4) : "";
        const size = fourcc ? u32(pos + 4) : 0;
        const data = pos + 8;
        const dataEnd = data + size;
        // A chunk cut short, or a VP8X that is not the 10 bytes it always
        // is, cannot be delimited, and nothing after it can: it goes with
        // the rest, but for image data cut short, which still shows what it
        // has. Image data that runs past the RIFF itself was not cut: its
        // size is wrong, and it would take what follows.
        if (!fourcc || dataEnd > end || (fourcc === "VP8X" && size !== 10)) {
            if (!(dataEnd > end && dataEnd <= riffEnd && WEBP_IMAGE_DATA.has(fourcc))) {
                edits.push({ start: pos, end });
                if (fourcc === "EXIF") exifDropped++;
                if (fourcc === "XMP ") xmpDropped++;
            }
            break;
        }
        const next = Math.min(dataEnd + (size & 1), end);
        if (fourcc === "VP8X" && vp8x < 0) {
            vp8x = data;
        } else if (fourcc === "EXIF") {
            // A TIFF block, behind EXIF's JPEG header when a writer put one there.
            const tiffAt = startsWith(bytes, EXIF, data, dataEnd) ? data + 6 : data;
            const tiff = bytes.subarray(tiffAt, dataEnd);
            const clean = tiffWithoutGps(tiff, 0);
            if (!clean) {
                edits.push({ start: pos, end: next });
                exifDropped++;
            } else {
                exifKept++;
                if (clean !== tiff) edits.push({ start: tiffAt, end: dataEnd, replace: clean });
            }
        } else if (!WEBP_KEPT.has(fourcc)) {
            // XMP, and every chunk this does not read (a second VP8X among them).
            edits.push({ start: pos, end: next });
            if (fourcc === "XMP ") xmpDropped++;
        }
        pos = next;
    }
    if (vp8x >= 0) {
        let flags = bytes[vp8x];
        if (xmpDropped) flags &= ~WEBP_XMP_FLAG;
        if (exifDropped && !exifKept) flags &= ~WEBP_EXIF_FLAG;
        if (flags !== bytes[vp8x]) edits.push({ start: vp8x, end: vp8x + 1, replace: Uint8Array.of(flags) });
    }
    let dropped = 0;
    for (const e of edits) if (!e.replace) dropped += e.end - e.start;
    if (dropped) {
        const size = new Uint8Array(4);
        writer(size, true).u32(0, riffSize - dropped);
        edits.push({ start: 4, end: 8, replace: size });
    }
    if (riffEnd < len) edits.push({ start: riffEnd, end: len });     // after the RIFF
    return edits;
}
