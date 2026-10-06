/**
 * A PHOTO WITHOUT WHERE IT WAS TAKEN IS STILL THE SAME PICTURE, IN A BROWSER
 * (James, 2026-10-05: no photo leaves with GPS location, whatever its format).
 *
 * photo_metadata.test.mjs takes withoutLocation's output apart; this has
 * Chromium decode it. Each photo, as picked and as it leaves, is decoded
 * twice (an <img> and createImageBitmap with the image's own orientation),
 * and the two must be the same picture: the same size, upright the same way,
 * pixel for pixel. A JPEG and a PNG whose EXIF says "rotate 90" are shown
 * 8x16, not 16x8, both ways (Chromium rotates by a PNG's eXIf too), and the
 * same JPEG with its EXIF gone is shown 16x8: keeping Orientation is what
 * keeps it upright. Nothing is fetched: the page is blank and the bytes
 * come from here.
 *
 * It runs only with RETICHAT_BOOT_TESTS=1 (`npm run test:full`; deploy.sh
 * always sets it), as the other Chromium tests do.
 *
 * Run: RETICHAT_BOOT_TESTS=1 node --test photo_metadata_decode.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { createRequire } from "node:module";
import { withoutLocation } from "./lib/photo_metadata.js";
import {
    PROGRESSIVE_JPEG, THUMB_JPEG, SENTINEL, XMP_PACKET, sentinelsIn, tiffBlock, gpsEntries,
    exifSegment, xmpSegment, iptcSegment, iccSegment, adobeSegment, comSegment, goproSegment, jpegWith, jpegSegments,
    gainMapJpeg, png, pngChunk, textChunk, webp, riffChunk,
} from "./test_photos.mjs";

const BOOT_TESTS = process.env.RETICHAT_BOOT_TESTS === "1";
const chromiumTest = BOOT_TESTS ? test
    : (name, fn) => test(name, { skip: "RETICHAT_BOOT_TESTS is not 1: run `npm run test:full` (deploy.sh always does)" }, fn);

/** Playwright's Chromium, or null when the test was skipped for want of it. */
async function launchChromium(t) {
    let chromium;
    try {
        ({ chromium } = createRequire(new URL("../test-harnesses/distro-pipeline/package.json", import.meta.url))("playwright"));
    } catch {
        t.skip("no Playwright in ../test-harnesses/distro-pipeline");
        return null;
    }
    try {
        return await chromium.launch({ headless: true, args: ["--disable-dev-shm-usage"] });
    } catch (e) {
        if (/Executable doesn't exist/i.test(e?.message ?? "")) { t.skip("Playwright has no Chromium installed"); return null; }
        throw e;
    }
}

/** What Chromium shows of `bytes`: the <img>'s size, and the bitmap's size
 *  and pixels (a hash) with the image's own orientation. */
function decodeIn(page) {
    return (bytes, type) => page.evaluate(async ([b64, type]) => {
        const data = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
        const url = URL.createObjectURL(new Blob([data], { type }));
        const img = new Image();
        img.src = url;
        await img.decode();
        URL.revokeObjectURL(url);
        const bitmap = await createImageBitmap(new Blob([data], { type }), { imageOrientation: "from-image" });
        const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
        const context = canvas.getContext("2d");
        context.drawImage(bitmap, 0, 0);
        let hash = 0;
        for (const v of context.getImageData(0, 0, bitmap.width, bitmap.height).data) hash = (Math.imul(hash, 31) + v) >>> 0;
        return { img: `${img.naturalWidth}x${img.naturalHeight}`, bitmap: `${bitmap.width}x${bitmap.height}`, hash };
    }, [Buffer.from(bytes).toString("base64"), type]);
}

const thumbnail = jpegWith([exifSegment(tiffBlock({ exif: false, orientation: 1, gps: gpsEntries(SENTINEL.thumbGps) }).block)], { base: THUMB_JPEG });

/** [name, bytes, type, how Chromium shows it]: every photo here says "rotate
 *  90" (Orientation 6) but the WebP, whose EXIF Chromium does not apply. */
const PHOTOS = [
    ["JPEG, little-endian EXIF, XMP, IPTC, ICC, Adobe, COM, GoPro",
        jpegWith([exifSegment(tiffBlock().block), xmpSegment(), iptcSegment(), iccSegment(), adobeSegment(), comSegment(), goproSegment()]), "image/jpeg", "8x16"],
    ["JPEG, big-endian EXIF with a thumbnail that has its own GPS",
        jpegWith([exifSegment(tiffBlock({ le: false, thumbnail }).block), xmpSegment()]), "image/jpeg", "8x16"],
    ["progressive JPEG", jpegWith([exifSegment(tiffBlock().block), xmpSegment()], { base: PROGRESSIVE_JPEG }), "image/jpeg", "8x16"],
    ["JPEG with an MPF gain map, a video and a trailer after it", gainMapJpeg().bytes, "image/jpeg", "8x16"],
    ["PNG, big-endian eXIf, XMP, location text",
        png({ before: [pngChunk("eXIf", tiffBlock({ le: false }).block), textChunk("iTXt", "XML:com.adobe.xmp", XMP_PACKET), textChunk("tEXt", "Location", SENTINEL.location)] }),
        "image/png", "8x16"],
    ["WebP, EXIF and XMP", webp([riffChunk("EXIF", tiffBlock().block), riffChunk("XMP ", XMP_PACKET)]), "image/webp", "16x8"],
];

chromiumTest("in Chromium, each photo as it leaves is the very picture it was as picked, upright the same way", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    try {
        const page = await browser.newPage();
        const requests = [];
        page.on("request", (r) => requests.push(r.url()));
        await page.setContent("<!doctype html><title>decode</title>");
        const decode = decodeIn(page);
        for (const [name, bytes, type, shown] of PHOTOS) {
            const cleaned = withoutLocation(bytes);
            assert.ok(cleaned instanceof Uint8Array && cleaned !== bytes, name);
            assert.notDeepEqual(sentinelsIn(bytes), [], `${name}: as picked, it says where it was taken`);
            assert.deepEqual(sentinelsIn(cleaned), [], `${name}: as it leaves, it does not`);
            const before = await decode(bytes, type);
            const after = await decode(cleaned, type);
            assert.deepEqual(after, before, `${name}: the same picture`);
            assert.equal(after.img, shown, `${name}: shown ${shown}`);
            assert.equal(after.bitmap, shown, `${name}: drawn ${shown}`);
        }
        // The control: the first JPEG with its EXIF gone is shown as stored, 16x8.
        const [, first] = PHOTOS[0];
        const exif = jpegSegments(first).segments.find((s) => s.marker === 0xE1);
        const noExif = Buffer.concat([first.subarray(0, exif.start), first.subarray(exif.end)]);
        assert.equal((await decode(noExif, "image/jpeg")).img, "16x8", "without Orientation the photo is on its side");
        assert.deepEqual(requests.filter((u) => !u.startsWith("blob:") && !u.startsWith("about:") && !u.startsWith("data:")), [], "nothing fetched");
    } finally {
        await browser.close();
    }
});
