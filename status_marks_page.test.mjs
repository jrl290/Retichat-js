/**
 * THE DELIVERY MARKS ON THE LIGHT THEME (Retichat-js #2).
 *
 * On the light theme the outgoing bubble is --primary itself, and the sent
 * and delivered checks were drawn in --primary: blue on the same blue, not
 * there at all. The sending dot and the propagated check (--text-secondary)
 * and the failed cross (--danger) came out about as dark as the bubble too.
 *
 * This draws an outgoing bubble in each state with the real stylesheet in
 * Chromium, on both themes, and checks each mark against its bubble as it is
 * drawn: its colour at its own opacity and the footer's dimming, over the
 * bubble's colour, at least 2:1 by WCAG's contrast ratio. The dark theme's
 * marks, which nobody has missed, are 2.1:1 to 3:1. The hourglass is an emoji
 * and keeps its own colours. The bubble is App._buildMsgBubble's markup.
 *
 * It runs only with RETICHAT_BOOT_TESTS=1 (`npm run test:full`; deploy.sh
 * always sets it), as the other Chromium tests do.
 *
 * Run: RETICHAT_BOOT_TESTS=1 node --test status_marks_page.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

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

const STYLE = readFileSync(new URL("./style.css", import.meta.url), "utf8");
// App._statusIcon's glyphs, but the hourglass.
const MARKS = { sending: "●", propagated: "✓", sent: "✓", proved: "✓✓", failed: "✗" };

const page = (theme) => `<!doctype html><html data-theme="${theme}"><head><meta charset="utf-8">
<style>${STYLE}</style></head><body>${Object.entries(MARKS).map(([status, glyph]) => `
<div class="msg-row own"><div class="msg-line"><div class="msg-bubble">
  <div class="msg-text">${status}</div>
  <div class="msg-meta"><span class="msg-time">12:34</span><span class="msg-status ${status}" data-msg-status="${status}">${glyph}</span></div>
</div></div></div>`).join("")}</body></html>`;

/** Each mark as drawn: its colour, the alpha it is drawn at, and its bubble's colour. */
function drawn() {
    const rgba = (s) => { const [r, g, b, a = 1] = s.match(/[\d.]+/g).map(Number); return [r, g, b, a]; };
    return [...document.querySelectorAll(".msg-status")].map((mark) => {
        const style = getComputedStyle(mark);
        const dim = style.filter.match(/opacity\(([\d.]+)\)/);
        const [r, g, b, a] = rgba(style.color);
        return {
            status: mark.dataset.msgStatus,
            color: [r, g, b],
            alpha: a * Number(style.opacity) * (dim ? Number(dim[1]) : 1),
            bubble: rgba(getComputedStyle(mark.closest(".msg-bubble")).backgroundColor).slice(0, 3),
        };
    });
}

function contrast({ color, alpha, bubble }) {
    const over = color.map((c, i) => alpha * c + (1 - alpha) * bubble[i]);
    const luminance = (rgb) => {
        const [r, g, b] = rgb.map((c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; });
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const [hi, lo] = [luminance(over), luminance(bubble)].sort((x, y) => y - x);
    return (hi + 0.05) / (lo + 0.05);
}

chromiumTest("every delivery mark shows on its bubble, on both themes", async (t) => {
    const browser = await launchChromium(t);
    if (!browser) return;
    t.after(() => browser.close());
    const tab = await browser.newPage();
    for (const theme of ["light", "dark"]) {
        await tab.setContent(page(theme));
        const marks = await tab.evaluate(drawn);
        assert.deepEqual(marks.map((m) => m.status), Object.keys(MARKS), `${theme}: every mark drawn`);
        for (const mark of marks) {
            const ratio = contrast(mark);
            assert.ok(ratio >= 2, `${theme} ${mark.status}: ${ratio.toFixed(2)}:1 against its bubble (rgb ${mark.color} at ${mark.alpha.toFixed(2)} on rgb ${mark.bubble})`);
        }
    }
});
