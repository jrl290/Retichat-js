/**
 * CHANNEL INFO SHARES THE FULL NAME — _renderChannelInfoModal in app.js.
 *
 * James, 2026-09-27: a channel is shared by its full name "<root>.<name>";
 * for a private channel that name is the invite. The info sheet showed only
 * "#name" as a title and the hash (useless for joining). Now it shows the
 * full name whole and selectable, the hash secondary, a Copy name button that
 * copies exactly the full name, Share where navigator.share exists, and a
 * one-line hint that says who can join.
 *
 * The modal and h() are lifted out of app.js and run over a tiny fake DOM,
 * so this is the shipped code, not a copy.
 *
 * Run: node --test channel_info.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
    channelShareText, channelShareHint, isPrivateChannelName,
} from "./lib/channel_name.js";

const PRIVATE_HINT = "Share the full name to invite someone. Anyone with it can read and post.";
const PUBLIC_HINT = "Anyone who knows the name can join.";

test("share text is exactly the full name: no '#', no whitespace", () => {
    assert.equal(channelShareText("abd77af5c72e6b5b.general"), "abd77af5c72e6b5b.general");
    assert.equal(channelShareText("#abd77af5c72e6b5b.general"), "abd77af5c72e6b5b.general");
    assert.equal(channelShareText("  public.general\n"), "public.general");
    assert.equal(channelShareText(null), "");
});

test("a root other than public is private; public and root-less names are not", () => {
    assert.equal(isPrivateChannelName("abd77af5c72e6b5b.general"), true);
    assert.equal(isPrivateChannelName("4cdc4115.nametest-096499"), true);
    assert.equal(isPrivateChannelName("public.general"), false);
    assert.equal(isPrivateChannelName("general"), false);
    assert.equal(channelShareHint("abd77af5c72e6b5b.general"), PRIVATE_HINT);
    assert.equal(channelShareHint("public.general"), PUBLIC_HINT);
});

// ── the real modal, over a minimal DOM ─────────────────────────────────────

class FakeEl {
    constructor(tag) {
        this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {};
        this.style = {}; this.listeners = {}; this.className = ""; this.disabled = false;
        this._text = "";
        const self = this;
        this.classList = {
            add(c) { if (!self.className.split(" ").includes(c)) self.className = (self.className + " " + c).trim(); },
            remove(c) { self.className = self.className.split(" ").filter((x) => x && x !== c).join(" "); },
            contains(c) { return self.className.split(" ").includes(c); },
        };
    }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === "id") this.id = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
    appendChild(c) { this.children.push(c); return c; }
    set textContent(t) { this._text = t; this.children = []; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
    *walk() { yield this; for (const c of this.children) if (c instanceof FakeEl) yield* c.walk(); }
    byClass(cls) { return [...this.walk()].find((e) => e.className.split(" ").includes(cls)) ?? null; }
    fire(t) { for (const f of this.listeners[t] || []) f({ target: this, preventDefault() {} }); }
}

const flush = () => new Promise((r) => setImmediate(r));

async function renderInfo({ channelName, share = false, clipboardFails = false }) {
    const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
    const brace = (from) => {
        const open = app.indexOf("{", from); let d = 0;
        for (let i = open; i < app.length; i++) {
            if (app[i] === "{") d++; else if (app[i] === "}" && --d === 0) return [open, i];
        }
        throw new Error("brace-match failed");
    };
    const hStart = app.indexOf("\nfunction h(tag, a={}, ...kids) {");
    assert.notEqual(hStart, -1, "h() is missing from app.js");
    const [ho, hc] = brace(app.indexOf("...kids) {", hStart) + 7);
    const sig = "_renderChannelInfoModal()";
    const fStart = app.indexOf(`\n    ${sig} {`);
    assert.notEqual(fStart, -1, "_renderChannelInfoModal is missing from app.js");
    const [fo, fc] = brace(fStart + sig.length);

    const copied = [], shared = [], alerts = [], timers = [];
    const document = {
        createElement: (t) => new FakeEl(t),
        createTextNode: (t) => { const e = new FakeEl("#text"); e._text = t; return e; },
        body: { classList: { remove() {} } },
    };
    const navigator = {
        clipboard: {
            writeText: (t) => { copied.push(t); return clipboardFails ? Promise.reject(new Error("denied")) : Promise.resolve(); },
        },
    };
    if (share) navigator.share = (d) => { shared.push(d); return Promise.resolve(); };
    const ch = { channelName, channelHash: "9f1e2d3c4b5a69788796a5b4c3d2e1f0", rfedNodeHash: "2c29f67404f1babdd0b76bb88cb05ac9", stampCost: 8 };
    const ChannelStore = { get: (n) => (n === channelName ? ch : null) };
    const lib = await import("./lib/channel_name.js");
    const env = {
        document, navigator, ChannelStore,
        RnsClient: { leaveChannel: async () => {} },
        alert: (m) => alerts.push(m), confirm: () => false,
        setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; },
        ...lib,
    };
    const names = Object.keys(env);
    const h = new Function(...names, `return function h(tag, a={}, ...kids) {${app.slice(ho + 1, hc)}};`)(
        ...names.map((n) => env[n]));
    const render = new Function(...names, "h", app.slice(fo + 1, fc));
    const root = new FakeEl("div");
    const self = { root, state: { channelInfoName: channelName, showChannelInfo: true }, render() {} };
    render.call(self, ...names.map((n) => env[n]), h);
    const btn = (re) => [...root.walk()].find((e) => e.tagName === "BUTTON" && re.test(e.textContent)) ?? null;
    return { root, btn, copied, shared, alerts, timers };
}

test("info shows the full private name whole, without '#', and the hash as secondary", async () => {
    const r = await renderInfo({ channelName: "abd77af5c72e6b5b.general" });
    const nameEl = r.root.byClass("channel-full-name");
    assert.ok(nameEl, "no .channel-full-name element");
    assert.equal(nameEl.textContent, "abd77af5c72e6b5b.general");
    assert.match(r.root.textContent, /Hash: 9f1e2d3c4b5a69788796a5b4c3d2e1f0/);
    assert.doesNotMatch(r.root.textContent, /#abd77af5c72e6b5b/);
});

test("info: the private hint and the public hint", async () => {
    const priv = await renderInfo({ channelName: "abd77af5c72e6b5b.general" });
    assert.equal(priv.root.byClass("channel-share-hint").textContent, PRIVATE_HINT);
    const pub = await renderInfo({ channelName: "public.general" });
    assert.equal(pub.root.byClass("channel-share-hint").textContent, PUBLIC_HINT);
});

test("Copy name puts exactly the full name on the clipboard and confirms briefly", async () => {
    const r = await renderInfo({ channelName: "abd77af5c72e6b5b.general" });
    const copy = r.btn(/Copy name/);
    assert.ok(copy, "no Copy name button");
    copy.fire("click");
    await flush();
    assert.deepEqual(r.copied, ["abd77af5c72e6b5b.general"]);
    assert.match(copy.textContent, /Copied/);
    assert.ok(copy.classList.contains("copied"));
    assert.equal(r.timers.length, 1);
    assert.ok(r.timers[0].ms > 0 && r.timers[0].ms <= 3000, "the confirmation is not brief");
    r.timers[0].f();
    assert.match(copy.textContent, /Copy name/);
    assert.equal(copy.classList.contains("copied"), false);
});

test("a failed copy says so instead of pretending", async () => {
    const r = await renderInfo({ channelName: "public.general", clipboardFails: true });
    r.btn(/Copy name/).fire("click");
    await flush();
    assert.equal(r.alerts.length, 1);
    assert.doesNotMatch(r.btn(/Copy name/)?.textContent ?? "", /Copied/);
});

test("Share uses navigator.share with the full name when available, and is absent otherwise", async () => {
    const withShare = await renderInfo({ channelName: "abd77af5c72e6b5b.general", share: true });
    const share = withShare.btn(/Share/);
    assert.ok(share, "no Share button with navigator.share");
    share.fire("click");
    await flush();
    assert.deepEqual(withShare.shared, [{ text: "abd77af5c72e6b5b.general" }]);

    const without = await renderInfo({ channelName: "abd77af5c72e6b5b.general" });
    assert.equal(without.btn(/Share/), null, "Share shown without navigator.share");
    assert.ok(without.btn(/Copy name/), "Copy name missing without navigator.share");
});

test("style.css: the full name is selectable and never truncated", async () => {
    const css = await readFile(new URL("./style.css", import.meta.url), "utf8");
    const m = css.match(/\.channel-full-name\s*\{([^}]*)\}/);
    assert.ok(m, ".channel-full-name has no rule in style.css");
    const rule = m[1];
    assert.match(rule, /(^|[^-])user-select:\s*text/);
    assert.match(rule, /-webkit-user-select:\s*text/);
    assert.match(rule, /word-break:\s*break-all|overflow-wrap:\s*anywhere/);
    assert.doesNotMatch(rule, /text-overflow|nowrap/);
});
