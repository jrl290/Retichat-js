/**
 * CHANNEL NAMES IN THE NEW CHANNEL FORM — lib/channel_name.js.
 *
 * James, 2026-09-27: a channel name is "<root>.<name>"; public channels use
 * the root "public". A private root was a random 8-hex prefix nobody could
 * change, so the iPad could not join the phone's 4cdc4115.nametest-096499.
 * Now the root is editable, defaults to 16 hex from crypto.getRandomValues,
 * a pasted full name lands whole, and "public" is refused in Private mode.
 *
 * Run: node --test channel_name.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
    PUBLIC_ROOT, PRIVATE_ROOT_HEX_LEN,
    genPrivateRoot, filterChannelChars, splitChannelName, applyVisibility,
    initialChannelValue, regenerateRoot, pasteChannelName, typeChannelName,
    validateChannelName, visibilityHint,
} from "./lib/channel_name.js";

const fixedRoot = () => "0123456789abcdef";

test("the default private root is 16 lowercase hex from getRandomValues", () => {
    assert.equal(PRIVATE_ROOT_HEX_LEN, 16);
    let calls = 0;
    const root = genPrivateRoot((a) => { calls++; a.set([0, 1, 0xab, 0xcd, 0xef, 0x10, 0x7f, 0xff]); return a; });
    assert.equal(calls, 1);
    assert.equal(root, "0001abcdef107fff");
    const live = genPrivateRoot();
    assert.match(live, /^[0-9a-f]{16}$/);
    assert.notEqual(genPrivateRoot(), live, "two fresh roots collide (64 bits)");
});

test("the default root never comes from Math.random", () => {
    const real = Math.random;
    Math.random = () => { throw new Error("Math.random used"); };
    try {
        assert.match(genPrivateRoot(), /^[0-9a-f]{16}$/);
        assert.match(initialChannelValue("private"), /^[0-9a-f]{16}\.$/);
        assert.match(applyVisibility("public.general", "private"), /^[0-9a-f]{16}\.general$/);
    } finally {
        Math.random = real;
    }
});

test("the character rule: lowercase letters, digits, '.' and '-'", () => {
    assert.equal(filterChannelChars("My Chan_nel!.Foo-9"), "mychannel.foo-9");
    assert.equal(filterChannelChars("  4cdc4115.nametest-096499\n"), "4cdc4115.nametest-096499");
    assert.deepEqual(splitChannelName("a.b.c"), { root: "a", name: "b.c", hasDot: true });
    assert.deepEqual(splitChannelName("abc"), { root: "", name: "abc", hasDot: false });
});

// ── review fixes (F1-F4) ────────────────────────────────────────────────────

test("F3: letters and digits are Unicode, as on iOS and Android", () => {
    // Native: iOS c.isLetter || c.isNumber, Android isLetterOrDigit.
    assert.equal(filterChannelChars("public.Café"), "public.café");
    assert.equal(filterChannelChars("public.cafe\u0301"), "public.caf\u00e9", "NFC");
    assert.equal(filterChannelChars("Équipe.日本-2"), "équipe.日本-2");
    assert.equal(filterChannelChars("a_b!c d.é"), "abcd.é");
    assert.equal(validateChannelName("public.café", "public").ok, true);
    assert.equal(validateChannelName("équipe.日本", "private").ok, true);
    assert.equal(validateChannelName("ro_ot.général", "private").ok, false);
    assert.equal(validateChannelName("équipe.Général", "private").ok, false, "uppercase");
});

test("F1: a full name pasted over the selected root leaves no stray '.'", () => {
    const cur = "abcd1234abcd1234.";
    const r = pasteChannelName({ value: cur, selStart: 0, selEnd: 16,
        pasted: "4cdc4115.nametest-096499", mode: "private", genRoot: fixedRoot });
    assert.deepEqual(r, { value: "4cdc4115.nametest-096499", caret: 24 });
    const pub = pasteChannelName({ value: "public.", selStart: 0, selEnd: 6,
        pasted: "public.foo", mode: "public" });
    assert.equal(pub.value, "public.foo");
    // An existing name part is kept after the pasted one, never glued on.
    const kept = pasteChannelName({ value: "abc.old", selStart: 0, selEnd: 3,
        pasted: "x.y", mode: "private", genRoot: fixedRoot });
    assert.equal(kept.value, "x.y.old");
    const endsDot = pasteChannelName({ value: "abc.old", selStart: 0, selEnd: 3,
        pasted: "x.", mode: "private", genRoot: fixedRoot });
    assert.equal(endsDot.value, "x.old");
});

test("F1: a name with an empty segment is refused", () => {
    for (const v of ["4cdc4115.nametest-096499.", "a..b", "a.b..c", "public.foo."]) {
        const r = validateChannelName(v, v.startsWith("public.") ? "public" : "private");
        assert.equal(r.ok, false, v);
        assert.equal(r.code, "name-segment", v);
    }
    const lead = pasteChannelName({ value: "myroot.", selStart: 7, selEnd: 7, pasted: ".foo",
        mode: "private", genRoot: fixedRoot });
    assert.equal(lead.value, "myroot..foo", "a leading '.' must not wipe the root");
    assert.equal(validateChannelName(lead.value, "private").ok, false);
});

test("F2: Private: typing a '.' into the name part moves its root into the root", () => {
    let v = "abcd1234abcd1234.";
    for (const ch of "4cdc4115.nametest-096499") {
        const r = typeChannelName({ old: v, value: v + ch, caret: v.length + 1, mode: "private" });
        assert.equal(r.caret, r.value.length);
        v = r.value;
    }
    assert.equal(v, "4cdc4115.nametest-096499");
    // One input event carrying the whole name (autofill, drag-and-drop).
    assert.deepEqual(typeChannelName({ old: "abcd.", value: "abcd.4cdc4115.x", caret: 15, mode: "private" }),
        { value: "4cdc4115.x", caret: 10 });
    // A name part that already holds a "." is edited in place.
    assert.equal(typeChannelName({ old: "r.team.ops", value: "r.team.ops.x", mode: "private" }).value,
        "r.team.ops.x");
    // A "." at the start of the name part has no root before it.
    assert.equal(typeChannelName({ old: "r.ab", value: "r..ab", caret: 3, mode: "private" }).value, "r..ab");
    // Edits of the root are only filtered.
    assert.equal(typeChannelName({ old: "abc.x", value: "aBc-d.x", mode: "private" }).value, "abc-d.x");
});

test("F2: Public: a typed name part starting public. drops it; other x.y stays", () => {
    assert.deepEqual(typeChannelName({ old: "public.", value: "public.public.foo", caret: 17, mode: "public" }),
        { value: "public.foo", caret: 10 });
    assert.equal(typeChannelName({ old: "public.abc", value: "public.abc.def", mode: "public" }).value,
        "public.abc.def");
});

test("F4: Public mode joins only the root public", () => {
    const r = validateChannelName("abc.foo", "public");
    assert.equal(r.ok, false);
    assert.equal(r.code, "root-not-public");
    assert.match(r.error, /Choose Private/);
    assert.equal(validateChannelName("abc.foo", "private").ok, true);
});

test("the form opens with public. or a fresh 16-hex root", () => {
    assert.equal(initialChannelValue("public"), "public.");
    assert.equal(initialChannelValue("private", fixedRoot), "0123456789abcdef.");
});

test("toggling to Public replaces the root with public and keeps the name", () => {
    assert.equal(applyVisibility("0123456789abcdef.general", "public"), "public.general");
    assert.equal(applyVisibility("myroot.a.b", "public"), "public.a.b");
    assert.equal(applyVisibility("general", "public"), "public.general");
    assert.equal(applyVisibility("", "public"), "public.");
});

test("toggling to Private keeps a typed non-public root", () => {
    assert.equal(applyVisibility("myroot.general", "private", fixedRoot), "myroot.general");
    assert.equal(applyVisibility("4cdc4115.nametest", "private", fixedRoot), "4cdc4115.nametest");
});

test("toggling to Private replaces public or a missing root with a fresh one", () => {
    assert.equal(applyVisibility("public.general", "private", fixedRoot), "0123456789abcdef.general");
    assert.equal(applyVisibility("public.", "private", fixedRoot), "0123456789abcdef.");
    assert.equal(applyVisibility(".general", "private", fixedRoot), "0123456789abcdef.general");
    assert.equal(applyVisibility("general", "private", fixedRoot), "0123456789abcdef.general");
});

test("Regenerate prefix replaces only the root", () => {
    assert.equal(regenerateRoot("myroot.a.b", fixedRoot), "0123456789abcdef.a.b");
    assert.equal(regenerateRoot("x.", fixedRoot), "0123456789abcdef.");
});

test("Private: pasting a full root.name after the root moves its root into the root", () => {
    const cur = "0123456789abcdef.";
    const r = pasteChannelName({ value: cur, selStart: cur.length, selEnd: cur.length,
        pasted: "4cdc4115.nametest-096499", mode: "private", genRoot: fixedRoot });
    assert.deepEqual(r, { value: "4cdc4115.nametest-096499", caret: "4cdc4115.nametest-096499".length });
});

test("Private: pasting a full name over a selected field replaces it whole", () => {
    const cur = "0123456789abcdef.old";
    const r = pasteChannelName({ value: cur, selStart: 0, selEnd: cur.length,
        pasted: " 4cdc4115.NameTest-096499 ", mode: "private", genRoot: fixedRoot });
    assert.equal(r.value, "4cdc4115.nametest-096499");
});

test("Private: a pasted name with no '.' keeps the root", () => {
    const cur = "myroot.";
    const r = pasteChannelName({ value: cur, selStart: 7, selEnd: 7, pasted: "general",
        mode: "private", genRoot: fixedRoot });
    assert.deepEqual(r, { value: "myroot.general", caret: 14 });
    const all = pasteChannelName({ value: "myroot.old", selStart: 0, selEnd: 10, pasted: "general",
        mode: "private", genRoot: fixedRoot });
    assert.equal(all.value, "myroot.general");
    const fromPublic = pasteChannelName({ value: "public.", selStart: 0, selEnd: 7, pasted: "general",
        mode: "private", genRoot: fixedRoot });
    assert.equal(fromPublic.value, "0123456789abcdef.general");
});

test("Private: a paste inside the root edits the root", () => {
    const r = pasteChannelName({ value: "abc.general", selStart: 0, selEnd: 3, pasted: "My-Team",
        mode: "private", genRoot: fixedRoot });
    assert.deepEqual(r, { value: "my-team.general", caret: 7 });
});

test("Public: a pasted public.name drops the duplicate public.", () => {
    const r = pasteChannelName({ value: "public.", selStart: 7, selEnd: 7, pasted: "public.general",
        mode: "public" });
    assert.deepEqual(r, { value: "public.general", caret: 14 });
    const all = pasteChannelName({ value: "public.x", selStart: 0, selEnd: 8, pasted: "public.general",
        mode: "public" });
    assert.equal(all.value, "public.general");
});

test("Public: any other x.y stays as typed in the name part", () => {
    const r = pasteChannelName({ value: "public.", selStart: 7, selEnd: 7, pasted: "4cdc4115.nametest",
        mode: "public" });
    assert.equal(r.value, "public.4cdc4115.nametest");
    const all = pasteChannelName({ value: "public.", selStart: 0, selEnd: 7, pasted: "abc.def",
        mode: "public" });
    assert.equal(all.value, "public.abc.def");
});

test("Join: an empty root, an empty name or a bad character is refused", () => {
    assert.equal(validateChannelName("", "private").ok, false);
    assert.equal(validateChannelName(".general", "private").ok, false);
    assert.equal(validateChannelName("general", "private").ok, false);
    assert.equal(validateChannelName("myroot.", "private").ok, false);
    assert.equal(validateChannelName("public.", "public").ok, false);
    assert.equal(validateChannelName("My.general", "private").ok, false);
    assert.equal(validateChannelName("root.gen eral", "private").ok, false);
    assert.equal(validateChannelName("ro_ot.general", "public").ok, false);
});

test("Join: the root public is refused in Private mode, allowed in Public", () => {
    const priv = validateChannelName("public.general", "private");
    assert.equal(priv.ok, false);
    assert.match(priv.error, /public/);
    assert.deepEqual(validateChannelName("public.general", "public"),
        { ok: true, name: "public.general", error: "", code: "" });
});

test("Join: typed roots, including an old 8-hex root, are accepted", () => {
    assert.equal(validateChannelName("4cdc4115.nametest-096499", "private").ok, true);
    assert.equal(validateChannelName("0123456789abcdef.general", "private").ok, true);
    assert.equal(validateChannelName("my-team.a.b", "private").ok, true);
    assert.equal(validateChannelName("public.a.b-c", "public").ok, true);
});

test("the hints stay accurate about who can join", () => {
    assert.equal(visibilityHint("private"), "Only people you share the full name with can join.");
    assert.equal(visibilityHint("public"), "Anyone who knows the name can join.");
    assert.equal(PUBLIC_ROOT, "public");
});

test("app.js: the channel form uses these rules and never Math.random", async () => {
    const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
    assert.match(app, /from "\.\/lib\/channel_name\.js";/);
    const start = app.indexOf("    _renderChannelForm(top, scroll, footer) {");
    assert.notEqual(start, -1, "_renderChannelForm is missing from app.js");
    const end = app.indexOf("\n    },\n", start);
    const body = app.slice(start, end);
    assert.doesNotMatch(body, /Math\.random/);
    for (const name of ["initialChannelValue", "applyVisibility", "pasteChannelName",
        "filterChannelChars", "validateChannelName", "regenerateRoot", "visibilityHint"]) {
        assert.match(body, new RegExp(`\\b${name}\\(`), `the form does not call ${name}`);
    }
    // Join goes through the validator, not the raw field.
    assert.match(body, /RnsClient\.joinChannel\(v\.name\)/);
    assert.match(body, /Regenerate prefix/);
});

// ── the real form, over a minimal DOM ───────────────────────────────────────
//
// _renderChannelForm and h() are lifted out of app.js and run against a tiny
// fake document, so the wiring (toggle, paste, filter, Join enablement, the
// name passed to joinChannel) is the shipped code, not a copy.

class FakeEl {
    constructor(tag) {
        this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {};
        this.style = {}; this.listeners = {}; this.className = ""; this.disabled = false;
        this.value = ""; this._text = ""; this.selectionStart = 0; this.selectionEnd = 0;
    }
    setAttribute(k, v) { this.attrs[k] = String(v); if (k === "id") this.id = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
    appendChild(c) { this.children.push(c); return c; }
    set textContent(t) { this._text = t; this.children = []; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
    setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
    *walk() { yield this; for (const c of this.children) if (c instanceof FakeEl) yield* c.walk(); }
    querySelectorAll(sel) {
        const cls = sel.replace(/^\./, "");
        return [...this.walk()].filter((e) => e !== this && e.className.split(" ").includes(cls));
    }
    fire(t, ev = {}) { for (const f of this.listeners[t] || []) f({ target: this, preventDefault() {}, ...ev }); }
}

async function renderForm({ vis = "public" } = {}) {
    const app = await readFile(new URL("./app.js", import.meta.url), "utf8");
    const brace = (from) => {
        const open = app.indexOf("{", from); let d = 0;
        for (let i = open; i < app.length; i++) {
            if (app[i] === "{") d++; else if (app[i] === "}" && --d === 0) return [open, i];
        }
    };
    const hStart = app.indexOf("\nfunction h(tag, a={}, ...kids) {");
    const [ho, hc] = brace(app.indexOf("...kids) {", hStart) + 7);
    const sig = "_renderChannelForm(top, scroll, footer)";
    const fStart = app.indexOf(`\n    ${sig} {`);
    const [fo, fc] = brace(fStart + sig.length);
    const roots = [];
    const document = {
        createElement: (t) => new FakeEl(t),
        createTextNode: (t) => { const e = new FakeEl("#text"); e._text = t; return e; },
        querySelector: (sel) => roots.flatMap((r) => r.querySelectorAll(sel))[0] ?? null,
        getElementById: (id) => roots.flatMap((r) => [...r.walk()]).find((e) => e.id === id) ?? null,
    };
    const joined = [];
    const RnsClient = {
        cfg: { rfedNodeHash: "2c29f67404f1babdd0b76bb88cb05ac9" },
        joinChannel: async (n) => { joined.push(n); return { channelName: n }; },
    };
    const lib = await import("./lib/channel_name.js");
    const env = { document, RnsClient, alert: (m) => { throw new Error("alert: " + m); }, ...lib };
    const names = Object.keys(env);
    const h = new Function(...names, `return function h(tag, a={}, ...kids) {${app.slice(ho + 1, hc)}};`)(
        ...names.map((n) => env[n]));
    const render = new Function(...names, "h", "top", "scroll", "footer", app.slice(fo + 1, fc));
    const self = { state: { channelVis: vis }, openChat() {} };
    const top = new FakeEl("div"), scroll = new FakeEl("div"), footer = new FakeEl("div");
    roots.push(top, scroll, footer);
    render.call(self, ...names.map((n) => env[n]), h, top, scroll, footer);
    const inp = document.getElementById("nc-channel-name");
    const join = footer.children[0];
    const btn = (label) => [...top.walk()].find((e) => e.tagName === "BUTTON" && e.textContent === label);
    const type = (v) => { inp.value = v; inp.selectionStart = inp.selectionEnd = v.length; inp.fire("input"); };
    const typeChar = (ch) => {
        const v = inp.value + ch;
        inp.value = v; inp.selectionStart = inp.selectionEnd = v.length; inp.fire("input");
    };
    const paste = (text, s = inp.value.length, e = s) => {
        inp.selectionStart = s; inp.selectionEnd = e;
        inp.fire("paste", { clipboardData: { getData: () => text } });
    };
    return { self, inp, join, btn, type, typeChar, paste, joined, top };
}

test("form: opens Public with public. and Join disabled until a name is typed", async () => {
    const f = await renderForm();
    assert.equal(f.inp.value, "public.");
    assert.equal(f.join.disabled, true);
    f.type("public.General Chat");
    assert.equal(f.inp.value, "public.generalchat");
    assert.equal(f.join.disabled, false);
    f.join.fire("click");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(f.joined, ["public.generalchat"]);
});

test("form: Private gets a 16-hex root, keeps a typed one, and Public restores public.", async () => {
    const f = await renderForm();
    f.type("public.general");
    f.btn("Private").fire("click");
    assert.match(f.inp.value, /^[0-9a-f]{16}\.general$/);
    assert.equal(f.self.state.channelVis, "private");
    assert.match(f.top.textContent, /Only people you share the full name with can join\./);
    f.type("my-team.general");
    f.btn("Public").fire("click");
    assert.equal(f.inp.value, "public.general");
    f.type("my-team.general");
    f.btn("Private").fire("click");
    assert.equal(f.inp.value, "my-team.general", "a typed root was overwritten");
});

test("form: pasting a shared private name joins that channel", async () => {
    const f = await renderForm({ vis: "private" });
    assert.match(f.inp.value, /^[0-9a-f]{16}\.$/);
    f.paste("4cdc4115.nametest-096499");
    assert.equal(f.inp.value, "4cdc4115.nametest-096499");
    assert.equal(f.join.disabled, false);
    f.join.fire("click");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(f.joined, ["4cdc4115.nametest-096499"]);
});

test("form: Private refuses the root public and an empty root", async () => {
    const f = await renderForm({ vis: "private" });
    f.type("public.general");
    assert.equal(f.join.disabled, true);
    assert.match(f.top.textContent, /"public" is the root of public channels/);
    f.join.fire("click");
    f.type(".general");
    assert.equal(f.join.disabled, true);
    f.join.fire("click");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(f.joined, []);
});

test("form F2: typing a shared private name after the default root joins it", async () => {
    const f = await renderForm({ vis: "private" });
    for (const ch of "4cdc4115.nametest-096499") f.typeChar(ch);
    assert.equal(f.inp.value, "4cdc4115.nametest-096499");
    assert.equal(f.join.disabled, false);
    f.join.fire("click");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(f.joined, ["4cdc4115.nametest-096499"]);
});

test("form F1: a full name pasted over the selected root joins that channel", async () => {
    const f = await renderForm({ vis: "private" });
    f.paste("4cdc4115.nametest-096499", 0, 16);
    assert.equal(f.inp.value, "4cdc4115.nametest-096499");
    f.join.fire("click");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(f.joined, ["4cdc4115.nametest-096499"]);
});

test("form F4: Public refuses a root other than public, and says why", async () => {
    const f = await renderForm();
    f.type("team.foo");
    assert.equal(f.join.disabled, true);
    assert.match(f.top.textContent, /Public channels use the root "public"/);
    f.join.fire("click");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(f.joined, []);
});

test("form: Regenerate prefix swaps only the root", async () => {
    const f = await renderForm({ vis: "private" });
    f.type("my-team.general");
    f.btn("Regenerate prefix").fire("click");
    assert.match(f.inp.value, /^[0-9a-f]{16}\.general$/);
});
