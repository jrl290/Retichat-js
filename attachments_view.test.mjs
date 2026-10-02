/**
 * SHOWING ATTACHMENTS — the bubble (app.js _buildMsgBubble, _buildAttachments,
 * _loadAttachment) over a small fake DOM.
 *
 *   An image (a FIELD_IMAGE, or a file with one of iOS's image extensions:
 *   Models.swift Attachment.isImage) is an inline <img> from an object URL;
 *   anything else, FIELD_AUDIO included, a download link with its name and
 *   size. An image the browser cannot decode (HEIC outside Safari) becomes
 *   the link. Bytes that are gone say so. The object URL is revoked once the
 *   bubble has left the page.
 *   Under them, what the user must know: kept for this session only, not
 *   saved (and why), attachments that could not be read.
 *   An outgoing message still sending shows its progress; a failed one, why.
 *
 * The staging stage checks the real thing in Chromium: a decoded <img> in
 * .msg-row[data-msg-id] (test-harnesses/staging/lib/attach.mjs).
 *
 * Run: node --test attachments_view.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { isImageAttachment } from "./lib/rns/lxmf/lxmf.js";
import { formatSize } from "./lib/attachment_limits.js";
import { AttachmentStore, memoryBackend } from "./lib/attachment_store.js";
import { ObjectUrls, blobType, INLINE_TYPES } from "./lib/object_urls.js";
import { SendTransfers } from "./lib/send_progress.js";
import { bubbleText } from "./lib/message_text.js";
import { compile, fn, install } from "./test_app_source.mjs";

// ── a fake DOM, just enough for h() and the bubble ──────────────────────────

const ROOT = { isRoot: true };
class El {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parent = null;
        this.attrs = {};
        this.listeners = {};
        this.style = {};
        this.className = "";
    }
    appendChild(c) { if (c && typeof c === "object") c.parent = this; this.children.push(c); return c; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    fire(type) { const fs = this.listeners[type] ?? []; this.listeners[type] = []; for (const f of fs) f(); }
    get isConnected() { let n = this; while (n.parent && n.parent !== ROOT) n = n.parent; return n.parent === ROOT; }
    replaceWith(other) {
        const list = this.parent.children;
        list[list.indexOf(this)] = other;
        other.parent = this.parent;
        this.parent = null;
    }
    get firstChild() { return this.children[0] ?? null; }
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
    /** Every descendant element matching `test`. */
    all(test) {
        const out = [];
        const walk = (n) => { for (const c of n.children ?? []) { if (c instanceof El) { if (test(c)) out.push(c); walk(c); } } };
        walk(this);
        return out;
    }
}
const document = {
    createElement: (tag) => new El(tag),
    createTextNode: (text) => ({ textContent: text }),
    getElementById: () => null,
};
const h = fn("h", "tag, a={}, ...kids", { document });
const byClass = (root, name) => root.all((e) => e.className.split(" ").includes(name));
const settle = () => new Promise((r) => setTimeout(r, 0));

function view() {
    const backend = memoryBackend({ persistent: true });
    const Attachments = new AttachmentStore(backend, { warn() {} });
    const created = [];
    const revoked = [];
    const AttachmentUrls = new ObjectUrls({
        create: (blob) => { created.push(blob); return `blob:${created.length}`; },
        revoke: (url) => revoked.push(url),
        makeBlob: (bytes, type) => ({ bytes, type }),
    });
    const transfers = new SendTransfers();
    const app = { _statusIcon: (s) => ({ sending: "●", failed: "✗", proved: "✓✓" }[s] ?? "") };
    install(app, {
        h, document, Attachments, AttachmentUrls, isImageAttachment, formatSize, bubbleText,
        fmtTime: () => "12:00", RnsClient: { _sendTransfers: transfers }, console: { warn() {} },
    }, [
        "_buildMsgBubble(m, sender = null)", "_buildAttachments(m)", "_attachmentLink(a)", "_loadAttachment(el, a)",
        "_buildProgressBar(progress)", "_buildSenderLabel(sender)",
    ]);
    /** Build a bubble and put it on the page, as the chat list does. */
    const show = (m) => {
        const row = app._buildMsgBubble(m);
        row.parent = ROOT;
        return row;
    };
    return { app, Attachments, AttachmentUrls, created, revoked, transfers, show };
}

const meta = (over) => ({ key: "m:0", name: "cat.png", mime: "image/png", size: 1234, sha256: "x", field: 5, stored: "persisted", ...over });

test("an image attachment is an inline <img> from an object URL, inside .msg-row[data-msg-id]", async () => {
    const v = view();
    await v.Attachments.put("m:0", Buffer.from("png bytes"));
    const row = v.show({ id: "m", dir: "in", content: "", timestamp: 0, attachments: [meta()] });
    assert.equal(row.getAttribute("data-msg-id"), "m");
    assert.ok(row.className.includes("msg-row"));
    const [img] = row.all((e) => e.tagName === "IMG");
    assert.ok(img, "an <img>");
    assert.equal(img.className, "msg-image");
    assert.equal(img.getAttribute("alt"), "cat.png");
    await settle();
    assert.equal(img.src, "blob:1");
    assert.equal(v.created[0].type, "image/png");
    assert.equal(Buffer.from(v.created[0].bytes).toString(), "png bytes", "the stored bytes, not a copy of something else");
    assert.equal(byClass(row, "msg-attach-note").length, 0, "nothing to note for a persisted one");
});

test("FIELD_IMAGE is shown as an image whatever its name; a file and FIELD_AUDIO are download links with name and size", async () => {
    const v = view();
    for (const k of ["a:0", "a:1", "a:2"]) await v.Attachments.put(k, Buffer.from(k));
    const row = v.show({ id: "a", dir: "in", content: "three", timestamp: 0, attachments: [
        meta({ key: "a:0", name: "webp", mime: "image/webp", field: 6 }),
        meta({ key: "a:1", name: "report.pdf", mime: "application/pdf", size: 2_500_000 }),
        meta({ key: "a:2", name: "audio.ogg", mime: "audio/ogg", size: 900, field: 7 }),
    ] });
    await settle();
    const imgs = row.all((e) => e.tagName === "IMG");
    const links = row.all((e) => e.tagName === "A");
    assert.equal(imgs.length, 1);
    assert.deepEqual(links.map((a) => [a.getAttribute("download"), a.textContent]), [
        ["report.pdf", "📄 report.pdf · 2.50 MB"],
        ["audio.ogg", "📄 audio.ogg · 900 B"],
    ]);
    assert.deepEqual(links.map((a) => a.href), ["blob:2", "blob:3"]);
    assert.ok(row.textContent.includes("three"), "the caption is shown too");
});

test("an object URL is typed as an image, audio or video only; anything else is a download (no script runs as this page)", async () => {
    // A blob URL belongs to the page's origin: typed image/svg+xml or
    // text/html and opened in a tab, its script reads the identity key in
    // localStorage (review of adee619). Old records may carry such a type.
    for (const type of ["image/svg+xml", "IMAGE/SVG+XML", "text/html", "application/xhtml+xml", "text/xml", "application/xml",
        "application/pdf", "text/plain", "image/*", "", null, undefined]) {
        assert.equal(blobType(type), "application/octet-stream", String(type));
    }
    for (const type of INLINE_TYPES) assert.equal(blobType(type), type);
    assert.equal(blobType(" Image/PNG "), "image/png");
    assert.ok([...INLINE_TYPES].every((t) => /^(image|audio|video)\//.test(t) && !t.includes("svg")));

    const v = view();
    for (const k of ["s:0", "s:1", "s:2"]) await v.Attachments.put(k, Buffer.from(k));
    v.show({ id: "s", dir: "in", content: "", timestamp: 0, attachments: [
        meta({ key: "s:0", name: "svg+xml", mime: "image/svg+xml", field: 6 }),
        meta({ key: "s:1", name: "page.html", mime: "text/html" }),
        meta({ key: "s:2", name: "cat.png", mime: "image/png" }),
    ] });
    await settle();
    assert.deepEqual(v.created.map((b) => b.type), ["application/octet-stream", "application/octet-stream", "image/png"]);
});

test("an image the browser cannot decode becomes its download link, and its first URL is revoked", async () => {
    const v = view();
    await v.Attachments.put("m:0", Buffer.from("heic bytes"));
    const row = v.show({ id: "m", dir: "in", content: "", timestamp: 0, attachments: [meta({ name: "IMG_1.HEIC", mime: "image/heic" })] });
    await settle();
    const [img] = row.all((e) => e.tagName === "IMG");
    img.fire("error");
    await settle();
    assert.equal(row.all((e) => e.tagName === "IMG").length, 0);
    const [link] = row.all((e) => e.tagName === "A");
    assert.equal(link.getAttribute("download"), "IMG_1.HEIC");
    assert.equal(link.href, "blob:2");
    assert.deepEqual(v.revoked, ["blob:1"]);
});

test("bytes that are gone say so, with the name and size", async () => {
    const v = view();
    const row = v.show({ id: "m", dir: "in", content: "", timestamp: 0, attachments: [meta({ stored: "session" })] });
    await settle();
    assert.match(row.textContent, /cat\.png · 1 KB — no longer available \(it was kept for that session only\)/);
    assert.match(row.textContent, /Kept for this session only/);
});

test("the notes: not saved and why, unreadable attachments, an unreadable part", async () => {
    const v = view();
    await v.Attachments.put("m:0", Buffer.from("x"));
    const row = v.show({ id: "m", dir: "in", content: "hi", timestamp: 0,
        attachments: [meta({ stored: "failed", storeError: "QuotaExceededError" })], attachmentsSkipped: 2, fieldsUnreadable: true });
    const notes = byClass(row, "msg-attach-note").map((n) => n.textContent);
    assert.deepEqual(notes, [
        "Not saved (QuotaExceededError): kept until this tab closes.",
        "2 attachments in this message could not be read.",
        "Part of this message could not be read.",
    ]);
    const plain = v.show({ id: "p", dir: "in", content: "just text", timestamp: 0 });
    assert.equal(byClass(plain, "msg-attachments").length, 0, "a text message has no attachment section");
});

test("an object URL lives as long as its bubble is on the page", async () => {
    const v = view();
    await v.Attachments.put("m:0", Buffer.from("x"));
    const row = v.show({ id: "m", dir: "in", content: "", timestamp: 0, attachments: [meta()] });
    await settle();
    assert.equal(v.AttachmentUrls.sweep(), 0);
    row.parent = null;   // the chat re-rendered: this bubble is gone
    assert.equal(v.AttachmentUrls.sweep(), 1);
    assert.deepEqual(v.revoked, ["blob:1"]);
});

test("a bubble built for a page it never reaches makes no URL", async () => {
    const v = view();
    await v.Attachments.put("m:0", Buffer.from("x"));
    v.app._buildMsgBubble({ id: "m", dir: "in", content: "", timestamp: 0, attachments: [meta()] });
    await settle();
    assert.deepEqual(v.created, []);
});

test("a send in progress shows its bar; a failed one says why", () => {
    const v = view();
    const t = v.transfers.begin("s", "direct");
    v.transfers.progress(t, 0.5);
    const sending = v.show({ id: "s", dir: "out", content: "", status: "sending", timestamp: 0 });
    const [bar] = byClass(sending, "msg-progress");
    assert.ok(bar);
    assert.equal(bar.children[0].style.width, "55%", "0.10 + 0.90 x 0.5");
    const done = v.show({ id: "s", dir: "out", content: "", status: "proved", timestamp: 0 });
    assert.equal(byClass(done, "msg-progress").length, 0, "no bar once it is not sending");
    const failed = v.show({ id: "f", dir: "out", content: "", status: "failed", timestamp: 0, sendError: "its attachment is gone" });
    assert.deepEqual(byClass(failed, "msg-attach-note").map((n) => n.textContent), ["Not sent: its attachment is gone"]);
});

test("the composer has a paperclip in DMs and groups, none in channels; renders sweep their URLs", async () => {
    const { methodBody } = await import("./test_app_source.mjs");
    assert.match(methodBody("_buildDmChatView()"), /className: "btn-attach"[\s\S]*?onClick: \(\) => this\._pickAttachments\(\)/);
    assert.match(methodBody("_buildGroupChatView()"), /className: "btn-attach"/);
    assert.doesNotMatch(methodBody("_buildChannelChatView()"), /btn-attach/);
    assert.match(methodBody("render()"), /AttachmentUrls\.sweep\(\);/);
    assert.match(methodBody("_rebuildDetail()"), /AttachmentUrls\.sweep\(\);/);
    assert.match(methodBody("_repaintMsgRow(convHash, msgId)"), /AttachmentUrls\.sweep\(\);/);
    assert.match(methodBody("_pickAttachments()"), /type: "file", multiple: "multiple"/, "several files at once, as iOS allows");
});
