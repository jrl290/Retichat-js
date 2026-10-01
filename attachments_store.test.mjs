/**
 * WHERE ATTACHMENTS ARE KEPT — lib/attachment_store.js and its use in app.js.
 *
 * Message records live in localStorage, which cannot hold photos (and sSet
 * swallows a failed write): the bytes go to IndexedDB, one entry per
 * attachment keyed "<message id>:<index>", and the record keeps
 * {key, name, mime, size, sha256, field, stored}. A write that fails is never
 * silent: the bytes stay for the session and the record (and so the bubble)
 * says so. Without IndexedDB (private mode) the page still works, attachments
 * live for the session, and the bubble says that too. Deleting a conversation,
 * or trimming its oldest messages, deletes their bytes.
 *
 * IndexedDB itself is a browser API (no fake-indexeddb here): the store takes
 * any backend, and these tests give it an in-memory one that stands in for it.
 *
 * Run: node --test attachments_store.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Cryptography from "./lib/rns/cryptography.js";
import { AttachmentStore, attachmentKey, keysOf, memoryBackend, indexedDbBackend } from "./lib/attachment_store.js";
import { ObjectUrls } from "./lib/object_urls.js";
import { build, fn, install, memoryStorage } from "./test_app_source.mjs";

const quiet = { log() {}, warn() {}, error() {} };
const sha = (b) => Cryptography.fullHash(Buffer.from(b)).toString("hex");
const flush = () => new Promise((r) => setTimeout(r, 0));

// ── the store ───────────────────────────────────────────────────────────────

test("a write lands in the backend, is readable at once, and leaves memory once it has landed", async () => {
    const backend = memoryBackend({ persistent: true });
    const store = new AttachmentStore(backend, { warn() {} });
    const key = attachmentKey("m1", 0);
    assert.equal(key, "m1:0");
    const photo = Buffer.alloc(300_000, 5);
    const done = store.put(key, photo);
    assert.ok(store.peek(key), "readable in the same tick: _sendPacket packs synchronously");
    assert.deepEqual(await done, { stored: "persisted", error: null });
    assert.equal(store.peek(key), null, "not held twice");
    assert.equal(sha(await store.readBack(key)), sha(photo), "read back from the backend");
    assert.ok(backend.data.has(key));
    assert.equal(await store.persistent(), true);
});

test("an attachment that is a view into its message is stored as its own bytes, not the buffer behind it", async () => {
    // IndexedDB's structured clone keeps a view's whole buffer: a photo
    // sliced from a 1 MB payload would store the payload again per attachment.
    const handed = [];
    const store = new AttachmentStore({ persistent: true, async put(k, b) { handed.push(b); }, async get() { return null; } }, { warn() {} });
    const payloadBytes = Buffer.alloc(100_000, 1);
    await store.put("v:0", payloadBytes.subarray(1000, 1500));
    assert.equal(handed[0].byteLength, 500);
    assert.equal(handed[0].buffer.byteLength, 500, "a tight copy");
    const tight = new Uint8Array(10);
    await store.put("v:1", tight);
    assert.equal(handed[1], tight, "already tight: not copied again");
});

test("a write that fails keeps the bytes for the session and says why (never a silent loss)", async () => {
    const warnings = [];
    const store = new AttachmentStore(memoryBackend({ persistent: true, failPut: "QuotaExceededError" }), { warn: (m) => warnings.push(m) });
    const r = await store.put("m2:0", Buffer.from("photo"));
    assert.deepEqual(r, { stored: "failed", error: "QuotaExceededError" });
    assert.equal(Buffer.from(await store.get("m2:0")).toString(), "photo", "still shown this session");
    assert.equal(Buffer.from(await store.readBack("m2:0")).toString(), "photo");
    assert.ok(warnings.some((w) => w.includes("could not save m2:0")), warnings.join("\n"));
});

test("without IndexedDB the store keeps attachments for the session, and says so once", async () => {
    const warnings = [];
    const store = new AttachmentStore(Promise.reject(new Error("IndexedDB is not available")), { warn: (m) => warnings.push(m) });
    assert.deepEqual(await store.put("m3:0", Buffer.from("x")), { stored: "session", error: "IndexedDB is not available" });
    assert.equal(Buffer.from(await store.get("m3:0")).toString(), "x");
    assert.equal(await store.persistent(), false);
    assert.equal(warnings.length, 1);
    // The page's own opener on a browser with no IndexedDB (private mode in
    // some browsers): a rejection, which the store turns into session-only.
    await assert.rejects(indexedDbBackend(undefined), /not available/);
    await assert.rejects(indexedDbBackend({ open() { throw new Error("InvalidStateError"); } }), /InvalidStateError/);
    const opened = AttachmentStore.open(undefined);
    opened._warn = () => {};
    assert.equal((await opened.put("k", Buffer.from("y"))).stored, "session");
});

test("remove deletes from the backend and from memory; clear empties both", async () => {
    const backend = memoryBackend({ persistent: true });
    const store = new AttachmentStore(backend, { warn() {} });
    await store.put("a:0", Buffer.from("1"));
    await store.put("a:1", Buffer.from("2"));
    await store.put("b:0", Buffer.from("3"));
    assert.deepEqual(await store.remove(["a:0", "a:1"]), []);
    assert.deepEqual([...backend.data.keys()], ["b:0"]);
    assert.equal(await store.get("a:0"), null);
    await store.clear();
    assert.equal(backend.data.size, 0);
    assert.equal(await store.get("b:0"), null);
});

test("warm holds bytes in memory for a synchronous send; cool lets the backend's go", async () => {
    const backend = memoryBackend({ persistent: true });
    const store = new AttachmentStore(backend, { warn() {} });
    await store.put("q:0", Buffer.from("queued photo"));
    assert.equal(store.peek("q:0"), null);
    assert.deepEqual(await store.warm(["q:0", "gone:0"]), ["gone:0"], "says which are gone");
    assert.equal(Buffer.from(store.peek("q:0")).toString(), "queued photo");
    await store.cool(["q:0", "gone:0"]);
    assert.equal(store.peek("q:0"), null);
});

test("keysOf: the attachment keys of records", () => {
    assert.deepEqual(keysOf([{ attachments: [{ key: "x:0" }, { key: "x:1" }] }, { content: "text" }, null]), ["x:0", "x:1"]);
});

// ── object URLs ─────────────────────────────────────────────────────────────

test("an object URL is revoked once its element has left the page, and only then", () => {
    const made = [];
    const revoked = [];
    const urls = new ObjectUrls({ create: () => `blob:${made.push(1)}`, revoke: (u) => revoked.push(u), makeBlob: (b, t) => ({ b, t }) });
    const shown = { isConnected: true };
    const gone = { isConnected: true };
    const u1 = urls.attach(shown, Buffer.from("a"), "image/png");
    const u2 = urls.attach(gone, Buffer.from("b"), "image/png");
    assert.equal(urls.sweep(), 0);
    gone.isConnected = false;
    assert.equal(urls.sweep(), 1);
    assert.deepEqual(revoked, [u2]);
    urls.release(u1);
    assert.deepEqual(revoked, [u2, u1]);
    assert.equal(urls.size, 0);
});

// ── app.js: the stores, the hook, the bubble's data ─────────────────────────

function stores() {
    const storage = memoryStorage();
    const inbox = [];
    const Harness = build("Harness", {});
    Harness.event = () => {};
    const recorded = { recordInbound: (peer, msg) => { Harness.recordInbound(peer, msg); inbox.push(msg); } };
    const MsgStore = build("MsgStore", { sGet: storage.sGet, sSet: storage.sSet, Harness, Date });
    const GroupMsgStore = build("GroupMsgStore", { sGet: storage.sGet, sSet: storage.sSet, Date });
    return { storage, Harness, MsgStore, GroupMsgStore, inbox, recorded };
}

function client({ backend = memoryBackend({ persistent: true }) } = {}) {
    const s = stores();
    const Attachments = new AttachmentStore(backend, { warn() {} });
    const contacts = new Map();
    const ContactStore = { getAll: () => [...contacts.values()] };
    const GroupStore = { getAll: () => [] };
    const env = { MsgStore: s.MsgStore, GroupMsgStore: s.GroupMsgStore, ContactStore, GroupStore, Attachments, attachmentKey, Cryptography, console: quiet };
    const self = install({ _onAttachmentState: [] }, env, [
        "_keepAttachments(store, convHash, record, found, fieldsUnreadable = null)",
        "_findRecord(msgId)",
        "async attachmentsFor(msgId)",
    ]);
    return { ...s, Attachments, backend, contacts, self };
}

const found = (...list) => Object.defineProperty(list, "skipped", { value: 0 });

test("a received attachment: bytes to the store, {key, name, mime, size, sha256, field} on the record", async () => {
    const c = client();
    const peer = "a".repeat(32);
    c.contacts.set(peer, { destHash: peer });
    const photo = Buffer.alloc(200_000, 3);
    const record = c.MsgStore.add(peer, { dir: "in", content: "", status: "delivered", srcHash: peer });
    const kept = c.self._keepAttachments(c.MsgStore, peer, record, found({ name: "cat.png", mime: "image/png", bytes: photo, field: 5 }));
    assert.deepEqual(kept.attachments, [{
        key: `${record.id}:0`, name: "cat.png", mime: "image/png", size: 200_000, sha256: sha(photo), field: 5, stored: "saving",
    }]);
    assert.equal(kept.content, "", "captionless: content stays empty, the bubble shows the attachment");
    // The record in localStorage holds no bytes.
    assert.ok(c.storage.data.get(`msg_${peer}`).length < 2000, "only metadata in localStorage");
    await flush();
    assert.equal(c.MsgStore.get(peer)[0].attachments[0].stored, "persisted");
    assert.ok(c.backend.data.has(`${record.id}:0`));
    // The staging hook (test-harnesses/staging/lib/attach.mjs): read back.
    assert.deepEqual(await c.self.attachmentsFor(record.id), [
        { name: "cat.png", size: 200_000, sha256: sha(photo), mime: "image/png", field: 5, stored: "persisted" },
    ]);
    assert.deepEqual(await c.self.attachmentsFor("no-such-message"), []);
});

test("the hook's sha256 is of what the store holds, not of what arrived", async () => {
    const c = client();
    const peer = "b".repeat(32);
    c.contacts.set(peer, { destHash: peer });
    const record = c.MsgStore.add(peer, { dir: "in", content: "x" });
    c.self._keepAttachments(c.MsgStore, peer, record, found({ name: "f.bin", mime: "application/octet-stream", bytes: Buffer.from("original"), field: 5 }));
    await flush();
    c.backend.data.set(`${record.id}:0`, new Uint8Array(Buffer.from("corrupted")));
    const [got] = await c.self.attachmentsFor(record.id);
    assert.equal(got.sha256, sha(Buffer.from("corrupted")));
    assert.notEqual(got.sha256, c.MsgStore.get(peer)[0].attachments[0].sha256);
});

test("a write that fails shows on the record (and so the bubble), and the attachment is still there this session", async () => {
    const c = client({ backend: memoryBackend({ persistent: true, failPut: "QuotaExceededError: the quota has been exceeded" }) });
    const peer = "c".repeat(32);
    c.contacts.set(peer, { destHash: peer });
    const told = [];
    c.self._onAttachmentState.push((conv, id) => told.push([conv, id]));
    const record = c.MsgStore.add(peer, { dir: "in", content: "look" });
    c.self._keepAttachments(c.MsgStore, peer, record, found({ name: "big.jpg", mime: "image/jpeg", bytes: Buffer.alloc(10, 1), field: 5 }));
    await flush();
    const [meta] = c.MsgStore.get(peer)[0].attachments;
    assert.equal(meta.stored, "failed");
    assert.match(meta.storeError, /quota/);
    assert.deepEqual(told, [[peer, record.id]], "the UI is told, to repaint the bubble");
    assert.equal((await c.self.attachmentsFor(record.id))[0].size, 10);
});

test("without IndexedDB: stored \"session\" on the record, and the UI is told", async () => {
    const c = client({ backend: Promise.reject(new Error("IndexedDB is not available")) });
    const peer = "d".repeat(32);
    c.contacts.set(peer, { destHash: peer });
    const told = [];
    c.self._onAttachmentState.push((conv, id) => told.push(id));
    const record = c.MsgStore.add(peer, { dir: "in", content: "" });
    c.self._keepAttachments(c.MsgStore, peer, record, found({ name: "p.png", mime: "image/png", bytes: Buffer.alloc(4), field: 5 }));
    await flush();
    await flush();
    assert.equal(c.MsgStore.get(peer)[0].attachments[0].stored, "session");
    assert.deepEqual(told, [record.id]);
});

test("unreadable entries and an unreadable fields map are kept on the record for the bubble to say", () => {
    const c = client();
    const peer = "e".repeat(32);
    const record = c.MsgStore.add(peer, { dir: "in", content: "text" });
    const list = Object.defineProperty([], "skipped", { value: 2 });
    const kept = c.self._keepAttachments(c.MsgStore, peer, record, list, "Unknown extension 1");
    assert.equal(kept.attachmentsSkipped, 2);
    assert.equal(kept.fieldsUnreadable, true);
    assert.equal(kept.attachments, undefined);
});

test("deleting a conversation, or trimming its oldest messages, deletes their attachment bytes", async () => {
    const s = stores();
    const backend = memoryBackend({ persistent: true });
    const Attachments = new AttachmentStore(backend, { warn() {} });
    const discard = fn("discardAttachments", "records", { keysOf, Attachments, console: quiet });
    s.MsgStore.onDiscard = discard;
    s.GroupMsgStore.onDiscard = discard;
    const peer = "f".repeat(32);
    for (const i of [0, 1]) await Attachments.put(`dm${i}:0`, Buffer.from("x"));
    s.MsgStore.add(peer, { id: "dm0", dir: "in", content: "", attachments: [{ key: "dm0:0" }] });
    s.MsgStore.add(peer, { id: "dm1", dir: "in", content: "", attachments: [{ key: "dm1:0" }] });
    // Trim: the 501st message pushes out the oldest, and its bytes go.
    for (let i = 0; i < 499; i++) s.MsgStore.add(peer, { dir: "in", content: `m${i}` });
    await flush();
    assert.deepEqual([...backend.data.keys()], ["dm1:0"], "the trimmed message's bytes are gone, the kept one's stay");
    s.MsgStore.remove(peer);
    await flush();
    assert.deepEqual([...backend.data.keys()], [], "the conversation's");
    // Groups the same.
    await Attachments.put("g0:0", Buffer.from("y"));
    s.GroupMsgStore.add("g".repeat(32), { id: "g0", dir: "in", content: "", attachments: [{ key: "g0:0" }] });
    s.GroupMsgStore.remove("g".repeat(32));
    await flush();
    assert.equal(backend.data.size, 0);
});

test("the stores' hooks are wired at load, and Reset All deletes the attachments too", async () => {
    const { app } = await import("./test_app_source.mjs");
    assert.match(app, /\nconst Attachments = AttachmentStore\.open\(\);/);
    assert.match(app, /\nMsgStore\.onDiscard = discardAttachments;\nGroupMsgStore\.onDiscard = discardAttachments;/);
    const { methodBody } = await import("./test_app_source.mjs");
    assert.match(methodBody("_resetAll()"), /Attachments\.clear\(\)\.then\(done/);
    assert.doesNotMatch(app, /sSet\([^)]*bytes/, "bytes never go to localStorage");
});

test("Debug.inbox carries each stored message's LXMF hash; a captionless one is found by it", () => {
    const s = stores();
    const peer = "1".repeat(32);
    const stored = s.MsgStore.add(peer, { dir: "in", content: "", srcHash: peer, via: "direct", lxmfHash: "ab".repeat(32) });
    assert.deepEqual(s.Harness.inbox.map((m) => [m.id, m.content, m.lxmfHash]), [[stored.id, "", "ab".repeat(32)]]);
});

test("the chat list names a captionless attachment; a caption still wins", () => {
    const s = stores();
    const MsgStore = build("MsgStore", {
        sGet: s.storage.sGet, sSet: s.storage.sSet, Harness: { recordInbound() {} }, Date,
        attachmentPreview: fn("attachmentPreview", "m", {}),
    });
    const peer = "2".repeat(32);
    MsgStore.add(peer, { dir: "in", content: "", attachments: [{ name: "cat.png" }, { name: "dog.png" }] });
    assert.equal(MsgStore.preview(peer), "📎 cat.png +1");
    MsgStore.add(peer, { dir: "out", content: "", attachments: [{ name: "doc.pdf" }] });
    assert.equal(MsgStore.preview(peer), "You: 📎 doc.pdf");
    MsgStore.add(peer, { dir: "out", content: "with a caption", attachments: [{ name: "doc.pdf" }] });
    assert.equal(MsgStore.preview(peer), "You: with a caption");
});

test("the staging hooks (test-harnesses/staging/lib/attach.mjs HOOK_CONTRACT) are on window.RetichatTest", async () => {
    const { app } = await import("./test_app_source.mjs");
    const start = app.indexOf("\nwindow.RetichatTest = {");
    assert.notEqual(start, -1);
    const surface = app.slice(start, app.indexOf("\n};", start));
    assert.match(surface, /get inbox\(\) \{ return Harness\.inbox; \}/, "Debug.inbox");
    assert.match(surface, /\n    client: RnsClient,/, "Debug.client.attachmentsFor is RnsClient.attachmentsFor");
    assert.match(surface, /\n    app: App,/, "Debug.app.openChat");
    assert.match(surface, /fetchPropagated\(\) \{ return RnsClient\._fetchPropagatedMessages\(\); \}/, "Debug.fetchPropagated()");
    assert.match(app, /\n    async attachmentsFor\(msgId\) \{/);
    assert.match(app, /\n    openChat\(hash, activateChannel = true\) \{/);
});
