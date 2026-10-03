/**
 * lib/distro_outbox.js: what this device still owes its distro, each kept
 * until the propagation node proves it (review of Retichat-js 9f058e9,
 * 2026-10-03). The app's use of it (owing, sending on the link's events,
 * settling on the proof, across a disconnect and a reload) is tested in
 * distro_channels.test.mjs and distro_sent_sync.test.mjs.
 *
 * Run: node --test distro_outbox.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { DistroOutbox, channelSyncEntryId, sentCopyEntryId } from "./lib/distro_outbox.js";
import { memoryStorage } from "./test_app_source.mjs";

const D = "d".repeat(32);
const entry = (id, packed, extra = {}) => ({ id, kind: "channel", distro: D, packed, label: `the join of #${id}`, op: "join", name: id, at: 1, ...extra });
const outbox = (storage = memoryStorage()) => ({ storage, box: new DistroOutbox({ get: storage.sGet, set: storage.sSet }) });

test("an entry is owed until it is settled, oldest first, and kept in storage", () => {
    const { storage, box } = outbox();
    assert.deepEqual(box.list(), []);
    box.put(entry(channelSyncEntryId("aa"), "AAAA"));
    box.put(entry(sentCopyEntryId("ff"), "BBBB", { kind: "sent", to: "0".repeat(32) }));
    assert.deepEqual(box.list().map((e) => e.id), ["channel:aa", "sent:ff"]);
    assert.equal(box.get("sent:ff").to, "0".repeat(32));
    // Another page (a reload, or the tab that took the connection over)
    // sees what this one owes, and what either changes.
    const other = new DistroOutbox({ get: storage.sGet, set: storage.sSet });
    assert.deepEqual(other.list().map((e) => e.id), ["channel:aa", "sent:ff"]);
    assert.equal(other.settle("channel:aa", "AAAA"), true);
    assert.deepEqual(box.list().map((e) => e.id), ["sent:ff"], "read through on every use");
    assert.equal(box.settle("sent:ff", "BBBB"), true);
    assert.deepEqual(box.list(), []);
    assert.equal(box.settle("sent:ff", "BBBB"), false, "settled once");
});

test("put says whether storage kept the entry: the page's storage drops a write it cannot hold without a word", () => {
    const real = memoryStorage();
    const full = new DistroOutbox({ get: real.sGet, set() {} });
    assert.equal(full.put(entry("channel:aa", "AAAA")), false);
    assert.equal(outbox(real).box.put(entry("channel:aa", "AAAA")), true);
});

test("storage that refuses a write: this page holds what is owed, the refused entry in place of the one it replaced, and storage is written without that one", () => {
    const real = memoryStorage();
    let full = false;
    // A full localStorage: a larger write is refused (app.js sSet drops it
    // without a word), a smaller one is taken.
    const storage = { get: real.sGet, set: (k, v) => { if (!(full && JSON.stringify(v).length > (real.data.get(k)?.length ?? 0))) real.sSet(k, v); } };
    const box = new DistroOutbox(storage);
    assert.equal(box.put(entry("channel:aa", "AAAA")), true);
    assert.equal(box.put(entry("sent:ff", "BBBB", { kind: "sent", to: "0".repeat(32) })), true);
    full = true;
    assert.equal(box.put(entry("channel:aa", "CCCCCCCC", { op: "leave", at: 2 })), false, "refused, and said");
    // Review of 73a725d: the join stayed owed under the channel's id, and
    // went to the siblings after the user had left.
    assert.deepEqual(box.list().map((e) => [e.id, e.packed]), [["sent:ff", "BBBB"], ["channel:aa", "CCCCCCCC"]],
        "this page owes the newer action, never the one it replaced");
    assert.equal(box.get("channel:aa").packed, "CCCCCCCC");
    assert.deepEqual(new DistroOutbox(storage).list().map((e) => e.id), ["sent:ff"], "a later page owes neither");
    assert.equal(box.settle("channel:aa", "CCCCCCCC"), true);
    assert.deepEqual(box.list().map((e) => e.id), ["sent:ff"]);
    // That write was taken: storage is the outbox again, read through.
    assert.equal(new DistroOutbox(storage).settle("sent:ff", "BBBB"), true);
    assert.deepEqual(box.list(), []);
});

test("a later entry under the same id replaces the one owed, and goes to the end", () => {
    const { box } = outbox();
    box.put(entry("channel:aa", "AAAA"));
    box.put(entry("channel:bb", "BBBB"));
    box.put(entry("channel:aa", "CCCC", { op: "leave", at: 2 }));
    assert.deepEqual(box.list().map((e) => [e.id, e.packed, e.op]), [["channel:bb", "BBBB", "join"], ["channel:aa", "CCCC", "leave"]]);
});

test("settling the earlier message under an id leaves the later one owed", () => {
    const { box } = outbox();
    box.put(entry("channel:aa", "AAAA"));
    box.put(entry("channel:aa", "CCCC", { op: "leave", at: 2 }));
    assert.equal(box.settle("channel:aa", "AAAA"), false, "the join's proof");
    assert.deepEqual(box.list().map((e) => e.packed), ["CCCC"], "the leave is still owed");
    assert.equal(box.settle("channel:aa", "CCCC"), true);
});

test("what is stored and is not an entry is ignored, and a malformed entry is refused", () => {
    const storage = memoryStorage();
    storage.sSet("distro_outbox_v1", [null, 7, { id: "x" }, entry("channel:aa", "not base64!"), entry("channel:bb", "QUJD", { distro: "short" }),
        entry("channel:cc", "QUJD", { kind: "other" }), entry("channel:ok", "QUJD")]);
    const { box } = outbox(storage);
    assert.deepEqual(box.list().map((e) => e.id), ["channel:ok"]);
    storage.sSet("distro_outbox_v1", { not: "a list" });
    assert.deepEqual(box.list(), []);
    for (const bad of [null, entry("", "QUJD"), entry("channel:x", ""), entry("channel:x", "QUJD", { distro: "D".repeat(32) }),
        entry("channel:x", "QUJD", { label: 7 })]) {
        assert.throws(() => box.put(bad), /not an entry the distro can be owed/);
    }
});
