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
import { DistroOutbox, UnprovedUploads, channelSyncEntryId, sentCopyEntryId } from "./lib/distro_outbox.js";
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

/** Storage that refuses a write of the outbox larger than what it holds once
 *  `on` is set, as a full localStorage does (app.js sSet drops it without a
 *  word); a smaller write is taken. With `frozen` set it refuses every write. */
function fullStorage() {
    const real = memoryStorage();
    const s = {
        on: false, frozen: false, real,
        get: real.sGet,
        set: (k, v) => {
            if (s.frozen) return;
            if (s.on && JSON.stringify(v).length > (real.data.get(k)?.length ?? 0)) return;
            real.sSet(k, v);
        },
    };
    return s;
}
const SENT = (hash, packed) => entry(sentCopyEntryId(hash), packed, { kind: "sent", to: "0".repeat(32) });

test("RFed SPEC §17.12: owe a join (kept), storage fills, a sent-copy and then a leave of that channel are refused; what storage holds no longer holds the join", () => {
    const storage = fullStorage();
    const lines = [];
    const box = new DistroOutbox(storage, { log: { error: (line) => lines.push(line) } });
    assert.equal(box.put(entry("channel:aa", "AAAA")), true, "the join is kept");
    storage.on = true;
    assert.equal(box.put(SENT("ff", "BBBBBBBBBBBB")), false, "the sent-copy is refused: this page holds it");
    assert.equal(box.put(entry("channel:aa", "CCCCCCCC", { op: "leave", at: 2 })), false, "the leave is refused too");
    assert.deepEqual(box.list().map((e) => [e.id, e.packed]), [["sent:ff", "BBBBBBBBBBBB"], ["channel:aa", "CCCCCCCC"]],
        "this page owes the sent-copy and the leave");
    // Review of a448e98: the write after the second refusal was what this
    // page held, less the join ([sent-copy]), larger than what storage held
    // ([join]); storage refused it, kept the join, and the next page sent
    // the join the user had undone.
    assert.deepEqual(new DistroOutbox(storage).list(), [], "a later page owes neither the join nor what storage refused");
    // Storage took the smaller write: nothing it holds would go from a
    // later page, and no such error is said (review of 3411e19, N2).
    assert.deepEqual(lines, []);
});

test("storage that refuses writes: what this page settles or drops is taken out of storage too, never left for a later page", () => {
    const storage = fullStorage();
    const lines = [];
    const box = new DistroOutbox(storage, { log: { error: (line) => lines.push(line) } });
    const OTHER = "e".repeat(32);
    box.put(entry("channel:aa", "AAAA"));
    box.put(SENT("ff", "BBBB"));
    box.put(entry("channel:bb", "DDDD", { distro: OTHER }));
    storage.on = true;
    assert.equal(box.put(SENT("ee", "EEEEEEEEEEEEEEEEEEEE")), false);
    // The join is proved: the write of what this page now owes is larger
    // than what storage holds, and refused; storage still drops the join.
    assert.equal(box.settle("channel:aa", "AAAA"), true);
    assert.deepEqual(new DistroOutbox(storage).list().map((e) => e.id), ["sent:ff", "channel:bb"], "a later page never uploads the proved join again");
    // The distro OTHER was given up: the membership message owed to it
    // leaves storage too.
    assert.deepEqual(box.dropMembershipNotFor(D).map((e) => e.id), ["channel:bb"]);
    assert.deepEqual(box.list().map((e) => e.id), ["sent:ff", "sent:ee"]);
    assert.deepEqual(new DistroOutbox(storage).list().map((e) => e.id), ["sent:ff"]);
    assert.deepEqual(lines, [], "each smaller write was taken: nothing is said");
});

test("storage that refuses even a smaller write is said: what it still holds that is owed no more, which a later page would send", () => {
    const storage = fullStorage();
    const lines = [];
    const box = new DistroOutbox(storage, { log: { error: (line) => lines.push(line) } });
    box.put(entry("channel:aa", "AAAA"));
    storage.frozen = true;
    assert.equal(box.put(entry("channel:aa", "CCCC", { op: "leave", at: 2, label: "the leave of #aa" })), false);
    assert.deepEqual(box.list().map((e) => e.packed), ["CCCC"], "this page holds the leave");
    assert.deepEqual(lines.length, 1);
    assert.match(lines[0], /refuses even a smaller write: it still holds the join of #channel:aa, owed no more, which a later page would send/);
    // A write storage takes again makes it the outbox again, the join gone.
    storage.frozen = false;
    assert.equal(box.settle("channel:aa", "CCCC"), true);
    assert.deepEqual(new DistroOutbox(storage).list(), []);
    assert.equal(lines.length, 1, "nothing more said once storage takes the write");
});

test("dropMembershipNotFor: every membership message owed to another distro, or all of them when none is held, is dropped and returned; sent-copies are kept, to whatever distro they are owed", () => {
    // James, 2026-10-03: a sent-copy is already packed and signed as the
    // distro, and is still owed to it after the device gives it up. Until
    // then (dropAllBut, Retichat-js 3411e19 and 145ca2f) it was dropped too.
    const { storage, box } = outbox();
    const OTHER = "e".repeat(32);
    box.put(entry("channel:aa", "AAAA"));
    box.put(entry("channel:bb", "BBBB", { distro: OTHER }));
    box.put(SENT("ff", "CCCC"));
    box.put(entry(sentCopyEntryId("ee"), "DDDD", { kind: "sent", to: "0".repeat(32), distro: OTHER }));
    assert.deepEqual(box.dropMembershipNotFor(D).map((e) => e.id), ["channel:bb"]);
    assert.deepEqual(new DistroOutbox({ get: storage.sGet, set: storage.sSet }).list().map((e) => e.id), ["channel:aa", "sent:ff", "sent:ee"], "in storage");
    assert.deepEqual(box.dropMembershipNotFor(D), [], "nothing more to drop");
    assert.deepEqual(box.dropMembershipNotFor(null).map((e) => e.id), ["channel:aa"], "no distro held: no membership message is owed");
    assert.deepEqual(box.list().map((e) => [e.id, e.distro]), [["sent:ff", D], ["sent:ee", OTHER]], "each sent-copy still owed to its own distro");
});

test("an entry may carry its distro's public key, 128 lowercase hex; one without it (written before 2026-10-03) is still an entry", () => {
    const { box } = outbox();
    const KEY = "ab".repeat(64);
    box.put(SENT("ff", "CCCC"));
    box.put({ ...SENT("ee", "DDDD"), distroKey: KEY });
    assert.deepEqual(box.list().map((e) => [e.id, e.distroKey ?? null]), [["sent:ff", null], ["sent:ee", KEY]]);
    for (const bad of ["AB".repeat(64), "ab".repeat(32), 7, null]) {
        assert.throws(() => box.put({ ...SENT("dd", "EEEE"), distroKey: bad }), /not an entry the distro can be owed/, String(bad));
    }
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

test("UnprovedUploads: a failure record is one message's (its id and its bytes); recording, reading or forgetting one never touches another's, the same channel's included", () => {
    // Review of 367b266 (verifier probe VR4-OW): the record was kept per
    // id, so the join's failure, decided after the leave's, replaced the
    // leave's record (app.js _uploadOwed; distro_channels.test.mjs).
    const unproved = new UnprovedUploads();
    const join = entry("channel:aa", "AAAA");
    const leave = entry("channel:aa", "CCCC", { op: "leave", at: 2 });
    const other = entry("channel:bb", "AAAA");
    assert.deepEqual([unproved.at(leave), unproved.since(leave, 0), unproved.size], [undefined, false, 0]);
    unproved.record(leave, 3);
    unproved.record(join, 4);              // the older action's, decided later
    unproved.record(other, 1);             // the same bytes under another id
    assert.deepEqual([unproved.at(join), unproved.at(leave), unproved.at(other), unproved.size], [4, 3, 1, 3]);
    assert.deepEqual([3, 4].map((comingUp) => unproved.since(leave, comingUp)), [true, false], "a flush taken at 3 leaves the leave; one taken at 4 sends it");
    unproved.record(leave, 5);             // the same message decided again, later
    assert.equal(unproved.at(leave), 5);
    unproved.forget(join);                 // the join proved, late
    assert.deepEqual([unproved.at(join), unproved.at(leave), unproved.at(other), unproved.size], [undefined, 5, 1, 2]);
    unproved.forget(join);                 // nothing left of it to forget
    unproved.forget(leave);
    unproved.forget(other);
    assert.equal(unproved.size, 0);
});
