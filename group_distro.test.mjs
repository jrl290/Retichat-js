/**
 * The client-local stores of groups reached through the distro D
 * (lib/group_distro.js; GROUPS-DISTRO-DESIGN.md §6.5, §9.1, §10.2): the held
 * arrivals and their bounds, the filtered-invite set, the per-D `left` list
 * and the known siblings.
 *
 * Run: node --test group_distro.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { HeldGroupArrivals, FilteredInvites, DistroLeftGroups, KnownSiblings } from "./lib/group_distro.js";
import { memoryStorage } from "./test_app_source.mjs";

const store = (s = memoryStorage()) => ({ get: s.sGet, set: s.sSet });
const D = "d".repeat(32);
const hex32 = (n) => n.toString(16).padStart(32, "0");
let seq = 0;
const arrival = (groupId, src, extra = {}) => {
    const n = ++seq;
    return { blob: Buffer.alloc(extra.size ?? 200, n & 0xff), groupId, src, hash: n.toString(16).padStart(64, "0"), signature: n.toString(16).padStart(128, "0"), validated: true, pending: false, ...extra };
};

test("held arrivals: kept in arrival order, persisted, per group, released one by one; held again is a no-op", () => {
    const s = store();
    const held = new HeldGroupArrivals(s);
    const a = arrival(hex32(1), hex32(0xa), { pending: true });
    const b = arrival(hex32(1), hex32(0xb), { pending: true });
    assert.equal(held.hold(a, D).held, true);
    assert.equal(held.hold(b, D).held, true);
    assert.deepEqual(held.hold(a, D), { held: true, why: "it is held already", evicted: [] });
    const again = new HeldGroupArrivals(s);
    assert.deepEqual(again.forGroup(hex32(1)).map((r) => r.src), [hex32(0xa), hex32(0xb)]);
    assert.ok(Buffer.from(again.forGroup(hex32(1))[0].blob, "base64").equals(Buffer.from(a.blob)));
    assert.equal(again.release(again.forGroup(hex32(1))[0]), true);
    assert.deepEqual(new HeldGroupArrivals(s).forGroup(hex32(1)).map((r) => r.src), [hex32(0xb)]);
    assert.equal(again.forgetGroup(hex32(1)), 1);
    assert.deepEqual(new HeldGroupArrivals(s).list(), []);
});

test("held arrivals: a copy with another signature never shadows one held; a validated copy replaces an unverified one of the same hash", () => {
    const held = new HeldGroupArrivals(store());
    const a = arrival(hex32(1), hex32(0xa), { validated: false, pending: true });
    held.hold(a, D);
    const forged = { ...a, signature: "ff".repeat(64) };
    assert.equal(held.hold(forged, D).held, true);
    assert.equal(held.list().length, 2, "held beside it, not over it");
    const good = { ...a, signature: "ee".repeat(64), validated: true };
    assert.equal(held.hold(good, D).why, "it replaces an unverified copy of the same message");
    assert.deepEqual(held.list().map((r) => [r.signature.slice(0, 2), r.validated]), [["ee", true], ["ff", false]]);
});

test("held arrivals: a blob over 64 KiB is never held", () => {
    const held = new HeldGroupArrivals(store());
    const r = held.hold(arrival(hex32(1), hex32(0xa), { size: 64 * 1024 + 1, pending: true }), D);
    assert.equal(r.held, false);
    assert.match(r.why, /65537 bytes/);
    assert.equal(held.list().length, 0);
});

test("held arrivals: 16 per group, the oldest of the source holding the most pushed out; 8 per source other than D; D's post G counts against its group only", () => {
    const held = new HeldGroupArrivals(store());
    const g = hex32(1);
    for (let i = 0; i < 6; i++) held.hold(arrival(g, hex32(0xa), { pending: true }), D);
    for (let i = 0; i < 10; i++) held.hold(arrival(g, D, { pending: true }), D);
    assert.equal(held.forGroup(g).length, 16);
    const r = held.hold(arrival(g, hex32(0xb), { pending: true }), D);
    assert.equal(r.held, true);
    assert.deepEqual(r.evicted, [{ groupId: g, src: D, bound: "16 per group" }], "D holds the most there: its oldest goes");
    // 8 per source, across groups.
    const h2 = new HeldGroupArrivals(store());
    for (let i = 0; i < 8; i++) h2.hold(arrival(hex32(10 + i), hex32(0xc), { pending: true }), D);
    const r2 = h2.hold(arrival(hex32(30), hex32(0xc), { pending: true }), D);
    assert.deepEqual(r2.evicted, [{ groupId: hex32(10), src: hex32(0xc), bound: "8 per source" }]);
    assert.equal(h2.list().length, 8);
});

test("held arrivals (§19.2): 64 proven messages from strangers for random group ids never push out a held creator status: groups not held here get 16 in all", () => {
    const held = new HeldGroupArrivals(store());
    const status = arrival(hex32(0xabc), hex32(0xc4ea), { pending: true });
    assert.equal(held.hold(status, D).held, true);
    for (let i = 0; i < 64; i++) {
        const r = held.hold(arrival(hex32(0x1000 + i), hex32(0x5000 + i)), D);
        assert.equal(r.held, true, `stranger ${i}`);
        assert.ok(r.evicted.every((e) => e.src !== status.src), "the creator's status is never pushed out");
    }
    assert.equal(held.list().filter((r) => !r.pending).length, 16);
    assert.equal(held.forGroup(hex32(0xabc)).length, 1, "the status is still held");
});

test("held arrivals: 64 blobs and 256 KiB in all; when nothing may be pushed out, the new blob is refused and says which bound", () => {
    const held = new HeldGroupArrivals(store());
    for (let i = 0; i < 64; i++) assert.equal(held.hold(arrival(hex32(100 + (i % 8)), hex32(200 + (i % 8)), { pending: true }), D).held, true);
    assert.equal(held.list().length, 64);
    const r = held.hold(arrival(hex32(300), hex32(400), { pending: true }), D);
    assert.equal(r.held, true);
    assert.equal(r.evicted.length, 1);
    assert.equal(r.evicted[0].bound, "64 blobs and 262144 bytes in all");
    assert.equal(held.list().length, 64);
    // Bytes: four 60 KiB blobs fill it.
    const big = new HeldGroupArrivals(store());
    for (let i = 0; i < 4; i++) big.hold(arrival(hex32(500 + i), hex32(600 + i), { size: 60 * 1024, pending: true }), D);
    const r2 = big.hold(arrival(hex32(700), hex32(800), { size: 30 * 1024, pending: true }), D);
    assert.equal(r2.evicted.length, 1);
    // A blob for a group not held here may push out nothing a pending group holds.
    const full = new HeldGroupArrivals(store());
    for (let i = 0; i < 64; i++) full.hold(arrival(hex32(900 + (i % 4)), hex32(1000 + (i % 8)), { pending: true }), D);
    const r3 = full.hold(arrival(hex32(2000), hex32(3000)), D);
    assert.equal(r3.held, false);
    assert.match(r3.why, /64 blobs/);
    assert.equal(full.list().length, 64);
});

test("the filtered-invite set: at most 64, oldest forgotten first, persisted; an id leaves when removed", () => {
    const s = store();
    const f = new FilteredInvites(s);
    for (let i = 0; i < 70; i++) f.add(hex32(i));
    assert.equal(f.has(hex32(5)), false);
    assert.equal(f.has(hex32(6)), true);
    assert.equal(new FilteredInvites(s).ids.length, 64);
    assert.equal(f.remove(hex32(69)), true);
    assert.equal(new FilteredInvites(s).has(hex32(69)), false);
});

test("the left list: per D, most recent first, at most 32, persisted", () => {
    const s = store();
    const l = new DistroLeftGroups(s);
    for (let i = 0; i < 40; i++) l.record(D, hex32(i));
    l.record(D, hex32(20));
    const ids = new DistroLeftGroups(s).of(D);
    assert.equal(ids.length, 32);
    assert.equal(ids[0], hex32(20));
    assert.equal(ids[1], hex32(39));
    assert.deepEqual(l.of("e".repeat(32)), []);
});

test("known siblings: per D, learned once, persisted, dropped for distros given up", () => {
    const s = store();
    const k = new KnownSiblings(s);
    assert.equal(k.add(D, hex32(1)), true);
    assert.equal(k.add(D, hex32(1)), false);
    assert.equal(k.add(D, "nope"), false);
    k.add("e".repeat(32), hex32(2));
    assert.deepEqual(new KnownSiblings(s).of(D), [hex32(1)]);
    assert.deepEqual(k.keepOnly([D]), ["e".repeat(32)]);
    assert.deepEqual(new KnownSiblings(s).of("e".repeat(32)), []);
    assert.equal(new KnownSiblings(s).has(D, hex32(1)), true);
});
