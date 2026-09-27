/**
 * DISPLAY NAMES — LXMF-rust/DISPLAY_NAMES.md, the web client's half.
 *
 * §3 cleaning, the 0xD1 decode and the name digest run against the SAME
 * vectors as LXMF-rust (tests/display_name_vectors.json, read from that
 * crate, not copied), so the two implementations cannot drift apart. The
 * rest pins the rules every client applies itself: §4.1 (the ledger
 * decision), §4.2 (the channel rule), §5.2 (accepting a name), §5.3 (the
 * resolver) and §5.4 (migration).
 *
 * Run: node --test display_names.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import * as DN from "./lib/display_name.js";
import { NameLedger, ChannelPostNames, ChannelSenderNames } from "./lib/name_ledger.js";

const vectors = JSON.parse(await readFile(
    new URL("../LXMF-rust/tests/display_name_vectors.json", import.meta.url), "utf8"));
const hex = (s) => Buffer.from(s, "hex");

function memoryStorage() {
    const data = new Map();
    return { data, get: (k) => (data.has(k) ? JSON.parse(data.get(k)) : null), set: (k, v) => data.set(k, JSON.stringify(v)) };
}

test("§3 clean: every shared vector", () => {
    assert.ok(vectors.clean.length >= 50);
    for (const v of vectors.clean) {
        assert.equal(DN.clean(hex(v.input_hex)), v.expected, v.name);
    }
});

test("§3 clean_announce: every shared vector", () => {
    assert.ok(vectors.clean_announce.length >= 8);
    for (const v of vectors.clean_announce) {
        assert.equal(DN.cleanAnnounce(hex(v.input_hex)), v.expected, v.name);
    }
});

test("§3 decode of 0xD1: every shared vector, through the client's own msgpack", () => {
    assert.ok(vectors.decode_field.length >= 15);
    for (const v of vectors.decode_field) {
        const fields = MsgPack.unpack(hex(v.fields_msgpack_hex));
        const got = DN.decodeField(fields);
        assert.equal(got.state, v.state, v.name);
        assert.equal(got.state === "name" ? got.name : null, v.display_name, v.name);
    }
});

test("§4.1 digest: every shared vector", () => {
    for (const v of vectors.digest) {
        assert.equal(DN.digestHex(v.input === "" ? null : v.input), v.digest_hex, v.name);
    }
    assert.equal(DN.EMPTY_DIGEST, vectors.digest.find((v) => v.input === "").digest_hex);
});

test("M8: a Map at 0xD1 (MeshChatX/Columba dicts) never becomes a name, and 0x10 is not read", () => {
    assert.equal(DN.decodeField(new Map([[0xD1, new Map([["r", 1]])]])).state, "absent");
    assert.equal(DN.decodeField(new Map([[0x10, new Map([["r", 1]])]])).state, "absent");
    assert.equal(DN.decodeField(new Map([[0x10, "Alice"]])).state, "absent");
    assert.equal(DN.decodeField({ 209: "Alice" }).state, "absent", "a plain object is not a fields map");
});

test("§2.1 the value sent is bin (a Buffer), never a JS string", () => {
    const fields = DN.applyToFields(new Map(), DN.nameState("Alice"));
    assert.ok(Buffer.isBuffer(fields.get(0xD1)));
    assert.equal(MsgPack.pack(fields).toString("hex"), "81ccd1c405416c696365");
    assert.equal(MsgPack.pack(DN.applyToFields(new Map(), DN.CLEAR)).toString("hex"), "81ccd1c400");
    assert.equal(DN.applyToFields(new Map(), DN.ABSENT).size, 0);
});

test("announce names: first element of the list, cleaned, Anonymous Peer as none", () => {
    const unpack = (d) => MsgPack.unpack(d);
    assert.equal(DN.announceNameFromAppData(MsgPack.pack([Buffer.from(" Alice\n"), 8]), unpack), "Alice");
    assert.equal(DN.announceNameFromAppData(MsgPack.pack(["Bob", null, []]), unpack), "Bob");
    assert.equal(DN.announceNameFromAppData(MsgPack.pack([null, null, [0xD0]]), unpack), null);
    assert.equal(DN.announceNameFromAppData(MsgPack.pack([Buffer.from("anonymous peer"), 8]), unpack), null);
    assert.equal(DN.announceNameFromAppData(Buffer.from("Carol"), unpack), "Carol", "original raw format");
    assert.equal(DN.announceNameFromAppData(null, unpack), null);
});

test("§4.1 ledger decision", () => {
    const now = 1_800_000_000;
    const alice = DN.digestHex("Alice");
    assert.deepEqual(DN.decide("Alice", null, now), DN.nameState("Alice"), "no row: include");
    assert.deepEqual(DN.decide("Alice", { digest: alice, confirmedAt: now - 10 }, now), DN.ABSENT, "confirmed recently");
    assert.deepEqual(DN.decide("Alice", { digest: alice, confirmedAt: now - DN.NAME_REFRESH_SECS }, now), DN.ABSENT, "exactly 30 days is not older");
    assert.deepEqual(DN.decide("Alice", { digest: alice, confirmedAt: now - DN.NAME_REFRESH_SECS - 1 }, now), DN.nameState("Alice"), "older than 30 days");
    assert.deepEqual(DN.decide("Alice", { digest: DN.digestHex("Al"), confirmedAt: now }, now), DN.nameState("Alice"), "name changed");
    assert.deepEqual(DN.decide(null, null, now), DN.ABSENT, "unset, never sent");
    assert.deepEqual(DN.decide(null, { digest: alice, confirmedAt: now }, now), DN.CLEAR, "unset after a real name: clear");
    assert.deepEqual(DN.decide(null, { digest: DN.EMPTY_DIGEST, confirmedAt: now }, now), DN.ABSENT, "clear already delivered");
});

test("§4.1 NameLedger persists per (source, recipient) and records only what was sent", () => {
    const storage = memoryStorage();
    const ledger = new NameLedger(storage);
    assert.equal(ledger.recordDelivered("aa", "bb", DN.ABSENT, 5), false);
    assert.equal(ledger.lookup("aa", "bb"), null);
    ledger.recordDelivered("aa", "bb", DN.nameState("Alice"), 100);
    const reloaded = new NameLedger(storage);
    assert.deepEqual(reloaded.lookup("aa", "bb"), { digest: DN.digestHex("Alice"), confirmedAt: 100 });
    assert.equal(reloaded.lookup("cc", "bb"), null, "the source is part of the key (distro vs device)");
    assert.deepEqual(reloaded.decideFor("Alice", "aa", "bb", 200), DN.ABSENT);
    assert.deepEqual(reloaded.decideFor("Alice", "cc", "bb", 200), DN.nameState("Alice"));
    reloaded.recordDelivered("aa", "bb", DN.CLEAR, 300);
    assert.deepEqual(reloaded.decideFor(null, "aa", "bb", 400), DN.ABSENT, "the clear was delivered");
});

test("§4.2 channel rule: first post, change, new sender, 24 h, clear once", () => {
    const storage = memoryStorage();
    const posts = new ChannelPostNames(storage);
    const H = 3_600_000;
    let t = 1_000 * H;
    const post = (name) => {
        const state = posts.decide("public.x", name, t);
        posts.recordIncluded("public.x", state, t);
        return state.state;
    };
    assert.equal(post("Alice"), "name", "first post");
    t += H;
    assert.equal(post("Alice"), "absent");
    assert.equal(posts.noteSender("public.x", "me", "me", t), false, "own echo is not a new sender");
    assert.equal(posts.noteSender("public.x", "b0b", "me", t + 1), true);
    t += H;
    assert.equal(post("Alice"), "name", "a new sender posted since the last inclusion");
    assert.equal(posts.noteSender("public.x", "b0b", "me", t + 1), false, "seen before");
    t += H;
    assert.equal(post("Alice"), "absent");
    t += 24 * H + 1;
    assert.equal(post("Alice"), "name", "more than 24 hours");
    t += H;
    assert.equal(post("Alicia"), "name", "name changed");
    t += H;
    assert.equal(post(null), "clear", "unset after a real name: clear once");
    t += H;
    assert.equal(post(null), "absent");
    assert.equal(new ChannelPostNames(storage).decide("public.x", null, t).state, "absent", "persisted");
    assert.equal(new ChannelPostNames(storage).decide("public.y", null, t).state, "absent", "never named: nothing");
});

test("§5.2 accepting a 0xD1", () => {
    const { acceptMessageName: accept, nameState, CLEAR, ABSENT } = DN;
    assert.equal(accept(null, nameState("A"), DN.SIG_VALIDATED), "A");
    assert.equal(accept("B", nameState("A"), DN.SIG_VALIDATED), "A");
    assert.equal(accept("B", CLEAR, DN.SIG_VALIDATED), null);
    assert.equal(accept(null, nameState("A"), DN.SIG_UNKNOWN), "A", "unknown source sets only an empty name");
    assert.equal(accept("B", nameState("A"), DN.SIG_UNKNOWN), "B");
    assert.equal(accept("B", CLEAR, DN.SIG_UNKNOWN), "B");
    assert.equal(accept(null, nameState("A"), DN.SIG_INVALID), null);
    assert.equal(accept("B", CLEAR, DN.SIG_INVALID), "B");
    assert.equal(accept("B", ABSENT, DN.SIG_VALIDATED), "B");
});

test("§5.1 channel names are per (channel, sender) and clearable", () => {
    const storage = memoryStorage();
    const names = new ChannelSenderNames(storage);
    assert.equal(names.apply("c1", "s", DN.nameState("Pseud")), true);
    assert.equal(new ChannelSenderNames(storage).get("c1", "s"), "Pseud");
    assert.equal(names.get("c2", "s"), null, "another channel does not share it");
    assert.equal(names.apply("c1", "s", DN.ABSENT), false);
    assert.equal(names.apply("c1", "s", DN.CLEAR), true);
    assert.equal(names.get("c1", "s"), null);
});

test("§5.3 resolver: local > message > announce > 8-hex short hash; channel label with secondary hash", () => {
    const h = "0123456789abcdef0123456789abcdef";
    assert.equal(DN.shortHash(h), "01234567…");
    assert.equal(DN.contactName(null, h), "01234567…");
    assert.equal(DN.contactName({ destHash: h, announceName: "Ann" }, h), "Ann");
    assert.equal(DN.contactName({ destHash: h, announceName: "Ann", messageName: "Msg" }, h), "Msg");
    assert.equal(DN.contactName({ destHash: h, announceName: "Ann", messageName: "Msg", localName: "Mine" }, h), "Mine");
    assert.deepEqual(DN.channelPosterName("Pseud", { localName: "Mine" }, h), { label: "Pseud", secondary: "01234567…" });
    assert.deepEqual(DN.channelPosterName(null, { localName: "Mine" }, h), { label: "Mine", secondary: null });
    assert.deepEqual(DN.channelPosterName(null, null, h), { label: "01234567…", secondary: null });
});

test("§5.4 contact migration: nameCustomized → local, otherwise message, ?hash dropped", () => {
    const h = "0123456789abcdef0123456789abcdef";
    const base = { destHash: h, publicKey: null, lastSeen: 1 };
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bob", nameCustomized: true }),
        { ...base, localName: "Bob", messageName: null, announceName: null });
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bob", nameCustomized: false }),
        { ...base, localName: null, messageName: "Bob", announceName: null });
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "?01234567", nameCustomized: false }),
        { ...base, localName: null, messageName: null, announceName: null });
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "?01234567", nameCustomized: true }),
        { ...base, localName: null, messageName: null, announceName: null }, "a cleared rename");
    const migrated = { ...base, localName: null, messageName: "M", announceName: "A" };
    assert.deepEqual(DN.migrateContact(migrated), migrated, "idempotent");
});

test("§5.4 own name: the old display name becomes the Message Display Name, placeholders empty", () => {
    assert.equal(DN.migrateOwnDisplayName("James", "Retichat Web (E2E)"), "James");
    assert.equal(DN.migrateOwnDisplayName("Retichat Web", null), null);
    assert.equal(DN.migrateOwnDisplayName("Retichat Web (E2E)", "Retichat Web (E2E)"), null, "config.json default");
    assert.equal(DN.migrateOwnDisplayName("  ", null), null);
    assert.equal(DN.migrateOwnDisplayName(null, null), null);
});
