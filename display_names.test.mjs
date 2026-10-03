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

/** A packed LXMF payload [timestamp, title, content, <fields bytes>]. */
const payloadWith = (fieldsBytes) => Buffer.concat([hex("94cb41d9d7a4b8000000c400c400"), fieldsBytes]);
/** msgpack str header + the raw bytes, valid UTF-8 or not. */
const rawStr = (bytes) => Buffer.concat([
    bytes.length < 32 ? Buffer.from([0xa0 | bytes.length]) : Buffer.from([0xd9, bytes.length]), bytes]);

test("§3 decode of 0xD1: every shared vector, read from the payload bytes", () => {
    assert.ok(vectors.decode_field.length >= 15);
    for (const v of vectors.decode_field) {
        const got = DN.decodePayload(payloadWith(hex(v.fields_msgpack_hex)));
        assert.equal(got.state, v.state, v.name);
        assert.equal(got.state === "name" ? got.name : null, v.display_name, v.name);
    }
});

test("§3 rule 1 on received str: every clean vector as a str 0xD1 and a str announce name", () => {
    // msgpackr rewrites a str holding invalid UTF-8 before any JS sees it
    // (U+FFFD under Node; "ÿ" for 0xFF, "/" for overlong C0 AF in its
    // browser decoder), so a received name must be read from the bytes.
    for (const v of vectors.clean) {
        const raw = hex(v.input_hex);
        for (const [type, value] of [["str", rawStr(raw)], ["bin", Buffer.concat([Buffer.from([0xc4, raw.length]), raw])]]) {
            const got = DN.decodePayload(payloadWith(Buffer.concat([hex("81ccd18100"), value])));
            const want = raw.length === 0 ? "clear" : v.expected === null ? "absent" : "name";
            assert.equal(got.state, want, `${v.name} (${type})`);
            if (want === "name") assert.equal(got.name, v.expected, `${v.name} (${type})`);
        }
    }
    for (const v of vectors.clean_announce) {
        const appData = Buffer.concat([hex("93"), rawStr(hex(v.input_hex)), hex("c090")]);
        assert.equal(DN.announceNameFromAppData(appData), v.expected, `${v.name} (str)`);
    }
    assert.equal(DN.decodePayload(payloadWith(hex("81ccd18100a6416c696365ed"))).state, "absent", "Alice + a stray 0xED");
    assert.equal(DN.decodePayload(payloadWith(hex("81ccd18100a1ff"))).state, "absent", "a lone 0xFF");
    assert.equal(DN.decodePayload(payloadWith(hex("81ccd18100a2c0af"))).state, "absent", "overlong '/'");
    assert.equal(DN.announceNameFromAppData(hex("92a6416c696365edc0")), null, "announce: Alice + a stray 0xED");
});

test("decodePayload walks every msgpack type before the fields and inside them", () => {
    const fields = MsgPack.pack(new Map([
        [1, [1.5, -3, 70000, -70000, 2 ** 40, null, true, false, "s".repeat(40), Buffer.alloc(300)]],
        [2, new Map([["k", new Map([[0xD1, new Map([[0, Buffer.from("not this one")]])]])]])],
        [0xD1, new Map([[0, Buffer.from("Alice")]])],
    ]));
    assert.deepEqual(DN.decodePayload(payloadWith(fields)), DN.nameState("Alice"));
    const stamped = Buffer.concat([hex("95cb41d9d7a4b8000000c400c400"), MsgPack.pack(new Map([[0xD1, new Map([[0, Buffer.from("Bob")]])]])), hex("c420"), Buffer.alloc(32)]);
    assert.deepEqual(DN.decodePayload(stamped), DN.nameState("Bob"), "a fifth element (a stamp) is fine");
    assert.deepEqual(DN.decodePayload(payloadWith(hex("82cd00d18100a3426f62ccd18100a3457665"))), DN.nameState("Bob"),
        "any integer width for the key, and the first 0xD1 counts, as in LXMF-rust");
    assert.equal(DN.decodePayload(payloadWith(hex("81ccd18100a5416c"))).state, "absent", "truncated");
    assert.equal(DN.decodePayload(hex("93cb41d9d7a4b8000000c400c400")).state, "absent", "no fields element");
    assert.equal(DN.decodePayload(null).state, "absent");
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
    assert.ok(Buffer.isBuffer(fields.get(0xD1).get(0)));
    assert.equal(MsgPack.pack(fields).toString("hex"), "81ccd18100c405416c696365");
    assert.equal(MsgPack.pack(DN.applyToFields(new Map(), DN.CLEAR)).toString("hex"), "81ccd18100c400");
    assert.equal(DN.applyToFields(new Map(), DN.ABSENT).size, 0);
});

test("announce names: first element of the list, cleaned, Anonymous Peer as none", () => {
    assert.equal(DN.announceNameFromAppData(MsgPack.pack([Buffer.from(" Alice\n"), 8])), "Alice");
    assert.equal(DN.announceNameFromAppData(MsgPack.pack(["Bob", null, []])), "Bob");
    assert.equal(DN.announceNameFromAppData(MsgPack.pack([null, null, [0xD0]])), null);
    assert.equal(DN.announceNameFromAppData(MsgPack.pack([Buffer.from("anonymous peer"), 8])), null);
    assert.equal(DN.announceNameFromAppData(Buffer.from("Carol")), "Carol", "original raw format");
    assert.equal(DN.announceNameFromAppData(null), null);
    assert.equal(DN.announceNameFromAppData(hex("93a3426f62c0")), null, "a list that does not read whole is none, as rmpv");
    assert.equal(DN.announceNameFromAppData(hex("90")), null);
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
        const state = posts.decide("public.x", "me", name, t);
        posts.recordIncluded("public.x", "me", state, t);
        return state.state;
    };
    assert.equal(post("Alice"), "name", "first post");
    t += H;
    assert.equal(post("Alice"), "absent");
    assert.equal(posts.noteSender("public.x", "me", "me", t), false, "own echo is not a new sender");
    assert.equal(posts.noteSender("public.x", "d1st", ["me", "d1st"], t), false, "nor is the distro this device posts as");
    assert.equal(posts.noteSender("public.x", "b0b", ["me", "d1st"], t + 1), true);
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
    assert.equal(new ChannelPostNames(storage).decide("public.x", "me", null, t).state, "absent", "persisted");
    assert.equal(new ChannelPostNames(storage).decide("public.y", "me", null, t).state, "absent", "never named: nothing");
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

test("§5.2 order: a 0xD1 counts only from a message newer than the one that last set or cleared the name", () => {
    const { acceptMessageNameAt: accept, nameState, CLEAR, ABSENT, SIG_VALIDATED: V, SIG_UNKNOWN: U, SIG_INVALID: I } = DN;
    const empty = { messageName: null, messageNameAt: null, legacyName: null };
    assert.deepEqual(accept(empty, nameState("A"), V, 100), { messageName: "A", messageNameAt: 100, legacyName: null });
    const a = { messageName: "A", messageNameAt: 100, legacyName: null };
    assert.equal(accept(a, nameState("Old"), V, 99), null, "an older message (a propagated copy landing late) is ignored");
    assert.equal(accept(a, CLEAR, V, 50), null, "an older clear too");
    assert.equal(accept(a, nameState("B"), V, 100), null, "the same timestamp is not newer");
    assert.deepEqual(accept(a, nameState("A"), V, 150), { messageName: "A", messageNameAt: 150, legacyName: null },
        "a repeat of the current name advances the timestamp");
    assert.equal(accept({ messageName: "A", messageNameAt: 150 }, nameState("Old"), V, 120), null,
        "so an older name after the repeat still loses");
    assert.deepEqual(accept(a, CLEAR, V, 200), { messageName: null, messageNameAt: 200, legacyName: null });
    assert.equal(accept({ messageName: null, messageNameAt: 200 }, nameState("A"), V, 150), null,
        "a clear is not undone by an older name");
    assert.equal(accept(a, ABSENT, V, 300), null, "absent records nothing");
    assert.equal(accept(a, nameState("B"), I, 300), null, "invalid is ignored, the timestamp included");
    assert.equal(accept(a, nameState("B"), U, 300), null, "unknown never replaces a name");
    assert.equal(accept(a, CLEAR, U, 300), null, "unknown never clears");
    assert.deepEqual(accept(empty, nameState("B"), U, 300), { messageName: "B", messageNameAt: null, legacyName: null },
        "unknown fills an empty name without recording its (unverifiable) time");
    const forged = accept(empty, nameState("Mallory"), U, 4e9);
    assert.deepEqual(accept(forged, nameState("Real"), V, 1790000000), { messageName: "Real", messageNameAt: 1790000000, legacyName: null },
        "a far-future source-unknown name never locks out the real sender's validated name");
    const cleared = { messageName: null, messageNameAt: 200, legacyName: null };
    assert.deepEqual(accept(cleared, nameState("B"), U, 300), { messageName: "B", messageNameAt: 200, legacyName: null },
        "a fill after a validated clear keeps the clear's time");
    assert.equal(accept(empty, nameState("B"), V, undefined), null, "no timestamp: cannot be ordered");
    assert.equal(accept(empty, nameState("B"), V, NaN), null);
    assert.deepEqual(accept(empty, nameState("B"), V, 1700000000.25).messageNameAt, 1700000000.25, "float seconds kept");
});

test("§5.1 an accepted 0xD1 drops legacyName; one that is ignored keeps it", () => {
    const { acceptMessageNameAt: accept, nameState, CLEAR } = DN;
    const legacy = { messageName: null, messageNameAt: null, legacyName: "Old Bob" };
    assert.deepEqual(accept(legacy, nameState("Bob"), DN.SIG_VALIDATED, 10), { messageName: "Bob", messageNameAt: 10, legacyName: null });
    assert.deepEqual(accept(legacy, CLEAR, DN.SIG_VALIDATED, 10), { messageName: null, messageNameAt: 10, legacyName: null },
        "a validated clear is accepted and drops it too");
    assert.deepEqual(accept(legacy, nameState("Bob"), DN.SIG_UNKNOWN, 10).legacyName, null, "unknown filling the empty messageName");
    assert.equal(accept(legacy, nameState("Bob"), DN.SIG_INVALID, 10), null, "an invalid one changes nothing");
    assert.equal(accept(legacy, CLEAR, DN.SIG_UNKNOWN, 10), null);
});

test("§5.1 channel names are per (channel, sender) and clearable", () => {
    const storage = memoryStorage();
    const names = new ChannelSenderNames(storage);
    assert.equal(names.apply("c1", "s", DN.nameState("Pseud"), 1000), true);
    assert.equal(new ChannelSenderNames(storage).get("c1", "s"), "Pseud");
    assert.equal(names.get("c2", "s"), null, "another channel does not share it");
    assert.equal(names.apply("c1", "s", DN.ABSENT, 2000), false);
    assert.equal(names.apply("c1", "s", DN.CLEAR, 3000), true);
    assert.equal(names.get("c1", "s"), null);
});

test("§5.2 channel order: an older post pulled late never undoes a newer name or clear", () => {
    const storage = memoryStorage();
    const names = new ChannelSenderNames(storage);
    names.apply("c", "s", DN.nameState("New"), 5000);
    assert.equal(names.apply("c", "s", DN.nameState("Old"), 4000), false, "history pulled after the newer post");
    assert.equal(names.get("c", "s"), "New");
    assert.equal(names.apply("c", "s", DN.CLEAR, 4500), false, "an older clear");
    assert.equal(names.get("c", "s"), "New");
    assert.equal(names.apply("c", "s", DN.nameState("New"), 6000), false, "a newer repeat changes no name…");
    assert.equal(names.entry("c", "s").at, 6000, "…but advances the timestamp");
    assert.equal(names.apply("c", "s", DN.nameState("Mid"), 5500), false, "so a post between the two loses");
    assert.equal(names.get("c", "s"), "New");
    assert.equal(names.apply("c", "s", DN.CLEAR, 7000), true);
    assert.equal(names.apply("c", "s", DN.nameState("New"), 6500), false, "a clear is not undone by an older name");
    assert.equal(names.get("c", "s"), null);
    assert.equal(new ChannelSenderNames(storage).entry("c", "s").at, 7000, "the timestamp is persisted");
    assert.equal(names.apply("c", "s", DN.nameState("X"), undefined), false, "a post with no time cannot be ordered");

    // A post at the very time of the one that set or cleared the name is not
    // newer: ignored, as Android acceptChannelName (postAt <= currentAt is
    // Unchanged) and iOS DisplayNames.isNewer (messageTime > heldAt).
    assert.equal(names.apply("c", "s", DN.nameState("Same"), 7000), false, "a name at the clear's own time");
    assert.equal(names.get("c", "s"), null);
    names.apply("c", "s", DN.nameState("Set"), 8000);
    assert.equal(names.apply("c", "s", DN.CLEAR, 8000), false, "a clear at the name's own time");
    assert.equal(names.apply("c", "s", DN.nameState("Other"), 8000), false, "another name at the same time");
    assert.equal(names.get("c", "s"), "Set");
    assert.deepEqual(names.entry("c", "s"), { name: "Set", at: 8000 });
    assert.equal(DN.acceptChannelName({ name: "Set", at: 8000 }, DN.nameState("Other"), 8000), null);
    assert.deepEqual(DN.acceptChannelName({ name: "Set", at: 8000 }, DN.nameState("Other"), 8001), { name: "Other", at: 8001 },
        "one millisecond later is newer");

    // Stored by the build before the order rule: a bare name of unknown age.
    const old = memoryStorage();
    old.set("channel_sender_names_v1", { c: { s: "Stored" } });
    const loaded = new ChannelSenderNames(old);
    assert.equal(loaded.get("c", "s"), "Stored");
    assert.equal(loaded.apply("c", "s", DN.nameState("Next"), 1), true, "any post is newer than an unknown time");
    assert.equal(loaded.apply("c", "s", DN.nameState("Stored"), 0), false);
});

test("§5.3 resolver: local > message > announce > legacy > 8-hex short hash; channel label with secondary hash", () => {
    const h = "0123456789abcdef0123456789abcdef";
    assert.equal(DN.shortHash(h), "01234567…");
    assert.equal(DN.contactName(null, h), "01234567…");
    assert.equal(DN.contactName({ destHash: h, legacyName: "Legacy" }, h), "Legacy");
    assert.equal(DN.contactName({ destHash: h, legacyName: "Legacy", announceName: "Ann" }, h), "Ann",
        "a current announce name outranks a migrated one");
    assert.deepEqual(DN.channelPosterName(null, { legacyName: "Legacy" }, h), { label: "Legacy", secondary: null, secondaryKind: null });
    assert.equal(DN.contactName({ destHash: h, announceName: "Ann" }, h), "Ann");
    assert.equal(DN.contactName({ destHash: h, announceName: "Ann", messageName: "Msg" }, h), "Msg");
    assert.equal(DN.contactName({ destHash: h, announceName: "Ann", messageName: "Msg", localName: "Mine" }, h), "Mine");
    assert.deepEqual(DN.channelPosterName(null, { localName: "Mine" }, h), { label: "Mine", secondary: null, secondaryKind: null });
    assert.deepEqual(DN.channelPosterName(null, null, h), { label: "01234567…", secondary: null, secondaryKind: null });
});

test("§5.3 channel label: a local name leads and the channel name goes grey; a channel name alone keeps the short hash", () => {
    const h = "0123456789abcdef0123456789abcdef";
    // A channelName and a localName: the user's own name for the poster is
    // the main label, the channel name the secondary text.
    assert.deepEqual(DN.channelPosterName("Pseud", { localName: "Mine" }, h),
        { label: "Mine", secondary: "Pseud", secondaryKind: "channel" });
    assert.deepEqual(DN.channelPosterName("Pseud", { localName: "Mine", messageName: "Msg", announceName: "Ann" }, h),
        { label: "Mine", secondary: "Pseud", secondaryKind: "channel" });
    // A channelName, no localName: the channel name with the short hash,
    // whatever other names the contact holds.
    for (const contact of [null, {}, { localName: null, messageName: "Msg", announceName: "Ann", legacyName: "Leg" }]) {
        assert.deepEqual(DN.channelPosterName("Pseud", contact, h),
            { label: "Pseud", secondary: "01234567…", secondaryKind: "hash" });
    }
    // No channelName: the contact chain, no secondary.
    assert.deepEqual(DN.channelPosterName(null, { messageName: "Msg", announceName: "Ann" }, h),
        { label: "Msg", secondary: null, secondaryKind: null });
    assert.deepEqual(DN.channelPosterName("", { localName: "Mine" }, h),
        { label: "Mine", secondary: null, secondaryKind: null }, "an empty channel name is no channel name");
});

test("§5.4 contact migration: nameCustomized → local, otherwise legacy, placeholders dropped", () => {
    const h = "0123456789abcdef0123456789abcdef";
    const base = { destHash: h, publicKey: null, lastSeen: 1 };
    const slots = (localName, legacyName) => ({ ...base, localName, messageName: null, messageNameAt: null, announceName: null, legacyName });
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bob", nameCustomized: true }), slots("Bob", null));
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bob", nameCustomized: false }), slots(null, "Bob"),
        "legacyName, not messageName: it may have come from an announce");
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "?01234567", nameCustomized: false }), slots(null, null));
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "?01234567", nameCustomized: true }), slots(null, null),
        "a rename saved with the pre-filled placeholder");
    for (const placeholder of ["Retichat", "retichat web", "ANONYMOUS PEER", "0123456789abcdef", "01234567…", "?0123456789ABCDEF0123456789abcdef"]) {
        assert.deepEqual(DN.migrateContact({ ...base, displayName: placeholder, nameCustomized: false }), slots(null, null), placeholder);
    }
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bea", nameCustomized: true }), slots("Bea", null),
        "a short all-hex name is not a hash form");
    // "Never lose a name the user typed": only the old field's pre-fill (this
    // contact's own hash) is dropped from a customized name, never another
    // hash-looking name the user typed.
    for (const typed of ["deadbeef", "CafeBabe12", "?deadbeef", "fedcba9876543210"]) {
        assert.deepEqual(DN.migrateContact({ ...base, displayName: typed, nameCustomized: true }), slots(typed, null), typed);
    }
    for (const prefill of ["01234567", "?0123456789ABCDEF", "01234567\u2026"]) {
        assert.deepEqual(DN.migrateContact({ ...base, displayName: prefill, nameCustomized: true }), slots(null, null),
            `${prefill}: this contact's own hash, as the old rename field pre-filled it`);
    }
    const migrated = slots("L", "Leg");
    assert.deepEqual(DN.migrateContact(migrated), migrated, "idempotent");

    // Rows from the first three-slot build put migrated names in messageName.
    assert.deepEqual(DN.migrateContact({ ...base, localName: null, messageName: "M", announceName: "A" }),
        { ...base, localName: null, messageName: null, messageNameAt: null, announceName: "A", legacyName: "M" });
    assert.deepEqual(DN.migrateContact({ ...base, localName: "L", messageName: "Retichat", announceName: null }),
        { ...base, localName: "L", messageName: null, messageNameAt: null, announceName: null, legacyName: null },
        "a placeholder there is dropped");
});

test("§5.4 one placeholder list: hash forms, \"Retichat\", \"Retichat Web\", \"Anonymous Peer\", any case", () => {
    for (const p of ["0123abcd", "0123ABCD…", "?0123abcd", "?0123abcd…", "0123456789abcdef0123456789abcdef",
        "?0123456789abcdef0123456789abcdef…", "Retichat", "RETICHAT", "Retichat Web", "retichat WEB",
        "Anonymous Peer", "anonymous peer", "  Retichat  "]) {
        assert.equal(DN.isPlaceholderName(p), true, p);
    }
    for (const n of ["0123abc", "0123456789abcdef0123456789abcdef0", "Bob", "Retichat User", "Anonymous", "cafe", "?Bob",
        "0123abcd...x", null, undefined]) {
        assert.equal(DN.isPlaceholderName(n), false, String(n));
    }
});

/** A hash form (8 to 32 hex, "?" before or "…" after) of `own`: what §5.4
 *  drops where a name may have been typed. Written here from the spec, not
 *  taken from display_name.js. */
function ownHashForm(name, own) {
    const m = /^\??([0-9a-f]{8,32})…?$/i.exec(name.trim());
    return !!m && own.toLowerCase().startsWith(m[1].toLowerCase());
}

test("§5.4 placeholders: every shared vector (LXMF-rust display_name_vectors.json \"placeholder\")", () => {
    assert.ok(vectors.placeholder.length >= 30);
    assert.ok(vectors.placeholder.some((v) => v.web_node_default), "the old web node defaults are in the vectors");
    for (const v of vectors.placeholder) {
        assert.equal(DN.isPlaceholderName(v.input), v.placeholder, `placeholder: ${v.name}`);
        assert.equal(DN.isWebNodeDefault(v.input), v.web_node_default, `web_node_default: ${v.name}`);
    }
});

test("§5.4 contact migration over the shared vectors: an old web node default is dropped, typed or not", () => {
    for (const v of vectors.placeholder) {
        const base = { destHash: v.own_hash, publicKey: null, lastSeen: 1 };
        const cleaned = DN.clean(v.input);
        const asReceived = DN.migrateContact({ ...base, displayName: v.input, nameCustomized: false });
        assert.equal(asReceived.legacyName, v.placeholder ? null : cleaned, `not customized: ${v.name}`);
        assert.equal(asReceived.localName, null);
        // Customized: only what the old rename field could save untouched is
        // dropped — this contact's own hash form, or an old web node default.
        const asTyped = DN.migrateContact({ ...base, displayName: v.input, nameCustomized: true });
        const dropped = v.web_node_default || ownHashForm(v.input, v.own_hash);
        assert.equal(asTyped.localName, dropped ? null : cleaned, `customized: ${v.name}`);
        assert.equal(asTyped.legacyName, null);
    }
});

test("§5.4 the old web node defaults as the web held them: config.json's, announced with the hash, customized", () => {
    const h = "0123456789abcdef0123456789abcdef";
    const base = { destHash: h, publicKey: null, lastSeen: 1 };
    const slots = (localName, legacyName) => ({ ...base, localName, messageName: null, messageNameAt: null, announceName: null, legacyName });
    for (const old of ["Retichat Web (retichat)", "Retichat Web (selectiv)", "Retichat Web (retichat) (0123456789ab)",
        "Retichat Web (selectiv) (fedcba987654)", "Retichat Web (0123456789ab)"]) {
        assert.deepEqual(DN.migrateContact({ ...base, displayName: old, nameCustomized: false }), slots(null, null),
            `${old}: received from a web user, not a legacyName`);
        assert.deepEqual(DN.migrateContact({ ...base, displayName: old, nameCustomized: true }), slots(null, null),
            `${old}: Save on the old rename field, which was pre-filled with it`);
    }
    // Everything else a user may have typed is still theirs.
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bob (work)", nameCustomized: true }), slots("Bob (work)", null));
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Retichat Web ()", nameCustomized: false }), slots(null, "Retichat Web ()"));
    // Rows from the first three-slot build hold it in messageName.
    assert.deepEqual(DN.migrateContact({ ...base, localName: null, messageName: "Retichat Web (selectiv)", announceName: null }),
        { ...base, localName: null, messageName: null, messageNameAt: null, announceName: null, legacyName: null });
});

test("§5.4 the old web announce suffix: every shared vector (LXMF-rust display_name_vectors.json \"own_hash_suffix\")", () => {
    assert.ok(vectors.own_hash_suffix.length >= 15);
    assert.ok(vectors.own_hash_suffix.some((v) => v.expected !== v.input), "some are stripped");
    assert.ok(vectors.own_hash_suffix.some((v) => v.expected === v.input), "and some are not");
    for (const v of vectors.own_hash_suffix) {
        assert.equal(DN.stripOwnHashSuffix(v.input, v.own_hash), v.expected, v.name);
    }
    assert.equal(DN.stripOwnHashSuffix(null, "0123456789abcdef0123456789abcdef"), null);
    assert.equal(DN.stripOwnHashSuffix("Alice (0123456789ab)", null), "Alice (0123456789ab)", "no hash, no rule");
});

test("§5.4 white space is §3's, Unicode White_Space: the shared vectors tell it from every platform's own trim", () => {
    // Review of 8319411: the contract said "trim surrounding white space"
    // while its SQLite form trimmed U+0020 alone and the web trimmed with
    // String.prototype.trim, so the clients disagreed on a stored name such
    // as "Alice (0123456789ab)\n". The rule, with the trim as a parameter:
    const trimOf = (set) => (s) => {
        let a = 0, b = s.length;
        while (a < b && set.has(s.charCodeAt(a))) a++;
        while (b > a && set.has(s.charCodeAt(b - 1))) b--;
        return s.slice(a, b);
    };
    const range = (lo, hi) => Array.from({ length: hi - lo + 1 }, (_, i) => lo + i);
    const WS = [...range(0x09, 0x0D), 0x20, 0x85, 0xA0, 0x1680, ...range(0x2000, 0x200A), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000];
    const rule = (trim) => ({
        strip: (name, own) => {
            const m = /^(.+) \(([0-9a-f]{12})\)$/is.exec(trim(name));
            return m && m[2].toLowerCase() === own.slice(0, 12).toLowerCase() ? trim(m[1]) : name;
        },
        nodeDefault: (name) => /^retichat web \(.+\)$/is.test(trim(name)),
    });
    const misses = ({ strip, nodeDefault }) => [
        ...vectors.own_hash_suffix.filter((v) => strip(v.input, v.own_hash) !== v.expected),
        ...vectors.placeholder.filter((v) => nodeDefault(v.input) !== v.web_node_default),
    ].map((v) => v.name);

    assert.deepEqual(misses(rule(trimOf(new Set(WS)))), [], "the contract's set meets every vector");
    const platforms = {
        "String.prototype.trim (adds U+FEFF, keeps U+0085)": (s) => s.trim(),
        "Swift .whitespacesAndNewlines (adds U+200B)": trimOf(new Set([...WS, 0x200B])),
        "Kotlin trim() (adds U+001C-U+001F, keeps U+0085)": trimOf(new Set([...WS.filter((c) => c !== 0x85), ...range(0x1C, 0x1F)])),
        "SQLite trim(x) (U+0020 alone)": trimOf(new Set([0x20])),
    };
    for (const [platform, trim] of Object.entries(platforms)) {
        assert.ok(misses(rule(trim)).length > 0, `a vector tells it from ${platform}`);
    }
    // And the web's §5.4 rules use the contract's set, not the platform's.
    assert.equal(DN.stripOwnHashSuffix("Alice (0123456789ab)\u0085", "0123456789abcdef0123456789abcdef"), "Alice");
    assert.equal(DN.stripOwnHashSuffix("﻿Alice (0123456789ab)", "0123456789abcdef0123456789abcdef"), "﻿Alice");
    assert.equal(DN.isWebNodeDefault("\u0085Retichat Web (selectiv)"), true);
    assert.equal(DN.isPlaceholderName("Retichat\u0085"), true);
    assert.equal(DN.isPlaceholderName("﻿Retichat"), false, "U+FEFF is §3's to remove, not white space to trim");
});

test("§5.4 contact migration strips the old web announce suffix, only for the contact's own hash", () => {
    // Until 2026-09-23 the web announced "<name> (<first 12 hex of its
    // lxmf.delivery hash>)", and the old web stored it as the name; its
    // rename field was pre-filled with it, so Save untouched customized it.
    const h = "0123456789abcdef0123456789abcdef";
    const base = { destHash: h, publicKey: null, lastSeen: 1 };
    const slots = (localName, legacyName) => ({ ...base, localName, messageName: null, messageNameAt: null, announceName: null, legacyName });
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Alice (0123456789ab)", nameCustomized: false }), slots(null, "Alice"));
    // Save on the old rename field, pre-filled with the announced name: no
    // name the user typed (James, 2026-10-01), so a legacyName, which her
    // first 0xD1 or named announce replaces, not a localName that would
    // outrank them for good.
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Alice (0123456789ab)", nameCustomized: true }), slots(null, "Alice"),
        "customized with the suffix: legacyName");
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Bob (work) (0123456789ab)", nameCustomized: true }), slots(null, "Bob (work)"));
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Alice (0123456789AB)", nameCustomized: true }), slots(null, "Alice"), "hex in any case");
    // Only the contact's own hash: parentheses a user typed stay.
    for (const kept of ["Alice (fedcba987654)", "Bob (work)", "Alice (0123456789abcdef)"]) {
        assert.deepEqual(DN.migrateContact({ ...base, displayName: kept, nameCustomized: true }), slots(kept, null), kept);
        assert.deepEqual(DN.migrateContact({ ...base, displayName: kept, nameCustomized: false }), slots(null, kept), kept);
    }
    // What is left came from an announce: a placeholder goes, even
    // customized, and an old web node default with or without it goes too.
    for (const announced of ["Retichat (0123456789ab)", "Retichat Web (0123456789ab)", "Retichat Web (retichat) (0123456789ab)", "01234567 (0123456789ab)"]) {
        assert.deepEqual(DN.migrateContact({ ...base, displayName: announced, nameCustomized: true }), slots(null, null), `${announced}, customized`);
        assert.deepEqual(DN.migrateContact({ ...base, displayName: announced, nameCustomized: false }), slots(null, null), announced);
    }
    // A typed "Retichat" with no suffix is still the user's (unchanged rule).
    assert.deepEqual(DN.migrateContact({ ...base, displayName: "Retichat", nameCustomized: true }), slots("Retichat", null));

    // The first three-slot build: its messageName moves to legacyName, and
    // all its slots lose the suffix. Its localName with the suffix was the
    // customized pre-fill: what is left goes to legacyName, unless that
    // holds a name already or a named announce has been heard since (§5.1
    // would have dropped it).
    assert.deepEqual(DN.migrateContact({ ...base, localName: "Lou (0123456789ab)", messageName: "Max (0123456789ab)", announceName: "Ann (0123456789ab)" }),
        { ...base, localName: null, messageName: null, messageNameAt: null, announceName: "Ann", legacyName: "Max" });
    assert.deepEqual(DN.migrateContact({ ...base, localName: "Lou (0123456789ab)", messageName: null, announceName: null }),
        { ...base, localName: null, messageName: null, messageNameAt: null, announceName: null, legacyName: "Lou" });
    assert.deepEqual(DN.migrateContact({ ...base, localName: "Lou (0123456789ab)", messageName: null, announceName: "Ann" }),
        { ...base, localName: null, messageName: null, messageNameAt: null, announceName: "Ann", legacyName: null });
    assert.deepEqual(DN.migrateContact({ ...base, localName: "Lou", messageName: null, announceName: "Ann" }),
        { ...base, localName: "Lou", messageName: null, messageNameAt: null, announceName: "Ann", legacyName: null }, "no suffix: the user's");

    // Current shape: untouched, but by the one-off pass.
    const current = { ...base, localName: "Lou (0123456789ab)", messageName: "Msg (0123456789ab)", messageNameAt: 5,
        announceName: "Retichat Web (0123456789ab)", legacyName: "Leg (0123456789ab)" };
    assert.deepEqual(DN.migrateContact(current), current, "not without the pass");
    const passed = DN.migrateContact(current, { ownHashSuffixPass: true });
    assert.deepEqual(passed, { ...current, localName: null, announceName: null, legacyName: "Leg" },
        "the pass: localName, announceName and legacyName; messageName comes from 0xD1, which never carried it; the suffixed localName is no name typed");
    assert.deepEqual(DN.migrateContact(passed), passed);
    const typed = { ...base, localName: "Bob (work)", messageName: null, messageNameAt: null, announceName: null, legacyName: null };
    assert.deepEqual(DN.migrateContact(typed, { ownHashSuffixPass: true }), typed);
    // The pass on a suffixed localName: legacyName when nothing has been
    // heard since; dropped when a 0xD1 was accepted (a name, or a clear:
    // messageNameAt) or a named announce heard; a placeholder goes.
    const quiet = { ...base, localName: "Lou (0123456789ab)", messageName: null, messageNameAt: null, announceName: null, legacyName: null };
    assert.deepEqual(DN.migrateContact(quiet, { ownHashSuffixPass: true }), { ...quiet, localName: null, legacyName: "Lou" });
    for (const since of [{ messageName: "Lu", messageNameAt: 9 }, { messageNameAt: 9 }, { announceName: "Ann" }, { announceName: "Retichat Web (0123456789ab)" }]) {
        const got = DN.migrateContact({ ...quiet, ...since }, { ownHashSuffixPass: true });
        assert.deepEqual([got.localName, got.legacyName], [null, null], JSON.stringify(since));
    }
    assert.deepEqual(DN.migrateContact({ ...quiet, legacyName: "Old" }, { ownHashSuffixPass: true }), { ...quiet, localName: null, legacyName: "Old" },
        "a legacyName held is kept");
    assert.deepEqual(DN.migrateContact({ ...quiet, localName: "Retichat (0123456789ab)" }, { ownHashSuffixPass: true }), { ...quiet, localName: null, legacyName: null });
});

test("§5.4 own name: an old web node default is no Message Display Name, whichever node's it was", () => {
    assert.equal(DN.migrateOwnDisplayName("Retichat Web (selectiv)", "Retichat Web (retichat)"), null,
        "a name saved on another node, or before this node's default changed");
    assert.equal(DN.migrateOwnDisplayName("Retichat Web (retichat)", null), null, "before config.json is read");
    assert.equal(DN.migrateOwnDisplayName("retichat web (E2E)", null), null);
    assert.equal(DN.migrateOwnDisplayName("Retichat Web Fan", "Retichat Web (retichat)"), "Retichat Web Fan");
});

test("§5.4 own name: the old display name becomes the Message Display Name, placeholders empty", () => {
    assert.equal(DN.migrateOwnDisplayName("James", "Retichat Web (E2E)"), "James");
    assert.equal(DN.migrateOwnDisplayName("Retichat Web", null), null);
    assert.equal(DN.migrateOwnDisplayName("Retichat Web (E2E)", "Retichat Web (E2E)"), null, "config.json default");
    assert.equal(DN.migrateOwnDisplayName("  ", null), null);
    assert.equal(DN.migrateOwnDisplayName(null, null), null);
});

test("the name modules load in the browser's order: nothing hashes before app.js sets the global Buffer", async () => {
    // In the browser "crypto" is lib/shims/crypto.js, which hashes into the
    // global Buffer — and app.js installs that global only after every module
    // it imports has been evaluated. A module-level digest (EMPTY_DIGEST was
    // one) threw "Buffer is not defined" and left the page blank.
    const { spawnSync } = await import("node:child_process");
    const shim = new URL("./lib/shims/crypto.js", import.meta.url).href;
    const hook = `export async function resolve(s, c, n) { return s === "crypto" ? { url: ${JSON.stringify(shim)}, shortCircuit: true } : n(s, c); }`;
    const modules = ["./lib/display_name.js", "./lib/name_ledger.js", "./lib/rns/lxmf/lxmf.js",
        "./lib/rns/lxmf/lxmf_message.js", "./lib/rns/lxmf/lxmf_router.js", "./lib/rns/rfed_channel.js"]
        .map((m) => new URL(m, import.meta.url).href);
    const script = `
        import { register } from "node:module";
        register("data:text/javascript," + encodeURIComponent(${JSON.stringify(hook)}));
        delete globalThis.Buffer;
        for (const m of ${JSON.stringify(modules)}) await import(m);
        console.log("loaded");`;
    const run = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /loaded/);
});
