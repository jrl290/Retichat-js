/**
 * MEMBER STATUSES AND KEYS — the web client's half (RFed-spec Group.md,
 * "Member statuses and keys (2026-10-06)", decided and approved by James the
 * same day; LXMF-rust DISPLAY_NAMES.md §10 key 10). The web is the reference
 * the phones port next, so each rule below is pinned where it is made.
 *
 * Two problems are closed. A member who accepts late never learned of the
 * accepts the privacy filter dropped before; and an accept or leave from a
 * sender whose key the receiver never got could not be verified, yet a leave
 * counts as final. So:
 *
 *   1. Every accept and leave (a decline is a leave) carries its sender's own
 *      key, `hash:base64-public-key`, in the form an invite chunk uses: the
 *      old field 0xA8 until the switch, key 9 of the Retichat field after.
 *   2. A receiver binds that key (it derives the lxmf.delivery destination
 *      that is the entry's hash and the message's source), remembers it, and
 *      checks the signature under it: verified counts, forged is ignored,
 *      unverifiable counts until the switch (GROUP_ENTRIES_IN_RETICHAT_FIELD,
 *      around 2026-10-26, exactly as the phones count it) and from then on is
 *      held until its sender's key arrives.
 *   3. The creator keeps, per group and member, the packed message of the
 *      newest accept or leave that counted, and answers each accept that
 *      carries its sender's key with one `status`: the other members' copies.
 *   4. A `status` counts only from the creator, only in a group the user
 *      accepted; each element is checked on its own, as if it had arrived
 *      directly, and a failing one is skipped.
 *
 * These run the real shipped code, as privacy_filter.test.mjs does: the real
 * LXMRouter given the real PrivacyFilter, ContactStore, GroupStore, the
 * handler and the send path extracted from app.js (test_group_net.mjs), with
 * real identities, real signatures and real LXMF packing. No clock decides a
 * result (DESIGN_PRINCIPLES.md §1, §3): nothing here retries or waits.
 *
 * Run: node --test group_statuses.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Link from "./lib/rns/link.js";
import * as RF from "./lib/retichat_field.js";
import { senderKeyEntry, packedMessage, STATUS_PACKED_LIMIT } from "./lib/group_status.js";
import { app, methodBody, objectLiteral } from "./test_app_source.mjs";
import { groupClient, network, settle, lxm, lxmfHash, hex, oldFields, newFields, groupRule, LXMessage, Identity } from "./test_group_net.mjs";

const G = "9a".repeat(16);
const keyOf = (identity) => senderKeyEntry(lxmfHash(identity), identity.getPublicKey().toString("hex"));

/**
 * An accept, leave or decline from `from` to `to` for group `groupId`, as a
 * member's client sends it: GROUP_SENDER the member, no content, its own key
 * entry unless `key` is false (a client from before 2026-10-06 sends none),
 * in the old fields (`form` "old", until the switch) or the Retichat field
 * ("new"). `signer` and `carry` are for the forger: who signs it, and whose
 * key it carries.
 */
function control(from, to, action, { key = true, signer = from, carry = from, form = "old", timestamp = null, sender = null, groupId = G } = {}) {
    const entries = { id: groupId, action, sender: sender ?? lxmfHash(from), keys: key ? keyOf(carry) : null };
    return lxm(from, to, "", (form === "old" ? oldFields : newFields)(entries), { signer, timestamp });
}

/** A group G held by client `r`, created by `creator` (an identity) and listing `members` (identities) and `r`: pending, the creator accepted, `r` holding the creator's key and nobody else's. */
function holds(r, creator, members, { groupId = G, active = false, keys = [] } = {}) {
    const C = lxmfHash(creator);
    r.know(creator);
    r.GroupStore.addPending(groupId, "G", C, [C, ...members.map(lxmfHash), r.own]);
    for (const id of keys) r.know(id);
    if (active) {
        for (const id of members) r.know(id);
        r.page._acceptGroupInvite(groupId);
        assert.equal(r.GroupStore.get(groupId).groupStatus, "active");
    }
    return r.GroupStore.get(groupId);
}

const decodeFields = (m) => LXMessage.extractGroupFields(m.fields);

// ═══ 1. the sender's key, on every accept and leave ═══════════════════════

/** A creator C, members as clients, the invites delivered: every member is a pending group. */
async function started({ members = 3, switched = false, filter = false, deliverInvitesTo = null } = {}) {
    const c = groupClient({ switched, filter });
    const ms = Array.from({ length: members }, () => groupClient({ switched, filter }));
    const all = [c, ...ms];
    for (const x of all) for (const y of all) if (x !== y) x.reachable(y.own);
    for (const m of ms) c.know(m);                                 // the creator's contacts
    const net = network(...all);
    const group = c.GroupStore.create("G", ms.map((m) => m.own));
    const sending = c.self.sendGroupInvites(group.groupId, "G", ms.map((m) => m.own));
    await net.pump(c, deliverInvitesTo ? { to: deliverInvitesTo } : {});
    if (!deliverInvitesTo) await sending;                          // every invite was proved on delivery
    return { c, ms, all, net, id: group.groupId };
}

test("every accept carries exactly the sender's own key, hash:base64 as an invite chunk's: in the old field 0xA8 until the switch, key 9 of the Retichat field after", async () => {
    for (const switched of [false, true]) {
        const when = switched ? "after the switch" : "before the switch";
        const { c, ms: [a, b], id } = await started({ members: 2, switched });
        a.page._acceptGroupInvite(id);
        await settle();
        const sent = a.decoded();
        assert.deepEqual(sent.map((s) => s.to).sort(), [c.own, b.own].sort(), `${when}: an accept to every member`);
        const entry = senderKeyEntry(a.own, a.pubKey);
        for (const { message: m } of sent) {
            const g = decodeFields(m);
            assert.equal(g.groupAction, "accept", when);
            assert.equal(g.groupSender, a.own, when);
            assert.deepEqual([...g.memberKeys], [[a.own, Buffer.from(a.pubKey, "hex").toString("base64")]], `${when}: one entry, the sender's own`);
            assert.equal(m.signatureValidated, true, `${when}: signed by the sender`);
            if (switched) {
                assert.equal(m.fields.get(0xD1).get(RF.RF_GROUP_MEMBER_KEYS), entry, `${when}: key 9 of the Retichat field`);
                assert.equal(m.fields.has(0xA8), false, `${when}: and no old field`);
            } else {
                assert.equal(m.fields.get(0xA8), entry, `${when}: the old field 0xA8, as every group entry`);
                assert.equal(m.fields.get(0xD1)?.has?.(RF.RF_GROUP_MEMBER_KEYS) ?? false, false, `${when}: not in the Retichat field`);
            }
            assert.equal(entry.split(":").length, 2, `${when}: exactly one hash:key pair, no list`);
        }
        // The same entry the member's invite chunk carries for it (the creator's _groupMemberKeys).
        assert.equal(c.self._groupMemberKeys([a.own])[0], entry, `${when}: the invite chunk's form`);
    }
});

test("a leave and a decline (the very message) carry the sender's own key too; the decline of a pending group and the leave of a joined one are the same message", async () => {
    for (const switched of [false, true]) {
        const when = switched ? "after the switch" : "before the switch";
        const { c, ms: [a, b], id } = await started({ members: 2, switched });
        b.page._acceptGroupInvite(id);                                 // b joins, then leaves
        await settle();
        const joined = b.sent.length;
        b.page._leaveGroup(id);                                        // the leave of a joined group
        a.page._declineGroupInvite(id);                                // the decline of a pending one
        await settle();
        const left = b.decoded(joined), declined = a.decoded();
        assert.deepEqual(left.map((s) => s.to).sort(), [a.own, c.own].sort(), when);
        assert.deepEqual(declined.map((s) => s.to).sort(), [b.own, c.own].sort(), when);
        const shape = (m, who) => {
            const g = decodeFields(m);
            return { action: g.groupAction, sender: g.groupSender, keys: [...g.memberKeys.keys()], signed: m.signatureValidated, title: m.title, content: m.content,
                key: switched ? m.fields.get(0xD1).get(9) : m.fields.get(0xA8), mine: senderKeyEntry(who.own, who.pubKey), forms: [...m.fields.keys()].sort() };
        };
        for (const { message: m } of left) {
            const s = shape(m, b);
            assert.deepEqual([s.action, s.sender, s.keys, s.signed, s.title, s.content, s.key === s.mine], ["leave", b.own, [b.own], true, "", "", true], `${when}: b's leave`);
        }
        for (const { message: m } of declined) {
            const s = shape(m, a);
            assert.deepEqual([s.action, s.sender, s.keys, s.signed, s.title, s.content, s.key === s.mine], ["leave", a.own, [a.own], true, "", "", true], `${when}: a's decline is a leave`);
        }
        assert.deepEqual(shape(left[0].message, b).forms.length, shape(declined[0].message, a).forms.length, `${when}: the same fields`);
    }
});

test("the key is read from the identity, not from the router: a leave carries it with no connection (the group is closed at once, the leave goes on after it)", async () => {
    const { c, ms: [a], id } = await started({ members: 1 });
    const body = methodBody("_ownGroupMemberKey()");
    assert.doesNotMatch(body, /_lxmfRouter|this\.ownHash/, "no router needed");
    assert.match(body, /ownLxmfDestinationHash\(\)/);
    const fresh = a.reload();
    assert.equal(fresh.self._ownGroupMemberKey(), senderKeyEntry(a.own, a.pubKey), "a reload holds the same");
    assert.equal(c.self._ownGroupMemberKey(), senderKeyEntry(c.own, c.pubKey));
    assert.ok(id);
});

// ═══ 2. receiving: bind, remember, verify ═════════════════════════════════

test("a keyed accept from a source nobody holds a key for is verified by the key it carries, remembered, and counts: before and after the switch, in either form", async () => {
    for (const switched of [false, true]) for (const form of ["old", "new"]) {
        const label = `${switched ? "after" : "before"} the switch, ${form} form`;
        const r = groupClient({ switched });
        const [creator, a, b] = [1, 2, 3].map(() => Identity.create());
        const [C, A, B] = [creator, a, b].map(lxmfHash);
        holds(r, creator, [a, b]);
        assert.equal(r.ContactStore.get(A), null, `${label}: nobody knows A`);

        await r.receive(control(a, r.me, "accept", { form }));
        assert.equal(r.proofs.length, 1, `${label}: proved`);
        assert.equal(r.emitted[0].signatureState, "validated", `${label}: validated under the carried key`);
        assert.equal(r.status(G, A), "accepted", label);
        assert.deepEqual(r.held(), [], `${label}: nothing held`);
        assert.deepEqual(r.notices(G), [["joined the group", A]], label);
        const row = r.ContactStore.get(A);
        assert.deepEqual([row.publicKey, row.hidden, r.ContactStore.isContact(A), r.ContactStore.allowlisted(A)], [a.getPublicKey().toString("hex"), true, false, false],
            `${label}: the key is remembered as an invite chunk's is: a hidden row, no contact, allowed nothing in a pending group`);
        assert.deepEqual(r.events.filter((e) => e.kind === "group-change-held"), [], label);

        // The same key now verifies A's next message with no key carried.
        await r.receive(control(a, r.me, "leave", { key: false, form }));
        assert.equal(r.emitted[1].signatureState, "validated", `${label}: the remembered key`);
        assert.equal(r.status(G, A), "left", label);
    }
});

test("a keyed leave from a source nobody holds a key for is verified, remembered and final: a later accept of the same member, keyed or not, is dropped unproved", async () => {
    for (const switched of [false, true]) {
        const r = groupClient({ switched });
        const [creator, a, b] = [1, 2, 3].map(() => Identity.create());
        const A = lxmfHash(a);
        holds(r, creator, [a, b]);
        await r.receive(control(a, r.me, "leave"));
        assert.equal(r.proofs.length, 1);
        assert.equal(r.status(G, A), "left");
        assert.deepEqual(r.notices(G), [["left the group", A]]);
        assert.equal(r.ContactStore.get(A).publicKey, a.getPublicKey().toString("hex"));
        for (const key of [true, false]) {
            await r.receive(control(a, r.me, "accept", { key }));
            assert.equal(r.proofs.length, 1, `keyed=${key}: dropped unproved`);
            assert.equal(r.status(G, A), "left", `keyed=${key}: final`);
        }
    }
});

test("a forged accept or leave that carries its sender's real key is invalid under it: dropped unproved, no change, nothing held, no key remembered; the member's own message still counts after", async () => {
    for (const switched of [false, true]) for (const action of ["accept", "leave"]) {
        const label = `${switched ? "after" : "before"} the switch, ${action}`;
        const r = groupClient({ switched });
        const [creator, a, b, mallory] = [1, 2, 3, 4].map(() => Identity.create());
        const A = lxmfHash(a);
        holds(r, creator, [a, b]);

        await r.receive(control(a, r.me, action, { signer: mallory }));          // a's hash and key, mallory's signature
        assert.equal(r.proofs.length, 0, `${label}: not proved`);
        assert.equal(r.emitted.length, 0, `${label}: not even handed to the handler (the router's second look drops it)`);
        assert.equal(r.status(G, A), "invited", label);
        assert.deepEqual(r.held(), [], `${label}: not held either: the key it carries settles it`);
        assert.equal(r.ContactStore.get(A), null, `${label}: and the key is not remembered`);
        assert.deepEqual(r.notices(G), [], label);

        await r.receive(control(a, r.me, action));                                // the real one
        assert.equal(r.proofs.length, 1, label);
        assert.equal(r.status(G, A), action === "accept" ? "accepted" : "left", `${label}: the member's own counts`);
    }
});

test("a key that does not bind is no key: before the switch the message counts as any unverifiable one; from the switch it is held, and counted once the member's real key arrives and the signature verifies, or dropped when it does not", async () => {
    const [creator, a, b, mallory] = [1, 2, 3, 4].map(() => Identity.create());
    const [C, A, B] = [creator, a, b].map(lxmfHash);
    // mallory's key under a's hash and a's source: it derives mallory's destination, so it binds nothing

    // Before the switch: counts (James, 2026-10-06), though nothing can say whose it is.
    const before = groupClient({ switched: false });
    holds(before, creator, [a, b]);
    await before.receive(lxm(a, before.me, "", oldFields({ id: G, action: "accept", sender: A, keys: `${A}:${mallory.getPublicKey().toString("base64")}` })));
    assert.equal(before.emitted[0].signatureState, "unknown");
    assert.equal(before.status(G, A), "accepted", "counts until the switch");
    assert.deepEqual(before.held(), []);
    assert.equal(before.ContactStore.get(A)?.publicKey ?? null, null, "the key that does not bind is not remembered");
    assert.equal(before.proofs.length, 1);

    // From the switch: held.
    for (const [signer, outcome] of [[a, "counted"], [mallory, "dropped"]]) {
        const after = groupClient({ switched: true });
        holds(after, creator, [a, b]);
        await after.receive(lxm(a, after.me, "", oldFields({ id: G, action: "accept", sender: A, keys: `${A}:${mallory.getPublicKey().toString("base64")}` }), { signer }));
        assert.equal(after.status(G, A), "invited", `${outcome}: held, not counted`);
        assert.deepEqual(after.held(), [[A, "accept"]], outcome);
        assert.equal(after.ContactStore.get(A)?.publicKey ?? null, null, "no key remembered");
        // A's real key arrives with an invite chunk (one per member).
        await after.receive(lxm(creator, after.me, "", oldFields({ id: G, action: "invite", sender: C, members: [C, A, B, after.own].join(","), keys: keyOf(a) })));
        assert.deepEqual(after.held(), [], `${outcome}: decided`);
        assert.equal(after.status(G, A), signer === a ? "accepted" : "invited", outcome);
    }
});

test("a keyless accept or leave (a client from before this change): before the switch it counts, unverified; from the switch it is held until its sender's key arrives, as before", async () => {
    const [creator, a, b] = [1, 2, 3].map(() => Identity.create());
    const [C, A, B] = [creator, a, b].map(lxmfHash);
    const before = groupClient({ switched: false });
    holds(before, creator, [a, b]);
    await before.receive(control(a, before.me, "accept", { key: false }));
    assert.equal(before.emitted[0].signatureState, "unknown");
    assert.equal(before.proofs.length, 1, "proved, as every message kept");
    assert.equal(before.status(G, A), "accepted", "counts until the switch");
    assert.deepEqual([before.held(), before.notices(G).at(-1)], [[], ["joined the group", A]]);
    await before.receive(control(b, before.me, "leave", { key: false }));
    assert.equal(before.status(G, B), "left", "a leave too: final");
    assert.equal(before.ContactStore.get(B)?.publicKey ?? null, null, "no key learned from a message that carried none");

    const after = groupClient({ switched: true });
    holds(after, creator, [a, b]);
    await after.receive(control(a, after.me, "accept", { key: false }));
    await after.receive(control(b, after.me, "leave", { key: false }));
    assert.equal(after.proofs.length, 2, "proved");
    assert.deepEqual([after.status(G, A), after.status(G, B)], ["invited", "invited"], "none counts yet");
    assert.deepEqual(after.held(), [[A, "accept"], [B, "leave"]]);
    await after.receive(lxm(creator, after.me, "", oldFields({ id: G, action: "invite", sender: C, members: [C, A, B, after.own].join(","), keys: keyOf(a) })));
    assert.deepEqual([after.status(G, A), after.status(G, B)], ["accepted", "invited"], "A's key came: A's accept verifies and counts; B's still waits");
    assert.deepEqual(after.held(), [[B, "leave"]]);
});

test("a key already held decides, whether or not the message carries one; a keyed message does not replace the held key", async () => {
    for (const switched of [false, true]) {
        const r = groupClient({ switched });
        const [creator, a, b] = [1, 2, 3].map(() => Identity.create());
        const A = lxmfHash(a);
        holds(r, creator, [a, b], { keys: [a] });
        const stored = r.ContactStore.get(A).publicKey;
        await r.receive(control(a, r.me, "accept"));
        assert.equal(r.emitted[0].signatureState, "validated");
        assert.equal(r.status(G, A), "accepted");
        assert.equal(r.ContactStore.get(A).publicKey, stored);
        await r.receive(control(a, r.me, "leave", { signer: Identity.create() }));
        assert.equal(r.proofs.length, 1, "a forgery under the held key is dropped unproved");
        assert.equal(r.status(G, A), "accepted");
    }
});

test("a keyed message decides a member's older held accept first, so they count in the order they came (from the switch)", async () => {
    const r = groupClient({ switched: true });
    const [creator, a, b] = [1, 2, 3].map(() => Identity.create());
    const A = lxmfHash(a);
    holds(r, creator, [a, b]);
    await r.receive(control(a, r.me, "accept", { key: false }));
    assert.deepEqual(r.held(), [[A, "accept"]]);
    assert.equal(r.status(G, A), "invited");
    await r.receive(control(a, r.me, "leave"));                       // keyed: brings the key
    assert.deepEqual(r.held(), []);
    assert.equal(r.status(G, A), "left");
    assert.deepEqual(r.notices(G), [["joined the group", A], ["left the group", A]], "the accept counted first, then the leave");
});

test("only a listed member's own accept or leave counts, keyed or not: a stranger's, one naming another and one for a group not held are dropped unproved, and no key is remembered from them", async () => {
    for (const switched of [false, true]) {
        const r = groupClient({ switched });
        const [creator, a, b, x] = [1, 2, 3, 4].map(() => Identity.create());
        const [A, B, X] = [a, b, x].map(lxmfHash);
        holds(r, creator, [a, b]);
        await r.receive(control(x, r.me, "accept"));                            // on no list
        await r.receive(control(a, r.me, "accept", { sender: B }));             // a speaking for b
        await r.receive(control(a, r.me, "accept", { groupId: "ee".repeat(16) })); // a group not held
        assert.equal(r.proofs.length, 0, "none proved");
        assert.deepEqual([r.status(G, A), r.status(G, B), r.status(G, X)], ["invited", "invited", undefined]);
        assert.deepEqual([r.ContactStore.get(X), r.ContactStore.get(A)], [null, null], "no key remembered from any of them");
        assert.deepEqual(r.held(), []);
    }
});

test("the creator's accept is not needed: a member's accept in a pending group counts and is recorded, the user's accept still allows every member and nobody before it", async () => {
    const r = groupClient({ filter: true });
    const [creator, a, b] = [1, 2, 3].map(() => Identity.create());
    const [A, B] = [a, b].map(lxmfHash);
    holds(r, creator, [a, b]);
    await r.receive(control(a, r.me, "accept"));
    assert.equal(r.status(G, A), "accepted");
    assert.equal(r.ContactStore.allowlisted(A), false, "allowed nothing by it: the user has not accepted");
    assert.equal(r.PrivacyFilter.knows(A), false);
    r.know(b);
    r.page._acceptGroupInvite(G);
    assert.deepEqual([A, B].map((h) => r.ContactStore.allowlisted(h)), [true, true], "the user's accept allows every member (James, 2026-10-01): kept");
    assert.deepEqual([A, B].map((h) => r.PrivacyFilter.knows(h)), [true, true]);
});

// ═══ 3. the creator: its copies, and its answer ═══════════════════════════

/** The creator's copies of group `id`, as [member, action, hex of the packed message]. */
const copies = (c, id) => c.GroupStore.statusMessages(id).map((s) => [s.member, s.action, hex(s.packed)]);
/** What the creator sent that is a `status`, parsed as its recipient parses it: [to, via, group entries, the elements as hex]. */
const statusesSent = (c, from = 0) => c.decoded(from).filter(({ message }) => decodeFields(message)?.groupAction === "status")
    .map(({ to, via, message, bytes }) => ({ to, via, message, bytes, group: decodeFields(message), elements: (decodeFields(message).statuses ?? []).map(hex) }));

test("the creator keeps the newest accept or leave that counted for each member, exactly as received, and answers each accept that carries its sender's key with one status to that member: the other members' copies, never its own nor the recipient's, by member hash", async () => {
    for (const switched of [false, true]) {
        const when = switched ? "after the switch" : "before the switch";
        const { c, ms: [a, b, d], net, id } = await started({ members: 3, switched });

        a.page._acceptGroupInvite(id);
        await net.pump(a);
        const acceptA = a.sent.filter((s) => s.to === c.own).at(-1).bytes;
        assert.deepEqual(copies(c, id), [[a.own, "accept", hex(acceptA)]], `${when}: a's accept, byte for byte`);
        assert.equal(c.status(id, a.own), "accepted", when);
        let sent = statusesSent(c);
        assert.deepEqual(sent.map((s) => [s.to, s.elements]), [[a.own, []]], `${when}: a is answered; nobody else has answered, so the answer is empty (a's own is not sent back)`);

        b.page._acceptGroupInvite(id);
        await net.pump(b);
        const acceptB = b.sent.filter((s) => s.to === c.own).at(-1).bytes;
        sent = statusesSent(c);
        assert.deepEqual(sent.map((s) => [s.to, s.elements]), [[a.own, []], [b.own, [hex(acceptA)]]], `${when}: b is told of a's accept, as a signed it`);

        d.page._acceptGroupInvite(id);
        await net.pump(d);
        sent = statusesSent(c);
        const toD = sent.at(-1);
        assert.equal(toD.to, d.own, when);
        const sorted = [[a.own, hex(acceptA)], [b.own, hex(acceptB)]].sort(([x], [y]) => (x < y ? -1 : 1)).map(([, e]) => e);
        assert.deepEqual(toD.elements, sorted, `${when}: d is told of a's and b's, by member hash ascending`);
        assert.equal(toD.elements.includes(hex(d.sent.filter((s) => s.to === c.own).at(-1).bytes)), false, `${when}: never d's own`);
        assert.equal(toD.elements.some((e) => e.slice(32, 64) === c.own), false, `${when}: nor the creator's`);

        // The envelope: GROUP_ID, GROUP_ACTION status, GROUP_SENDER the creator, signed by it, no content;
        // key 10 in the Retichat field even before the switch.
        for (const s of sent) {
            assert.deepEqual([s.group.groupId, s.group.groupAction, s.group.groupSender], [id, "status", c.own], when);
            assert.deepEqual([s.message.title, s.message.content, s.message.signatureValidated], ["", "", true], when);
            assert.deepEqual([...s.message.fields.get(0xD1).keys()].filter((k) => k >= 10), [10], `${when}: key 10 in 0xD1`);
            assert.equal(s.message.fields.has(0xA9) || s.message.fields.has(0xAA), false, `${when}: no old field for it`);
            assert.equal(s.message.fields.has(0xA0), !switched, `${when}: the other entries in the form the switch selects`);
            assert.equal(s.message.fields.get(0xD1).has(RF.RF_GROUP_ID), switched, when);
        }
        // Sent as every group envelope is: a propagated fallback armed for each.
        assert.deepEqual([...c.fallbacks].filter((h) => [a.own, b.own, d.own].includes(h)).length >= 3, true, `${when}: armed per recipient`);
    }
});

test("a status answers the accept that just counted, once: a repeated accept (another message) is answered again and is the newest copy; the same message twice is one", async () => {
    const { c, ms: [a, b], net, id } = await started({ members: 2 });
    a.page._acceptGroupInvite(id);
    await net.pump(a);
    assert.deepEqual(statusesSent(c).map((s) => s.to), [a.own]);
    const first = copies(c, id)[0][2];

    // The very same bytes again (a direct copy and a propagated one are one LXMF message): dropped as a duplicate.
    const accepted = a.sent.filter((s) => s.to === c.own).at(-1).bytes;
    await c.receive(accepted);
    assert.deepEqual(statusesSent(c).map((s) => s.to), [a.own], "no second answer for the same message");

    // A second accept of a's, as a new message: counts (changing nothing), is the newest copy, and is answered.
    const again = lxm(a.me, c.me, "", oldFields({ id, action: "accept", sender: a.own, keys: senderKeyEntry(a.own, a.pubKey) }));
    await c.receive(again);
    assert.deepEqual(statusesSent(c).map((s) => s.to), [a.own, a.own], "a repeated accept is answered again");
    assert.deepEqual(copies(c, id), [[a.own, "accept", hex(again)]], "the newest accept is the copy");
    assert.notEqual(hex(again), first);
    assert.deepEqual(c.notices(id), [["joined the group", a.own]], "and it said nothing more: nothing changed");
    void b;
});

test("a leave is kept as the member's copy and is final: it replaces the accept, nothing replaces it, and a later accept is dropped unproved and unanswered; a leave is never answered", async () => {
    for (const switched of [false, true]) {
        const { c, ms: [a, b, d], net, id } = await started({ members: 3, switched });
        a.page._acceptGroupInvite(id);
        await net.pump(a);
        const leaveFrom = a.sent.length;
        a.page._leaveGroup(id);
        await net.pump(a);
        const leaveToC = a.sent.slice(leaveFrom).find((s) => s.to === c.own).bytes;
        assert.deepEqual(copies(c, id), [[a.own, "leave", hex(leaveToC)]], "the leave replaced the accept");
        assert.equal(c.status(id, a.own), "left");
        assert.deepEqual(statusesSent(c).map((s) => s.to), [a.own], "only the accept was answered");

        const proofs = c.proofs.length;
        await c.receive(lxm(a.me, c.me, "", oldFields({ id, action: "accept", sender: a.own, keys: senderKeyEntry(a.own, a.pubKey) })));
        assert.equal(c.proofs.length, proofs, "a later accept is dropped unproved");
        assert.deepEqual(copies(c, id), [[a.own, "leave", hex(leaveToC)]], "and the copy is still the leave");
        assert.equal(statusesSent(c).length, 1, "and unanswered");

        // d is told of a's leave, not of its accept.
        d.page._acceptGroupInvite(id);
        await net.pump(d);
        assert.deepEqual(statusesSent(c).at(-1).elements, [hex(leaveToC)], "the newest of a's: the leave");
        void b;
    }
});

test("the creator's own copy is never sent in an answer, nor the recipient's, even if one were kept", async () => {
    const { c, ms: [a, b], net, id } = await started({ members: 2 });
    assert.equal(c.GroupStore.keepStatus(id, c.own, "accept", Buffer.alloc(120, 5)), null, "a copy for the creator is kept (the store only asks that it is listed)");
    a.page._acceptGroupInvite(id);
    await net.pump(a);
    b.page._acceptGroupInvite(id);
    await net.pump(b);
    const toB = statusesSent(c).find((s) => s.to === b.own);
    assert.deepEqual(toB.elements, [copies(c, id).find(([m]) => m === a.own)[2]], "only a's: not the creator's own, not b's");
});

test("only an accept that carries its sender's own key is answered: a keyless accept counts (and is kept for the others) but is never sent an action it does not know, whether the key is held or not; nor is a leave, a forged accept, one from no member, or one for a group not held", async () => {
    for (const switched of [false, true]) {
        const c = groupClient({ switched });
        const [a, old, x, mallory] = [1, 2, 3, 4].map(() => Identity.create());
        const [A, O, X] = [a, old, x].map(lxmfHash);
        c.know(a).know(old).reachable(A, O, X);
        const id = c.GroupStore.create("G", [A, O]).groupId;

        await c.receive(control(old, c.me, "accept", { key: false, groupId: id }));         // a client from before this change
        assert.equal(c.status(id, O), "accepted", "counted");
        assert.equal(copies(c, id).length, 1, "and kept: the other members are told of it");
        assert.deepEqual(statusesSent(c), [], "but not answered: its client does not know the action");

        await c.receive(control(a, c.me, "accept", { signer: mallory, groupId: id }));      // forged
        await c.receive(control(x, c.me, "accept", { groupId: id }));                       // on no list
        await c.receive(control(a, c.me, "accept", { groupId: "ee".repeat(16) }));          // a group not held
        assert.deepEqual([statusesSent(c), c.status(id, A), c.status(id, X), copies(c, id).length], [[], "invited", undefined, 1], "none answered, none kept");

        await c.receive(control(a, c.me, "leave", { groupId: id }));                        // a leave: kept, not answered
        assert.deepEqual([statusesSent(c), c.status(id, A), copies(c, id).map(([m, act]) => [m, act])], [[], "left", [[A, "leave"], [O, "accept"]].sort(([m], [n]) => (m < n ? -1 : 1))]);
    }
});

test("the old client's accept that counted unverified before the switch is the copy until a keyed one replaces it; and (from the switch) an accept held for its key is kept once it counts, as the held entry carried it", async () => {
    // before the switch: no key held, none carried: counts and is kept
    const c0 = groupClient({ switched: false });
    const [m0, other] = [1, 2].map(() => Identity.create());
    const id0 = c0.GroupStore.create("G", [lxmfHash(m0), lxmfHash(other)]).groupId;
    c0.reachable(lxmfHash(m0));
    const keyless = control(m0, c0.me, "accept", { key: false, groupId: id0 });
    await c0.receive(keyless);
    assert.equal(c0.ContactStore.get(lxmfHash(m0))?.publicKey ?? null, null, "the creator holds no key of its member");
    assert.equal(c0.status(id0, lxmfHash(m0)), "accepted");
    assert.deepEqual(copies(c0, id0), [[lxmfHash(m0), "accept", hex(keyless)]], "unverified, counted, kept");
    const keyed = control(m0, c0.me, "accept", { groupId: id0 });
    await c0.receive(keyed);
    assert.deepEqual(copies(c0, id0), [[lxmfHash(m0), "accept", hex(keyed)]], "the keyed accept is the newest");
    assert.deepEqual(statusesSent(c0).map((s) => s.to), [lxmfHash(m0)], "and answered");

    // from the switch: held, then counted when the key comes, then kept as the held entry carried it
    const c1 = groupClient({ switched: true });
    const id1 = c1.GroupStore.create("G", [lxmfHash(m0), lxmfHash(other)]).groupId;
    const heldAccept = control(m0, c1.me, "accept", { key: false, groupId: id1 });
    await c1.receive(heldAccept);
    assert.deepEqual([c1.status(id1, lxmfHash(m0)), c1.held(), copies(c1, id1)], ["invited", [[lxmfHash(m0), "accept"]], []], "held: not counted, so not kept");
    c1.know(m0);
    c1.self._decideHeldGroupChanges();                                // the key arrived (an announce): decided
    assert.deepEqual([c1.status(id1, lxmfHash(m0)), c1.held()], ["accepted", []]);
    assert.deepEqual(copies(c1, id1), [[lxmfHash(m0), "accept", hex(heldAccept)]], "kept once it counted, byte for byte what was held");
    assert.deepEqual(statusesSent(c1), [], "a held accept is keyless: never answered");
});

test("the copies survive a reload and answer after it; they go with the group; a copy is kept only for a listed member that has not left, and never over STATUS_PACKED_LIMIT", async () => {
    const { c, ms: [a, b, d], net, id } = await started({ members: 3 });
    a.page._acceptGroupInvite(id);
    b.page._acceptGroupInvite(id);
    await net.pump(a);
    await net.pump(b);
    const before = copies(c, id);
    assert.equal(before.length, 2);
    assert.deepEqual(c.storage.sGet("groups_statuses_v1").map((r) => [r.groupId, r.member, r.action]).sort(), before.map(([m, act]) => [id, m, act]).sort());

    const again = c.reload();
    assert.deepEqual(copies(again, id), before, "read back");
    assert.equal(again.GroupStore.get(id).creator, c.own, "the creator is persisted with the group");
    // D accepts at the reloaded creator: the answer carries both copies.
    again.know(d).know(a).know(b);
    again.reachable(a.own, b.own, d.own);
    const net2 = network(again, d);
    await net2.pump(again);                                          // (nothing to send yet)
    d.page._acceptGroupInvite(id);
    await net2.pump(d);
    const toD = statusesSent(again).find((s) => s.to === d.own);
    assert.deepEqual(toD.elements.slice().sort(), before.map(([, , e]) => e).sort(), "answered from the persisted copies");

    // Bounds and rules of keepStatus.
    const store = again.GroupStore;
    const bytes = Buffer.alloc(100, 1);
    assert.match(store.keepStatus("0".repeat(32), a.own, "accept", bytes), /not held/);
    assert.match(store.keepStatus(id, "f".repeat(32), "accept", bytes), /on no list/);
    assert.match(store.keepStatus(id, a.own, "relay_req", bytes), /neither an accept nor a leave/);
    assert.match(store.keepStatus(id, a.own, "accept", Buffer.alloc(STATUS_PACKED_LIMIT + 1, 1)), /over 2144 bytes/);
    assert.match(store.keepStatus(id, a.own, "accept", Buffer.alloc(0)), /no packed message/);
    assert.equal(store.keepStatus(id, a.own, "accept", Buffer.alloc(STATUS_PACKED_LIMIT, 1)), null, "exactly the limit is kept");
    assert.equal(store.keepStatus(id, a.own, "leave", bytes), null, "a leave replaces an accept");
    assert.match(store.keepStatus(id, a.own, "accept", bytes), /a leave is kept/, "nothing replaces a leave");
    assert.match(store.keepStatus(id, a.own, "leave", bytes), /a leave is kept/);
    store.updateMember(id, d.own, "left");
    assert.match(store.keepStatus(id, d.own, "accept", bytes), /left, for good/);

    // They go with the group (the creator leaving it).
    again.page._leaveGroup(id);
    assert.deepEqual([again.GroupStore.statusMessages(id), again.storage.sGet("groups_statuses_v1")], [[], []], "removed, and persisted so");
    assert.equal(again.GroupStore.get(id), null);
});

test("a copy too large for a packet makes a status that goes as a Resource: sent as every group envelope is (direct, a propagated fallback armed); a small one is one packet", async () => {
    const { c, ms, net, id } = await started({ members: 9 });
    for (const m of ms.slice(0, 8)) {
        m.page._acceptGroupInvite(id);
        await net.pump(m);
    }
    const last = ms[8];
    last.page._acceptGroupInvite(id);
    await net.pump(last);
    const toLast = statusesSent(c).find((s) => s.to === last.own);
    assert.equal(toLast.elements.length, 8, "eight copies for the ninth");
    assert.equal(toLast.via, "resource", "too large for one link packet");
    assert.ok(toLast.bytes.length > Link.MDU, `${toLast.bytes.length} bytes over the link MDU ${Link.MDU}`);
    assert.equal(c.GroupStore.get(id).members.get(last.own), "accepted");
    const first = statusesSent(c)[0];
    assert.deepEqual([first.elements.length, first.via], [0, "packet"], "the first answer is empty and small: one packet");
    assert.ok([...c.fallbacks].includes(last.own), "the propagated fallback is armed for it, as for every group send");
    // The ninth reads it through the router's Resource-sized message: it applies all eight.
    assert.equal(ms.slice(0, 8).filter((m) => last.status(id, m.own) === "accepted").length, 8);
});

test("only the creator answers: a member that gets an accept sends nothing; a group whose creator is not recorded (held before this change) neither keeps nor answers; a creator that left holds no group and answers nothing", async () => {
    const { c, ms: [a, b], net, id } = await started({ members: 2 });
    a.page._acceptGroupInvite(id);
    await net.pump(a);
    // b (a member, not the creator) received a's accept: no status, no copy.
    assert.deepEqual([statusesSent(b), copies(b, id), b.GroupStore.get(id).creator], [[], [], c.own], "b records the creator but is not it");
    assert.equal(b.status(id, a.own), "accepted", "and counted a's accept as any member does");
    assert.equal(b.sent.length, 0, "b sent nothing at all");

    // A group held before this change has no creator: nothing is kept, nothing answered.
    const legacy = groupClient();
    const m = groupClient();
    legacy.know(m).reachable(m.own);
    const lid = legacy.GroupStore.create("L", [m.own]).groupId;
    legacy.GroupStore.get(lid).creator = null;
    legacy.GroupStore._save();
    await legacy.receive(control(m.me, legacy.me, "accept", { groupId: lid }));
    assert.deepEqual([legacy.status(lid, m.own), copies(legacy, lid), statusesSent(legacy)], ["accepted", [], []]);
    const reloaded = legacy.reload();
    assert.equal(reloaded.GroupStore.get(lid).creator, null, "and a reload keeps it unrecorded");

    // The creator leaves: the group is closed and removed here, so nothing it still gets is answered.
    c.page._leaveGroup(id);
    await settle();
    assert.equal(c.GroupStore.get(id), null);
    const [sentBefore, provedBefore] = [c.sent.length, c.proofs.length];
    await c.receive(lxm(b.me, c.me, "", oldFields({ id, action: "accept", sender: b.own, keys: senderKeyEntry(b.own, b.pubKey) })));
    assert.equal(c.sent.length, sentBefore, "nothing sent");
    assert.equal(c.proofs.length, provedBefore, "and nothing even proved: the group is closed for good");
});

// ═══ 4. receiving a status ════════════════════════════════════════════════

/** A `status` from `creator` (an identity) to `to`: GROUP_ID, GROUP_ACTION status, GROUP_SENDER the creator and `elements` as
 *  GROUP_STATUSES, written as the page writes it (applyGroupFields), in the form the switch selects. `signer` is for the forger. */
function status(creator, to, elements, { switched = false, groupId = G, signer = creator, timestamp = null, raw = false } = {}) {
    // `raw` writes whatever `elements` holds (an array of anything), as a sender that does not check what it writes would.
    const fields = RF.applyGroupFields(new Map(), { groupId, groupAction: "status", groupSender: lxmfHash(creator), groupStatuses: raw ? null : elements }, switched);
    if (raw) RF.setEntry(fields, RF.RF_GROUP_STATUSES, elements);
    return lxm(creator, to, "", fields, { signer, timestamp });
}

/** The receiver in group G: it accepted it (active), the creator and `members` listed, `keys` (identities) held. */
function joined({ switched = false, filter = false, members = [], keys = [] } = {}) {
    const r = groupClient({ switched, filter });
    const creator = Identity.create();
    holds(r, creator, members, { keys });
    r.GroupStore.accept(G);
    return { r, creator, C: lxmfHash(creator) };
}

test("the late acceptor: the accepts its client never saw (they reached it before the invite, and were dropped) come back in the creator's answer to its own accept, and apply under the normal rules", async () => {
    for (const filter of [false, true]) {
        const when = filter ? "filter on" : "filter off";
        const c = groupClient({ filter }), a = groupClient({ filter }), b = groupClient({ filter }), d = groupClient({ filter });
        const all = [c, a, b, d];
        for (const x of all) for (const y of all) if (x !== y) x.reachable(y.own);
        for (const m of [a, b, d]) c.know(m);
        if (filter) for (const m of [a, b, d]) m.know(c).ContactStore.allow(c.own);       // an invite counts only from an allowlisted inviter
        const net = network(...all);
        const id = c.GroupStore.create("G", [a.own, b.own, d.own]).groupId;
        const sending = c.self.sendGroupInvites(id, "G", [a.own, b.own, d.own]);
        // d's invites are held back: a and b get theirs, accept, and their accepts reach d before it knows the group.
        await net.pump(c, { skip: [d] });
        a.page._acceptGroupInvite(id);
        b.page._acceptGroupInvite(id);
        await net.pump(a);
        await net.pump(b);
        assert.equal(d.GroupStore.get(id), null, `${when}: d has not heard of the group`);
        assert.equal(d.proofs.length, 0, `${when}: a's and b's accepts were dropped unproved: a group not held here`);
        assert.equal(a.status(id, b.own), "accepted", `${when}: a and b know each other's, as do c`);

        // Now d's invites arrive, and d accepts.
        await net.pump(c);
        await sending;
        assert.equal(d.GroupStore.get(id).groupStatus, "pending", when);
        assert.deepEqual([a.own, b.own].map((h) => d.status(id, h)), ["invited", "invited"], `${when}: d still thinks a and b have not answered`);
        d.page._acceptGroupInvite(id);
        await net.run();
        assert.deepEqual([a.own, b.own, c.own].map((h) => d.status(id, h)), ["accepted", "accepted", "accepted"], `${when}: the creator's status brought back what d missed`);
        assert.deepEqual(d.notices(id).filter(([text]) => text === "joined the group").map(([, who]) => who).sort(), [a.own, b.own].sort(), `${when}: said once each`);
        assert.deepEqual([a, b].map((m) => d.ContactStore.allowlisted(m.own)), [true, true], `${when}: members pass the filter from the user's accept`);
        const answered = statusesSent(c).filter((s) => s.to === d.own);
        assert.equal(answered.length, 1, `${when}: one status for d's one accept`);
        assert.equal(answered[0].elements.length, 2, when);
        assert.equal(d.events.find((e) => e.kind === "group-status-received").detail.counted, 2, when);
    }
});

test("a status counts only from the group's creator, whose signature shows it: not from another member (a joined one), a stranger, the creator forged, or a creator not recorded; each dropped unproved", async () => {
    for (const switched of [false, true]) {
        const [a, stranger, mallory] = [1, 2, 3].map(() => Identity.create());
        const A = lxmfHash(a);
        const { r, creator, C } = joined({ switched, members: [a], keys: [a] });
        const element = control(a, creator, "accept", { groupId: G });
        const proofs = () => r.proofs.length;
        const applied = () => r.status(G, A);
        assert.equal(applied(), "invited");

        // another member's, signed, with a valid element inside
        await r.receive(status(a, r.me, [element], { switched }));
        assert.deepEqual([proofs(), applied()], [0, "invited"], "a member that is not the creator");
        // a stranger's
        await r.receive(status(stranger, r.me, [element], { switched }));
        assert.deepEqual([proofs(), applied()], [0, "invited"], "a stranger");
        // the creator's name, mallory's signature
        await r.receive(status(creator, r.me, [element], { switched, signer: mallory }));
        assert.deepEqual([proofs(), applied()], [0, "invited"], "the creator forged");
        // the creator, signed: counts
        await r.receive(status(creator, r.me, [element], { switched }));
        assert.deepEqual([proofs(), applied()], [1, "accepted"], "the creator's own, proved and applied");
        void C;

        // A group whose creator is not recorded: nothing is the creator's.
        const legacy = joined({ switched, members: [a], keys: [a, creator] });
        legacy.r.GroupStore.get(G).creator = null;
        const el = control(a, legacy.creator, "accept", { groupId: G });
        await legacy.r.receive(status(legacy.creator, legacy.r.me, [el], { switched }));
        assert.deepEqual([legacy.r.proofs.length, legacy.r.status(G, A)], [0, "invited"], "a group held before this change counts no status");
    }
});

test("a status whose signature is not validated counts for nothing, and nothing in it is held: the creator's key not held here (unverifiable), the creator forged, before and from the switch; once the creator's key is held the same status counts", async () => {
    const [a, b, mallory] = [1, 2, 3].map(() => Identity.create());
    const [A, B] = [a, b].map(lxmfHash);
    for (const switched of [false, true]) {
        const when = switched ? "from the switch" : "before the switch";
        // Group G joined by the user, the creator's key NOT held: the status cannot be verified, so it is not the creator's to be believed.
        const r = groupClient({ switched });
        const creator = Identity.create(), C = lxmfHash(creator);
        r.GroupStore.addPending(G, "G", C, [C, A, B, r.own]);
        r.GroupStore.accept(G);
        assert.equal(r.ContactStore.get(C)?.publicKey ?? null, null, `${when}: the creator's key is not held`);
        // A keyed element and a keyless one: each would count (or be held) arriving directly.
        const elements = [control(a, creator, "accept", { groupId: G }), control(b, creator, "accept", { key: false, groupId: G })];
        const nothing = (label) => assert.deepEqual([r.proofs.length, r.status(G, A), r.status(G, B), r.held(), r.notices(G), r.ContactStore.get(A)?.publicKey ?? null],
            [0, "invited", "invited", [], [], null], `${when}: ${label}: unproved, nothing counted, nothing held, no key remembered`);
        await r.receive(status(creator, r.me, elements, { switched, timestamp: 1 }));
        nothing("the creator's key not held");
        assert.equal(r.events.some((e) => e.kind === "group-status-received"), false, `${when}: no element was read`);
        // The creator's name under mallory's signature, with the creator's key now held: forged.
        r.know(creator);
        await r.receive(status(creator, r.me, elements, { switched, signer: mallory, timestamp: 2 }));
        nothing("forged under the creator's key");
        assert.equal(r.events.some((e) => e.kind === "group-status-received"), false, `${when}: no element was read`);
        // The creator's own, now that its key is held: counts, as any status does.
        await r.receive(status(creator, r.me, elements, { switched, timestamp: 3 }));
        assert.deepEqual([r.proofs.length, r.status(G, A)], [1, "accepted"], `${when}: validated: counts`);
        assert.deepEqual([r.status(G, B), r.held()], switched ? ["invited", [[B, "accept"]]] : ["accepted", []],
            `${when}: its keyless element is unverifiable: held from the switch, counted before it, as arriving directly`);
    }
});

test("a status counts only in a group the user has accepted: a pending group's, a group not held and one the user left are dropped unproved, and nothing is applied", async () => {
    const a = Identity.create(), creator = Identity.create();
    const A = lxmfHash(a);
    const pending = groupClient();
    holds(pending, creator, [a], { keys: [a] });
    const element = control(a, creator, "accept", { groupId: G });
    await pending.receive(status(creator, pending.me, [element]));
    assert.deepEqual([pending.proofs.length, pending.status(G, A), pending.GroupStore.get(G).groupStatus], [0, "invited", "pending"], "pending");
    // The very same status once the user accepts is applied.
    pending.GroupStore.accept(G);
    await pending.receive(status(creator, pending.me, [element], { timestamp: 1 }));
    assert.deepEqual([pending.proofs.length, pending.status(G, A)], [1, "accepted"], "accepted");

    const none = groupClient();
    none.know(creator);
    await none.receive(status(creator, none.me, [element]));
    assert.equal(none.proofs.length, 0, "a group not held");

    const left = groupClient();
    holds(left, creator, [a], { keys: [a] });
    left.GroupStore.accept(G);
    left.page._leaveGroup(G);
    await left.receive(status(creator, left.me, [element]));
    assert.deepEqual([left.proofs.length, left.GroupStore.get(G)], [0, null], "a group the user left");
});

test("each element is checked on its own, as if it had arrived directly: a failing one is skipped and the rest apply; the creator can pass on only what the members signed", async () => {
    const [a, b, d, e, f, x, mallory] = [1, 2, 3, 4, 5, 6, 7].map(() => Identity.create());
    const members = [a, b, d, e, f, ...Array.from({ length: 8 }, () => Identity.create())];
    const { r, creator } = joined({ members });
    const [A, B, D, E, F] = [a, b, d, e, f].map(lxmfHash);
    const R = r.own;
    const other = "ee".repeat(16);
    const good = control(a, creator, "accept", { groupId: G });                         // a: counts
    const elements = [
        good,
        control(b, creator, "accept", { signer: mallory, groupId: G }),                  // b: forged under the key it carries
        control(d, creator, "accept", { groupId: other }),                               // d: about another group
        control(x, creator, "accept", { groupId: G }),                                   // x: no member of G
        lxm(e, creator, "", oldFields({ id: G, action: "invite", sender: E, members: [lxmfHash(creator), E].join(","), keys: keyOf(e) })),   // e: an invite, not an accept or leave
        control(f, creator, "accept", { sender: B, groupId: G }),                        // f: names b
        "a string", 7, null, [1, 2],                                                     // not bin
        Buffer.from("not a message, only bytes that are not one"),                        // junk
        Buffer.alloc(40, 3),                                                             // too short
        Buffer.concat([good, Buffer.alloc(STATUS_PACKED_LIMIT)]),                        // over the limit
        control(r.me, creator, "leave", { groupId: G }),                                 // about this device
    ];
    await r.receive(status(creator, r.me, elements, { raw: true }));
    assert.deepEqual([A, B, D, E, F, lxmfHash(x), R].map((h) => r.status(G, h)), ["accepted", "invited", "invited", "invited", "invited", undefined, "accepted"], "only a's accept applied; this device unchanged");
    assert.deepEqual(r.notices(G), [["joined the group", A]], "said once");
    const tally = r.events.find((ev) => ev.kind === "group-status-received").detail;
    assert.deepEqual([tally.elements, tally.counted, tally.held, tally.skipped], [elements.length, 1, 0, elements.length - 1]);
    assert.equal(r.ContactStore.get(lxmfHash(x)), null, "a skipped element leaves nothing behind");
    assert.equal(r.ContactStore.get(B)?.publicKey ?? null, null, "not even the key a forged one carried");
});

test("an element is about this status's group and no other: one a member signed for another group the user also holds is skipped, and changes neither; a valid accept over the size limit is skipped, the same message arriving directly is not", async () => {
    const a = Identity.create(), A = lxmfHash(a);
    const G2 = "7c".repeat(16);
    const { r, creator } = joined({ members: [a] });
    holds(r, creator, [a], { groupId: G2 });
    r.GroupStore.accept(G2);
    assert.deepEqual([r.status(G, A), r.GroupStore.get(G2).members.get(A)], ["invited", "invited"]);
    await r.receive(status(creator, r.me, [control(a, creator, "accept", { groupId: G2 })]));
    assert.deepEqual([r.status(G, A), r.GroupStore.get(G2).members.get(A)], ["invited", "invited"], "an accept for G2 inside a status for G counts for neither");
    assert.deepEqual(r.events.find((e) => e.kind === "group-status-received").detail.skipped, 1);

    // Over the limit (no genuine accept carries content): skipped though it is valid; arriving directly it counts.
    const big = lxm(a, creator, "x".repeat(2100), oldFields({ id: G, action: "accept", sender: A, keys: keyOf(a) }));
    assert.ok(big.length > STATUS_PACKED_LIMIT);
    assert.equal(LXMessage.fromBytes(big.subarray(16), big.subarray(0, 16), () => a).signatureState, "validated", "a genuine signature");
    await r.receive(status(creator, r.me, [big], { timestamp: 5 }));
    assert.equal(r.status(G, A), "invited", "skipped for its size");
    const direct = joined({ members: [a] });
    await direct.r.receive(lxm(a, direct.r.me, "x".repeat(2100), oldFields({ id: G, action: "accept", sender: A, keys: keyOf(a) })));
    assert.equal(direct.r.status(G, A), "accepted", "the size bound is for what a creator keeps and passes on, not for a message that arrives");
    assert.deepEqual(copies(direct.r, G), [], "and a receiver that is not the creator keeps no copy");
});

test("an element applies with the normal rules: a leave stays final and order does not matter, whether the elements, the direct messages or both come first", async () => {
    for (const order of ["accept then leave", "leave then accept"]) {
        const a = Identity.create(), A = lxmfHash(a);
        const { r, creator } = joined({ members: [a, Identity.create()] });
        const accept = control(a, creator, "accept", { groupId: G, timestamp: 1 });
        const leave = control(a, creator, "leave", { groupId: G, timestamp: 2 });
        await r.receive(status(creator, r.me, order === "accept then leave" ? [accept, leave] : [leave, accept]));
        assert.equal(r.status(G, A), "left", order);
        assert.deepEqual(r.notices(G).map(([text]) => text), order === "accept then leave" ? ["joined the group", "left the group"] : ["left the group"], order);
    }
    // A leave that came directly first: the element's accept changes nothing, and the other way round.
    const a = Identity.create(), A = lxmfHash(a);
    const first = joined({ members: [a, Identity.create()] });
    await first.r.receive(control(a, first.r.me, "leave", { groupId: G }));
    await first.r.receive(status(first.creator, first.r.me, [control(a, first.creator, "accept", { groupId: G })]));
    assert.deepEqual([first.r.status(G, A), first.r.notices(G)], ["left", [["left the group", A]]], "the direct leave, then a status's accept");
    const second = joined({ members: [a, Identity.create()] });
    await second.r.receive(status(second.creator, second.r.me, [control(a, second.creator, "leave", { groupId: G })]));
    const proofs = second.r.proofs.length;
    await second.r.receive(control(a, second.r.me, "accept", { groupId: G }));
    assert.deepEqual([second.r.status(G, A), second.r.proofs.length], ["left", proofs], "a status's leave, then the direct accept: dropped unproved");
    // An accept of a member already accepted changes nothing and says nothing.
    const third = joined({ members: [a, Identity.create()] });
    await third.r.receive(control(a, third.r.me, "accept", { groupId: G }));
    const said = third.r.notices(G).length;
    await third.r.receive(status(third.creator, third.r.me, [control(a, third.creator, "accept", { groupId: G, timestamp: 5 })]));
    assert.deepEqual([third.r.status(G, A), third.r.notices(G).length], ["accepted", said], "a member already accepted: no change, no second notice");
});

test("an element that is unverifiable (no key held, none carried that binds) counts until the switch, exactly as the message arriving directly does, and from the switch is held until its sender's key arrives; one that is forged under a held key is skipped either way", async () => {
    const [a, b, mallory] = [1, 2, 3].map(() => Identity.create());
    const [A, B] = [a, b].map(lxmfHash);
    for (const switched of [false, true]) {
        const when = switched ? "from the switch" : "before the switch";
        const { r, creator, C } = joined({ switched, members: [a, b] });
        const keyless = control(a, creator, "accept", { key: false, groupId: G });
        await r.receive(status(creator, r.me, [keyless], { switched }));
        if (!switched) {
            assert.deepEqual([r.status(G, A), r.held()], ["accepted", []], `${when}: counted, as the phones count it`);
        } else {
            assert.deepEqual([r.status(G, A), r.held()], ["invited", [[A, "accept"]]], `${when}: held`);
            // a's key arrives (an invite chunk): decided, and counted.
            await r.receive(lxm(creator, r.me, "", oldFields({ id: G, action: "invite", sender: C, members: [C, A, B, r.own].join(","), keys: keyOf(a) })));
            assert.deepEqual([r.status(G, A), r.held()], ["accepted", []], `${when}: counted once its key came`);
        }
        // b's accept forged under a key held: skipped, in either state.
        r.know(b);
        await r.receive(status(creator, r.me, [control(b, creator, "accept", { key: false, signer: mallory, groupId: G })], { switched, timestamp: 9 }));
        assert.deepEqual([r.status(G, B), r.held()], ["invited", []], `${when}: forged under b's held key: skipped, not held`);
    }
});

test("the key an element carries is remembered as one arriving directly brings it, and an accept element allows its member in the group the user has joined (as any accept does)", async () => {
    const a = Identity.create(), A = lxmfHash(a);
    const { r, creator } = joined({ filter: true, members: [a] });
    assert.equal(r.ContactStore.get(A)?.publicKey ?? null, null);
    assert.equal(r.ContactStore.allowlisted(A), false);
    await r.receive(status(creator, r.me, [control(a, creator, "accept", { groupId: G })]));
    assert.deepEqual([r.status(G, A), r.ContactStore.get(A).publicKey, r.ContactStore.get(A).hidden, r.ContactStore.allowlisted(A)],
        ["accepted", a.getPublicKey().toString("hex"), true, true], "kept, hidden, allowed");
    // The key it brought verifies the member's next message with none carried.
    await r.receive(control(a, r.me, "leave", { key: false, groupId: G }));
    assert.equal(r.status(G, A), "left");
});

test("a status reads at most as many elements as the group has members, an empty one or one with no key 10 changes nothing, and the same status twice is one", async () => {
    const a = Identity.create(), A = lxmfHash(a);
    const junk = Buffer.alloc(120, 7);
    const tallyOf = (r) => r.events.filter((e) => e.kind === "group-status-received").at(-1).detail;

    // The creator, a and this device: three members, so three elements are read.
    const within = joined({ members: [a] });
    await within.r.receive(status(within.creator, within.r.me, [junk, junk, control(a, within.creator, "accept", { groupId: G })]));
    assert.equal(within.r.status(G, A), "accepted", "a's accept is the third element: read");
    assert.deepEqual([tallyOf(within.r).elements, tallyOf(within.r).counted, tallyOf(within.r).skipped], [3, 1, 2]);

    const beyond = joined({ members: [a] });
    await beyond.r.receive(status(beyond.creator, beyond.r.me, [junk, junk, junk, control(a, beyond.creator, "accept", { groupId: G })]));
    assert.equal(beyond.r.status(G, A), "invited", "a's accept is the fourth: more than an honest creator sends, not read");
    assert.deepEqual([tallyOf(beyond.r).elements, tallyOf(beyond.r).counted, tallyOf(beyond.r).skipped], [4, 0, 4], "three skipped as junk, one unread");

    const b = joined({ members: [a] });
    await b.r.receive(status(b.creator, b.r.me, []));
    await b.r.receive(lxm(b.creator, b.r.me, "", oldFields({ id: G, action: "status", sender: b.C })));            // no key 10 at all
    assert.equal(b.r.proofs.length, 2, "both are the creator's: proved");
    assert.deepEqual([b.r.status(G, A), b.r.notices(G)], ["invited", []]);
    assert.deepEqual(b.r.events.filter((e) => e.kind === "group-status-received").map((e) => e.detail.elements), [0, 0]);

    const c = joined({ members: [a] });
    const same = status(c.creator, c.r.me, [control(a, c.creator, "accept", { groupId: G })], { timestamp: 77 });
    await c.r.receive(same);
    await c.r.receive(same);
    assert.equal(c.r.proofs.length, 2, "each copy is proved, as any delivered message is");
    assert.equal(c.r.events.filter((e) => e.kind === "group-status-received").length, 1, "the second is a duplicate LXMF message, dropped by its hash before it is read, as any");
    assert.equal(c.r.notices(G).length, 1);
});

test("a stranger's status is dropped at the router's first look, unproved and unparsed; the creator's is read whole even once the creator has left, being only the carrier of what members signed", async () => {
    const a = Identity.create(), A = lxmfHash(a), stranger = Identity.create();
    const { r, creator, C } = joined({ filter: true, members: [a] });
    const element = control(a, creator, "accept", { groupId: G });
    let parses = 0;
    const real = LXMessage.fromBytes;
    LXMessage.fromBytes = (...args) => { parses++; return real.apply(LXMessage, args); };
    try {
        await r.receive(status(stranger, r.me, [element]));
        assert.equal(parses, 0, "a stranger's message, not a member's: dropped before the parse");
        assert.deepEqual([r.proofs.length, r.status(G, A)], [0, "invited"]);
        assert.ok(r.events.some((e) => e.kind === "privacy-drop" && e.detail.at === "source"), "dropped by the first look");
    } finally {
        LXMessage.fromBytes = real;
    }
    // The creator left (its leave counted, final); a status it had sent before still counts.
    await r.receive(control(creator, r.me, "leave", { groupId: G }));
    assert.equal(r.status(G, C), "left");
    await r.receive(status(creator, r.me, [element]));
    assert.deepEqual([r.status(G, A), r.notices(G).map(([text]) => text)], ["accepted", ["left the group", "joined the group"]]);
});

test("the group rule for a status, as a table: only the creator, only for a joined group, only a signature that shows it; nothing else about the source matters", () => {
    const { shouldProcessGroupMessage } = groupRule();
    // [groupStatus, sourceStatus, signature, sourceIsCreator, want]
    for (const [groupStatus, sourceStatus, signature, sourceIsCreator, want] of [
        ["active", "accepted", "validated", true, true],
        ["active", "accepted", null, true, true],                 // the router's first look: not checked yet
        ["active", "left", "validated", true, true],              // a creator that left is only a carrier
        ["active", "invited", "validated", true, true],
        ["active", "accepted", "validated", false, false],        // a member that is not the creator
        ["active", "accepted", "unknown", true, false],           // the creator's key not held: not proven
        ["active", "accepted", "invalid", true, false],           // forged
        ["pending", "accepted", "validated", true, false],        // not joined
        [null, undefined, "validated", true, false],              // not held
        ["active", undefined, "validated", true, true],
    ]) {
        for (const allowed of [true, false]) {
            assert.equal(shouldProcessGroupMessage("status", allowed, groupStatus, sourceStatus, false, false, signature, sourceIsCreator), want,
                `${groupStatus} source=${sourceStatus} signature=${signature} creator=${sourceIsCreator} allowed=${allowed}`);
        }
    }
    // The default: nothing is the creator's unless the filter says so; the unknown-action rule is unchanged.
    assert.equal(shouldProcessGroupMessage("status", true, "active", "accepted", false, false, "validated"), false);
    assert.equal(shouldProcessGroupMessage("promote", false, "active", "accepted", false, false, "validated"), true, "any other action: a current member of a joined group");
    assert.equal(shouldProcessGroupMessage("promote", false, "active", "accepted", false, false, "validated", true), true);
});

// ═══ 5. mixed versions ════════════════════════════════════════════════════

test("mixed versions: a client from before this change sends no key and is sent no status, a client after it does and is; the creator counts both and tells the new one of the old one's accept", async () => {
    for (const switched of [false, true]) {
        const when = switched ? "from the switch" : "before the switch";
        const c = groupClient({ switched });
        const n = groupClient({ switched });                           // a member of the new build
        const old = Identity.create(), O = lxmfHash(old);              // a member of the old build: only its bytes exist here
        c.know(n).know(old).reachable(n.own, O);
        n.know(c).reachable(c.own);
        const net = network(c, n);
        const id = c.GroupStore.create("G", [n.own, O]).groupId;
        void c.self.sendGroupInvites(id, "G", [n.own, O]);               // the old member is no client here: its invites are never proved
        await net.pump(c);

        await c.receive(control(old, c.me, "accept", { key: false, groupId: id }));         // the old build's accept: no key, the old field
        n.page._acceptGroupInvite(id);
        await net.pump(n);
        assert.deepEqual([c.status(id, O), c.status(id, n.own)], ["accepted", "accepted"], `${when}: both counted at the creator (its contact's key is held)`);
        const answered = statusesSent(c).map((s) => s.to);
        assert.deepEqual(answered, [n.own], `${when}: only the new build is answered`);
        const oldCopy = copies(c, id).find(([m]) => m === O)[2];
        assert.deepEqual(statusesSent(c)[0].elements, [oldCopy], `${when}: and told of the old build's accept, as it signed it`);
        assert.equal(statusesSent(c).filter((s) => s.to === O).length, 0, `${when}: never an action the old build does not know`);
    }
});

test("mixed versions: before the switch what a new build sends is read by a released one as it always read an accept, a leave or a status: the group entries in the old fields, the Retichat field holding only a name and key 10, which a released reader skips", async () => {
    const { c, ms: [a, b], net, id } = await started({ members: 2, switched: false });
    a.page._acceptGroupInvite(id);
    await net.pump(a);
    a.page._leaveGroup(id);
    await net.pump(a);
    const released = (m) => {                                          // what a released reader takes: 0xA0-0xA8, in top-level fields only
        const f = m.fields;
        return { id: f.get(0xA0), action: f.get(0xA3), sender: f.get(0xA4), key: f.get(0xA8), rest: [...f.keys()].filter((k) => k < 0xA0 || k > 0xA8) };
    };
    for (const { message: m, to } of a.decoded()) {
        const r = released(m);
        assert.deepEqual([r.id, r.sender], [id, a.own], to);
        assert.ok(["accept", "leave"].includes(r.action), to);
        assert.equal(r.key, senderKeyEntry(a.own, a.pubKey), "the key in 0xA8, which a released reader ignores outside an invite");
        assert.deepEqual(r.rest.filter((k) => k !== 0xD1), [], "nothing else in the message");
        assert.equal(m.fields.get(0xD1)?.has(RF.RF_GROUP_STATUSES) ?? false, false);
    }
    const s = statusesSent(c)[0];
    const r = released(s.message);
    assert.deepEqual([r.id, r.action, r.sender], [id, "status", c.own], "the status's entries in the old fields too");
    assert.deepEqual([...s.message.fields.get(0xD1).keys()], [10], "the Retichat field holds key 10 alone (no name is set), unknown to a released reader and skipped");
    void b;
});

test("after the switch every group entry, the key included, goes into the Retichat field alone, and the old top-level fields are not written", async () => {
    const { c, ms: [a], net, id } = await started({ members: 1, switched: true });
    a.page._acceptGroupInvite(id);
    await net.pump(a);
    for (const { message: m } of [...a.decoded(), ...c.decoded().filter(({ message }) => decodeFields(message)?.groupAction === "status")]) {
        const old = [...m.fields.keys()].filter((k) => k >= 0xA0 && k <= 0xA8);
        assert.deepEqual(old, [], "no top-level group field");
        assert.ok(m.fields.get(0xD1) instanceof Map);
    }
    const accept = a.decoded()[0].message;
    assert.deepEqual([...accept.fields.get(0xD1).keys()], [1, 4, 5, 9], "id, action, sender and the key, ascending");
    const st = statusesSent(c)[0].message;
    assert.deepEqual([...st.fields.get(0xD1).keys()], [1, 4, 5, 10], "id, action, sender and the statuses");
});

// ═══ 6. the privacy filter, and the wiring ════════════════════════════════

test("the web still lets a group's members through the privacy filter from the user's accept, not from the invite's arrival; nothing a status brings changes that", async () => {
    const [a, b] = [1, 2].map(() => Identity.create());
    const [A, B] = [a, b].map(lxmfHash);
    const r = groupClient({ filter: true });
    const creator = Identity.create();
    holds(r, creator, [a, b], { keys: [a, b] });
    const dm = (from) => lxm(from, r.me, `hello from ${lxmfHash(from).slice(0, 4)}`);
    await r.receive(dm(a));
    assert.deepEqual([r.proofs.length, r.MsgStore.get(A).length], [0, 0], "a listed member of a group the user has not accepted: a stranger's DM, dropped");
    r.page._acceptGroupInvite(G);
    assert.deepEqual([A, B].map((h) => r.ContactStore.allowlisted(h)), [true, true]);
    await r.receive(dm(a));
    assert.equal(r.MsgStore.get(A).length, 1, "from the user's accept, a member's DM is kept");
    // A status brings member b's accept: b was already allowed by the user's accept; nobody outside the list is.
    const stranger = Identity.create();
    await r.receive(status(creator, r.me, [control(b, creator, "accept", { groupId: G }), control(stranger, creator, "accept", { groupId: G })]));
    assert.equal(r.status(G, B), "accepted");
    assert.deepEqual([r.ContactStore.allowlisted(lxmfHash(stranger)), r.PrivacyFilter.knows(lxmfHash(stranger))], [false, false]);
});

test("wiring: the carried key is remembered before anything looks for it; every accept and leave that counts keeps the creator's copy; the creator answers from the handler alone, and only an accept that counted and carried its key", () => {
    const handler = methodBody("_handleGroupMessage(lxmfMsg, srcHash, content, groupInfo)");
    const remember = handler.indexOf('this._rememberGroupMemberKeys(new Map([[srcHash, Buffer.from(lxmfMsg.senderKey).toString("base64")]]));');
    const held = handler.indexOf('GroupStore.heldChanges().some(e => e.src === srcHash)) this._decideHeldGroupChanges();');
    const rule = handler.indexOf("PrivacyFilter.groupAccepts(groupInfo, srcHash, signature)");
    const dedup = handler.indexOf("this._groupSeenIds.add(dedupKey);");
    assert.ok(rule < dedup && dedup < remember && remember < held, "after the rule and the duplicate check, before the held decision");
    assert.match(handler, /if \(\(groupAction === "accept" \|\| groupAction === "leave"\) && lxmfMsg\.senderKey\) \{/);
    assert.match(handler, /const counted = this\._takeGroupStatusChange\(lxmfMsg, groupId, srcHash, groupAction, lxmfMsg\);/);
    assert.match(handler, /if \(counted && groupAction === "accept" && lxmfMsg\.senderKey\) \{\n\s*this\.sendGroupStatus\(groupId, srcHash\)\.catch\(/);
    assert.match(handler, /case "status": \{[^]*?this\._takeGroupStatuses\(group, groupInfo\.statuses\);\n\s*break;/, "a status has its own case: it never falls into a plain message");
    assert.equal((app.match(/\.sendGroupStatus\(/g) ?? []).length, 1, "one caller of the answer");
    assert.equal((app.match(/groupAction: "status"/g) ?? []).length, 1, "and one place that builds a status");

    assert.match(methodBody("_takeGroupStatusChange(lxmfMsg, groupId, src, action, event = null)"),
        /const verdict = statusChangeVerdict\(lxmfMsg\.signatureState \?\? "invalid", GROUP_ENTRIES_IN_RETICHAT_FIELD\);\n\s*if \(verdict === "hold"\) \{\n\s*this\._holdGroupStatusChange\(lxmfMsg, groupId, src, action\);\n\s*return false;\n\s*\}\n\s*if \(verdict === "ignore"\) return false;\n\s*this\._applyGroupStatusChange\(groupId, src, action, event, packedMessage\(lxmfMsg\)\);\n\s*return true;/);
    assert.match(methodBody("_decideHeldGroupChanges()"), /this\._applyGroupStatusChange\(entry\.groupId, entry\.src, entry\.action, null, packedHeld\(entry\)\);/);
    assert.match(methodBody("_takeGroupStatusElement(groupId, element, ownHash)"), /return this\._takeGroupStatusChange\(message, groupId, src, action\) \? "counted" : "held";/);
    // Every count goes through _applyGroupStatusChange, with the copy: its callers are these two and nothing else.
    assert.equal((app.match(/this\._applyGroupStatusChange\(/g) ?? []).length, 2, "the verdict's, and the held decision's");
    assert.match(methodBody("_applyGroupStatusChange(groupId, src, action, event = null, packed = null)"),
        /if \(packed && group\.creator === \(this\.ownHash \?\? ownLxmfDestinationHash\(\)\)\) \{\n\s*const refused = GroupStore\.keepStatus\(groupId, src, action, packed\);[^]*?\n\s*\}\n\s*if \(!GroupStore\.updateMember\(/, "kept before the member's status moves, by the creator only");
    // The switch is the one constant, imported, not a second.
    assert.match(app, /import \{ applyGroupFields, GROUP_ENTRIES_IN_RETICHAT_FIELD \} from "\.\/lib\/retichat_field\.js";/);
    assert.doesNotMatch(app, /const GROUP_ENTRIES_IN_RETICHAT_FIELD/);
    assert.equal(RF.GROUP_ENTRIES_IN_RETICHAT_FIELD, false, "the switch is around 2026-10-26, not before");
});

test("wiring: every accept and leave the page sends is built in one place each and carries the user's own key; a creator is recorded when a group is made or invited into; nothing here runs a timer or a retry", () => {
    assert.match(methodBody("async sendGroupAccept(groupId)"), /groupAction: "accept",\n\s*groupSender: ownHash,\n\s*groupMemberKey: this\._ownGroupMemberKey\(\),/);
    assert.match(methodBody("async sendGroupLeave(groupId)"), /groupAction: "leave",\n\s*groupSender: ownHash,\n\s*groupMemberKey: this\._ownGroupMemberKey\(\),/);
    assert.equal((app.match(/groupAction: "accept"/g) ?? []).length, 1, "no other accept is built");
    assert.equal((app.match(/groupAction: "leave"/g) ?? []).length, 1, "no other leave is built: a decline is this one");
    assert.match(methodBody("_quitGroup(groupId, how)"), /RnsClient\.sendGroupLeave\(groupId\)/, "a decline and a leave are one path");
    assert.match(methodBody("create(groupName, memberHashes)"), /lastActivity: Date\.now\(\), creator: ownHash \};/);
    assert.match(methodBody("addPending(groupId, groupName, senderHash, memberHashes)"), /if \(existing\) return existing;[^]*?lastActivity: Date\.now\(\), creator: senderHash \};/, "the invite's source, recorded once");
    assert.match(objectLiteral("GroupStore"), /creator: g\.creator \?\? null,/, "persisted with the group");
    assert.match(methodBody("remove(groupId)"), /if \(this\._statuses\.delete\(groupId\)\) this\._saveStatuses\(\);/);
    const filter = objectLiteral("PrivacyFilter");
    assert.match(filter, /const sourceIsCreator = !!held && typeof held\.creator === "string" && held\.creator === src;/);
    assert.match(filter, /named !== src, s\.closed, signature, s\.sourceIsCreator\);/);

    for (const method of ["_takeGroupStatusChange(lxmfMsg, groupId, src, action, event = null)", "_takeGroupStatuses(group, statuses)",
        "_takeGroupStatusElement(groupId, element, ownHash)", "async sendGroupStatus(groupId, memberHash)", "_ownGroupMemberKey()"]) {
        assert.doesNotMatch(methodBody(method), /setTimeout|setInterval|requestAnimationFrame|retry|again|Promise\.race|while \(/i, `${method.split("(")[0]}: no timer, no retry (DESIGN_PRINCIPLES.md §1, §3)`);
    }
});
