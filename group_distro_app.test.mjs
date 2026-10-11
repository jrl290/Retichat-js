/**
 * GROUPS FOR DISTRO HOLDERS — the web client (GROUPS-DISTRO-DESIGN.md, approved
 * by James 2026-10-10; RFed SPEC §17.14; RFed-spec Group.md). The rows of the
 * design's §19.2 for the web, each run over the real shipped code: the real
 * LXMRouter, PrivacyFilter, ContactStore, GroupStore, the group handler and
 * the send path extracted from app.js (test_group_net.mjs), with real
 * identities, signatures and LXMF packing.
 *
 * Terms (§5): D is the distro's lxmf.delivery hash, held by this device and
 * its siblings; a D-group is a group whose own address (ownMember) is D.
 *
 * Run: node --test group_distro_app.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { senderKeyEntry } from "./lib/group_status.js";
import { shortHash } from "./lib/display_name.js";
import { compile, methodBody } from "./test_app_source.mjs";
import { groupClient, network, settle, lxmfHash, lxm, oldFields, Identity, LXMessage, GROUP_FIELDS } from "./test_group_net.mjs";

const decodeFields = (m) => LXMessage.extractGroupFields(m.fields);
const hex = (b) => Buffer.from(b).toString("hex");

const FORMER_D = (d) => `This group uses your distro address ${shortHash(d)}, which this device no longer holds. You can read it here, but cannot post or change your membership from this device.`;
const DELETE_HERE = "This removes the group from this device only. You stay in the group on your other devices and for the other members.";
const DECLINE_D = "Decline this invitation? This declines it on all your devices, and you cannot join this group later.";
const LEAVE_D = "Leave this group? You will leave it on all your devices, its messages are deleted from all of them, and you cannot rejoin.";
const DECLINE_DEVICE = "Decline this group invite? You won't be able to join this group later.";
const LEAVE_DEVICE = "Leave this group? You won't receive future messages, and you won't be able to rejoin it.";

/**
 * A creator C (another user), a member M, and U, a device of the user's
 * distro D. C creates a group listing M and D (C holds D's key, as a contact
 * of C's would), and its invites go out; U holds the invite as pending with
 * its own address D, as the invite handler admits one that lists D (§8.1).
 * `sibling` adds a known sibling S of D to the list (§9.1).
 */
async function dPending({ sibling = false, name = null } = {}) {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did, name });
    const c = groupClient();
    const m = groupClient();
    const Sid = sibling ? Identity.create() : null;
    const S = Sid ? lxmfHash(Sid) : null;
    const all = [u, c, m];
    for (const x of all) for (const y of all) if (x !== y) x.reachable(y.own);
    u.reachable(D);
    c.know(m).know(Did);
    m.know(c);
    const net = network(...all);
    const listed = [m.own, D, ...(S ? [S] : [])];
    if (S) c.know(Sid);
    const group = c.GroupStore.create("G", listed);
    void c.self.sendGroupInvites(group.groupId, "G", listed);
    await net.pump(c, { to: m });
    // U, as the invite to D would leave it (§8.1, §9.3): pending, own address D.
    u.know(c).know(m);
    if (S) u.KnownSiblingsStore.add(D, S);
    u.GroupStore.addPending(group.groupId, "G", c.own, [c.own, ...listed], D);
    return { u, c, m, D, Did, S, Sid, net, id: group.groupId };
}

/**
 * The group's invites reaching the user through D (§6): C creates a group
 * listing M and D and invites it, and RFed fans the invite to D out to every
 * device holding D (`devices` of them, each a web client of D). The filter of
 * each is `filter`; `allow` makes C allowlisted on each.
 */
async function viaD({ devices = 1, filter = false, allow = false, name = null } = {}) {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const us = Array.from({ length: devices }, () => groupClient({ distro: Did, filter, name }));
    const c = groupClient();
    const m = groupClient({ name: "Emm" });
    const all = [...us, c, m];
    for (const x of all) for (const y of all) if (x !== y) x.reachable(y.own);
    for (const x of all) x.reachable(D);
    c.know(m).know(Did);
    m.know(c).know(Did);
    for (const u of us) { u.know(c); if (allow) u.ContactStore.allow(c.own); }
    const net = network(...all);
    const listed = [m.own, D];
    const group = c.GroupStore.create("G", listed);
    void c.self.sendGroupInvites(group.groupId, "G", listed);
    await net.pump(c);
    return { us, u: us[0], c, m, D, Did, net, id: group.groupId };
}

/** What `client` notified the page of: [conversation, stored message or LXMF message]. */
function notified(client) {
    const notes = [];
    client.self._onMsg.push((msg, conv) => notes.push([conv, msg]));
    return notes;
}

/** The LXMF hash of a full packing (destination first), as the distro path keys it. */
const packingHash = (packed) => {
    const m = LXMessage.fromBytes(packed.subarray(16), packed.subarray(0, 16), () => null);
    return hex(m.hash);
};

// ═══ §8, §9: sending as D, self ═══════════════════════════════════════════

test("§9.3: the invite's list decides the user's own entry, never added unlisted: D when it lists D, else the device, else no group", () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const C = lxmfHash(Identity.create()), M = lxmfHash(Identity.create());
    const gid = (n) => n.toString(16).padStart(32, "0");
    const asD = u.GroupStore.addPending(gid(1), "G", C, [C, M, D], D);
    assert.equal(asD.ownMember, D);
    assert.deepEqual([...asD.members.entries()].sort(), [[C, "accepted"], [D, "invited"], [M, "invited"]].sort(), "the user's entry is D: the device is not added");
    assert.equal(u.GroupStore.addPending(gid(2), "G", C, [C, M], D), null, "a list without the user's own address makes no group");
    assert.equal(u.GroupStore.get(gid(2)), null);
    const asDevice = u.GroupStore.addPending(gid(3), "G", C, [C, u.own]);
    assert.equal(asDevice.ownMember, null, "the device: no own address of its own is stored");
    assert.equal(u.GroupStore.ownMemberOf(asDevice), u.own);
    assert.equal(u.GroupStore.addPending(gid(4), "G", C, [C, M]), null, "nor one listing neither");
    // Persisted with the group.
    const again = u.reload();
    assert.equal(again.GroupStore.get(gid(1)).ownMember, D);
    assert.equal(again.GroupStore.get(gid(3)).ownMember, null);
});

test("§19.2: in a D-group the accept goes out with source D, signed by D, GROUP_SENDER D and the carried key D:<key>, to every listed member but D, the device and a known sibling; the user's own entry is D only", async () => {
    const { u, c, m, D, Did, S, net, id } = await dPending({ sibling: true });
    u.page._acceptGroupInvite(id);
    await settle();
    const sent = u.decoded(0, Did);
    assert.deepEqual(sent.map((s) => s.to).sort(), [c.own, m.own].sort(), "never D, the device or the sibling");
    for (const { message } of sent) {
        assert.equal(hex(message.sourceHash), D, "source D");
        assert.equal(message.signatureValidated, true, "signed by D");
        const g = decodeFields(message);
        assert.equal(g.groupAction, "accept");
        assert.equal(g.groupSender, D, "GROUP_SENDER D");
        assert.deepEqual([...g.memberKeys], [[D, Buffer.from(Did.getPublicKey()).toString("base64")]], "D's own key");
    }
    assert.equal(senderKeyEntry(D, Did.getPublicKey().toString("hex")), u.self._ownGroupMemberKey(u.self._groupSigner(u.GroupStore.get(id))));
    assert.equal(u.status(id, D), "accepted", "the own entry D is joined");
    assert.equal(u.status(id, u.own), undefined, "the device is not on the list");
    assert.equal(u.status(id, S), "invited", "the sibling stays as listed");
    assert.equal(u.ContactStore.get(D), null, "D is never a contact");
    assert.equal(u.ContactStore.get(S), null, "nor a sibling");
    // The creator counts D's accept: D's key binds whichever device sent it.
    await net.pump(u, { to: c });
    assert.equal(c.status(id, D), "accepted");
});

test("§19.2: in a D-group a post and a leave go to every accepted member but self, as D; a group held at upgrade that also lists D keeps acting as the device, D and its siblings self", async () => {
    const { u, c, m, D, Did, S, id } = await dPending({ sibling: true });
    u.page._acceptGroupInvite(id);
    u.GroupStore.updateMember(id, m.own, "accepted");
    u.GroupStore.updateMember(id, S, "accepted");
    await settle();
    const from = u.sent.length;
    void u.self.sendGroupMessage(id, "hello");
    await settle();
    const posts = u.decoded(from, Did);
    assert.deepEqual(posts.map((s) => s.to).sort(), [c.own, m.own].sort(), "never D or the sibling, accepted or not");
    for (const { message } of posts) {
        assert.equal(hex(message.sourceHash), D);
        assert.equal(message.signatureValidated, true);
        assert.equal(decodeFields(message).groupSender, D);
    }
    const leaveFrom = u.sent.length;
    void u.self.sendGroupLeave(id);
    await settle();
    const leaves = u.decoded(leaveFrom, Did);
    assert.deepEqual(leaves.map((s) => s.to).sort(), [c.own, m.own].sort());
    for (const { message } of leaves) assert.equal(hex(message.sourceHash), D);

    // Held at upgrade: own address the device, the list naming the device and D.
    const v = groupClient({ distro: Did });
    v.know(c).know(m);
    v.KnownSiblingsStore.add(D, S);
    for (const h of [c.own, m.own, D, S]) v.reachable(h);
    v.GroupStore.addPending(id, "G", c.own, [c.own, m.own, D, S, v.own]);
    v.page._acceptGroupInvite(id);
    await settle();
    const sent = v.decoded();
    assert.deepEqual(sent.map((s) => s.to).sort(), [c.own, m.own].sort(), "D and the sibling are self there too");
    for (const { message } of sent) {
        assert.equal(hex(message.sourceHash), v.own, "but the user acts as the device");
        assert.equal(decodeFields(message).groupSender, v.own);
    }
    assert.equal(v.ContactStore.get(D), null);
});

test("§19.2: a D-group created on a device of D is created as D: D the creator and own entry, the invites signed by D, GROUP_SENDER D, the list naming D (not the device) and carrying D's own key", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const a = groupClient(), b = groupClient();
    u.know(a).know(b).reachable(a.own, b.own);
    const { group, sending } = u.self.createGroup("G", [a.own, b.own]);
    await settle();
    assert.equal(group.creator, D);
    assert.equal(group.ownMember, D);
    assert.deepEqual([...group.members.entries()].sort(), [[D, "accepted"], [a.own, "invited"], [b.own, "invited"]].sort());
    const sent = u.decoded(0, Did);
    assert.deepEqual([...new Set(sent.map((s) => s.to))].sort(), [a.own, b.own].sort(), "never D or the device");
    const keys = new Map();
    for (const { message } of sent) {
        assert.equal(hex(message.sourceHash), D);
        assert.equal(message.signatureValidated, true);
        const g = decodeFields(message);
        assert.equal(g.groupAction, "invite");
        assert.equal(g.groupSender, D);
        assert.deepEqual([...g.members].sort(), [D, a.own, b.own].sort(), "the list names D, not the device");
        for (const [h, k] of g.memberKeys) keys.set(h, k);
    }
    assert.equal(keys.get(D), Buffer.from(Did.getPublicKey()).toString("base64"), "D's chunk carries D's own key");
    void sending;
    // Without D the group is the device's, as today.
    const w = groupClient();
    w.know(a).reachable(a.own);
    const { group: plain } = w.self.createGroup("G", [a.own]);
    assert.equal(plain.creator, w.own);
    assert.equal(plain.ownMember, null);
});

test("§19.2: groupSigner: with D given up or replaced by D', a D-group post, accept or leave sends nothing, never as the device or D', and the §8.7 text says why", async () => {
    for (const replaced of [false, true]) {
        const { u, D, id } = await dPending();
        const other = Identity.create();
        u.DistroManager.set(replaced ? other : null);
        const group = u.GroupStore.get(id);
        assert.equal(u.self._groupSigner(group), null);
        assert.equal(u.self.groupFormerDistroText(group), FORMER_D(D));
        await assert.rejects(u.self.sendGroupAccept(id), { message: FORMER_D(D) });
        await assert.rejects(u.self.sendGroupLeave(id), { message: FORMER_D(D) });
        // The page refuses its own acts with the same text.
        u.page._acceptGroupInvite(id);
        assert.equal(u.alerts.at(-1), FORMER_D(D));
        assert.equal(u.GroupStore.get(id).groupStatus, "pending", "not accepted here either");
        u.GroupStore.accept(id);
        await assert.rejects(u.self.sendGroupMessage(id, "hi"), { message: FORMER_D(D) });
        assert.equal(u.GroupMsgStore.get(id).filter((x) => x.dir === "out").length, 0, "nothing stored to send");
        await settle();
        assert.equal(u.sent.length, 0, "nothing sent");
        assert.equal(u.propagated.length, 0, "nothing propagated");
    }
});

test("§19.2: \"Delete from this device\" in a former-D group sends no leave, closes nothing, and removes the group and its messages here only", async () => {
    const { u, D, id } = await dPending();
    u.GroupStore.accept(id);
    u.GroupMsgStore.addSystem(id, "x");
    u.DistroManager.set(null);
    u.page._deleteGroupFromDevice(id);
    assert.equal(u.confirms.at(-1), DELETE_HERE);
    await settle();
    assert.equal(u.GroupStore.get(id), null);
    assert.equal(u.GroupStore.isClosed(id), false, "not a leave: the user stays in the group elsewhere");
    assert.deepEqual(u.GroupMsgStore.get(id), []);
    assert.equal(u.sent.length + u.propagated.length, 0, "no leave sent");
    void D;
});

test("§13: the decline and leave confirmations in a D-group say all your devices; in a device-listed group they stay as today", async () => {
    const d = await dPending();
    d.u.page._declineGroupInvite(d.id);
    assert.equal(d.u.confirms.at(-1), DECLINE_D);
    const e = await dPending();
    e.u.GroupStore.accept(e.id);
    e.u.page._leaveGroup(e.id);
    assert.equal(e.u.confirms.at(-1), LEAVE_D);
    const v = groupClient();
    const C = lxmfHash(Identity.create());
    v.GroupStore.addPending("ab".repeat(16), "G", C, [C, v.own]);
    v.page._declineGroupInvite("ab".repeat(16));
    assert.equal(v.confirms.at(-1), DECLINE_DEVICE);
    v.GroupStore.addPending("cd".repeat(16), "G", C, [C, v.own]);
    v.GroupStore.accept("cd".repeat(16));
    v.page._leaveGroup("cd".repeat(16));
    assert.equal(v.confirms.at(-1), LEAVE_DEVICE);
});

test("§19.2 (web): the 0xD1 name of a D-group envelope is decided under (D, member) and confirmed only on a direct fulfilment", async () => {
    const { u, c, m, D, Did, net, id } = await dPending({ name: "Ann" });
    u.ContactStore.get(m.own).isDistro = true;                 // M is reached only by propagation
    // The device already gave C its name: that says nothing of D.
    const now = Math.floor(Date.now() / 1000);
    u.NameLedgerStore.recordDelivered(u.own, c.own, u.self._decideMessageName(u.own, c.own), now);
    const deviceRow = u.NameLedgerStore.lookup(u.own, c.own);
    assert.ok(deviceRow);
    u.page._acceptGroupInvite(id);
    await settle();
    const toC = u.decoded(0, Did).find((s) => s.to === c.own).message;
    assert.ok(toC.fields.get(0xD1)?.get(0), "the name goes to C: decided under (D, C), where nothing was confirmed");
    assert.equal(u.NameLedgerStore.lookup(D, c.own), null, "not confirmed before delivery");
    await net.pump(u, { to: c });                              // C proves it directly
    assert.ok(u.NameLedgerStore.lookup(D, c.own), "confirmed under (D, C) on the direct proof");
    assert.deepEqual(u.NameLedgerStore.lookup(u.own, c.own), deviceRow, "the device's row is untouched");
    assert.equal(u.NameLedgerStore.lookup(D, m.own), null, "a propagated copy confirms nothing");
});

test("§19.2: a member that is a distro gets the envelope propagated at once: no link, no 5 s direct attempt first", async () => {
    const { u, c, m, Did, id } = await dPending();
    u.ContactStore.get(m.own).isDistro = true;
    u.page._acceptGroupInvite(id);
    await settle();
    assert.deepEqual(u.propagated.map((p) => p.to), [m.own], "propagated at once");
    assert.equal(u.sent.some((s) => s.to === m.own && s.via !== "propagation"), false, "no link to it");
    assert.equal(u.fallbacks.includes(m.own), false, "no 5 s fallback armed for it");
    assert.ok(u.sent.some((s) => s.to === c.own), "a member that is no distro is reached as before");
    const p = LXMessage.fromBytes(u.propagated[0].bytes.subarray(16), u.propagated[0].bytes.subarray(0, 16), () => Did);
    assert.equal(p.signatureValidated, true);
});

test("§12: a creator that is D answers a keyed accept with a status sent as D, from a device of D", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const a = groupClient(), b = groupClient();
    u.know(a).know(b).reachable(a.own, b.own);
    const { group } = u.self.createGroup("G", [a.own, b.own]);
    await settle();
    const from = u.sent.length;
    const delivery = await Promise.race([u.self.sendGroupStatus(group.groupId, a.own), settle().then(() => "pending")]);
    assert.notEqual(delivery, null, "the creator D answers");
    await settle();
    const status = u.decoded(from, Did);
    assert.deepEqual(status.map((s) => s.to), [a.own]);
    assert.equal(hex(status[0].message.sourceHash), D);
    assert.equal(decodeFields(status[0].message).groupAction, "status");
    assert.equal(decodeFields(status[0].message).groupSender, D);
});

test("§9.2: \"You\" is every self address of the group shown: D and a known sibling in a D-group, the device elsewhere", async () => {
    const { u, D, S, m, id } = await dPending({ sibling: true });
    const page = { state: { groupInfoId: id } };
    const label = compile("_groupMemberLabel(hash)", {
        GroupStore: u.GroupStore, RnsClient: u.self, ContactStore: u.ContactStore, ownLxmfDestinationHash: () => u.own,
    })(page);
    assert.equal(label(D), "You");
    assert.equal(label(S), "You");
    assert.equal(label(u.own), "You");
    assert.notEqual(label(m.own), "You");
    page.state.groupInfoId = null;
    assert.equal(label(u.own), "You");
    assert.notEqual(label(D), "You", "outside a group that lists it, D is not shown as the user");
});

test("wiring: every group send resolves its signer through _groupSigner at send time, and nothing in group code signs with sendingIdentity() or captures the router's source", () => {
    for (const sig of ["async sendGroupInvites(groupId, groupName, memberHashes)", "async sendGroupAccept(groupId)", "async sendGroupLeave(groupId)",
        "async sendGroupStatus(groupId, memberHash)", "async _dispatchGroupMessage(groupId, outMsg)"]) {
        const body = methodBody(sig);
        assert.match(body, /this\._groupSigner\(/, `${sig} resolves its signer`);
        assert.doesNotMatch(body, /sendingIdentity\(\)/, `${sig} never uses the fallback helper`);
    }
    assert.doesNotMatch(methodBody("async _sendGroupEnvelope(memberHash, content, fields, signer = null)"), /msg\.sourceHash = this\._lxmfRouter\.destination\.hash;/);
    assert.match(methodBody("_groupSigner(group)"), /this\._signerFor\(/, "groupSigner is _signerFor(ownMember)");
});

// ═══ §6: inbound on the distro path ═══════════════════════════════════════

test("§19.2: an invite to D (the filter allows the inviter) becomes a pending group, own entry D, keyed by its LXMF hash; no DM, no visible or allowlisted contact, no DM notification", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const c = groupClient();
    const m = groupClient();
    c.know(m).know(Did).reachable(D, m.own);
    const net = network(u, c, m);
    const notes = notified(u);
    const group = c.GroupStore.create("G", [m.own, D]);
    void c.self.sendGroupInvites(group.groupId, "G", [m.own, D]);
    await net.pump(c, { to: D });
    const id = group.groupId;
    const held = u.GroupStore.get(id);
    assert.equal(held?.groupStatus, "pending", "a pending group");
    assert.equal(held.ownMember, D);
    assert.equal(held.creator, c.own);
    const invites = c.sent.filter((s) => s.to === D);
    assert.ok(invites.length > 1, "a web inviter sends its invite in chunks, one key each");
    assert.deepEqual(u.distroKept, invites.map(() => true), "every chunk is kept");
    assert.deepEqual(u.MsgStore.get(c.own), [], "no DM");
    const row = u.ContactStore.get(c.own);
    assert.deepEqual([row?.hidden, u.ContactStore.allowlisted(c.own), u.ContactStore.listed().length], [true, false, 0], "the inviter's name row only: hidden, not allowlisted");
    assert.equal(notes.some(([conv]) => conv === c.own), false, "no DM notification");
    assert.ok(notes.some(([conv]) => conv === id), "the group's own invite notice");
    for (const invite of invites) assert.equal(u.DistroSeen._keys.has(`grp:${packingHash(invite.bytes)}`), true, "kept: recorded under grp:<hash>");
});

test("§19.2: a member's accept via D carrying a 0xD1 name shows that name in the member list and counts the member", async () => {
    const { u, c, m, D, net, id } = await viaD();
    u.page._acceptGroupInvite(id);
    await net.pump(u);
    m.page._acceptGroupInvite(id);
    await net.pump(m, { to: D });
    assert.equal(u.status(id, m.own), "accepted", "counted from the accept that reached D");
    assert.equal(u.ContactStore.get(m.own).messageName, "Emm", "the name row holds its 0xD1 name");
    assert.deepEqual(u.MsgStore.get(m.own), [], "no DM");
    assert.equal(u.ContactStore.get(m.own).hidden, true);
    assert.equal(c.status(id, D), "accepted");
});

test("§19.2: N invite chunks with one src:ts (a web sender, one millisecond) all reach the group handler through D; every member key is remembered", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const c = Identity.create();
    const C = lxmfHash(c);
    u.know({ own: C, pubKey: c.getPublicKey().toString("hex") });
    const others = Array.from({ length: 4 }, () => Identity.create());
    const listed = [C, D, ...others.map(lxmfHash)];
    const id = "5".repeat(32);
    const keyOf = (i) => `${lxmfHash(i)}:${Buffer.from(i.getPublicKey()).toString("base64")}`;
    const timestamp = 1_790_000_000.123;
    for (const pair of [others.slice(0, 2), others.slice(2)]) {
        const fields = oldFields({ id, members: listed.join(","), name: "Chunks", action: "invite", sender: C, keys: pair.map(keyOf).join(",") });
        await u.receiveDistro(lxm(c, D, "", fields, { timestamp }));
    }
    assert.deepEqual(u.distroKept, [true, true], "neither is taken for a repeat of the other");
    for (const o of others) assert.equal(u.ContactStore.get(lxmfHash(o))?.publicKey, o.getPublicKey().toString("hex"), "each chunk's keys are kept");
    assert.equal(u.GroupStore.get(id)?.groupStatus, "pending");
});

test("§19.2: a GROUP_ID that is an int on the distro path is dropped in the group branch, never a DM, and is not recorded as seen", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const x = Identity.create();
    const X = lxmfHash(x);
    u.know({ own: X, pubKey: x.getPublicKey().toString("hex") });
    const notes = notified(u);
    await u.receiveDistro(lxm(x, D, "hello", new Map([[GROUP_FIELDS.GROUP_ID, 12345]])));
    assert.deepEqual(u.distroKept, [false]);
    assert.deepEqual(u.MsgStore.get(X), [], "no DM");
    assert.deepEqual(notes, []);
    assert.equal([...u.DistroSeen._keys].some((k) => k.startsWith(X)), false, "no src:ts key either");
});

test("§19.2: with the filter on, an invite to D from an inviter it does not allow is ignored, its id enters the filtered-invite set, and its group's traffic is never held", async () => {
    const { u, c, m, D, net, id } = await viaD({ filter: true });
    assert.equal(u.GroupStore.get(id), null, "no group");
    assert.ok(u.distroKept.length > 0 && u.distroKept.every((k) => k === false), "every chunk dropped");
    const dropped = u.distroKept.length;
    assert.deepEqual(u.MsgStore.get(c.own), [], "no DM");
    assert.equal(u.FilteredInvitesStore.has(id), true);
    // M accepts: its accept reaches D, proven (its key is carried), and is not held.
    m.page._acceptGroupInvite(id);
    await net.pump(m, { to: D });
    assert.deepEqual(u.HeldGroupArrivalsStore.list(), [], "nothing held for a filtered group");
    assert.deepEqual(u.distroKept.slice(dropped), [false], "the accept reached D, and was dropped");
    // The same with the filter off (or C allowed): pending, nothing filtered.
    const open = await viaD({ filter: true, allow: true });
    assert.equal(open.u.GroupStore.get(open.id)?.groupStatus, "pending");
    assert.equal(open.u.FilteredInvitesStore.has(open.id), false);
});

test("§19.2: a post naming the user as its sender from someone else is dropped, never stored as the user's own: GROUP_SENDER D via D, GROUP_SENDER the device on the direct path", async () => {
    const { u, m, D, id } = await dPending();
    u.page._acceptGroupInvite(id);
    u.GroupStore.updateMember(id, m.own, "accepted");
    const notes = notified(u);
    await u.receiveDistro(lxm(m.me, D, "I am you", oldFields({ id, sender: D })));
    assert.deepEqual(u.distroKept, [false]);
    assert.equal(u.GroupMsgStore.get(id).some((x) => x.content === "I am you"), false, "via D: not stored, in or out");
    // The direct path, in a group listing the device.
    const H = "6".repeat(32);
    u.GroupStore.addPending(H, "H", m.own, [m.own, u.own]);
    u.GroupStore.accept(H);
    await u.receive(lxm(m.me, u.me, "I am you too", oldFields({ id: H, sender: u.own })));
    assert.equal(u.GroupMsgStore.get(H).some((x) => x.content === "I am you too"), false, "direct: not stored, in or out");
    assert.deepEqual(notes.filter(([conv]) => conv === id || conv === H), []);
    // M's own post still is M's, both ways.
    await u.receiveDistro(lxm(m.me, D, "M's own", oldFields({ id })));
    assert.deepEqual(u.GroupMsgStore.get(id).filter((x) => x.dir !== "system").map((x) => [x.content, x.dir, x.srcHash]), [["M's own", "in", m.own]]);
});

test("§19.2: a post claiming member M2's source with an invalid signature is not stored and not notified, via D and on the direct path", async () => {
    const { u, m, D, id } = await dPending();
    u.page._acceptGroupInvite(id);
    const attacker = Identity.create();
    const notes = notified(u);
    await u.receiveDistro(lxm(m.own, D, "forged", oldFields({ id }), { signer: attacker }));
    assert.deepEqual(u.distroKept, [false]);
    const H = "7".repeat(32);
    u.GroupStore.addPending(H, "H", m.own, [m.own, u.own]);
    u.GroupStore.accept(H);
    await u.receive(lxm(m.own, u.me, "forged too", oldFields({ id: H }), { signer: attacker }));
    assert.equal(u.GroupMsgStore.get(id).some((x) => x.content === "forged"), false);
    assert.equal(u.GroupMsgStore.get(H).some((x) => x.content === "forged too"), false);
    assert.deepEqual(notes, [], "no notification");
    assert.deepEqual(u.HeldGroupArrivalsStore.list(), [], "never held");
});

test("§6.3: a group message from D itself is the user's own echo, dropped; a relay request reaching D is acted on by no device", async () => {
    const { u, m, D, Did, id } = await dPending();
    u.page._acceptGroupInvite(id);
    u.GroupStore.updateMember(id, m.own, "accepted");
    await settle();
    const from = u.sent.length;
    await u.receiveDistro(lxm(Did, D, "echo", oldFields({ id })));
    await u.receiveDistro(lxm(m.me, D, "relay this", oldFields({ id, action: "relay_req", sender: m.own })));
    assert.deepEqual(u.distroKept, [false, false]);
    assert.equal(u.GroupMsgStore.get(id).some((x) => x.content === "echo" || x.content === "relay this"), false);
    assert.equal(u.sent.length, from, "nothing relayed, no relay_done");
    assert.equal([...u.DistroSeen._keys].some((k) => k.startsWith("grp:")), false, "a dropped group message is not recorded as seen (§6.2)");
    // On the distro path D is the user's in any group: a group listing the
    // device (not D) takes a message from D as the user's own echo too.
    const H = "9".repeat(31) + "a";
    u.GroupStore.addPending(H, "H", m.own, [m.own, u.own]);
    u.GroupStore.accept(H);
    await u.receiveDistro(lxm(Did, D, "echo in H", oldFields({ id: H })));
    assert.equal(u.distroKept.at(-1), false);
    assert.equal(u.GroupMsgStore.get(H).some((x) => x.content === "echo in H"), false, "never shown as a post from D");
});

test("§19.2: a creator's status reaching a device of D where the group is pending is held, not dropped, and applied after the user's accept there, not as a repeat", async () => {
    const { us: [u1, u2], c, m, D, net, id } = await viaD({ devices: 2 });
    assert.deepEqual([u1, u2].map((u) => u.GroupStore.get(id)?.groupStatus), ["pending", "pending"]);
    // M accepts; its accept to D is lost. C counts it and holds M's copy.
    m.page._acceptGroupInvite(id);
    net.drop(m, { to: D });
    await net.pump(m, { to: c });
    // The user accepts on u1: C answers D with a status carrying M's element.
    u1.page._acceptGroupInvite(id);
    await net.pump(u1, { to: c });
    await net.pump(c, { to: D });
    assert.equal(u1.status(id, m.own), "accepted", "u1, joined, applies it");
    assert.equal(u2.status(id, m.own), "invited", "u2, pending, has not");
    assert.equal(u2.HeldGroupArrivalsStore.forGroup(id).length, 1, "held");
    assert.equal(u2.distroKept.at(-1), true, "held is kept here (the rfed.link answer)");
    const [status] = c.sent.filter((s) => s.to === D && decodeFields(LXMessage.fromBytes(s.bytes.subarray(16), s.bytes.subarray(0, 16), () => null)).groupAction === "status");
    const key = `grp:${packingHash(status.bytes)}`;
    assert.equal(u2.DistroSeen._keys.has(key), false, "a held message is not recorded as seen");
    // The user accepts on u2 too: what was held is judged again, and applied.
    u2.page._acceptGroupInvite(id);
    await settle();
    assert.equal(u2.status(id, m.own), "accepted", "applied after the accept");
    assert.deepEqual(u2.HeldGroupArrivalsStore.list(), [], "released");
    assert.equal(u2.DistroSeen._keys.has(key), true, "recorded once kept");
});

test("§19.2: 64 proven group messages from strangers for random group ids never push out a held creator status; a forged or self-source message, or an unproven one for a group not held here, is never held", async () => {
    const { us: [u1, u2], c, m, D, Did, net, id } = await viaD({ devices: 2 });
    m.page._acceptGroupInvite(id);
    net.drop(m, { to: D });
    await net.pump(m, { to: c });
    u1.page._acceptGroupInvite(id);
    await net.pump(u1, { to: c });
    await net.pump(c, { to: D });
    assert.equal(u2.HeldGroupArrivalsStore.forGroup(id).length, 1);
    for (let i = 0; i < 64; i++) {
        const s = Identity.create();
        u2.know({ own: lxmfHash(s), pubKey: s.getPublicKey().toString("hex") });
        await u2.receiveDistro(lxm(s, D, `stranger ${i}`, oldFields({ id: (0x1000 + i).toString(16).padStart(32, "0") })));
    }
    assert.equal(u2.HeldGroupArrivalsStore.forGroup(id).length, 1, "the status is still held");
    assert.equal(u2.HeldGroupArrivalsStore.list().filter((r) => !r.pending).length, 16, "groups not held here: 16 in all");
    const before = u2.HeldGroupArrivalsStore.list().length;
    await u2.receiveDistro(lxm(m.own, D, "forged", oldFields({ id }), { signer: Identity.create() }));
    await u2.receiveDistro(lxm(Did, D, "self", oldFields({ id, action: "accept", sender: D })));
    // For a group not held here only a proven message is held: one from a
    // source whose key is not here (unverifiable) is not.
    await u2.receiveDistro(lxm(Identity.create(), D, "unproven", oldFields({ id: "a".repeat(32) })));
    assert.equal(u2.HeldGroupArrivalsStore.list().length, before, "none of them is held");
    assert.deepEqual(u2.distroKept.slice(-3), [false, false, false]);
    u2.page._acceptGroupInvite(id);
    await settle();
    assert.equal(u2.status(id, m.own), "accepted");
});

test("§19.2: an older sibling's post (packet source a known sibling, validated) in a D-group is stored as the user's own outgoing post, SENT, with no notification", async () => {
    const { u, D, S, Sid, id } = await dPending({ sibling: true });
    u.page._acceptGroupInvite(id);
    u.know(Sid);
    const notes = notified(u);
    await u.receiveDistro(lxm(Sid, D, "from my old phone", oldFields({ id })));
    assert.deepEqual(u.distroKept, [true]);
    const [post] = u.GroupMsgStore.get(id).filter((x) => x.content === "from my old phone");
    assert.deepEqual([post?.dir, post?.status, post?.srcHash], ["out", "sent", S]);
    assert.equal(notes.every(([, msg]) => msg?.dir === "out"), true, "shown, never notified as a member's post");
    // A source that is no address of the user's is someone else's post.
    const stranger = Identity.create();
    u.know(stranger);
    await u.receiveDistro(lxm(stranger, D, "not the user", oldFields({ id })));
    assert.equal(u.GroupMsgStore.get(id).find((x) => x.content === "not the user")?.dir, "in");
});

test("§6.3, §9.3: an invite reaching D whose list does not name D is not for the user there, though it lists this device", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const c = Identity.create();
    const C = lxmfHash(c);
    u.know({ own: C, pubKey: c.getPublicKey().toString("hex") });
    const id = "8".repeat(32);
    await u.receiveDistro(lxm(c, D, "", oldFields({ id, members: [C, u.own].join(","), name: "Not D", action: "invite", sender: C })));
    assert.deepEqual(u.distroKept, [false]);
    assert.equal(u.GroupStore.get(id), null, "no group");
    assert.deepEqual(u.MsgStore.get(C), [], "no DM");
});

test("§9.2, §12: a creator that is D counts a known sibling's keyed accept reaching D as the user's own, and sends no status to it; a member's keyed accept is answered", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const Sid = Identity.create();
    const S = lxmfHash(Sid);
    const a = groupClient();
    u.KnownSiblingsStore.add(D, S);
    u.know(a).know(Sid).reachable(a.own, S);
    const { group } = u.self.createGroup("G", [a.own, S]);
    const id = group.groupId;
    await settle();
    const keyed = (who, W) => oldFields({ id, action: "accept", sender: W, keys: `${W}:${Buffer.from(who.getPublicKey()).toString("base64")}` });
    const from = u.sent.length;
    await u.receiveDistro(lxm(Sid, D, "", keyed(Sid, S)));
    await settle();
    assert.equal(u.status(id, S), "accepted", "counted: an older device of the user accepted as its own entry");
    assert.equal(u.sent.slice(from).some((s) => s.to === S), false, "no status to a self address");
    await u.receiveDistro(lxm(a.me, D, "", keyed(a.me, a.own)));
    await settle();
    assert.deepEqual(u.decoded(from, Did).map((s) => [s.to, decodeFields(s.message).groupAction]), [[a.own, "status"]], "the member is answered");
});
