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
import { app, compile, methodBody } from "./test_app_source.mjs";
import { groupClient, network, settle, lxmfHash, lxm, oldFields, Identity, LXMessage, GROUP_FIELDS } from "./test_group_net.mjs";
import { groupSyncFields } from "./lib/group_sync.js";
import LXMF from "./lib/rns/lxmf/lxmf.js";

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

// ═══ §10, §11, §12: the group sync G ═════════════════════════════════════

/** A group sync G of D's (`Did`) from device `dev`, packed as a sibling
 *  packs it: source D, signed by D unless `signer` or `from` say otherwise. */
const G = (Did, dev, sync, { signer = Did, from = Did } = {}) =>
    lxm(from, lxmfHash(Did), "", groupSyncFields({ left: [], ...sync }, lxmfHash(Did), dev), { signer, timestamp: Date.now() / 1000 });

/** The §10.1 sync an owed G entry carries, read as a sibling reads it. */
const readG = (entry, D) => LXMF.distroGroupSyncFromPayload(Buffer.from(entry.packed, "base64").subarray(96), D);

/** A GROUP_MEMBER_KEYS entry for identity `who` (§10.2). */
const keyEntry = (who) => `${lxmfHash(who)}:${Buffer.from(who.getPublicKey()).toString("base64")}`;

/** Two devices of D, u1 and u2, that both hold C's invite to D pending
 *  (viaD), with M on the list. */
const twoPending = () => viaD({ devices: 2 });

/** u1 and u2 hold group(s) u1 created as D, listing a member A, after the
 *  create syncs reached u2. */
async function created(names = ["Y"]) {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u1 = groupClient({ distro: Did }), u2 = groupClient({ distro: Did });
    const a = groupClient();
    for (const u of [u1, u2]) u.know(a).reachable(a.own);
    a.know(Did).reachable(D);
    const net = network(u1, u2, a);
    const ids = names.map((name) => u1.self.createGroup(name, [a.own]).group.groupId);
    await net.syncs(u1);
    return { u1, u2, a, D, Did, net, ids };
}

test("§19.2: a D-group post owes one post G (and no §17.11 copy) once its fan-out is submitted; the siblings show it as the user's own, SENT; a post whose send throws owes nothing", async () => {
    const { us: [u1, u2], m, D, net, id } = await twoPending();
    u1.page._acceptGroupInvite(id);
    await net.syncs(u1);
    u1.GroupStore.updateMember(id, m.own, "accepted");
    void u1.self.sendGroupMessage(id, "hello all");
    await settle();
    const posts = u1.owed.filter((e) => e.op === "post");
    assert.equal(posts.length, 1, "one post G");
    assert.deepEqual([posts[0].kind, posts[0].distro, posts[0].groupId], ["group", D, id]);
    assert.match(posts[0].id, /^group:[0-9a-f]{64}$/, "owed on its own, under its LXMF hash");
    assert.deepEqual(u1.owed.map((e) => e.kind), ["group", "group"], "the accept and the post: no sent-copy");
    await net.syncs(u1);
    const [shown] = u2.GroupMsgStore.get(id).filter((x) => x.content === "hello all");
    assert.deepEqual([shown?.dir, shown?.status, shown?.srcHash, shown?.id], ["out", "sent", D, posts[0].id.slice("group:".length)]);
    assert.equal(u1.GroupMsgStore.get(id).filter((x) => x.content === "hello all").length, 1, "u1's own echo stores nothing more");
    // A send that throws before its fan-out is submitted owes nothing.
    const owedBefore = u1.owed.length;
    u1.self._fanoutGroupEnvelope = () => { throw new Error("the fan-out could not start"); };
    await assert.rejects(u1.self.sendGroupMessage(id, "never left"));
    assert.equal(u1.owed.length, owedBefore, "no G for a send that threw");
});

test("§19.2, §11.2: an accept G joins a sibling's matching pending invite, and a leave in a D-group sends one leave as D and owes one leave G, which closes and removes the group on the siblings, sending nothing", async () => {
    const { us: [u1, u2], c, m, D, Did, net, id } = await twoPending();
    m.page._acceptGroupInvite(id);
    await net.pump(m);
    assert.equal(u2.status(id, m.own), "accepted", "M's own accept counts on u2 while pending");
    const pendingLines = u2.GroupMsgStore.get(id).map((x) => x.id);
    assert.ok(u2.GroupMsgStore.get(id).some((x) => x.actor === c.own), "C's invite line");
    u1.page._acceptGroupInvite(id);
    const sentBefore = u2.sent.length;
    await net.syncs(u1);
    assert.deepEqual([u2.GroupStore.get(id)?.groupStatus, u2.status(id, D), u2.GroupStore.get(id)?.creator], ["active", "accepted", c.own], "joined as is");
    assert.equal(u2.status(id, m.own), "accepted", "the invite joined as is, never replaced: M's accept still counts");
    assert.ok(pendingLines.every((x) => u2.GroupMsgStore.get(id).some((y) => y.id === x)), "and its conversation is kept");
    assert.equal(u2.ContactStore.allowlisted(m.own), true, "the members pass the filter by association");
    assert.equal(u2.sent.length, sentBefore, "joined without sending anything");
    assert.equal(u2.KnownSiblingsStore.has(D, u1.own), true, "u1 is a known sibling now (§9.1)");
    const from = u1.sent.length;
    u1.page._leaveGroup(id);
    await settle();
    const leaves = u1.decoded(from, Did).filter((s) => decodeFields(s.message)?.groupAction === "leave");
    assert.deepEqual(leaves.map((s) => s.to).sort(), [c.own, m.own].sort(), "one leave, as D, to each member");
    assert.deepEqual(u1.owed.filter((e) => e.op === "leave").map((e) => e.groupId), [id], "one leave G");
    await net.syncs(u1);
    assert.equal(u2.GroupStore.get(id), null, "removed on the sibling");
    assert.equal(u2.GroupStore.isClosed(id), true, "closed for good");
    assert.deepEqual(u2.GroupMsgStore.get(id), [], "its messages too");
    assert.equal(u2.sent.length, sentBefore, "and nothing was sent from there");
    assert.deepEqual(u2.DistroLeftStore.of(D), [id], "on u2's own left list for D");
});

test("§19.2: group sync rules: a source not D, or a forged signature, is dropped; the own echo is recorded; a later accept after a leave never reopens; a leave for a group not held blocks a later invite; a G for a group held as the device is ignored", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const other = groupClient({ distro: Did });
    const m = Identity.create();
    const M = lxmfHash(m);
    const X = "c".repeat(32);
    const create = { op: "create", group_id: X, at_ms: 1000, name: "X", members: [M, D].join(","), keys: [] };
    // Rule 1: source not D.
    await u.receiveDistro(G(Did, other.own, create, { from: m, signer: m }));
    // Rule 2: source D, signed by someone else.
    await u.receiveDistro(G(Did, other.own, create, { signer: Identity.create() }));
    assert.deepEqual(u.distroKept, [false, false]);
    assert.deepEqual(u.events.filter((e) => e.kind === "distro-group-sync").map((e) => e.detail.rule), [1, 2], "each by its own rule");
    assert.equal(u.GroupStore.get(X), null, "nothing held from either");
    assert.equal([...u.DistroSeen._keys].some((k) => k.startsWith("gsync:")), false, "neither is recorded as seen");
    // Rule 3: this device's own G: kept, recorded, nothing applied.
    const echo = G(Did, u.own, create);
    await u.receiveDistro(echo);
    assert.deepEqual([u.distroKept.at(-1), u.GroupStore.get(X)], [true, null]);
    assert.equal(u.DistroSeen._keys.has(`gsync:${packingHash(echo)}`), true);
    // A leave, then a later-stamped accept: still closed.
    await u.receiveDistro(G(Did, other.own, create));
    assert.equal(u.GroupStore.get(X)?.groupStatus, "active", "held from the create");
    await u.receiveDistro(G(Did, other.own, { op: "leave", group_id: X, at_ms: 2000 }));
    await u.receiveDistro(G(Did, other.own, { op: "accept", group_id: X, at_ms: 9000, name: "X", members: [M, D].join(","), keys: [], creator: M }));
    assert.deepEqual([u.GroupStore.get(X), u.GroupStore.isClosed(X)], [null, true], "a leave is final, whatever the time");
    // A post G for a group closed here is dropped, and not recorded as seen.
    const late = G(Did, other.own, { op: "post", group_id: X, at_ms: 9500, text: "after the leave" });
    await u.receiveDistro(late);
    assert.deepEqual([u.distroKept.at(-1), u.GroupMsgStore.get(X), u.HeldGroupArrivalsStore.forGroup(X)], [false, [], []]);
    assert.equal(u.DistroSeen._keys.has(`gsync:${packingHash(late)}`), false);
    // A leave for a group not held here blocks a later invite.
    const Y = "d".repeat(32);
    await u.receiveDistro(G(Did, other.own, { op: "leave", group_id: Y, at_ms: 1 }));
    assert.equal(u.GroupStore.isClosed(Y), true, "a tombstone");
    u.know({ own: M, pubKey: m.getPublicKey().toString("hex") });
    await u.receiveDistro(lxm(m, D, "", oldFields({ id: Y, members: [M, D].join(","), name: "Y", action: "invite", sender: M })));
    assert.equal(u.GroupStore.get(Y), null, "the invite is dropped");
    // Rule 5: a group held here as the device.
    const H = "e".repeat(32);
    u.GroupStore.addPending(H, "H", M, [M, u.own, D]);
    await u.receiveDistro(G(Did, other.own, { op: "leave", group_id: H, at_ms: 3 }));
    assert.equal(u.GroupStore.get(H)?.groupStatus, "pending", "ignored: the user acts as the device there");
    // `left` naming it, on a G that passes rules 0-4: still not touched.
    await u.receiveDistro(G(Did, other.own, { op: "leave", group_id: "a".repeat(32), at_ms: 4, left: [H] }));
    assert.deepEqual([u.GroupStore.get(H)?.groupStatus, u.GroupStore.isClosed(H)], ["pending", false], "a group held as the device is not closed by `left`");
});

test("§19.2 (squat): a pending invite from M for id X, then an accept G for X from creator C: M's invite is discarded with nothing sent, the group is held from G with creator C and C's list; nothing ever goes to M's extra member", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u1 = groupClient({ distro: Did });
    const u2 = groupClient({ distro: Did, filter: true });
    const c = groupClient(), m = groupClient();
    const M3 = lxmfHash(Identity.create());
    for (const x of [u1, u2, c, m]) for (const y of [u1, u2, c, m]) if (x !== y) x.reachable(y.own);
    for (const x of [u1, u2, c, m]) x.reachable(D);
    c.know(m).know(Did);
    for (const u of [u1, u2]) u.know(c).know(m);
    u2.ContactStore.allow(m.own);                    // u2's filter lets M invite, not C
    const net = network(u1, u2, c, m);
    const group = c.GroupStore.create("G", [m.own, D]);
    const X = group.groupId;
    void c.self.sendGroupInvites(X, "G", [m.own, D]);
    await net.pump(c, { to: D });
    assert.deepEqual([u1.GroupStore.get(X)?.groupStatus, u2.GroupStore.get(X), u2.FilteredInvitesStore.has(X)], ["pending", null, true]);
    // M's own invite for X, listing M3, reaches D.
    await u2.receiveDistro(lxm(m.me, D, "", oldFields({ id: X, members: [m.own, D, M3].join(","), name: "G", action: "invite", sender: m.own })));
    assert.equal(u2.GroupStore.get(X)?.creator, m.own, "u2 holds M's version, pending");
    assert.ok(u2.GroupMsgStore.get(X).some((x) => x.actor === m.own), "with M's invite line");
    const sentBefore = u2.sent.length;
    u1.page._acceptGroupInvite(X);
    await net.syncs(u1);
    const held = u2.GroupStore.get(X);
    assert.deepEqual([held?.groupStatus, held?.creator, held?.ownMember], ["active", c.own, D], "held from G, creator C");
    assert.deepEqual([...held.members.keys()].sort(), [c.own, m.own, D].sort(), "C's list: M3 is not on it");
    assert.equal(u2.sent.length, sentBefore, "the discard sent nothing (no decline to M's list)");
    assert.equal(u2.GroupMsgStore.get(X).some((x) => x.actor === m.own), false, "M's version is discarded with its conversation");
    assert.equal(u2.FilteredInvitesStore.has(X), false, "the id left the filtered-invite set");
    u2.GroupStore.updateMember(X, m.own, "accepted");
    void u2.self.sendGroupMessage(X, "to C's group");
    await settle();
    assert.equal(u2.sent.slice(sentBefore).some((s) => s.to === M3), false, "nothing goes to M3, then or after a post");
});

test("§19.2: a create G applied lets the members pass the filter by association, never a self address; the creator is D, and the sender is learned as a sibling", async () => {
    const { u2, a, D, u1, ids: [Y] } = await created();
    const g = u2.GroupStore.get(Y);
    assert.deepEqual([g?.groupStatus, g?.creator, g?.ownMember], ["active", D, D]);
    assert.equal(u2.ContactStore.allowlisted(a.own), true);
    assert.deepEqual([u2.ContactStore.get(D), u2.ContactStore.get(u1.own)], [null, null], "D and the sibling are no contacts");
    assert.equal(u2.KnownSiblingsStore.has(D, u1.own), true);
    assert.equal(u2.status(Y, a.own), "invited");
});

test("§19.2: `left`: a sibling still joined in Y receives a post G for Z carrying Y in left: Y is removed and closed there", async () => {
    const { u1, u2, a, D, Did, net, ids: [Y, Z] } = await created(["Y", "Z"]);
    u1.page._leaveGroup(Y);
    await net.syncs(u1, { skip: [u2] });             // u2 misses the leave G (a full queue)
    assert.equal(u2.GroupStore.get(Y)?.groupStatus, "active");
    u1.GroupStore.updateMember(Z, a.own, "accepted");
    void u1.self.sendGroupMessage(Z, "in Z");
    await settle();
    const [post] = u1.owed.filter((e) => e.op === "post");
    assert.ok(post, "a post G");
    await net.syncs(u1);
    assert.deepEqual([u2.GroupStore.get(Y), u2.GroupStore.isClosed(Y)], [null, true], "Y repaired by left");
    assert.ok(u2.GroupMsgStore.get(Z).some((x) => x.content === "in Z" && x.dir === "out"), "Z's post shown");
    assert.ok(u2.DistroLeftStore.of(D).includes(Y), "Y travels on in u2's own left list");
    // Each id other than the G's own group_id (§11.2).
    await u2.receiveDistro(G(Did, u1.own, { op: "post", group_id: Z, at_ms: Date.now(), text: "Z, in its own left", left: [Z] }));
    assert.deepEqual([u2.GroupStore.get(Z)?.groupStatus, u2.GroupStore.isClosed(Z)], ["active", false], "a G's own id in its left list closes nothing");
    assert.ok(u2.GroupMsgStore.get(Z).some((x) => x.content === "Z, in its own left"));
});

test("§19.2: a creator status and a post G held while pending are applied after the accept G, not dropped as repeats", async () => {
    const { us: [u1, u2], c, m, D, net, id } = await twoPending();
    m.page._acceptGroupInvite(id);
    net.drop(m, { to: D });
    await net.pump(m, { to: c });
    u1.page._acceptGroupInvite(id);
    await net.pump(u1, { to: c });
    await net.pump(c, { to: D });                    // the status: u2 still pending
    u1.GroupStore.updateMember(id, m.own, "accepted");
    void u1.self.sendGroupMessage(id, "early post");
    await settle();
    const [acceptG, postG] = u1.owed;
    assert.deepEqual([acceptG.op, postG.op], ["accept", "post"]);
    await u2.receiveDistro(Buffer.from(postG.packed, "base64"));   // the post G first
    assert.equal(u2.distroKept.at(-1), true, "held: kept here");
    assert.equal(u2.HeldGroupArrivalsStore.forGroup(id).length, 2, "the status and the post G");
    assert.equal(u2.DistroSeen._keys.has(`gsync:${packingHash(Buffer.from(postG.packed, "base64"))}`), false, "not recorded as seen");
    await u2.receiveDistro(Buffer.from(acceptG.packed, "base64"));
    assert.equal(u2.GroupStore.get(id)?.groupStatus, "active");
    assert.equal(u2.status(id, m.own), "accepted", "the status applied");
    assert.ok(u2.GroupMsgStore.get(id).some((x) => x.content === "early post" && x.dir === "out" && x.status === "sent"), "the post applied");
    assert.deepEqual(u2.HeldGroupArrivalsStore.list(), [], "nothing left held");
});

test("§19.2, §12: creator D on two devices: both answer a keyed accept with a status as D; after the leave, neither answers", async () => {
    const { u1, u2, a, D, Did, net, ids: [Y] } = await created();
    await net.pump(u1, { to: a });                   // u1's invites reach A
    a.page._acceptGroupInvite(Y);
    const [b1, b2] = [u1.sent.length, u2.sent.length];
    await net.pump(a, { to: D });
    const statuses = (u, from) => u.decoded(from, Did).filter((s) => decodeFields(s.message)?.groupAction === "status").map((s) => s.to);
    assert.deepEqual([statuses(u1, b1), statuses(u2, b2)], [[a.own], [a.own]], "each device of D answers");
    u1.page._leaveGroup(Y);
    await net.syncs(u1);
    assert.equal(u2.GroupStore.get(Y), null);
    const [c1, c2] = [u1.sent.length, u2.sent.length];
    const keyed = oldFields({ id: Y, action: "accept", sender: a.own, keys: `${a.own}:${Buffer.from(a.me.getPublicKey()).toString("base64")}` });
    await u1.receiveDistro(lxm(a.me, D, "", keyed));
    await u2.receiveDistro(lxm(a.me, D, "", keyed));
    assert.deepEqual([statuses(u1, c1), statuses(u2, c2)], [[], []], "a device that applied D's leave answers nothing");
});

test("§9.1: a sent-copy's 0xFD teaches a sibling; giving D up forgets what was held for it and the siblings of a distro no group uses", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = groupClient({ distro: Did });
    const S = lxmfHash(Identity.create());
    const R = lxmfHash(Identity.create());
    const copy = new Map([[LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_SENT_TYPE], [LXMF.FIELD_CUSTOM_DATA, R], [LXMF.FIELD_CUSTOM_META, S]]);
    await u.receiveDistro(lxm(Did, D, "sent elsewhere", copy));
    assert.equal(u.KnownSiblingsStore.has(D, S), true, "learned from a §17.11 copy");
    // Something held for a group not held here, then D given up.
    const x = Identity.create();
    u.know({ own: lxmfHash(x), pubKey: x.getPublicKey().toString("hex") });
    await u.receiveDistro(lxm(x, D, "early", oldFields({ id: "f".repeat(32) })));
    assert.equal(u.HeldGroupArrivalsStore.list().length, 1);
    u.self._onDistroChangedForGroups();
    assert.equal(u.HeldGroupArrivalsStore.list().length, 1, "D still held: what reached it stays held");
    u.self._learnDistroSibling(D, u.own, "a test");
    assert.equal(u.KnownSiblingsStore.has(D, u.own), false, "this device is never its own sibling");
    u.DistroManager.set(null);
    u.self._onDistroChangedForGroups();
    assert.deepEqual(u.HeldGroupArrivalsStore.list(), [], "forgotten with D");
    assert.deepEqual(u.KnownSiblingsStore.of(D), [], "no group uses D here: its siblings go");
});

test("§19.2: \"Delete from this device\" owes no G, and nothing is owed for a group whose own address is the device or on a device without D", async () => {
    const { u, D, Did, id } = await dPending();
    u.page._acceptGroupInvite(id);
    const owed = u.owed.length;
    assert.deepEqual(u.owed.map((e) => e.op), ["accept"]);
    u.DistroManager.set(Identity.create());           // D replaced: a former-D group
    u.page._deleteGroupFromDevice(id);
    assert.equal(u.owed.length, owed, "no G for the local delete");
    const plain = groupClient();
    const a = groupClient();
    plain.know(a).reachable(a.own);
    const { group } = plain.self.createGroup("P", [a.own]);
    plain.page._leaveGroup(group.groupId);
    assert.deepEqual(plain.owed, [], "no D: nothing owed");
    // A group held as the device, on a device that holds D: the user acts as the device there.
    const H = "b".repeat(32);
    u.DistroManager.set(Did);
    u.GroupStore.addPending(H, "H", a.own, [a.own, u.own]);
    const before = u.owed.length;
    u.page._declineGroupInvite(H);
    assert.deepEqual([u.owed.length, u.GroupStore.isClosed(H)], [before, true], "declined, and no G");
    void D;
});

test("§10.6: a G that cannot be owed is said and recorded, and the user's action goes on: the leave is sent and the group closed", async () => {
    const { u, c, Did, id } = await dPending();
    u.page._acceptGroupInvite(id);
    const errors = [];
    u.Harness.error = (kind, error) => errors.push([kind, error.message]);
    u.self._oweDistro = () => { throw new Error("storage is full"); };
    const from = u.sent.length;
    u.page._leaveGroup(id);
    await settle();
    assert.deepEqual(errors, [["distro-group-sync", "storage is full"]]);
    assert.equal(u.GroupStore.isClosed(id), true, "closed");
    assert.ok(u.decoded(from, Did).some((s) => s.to === c.own && decodeFields(s.message)?.groupAction === "leave"), "the leave went, as D");
});

test("§10.2: what a G carries: a create the csv its invites carried and the keys of the listed members this device holds; a post the time its message was stored, shown there on the sibling; a key a G gives for a member not listed is never kept", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u1 = groupClient({ distro: Did }), u2 = groupClient({ distro: Did });
    const a = groupClient();
    for (const u of [u1, u2]) u.know(a).reachable(a.own);
    const net = network(u1, u2, a);
    const from = u1.sent.length;
    const Y = u1.self.createGroup("Y", [a.own]).group.groupId;
    await settle();
    const carried = u1.decoded(from, Did).map((s) => decodeFields(s.message)?.membersCsv).find(Boolean);
    assert.ok(carried);
    const create = readG(u1.owed[0], D);
    assert.equal(create.op, "create");
    assert.equal(create.members, carried, "the csv exactly as its invites carried it");
    assert.deepEqual([...create.keys].sort(), [keyEntry(a.me), keyEntry(Did)].sort(), "A's key and D's own");
    // A post stored earlier (queued, say) and dispatched now: at the time it was stored.
    u1.GroupStore.updateMember(Y, a.own, "accepted");
    const early = u1.GroupMsgStore.add(Y, { dir: "out", content: "written earlier", status: "queued", waitFor: "init", srcHash: D, timestamp: 5000 });
    void u1.self._dispatchGroupMessage(Y, early);
    await settle();
    const post = readG(u1.owed.find((e) => e.op === "post"), D);
    assert.deepEqual([post.at_ms, post.text], [5000, "written earlier"]);
    await net.syncs(u1);
    assert.equal(u2.GroupMsgStore.get(Y).find((x) => x.content === "written earlier")?.timestamp, 5000, "shown at at_ms on the sibling");
    // Keys a create G gives: a listed member's is kept, one for a hash not listed is not.
    const b = Identity.create(), x = Identity.create();
    const Z = "9".repeat(32);
    await u2.receiveDistro(G(Did, u1.own, { op: "create", group_id: Z, at_ms: 1, name: "Z", members: [lxmfHash(b), D].join(","), keys: [keyEntry(b), keyEntry(x)] }));
    assert.equal(u2.GroupStore.get(Z)?.groupStatus, "active");
    assert.equal(u2.ContactStore.get(lxmfHash(b))?.publicKey, Buffer.from(b.getPublicKey()).toString("hex"), "the listed member's key");
    assert.equal(u2.ContactStore.get(lxmfHash(x))?.publicKey ?? null, null, "never a key for a hash the list does not name");
});

test("§11.2: an accept G that brings a member's key decides that member's accept held here for want of it (from the switch, when an accept that cannot be verified is held)", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u1 = groupClient({ distro: Did, switched: true }), u2 = groupClient({ distro: Did, switched: true });
    const c = groupClient(), m = groupClient();
    const all = [u1, u2, c, m];
    for (const p of all) for (const q of all) if (p !== q) p.reachable(q.own);
    for (const p of all) p.reachable(D);
    const net = network(...all);
    for (const u of [u1, u2]) u.know(c);
    u1.know(m);                                       // u1 holds M's key; u2 does not
    const id = "7".repeat(32);
    const invite = lxm(c.me, D, "", oldFields({ id, members: [c.own, m.own, D].join(","), name: "G", action: "invite", sender: c.own }));
    await u1.receiveDistro(invite);
    await u2.receiveDistro(invite);
    assert.deepEqual([u1.GroupStore.get(id)?.groupStatus, u2.GroupStore.get(id)?.groupStatus], ["pending", "pending"]);
    await u2.receiveDistro(lxm(m.me, D, "", oldFields({ id, action: "accept", sender: m.own })));
    assert.equal(u2.status(id, m.own), "invited", "M's accept is held: its key is not here");
    assert.deepEqual(u2.held(), [[m.own, "accept"]]);
    u1.page._acceptGroupInvite(id);
    await net.syncs(u1);
    assert.equal(u2.GroupStore.get(id)?.groupStatus, "active");
    assert.equal(u2.status(id, m.own), "accepted", "decided once the accept G brought M's key");
    assert.deepEqual(u2.held(), []);
});

test("§19.2: a post G for a group not joined here is held (pending: as a pending group's), never for a group whose invite the filter dropped; a decline G closes a pending group as a decline, forgets what was held for it and closes its open chat", async () => {
    const { us: [u1, u2], Did, net, id } = await twoPending();
    // A post G for a group not held here.
    const N = "5".repeat(32);
    await u2.receiveDistro(G(Did, u1.own, { op: "post", group_id: N, at_ms: 1, text: "elsewhere" }));
    assert.deepEqual([u2.distroKept.at(-1), u2.HeldGroupArrivalsStore.forGroup(N).map((r) => r.pending)], [true, [false]]);
    // One for a group whose invite this device's filter dropped.
    const F = "6".repeat(32);
    u2.FilteredInvitesStore.add(F);
    await u2.receiveDistro(G(Did, u1.own, { op: "post", group_id: F, at_ms: 1, text: "filtered" }));
    assert.deepEqual([u2.distroKept.at(-1), u2.HeldGroupArrivalsStore.forGroup(F)], [false, []], "dropped, never held");
    // One for the pending group.
    await u2.receiveDistro(G(Did, u1.own, { op: "post", group_id: id, at_ms: 1, text: "pending" }));
    assert.deepEqual(u2.HeldGroupArrivalsStore.forGroup(id).map((r) => r.pending), [true], "held as a pending group's");
    const notes = notified(u2);
    u1.page._declineGroupInvite(id);
    await net.syncs(u1);
    assert.deepEqual([u2.GroupStore.get(id), u2.GroupStore._closed.get(id)], [null, "rejected"], "closed as the local decline closes it");
    assert.deepEqual(u2.HeldGroupArrivalsStore.forGroup(id), [], "what was held for it goes");
    assert.deepEqual(notes.filter(([conv, msg]) => conv === id && msg?.kind === "group-left").map(([, msg]) => msg.synced), [true], "the page closes its chat if open");
});

test("wiring (§6.5, §9.1, §11.2): the distro changing runs what giving D up forgets; a group left on a sibling closes its open chat as a channel left there does", () => {
    assert.match(app, /\nDistroManager\.onChange\(\(\) => RnsClient\._onDistroChangedForGroups\(\)\);\n/);
    assert.match(app, /if \(\(msg\.kind === "channel-left" \|\| msg\.kind === "group-left"\) && msg\.synced\) \{\s*if \(inActiveChat\) \{\s*this\.state\.activeHash = null;/);
});
