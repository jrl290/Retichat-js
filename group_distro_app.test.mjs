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
import { groupClient, network, settle, lxmfHash, Identity, LXMessage } from "./test_group_net.mjs";

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
    const S = sibling ? lxmfHash(Identity.create()) : null;
    const all = [u, c, m];
    for (const x of all) for (const y of all) if (x !== y) x.reachable(y.own);
    u.reachable(D);
    c.know(m).know(Did);
    m.know(c);
    const net = network(...all);
    const listed = [m.own, D, ...(S ? [S] : [])];
    if (S) c.know({ own: S, pubKey: Identity.create().getPublicKey().toString("hex") });
    const group = c.GroupStore.create("G", listed);
    void c.self.sendGroupInvites(group.groupId, "G", listed);
    await net.pump(c, { to: m });
    // U, as the invite to D would leave it (§8.1, §9.3): pending, own address D.
    u.know(c).know(m);
    if (S) u.KnownSiblingsStore.add(D, S);
    u.GroupStore.addPending(group.groupId, "G", c.own, [c.own, ...listed], D);
    return { u, c, m, D, Did, S, net, id: group.groupId };
}

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
    assert.equal(u.sent.some((s) => s.to === m.own), false, "no link to it");
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
