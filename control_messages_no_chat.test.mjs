/**
 * OUR CONTROL MESSAGES NEVER MAKE A CHAT (James, 2026-10-24: "make sure that
 * none of our sync packets, none of our nickname packets, none of our group
 * status packets trigger the 'Tap to chat' row").
 *
 * The chat list's direct-message rows are ContactStore.chats over MsgStore
 * (_buildSidebarContent): a contact (a listed row), shown with "Tap to chat"
 * until it has a message, and a hidden row with direct-message records,
 * shown with its preview. A control message must make neither: no contact,
 * and no record in MsgStore. Here every kind our clients send runs through
 * the real receive paths, the direct one (the router's message handler) and
 * the Distro one (_handleDistroBlob), and after each step no client shows a
 * direct-message row or lists a contact:
 *   - Group actions: invites, accepts, the creator's statuses, a decline,
 *     posts, a status, a leave; with the privacy filter off and on;
 *   - the same with the Distro on two devices: the Distro Syncs of Group
 *     actions and the Distro Fanout of what members send to the Distro
 *     Address;
 *   - one-off control messages on the Distro path: a delivery notification
 *     nobody waits on, a reaction to a message not held, a Distro Sync of a
 *     send carrying only a reaction, Distro Syncs of a channel join and leave
 *     (usable and not), a Distro Sync of Group actions it cannot read, and a
 *     Distro message of a kind this build does not know;
 *   - and on the direct path, a Distro control message that reached the
 *     Device Address instead of the Distro Address.
 * No client sends a message for a name alone (DISPLAY_NAMES.md: names ride
 * on messages as 0xD1, and on announces); every client here has a Message
 * Display Name, so every control message carries one, and an announce of a
 * stranger is checked too.
 *
 * The clients are test_group_net.mjs's: the real shipped code extracted
 * from app.js, stubbed at the edge only.
 *
 * Run: node --test control_messages_no_chat.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { install, methodBody } from "./test_app_source.mjs";
import { groupClient, network, settle, lxmfHash, lxm, quiet, Identity } from "./test_group_net.mjs";
import LXMF from "./lib/rns/lxmf/lxmf.js";
import { DISTRO_CHANNEL_TYPE } from "./lib/channel_sync.js";
import { DISTRO_GROUP_TYPE } from "./lib/group_sync.js";
import { applyReaction } from "./lib/reactions.js";

/** The direct-message rows the chat list shows, as _buildSidebarContent picks them. */
const chatRows = (c) => c.ContactStore.chats((hash) => c.MsgStore.get(hash).length > 0).map((r) => r.destHash);
const named = (label, client) => Object.assign(client, { label });

/** No client shows a direct-message row or lists a contact. */
function noChat(clients, when) {
    for (const c of clients) {
        assert.deepEqual(chatRows(c), [], `${c.label}: no chat row ${when}`);
        assert.deepEqual(c.ContactStore.listed().map((r) => r.destHash), [], `${c.label}: no contact ${when}`);
    }
}

/** Every pair reaches each other and holds the other's key, as the
 *  invites and announces would give them. */
function acquaint(all, extra = []) {
    for (const x of all) {
        for (const y of all) if (x !== y) x.reachable(y.own).know(y);
        for (const h of extra) x.reachable(h);
    }
}

test("these tests read the chat list's rule: its direct-message rows are ContactStore.chats over MsgStore", () => {
    assert.match(methodBody("_buildSidebarContent()"),
        /const dms = ContactStore\.chats\(\(hash\) => MsgStore\.get\(hash\)\.length > 0\);/);
});

for (const filter of [false, true]) {
    test(`Group actions on the direct path, statuses included, make no chat row and no contact (privacy filter ${filter ? "on" : "off"})`, async () => {
        const c = named("the creator", groupClient({ filter, name: "Cee" }));
        const m = named("a member", groupClient({ filter, name: "Emm" }));
        const n = named("one who declines", groupClient({ filter, name: "Enn" }));
        const all = [c, m, n];
        acquaint(all);
        // With the filter on, an invite counts only from an allowlisted
        // inviter; allowlisting lists nobody.
        if (filter) for (const x of [m, n]) x.ContactStore.allow(c.own);
        const net = network(...all);

        const { group } = c.self.createGroup("G", [m.own, n.own]);
        const id = group.groupId;
        await net.run();
        assert.equal(m.GroupStore.get(id)?.groupStatus, "pending", "the invite arrived");
        noChat(all, "after the invites");

        m.page._acceptGroupInvite(id);
        await net.run();
        noChat(all, "after an accept and the creator's statuses");

        n.page._declineGroupInvite(id);
        await net.run();
        noChat(all, "after a decline");

        void c.self.sendGroupMessage(id, "hello");
        void m.self.sendGroupMessage(id, "hi back");
        await net.run();
        assert.ok(m.GroupMsgStore.get(id).some((r) => r.content === "hello"), "the posts arrived, in the group");
        assert.ok(c.GroupMsgStore.get(id).some((r) => r.content === "hi back"));
        noChat(all, "after posts");

        void c.self.sendGroupStatus(id, m.own);
        await net.run();
        noChat(all, "after a status");

        m.page._leaveGroup(id);
        await net.run();
        noChat(all, "after a leave");
    });
}

test("as the Distro on two devices: Group actions, their Distro Syncs and the Distro Fanout make no chat row and no contact", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u1 = named("Distro Device 1", groupClient({ distro: Did, name: "You" }));
    const u2 = named("Distro Device 2", groupClient({ distro: Did, name: "You" }));
    const c = named("the creator", groupClient({ name: "Cee" }));
    const m = named("a member", groupClient({ name: "Emm" }));
    const all = [u1, u2, c, m];
    acquaint(all, [D]);
    c.know(Did);
    m.know(Did);
    const net = network(...all);

    const listed = [m.own, D];
    const id = c.GroupStore.create("G", listed).groupId;
    void c.self.sendGroupInvites(id, "G", listed);
    await net.run();
    assert.equal(u2.GroupStore.get(id)?.groupStatus, "pending", "the invite reached both devices");
    noChat(all, "after the invite to the Distro Address");

    u1.page._acceptGroupInvite(id);
    await net.run();
    assert.ok((await net.syncs(u1)).length > 0, "the accept owed a Distro Sync");
    await net.run();
    assert.equal(u2.GroupStore.get(id)?.groupStatus, "active", "the Distro Sync joined the other device");
    noChat(all, "after the accept, its Distro Sync and the creator's statuses");

    void u1.self.sendGroupMessage(id, "from device 1");
    void m.self.sendGroupMessage(id, "from the member");
    await net.run();
    await net.syncs(u1);
    await net.run();
    assert.ok(u2.GroupMsgStore.get(id).some((r) => r.content === "from device 1"), "the post's Distro Sync arrived");
    assert.ok(u2.GroupMsgStore.get(id).some((r) => r.content === "from the member"), "the member's post came by Distro Fanout");
    noChat(all, "after posts, one of them synced");

    void c.self.sendGroupStatus(id, D);
    await net.run();
    noChat(all, "after a status to the Distro Address");

    u2.page._leaveGroup(id);
    await net.run();
    assert.ok((await net.syncs(u2)).length > 0, "the leave owed a Distro Sync");
    await net.run();
    noChat(all, "after a leave on the other device and its Distro Sync");
});

/** A Distro Device over the real Distro path, with the real reaction code
 *  (test_group_net.mjs leaves it out), a peer that knows it, and the Distro
 *  Sync of a channel join or leave recorded where the path hands it on
 *  (distro_channels.test.mjs runs that handler itself). */
function distroDevice() {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = named("the Distro Device", groupClient({ distro: Did, name: "You" }));
    const sibling = Identity.create();
    const peer = Identity.create();
    u.know(peer);
    install(u.self, { Buffer, console: quiet, Harness: u.Harness, applyReaction }, [
        "_applyReaction(store, convHash, record, reactor, emoji, at)",
        "_takeReaction(reaction, chat)",
    ]);
    const channelSyncs = [];
    u.self._handleDistroChannelSync = (marker) => { channelSyncs.push(marker); return true; };
    return { u, Did, D, sibling, siblingHex: lxmfHash(sibling), peer, P: lxmfHash(peer), channelSyncs };
}

test("one-off control messages on the Distro path make no chat row and no contact", async () => {
    const { u, Did, D, siblingHex, peer, P, channelSyncs } = distroDevice();
    const name = (fields) => { fields.set(0xD1, new Map([[0x00, Buffer.from("Pea")]])); return fields; };
    const reaction = () => LXMF.reactionField(Buffer.alloc(32, 7), "👍");
    const cases = [
        ["a delivery notification nobody waits on", peer, new Map([[LXMF.FIELD_TICKET, Buffer.alloc(8, 9)]])],
        ["a reaction to a message not held", peer, new Map([[LXMF.FIELD_REACTION, reaction()]])],
        ["a Distro Sync of a send carrying only a reaction", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_SENT_TYPE], [LXMF.FIELD_CUSTOM_DATA, P], [LXMF.FIELD_CUSTOM_META, siblingHex],
            [LXMF.FIELD_REACTION, reaction()]])],
        ["a Distro Sync of a send with no recipient", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_SENT_TYPE], [LXMF.FIELD_CUSTOM_META, siblingHex]])],
        ["a Distro Sync of a channel join", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, DISTRO_CHANNEL_TYPE], [LXMF.FIELD_CUSTOM_DATA, ["join", "public.tea", Date.now()]],
            [LXMF.FIELD_CUSTOM_META, siblingHex]])],
        ["a Distro Sync of a channel leave", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, DISTRO_CHANNEL_TYPE], [LXMF.FIELD_CUSTOM_DATA, ["leave", "public.tea", Date.now()]],
            [LXMF.FIELD_CUSTOM_META, siblingHex]])],
        ["a Distro Sync of a channel join with no 0xFC", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, DISTRO_CHANNEL_TYPE], [LXMF.FIELD_CUSTOM_META, siblingHex]])],
        ["a Distro Sync of Group actions with no 0xFC", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, DISTRO_GROUP_TYPE], [LXMF.FIELD_CUSTOM_META, siblingHex]])],
        ["a Distro message of a kind this build does not know", Did, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, "rfed.distro.newer"], [LXMF.FIELD_CUSTOM_META, siblingHex]])],
        ["a Distro Identity transfer, which goes to a Device Address, not the Distro Address", peer, new Map([
            [LXMF.FIELD_CUSTOM_TYPE, LXMF.DISTRO_TRANSFER_TYPE], [LXMF.FIELD_CUSTOM_DATA, "00".repeat(64)]])],
    ];
    for (const [what, from, fields] of cases) {
        await u.receiveDistro(lxm(from, D, "", name(fields)));
        await settle();
        noChat([u], `after ${what}`);
    }
    assert.equal(channelSyncs.length, 3, "the three Distro Syncs of a channel join or leave went to their handler");
});

test("a Distro control message that reached the Device Address instead of the Distro Address makes no chat row", async () => {
    const Did = Identity.create();
    const D = lxmfHash(Did);
    const u = named("the device", groupClient({ name: "You" }));
    const sibling = lxmfHash(Identity.create());
    u.know(Did);
    for (const [type, data] of [
        [LXMF.DISTRO_SENT_TYPE, lxmfHash(Identity.create())],
        [DISTRO_CHANNEL_TYPE, ["join", "public.tea", Date.now()]],
        [DISTRO_GROUP_TYPE, ["post", "00".repeat(16), Date.now()]],
        ["rfed.distro.newer", null],
    ]) {
        const fields = new Map([[LXMF.FIELD_CUSTOM_TYPE, type], [LXMF.FIELD_CUSTOM_META, sibling]]);
        if (data !== null) fields.set(LXMF.FIELD_CUSTOM_DATA, data);
        await u.receive(lxm(Did, u.own, "", fields));
        noChat([u], `after a ${type} message from the Distro Address`);
    }
    // ... while a message from it is a message, as ever.
    await u.receive(lxm(Did, u.own, "a real message"));
    assert.deepEqual(chatRows(u), [D]);
});

test("an announce from a stranger makes no row at all, and one from a known peer lists nobody", () => {
    const u = named("the device", groupClient({ name: "You" }));
    const stranger = Identity.create();
    u.ContactStore.updateFromAnnounce(lxmfHash(stranger), { appData: null, identity: stranger });
    assert.equal(u.ContactStore.known(lxmfHash(stranger)), false);
    const peer = Identity.create();
    u.know(peer);
    u.ContactStore.updateFromAnnounce(lxmfHash(peer), { appData: null, identity: peer });
    noChat([u], "after the announces");
});
