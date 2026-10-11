/**
 * Test support (not a test, not deployed): run shipped code from app.js under
 * Node. app.js cannot be imported here (its module graph needs the browser's
 * importmap), so a method, an object literal or a function is cut out of the
 * source and compiled over the names a test binds — as privacy_filter.test.mjs
 * and display_names_wiring.test.mjs do. `this.` reads as `self.`.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { addInOrder } from "./lib/message_order.js";
import Cryptography from "./lib/rns/cryptography.js";
import { statusChangeVerdict, packedMessage, packedHeld } from "./lib/group_status.js";
import { GROUP_ENTRIES_IN_RETICHAT_FIELD } from "./lib/retichat_field.js";
import { groupSyncFields, groupSyncDisposition, inviteMembers } from "./lib/group_sync.js";
import { groupSyncEntryId } from "./lib/distro_outbox.js";

export const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

function braceMatch(from, label) {
    const open = app.indexOf("{", from);
    let depth = 0;
    for (let i = open; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}" && --depth === 0) return [open, i];
    }
    throw new Error(`could not brace-match ${label}`);
}

/** The body of the method with this exact signature (4-space indent). */
export function methodBody(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const [open, close] = braceMatch(start + signature.length, signature);
    return app.slice(open + 1, close);
}

/** The source of `const name = { ... }`. */
export function objectLiteral(name) {
    const start = app.indexOf(`\nconst ${name} = {`);
    assert.notEqual(start, -1, `${name} is missing from app.js`);
    const [open, close] = braceMatch(start, name);
    return app.slice(open, close + 1);
}

function functionBody(name) {
    const start = app.indexOf(`\nfunction ${name}(`);
    assert.notEqual(start, -1, `function ${name} is missing from app.js`);
    const [open, close] = braceMatch(app.indexOf(")", start), name);
    return app.slice(open + 1, close);
}

const params = (signature) => signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
    .split(",").map((p) => p.trim()).filter(Boolean);

/** A method compiled over `env`; call the result with `self` to bind it. */
export function compile(signature, env) {
    const body = methodBody(signature).replaceAll("this.", "self.");
    const names = Object.keys(env);
    const f = new Function(...names, "self", ...params(signature),
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => f(...names.map((n) => env[n]), self, ...args);
}

export const methodName = (signature) => signature.replace(/^async /, "").split("(")[0];

/** Compile `signatures` onto `self` over `env`. */
export function install(self, env, signatures) {
    for (const signature of signatures) self[methodName(signature)] = compile(signature, env)(self);
    return self;
}

/** What the message stores (MsgStore, GroupMsgStore, ChannelMsgStore)
 *  import from lib/ for their order (lib/message_order.js), bound under
 *  every build unless `env` names it, so a store built here keeps the
 *  shipped conversation order. */
const STORE_IMPORTS = { addInOrder };

/** An object literal (MsgStore, Harness, …) built over `env`. */
export function build(name, env) {
    env = { ...STORE_IMPORTS, ...env };
    const names = Object.keys(env);
    return new Function(...names, `return ${objectLiteral(name)};`)(...names.map((n) => env[n]));
}

/** A top-level function built over `env`. */
export function fn(name, args, env) {
    const names = Object.keys(env);
    return new Function(...names, `return function(${args}) {${functionBody(name)}};`)(...names.map((n) => env[n]));
}

/** The value of a top-level `const NAME = <expression>;` (one statement). */
export function constValue(name, env = {}) {
    const start = app.indexOf(`\nconst ${name} = `);
    assert.notEqual(start, -1, `const ${name} is missing from app.js`);
    const from = start + `\nconst ${name} = `.length;
    const end = app.indexOf(";\n", from);
    const names = Object.keys(env);
    return new Function(...names, `return (${app.slice(from, end)});`)(...names.map((n) => env[n]));
}

/** The body of connect()'s router message handler, compiled over `env`. */
export function messageHandler(env) {
    const marker = `this._lxmfRouter.on("message", (lxmfMsg) => {`;
    const start = app.indexOf(marker);
    assert.notEqual(start, -1);
    const [open, close] = braceMatch(start + marker.length - 1, "message handler");
    const body = app.slice(open + 1, close).replaceAll("this.", "self.");
    const names = Object.keys(env);
    const f = new Function(...names, "self", "lxmfMsg", body);
    return (self) => (lxmfMsg) => f(...names.map((n) => env[n]), self, lxmfMsg);
}

/** localStorage as sGet/sSet see it. */
export function memoryStorage() {
    const data = new Map();
    return {
        data,
        sGet: (k) => (data.has(k) ? JSON.parse(data.get(k)) : null),
        sSet: (k, v) => data.set(k, JSON.stringify(v)),
    };
}

/** A PropagatedHeld of its own, on storage of its own (`storage`, or a
 *  fresh memoryStorage), as the page builds it at load. */
export function propagatedHeld(storage = memoryStorage()) {
    const held = build("PropagatedHeld", { sGet: storage.sGet, sSet: storage.sSet });
    held.init();
    return held;
}

/**
 * The shipped propagated-message path on `self`, over `env`:
 * _fetchPropagatedMessages (/get), _onPropagatedPush (a live push on
 * rfed.link) and the _ingestPropagatedBlob both hand each message to. `env`
 * gives what they read from the page (IdMgr, LXMessage, Link, Buffer,
 * MsgPack, console, …); PropagatedHeld is a fresh one unless `env` names
 * one, and Cryptography the real one. Returns `self`.
 */
export function installPropagated(self, env) {
    env = { Cryptography, PropagatedHeld: propagatedHeld(), ...env };
    return install(self, env, [
        "async _fetchPropagatedMessages()",
        "_ingestPropagatedBlob(lxmfData, label)",
        "_onPropagatedPush(lxmfData)",
    ]);
}

/**
 * The methods an accept or a leave goes through once the group handler has
 * taken it (RFed-spec Group.md, "Member statuses and keys"): the decision by
 * signature, the count (and the creator's copy), the hold, and the elements
 * of a `status`. A test that runs the real _handleGroupMessage over accepts
 * and leaves installs these beside it, over groupStatusEnv().
 */
export const GROUP_STATUS_METHODS = [
    "_applyGroupStatusChange(groupId, src, action, event = null, packed = null)",
    "_takeGroupStatusChange(lxmfMsg, groupId, src, action, event = null)",
    "_takeGroupStatuses(group, statuses)",
    "_takeGroupStatusElement(groupId, element, mine)",
    "_holdGroupStatusChange(lxmfMsg, groupId, src, action)",
    "_decideHeldGroupChanges()",
];

/**
 * Who the user is in a group, and as whom it sends there
 * (GROUPS-DISTRO-DESIGN.md §8.1, §8.7, §9.1): the self set of a member list,
 * a held group's, the group signer and the §8.7 refusal, over the sending
 * identity they resolve through. A test that runs group code installs these
 * beside it, over groupSelfEnv().
 */
export const GROUP_SELF_METHODS = [
    "sendingIdentity()",
    "_signerFor(srcHash)",
    "_selfOf(members, ownMember)",
    "_groupSelf(group)",
    "_groupSigner(group)",
    "_inviteOwnMember(listed)",
    "groupFormerDistroText(group)",
    "_distroSelf()",
    "_isKnownSibling(group, hash)",
];

/**
 * The distro path's group branch (GROUPS-DISTRO-DESIGN.md §6.1-6.5): the
 * group message reaching D, its hold and the replay and forgetting of what
 * is held. A test that runs _handleDistroBlob over group traffic installs
 * these beside it and beside _handleGroupMessage.
 */
export const GROUP_DISTRO_METHODS = [
    "_holdGroupArrival(lxmfMsg, groupInfo, srcHash, group, arrival)",
    "_replayHeldGroupArrivals(groupId)",
    "_forgetHeldGroupArrivals(groupId, why)",
    "_handleDistroGroupMessage(data, destHash, decrypted, srcHex, entries)",
];

/**
 * The group sync G (GROUPS-DISTRO-DESIGN.md §10, §11; RFed SPEC §17.14): the
 * user's action owed to the distro as a G, and a G received, its rules, the
 * apply table and `left`, the known siblings and what giving D up forgets.
 * Installed beside GROUP_DISTRO_METHODS over groupSyncEnv() and what the
 * send and receive paths read.
 */
export const GROUP_SYNC_METHODS = [
    "_syncGroupAction(op, groupId, extra = null)",
    "_sendDistroGroupSync(op, group, extra = null)",
    "_groupSyncKeys(listed, distroHash, deviceHash)",
    "_handleDistroGroupSync(read, facts)",
    "_applyGroupSync(sync, group, facts)",
    "_joinedFromSync(group, sync, how)",
    "_closeGroupFromSync(id, group, why)",
    "_applyGroupSyncLeft(sync)",
    "_learnDistroSibling(d, by, what)",
    "_onDistroChangedForGroups()",
];

/** What GROUP_SYNC_METHODS import from lib/. */
export function groupSyncEnv() {
    return { groupSyncFields, groupSyncDisposition, inviteMembers, groupSyncEntryId };
}

/** What GROUP_SELF_METHODS read from the page: the distro this device holds
 *  (none unless `DistroManager` is given), its known siblings (none unless
 *  `KnownSiblingsStore` is given), the device's identity and hash. */
export function groupSelfEnv({ DistroManager = { has: false, identity: null, lxmfDeliveryHash: null, pubKey: null },
    KnownSiblingsStore = { of: () => [], has: () => false }, IdMgr, own, shortHash = (h) => `${String(h ?? "").slice(0, 8)}…` } = {}) {
    return { DistroManager, KnownSiblingsStore, IdMgr, ownLxmfDestinationHash: () => own, shortHash };
}

/** GROUP_SELF_METHODS compiled onto `self` over groupSelfEnv and
 *  `GroupStore`, leaving any of them `self` already has (a test's own
 *  sendingIdentity, say). `own` is the device's lxmf.delivery hash, `me` its
 *  identity. Returns `self`. */
export function installGroupSelf(self, { GroupStore, own, me = null, DistroManager, KnownSiblingsStore } = {}) {
    const IdMgr = { has: true, id: me, pubKey: me ? me.getPublicKey().toString("hex") : null };
    const env = { ...groupSelfEnv({ DistroManager, KnownSiblingsStore, IdMgr, own }), GroupStore };
    return install(self, env, GROUP_SELF_METHODS.filter((signature) => !(methodName(signature) in self)));
}

/** What GROUP_STATUS_METHODS read from the page beside the stores: the
 *  verdict and packing helpers, and the switch (GROUP_ENTRIES_IN_RETICHAT_FIELD,
 *  false until around 2026-10-26; `overrides` {GROUP_ENTRIES_IN_RETICHAT_FIELD:
 *  true} is the page after it). */
export function groupStatusEnv(overrides = {}) {
    return { statusChangeVerdict, packedMessage, packedHeld, GROUP_ENTRIES_IN_RETICHAT_FIELD, ...overrides };
}
