// The distro's queue before the stored channels (DESIGN_PRINCIPLES §5), and a
// pull that a switch cancels said as cancelled (the truth rule).
//
// Found on Android in private staging, 2026-10-10: on a push wake the start
// re-subscribed the persisted channels while the distro pull was still to
// apply a sibling's leave, so RFed saw /rfed/subscribe and, 0.3 s later,
// /rfed/unsubscribe; a post fanned out between them reached a device whose
// distro had left the channel. This page did the same: _initChannels
// subscribed its stored channels on the rfed.channel announce, beside the
// distro pull. Now _initChannels waits for the pull's outcome (_distroFirst),
// whatever it is, and the channels a sibling left are not subscribed again.
//
// Web A, the same day: "[distro] PULL failed: Error: /distro/pull: the link
// closed before a response" when reconnect() for the saved settings had
// itself closed the pull's link. That is a cancellation, said as one; a real
// failure still says failed.
//
// The shipped _initChannels, _distroFirst and _pullDistroMessages run here
// over stubs (test_app_source.mjs).

import assert from "node:assert/strict";
import test from "node:test";

import MsgPack from "./lib/rns/msgpack.js";
import { compile, constValue, install, methodBody, app } from "./test_app_source.mjs";

const RFED_LINK_FAILED = constValue("RFED_LINK_FAILED");

/**
 * A page holding stored channels, with or without a distro. `pages` are the
 * /distro/pull answers in turn; an Error in it is thrown by the request. A
 * blob "leave:<name>" is a sibling's leave, applied as _applyDistroChannelSync
 * applies it: the channel leaves the store at once, and its unsubscribe goes.
 */
function page({ distro = true, channels = ["a", "b"], pages = [[[], false]], onRequest = null } = {}) {
    const wire = [];
    const logged = { log: [], warn: [], error: [] };
    const say = (level) => (...args) => logged[level].push(args.map((a) => (a instanceof Error ? `Error: ${a.message}` : String(a))).join(" "));
    const store = channels.map((name) => ({ channelName: name, channelHash: `h-${name}`, isSubscribed: true }));
    const ChannelStore = {
        getAll: () => store.slice(),
        leave: (name) => { const i = store.findIndex((c) => c.channelName === name); if (i >= 0) store.splice(i, 1); },
    };
    const env = {
        DistroManager: { has: distro }, MsgPack, RFED_LINK_FAILED, ChannelStore,
        console: { log: say("log"), warn: say("warn"), error: say("error") },
    };
    const answers = pages.slice();
    const self = {
        _rns: { name: "connection 1" },
        _stopReasons: new WeakMap(),
        _cfg: { rfedNodeHash: "aa".repeat(16), rfedNodePubKey: "bb".repeat(64) },
        _channelsInitialized: true,
        _channelsResubscribed: false,
        _rfedOpenedChannelHashes: new Set(),
        _ensureChannelStreamConfigured: async () => {},
        _distroPullInFlight: null,
        _rfedLinkState: new Map(),
        _rfedLinkKeyFor: () => "link",
        _closeRefusedRfedLink() {},
        _rfedDeferUntilAnnounce() {},
        _redriveRfedLink() {},
        _rfedRequest: async (aspects, path) => {
            wire.push(path);
            if (onRequest) await onRequest(self);
            const answer = answers.shift();
            if (answer instanceof Error) throw answer;
            return answer;
        },
        _handleDistroBlob: (hash, blob) => {
            const [kind, name] = String(blob).split(":");
            if (kind === "leave" && store.some((c) => c.channelName === name)) {
                ChannelStore.leave(name);
                wire.push(`/rfed/unsubscribe #${name}`);
            }
            return true;
        },
        _ensureChannelSubscribed: async (ch) => { wire.push(`/rfed/subscribe #${ch.channelName}`); return null; },
    };
    install(self, env, ["async _initChannels()", "async _distroFirst()", "async _pullDistroMessages()"]);
    return { self, wire, logged, store };
}

const pair = (blob) => [Buffer.alloc(16), blob];

test("a sibling's leave the pull applies is applied before any stored channel is subscribed again, and the left one is not", async () => {
    const p = page({ pages: [[[pair("leave:b")], false]] });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/pull", "/rfed/unsubscribe #b", "/rfed/subscribe #a"]);
    assert.ok(p.logged.log.includes("[retichat] 📡 Distro queue pulled and applied first (1 blob(s)): re-subscribing stored channels"));
    assert.deepEqual(p.logged.warn, []);
});

test("the gate waits for every page the pull follows: a leave on the second page is applied before the subscription", async () => {
    const p = page({ pages: [[[pair("other")], true], [[pair("leave:b")], false]] });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/pull", "/rfed/pull", "/rfed/unsubscribe #b", "/rfed/subscribe #a"]);
    assert.ok(p.logged.log.includes("[distro] 📬 More is queued — pulling the next page"));
    assert.ok(p.logged.log.includes("[retichat] 📡 Distro queue pulled and applied first (2 blob(s)): re-subscribing stored channels"));
});

test("a pull already in flight is joined, not doubled: one /distro/pull, and the subscription after its leave", async () => {
    let release;
    const p = page({ pages: [[[pair("leave:b")], false]], onRequest: () => new Promise((r) => { release = r; }) });
    const earlier = p.self._pullDistroMessages(); // the rfed.link "established" pull
    const init = p.self._initChannels();
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(p.wire, ["/rfed/pull"], "nothing is subscribed while the pull is out");
    release();
    await Promise.all([earlier, init]);
    assert.deepEqual(p.wire, ["/rfed/pull", "/rfed/unsubscribe #b", "/rfed/subscribe #a"]);
});

test("a page with no distro subscribes its stored channels at once, with no pull", async () => {
    const p = page({ distro: false });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/subscribe #a", "/rfed/subscribe #b"]);
});

test("a pull that fails still lets the subscription go, and says so; the failure still says failed", async () => {
    const p = page({ pages: [new Error("/distro/pull: the request timed out (rtt=80ms)")] });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/pull", "/rfed/subscribe #a", "/rfed/subscribe #b"]);
    assert.deepEqual(p.logged.error, ["[distro] PULL failed: Error: /distro/pull: the request timed out (rtt=80ms)"]);
    assert.deepEqual(p.logged.warn, [
        "[retichat] 📡 Distro pull before re-subscribing stopped after 0 blob(s): failed: /distro/pull: the request timed out (rtt=80ms); "
        + "re-subscribing stored channels now; a sibling's leave still queued at RFed, if any, is applied when a later pull brings it",
    ]);
});

test("a pull RFed refuses still lets the subscription go, and says what came back", async () => {
    const p = page({ pages: [0xF4] });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/pull", "/rfed/subscribe #a", "/rfed/subscribe #b"]);
    assert.match(p.logged.warn.at(-1), /^\[retichat\] 📡 Distro pull before re-subscribing stopped after 0 blob\(s\): refused: 0xf4 \(INVALID_DATA\); re-subscribing stored channels now/);
});

test("an answer that is not a page is said, not dropped silently, and the subscription goes", async () => {
    const p = page({ pages: [true] });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/pull", "/rfed/subscribe #a", "/rfed/subscribe #b"]);
    assert.deepEqual(p.logged.warn[0], "[distro] 📬 PULL answered with something that is not a page — nothing handled: true");
});

test("reconnect() for the saved settings closes the pull's link: cancelled, never failed, and the stopped connection subscribes nothing", async () => {
    const p = page({
        pages: [new Error("/distro/pull: the link closed before a response (rtt=80ms)")],
        // reconnect() → disconnect() under the request, as _saveSettings runs it.
        onRequest: (self) => {
            self._stopReasons.set(self._rns, "reconnect() for the saved settings");
            self._rns = { name: "connection 2" };
            self._channelsResubscribed = false;
        },
    });
    await p.self._initChannels();
    assert.deepEqual(p.wire, ["/rfed/pull"], "nothing is subscribed on the stopped connection: the next one subscribes its own");
    assert.deepEqual(p.logged.error, [], "no \"PULL failed\"");
    assert.ok(p.logged.log.includes(
        "[distro] 📬 PULL cancelled by reconnect() for the saved settings: /distro/pull: the link closed before a response (rtt=80ms)"));
    assert.ok(p.logged.log.includes(
        "[retichat] 📡 Stored channels not subscribed on the stopped connection (reconnect() for the saved settings): the distro pull before it did not finish on it"));
});

test("a stop while a page that said more was handled ends the pull there, and says so", async () => {
    const p = page({
        pages: [[[pair("other")], true], [[], false]],
        onRequest: (self) => {
            self._stopReasons.set(self._rns, "another tab taking over");
            self._rns = { name: "connection 2" };
        },
    });
    assert.equal((await p.self._pullDistroMessages()).length, 1);
    assert.deepEqual(p.wire, ["/rfed/pull"], "the next page is not pulled on the stopped connection");
    assert.ok(p.logged.log.includes("[distro] 📬 More is queued, but another tab taking over stopped the connection: the next page is not pulled on it"));
});

test("the stop's reason is what reconnect() and the tab takeover say, recorded by disconnect() for the connection it stops", () => {
    assert.match(methodBody("disconnect()"),
        /^\s*\/\/[^\n]*\n(?:\s*\/\/[^\n]*\n)*\s*if \(this\._rns\) this\._stopReasons\?\.set\(this\._rns, this\._stopWhy \?\? "disconnect\(\)"\);\s*this\._stopWhy = null;/,
        "first, before any link is closed");
    assert.match(app, /async reconnect\(why = "reconnect\(\)"\) \{ this\._stopWhy = why; this\.disconnect\(\); await this\.connect\(\); \},/);
    assert.match(methodBody("async _saveSettings()"), /await RnsClient\.reconnect\("reconnect\(\) for the saved settings"\);/);
    assert.match(methodBody("_takenOver()"), /RnsClient\._stopWhy = "another tab taking over";\s*RnsClient\.disconnect\(\);/);
});

test("the registration and the pre-signed announce, closed under by a stop, say cancelled, and only a real failure says failed", () => {
    const register = methodBody("async _registerDistro()");
    assert.match(register,
        /\} catch\(e\) \{[\s\S]*?if \(this\._rns !== rns\) \{\s*console\.log\(`\[distro\] Registration cancelled by \$\{this\._stopReasons\?\.get\(rns\) \?\? "disconnect\(\)"\}: \$\{e\?\.message \?\? e\}`\);\s*return false;\s*\}\s*console\.error\(`\[distro\] Registration failed:`, e\);/);
    const announce = methodBody("async _publishDistroAnnounce()");
    assert.match(announce, /^\s*if \(!DistroManager\.has\) return false;\s*const rns = this\._rns;/);
    assert.match(announce,
        /\} catch\(e\) \{\s*if \(this\._rns !== rns\) \{[\s\S]*?console\.log\(`\[distro\] Announce publication cancelled by \$\{this\._stopReasons\?\.get\(rns\) \?\? "disconnect\(\)"\}: \$\{e\?\.message \?\? e\}`\);\s*return false;\s*\}\s*console\.error\(`\[distro\] Announce publication failed:`, e\);/);
    // A refusal is said only of an answer, with what came back; no answer is the catch above.
    assert.match(announce, /console\.warn\(`\[distro\] RFed refused the pre-signed announce:`, response\);/);
});

test("the gate is the one place the stored channels wait for the distro, and it schedules nothing", () => {
    const init = methodBody("async _initChannels()");
    assert.match(init, /this\._channelsResubscribed = true;\s*(?:\/\/[^\n]*\n\s*)*if \(DistroManager\.has && !\(await this\._distroFirst\(\)\)\) return;\s*const subscriptions = ChannelStore\.getAll\(\)/);
    for (const sig of ["async _distroFirst()", "async _pullDistroMessages()"]) {
        assert.doesNotMatch(methodBody(sig), /setTimeout|setInterval/, `${sig}: an event, never a clock`);
    }
});
