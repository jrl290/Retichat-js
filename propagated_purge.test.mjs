/**
 * /get purges every message the propagation node returned, as LXMF does:
 * LXMRouter.py message_get_response appends every returned lxmf_data to the
 * haves of its next /get, whatever lxmf_propagation made of it, so the node
 * deletes it. Until 2026-10-01 the web purged only what it kept or its
 * privacy filter dropped: a message that was too short, not for this
 * destination, could not be decrypted, whose first three payload elements
 * could not be read, or that threw, stayed on the node and was downloaded
 * again on every fetch, for ever. Each one purged unread is logged with why.
 * A message the node did not return (an empty answer) is not purged.
 *
 * Runs the shipped _fetchPropagatedMessages cut out of app.js
 * (test_app_source.mjs) over the real LXMRouter and LXMessage.
 *
 * Run: node --test propagated_purge.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import MsgPack from "./lib/rns/msgpack.js";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import Link from "./lib/rns/link.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { settle } from "./test_link_pair.mjs";
import { installPropagated } from "./test_app_source.mjs";

const hex = (b) => Buffer.from(b).toString("hex");
const lxmfHashOf = (identity) => Destination.hash(identity, "lxmf", "delivery");

/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content) {
    const m = new LXMessage();
    m.sourceHash = lxmfHashOf(from);
    m.destinationHash = Buffer.from(toHash);
    m.title = "";
    m.content = content;
    m.fields = new Map();
    return m.pack(from, false);
}

/** What a propagation node returns for a message: destination | encrypted(rest). */
const blobFor = (encryptTo, dest, rest) => Buffer.concat([Buffer.from(dest), encryptTo.encrypt(Buffer.from(rest))]);

/**
 * One fetch over `node`: tid (hex) → the blob the node returns for it, or
 * null for one it lists and then does not return. Resolves to the haves
 * the purge sent (hex), what the router handed on, and the log.
 */
async function fetchFrom(me, node, { decrypt = null, routerPatch = null } = {}) {
    const destination = new EventEmitter();
    destination.hash = lxmfHashOf(me);
    const router = new LXMRouter({ registerDestination: () => destination }, me);
    routerPatch?.(router);
    const emitted = [];
    router.on("message", (m) => emitted.push(m.content));
    const logs = [];
    const capture = { log: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")), error() {} };
    const purged = [];
    const self = {
        _lxmfRouter: router,
        _propLink: { status: Link.ACTIVE, sendRequest: (path, data) => data },
        async _waitForResponse(link, [wants, haves]) {
            if (haves) { purged.push(...haves.map(hex)); return true; }
            if (wants) {
                const blob = node.get(hex(wants[0]));
                return blob ? [blob] : [];
            }
            return [...node.keys()].map((k) => Buffer.from(k, "hex"));
        },
    };
    const IdMgr = { id: decrypt ? { decrypt } : me };
    await installPropagated(self, { Link, Buffer, LXMessage, MsgPack, IdMgr, console: capture })._fetchPropagatedMessages();
    await settle();
    return { purged, emitted, logs, self };
}

const tid = (n) => hex(Buffer.alloc(32, n));

test("every message the node returned is purged, read or not, and each one purged unread is logged with why", async () => {
    const me = Identity.create(), sender = Identity.create(), someoneElse = Identity.create();
    const mine = lxmfHashOf(me);
    const kept = lxm(sender, mine, "kept");
    const node = new Map([
        [tid(1), blobFor(me, mine, kept.subarray(16))],
        [tid(2), Buffer.alloc(40, 7)],                                                   // too short
        [tid(3), blobFor(someoneElse, lxmfHashOf(someoneElse), lxm(sender, lxmfHashOf(someoneElse), "x").subarray(16))], // not for us
        [tid(4), blobFor(someoneElse, mine, kept.subarray(16))],                         // encrypted to another key
        [tid(5), blobFor(me, mine, Buffer.concat([lxmfHashOf(sender), Buffer.alloc(64, 1), MsgPack.pack([1])]))], // payload: a list of one
        [tid(6), blobFor(me, mine, Buffer.concat([lxmfHashOf(sender), Buffer.alloc(64, 1), Buffer.from([0xc1])]))], // payload: no msgpack at all
        [tid(7), null],                                                                  // listed, not returned
    ]);
    const { purged, emitted, logs } = await fetchFrom(me, node);

    assert.deepEqual(emitted, ["kept"], "the readable one is handed on");
    assert.deepEqual(purged.sort(), [1, 2, 3, 4, 5, 6].map(tid).sort(),
        "every message returned is purged; the one the node did not return is not");
    const unreadLines = logs.filter((l) => l.includes("purged unread"));
    assert.deepEqual(unreadLines.map((l) => l.replace(/.*\[3\/4\] [0-9a-f]{8} /, "")), [
        "too short: purged unread",
        "not for us: purged unread",
        "decrypt failed (Token HMAC was invalid): purged unread",
        "bad payload: purged unread",
        "bad payload: purged unread",
    ]);
    const step4 = logs.find((l) => l.includes("[4/4] Purging"));
    assert.match(step4, /Purging 6 returned, 5 of them unread: 02020202 too short; 03030303 not for us; 04040404 decrypt failed \(Token HMAC was invalid\); 05050505 bad payload; 06060606 bad payload/);
});

test("a message whose read throws, or that decrypts to nothing, is purged unread, with why", async () => {
    const me = Identity.create(), sender = Identity.create();
    const mine = lxmfHashOf(me);
    const node = new Map([
        [tid(1), blobFor(me, mine, lxm(sender, mine, "first").subarray(16))],
        [tid(2), blobFor(me, mine, lxm(sender, mine, "second").subarray(16))],
        [tid(3), blobFor(me, mine, lxm(sender, mine, "third").subarray(16))],
    ]);
    let n = 0;
    const decrypt = (b) => (++n === 3 ? null : me.decrypt(b));   // an identity that cannot read it
    const { purged, emitted, logs } = await fetchFrom(me, node, {
        decrypt,
        // Anything else that throws while it is read: here the router's filter.
        routerPatch: (router) => {
            const accepts = router.acceptsSource.bind(router);
            let calls = 0;
            router.acceptsSource = (...a) => { if (++calls === 2) throw new Error("boom"); return accepts(...a); };
        },
    });
    assert.deepEqual(emitted, ["first"]);
    assert.deepEqual(purged.sort(), [tid(1), tid(2), tid(3)].sort(), "all three purged");
    assert.ok(logs.some((l) => l.includes("02020202 exception (boom): purged unread")), "the one that threw, and why");
    assert.ok(logs.some((l) => l.includes("03030303 decrypt failed: purged unread")), "the one that decrypted to nothing");
});

test("a fetch that returned nothing purges nothing", async () => {
    const me = Identity.create();
    const { purged, logs } = await fetchFrom(me, new Map([[tid(9), null]]));
    assert.deepEqual(purged, []);
    assert.ok(logs.some((l) => l.includes("[4/4] Nothing to purge")));
});
