/**
 * Delivery tickets (FIELD_TICKET, 0x0C), as LXMF handles them:
 *
 *   - no reply. LXMF answers a ticketed message with nothing but the
 *     delivery proof (LXMRouter.py delivery_packet / delivery_link_established).
 *     Until 2026-10-01 the web sent a "delivery notification" on the link for
 *     every ticketed link message, carrying the destination hash twice, so no
 *     receiver could parse it and no web sender listened for it;
 *   - the ticket is remembered (LXMRouter.py lxmf_delivery -> remember_ticket):
 *     from a message whose signature validated, in LXMF's form [expires,
 *     ticket(16 bytes)], expiry still ahead, as the outbound ticket for the
 *     message's source (get_outbound_ticket). On every path the router hands
 *     a message on, the propagated /get's emit included, and only after the
 *     privacy filter: a dropped stranger's ticket is not remembered.
 *
 * These run the real LXMRouter over real links (test_link_pair.mjs) and the
 * shipped OutboundTickets store cut out of app.js (test_app_source.mjs).
 *
 * Run: node --test lxmf_tickets.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import Packet from "./lib/rns/packet.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { linkPair, settle, within } from "./test_link_pair.mjs";
import { build, methodBody, memoryStorage } from "./test_app_source.mjs";

const FIELD_TICKET = 0x0C;
const hex = (b) => Buffer.from(b).toString("hex");
const lxmfHashOf = (identity) => Destination.hash(identity, "lxmf", "delivery");
const now = () => Date.now() / 1000;
const pythonTicket = (bytes, expires = now() + 21 * 24 * 3600) => [expires, bytes];

/** A router for `me`, its message events, and a store of known keys. */
function recipient({ filter = null, tickets = null } = {}) {
    const me = Identity.create();
    const destination = new EventEmitter();
    destination.hash = lxmfHashOf(me);
    const router = new LXMRouter({ registerDestination: () => destination }, me, { filter, tickets });
    const emitted = [];
    router.on("message", (m) => emitted.push(m));
    return { me, destination, router, emitted };
}

/** The full packing (destination | source | signature | payload), signed by `from`. */
function lxm(from, toHash, content, fields) {
    const m = new LXMessage();
    m.sourceHash = lxmfHashOf(from);
    m.destinationHash = Buffer.from(toHash);
    m.title = "";
    m.content = content;
    m.fields = fields;
    return m.pack(from, false);
}

/** Make `identities` the ones whose keys the router can recall (as app.js
 *  installs recallLxmfIdentity), for the length of test `t`. */
function knownKeys(t, ...identities) {
    const saved = LXMessage.recall;
    LXMessage.recall = (h) => identities.find((i) => lxmfHashOf(i).equals(Buffer.from(h))) ?? null;
    t.after(() => { LXMessage.recall = saved; });
}

/** An established delivery link into the router: `a` is the sender's end. */
async function deliveryLink(r) {
    const { a, b, wire } = linkPair();
    b.accept = () => {};
    r.destination.emit("link_request", b);
    await settle();
    return { a, wire };
}

test("a ticketed link message is proved, and nothing else comes back: LXMF has no ticket reply", async (t) => {
    const r = recipient();
    const sender = Identity.create();
    knownKeys(t, sender);
    const { a, wire } = await deliveryLink(r);

    a.send(lxm(sender, r.destination.hash, "a web ticket", new Map([[FIELD_TICKET, "0123456789abcdef"]])));
    a.send(lxm(sender, r.destination.hash, "a Python ticket", new Map([[FIELD_TICKET, pythonTicket(Buffer.alloc(16, 7))]])));
    await settle(8);

    assert.deepEqual(r.emitted.map((m) => m.content), ["a web ticket", "a Python ticket"], "both kept");
    assert.equal(wire.b.length, 2, "two packets back");
    assert.ok(wire.b.every((p) => p.packetType === Packet.PROOF), "each the delivery proof of one message");
    assert.equal(wire.b.filter((p) => p.packetType === Packet.DATA).length, 0, "and no data: no delivery notification");

    // A Resource: proved by the Resource protocol, and no data packet after it.
    await within(a.sendResource(lxm(sender, r.destination.hash, "z".repeat(3000), new Map([[FIELD_TICKET, "fedcba9876543210"]]))), 5000, "the Resource");
    await settle(8);
    assert.equal(r.emitted.at(-1)?.content, "z".repeat(3000));
    assert.equal(wire.b.filter((p) => p.packetType === Packet.DATA && p.context === Packet.NONE).length, 0,
        "no delivery notification after a Resource either");
});

test("a validated message's LXMF ticket is remembered for its source, on the opportunistic, link and propagated paths", async (t) => {
    const r = recipient();
    const s1 = Identity.create(), s2 = Identity.create(), s3 = Identity.create();
    knownKeys(t, s1, s2, s3);
    const k1 = Buffer.alloc(16, 1), k2 = Buffer.alloc(16, 2), k3 = Buffer.alloc(16, 3);
    const expires = now() + 3600;

    // Opportunistic: the packet's plaintext is the packing without the destination hash.
    const packed = lxm(s1, r.destination.hash, "opportunistic", new Map([[FIELD_TICKET, pythonTicket(k1, expires)]]));
    r.destination.emit("packet", { data: packed.subarray(16), packet: { prove() {} } });
    // A link packet.
    const { a } = await deliveryLink(r);
    a.send(lxm(s2, r.destination.hash, "link", new Map([[FIELD_TICKET, pythonTicket(k2)]])));
    // The propagated /get hands its message on with the router's own event
    // (app.js _fetchPropagatedMessages: this._lxmfRouter.emit("message", …)).
    const fetched = LXMessage.fromBytes(lxm(s3, r.destination.hash, "propagated", new Map([[FIELD_TICKET, pythonTicket(k3)]])).subarray(16), r.destination.hash);
    r.router.emit("message", fetched);
    await settle(8);

    assert.equal(r.emitted.length, 3);
    assert.equal(hex(r.router.getOutboundTicket(lxmfHashOf(s1))), hex(k1), "the opportunistic sender's");
    assert.deepEqual(r.router.outboundTickets.get(hex(lxmfHashOf(s1))), [expires, hex(k1)], "kept as [expires, ticket]");
    assert.equal(hex(r.router.getOutboundTicket(lxmfHashOf(s2))), hex(k2), "the link sender's");
    assert.equal(hex(r.router.getOutboundTicket(hex(lxmfHashOf(s3)))), hex(k3), "the propagated sender's (looked up by hex too)");

    // A newer ticket from the same source replaces it (one per source).
    const k1b = Buffer.alloc(16, 0x11);
    r.destination.emit("packet", { data: lxm(s1, r.destination.hash, "again", new Map([[FIELD_TICKET, pythonTicket(k1b)]])).subarray(16), packet: { prove() {} } });
    await settle(6);
    assert.equal(hex(r.router.getOutboundTicket(lxmfHashOf(s1))), hex(k1b));
});

test("only a validated message's ticket in LXMF's form, unexpired and 16 bytes, is remembered", async (t) => {
    const r = recipient();
    const known = Identity.create(), unknown = Identity.create();
    knownKeys(t, known);
    const deliver = (from, ticket) => r.destination.emit("packet", {
        data: lxm(from, r.destination.hash, "x", new Map([[FIELD_TICKET, ticket]])).subarray(16), packet: { prove() {} },
    });

    deliver(unknown, pythonTicket(Buffer.alloc(16, 9)));               // its key is not known: not validated
    await settle(6);
    assert.equal(r.emitted.at(-1).signatureValidated, false);
    assert.equal(r.router.getOutboundTicket(lxmfHashOf(unknown)), null, "a source whose signature did not validate");

    for (const [why, ticket] of [
        ["the web's own ticket (a str)", "0123456789abcdef"],
        ["an expired one", pythonTicket(Buffer.alloc(16, 1), now() - 1)],
        ["a short one", pythonTicket(Buffer.alloc(8, 1))],
        ["a long one", pythonTicket(Buffer.alloc(32, 1))],
        ["a ticket that is no bytes", [now() + 3600, "0123456789abcdef0123456789abcdef"]],
        ["a list of one", [now() + 3600]],
    ]) {
        deliver(known, ticket);
        await settle(6);
        assert.equal(r.emitted.at(-1).signatureValidated, true);
        assert.equal(r.router.getOutboundTicket(lxmfHashOf(known)), null, why);
    }
    assert.equal(r.router.outboundTickets.size, 0, "nothing stored");

    // One that expires after it was remembered is no longer returned
    // (get_outbound_ticket checks the expiry).
    r.router.outboundTickets.set(hex(lxmfHashOf(known)), [now() - 1, hex(Buffer.alloc(16, 4))]);
    assert.equal(r.router.getOutboundTicket(lxmfHashOf(known)), null);
});

test("a stranger the privacy filter drops has no ticket remembered", async (t) => {
    const stranger = Identity.create(), friend = Identity.create();
    knownKeys(t, stranger, friend);
    const allowed = hex(lxmfHashOf(friend));
    const filter = {
        acceptsSource: (source) => hex(source) === allowed,
        acceptsMessage: () => true,
    };
    const r = recipient({ filter });
    for (const from of [stranger, friend]) {
        r.destination.emit("packet", {
            data: lxm(from, r.destination.hash, "hi", new Map([[FIELD_TICKET, pythonTicket(Buffer.alloc(16, 5))]])).subarray(16),
            packet: { prove() {} },
        });
    }
    await settle(6);
    assert.equal(r.router.getOutboundTicket(lxmfHashOf(stranger)), null, "dropped: no ticket remembered");
    assert.equal(hex(r.router.getOutboundTicket(lxmfHashOf(friend))), hex(Buffer.alloc(16, 5)), "kept: remembered");
});

test("OutboundTickets persists what the router remembers and drops expired tickets on load; connect() gives it to the router", async (t) => {
    const storage = memoryStorage();
    const make = () => {
        const store = build("OutboundTickets", { sGet: storage.sGet, sSet: storage.sSet, Date });
        store.init();
        return store;
    };
    const sender = Identity.create();
    knownKeys(t, sender);
    const tickets = make();
    const r = recipient({ tickets });
    r.destination.emit("packet", {
        data: lxm(sender, r.destination.hash, "hi", new Map([[FIELD_TICKET, pythonTicket(Buffer.alloc(16, 6))]])).subarray(16),
        packet: { prove() {} },
    });
    await settle(6);
    const source = hex(lxmfHashOf(sender));
    assert.equal(storage.sGet("outbound_tickets")[source][1], hex(Buffer.alloc(16, 6)), "persisted");

    // A reload keeps it; an entry that has expired since is dropped.
    const stale = storage.sGet("outbound_tickets");
    stale.ab = [now() - 10, hex(Buffer.alloc(16, 1))];
    storage.sSet("outbound_tickets", stale);
    const reloaded = make();
    assert.equal(reloaded.get(source)[1], hex(Buffer.alloc(16, 6)));
    assert.equal(reloaded.get("ab"), undefined, "expired: dropped on load");
    assert.deepEqual(Object.keys(storage.sGet("outbound_tickets")), [source]);
    const r2 = recipient({ tickets: reloaded });
    assert.equal(hex(r2.router.getOutboundTicket(source)), hex(Buffer.alloc(16, 6)), "the router reads it after a reload");

    assert.match(methodBody("async connect()"), /new LXMRouter\(this\._rns, IdMgr\.id, \{ filter: PrivacyFilter, tickets: OutboundTickets \}\)/);
});
