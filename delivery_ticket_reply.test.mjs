/**
 * The delivery-ticket reply the web sends on a delivery link, for a
 * received message that carries FIELD_TICKET (0x0C), is an LXMF message
 * from this client: its source is the lxmf.delivery destination hash, the
 * one a recipient recalls the signing key by (LXMessage.py
 * unpack_from_bytes: RNS.Identity.recall(source_hash)). Until 2026-09-30 it
 * was the identity hash, which no LXMF client can recall, so no reply ever
 * validated.
 *
 * Run: node --test delivery_ticket_reply.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import Identity from "./lib/rns/identity.js";
import Destination from "./lib/rns/destination.js";
import LXMessage from "./lib/rns/lxmf/lxmf_message.js";
import LXMRouter from "./lib/rns/lxmf/lxmf_router.js";
import EventEmitter from "./lib/rns/utils/events.js";
import { linkPair, settle } from "./test_link_pair.mjs";

const FIELD_TICKET = 0x0C;
const hex = (b) => Buffer.from(b).toString("hex");

test("the delivery-ticket reply comes from this client's lxmf.delivery hash, not its identity hash, and validates", async () => {
    const me = Identity.create(), sender = Identity.create();
    const destination = new EventEmitter();
    destination.hash = Destination.hash(me, "lxmf", "delivery");
    new LXMRouter({ registerDestination: () => destination }, me);
    const { a, b } = linkPair();
    b.accept = () => {};                          // already established here
    destination.emit("link_request", b);
    await settle();

    const m = new LXMessage();
    m.sourceHash = Destination.hash(sender, "lxmf", "delivery");
    m.destinationHash = destination.hash;
    m.title = "";
    m.content = "with a ticket";
    m.fields = new Map([[FIELD_TICKET, "0123456789abcdef"]]);
    const got = [];
    a.on("packet", ({ data }) => got.push(Buffer.from(data)));
    a.send(m.pack(sender, false));
    await settle(6);

    assert.equal(got.length, 1, "one reply");
    // The payload is the sender's hash, then the reply's full packing
    // (destination | source | signature | payload): see the NOTE in
    // LXMRouter.handleLinkPayload on the doubled destination hash.
    const full = got[0].subarray(16);
    assert.equal(hex(full.subarray(0, 16)), hex(m.sourceHash), "addressed to the sender");
    const recall = (h) => (Buffer.from(h).equals(destination.hash) ? me : null);
    const reply = LXMessage.fromBytes(full.subarray(16), full.subarray(0, 16), recall);
    assert.equal(hex(reply.sourceHash), hex(destination.hash), "the LXMF source is our lxmf.delivery hash");
    assert.notEqual(hex(reply.sourceHash), hex(me.hash), "never the identity hash");
    assert.equal(reply.signatureValidated, true, "so a recipient that knows our key validates it");
    assert.equal(reply.fields.get(FIELD_TICKET), "0123456789abcdef", "carrying the sender's ticket");
    assert.equal(reply.content, "");
});
