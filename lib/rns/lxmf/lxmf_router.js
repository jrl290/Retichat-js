import {Destination, LXMessage} from "../reticulum.js";
import EventEmitter from "../utils/events.js";
import Link from "../link.js";
import Packet from "../packet.js";
import MsgPack from "../msgpack.js";

class LXMRouter extends EventEmitter {

    /**
     * LXMF's per-transfer delivery limit, in KB (LXMF/LXMRouter.py
     * DELIVERY_LIMIT = 1000; LXMF-rust lxm_router.rs DELIVERY_LIMIT = 1000.0).
     * delivery_resource_advertised rejects a delivery Resource whose data
     * size exceeds delivery_per_transfer_limit * 1000 bytes.
     */
    static DELIVERY_LIMIT = 1000;

    /** LXMF/LXMRouter.py delivery_resource_advertised(). */
    static deliveryResourceAdvertised(advertisement) {
        const size = Number(advertisement?.dataSize);
        const limit = LXMRouter.DELIVERY_LIMIT * 1000;
        if(!Number.isFinite(size) || size > limit){
            console.log(`[lxmf-router] rejecting an incoming delivery Resource of ${advertisement?.dataSize} bytes (limit ${limit})`);
            return false;
        }
        return true;
    }

    /** Where the LXMF source sits in the decrypted bytes: first in an
     *  opportunistic packet's plaintext and a propagated message (source |
     *  signature | payload), after the destination hash in a link packet or
     *  a link Resource (destination | source | signature | payload). */
    static SOURCE_LENGTH = 16;

    /**
     * @param rns
     * @param identity
     * @param {{filter?: {acceptsSource(sourceHash: Buffer, path: string): boolean,
     *                    acceptsMessage(message: LXMessage, path: string): boolean}}} options
     *   `filter` is the client's privacy filter (see acceptsSource and
     *   acceptsMessage). None accepts everything, as before 2026-09-30.
     */
    constructor(rns, identity, { filter = null } = {}) {

        super();

        this.rns = rns;
        this.identity = identity;
        this.announceName = null;
        this.filter = filter;

        // register lxmf.delivery destination
        this.destination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");

        // listen for incoming packets
        this.destination.on("packet", (event) => {

            const data = event.data;
            console.log(`[lxmf-router] 📨 Opportunistic packet: ${data?.length ?? 0} bytes, first 8: ${Buffer.from(data?.slice(0,8) ?? []).toString('hex')}`);

            // RNS Destination.receive hands its packet callback only what it
            // could decrypt, so LXMF (LXMRouter.py delivery_packet) never
            // proves a packet it cannot read. destination.js emits one anyway,
            // with no plaintext.
            if(!data){
                console.log("[lxmf-router] Opportunistic packet could not be decrypted");
                return;
            }

            // The privacy filter first, on the decrypted bytes: a stranger's
            // message is dropped here, unproved and unparsed.
            if(!this.acceptsSource(data.subarray(0, LXMRouter.SOURCE_LENGTH), "opportunistic")){
                return;
            }

            // parse and log lxmf message
            const receivedLxmfMessage = LXMessage.fromBytes(data, this.destination.hash);
            if(!receivedLxmfMessage){
                // LXMRouter.py delivery_packet proves before it parses, so a
                // packet that decrypts but is no message is proved, as it
                // always was here.
                event.packet.prove();
                console.log("[lxmf-router] Failed to parse opportunistic LXMF from packet data");
                return;
            }

            if(!this.acceptsMessage(receivedLxmfMessage, "opportunistic")){
                return;
            }

            // prove that the packet was received: only once the message is
            // kept (see acceptsSource)
            event.packet.prove();

            console.log(`[lxmf-router] ✅ RX opportunistic: src=${receivedLxmfMessage.sourceHash?.toString('hex')?.slice(0,12)}... content="${(receivedLxmfMessage.content?.toString() ?? '').slice(0,60)}"`);

            // fire callback
            this.emit("message", receivedLxmfMessage);

        });

        // listen for link requests for receiving direct lxmf messages
        this.destination.on("link_request", (link) => {

            // log
            console.log("on link request", link);

            // log when link is established
            link.on("established", () => {
                console.log(`link established rtt: ${link.rtt}ms`);
            });

            // A delivery link proves nothing by itself (LXMF's delivery
            // destination is PROVE_NONE): the handler below proves a
            // message once it is kept.
            link.proveAll = false;

            // handle packet received over link
            link.on("packet", (event) => {

                console.log(`[lxmf-router] 📨 Link packet: ${event.data?.length ?? 0} bytes, first 8: ${Buffer.from(event.data?.slice(0,8) ?? []).toString('hex')}`);

                // prove that the packet was received: only a message this
                // client parsed and kept (a dropped one is never proved)
                if(this.handleLinkPayload(link, event.data, "link")){
                    link.proveLinkPacket(event.packet);
                }

            });

            // A message too large for one link packet arrives as a resource.
            // The payload is the same destination hash plus LXMF bytes, and
            // the resource protocol has already proved it. As LXMF does
            // (LXMRouter.py:1959-1960), each advertisement is checked against
            // the per-transfer limit before a single part is asked for: until
            // 2026-09-30 this link took any Resource (ACCEPT_ALL), so a peer
            // could make the tab fetch and hold whatever it advertised.
            //
            // The privacy filter cannot act on the advertisement: an LXMF
            // delivery link is not identified (the reference sender identifies
            // only after its message is delivered, for the backchannel:
            // LXMRouter.py process_outbound), and the source is inside the
            // encrypted data. So a stranger's Resource is transferred, and the
            // Resource protocol proves it on assembly (RNS/Resource.py
            // assemble -> prove) before this link hands it up. The filter then
            // drops it in handleLinkPayload: no parse, no ticket reply, nothing
            // stored.
            link.setResourceStrategy(Link.ACCEPT_APP);
            link.setResourceCallback((advertisement) => LXMRouter.deliveryResourceAdvertised(advertisement));
            link.on("resource", ({ data }) => {
                console.log(`[lxmf-router] 📨 Link resource: ${data?.length ?? 0} bytes`);
                this.handleLinkPayload(link, data, "resource");
            });

            // accept link from sender
            link.accept();

        });

    }

    /**
     * The privacy filter's first question, asked of every message the
     * moment it is decrypted and before anything else is spent on it: may
     * a message from this LXMF source be kept? `sourceHash` is bytes 0..16
     * of the plaintext (16..32 of a link payload). No: the message is
     * dropped where it stands, with no proof, no parse (no msgpack, no hash,
     * no signature check), no delivery-ticket reply and nothing stored.
     *
     * This departs from the reference on purpose. LXMF proves every
     * delivery packet before it parses it (LXMRouter.py delivery_packet) and
     * drops an ignored source only after the parse (lxmf_delivery,
     * ignored_list). A proof tells the sender the message was delivered;
     * for a message this client throws away that is a false outcome, and it
     * costs the tab a signature (James, 2026-09-30: no proof is sent when a
     * message is dropped).
     *
     * A filter that throws drops the message (a stranger's message must not
     * get in through a bug), and says so.
     * @returns {boolean}
     */
    acceptsSource(sourceHash, path) {
        if(!this.filter){
            return true;
        }
        let accepted;
        try {
            accepted = !!this.filter.acceptsSource(sourceHash, path);
        } catch(e) {
            console.error(`[lxmf-router] the privacy filter failed on a ${path} message (${e.message}); dropped`);
            accepted = false;
        }
        if(!accepted){
            console.log(`[lxmf-router] 🔒 ${path} message from ${Buffer.from(sourceHash ?? []).toString('hex').slice(0,12)}... dropped by the privacy filter before parsing: no proof, nothing stored`);
        }
        return accepted;
    }

    /**
     * The privacy filter's second question, for a message whose source
     * passed acceptsSource but whose fate depends on what it is (a group
     * message, a group invite, a distro identity transfer): asked after the
     * parse and before the proof, the ticket reply and the listeners. No:
     * dropped, unproved. Same failure rule as acceptsSource.
     * @returns {boolean}
     */
    acceptsMessage(message, path) {
        if(!this.filter){
            return true;
        }
        let accepted;
        try {
            accepted = !!this.filter.acceptsMessage(message, path);
        } catch(e) {
            console.error(`[lxmf-router] the privacy filter failed on a ${path} message (${e.message}); dropped`);
            accepted = false;
        }
        if(!accepted){
            console.log(`[lxmf-router] 🔒 ${path} message from ${message?.sourceHash?.toString('hex')?.slice(0,12)}... dropped by the privacy filter: no proof, nothing stored`);
        }
        return accepted;
    }

    /**
     * Parse an LXMF message delivered over a link and notify listeners.
     * `path` is "link" (a link packet) or "resource" (a link Resource).
     * @returns {boolean} whether the payload was a message we parsed and
     *   kept; only then is a link packet proved
     */
    handleLinkPayload(link, payload, path = "link") {

        // parse destination hash and lxmf message bytes from link payload:
        // destination | source | signature | payload
        const data = Buffer.from(payload ?? []);
        const destinationHash = data.subarray(0, Packet.DESTINATION_HASH_LENGTH);
        const lxmfMessageBytes = data.subarray(Packet.DESTINATION_HASH_LENGTH); // remaining data

        // the privacy filter first, on the decrypted bytes (acceptsSource)
        if(!this.acceptsSource(lxmfMessageBytes.subarray(0, LXMRouter.SOURCE_LENGTH), path)){
            return false;
        }

        // parse and log lxmf message
        const receivedLxmfMessage = LXMessage.fromBytes(lxmfMessageBytes, destinationHash);
        if(!receivedLxmfMessage){
            console.log("[lxmf-router] Failed to parse direct LXMF from link payload");
            return false;
        }

        if(!this.acceptsMessage(receivedLxmfMessage, path)){
            return false;
        }

        console.log(`[lxmf-router] ✅ RX direct: src=${receivedLxmfMessage.sourceHash?.toString('hex')?.slice(0,12)}... content="${(receivedLxmfMessage.content?.toString() ?? '').slice(0,60)}"`);

        // fire callback
        this.emit("message", receivedLxmfMessage);

        // Send delivery notification back to the sender if the message
        // includes a delivery ticket (FIELD_TICKET = 0x0C).
        const FIELD_TICKET = 0x0C;
        if (receivedLxmfMessage.fields && receivedLxmfMessage.fields.has(FIELD_TICKET)) {
            const ticket = receivedLxmfMessage.fields.get(FIELD_TICKET);
            try {
                // The sender's lxmf.delivery hash is the received message's source
                const senderHash = receivedLxmfMessage.sourceHash;
                // Build a minimal delivery notification LXMF message
                const deliveryMsg = new LXMessage();
                // An LXMF source is an lxmf.delivery destination hash, the
                // one the recipient recalls the signing key by. Until
                // 2026-09-30 this was the identity hash, which no LXMF
                // client can recall, so no reply ever validated.
                deliveryMsg.sourceHash = this.destination.hash;
                deliveryMsg.destinationHash = senderHash;
                deliveryMsg.title = "";
                deliveryMsg.content = "";
                deliveryMsg.fields = new Map();
                // Include the same ticket so the sender can match it
                deliveryMsg.fields.set(FIELD_TICKET, ticket);

                // Pack the delivery notification
                const packed = deliveryMsg.pack(this.identity, false);
                // For link delivery, prepend the destination hash.
                // NOTE (2026-09-30, not changed here): pack(identity, false)
                // already starts with the destination hash, so the payload
                // carries it twice and no LXMF receiver can parse it (the
                // reference sends the full packing alone on a link:
                // LXMessage.py __as_packet). Reported rather than fixed: a
                // parseable reply would reach a Python sender's backchannel
                // (LXMRouter.py delivery_link_established) as an empty message.
                const deliveryData = Buffer.concat([
                    senderHash,  // destinationHash for link routing
                    packed       // full LXMF message bytes
                ]);
                link.send(deliveryData);
                console.log(`[lxmf-router] 📤 Sent delivery notification to ${senderHash.toString('hex').slice(0,12)}...`);
            } catch (e) {
                console.log("[lxmf-router] Failed to send delivery notification:", e.message);
            }
        }

        return true;

    }

    /**
     * The Announce Display Name (LXMF-rust/DISPLAY_NAMES.md §1, §2.2): the
     * one name this client broadcasts, only when the user fills it in. A
     * change takes effect on the next announce. `name` is cleaned already
     * (display_name.js clean); anything else is treated as no name.
     */
    setAnnounceName(name) {
        this.announceName = (typeof name === "string" && name.length > 0) ? name : null;
    }

    /** The app_data the next announce carries (see announce()). */
    announceAppData() {
        return MsgPack.pack([
            this.announceName ? Buffer.from(this.announceName, "utf8") : null,
            null,
            [],
        ]);
    }

    /**
     * Announce the delivery destination with LXMF 1.1 app_data:
     * `[announce_name, stamp_cost, supported_functionality]`.
     *
     * - announce_name is the Announce Display Name as bin, or nil when the
     *   user has not set one (DISPLAY_NAMES.md §2.2: the web client's
     *   `[announce_name, nil, []]`). Names are otherwise carried inside
     *   messages (field 0xD1), never broadcast by default.
     * - stamp_cost is nil: this client requires no delivery stamp.
     * - supported_functionality is an empty list: LXMF/LXMF.py
     *   compression_support_from_app_data() reads SF_COMPRESSION (0x00)
     *   from it, and senders compress a Resource only when it is present.
     *   This client cannot decompress (lib/rns/resource.js), so the raw
     *   format, which peers read as "supports compression", made every
     *   message over the link MDU from a Python or Rust peer arrive as a
     *   compressed Resource that the client had to reject.
     */
    announce() {
        console.log("announcing lxmf destination", this.destination.hash.toString("hex"));
        this.destination.announce(this.announceAppData());
    }

}

export default LXMRouter;
