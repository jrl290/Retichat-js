import {Destination, LXMessage} from "../reticulum.js";
import EventEmitter from "../utils/events.js";
import Link from "../link.js";
import Packet from "../packet.js";
import MsgPack from "../msgpack.js";

class LXMRouter extends EventEmitter {

    constructor(rns, identity) {

        super();

        this.rns = rns;
        this.identity = identity;

        // register lxmf.delivery destination
        this.destination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");

        // listen for incoming packets
        this.destination.on("packet", (event) => {

            console.log(`[lxmf-router] 📨 Opportunistic packet: ${event.data?.length ?? 0} bytes, first 8: ${Buffer.from(event.data?.slice(0,8) ?? []).toString('hex')}`);

            // prove that the packet was received
            event.packet.prove();

            // parse and log lxmf message
            const receivedLxmfMessage = LXMessage.fromBytes(event.data, this.destination.hash);
            if(!receivedLxmfMessage){
                console.log("[lxmf-router] Failed to parse opportunistic LXMF from packet data");
                return;
            }

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

            // handle packet received over link
            link.on("packet", (event) => {

                console.log(`[lxmf-router] 📨 Link packet: ${event.data?.length ?? 0} bytes, first 8: ${Buffer.from(event.data?.slice(0,8) ?? []).toString('hex')}`);

                // prove that the packet was received
                if(this.handleLinkPayload(link, event.data)){
                    link.proveLinkPacket(event.packet);
                }

            });

            // A message too large for one link packet arrives as a resource.
            // The payload is the same destination hash plus LXMF bytes, and
            // the resource protocol has already proved it.
            link.setResourceStrategy(Link.ACCEPT_ALL);
            link.on("resource", ({ data }) => {
                console.log(`[lxmf-router] 📨 Link resource: ${data?.length ?? 0} bytes`);
                this.handleLinkPayload(link, data);
            });

            // accept link from sender
            link.accept();

        });

    }

    /**
     * Parse an LXMF message delivered over a link and notify listeners.
     * @returns {boolean} whether the payload was a message we could parse
     */
    handleLinkPayload(link, payload) {

        // parse destination hash and lxmf message bytes from link payload
        const data = Array.from(payload ?? []);
        const destinationHash = Buffer.from(data.splice(0, Packet.DESTINATION_HASH_LENGTH));
        const lxmfMessageBytes = Buffer.from(data); // remaining data

        // parse and log lxmf message
        const receivedLxmfMessage = LXMessage.fromBytes(lxmfMessageBytes, destinationHash);
        if(!receivedLxmfMessage){
            console.log("[lxmf-router] Failed to parse direct LXMF from link payload");
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
                // The sender's identity hash is in the received message
                const senderHash = receivedLxmfMessage.sourceHash;
                // Build a minimal delivery notification LXMF message
                const deliveryMsg = new LXMessage();
                deliveryMsg.sourceHash = this.identity.hash;
                deliveryMsg.destinationHash = senderHash;
                deliveryMsg.title = "";
                deliveryMsg.content = "";
                deliveryMsg.fields = new Map();
                // Include the same ticket so the sender can match it
                deliveryMsg.fields.set(FIELD_TICKET, ticket);

                // Pack the delivery notification
                const packed = deliveryMsg.pack(this.identity, false);
                // For link delivery, prepend the destination hash
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
     * Announce the delivery destination with LXMF 1.1 app_data:
     * `[display_name, stamp_cost, supported_functionality]`.
     *
     * - display_name is nil: names travel only inside encrypted messages
     *   (DESIGN_PRINCIPLES.md "Display names are personal data"). Until
     *   2026-09-23 this announced the display name and short hash as raw
     *   bytes, the pre-0.5.0 format.
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
        this.destination.announce(MsgPack.pack([null, null, []]));
    }

}

export default LXMRouter;
