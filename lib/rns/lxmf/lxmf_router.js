import {Destination, LXMessage} from "../reticulum.js";
import EventEmitter from "../utils/events.js";
import Packet from "../packet.js";

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
            const receivedLxmfMessage = LXMessage.fromBytes(event.data);
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

                // parse destination hash and lxmf message bytes from link packet
                const data = Array.from(event.data);
                const destinationHash = Buffer.from(data.splice(0, Packet.DESTINATION_HASH_LENGTH));
                const lxmfMessageBytes = Buffer.from(data); // remaining data

                // parse and log lxmf message
                const receivedLxmfMessage = LXMessage.fromBytes(lxmfMessageBytes);
                if(!receivedLxmfMessage){
                    console.log("[lxmf-router] Failed to parse direct LXMF from link packet data");
                    return;
                }

                // prove that the packet was received
                link.proveLinkPacket(event.packet);

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

            });

            // accept link from sender
            link.accept();

        });

    }

    announce(displayName) {
        console.log("announcing lxmf destination", this.destination.hash.toString("hex"));
        // fixme: this is using the old format, need to update to new format with stamp cost
        this.destination.announce(Buffer.from(displayName));
    }

}

export default LXMRouter;
