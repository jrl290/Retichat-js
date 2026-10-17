import {Destination, LXMessage} from "../reticulum.js";
import EventEmitter from "../utils/events.js";
import Link from "../link.js";
import Packet from "../packet.js";
import MsgPack from "../msgpack.js";
import { isRefusal } from "../msgpack_keys.js";

class LXMRouter extends EventEmitter {

    /**
     * LXMF's per-transfer delivery limit, in KB (LXMF/LXMRouter.py
     * DELIVERY_LIMIT = 1000; LXMF-rust lxm_router.rs DELIVERY_LIMIT = 1000.0).
     * delivery_resource_advertised rejects a delivery Resource whose data
     * size exceeds delivery_per_transfer_limit * 1000 bytes.
     */
    static DELIVERY_LIMIT = 1000;

    /**
     * The least time between two rotations of the delivery destination's
     * ratchets, in seconds: RATCHET_EXPIRY / (RATCHET_COUNT - 1), 30 days
     * over the 511 ratchets older than the newest, about 85 minutes. A
     * sender encrypts to the ratchet it heard last for up to 30 days (RNS
     * Identity.get_ratchet), so the 512 kept must span that long. The web
     * announces every 5 minutes, and at RNS's 30-minute interval (LXMF's
     * default) its 512 would span about 11 days. Literals here, as this
     * module is evaluated inside the Identity/Destination import cycle;
     * ratchets.test.mjs checks the value.
     */
    static DELIVERY_RATCHET_INTERVAL = Math.ceil((30 * 24 * 60 * 60) / (512 - 1));

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

    /** Where the payload starts after the source: the signature's length. */
    static SIGNATURE_LENGTH = 64;

    /** LXMF's delivery ticket field (LXMF.py FIELD_TICKET). */
    static FIELD_TICKET = 0x0C;

    /**
     * @param rns
     * @param identity
     * @param {{filter?: {acceptsSource(sourceHash: Buffer, path: string,
     *                                  peekGroup: () => ({groupId: string, groupAction: string|null}|null)): boolean,
     *                    acceptsMessage(message: LXMessage, path: string): boolean},
     *          tickets?: {get(sourceHex: string): ([number, string]|undefined),
     *                     set(sourceHex: string, entry: [number, string]): void}}} options
     *   `filter` is the client's privacy filter (see acceptsSource and
     *   acceptsMessage). None accepts everything, as before 2026-09-30.
     *   `tickets` keeps the outbound tickets rememberTicket learns, by
     *   source hash (hex): [expires (s), ticket (hex)]; the app's persists
     *   them, as LXMF saves available_tickets. None keeps them in memory.
     *   `ratchets` keeps the delivery destination's ratchet keys
     *   ({load(), save(blob)}, Destination.enableRatchets); the app's
     *   stores them per destination (OwnRatchets). None: no ratchets, so an
     *   app.js that knows nothing of them (one older than this lib, during a
     *   deploy or from a cache) never announces a ratchet it cannot keep or
     *   decrypt the propagated messages for.
     */
    constructor(rns, identity, { filter = null, tickets = null, ratchets = null } = {}) {

        super();

        this.rns = rns;
        this.identity = identity;
        this.announceName = null;
        this.filter = filter;
        this.outboundTickets = tickets ?? new Map();

        // Every message handed on, on every path, first has its ticket
        // remembered (rememberTicket). Registered before anyone else can
        // listen, so it runs before the app's handler.
        this.on("message", (message) => this.rememberTicket(message));

        // register lxmf.delivery destination
        this.destination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");

        // LXMF enables ratchets on the delivery destination it registers
        // (LXMRouter.py register_delivery_identity): its announces carry
        // the newest ratchet, and what peers encrypt to one is decrypted
        // with it. Only this destination has them: not rfed.delivery, not
        // the distro's announce (app.js _publishDistroAnnounce). A test's
        // stand-in for the destination has none. They rotate every
        // DELIVERY_RATCHET_INTERVAL, not RNS's 30 minutes.
        if(ratchets && this.destination instanceof Destination){
            this.destination.enableRatchets(ratchets);
            this.destination.setRatchetInterval(LXMRouter.DELIVERY_RATCHET_INTERVAL);
        }

        // listen for incoming packets
        this.destination.on("packet", (event) => {

            const data = event.data;
            console.log(`[lxmf-router] 📨 Opportunistic packet: ${data?.length ?? 0} bytes, first 8: ${Buffer.from(data?.slice(0,8) ?? []).toString('hex')}`);

            // RNS Destination.receive hands its packet callback only what it
            // could decrypt, so LXMF (LXMRouter.py delivery_packet) never
            // proves a packet it cannot read. destination.js drops such a
            // packet before it gets here (Destination.onPacket); this guard
            // stays for any packet handed on without plaintext.
            if(!data){
                console.log("[lxmf-router] Opportunistic packet could not be decrypted");
                return;
            }
            this.decrypted(event.packet?.ratchetId);

            // The privacy filter first, on the decrypted bytes: a stranger's
            // message is dropped here, unproved and unparsed, unless it is a
            // group message for a group held here (admission).
            const admitted = this.admission(data, "opportunistic");
            if(!admitted){
                return;
            }

            // parse and log lxmf message
            const receivedLxmfMessage = this.parse(data, this.destination.hash, "opportunistic");
            if(!receivedLxmfMessage){
                // LXMRouter.py delivery_packet proves before it parses, so a
                // packet from a source the filter keeps that decrypts but is
                // no message, or is refused whole (a payload that repeats a
                // key: lxmf_delivery drops it after the proof), is proved, as
                // it always was here. A stranger's is not: it got this far
                // only as a group message, and it is none.
                if(admitted === "source"){
                    event.packet.prove();
                }
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
            // destination is PROVE_NONE): the handler below proves what
            // LXMF's delivery_packet would, except a filtered message.
            link.proveAll = false;

            // handle packet received over link
            link.on("packet", (event) => {

                console.log(`[lxmf-router] 📨 Link packet: ${event.data?.length ?? 0} bytes, first 8: ${Buffer.from(event.data?.slice(0,8) ?? []).toString('hex')}`);

                // handleLinkPayload proves the packet when LXMF would and the
                // privacy filter did not drop it (a dropped one is never proved)
                this.handleLinkPayload(link, event.data, "link", () => link.proveLinkPacket(event.packet));

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
            // drops it in handleLinkPayload: no parse, nothing stored
            // (unless it is a group message for a group held here: admission
            // walks past its content without reading it).
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
     * A propagated message's ciphertext (what follows its destination hash),
     * decrypted for the delivery destination with its ratchets, as
     * LXMRouter.py lxmf_propagation does (delivery_destination.decrypt):
     * the plaintext, or null when no key opens it. app.js
     * _ingestPropagatedBlob calls it for a /get result and an rfed.link
     * push alike. The older ratchets are tried without holding the page
     * (Destination.decryptSoon), so the answer may come later.
     * @returns {Buffer|null|Promise<Buffer|null>} a promise when the older
     *   ratchets had to be tried
     */
    decryptPropagated(ciphertext) {
        const said = (plaintext) => {
            if(plaintext){
                this.decrypted();
            }
            return plaintext;
        };
        const plaintext = this.destination.decryptSoon(ciphertext);
        return plaintext instanceof Promise ? plaintext.then(said) : said(plaintext);
    }

    /**
     * Says which key opened a message to the delivery destination: the
     * ratchet's id, or "identity". Staging reads this line. `ratchetId` is
     * the one an opportunistic packet carries (Destination.onPacket keeps it
     * on the packet when it decrypts, as this runs a task later); a
     * propagated message's is read at once (decryptPropagated).
     */
    decrypted(ratchetId = this.destination.latestRatchetId) {
        console.log(`[RATCHET] decrypt dest=${Buffer.from(this.destination.hash).toString("hex").slice(0, 8)} key=${ratchetId ? Buffer.from(ratchetId).toString("hex") : "identity"}`);
    }

    /**
     * The privacy filter's first question, asked of every message the
     * moment it is decrypted and before anything else is spent on it: may
     * a message from this LXMF source be kept? `lxmfBytes` is the plaintext
     * from the LXMF source on: source (16) | signature (64) | payload, the
     * whole of an opportunistic packet's plaintext and of a propagated
     * message, a link payload after its destination hash. No: the message is
     * dropped where it stands, with no proof, no parse (no msgpack decode, no
     * hash, no signature check), no ticket remembered and nothing stored.
     *
     * The filter answers from the source alone when it knows it (an
     * allowlisted contact, a member of a group the user has joined): nothing more is
     * read. For any other source it may call `peekGroup`, which reads the
     * payload just far enough to see whether this is a group message for a
     * group held here (LXMessage.peekGroupFields: the fields are walked,
     * only the group id and action decoded), the one thing iOS keeps from a
     * source it has not allowlisted (ChatRepository.swift
     * groupMessagePolicy; James, 2026-09-30). Such a message then goes on as
     * any other: parsed, asked about again (acceptsMessage), proved, kept.
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
    acceptsSource(lxmfBytes, path) {
        return this.admission(lxmfBytes, path) !== null;
    }

    /**
     * acceptsSource, saying why a message was let through: "source" when
     * the filter knows its source (or there is no filter), "group" when a
     * stranger's message was let through only as a group message for a
     * group held here; null when it is dropped. The router proves a packet
     * that does not parse only for a "source" (see the opportunistic path):
     * a stranger's was let in as a group message, and it is none.
     * @returns {"source"|"group"|null}
     */
    admission(lxmfBytes, path) {
        if(!this.filter){
            return "source";
        }
        const bytes = lxmfBytes ?? Buffer.alloc(0);
        const sourceHash = bytes.subarray(0, LXMRouter.SOURCE_LENGTH);
        let peeked = false;
        const peekGroup = () => {
            peeked = true;
            return LXMessage.peekGroupFields(bytes.subarray(LXMRouter.SOURCE_LENGTH + LXMRouter.SIGNATURE_LENGTH));
        };
        let accepted;
        try {
            accepted = !!this.filter.acceptsSource(sourceHash, path, peekGroup);
        } catch(e) {
            console.error(`[lxmf-router] the privacy filter failed on a ${path} message (${e.message}); dropped`);
            accepted = false;
        }
        if(!accepted){
            console.log(`[lxmf-router] 🔒 ${path} message from ${Buffer.from(sourceHash).toString('hex').slice(0,12)}... dropped by the privacy filter before parsing: no proof, nothing stored`);
            return null;
        }
        if(peeked){
            console.log(`[lxmf-router] ${path} message from ${Buffer.from(sourceHash).toString('hex').slice(0,12)}..., a source the filter does not know, kept as a group message for a group held here`);
            return "group";
        }
        return "source";
    }

    /**
     * A received message parsed (LXMessage.unpackFromBytes), or null with
     * one log line: a payload that repeats a key was refused whole and said
     * so where it was refused (RFed SPEC §17.14 "Repeated keys"; LXMF-rust's
     * router adds no line of its own either); anything else that is no
     * message is said here.
     */
    parse(lxmfBytes, destinationHash, path) {
        try {
            return LXMessage.unpackFromBytes(lxmfBytes, destinationHash);
        } catch(e) {
            if(!isRefusal(e)){
                console.log(`[lxmf-router] Failed to parse ${path} LXMF (${e?.message ?? e})`);
            }
            return null;
        }
    }

    /**
     * The privacy filter's second question, for a message whose source
     * passed acceptsSource but whose fate depends on what it is (a group
     * message, a group invite, a distro identity transfer): asked after the
     * parse and before the proof and the listeners. No:
     * dropped, unproved. Same failure rule as acceptsSource.
     *
     * Asked first, filter or none: a message whose GROUP_ID is not a str of
     * 32 hex characters is refused, with one line, never a direct message
     * or a group (RFed SPEC §17.14, the direct path; LXMessage.groupIdRefusal).
     * Every direct path asks here before the proof and the listeners: the
     * opportunistic packet, the link packet and Resource, and the
     * propagated message (app.js _ingestPropagatedBlob).
     * @returns {boolean}
     */
    acceptsMessage(message, path) {
        const refusal = LXMessage.groupIdRefusal(message);
        if(refusal !== null){
            console.log(`[lxmf-router] ${path} message from ${message?.sourceHash?.toString('hex')?.slice(0,12)}... refused: ${refusal} (RFed SPEC §17.14): never a direct message or a group, no proof, nothing stored`);
            return false;
        }
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
     * `prove` proves a link packet; a Resource passes none, since the
     * Resource protocol proved it on assembly.
     *
     * LXMF hands link packets to delivery_packet too (LXMRouter.py
     * delivery_link_established: set_packet_callback(self.delivery_packet)),
     * which proves before it parses. So a packet whose source passed the
     * privacy filter is proved even when it does not parse, as on the
     * opportunistic path; only the filter's drops go unproved.
     * @returns {boolean} whether the payload was a message we parsed and kept
     */
    handleLinkPayload(link, payload, path = "link", prove = null) {

        // RNS Link.receive calls LXMF only with plaintext (RNS/Link.py:951-957)
        if(!payload){
            console.log(`[lxmf-router] ${path} payload has no plaintext; ignored`);
            return false;
        }

        // parse destination hash and lxmf message bytes from link payload:
        // destination | source | signature | payload
        const data = Buffer.from(payload);
        const destinationHash = data.subarray(0, Packet.DESTINATION_HASH_LENGTH);
        const lxmfMessageBytes = data.subarray(Packet.DESTINATION_HASH_LENGTH); // remaining data

        // the privacy filter first, on the decrypted bytes (acceptsSource)
        const admitted = this.admission(lxmfMessageBytes, path);
        if(!admitted){
            return false;
        }

        // parse and log lxmf message
        const receivedLxmfMessage = this.parse(lxmfMessageBytes, destinationHash, path);
        if(!receivedLxmfMessage){
            // proved, as delivery_packet proves before it parses (see above),
            // when its source is one the filter keeps (admission)
            if(admitted === "source"){
                prove?.();
            }
            return false;
        }

        if(!this.acceptsMessage(receivedLxmfMessage, path)){
            return false;
        }

        // prove that the packet was received: only once the message is
        // kept (see acceptsSource), and first, as delivery_packet does
        prove?.();

        console.log(`[lxmf-router] ✅ RX direct: src=${receivedLxmfMessage.sourceHash?.toString('hex')?.slice(0,12)}... content="${(receivedLxmfMessage.content?.toString() ?? '').slice(0,60)}"`);

        // fire callback. Nothing is sent back for a ticket the message
        // carries: LXMF has no ticket reply. It remembers the ticket
        // (rememberTicket, on every path) and answers nothing; the proof
        // above is the sender's delivery evidence. Until 2026-10-01 this
        // sent a "delivery notification" on the link for every ticketed
        // message: an LXMF message that carried the destination hash twice,
        // which no receiver could parse, on a link the web sender does not
        // listen to (RnsClient._ensureGroupLink sets no packet handler), and
        // which the Python sender's backchannel (LXMRouter.py
        // delivery_link_established) logged as unassemblable.
        this.emit("message", receivedLxmfMessage);

        return true;

    }

    /** LXMF's ticket length, 16 bytes (LXMessage.py TICKET_LENGTH =
     *  RNS.Identity.TRUNCATED_HASHLENGTH//8). */
    static TICKET_LENGTH = 16;

    /**
     * Remember the ticket a delivered message carries, as LXMF does for
     * every message it delivers (LXMRouter.py lxmf_delivery ->
     * remember_ticket): only from a message whose signature validated, only
     * a ticket in LXMF's form [expires, ticket] whose expiry is still ahead
     * and whose ticket is 16 bytes, kept as the outbound ticket for the
     * message's source (available_tickets["outbound"][source_hash], the one
     * get_outbound_ticket returns). The web's own ticket (a 16-character hex
     * str, app.js _sendPacket) is not in that form and is not remembered.
     *
     * Run for every message the router hands on (its "message" event, the
     * propagated /get included), so after the privacy filter: a dropped
     * stranger's ticket is not remembered. LXMF remembers it before its
     * ignored_list check; James, 2026-09-30: a dropped message gets "no
     * proof, no ticket reply, no name, no store".
     *
     * Nothing here sends with a remembered ticket yet: LXMF's one use of it
     * is the ticket stamp (LXMessage.py get_stamp), and the web generates
     * no delivery stamps.
     * @returns {boolean} whether a ticket was remembered
     */
    rememberTicket(message) {
        if (!message || message.signatureValidated !== true) return false;
        const entry = message.fields instanceof Map ? message.fields.get(LXMRouter.FIELD_TICKET) : null;
        if (!Array.isArray(entry) || entry.length < 2) return false;
        const [expires, ticket] = entry;
        if (typeof expires !== "number" || !(Date.now() / 1000 < expires)) return false;
        if (!(ticket instanceof Uint8Array) || ticket.length !== LXMRouter.TICKET_LENGTH) return false;
        let source;
        try {
            source = Buffer.from(message.sourceHash).toString("hex");
            this.outboundTickets.set(source, [expires, Buffer.from(ticket).toString("hex")]);
        } catch (e) {
            console.warn(`[lxmf-router] could not remember a ticket: ${e.message}`);
            return false;
        }
        console.log(`[lxmf-router] remembering the ticket from ${source.slice(0, 12)}..., expires in ${Math.round(expires - Date.now() / 1000)} s`);
        return true;
    }

    /** The ticket remembered for `destinationHash` (Buffer or hex) while it
     *  has not expired, else null (LXMRouter.py get_outbound_ticket). */
    getOutboundTicket(destinationHash) {
        const key = typeof destinationHash === "string" ? destinationHash : Buffer.from(destinationHash).toString("hex");
        const entry = this.outboundTickets.get(key);
        if (!Array.isArray(entry) || !(entry[0] > Date.now() / 1000)) return null;
        return Buffer.from(entry[1], "hex");
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
