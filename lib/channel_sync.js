/**
 * Channel membership across a distro's devices: RFed-rust SPEC.md §17.12,
 * "Membership sync" (decided by James, 2026-10-03). Pure rules, no network,
 * no DOM; app.js sends and applies (RnsClient._sendDistroChannelSync,
 * _handleDistroBlob, _applyDistroChannelSync).
 *
 * Joining or leaving a channel on one device is applied on every other
 * device of the distro D. The change travels as one LXMF message C from D to
 * D, through the distro fan-out, the way a §17.11 sent copy does; each
 * sibling then subscribes or unsubscribes with its own device key, so RFed
 * sees only ordinary subscriptions.
 *
 *   0x0C FIELD_TICKET       an empty bin: no ticket, but it makes older
 *                           clients take C for a delivery notification and
 *                           drop it. Never read here.
 *   0xFB FIELD_CUSTOM_TYPE  "rfed.distro.channel"
 *   0xFC FIELD_CUSTOM_DATA  [op, name, at_ms] as a native msgpack array,
 *                           never a bin holding packed msgpack
 *                           (CHECK_THESE_THINGS_FIRST.md §11)
 *   0xFD FIELD_CUSTOM_META  the sending device's own lxmf.delivery address
 *
 * A received C is read from the payload's bytes (msgpack_raw.js), not from
 * msgpackr's decoding: msgpackr hands a float that happens to be integral
 * back as a plain number, and §17.12 rule 4 takes only an integer at_ms, as
 * LXMF-rust does (rmpv). A float at_ms would otherwise be applied here and
 * dropped by the phones, and the devices would disagree.
 */

import { readHead, skipValue } from "./rns/msgpack_raw.js";
import { PUBLIC_ROOT, splitChannelName, validateChannelName } from "./channel_name.js";

export const DISTRO_CHANNEL_TYPE = "rfed.distro.channel";

const FIELD_TICKET = 0x0C;
const FIELD_CUSTOM_TYPE = 0xFB;
const FIELD_CUSTOM_DATA = 0xFC;
const FIELD_CUSTOM_META = 0xFD;

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/**
 * The fields of a membership message C (§17.12, the table). `atMs` is the
 * action's time in ms since the epoch (ChannelMembership.stampLocal).
 *
 * at_ms goes as a BigInt: msgpackr writes a JS number above 32 bits as a
 * float 64, which no receiver takes for an integer, and a BigInt below 2^63
 * as an int 64 (0xd3). An int 64 holding a non-negative value is the same
 * non-negative integer to every reader (rmpv Integer::from(i64) is a
 * PosInt; umsgpack an int; readChannelSync below).
 */
export function channelSyncFields(op, name, atMs, deviceHex) {
    if (op !== "join" && op !== "leave") throw new Error(`a membership action is "join" or "leave", not ${op}`);
    if (typeof name !== "string" || name.length === 0) throw new Error("a membership message names its channel");
    if (!Number.isSafeInteger(atMs) || atMs < 0) throw new Error(`at_ms must be a non-negative integer, not ${atMs}`);
    if (typeof deviceHex !== "string" || !/^[0-9a-f]{32}$/i.test(deviceHex)) throw new Error("0xFD is the sending device's own lxmf.delivery address");
    return new Map([
        [FIELD_TICKET, new Uint8Array(0)],
        [FIELD_CUSTOM_TYPE, DISTRO_CHANNEL_TYPE],
        [FIELD_CUSTOM_DATA, [op, name, BigInt(atMs)]],
        [FIELD_CUSTOM_META, deviceHex.toLowerCase()],
    ]);
}

/** A str or bin value as text (strict UTF-8), else null. */
function textOf(head) {
    if (head.kind !== "str" && head.kind !== "bin") return null;
    try {
        return strictUtf8.decode(head.raw);
    } catch {
        return null;
    }
}

/** The head of the value of the first entry of the map at `pos` whose key
 *  is the integer `key`, with its position; null when there is none. */
function mapEntry(b, pos, key) {
    const map = readHead(b, pos);
    if (map.kind !== "map") return null;
    pos = map.end;
    for (let i = 0; i < map.count; i++) {
        const k = readHead(b, pos);
        pos = skipValue(b, pos);
        if (k.kind === "int" && k.int === key) return { pos, head: readHead(b, pos) };
        pos = skipValue(b, pos);
    }
    return null;
}

/**
 * The membership marker of a received LXMF message, from its packed payload
 * [timestamp, title, content, fields, (stamp)]:
 *   - null when the message is no membership message (0xFB is not
 *     "rfed.distro.channel", or the payload has no fields map);
 *   - { byHex, sync: { op, name, atMs }, problem: null } for a usable one;
 *   - { byHex, sync: null, problem } once the type matches but 0xFC is
 *     unusable (§17.12 rule 4: dropped and logged, never taken for an
 *     ordinary message).
 * byHex is 0xFD lowercased, "" when absent; it is not format-checked (a
 * malformed one is simply never this device's own address). op must be
 * "join" or "leave"; name a non-empty str or bin of valid UTF-8; at_ms a
 * non-negative integer of any width. Elements after the third are ignored.
 * The name rules are the disposition's (joinNameAccepted), not this
 * reader's: a leave is not held to them.
 */
export function readChannelSync(packedPayload) {
    if (!(packedPayload instanceof Uint8Array)) return null;
    const b = packedPayload;
    let pos;
    try {
        const top = readHead(b, 0);
        if (top.kind !== "array" || top.count < 4) return null;
        pos = top.end;
        for (let i = 0; i < 3; i++) pos = skipValue(b, pos);
        const type = mapEntry(b, pos, FIELD_CUSTOM_TYPE);
        if (!type || textOf(type.head) !== DISTRO_CHANNEL_TYPE) return null;
    } catch {
        return null;
    }
    let byHex = "";
    const bad = (problem) => ({ byHex, sync: null, problem });
    try {
        const meta = mapEntry(b, pos, FIELD_CUSTOM_META);
        byHex = ((meta && textOf(meta.head)) ?? "").toLowerCase();
        const data = mapEntry(b, pos, FIELD_CUSTOM_DATA);
        if (!data) return bad("it carries no 0xFC");
        if (data.head.kind !== "array") return bad(`its 0xFC is a ${data.head.kind}, not an array`);
        if (data.head.count < 3) return bad(`its 0xFC holds ${data.head.count} element(s), not [op, name, at_ms]`);
        let p = data.head.end;
        const opHead = readHead(b, p);
        p = skipValue(b, p);
        const nameHead = readHead(b, p);
        p = skipValue(b, p);
        const atHead = readHead(b, p);
        const op = textOf(opHead);
        if (op !== "join" && op !== "leave") return bad(`its op is ${op === null ? "not text" : JSON.stringify(op)}, not "join" or "leave"`);
        const name = textOf(nameHead);
        if (!name) return bad("its name is empty, not text, or not UTF-8");
        if (atHead.kind !== "int" || !(atHead.int >= 0)) return bad("its at_ms is not a non-negative integer");
        return { byHex, sync: { op, name, atMs: atHead.int }, problem: null };
    } catch (e) {
        return bad(`its fields cannot be read (${e.message})`);
    }
}

/**
 * Whether a synced join's name is one this client's own join accepts: the
 * rules a typed name must pass in the New Channel form (channel_name.js:
 * the character rule, lowercase and NFC, then validateChannelName in the
 * mode its root gives), exactly, with nothing trimmed. §17.12 rule 4.
 */
export function joinNameAccepted(name) {
    if (typeof name !== "string" || name.normalize("NFC") !== name) return false;
    const { root } = splitChannelName(name);
    const v = validateChannelName(name, root === PUBLIC_ROOT ? "public" : "private");
    return v.ok && v.name === name;
}

/**
 * §17.12 rule 5: whether `incoming` ({op, atMs}) replaces the action
 * recorded for its channel ({op, at}, or null). A later time wins; at an
 * equal time a leave replaces a join and a join never replaces a leave, so
 * every device ends in the same state whatever order the messages arrive in.
 */
export function supersedes(incoming, recorded) {
    if (!recorded) return true;
    if (incoming.atMs > recorded.at) return true;
    if (incoming.atMs < recorded.at) return false;
    return incoming.op === "leave" && recorded.op === "join";
}

/**
 * §17.12 receive rules 1-5, in order; the first that drops a message ends
 * the check. `marker` is readChannelSync's result (not null). The facts the
 * rules need are given, computed by the caller:
 *   fromDistro      the unwrapped source is D (rule 1);
 *   signedByDistro  the LXMF signature is D's (rule 2);
 *   ownDeviceHex    this device's own lxmf.delivery address (rule 3);
 *   channelHashOf   name → the channel hash it gives (§1), the key every
 *                   client stores its channels and this record under;
 *   recordOf        channel hash → the action recorded for it, or null.
 * Returns one of
 *   { verdict: "drop", rule, reason }    dropped with a log line;
 *   { verdict: "echo" }                  this device's own message (rule 3);
 *   { verdict: "stale", op, name, atMs, channelHash, recorded }  rule 5;
 *   { verdict: "apply", op, name, atMs, channelHash }            rule 6 next.
 */
export function channelSyncDisposition(marker, { fromDistro, signedByDistro, ownDeviceHex, channelHashOf, recordOf }) {
    const drop = (rule, reason) => ({ verdict: "drop", rule, reason });
    if (!fromDistro) return drop(1, "its source is not this device's distro");
    if (!signedByDistro) return drop(2, "it fails the distro signature");
    if (ownDeviceHex && marker.byHex === String(ownDeviceHex).toLowerCase()) return { verdict: "echo" };
    if (!marker.sync) return drop(4, marker.problem ?? "its 0xFC is unusable");
    const { op, name, atMs } = marker.sync;
    if (op === "join" && !joinNameAccepted(name)) return drop(4, "its name is one this client's own join refuses");
    const channelHash = channelHashOf(name);
    const recorded = recordOf(channelHash);
    if (!supersedes({ op, atMs }, recorded)) return { verdict: "stale", op, name, atMs, channelHash, recorded };
    return { verdict: "apply", op, name, atMs, channelHash };
}

const MEMBERSHIP_KEY = "channel_membership_v1";

/**
 * §17.12 rule 5's record: per channel hash, the last membership action this
 * device made or applied, { op, at } with `at` in ms. Persisted, and kept
 * after a leave (a leave's record is what stops an older join coming back).
 * Takes a storage adapter { get(key), set(key, value) } holding JSON
 * values, as name_ledger.js does.
 */
export class ChannelMembership {
    constructor(storage) {
        this.storage = storage;
        this.rows = {};
        const stored = storage.get(MEMBERSHIP_KEY);
        if (stored && typeof stored === "object" && !Array.isArray(stored)) this.rows = stored;
    }

    /** The recorded { op, at } for `channelHash`, or null. */
    get(channelHash) {
        const r = this.rows[channelHash];
        if (!r || (r.op !== "join" && r.op !== "leave") || !Number.isFinite(r.at)) return null;
        return { op: r.op, at: r.at };
    }

    record(channelHash, op, at) {
        this.rows[channelHash] = { op, at };
        this.storage.set(MEMBERSHIP_KEY, this.rows);
    }

    /**
     * The user's own join or leave on this device, recorded and stamped:
     * the current time, or one more than the time already recorded for the
     * channel when that is later. So an action made after this device took a
     * sibling's record is newer than that record on every device, even with
     * this device's clock behind the sibling's (§17.12 rule 5). Returns the
     * at_ms the membership message carries.
     */
    stampLocal(channelHash, op, nowMs) {
        const recorded = this.get(channelHash);
        const at = recorded && recorded.at + 1 > nowMs ? recorded.at + 1 : nowMs;
        this.record(channelHash, op, at);
        return at;
    }
}
