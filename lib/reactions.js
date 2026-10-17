/**
 * Reactions on messages (REACTIONS-DESIGN.md): the rules a message record's
 * reactions follow, with no network and no DOM. app.js reads and writes the
 * wire (LXMF's 0x40 field, lib/rns/lxmf/lxmf.js readReaction and
 * reactionField) and keeps the records (MsgStore, GroupMsgStore).
 *
 * A record's `reactions` is an object keyed by the reactor's address (32
 * lowercase hex): { e: the reaction (an emoji, or any text up to 64 bytes),
 * t: when it was made, ms }. One reaction per person per message: a newer
 * one replaces theirs. An `e` of "" is a reaction taken back, kept so that
 * an older reaction arriving late cannot bring it back (§3 apply_reaction).
 */

/** The six quick reactions every Retichat offers (§7). */
export const QUICK_REACTIONS = Object.freeze(["👍", "❤️", "😂", "😮", "😢", "🙏"]);

const HEX32 = /^[0-9a-f]{32}$/;

/**
 * §3 apply_reaction: `reactions` (a record's, or undefined) with reactor
 * `reactor`'s reaction `emoji` made at `at` (ms). Returns the new reactions
 * object, or null when nothing changes: the reactor's reaction held is as
 * new as this one or newer (an older or a repeated one is ignored). Never
 * changes `reactions` itself. Throws on a reactor that is not 32 lowercase
 * hex, an emoji that is not a string, or a time that is not a finite number.
 */
export function applyReaction(reactions, reactor, emoji, at) {
    if (typeof reactor !== "string" || !HEX32.test(reactor)) throw new TypeError("a reactor is an address of 32 lowercase hex");
    if (typeof emoji !== "string") throw new TypeError("a reaction is a string");
    if (!Number.isFinite(at)) throw new TypeError("a reaction's time is a number of ms");
    const held = reactions && typeof reactions === "object" ? reactions : {};
    const old = Object.prototype.hasOwnProperty.call(held, reactor) ? held[reactor] : null;
    if (old && Number.isFinite(old.t) && old.t >= at) return null;
    return { ...held, [reactor]: { e: emoji, t: at } };
}

/** The reaction `reactor` holds on `reactions`, "" when none (or taken back). */
export function reactionOf(reactions, reactor) {
    const held = reactions && typeof reactions === "object" && Object.prototype.hasOwnProperty.call(reactions, reactor)
        ? reactions[reactor] : null;
    return typeof held?.e === "string" ? held.e : "";
}

/**
 * The chips shown under a bubble (§3 display): one per reaction someone
 * holds (a taken-back one is none), in the order each was first made, with
 * how many hold it, who, and whether one of them is the user (`isMine`,
 * called with each reactor's address: any address the user sends that chat
 * as). [] when nobody holds a reaction.
 */
export function reactionChips(reactions, isMine = () => false) {
    if (!reactions || typeof reactions !== "object") return [];
    const chips = new Map();
    const held = Object.entries(reactions)
        .filter(([, r]) => r && typeof r.e === "string" && r.e !== "")
        .sort(([a, x], [b, y]) => (x.t ?? 0) - (y.t ?? 0) || (a < b ? -1 : a > b ? 1 : 0));
    for (const [reactor, r] of held) {
        const chip = chips.get(r.e) ?? { emoji: r.e, count: 0, mine: false, reactors: [] };
        chip.count++;
        chip.reactors.push(reactor);
        if (isMine(reactor)) chip.mine = true;
        chips.set(r.e, chip);
    }
    return [...chips.values()];
}
