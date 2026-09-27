/**
 * The Retichat field 0xD1 (LXMF-rust/DISPLAY_NAMES.md §2.1 and §10) — the
 * JS mirror of LXMF-rust `retichat_field`.
 *
 * Retichat owns one LXMF field number, FIELD_RETICHAT. Its value is a msgpack
 * map whose keys are small non-negative integers (one byte on the wire,
 * 0..127):
 *
 *   - A 0xD1 that is not a map is ignored whole; unknown keys inside it are
 *     ignored. A message with no Retichat entries carries no 0xD1 at all.
 *   - Keys (top-level field numbers and keys inside the map) match as
 *     integers of any msgpack width: msgpackr hands a uint64 back as a
 *     BigInt, every other width as a number. String and negative keys never
 *     match. Writers emit plain numbers, which msgpackr packs as positive
 *     fixints, and keep the map in ascending key order so the bytes are the
 *     ones LXMF-rust writes.
 *   - Key 0 is the display name. Only the name ledger and the channel codec
 *     write it (display_name.js applyToFields); read it with display_name.js
 *     decodePayload (received bytes) or decodeField (maps built here).
 *
 * Group entries: the transition (§10). Groups used nine top-level fields
 * 0xA0-0xA8; they move to keys 1-9. Readers take each group entry from the
 * Retichat field when it is there with its type, otherwise from its old
 * top-level field (readGroupEntry). Senders keep writing the old fields while
 * GROUP_ENTRIES_IN_RETICHAT_FIELD is false (setGroupEntry); both forms are
 * implemented and tested against LXMF-rust/tests/retichat_field_vectors.json,
 * so the switch is this one constant.
 *
 * Nothing here imports anything: display_name.js and lxmf.js both build on it.
 */

/** §2.1: the one LXMF field number Retichat owns. */
export const FIELD_RETICHAT = 0xD1;

/** §2.1: the LXMF source's display name. bin (receivers accept bin or str). */
export const RF_DISPLAY_NAME = 0;
/** str: 32-hex group id (was 0xA0). */
export const RF_GROUP_ID = 1;
/** str: comma-separated hex hashes of all members, invite only (was 0xA1). */
export const RF_GROUP_MEMBERS = 2;
/** str: group name (was 0xA2). */
export const RF_GROUP_NAME = 3;
/** str: invite | accept | leave | relay_req | relay_done (was 0xA3). */
export const RF_GROUP_ACTION = 4;
/** str: original sender hex (was 0xA4). */
export const RF_GROUP_SENDER = 5;
/** str: comma-separated hashes already delivered to (was 0xA5). */
export const RF_GROUP_RELAY_SEEN = 6;
/** str: hash of the member being relayed for (was 0xA6). */
export const RF_GROUP_RELAY_FOR = 7;
/** bool: relay-complete signal (was 0xA7). */
export const RF_GROUP_RELAY_DONE = 8;
/** str: one hash:base64-public-key pair per invite chunk (was 0xA8). */
export const RF_GROUP_MEMBER_KEYS = 9;

/** The largest key: keys are positive fixints, one byte on the wire. */
export const RF_MAX_KEY = 127;

/**
 * §10: where senders put group entries. false until the switch (around
 * 2026-10-26, with DELIVERY_PACKET_PROOF = Required): released apps read only
 * 0xA0-0xA8. The same constant as LXMF-rust GROUP_ENTRIES_IN_RETICHAT_FIELD
 * and Swift groupEntriesInRetichatField.
 */
export const GROUP_ENTRIES_IN_RETICHAT_FIELD = false;

/** The msgpack type a group entry has, in either form (§10). */
export const STR = "str";
export const BOOL = "bool";

/** The group entries, in key order: { key, legacy (old top-level field),
 *  type }. */
export const GROUP_ENTRIES = Object.freeze([
    { key: RF_GROUP_ID, legacy: 0xA0, type: STR },
    { key: RF_GROUP_MEMBERS, legacy: 0xA1, type: STR },
    { key: RF_GROUP_NAME, legacy: 0xA2, type: STR },
    { key: RF_GROUP_ACTION, legacy: 0xA3, type: STR },
    { key: RF_GROUP_SENDER, legacy: 0xA4, type: STR },
    { key: RF_GROUP_RELAY_SEEN, legacy: 0xA5, type: STR },
    { key: RF_GROUP_RELAY_FOR, legacy: 0xA6, type: STR },
    { key: RF_GROUP_RELAY_DONE, legacy: 0xA7, type: BOOL },
    { key: RF_GROUP_MEMBER_KEYS, legacy: 0xA8, type: STR },
].map(Object.freeze));

/** The GROUP_ENTRIES row of a group key 1..9, else null. */
export function groupEntry(key) {
    return GROUP_ENTRIES.find((e) => e.key === key) ?? null;
}

/** The non-negative integer value of a decoded map key, else null. */
function intKey(key) {
    if (typeof key === "number") return Number.isInteger(key) && key >= 0 ? key : null;
    if (typeof key === "bigint") return key >= 0n && key <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(key) : null;
    return null;
}

/** Whether a decoded map key is the integer `target` (any msgpack width). */
export function keyIs(key, target) {
    return intKey(key) === target;
}

/** The first [key, value] of `map` whose key is the integer `target`. */
function findKey(map, target) {
    for (const entry of map) if (keyIs(entry[0], target)) return entry;
    return null;
}

/** The value of top-level field `field` of an LXMF fields Map, or undefined. */
export function topLevel(fields, field) {
    if (!(fields instanceof Map)) return undefined;
    return findKey(fields, field)?.[1];
}

/** The Retichat field's Map, when `fields` holds a Map at 0xD1. A 0xD1 that
 *  is not a map is ignored whole (§2.1): null. */
export function retichatMap(fields) {
    const value = topLevel(fields, FIELD_RETICHAT);
    return value instanceof Map ? value : null;
}

/** Entry `key` of the Retichat field, raw (no type check), or undefined. */
export function readEntry(fields, key) {
    const map = retichatMap(fields);
    return map ? findKey(map, key)?.[1] : undefined;
}

/** `value` as a group entry of `type`, or null. Types are strict: a str
 *  entry is a msgpack str (a JS string; bin is a Uint8Array and is not a
 *  str), a bool entry a msgpack bool. */
export function groupValue(value, type) {
    if (type === STR) return typeof value === "string" ? value : null;
    if (type === BOOL) return typeof value === "boolean" ? value : null;
    return null;
}

/**
 * §10 reader: group entry `key` (1..9), typed, from the Retichat field when
 * it holds that key with the entry's type, otherwise from its old top-level
 * field when that holds the entry's type; otherwise null. An empty string or
 * false in the map is a value and wins.
 */
export function readGroupEntry(fields, key) {
    const entry = groupEntry(key);
    if (!entry) return null;
    return groupValue(readEntry(fields, key), entry.type)
        ?? groupValue(topLevel(fields, entry.legacy), entry.type);
}

/** Set top-level field `field`: replace the first entry with that integer
 *  key (any width) in place, dropping any others, or append. */
export function setTopLevel(fields, field, value) {
    const found = findKey(fields, field);
    if (!found) { fields.set(field, value); return fields; }
    for (const key of [...fields.keys()]) if (key !== found[0] && keyIs(key, field)) fields.delete(key);
    fields.set(found[0], value);
    return fields;
}

/** Remove every top-level entry whose key is the integer `field`. */
export function removeTopLevel(fields, field) {
    for (const key of [...fields.keys()]) if (keyIs(key, field)) fields.delete(key);
    return fields;
}

/**
 * Set entry `key` of the Retichat field to `value`, as LXMF-rust set_entry:
 * 0xD1 is appended when there is none and replaced when it is not a map;
 * other entries are kept, any entry with this key is replaced, and the new
 * one goes before the first larger integer key, so a map built here is in
 * ascending key order whatever order the entries were set in.
 */
export function setEntry(fields, key, value) {
    const found = findKey(fields, FIELD_RETICHAT);
    const old = found && found[1] instanceof Map ? found[1] : new Map();
    const entries = [...old].filter(([k]) => !keyIs(k, key));
    let at = entries.findIndex(([k]) => intKey(k) !== null && intKey(k) > key);
    if (at < 0) at = entries.length;
    entries.splice(at, 0, [key, value]);
    setTopLevel(fields, FIELD_RETICHAT, new Map(entries));
    return fields;
}

/** Remove entry `key` from the Retichat field. When the map is left empty,
 *  or 0xD1 is not a map at all, 0xD1 is dropped: a message with no Retichat
 *  entries carries no 0xD1. */
export function removeEntry(fields, key) {
    const found = findKey(fields, FIELD_RETICHAT);
    if (!found) return fields;
    if (found[1] instanceof Map) {
        const rest = [...found[1]].filter(([k]) => !keyIs(k, key));
        if (rest.length > 0) { setTopLevel(fields, FIELD_RETICHAT, new Map(rest)); return fields; }
    }
    return removeTopLevel(fields, FIELD_RETICHAT);
}

/**
 * §10 sender, in a chosen form: group entry `key` (1..9) with `value` written
 * into the Retichat field (inRetichatField) or its old top-level field. The
 * other form's entry for this key is removed, so a message never carries two
 * values for one entry. Throws on a key that is not a group key or a value
 * of the wrong type (a str entry takes a JS string, relay_done a boolean).
 */
export function setGroupEntryAs(fields, key, value, inRetichatField) {
    const entry = groupEntry(key);
    if (!entry) throw new RangeError(`${key} is not a group key (1..9)`);
    if (groupValue(value, entry.type) === null) {
        throw new TypeError(`group key ${key} holds a ${entry.type}, not ${typeof value}`);
    }
    if (inRetichatField) {
        removeTopLevel(fields, entry.legacy);
        setEntry(fields, key, value);
    } else {
        removeEntry(fields, key);
        setTopLevel(fields, entry.legacy, value);
    }
    return fields;
}

/** §10 sender: group entry `key` in the form GROUP_ENTRIES_IN_RETICHAT_FIELD
 *  selects. */
export function setGroupEntry(fields, key, value) {
    return setGroupEntryAs(fields, key, value, GROUP_ENTRIES_IN_RETICHAT_FIELD);
}

/**
 * The group entries of an outgoing group envelope, from the object app.js
 * builds ({ groupId, groupMembers, groupName, groupAction, groupSender,
 * groupRelaySeen, groupRelayFor, groupRelayDone, groupMemberKey }), written
 * in key order in the form `inRetichatField` selects. groupId is always
 * written; a str entry only when non-empty, relay_done only when not null —
 * as the envelope has always been built.
 */
export function applyGroupFields(fields, group, inRetichatField = GROUP_ENTRIES_IN_RETICHAT_FIELD) {
    const str = [
        [RF_GROUP_MEMBERS, group.groupMembers],
        [RF_GROUP_NAME, group.groupName],
        [RF_GROUP_ACTION, group.groupAction],
        [RF_GROUP_SENDER, group.groupSender],
        [RF_GROUP_RELAY_SEEN, group.groupRelaySeen],
        [RF_GROUP_RELAY_FOR, group.groupRelayFor],
    ];
    setGroupEntryAs(fields, RF_GROUP_ID, group.groupId, inRetichatField);
    for (const [key, value] of str) if (value) setGroupEntryAs(fields, key, value, inRetichatField);
    if (group.groupRelayDone != null) setGroupEntryAs(fields, RF_GROUP_RELAY_DONE, group.groupRelayDone, inRetichatField);
    if (group.groupMemberKey) setGroupEntryAs(fields, RF_GROUP_MEMBER_KEYS, group.groupMemberKey, inRetichatField);
    return fields;
}
