/**
 * Channel names in the New Channel form — pure rules, no DOM.
 *
 * A channel name is "<root>.<name>". Public channels use the root "public".
 * A private channel's root is whatever the creator chose: by default a fresh
 * random root, but editable, so a private channel someone shared with you can
 * be joined by typing or pasting its full name (James, 2026-09-27: the iPad
 * could not join the phone's 4cdc4115.nametest-096499 because the root was
 * fixed to a random value nobody could change).
 *
 * The same rules hold on iOS (NewConversationView.swift NewChannelForm) and
 * Android (JoinChannelScreen.kt):
 *   - characters: letters (lowercased) and digits — Unicode, as the native
 *     clients' isLetter/isLetterOrDigit checks are — and "-"; the name part
 *     may also hold "."; the root never does (its first "." ends it);
 *   - the root "public" is refused in Private mode — that is a public channel;
 *     Public mode always uses the root "public" (native has no root field in
 *     Public mode, so any other root there is refused rather than joined);
 *   - an empty root or an empty name cannot be joined, nor a name with an
 *     empty segment (a leading or trailing ".", or "..");
 *   - typing or pasting a "." into the name part of a Private name that had
 *     none moves everything before it into the root (the native rule);
 *   - the default private root is 16 lowercase hex characters (64 bits) from a
 *     cryptographically secure source. Existing channels with an 8-hex root
 *     are unaffected and can still be joined by typing their name.
 */

export const PUBLIC_ROOT = "public";
export const PRIVATE_ROOT_BYTES = 8;
export const PRIVATE_ROOT_HEX_LEN = PRIVATE_ROOT_BYTES * 2;

const ROOT_RE = /^[\p{L}\p{N}-]+$/u;
const NAME_RE = /^[\p{L}\p{N}.-]+$/u;

/**
 * A fresh private root: 16 lowercase hex characters from `getRandomValues`
 * (crypto.getRandomValues by default). Never Math.random.
 */
export function genPrivateRoot(getRandomValues = (a) => globalThis.crypto.getRandomValues(a)) {
    const bytes = new Uint8Array(PRIVATE_ROOT_BYTES);
    getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * The character rule for the full field: lowercase, NFC; keep letters, digits,
 * "." and "-". Letters and digits are Unicode, as on iOS (isLetter/isNumber)
 * and Android (isLetterOrDigit), so "public.café" means the same channel on
 * every client.
 */
export function filterChannelChars(text) {
    return String(text ?? "").toLowerCase().normalize("NFC").replace(/[^\p{L}\p{N}.-]/gu, "");
}

/** Split at the first ".". A value with no "." is all name part (root ""). */
export function splitChannelName(full) {
    const dot = full.indexOf(".");
    if (dot < 0) return { root: "", name: full, hasDot: false };
    return { root: full.slice(0, dot), name: full.slice(dot + 1), hasDot: true };
}

/** A root the user may keep when switching to Private. */
function isKeepablePrivateRoot(root) {
    return root !== "" && root !== PUBLIC_ROOT && ROOT_RE.test(root);
}

/**
 * The field's value after the Public/Private toggle. The name part is kept.
 * Public replaces the root with "public". Private keeps a root the user typed
 * (anything but "" or "public"), otherwise takes `genRoot()`.
 */
export function applyVisibility(value, mode, genRoot = genPrivateRoot) {
    const v = filterChannelChars(value);
    const { root, name, hasDot } = splitChannelName(v);
    // With no "." the text is the name part; there is no root to keep.
    const typedRoot = hasDot ? root : "";
    if (mode === "public") return `${PUBLIC_ROOT}.${name}`;
    const r = isKeepablePrivateRoot(typedRoot) ? typedRoot : genRoot();
    return `${r}.${name}`;
}

/** The value the form opens with for a mode. */
export function initialChannelValue(mode, genRoot = genPrivateRoot) {
    return mode === "private" ? `${genRoot()}.` : `${PUBLIC_ROOT}.`;
}

/** Replace the root with a fresh one (the "Regenerate prefix" button). */
export function regenerateRoot(value, genRoot = genPrivateRoot) {
    const { name } = splitChannelName(filterChannelChars(value));
    return `${genRoot()}.${name}`;
}

/**
 * A paste into the full-name field.
 *
 * `value` is the field before the paste, `selStart`/`selEnd` the selection it
 * replaces, `pasted` the clipboard text. Returns { value, caret }.
 *
 *   - A paste wholly inside the root edits the root (filtered, and a "." in
 *     it ends the root where it lands — that is what the field means).
 *   - Private: a paste into the name part that brings a "." makes the name
 *     part a full "root.name": everything before its first "." becomes the
 *     root, the rest the name. So a shared private channel name pastes in one
 *     go, whether the field held "<root>." or was selected whole.
 *   - Public: a pasted "public.name" drops the duplicate "public."; any other
 *     "x.y" stays as typed in the name part, under the root "public".
 */
export function pasteChannelName({ value, selStart, selEnd, pasted, mode, genRoot = genPrivateRoot }) {
    const cur = String(value ?? "");
    const start = Math.max(0, Math.min(selStart ?? cur.length, cur.length));
    const end = Math.max(start, Math.min(selEnd ?? start, cur.length));
    const p = filterChannelChars(pasted);
    const dot = cur.indexOf(".");

    // Inside the root: an ordinary edit. A paste that brings its own "." (a
    // whole "root.name" pasted over the selected root) makes the field's old
    // separator redundant: drop it, or "<root>." would become "root.name." —
    // a different channel.
    if (dot >= 0 && end <= dot) {
        let tail = cur.slice(end);
        let ins = p;
        if (p.includes(".")) {
            const td = tail.indexOf(".");
            const oldName = tail.slice(td + 1);
            tail = tail.slice(0, td) + (oldName ? `.${oldName}` : "");
            if (ins.endsWith(".") && tail.startsWith(".")) ins = ins.slice(0, -1);
        }
        return { value: cur.slice(0, start) + ins + tail, caret: start + ins.length };
    }

    // The paste lands in the name part. If the selection also covered the
    // root (select-all, or no "." yet) the root it covered goes with it.
    const touchesRoot = dot < 0 || start <= dot;
    const keptRoot = touchesRoot ? "" : cur.slice(0, dot);
    const before = touchesRoot ? "" : cur.slice(dot + 1, start);
    const after = cur.slice(end);
    const namePart = before + p + after;
    const caretInName = before.length + p.length;

    if (mode === "private") {
        // The name part now holds "root.name": its root becomes the root, and
        // the field reads exactly as the name part does. A "." at the very
        // start has no root before it and does not split (it would wipe it).
        if (p.includes(".") && namePart.indexOf(".") > 0) return { value: namePart, caret: caretInName };
        const coveredRoot = dot >= 0 ? cur.slice(0, dot) : "";
        const root = keptRoot
            || (isKeepablePrivateRoot(coveredRoot) ? coveredRoot : genRoot());
        return { value: `${root}.${namePart}`, caret: root.length + 1 + caretInName };
    }

    // Public.
    let name = namePart;
    let caret = caretInName;
    const dup = `${PUBLIC_ROOT}.`;
    if (p.startsWith(dup) && before === "") {
        name = namePart.slice(dup.length);
        caret -= dup.length;
    }
    const root = keptRoot || PUBLIC_ROOT;
    return { value: `${root}.${name}`, caret: root.length + 1 + Math.max(0, caret) };
}

/**
 * Whether a Private name-part edit moves a root out of the name: the inserted
 * text holds a ".", and either the old name part had none or the edit
 * replaced its start. The rule of iOS ChannelNameRules.editSplitsTheRoot and
 * Android ChannelNameForm.onNameInput.
 */
function editSplitsRoot(oldName, newName) {
    let prefix = 0;
    while (prefix < oldName.length && prefix < newName.length && oldName[prefix] === newName[prefix]) prefix++;
    let suffix = 0;
    while (suffix < oldName.length - prefix && suffix < newName.length - prefix
        && oldName[oldName.length - 1 - suffix] === newName[newName.length - 1 - suffix]) suffix++;
    const inserted = newName.slice(prefix, newName.length - suffix);
    return inserted.includes(".") && (!oldName.includes(".") || prefix === 0);
}

/**
 * A typed edit of the field (an input event). `old` is the field before the
 * edit, `value` the raw field after it, `caret` the caret in the filtered
 * value. Returns { value, caret }.
 *
 * Only an edit wholly in the name part (the root and its "." unchanged) is
 * interpreted:
 *   - Private: typing a "." into a name part that had none (or one arriving
 *     whole, from autofill or drag-and-drop) makes the name part a full
 *     "root.name": what precedes its first "." becomes the root. So typing a
 *     shared "4cdc4115.nametest" after the default root joins that channel,
 *     not "<random>.4cdc4115.nametest".
 *   - Public: a name part that newly starts with "public." drops it.
 * Anything else is just the character rule.
 */
export function typeChannelName({ old, value, caret, mode }) {
    const prev = String(old ?? "");
    const v = filterChannelChars(value);
    const c = Math.max(0, Math.min(caret ?? v.length, v.length));
    const dot = prev.indexOf(".");
    if (dot < 0 || !v.startsWith(prev.slice(0, dot + 1))) return { value: v, caret: c };
    const root = prev.slice(0, dot);
    const oldName = prev.slice(dot + 1);
    const name = v.slice(dot + 1);
    if (mode === "private") {
        if (name.indexOf(".") > 0 && editSplitsRoot(oldName, name)) {
            return { value: name, caret: Math.max(0, c - (dot + 1)) };
        }
        return { value: v, caret: c };
    }
    const dup = `${PUBLIC_ROOT}.`;
    if (name.startsWith(dup) && !oldName.startsWith(dup)) {
        return { value: `${root}.${name.slice(dup.length)}`, caret: Math.max(dot + 1, c - dup.length) };
    }
    return { value: v, caret: c };
}

/**
 * Whether the field can be joined in `mode`. Returns { ok, name, error }:
 * `name` is the channel name to join; `error` says why not, for the hint line;
 * `code` names the problem ("" when ok). Joining is refused for an empty root
 * or name, characters outside the rule, an empty name segment, the root
 * "public" in Private mode and any other root in Public mode.
 */
export function validateChannelName(value, mode) {
    const full = String(value ?? "").trim();
    const { root, name, hasDot } = splitChannelName(full);
    const no = (code, error) => ({ ok: false, name: full, error, code });
    if (!hasDot || root === "") {
        return no("root-empty", "Enter a root before the first \".\".");
    }
    if (!ROOT_RE.test(root) || root !== root.toLowerCase()) {
        return no("root-chars", "The root may hold only lowercase letters, digits and \"-\".");
    }
    if (mode === "private" && root === PUBLIC_ROOT) {
        return no("root-public", "\"public\" is the root of public channels. Choose Public, or another root.");
    }
    if (mode !== "private" && root !== PUBLIC_ROOT) {
        return no("root-not-public", "Public channels use the root \"public\". Choose Private to use another root.");
    }
    if (name === "") {
        return no("name-empty", "Enter a channel name after the \".\".");
    }
    if (!NAME_RE.test(name) || name !== name.toLowerCase()) {
        return no("name-chars", "The name may hold only lowercase letters, digits, \".\" and \"-\".");
    }
    if (name.startsWith(".") || name.endsWith(".") || name.includes("..")) {
        return no("name-segment", "The name cannot start or end with \".\", or hold \"..\".");
    }
    return { ok: true, name: full, error: "", code: "" };
}

/** The hint under the visibility picker. */
export function visibilityHint(mode) {
    return mode === "private"
        ? "Only people you share the full name with can join."
        : "Anyone who knows the name can join.";
}

/**
 * Channel info (James, 2026-09-27): a channel is shared by its full name,
 * "<root>.<name>" — for a private channel that name is the invite. The hash
 * is useless for joining. These are the rules the info sheet shows and copies
 * by, the same on iOS and Android.
 */

/** Exactly what Copy and Share hand out: the full name, no "#", no whitespace. */
export function channelShareText(full) {
    return String(full ?? "").replace(/\s+/g, "").replace(/^#+/, "");
}

/** A channel is private when its root is anything but "public". */
export function isPrivateChannelName(full) {
    const { root, hasDot } = splitChannelName(channelShareText(full));
    return hasDot && root !== "" && root !== PUBLIC_ROOT;
}

/** The one-line hint under the full name in channel info. */
export function channelShareHint(full) {
    return isPrivateChannelName(full)
        ? "Share the full name to invite someone. Anyone with it can read and post."
        : "Anyone who knows the name can join.";
}
