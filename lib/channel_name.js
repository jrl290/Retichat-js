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
 *   - characters: lowercase letters, digits and "-"; the name part may also
 *     hold "."; the root never does (its first "." ends it);
 *   - the root "public" is refused in Private mode — that is a public channel;
 *   - an empty root or an empty name cannot be joined;
 *   - the default private root is 16 lowercase hex characters (64 bits) from a
 *     cryptographically secure source. Existing channels with an 8-hex root
 *     are unaffected and can still be joined by typing their name.
 */

export const PUBLIC_ROOT = "public";
export const PRIVATE_ROOT_BYTES = 8;
export const PRIVATE_ROOT_HEX_LEN = PRIVATE_ROOT_BYTES * 2;

const ROOT_RE = /^[a-z0-9-]+$/;
const NAME_RE = /^[a-z0-9.-]+$/;

/**
 * A fresh private root: 16 lowercase hex characters from `getRandomValues`
 * (crypto.getRandomValues by default). Never Math.random.
 */
export function genPrivateRoot(getRandomValues = (a) => globalThis.crypto.getRandomValues(a)) {
    const bytes = new Uint8Array(PRIVATE_ROOT_BYTES);
    getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The character rule for the full field: lowercase; keep a-z 0-9 "." "-". */
export function filterChannelChars(text) {
    return String(text ?? "").toLowerCase().replace(/[^a-z0-9.-]/g, "");
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

    // Inside the root: an ordinary edit.
    if (dot >= 0 && end <= dot) {
        const v = cur.slice(0, start) + p + cur.slice(end);
        return { value: v, caret: start + p.length };
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
        // the field reads exactly as the name part does.
        if (p.includes(".")) return { value: namePart, caret: caretInName };
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
 * Whether the field can be joined in `mode`. Returns { ok, name, error }:
 * `name` is the channel name to join; `error` says why not, for the hint line.
 * Joining is refused for an empty root or name, characters outside the rule,
 * and the root "public" in Private mode.
 */
export function validateChannelName(value, mode) {
    const full = String(value ?? "").trim();
    const { root, name, hasDot } = splitChannelName(full);
    if (!hasDot || root === "") {
        return { ok: false, name: full, error: "Enter a root before the first \".\"." };
    }
    if (!ROOT_RE.test(root)) {
        return { ok: false, name: full, error: "The root may hold only a-z, 0-9 and \"-\"." };
    }
    if (mode === "private" && root === PUBLIC_ROOT) {
        return { ok: false, name: full, error: "\"public\" is the root of public channels. Choose Public, or another root." };
    }
    if (name === "") {
        return { ok: false, name: full, error: "Enter a channel name after the \".\"." };
    }
    if (!NAME_RE.test(name)) {
        return { ok: false, name: full, error: "The name may hold only a-z, 0-9, \".\" and \"-\"." };
    }
    return { ok: true, name: full, error: "" };
}

/** The hint under the visibility picker. */
export function visibilityHint(mode) {
    return mode === "private"
        ? "Only people you share the full name with can join."
        : "Anyone who knows the name can join.";
}
