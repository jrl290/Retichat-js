/**
 * A message's line breaks in the web client (James, 2026-10-02: "It looks
 * like the web chat strips out newline characters").
 *
 * Nothing on the way in or out removed them: the composer's textarea keeps
 * them, the send paths (DM, group, channel) pack the text as typed (trimmed
 * at both ends, as iOS trims), LXMF and channel unpacking decode it as it
 * came, and the stores keep it. Two places lost them:
 *   - the bubble: the text was a bare text node in .msg-bubble, whose
 *     white-space is normal, so every line break was drawn as a space;
 *   - the composer on a phone: the return key sent the message, and a
 *     phone's keyboard has no Shift+Return, so a line break could not be
 *     typed at all.
 */

/**
 * The text a bubble shows for a message: its line breaks as sent, a CR LF
 * (Windows) or a lone CR read as one break, and the white space at either
 * end left out, as iOS leaves it out of a message it receives
 * (ChatRepository.swift handleIncomingMessage) and as this client's
 * composer leaves it out of one it sends. "" when nothing is left. For
 * display only: the stored and sent text is never changed.
 */
export function bubbleText(content) {
    return String(content ?? "").replace(/\r\n?/g, "\n").trim();
}

/** A device whose primary input is a finger and that cannot hover: a phone
 *  or a tablet without a keyboard and pointer. */
export const TOUCH_FIRST = "(hover: none) and (pointer: coarse)";

/**
 * Whether a keydown in the composer sends the message (the key's default,
 * a line break, is then prevented). With a keyboard, Enter sends and
 * Shift+Enter breaks the line. On a touch-first device (TOUCH_FIRST) the
 * return key breaks the line and the send button sends, as in the iOS and
 * Android apps. An Enter that ends an IME composition (Chinese, Japanese,
 * Korean input) never sends.
 */
export function enterSends(e, touchFirst) {
    return e.key === "Enter" && !e.shiftKey && !e.isComposing && !touchFirst;
}
