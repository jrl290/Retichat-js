/**
 * Date markers in the message lists (James, 2026-09-30): a marker above a
 * message sent on a different day than the message shown just above it, and
 * above the first message shown. A received message is marked by the day
 * its sender sent it (sentTimeMs), as on iOS and Android. The web's half of
 * iOS d891c2d (Retichat/Views/Conversation/DayMarkers.swift) and Android
 * 5ac43d2 (ui/conversation/DayMarkers.kt).
 *
 * The label is "Today" or "Yesterday" in the locale's words
 * (Intl.RelativeTimeFormat, numeric "auto"), otherwise the weekday, day and
 * month (Intl.DateTimeFormat), with the year for a day outside the current
 * year of the locale's calendar. Days are calendar days in the given time
 * zone. Yesterday is found by calendar arithmetic on the civil date, never by
 * counting hours, so it holds on a 23- or 25-hour day and where a clock
 * change skips midnight (America/Santiago 2026-09-06 starts at 01:00).
 * Labels start with a capital, as iOS's beginning-of-sentence context does.
 *
 * Pure: the clock, the time zone and the locale are passed in (a "context"
 * { now, timeZone, locale }), so day_markers.test.mjs runs it as it is.
 * deviceDayContext() is the device's, read fresh each time: a formatter made
 * without a time zone keeps the zone it was made in, so nothing here caches
 * one without an explicit zone and locale.
 *
 * Nothing here touches the DOM: app.js puts each label inside its message's
 * row (_applyDayMarkers), so a marker is never a row of its own.
 */

const formatters = new Map();

/** An Intl formatter, made once per (kind, locale, options). Callers pass an
 *  explicit timeZone and locale (deviceDayContext resolves them). */
function cached(kind, locale, options, make) {
    const key = `${kind}\u0000${locale ?? ""}\u0000${JSON.stringify(options)}`;
    let f = formatters.get(key);
    if (!f) {
        f = make();
        formatters.set(key, f);
    }
    return f;
}

function dateFormat(locale, options) {
    return cached("date", locale, options, () => new Intl.DateTimeFormat(locale, options));
}

/** The Gregorian civil date of `ms` in `timeZone`: { y, m, d }. */
function civilDate(ms, timeZone) {
    const parts = dateFormat("en-US", {
        timeZone, calendar: "gregory", numberingSystem: "latn", era: "short",
        year: "numeric", month: "numeric", day: "numeric",
    }).formatToParts(new Date(ms));
    const part = (type) => parts.find((p) => p.type === type)?.value;
    const year = Number(part("year"));
    return {
        // en-US writes 1 BC as year 1, era "BC": astronomical year 0.
        y: part("era") === "BC" ? 1 - year : year,
        m: Number(part("month")),
        d: Number(part("day")),
    };
}

const keyOf = ({ y, m, d }) => `${y}-${m}-${d}`;

/** dayKey's answers, by time zone and timestamp. A list is relabelled
 *  whole on every message appended to it and at every day check, and each
 *  answer costs a formatToParts: 3 to 4 ms per relabel of 500 rows (review
 *  of 505d0ed), so a burst of n channel posts cost n times that on the main
 *  thread. A timestamp's day in a zone never changes, so a relabel now
 *  costs a lookup per row (about 0.2 ms for 500 rows, 0.7 ms for 5000).
 *  Emptied when it holds DAY_KEYS_MAX answers, so it cannot grow without
 *  end. */
const dayKeys = new Map();   // time zone -> Map(ms -> day key)
export const DAY_KEYS_MAX = 20_000;
let dayKeysHeld = 0;

/** The calendar day of `ms` in `timeZone`, as a key that two timestamps
 *  share exactly when they fall on the same day there. Remembered only for
 *  an explicit zone: the device's default can change under the page. */
export function dayKey(ms, timeZone) {
    if (typeof timeZone !== "string") return keyOf(civilDate(ms, timeZone));
    let zone = dayKeys.get(timeZone);
    const known = zone?.get(ms);
    if (known !== undefined) return known;
    const key = keyOf(civilDate(ms, timeZone));
    if (dayKeysHeld >= DAY_KEYS_MAX) {
        dayKeys.clear();
        dayKeysHeld = 0;
        zone = undefined;
    }
    if (!zone) dayKeys.set(timeZone, zone = new Map());
    zone.set(ms, key);
    dayKeysHeld++;
    return key;
}

/** The day before a civil date, by calendar arithmetic. */
function dayBefore({ y, m, d }) {
    const t = new Date(0);
    t.setUTCFullYear(y, m - 1, d - 1);
    return { y: t.getUTCFullYear(), m: t.getUTCMonth() + 1, d: t.getUTCDate() };
}

/** The year of `ms` in the locale's calendar (era included), as a key. */
function yearKey(ms, timeZone, locale) {
    return dateFormat(locale, { timeZone, year: "numeric", era: "short" })
        .formatToParts(new Date(ms))
        .filter((p) => p.type === "era" || p.type === "year" || p.type === "relatedYear" || p.type === "yearName")
        .map((p) => `${p.type}:${p.value}`)
        .join("|");
}

/** `text` with its first character in upper case, in `locale`'s rules. */
function capitalized(text, locale) {
    if (!text) return text;
    const first = String.fromCodePoint(text.codePointAt(0));
    return first.toLocaleUpperCase(locale) + text.slice(first.length);
}

/** The locale's named relative day ("today", "hier", "昨日"), or null where
 *  the platform has no Intl.RelativeTimeFormat. */
function relativeDay(days, locale) {
    if (typeof Intl.RelativeTimeFormat !== "function") return null;
    const f = cached("relative", locale, { numeric: "auto" },
        () => new Intl.RelativeTimeFormat(locale, { numeric: "auto" }));
    return capitalized(f.format(days, "day"), locale);
}

/** The weekday, day and month of `ms`, and the year when `withYear`. */
function dateLabel(ms, timeZone, locale, withYear) {
    const options = { timeZone, weekday: "long", day: "numeric", month: "long" };
    if (withYear) options.year = "numeric";
    return capitalized(dateFormat(locale, options).format(new Date(ms)), locale);
}

/**
 * The labeller for one context: what today and yesterday are, and the
 * current year, worked out once for a whole list.
 */
function labeller({ now, timeZone, locale }) {
    const today = civilDate(now, timeZone);
    const todayKey = keyOf(today);
    const yesterdayKey = keyOf(dayBefore(today));
    const thisYear = yearKey(now, timeZone, locale);
    return (ms, day = dayKey(ms, timeZone)) => {
        if (day === todayKey) return relativeDay(0, locale) ?? dateLabel(ms, timeZone, locale, false);
        if (day === yesterdayKey) return relativeDay(-1, locale) ?? dateLabel(ms, timeZone, locale, false);
        return dateLabel(ms, timeZone, locale, yearKey(ms, timeZone, locale) !== thisYear);
    };
}

/** The label of the marker for a message sent at `ms` (Unix ms). */
export function dayLabel(ms, context) {
    return labeller(context)(ms);
}

/**
 * For each timestamp (Unix ms) of a message list in display order, top to
 * bottom, the label of the marker above it, or null for none: above the
 * first, and above each one whose day differs from the day of the one just
 * above it. Adjacent messages are compared, not sorted, so out-of-order
 * timestamps get a marker at every change of day. A timestamp that is not a
 * finite number gets none and leaves the day above as it was.
 */
export function dayMarkers(timestamps, context) {
    const label = labeller(context);
    let previous = null;
    return timestamps.map((ms) => {
        if (typeof ms !== "number" || !Number.isFinite(ms)) return null;
        const day = dayKey(ms, context.timeZone);
        if (day === previous) return null;
        previous = day;
        return label(ms, day);
    });
}

/**
 * What the labels of a context depend on: the day, the time zone and the
 * locale. Labels made under one stamp are still right while the stamp is the
 * same; when it changes (midnight, a zone or language change) they must be
 * made again.
 */
export function dayStamp({ now, timeZone, locale }) {
    // The clock, not a message: worked out each time, never remembered.
    return `${keyOf(civilDate(now, timeZone))}|${timeZone}|${locale}`;
}

/**
 * When a received message was sent, as its sender stamped it: the Unix ms
 * app.js stores as its record's `timestamp`, which the bubble's time, the
 * marker above it and the sidebar's order show. `seconds` is the LXMF
 * timestamp (a channel post's tsMs divided by 1000). iOS and Android store
 * the sender's time too (iOS ChatRepository.swift handleIncomingMessage,
 * handleDistroMessage and handleGroupChatMessage, RfedChannelClient.swift
 * `timestamp: Double(tsMs)`; Android ChatRepository.kt
 * `timestamp = (timestamp * 1000).toLong()`, RfedChannelClient.kt
 * `timestamp = result.timestampMs`). Until 2026-09-30 the web stored the
 * time a message arrived, so one sent on Monday and pulled on Wednesday sat
 * under "Today". A sender's clock is shown as it is, ahead or behind. A
 * message with no usable time (not a finite number, or not after 1970:
 * rfed_channel.js unpacks a missing one as 0) keeps the time it arrived,
 * `now`, rather than show 1 January 1970, a date no sender meant.
 */
export function sentTimeMs(seconds, now = Date.now()) {
    return Number.isFinite(seconds) && seconds > 0 ? Math.round(seconds * 1000) : now;
}

/**
 * A conversation's time in the chat list, which orders it there and is
 * shown beside it: the latest `timestamp` among its records, or `fallback`
 * when it has none. Received records carry the time they were sent
 * (sentTimeMs), so the last one stored need not be the latest: a message
 * pulled late keeps its earlier time and neither pulls its conversation
 * down nor dates it back, as iOS keeps the larger time
 * (ChatRepository.swift updateChatTimestamp: max(lastMessageTime, ts)).
 */
export function lastMessageTime(records, fallback) {
    let latest = null;
    for (const r of records) {
        if (Number.isFinite(r?.timestamp) && (latest === null || r.timestamp > latest)) latest = r.timestamp;
    }
    return latest ?? fallback;
}

/** The device's context now: the clock, and the time zone and locale the
 *  browser has at this moment, resolved fresh so a change is seen. */
export function deviceDayContext() {
    const resolved = new Intl.DateTimeFormat().resolvedOptions();
    return { now: Date.now(), timeZone: resolved.timeZone, locale: resolved.locale };
}
