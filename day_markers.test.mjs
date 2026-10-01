/**
 * DATE MARKERS — James, 2026-09-30, before the release: a date marker above
 * a message sent on a different day than the message shown just above it,
 * and above the first message shown, in the DM, group and channel lists. The
 * web's half of iOS d891c2d (tests/DayMarkersTests.swift) and Android
 * 5ac43d2 (DayMarkersTest.kt), with the same cases:
 *
 *   lib/day_markers.js for real, the clock, time zone and locale injected:
 *   same day, midnight on both sides, DST change days (a day that starts at
 *   01:00 included), the year boundary, a time-zone change, the first item,
 *   paging prepend, a new message arriving, out-of-order timestamps and
 *   localized labels.
 *
 *   app.js's wiring over a small fake DOM: the marker rides inside its
 *   message's row (no new rows, ids unchanged), the three lists label their
 *   rows, an appended message and a rebuilt row keep the markers right, and
 *   a chat left open across midnight is relabelled in place by the page's
 *   events and the open chat's update paths, with no timer of its own.
 *
 * Run: node --test day_markers.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { dayKey, dayLabel, dayMarkers, dayStamp, deviceDayContext } from "./lib/day_markers.js";
import { app, compile, fn, install, methodBody } from "./test_app_source.mjs";

// ── fixtures ────────────────────────────────────────────────────────────────

const UTC = "UTC";
const NY = "America/New_York";
const CL = "America/Santiago";
const EN = "en-US";

/** The wall clock of `t` in `tz`, as UTC milliseconds. */
function wall(t, tz) {
    const parts = new Intl.DateTimeFormat("en-US", {
        timeZone: tz, calendar: "gregory", numberingSystem: "latn", hourCycle: "h23",
        year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric",
    }).formatToParts(new Date(t));
    const p = (type) => Number(parts.find((x) => x.type === type).value);
    return Date.UTC(p("year"), p("month") - 1, p("day"), p("hour"), p("minute"), p("second"));
}

/** Unix ms of a wall-clock time in `tz` (which must exist there). */
function at(tz, y, mo, d, h = 0, mi = 0, s = 0) {
    const want = Date.UTC(y, mo - 1, d, h, mi, s);
    let t = want;
    for (let i = 0; i < 4; i++) t += want - wall(t, tz);
    assert.equal(wall(t, tz), want, `(fixture) ${y}-${mo}-${d} ${h}:${mi}:${s} exists in ${tz}`);
    return t;
}

const msg = (id, t) => ({ id, t });
const markers = (msgs, tz, now, locale = EN) => dayMarkers(msgs.map((m) => m.t), { now, timeZone: tz, locale });
const marked = (msgs, tz, now) => markers(msgs, tz, now).map((m) => m !== null);
const label = (t, now, tz, locale = EN) => dayLabel(t, { now, timeZone: tz, locale });

// ── the rules ───────────────────────────────────────────────────────────────

test("the first message loaded gets a marker, whatever its day; an empty list has none", () => {
    const now = at(UTC, 2026, 9, 30, 12);
    assert.deepEqual(markers([], UTC, now), []);
    assert.deepEqual(markers([msg("a", at(UTC, 2026, 9, 30, 9))], UTC, now), ["Today"]);
    assert.deepEqual(markers([msg("a", at(UTC, 2026, 9, 21, 9))], UTC, now), ["Monday, September 21"]);
});

test("messages on the same day share the one marker above the first", () => {
    const now = at(UTC, 2026, 9, 30, 20);
    const msgs = [msg("a", at(UTC, 2026, 9, 30, 0, 0, 1)), msg("b", at(UTC, 2026, 9, 30, 9)), msg("c", at(UTC, 2026, 9, 30, 19, 59))];
    assert.deepEqual(marked(msgs, UTC, now), [true, false, false]);
});

test("midnight: the first second after it starts a new day; a chat left open across it relabels", () => {
    const now = at(UTC, 2026, 9, 30, 12);
    const across = [msg("a", at(UTC, 2026, 9, 29, 23, 59, 59)), msg("b", at(UTC, 2026, 9, 30, 0, 0, 0))];
    assert.deepEqual(markers(across, UTC, now), ["Yesterday", "Today"]);
    const within = [msg("a", at(UTC, 2026, 9, 30, 0, 0, 0)), msg("b", at(UTC, 2026, 9, 30, 23, 59, 59))];
    assert.deepEqual(marked(within, UTC, now), [true, false], "midnight and the last second before the next one are one day");

    const m = at(UTC, 2026, 9, 29, 23, 59);
    assert.equal(label(m, at(UTC, 2026, 9, 29, 23, 59, 59), UTC), "Today", "just before midnight");
    assert.equal(label(m, at(UTC, 2026, 9, 30, 0, 0, 0), UTC), "Yesterday", "at midnight");
    assert.equal(label(m, at(UTC, 2026, 9, 30, 23, 59, 59), UTC), "Yesterday", "to the end of the next day");
    assert.equal(label(m, at(UTC, 2026, 10, 1, 0, 0, 0), UTC), "Tuesday, September 29", "two midnights on");
});

test("DST change days are one day each, and Yesterday holds on 23- and 25-hour days and a day starting at 01:00", () => {
    // New York: spring forward 2026-03-08 (23 hours), fall back 2026-11-01 (25 hours).
    for (const c of [
        { what: "spring forward", before: [3, 7], day: [3, 8], after: [3, 9] },
        { what: "fall back", before: [10, 31], day: [11, 1], after: [11, 2] },
    ]) {
        const now = at(NY, 2026, ...c.day, 23, 45);
        const msgs = [msg("a", at(NY, 2026, ...c.before, 23, 30)), msg("b", at(NY, 2026, ...c.day, 0, 30)),
            msg("c", at(NY, 2026, ...c.day, 3, 30)), msg("d", at(NY, 2026, ...c.day, 23, 30))];
        assert.deepEqual(markers(msgs, NY, now), ["Yesterday", "Today", null, null], c.what);
        assert.equal(label(at(NY, 2026, ...c.day, 0, 30), at(NY, 2026, ...c.after, 0, 15), NY), "Yesterday",
            `${c.what}: the change day is Yesterday just after the next midnight`);
    }

    // Santiago springs forward at midnight: 2026-09-06 has no 00:00.
    assert.equal(wall(at(UTC, 2026, 9, 6, 4, 0), CL), Date.UTC(2026, 8, 6, 1, 0), "(fixture) Santiago's 2026-09-06 starts at 01:00");
    assert.equal(label(at(CL, 2026, 9, 6, 1, 30), at(CL, 2026, 9, 7, 0, 30), CL), "Yesterday",
        "a day that starts at 01:00 is Yesterday just after the next midnight");
    assert.equal(label(at(CL, 2026, 9, 6, 1, 0), at(CL, 2026, 9, 6, 23, 0), CL), "Today", "and Today to its end");
    const aroundGap = [msg("a", at(CL, 2026, 9, 5, 23, 59)), msg("b", at(CL, 2026, 9, 6, 1, 0))];
    assert.deepEqual(marked(aroundGap, CL, at(CL, 2026, 9, 6, 12)), [true, true],
        "the minute before the skipped hour and the minute after it are different days");
});

test("the year boundary: two days; the relative words win over the year; a past year's day carries its year", () => {
    const msgs = [msg("a", at(UTC, 2025, 12, 31, 23, 30)), msg("b", at(UTC, 2026, 1, 1, 0, 30))];
    assert.deepEqual(markers(msgs, UTC, at(UTC, 2026, 1, 1, 10)), ["Yesterday", "Today"]);
    assert.deepEqual(markers(msgs, UTC, at(UTC, 2026, 1, 5, 10)), ["Wednesday, December 31, 2025", "Thursday, January 1"]);
    assert.equal(label(at(UTC, 2026, 1, 1, 9), at(UTC, 2026, 12, 31, 23, 59), UTC), "Thursday, January 1",
        "this year's to its last minute");
    assert.equal(label(at(UTC, 2026, 1, 1, 9), at(UTC, 2027, 1, 2, 0, 1), UTC), "Thursday, January 1, 2026",
        "and with its year once the year has turned");
});

test("a time-zone change moves the days: the same messages are two days in UTC, one in New York and Tokyo", () => {
    const msgs = [msg("a", at(UTC, 2026, 9, 29, 23, 30)), msg("b", at(UTC, 2026, 9, 30, 0, 30))];
    const now = at(UTC, 2026, 9, 30, 2);
    assert.deepEqual(marked(msgs, UTC, now), [true, true]);
    assert.deepEqual(marked(msgs, NY, now), [true, false]);
    assert.deepEqual(markers(msgs, NY, now), ["Today", null], "22:00 on the 29th in New York");
    assert.deepEqual(markers(msgs, "Asia/Tokyo", now), ["Today", null], "the morning of the 30th in Tokyo");
});

test("paging prepend: an older page of the same day takes the marker; of an earlier day it leaves it", () => {
    const now = at(UTC, 2026, 9, 30, 12);
    const newer = [msg("c", at(UTC, 2026, 9, 29, 10)), msg("d", at(UTC, 2026, 9, 29, 11)), msg("e", at(UTC, 2026, 9, 30, 9))];
    assert.deepEqual(marked(newer, UTC, now), [true, false, true]);
    const sameDay = [msg("a", at(UTC, 2026, 9, 28, 9)), msg("b", at(UTC, 2026, 9, 29, 8))];
    assert.deepEqual(marked([...sameDay, ...newer], UTC, now), [true, true, false, false, true]);
    const earlier = [msg("a", at(UTC, 2026, 9, 27, 9))];
    assert.deepEqual(marked([...earlier, ...newer], UTC, now), [true, true, false, true]);
});

test("a new message arriving: on the last message's day no marker; after midnight Today, and yesterday's says so", () => {
    const now = at(UTC, 2026, 9, 30, 12);
    const list = [msg("a", at(UTC, 2026, 9, 29, 22)), msg("b", at(UTC, 2026, 9, 30, 9))];
    const sameDay = [...list, msg("c", at(UTC, 2026, 9, 30, 11, 59))];
    assert.deepEqual(marked(sameDay, UTC, now), [true, true, false]);
    const later = at(UTC, 2026, 10, 1, 0, 5);
    assert.deepEqual(markers([...sameDay, msg("d", later)], UTC, later), ["Tuesday, September 29", "Yesterday", null, "Today"]);
});

test("out of order: adjacent messages in display order are compared, so each change of day is marked", () => {
    const now = at(UTC, 2026, 9, 30, 12);
    const back = [msg("a", at(UTC, 2026, 9, 30, 9)), msg("b", at(UTC, 2026, 9, 29, 9)), msg("c", at(UTC, 2026, 9, 30, 10))];
    assert.deepEqual(markers(back, UTC, now), ["Today", "Yesterday", "Today"]);
    const sameDayBackwards = [msg("a", at(UTC, 2026, 9, 30, 10)), msg("b", at(UTC, 2026, 9, 30, 9))];
    assert.deepEqual(marked(sameDayBackwards, UTC, now), [true, false]);
});

test("labels are in the locale's words, capitalized as a heading; the year only outside the current year", () => {
    const m = at(UTC, 2026, 9, 30, 9);
    const now = at(UTC, 2026, 9, 30, 12);
    const tomorrow = at(UTC, 2026, 10, 1, 12);
    assert.equal(label(m, now, UTC, "fr-FR"), "Aujourd’hui");
    assert.equal(label(m, tomorrow, UTC, "fr-FR"), "Hier");
    assert.equal(label(m, now, UTC, "de-DE"), "Heute");
    assert.equal(label(m, tomorrow, UTC, "de-DE"), "Gestern");
    const fr = label(at(UTC, 2026, 9, 21, 9), now, UTC, "fr-FR");
    assert.ok(fr.includes("septembre") && fr.includes("21") && !fr.includes("2026"), fr);
    assert.ok(label(at(UTC, 2025, 9, 21, 9), now, UTC, "fr-FR").includes("2025"));
    assert.ok(label(at(UTC, 2026, 9, 21, 9), now, UTC, "ja-JP").includes("9月21日"));
    // The year is the locale's calendar's: 2026 is 2569 in the Thai Buddhist era.
    assert.ok(label(at(UTC, 2025, 9, 21, 9), now, UTC, "th-TH").includes("2568"));
    assert.ok(!label(at(UTC, 2026, 9, 21, 9), now, UTC, "th-TH").includes("2569"));
    // …whose year need not turn with the Gregorian one: 1448 AH began on
    // 2026-06-16, so 1 May 2026 is last year there, and 1 July this year.
    const hijri = "en-US-u-ca-islamic-umalqura";
    assert.equal(label(at(UTC, 2026, 5, 1, 9), now, UTC, hijri), "Friday, Dhuʻl-Qiʻdah 14, 1447 AH");
    assert.equal(label(at(UTC, 2026, 7, 1, 9), now, UTC, hijri), "Wednesday, Muharram 16");
});

test("a marker is no message: one entry per message, in order, ten days ten markers", () => {
    const now = at(UTC, 2026, 9, 30, 12);
    const msgs = Array.from({ length: 10 }, (_, i) => msg(`m${i}`, at(UTC, 2026, 9, 20 + i, 9)));
    const out = markers(msgs, UTC, now);
    assert.equal(out.length, msgs.length);
    assert.ok(out.every((m) => m !== null));
    assert.deepEqual(markers([msg("a", NaN), msg("b", at(UTC, 2026, 9, 30, 9)), msg("c", undefined)], UTC, now),
        [null, "Today", null], "a message with no usable time gets none and moves no day");
});

test("the stamp moves at midnight, with the time zone and with the locale, and not within a day", () => {
    const ctx = (now, timeZone = UTC, locale = EN) => ({ now, timeZone, locale });
    const morning = dayStamp(ctx(at(UTC, 2026, 9, 30, 0, 0, 0)));
    assert.equal(dayStamp(ctx(at(UTC, 2026, 9, 30, 23, 59, 59))), morning);
    assert.notEqual(dayStamp(ctx(at(UTC, 2026, 10, 1, 0, 0, 0))), morning);
    assert.notEqual(dayStamp(ctx(at(UTC, 2026, 9, 30, 12), "Asia/Tokyo")), dayStamp(ctx(at(UTC, 2026, 9, 30, 12))));
    assert.notEqual(dayStamp(ctx(at(UTC, 2026, 9, 30, 12), UTC, "fr-FR")), dayStamp(ctx(at(UTC, 2026, 9, 30, 12))));
    assert.equal(dayKey(at(NY, 2026, 3, 8, 23, 59), NY), "2026-3-8");
    const device = deviceDayContext();
    assert.equal(typeof device.timeZone, "string", "the device's zone, resolved, never left implicit");
    assert.equal(typeof device.locale, "string");
    assert.ok(Math.abs(device.now - Date.now()) < 1000);
});

// ── the wiring in app.js, over a fake DOM ──────────────────────────────────

class El {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parent = null;
        this.attrs = {};
        this.listeners = {};
        this.style = {};
        this.className = "";
        const self = this;
        this.classList = {
            contains: (c) => self.className.split(" ").includes(c),
            add: (c) => { if (!self.classList.contains(c)) self.className = `${self.className} ${c}`.trim(); },
            remove: (c) => { self.className = self.className.split(" ").filter((x) => x && x !== c).join(" "); },
        };
    }
    appendChild(c) { if (c && typeof c === "object") c.parent = this; this.children.push(c); return c; }
    insertBefore(c, ref) {
        c.parent = this;
        const i = ref ? this.children.indexOf(ref) : -1;
        if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
        return c;
    }
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; }
    replaceWith(other) {
        const list = this.parent.children;
        list[list.indexOf(this)] = other;
        other.parent = this.parent;
        this.parent = null;
    }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    get firstChild() { return this.children[0] ?? null; }
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
    set textContent(v) { this.children = [{ textContent: String(v) }]; }
    /** Supports the one selector the code under test uses. */
    querySelectorAll(selector) {
        assert.equal(selector, "[data-msg-id]");
        const out = [];
        const walk = (n) => { for (const c of n.children) if (c instanceof El) { if ("data-msg-id" in c.attrs) out.push(c); walk(c); } };
        walk(this);
        return out;
    }
    querySelector() { return null; }
}
const document = {
    createElement: (tag) => new El(tag),
    createTextNode: (text) => ({ textContent: text }),
};
const h = fn("h", "tag, a={}, ...kids", { document });

/** A clock the test moves, in New York, en-US. */
function deviceClock(now) {
    const clock = { now, timeZone: NY, locale: EN };
    return { clock, deviceDayContext: () => ({ ...clock }) };
}

/** A row as the bubble builders make it: .msg-row[data-msg-id] > .msg-bubble. */
const row = (m) => h("div", { className: "msg-row their", "data-msg-id": m.id }, h("div", { className: "msg-bubble" }, m.content ?? ""));
const rowsOf = (list) => list.children.filter((c) => c instanceof El && "data-msg-id" in c.attrs);
const markerOf = (r) => (r.firstChild?.className === "day-marker" ? r.firstChild.textContent : null);

function appOver(device, stores = {}) {
    const self = { state: { view: "main", activeHash: null }, _dayStamp: null };
    install(self, {
        h, document: { ...document, getElementById: (id) => (id === "msg-list" ? stores.list ?? null : null) },
        dayMarkers, dayStamp, deviceDayContext: device.deviceDayContext,
        GroupStore: { isGroupChat: () => false }, ChannelStore: { get: () => null },
        MsgStore: { get: () => stores.records ?? [] }, GroupMsgStore: { get: () => [] }, ChannelMsgStore: { get: () => [] },
    }, ["_applyDayMarkers(list, records)", "_setDayMarker(row, label)", "_chatRecords(id)", "_checkDayTurn()"]);
    return self;
}

test("the marker rides inside its message's row: no new rows, the rows' ids and order unchanged", () => {
    const device = deviceClock(at(NY, 2026, 9, 30, 12));
    const self = appOver(device);
    const records = [
        { id: "a", timestamp: at(NY, 2026, 9, 29, 9), content: "one" },
        { id: "b", timestamp: at(NY, 2026, 9, 29, 10), content: "two" },
        { id: "c", timestamp: at(NY, 2026, 9, 30, 9), content: "three" },
    ];
    const list = h("div", { className: "message-list", id: "msg-list" }, ...records.map(row));
    assert.equal(self._applyDayMarkers(list, records), list, "the list itself, so a view can wrap its list in it");
    assert.equal(list.children.length, 3, "a marker adds no row");
    assert.deepEqual(rowsOf(list).map((r) => r.getAttribute("data-msg-id")), ["a", "b", "c"]);
    assert.deepEqual(rowsOf(list).map(markerOf), ["Yesterday", null, "Today"]);
    const first = rowsOf(list)[0];
    assert.equal(first.firstChild.getAttribute("role"), "heading", "read as a heading");
    assert.ok(first.classList.contains("has-day-marker"), "the row is laid out for its marker (style.css)");
    assert.ok(!rowsOf(list)[1].classList.contains("has-day-marker"));
    assert.equal(first.children[1].className, "msg-bubble", "the bubble follows the marker, untouched");
});

test("in place: an appended message, a prepended older one and a relabel patch only the markers", () => {
    const device = deviceClock(at(NY, 2026, 9, 30, 12));
    const self = appOver(device);
    const records = [{ id: "b", timestamp: at(NY, 2026, 9, 30, 9) }];
    const list = h("div", { id: "msg-list" }, ...records.map(row));
    self._applyDayMarkers(list, records);
    const b = rowsOf(list)[0];
    const bMarker = b.firstChild;

    // A message on the same day appended below: no marker.
    records.push({ id: "c", timestamp: at(NY, 2026, 9, 30, 11) });
    list.appendChild(row(records[1]));
    self._applyDayMarkers(list, records);
    assert.deepEqual(rowsOf(list).map(markerOf), ["Today", null]);
    assert.equal(b.firstChild, bMarker, "the marker element is kept, not rebuilt");

    // An older message of the same day shown above: it takes the marker.
    records.unshift({ id: "a", timestamp: at(NY, 2026, 9, 30, 8) });
    list.insertBefore(row(records[0]), b);
    self._applyDayMarkers(list, records);
    assert.deepEqual(rowsOf(list).map(markerOf), ["Today", null, null]);
    assert.ok(!b.classList.contains("has-day-marker"));
    assert.equal(b.firstChild.className, "msg-bubble", "b's marker is gone, its bubble first again");
});

test("a chat left open across midnight relabels in place, once, on the next check; no change within the day", () => {
    const device = deviceClock(at(NY, 2026, 9, 30, 23, 50));
    const records = [{ id: "a", timestamp: at(NY, 2026, 9, 30, 9) }];
    const stores = { records, list: null };
    const self = appOver(device, stores);
    self.state.activeHash = "0".repeat(32);
    stores.list = self._applyDayMarkers(h("div", { id: "msg-list" }, ...records.map(row)), records);
    self._dayStamp = dayStamp(device.deviceDayContext()); // as render() leaves it
    const marker = rowsOf(stores.list)[0].firstChild;
    assert.equal(marker.textContent, "Today");

    device.clock.now = at(NY, 2026, 9, 30, 23, 59, 59);
    assert.equal(self._checkDayTurn(), false, "the same day: nothing to do");
    device.clock.now = at(NY, 2026, 10, 1, 0, 0, 1);
    assert.equal(self._checkDayTurn(), true, "the day turned");
    assert.equal(rowsOf(stores.list)[0].firstChild, marker, "the same marker element…");
    assert.equal(marker.textContent, "Yesterday", "…now says Yesterday");
    assert.equal(self._checkDayTurn(), false, "and only once");

    device.clock.timeZone = "Asia/Tokyo";
    assert.equal(self._checkDayTurn(), true, "a time-zone change relabels too");
    device.clock.locale = "de-DE";
    assert.equal(self._checkDayTurn(), true, "and a language change");
    assert.equal(marker.textContent, "Gestern");
    self.state.view = "onboarding";
    device.clock.now += 86_400_000;
    assert.equal(self._checkDayTurn(), false, "nothing to label outside the main view");
});

test("the DM, group and channel lists label their rows; appends and rebuilt rows keep the markers right", () => {
    for (const view of ["_buildDmChatView()", "_buildGroupChatView()", "_buildChannelChatView()"]) {
        const body = methodBody(view);
        assert.match(body, /this\._applyDayMarkers\(h\("div", \{ className: "message-list", id: "msg-list" \},/, view);
        assert.match(body, /\), msgs\),\n/, `${view}: labelled from the records it shows`);
    }
    const sync = methodBody("_syncOpenChatMessages()");
    const append = sync.indexOf("for (const m of missing) list.appendChild(build(m));");
    assert.notEqual(append, -1);
    assert.ok(sync.indexOf("this._applyDayMarkers(list, records);", append) > append,
        "an append labels the whole list after it, as of now");
    assert.match(methodBody("render()"), /this\._dayStamp = dayStamp\(deviceDayContext\(\)\);/, "render() labels as of now");
});

test("a message appended to the open chat (sent or received) is labelled, after midnight with yesterday's relabelled", () => {
    const device = deviceClock(at(NY, 2026, 9, 30, 23, 0));
    const records = [{ id: "a", dir: "in", timestamp: at(NY, 2026, 9, 30, 22, 0), content: "late" }];
    const stores = { records, list: null };
    const self = appOver(device, stores);
    install(self, {
        document: { getElementById: (id) => (id === "msg-list" ? stores.list : null) },
        GroupStore: { isGroupChat: () => false }, ChannelStore: { get: () => null },
        MsgStore: { get: () => records },
    }, ["_syncOpenChatMessages()"]);
    self._buildMsgBubble = (m) => row(m);
    self.state.activeHash = "d".repeat(32);
    stores.list = self._applyDayMarkers(h("div", { id: "msg-list" }, ...records.map(row)), records);
    self._dayStamp = dayStamp(device.deviceDayContext());

    records.push({ id: "b", dir: "out", timestamp: at(NY, 2026, 9, 30, 23, 30), content: "same day" });
    assert.equal(self._syncOpenChatMessages(), true);
    assert.deepEqual(rowsOf(stores.list).map(markerOf), ["Today", null]);

    device.clock.now = at(NY, 2026, 10, 1, 0, 10);
    records.push({ id: "c", dir: "in", timestamp: at(NY, 2026, 10, 1, 0, 10), content: "after midnight" });
    self._syncOpenChatMessages();
    assert.deepEqual(rowsOf(stores.list).map(markerOf), ["Yesterday", null, "Today"]);
    assert.equal(stores.list.children.length, 3, "one row per message");
});

test("a rebuilt row (an attachment's state changed) keeps its date marker", () => {
    const device = deviceClock(at(NY, 2026, 9, 30, 12));
    const self = appOver(device);
    const m = { id: "a", dir: "in", timestamp: at(NY, 2026, 9, 30, 9), content: "x" };
    const list = h("div", { id: "msg-list" }, row(m));
    self._applyDayMarkers(list, [m]);
    const old = rowsOf(list)[0];
    install(self, {
        document: { querySelector: () => old }, GroupStore: { isGroupChat: () => false },
        MsgStore: { get: () => [m] }, GroupMsgStore: { get: () => [] }, AttachmentUrls: { sweep() {} },
        groupSenderLabel: () => null,
    }, ["_repaintMsgRow(convHash, msgId)"]);
    self._buildMsgBubble = (rec) => row(rec);
    self.state.activeHash = "c";
    self._repaintMsgRow("c", "a");
    const rebuilt = rowsOf(list)[0];
    assert.notEqual(rebuilt, old, "the row was rebuilt");
    assert.equal(markerOf(rebuilt), "Today");
    assert.ok(rebuilt.classList.contains("has-day-marker"));
});

test("the day is checked on the page's events and the open chat's updates, never on a timer of its own", async () => {
    const listeners = { document: [], window: [] };
    const listen = compile("_listenDayTurn()", {
        document: { visibilityState: "visible", addEventListener: (t, f) => listeners.document.push([t, f]) },
        window: { addEventListener: (t, f) => listeners.window.push([t, f]) },
    });
    let checks = 0;
    listen({ _checkDayTurn: () => { checks++; } })();
    assert.deepEqual(listeners.document.map(([t]) => t), ["visibilitychange"]);
    assert.deepEqual(listeners.window.map(([t]) => t).sort(), ["focus", "languagechange", "pageshow"]);
    for (const [, f] of [...listeners.document, ...listeners.window]) f({});
    assert.equal(checks, 4, "each of them checks");

    assert.match(methodBody("async start()"), /this\._listenDayTurn\(\);/);
    const wire = methodBody("_wire()");
    for (const hook of ["RnsClient.onTick(", "RnsClient.onStatus(", "RnsClient.onMessage(", "RnsClient.onSendProgress(", "ContactStore.onChange("]) {
        const at = wire.indexOf(hook);
        assert.notEqual(at, -1, hook);
        assert.ok(wire.slice(at, at + 260).includes("this._checkDayTurn();"), `${hook} checks the day`);
    }
    const lib = await readFile(new URL("./lib/day_markers.js", import.meta.url), "utf8");
    const code = [lib, ...["_applyDayMarkers(list, records)", "_setDayMarker(row, label)", "_checkDayTurn()", "_listenDayTurn()"]
        .map(methodBody)].join("\n");
    assert.doesNotMatch(code, /setInterval|setTimeout|requestAnimationFrame/, "no timer");
    assert.equal(app.match(/setInterval\(/g).length, 1, "app.js keeps its one interval, the announce");
});

test("an idle tab left open across midnight relabels on the announce interval's tick, the page's one interval", () => {
    // Review of 505d0ed: with nothing arriving and no focus or visibility
    // change, yesterday's "Today" stayed until the next event, for hours.
    // The phones relabel on the OS's date-change events; the browser has
    // none, so the check rides on the interval the page already runs.
    const device = deviceClock(at(NY, 2026, 9, 30, 23, 50));
    const records = [{ id: "a", timestamp: at(NY, 2026, 9, 30, 9) }];
    const stores = { records, list: null };
    const self = appOver(device, stores);
    self.state.activeHash = "a".repeat(32);
    stores.list = self._applyDayMarkers(h("div", { id: "msg-list" }, ...records.map(row)), records);
    self._dayStamp = dayStamp(device.deviceDayContext());

    // The client as connect() runs it: _tick() is what the interval calls.
    let announces = 0;
    const rns = { _onTick: [], _announce() { announces++; } };
    install(rns, {}, ["_tick()"]);
    const registered = {};
    const recorder = (owner) => new Proxy({}, { get: (_, name) => (f) => { registered[`${owner}.${String(name)}`] = f; } });
    compile("_wire()", {
        RnsClient: new Proxy({}, { get: (_, name) => (name === "onTick" ? (f) => rns._onTick.push(f) : recorder("RnsClient")[name]) }),
        ContactStore: recorder("ContactStore"), GroupStore: recorder("GroupStore"), ChannelStore: recorder("ChannelStore"),
    })(self)();
    assert.equal(rns._onTick.length, 1, "_wire() listens to the tick");

    rns._tick();
    assert.equal(announces, 1, "the tick still announces");
    assert.equal(markerOf(rowsOf(stores.list)[0]), "Today", "the same day: unchanged");
    device.clock.now = at(NY, 2026, 10, 1, 0, 3);
    rns._tick();
    assert.equal(announces, 2);
    assert.equal(markerOf(rowsOf(stores.list)[0]), "Yesterday", "the first tick after midnight relabels the open list");
    assert.equal(stores.list.children.length, 1, "in place: still one row");

    assert.match(methodBody("async connect()"), /setInterval\(\(\) => this\._tick\(\), this\._cfg\.announceIntervalMs\)/,
        "the announce interval runs _tick(), not _announce() alone");
});
