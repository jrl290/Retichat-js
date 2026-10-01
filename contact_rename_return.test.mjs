/**
 * RETURN SAVES THE RENAME — the contact-info sheet (app.js
 * _renderContactInfoModal), as iOS e138bbb: Return in the name field runs
 * the Save button's _saveContactInfo. Not while an IME is composing, where
 * Return picks the candidate.
 *
 * The sheet is built by the shipped method over a small fake DOM; the key
 * goes to the listener h() attached to #ci-display-name.
 *
 * Run: node --test contact_rename_return.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { compile, fn } from "./test_app_source.mjs";

class El {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.attrs = {};
        this.listeners = {};
        this.style = {};
        this.className = "";
    }
    appendChild(c) { this.children.push(c); return c; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    querySelector() { return null; }
    /** The first descendant element with this id attribute. */
    byId(id) {
        for (const c of this.children) {
            if (!(c instanceof El)) continue;
            if (c.attrs.id === id) return c;
            const found = c.byId(id);
            if (found) return found;
        }
        return null;
    }
}
const document = {
    createElement: (tag) => new El(tag),
    createTextNode: (text) => ({ textContent: text }),
    getElementById: () => null,
};
const h = fn("h", "tag, a={}, ...kids", { document });

const HASH = "0123456789abcdef0123456789abcdef";

/** The sheet for one contact; returns the name field and the calls made. */
function openSheet() {
    const calls = { save: 0, render: 0 };
    const ContactStore = {
        get: (hash) => (hash === HASH ? { destHash: HASH, localName: "Mine" } : null),
        name: () => "Mine",
        providedName: () => "Provided",
    };
    const render = compile("_renderContactInfoModal()", {
        h, document, ContactStore, avatarHue: () => 0, setTimeout: () => {},
    });
    const self = {
        state: { contactInfoHash: HASH, showContactInfo: true },
        root: new El("div"),
        render() { calls.render++; },
        _saveContactInfo() { calls.save++; },
        _deleteContact() {},
    };
    render(self)();
    const field = self.root.byId("ci-display-name");
    assert.ok(field, "the sheet has the name field");
    return { field, calls };
}

function key(field, init) {
    const event = { isComposing: false, prevented: false, preventDefault() { this.prevented = true; }, ...init };
    for (const f of field.listeners.keydown ?? []) f(event);
    return event;
}

test("Return in the contact name field saves, as the Save button does (iOS e138bbb)", () => {
    const { field, calls } = openSheet();
    const event = key(field, { key: "Enter" });
    assert.equal(calls.save, 1, "Return runs _saveContactInfo");
    assert.equal(event.prevented, true, "and nothing else takes the key");
});

test("other keys, and Return while an IME is composing, do not save", () => {
    const { field, calls } = openSheet();
    key(field, { key: "a" });
    key(field, { key: "Escape" });
    key(field, { key: "Enter", isComposing: true });
    assert.equal(calls.save, 0);
});

test("what Return runs is the Save button's save: the typed name becomes the local name and the sheet closes", () => {
    const set = [];
    const save = compile("_saveContactInfo()", {
        document: { getElementById: (id) => (id === "ci-display-name" ? { value: "  Bob " } : null) },
        ContactStore: { setLocalName: (hash, value) => set.push([hash, value]) },
    });
    const self = { state: { contactInfoHash: HASH, showContactInfo: true }, render() { this.rendered = true; } };
    save(self)();
    assert.deepEqual(set, [[HASH, "  Bob "]], "ContactStore.setLocalName cleans it (display_names_wiring)");
    assert.equal(self.state.showContactInfo, false);
    assert.equal(self.rendered, true);
});
