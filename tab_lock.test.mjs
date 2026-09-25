/**
 * REGRESSION GUARD — one active tab per identity (D11).
 *
 * James, 2026-09-25: "a pop-up saying another tab is active, and if
 * possible, a button that will defeat the other tab in order to load the new
 * tab." Until then every tab of an identity registered the same exchange
 * interface, and the node rotates the session token on every registration,
 * so two tabs knocked each other's session out in a 401 ping-pong
 * (CONNECTIVITY_READINESS.md §9.4).
 *
 * The real TabLock runs over a fake LockManager (FIFO, ifAvailable, granted
 * on release, as navigator.locks; also a steal, a refusal, and grants that
 * reach the tab late) and a fake BroadcastChannel shared by the "tabs" of one
 * browser. The ActiveTab tests run the real shipped object from app.js, one
 * copy per tab, with the DOM replaced by a record of what each tab shows.
 * RnsClient.connect() runs for real up to its exchange interface.
 *
 * Run: node --test tab_lock.test.mjs
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { TabLock } from "./lib/tab_lock.js";

const app = await readFile(new URL("./app.js", import.meta.url), "utf8");

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/** Wait (a few macrotasks at most) for `probe` to return something truthy. A failure mechanism only. */
async function eventually(probe, what) {
    for (let i = 0; i < 100; i++) {
        const value = probe();
        if (value) return value;
        await tick();
    }
    throw new Error(`never happened: ${what}`);
}

/**
 * navigator.locks for one origin: exclusive locks, a FIFO queue per name,
 * ifAvailable. With `grantLater` a grant reaches the tab a macrotask after the
 * lock manager made it (the lock manager is another process), so a broadcast
 * posted earlier can arrive first.
 */
class FakeLocks {
    constructor({ grantLater = false } = {}) {
        this.holder = new Map(); // name → the grant holding it
        this.queues = new Map();
        this.grantLater = grantLater;
    }
    request(name, options, callback) {
        return new Promise((resolve, reject) => {
            const grant = { reject };
            const run = () => {
                this.holder.set(name, grant);
                const deliver = this.grantLater ? (fn) => setTimeout(fn, 0) : queueMicrotask;
                deliver(() => {
                    Promise.resolve()
                        .then(() => callback({ name, mode: "exclusive" }))
                        .then(resolve, reject)
                        .finally(() => this._release(name, grant));
                });
            };
            const queue = this.queues.get(name) ?? [];
            this.queues.set(name, queue);
            if (!this.holder.has(name) && queue.length === 0) return run();
            if (options.ifAvailable) {
                queueMicrotask(() => Promise.resolve().then(() => callback(null)).then(resolve, reject));
                return undefined;
            }
            queue.push(run);
            return undefined;
        });
    }
    /** As request(name, { steal: true }) elsewhere: the holder's request rejects, and the lock is no longer its. */
    steal(name) {
        const grant = this.holder.get(name);
        grant.reject(new DOMException("The lock was stolen.", "AbortError"));
        this._release(name, grant);
    }
    _release(name, grant) {
        if (this.holder.get(name) !== grant) return;
        this.holder.delete(name);
        this.queues.get(name)?.shift()?.();
    }
}

/** navigator.locks that refuses every request, as in a sandboxed or opaque-origin document. */
const refusingLocks = {
    request: () => Promise.reject(new DOMException("The request was denied.", "SecurityError")),
};
const throwingLocks = {
    request: () => { throw new DOMException("The request was denied.", "SecurityError"); },
};

/** BroadcastChannel for one origin: a message reaches every other channel of the same name, later. */
function channelsOf() {
    const open = new Set();
    return class FakeChannel {
        constructor(name) { this.name = name; this.onmessage = null; open.add(this); }
        postMessage(data) {
            for (const other of open) {
                if (other === this || other.name !== this.name) continue;
                setTimeout(() => other.onmessage?.({ data: structuredClone(data) }), 0);
            }
        }
        close() { open.delete(this); }
    };
}

/** One browser profile: tabs share its locks and channels. */
function browser(options) {
    return { locks: new FakeLocks(options), BroadcastChannel: channelsOf() };
}

const NAME = "retichat:tab:" + "ab".repeat(16);

// ── TabLock ────────────────────────────────────────────────────────────────

test("the first tab of an identity is active; a second is not, and is not queued", async () => {
    const b = browser();
    const first = new TabLock(NAME, b);
    const second = new TabLock(NAME, b);
    assert.equal(await first.tryAcquire(), true);
    assert.equal(first.held, true);
    assert.equal(await second.tryAcquire(), false);
    assert.equal(second.held, false);
    assert.equal(b.locks.queues.get(NAME).length, 0, "a blocked tab waits for the user, not in the lock queue");

    const other = new TabLock("retichat:tab:" + "cd".repeat(16), b);
    assert.equal(await other.tryAcquire(), true, "another identity is not blocked");
});

test("\"Use here\" stops the active tab before the new tab holds the lock, once", async () => {
    const b = browser();
    const order = [];
    const active = new TabLock(NAME, {
        ...b,
        onTakenOver: async () => {
            order.push("active tab stopping");
            await tick(); // stopping may take a turn; the lock waits for it
            order.push("active tab stopped");
        },
    });
    const bystander = new TabLock(NAME, { ...b, onTakenOver: () => order.push("bystander stopped") });
    const newTab = new TabLock(NAME, { ...b, onTakenOver: () => order.push("new tab stopped") });
    assert.equal(await active.tryAcquire(), true);
    assert.equal(await bystander.tryAcquire(), false);
    assert.equal(await newTab.tryAcquire(), false);

    const granted = newTab.takeOver();
    assert.equal(newTab.held, false, "not before the active tab lets go");
    assert.equal(await granted, true);
    order.push("new tab holds the lock");
    assert.deepEqual(order, ["active tab stopping", "active tab stopped", "new tab holds the lock"],
        "the tab that is not active ignores the takeover");
    assert.equal(active.held, false);
    assert.equal(newTab.held, true);

    // Pressed again: it already holds the lock; nobody else is stopped.
    assert.equal(await newTab.takeOver(), true);
    await tick(); await tick();
    assert.equal(order.length, 3);
    assert.equal(await active.tryAcquire(), false, "the old tab is now the blocked one");
});

test("a tab waiting on \"Use here\" gets the lock when the active tab closes instead", async () => {
    const b = browser();
    const active = new TabLock(NAME, { ...b, BroadcastChannel: null }); // frozen: never hears the takeover
    const newTab = new TabLock(NAME, b);
    assert.equal(await active.tryAcquire(), true);
    const granted = newTab.takeOver();
    await tick();
    assert.equal(newTab.held, false);
    active.release(); // the tab closed: the browser releases its lock
    assert.equal(await granted, true);
});

test("two presses of \"Use here\" queue one request", async () => {
    const b = browser();
    const active = new TabLock(NAME, { ...b, BroadcastChannel: null });
    const newTab = new TabLock(NAME, b);
    await active.tryAcquire();
    const one = newTab.takeOver();
    const two = newTab.takeOver();
    assert.equal(one, two);
    assert.equal(b.locks.queues.get(NAME).length, 1);
    active.release();
    assert.equal(await two, true);
});

test("without navigator.locks the newest tab wins, and the older one stops", async () => {
    const b = { ...browser(), locks: null };
    const stopped = [];
    const older = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("older") });
    assert.equal(await older.tryAcquire(), true);
    const newer = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("newer") });
    assert.equal(await newer.tryAcquire(), true, "it cannot learn of the older tab without waiting on a reply");
    await eventually(() => stopped.length === 1, "the older tab stops");
    assert.deepEqual(stopped, ["older"]);
    assert.equal(older.held, false);
    assert.equal(newer.held, true);
});

test("with neither navigator.locks nor BroadcastChannel a tab runs unguarded", async () => {
    const lock = new TabLock(NAME, { locks: null, BroadcastChannel: null });
    assert.equal(await lock.tryAcquire(), true);
    assert.equal(lock.held, true);
});

test("a BroadcastChannel that cannot be opened leaves the tab running, as without one", async () => {
    const Refused = class { constructor() { throw new DOMException("The operation is insecure.", "SecurityError"); } };
    const lock = new TabLock(NAME, { locks: null, BroadcastChannel: Refused });
    assert.equal(await lock.tryAcquire(), true);
    assert.equal(lock.held, true);
});

test("two tabs pressing \"Use here\" at once: the one left waiting asks again, and gets the lock", async () => {
    const b = browser({ grantLater: true });
    const stopped = [];
    const active = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("active") });
    const first = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("first") });
    const second = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("second") });
    assert.equal(await active.tryAcquire(), true);

    const firstGranted = first.takeOver();
    const secondGranted = second.takeOver();
    assert.equal(await firstGranted, true);
    await tick(); await tick();
    // The second request reached the first tab before its grant did.
    assert.deepEqual(stopped, ["active"]);
    assert.equal(second.held, false);
    assert.equal(second.waiting, true, "still queued, with nothing left that would end the wait");

    assert.equal(second.takeOver(), secondGranted, "asked again from the same place in the queue");
    assert.equal(b.locks.queues.get(NAME).length, 1, "its one request, not a second");
    await eventually(() => second.held, "the second tab holds the lock");
    assert.equal(await secondGranted, true);
    assert.deepEqual(stopped, ["active", "first"]);
    assert.equal(first.held, false);
    assert.equal(second.waiting, false);
});

test("a lock the browser takes from the active tab stops it, as a takeover does", async () => {
    const b = browser();
    const stopped = [];
    const active = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("active") });
    assert.equal(await active.tryAcquire(), true);
    b.locks.steal(NAME);
    await eventually(() => stopped.length === 1, "the tab stops");
    assert.equal(active.held, false);

    // A release this tab asked for is not a loss.
    const next = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("next") });
    assert.equal(await next.tryAcquire(), true);
    next.release();
    await tick(); await tick();
    assert.deepEqual(stopped, ["active"]);
});

test("where navigator.locks refuses the request, the newest tab wins, as without it", async () => {
    for (const locks of [refusingLocks, throwingLocks]) {
        const b = { ...browser(), locks };
        const stopped = [];
        const older = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("older") });
        assert.equal(await older.tryAcquire(), true, "a refusal does not leave the tab stopped and silent");
        const newer = new TabLock(NAME, { ...b, onTakenOver: () => stopped.push("newer") });
        assert.equal(await newer.takeOver(), true);
        await eventually(() => stopped.length === 1, "the older tab stops");
        assert.deepEqual(stopped, ["older"]);
        assert.equal(newer.held, true);
    }
});

// ── ActiveTab (app.js) ─────────────────────────────────────────────────────

function braceMatch(from, label) {
    const bodyStart = app.indexOf("{", from);
    let depth = 0;
    for (let i = bodyStart; i < app.length; i++) {
        if (app[i] === "{") depth++;
        else if (app[i] === "}") {
            depth--;
            if (depth === 0) return [bodyStart, i];
        }
    }
    throw new Error(`could not brace-match ${label}`);
}

function extractObject(name) {
    const start = app.indexOf(`\nconst ${name} = {`);
    assert.notEqual(start, -1, `${name} is missing from app.js`);
    const [open, close] = braceMatch(start, name);
    return app.slice(open, close + 1);
}

function extractMethod(signature) {
    const start = app.indexOf(`\n    ${signature} {`);
    assert.notEqual(start, -1, `${signature} is missing from app.js`);
    const [open, close] = braceMatch(start + signature.length, signature);
    return app.slice(open + 1, close);
}

/**
 * One tab of the real ActiveTab. `log` is shared by every tab of the test, so
 * the order of connects and disconnects across tabs is visible.
 */
function openTab(label, b, log, sessionStorage = new Map(), { storageRefuses = false } = {}) {
    const shown = [];
    const events = [];
    const env = {
        // navigator.locks and BroadcastChannel of this browser.
        TabLock: class extends TabLock {
            constructor(name, options) { super(name, { ...options, locks: b.locks, BroadcastChannel: b.BroadcastChannel }); }
        },
        IdMgr: { hash: "ab".repeat(16) },
        Harness: { event: (kind, detail) => events.push(detail.state) },
        RnsClient: { disconnect: () => log.push(`${label} disconnect`) },
        sessionStorage: {
            getItem: (k) => sessionStorage.get(k) ?? null,
            setItem: (k, v) => {
                if (storageRefuses) throw new DOMException("The operation is insecure.", "SecurityError");
                sessionStorage.set(k, v);
            },
            removeItem: (k) => sessionStorage.delete(k),
        },
        location: { reload: () => log.push(`${label} reload`) },
        console: { log() {}, warn() {}, error: (...a) => log.push(`${label} error ${a.join(" ")}`) },
        document: {},
        h: () => { throw new Error("no DOM in this test"); },
    };
    const names = Object.keys(env);
    const tab = new Function(...names, `return ${extractObject("ActiveTab")};`)(...names.map((n) => env[n]));
    tab._show = (kind) => shown.push(kind);
    tab._hide = () => shown.push("hidden");
    // RnsClient.connect(), which refuses without the lock.
    const connect = async () => {
        assert.equal(tab.held, true, `${label} connects only while it holds the lock`);
        log.push(`${label} connect`);
    };
    return { tab, shown, events, sessionStorage, start: () => tab.start(connect) };
}

test("two tabs, one identity: one connects, the other says so, and \"Use here\" moves it once", async () => {
    const b = browser();
    const log = [];
    const a = openTab("A", b, log);
    await a.start();
    assert.deepEqual(log, ["A connect"]);
    assert.deepEqual(a.events, ["active"]);

    const tabB = openTab("B", b, log);
    await tabB.start();
    assert.deepEqual(log, ["A connect"], "the second tab registers nothing");
    assert.deepEqual(tabB.shown, ["blocked"], "Retichat is open in another tab");
    assert.deepEqual(tabB.events, ["blocked"]);

    // "Use here" reloads B with the takeover flag; the reloaded page takes over.
    await tabB.tab.useHere();
    assert.deepEqual(log, ["A connect", "B reload"]);
    const b2 = openTab("B", b, log, tabB.sessionStorage);
    await b2.start();
    assert.deepEqual(log, ["A connect", "B reload", "A disconnect", "B connect"],
        "A stops exchanging before B holds the lock and connects");
    assert.deepEqual(a.shown, ["hidden", "taken-over"], "Retichat was opened in another tab");
    assert.deepEqual(a.events, ["active", "taken-over"]);
    assert.deepEqual(b2.shown, ["taking-over", "hidden"]);
    assert.equal(b2.sessionStorage.has("retichat_takeover"), false, "the flag is used once");

    // A takes it back the same way.
    await a.tab.useHere();
    const a2 = openTab("A", b, log, a.sessionStorage);
    await a2.start();
    assert.deepEqual(log.slice(4), ["A reload", "B disconnect", "A connect"]);
    assert.equal(a2.tab.held, true);
    assert.equal(b2.tab.held, false);
});

test("without sessionStorage, \"Use here\" takes over in place", async () => {
    const b = browser();
    const log = [];
    const a = openTab("A", b, log);
    await a.start();
    const tabB = openTab("B", b, log, new Map(), { storageRefuses: true });
    await tabB.start();
    await tabB.tab.useHere();
    assert.deepEqual(log, ["A connect", "A disconnect", "B connect"], "no reload that would come back blocked");
    assert.deepEqual(tabB.shown, ["blocked", "taking-over", "hidden"]);
});

test("the \"Taking over…\" pop-up keeps \"Use here\": pressed, it asks the active tab again, without a reload", async () => {
    const b = browser({ grantLater: true });
    const log = [];
    const a = openTab("A", b, log);
    await a.start();
    const tabB = openTab("B", b, log);
    await tabB.start();
    const tabC = openTab("C", b, log);
    await tabC.start();
    await tabB.tab.useHere();
    await tabC.tab.useHere();
    assert.deepEqual(log, ["A connect", "B reload", "C reload"]);

    // Both reloaded pages take over at once.
    const b2 = openTab("B", b, log, tabB.sessionStorage);
    const c2 = openTab("C", b, log, tabC.sessionStorage);
    const startedB = b2.start();
    const startedC = c2.start();
    await startedB;
    await tick(); await tick();
    assert.deepEqual(log.slice(3), ["A disconnect", "B connect"], "C's request reached B before B held the lock");
    assert.deepEqual(c2.shown, ["taking-over"], "C is left waiting");

    await c2.tab.useHere(); // its "Use here"
    await eventually(() => log.includes("C connect"), "C connects");
    await startedC;
    assert.deepEqual(log.slice(3), ["A disconnect", "B connect", "B disconnect", "C connect"],
        "no reload: the queued request asks again, and B stops before C connects");
    assert.deepEqual(c2.shown, ["taking-over", "hidden"]);
    assert.deepEqual(b2.shown, ["taking-over", "hidden", "taken-over"]);
});

test("every state of the pop-up has a \"Use here\" button, \"Taking over…\" included", () => {
    const appended = [];
    const h = (tag, attrs = {}, ...kids) => ({ tag, attrs, kids: kids.flat(), remove() {} });
    const env = {
        TabLock, IdMgr: { hash: "ab".repeat(16) }, Harness: { event() {} }, RnsClient: {},
        sessionStorage: {}, location: {}, console,
        document: { activeElement: null, body: { appendChild: (el) => appended.push(el) } }, h,
    };
    const names = Object.keys(env);
    const tab = new Function(...names, `return ${extractObject("ActiveTab")};`)(...names.map((n) => env[n]));
    const pressed = [];
    tab.useHere = () => pressed.push(tab._overlay.attrs["data-tab-state"]);
    const find = (el, match) => {
        if (!el || typeof el !== "object") return null;
        if (match(el)) return el;
        for (const kid of el.kids ?? []) {
            const found = find(kid, match);
            if (found) return found;
        }
        return null;
    };
    for (const kind of ["blocked", "taken-over", "taking-over"]) {
        tab._show(kind);
        const button = find(appended.at(-1), (el) => el.tag === "button");
        assert.ok(button, `${kind}: a button`);
        assert.deepEqual(button.kids, ["Use here"]);
        button.attrs.onClick();
    }
    assert.deepEqual(pressed, ["blocked", "taken-over", "taking-over"], "each one is useHere()");
});

test("where navigator.locks refuses the request, a tab still connects, and the newest wins", async () => {
    const b = { ...browser(), locks: refusingLocks };
    const log = [];
    const a = openTab("A", b, log);
    await a.start();
    assert.deepEqual(log, ["A connect"], "not left stopped and silent");
    const tabB = openTab("B", b, log);
    await tabB.start();
    await eventually(() => log.includes("A disconnect"), "the older tab stops");
    assert.deepEqual(log, ["A connect", "B connect", "A disconnect"]);
    assert.deepEqual(a.shown, ["hidden", "taken-over"]);
});

/** A real method body, `this.` read as `self.`, its free names bound from env. */
function compile(signature, env) {
    const body = extractMethod(signature).replaceAll("this.", "self.");
    const params = signature.slice(signature.indexOf("(") + 1, signature.lastIndexOf(")"))
        .split(",").map((p) => p.trim()).filter(Boolean);
    const names = Object.keys(env);
    const fn = new Function(...names, "self", ...params,
        signature.startsWith("async ") ? `return (async () => {${body}})();` : body);
    return (self) => (...args) => fn(...names.map((n) => env[n]), self, ...args);
}

/**
 * The real RnsClient.connect() up to the exchange interface: `held` is
 * ActiveTab.held, and `takenOverWhileLoading` drops it while the config
 * loads. The LXMF router's constructor ends the run once the interface exists.
 */
async function runConnect({ held, takenOverWhileLoading = false }) {
    const made = [];
    let configLoads = 0;
    const STOP = new Error("the interface exists (the test stops here)");
    const activeTab = { held };
    const env = {
        IdMgr: { has: true, hash: "ab".repeat(16) },
        ActiveTab: activeTab,
        loadConfig: async () => {
            configLoads++;
            await tick();
            if (takenOverWhileLoading) activeTab.held = false; // _takenOver() ran meanwhile
            return { lxmfPropagationOverride: "b".repeat(32), exchangeUrl: "https://node.example/reticulum", interfaceName: "Retichat Web" };
        },
        console: { log() {}, warn() {}, error() {} },
        ContactStore: { resetPropagationTimers() {} },
        Reticulum: class { constructor() { this.interfaces = []; } addInterface(i) { this.interfaces.push(i); made.push("addInterface"); } },
        PostInterface: class { constructor() { made.push("PostInterface"); } on() {} },
        LXMRouter: class { constructor() { throw STOP; } },
    };
    const self = { _setStatus() {}, _followExchange() {} };
    let outcome;
    try {
        outcome = await compile("async connect()", env)(self)();
    } catch (e) {
        outcome = e;
    }
    return { made, configLoads, outcome, STOP };
}

test("no tab registers with the exchange before it holds the lock", async () => {
    const holder = await runConnect({ held: true });
    assert.equal(holder.outcome, holder.STOP, "control: a tab holding the lock gets as far as its interface");
    assert.deepEqual(holder.made, ["PostInterface", "addInterface"]);

    const blocked = await runConnect({ held: false });
    assert.match(blocked.outcome?.message ?? "", /Retichat is active in another tab/, "refused, and says why");
    assert.equal(blocked.configLoads, 0, "refused before anything else");
    assert.deepEqual(blocked.made, [], "no interface, so no registration");

    const takenOver = await runConnect({ held: true, takenOverWhileLoading: true });
    assert.equal(takenOver.outcome, undefined, "taken over while the config loaded: it stops quietly");
    assert.equal(takenOver.configLoads, 1);
    assert.deepEqual(takenOver.made, [], "no interface after the lock is gone");

    // Every start path goes through ActiveTab.
    assert.match(extractMethod("async start()"), /await ActiveTab\.start\(\(\) => RnsClient\.connect\(\)\);/);
    assert.match(extractMethod("async _enterApp()"), /await ActiveTab\.start\(\(\) => RnsClient\.connect\(\)\);/);
    assert.equal((app.match(/ActiveTab\.start\(\(\) => RnsClient\.connect\(\)\)/g) ?? []).length, 2);
    assert.doesNotMatch(app, /await RnsClient\.connect\(/, "every connect goes through ActiveTab");
});
