/**
 * REGRESSION GUARD — the page says why the PHP node stopped its connection.
 *
 * Reticulum-post REGISTRATION-STAGE1.md §10 and §17.2, §14's page test.
 * app.js gives PostInterface the identity's hash third, a string, as it
 * always did (IdMgr.hash), and the identity itself (IdMgr.id), which signs
 * the registration and decrypts its session token, in the options: a lib
 * older than Stage 1 sends the third argument to the PHP node, so the
 * identity there would carry its private keys (2026-10-14, the review of
 * stage1-sign), and it ignores the options. When the PHP node's answer stops the interface
 * ("stopped": superseded by another tab or device, refused, out of date),
 * the page keeps the reason as its own state (RnsClient.exchangeStopped,
 * never exchangeBlocked, which Settings shows as the policy error on the
 * exchange URL), sets the status "stopped", shows the reason under the
 * status dot after every render (App._applyStatusDot, where the blocked
 * notice goes), and from then on ignores the interface's "up" and "down".
 * Until Stage 1 a "down" only set "offline".
 *
 * The real shipped code from app.js (IdMgr, _followExchange, _setStatus,
 * _exchangeIsStopped, _applyStatusDot, h, clear) over a real PostInterface
 * and the scripted PHP node of test_stage1_node.mjs.
 *
 * Run: node --test exchange_stopped.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { Identity } from "./lib/rns/reticulum.js";
import EventEmitter from "./lib/rns/utils/events.js";
import PostInterface from "./lib/rns/interfaces/post_interface.js";
import { build, compile, constValue, fn, methodBody } from "./test_app_source.mjs";
import { captureConsole, eventually, fakeTimers, signingInterface, stage1Node, tick } from "./test_stage1_node.mjs";

class El {
    constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this.style = {}; this.className = ""; this.title = ""; }
    appendChild(c) { this.children.push(c); return c; }
    removeChild(c) { this.children.splice(this.children.indexOf(c), 1); return c; }
    get firstChild() { return this.children[0] ?? null; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    addEventListener(type, f) { (this.listeners[type] ??= []).push(f); }
    get textContent() { return this.children.map((c) => c.textContent ?? "").join(""); }
}

/** The status dot and the line under it, as render() builds them; rerender() builds them anew, as every render does. */
function statusPage() {
    const els = {};
    const rerender = () => { els["status-dot"] = new El("span"); els["exchange-blocked"] = new El("div"); };
    rerender();
    const document = {
        createElement: (tag) => new El(tag),
        createTextNode: (text) => ({ textContent: text }),
        getElementById: (id) => els[id] ?? null,
    };
    return {
        document, rerender,
        h: fn("h", "tag, a={}, ...kids", { document }),
        clear: fn("clear", "el", {}),
        get dot() { return els["status-dot"]; },
        get line() { return els["exchange-blocked"]; },
    };
}

/** RnsClient's side of one connection, from app.js: the real _followExchange, _setStatus and _exchangeIsStopped over `iface`. */
function connection(iface) {
    const statuses = [];
    const harness = [];
    const Harness = { event: (kind, detail) => { harness.push({ kind, detail }); if (kind === "status") statuses.push(detail.status); }, markReady() {} };
    const RnsClient = {
        _rns: { interfaces: [iface] }, _status: "connecting", _connType: "exchange", _onStatus: [], exchangeBlocked: null, exchangeStopped: null,
        _onExchangeRegistered() {}, _onPacketsLost() {}, _onPageResume() {}, _sendDistroNeverLeft() {},
    };
    RnsClient._setStatus = compile("_setStatus(s, type)", { Harness })(RnsClient);
    RnsClient._exchangeIsStopped = compile("_exchangeIsStopped(iface, reason)", { Harness, console: { warn() {} } })(RnsClient);
    compile("_followExchange(iface)", {})(RnsClient)(iface);
    return { RnsClient, statuses, harness };
}

/**
 * The arguments of every `new PostInterface(` in `text`, as source text: a
 * scan to the matching parenthesis that splits at the top-level commas,
 * past strings and nested brackets.
 */
function constructions(text) {
    const calls = [];
    for (let at = text.indexOf("new PostInterface("); at !== -1; at = text.indexOf("new PostInterface(", at + 1)) {
        const args = [];
        let depth = 0, quote = null, arg = "";
        for (let i = at + "new PostInterface(".length; i < text.length; i++) {
            const c = text[i];
            if (quote) {
                arg += c;
                if (c === "\\") arg += text[++i];
                else if (c === quote) quote = null;
                continue;
            }
            if (c === "'" || c === '"' || c === "`") quote = c;
            else if ("([{".includes(c)) depth++;
            else if (")]}".includes(c)) {
                if (depth === 0) { args.push(arg.trim()); break; }
                depth--;
            } else if (c === "," && depth === 0) { args.push(arg.trim()); arg = ""; continue; }
            arg += c;
        }
        calls.push(args.filter((a) => a !== ""));
    }
    return calls;
}

test("every page passes the identity's hash third, a string, and the identity in the options: a lib older than Stage 1 never sends its keys", async (t) => {
    // A PostInterface older than Stage 1 (f54d7cd) sends its third argument
    // to the PHP node as metadata.identity_hash, through JSON.stringify: an
    // Identity there would carry its private keys. So the third argument
    // stays the hash, a string, on every page, and the identity goes in the
    // options, which such a lib ignores.
    const pages = {
        "app.js": { hash: "IdMgr.hash", options: "{ identity: IdMgr.id }" },
        "debug-standalone.html": { hash: "identHash", options: "{ identity: ident }" },
    };
    for (const [file, expected] of Object.entries(pages)) {
        const calls = constructions(readFileSync(new URL(`./${file}`, import.meta.url), "utf8"));
        assert.equal(calls.length, 1, `${file} makes one PostInterface`);
        for (const args of calls) {
            assert.equal(args[2], expected.hash, `${file}: the third argument is the identity's hash, a string, never the identity`);
            assert.equal(args[4], expected.options, `${file}: the identity goes in the options`);
            assert.equal(args.length, 5, file);
        }
    }
    const debugPage = readFileSync(new URL("./debug-standalone.html", import.meta.url), "utf8");
    assert.match(debugPage, /identHash = ident\.hash\.toString\('hex'\);/, "the debug page's identHash is the hex string");

    // IdMgr.hash is that string, and the interface made as app.js makes it signs as IdMgr.id.
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge", "exchange"] });
    const IdMgr = build("IdMgr", { Identity, Buffer, sGet: () => null, sSet: () => {}, ID_KEY: "identity" });
    IdMgr.create();
    assert.equal(typeof IdMgr.hash, "string");
    assert.equal(IdMgr.hash, IdMgr.id.hash.toString("hex"));
    const iface = new PostInterface("Retichat Web", "https://node.example/reticulum", IdMgr.hash, undefined, { identity: IdMgr.id });
    t.after(() => iface.disconnect());
    iface.connect();
    const registering = await node.pending("register");
    assert.equal(registering.body.registration.public_key, IdMgr.pubKey, "it signs as this identity");
    assert.equal(node.serve(registering).json.identity_hash, IdMgr.hash);
    await eventually(() => iface.isUp, "up");
    assert.equal(clock.armed().ms, 1000);
});

test("a stop's reason shows under the status dot, survives a re-render, and is not replaced by a later down or up", async (t) => {
    captureConsole(t);
    const clock = fakeTimers(t);
    const node = stage1Node(t, { auto: ["challenge", "register"] });
    const identity = Identity.create();
    const iface = signingInterface(identity);
    t.after(() => iface.disconnect());
    const { RnsClient, statuses, harness } = connection(iface);

    // The page applies the status on every change (_wire's onStatus listener) and after every render.
    const page = statusPage();
    const App = { state: {}, render() {} };
    const apply = compile("_applyStatusDot()", { document: page.document, h: page.h, clear: page.clear, RnsClient,
        EXCHANGE_BLOCKED_NOTICE: constValue("EXCHANGE_BLOCKED_NOTICE") })(App);
    RnsClient._onStatus.push(() => apply());

    iface.connect();
    await node.serveNext("exchange");
    await eventually(() => RnsClient._status === "online", "online");
    assert.deepEqual([page.dot.className, page.line.children.length], ["status-dot online", 0], "nothing under the dot while all is well");

    // Another tab or device of this identity connects: newest wins, and this one stops.
    node.supersede(identity.hash.toString("hex"));
    clock.fire(clock.armed());
    await node.serveNext("exchange");
    await eventually(() => RnsClient._status === "stopped", "stopped");
    const REASON = PostInterface.STOP_SUPERSEDED;
    assert.equal(REASON, "This identity connected from another tab or device. Reload to connect here.");
    assert.equal(RnsClient.exchangeStopped, REASON, "kept as the connection's own state");
    assert.equal(RnsClient.exchangeBlocked, null, "never in exchangeBlocked, the policy error Settings shows");
    assert.deepEqual([page.dot.className, page.dot.title, page.line.textContent], ["status-dot stopped", REASON, REASON],
        "the reason, under the status dot");
    assert.deepEqual(harness.filter((e) => e.kind === "exchange-stopped").map((e) => e.detail), [{ reason: REASON }]);

    // A render destroys the old DOM and applies the status again.
    for (let render = 0; render < 2; render++) {
        page.rerender();
        apply();
        assert.deepEqual([page.dot.className, page.dot.title, page.line.textContent, page.line.children.length],
            ["status-dot stopped", REASON, REASON, 1], `re-render ${render + 1}: said again, once`);
    }

    // A down or an up heard later moves nothing (as once blocked).
    iface.emit("down", "Failed to fetch");
    iface.emit("up");
    await tick(); await tick();
    assert.equal(RnsClient._status, "stopped");
    assert.equal(page.line.textContent, REASON);
    assert.deepEqual(statuses, ["online", "stopped"]);

    // And so does a second stop: the first reason stays.
    iface.emit("stopped", "Something else.");
    await tick(); await tick();
    assert.equal(RnsClient.exchangeStopped, REASON);
    assert.equal(harness.filter((e) => e.kind === "exchange-stopped").length, 1);
});

test("a stop heard from an interface that is no longer this connection's changes nothing; a disconnect or a reconnect starts again", async () => {
    const iface = new EventEmitter();
    const { RnsClient, statuses } = connection(iface);
    RnsClient._rns = { interfaces: [] }; // disconnect() replaced it
    iface.emit("stopped", PostInterface.STOP_SUPERSEDED);
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(RnsClient.exchangeStopped, null);
    assert.deepEqual(statuses, []);

    // The status "stopped" with no reason kept says nothing under the dot.
    const page = statusPage();
    const apply = compile("_applyStatusDot()", { document: page.document, h: page.h, clear: page.clear,
        RnsClient: { _status: "stopped", exchangeStopped: null }, EXCHANGE_BLOCKED_NOTICE: constValue("EXCHANGE_BLOCKED_NOTICE") })({});
    apply();
    assert.deepEqual([page.dot.className, page.dot.title, page.line.children.length], ["status-dot stopped", "RNS: stopped", 0]);

    // A reload or an explicit reconnect starts again: both clear the state; the Harness's snapshot carries it.
    assert.match(methodBody("async connect()"), /this\.exchangeBlocked = null;\n\s+this\.exchangeStopped = null;/);
    assert.match(methodBody("disconnect()"), /this\.exchangeBlocked = null;\n\s+this\.exchangeStopped = null;/);
    assert.match(methodBody("state()"), /exchangeStopped: RnsClient\.exchangeStopped,/);
    const css = readFileSync(new URL("./style.css", import.meta.url), "utf8");
    assert.match(css, /\.status-dot\.stopped \{ background: var\(--danger\); \}/);
});

test("the debug page writes what the exchange reports as text: a stop reason, which can be the PHP node's own message, is never parsed as HTML", () => {
    const page = readFileSync(new URL("./debug-standalone.html", import.meta.url), "utf8");
    assert.match(page, /iface\.on\('stopped', function\(reason\) \{ logText\('Exchange stopped: ' \+ reason, 'err'\); \}\);/);
    assert.match(page, /iface\.on\('down', function\(reason\) \{ logText\('Exchange down: ' \+ reason, 'err'\); \}\);/);

    // logText itself, over stand-ins: the reason goes in as text, and nothing is set as HTML.
    const start = page.indexOf("function logText(");
    const source = page.slice(start, page.indexOf("\n}\n", start) + 2);
    assert.doesNotMatch(source, /innerHTML/);
    const appended = [];
    const document = { createElement: (tag) => ({ tag, className: "", textContent: "" }) };
    const $el = { append: (...nodes) => appended.push(...nodes), scrollTop: 0, scrollHeight: 0,
        set innerHTML(html) { throw new Error(`set as HTML: ${html}`); } };
    const logText = new Function("document", "$el", `${source}\nreturn logText;`)(document, $el);
    const reason = '<img src=x onerror="alert(1)">The PHP node says no.';
    logText(`Exchange stopped: ${reason}`, "err");
    const line = appended.find((node) => node?.tag === "span" && node.className === "err");
    assert.equal(line.textContent, `Exchange stopped: ${reason}`, "set as text");
});
