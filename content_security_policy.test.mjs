/**
 * The page's Content-Security-Policy (.htaccess, on index.html only) against
 * what the page loads:
 *
 *   - script-src is this origin, exactly the hosts index.html's importmap and
 *     script tags name (esm.sh), and the inline importmap by the hash of its
 *     exact text; no 'unsafe-inline', and index.html has no other inline
 *     script. Change a byte of the importmap and this test says which hash
 *     the policy must carry;
 *   - no 'unsafe-eval': the importmap names msgpackr's no-eval build, which
 *     is the default build's code with its `new Function` calls replaced and
 *     which, unlike the default, attempts no string evaluation at load or
 *     while reading; the harness pages (debug.html, debug-standalone.html)
 *     map every module as index.html does, so they run the build it ships;
 *   - the directives the page needs and the walls it must keep (object-src,
 *     base-uri, frame-ancestors, img/media for attachment blobs, connect-src
 *     for this origin, each production node's exchange and esm.sh);
 *   - the boot gate (deploy.sh boot_gate_js) reads this same line from the
 *     same file, so the page is booted under exactly what it is served with.
 *
 * That the page boots under it with no violation is the boot gate's to show
 * (deploy_gates.test.mjs, and every deploy).
 *
 * Run: node --test content_security_policy.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import vm from "node:vm";

const read = (f) => readFileSync(new URL(`./${f}`, import.meta.url), "utf8");
const htaccess = read(".htaccess");
const index = read("index.html");

/** The policy's value and the block that sets it. */
function policy() {
    const lines = [...htaccess.matchAll(/^\s*Header\s+(?:always\s+)?set\s+Content-Security-Policy\s+"([^"]+)"\s*$/gm)];
    assert.equal(lines.length, 1, "one Content-Security-Policy line in .htaccess");
    const value = lines[0][1];
    const directives = new Map(value.split(";").map((d) => d.trim()).filter(Boolean).map((d) => {
        const [name, ...sources] = d.split(/\s+/);
        return [name, sources];
    }));
    return { value, directives, at: lines[0].index };
}

/** index.html's script elements: [{attrs, text}]. */
const scripts = () => [...index.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)].map((m) => ({ attrs: m[1], text: m[2] }));

test("script-src: this origin, exactly the importmap's hosts, and the inline importmap by its hash; nothing else inline", () => {
    const { directives } = policy();
    const scriptSrc = directives.get("script-src");
    assert.ok(scriptSrc, "a script-src");
    assert.ok(!scriptSrc.includes("'unsafe-inline'"), "no 'unsafe-inline'");

    const inline = scripts().filter((s) => !/\bsrc\s*=/.test(s.attrs));
    assert.deepEqual(inline.map((s) => s.attrs.trim()), ['type="importmap"'], "the importmap is the page's one inline script");
    const hash = `'sha256-${createHash("sha256").update(inline[0].text, "utf8").digest("base64")}'`;
    const hashes = scriptSrc.filter((s) => s.startsWith("'sha"));
    assert.deepEqual(hashes, [hash], `the policy carries the importmap's hash, ${hash}, and no other`);

    // Every host a script can come from: the importmap's targets and src attributes.
    const map = JSON.parse(inline[0].text).imports;
    const urls = [...Object.values(map), ...scripts().map((s) => s.attrs.match(/\bsrc\s*=\s*"([^"]+)"/)?.[1]).filter(Boolean)];
    const hosts = [...new Set(urls.filter((u) => /^https?:/.test(u)).map((u) => new URL(u).origin))].sort();
    assert.deepEqual(hosts, ["https://esm.sh"], "(the importmap's hosts today)");
    const sources = scriptSrc.filter((s) => !s.startsWith("'"));
    assert.deepEqual(sources.sort(), hosts, "script-src names exactly those hosts");
    assert.deepEqual(scriptSrc.filter((s) => s.startsWith("'") && !s.startsWith("'sha")), ["'self'"],
        "this origin; no 'unsafe-eval' (msgpackr is its no-eval build, below)");
});

/** The importmap of an HTML page in this repo, parsed. */
const importmap = (page) => JSON.parse(read(page).match(/<script type="importmap">([\s\S]*?)<\/script>/)[1]).imports;

test("msgpackr is its no-eval build, at the version the suite tests; the harness pages map every module as the app does", () => {
    const url = importmap("index.html").msgpackr;
    const m = url.match(/^https:\/\/esm\.sh\/msgpackr@([\d.]+)\/index-no-eval$/);
    assert.ok(m, `the importmap's msgpackr is the package's "./index-no-eval" export, not ${url}`);
    const pinned = JSON.parse(read("package.json")).devDependencies.msgpackr;
    assert.equal(m[1], pinned, "the version package.json pins, which node_modules holds and the suite tests");
    assert.equal(JSON.parse(readFileSync(join(msgpackrDir(), "package.json"), "utf8")).version, pinned);
    // debug.html says it carries an "Identical import map to index.html: the
    // harness runs the REAL stack", and debug-standalone.html loads the same
    // stack: neither may run a different build of anything.
    for (const page of ["debug.html", "debug-standalone.html"]) {
        assert.deepEqual(importmap(page), importmap("index.html"), `${page} maps every module as index.html does`);
    }
});

/** node_modules/msgpackr. */
const msgpackrDir = () => dirname(dirname(createRequire(import.meta.url).resolve("msgpackr/index-no-eval")));

/**
 * Load a UMD build of msgpackr into a realm that refuses string evaluation
 * as the page's policy does: `Function` there throws, as a CSP without
 * 'unsafe-eval' makes it, and counts each attempt. Then pack and read back
 * an LXMF-shaped payload and a run of plain objects (msgpackr's records,
 * whose reader the default build compiles with `new Function`, where it may,
 * once it has read the same shape twice). Returns the attempts and the
 * read-back values as JSON text.
 */
function underNoEval(file) {
    const context = vm.createContext({ exports: {}, module: {}, TextDecoder, TextEncoder, attempts: 0 });
    vm.runInContext(`Function = new Proxy(Function, {
        construct() { attempts++; throw new EvalError("refused: no 'unsafe-eval'"); },
        apply() { attempts++; throw new EvalError("refused: no 'unsafe-eval'"); },
    });`, context);
    vm.runInContext(readFileSync(join(msgpackrDir(), file), "utf8"), context, { filename: file });
    const out = vm.runInContext(`(() => {
        const p = new exports.Packr({ mapsAsObjects: false });
        const title = new Uint8Array([0x68, 0x69]);
        const fields = new Map([[0xD1, new Map([[0, "Zoë, a name of more than sixteen bytes"]])], [5, [[ "a.jpg", new Uint8Array(3) ]]]]);
        const lxmf = p.unpack(p.pack([1790000000.25, title, new Uint8Array([0xe2, 0x82, 0xac]), fields]));
        const records = [];
        for (let i = 0; i < 5; i++) records.push(p.unpack(p.pack({ seq: i, text: "same shape" })));
        return JSON.stringify([lxmf[0], [...lxmf[1]], [...lxmf[2]], [...lxmf[3].get(0xD1)], lxmf[3].get(5)[0][0], records],
            (k, v) => v instanceof Map ? [...v] : v);
    })()`, context);
    return { attempts: context.attempts, out };
}

test("msgpackr's no-eval build: the default build's code with only its string evaluation removed, and it never attempts one", (t) => {
    const dist = (f) => readFileSync(join(msgpackrDir(), "dist", f), "utf8").replace(/\n\/\/# sourceMappingURL=.*\n?$/, "\n");
    const noEval = dist("index-no-eval.cjs");
    // Undo the build's one edit (rollup replace: Function -> "BlockedFunction ",
    // msgpackr rollup.config.js) at the evaluation sites only.
    const undone = noEval
        .replace(/^\s*var BlockedFunction;.*\n/m, "")
        .replaceAll("new BlockedFunction (", "new Function(");
    assert.equal(undone, dist("index.js"),
        "apart from its `new Function` calls, the no-eval build is the default build, line for line");
    assert.equal((noEval.match(/new BlockedFunction \(/g) ?? []).length, 2, "the probe at load and the record reader");
    assert.doesNotMatch(noEval, /\bnew Function\b|\bFunction\s*\(|\beval\s*\(/, "no evaluation left");

    // Run both where evaluation is refused, as under the page's policy.
    const plain = underNoEval("dist/index.js");
    const safe = underNoEval("dist/index-no-eval.cjs");
    t.diagnostic(`evaluation attempts: default build ${plain.attempts}, no-eval build ${safe.attempts}; read back ${safe.out}`);
    assert.equal(plain.attempts, 1, "the premise: the default build tries once, at load, a violation under the policy even though it "
        + "catches the refusal (and, refused, never compiles a record reader)");
    assert.equal(safe.attempts, 0, "the no-eval build never tries, at load or reading records");
    assert.equal(safe.out, plain.out, "and both read back the same values");
    assert.match(safe.out, /Zoë, a name of more than sixteen bytes/);
});

test("the walls and what the page needs: objects, base, framing, forms, styles, attachment blobs, the exchanges", () => {
    const { directives } = policy();
    const d = (name) => directives.get(name) ?? [];
    assert.deepEqual(d("default-src"), ["'self'"]);
    assert.deepEqual(d("object-src"), ["'none'"]);
    assert.deepEqual(d("base-uri"), ["'self'"]);
    assert.deepEqual(d("frame-ancestors"), ["'none'"]);
    assert.deepEqual(d("form-action"), ["'self'"]);
    assert.deepEqual(d("style-src"), ["'self'"], "style.css; the DOM sets the rest (el.style)");
    assert.deepEqual(d("img-src").sort(), ["'self'", "blob:", "data:"].sort());
    assert.deepEqual(d("media-src").sort(), ["'self'", "blob:"].sort());

    // connect-src: this origin (config.json, the node's own exchange), each
    // production node's exchange as a config.json may name it, and esm.sh.
    // PostInterface requests <exchangeUrl>/v1/…, so each is a path prefix.
    const connect = d("connect-src");
    const app = read("app.js");
    const fallback = app.match(/const DEFAULT_CONFIG = \{[\s\S]*?exchangeUrl: "([^"]+)"/)[1];
    assert.equal(fallback, "https://retichat.com/reticulum");
    for (const exchange of [fallback, "https://selectivesubconscious.com/reticulum"]) {
        assert.ok(connect.includes(`${exchange}/`), `connect-src allows ${exchange}/…`);
    }
    assert.deepEqual(connect.sort(), ["'self'", "https://esm.sh", "https://retichat.com/reticulum/",
        "https://selectivesubconscious.com/reticulum/"].sort(), "and nothing else");
    assert.match(read("lib/rns/interfaces/post_interface.js"), /const url = this\._baseUrl \+ path;/,
        "(the exchange is requested under its base URL)");
});

test("set on the app's document only, by mod_headers, beside the cache policy", () => {
    const { at } = policy();
    const before = htaccess.slice(0, at);
    const open = before.lastIndexOf("<Files");
    assert.notEqual(open, -1);
    assert.match(before.slice(open), /^<Files "index\.html">\s*$/m, "inside <Files \"index.html\">: never the exchange's or anyone else's pages");
    assert.ok(before.lastIndexOf("<IfModule mod_headers.c>") > before.lastIndexOf("</IfModule>"), "inside <IfModule mod_headers.c>");
});

test("the boot gate reads this line from this file", () => {
    const { value } = policy();
    const gate = execFileSync("/bin/bash", ["-c", 'source "$1" && boot_gate_js', "_", new URL("./deploy.sh", import.meta.url).pathname],
        { encoding: "utf8", env: { PATH: process.env.PATH } });
    const source = gate.match(/const CSP_LINE = (\/.+\/m);/)?.[1];
    assert.ok(source, "the gate has its CSP_LINE");
    const regex = new Function(`return ${source};`)();
    assert.equal(htaccess.match(regex)?.[1], value, "and it reads the same value");
    assert.match(gate, /join\(ROOT, "\.htaccess"\)/, "from the .htaccess of the directory it boots");
    assert.match(gate, /"content-security-policy": csp/, "and serves it");
    assert.match(gate, /addEventListener\("securitypolicyviolation"/, "and fails on any violation");
});
