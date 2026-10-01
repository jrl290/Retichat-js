/**
 * The page's Content-Security-Policy (.htaccess, on index.html only) against
 * what the page loads:
 *
 *   - script-src is this origin, exactly the hosts index.html's importmap and
 *     script tags name (esm.sh), and the inline importmap by the hash of its
 *     exact text; no 'unsafe-inline', and index.html has no other inline
 *     script. Change a byte of the importmap and this test says which hash
 *     the policy must carry;
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
    assert.deepEqual(scriptSrc.filter((s) => s.startsWith("'") && !s.startsWith("'sha")).sort(), ["'self'", "'unsafe-eval'"],
        "this origin, and eval for msgpackr's probe (see .htaccess)");
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
