// The module graph's shipping invariants.
//
// There is no build step here: index.html declares an importmap and the browser
// fetches ~34 ES modules directly off the static host. Two failure modes that
// follow from that are invisible in Node and only appear in a live tab, so they
// are checked here instead of being discovered later:
//
//   1. A stale module served from a browser cache. Staleness used to be managed
//      by appending `?v=<date>` to individual import specifiers by hand. On
//      2026-08-17 8 of 34 local imports carried a tag and 26 did not — every
//      transport module (link.js, packet.js, resource.js, post_interface.js,
//      lxmf_router.js) was untagged — and the host sent no Cache-Control header
//      at all. A fix could be committed, deployed and hash-verified and still
//      not be the code running in the tab. That is indistinguishable from a
//      regression and much harder to find, so .htaccess now owns the cache
//      policy and no source file may carry a version tag.
//
//   2. An import that does not resolve. No bundler checks these; the symptom is
//      a blank screen and one console line.
//
// deploy.sh gates on this suite, so both are checked before anything ships.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));

/** Every file the browser loads, relative to the repo root. */
function servedFiles(exts) {
    const out = [];
    const walk = (dir) => {
        for (const entry of readdirSync(dir)) {
            if (entry === "node_modules" || entry === "selectiv-snapshot" || entry.startsWith(".")) {
                continue;
            }
            const full = join(dir, entry);
            if (statSync(full).isDirectory()) {
                walk(full);
            } else if (exts.some((e) => entry.endsWith(e)) && !entry.endsWith(".test.mjs")) {
                out.push(full);
            }
        }
    };
    walk(join(ROOT, "lib"));
    for (const top of ["app.js", "index.html"]) {
        out.push(join(ROOT, top));
    }
    return out.filter((f) => exts.some((e) => f.endsWith(e)));
}

test("no source file carries a hand-maintained cache-busting tag", () => {
    const offenders = [];
    for (const file of servedFiles([".js", ".html"])) {
        const lines = readFileSync(file, "utf8").split("\n");
        lines.forEach((line, i) => {
            if (line.includes("?v=")) {
                offenders.push(`${relative(ROOT, file)}:${i + 1}: ${line.trim()}`);
            }
        });
    }
    assert.deepEqual(
        offenders,
        [],
        "Cache busting belongs to .htaccess, not to import specifiers. Tagging " +
        "by hand means walking the whole import chain on every change, and the " +
        "modules that get missed are the ones that stay stale in the browser:\n" +
        offenders.join("\n"),
    );
});

test("every relative import resolves to a file that ships", () => {
    const missing = [];
    for (const file of servedFiles([".js"])) {
        const source = readFileSync(file, "utf8");
        for (const match of source.matchAll(/(?:from|import)\s+"(\.[^"]+)"/g)) {
            const spec = match[1];
            const target = resolve(dirname(file), spec);
            if (!existsSync(target)) {
                missing.push(`${relative(ROOT, file)} imports ${spec}`);
            }
        }
    }
    assert.deepEqual(missing, [], `unresolvable imports:\n${missing.join("\n")}`);
});

test("index.html loads the entry point and stylesheet without a query string", () => {
    const html = readFileSync(join(ROOT, "index.html"), "utf8");
    assert.match(html, /src="app\.js"/, "index.html must load app.js at a bare URL");
    assert.match(html, /href="style\.css"/, "index.html must load style.css at a bare URL");
});

test(".htaccess makes modules revalidate", () => {
    const htaccess = join(ROOT, ".htaccess");
    assert.ok(
        existsSync(htaccess),
        ".htaccess is the only thing preventing a browser from serving a stale " +
        "module now that version tags are gone — it must exist and must deploy",
    );
    const text = readFileSync(htaccess, "utf8");
    assert.match(
        text,
        /Header set Cache-Control "no-cache/,
        ".htaccess must set a no-cache policy for the module files",
    );
    assert.match(
        text,
        /js\|mjs\|css/,
        "the no-cache policy must cover js/mjs/css",
    );
});

test(".htaccess keeps forcing HTTPS", () => {
    // retichat.com's public_html/.htaccess was hand-edited and tracked nowhere;
    // all it contained was this redirect. Since deploy.sh overwrites that file,
    // dropping the block here would silently disable TLS enforcement on the
    // next deploy.
    const text = readFileSync(join(ROOT, ".htaccess"), "utf8");
    assert.match(text, /RewriteEngine On/, ".htaccess must enable mod_rewrite");
    assert.match(
        text,
        /RewriteRule \^\(\.\*\)\$ https:\/\/%\{HTTP_HOST\}\/\$1 \[R=301,L\]/,
        ".htaccess must redirect plain HTTP to HTTPS — this file replaces the " +
        "node's only copy of that rule",
    );
    assert.match(
        text,
        /RewriteCond %\{HTTP:X-Forwarded-Proto\} !https/,
        "the proxy's X-Forwarded-Proto must be honoured or the redirect loops",
    );
});
