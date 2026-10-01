// deploy.sh and verify-deploy.sh, offline.
//
// The deploy gates added on 2026-09-30 for the web release:
//
//   - stray files: deploy.sh lists each node's web client directory over the
//     SSH it already uses (ls, nothing else) and refuses to deploy while a
//     file outside the payload and the node's config.json is served there;
//     `clean-strays <node> --yes` moves exactly those files out of the
//     docroot, reversibly. The node layouts differ: selectiv's directory holds
//     only the web client, retichat.com's is the host's docroot and also holds
//     the PHP node and other things this script must never flag or touch.
//   - debug.html and debug-standalone.html are no longer served: they are not
//     in the payload and are stray on every node.
//   - verify-deploy.sh probes known stray names over HTTPS and fails if one
//     answers, or if the node answers 200 for a name that cannot exist.
//   - a headless boot gate: the staged export is loaded in Chromium and any
//     pageerror or failed module import in the first 10 s refuses the deploy.
//   - with no node named, retichat.com is deployed first, then selectiv.
//
// Nothing here reaches a real node. The scripts under test are copied into a
// fixture repo with no deploy.env; `ssh` and `curl` are PATH shims that serve
// fake node homes on this disk, and every host name the tests hand the
// scripts ends in .invalid or names no host at all, so a missing shim fails
// to resolve instead of reaching production. The boot gate runs the
// Playwright + Chromium of test-harnesses/distro-pipeline against pages
// served from this disk; those tests skip if no browser is installed.
//
// The tests that start Chromium run only with RETICHAT_BOOT_TESTS=1
// (`npm run test:full`), and deploy.sh sets it when it runs the suite, so
// they still run on every deploy. A plain `npm test` skips them, each one
// marked SKIP with the reason, and says so on stderr: they add headless
// browsers and about 25 s to a run, which a quick check does not need.

import test, { describe, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
    mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, copyFileSync,
    chmodSync, readdirSync, statSync, symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PLAYWRIGHT_DIR = resolve(ROOT, "../test-harnesses/distro-pipeline");

// Chromium runs only when asked for; deploy.sh always asks (see the header).
const BOOT_TESTS = process.env.RETICHAT_BOOT_TESTS === "1";
const BOOT_SKIP = "RETICHAT_BOOT_TESTS is not 1: run `npm run test:full` (deploy.sh always does)";
/** A test that starts Chromium: it runs only with RETICHAT_BOOT_TESTS=1. */
const chromiumTest = BOOT_TESTS ? test : (name, fn) => test(name, { skip: BOOT_SKIP }, fn);
if (!BOOT_TESTS) {
    process.stderr.write("\n⚠ deploy_gates.test.mjs: the boot-gate tests that start Chromium are SKIPPED.\n"
        + `  ${BOOT_SKIP}.\n\n`);
}
const TMP = mkdtempSync(join(tmpdir(), "deploy-gates-"));
after(() => rmSync(TMP, { recursive: true, force: true }));

let seq = 0;
const scratch = (name) => {
    const d = join(TMP, `${String(++seq).padStart(3, "0")}-${name}`);
    mkdirSync(d, { recursive: true });
    return d;
};
const write = (file, body) => { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, body); };

// ── Shims ──────────────────────────────────────────────────────────────────

const SHIMS = scratch("shims");
// Bash in a template literal: String.raw keeps the backslashes, and \${ (a
// bash expansion, escaped so JS leaves it alone) is put back to ${.
const sh = (s, ...v) => String.raw(s, ...v).replaceAll("\\${", "${");
// ssh: runs the remote command locally with HOME = $FAKE_SSH_ROOT/<host>, and
// logs host and command. A host with no home there is refused, as an
// unresolvable host is by real ssh.
write(join(SHIMS, "ssh"), sh`#!/bin/bash
host=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-p|-i|-l|-F) shift 2 ;;
    -*) shift ;;
    *) host="$1"; shift; break ;;
  esac
done
cmd="$*"
printf '%s\x1f%s\x1e' "$host" "$cmd" >> "$FAKE_SSH_LOG"
if [ -z "$host" ] || [ -z "$FAKE_SSH_ROOT" ] || [ ! -d "$FAKE_SSH_ROOT/$host" ]; then
  echo "ssh: Could not resolve hostname $host (test shim)" >&2
  exit 255
fi
HOME="$FAKE_SSH_ROOT/$host" exec /bin/bash -c "$cmd"
`);
// curl: serves $FAKE_CURL_MAP ("host/path=dir;...") like the nodes do: https
// serves files (403 for .ht* and directories, Cache-Control when the docroot
// has an .htaccess, as the real one sets), http answers 301 to https. Any
// other URL is logged UNMAPPED and fails as an unresolvable host.
write(join(SHIMS, "curl"), sh`#!/bin/bash
out=""; fmt=""; dump=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) fmt="$2"; shift 2 ;;
    -D) dump="$2"; shift 2 ;;
    --max-time|-m|--connect-timeout) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
emit() { [ -n "$fmt" ] && printf '%s' "$fmt" | sed -e "s|%{http_code}|$1|g" -e "s|%{redirect_url}|$2|g"; return 0; }
scheme="\${url%%://*}"; rest="\${url#*://}"; rest="\${rest%%\?*}"
root=""; path=""
IFS=';' read -ra maps <<< "$FAKE_CURL_MAP"
for m in "\${maps[@]}"; do
  prefix="\${m%%=*}"; dir="\${m#*=}"
  if [ "$rest" = "$prefix" ] || [ "\${rest#"$prefix"/}" != "$rest" ]; then root="$dir"; path="\${rest#"$prefix"}"; break; fi
done
if [ -z "$root" ]; then
  echo "UNMAPPED $url" >> "$FAKE_CURL_LOG"; emit 000 ""
  echo "curl: (6) Could not resolve host (test shim)" >&2; exit 6
fi
code=404; redirect=""; file=""; cache=""
if [ "$scheme" = http ]; then
  code=301; redirect="https://$rest"
else
  name="\${path##*/}"; f="$root$path"
  if [ "\${name#.ht}" != "$name" ] || [ -d "$f" ]; then code=403
  elif [ -f "$f" ]; then code=200; file="$f"
  elif [ -n "$FAKE_CURL_ALL_200" ]; then code=200; fi
  if [ "$code" = 200 ] && [ -f "$root/.htaccess" ]; then
    case "$name" in *.js|*.mjs|*.css|*.html|*.json) cache="no-cache, must-revalidate" ;; esac
  fi
fi
if [ "$dump" = "-" ]; then
  printf 'HTTP/1.1 %s\r\n' "$code"; [ -n "$cache" ] && printf 'Cache-Control: %s\r\n' "$cache"; printf '\r\n'
fi
if [ -n "$out" ] && [ "$out" != /dev/null ]; then
  if [ -n "$file" ]; then cp "$file" "$out"; else printf 'not found' > "$out"; fi
fi
emit "$code" "$redirect"
exit 0
`);
chmodSync(join(SHIMS, "ssh"), 0o755);
chmodSync(join(SHIMS, "curl"), 0o755);

// ── Fixtures ───────────────────────────────────────────────────────────────

const PAGE = (importmap = {}) => `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>fixture</title>
<link rel="stylesheet" href="style.css">
<script type="importmap">${JSON.stringify({ imports: importmap })}</script>
</head><body><div id="app"></div><script type="module" src="app.js"></script></body></html>
`;
const RENDER = `document.getElementById("app").append(Object.assign(document.createElement("p"), { textContent: "booted" }));\n`;

/** The fixture's .htaccess: a Content-Security-Policy for `page` as the real
 *  one is built (.htaccess, content_security_policy.test.mjs): its inline
 *  importmap by hash, the importmap's hosts, this origin. connect-src also
 *  names the host the good page beacons to, so that request reaches the
 *  gate's own block. The boot gate reads it from here. */
function fixtureHtaccess(page) {
    const map = page.match(/<script type="importmap">([\s\S]*?)<\/script>/)?.[1];
    const hash = map ? ` 'sha256-${createHash("sha256").update(map, "utf8").digest("base64")}'` : "";
    const hosts = map ? [...new Set(Object.values(JSON.parse(map).imports).filter((u) => /^https?:/.test(u)).map((u) => new URL(u).origin))] : [];
    const csp = `default-src 'self'; script-src 'self'${hash}${hosts.map((h) => ` ${h}`).join("")}; `
        + `connect-src 'self' https://blocked-host.invalid; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`;
    return `# fixture\n<IfModule mod_headers.c>\n  <Files "index.html">\n    Header set Content-Security-Policy "${csp}"\n  </Files>\n</IfModule>\n`;
}

/** A web client payload that boots: a local module, a mapped bare specifier,
 *  and a boot that reads config.json and posts to the exchange it names. */
function goodSite(dir, extra = {}) {
    const files = {
        "index.html": PAGE({ shim: "./lib/shim.js" }),
        "app.js": `import { word } from "./lib/a.js";
import shim from "shim";
const cfg = await (await fetch("./config.json")).json();
// The gate's own config: the exchange must be on this page's origin, and it
// refuses (503), so a boot never reaches a real one.
if (new URL(cfg.exchangeUrl).origin !== location.origin) throw new Error("exchange is not local: " + cfg.exchangeUrl);
const r = await fetch(cfg.exchangeUrl, { method: "POST", body: "{}" });
if (r.status !== 503) throw new Error("the exchange answered " + r.status);
// Any other host is blocked and never sent; the page carries on.
await fetch("https://blocked-host.invalid/beacon").catch(() => {});
document.getElementById("app").append(Object.assign(document.createElement("p"), { textContent: word + shim }));
`,
        "lib/a.js": `export const word = "booted";\n`,
        "lib/shim.js": `export default 1;\n`,
        // verify-deploy.sh reads the cache header of this one by name.
        "lib/rns/link.js": `export const link = 1;\n`,
        "style.css": "body { margin: 0 }\n",
        "retichat-icon.png": "png",
        ...extra,
    };
    if (!(".htaccess" in files)) files[".htaccess"] = fixtureHtaccess(files["index.html"] ?? "");
    for (const [f, body] of Object.entries(files)) if (body !== null) write(join(dir, f), body);
    return dir;
}

const git = (dir, ...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });

/** A git repo holding a payload and copies of the scripts under test. */
function fixtureRepo(name, extra = {}) {
    const repo = scratch(name);
    goodSite(repo, {
        "debug.html": "<!-- harness page: never deployed -->\n",
        "debug-standalone.html": "<!-- harness page: never deployed -->\n",
        "package.json": JSON.stringify({ name: "fixture", version: "0.0.0", private: true, scripts: { test: "node -e \"console.log('ℹ pass 1')\"" } }),
        ...extra,
    });
    mkdirSync(join(repo, "node_modules"));
    git(repo, "init", "-q");
    git(repo, "add", "-A", "--", ".", ":!node_modules");
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "fixture");
    copyFileSync(join(ROOT, "deploy.sh"), join(repo, "deploy.sh"));
    copyFileSync(join(ROOT, "verify-deploy.sh"), join(repo, "verify-deploy.sh"));
    chmodSync(join(repo, "deploy.sh"), 0o755);
    chmodSync(join(repo, "verify-deploy.sh"), 0o755);
    return repo;
}

const HOSTS = { retichat: "retichat-node", selectiv: "selectiv-node" };
const WEB = { retichat: "retichat-node.invalid", selectiv: "selectiv-node.invalid/retichat" };

/** Two fake node homes, each as the host holds it: retichat.com's docroot is
 *  shared with the PHP node, cPanel and another site; selectiv's web client
 *  lives in its own directory beside the PHP node and an old copy. */
function fakeNodes(name, { retichat = {}, selectiv = {} } = {}) {
    const root = scratch(name);
    const r = join(root, HOSTS.retichat, "public_html");
    const s = join(root, HOSTS.selectiv, "public_html", "retichat");
    const old = { "index.html": "old index\n", "app.js": "old app\n", "style.css": "old css\n", "retichat-icon.png": "old", ".htaccess": "# old\n", "lib/old.js": "old lib\n" };
    for (const [f, b] of Object.entries({
        ...old,
        "config.json": '{"exchangeUrl": "https://retichat.com/reticulum"}\n',
        "reticulum/index.php": "<?php // the PHP node\n",
        "reticulum/config.toml": "[node]\n",
        "cgi-bin/.keep": "",
        ".well-known/acme-challenge/token": "acme\n",
        "other-site/index.html": "another site\n",
        "error_log": "host log\n",
        "index.php": "<?php // not ours\n",
        ...retichat,
    })) if (b !== null) write(join(r, f), b);
    for (const [f, b] of Object.entries({
        ...old,
        "config.json": '{"exchangeUrl": "https://selectivesubconscious.com/reticulum"}\n',
        ...selectiv,
    })) if (b !== null) write(join(s, f), b);
    write(join(root, HOSTS.selectiv, "public_html", "reticulum", "index.php"), "<?php // selectiv PHP node\n");
    write(join(root, HOSTS.selectiv, "public_html", "retichat.old", "app.js"), "older copy\n");
    return { root, retichat: r, selectiv: s, home: (n) => join(root, HOSTS[n]) };
}

/** Every file under dir with its bytes, for before/after comparisons. */
function snapshot(dir) {
    const out = {};
    const walk = (d) => {
        for (const e of readdirSync(d)) {
            const p = join(d, e);
            if (statSync(p).isDirectory()) walk(p);
            else out[relative(dir, p)] = readFileSync(p, "latin1");
        }
    };
    if (existsSync(dir)) walk(dir);
    return out;
}

function run(cmd, args, { env = {}, cwd } = {}) {
    return new Promise((ok) => {
        const p = spawn(cmd, args, { cwd, env: { ...process.env, ...env } });
        let out = "";
        p.stdout.on("data", (d) => { out += d; });
        p.stderr.on("data", (d) => { out += d; });
        p.on("close", (code) => ok({ code, out: out.replace(/\x1b\[[0-9;]*m/g, "") }));
    });
}

/** deploy.sh / verify-deploy.sh from a fixture repo, against fake nodes. */
function scriptEnv(nodes, extra = {}) {
    const logs = scratch("logs");
    return {
        logs,
        env: {
            PATH: `${SHIMS}:${process.env.PATH}`,
            FAKE_SSH_ROOT: nodes?.root ?? "",
            FAKE_SSH_LOG: join(logs, "ssh.log"),
            FAKE_CURL_LOG: join(logs, "curl.log"),
            FAKE_CURL_MAP: nodes ? `${WEB.retichat}=${nodes.retichat};${WEB.selectiv}=${nodes.selectiv}` : "",
            RETICHAT_SSH_HOST: HOSTS.retichat, RETICHAT_SSH_PASS: "",
            SELECTIV_SSH_HOST: HOSTS.selectiv, SELECTIV_SSH_PASS: "",
            RETICHAT_WEB_URL: `https://${WEB.retichat}`,
            SELECTIV_WEB_URL: `https://${WEB.selectiv}`,
            DEPLOY_PLAYWRIGHT_DIR: PLAYWRIGHT_DIR,
            ...extra,
        },
    };
}
const sshCalls = (logs) => {
    const f = join(logs, "ssh.log");
    if (!existsSync(f)) return [];
    return readFileSync(f, "utf8").split("\x1e").filter(Boolean).map((r) => {
        const [host, cmd] = r.split("\x1f");
        return { host, cmd };
    });
};
const curlUrls = (logs) => {
    const f = join(logs, "curl.log");
    return existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean) : [];
};
const LISTING = /^if \[ -d ~\/[^ ;]+ \]; then cd ~\/[^ ;]+ && ls -1Ap; fi$/;
const isUpload = (c) => /tar -C ~\/\.retichat-web-incoming -xf -/.test(c.cmd);
const NO_BROWSER = scratch("no-playwright"); // DEPLOY_PLAYWRIGHT_DIR with no Playwright: the gate skips

/** Asserts no request left for a real host: every curl URL is a fake node's. */
function assertOffline(logs) {
    for (const u of curlUrls(logs)) {
        assert.doesNotMatch(u, /^UNMAPPED/, u);
        assert.match(u, /^https?:\/\/[a-z-]+-node\.invalid(\/|$)/, `curl went to ${u}`);
    }
    for (const c of sshCalls(logs)) assert.ok(Object.values(HOSTS).includes(c.host), `ssh went to ${c.host}`);
}

// The boot gate alone: `deploy.sh boot-check <dir>` from a copy with no deploy.env.
const SCRIPT_DIR = scratch("boot-script");
copyFileSync(join(ROOT, "deploy.sh"), join(SCRIPT_DIR, "deploy.sh"));
chmodSync(join(SCRIPT_DIR, "deploy.sh"), 0o755);
const bootCheck = (dir, env = {}) => run(join(SCRIPT_DIR, "deploy.sh"), ["boot-check", dir], {
    env: { DEPLOY_PLAYWRIGHT_DIR: PLAYWRIGHT_DIR, ...env },
});
async function booted(t, site) {
    const r = await bootCheck(site);
    if (r.code === 3) { t.skip("no Chromium installed for the boot gate"); return null; }
    return r;
}

/** A Playwright project dir whose `playwright` module is `indexJs`: the boot
 *  gate's handling of a broken or browserless install, with no real browser. */
function fakePlaywright(name, indexJs) {
    const dir = scratch(name);
    write(join(dir, "package.json"), JSON.stringify({ name: "pw-fixture", private: true }));
    write(join(dir, "node_modules/playwright/package.json"), JSON.stringify({ name: "playwright", version: "0.0.0-fixture", main: "index.js" }));
    write(join(dir, "node_modules/playwright/index.js"), indexJs);
    return dir;
}

/** PATH with the shims first and no node: every PATH directory holding node
 *  (or npm, npx, corepack) is mirrored by symlinks without them. */
function pathWithoutNode() {
    const NODE_BINS = ["node", "npm", "npx", "corepack"];
    const mirror = scratch("path-without-node");
    const dirs = [];
    for (const d of (process.env.PATH ?? "").split(":").filter(Boolean)) {
        if (!existsSync(d) || !statSync(d).isDirectory()) continue;
        if (!NODE_BINS.some((n) => existsSync(join(d, n)))) { dirs.push(d); continue; }
        const m = join(mirror, String(dirs.length));
        mkdirSync(m);
        for (const e of readdirSync(d)) if (!NODE_BINS.includes(e)) symlinkSync(join(d, e), join(m, e));
        dirs.push(m);
    }
    const path = [SHIMS, ...dirs].join(":");
    assert.equal(execFileSync("/bin/bash", ["-c", "command -v node || true"], { env: { PATH: path }, encoding: "utf8" }), "", "node is off this PATH");
    return path;
}

/** clean_strays_remote_script's output, from a fixture repo's deploy.sh
 *  (sourced: it defines its functions and runs nothing). */
function remoteScript(repo, remoteDir, dest, entries) {
    return execFileSync("/bin/bash", ["-c", 'source "$1" && shift && clean_strays_remote_script "$@"', "_",
        join(repo, "deploy.sh"), remoteDir, dest, ...entries], { encoding: "utf8", env: { PATH: process.env.PATH } });
}
/** Runs a remote script as the ssh shim does: bash -c with HOME = the node home. */
function runRemote(home, script) {
    return run("/bin/bash", ["-c", script], { env: { HOME: home } });
}

// ── Tests ──────────────────────────────────────────────────────────────────

// Two suites run side by side. The Chromium one (RETICHAT_BOOT_TESTS=1 only)
// runs at most two browsers at a time: its peak with five boot gates was 16
// Chromium processes beside the rest of the suite; two slots halve it (8
// processes). Its first three tests each watch the whole 10 s window, so two
// slots cost the file only about 4 s. The 100 ms and 150 ms budgets of
// link_request_resource.test.mjs that went red under load on 2026-09-30 run
// on virtual time since (test_virtual_time.mjs), so load no longer decides
// them, whichever peak this file has.
describe("deploy gates", { concurrency: 2 }, () => {

    describe("in Chromium, at most two browsers at a time", { concurrency: 2 }, () => {

        chromiumTest("a clean deploy: boots, lists both nodes before uploading, retichat first, never ships the debug pages, and verifies", async (t) => {
            const repo = fixtureRepo("deploy-e2e");
            const nodes = fakeNodes("deploy-e2e");
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), [], { env });
            if (/BOOT GATE SKIPPED/.test(r.out)) return t.skip("no Chromium installed for the boot gate");
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /rendered at .* no pageerror and no failed module import in the first 10 s/);

            const calls = sshCalls(logs);
            const firstWrite = calls.findIndex((c) => !LISTING.test(c.cmd));
            assert.deepEqual(calls.slice(0, firstWrite).map((c) => c.host), [HOSTS.retichat, HOSTS.selectiv],
                "both nodes listed, read-only, before any node is written to");
            assert.equal(calls.filter((c) => LISTING.test(c.cmd)).length, 2, "and only then");
            const uploads = calls.filter(isUpload).map((c) => c.host);
            assert.deepEqual(uploads, [HOSTS.retichat, HOSTS.selectiv], "retichat.com first, then selectiv");

            for (const n of ["retichat", "selectiv"]) {
                const dir = nodes[n];
                for (const f of ["index.html", "app.js", "style.css", "lib/a.js", "lib/shim.js", "lib/rns/link.js", ".htaccess"]) {
                    assert.equal(readFileSync(join(dir, f), "utf8"), git(repo, "show", `HEAD:${f}`), `${n}:${f}`);
                }
                assert.ok(!existsSync(join(dir, "lib/old.js")), `${n}: lib replaced wholesale`);
                assert.ok(!existsSync(join(dir, "debug.html")) && !existsSync(join(dir, "debug-standalone.html")), `${n}: no debug page shipped`);
                assert.match(readFileSync(join(dir, "config.json"), "utf8"), /exchangeUrl/, `${n}: config.json kept`);
            }
            assert.ok(existsSync(join(nodes.retichat, "reticulum/index.php")) && existsSync(join(nodes.retichat, "other-site/index.html")));
            const log = readFileSync(join(repo, ".deploy.log"), "utf8");
            assert.match(log, /nodes=all .*boot_checked=1 +verified=1/);
            assertOffline(logs);
            assert.ok(curlUrls(logs).some((u) => u.endsWith("/debug.html")), "verify-deploy.sh probed the debug page");
        });

        chromiumTest("boot gate: a page that renders, with its exchange refused locally and other hosts blocked, passes after the full 10 s", async (t) => {
            const t0 = Date.now();
            const r = await booted(t, goodSite(scratch("boot-good")));
            if (!r) return;
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /no pageerror and no failed module import in the first 10 s/);
            assert.match(r.out, /blocked, never sent: fetch https:\/\/blocked-host\.invalid\/beacon/);
            assert.ok(Date.now() - t0 >= 10_000, "the whole window was watched");
        });

        chromiumTest("boot gate: a page that loads cleanly and renders nothing (a blank screen) fails", async (t) => {
            const r = await booted(t, goodSite(scratch("boot-blank"), { "app.js": `export {};\n` }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /nothing rendered into #app within 10 s/);
        });

        chromiumTest("a page that dies at load refuses the deploy before any node is contacted", async (t) => {
            const repo = fixtureRepo("deploy-buffer", { "app.js": `Buffer.from("x");\n${RENDER}` });
            const nodes = fakeNodes("deploy-buffer");
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["HEAD", "selectiv"], { env });
            if (/BOOT GATE SKIPPED/.test(r.out)) return t.skip("no Chromium installed for the boot gate");
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /pageerror: Buffer is not defined/);
            assert.match(r.out, /does not boot in a browser — not deploying/);
            assert.equal(sshCalls(logs).length, 0);
        });

        chromiumTest("boot gate: \"Buffer is not defined\" at module load (0760960) fails", async (t) => {
            const r = await booted(t, goodSite(scratch("boot-buffer"), { "app.js": `import "./lib/a.js";\nBuffer.from("x");\n${RENDER}` }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL .*pageerror: Buffer is not defined/);
        });

        chromiumTest("boot gate: a relative import with no file fails", async (t) => {
            const r = await booted(t, goodSite(scratch("boot-missing"), { "app.js": `import "./lib/gone.js";\n${RENDER}` }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL .*module import failed: http:\/\/127\.0\.0\.1:\d+\/lib\/gone\.js/);
        });

        chromiumTest("boot gate: a bare specifier the importmap does not map fails", async (t) => {
            const r = await booted(t, goodSite(scratch("boot-bare"), { "app.js": `import "buffer";\n${RENDER}` }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL .*buffer/);
        });

        chromiumTest("boot gate: a module from a host other than esm.sh is blocked, never fetched, and fails", async (t) => {
            const site = goodSite(scratch("boot-cdn"), {
                "index.html": PAGE({ dep: "https://cdn-host.invalid/dep.js" }),
                "app.js": `import "dep";\n${RENDER}`,
            });
            const r = await booted(t, site);
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL .*module import failed: https:\/\/cdn-host\.invalid\/dep\.js .*blocked/);
        });

        // ── Content-Security-Policy: the page boots under the policy its .htaccess sets ──

        chromiumTest("boot gate: an inline script the page's policy does not allow is a violation, and fails", async (t) => {
            const page = PAGE({ shim: "./lib/shim.js" }).replace("</body>", `<script>document.title = "inline";</script></body>`);
            const r = await booted(t, goodSite(scratch("boot-csp-inline"), { "index.html": page }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL \d+\.\d s Content-Security-Policy violation: script-src-elem refused inline/);
        });

        chromiumTest("boot gate: the policy is read from the directory's .htaccess: a stale importmap hash fails", async (t) => {
            const site = goodSite(scratch("boot-csp-stale"));
            const fresh = readFileSync(join(site, ".htaccess"), "utf8");
            write(join(site, ".htaccess"), fresh.replace(/'sha256-[^']+'/, `'sha256-${Buffer.alloc(32, 1).toString("base64")}'`));
            const r = await booted(t, site);
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL \d+\.\d s Content-Security-Policy violation: script-src-elem refused inline/, "the importmap itself is refused");
        });

        chromiumTest("boot gate: a string evaluated under a policy without 'unsafe-eval' is a violation, even one the page catches", async (t) => {
            // What msgpackr does at load (unpack.mjs: new Function('') in a
            // try), which is why the page's policy carries 'unsafe-eval'.
            const r = await booted(t, goodSite(scratch("boot-csp-eval"), { "app.js": `try { new Function(""); } catch (e) {}\n${RENDER}` }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL \d+\.\d s Content-Security-Policy violation: script-src refused eval/);
        });

        chromiumTest("boot gate: a fetch the policy's connect-src does not allow is a violation, never a request", async (t) => {
            const r = await booted(t, goodSite(scratch("boot-csp-connect"), {
                "app.js": `${RENDER}fetch("https://not-in-the-policy.invalid/x").catch(() => {});\n`,
            }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL \d+\.\d s Content-Security-Policy violation: connect-src refused https:\/\/not-in-the-policy\.invalid\/x/);
            assert.doesNotMatch(r.out, /blocked, never sent: fetch https:\/\/not-in-the-policy/, "the browser refused it before the gate could see it");
        });

        chromiumTest("boot gate: an error thrown after load, inside the window, fails", async (t) => {
            const r = await booted(t, goodSite(scratch("boot-late"), { "app.js": `${RENDER}setTimeout(() => { throw new Error("late failure"); }, 1500);\n` }));
            if (!r) return;
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL \d+\.\d s pageerror: late failure/);
        });
    });

    describe("offline", { concurrency: 6 }, () => {

        // ── strays: classification ───────────────────────────────────────────

        test("strays on selectiv's own directory: everything but the payload and config.json, debug pages included", async () => {
            const repo = fixtureRepo("strays-dedicated");
            const nodes = fakeNodes("strays-dedicated", { selectiv: {
                "debug.html": "d", "debug-standalone.html": "d", "debug.html.bak-bug135": "d",
                "app.js.bak-bug135": "a", "app.js.bak2-20260808-120601": "a", "index.html.bak-sendas-20260816": "i",
                "style.css.bak-reftimeouts-20260817": "s", "packet.js": "p", "post_interface.js": "p",
                "assets/index-abc.js": "vite era", "notes.txt": "n", ".htaccess.bak": "h",
            } });
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["strays", "selectiv"], { env });
            assert.equal(r.code, 1, r.out);
            const listed = r.out.split("\n").filter((l) => /^ {6}\S/.test(l)).map((l) => l.trim()).sort();
            assert.deepEqual(listed, [
                "app.js.bak-bug135", "app.js.bak2-20260808-120601", "assets/", "debug-standalone.html", "debug.html",
                "debug.html.bak-bug135", "index.html.bak-sendas-20260816", "notes.txt", "packet.js", "post_interface.js",
                "style.css.bak-reftimeouts-20260817",
            ]);
            assert.match(r.out, /payload and node config: 7 entries/, "index.html app.js style.css icon .htaccess lib/ config.json");
            assert.deepEqual(snapshot(nodes.root), before, "listing changes nothing");
            const calls = sshCalls(logs);
            assert.equal(calls.length, 1);
            assert.equal(calls[0].host, HOSTS.selectiv);
            assert.match(calls[0].cmd, LISTING, "the only remote command is ls");
            assert.match(calls[0].cmd, /~\/public_html\/retichat /);
        });

        test("strays on retichat.com's shared docroot: only the web client's own names; the PHP node, cPanel and other sites are left alone", async () => {
            const repo = fixtureRepo("strays-shared");
            const nodes = fakeNodes("strays-shared", { retichat: {
                "debug.html": "d", "debug-standalone.html": "d", "app.js.bak-sendas-20260816": "a", "app.js~": "a",
                "index.html.orig": "i", "packet.js": "p", "lib.old/x.js": "l", "config.json.bak": "c",
                "robots.txt": "r", "assets/app.css": "someone's",
            } });
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["strays", "retichat"], { env });
            assert.equal(r.code, 1, r.out);
            const listed = r.out.split("\n").filter((l) => /^ {6}\S/.test(l)).map((l) => l.trim()).sort();
            assert.deepEqual(listed, [
                "app.js.bak-sendas-20260816", "app.js~", "config.json.bak", "debug-standalone.html", "debug.html",
                "index.html.orig", "lib.old/", "packet.js",
            ]);
            const foreign = r.out.match(/not the web client's, left alone: (.*)/)?.[1].split(" ").sort();
            assert.deepEqual(foreign, [".well-known/", "assets/", "cgi-bin/", "error_log", "index.php", "other-site/", "robots.txt"]);
            assert.doesNotMatch(listed.join(" "), /reticulum|config\.json$|\.htaccess/);
            assertOffline(logs);
        });

        test("on retichat.com's shared docroot a web client name with a non-backup suffix is someone else's: reported, never flagged or moved; on selectiv's own directory it is stray", async () => {
            // Names another site or the host could own beside ours: a base we
            // own followed by anything but a backup suffix, and look-alikes.
            const generic = {
                "lib-vendor/x.js": "v", "lib_legacy/y.js": "l", "app.js-old": "a", "index.html.en": "i",
                "config.json.dist": "c", "style.css-print": "s", "libs/z.js": "z", "app-old.js": "o",
            };
            const genericTop = ["app-old.js", "app.js-old", "config.json.dist", "index.html.en", "lib-vendor/", "lib_legacy/", "libs/", "style.css-print"];
            const backups = { "app.js.bak-bug135": "b", "app.js.save": "b", "style.css.old": "b", "lib.orig/x.js": "b", "index.html~": "b" };
            const repo = fixtureRepo("strays-generic");
            const nodes = fakeNodes("strays-generic", { retichat: { ...generic, ...backups }, selectiv: generic });
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes);
            const listedIn = (out) => out.split("\n").filter((l) => /^ {6}\S/.test(l)).map((l) => l.trim()).sort();

            const shared = await run(join(repo, "deploy.sh"), ["strays", "retichat"], { env });
            assert.equal(shared.code, 1, shared.out);
            assert.deepEqual(listedIn(shared.out), ["app.js.bak-bug135", "app.js.save", "index.html~", "lib.orig/", "style.css.old"], "backups of our names are stray");
            const foreign = shared.out.match(/not the web client's, left alone: (.*)/)?.[1].split(" ") ?? [];
            for (const g of genericTop) assert.ok(foreign.includes(g), `${g} is reported as not ours: ${foreign.join(" ")}`);

            const dedicated = await run(join(repo, "deploy.sh"), ["strays", "selectiv"], { env });
            assert.equal(dedicated.code, 1, dedicated.out);
            assert.deepEqual(listedIn(dedicated.out), genericTop, "selectiv's directory holds only the web client");

            const clean = await run(join(repo, "deploy.sh"), ["clean-strays", "retichat", "--yes"], { env });
            assert.equal(clean.code, 0, clean.out);
            const after = snapshot(nodes.root);
            const gone = Object.keys(before).filter((f) => !(f in after)).map((f) => relative(join(HOSTS.retichat, "public_html"), f)).sort();
            assert.deepEqual(gone, Object.keys(backups).sort(), "exactly the backups left retichat.com's docroot");
            for (const f of Object.keys(generic)) {
                const k = join(HOSTS.retichat, "public_html", f);
                assert.equal(after[k], before[k], `${f} untouched`);
            }
            assertOffline(logs);
        });

        test("strays with none present: exit 0, both nodes listed read-only, retichat first", async () => {
            const repo = fixtureRepo("strays-clean");
            const nodes = fakeNodes("strays-clean");
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["strays"], { env });
            assert.equal(r.code, 0, r.out);
            assert.equal((r.out.match(/no stray files/g) ?? []).length, 2);
            assert.deepEqual(sshCalls(logs).map((c) => c.host), [HOSTS.retichat, HOSTS.selectiv]);
            for (const c of sshCalls(logs)) assert.match(c.cmd, LISTING);
        });

        test("strays cannot tell when the node cannot be listed, and says so (exit 2)", async () => {
            const repo = fixtureRepo("strays-unreachable");
            const nodes = fakeNodes("strays-unreachable");
            const { env } = scriptEnv(nodes, { SELECTIV_SSH_HOST: "no-such-node" });
            const r = await run(join(repo, "deploy.sh"), ["strays", "selectiv"], { env });
            assert.equal(r.code, 2, r.out);
            assert.match(r.out, /could not list ~\/public_html\/retichat on selectiv/);
        });

        test("every name verify-deploy.sh probes is one deploy.sh classifies as stray, on the shared docroot too", async () => {
            const src = readFileSync(join(ROOT, "verify-deploy.sh"), "utf8");
            const block = src.slice(src.indexOf("STRAY_PROBES=("), src.indexOf(")", src.indexOf("STRAY_PROBES=(")));
            const probes = block.replace("STRAY_PROBES=(", "").split(/\s+/).filter(Boolean);
            assert.ok(probes.length >= 30, `probes: ${probes.length}`);
            for (const must of ["debug.html", "debug-standalone.html", "packet.js", "post_interface.js",
                "app.js.bak-bug135", "app.js.bak-sendas-20260816", "index.html.bak", "style.css.bak"]) {
                assert.ok(probes.includes(must), `verify-deploy.sh probes ${must}`);
            }
            const repo = fixtureRepo("probes-agree");
            const nodes = fakeNodes("probes-agree", { retichat: Object.fromEntries(probes.map((p) => [p, "x"])) });
            const { env } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["strays", "retichat"], { env });
            const listed = r.out.split("\n").filter((l) => /^ {6}\S/.test(l)).map((l) => l.trim()).sort();
            assert.deepEqual(listed, [...probes].sort());
        });

        // ── the deploy refuses strays ───────────────────────────────────────

        test("a deploy refuses while selectiv serves strays, before either node receives a byte", async () => {
            const repo = fixtureRepo("deploy-refused");
            const nodes = fakeNodes("deploy-refused", { selectiv: { "debug.html": "d", "app.js.bak-bug135": "a" } });
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER });
            const r = await run(join(repo, "deploy.sh"), [], { env });
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /refusing to deploy while selectiv serve\(s\) stray files/);
            assert.match(r.out, /\.\/deploy\.sh clean-strays selectiv --yes/);
            assert.match(r.out, /\n {6}debug\.html\n/);
            assert.match(r.out, /\n {6}app\.js\.bak-bug135\n/);
            const calls = sshCalls(logs);
            assert.deepEqual(calls.map((c) => c.host), [HOSTS.retichat, HOSTS.selectiv], "one listing per node, nothing else");
            for (const c of calls) assert.match(c.cmd, LISTING);
            assert.deepEqual(snapshot(nodes.root), before, "no node changed, retichat.com included");
            assert.ok(!existsSync(join(repo, ".deploy.log")), "nothing deployed, nothing logged");
        });

        test("a deploy refuses when a node cannot be listed: no proof of no strays, no upload", async () => {
            const repo = fixtureRepo("deploy-unlisted");
            const nodes = fakeNodes("deploy-unlisted");
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER, SELECTIV_SSH_HOST: "no-such-node" });
            const r = await run(join(repo, "deploy.sh"), [], { env });
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /cannot tell whether selectiv serves stray files/);
            assert.equal(sshCalls(logs).filter(isUpload).length, 0);
            assert.deepEqual(snapshot(nodes.root), before);
        });

        // ── clean-strays ────────────────────────────────────────────────────

        test("clean-strays without --yes lists what it would move and moves nothing", async () => {
            const repo = fixtureRepo("clean-dry");
            const nodes = fakeNodes("clean-dry", { selectiv: { "debug.html": "d" } });
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["clean-strays", "selectiv"], { env });
            assert.equal(r.code, 2, r.out);
            assert.match(r.out, /nothing moved — run again with --yes/);
            assert.match(r.out, /~\/retichat-web-strays\/selectiv-\d{8}T\d{6}Z\//);
            assert.deepEqual(snapshot(nodes.root), before);
            for (const c of sshCalls(logs)) assert.match(c.cmd, LISTING);
        });

        test("clean-strays --yes on selectiv moves exactly the strays out of the docroot, byte for byte, and RESTORE.sh puts them back", async () => {
            const repo = fixtureRepo("clean-dedicated");
            const strays = { "debug.html": "debug page\n", "debug-standalone.html": "standalone\n", "app.js.bak-bug135": "bak\n", "assets/x.js": "old build\n", "packet.js": "july\n" };
            const nodes = fakeNodes("clean-dedicated", { selectiv: strays });
            const before = snapshot(nodes.root);
            const { env } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["clean-strays", "selectiv", "--yes"], { env });
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /selectiv serves no stray files/);

            const home = nodes.home("selectiv");
            const archives = readdirSync(join(home, "retichat-web-strays"));
            assert.equal(archives.length, 1);
            assert.match(archives[0], /^selectiv-\d{8}T\d{6}Z$/);
            const dest = join(home, "retichat-web-strays", archives[0]);
            const after = snapshot(nodes.root);
            for (const [f, body] of Object.entries(strays)) {
                assert.ok(!existsSync(join(nodes.selectiv, f)), `${f} left the docroot`);
                assert.equal(readFileSync(join(dest, f), "utf8"), body, `${f} kept byte for byte`);
            }
            // Everything else under both homes is exactly as it was.
            const moved = new Set(Object.keys(strays).map((f) => relative(nodes.root, join(nodes.selectiv, f))));
            for (const [f, body] of Object.entries(before)) {
                if (moved.has(f)) continue;
                assert.equal(after[f], body, `${f} untouched`);
            }
            const added = Object.keys(after).filter((f) => !(f in before)).map((f) => relative(join(HOSTS.selectiv, "retichat-web-strays", archives[0]), f)).sort();
            assert.deepEqual(added, [...Object.keys(strays), "RESTORE.sh"].sort(), "the archive holds the strays and RESTORE.sh, nothing else was created");

            execFileSync("sh", [join(dest, "RESTORE.sh")]);
            const restored = snapshot(nodes.root);
            for (const f of Object.keys(before)) assert.equal(restored[f], before[f], `${f} restored`);
        });

        test("clean-strays --yes on retichat.com moves the web client's strays and nothing of the PHP node, cPanel or other sites", async () => {
            const repo = fixtureRepo("clean-shared");
            const nodes = fakeNodes("clean-shared", { retichat: { "debug.html": "d\n", "app.js.bak-sendas-20260816": "a\n", "index.html.bak-stamp-parity-20260816": "i\n" } });
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["clean-strays", "retichat", "--yes"], { env });
            assert.equal(r.code, 0, r.out);
            const after = snapshot(nodes.root);
            const gone = Object.keys(before).filter((f) => !(f in after)).sort();
            assert.deepEqual(gone, ["app.js.bak-sendas-20260816", "debug.html", "index.html.bak-stamp-parity-20260816"].map((f) => join(HOSTS.retichat, "public_html", f)).sort());
            for (const keep of ["reticulum/index.php", "reticulum/config.toml", "config.json", ".htaccess", "cgi-bin/.keep",
                ".well-known/acme-challenge/token", "other-site/index.html", "error_log", "index.php", "app.js", "lib/old.js"]) {
                const f = join(HOSTS.retichat, "public_html", keep);
                assert.equal(after[f], before[f], `${keep} untouched`);
            }
            assertOffline(logs);
        });

        test("the node side of clean-strays refuses a protected entry however it got into the list, before anything moves", async () => {
            const repo = fixtureRepo("remote-protected");
            const nodes = fakeNodes("remote-protected", { selectiv: { "debug.html": "d\n" }, retichat: { "debug.html": "d\n" } });
            const before = snapshot(nodes.root);
            const protectedEntries = ["config.json", ".htaccess", ".htpasswd", ".ht-anything", "reticulum", "reticulum/",
                "index.html", "app.js", "style.css", "retichat-icon.png", ".htaccess", "lib", "lib/", "lib/rns", "a/b", "..", ".", ""];
            for (const [node, dir] of [["selectiv", "public_html/retichat"], ["retichat", "public_html"]]) {
                for (const p of protectedEntries) {
                    // debug.html first: a refusal anywhere in the list moves nothing.
                    const r = await runRemote(nodes.home(node), remoteScript(repo, dir, `retichat-web-strays/${node}-T`, ["debug.html", p]));
                    assert.equal(r.code, 3, `${node} ${JSON.stringify(p)}: ${r.out}`);
                    assert.match(r.out, /refusing to move .*: it is protected/, `${node} ${JSON.stringify(p)}`);
                    assert.ok(!existsSync(join(nodes.home(node), "retichat-web-strays")), "no archive was even created");
                }
            }
            assert.deepEqual(snapshot(nodes.root), before, "nothing moved on either node");
            // The same script with only the stray moves it: the refusals above are the checks, not a broken script.
            const ok = await runRemote(nodes.home("selectiv"), remoteScript(repo, "public_html/retichat", "retichat-web-strays/selectiv-T", ["debug.html"]));
            assert.equal(ok.code, 0, ok.out);
            assert.equal(readFileSync(join(nodes.home("selectiv"), "retichat-web-strays/selectiv-T/debug.html"), "utf8"), "d\n");
            assert.ok(!existsSync(join(nodes.selectiv, "debug.html")));
        });

        test("the node side of clean-strays refuses a destination inside a served directory, or one that climbs out with ..", async () => {
            const repo = fixtureRepo("remote-dest");
            const nodes = fakeNodes("remote-dest", { selectiv: { "debug.html": "d\n" }, retichat: { "debug.html": "d\n" } });
            const before = snapshot(nodes.root);
            const cases = [
                ["selectiv", "public_html/retichat", ["public_html", "public_html/strays", "public_html/retichat", "public_html/retichat/old",
                    "retichat-web-strays/../public_html/x", "retichat-web-strays/.."]],
                ["retichat", "public_html", ["public_html", "public_html/strays", "public_html/reticulum/x", "retichat-web-strays/../public_html"]],
            ];
            for (const [node, dir, dests] of cases) {
                for (const dest of dests) {
                    const r = await runRemote(nodes.home(node), remoteScript(repo, dir, dest, ["debug.html"]));
                    assert.equal(r.code, 3, `${node} → ${dest}: ${r.out}`);
                    assert.match(r.out, /refusing: the destination is inside a served directory/, `${node} → ${dest}`);
                }
            }
            assert.deepEqual(snapshot(nodes.root), before, "nothing moved, no directory created");
        });

        test("clean-strays refuses a name it will not hand to a remote shell, and moves nothing", async () => {
            const repo = fixtureRepo("clean-unsafe");
            const nodes = fakeNodes("clean-unsafe", { selectiv: { "debug.html": "d", "app copy's.js": "x" } });
            const before = snapshot(nodes.root);
            const { env } = scriptEnv(nodes);
            const r = await run(join(repo, "deploy.sh"), ["clean-strays", "selectiv", "--yes"], { env });
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /nothing moved — move them by hand/);
            assert.deepEqual(snapshot(nodes.root), before);
        });

        test("clean-strays needs one named node and --yes, nothing else", async () => {
            const repo = fixtureRepo("clean-usage");
            const nodes = fakeNodes("clean-usage", { selectiv: { "debug.html": "d" } });
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes);
            for (const args of [["clean-strays"], ["clean-strays", "all", "--yes"], ["clean-strays", "selectiv", "--force"], ["clean-strays", "selectiv", "--yes", "extra"]]) {
                const r = await run(join(repo, "deploy.sh"), args, { env });
                assert.equal(r.code, 1, `${args.join(" ")}: ${r.out}`);
            }
            assert.equal(sshCalls(logs).length, 0);
            assert.deepEqual(snapshot(nodes.root), before);
        });

        // ── the suite step: the boot gate's Chromium tests run on every deploy ──

        test("the deploy runs the suite with RETICHAT_BOOT_TESTS=1, so the Chromium tests run on every deploy", async () => {
            // The fixture's suite passes only when the flag reaches it.
            const suite = `node -e "if (process.env.RETICHAT_BOOT_TESTS !== '1') { console.log('RETICHAT_BOOT_TESTS=' + process.env.RETICHAT_BOOT_TESTS); process.exit(1); } console.log('ℹ pass 1')"`;
            const repo = fixtureRepo("deploy-boot-flag", {
                "package.json": JSON.stringify({ name: "fixture", version: "0.0.0", private: true, scripts: { test: suite } }),
            });
            const nodes = fakeNodes("deploy-boot-flag");
            // Unset where the deploy is run from: deploy.sh sets it itself.
            const { env } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER, RETICHAT_BOOT_TESTS: "" });
            const r = await run(join(repo, "deploy.sh"), ["HEAD", "selectiv"], { env });
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /suite green — ℹ pass 1/);
        });

        test("npm test leaves the Chromium tests out and says so; npm run test:full runs them", async () => {
            const scripts = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).scripts;
            assert.equal(scripts["test:full"], `RETICHAT_BOOT_TESTS=1 ${scripts.test}`, "test:full is npm test with the flag");
            assert.doesNotMatch(scripts.test, /RETICHAT_BOOT_TESTS/);
            // This file without the flag, one Chromium test selected: skipped, with the reason, and a warning.
            // NODE_TEST_CONTEXT is how this runner tells its own children to report to it; the child here reports to us.
            const { NODE_TEST_CONTEXT, ...outside } = process.env;
            const r = await new Promise((ok) => {
                const p = spawn(process.execPath, ["--test", "--test-reporter=spec",
                    "--test-name-pattern=boot gate: a relative import with no file fails", "deploy_gates.test.mjs"], {
                    cwd: ROOT, env: { ...outside, RETICHAT_BOOT_TESTS: "", DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER },
                });
                let out = "";
                p.stdout.on("data", (d) => { out += d; });
                p.stderr.on("data", (d) => { out += d; });
                p.on("close", (code) => ok({ code, out }));
            });
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /﹣ boot gate: a relative import with no file fails .*# RETICHAT_BOOT_TESTS is not 1: run `npm run test:full` \(deploy\.sh always does\)/);
            assert.match(r.out, /ℹ skipped 1\n/);
            assert.match(r.out, /⚠ deploy_gates\.test\.mjs: the boot-gate tests that start Chromium are SKIPPED/);
            assert.doesNotMatch(r.out, /✔ boot gate: a relative import/, "it did not run");
        });

        // ── the whole deploy, offline ───────────────────────────────────────

        test("with no browser installed the boot gate is skipped loudly and the deploy log says so", async () => {
            const repo = fixtureRepo("deploy-nobrowser");
            const nodes = fakeNodes("deploy-nobrowser");
            const { env } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER });
            const r = await run(join(repo, "deploy.sh"), ["HEAD", "selectiv"], { env });
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /BOOT GATE SKIPPED — no headless browser is installed/);
            assert.match(readFileSync(join(repo, ".deploy.log"), "utf8"), /nodes=selectiv .*boot_checked=0 +verified=1/);
        });

        test("an unknown node name is refused before the suite runs or any node is contacted", async () => {
            const repo = fixtureRepo("deploy-unknown-node");
            const nodes = fakeNodes("deploy-unknown-node");
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER });
            for (const name of ["nosuchnode", "all", "retichat.com", "Selectiv"]) {
                const r = await run(join(repo, "deploy.sh"), ["HEAD", name], { env });
                assert.equal(r.code, 1, `${name}: ${r.out}`);
                assert.ok(r.out.includes(`no node matched '${name}' (valid: retichat selectiv`), `${name}: ${r.out}`);
                assert.doesNotMatch(r.out, /Checking working tree|Running test suite|Booting/, `${name}: refused first`);
            }
            assert.equal(sshCalls(logs).length, 0);
            assert.equal(curlUrls(logs).length, 0);
            assert.deepEqual(snapshot(nodes.root), before);
            assert.ok(!existsSync(join(repo, ".deploy.log")));
        });

        test("a subcommand that fails says why and never prints \"deploy aborted\", which belongs to the deploy flow", async () => {
            const repo = fixtureRepo("err-trap");
            const nodes = fakeNodes("err-trap", { selectiv: { "debug.html": "d" } });
            const { env } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER });
            const cases = [
                [["strays", "selectiv"], {}, 1],                                   // strays present
                [["strays"], {}, 1],
                [["strays", "selectiv"], { SELECTIV_SSH_HOST: "no-such-node" }, 2], // cannot list
                [["clean-strays", "selectiv"], {}, 2],                             // dry run
                [["boot-check", scratch("err-trap-empty")], {}, 1],                 // no index.html
                [["boot-check", goodSite(scratch("err-trap-site"))], {}, 3],        // no browser: skipped
            ];
            for (const [args, extra, code] of cases) {
                const r = await run(join(repo, "deploy.sh"), args, { env: { ...env, ...extra } });
                assert.equal(r.code, code, `${args.join(" ")}: ${r.out}`);
                assert.doesNotMatch(r.out, /deploy aborted/, `${args.join(" ")}: ${r.out}`);
            }
        });

        test("with no node the deploy is refused for that reason, never as a page that does not boot", async () => {
            const repo = fixtureRepo("deploy-no-node");
            const nodes = fakeNodes("deploy-no-node");
            const before = snapshot(nodes.root);
            const { env, logs } = scriptEnv(nodes, { PATH: pathWithoutNode(), DEPLOY_SKIP_TESTS: "1" });
            const r = await run(join(repo, "deploy.sh"), ["HEAD", "selectiv"], { env });
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /node not found — the boot gate cannot run, so nothing shows [0-9a-f]+ boots — not deploying/);
            assert.doesNotMatch(r.out, /does not boot in a browser|command not found/);
            assert.equal(sshCalls(logs).length, 0);
            assert.deepEqual(snapshot(nodes.root), before);
        });

        test("a Playwright that is installed but will not load refuses the deploy as a gate that could not run, not a skip", async () => {
            const repo = fixtureRepo("deploy-broken-pw");
            const nodes = fakeNodes("deploy-broken-pw");
            const before = snapshot(nodes.root);
            const broken = fakePlaywright("broken-pw-deploy", `throw new Error("playwright 1.x requires Node 18: broken install");\n`);
            const { env, logs } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: broken });
            const r = await run(join(repo, "deploy.sh"), ["HEAD", "selectiv"], { env });
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /FAIL Playwright is installed in .* but will not load: playwright 1\.x requires Node 18: broken install/);
            assert.match(r.out, /the boot gate could not run \(see above\), so nothing shows [0-9a-f]+ boots — not deploying/);
            assert.doesNotMatch(r.out, /SKIPPED|does not boot in a browser/);
            assert.equal(sshCalls(logs).length, 0);
            assert.deepEqual(snapshot(nodes.root), before);
            assert.ok(!existsSync(join(repo, ".deploy.log")));
        });

        test("usage names the default order and why", async () => {
            const repo = fixtureRepo("usage");
            const r = await run(join(repo, "deploy.sh"), ["help"], { env: scriptEnv(null).env });
            assert.equal(r.code, 0);
            assert.match(r.out, /retichat\.com is deployed first and selectiv straight after/);
            assert.match(r.out, /selectiv depends on retichat\.com/);
            assert.match(r.out, /clean-strays <node> --yes/);
        });

        // ── verify-deploy.sh ────────────────────────────────────────────────

        async function verify(nodeName, { retichat = {}, selectiv = {}, env: extra = {} } = {}) {
            const repo = fixtureRepo(`verify-${nodeName}`);
            const nodes = fakeNodes(`verify-${nodeName}`, { retichat, selectiv });
            for (const dir of [nodes.retichat, nodes.selectiv]) {
                // The ref's files, as a finished deploy leaves them.
                rmSync(join(dir, "lib"), { recursive: true });
                for (const f of ["index.html", "app.js", "style.css", "retichat-icon.png", ".htaccess", "lib/a.js", "lib/shim.js", "lib/rns/link.js"]) {
                    write(join(dir, f), git(repo, "show", `HEAD:${f}`));
                }
            }
            const { env, logs } = scriptEnv(nodes, extra);
            const r = await run(join(repo, "verify-deploy.sh"), ["HEAD", nodeName], { env });
            assertOffline(logs);
            return r;
        }

        test("verify-deploy.sh passes a node serving the ref and no stray name", async () => {
            const r = await verify("selectiv");
            assert.equal(r.code, 0, r.out);
            assert.match(r.out, /none served \(this is a list of names, not a listing/);
        });

        test("verify-deploy.sh fails a node that serves debug.html or a backup, and names them", async () => {
            const r = await verify("retichat", { retichat: { "debug.html": "d", "app.js.bak-bug135": "a", "post_interface.js": "p" } });
            assert.equal(r.code, 1, r.out);
            for (const f of ["debug.html", "app.js.bak-bug135", "post_interface.js"]) {
                assert.match(r.out, new RegExp(`\\n  ${f.replace(/\./g, "\\.")} +served \\(HTTP 200\\)`), f);
            }
            assert.match(r.out, /\.\/deploy\.sh clean-strays retichat --yes/);
            assert.match(r.out, /7 match, 0 drifted/, "the ref's files themselves still match");
        });

        test("verify-deploy.sh fails as inconclusive when the node answers 200 for a name that cannot exist", async () => {
            const r = await verify("selectiv", { env: { FAKE_CURL_ALL_200: "1" } });
            assert.equal(r.code, 1, r.out);
            assert.match(r.out, /verify-deploy-canary-\d+\.html +HTTP 200 — inconclusive/);
            assert.doesNotMatch(r.out, /served \(HTTP/, "no probe is reported as a finding it cannot prove");
        });

        test("verify-deploy.sh's header claims only what it checks", () => {
            const head = readFileSync(join(ROOT, "verify-deploy.sh"), "utf8").split("\nset -uo pipefail")[0];
            assert.doesNotMatch(head, /in both directions/, "it cannot list the node, so it cannot see every file the ref lacks");
            assert.match(head, /STRAY_PROBES/);
            assert.match(head, /deploy\.sh strays <node>/);
        });

        // ── the boot gate ───────────────────────────────────────────────────

        test("boot gate: no Playwright, or Playwright without Chromium, skips loudly with exit 3", async () => {
            const site = goodSite(scratch("boot-skip"));
            const none = await bootCheck(site, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER });
            assert.equal(none.code, 3, none.out);
            assert.match(none.out, /no Playwright in .*\n.*BOOT GATE SKIPPED/);
            if (existsSync(join(PLAYWRIGHT_DIR, "node_modules", "playwright"))) {
                const noChromium = await bootCheck(site, { PLAYWRIGHT_BROWSERS_PATH: scratch("no-browsers") });
                assert.equal(noChromium.code, 3, noChromium.out);
                assert.match(noChromium.out, /has no Chromium installed/);
            }
        });

        test("boot gate: only a missing Playwright or a missing Chromium skips; a broken one is a gate that could not run (exit 2)", async () => {
            const site = goodSite(scratch("boot-fake-pw"));
            const cases = [
                // installed, will not load
                [`throw new Error("playwright 1.x requires Node 18: broken install");\n`, 2,
                    /FAIL Playwright is installed in .* but will not load: .*broken install/],
                // installed, a dependency missing
                [`require("playwright-core-missing-fixture");\n`, 2, /FAIL Playwright is installed in .* but will not load: Cannot find module 'playwright-core-missing-fixture'/],
                // Chromium present but will not start
                [`exports.chromium = { launch: async () => { throw new Error("spawn EACCES"); } };\n`, 2, /FAIL Chromium would not start: spawn EACCES/],
                // the gate breaks after launch, before it watches the page
                [`exports.chromium = { launch: async () => ({ newContext: async () => { throw new Error("context refused"); }, close: async () => {} }) };\n`, 2,
                    /FAIL the gate itself failed: context refused/],
                // Playwright without its Chromium: the one skip besides no Playwright at all
                [`exports.chromium = { launch: async () => { throw new Error("browserType.launch: Executable doesn't exist at /nowhere/chrome"); } };\n`, 3,
                    /has no Chromium installed\n.*BOOT GATE SKIPPED/],
            ];
            for (const [i, [indexJs, code, pattern]] of cases.entries()) {
                const r = await bootCheck(site, { DEPLOY_PLAYWRIGHT_DIR: fakePlaywright(`fake-pw-${i}`, indexJs) });
                assert.equal(r.code, code, `case ${i}: ${r.out}`);
                assert.match(r.out, pattern, `case ${i}`);
                if (code === 2) {
                    assert.match(r.out, /the boot gate could not run \(see above\): this says nothing about the page/, `case ${i}`);
                    assert.doesNotMatch(r.out, /SKIPPED|the page does not boot/, `case ${i}`);
                }
            }
        });

        test("boot gate: a directory without index.html fails", async () => {
            const r = await bootCheck(scratch("boot-empty"));
            assert.equal(r.code, 1, r.out);
        });

        test("boot gate: an .htaccess that sets no Content-Security-Policy fails, browser or not: the page would be served without one", async () => {
            for (const [name, htaccess] of [["boot-no-csp", "# fixture: the cache policy only\n"], ["boot-no-htaccess", null]]) {
                const site = goodSite(scratch(name), { ".htaccess": htaccess });
                for (const env of [{ DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER }, {}]) {
                    const r = await bootCheck(site, env);
                    assert.equal(r.code, 1, `${name}: ${r.out}`);
                    assert.match(r.out, /FAIL no Content-Security-Policy in .*\.htaccess: the page would be served without one/);
                    assert.match(r.out, /the page does not boot/);
                }
            }
        });
    });
});
