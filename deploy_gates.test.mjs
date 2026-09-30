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

import test, { describe, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import {
    mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, copyFileSync,
    chmodSync, readdirSync, statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PLAYWRIGHT_DIR = resolve(ROOT, "../test-harnesses/distro-pipeline");
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
        ".htaccess": "# fixture\n",
        ...extra,
    };
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

// ── Tests ──────────────────────────────────────────────────────────────────

describe("deploy gates", { concurrency: 6 }, () => {

    // The three that watch the whole 10 s window go first, so they overlap.
    test("a clean deploy: boots, lists both nodes before uploading, retichat first, never ships the debug pages, and verifies", async (t) => {
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

    test("boot gate: a page that renders, with its exchange refused locally and other hosts blocked, passes after the full 10 s", async (t) => {
        const t0 = Date.now();
        const r = await booted(t, goodSite(scratch("boot-good")));
        if (!r) return;
        assert.equal(r.code, 0, r.out);
        assert.match(r.out, /no pageerror and no failed module import in the first 10 s/);
        assert.match(r.out, /blocked, never sent: fetch https:\/\/blocked-host\.invalid\/beacon/);
        assert.ok(Date.now() - t0 >= 10_000, "the whole window was watched");
    });

    test("boot gate: a page that loads cleanly and renders nothing (a blank screen) fails", async (t) => {
        const r = await booted(t, goodSite(scratch("boot-blank"), { "app.js": `export {};\n` }));
        if (!r) return;
        assert.equal(r.code, 1, r.out);
        assert.match(r.out, /nothing rendered into #app within 10 s/);
    });


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

    // ── the whole deploy, offline ───────────────────────────────────────

    test("a page that dies at load refuses the deploy before any node is contacted", async (t) => {
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

    test("with no browser installed the boot gate is skipped loudly and the deploy log says so", async () => {
        const repo = fixtureRepo("deploy-nobrowser");
        const nodes = fakeNodes("deploy-nobrowser");
        const { env } = scriptEnv(nodes, { DEPLOY_PLAYWRIGHT_DIR: NO_BROWSER });
        const r = await run(join(repo, "deploy.sh"), ["HEAD", "selectiv"], { env });
        assert.equal(r.code, 0, r.out);
        assert.match(r.out, /BOOT GATE SKIPPED — no headless browser is installed/);
        assert.match(readFileSync(join(repo, ".deploy.log"), "utf8"), /nodes=selectiv .*boot_checked=0 +verified=1/);
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

    test("boot gate: \"Buffer is not defined\" at module load (0760960) fails", async (t) => {
        const r = await booted(t, goodSite(scratch("boot-buffer"), { "app.js": `import "./lib/a.js";\nBuffer.from("x");\n${RENDER}` }));
        if (!r) return;
        assert.equal(r.code, 1, r.out);
        assert.match(r.out, /FAIL .*pageerror: Buffer is not defined/);
    });

    test("boot gate: a relative import with no file fails", async (t) => {
        const r = await booted(t, goodSite(scratch("boot-missing"), { "app.js": `import "./lib/gone.js";\n${RENDER}` }));
        if (!r) return;
        assert.equal(r.code, 1, r.out);
        assert.match(r.out, /FAIL .*module import failed: http:\/\/127\.0\.0\.1:\d+\/lib\/gone\.js/);
    });

    test("boot gate: a bare specifier the importmap does not map fails", async (t) => {
        const r = await booted(t, goodSite(scratch("boot-bare"), { "app.js": `import "buffer";\n${RENDER}` }));
        if (!r) return;
        assert.equal(r.code, 1, r.out);
        assert.match(r.out, /FAIL .*buffer/);
    });

    test("boot gate: a module from a host other than esm.sh is blocked, never fetched, and fails", async (t) => {
        const site = goodSite(scratch("boot-cdn"), {
            "index.html": PAGE({ dep: "https://cdn-host.invalid/dep.js" }),
            "app.js": `import "dep";\n${RENDER}`,
        });
        const r = await booted(t, site);
        if (!r) return;
        assert.equal(r.code, 1, r.out);
        assert.match(r.out, /FAIL .*module import failed: https:\/\/cdn-host\.invalid\/dep\.js .*blocked/);
    });

    test("boot gate: an error thrown after load, inside the window, fails", async (t) => {
        const r = await booted(t, goodSite(scratch("boot-late"), { "app.js": `${RENDER}setTimeout(() => { throw new Error("late failure"); }, 1500);\n` }));
        if (!r) return;
        assert.equal(r.code, 1, r.out);
        assert.match(r.out, /FAIL \d+\.\d s pageerror: late failure/);
    });

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

    test("boot gate: a directory without index.html fails", async () => {
        const r = await bootCheck(scratch("boot-empty"));
        assert.equal(r.code, 1, r.out);
    });
});
