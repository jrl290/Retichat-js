#!/usr/bin/env bash
#
# deploy.sh — the only supported way to move the web client onto a live node.
#
#   ./deploy.sh                  # deploy HEAD to both nodes: retichat, then selectiv
#   ./deploy.sh HEAD selectiv    # ...to one node
#   ./deploy.sh be8964d          # ...a specific ref (rollback)
#   ./deploy.sh strays [node]    # list files a node serves outside the payload (SSH ls, read-only)
#   ./deploy.sh clean-strays <node> --yes
#                                # move exactly those files out of the docroot (never rm)
#   ./deploy.sh boot-check <dir> # the headless boot gate alone, on any directory
#                                # (e.g. `test-harnesses/staging/staging.sh export Retichat-js <ref>`)
#
# NODE ORDER
# ==========
# With no node named, retichat.com is deployed first and selectiv straight after
# it (the order of NODES below). selectiv depends on retichat.com: its PHP node
# reaches the network only through retichat.com (selectiv's own gateway bridge
# row is offline; the 'retichat.com' PHP peer is its one route), so every
# selectiv user's traffic crosses retichat.com's relay, and selectiv's browsers
# mostly talk to browsers on retichat.com. selectiv is therefore no independent
# canary: a change is only live end to end there once retichat.com carries it.
# Every stray check and every local gate runs for both nodes before either
# receives a byte, so a refused deploy never leaves the two nodes on different
# builds. To deploy one node alone, name it.
#
# TWO NODES, ONE SOURCE
# =====================
# The client is served from retichat.com (docroot) AND
# selectivesubconscious.com/retichat/ (subdirectory). The selectiv copy was
# deployed by hand and covered by no gate; on 2026-08-17 it was discovered
# serving a morning-old build while retichat.com had received four fixes —
# the same shadow-copy failure mode as Reticulum-post's js/ fork, but live on
# a public URL. Every node this script does not know about is a regression
# that has already happened and merely hasn't been noticed.
#
# config.json is per-node (it names that node's exchangeUrl) and is never
# deployed; .htaccess is shared, which is why its redirect uses REQUEST_URI
# (see the comment there — the $1 form breaks in the subdirectory layout).
#
# WHAT THIS EXISTS TO PREVENT
# ===========================
# Reticulum-post got these gates on 2026-08-17 after a working tree that was
# HEAD-with-the-newest-fixes-removed nearly shipped by scp. The web client — the
# component whose console log is what you actually read when something breaks —
# never got them. It was still deployed by hand, from the filesystem, with no
# check that what landed matched any commit.
#
# The checks, in order:
#
#   1. refuse a dirty working tree      — you cannot ship what isn't committed
#   2. run the test suite               — and refuse on any failure
#   3. deploy from `git archive <ref>`  — never from the working directory
#   4. boot the staged export in headless Chromium — refuse on a pageerror or a
#      failed module import in the first 10 s (0760960 passed 1–3 and died at
#      load with "Buffer is not defined"; only a browser sees that class)
#   5. refuse while a node serves stray files — anything in the web client's
#      directory that is not the payload or the node's config.json
#   6. verify the served bytes          — proof, not hope
#
# Step 6 is cheaper here than for the PHP node: every file is fetchable over
# plain HTTPS, so verify-deploy.sh needs no credentials and can be run by anyone,
# at any time, without touching the node. Run it whenever you suspect drift.
#
# STRAY FILES
# ===========
# On 2026-09-30 both nodes served files no gate knew about: debug.html and
# debug-standalone.html (same origin as the app, so a crafted debug.html link
# could wipe or replace a user's identity and exchange URL), nine
# app.js.bak-*, five each of index.html.bak-* and style.css.bak-*, and a
# July-era packet.js and post_interface.js at the top level. The debug pages
# are for the harness, which serves them from the working copy
# (HARNESS_PAGE=local); no production node serves them any more.
#
# `strays` lists the node's directory over the SSH the deploy already uses
# (`ls`, nothing else) and sorts every entry per node layout:
#   dedicated (selectiv: public_html/retichat holds only the web client) —
#     everything but the payload and config.json is stray.
#   shared (retichat.com: public_html is also the host's docroot, with the PHP
#     node in reticulum/, cPanel's cgi-bin/ and .well-known/, and maybe other
#     sites) — only names the web client owns count (OWNED_NAMES, and
#     OWNED_BASES with a backup suffix, below); everything else is reported
#     as not ours and is never flagged or touched.
# config.json, every .ht* file and reticulum/ are never stray on either.
# `clean-strays <node> --yes` moves exactly the listed entries into
# ~/retichat-web-strays/<node>-<UTC time>/, outside every served directory,
# with a RESTORE.sh beside them. Nothing is deleted.
#
# Credentials come from the environment. Keep them in a gitignored deploy.env:
#
#   export RETICHAT_SSH_HOST=retichat@retichat.com
#   export RETICHAT_SSH_PASS=...        # leave empty to use key auth
#
# Bypass for a genuine emergency: DEPLOY_ALLOW_DIRTY=1 (tree check) and
# DEPLOY_SKIP_TESTS=1 (suite). Both print a loud warning and are recorded in
# .deploy.log. If you find yourself using them routinely, fix the cause.
# There is no bypass for strays: clean them, it is reversible.
#
# The boot gate uses the Playwright + Chromium that the staging harness uses
# (../test-harnesses/distro-pipeline; DEPLOY_PLAYWRIGHT_DIR names another
# project dir). With no browser installed (no Playwright there, or Playwright
# without its Chromium) it is skipped with a loud warning and boot_checked=0 in
# .deploy.log. A gate that cannot run — no node, a Playwright that is installed
# but will not load, a Chromium that will not start — refuses the deploy and
# says so; it never reports that as the page failing to boot.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${REPO_DIR}/.deploy.log"

# name : host env var : pass env var : remote dir : served base URL : layout
# The order is the default deploy order (see NODE ORDER above).
NODES=(
  "retichat|RETICHAT_SSH_HOST|RETICHAT_SSH_PASS|public_html|https://retichat.com|shared"
  "selectiv|SELECTIV_SSH_HOST|SELECTIV_SSH_PASS|public_html/retichat|https://selectivesubconscious.com/retichat|dedicated"
)

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'
SSH_OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR)

# The web client's deployable surface. Tests, README, the local config
# template and the harness pages (debug.html, debug-standalone.html) are not
# served. config.json is per-node runtime config the node owns (it names that
# node's exchangeUrl) — deploying ours would repoint the live app at 127.0.0.1.
PAYLOAD=(index.html app.js style.css retichat-icon.png .htaccess lib)
EXCLUDE=(config.json config.local.json)

# Names the web client owns, so they are stray on a shared docroot too.
# OWNED_NAMES match exactly. OWNED_BASES match only with a backup suffix
# (BACKUP_SUFFIXES: app.js.bak-bug135, app.js.bak2-20260808-120601,
# index.html.orig, lib.old, app.js~). A base followed by anything else —
# lib-vendor/, lib_legacy/, index.html.en, config.json.dist, style.css-print —
# could be the host's or another site's on a shared docroot, so it is reported
# there as not ours and never flagged or moved.
OWNED_NAMES=(debug.html debug-standalone.html packet.js post_interface.js
             config.local.json config.template.json selectiv-snapshot
             deploy.sh verify-deploy.sh deploy.env deploy.env.example .deploy.log)
OWNED_BASES=(index.html app.js style.css retichat-icon.png config.json lib
             debug.html debug-standalone.html packet.js post_interface.js)
BACKUP_SUFFIXES=('.bak*' '.orig*' '.old*' '.save*' '~')

# Moved strays go here, relative to the node account's home: outside every
# served directory (the docroots are under ~/public_html).
STRAY_ARCHIVE="retichat-web-strays"

PLAYWRIGHT_DIR="${DEPLOY_PLAYWRIGHT_DIR:-$REPO_DIR/../test-harnesses/distro-pipeline}"

die() { echo "${RED}✗ $*${NC}" >&2; exit 1; }
step() { echo; echo "${CYAN}▸ $*${NC}"; }
# The header down to NODE ORDER's end: the commands, and why retichat goes first.
usage() { sed -n '3,/^# TWO NODES, ONE SOURCE/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

[[ -f "$REPO_DIR/deploy.env" ]] && source "$REPO_DIR/deploy.env"

# ── Nodes ─────────────────────────────────────────────────────────────────

# node_fields <name> — sets NODE_NAME HOST_VAR PASS_VAR REMOTE_DIR BASE_URL LAYOUT.
node_fields() {
  local entry
  for entry in "${NODES[@]}"; do
    IFS='|' read -r NODE_NAME HOST_VAR PASS_VAR REMOTE_DIR BASE_URL LAYOUT <<< "$entry"
    [[ "$NODE_NAME" == "$1" ]] && return 0
  done
  return 1
}

node_names() { local e; for e in "${NODES[@]}"; do echo "${e%%|*}"; done; }

# set_ssh <pass> — SSH=(...) for a node: key auth with BatchMode, or sshpass
# when the node's password is set.
set_ssh() {
  if [[ -n "$1" ]]; then
    if ! command -v sshpass >/dev/null 2>&1; then
      echo "${RED}sshpass required when the node's password is set${NC}" >&2
      return 1
    fi
    SSH=(env "SSHPASS=$1" sshpass -e ssh "${SSH_OPTS[@]}")
  else
    SSH=(ssh "${SSH_OPTS[@]}" -o BatchMode=yes)
  fi
}

# ── Stray files ───────────────────────────────────────────────────────────

owned_name() { # name — is this a name the web client owns?
  local n="$1" b s
  for b in "${OWNED_NAMES[@]}"; do [[ "$n" == "$b" ]] && return 0; done
  for b in "${OWNED_BASES[@]}"; do
    # $s unquoted: the suffix is a glob (.bak* matches .bak2-20260808-120601).
    for s in "${BACKUP_SUFFIXES[@]}"; do [[ "$n" == "$b"$s ]] && return 0; done
  done
  [[ "$n" == *.test.mjs ]] && return 0
  return 1
}

# entry_class <layout> <entry> — payload | node | protected | stray | foreign.
# An entry is one line of `ls -1Ap` (directories end in /).
entry_class() {
  local layout="$1" name="${2%/}" p
  case "$name" in ""|.|..) echo protected; return ;; esac
  for p in "${PAYLOAD[@]}"; do
    [[ "$name" == "$p" ]] && { echo payload; return; }
  done
  case "$name" in
    config.json) echo node; return ;;
    # Apache serves no .ht* file, and .htaccess is deployed; reticulum/ is the
    # PHP node. Neither is the stray check's business on any layout.
    .ht*|reticulum) echo protected; return ;;
  esac
  if owned_name "$name"; then echo stray; return; fi
  if [[ "$layout" == dedicated ]]; then echo stray; else echo foreign; fi
}

# remote_listing <host> <remote_dir> — the directory's top-level entries, one
# per line. Read-only: the one command is ls. An absent directory lists nothing.
remote_listing() {
  "${SSH[@]}" "$1" "if [ -d ~/$2 ]; then cd ~/$2 && ls -1Ap; fi"
}

# classify_listing <layout> <listing> — fills KEPT (payload and config.json),
# PROTECTED, STRAYS and FOREIGN.
classify_listing() {
  STRAYS=(); FOREIGN=(); KEPT=(); PROTECTED=()
  local entry
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "$(entry_class "$1" "$entry")" in
      stray) STRAYS+=("$entry") ;;
      foreign) FOREIGN+=("$entry") ;;
      protected) PROTECTED+=("$entry") ;;
      *) KEPT+=("$entry") ;;
    esac
  done <<< "$2"
}

print_classes() { # name remote_dir layout
  if [[ "$3" == dedicated ]]; then
    echo "  ${DIM}~/$2 holds only the web client: everything but the payload and config.json is stray${NC}"
  else
    echo "  ${DIM}~/$2 is shared with the host and the PHP node: only the web client's own names count${NC}"
  fi
  echo "  ${GREEN}✓${NC} payload and node config: ${#KEPT[@]} entries"
  if [[ ${#PROTECTED[@]} -gt 0 ]]; then
    echo "  ${DIM}never touched (.ht*, the PHP node): ${PROTECTED[*]}${NC}"
  fi
  if [[ ${#FOREIGN[@]} -gt 0 ]]; then
    echo "  ${DIM}not the web client's, left alone: ${FOREIGN[*]}${NC}"
  fi
  if [[ ${#STRAYS[@]} -gt 0 ]]; then
    echo "  ${RED}✗ ${#STRAYS[@]} stray (served from the app's origin, in no payload):${NC}"
    printf '      %s\n' "${STRAYS[@]}"
  else
    echo "  ${GREEN}✓${NC} no stray files"
  fi
}

# check_node_strays <name> — lists and classifies one node. Returns 0 clean,
# 1 strays present, 2 the node could not be listed.
check_node_strays() {
  node_fields "$1" || { echo "${RED}no node named '$1'${NC}" >&2; return 2; }
  local host="${!HOST_VAR:-}" listing
  if [[ -z "$host" ]]; then
    echo "${RED}${HOST_VAR} not set (see deploy.env.example)${NC}" >&2
    return 2
  fi
  set_ssh "${!PASS_VAR:-}" || return 2
  if ! listing="$(remote_listing "$host" "$REMOTE_DIR")"; then
    echo "${RED}could not list ~/${REMOTE_DIR} on ${NODE_NAME} over SSH${NC}" >&2
    return 2
  fi
  classify_listing "$LAYOUT" "$listing"
  print_classes "$NODE_NAME" "$REMOTE_DIR" "$LAYOUT"
  [[ ${#STRAYS[@]} -eq 0 ]] || return 1
  return 0
}

cmd_strays() { # [node]
  local want="${1:-}" name rc worst=0
  if [[ -n "$want" ]] && ! node_fields "$want"; then
    die "no node named '${want}' (valid: $(node_names | tr '\n' ' '))"
  fi
  for name in $(node_names); do
    [[ -n "$want" && "$want" != "$name" ]] && continue
    step "Stray files on ${name}"
    if check_node_strays "$name"; then rc=0; else rc=$?; fi
    [[ $rc -gt $worst ]] && worst=$rc
  done
  return $worst
}

# Names clean-strays will hand to a remote shell. Anything else is refused
# rather than quoted: the listing is the node's word, not ours.
SAFE_NAME='^[A-Za-z0-9._~+,@=-]+/?$'

# clean_strays_remote_script <remote_dir> <dest> <entry>... — the script
# clean-strays runs on the node over SSH; both dirs are relative to the node
# account's home. It refuses what is protected even though the entries were
# classified here: config.json, .ht*, reticulum/ and the payload never move,
# and neither does a path (no /), whatever the listing said; a destination
# inside public_html or the source, or climbing out with .., is refused. Every
# refusal happens before anything moves.
clean_strays_remote_script() {
  local remote_dir="$1" dest="$2" names="" n protected
  shift 2
  for n in "$@"; do names+=" '${n%/}'"; done
  protected="$(IFS='|'; echo "${PAYLOAD[*]}")"
  printf '%s\n' "
    set -e
    src=\"\$HOME/${remote_dir}\"
    dest=\"\$HOME/${dest}\"
    case \"\$dest\" in \"\$HOME/public_html\"|\"\$HOME/public_html/\"*|\"\$src\"|\"\$src/\"*|*/..|*/../*)
      echo 'refusing: the destination is inside a served directory, or climbs out with ..' >&2; exit 3 ;;
    esac
    for n in ${names}; do
      case \"\$n\" in ''|.|..|*/*|config.json|.ht*|reticulum|${protected})
        echo \"refusing to move \$n: it is protected\" >&2; exit 3 ;;
      esac
    done
    cd \"\$src\"
    mkdir -p \"\$dest\"
    for n in ${names}; do
      if [ -e \"\$n\" ] || [ -L \"\$n\" ]; then
        if [ -e \"\$dest/\$n\" ] || [ -L \"\$dest/\$n\" ]; then
          echo \"\$dest/\$n already exists — \$n not moved\" >&2; exit 4
        fi
        mv -- \"\$n\" \"\$dest/\$n\"
        printf \"mv -- '%s' '%s'\\n\" \"\$dest/\$n\" \"\$src/\$n\" >> \"\$dest/RESTORE.sh\"
        echo \"  moved \$n\"
      else
        echo \"  already gone: \$n\"
      fi
    done"
}

cmd_clean_strays() { # <node> [--yes]
  local want="${1:-}" confirm="${2:-}"
  if [[ -z "$want" || ( -n "$confirm" && "$confirm" != "--yes" ) || $# -gt 2 ]]; then
    die "usage: ./deploy.sh clean-strays <$(node_names | paste -sd'|' -)> --yes"
  fi
  node_fields "$want" || die "no node named '${want}' (valid: $(node_names | tr '\n' ' '))"
  local host="${!HOST_VAR:-}"
  [[ -n "$host" ]] || die "${HOST_VAR} not set (see deploy.env.example)"
  set_ssh "${!PASS_VAR:-}" || die "no SSH to ${NODE_NAME}"

  step "Stray files on ${NODE_NAME}"
  local listing
  listing="$(remote_listing "$host" "$REMOTE_DIR")" || die "could not list ~/${REMOTE_DIR} on ${NODE_NAME} over SSH"
  classify_listing "$LAYOUT" "$listing"
  print_classes "$NODE_NAME" "$REMOTE_DIR" "$LAYOUT"
  if [[ ${#STRAYS[@]} -eq 0 ]]; then
    echo "${GREEN}✓ nothing to move${NC}"
    return 0
  fi

  local n unsafe=()
  for n in "${STRAYS[@]}"; do
    [[ "$n" =~ $SAFE_NAME ]] || unsafe+=("$n")
  done
  if [[ ${#unsafe[@]} -gt 0 ]]; then
    echo "${RED}These names carry characters this script will not pass to a remote shell:${NC}"
    printf '      %q\n' "${unsafe[@]}"
    die "nothing moved — move them by hand (to ~/${STRAY_ARCHIVE}/, never rm), then run this again"
  fi

  local dest="${STRAY_ARCHIVE}/${NODE_NAME}-$(date -u +%Y%m%dT%H%M%SZ)" verb="go"
  [[ "$confirm" == "--yes" ]] || verb="would go"
  echo
  echo "  ${#STRAYS[@]} entries ${verb} to ~/${dest}/ on ${NODE_NAME} (outside every served directory),"
  echo "  with ~/${dest}/RESTORE.sh to put them back. Nothing is deleted."
  if [[ "$confirm" != "--yes" ]]; then
    echo "${YELLOW}nothing moved — run again with --yes to move exactly the entries above${NC}"
    return 2
  fi

  "${SSH[@]}" "$host" "$(clean_strays_remote_script "$REMOTE_DIR" "$dest" "${STRAYS[@]}")" \
    || die "moving the strays on ${NODE_NAME} failed — see above; whatever moved is listed in ~/${dest}/RESTORE.sh"

  step "Listing ${NODE_NAME} again"
  if check_node_strays "$NODE_NAME"; then
    echo
    echo "${GREEN}✓ ${NODE_NAME} serves no stray files; they are in ~/${dest}/ (restore: sh ~/${dest}/RESTORE.sh)${NC}"
    return 0
  fi
  die "strays remain on ${NODE_NAME}"
}

# ── The boot gate ─────────────────────────────────────────────────────────
#
# Loads index.html from a local static server in headless Chromium and fails on
# any pageerror or failed module import (or stylesheet, or the page itself) in
# the first 10 s, and if nothing is rendered into #app by then. Only this
# directory and esm.sh (the importmap's CDN) are reachable; every other request
# is blocked, never sent, and listed. The node's config.json is never deployed,
# so the gate answers /config.json itself with an exchange on its own server
# that refuses everything: a boot never reaches a real exchange.
#
# Exit status: 0 booted clean; 1 the page failed; 2 the gate could not run (a
# Playwright that is installed but will not load, a Chromium that will not
# start), which says nothing about the page; 3 no browser installed (no
# Playwright, or Playwright without its Chromium) — the only skip.
boot_gate() { # dir
  local tmp rc
  tmp="$(mktemp -d)"
  boot_gate_js > "$tmp/boot-gate.mjs"
  if node "$tmp/boot-gate.mjs" "$1" "$PLAYWRIGHT_DIR"; then rc=0; else rc=$?; fi
  rm -rf "$tmp"
  return $rc
}

boot_gate_js() {
  cat <<'JS'
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, resolve, sep } from "node:path";

// The observation window the deploy gate asks for: the first 10 s after
// navigation. It decides pass/fail; it is not a wait for anything to get ready.
const WINDOW_MS = 10_000;
const REMOTE_OK = new Set(["esm.sh"]);
const LOADS = { document: "the page", script: "module import", stylesheet: "stylesheet" };
const EXCHANGE = "/__deploy_boot_gate_no_exchange__";
const TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml",
    ".ico": "image/x-icon", ".wasm": "application/wasm",
};
const say = (s) => console.log(`  ${s}`);
const [rootArg, pwDir] = process.argv.slice(2);
const ROOT = resolve(rootArg ?? ".");
if (!existsSync(join(ROOT, "index.html"))) { say(`FAIL no index.html in ${ROOT}`); process.exit(1); }

// Only "not installed" skips: Playwright that cannot be found, or Playwright
// whose Chromium was never downloaded. An installed Playwright that fails to
// load, or a Chromium that will not start, is a broken gate (exit 2), not a
// missing browser.
const firstLine = (e) => String(e?.message ?? e).split("\n")[0];
const requirePw = createRequire(join(resolve(pwDir), "package.json"));
let pwPath;
try {
    pwPath = requirePw.resolve("playwright");
} catch (e) {
    if (e.code !== "MODULE_NOT_FOUND") { say(`FAIL cannot resolve Playwright in ${pwDir}: ${firstLine(e)}`); process.exit(2); }
    say(`no Playwright in ${pwDir} (${e.code})`);
    process.exit(3);
}
let chromium;
try {
    ({ chromium } = requirePw(pwPath));
} catch (e) {
    say(`FAIL Playwright is installed in ${pwDir} but will not load: ${firstLine(e)}`);
    process.exit(2);
}
let browser;
try {
    browser = await chromium.launch({ headless: true, args: ["--disable-dev-shm-usage"] });
} catch (e) {
    if (/Executable doesn't exist/i.test(e?.message ?? "")) {
        say(`Playwright in ${pwDir} has no Chromium installed`);
        process.exit(3);
    }
    say(`FAIL Chromium would not start: ${firstLine(e)}`);
    process.exit(2);
}

const server = createServer(async (req, res) => {
    let path;
    try { path = decodeURIComponent(new URL(req.url, "http://gate").pathname); }
    catch { res.writeHead(400).end(); return; }
    if (path.startsWith(EXCHANGE)) {
        res.writeHead(503, { "content-type": "text/plain" }).end("the boot gate runs no exchange");
        return;
    }
    if (path === "/config.json") {
        res.writeHead(200, { "content-type": TYPES[".json"], "cache-control": "no-store" })
            .end(JSON.stringify({ exchangeUrl: `http://127.0.0.1:${server.address().port}${EXCHANGE}` }));
        return;
    }
    const file = resolve(ROOT, "." + (path.endsWith("/") ? `${path}index.html` : path));
    if (file !== ROOT && !file.startsWith(ROOT + sep)) { res.writeHead(403).end(); return; }
    try {
        const body = await readFile(file);
        res.writeHead(200, {
            "content-type": TYPES[extname(file).toLowerCase()] ?? "application/octet-stream",
            "cache-control": "no-store",
        }).end(body);
    } catch {
        res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    }
});
await new Promise((ok, no) => { server.once("error", no); server.listen(0, "127.0.0.1", ok); });
const origin = `http://127.0.0.1:${server.address().port}`;

const failures = [];
const blocked = [];
let rendered = null;
let settle;
const settled = new Promise((r) => { settle = r; });
let t0 = Date.now(); // reset at navigation: times below are from there
const at = () => `${((Date.now() - t0) / 1000).toFixed(1)} s`;
const fail = (why) => { failures.push(`${at()} ${why}`); settle(); };
let gateError = null;

try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.route("**/*", (route) => {
        const req = route.request();
        let u;
        try { u = new URL(req.url()); } catch { return route.continue(); }
        if (u.origin === origin || (u.protocol === "https:" && REMOTE_OK.has(u.hostname))) return route.continue();
        blocked.push(`${req.resourceType()} ${req.url()}`);
        return route.abort("blockedbyclient");
    });
    const page = await context.newPage();
    page.on("pageerror", (e) => fail(`pageerror: ${e.message}`));
    page.on("crash", () => fail("the page crashed"));
    page.on("requestfailed", (req) => {
        const what = LOADS[req.resourceType()];
        if (!what) return;
        const err = req.failure()?.errorText ?? "failed";
        const why = /BLOCKED_BY_CLIENT/.test(err) ? " — blocked: the gate allows only this directory and esm.sh" : "";
        fail(`${what} failed: ${req.url()} (${err})${why}`);
    });
    page.on("response", (r) => {
        const what = LOADS[r.request().resourceType()];
        if (what && r.status() >= 400) fail(`${what} failed: ${r.url()} → HTTP ${r.status()}`);
    });
    page.on("console", (m) => {
        if (m.type() === "error" && /module script|module specifier|import ?map/i.test(m.text())) fail(m.text());
    });
    await page.exposeFunction("__deployBootGateRendered", () => { rendered ??= at(); });
    await page.addInitScript(() => {
        const seen = () => {
            const app = document.getElementById("app");
            if (app && app.childElementCount > 0) { observer.disconnect(); window.__deployBootGateRendered(); }
        };
        const observer = new MutationObserver(seen);
        observer.observe(document, { childList: true, subtree: true });
    });
    t0 = Date.now();
    page.goto(`${origin}/index.html`, { waitUntil: "commit" })
        .catch((e) => fail(`navigation failed: ${e.message.split("\n")[0]}`));
    await Promise.race([settled, new Promise((r) => setTimeout(r, WINDOW_MS))]);
} catch (e) {
    // The gate broke before it could watch the window: that says nothing about
    // the page, unless the page had already failed.
    gateError = `the gate itself failed: ${firstLine(e)}`;
}
const renderedAt = rendered;
await browser.close().catch(() => {});
server.close();

for (const b of blocked) say(`blocked, never sent: ${b}`);
if (gateError && !failures.length) { say(`FAIL ${gateError}`); process.exit(2); }
if (gateError) say(`(and then ${gateError})`);
if (!failures.length && !renderedAt) failures.push(`nothing rendered into #app within ${WINDOW_MS / 1000} s: a blank page`);
if (failures.length) {
    for (const f of failures) say(`FAIL ${f}`);
    process.exit(1);
}
say(`rendered at ${renderedAt}; no pageerror and no failed module import in the first ${WINDOW_MS / 1000} s`);
process.exit(0);
JS
}

boot_skipped_warning() {
  echo "  ${YELLOW}⚠⚠⚠ BOOT GATE SKIPPED — no headless browser is installed ⚠⚠⚠${NC}"
  echo "  ${YELLOW}Nothing has shown that this build boots. 0760960 passed every other gate${NC}"
  echo "  ${YELLOW}and died at load in every browser with \"Buffer is not defined\".${NC}"
  echo "  ${YELLOW}Install: (cd ${PLAYWRIGHT_DIR} && npm install && npx playwright install chromium)${NC}"
}

cmd_boot_check() { # <dir>
  [[ $# -eq 1 && -d "$1" ]] || die "usage: ./deploy.sh boot-check <directory holding index.html>"
  command -v node >/dev/null 2>&1 || die "node not found"
  step "Booting $1 in headless Chromium"
  local rc
  if boot_gate "$1"; then rc=0; else rc=$?; fi
  case $rc in
    0) echo "  ${GREEN}✓${NC} boots" ;;
    3) boot_skipped_warning ;;
    2) echo "${RED}✗ the boot gate could not run (see above): this says nothing about the page${NC}" >&2 ;;
    *) echo "${RED}✗ the page does not boot${NC}" >&2; rc=1 ;;
  esac
  return $rc
}

# Sourced (the tests do, to run clean_strays_remote_script's output against a
# fake node home): the functions above are defined and nothing runs.
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

# ── Subcommands ───────────────────────────────────────────────────────────
case "${1:-}" in
  strays)       shift; cmd_strays "$@"; exit $? ;;
  clean-strays) shift; cmd_clean_strays "$@"; exit $? ;;
  boot-check)   shift; cmd_boot_check "$@"; exit $? ;;
  -h|--help|help) usage; exit 0 ;;
esac

# ── Deploy ────────────────────────────────────────────────────────────────
trap 'echo "${RED}deploy aborted${NC}"' ERR

REF="${1:-HEAD}"
ONLY_NODE="${2:-}"
if [[ -n "$ONLY_NODE" ]] && ! node_fields "$ONLY_NODE"; then
  die "no node matched '${ONLY_NODE}' (valid: $(node_names | tr '\n' ' '))"
fi
TARGETS=()
for name in $(node_names); do
  [[ -n "$ONLY_NODE" && "$ONLY_NODE" != "$name" ]] && continue
  TARGETS+=("$name")
done

# ── 1. The tree must be clean ────────────────────────────────────────────
step "Checking working tree"

if ! git -C "$REPO_DIR" rev-parse --verify "$REF" >/dev/null 2>&1; then
  die "not a valid git ref: ${REF}"
fi

DIRTY="$(git -C "$REPO_DIR" status --porcelain -- "${PAYLOAD[@]}")"
if [[ -n "$DIRTY" ]]; then
  if [[ "${DEPLOY_ALLOW_DIRTY:-0}" == "1" ]]; then
    echo "${YELLOW}⚠ working tree is dirty and DEPLOY_ALLOW_DIRTY=1 — deploying ${REF} anyway${NC}"
    echo "${YELLOW}  (the files below are NOT what will be deployed)${NC}"
    sed 's/^/    /' <<< "$DIRTY"
  else
    echo "${RED}Uncommitted changes in the deployable surface:${NC}"
    sed 's/^/    /' <<< "$DIRTY"
    echo
    echo "${DIM}Deploys come from git, not from your filesystem. Commit the work"
    echo "so that what runs in the browser is a thing you can name, diff and"
    echo "roll back to.${NC}"
    die "refusing to deploy with a dirty working tree"
  fi
else
  echo "  ${GREEN}✓${NC} clean"
fi

REF_SHA="$(git -C "$REPO_DIR" rev-parse --short "$REF")"
REF_SUBJECT="$(git -C "$REPO_DIR" log -1 --format=%s "$REF")"
echo "  ${GREEN}✓${NC} deploying ${REF_SHA} — ${REF_SUBJECT}"
echo "  ${GREEN}✓${NC} to: ${TARGETS[*]}"

# ── 2. The suite must be green ───────────────────────────────────────────
step "Running test suite"

if [[ "${DEPLOY_SKIP_TESTS:-0}" == "1" ]]; then
  echo "  ${YELLOW}⚠ skipped (DEPLOY_SKIP_TESTS=1)${NC}"
else
  if ! command -v node >/dev/null 2>&1; then
    die "node not found — the suite cannot run (DEPLOY_SKIP_TESTS=1 to override)"
  fi
  if [[ ! -d "$REPO_DIR/node_modules" ]]; then
    die "node_modules missing — run 'npm install' first (the browser uses the importmap; this is test-only)"
  fi
  if output="$(cd "$REPO_DIR" && npm test 2>&1)"; then
    echo "  ${GREEN}✓${NC} suite green — $(grep -E '^ℹ pass' <<< "$output" | tr -d '\n')"
  else
    sed 's/^/    /' <<< "$output" | tail -30
    echo
    echo "${DIM}A red suite is the reason regressions ship. Fix the failure before"
    echo "deploying.${NC}"
    die "test suite failed — not deploying"
  fi
fi

# ── 3. Static checks the browser would only reveal at runtime ────────────
step "Checking the module graph"

# Every hand-maintained ?v= tag is a staleness bug waiting to happen: the tree
# had 8 tagged imports and 26 untagged ones, so a fix in an untagged module
# stayed invisible behind a browser's heuristic cache. .htaccess now carries the
# cache policy for all of them. Reintroducing a tag means going back to walking
# the import chain by hand.
STRAY_VERSIONS="$(git -C "$REPO_DIR" grep -n '?v=' "$REF" -- '*.js' '*.html' || true)"
if [[ -n "$STRAY_VERSIONS" ]]; then
  echo "${RED}Hand-maintained cache-busting tags found:${NC}"
  sed 's/^/    /' <<< "$STRAY_VERSIONS"
  die "remove them — .htaccess owns the cache policy (see the comment in it)"
fi
echo "  ${GREEN}✓${NC} no hand-maintained ?v= tags"

# ── 4. Materialise the ref (never the working directory) ─────────────────
step "Staging ${REF_SHA} from git"

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap 'cleanup; echo "${RED}deploy aborted${NC}"' ERR
trap cleanup EXIT

git -C "$REPO_DIR" archive "$REF" "${PAYLOAD[@]}" | tar -x -C "$STAGE" \
  || die "git archive failed"

for excluded in "${EXCLUDE[@]}"; do
  rm -f "$STAGE/$excluded"
done

FILE_COUNT="$(find "$STAGE" -type f | wc -l | tr -d ' ')"
echo "  ${GREEN}✓${NC} ${FILE_COUNT} files staged from git (working tree untouched)"

# A relative import that does not resolve is a blank screen with one console
# line. There is no bundler here to catch it, so check the graph that is about
# to be served rather than the one in the working tree.
step "Resolving the module graph"
MISSING=0
while IFS= read -r src; do
  rel="${src#$STAGE/}"
  while IFS= read -r spec; do
    [[ -n "$spec" ]] || continue
    target="$(dirname "$src")/$spec"
    if [[ ! -f "$target" ]]; then
      echo "${RED}    ${rel} imports ${spec} — no such file${NC}"
      MISSING=$((MISSING + 1))
    fi
  done < <(grep -o -E '(from|import)[[:space:]]+"(\.[^"]+)"' "$src" 2>/dev/null \
             | grep -o -E '"\.[^"]+"' | tr -d '"')
done < <(find "$STAGE" -type f -name '*.js')
[[ $MISSING -eq 0 ]] || die "${MISSING} import(s) do not resolve in ${REF_SHA}"
echo "  ${GREEN}✓${NC} every relative import resolves"

# ── 5. Boot it ───────────────────────────────────────────────────────────
# Every check above reads files. The class that killed the page at 0760960
# ("Buffer is not defined" at module load) and a module the importmap cannot
# resolve pass all of them; only a browser executing the graph sees them.
step "Booting ${REF_SHA} in headless Chromium"
BOOT_CHECKED=0
# The gate drives Chromium from node. Without node it cannot run, which is not
# "no browser installed" and says nothing about whether the page boots.
command -v node >/dev/null 2>&1 \
  || die "node not found — the boot gate cannot run, so nothing shows ${REF_SHA} boots — not deploying"
if boot_gate "$STAGE"; then BOOT_RC=0; else BOOT_RC=$?; fi
case $BOOT_RC in
  0) BOOT_CHECKED=1; echo "  ${GREEN}✓${NC} boots" ;;
  3) boot_skipped_warning ;;
  2) die "the boot gate could not run (see above), so nothing shows ${REF_SHA} boots — not deploying" ;;
  *) die "${REF_SHA} does not boot in a browser — not deploying" ;;
esac

# ── 6. No node may serve stray files ─────────────────────────────────────
# Checked on every target before any node receives a byte.
STRAY_NODES=()
for name in "${TARGETS[@]}"; do
  step "Checking ${name} for stray files"
  if check_node_strays "$name"; then rc=0; else rc=$?; fi
  case $rc in
    0) ;;
    1) STRAY_NODES+=("$name") ;;
    *) die "cannot tell whether ${name} serves stray files — not deploying" ;;
  esac
done
if [[ ${#STRAY_NODES[@]} -gt 0 ]]; then
  echo
  echo "${DIM}Every file in the web client's directory is served from the app's origin."
  echo "Move the strays out of the docroot first (reversible, nothing is deleted):${NC}"
  for name in "${STRAY_NODES[@]}"; do echo "    ./deploy.sh clean-strays ${name} --yes"; done
  die "refusing to deploy while ${STRAY_NODES[*]} serve(s) stray files"
fi

# ── 7. Push to every node ────────────────────────────────────────────────
deploy_node() { # name host pass remote_dir
  local name="$1" host="$2" pass="$3" remote_dir="$4"

  set_ssh "$pass" || return 1

  # Roll back to the previous *served* state, not to a guess about it. Only the
  # files this deploy will overwrite are backed up, so the rest of the remote
  # tree (notably reticulum/, the PHP node) is never in scope.
  echo "  ${DIM}backing up current state${NC}"
  "${SSH[@]}" "$host" "
    set -e
    rm -rf ~/retichat-web-rollback
    mkdir -p ~/retichat-web-rollback ~/${remote_dir}
    cd ~/${remote_dir}
    for f in index.html app.js style.css retichat-icon.png .htaccess; do
      [ -f \"\$f\" ] && cp -p \"\$f\" ~/retichat-web-rollback/ || true
    done
    [ -d lib ] && cp -Rp lib ~/retichat-web-rollback/ || true
    true
  " || { echo "${RED}backup failed on ${name}${NC}"; return 1; }

  # Upload into a staging directory and move it into place, so a dropped
  # connection cannot leave half a module graph serving requests.
  echo "  ${DIM}uploading${NC}"
  "${SSH[@]}" "$host" "rm -rf ~/.retichat-web-incoming && mkdir -p ~/.retichat-web-incoming" \
    || { echo "${RED}could not create staging directory on ${name}${NC}"; return 1; }
  tar -C "$STAGE" -cf - . | "${SSH[@]}" "$host" "tar -C ~/.retichat-web-incoming -xf -" \
    || { echo "${RED}upload failed on ${name}${NC}"; return 1; }

  "${SSH[@]}" "$host" "
    set -e
    cd ~/.retichat-web-incoming
    # lib is replaced wholesale so a module deleted in git stops being served.
    rm -rf ~/${remote_dir}/lib
    cp -Rp lib ~/${remote_dir}/lib
    cp -p index.html app.js style.css retichat-icon.png .htaccess ~/${remote_dir}/
    cd ~ && rm -rf ~/.retichat-web-incoming
  " || { echo "${RED}install failed on ${name} — previous state is in ~/retichat-web-rollback${NC}"; return 1; }

  echo "  ${GREEN}✓${NC} ${name} — uploaded (rollback in ~/retichat-web-rollback)"
}

for name in "${TARGETS[@]}"; do
  node_fields "$name"
  step "Deploying to ${name} (${BASE_URL})"
  deploy_node "$name" "${!HOST_VAR:-}" "${!PASS_VAR:-}" "$REMOTE_DIR" || die "deploy to ${name} failed"
done

# ── 8. Prove it ──────────────────────────────────────────────────────────
step "Verifying served bytes against ${REF_SHA}"
if "$REPO_DIR/verify-deploy.sh" "$REF" "$ONLY_NODE"; then
  VERIFY_OK=1
else
  VERIFY_OK=0
fi

printf '%s  ref=%s  nodes=%s  dirty_override=%s  tests_skipped=%s  boot_checked=%s  verified=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REF_SHA" "${ONLY_NODE:-all}" \
  "${DEPLOY_ALLOW_DIRTY:-0}" "${DEPLOY_SKIP_TESTS:-0}" "$BOOT_CHECKED" "$VERIFY_OK" >> "$LOG_FILE"

[[ $VERIFY_OK -eq 1 ]] || die "post-deploy verification failed — a served app does not match ${REF_SHA}"

echo
echo "${GREEN}✓ ${REF_SHA} deployed and verified${NC}"
echo "${DIM}  rollback:  ./deploy.sh <older-ref>${NC}"
