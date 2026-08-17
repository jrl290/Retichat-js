#!/usr/bin/env bash
#
# deploy.sh — the only supported way to move the web client onto a live node.
#
#   ./deploy.sh                  # deploy HEAD to retichat.com
#   ./deploy.sh be8964d          # ...a specific ref (rollback)
#
# WHAT THIS EXISTS TO PREVENT
# ===========================
# Reticulum-post got these gates on 2026-08-17 after a working tree that was
# HEAD-with-the-newest-fixes-removed nearly shipped by scp. The web client — the
# component whose console log is what you actually read when something breaks —
# never got them. It was still deployed by hand, from the filesystem, with no
# check that what landed matched any commit.
#
# The checks are the same four, for the same reason:
#
#   1. refuse a dirty working tree      — you cannot ship what isn't committed
#   2. run the test suite               — and refuse on any failure
#   3. deploy from `git archive <ref>`  — never from the working directory
#   4. verify the served bytes          — proof, not hope
#
# Step 4 is cheaper here than for the PHP node: every file is fetchable over
# plain HTTPS, so verify-deploy.sh needs no credentials and can be run by anyone,
# at any time, without touching the node. Run it whenever you suspect drift.
#
# Credentials come from the environment. Keep them in a gitignored deploy.env:
#
#   export RETICHAT_SSH_HOST=retichat@retichat.com
#   export RETICHAT_SSH_PASS=...        # leave empty to use key auth
#
# Bypass for a genuine emergency: DEPLOY_ALLOW_DIRTY=1 (tree check) and
# DEPLOY_SKIP_TESTS=1 (suite). Both print a loud warning and are recorded in
# .deploy.log. If you find yourself using them routinely, fix the cause.

set -uo pipefail

REF="${1:-HEAD}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_DIR="public_html"
LOG_FILE="${REPO_DIR}/.deploy.log"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'
SSH_OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR)

# The web client's deployable surface. Tests, README and the local config
# template are not served. config.json is per-node runtime config the node owns
# (it names that node's exchangeUrl) — deploying ours would repoint the live app
# at 127.0.0.1.
PAYLOAD=(index.html app.js style.css retichat-icon.png .htaccess lib)
EXCLUDE=(config.json config.local.json)

die() { echo "${RED}✗ $*${NC}" >&2; exit 1; }
step() { echo; echo "${CYAN}▸ $*${NC}"; }

trap 'echo "${RED}deploy aborted${NC}"' ERR

[[ -f "$REPO_DIR/deploy.env" ]] && source "$REPO_DIR/deploy.env"

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

# ── 5. Push ──────────────────────────────────────────────────────────────
step "Deploying to retichat.com"

HOST="${RETICHAT_SSH_HOST:-}"
PASS="${RETICHAT_SSH_PASS:-}"
[[ -n "$HOST" ]] || die "RETICHAT_SSH_HOST not set (see deploy.env.example)"

if [[ -n "$PASS" ]]; then
  command -v sshpass >/dev/null 2>&1 || die "sshpass required when RETICHAT_SSH_PASS is set"
  SCP=(env "SSHPASS=$PASS" sshpass -e scp "${SSH_OPTS[@]}")
  SSH=(env "SSHPASS=$PASS" sshpass -e ssh "${SSH_OPTS[@]}")
else
  SCP=(scp "${SSH_OPTS[@]}" -o BatchMode=yes)
  SSH=(ssh "${SSH_OPTS[@]}" -o BatchMode=yes)
fi

# Roll back to the previous *served* state, not to a guess about it. Only the
# files this deploy will overwrite are backed up, so the rest of public_html
# (notably reticulum/, the PHP node) is never in scope.
echo "  ${DIM}backing up current state${NC}"
"${SSH[@]}" "$HOST" "
  set -e
  rm -rf ~/retichat-web-rollback
  mkdir -p ~/retichat-web-rollback
  cd ~/${REMOTE_DIR}
  for f in index.html app.js style.css retichat-icon.png .htaccess; do
    [ -f \"\$f\" ] && cp -p \"\$f\" ~/retichat-web-rollback/ || true
  done
  [ -d lib ] && cp -Rp lib ~/retichat-web-rollback/ || true
  true
" || die "backup failed"

# Upload into a staging directory and move it into place, so a dropped
# connection cannot leave half a module graph serving requests.
echo "  ${DIM}uploading${NC}"
"${SSH[@]}" "$HOST" "rm -rf ~/.retichat-web-incoming && mkdir -p ~/.retichat-web-incoming" \
  || die "could not create staging directory"
tar -C "$STAGE" -cf - . | "${SSH[@]}" "$HOST" "tar -C ~/.retichat-web-incoming -xf -" \
  || die "upload failed"

"${SSH[@]}" "$HOST" "
  set -e
  cd ~/.retichat-web-incoming
  # lib is replaced wholesale so a module deleted in git stops being served.
  rm -rf ~/${REMOTE_DIR}/lib
  cp -Rp lib ~/${REMOTE_DIR}/lib
  cp -p index.html app.js style.css retichat-icon.png .htaccess ~/${REMOTE_DIR}/
  cd ~ && rm -rf ~/.retichat-web-incoming
" || die "install failed — previous state is in ~/retichat-web-rollback"

echo "  ${GREEN}✓${NC} uploaded (rollback in ~/retichat-web-rollback)"

# ── 6. Prove it ──────────────────────────────────────────────────────────
step "Verifying served bytes against ${REF_SHA}"
if "$REPO_DIR/verify-deploy.sh" "$REF"; then
  VERIFY_OK=1
else
  VERIFY_OK=0
fi

printf '%s  ref=%s  dirty_override=%s  tests_skipped=%s  verified=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REF_SHA" \
  "${DEPLOY_ALLOW_DIRTY:-0}" "${DEPLOY_SKIP_TESTS:-0}" "$VERIFY_OK" >> "$LOG_FILE"

[[ $VERIFY_OK -eq 1 ]] || die "post-deploy verification failed — the served app does not match ${REF_SHA}"

echo
echo "${GREEN}✓ ${REF_SHA} deployed and verified${NC}"
echo "${DIM}  rollback:  ./deploy.sh <older-ref>${NC}"
