#!/usr/bin/env bash
#
# verify-deploy.sh — does the app each node is serving match a git ref?
#
#   ./verify-deploy.sh                    # compare both nodes against HEAD
#   ./verify-deploy.sh be8964d           # ...against a specific ref
#   ./verify-deploy.sh HEAD selectiv     # ...one node only
#
# Both nodes, always. selectivesubconscious.com/retichat/ was deployed by hand
# and checked by nothing; on 2026-08-17 it was found serving a morning-old
# build while retichat.com had four newer fixes. "Getting stuck on links" on
# one URL and fine on the other is what a shadow copy looks like from the
# outside.
#
# Exit 0 only on an exact match, in both directions: a file the node serves but
# the ref does not contain is drift too, and so is a committed fix that never
# reached the node. The first run of the PHP equivalent found exactly that —
# a committed security fix that had never been deployed.
#
# No credentials and no SSH. Every file is fetched over plain HTTPS, so this is
# safe to run at any time, including as the first thing you do when a fix
# "stopped working". Run it before you start re-debugging code that may simply
# not be the code in production.
#
# It also asserts the cache policy is live. Matching bytes on disk mean nothing
# if the browser is entitled to serve last week's copy from memory — see the
# comment at the top of .htaccess.

set -uo pipefail

REF="${1:-HEAD}"
ONLY_NODE="${2:-}"

# Must match deploy.sh's NODES (name and served base URL).
NODES=(
  "retichat|https://retichat.com"
  "selectiv|https://selectivesubconscious.com/retichat"
)

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'

# Must match deploy.sh's PAYLOAD, minus the per-node config it deliberately
# leaves alone.
PAYLOAD=(index.html app.js style.css retichat-icon.png lib)

die() { echo "${RED}✗ $*${NC}" >&2; exit 1; }

git -C "$REPO_DIR" rev-parse --verify "$REF" >/dev/null 2>&1 \
  || die "not a valid git ref: ${REF}"
REF_SHA="$(git -C "$REPO_DIR" rev-parse --short "$REF")"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

git -C "$REPO_DIR" archive "$REF" "${PAYLOAD[@]}" | tar -x -C "$STAGE" \
  || die "git archive failed"

TOTAL_DRIFT=0; TOTAL_MISSING=0; TOTAL_CACHE_FAIL=0; TOTAL_HTTPS_FAIL=0

check_node() { # name base_url
  local NODE_NAME="$1" BASE_URL="$2"
  echo "${CYAN}▸ Comparing ${BASE_URL} against ${REF_SHA}${NC}"
  echo

  OK=0; DRIFT=0; MISSING=0
  DRIFTED_FILES=()

  while IFS= read -r rel; do
    # Hash the file, never its contents through $(...) — command substitution
    # strips trailing newlines and reports every file as drifted.
    local_hash="$(shasum -a 256 "$STAGE/$rel" | cut -d' ' -f1)"

    code="$(curl -sS --max-time 30 -o "$STAGE/.fetched" -w '%{http_code}' "$BASE_URL/$rel" 2>/dev/null)"
    if [[ "$code" != "200" ]]; then
      printf '  %-48s %s\n' "$rel" "${RED}HTTP ${code}${NC}"
      MISSING=$((MISSING + 1))
      continue
    fi

    remote_hash="$(shasum -a 256 "$STAGE/.fetched" | cut -d' ' -f1)"
    if [[ "$local_hash" == "$remote_hash" ]]; then
      OK=$((OK + 1))
    else
      printf '  %-48s %s\n' "$rel" "${RED}DRIFT${NC}"
      printf '      %s  ref %s\n' "${DIM}expected${NC}" "${local_hash:0:16}"
      printf '      %s  live %s\n' "${DIM}serving ${NC}" "${remote_hash:0:16}"
      DRIFT=$((DRIFT + 1))
      DRIFTED_FILES+=("$rel")
    fi
  done < <(cd "$STAGE" && find . -type f ! -name '.fetched' | sed 's|^\./||' | sort)

  echo
  echo "  ${GREEN}${OK}${NC} match, ${RED}${DRIFT}${NC} drifted, ${YELLOW}${MISSING}${NC} unreachable"

  # ── Cache policy ─────────────────────────────────────────────────────────
  echo
  echo "${CYAN}▸ Checking the cache policy is live${NC}"
  CACHE_FAIL=0
  for probe in app.js lib/rns/link.js style.css; do
    header="$(curl -sS --max-time 20 -D - -o /dev/null "$BASE_URL/$probe" 2>/dev/null \
                | tr -d '\r' | grep -i '^cache-control:' | head -1)"
    if [[ -z "$header" ]]; then
      printf '  %-32s %s\n' "$probe" "${RED}no Cache-Control header${NC}"
      CACHE_FAIL=$((CACHE_FAIL + 1))
    elif ! grep -qi 'no-cache' <<< "$header"; then
      printf '  %-32s %s\n' "$probe" "${RED}${header}${NC}"
      CACHE_FAIL=$((CACHE_FAIL + 1))
    else
      printf '  %-32s %s\n' "$probe" "${GREEN}${header#*: }${NC}"
    fi
  done

  if [[ $CACHE_FAIL -gt 0 ]]; then
    echo
    echo "${DIM}Without a no-cache header and with no version strings in the source, a"
    echo "browser is free to keep serving an old module indefinitely — the fix is"
    echo "deployed and still not running. Check that .htaccess uploaded and that"
    echo "mod_headers is enabled on the node.${NC}"
  fi

  # ── HTTPS enforcement ────────────────────────────────────────────────────
  # The node's public_html/.htaccess was hand-edited and tracked nowhere, and all
  # it held was a force-HTTPS redirect. deploy.sh overwrites that file, so this
  # checks the rule survived rather than assuming it did.
  echo
  echo "${CYAN}▸ Checking HTTP still redirects to HTTPS${NC}"
  HTTPS_FAIL=0
  PLAIN_URL="http://${BASE_URL#https://}"
  PLAIN_URL="http://${PLAIN_URL#http://}"
  redirect="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code} %{redirect_url}' "$PLAIN_URL/app.js" 2>/dev/null)"
  case "$redirect" in
    30[128]" https://"*)
      printf '  %-32s %s\n' "http → https" "${GREEN}${redirect}${NC}" ;;
    *)
      printf '  %-32s %s\n' "http → https" "${RED}${redirect:-no response}${NC}"
      echo "${DIM}  The force-HTTPS redirect is gone. It lives in this repo's .htaccess"
      echo "  because deploying that file replaces the node's only copy of it.${NC}"
      HTTPS_FAIL=1 ;;
  esac

  TOTAL_DRIFT=$((TOTAL_DRIFT + DRIFT))
  TOTAL_MISSING=$((TOTAL_MISSING + MISSING))
  TOTAL_CACHE_FAIL=$((TOTAL_CACHE_FAIL + CACHE_FAIL))
  TOTAL_HTTPS_FAIL=$((TOTAL_HTTPS_FAIL + HTTPS_FAIL))
}

CHECKED=0
for node in "${NODES[@]}"; do
  IFS='|' read -r name base_url <<< "$node"
  [[ -n "$ONLY_NODE" && "$ONLY_NODE" != "$name" ]] && continue
  echo
  echo "${CYAN}── ${name} ─────────────────────────────────${NC}"
  check_node "$name" "$base_url"
  CHECKED=$((CHECKED + 1))
done
[[ $CHECKED -gt 0 ]] || die "no node matched '${ONLY_NODE}' (valid: retichat, selectiv)"

# ── Verdict ──────────────────────────────────────────────────────────────
echo
if [[ $TOTAL_DRIFT -eq 0 && $TOTAL_MISSING -eq 0 && $TOTAL_CACHE_FAIL -eq 0 && $TOTAL_HTTPS_FAIL -eq 0 ]]; then
  echo "${GREEN}✓ every checked node is serving ${REF_SHA} exactly${NC}"
  exit 0
fi

if [[ $TOTAL_DRIFT -gt 0 ]]; then
  echo "${DIM}To see what differs on a file:${NC}"
  echo "${DIM}  curl -s <node-url>/<file> | diff - <(git show ${REF}:<file>)${NC}"
  echo "${DIM}To make every node match: ./deploy.sh ${REF}${NC}"
fi
exit 1
