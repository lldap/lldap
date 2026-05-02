#!/usr/bin/env bash
# End-to-end test for the progressive opaque-ke 4.0 password upgrade.
#
# Builds two `lldap` binaries from this repository at two different commits:
#
#   1. BASELINE — a commit prior to the opaque-ke 4.0 work, which still
#      stores password files using opaque-ke 0.7 and operates on schema v11.
#   2. HEAD     — the commit currently under test, which adds schema v12
#      (`users.password_version`) and the legacy-credential auto-upgrade
#      path.
#
# Both binaries run sequentially against the SAME SQLite database, so the
# test exercises the full schema-migration + credential-upgrade flow that
# a real user would hit when redeploying after this change.
#
# Sequence:
#   1. Build the baseline binary in a throwaway git worktree.
#   2. Build the HEAD binary in the main checkout.
#   3. Start baseline lldap, bootstrap admin, create a test user, set its
#      password via baseline `lldap_set_password` (writes opaque-ke 0.7).
#   4. Bind via LDAP against the baseline server to confirm the credential
#      is functional before the upgrade.
#   5. Stop baseline.
#   6. Assert the on-disk SQLite schema is at v11 — no `password_version`
#      column yet.
#   7. Start the HEAD binary against the same DB. Assert the v12 migration
#      added `password_version` and the test user defaulted to 0 (legacy).
#   8. Bind to the HEAD server with the same password. The legacy bind path
#      should validate against the opaque-ke 0.7 file AND silently re-write
#      it as an opaque-ke 4.0 file (`password_version` flips to 1).
#   9. Bind a second time to confirm the upgraded credential keeps working.
#  10. Bind with a wrong password to confirm it's still rejected.
#
# Required commands: cargo, git, curl, jq, sqlite3, ldapsearch.
#
# Inputs (env vars):
#   BASELINE_REV    git revision to build as the baseline. Default:
#                   bb2ea7bf36742665a3f275faacff5f0a71dfdef0 — the parent
#                   of the opaque-ke 4.0 migration commit.
#   HEAD_REV        git revision to build as HEAD. Default: HEAD.
#   LDAP_PORT       default 3899 (avoid clashing with a running 3890)
#   HTTP_PORT       default 17179
#   TEST_USER       default opaque_upgrade_test
#   TEST_PASSWORD   default RealisticP@ssw0rd123
#
# Exit codes: 0 on full pass, non-zero on the first failed assertion.

set -euo pipefail

BASELINE_REV="${BASELINE_REV:-bb2ea7bf36742665a3f275faacff5f0a71dfdef0}"
HEAD_REV="${HEAD_REV:-HEAD}"
TEST_USER="${TEST_USER:-opaque_upgrade_test}"
TEST_PASSWORD="${TEST_PASSWORD:-RealisticP@ssw0rd123}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-adminpass}"
JWT_SECRET="${JWT_SECRET:-test-jwt-secret-do-not-use-in-prod}"
LDAP_PORT="${LDAP_PORT:-3899}"
HTTP_PORT="${HTTP_PORT:-17179}"
LDAP_BASE_DN="${LDAP_BASE_DN:-dc=example,dc=com}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="$(mktemp -d -t lldap-opaque-e2e.XXXXXX)"
BASELINE_WORKTREE="$WORKDIR/baseline-src"
RUNNING_PID=""

cleanup() {
  set +e
  if [ -n "$RUNNING_PID" ]; then
    kill "$RUNNING_PID" 2>/dev/null || true
    wait "$RUNNING_PID" 2>/dev/null || true
  fi
  if [ -d "$BASELINE_WORKTREE" ]; then
    git -C "$REPO_ROOT" worktree remove --force "$BASELINE_WORKTREE" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

log() { printf '\n[opaque-upgrade] %s\n' "$*"; }
die() { printf '\n[opaque-upgrade] FAIL: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd cargo
require_cmd git
require_cmd curl
require_cmd jq
require_cmd sqlite3
require_cmd ldapsearch

# --- Build the baseline binary in a worktree --------------------------------
log "Creating worktree at baseline rev $BASELINE_REV"
git -C "$REPO_ROOT" worktree add --detach "$BASELINE_WORKTREE" "$BASELINE_REV" >/dev/null

log "Building baseline lldap (cargo build --release -p lldap)"
( cd "$BASELINE_WORKTREE" && cargo build --release -p lldap -p lldap_set_password )
BASELINE_LLDAP="$BASELINE_WORKTREE/target/release/lldap"
BASELINE_SET_PWD="$BASELINE_WORKTREE/target/release/lldap_set_password"
[ -x "$BASELINE_LLDAP" ] || die "baseline lldap binary not built at $BASELINE_LLDAP"
[ -x "$BASELINE_SET_PWD" ] || die "baseline lldap_set_password not built"

# --- Build the HEAD binary --------------------------------------------------
log "Building HEAD lldap (cargo build --release -p lldap)"
( cd "$REPO_ROOT" && cargo build --release -p lldap )
HEAD_LLDAP="$REPO_ROOT/target/release/lldap"
[ -x "$HEAD_LLDAP" ] || die "HEAD lldap binary not built at $HEAD_LLDAP"

# --- Common runtime configuration -------------------------------------------
DB_PATH="$WORKDIR/users.db"
KEY_FILE="$WORKDIR/server_key"
export LLDAP_DATABASE_URL="sqlite://$DB_PATH?mode=rwc"
export LLDAP_LDAP_PORT="$LDAP_PORT"
export LLDAP_HTTP_PORT="$HTTP_PORT"
export LLDAP_LDAP_USER_PASS="$ADMIN_PASSWORD"
export LLDAP_JWT_SECRET="$JWT_SECRET"
export LLDAP_LDAP_BASE_DN="$LDAP_BASE_DN"
export LLDAP_VERBOSE="false"
# Pin the OPAQUE server key file to an absolute, run-scoped path so the
# baseline and HEAD phases share the same private key. Without this, lldap's
# default behavior writes ./server_key relative to PWD; the two phases run
# from different working directories, so HEAD would generate a fresh key
# and `compare_private_key_hashes` would refuse to start.
export LLDAP_KEY_FILE="$KEY_FILE"

wait_for_http() {
  local label="$1" pid="$2" log_file="$3"
  local i
  for i in $(seq 1 60); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -50 "$log_file" >&2 || true
      die "$label exited before becoming ready"
    fi
    if curl -fsS --max-time 1 "http://localhost:$HTTP_PORT/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  tail -50 "$log_file" >&2 || true
  die "$label did not become ready within 60s"
}

# --- Phase 1: baseline writes a legacy credential ---------------------------
log "Starting baseline lldap"
# `exec` replaces the subshell with lldap so $! is the lldap PID, not the
# subshell's. Without this, `kill $RUNNING_PID` reaps the subshell while
# lldap leaks as an orphan still bound to the listen port.
( cd "$BASELINE_WORKTREE" && exec "$BASELINE_LLDAP" run >"$WORKDIR/baseline.log" 2>&1 ) &
RUNNING_PID=$!
wait_for_http baseline "$RUNNING_PID" "$WORKDIR/baseline.log"
log "Baseline is ready"

log "Confirming baseline schema has no users.password_version column (v11)"
HAS_PV_BEFORE=$(sqlite3 -noheader -csv "$DB_PATH" \
  "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='password_version'")
[ "$HAS_PV_BEFORE" = "0" ] || \
  die "baseline already has password_version column — wrong baseline rev?"

log "Logging in as admin to obtain a token"
TOKEN=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" \
  "http://localhost:$HTTP_PORT/auth/simple/login" | jq -r .token)
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || die "admin login returned empty token"

log "Creating test user '$TEST_USER' via GraphQL"
curl -fsS "http://localhost:$HTTP_PORT/api/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary "{\"query\":\"mutation{createUser(user:{id:\\\"$TEST_USER\\\",email:\\\"$TEST_USER@example.com\\\"}){id}}\"}" \
  >"$WORKDIR/create-user.log"
grep -q "\"id\":\"$TEST_USER\"" "$WORKDIR/create-user.log" || \
  die "user creation did not return expected id (response: $(cat "$WORKDIR/create-user.log"))"

log "Setting password via baseline lldap_set_password (writes opaque-ke 0.7)"
"$BASELINE_SET_PWD" \
  --base-url "http://localhost:$HTTP_PORT" \
  --admin-username admin --admin-password "$ADMIN_PASSWORD" \
  --token "$TOKEN" \
  --username "$TEST_USER" --password "$TEST_PASSWORD" \
  >"$WORKDIR/set-pwd.log" 2>&1 || \
  die "lldap_set_password failed: $(cat "$WORKDIR/set-pwd.log")"

log "Sanity bind to baseline with the new credential"
ldapsearch -LLL -H "ldap://localhost:$LDAP_PORT" \
  -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "$TEST_PASSWORD" \
  -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
  >"$WORKDIR/baseline-bind.log" 2>&1 || \
  die "baseline bind failed: $(cat "$WORKDIR/baseline-bind.log")"
grep -q "uid=$TEST_USER" "$WORKDIR/baseline-bind.log" || \
  die "baseline bind did not return the user dn"

log "Stopping baseline lldap"
kill "$RUNNING_PID"
wait "$RUNNING_PID" 2>/dev/null || true
RUNNING_PID=""

# --- Phase 2a: HEAD rotates the OPAQUE server key (one-shot) ----------------
# `LLDAP_FORCE_UPDATE_PRIVATE_KEY=true` is the documented opt-in flag the
# admin sets exactly once when crossing the opaque-ke 0.7 → 4.0 boundary.
# It tells HEAD to accept the on-disk key file's old wire format, preserve
# it in memory as `legacy_server_key_bytes`, and atomically rotate the file
# to the v4.0 format. lldap then exits and refuses to serve while the
# force flag is set, requiring the admin to restart cleanly in 2b below.
log "Running HEAD with --force-update-private-key to rotate the key file"
LLDAP_FORCE_UPDATE_PRIVATE_KEY=true \
  "$HEAD_LLDAP" run >"$WORKDIR/head-rotate.log" 2>&1 &
ROTATE_PID=$!
# This invocation is expected to exit non-zero after rotating the file.
wait "$ROTATE_PID" 2>/dev/null || true
unset ROTATE_PID
grep -q "rotated to a new opaque-ke format" "$WORKDIR/head-rotate.log" || {
  cat "$WORKDIR/head-rotate.log" >&2
  die "HEAD did not rotate the server key file"
}
log "Key file rotated to opaque-ke 4.0 ✓"

# --- Phase 2b: HEAD serves normally and upgrades user credentials ----------
log "Starting HEAD lldap normally (no force flag)"
( cd "$REPO_ROOT" && exec "$HEAD_LLDAP" run >"$WORKDIR/head.log" 2>&1 ) &
RUNNING_PID=$!
wait_for_http head "$RUNNING_PID" "$WORKDIR/head.log"
log "HEAD is ready"

log "Confirming v12 migration added users.password_version"
HAS_PV_AFTER=$(sqlite3 -noheader -csv "$DB_PATH" \
  "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='password_version'")
[ "$HAS_PV_AFTER" = "1" ] || die "HEAD did not add password_version column"

PRE_VERSION=$(sqlite3 -noheader -csv "$DB_PATH" \
  "SELECT password_version FROM users WHERE user_id='$TEST_USER'")
[ "$PRE_VERSION" = "0" ] || \
  die "expected pre-bind password_version=0, got '$PRE_VERSION'"
log "Pre-bind password_version = 0 (legacy) ✓"

log "First bind against HEAD — should succeed AND auto-upgrade to v4.0"
ldapsearch -LLL -H "ldap://localhost:$LDAP_PORT" \
  -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "$TEST_PASSWORD" \
  -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
  >"$WORKDIR/head-bind1.log" 2>&1 || {
    cat "$WORKDIR/head-bind1.log" >&2
    tail -40 "$WORKDIR/head.log" >&2
    die "HEAD bind with legacy credential failed"
  }
grep -q "uid=$TEST_USER" "$WORKDIR/head-bind1.log" || \
  die "HEAD bind did not return the user dn"

POST_VERSION=$(sqlite3 -noheader -csv "$DB_PATH" \
  "SELECT password_version FROM users WHERE user_id='$TEST_USER'")
[ "$POST_VERSION" = "1" ] || \
  die "expected post-bind password_version=1, got '$POST_VERSION'"
log "Post-bind password_version = 1 (v4.0) ✓ — credential upgraded"

log "Second bind against the upgraded credential"
ldapsearch -LLL -H "ldap://localhost:$LDAP_PORT" \
  -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "$TEST_PASSWORD" \
  -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
  >"$WORKDIR/head-bind2.log" 2>&1 || \
  die "second HEAD bind failed: $(cat "$WORKDIR/head-bind2.log")"
grep -q "uid=$TEST_USER" "$WORKDIR/head-bind2.log" || \
  die "second HEAD bind did not return the user dn"
log "Second bind succeeded ✓"

log "Wrong password should be rejected"
if ldapsearch -LLL -H "ldap://localhost:$LDAP_PORT" \
     -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "definitely-not-the-password" \
     -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
     >/dev/null 2>&1; then
  die "wrong password unexpectedly succeeded"
fi
log "Wrong password rejected ✓"

log "ALL CHECKS PASSED — opaque-ke 4.0 upgrade flow works end-to-end"
