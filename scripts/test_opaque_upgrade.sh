#!/usr/bin/env bash
# End-to-end test for the progressive opaque-ke 4.0 password upgrade.
#
# Runs the full baseline (opaque-ke 0.7) -> HEAD (opaque-ke 4.0) upgrade twice,
# once for each way LLDAP can hold its OPAQUE server key. The upgrade is
# fully automatic — no flag, no extra restart:
#
#   * file  — the key lives in a `server_key` file. HEAD detects that the file
#             is a valid opaque-ke 0.7 key, confirms against the DB that it is
#             the key from the last successful startup, then rotates the file
#             to the v4.0 format and drops a `<keyfile>.v07` sidecar holding
#             the old key for backward-compatible validation.
#   * seed  — the key is derived from LLDAP_KEY_SEED. HEAD reconstructs the
#             old v0.7 key from the SAME seed in memory (no sidecar, no key
#             file on disk), confirms it against the DB, and records the new
#             key hash.
#
# Both variants run baseline + HEAD sequentially against the SAME SQLite DB,
# exercising the schema migration (v11 -> v12) and the credential auto-upgrade.
#
# Sequence (per variant):
#   1. Build the baseline + HEAD binaries (once, shared by both variants).
#   2. Start baseline lldap, bootstrap admin, create a test user, set its
#      password via baseline `lldap_set_password` (writes opaque-ke 0.7).
#   3. Bind via LDAP against the baseline server to confirm the credential
#      is functional before the upgrade.
#   4. Stop baseline. Assert the schema is at v11 (no `password_version`).
#   5. Start HEAD directly (no flag). Assert it detects the opaque-ke
#      0.7 -> 4.0 upgrade automatically:
#        - file: rotates the on-disk key file to v4.0 + writes the sidecar.
#        - seed: records the new key hash, writes NO file and NO sidecar.
#      Assert the v12 migration added `password_version` and the test user
#      defaulted to 0 (legacy).
#   6. Bind to HEAD with the same password. The legacy bind path validates
#      against the opaque-ke 0.7 credential AND silently re-writes it as
#      opaque-ke 4.0 (`password_version` flips to 1).
#   7. Bind again to confirm the upgraded credential keeps working.
#   8. Bind with a wrong password to confirm it's still rejected.
#
# Required commands: cargo, git, curl, jq, sqlite3, ldapsearch.
#
# Inputs (env vars):
#   BASELINE_REV    git revision to build as the baseline. Default:
#                   bb2ea7bf36742665a3f275faacff5f0a71dfdef0 — the parent
#                   of the opaque-ke 4.0 migration commit.
#   HEAD_REV        git revision to build as HEAD. Default: HEAD.
#   LDAP_PORT       base LDAP port; the file variant uses it, the seed
#                   variant uses LDAP_PORT+1. Default 3899.
#   HTTP_PORT       base HTTP port; the file variant uses it, the seed
#                   variant uses HTTP_PORT+1. Default 17179.
#   KEY_SEED        seed used for the seed variant. Default a fixed test seed.
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
KEY_SEED="${KEY_SEED:-e2e-opaque-upgrade-test-key-seed}"

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

# --- Common runtime configuration (DB / key / ports are set per-variant) ----
export LLDAP_LDAP_USER_PASS="$ADMIN_PASSWORD"
export LLDAP_JWT_SECRET="$JWT_SECRET"
export LLDAP_LDAP_BASE_DN="$LDAP_BASE_DN"
export LLDAP_VERBOSE="false"

wait_for_http() {
  local label="$1" pid="$2" log_file="$3" http_port="$4"
  local i
  for i in $(seq 1 60); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -50 "$log_file" >&2 || true
      die "$label exited before becoming ready"
    fi
    if curl -fsS --max-time 1 "http://localhost:$http_port/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  tail -50 "$log_file" >&2 || true
  die "$label did not become ready within 60s"
}

pv_count() {
  sqlite3 -noheader -csv "$1" \
    "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='password_version'"
}
pv_value() {
  sqlite3 -noheader -csv "$1" \
    "SELECT password_version FROM users WHERE user_id='$TEST_USER'"
}

# Run the complete baseline -> HEAD upgrade for one key-storage mode.
#   $1 mode: "file" or "seed"
#   $2 ldap port
#   $3 http port
run_variant() {
  local mode="$1" ldap_port="$2" http_port="$3"
  local db_path="$WORKDIR/users-$mode.db"
  local key_file="$WORKDIR/server_key-$mode"

  log "================= Variant: $mode-based server key ================="

  export LLDAP_DATABASE_URL="sqlite://$db_path?mode=rwc"
  export LLDAP_LDAP_PORT="$ldap_port"
  export LLDAP_HTTP_PORT="$http_port"
  # Pin the key file to an absolute, run-scoped path so the baseline and HEAD
  # phases (which run from different working directories) agree on it instead
  # of each writing ./server_key relative to their own PWD.
  export LLDAP_KEY_FILE="$key_file"
  if [ "$mode" = "seed" ]; then
    # Key is derived from the seed; the key_file above is never read or written
    # (its basename is not "server_key", so lldap takes the "generate from
    # key_seed" path rather than warning about an ignored default file).
    export LLDAP_KEY_SEED="$KEY_SEED"
  else
    unset LLDAP_KEY_SEED 2>/dev/null || true
  fi

  # --- Phase 1: baseline writes a legacy (opaque-ke 0.7) credential ---------
  log "[$mode] Starting baseline lldap"
  ( cd "$BASELINE_WORKTREE" && exec "$BASELINE_LLDAP" run >"$WORKDIR/$mode-baseline.log" 2>&1 ) &
  RUNNING_PID=$!
  wait_for_http "baseline($mode)" "$RUNNING_PID" "$WORKDIR/$mode-baseline.log" "$http_port"
  log "[$mode] Baseline is ready"

  log "[$mode] Confirming baseline schema has no users.password_version column (v11)"
  [ "$(pv_count "$db_path")" = "0" ] || \
    die "[$mode] baseline already has password_version column — wrong baseline rev?"

  log "[$mode] Logging in as admin to obtain a token"
  local token
  token=$(curl -fsS -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" \
    "http://localhost:$http_port/auth/simple/login" | jq -r .token)
  [ -n "$token" ] && [ "$token" != "null" ] || die "[$mode] admin login returned empty token"

  log "[$mode] Creating test user '$TEST_USER' via GraphQL"
  curl -fsS "http://localhost:$http_port/api/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    --data-binary "{\"query\":\"mutation{createUser(user:{id:\\\"$TEST_USER\\\",email:\\\"$TEST_USER@example.com\\\"}){id}}\"}" \
    >"$WORKDIR/$mode-create-user.log"
  grep -q "\"id\":\"$TEST_USER\"" "$WORKDIR/$mode-create-user.log" || \
    die "[$mode] user creation did not return expected id (response: $(cat "$WORKDIR/$mode-create-user.log"))"

  log "[$mode] Setting password via baseline lldap_set_password (writes opaque-ke 0.7)"
  "$BASELINE_SET_PWD" \
    --base-url "http://localhost:$http_port" \
    --admin-username admin --admin-password "$ADMIN_PASSWORD" \
    --token "$token" \
    --username "$TEST_USER" --password "$TEST_PASSWORD" \
    >"$WORKDIR/$mode-set-pwd.log" 2>&1 || \
    die "[$mode] lldap_set_password failed: $(cat "$WORKDIR/$mode-set-pwd.log")"

  log "[$mode] Sanity bind to baseline with the new credential"
  ldapsearch -LLL -H "ldap://localhost:$ldap_port" \
    -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "$TEST_PASSWORD" \
    -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
    >"$WORKDIR/$mode-baseline-bind.log" 2>&1 || \
    die "[$mode] baseline bind failed: $(cat "$WORKDIR/$mode-baseline-bind.log")"
  grep -q "uid=$TEST_USER" "$WORKDIR/$mode-baseline-bind.log" || \
    die "[$mode] baseline bind did not return the user dn"

  log "[$mode] Stopping baseline lldap"
  kill "$RUNNING_PID"
  wait "$RUNNING_PID" 2>/dev/null || true
  RUNNING_PID=""

  # --- Phase 2: HEAD upgrades the key automatically and serves --------------
  # No flag, no extra restart: HEAD must detect the opaque-ke 0.7 key
  # (positively, by parsing it) and confirm against the DB-stored key hash
  # that it is the key from the last successful startup.
  if [ "$mode" = "file" ]; then
    cp "$key_file" "$WORKDIR/$mode-original-key"
  fi
  log "[$mode] Starting HEAD lldap directly (no flag, no extra restart)"
  ( cd "$REPO_ROOT" && exec "$HEAD_LLDAP" run >"$WORKDIR/$mode-head.log" 2>&1 ) &
  RUNNING_PID=$!
  wait_for_http "head($mode)" "$RUNNING_PID" "$WORKDIR/$mode-head.log" "$http_port"
  log "[$mode] HEAD is ready"

  grep -q "Detected the opaque-ke 0.7 -> 4.0 upgrade" "$WORKDIR/$mode-head.log" || {
    tail -40 "$WORKDIR/$mode-head.log" >&2
    die "[$mode] HEAD did not report the automatic opaque-ke upgrade"
  }
  if [ "$mode" = "file" ]; then
    [ -f "$key_file.v07" ] || die "[$mode] HEAD did not write the v0.7 sidecar"
    cmp -s "$key_file.v07" "$WORKDIR/$mode-original-key" || \
      die "[$mode] v0.7 sidecar does not hold the original key"
    cmp -s "$key_file" "$WORKDIR/$mode-original-key" && \
      die "[$mode] key file was not rotated to the 4.0 format"
    log "[$mode] Key file rotated to opaque-ke 4.0 + sidecar written ✓"
  else
    # Seed mode derives the key from the seed: no file is written and no
    # sidecar is created — the v0.7 key is reconstructed in memory each start.
    [ ! -f "$key_file" ] || die "[$mode] seed mode unexpectedly wrote a key file"
    [ ! -f "$key_file.v07" ] || die "[$mode] seed mode unexpectedly wrote a v0.7 sidecar"
    log "[$mode] Key change accepted from seed; no file, no sidecar ✓"
  fi

  log "[$mode] Confirming v12 migration added users.password_version"
  [ "$(pv_count "$db_path")" = "1" ] || die "[$mode] HEAD did not add password_version column"

  local pre_version
  pre_version=$(pv_value "$db_path")
  [ "$pre_version" = "0" ] || die "[$mode] expected pre-bind password_version=0, got '$pre_version'"
  log "[$mode] Pre-bind password_version = 0 (legacy) ✓"

  log "[$mode] First bind against HEAD — should succeed AND auto-upgrade to v4.0"
  ldapsearch -LLL -H "ldap://localhost:$ldap_port" \
    -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "$TEST_PASSWORD" \
    -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
    >"$WORKDIR/$mode-head-bind1.log" 2>&1 || {
      cat "$WORKDIR/$mode-head-bind1.log" >&2
      tail -40 "$WORKDIR/$mode-head.log" >&2
      die "[$mode] HEAD bind with legacy credential failed"
    }
  grep -q "uid=$TEST_USER" "$WORKDIR/$mode-head-bind1.log" || \
    die "[$mode] HEAD bind did not return the user dn"

  local post_version
  post_version=$(pv_value "$db_path")
  [ "$post_version" = "1" ] || \
    die "[$mode] expected post-bind password_version=1, got '$post_version'"
  log "[$mode] Post-bind password_version = 1 (v4.0) ✓ — credential upgraded"

  log "[$mode] Second bind against the upgraded credential"
  ldapsearch -LLL -H "ldap://localhost:$ldap_port" \
    -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "$TEST_PASSWORD" \
    -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
    >"$WORKDIR/$mode-head-bind2.log" 2>&1 || \
    die "[$mode] second HEAD bind failed: $(cat "$WORKDIR/$mode-head-bind2.log")"
  grep -q "uid=$TEST_USER" "$WORKDIR/$mode-head-bind2.log" || \
    die "[$mode] second HEAD bind did not return the user dn"
  log "[$mode] Second bind succeeded ✓"

  log "[$mode] Wrong password should be rejected"
  if ldapsearch -LLL -H "ldap://localhost:$ldap_port" \
       -D "uid=$TEST_USER,ou=people,$LDAP_BASE_DN" -w "definitely-not-the-password" \
       -b "ou=people,$LDAP_BASE_DN" "(uid=$TEST_USER)" dn \
       >/dev/null 2>&1; then
    die "[$mode] wrong password unexpectedly succeeded"
  fi
  log "[$mode] Wrong password rejected ✓"

  log "[$mode] Stopping HEAD lldap"
  kill "$RUNNING_PID"
  wait "$RUNNING_PID" 2>/dev/null || true
  RUNNING_PID=""

  log "[$mode] Variant PASSED ✓"
}

run_variant file "$LDAP_PORT" "$HTTP_PORT"
run_variant seed "$((LDAP_PORT + 1))" "$((HTTP_PORT + 1))"

log "ALL CHECKS PASSED — opaque-ke 4.0 upgrade works end-to-end (file + seed)"
