#!/usr/bin/env bash
# Real-process smoke test: Compose PostgreSQL, the migration entry point, Uvicorn and HTTP.
#
# Safe to run beside anything else: it uses its own Compose project, a free database port and
# a free app port, generates passwords for this run only, and removes all of it on any exit.
# Exit codes: 0 passed, 1 a check failed, 2 prerequisites missing.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

STEP_TIMEOUT=${SMOKE_STEP_TIMEOUT:-60}
TOTAL_TIMEOUT=${SMOKE_TOTAL_TIMEOUT:-180}
HTTP_TIMEOUT=8

export COMPOSE_PROJECT_NAME="shiptrace-smoke-$$"
export COMPOSE_FILE=compose.yaml # Names it exactly, so that no override file can merge in.
step="prerequisites"
app_pid=""
watchdog=""
app_log=$(mktemp)
compose_up=false

log() { printf '[smoke] %s\n' "$*"; }

scrub() {
  sed -e "s/${SHIPTRACE_ADMIN_PASSWORD:-__none__}/[redacted]/g" \
    -e "s/${SHIPTRACE_APP_PASSWORD:-__none__}/[redacted]/g" \
    -e "s/${SHIPTRACE_MIGRATOR_PASSWORD:-__none__}/[redacted]/g"
}

cleanup() {
  local status=$?
  trap '' INT TERM # A second interrupt must not skip cleanup.
  trap - EXIT
  [[ -n $watchdog ]] && kill "$watchdog" 2>/dev/null
  if [[ -n $app_pid ]] && kill -0 "$app_pid" 2>/dev/null; then
    kill -TERM "$app_pid" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$app_pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$app_pid" 2>/dev/null
  fi
  if $compose_up; then
    timeout 60 docker compose down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1 ||
      log "WARNING: cleanup failed; run: docker compose -p $COMPOSE_PROJECT_NAME down -v"
  fi
  rm -f "$app_log"
  exit "$status"
}
trap cleanup EXIT
trap 'log "interrupted during: $step"; exit 130' INT TERM

fail() {
  log "FAILED during: $step"
  log "reason: $*"
  if [[ -s $app_log ]]; then
    log "last application output:"
    tail -20 "$app_log" | scrub | sed 's/^/    /'
  fi
  if $compose_up; then
    log "last database output:"
    timeout 15 docker compose logs --tail 10 postgres 2>&1 | scrub | sed 's/^/    /'
  fi
  exit 1
}

require() {
  command -v "$1" >/dev/null || { log "missing prerequisite: $1"; exit 2; }
}

free_port() {
  python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

http_code() { curl -s -o /dev/null -m "$HTTP_TIMEOUT" -w '%{http_code}' "http://127.0.0.1:$app_port$1"; }

expect() { # path expected-code label
  local actual
  actual=$(http_code "$1")
  [[ $actual == "$2" ]] || fail "$3: GET $1 returned $actual, expected $2"
  log "ok  $3: GET $1 -> $actual"
}

wait_for() { # path expected-code label
  local deadline=$((SECONDS + STEP_TIMEOUT))
  while ((SECONDS < deadline)); do
    [[ $(http_code "$1") == "$2" ]] && { log "ok  $3: GET $1 -> $2"; return 0; }
    kill -0 "$app_pid" 2>/dev/null || fail "$3: the application exited"
    sleep 0.2
  done
  fail "$3: GET $1 never returned $2 within ${STEP_TIMEOUT}s (last: $(http_code "$1"))"
}

for tool in docker uv curl python3 timeout; do require "$tool"; done
timeout 10 docker info >/dev/null 2>&1 || { log "docker daemon is not reachable"; exit 2; }

# Polls so that it dies with this script, and closes stdout so it can never hold a pipe open.
(
  exec >/dev/null 2>&1
  deadline=$((SECONDS + TOTAL_TIMEOUT))
  while ((SECONDS < deadline)); do
    kill -0 $$ || exit 0
    sleep 1
  done
  kill -TERM $$
) &
watchdog=$!

SHIPTRACE_ADMIN_PASSWORD=$(python3 -I -c 'import secrets; print(secrets.token_hex(16))')
SHIPTRACE_APP_PASSWORD=$(python3 -I -c 'import secrets; print(secrets.token_hex(16))')
SHIPTRACE_MIGRATOR_PASSWORD=$(python3 -I -c 'import secrets; print(secrets.token_hex(16))')
export SHIPTRACE_ADMIN_PASSWORD SHIPTRACE_APP_PASSWORD SHIPTRACE_MIGRATOR_PASSWORD
app_port=$(free_port)
export SHIPTRACE_ENVIRONMENT=local
export SHIPTRACE_READINESS_CACHE_SECONDS=0

step="install locked dependencies"
log "$step"
timeout "$STEP_TIMEOUT" uv sync --frozen --quiet >"$app_log" 2>&1 || fail "uv sync failed"

step="start PostgreSQL through Compose"
log "$step"
compose_up=true
# A port chosen here can still be refused: Docker Desktop binds it on Windows, where it may be
# reserved. Only that specific refusal is retried.
for attempt in 1 2 3 4 5; do
  SHIPTRACE_DB_PORT=$(free_port)
  export SHIPTRACE_DB_PORT
  timeout "$STEP_TIMEOUT" docker compose up --detach --wait --quiet-pull >/dev/null 2>"$app_log" && break
  if grep -q 'ports are not available' "$app_log" && ((attempt < 5)); then
    log "database port $SHIPTRACE_DB_PORT refused, retrying"
    timeout 60 docker compose down --volumes --timeout 5 >/dev/null 2>&1
    continue
  fi
  fail "docker compose up did not become healthy within ${STEP_TIMEOUT}s"
done
: >"$app_log"

driver=postgresql+psycopg
host="127.0.0.1:$SHIPTRACE_DB_PORT"
export SHIPTRACE_DATABASE_URL="$driver://shiptrace_app:$SHIPTRACE_APP_PASSWORD@$host/shiptrace"
export SHIPTRACE_MIGRATOR_DATABASE_URL="$driver://shiptrace_migrator:$SHIPTRACE_MIGRATOR_PASSWORD@$host/shiptrace"

step="start Uvicorn before migrations"
log "$step"
# The venv's Uvicorn directly, not through `uv run`, so that signals and app_pid reach it.
.venv/bin/uvicorn --factory shiptrace.bootstrap.app:create_app \
  --host 127.0.0.1 --port "$app_port" --timeout-graceful-shutdown 20 --log-level info \
  >>"$app_log" 2>&1 &
app_pid=$!
wait_for /healthz 200 "liveness comes up without a schema"
expect /readyz 503 "readiness refuses an unmigrated database"

step="run migrations"
log "$step"
timeout "$STEP_TIMEOUT" uv run --frozen shiptrace-migrate >>"$app_log" 2>&1 || fail "shiptrace-migrate failed"
wait_for /readyz 200 "readiness follows the migration"
timeout "$STEP_TIMEOUT" uv run --frozen shiptrace-migrate >>"$app_log" 2>&1 || fail "second migrate failed"
expect /readyz 200 "migrating twice changes nothing"

step="interrupt the database"
log "$step"
timeout "$STEP_TIMEOUT" docker compose stop --timeout 5 postgres >/dev/null 2>&1 || fail "could not stop PostgreSQL"
wait_for /readyz 503 "readiness reports the outage"
expect /healthz 200 "liveness survives the outage"

step="recover the database"
log "$step"
timeout "$STEP_TIMEOUT" docker compose start --wait postgres >/dev/null 2>&1 || fail "could not restart PostgreSQL"
wait_for /readyz 200 "readiness recovers without an app restart"
kill -0 "$app_pid" 2>/dev/null || fail "the application exited during the outage"

step="graceful shutdown"
log "$step"
kill -TERM "$app_pid"
for _ in $(seq 1 250); do kill -0 "$app_pid" 2>/dev/null || break; sleep 0.1; done
kill -0 "$app_pid" 2>/dev/null && fail "the application did not exit within 25s of SIGTERM"
wait "$app_pid"
code=$?
app_pid=""
# Uvicorn re-raises SIGTERM after a clean shutdown, so 143 (128 + 15) is the success code.
[[ $code == 143 || $code == 0 ]] || fail "unexpected exit code $code after SIGTERM"
[[ -s $app_log ]] || fail "no application output, so the secret scan below would prove nothing"
log "ok  graceful shutdown: exit code $code"

step="check application output for secrets"
for secret in "$SHIPTRACE_APP_PASSWORD" "$SHIPTRACE_MIGRATOR_PASSWORD" "$SHIPTRACE_ADMIN_PASSWORD"; do
  grep -qF -- "$secret" "$app_log"
  [[ $? == 1 ]] || { log "FAILED: a password reached application output, or the scan failed"; exit 1; }
done
log "ok  no password in application output"

log "PASSED"
