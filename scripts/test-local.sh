#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${ST_PG_BIN:-}" ]]; then
  if [[ -x /opt/homebrew/opt/postgresql@16/bin/initdb ]]; then
    ST_PG_BIN=/opt/homebrew/opt/postgresql@16/bin
  elif command -v pg_config >/dev/null; then
    ST_PG_BIN="$(pg_config --bindir)"
  else
    printf 'Install PostgreSQL 16+ or set ST_PG_BIN.\n' >&2
    exit 1
  fi
fi
cluster="$(mktemp -d /tmp/st-test.XXXXXX)"
port=54874
cleanup() {
  "$ST_PG_BIN/pg_ctl" -D "$cluster/pg" -m fast stop >/dev/null 2>&1 || true
  rm -rf "$cluster"
}
trap cleanup EXIT
"$ST_PG_BIN/initdb" -D "$cluster/pg" -U st_bootstrap --auth-local=trust --auth-host=scram-sha-256 --no-locale --encoding=UTF8 >/dev/null
"$ST_PG_BIN/pg_ctl" -D "$cluster/pg" -l "$cluster/postgres.log" -o "-k $cluster -c listen_addresses='' -p $port" -w start >/dev/null
"$ST_PG_BIN/psql" -h "$cluster" -p "$port" -U st_bootstrap -d postgres -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE shadowtrace_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
SQL
export ST_TEST_BOOTSTRAP_DSN="host=$cluster port=$port dbname=postgres user=st_bootstrap"
export ST_TEST_APP_DSN="host=$cluster port=$port dbname=postgres user=shadowtrace_app"
uv run --locked pytest "$@"
