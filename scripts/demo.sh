#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v uv >/dev/null; then
  printf 'Install uv and Python 3.12, then run this command again.\n' >&2
  exit 1
fi
exec uv run --locked --no-dev python -m scripts.demo "$@"
