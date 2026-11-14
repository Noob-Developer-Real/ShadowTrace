#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -d /opt/homebrew/bin ]]; then
  export PATH="/opt/homebrew/bin:$PATH"
fi
if ! command -v uv >/dev/null; then
  printf 'Install uv and PostgreSQL 16 or newer, then run this launcher again. See README.md.\n'
  exit 1
fi
./scripts/demo.sh serve
