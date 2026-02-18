#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$ROOT/backend" && npm install)
(cd "$ROOT/frontend" && npm install)
echo "Done."
