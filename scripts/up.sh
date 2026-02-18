#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$ROOT" && docker compose up --build -d && docker compose ps)
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:5000/api/v1/health"
