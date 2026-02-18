#!/usr/bin/env bash
set -euo pipefail
API_URL="${API_URL:-http://localhost:5000/api/v1}"
curl -s "$API_URL/health" | sed 's/.*/HEALTH: &/'
