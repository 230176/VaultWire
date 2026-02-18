#!/usr/bin/env bash
set -euo pipefail
docker compose exec backend npm test
