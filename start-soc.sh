#!/bin/bash
# ================================================================
#  start-soc.sh — SOC Stack Startup (IaC hardened)
# ================================================================
set -uo pipefail

STACK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ELASTIC_USERNAME="${ELASTIC_USERNAME:-elastic}"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"
KIBANA_PUBLIC_URL="${KIBANA_PUBLIC_URL:-https://localhost:5601}"
FLEET_URL="${FLEET_URL:-https://localhost:8220}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()   { echo -e "${GREEN}[✔]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
title() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

# Wait for Docker Desktop to be ready
title "STEP 1 — Wait for Docker"
for i in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
if ! docker info >/dev/null 2>&1; then
  err "Docker not ready after 60s — start Docker and retry"
  exit 1
fi

cd "$STACK_ROOT"

# Start core SOC stack
title "STEP 2 — Starting core SOC stack"
docker compose -f docker-compose.yml up -d
log "Core stack started"

# Start victim lab stack (optional)
title "STEP 3 — Starting victim lab stack"
docker compose -f docker-compose-lab.yml up -d
log "Victim lab started"

# Display basic health snapshot
title "STEP 4 — Stack status"
docker compose -f docker-compose.yml ps

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  Kibana  → ${KIBANA_PUBLIC_URL}     ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Fleet   → ${FLEET_URL}             ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Elastic → ${ELASTIC_USERNAME}@${ELASTIC_PASSWORD:+******} ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
