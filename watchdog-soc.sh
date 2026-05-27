#!/bin/bash
# SOC Watchdog v4.2 — no python3 dependency on agents, recent-errors only
LOG="/home/said/soc-stack/watchdog.log"
KEY_BACKUP="/home/said/soc-stack/.wazuh-agent-keys.bak"
WAZUH_API="https://localhost:55000"
WAZUH_USER="wazuh"; WAZUH_PASS="Wazuh1234!"
ES_PASS="Kjd9r43ANUymjjcba0M6"
SOC_DIR="/home/said/soc-stack"
TS=$(date '+%Y-%m-%d %H:%M:%S')
log() { echo "[$TS] $*" | tee -a "$LOG"; }

declare -A AGENT_IDS=(
  [victim-ubuntu]="019" [victim-jenkins]="014" [victim-database]="012"
  [victim-dvwa]="018"   [victim-dns]="011"     [victim-mail]="013"
  [victim-windows]="016" [victim-ftp]="015"    [victim-iot]="017"
  [victim-webapi]="022"
)

log "=== Watchdog v4.2 ==="

# 1. Containers up
for V in "${!AGENT_IDS[@]}"; do
  STATUS=$(docker inspect --format='{{.State.Status}}' "$V" 2>/dev/null || echo "missing")
  if [ "$STATUS" != "running" ]; then
    log "RESTART $V (was: $STATUS)"
    cd "$SOC_DIR" && docker compose -f docker-compose-lab.yml up -d "$V" >>"$LOG" 2>&1
    sleep 10
  fi
done

# 2. Clean stale DB entries via Python3 on manager (manager always has python3)
STALE=$(docker exec wazuh-manager python3 - 2>/dev/null <<'PY'
import sqlite3
c = sqlite3.connect('/var/ossec/var/db/global.db')
n = c.execute("SELECT COUNT(*) FROM agent WHERE id BETWEEN 1 AND 10").fetchone()[0]
if n > 0:
    c.execute("DELETE FROM agent WHERE id BETWEEN 1 AND 10")
    c.commit()
print(n)
c.close()
PY
)
STALE=$((${STALE:-0} + 0))
if [ "$STALE" -gt 0 ]; then
  log "Removed $STALE stale DB entries"
  docker exec wazuh-manager bash -c \
    "grep -v '^[0-9]* !' /var/ossec/etc/client.keys > /tmp/ck && cp /tmp/ck /var/ossec/etc/client.keys"
  PID=$(docker exec wazuh-manager bash -c "cat /var/ossec/var/run/wazuh-remoted*.pid 2>/dev/null | head -1")
  [ -n "$PID" ] && docker exec wazuh-manager kill -HUP "$PID" 2>/dev/null && sleep 3
fi

# 3. Backup keys
docker exec wazuh-manager grep -v '^[0-9]* !' /var/ossec/etc/client.keys \
  2>/dev/null > "$KEY_BACKUP"
log "Keys backed up ($(wc -l < "$KEY_BACKUP") entries)"

# 4. Fix victims — use pgrep (universal) and check only LAST 5 log lines for errors
for V in "${!AGENT_IDS[@]}"; do
  # pgrep works on all containers; fallback to 1 if not available (assume running)
  PROC=$(docker exec "$V" sh -c "pgrep wazuh-agentd | wc -l" 2>/dev/null || echo "1")
  PROC=$((PROC + 0))

  # Only check last 5 log lines to avoid historical error count triggering fixes
  ERR=$(docker exec "$V" sh -c \
    "tail -5 /var/ossec/logs/ossec.log 2>/dev/null | grep -c 'Unable to add agent\|Duplicate agent'" \
    2>/dev/null || echo "0")
  ERR=$(echo "${ERR}" | head -1 | tr -dc "0-9"); ERR=$((${ERR:-0} + 0))

  if [ "$PROC" -eq 0 ] || [ "$ERR" -gt 0 ]; then
    log "FIXING $V (agentd=$PROC recent_errors=$ERR)"
    KEY=$(docker exec wazuh-manager grep " ${V} " /var/ossec/etc/client.keys 2>/dev/null | grep -v '!')
    [ -z "$KEY" ] && KEY=$(grep " ${V} " "$KEY_BACKUP" 2>/dev/null | grep -v '!')
    if [ -z "$KEY" ]; then log "  No key for $V — skip"; continue; fi
    docker exec "$V" /var/ossec/bin/wazuh-control stop >>"$LOG" 2>&1 || true
    sleep 1
    docker exec "$V" sh -c "kill -9 \$(pgrep wazuh-agentd) 2>/dev/null; true"
    docker exec "$V" sh -c "echo '${KEY}' > /var/ossec/etc/client.keys; chmod 640 /var/ossec/etc/client.keys"
    docker exec "$V" /var/ossec/bin/wazuh-control start >>"$LOG" 2>&1
    sleep 3
    P2=$(docker exec "$V" sh -c "pgrep wazuh-agentd | wc -l" 2>/dev/null || echo "?")
    log "  $V fixed — agentd count: $P2"
  fi
done

# 5. Fleet-server
FS=$(docker inspect --format='{{.State.Status}}' fleet-server 2>/dev/null || echo "missing")
if [ "$FS" != "running" ]; then
  log "Restarting fleet-server"
  cd "$SOC_DIR" && docker compose -f docker-compose-lab.yml up -d fleet-server >>"$LOG" 2>&1
  sleep 15
fi

# 6. Summary
TOKEN=$(curl -sk -u "${WAZUH_USER}:${WAZUH_PASS}" \
  "${WAZUH_API}/security/user/authenticate?raw=true" 2>/dev/null)
W_ACTIVE=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "${WAZUH_API}/agents?q=id!=000&limit=50" 2>/dev/null | \
  python3 -c "
import sys,json
a=json.load(sys.stdin).get('data',{}).get('affected_items',[])
print(len([x for x in a if x.get('status')=='active']))
" 2>/dev/null || echo "?")
F_ONLINE=$(curl -sk -u "elastic:${ES_PASS}" \
  'http://localhost:9200/.fleet-agents-7/_count' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"active":true}}}' 2>/dev/null | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
log "SUMMARY — Wazuh: ${W_ACTIVE}/10 | Fleet: ${F_ONLINE}/11"
log "=== done ==="
