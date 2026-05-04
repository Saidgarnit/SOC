#!/bin/bash
# ================================================================
#  start-soc.sh — Unified SOC Stack Startup Script
#  Run once after every PC reboot: bash ~/soc-stack/start-soc.sh
# ================================================================
set -uo pipefail
# Wait for Docker Desktop to be ready
echo "Waiting for Docker..."
for i in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
docker info >/dev/null 2>&1 || { echo "Docker not ready after 60s — open Docker Desktop first"; exit 1; }
cd ~/soc-stack

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()   { echo -e "${GREEN}[✔]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
title() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

# Helper: wait for a URL to respond with optional grep pattern
wait_for_url() {
  local label="$1" url="$2" pattern="${3:-}" auth="${4:-}" retries="${5:-24}" interval="${6:-5}"
  local curl_opts=(-sf --connect-timeout 5)
  [ -n "$auth" ] && curl_opts+=(-u "$auth")
  for i in $(seq 1 "$retries"); do
    if [ -n "$pattern" ]; then
      curl "${curl_opts[@]}" "$url" 2>/dev/null | grep -q "$pattern" && { echo ""; log "$label ready"; return 0; }
    else
      curl "${curl_opts[@]}" "$url" > /dev/null 2>&1 && { echo ""; log "$label ready"; return 0; }
    fi
    echo -n "."; sleep "$interval"
  done
  echo ""
  warn "$label did not become ready after $((retries * interval))s — continuing"
}

PASS="sYVfKJCe2RCfELjf=GLa"
FLEET_TOKEN="RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw=="
VICTIMS=(victim-ubuntu victim-dvwa victim-iot victim-mail victim-database victim-dns victim-jenkins victim-windows victim-ftp victim-webapi victim-metasploitable)
FLEET_AGENTS=(victim-ubuntu victim-dvwa victim-iot victim-mail victim-database victim-dns victim-jenkins victim-windows victim-ftp victim-webapi)

title "STEP 1 — Wazuh log directories"
YEAR=$(date +%Y); MONTH=$(date +%b)
BASE=~/soc-stack/wazuh/logs
sudo mkdir -p $BASE/alerts/$YEAR/$MONTH $BASE/archives/$YEAR/$MONTH $BASE/firewall/$YEAR/$MONTH
sudo touch $BASE/active-responses.log 2>/dev/null || true
sudo chown -R 101:101 $BASE/alerts $BASE/archives $BASE/firewall 2>/dev/null || true
sudo chmod -R 775 $BASE/alerts $BASE/archives $BASE/firewall 2>/dev/null || true
log "Wazuh dirs ready"

title "STEP 2 — Starting main SOC stack"
docker compose -f docker-compose.yml up -d
log "Main stack started"

title "STEP 2b — Auto-fix Suricata interface"
bash ~/soc-stack/update-suricata-iface.sh
log "Suricata interface updated"

title "STEP 3 — Waiting for Elasticsearch"
for i in $(seq 1 36); do
    curl -sf -u elastic:"$PASS" http://localhost:9200/_cluster/health 2>/dev/null | grep -q 'green\|yellow' && break
    echo -n "."; sleep 5
done; echo ""; log "Elasticsearch ready"

title "STEP 4 — Waiting for Fleet Server"
for i in $(seq 1 24); do
    curl -sf http://localhost:8220/api/status 2>/dev/null | grep -q "HEALTHY" && break
    echo -n "."; sleep 5
done; echo ""; log "Fleet Server ready"

title "STEP 4b — Fix Fleet Server Hosts URL (HTTP)"
for i in $(seq 1 12); do curl -sf -u elastic:"$PASS" "http://localhost:5601/api/status" 2>/dev/null | grep -q "available" && break; sleep 5; done
curl -s -u elastic:"$PASS" -X PUT "http://localhost:5601/api/fleet/fleet_server_hosts/69090aca-4691-4427-8077-a5529a5d77ee" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d '{"name":"soc-fleet","host_urls":["http://fleet-server:8220"],"is_default":true}' > /dev/null 2>&1
curl -s -u elastic:"$PASS" -X PUT "http://localhost:5601/api/fleet/settings" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d '{"fleet_server_hosts":["http://fleet-server:8220"]}' > /dev/null 2>&1
log "Fleet Server Hosts forced to HTTP"

title "STEP 5 — Starting victim lab"
docker compose -f docker-compose-lab.yml up -d
log "Victim lab started — waiting 40s..."
# Fix MySQL bind address so it accepts remote connections
docker exec victim-database bash -c "sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null; service mysql restart > /dev/null 2>&1" 2>/dev/null && echo -e '\033[0;32m[✔]\033[0m MySQL bind fixed' || true

sleep 40

title "STEP 6 — Fixing Wazuh agents"
cat > /tmp/wazuh-fix.sh << 'WAZUH_EOF'
#!/bin/bash
exec >> /tmp/wazuh-fix.log 2>&1
echo "=== $(hostname) $(date) ==="
mkdir -p /var/ossec/queue/sockets
if [ ! -s /var/ossec/etc/client.keys ]; then
    /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A "$(hostname)" 2>&1 | grep -E 'Valid|ERROR'
fi
pkill -f wazuh-modulesd 2>/dev/null; sleep 1
/var/ossec/bin/wazuh-modulesd &
sleep 3
pkill -f wazuh-agentd 2>/dev/null; sleep 1
/var/ossec/bin/wazuh-agentd
sleep 5
PID=$(cat /var/ossec/var/run/wazuh-agentd*.pid 2>/dev/null | head -1)
[ -n "$PID" ] && kill -HUP "$PID" 2>/dev/null && echo "HUP sent pid=$PID"
WAZUH_EOF

docker exec wazuh-manager bash -c "
    /var/ossec/bin/agent_control -l | grep -E 'Disconnected|Never connected' | \
    awk '{print \$2}' | tr -d ',' | while read ID; do
        [ \"\$ID\" = '000' ] && continue
        echo y | /var/ossec/bin/manage_agents -r \$ID 2>/dev/null && echo \"Removed stale \$ID\"
    done" 2>/dev/null

for C in "${VICTIMS[@]}"; do
    docker ps --format '{{.Names}}' | grep -q "^${C}$" || continue
    docker cp /tmp/wazuh-fix.sh $C:/tmp/wazuh-fix.sh 2>/dev/null
    docker exec $C bash /tmp/wazuh-fix.sh 2>/dev/null && echo -n "." || echo -n "x"
done; echo ""; log "Wazuh agents fixed"

title "STEP 7 — Cleaning ghost Fleet agents"
# Deletes all offline/duplicate agents via Kibana Fleet API before victims enroll.
# Victims use smart entrypoints that check online status before enrolling.
bash /home/said/soc-stack/fix-on-start.sh
log "Fleet cleanup done"

title "STEP 8 — Cleaning ghost Wazuh agents"
sleep 20
docker exec wazuh-manager bash -c "
    /var/ossec/bin/agent_control -l | grep -E 'windows-pc|Never connected' | grep -v 'victim-windows' | \
    awk '{print \$2}' | tr -d ',' | while read ID; do
        echo y | /var/ossec/bin/manage_agents -r \$ID 2>/dev/null && echo \"Removed ghost: \$ID\"
    done" 2>/dev/null || true
log "Wazuh ghost cleanup done"

title "STEP 9 — Filebeat + OpenCTI"
docker exec filebeat sh -c "rm -rf /usr/share/filebeat/data/registry" 2>/dev/null \
    && docker restart filebeat > /dev/null 2>&1 && log "Filebeat reset" || warn "Filebeat skip"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/graphql 2>/dev/null)
[[ "$STATUS" =~ ^(200|400)$ ]] && \
    docker restart connector-misp connector-mitre opencti-worker > /dev/null 2>&1 \
    && log "OpenCTI connectors restarted" || warn "OpenCTI not ready yet"

title "STEP 10 — Fleet agent final status"
sleep 30
curl -s -u elastic:"$PASS" "http://localhost:5601/api/fleet/agents?perPage=20" \
  -H "kbn-xsrf: true" 2>/dev/null | python3 -c "
import sys,json
agents=json.load(sys.stdin).get('items',[])
for a in agents:
    host=a.get('local_metadata',{}).get('host',{}).get('hostname','?')
    print(f'  {a.get("status","?"):10} {host}')
" 2>/dev/null
log "Fleet status shown"

title "STEP 11 — Final Health Check"
echo ""
chk() {
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 "$2" 2>/dev/null)
    [[ "$CODE" =~ ^(200|302|301)$ ]] \
        && printf "  %-22s ${GREEN}UP${NC}\n" "$1" \
        || printf "  %-22s ${RED}DOWN${NC} ($CODE)\n" "$1"
}
chk "Kibana"         "http://localhost:5601"
chk "Fleet"          "http://localhost:8220/api/status"
chk "DVWA"           "http://localhost:8890"
chk "bWAPP"          "http://localhost:8892"
chk "Jenkins"        "http://localhost:9090/login"
chk "MISP"           "http://localhost:9001"
chk "OpenCTI"        "http://localhost:3000"
chk "Metasploitable" "http://localhost:8889"
chk "IoT-API"        "http://localhost:8891"

echo ""
echo -e "${BLUE}━━━ Wazuh Agents ━━━${NC}"
docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -v "^$\|^List\|^Wazuh"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     SOC Stack is Ready! 🚀           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Kibana  → http://localhost:5601     ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  DVWA    → http://localhost:8890     ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  OpenCTI → http://localhost:3000     ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  MISP    → http://localhost:9001     ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}  Jenkins → http://localhost:9090     ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"


echo ""
echo "━━━ STEP 12 — Enrolling Wazuh agents ━━━"

# Clean stale PID files before restart
for c in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-jenkins victim-database victim-dns victim-webapi victim-ftp; do
  docker exec $c bash -c "rm -f /var/ossec/var/run/wazuh-agentd-*.pid" 2>/dev/null
done

# Copy ossec.conf into wazuh-manager (bind mount unreliable in WSL2)
docker cp ~/soc-stack/wazuh/ossec.conf wazuh-manager:/tmp/ossec_new.conf 2>/dev/null
docker exec wazuh-manager bash -c "cp /tmp/ossec_new.conf /var/ossec/etc/ossec.conf && chown root:wazuh /var/ossec/etc/ossec.conf && chmod 640 /var/ossec/etc/ossec.conf" 2>/dev/null


docker restart wazuh-manager
sleep 20

for c in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-jenkins victim-database victim-dns victim-webapi victim-ftp; do
  docker exec $c bash -c "
    pkill -9 -f wazuh-agentd 2>/dev/null
    rm -f /var/ossec/etc/client.keys
    /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A \$(hostname) 2>&1 | grep -E 'Valid|ERROR'
  " 2>/dev/null
  docker exec -d $c /var/ossec/bin/wazuh-agentd
  sleep 6
done

sleep 20

for c in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-jenkins victim-database victim-dns victim-webapi victim-ftp; do
  docker exec -d $c /var/ossec/bin/wazuh-logcollector 2>/dev/null
done

echo "[✔] Wazuh agents enrolled"
docker exec wazuh-manager /var/ossec/bin/agent_control -l | grep -v agentless

# Add auth.log monitoring to all agent ossec.conf files
echo "Adding auth.log monitoring to agents..."
for c in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-jenkins victim-database victim-dns victim-webapi victim-ftp; do
  docker exec $c bash -c "grep -q 'auth.log' /var/ossec/etc/ossec.conf || sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n</ossec_config>|' /var/ossec/etc/ossec.conf" 2>/dev/null
  docker exec $c bash -c "pkill -f wazuh-logcollector 2>/dev/null; sleep 1; /var/ossec/bin/wazuh-logcollector &" 2>/dev/null
done
echo "[✔] Auth.log monitoring added to all agents"

# Fix victim-ftp auth log (CentOS uses /var/log/secure):
docker exec victim-ftp bash -c "
grep -q 'var/log/secure' /var/ossec/etc/ossec.conf || \
sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/secure</location>\n  </localfile>\n</ossec_config>|' /var/ossec/etc/ossec.conf
pkill -f wazuh-logcollector 2>/dev/null; sleep 1; /var/ossec/bin/wazuh-logcollector &
" 2>/dev/null

# Trigger automated fixes
bash /home/said/soc-stack/fix-on-start.sh
bash ~/soc-stack/soc-fix.sh

# ── PERMANENT FIXES (added $(date +%Y-%m-%d)) ──────────────────────────────

title "PERM-FIX 1 — Emergency swap (idempotent)"
if ! swapon --show | grep -q swapfile2; then
  sudo fallocate -l 4G /swapfile2 2>/dev/null || true
  sudo chmod 600 /swapfile2 2>/dev/null || true
  sudo mkswap /swapfile2 2>/dev/null || true
  sudo swapon /swapfile2 && log "Swap /swapfile2 activated" || warn "Swap already active"
else
  log "Swap /swapfile2 already active"
fi

title "PERM-FIX 2 — Runtime memory caps"
docker update --memory=1g    --memory-swap=1g    wazuh-manager  2>/dev/null && log "wazuh-manager capped"
docker update --memory=512m  --memory-swap=512m  fleet-server   2>/dev/null
docker update --memory=512m  --memory-swap=512m  rabbitmq       2>/dev/null
docker update --memory=256m  --memory-swap=256m  filebeat       2>/dev/null
docker update --memory=256m  --memory-swap=256m  minio          2>/dev/null
docker update --memory=256m  --memory-swap=256m  kali-attacker  2>/dev/null
docker update --memory=128m  --memory-swap=128m  yara-scanner vt-enricher \
  connector-misp connector-mitre opencti-redis misp-redis memcached 2>/dev/null
log "Memory caps applied"

title "PERM-FIX 3 — Wazuh index template"
for i in $(seq 1 12); do
  curl -sf -u elastic:"$PASS" http://localhost:9200/_cluster/health | grep -q '"status":"green"\|"status":"yellow"' && break
  sleep 5
done
curl -s -u elastic:"$PASS" \
  -X PUT "http://localhost:9200/_index_template/wazuh-alerts" \
  -H "Content-Type: application/json" -d '{
  "index_patterns":["wazuh-alerts-4.x-*"],
  "template":{
    "settings":{"number_of_shards":1,"number_of_replicas":0},
    "mappings":{"dynamic":true}
  }
}' | grep -q "acknowledged" && log "Wazuh index template loaded" || warn "Template load failed"

title "PERM-FIX 4 — Fix unassigned shards"
curl -s -u elastic:"$PASS" \
  -X POST "http://localhost:9200/_cluster/reroute?retry_failed=true" \
  -H "Content-Type: application/json" > /dev/null
log "Shard reroute triggered"


# ── PERM-FIX 5 — Force-start containers that exit 127 on WSL2 boot ──
title "PERM-FIX 5 — Restart WSL2-sensitive containers"
sleep 10
for c in wazuh-manager suricata kibana filebeat elastalert; do
  STATE=$(docker inspect $c --format '{{.State.Status}}' 2>/dev/null)
  if [ "$STATE" != "running" ]; then
    echo "  Restarting $c (was: $STATE)..."
    docker start $c 2>/dev/null && echo "  ✅ $c started" || echo "  ⚠ $c failed"
  else
    echo "  ✅ $c already running"
  fi
done
sleep 20
log "WSL2-sensitive containers recovered"

# ── PERM-FIX 6 — Force-recreate WSL2 bind-mount containers (stale UUID fix) ──
title "PERM-FIX 6 — Recreate bind-mount sensitive containers"
for c in suricata wazuh-manager kibana filebeat elastalert; do
  STATE=$(docker inspect $c --format '{{.State.Status}}' 2>/dev/null)
  if [ "$STATE" != "running" ]; then
    echo "  Force-recreating $c (WSL2 bind-mount stale)..."
    docker compose -f ~/soc-stack/docker-compose.yml up -d \
      --no-deps --force-recreate $c 2>/dev/null && \
      echo "  ✅ $c recreated" || echo "  ⚠ $c failed"
  else
    echo "  ✅ $c running"
  fi
done
sleep 15
log "Bind-mount containers recovered"

# ── PERM-FIX 7 — Reset logstash sincedb so suricata alerts re-index on boot ──
title "PERM-FIX 7 — Logstash sincedb reset for eve.json"
docker exec logstash bash -c "
  grep -v 'eve.json' /usr/share/logstash/data/sincedb > /tmp/sincedb_new 2>/dev/null || true
  cp /tmp/sincedb_new /usr/share/logstash/data/sincedb
" 2>/dev/null && log "Logstash sincedb reset" || warn "Logstash sincedb reset failed"
docker restart logstash > /dev/null 2>&1
sleep 5

# EA-4 Permanent Fix — DVWA MariaDB auto-init
bash ~/soc-stack/dvwa-db-init.sh &

# ATK-6 Permanent Fix — metasploitable syslog forwarder
bash ~/soc-stack/metasploitable-syslog.sh &
