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
title() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

PASS="SOCstack2026!"
FLEET_TOKEN="RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw=="
VICTIMS=(victim-ubuntu victim-dvwa victim-iot victim-mail victim-database victim-dns victim-jenkins victim-windows)

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
python3 /home/said/soc-stack/fix-on-start.sh
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

# Copy ossec.conf into container (WSL2 bind mount unreliable)
docker cp ~/soc-stack/wazuh/ossec.conf wazuh-manager:/tmp/ossec_new.conf 2>/dev/null
docker exec wazuh-manager bash -c "cp /tmp/ossec_new.conf /var/ossec/etc/ossec.conf && chown root:wazuh /var/ossec/etc/ossec.conf && chmod 640 /var/ossec/etc/ossec.conf" 2>/dev/null
echo "ossec.conf copied"

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
  docker exec $c python3 -c "
content = open('/var/ossec/etc/ossec.conf').read()
addition = '  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n'
if '/var/log/auth.log' not in content:
    content = content.replace('</ossec_config>', addition + '</ossec_config>')
    open('/var/ossec/etc/ossec.conf', 'w').write(content)
" 2>/dev/null
  docker exec $c bash -c "pkill -f wazuh-logcollector 2>/dev/null; sleep 1; /var/ossec/bin/wazuh-logcollector &" 2>/dev/null
done
echo "[✔] Auth.log monitoring added to all agents"

# Fix victim-ftp auth log (CentOS uses /var/log/secure):
docker exec victim-ftp bash -c "
grep -q 'var/log/secure' /var/ossec/etc/ossec.conf || \
sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/secure</location>\n  </localfile>\n</ossec_config>|' /var/ossec/etc/ossec.conf
pkill -f wazuh-logcollector 2>/dev/null; sleep 1; /var/ossec/bin/wazuh-logcollector &
" 2>/dev/null
