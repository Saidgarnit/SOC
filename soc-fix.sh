#!/bin/bash
# =============================================================================
# SOC Cyber Range — Permanent Fix & Startup Script
# =============================================================================

ELASTIC_PASS="sYVfKJCe2RCfELjf=GLa"
ES="http://localhost:9200"
AUTH="-u elastic:${ELASTIC_PASS}"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

echo "=== SOC Fix Script Starting ==="

# FIX 1 — ES replica template
echo "▶ FIX 1: Elasticsearch replicas..."
curl -s -X PUT ${AUTH} "${ES}/_template/default_replicas" \
  -H 'Content-Type: application/json' \
  -d '{"index_patterns":["*"],"settings":{"number_of_replicas":0},"order":0}' | grep -q "acknowledged" && ok "Replica template set" || warn "Template failed"

for idx in $(curl -s ${AUTH} "${ES}/_cat/shards?h=index,state" | grep UNASSIGNED | awk '{print $1}' | sort -u); do
  curl -s -X PUT ${AUTH} "${ES}/${idx}/_settings" \
    -H 'Content-Type: application/json' \
    -d '{"index":{"number_of_replicas":0}}' > /dev/null
  ok "Fixed shard: $idx"
done

STATUS=$(curl -s ${AUTH} "${ES}/_cluster/health" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
ok "Elasticsearch: $STATUS"

# FIX 2 — Wazuh manager up check
echo "▶ FIX 2: Wazuh Manager..."
if docker ps --format '{{.Names}}' | grep -q "^wazuh-manager$"; then
  ok "wazuh-manager running"
else
  warn "wazuh-manager DOWN — recreating..."
  docker rm -f wazuh-manager 2>/dev/null || true
  cd ~/soc-stack && docker-compose up -d wazuh-manager
  sleep 20
  ok "wazuh-manager recreated"
fi

# FIX 3 — Filebeat password
echo "▶ FIX 3: Filebeat password..."
CURRENT=$(docker exec wazuh-manager grep "password" /etc/filebeat/filebeat.yml 2>/dev/null | awk '{print $2}' | tr -d '"')
if [ "$CURRENT" != "${ELASTIC_PASS}" ]; then
  docker exec wazuh-manager sed -i "s|password:.*|password: \"${ELASTIC_PASS}\"|" /etc/filebeat/filebeat.yml
  docker exec wazuh-manager pkill -f filebeat 2>/dev/null || true
  ok "Filebeat password fixed"
else
  ok "Filebeat password correct"
fi

# FIX 4 — FIM direct injection into each victim ossec.conf
echo "▶ FIX 4: FIM config injection..."
VICTIMS="victim-ubuntu victim-ftp victim-dvwa victim-webapi victim-jenkins victim-database victim-mail victim-iot victim-dns victim-windows"

for container in $VICTIMS; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
    warn "$container not running — skipping"; continue
  fi
  if docker exec "$container" grep -q "SOC-FIM-INJECTED" /var/ossec/etc/ossec.conf 2>/dev/null; then
    ok "$container — FIM already injected"; continue
  fi
  docker exec "$container" bash -c "
cat >> /var/ossec/etc/ossec.conf << 'FIMEOF'
  <!-- SOC-FIM-INJECTED -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>60</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <directories check_all=\"yes\" report_changes=\"yes\" realtime=\"yes\">/etc</directories>
    <directories check_all=\"yes\" report_changes=\"yes\" realtime=\"yes\">/home,/tmp,/var/tmp</directories>
    <directories check_all=\"yes\" report_changes=\"yes\" realtime=\"yes\">/var/www,/var/www/html</directories>
    <directories check_all=\"yes\" report_changes=\"yes\">/usr/bin,/usr/sbin,/bin,/sbin</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore type=\"sregex\">.log\$|.swp\$</ignore>
  </syscheck>
FIMEOF
" && ok "$container — FIM injected" || warn "$container — FIM injection failed"
done

# FIX 5 — Restart all Wazuh agents
echo "▶ FIX 5: Restart Wazuh agents..."
for container in $VICTIMS; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then continue; fi
  docker exec "$container" /var/ossec/bin/wazuh-control restart 2>&1 | grep -q "Completed" && ok "$container restarted" || warn "$container restart had issues"
done

# FIX 6 — Jenkins
echo "▶ FIX 6: Jenkins..."
CODE=$(docker exec victim-jenkins curl -s localhost:8080 -o /dev/null -w "%{http_code}" 2>/dev/null)
if echo "$CODE" | grep -qE "200|302|403"; then
  ok "Jenkins running (HTTP $CODE)"
else
  warn "Jenkins down — starting..."
  docker exec -d victim-jenkins bash -c "java -jar /usr/share/jenkins/jenkins.war --httpPort=8080 > /tmp/jenkins.log 2>&1"
  sleep 15
  ok "Jenkins start issued — check: docker exec victim-jenkins curl -s localhost:8080 -o /dev/null -w '%{http_code}'"
fi

# FINAL HEALTH CHECK
echo "▶ HEALTH CHECK..."
sleep 10
WAZUH=$(curl -s ${AUTH} "${ES}/wazuh-alerts-*/_count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null)
ok "Total Wazuh alert docs: $WAZUH"

RECENT=$(curl -s ${AUTH} "${ES}/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"@timestamp":{"gte":"now-5m"}}}}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['hits']['total']['value'])" 2>/dev/null)
ok "Alerts last 5 min: $RECENT"

SURICATA=$(docker exec suricata grep '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null | wc -l)
ok "Suricata total alerts: $SURICATA"

echo "=== Done! Add to start-soc.sh: bash ~/soc-stack/soc-fix.sh ==="
