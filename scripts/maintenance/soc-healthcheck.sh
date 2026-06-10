#!/bin/bash
cd ~/soc-stack
FIX_MODE="${1:-}"
PASS=0; FAIL=0; WARN=0
RED='[0;31m'; GRN='[0;32m'; YEL='[1;33m'; CYN='[0;36m'; RST='[0m'
source .env 2>/dev/null || true
EP="SOCstack2026!"

ok()   { echo -e "  ${GRN}PASS: $1${RST}"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL: $1${RST}"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YEL}WARN: $1${RST}"; WARN=$((WARN+1)); }
hdr()  { echo -e "
${CYN}=== $1 ===${RST}"; }

fix() {
  if [ "$FIX_MODE" = "--fix" ]; then
    echo -e "  ${YEL}Restarting: $1${RST}"
    docker start "$1" 2>/dev/null || docker compose up -d "$1" 2>/dev/null
    sleep 3
  fi
}

hdr "1. CONTAINERS"
RUNNING=$(docker ps --format "{{.Names}}" | grep -c .)
TOTAL=$(docker ps -a --format "{{.Names}}" | grep -c .)
echo "  Running: $RUNNING / $TOTAL"
EXITED=$(docker ps -a --filter status=exited --format "{{.Names}}" | grep -v elasticsearch-init)
if [ -z "$EXITED" ]; then ok "No exited containers"
else for c in $EXITED; do fail "$c EXITED"; fix "$c"; done; fi

hdr "2. ELASTICSEARCH"
ES_ST=$(curl -sf -u "elastic:${EP}" http://localhost:9200/_cluster/health 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get("status","down"))" 2>/dev/null || echo down)
[ "$ES_ST" = "green" ] || [ "$ES_ST" = "yellow" ] && ok "ES cluster: $ES_ST" || fail "ES cluster: $ES_ST"
IDX=$(curl -sf -u "elastic:${EP}" "http://localhost:9200/_cat/indices?h=index" 2>/dev/null | grep -cv "^\." | tail -n 1 || echo 0)
ok "ES indices: $IDX"

hdr "3. WAZUH"
if docker ps --format "{{.Names}}" | grep -q wazuh-manager; then
  ok "Wazuh manager UP"
  ACT=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c Active | tail -n 1 || echo 0)
  TOT=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "ID:" | tail -n 1 || echo 0)
  [ "$ACT" -ge 5 ] && ok "Agents: $ACT/$TOT active" || warn "Agents: $ACT/$TOT active"
  ANALYSISD=$(docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep "wazuh-analysisd" | grep -c "is running" | tail -n 1 || echo 0)
  [ "$ANALYSISD" -eq 1 ] && ok "wazuh-analysisd running" || fail "wazuh-analysisd NOT running (no alerts)"
  ALR=$(docker exec wazuh-manager wc -l /var/ossec/logs/alerts/alerts.json 2>/dev/null | awk '{print $1}')
  ok "Wazuh alerts: $ALR"
else fail "Wazuh DOWN"; fix wazuh-manager; fi

hdr "4. FLEET + ENDPOINTS"
docker ps --format "{{.Names}}" | grep -q fleet-server && ok "Fleet UP" || fail "Fleet DOWN"
for v in victim-ubuntu victim-windows victim-metasploitable victim-database victim-dns victim-dvwa victim-ftp victim-iot victim-jenkins victim-mail victim-webapi; do
  docker ps --format "{{.Names}}" | grep -q "^${v}\$" && ok "$v UP" || { fail "$v DOWN"; fix "$v"; }
done

hdr "5. DATA PIPELINE"
docker ps --format "{{.Names}}" | grep -q filebeat && ok "Filebeat UP" || fail "Filebeat DOWN"
docker ps --format "{{.Names}}" | grep -q logstash && ok "Logstash UP" || fail "Logstash DOWN"
docker exec logstash ls /var/ossec/logs/alerts/alerts.json >/dev/null 2>&1 && ok "Logstash Wazuh volume OK" || fail "Logstash Wazuh volume MISSING"
ENR=$(curl -sf -u "elastic:${EP}" "http://localhost:9200/soc-logs-enriched-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' | tail -n 1 || echo 0)
ok "Enriched docs: $ENR"
RID=$(curl -sf -u "elastic:${EP}" "http://localhost:9200/soc-logs-enriched-*/_count" -H 'Content-Type: application/json' -d '{"query":{"exists":{"field":"rule.id"}}}' 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' | tail -n 1 || echo 0)
[ "$RID" -gt 0 ] && ok "Wazuh in enriched: $RID docs" || fail "Wazuh NOT in enriched index"

hdr "6. ELASTALERT"
docker ps --format "{{.Names}}" | grep -q elastalert && ok "ElastAlert UP" || fail "ElastAlert DOWN"
RC=$(ls ~/soc-stack/elastalert/rules/*.yaml 2>/dev/null | wc -l)
ok "Rules: $RC"
ER=$(docker logs elastalert --tail 50 2>&1 | grep -c ERROR | tail -n 1 || echo 0)
[ "$ER" -eq 0 ] && ok "No ElastAlert errors" || warn "ElastAlert $ER errors"
MT=$(docker logs elastalert --tail 100 2>&1 | grep matches | grep -v "0 matches" | wc -l)
[ "$MT" -gt 0 ] && ok "ElastAlert: $MT rules with detections" || warn "No recent detections"

hdr "7. SURICATA"
docker ps --format "{{.Names}}" | grep -q suricata && ok "Suricata UP" || fail "Suricata DOWN"
SA=$(curl -sf -u "elastic:${EP}" "http://localhost:9200/suricata-alerts-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' | tail -n 1 || echo 0)
ok "Suricata alerts: $SA"

hdr "8. THREAT INTEL"
docker ps --format "{{.Names}}" | grep -q "^misp\$" && ok "MISP UP" || fail "MISP DOWN"
docker ps --format "{{.Names}}" | grep -q vt-enricher && ok "VT enricher UP" || fail "VT DOWN"
docker ps --format "{{.Names}}" | grep -q "^opencti\$" && ok "OpenCTI UP" || fail "OpenCTI DOWN"

hdr "9. THEHIVE + KIBANA"
docker ps --format "{{.Names}}" | grep -q thehive && ok "TheHive UP" || fail "TheHive DOWN"
KH=$(curl -sf -o /dev/null -w "%{http_code}" http://localhost:5601/api/status 2>/dev/null | tail -n 1 || echo 0)
[ "$KH" = "200" ] && ok "Kibana HTTP 200" || warn "Kibana HTTP $KH"

hdr "10. ATTACK SIM"
docker ps --format "{{.Names}}" | grep -q kali-attacker && ok "Kali UP" || fail "Kali DOWN"
docker exec kali-attacker ls /root/attack-sim.sh >/dev/null 2>&1 && ok "Attack script present" || warn "No attack script"

hdr "11. MEMORY"
docker stats --no-stream --format "{{.Name}} {{.MemPerc}}" 2>/dev/null | while read name pct; do
  num=${pct%%%}; int=${num%%.*}
  [ "$int" -ge 95 ] && fail "$name at $pct CRITICAL"
  [ "$int" -ge 85 ] && [ "$int" -lt 95 ] && warn "$name at $pct HIGH"
done

hdr "RESULTS"
echo ""
echo -e "  ${GRN}PASS: $PASS${RST}  |  ${RED}FAIL: $FAIL${RST}  |  ${YEL}WARN: $WARN${RST}"
if [ "$FAIL" -eq 0 ]; then
  echo -e "
  ${GRN}SOC STACK 100% OPERATIONAL${RST}"
else
  echo -e "
  ${RED}Issues found - run with --fix${RST}"
fi
echo ""
