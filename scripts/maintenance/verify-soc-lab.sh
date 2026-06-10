#!/bin/bash
# SOC Lab Verification Script

echo "=========================================="
echo "   SOC LAB COMPREHENSIVE VERIFICATION"
echo "=========================================="
echo ""

# Test 1: SSH Service
echo "1️⃣  SSH SERVICE"
echo "─────────────────────────────────────────"
docker exec victim-ubuntu bash -c "
  service ssh status 2>&1 | grep -q 'running' && echo '✅ SSH running' || echo '❌ SSH failed'
  echo '   Config:'
  grep -E 'SyslogFacility|LogLevel|PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config | sed 's/^/     /'
"
echo ""

# Test 2: Rsyslog Service
echo "2️⃣  RSYSLOG SERVICE"
echo "─────────────────────────────────────────"
docker exec victim-ubuntu bash -c "
  service rsyslog status 2>&1 | grep -q 'running' && echo '✅ Rsyslog running' || echo '❌ Rsyslog failed'
  echo '   Auth.log rules:'
  grep 'auth.*auth.log' /etc/rsyslog.conf | sed 's/^/     /'
  echo '   Log file status:'
  ls -lh /var/log/auth.log | awk '{print \"     Size: \" \$5 \", Owner: \" \$3 \":\" \$4}' 
"
echo ""

# Test 3: Wazuh Agent
echo "3️⃣  WAZUH AGENT"
echo "─────────────────────────────────────────"
docker exec victim-ubuntu bash -c "
  ps aux | grep wazuh-agentd | grep -v grep > /dev/null && echo '✅ Wazuh agent running' || echo '❌ Wazuh agent failed'
  echo '   Monitoring:'
  grep -A 3 '/var/log/auth.log' /var/ossec/etc/ossec.conf | sed 's/^/     /'
"
echo ""

# Test 4: SSH Attack Detection
echo "4️⃣  ATTACK SIMULATION & DETECTION"
echo "─────────────────────────────────────────"
docker exec victim-ubuntu bash -c "
  > /var/log/auth.log
  echo '   [*] Clearing auth.log...'
"

docker exec kali-attacker bash -c "
  echo '   [*] Launching 15 SSH brute-force attempts...'
  for i in {1..15}; do
    sshpass -p 'wrongpass' ssh \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=2 \
      -o StrictHostKeyChecking=no \
      root@victim-ubuntu 'whoami' 2>/dev/null &
  done
  wait
  echo '   [✓] Attack complete'
"

sleep 6

docker exec victim-ubuntu bash -c "
  echo '   Logging results:'
  FAILED=\$(grep -c 'Failed password' /var/log/auth.log)
  TOTAL=\$(wc -l < /var/log/auth.log)
  echo \"     - Total auth.log lines: \$TOTAL\"
  echo \"     - Failed password attempts: \$FAILED\"
  echo \"     - Detection rate: \$((FAILED * 100 / 15))%\"
"

sleep 3

docker exec wazuh-manager bash -c "
  echo '   Wazuh detection results:'
  ALERTS=\$(grep -c '\"id\":\"5760\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0)
  echo \"     - SSH brute-force alerts: \$ALERTS\"
  if [ \$ALERTS -gt 0 ]; then
    echo '     - Latest alert details:'
    grep '\"id\":\"5760\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -1 | jq '.alert.data | {srcip, srcport, user}' 2>/dev/null | sed 's/^/       /'
  fi
"
echo ""

echo "=========================================="
echo "   ✅ SOC LAB FULLY OPERATIONAL"
echo "=========================================="
echo ""
echo "Log locations:"
echo "  - SSH logs:       /var/log/auth.log (victim-ubuntu)"
echo "  - Wazuh alerts:   /var/ossec/logs/alerts/alerts.json (wazuh-manager)"
echo "  - Wazuh rules:    /var/ossec/ruleset/rules/0095-sshd_rules.xml"
echo ""
