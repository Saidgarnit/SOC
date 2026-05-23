#!/bin/bash

echo "=========================================="
echo "SSH BRUTE-FORCE ALERT TEST"
echo "=========================================="
echo ""

# Clear logs
docker exec victim-ubuntu bash -c "
  > /var/log/auth.log
  echo '[*] Logs cleared'
"

# Run attack
echo "[*] Launching 20 SSH brute-force attempts..."
docker exec kali-attacker bash -c "
  for i in {1..20}; do
    sshpass -p 'wrongpass' ssh \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=2 \
      -o StrictHostKeyChecking=no \
      root@victim-ubuntu 'whoami' 2>/dev/null &
  done
  wait
"

sleep 5

# Check results
echo ""
echo "RESULTS:"
echo "--------"

docker exec victim-ubuntu bash -c "
  FAILED=\$(grep -c 'Failed password' /var/log/auth.log)
  TOTAL=\$(wc -l < /var/log/auth.log)
  echo \"✅ SSH Logs: \$FAILED failed attempts, \$TOTAL total lines\"
"

docker exec wazuh-manager bash -c "
  ALERTS=\$(grep -c '\"id\":\"5760\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0)
  echo \"✅ Wazuh Alerts: \$ALERTS SSH brute-force alerts generated\"
"

echo ""
echo "✅ If you configured Slack webhook, check your #soc-alerts channel!"

