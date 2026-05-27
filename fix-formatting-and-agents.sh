#!/bin/bash
echo "=== 1. FIXING ELASTALERT SLACK FORMATTING ==="
cd ~/soc-stack/elastalert/rules

# Replace {rule.id} with {match[rule.id]} in all yaml rules
sed -i 's/{rule.id}/{match[rule.id]}/g' *.yaml
sed -i 's/{rule.level}/{match[rule.level]}/g' *.yaml
sed -i 's/{rule.description}/{match[rule.description]}/g' *.yaml
sed -i 's/{agent.name}/{match[agent.name]}/g' *.yaml
sed -i 's/{syscheck.path}/{match[syscheck.path]}/g' *.yaml
sed -i 's/{rule.groups}/{match[rule.groups]}/g' *.yaml

echo "  Restarting ElastAlert to load fixed rules..."
docker restart elastalert

echo ""
echo "=== 2. RECONNECTING DISCONNECTED AGENTS ==="
# Restart the agents inside the containers that were force-recreated
for victim in victim-webapi victim-iot victim-windows victim-ubuntu; do
  echo "  Restarting Wazuh & Elastic agents on $victim..."
  docker exec $victim service wazuh-agent restart 2>/dev/null || docker exec $victim /var/ossec/bin/wazuh-control restart 2>/dev/null
  docker exec $victim elastic-agent restart 2>/dev/null || true
done

echo ""
echo "=== 3. WAITING FOR AGENTS TO COME ONLINE ==="
sleep 15

echo ""
echo "=== 4. RE-RUNNING SSH BRUTE FORCE TEST ==="
cd ~/soc-stack
# Send 15 bad passwords explicitly spaced out (Wazuh rule 5712 needs 8 failures in 2 mins)
echo "  Attacking victim-ubuntu via SSH..."
for i in {1..12}; do
  sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no -p 2222 root@localhost 2>/dev/null
  sleep 1
done

echo ""
echo "  Wait 15 seconds for Wazuh and ElastAlert to process the logs..."
sleep 15

echo "  Checking if Wazuh triggered the Active Response (firewall-drop)..."
docker exec victim-ubuntu iptables -L -n | grep DROP
