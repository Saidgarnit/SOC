#!/bin/bash
# Force reconnect all agents

echo "=== Re-enrolling Wazuh Agents ==="

for victim in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database; do
  docker exec wazuh-manager bash -c "
    ID=\$(grep \"Name: $victim\" /var/ossec/logs/active-responses.log 2>/dev/null | head -1 | grep -oP '(?<=ID:).*?(?=,)' | tr -d ' ' || echo '')
    if [ -n \"\$ID\" ] && [ \"\$ID\" != \"000\" ]; then
      echo y | /var/ossec/bin/manage_agents -r \$ID 2>/dev/null
    fi
  " 2>/dev/null || true
done

sleep 5

echo ""
echo "=== Force Restart Wazuh Agents ==="

for victim in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database; do
  docker exec $victim bash -c "
    pkill -9 wazuh-agentd wazuh-modulesd 2>/dev/null || true
    rm -f /var/ossec/etc/client.keys /var/ossec/var/run/wazuh-agentd*.pid
    sleep 2
    /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A \$(hostname) 2>&1 | head -1
    /var/ossec/bin/wazuh-agentd &
    /var/ossec/bin/wazuh-logcollector &
  " 2>/dev/null &
  sleep 3
done

sleep 30

echo ""
echo "=== Wazuh Agent Status ==="
docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | tail -12

echo ""
echo "=== Fleet Agent Fix ==="
FLEET_IP=$(docker inspect fleet-server --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "Fleet Server IP: $FLEET_IP"

for victim in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database; do
  docker exec $victim bash -c "
    pkill -9 elastic-agent 2>/dev/null || true
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ /opt/elastic-agent/fleet.enc 2>/dev/null
    AGENT_BIN=\$(find /opt/elastic-agent -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
    if [ -n \"\$AGENT_BIN\" ]; then
      cd /opt/elastic-agent
      timeout 30 \$AGENT_BIN enroll --url=http://$FLEET_IP:8220 --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== --insecure -f --skip-daemon-reload 2>&1 | grep -i success
      nohup \$AGENT_BIN run > /tmp/fleet.log 2>&1 &
    fi
  " 2>/dev/null &
  sleep 2
done

sleep 30

echo ""
echo "=== Final Status ==="
echo "Wazuh:"
docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -E "ID:|Active|Disconnected" | tail -12

echo ""
echo "Fleet:"
curl -s -u elastic:sYVfKJCe2RCfELjf=GLa "http://localhost:5601/api/fleet/agents?perPage=20" -H "kbn-xsrf: true" 2>/dev/null | \
  jq '[.items[] | select(.local_metadata.host.hostname | contains("victim")) | {host: .local_metadata.host.hostname, status}]' 2>/dev/null || echo "Unable to check Fleet"

echo ""
echo "✅ Agent reconnection complete!"
