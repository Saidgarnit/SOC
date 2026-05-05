#!/bin/bash
# Permanent SOC Stack Agent Cleanup & Enrollment

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║       SOC STACK — PERMANENT AGENT SETUP                    ║"
echo "╚════════════════════════════════════════════════════════════╝"

# Wait for services to stabilize
sleep 60

echo ""
echo "=== CLEANING STALE AGENT STATE ==="
for victim in victim-ubuntu victim-dns victim-jenkins victim-iot victim-mail victim-dvwa victim-database victim-windows; do
  docker exec $victim bash -c "
    rm -f /var/ossec/var/run/wazuh-agentd*.pid 2>/dev/null || true
  " 2>/dev/null &
done
wait

sleep 10

echo ""
echo "=== WAZUH: VERIFY ALL 10 AGENTS ACTIVE ==="
for i in {1..5}; do
  ACTIVE=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active" || echo "0")
  if [ "$ACTIVE" -ge 9 ]; then
    echo "✅ Wazuh: $ACTIVE/10 agents ACTIVE"
    break
  fi
  echo "  Attempt $i: $ACTIVE/10 active, waiting..."
  sleep 15
done

echo ""
echo "=== FLEET: VERIFY ALL 11 AGENTS ONLINE ==="
for i in {1..3}; do
  ONLINE=$(curl -s -u elastic:sYVfKJCe2RCfELjf=GLa "http://localhost:5601/api/fleet/agents?perPage=50" -H "kbn-xsrf: true" 2>/dev/null | jq '[.items[] | select(.status=="online")] | length' || echo "0")
  if [ "$ONLINE" -ge 11 ]; then
    echo "✅ Fleet: $ONLINE/11 agents ONLINE"
    break
  fi
  echo "  Attempt $i: $ONLINE/11 online, waiting..."
  sleep 10
done

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ SOC STACK READY FOR OPERATIONS                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
