#!/bin/bash
# SOC Stack Agent Enrollment Diagnostic & Fix Script

echo "═══════════════════════════════════════════════════════════"
echo "  SOC STACK AGENT ENROLLMENT DIAGNOSTIC"
echo "═══════════════════════════════════════════════════════════"

cd ~/soc-stack || exit 1

echo ""
echo "📊 VICTIM CONTAINERS STATUS"
echo "───────────────────────────────────────────────────────────"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep "victim-" | sort
VICTIM_COUNT=$(docker ps --format "{{.Names}}" | grep -c "victim-")
echo ""
echo "Total victim containers running: $VICTIM_COUNT"

echo ""
echo "🔐 WAZUH AGENT STATUS"
echo "───────────────────────────────────────────────────────────"
docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null || echo "Failed to get Wazuh agent list"
WAZUH_ACTIVE=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active")
echo ""
echo "Wazuh agents active: $WAZUH_ACTIVE / $VICTIM_COUNT expected"

echo ""
echo "🚢 FLEET AGENT STATUS"
echo "───────────────────────────────────────────────────────────"
PASS=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
curl -s -u elastic:$PASS "http://localhost:9200/.fleet-agents/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 100,
    "_source": ["local_metadata.host.hostname", "active", "last_checkin"],
    "query": {"match_all": {}}
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
agents = data['hits']['hits']
print(f'Total Fleet agents in index: {len(agents)}')
print(f'Active: {sum(1 for a in agents if a[\"_source\"].get(\"active\", False))}')
print(f'Inactive: {sum(1 for a in agents if not a[\"_source\"].get(\"active\", False))}')
print()
print('Active agents:')
for agent in agents:
    if agent['_source'].get('active', False):
        hostname = agent['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown')
        last_checkin = agent['_source'].get('last_checkin', 'never')[:19]
        print(f'  • {hostname} (last: {last_checkin})')
"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  DETECTED ISSUES & FIXES"
echo "═══════════════════════════════════════════════════════════"

# Check which victims are missing from Wazuh
echo ""
echo "🔍 Checking for missing Wazuh enrollments..."
WAZUH_AGENTS=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -oP '(?<=\().*?(?=\))' | sort)
for victim in $(docker ps --format "{{.Names}}" | grep "victim-" | sed 's/victim-//'); do
    if ! echo "$WAZUH_AGENTS" | grep -q "$victim"; then
        echo "  ❌ victim-$victim is NOT enrolled in Wazuh"
        echo "     Fix: docker exec -it victim-$victim /var/ossec/bin/agent-auth -m wazuh-manager"
    fi
done

# Check for stale Fleet agents
echo ""
echo "🧹 Checking for stale Fleet agents..."
INACTIVE_COUNT=$(curl -s -u elastic:$PASS "http://localhost:9200/.fleet-agents/_count?q=active:false" | grep -oP '(?<="count":)\d+')
echo "  Found $INACTIVE_COUNT inactive agents in Fleet index"
if [ "$INACTIVE_COUNT" -gt 0 ]; then
    echo "  Fix: Clean via Kibana → Fleet → Agents → filter Offline → select all → Unenroll"
    echo "  Or run: curl -X POST -u elastic:\$PASS 'http://localhost:5601/api/fleet/agents/bulk_unenroll' \\"
    echo "            -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \\"
    echo "            -d '{\"agents\":[...], \"revoke\":true}'"
fi

# Check for duplicate Fleet enrollments
echo ""
echo "🔄 Checking for duplicate Fleet agents..."
curl -s -u elastic:$PASS "http://localhost:9200/.fleet-agents/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 100,
    "_source": ["local_metadata.host.hostname", "active"],
    "query": {"term": {"active": true}}
  }' | python3 -c "
import sys, json
from collections import Counter
data = json.load(sys.stdin)
agents = data['hits']['hits']
hostnames = [a['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown') for a in agents]
duplicates = {name: count for name, count in Counter(hostnames).items() if count > 1}
if duplicates:
    print('  ⚠️  Duplicate active enrollments detected:')
    for name, count in duplicates.items():
        print(f'     • {name}: {count} active enrollments')
    print('  Fix: Unenroll the older instances via Fleet UI')
else:
    print('  ✅ No duplicate active agents found')
"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  RECOMMENDED ACTIONS"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "1. Enroll missing Wazuh agents (if any shown above)"
echo "2. Clean up 753 inactive Fleet records via Kibana Fleet UI:"
echo "   Fleet → Agents → Status: Offline (3) → Select all → Unenroll"
echo "3. After cleanup, verify counts:"
echo "   • Wazuh: docker exec wazuh-manager /var/ossec/bin/agent_control -l | grep Active"
echo "   • Fleet: Check Fleet UI should show ${VICTIM_COUNT}/$(($VICTIM_COUNT + 1)) (victims + fleet-server)"
echo ""
