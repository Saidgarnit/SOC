#!/bin/bash
# Quick investigation: Which agents are missing?

cd ~/soc-stack || exit 1
PASS=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)

echo "🔍 AGENT ENROLLMENT GAP ANALYSIS"
echo "════════════════════════════════════════════════════════════"
echo ""

# Get all running victim containers
echo "Running victim containers:"
VICTIMS=$(docker ps --format "{{.Names}}" | grep "^victim-" | sort)
echo "$VICTIMS" | sed 's/victim-/  • /'
VICTIM_COUNT=$(echo "$VICTIMS" | wc -l)
echo ""
echo "Total: $VICTIM_COUNT"
echo ""

# Get Wazuh enrolled agents
echo "────────────────────────────────────────────────────────────"
echo "Wazuh enrolled agents:"
WAZUH_AGENTS=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -oP '\([^)]+\)' | tr -d '()' | sort)
echo "$WAZUH_AGENTS" | sed 's/^/  • /'
WAZUH_COUNT=$(echo "$WAZUH_AGENTS" | grep -v "^$" | wc -l)
echo ""
echo "Total: $WAZUH_COUNT"
echo ""

# Find missing from Wazuh
echo "Missing from Wazuh:"
for victim in $(echo "$VICTIMS" | sed 's/victim-//'); do
    if ! echo "$WAZUH_AGENTS" | grep -q "^$victim$"; then
        echo "  ❌ $victim"
        MISSING_WAZUH=true
    fi
done
[ -z "$MISSING_WAZUH" ] && echo "  ✅ None - all enrolled"
echo ""

# Get Fleet active agents (excluding fleet-server)
echo "────────────────────────────────────────────────────────────"
echo "Fleet enrolled agents (active only):"
FLEET_AGENTS=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 100,
    "_source": ["local_metadata.host.hostname"],
    "query": {"term": {"active": true}}
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
agents = [a['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown') 
          for a in data['hits']['hits']]
# Filter out fleet-server
agents = [a for a in agents if not a.startswith('fleet-server')]
for agent in sorted(agents):
    print(agent)
")
echo "$FLEET_AGENTS" | sed 's/^/  • /'
FLEET_COUNT=$(echo "$FLEET_AGENTS" | grep -v "^$" | wc -l)
echo ""
echo "Total: $FLEET_COUNT (excluding fleet-server)"
echo ""

# Find missing from Fleet
echo "Missing from Fleet:"
for victim in $(echo "$VICTIMS" | sed 's/victim-//'); do
    if ! echo "$FLEET_AGENTS" | grep -q "^victim-$victim$"; then
        echo "  ❌ victim-$victim"
        MISSING_FLEET=true
    fi
done
[ -z "$MISSING_FLEET" ] && echo "  ✅ None - all enrolled"
echo ""

# Check for offline Fleet agents
echo "────────────────────────────────────────────────────────────"
echo "Fleet offline agents (should be 0):"
OFFLINE_AGENTS=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 100,
    "_source": ["local_metadata.host.hostname", "last_checkin"],
    "query": {"bool": {"must": [
      {"term": {"active": true}},
      {"range": {"last_checkin": {"lt": "now-5m"}}}
    ]}}
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for agent in data['hits']['hits']:
    hostname = agent['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown')
    last = agent['_source'].get('last_checkin', 'never')[:19]
    print(f'  ⚠️  {hostname} (last seen: {last})')
" || echo "  ✅ All active agents are checking in")
echo ""

echo "════════════════════════════════════════════════════════════"
echo "SUMMARY:"
echo "  Containers: $VICTIM_COUNT"
echo "  Wazuh:      $WAZUH_COUNT/$VICTIM_COUNT"
echo "  Fleet:      $FLEET_COUNT/$VICTIM_COUNT (+ 1 fleet-server = $(($FLEET_COUNT + 1)) total expected)"
echo ""
echo "TARGET STATE:"
echo "  • Wazuh should show: $VICTIM_COUNT/$VICTIM_COUNT agents active"
echo "  • Fleet should show: $(($VICTIM_COUNT + 1))/$(($VICTIM_COUNT + 1)) (victims + fleet-server)"
echo "════════════════════════════════════════════════════════════"
