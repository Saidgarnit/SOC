#!/bin/bash
# Automated agent enrollment for missing Wazuh and Fleet agents

set -e

cd ~/soc-stack || exit 1
PASS=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)
FLEET_URL=$(grep FLEET_URL .env | cut -d= -f2 || echo "https://fleet-server:8220")
FLEET_TOKEN=$(grep FLEET_ENROLLMENT_TOKEN .env | cut -d= -f2 || echo "")

echo "🔧 AUTOMATED AGENT ENROLLMENT"
echo "════════════════════════════════════════════════════════════"
echo ""

# Get list of running victims
VICTIMS=$(docker ps --format "{{.Names}}" | grep "^victim-" | sort)

# Check each victim for Wazuh enrollment
echo "Checking Wazuh enrollments..."
WAZUH_AGENTS=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -oP '\([^)]+\)' | tr -d '()' | sort)

for victim_container in $VICTIMS; do
    victim_name=$(echo "$victim_container" | sed 's/victim-//')
    
    if ! echo "$WAZUH_AGENTS" | grep -q "^$victim_name$"; then
        echo ""
        echo "⚙️  Enrolling $victim_container in Wazuh..."
        
        # Check if agent-auth binary exists in the container
        if docker exec "$victim_container" test -f /var/ossec/bin/agent-auth 2>/dev/null; then
            # Register with Wazuh manager
            docker exec "$victim_container" /var/ossec/bin/agent-auth -m wazuh-manager 2>&1 | grep -v "Waiting for server reply"
            
            # Start the Wazuh agent
            docker exec "$victim_container" /var/ossec/bin/wazuh-control start 2>&1 | grep -v "already running"
            
            echo "  ✅ $victim_container enrolled in Wazuh"
        else
            echo "  ⚠️  $victim_container doesn't have Wazuh agent installed"
        fi
    fi
done

echo ""
echo "────────────────────────────────────────────────────────────"
echo "Checking Fleet enrollments..."

# Get active Fleet agents
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
for a in data['hits']['hits']:
    hostname = a['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown')
    print(hostname)
" | sort)

for victim_container in $VICTIMS; do
    if ! echo "$FLEET_AGENTS" | grep -q "^$victim_container$"; then
        echo ""
        echo "⚙️  Enrolling $victim_container in Fleet..."
        
        # Check if elastic-agent binary exists
        if docker exec "$victim_container" test -f /usr/bin/elastic-agent 2>/dev/null || \
           docker exec "$victim_container" which elastic-agent >/dev/null 2>&1; then
            
            if [ -z "$FLEET_TOKEN" ]; then
                echo "  ⚠️  FLEET_ENROLLMENT_TOKEN not set in .env file"
                echo "  Get token from Kibana: Fleet → Enrollment tokens → victims-edr → Copy secret"
                continue
            fi
            
            # Enroll the agent
            docker exec "$victim_container" elastic-agent enroll \
              --url="$FLEET_URL" \
              --enrollment-token="$FLEET_TOKEN" \
              --insecure 2>&1 | tail -1
            
            echo "  ✅ $victim_container enrolled in Fleet"
        else
            echo "  ⚠️  $victim_container doesn't have elastic-agent installed"
        fi
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Re-checking enrollment status..."
sleep 3

# Final count
WAZUH_FINAL=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active")
FLEET_FINAL=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_count?q=active:true" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])")
VICTIM_COUNT=$(echo "$VICTIMS" | wc -l)

echo ""
echo "Final status:"
echo "  Wazuh: $WAZUH_FINAL/$VICTIM_COUNT"
echo "  Fleet: $FLEET_FINAL/$(($VICTIM_COUNT + 1)) (including fleet-server)"
echo ""

if [ "$WAZUH_FINAL" -eq "$VICTIM_COUNT" ]; then
    echo "✅ Wazuh enrollment complete!"
else
    echo "⚠️  Wazuh enrollment incomplete - may need manual intervention"
fi

if [ "$FLEET_FINAL" -eq $(($VICTIM_COUNT + 1)) ]; then
    echo "✅ Fleet enrollment complete!"
else
    echo "⚠️  Fleet enrollment incomplete - may need manual intervention"
fi
echo ""
