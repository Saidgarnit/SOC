#!/bin/bash
# Clean up stale and duplicate Fleet agents (IMPROVED VERSION)

set -e
cd ~/soc-stack || exit 1
PASS=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)

echo "🧹 FLEET AGENT CLEANUP (IMPROVED)"
echo "════════════════════════════════════════════════════════════"
echo ""

# Count inactive agents
INACTIVE_COUNT=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_count?q=active:false" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])")

echo "Inactive agents: $INACTIVE_COUNT"

# Count duplicates (same hostname, multiple active)
echo ""
echo "Checking for duplicate active agents..."
curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_search?size=100" \
  -H 'Content-Type: application/json' \
  -d '{
    "_source": ["local_metadata.host.hostname", "active", "enrolled_at"],
    "query": {"term": {"active": true}}
  }' | python3 - <<'PYTHON'
import sys, json
from collections import defaultdict
from datetime import datetime

data = json.load(sys.stdin)
agents_by_host = defaultdict(list)

for hit in data['hits']['hits']:
    hostname = hit['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown')
    agent_id = hit['_id']
    enrolled = hit['_source'].get('enrolled_at', '')
    active = hit['_source'].get('active', False)
    
    agents_by_host[hostname].append({
        'id': agent_id,
        'enrolled': enrolled,
        'active': active
    })

duplicates = {k: v for k, v in agents_by_host.items() if len(v) > 1}

if duplicates:
    print("Found duplicate enrollments:")
    for hostname, agents in duplicates.items():
        print(f"\n  {hostname}: {len(agents)} active enrollments")
        # Sort by enrollment date, oldest first
        agents.sort(key=lambda x: x['enrolled'])
        for i, agent in enumerate(agents):
            marker = "KEEP (newest)" if i == len(agents) - 1 else "DELETE (older)"
            print(f"    • {agent['id'][:8]}... enrolled {agent['enrolled'][:10]} [{marker}]")
            
    # Output IDs to delete (all but newest for each host)
    print("\n" + "="*60)
    ids_to_delete = []
    for hostname, agents in duplicates.items():
        agents.sort(key=lambda x: x['enrolled'])
        # Delete all but the last (newest) one
        ids_to_delete.extend([a['id'] for a in agents[:-1]])
    
    print(f"\nTotal duplicate agents to remove: {len(ids_to_delete)}")
    print(','.join(ids_to_delete))
else:
    print("✅ No duplicate active agents found")
PYTHON

echo ""
read -p "Clean up inactive agents AND duplicates? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Step 1: Deleting inactive agents using bulk delete..."

# Use delete_by_query for inactive agents (much faster)
curl -s -X POST -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_delete_by_query?conflicts=proceed" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "term": {"active": false}
    }
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  Deleted: {data.get('deleted', 0)} inactive agents\")
print(f\"  Failures: {len(data.get('failures', []))} \")
"

echo ""
echo "Step 2: Removing duplicate active agents (keeping newest)..."

# Get duplicate IDs to delete
DUPLICATE_IDS=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_search?size=100" \
  -H 'Content-Type: application/json' \
  -d '{
    "_source": ["local_metadata.host.hostname", "enrolled_at"],
    "query": {"term": {"active": true}}
  }' | python3 - <<'PYTHON'
import sys, json
from collections import defaultdict

data = json.load(sys.stdin)
agents_by_host = defaultdict(list)

for hit in data['hits']['hits']:
    hostname = hit['_source'].get('local_metadata', {}).get('host', {}).get('hostname', 'unknown')
    agent_id = hit['_id']
    enrolled = hit['_source'].get('enrolled_at', '')
    agents_by_host[hostname].append({'id': agent_id, 'enrolled': enrolled})

# For each hostname with duplicates, keep newest, delete others
ids_to_delete = []
for hostname, agents in agents_by_host.items():
    if len(agents) > 1:
        agents.sort(key=lambda x: x['enrolled'])
        ids_to_delete.extend([a['id'] for a in agents[:-1]])

print(','.join(ids_to_delete))
PYTHON
)

if [ -n "$DUPLICATE_IDS" ] && [ "$DUPLICATE_IDS" != "" ]; then
    echo "  Found $(echo $DUPLICATE_IDS | tr ',' '\n' | wc -l) duplicates to remove"
    
    # Delete each duplicate
    echo "$DUPLICATE_IDS" | tr ',' '\n' | while read agent_id; do
        if [ -n "$agent_id" ]; then
            curl -s -X DELETE -u elastic:$PASS \
              "http://localhost:9200/.fleet-agents/_doc/$agent_id" \
              >/dev/null 2>&1
            echo -n "."
        fi
    done
    echo ""
    echo "  ✅ Duplicates removed"
else
    echo "  ✅ No duplicates found"
fi

echo ""
echo "Step 3: Refreshing index..."
curl -s -X POST -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_refresh" >/dev/null 2>&1

sleep 2

echo ""
echo "════════════════════════════════════════════════════════════"
echo "FINAL STATUS:"
echo ""

INACTIVE_FINAL=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_count?q=active:false" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])")

ACTIVE_FINAL=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_count?q=active:true" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])")

echo "Active agents:   $ACTIVE_FINAL"
echo "Inactive agents: $INACTIVE_FINAL"
echo ""

if [ "$INACTIVE_FINAL" -eq 0 ]; then
    echo "✅ All inactive agents removed!"
else
    echo "⚠️  $INACTIVE_FINAL inactive agents remain (may need Kibana restart)"
fi

echo ""
echo "Restarting Kibana to clear cache..."
docker restart kibana
echo "✅ Done! Wait 30 seconds for Kibana to restart, then check Fleet UI"
