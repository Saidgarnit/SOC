#!/bin/bash
# Clean up stale Fleet agent records
# This addresses the "Fleet: 753 stale records" cosmetic issue

set -e

cd ~/soc-stack || exit 1
PASS=$(grep ELASTIC_PASSWORD .env | cut -d= -f2)

echo "🧹 Fleet Stale Agent Cleanup"
echo "════════════════════════════════════════════════════════════"
echo ""

# Get count of inactive agents
INACTIVE_COUNT=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_count?q=active:false" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])")

echo "Found $INACTIVE_COUNT inactive agents in Elasticsearch index"
echo ""

if [ "$INACTIVE_COUNT" -eq 0 ]; then
    echo "✅ No cleanup needed!"
    exit 0
fi

read -p "Delete all $INACTIVE_COUNT inactive agents? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Fetching inactive agent IDs..."

# Get all inactive agent IDs
AGENT_IDS=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 1000,
    "_source": false,
    "query": {"term": {"active": false}}
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
ids = [hit['_id'] for hit in data['hits']['hits']]
print(','.join(ids))
")

if [ -z "$AGENT_IDS" ]; then
    echo "No inactive agents found (query returned empty)"
    exit 0
fi

echo "Deleting $(echo $AGENT_IDS | tr ',' '\n' | wc -l) agents..."
echo ""

# Delete in batches (Elasticsearch bulk delete)
echo "$AGENT_IDS" | tr ',' '\n' | while read -r agent_id; do
    curl -s -X DELETE -u elastic:$PASS \
      "http://localhost:9200/.fleet-agents/_doc/$agent_id" \
      >/dev/null 2>&1
    echo -n "."
done

echo ""
echo ""
echo "✅ Cleanup complete!"
echo ""

# Verify
NEW_COUNT=$(curl -s -u elastic:$PASS \
  "http://localhost:9200/.fleet-agents/_count?q=active:false" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['count'])")

echo "Inactive agents remaining: $NEW_COUNT"
echo ""
echo "NOTE: This cleaned the Elasticsearch index directly."
echo "The Fleet UI might still show them until:"
echo "  1. Kibana refreshes its cache (up to 5 minutes)"
echo "  2. Or you restart Kibana: docker restart kibana"
echo ""
