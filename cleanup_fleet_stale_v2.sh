#!/bin/bash

cd ~/soc-stack

PASS=$(grep "^ELASTIC_PASSWORD" .env | cut -d= -f2)
AUTH="elastic:$PASS"
ES="http://localhost:9200"
KIBANA="http://localhost:5601"

echo "Testing connection..."
curl -s -u "$AUTH" "$ES/_cluster/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ES status:', d['status'])"

echo "Bulk unenrolling inactive agents..."
curl -s -u "$AUTH" -X POST "$KIBANA/api/fleet/agents/bulk_unenroll" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"kuery":"status:inactive","revoke":true}' | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print('Response:', d)
except:
  print('Raw:', sys.stdin.read()[:300])
"

sleep 3
echo "Final counts:"
for STATUS in online inactive; do
  COUNT=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count" \
    -H "Content-Type: application/json" \
    -d "{\"query\":{\"term\":{\"status\":\"$STATUS\"}}}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('count','ERR'))")
  echo "  $STATUS: $COUNT"
done
