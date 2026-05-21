#!/bin/bash
source "$(dirname "$0")/.env"

FLEET_URL="http://localhost:8220"
# Fetch fresh enrollment token dynamically
POLICY_ID="69515b3a-4bb6-46c8-836d-4a30c0bbf388"
TOKEN=$(curl -s -X POST "http://localhost:5601/api/fleet/enrollment_api_keys" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -d "{\"policy_id\":\"$POLICY_ID\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[\"item\"][\"api_key\"])" 2>/dev/null)
[ -z "$TOKEN" ] && TOKEN="ejgyZ01KNEJZOFhzcWFUT2RROEw6OC1LN2RDdWtSenU2UGZuc09ZRWRkQQ=="

# 1. Check Fleet Server (HTTP not HTTPS)
if ! curl -s "$FLEET_URL/api/status" | grep -q "HEALTHY"; then
    echo "$(date): Fleet Server down. Restarting..."
    docker restart fleet-server
    sleep 30
fi

# 2. Check for offline agents and re-enroll them
OFFLINE=$(curl -s -u elastic:${ELASTIC_PASSWORD} \
  "$FLEET_URL/api/fleet/agents?perPage=50" \
  -H "kbn-xsrf: true" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('items', []):
    if a['status'] == 'offline':
        print(a.get('local_metadata',{}).get('host',{}).get('hostname','?'))
" 2>/dev/null)

if [ -n "$OFFLINE" ]; then
    echo "$(date): Offline agents detected: $OFFLINE"
    bash "$(dirname "$0")/restart-agents.sh"
fi
# 3. Fix OpenCTI date-based threat-intel index (created daily without proper mapping)
TODAY=$(date +%Y.%m.%d)
INDEX="opencti-threat-intel-${TODAY}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -u "elastic:${ELASTIC_PASSWORD}" \
  "http://localhost:9200/${INDEX}")
if [ "$STATUS" = "200" ]; then
    echo "$(date): Deleting corrupt OpenCTI index ${INDEX}..."
    curl -s -u "elastic:${ELASTIC_PASSWORD}" -X DELETE "http://localhost:9200/${INDEX}"
    docker restart opencti
    echo "$(date): OpenCTI restarted after index cleanup"
fi
# 4. Revive crashed connectors
docker start connector-misp 2>/dev/null || true
docker start connector-mitre 2>/dev/null || true
