#!/bin/bash
cd ~/soc-stack
PASS=$(grep "^ELASTIC_PASSWORD" .env | cut -d= -f2)
AUTH="elastic:$PASS"
ES="http://localhost:9200"
KIBANA="http://localhost:5601"

echo "=== Current counts (using correct field) ==="
ACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count?q=active:true" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
INACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count?q=active:false" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "  active:true  = $ACTIVE  (target: 11)"
echo "  active:false = $INACTIVE  (target: 0)"

if [ "$INACTIVE" -eq 0 ]; then
  echo "Already clean!"
  exit 0
fi

echo ""
echo "=== Fetching inactive agent IDs ==="
AGENT_IDS=$(curl -s -u "$AUTH" \
  "$ES/.fleet-agents/_search?size=1000" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"active":false}},"_source":["agent.id"]}' | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
hits=d['hits']['hits']
ids=[h['_source']['agent']['id'] for h in hits if 'agent' in h['_source']]
print(len(ids),'agent IDs found')
# Write to file for next step
with open('/tmp/inactive_ids.json','w') as f:
    json.dump(ids, f)
")
echo "$AGENT_IDS"

echo ""
echo "=== Sending bulk unenroll with IDs ==="
python3 << 'PYEOF'
import json, urllib.request, urllib.error, base64

with open('/tmp/inactive_ids.json') as f:
    all_ids = json.load(f)

import subprocess
pass_result = subprocess.run(
    ["grep", "^ELASTIC_PASSWORD", ".env"],
    capture_output=True, text=True
)
password = pass_result.stdout.strip().split("=",1)[1]
creds = base64.b64encode(f"elastic:{password}".encode()).decode()
headers = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
    "Authorization": f"Basic {creds}"
}

# Send in batches of 100
batch_size = 100
total_done = 0
for i in range(0, len(all_ids), batch_size):
    batch = all_ids[i:i+batch_size]
    body = json.dumps({"agents": batch, "revoke": True}).encode()
    req = urllib.request.Request(
        "http://localhost:5601/api/fleet/agents/bulk_unenroll",
        data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.load(resp)
            total_done += len(batch)
            print(f"  Batch {i//batch_size + 1}: unenrolled {len(batch)} agents")
    except Exception as e:
        print(f"  Batch {i//batch_size + 1} error: {e}")

print(f"Total unenrolled: {total_done}")
PYEOF

echo ""
echo "=== Final counts ==="
sleep 5
ACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count?q=active:true" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
INACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count?q=active:false" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "  active:true  = $ACTIVE  (target: 11)"
echo "  active:false = $INACTIVE  (target: 0)"
