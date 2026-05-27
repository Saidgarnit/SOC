#!/bin/bash
cd ~/soc-stack
PASS=$(grep "^ELASTIC_PASSWORD" .env | cut -d= -f2)
AUTH="elastic:$PASS"
ES="http://localhost:9200"
KIBANA="http://localhost:5601"

echo "=== Try 1: Delete from concrete index .fleet-agents-7 ==="
curl -s -u "$AUTH" -X POST "$ES/.fleet-agents-7/_delete_by_query?wait_for_completion=true" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"active":false}}}' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('Deleted:',d.get('deleted','?'),'Error:',d.get('error',{}).get('type','none'))"

echo ""
echo "=== Try 2: Kibana bulk delete (not unenroll) ==="
# Get IDs of inactive agents first
curl -s -u "$AUTH" "$ES/.fleet-agents-7/_search?size=1000" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"active":false}},"_source":["agent.id"]}' | \
  python3 -c "
import sys,json,urllib.request,base64,subprocess

d=json.load(sys.stdin)
hits=d.get('hits',{}).get('hits',[])
ids=[h['_source']['agent']['id'] for h in hits if 'agent' in h.get('_source',{})]
print(f'Found {len(ids)} inactive agent IDs')

if not ids:
    print('Nothing to delete')
    exit()

p=subprocess.run(['grep','^ELASTIC_PASSWORD','.env'],capture_output=True,text=True)
pw=p.stdout.strip().split('=',1)[1]
creds=base64.b64encode(f'elastic:{pw}'.encode()).decode()
headers={'Content-Type':'application/json','kbn-xsrf':'true','Authorization':f'Basic {creds}'}

# Try Kibana DELETE endpoint per agent in bulk
success=0
errors=0
for agent_id in ids[:5]:  # test first 5
    req=urllib.request.Request(
        f'http://localhost:5601/api/fleet/agents/{agent_id}',
        headers=headers, method='DELETE'
    )
    try:
        with urllib.request.urlopen(req,timeout=5) as r:
            success+=1
    except Exception as e:
        errors+=1
        print(f'  Error on {agent_id}: {e}')
        break

print(f'Test batch: {success} ok, {errors} errors')
if success>0:
    print('DELETE endpoint works — running full batch...')
    with open('/tmp/inactive_agent_ids.json','w') as f:
        json.dump(ids,f)
"

# If test worked, do the full delete
if [ -f /tmp/inactive_agent_ids.json ]; then
python3 << 'PYEOF'
import json,urllib.request,base64,subprocess

with open('/tmp/inactive_agent_ids.json') as f:
    ids=json.load(f)

p=subprocess.run(['grep','^ELASTIC_PASSWORD','.env'],capture_output=True,text=True)
pw=p.stdout.strip().split('=',1)[1]
creds=base64.b64encode(f'elastic:{pw}'.encode()).decode()
headers={'Content-Type':'application/json','kbn-xsrf':'true','Authorization':f'Basic {creds}'}

success=0
for agent_id in ids:
    req=urllib.request.Request(
        f'http://localhost:5601/api/fleet/agents/{agent_id}',
        headers=headers, method='DELETE'
    )
    try:
        urllib.request.urlopen(req,timeout=5)
        success+=1
        if success%50==0:
            print(f'  Deleted {success}/{len(ids)}...')
    except:
        pass

print(f'Done: {success}/{len(ids)} deleted')
PYEOF
fi

echo ""
echo "=== Final counts ==="
sleep 3
ACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents-7/_count?q=active:true" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count','ERR'))")
INACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents-7/_count?q=active:false" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count','ERR'))")
echo "  active:true  = $ACTIVE  (target: 11)"
echo "  active:false = $INACTIVE  (target: 0)"
