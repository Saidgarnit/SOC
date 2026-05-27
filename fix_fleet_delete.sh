#!/bin/bash
cd ~/soc-stack
PASS=$(grep "^ELASTIC_PASSWORD" .env | cut -d= -f2)
AUTH="elastic:$PASS"
ES="http://localhost:9200"

echo "=== Step 1: Hard-delete 753 inactive records from ES directly ==="
curl -s -u "$AUTH" -X POST "$ES/.fleet-agents/_delete_by_query" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"active":false}}}' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('Deleted:', d.get('deleted','?'), '| Failures:', len(d.get('failures',[])))"

echo ""
echo "=== Step 2: Find victim-ftp duplicates ==="
curl -s -u "$AUTH" "$ES/.fleet-agents/_search?size=10" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"active":true}},"_source":["agent.id","local_metadata.host.hostname","enrolled_at"]}' | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
hits=d['hits']['hits']
from collections import defaultdict
by_host=defaultdict(list)
for h in hits:
    src=h['_source']
    host=src.get('local_metadata',{}).get('host',{}).get('hostname','unknown')
    by_host[host].append({'es_id':h['_id'],'enrolled':src.get('enrolled_at','?')})

print('Active agents by hostname:')
to_delete=[]
for host,entries in sorted(by_host.items()):
    entries.sort(key=lambda x:x['enrolled'],reverse=True)
    for i,e in enumerate(entries):
        mark='KEEP' if i==0 else 'DELETE'
        print(f'  [{mark}] {host} | enrolled={e[\"enrolled\"]} | es_id={e[\"es_id\"]}')
        if i>0:
            to_delete.append(e['es_id'])

if to_delete:
    import json
    with open('/tmp/dup_ids.json','w') as f:
        json.dump(to_delete,f)
    print(f'\n{len(to_delete)} duplicates written to /tmp/dup_ids.json')
else:
    print('\nNo duplicates found')
    with open('/tmp/dup_ids.json','w') as f:
        json.dump([],f)
"

echo ""
echo "=== Step 3: Delete duplicates ==="
python3 -c "
import json,urllib.request,base64,subprocess

with open('/tmp/dup_ids.json') as f:
    ids=json.load(f)

if not ids:
    print('No duplicates to delete')
else:
    p=subprocess.run(['grep','^ELASTIC_PASSWORD','.env'],capture_output=True,text=True)
    pw=p.stdout.strip().split('=',1)[1]
    creds=base64.b64encode(f'elastic:{pw}'.encode()).decode()

    bulk='\n'.join([
        f'{{\"delete\":{{\"_index\":\".fleet-agents\",\"_id\":\"{i}\"}}}}'
        for i in ids
    ]) + '\n'

    req=urllib.request.Request(
        'http://localhost:9200/_bulk',
        data=bulk.encode(),
        headers={'Content-Type':'application/x-ndjson','Authorization':f'Basic {creds}'},
        method='POST'
    )
    with urllib.request.urlopen(req) as resp:
        d=json.load(resp)
        errs=[i for i in d.get('items',[]) if i.get('delete',{}).get('status',0) not in [200,404]]
        print(f'Deleted {len(ids)} duplicates, errors: {len(errs)}')
"

echo ""
echo "=== Final counts ==="
sleep 3
ACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count?q=active:true" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
INACTIVE=$(curl -s -u "$AUTH" "$ES/.fleet-agents/_count?q=active:false" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
echo "  active:true  = $ACTIVE  (target: 11)"
echo "  active:false = $INACTIVE  (target: 0)"
