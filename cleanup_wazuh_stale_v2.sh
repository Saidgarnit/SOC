#!/bin/bash

cd ~/soc-stack

WAZUH_PASS=$(grep -E "^WAZUH_API_PASSWORD|^API_PASSWORD|^WAZUH_PASSWORD" .env | head -1 | cut -d= -f2)
[ -z "$WAZUH_PASS" ] && WAZUH_PASS="SecretPassword"
echo "Using password: ${WAZUH_PASS:0:3}***"

for USER in wazuh-wui admin wazuh; do
  echo "Trying $USER..."
  TOKEN=$(curl -sk -u "$USER:$WAZUH_PASS" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
  if [ ${#TOKEN} -gt 20 ]; then
    echo "Auth OK as $USER"
    break
  fi
  TOKEN=""
done

if [ -z "$TOKEN" ]; then
  echo "API auth failed - using direct container method..."
  docker exec wazuh-manager bash -c '
    for ID in $(seq -w 1 50); do
      /var/ossec/bin/agent_control -i $ID 2>/dev/null | grep -q "Disconnected\|Never connected" && \
      echo "y" | /var/ossec/bin/manage_agents -r $ID 2>/dev/null && \
      echo "Deleted agent $ID"
    done
  '
else
  AGENT_IDS=$(curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://localhost:55000/agents?status=disconnected,never_connected&limit=100" | \
    python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  ids=[a['id'] for a in d['data']['affected_items'] if a['id']!='000']
  print(','.join(ids))
except Exception as e:
  print('',end='')
")
  echo "Stale IDs: $AGENT_IDS"
  if [ -n "$AGENT_IDS" ]; then
    curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" \
      "https://localhost:55000/agents?agents_list=$AGENT_IDS&status=all&older_than=0s" | \
      python3 -c "import sys,json; d=json.load(sys.stdin); print('Deleted:',d.get('data',{}).get('total_affected_items','?'))"
  fi
fi
echo "Done"
