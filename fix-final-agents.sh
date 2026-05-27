#!/bin/bash
echo "1. Fetching Token..."
API_KEY_JSON=$(docker exec elasticsearch curl -sf -u elastic:Kjd9r43ANUymjjcba0M6 -X POST 'http://localhost:9200/_security/api_key' -H 'Content-Type: application/json' -d '{"name":"diag_token_missing_2","expiration":"1m"}')
API_KEY=$(echo "$API_KEY_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["encoded"])')
KEYS_JSON=$(docker exec kibana curl -sf 'http://localhost:5601/api/fleet/enrollment_api_keys' -H 'kbn-xsrf: true' -H "Authorization: ApiKey $API_KEY")
TOKEN=$(echo "$KEYS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print([k['api_key'] for k in d.get('list',[]) if k.get('active')][0])")

for container in victim-ubuntu victim-windows; do
  echo "--- Reinstalling Agent on $container ---"
  
  # Try to install curl/tar if missing, then download the agent
  docker exec -u root $container bash -c "apt-get update -y && apt-get install -y curl tar" 2>/dev/null
  docker exec -u root $container bash -c "mkdir -p /opt/elastic-agent && curl -sLk https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.0-linux-x86_64.tar.gz | tar -xz -C /opt/elastic-agent --strip-components=1" 2>/dev/null
  
  # Force enroll
  docker exec -u root $container /opt/elastic-agent/elastic-agent enroll --url=http://fleet-server:8220 --enrollment-token=$TOKEN --insecure -f
  
  # Start detached
  docker exec -d -u root $container /opt/elastic-agent/elastic-agent run
done

echo "Done! Wait 30 seconds and refresh Kibana."
