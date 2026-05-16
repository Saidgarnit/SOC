#!/bin/bash
source "$(dirname "$0")/.env"

FLEET_URL="http://fleet-server:8220"
# Fetch fresh enrollment token dynamically
POLICY_ID="261c9d63-7682-4a91-9a4b-744e6c96fba4"
TOKEN=$(curl -s -X POST "http://localhost:5601/api/fleet/enrollment_api_keys"   -H "kbn-xsrf: true" -H "Content-Type: application/json"   -u "elastic:${ELASTIC_PASSWORD}"   -d "{"policy_id":"$POLICY_ID"}"   | python3 -c "import sys,json; print(json.load(sys.stdin)["item"]["api_key"])" 2>/dev/null)
[ -z "$TOKEN" ] && TOKEN="ejgyZ01KNEJZOFhzcWFUT2RROEw6OC1LN2RDdWtSenU2UGZuc09ZRWRkQQ=="
echo "[*] Enrollment token ready."

echo "[*] Waiting for fleet-server..."
until curl -s "$FLEET_URL/api/status" | grep -q "HEALTHY"; do
  sleep 5
done
echo "[*] Fleet server ready."

# Restart Wazuh agents on all containers
echo ""
echo "=== Restarting Wazuh Agents ==="
for CONTAINER in victim-ubuntu victim-iot victim-mail victim-database \
                 victim-jenkins victim-dvwa victim-windows victim-dns \
                 victim-webapi victim-ftp; do
  echo "[wazuh] Restarting agent on $CONTAINER..."
  docker exec $CONTAINER bash -c '
    if [ -f /var/ossec/bin/wazuh-control ]; then
      /var/ossec/bin/wazuh-control restart 2>/dev/null && echo "  ✓ Wazuh agent restarted" || echo "  ✗ Failed"
    else
      echo "  - Wazuh not installed"
    fi
  ' 2>/dev/null || echo "  ✗ Container not running"
done

# Re-enroll Fleet agents with elastic-agent in PATH
echo ""
echo "=== Re-enrolling Fleet Agents ==="
for CONTAINER in victim-ubuntu victim-iot victim-mail victim-database \
                 victim-jenkins victim-dvwa victim-windows; do
  echo "[*] Re-enrolling $CONTAINER..."
  docker exec $CONTAINER elastic-agent enroll \
    --url=$FLEET_URL \
    --enrollment-token=$TOKEN \
    --insecure --force 2>/dev/null | grep -i "success\|error" || true
done

# Agents needing full path
for CONTAINER in victim-webapi victim-dns; do
  echo "[*] Re-enrolling $CONTAINER (full path)..."
  docker exec $CONTAINER /opt/elastic-agent/data/elastic-agent-1eb18c/elastic-agent enroll \
    --url=$FLEET_URL \
    --enrollment-token=$TOKEN \
    --insecure --force 2>/dev/null | grep -i "success\|error" || true
done

# victim-ftp handled by its own entrypoint automatically on container start
echo ""
echo "[*] All done! Check Fleet in Kibana and Wazuh dashboard."
