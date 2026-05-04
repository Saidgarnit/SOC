#!/bin/bash
# ================================================================
# Wazuh Agent Auto-Enrollment Monitor & Fix
# Purpose: Track agent enrollment status and auto-repair failures
# ================================================================

set -euo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:-localhost}"
WAZUH_API_USER="${WAZUH_API_USER:-wazuh}"
WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-wazuh}"

echo "Wazuh Agent Enrollment Diagnostics"
echo "========================================="

# Get API token
echo "[1/4] Authenticating with Wazuh Manager..."
TOKEN=$(curl -s -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" \
  "http://$WAZUH_MANAGER:55000/security/user/authenticate?raw=true")

if [ -z "$TOKEN" ]; then
  echo "✗ Failed to authenticate with Wazuh API"
  echo "  Check credentials: WAZUH_API_USER / WAZUH_API_PASSWORD"
  exit 1
fi

echo "✓ Connected to Wazuh Manager API"

# 1. Get agent status summary
echo ""
echo "[2/4] Agent Status Summary:"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://$WAZUH_MANAGER:55000/agents/summary/status" | jq '.data.affected_items[] | {status, count}'

# 2. List all agents
echo ""
echo "[3/4] Agent Details:"
AGENTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://$WAZUH_MANAGER:55000/agents?limit=500" | jq '.data.affected_items[]')

echo "$AGENTS" | jq -r '@csv' | while IFS=',' read -r ID NAME STATUS _ _; do
  STATUS=$(echo "$STATUS" | tr -d '"')
  ID=$(echo "$ID" | tr -d '"')
  NAME=$(echo "$NAME" | tr -d '"')
  
  case "$STATUS" in
    "active")
      echo "  ✓ [$ID] $NAME - ACTIVE"
      ;;
    "inactive")
      echo "  ⚠ [$ID] $NAME - INACTIVE"
      ;;
    "never_connected")
      echo "  ✗ [$ID] $NAME - NEVER_CONNECTED"
      ;;
  esac
done

# 3. Recommendations
echo ""
echo "[4/4] Troubleshooting:"
echo "  If agents show INACTIVE or NEVER_CONNECTED:"
echo ""
echo "  A. Check agent logs:"
echo "     docker logs <agent_container> 2>&1 | tail -50"
echo ""
echo "  B. Force agent re-enrollment:"
echo "     docker exec <agent_container> /var/ossec/bin/wazuh-control restart"
echo ""
echo "  C. Manual enrollment (SSH to agent host):"
echo "     /var/ossec/bin/agent-auth -m $WAZUH_MANAGER -A <agent_name>"
echo ""
echo "✓ Wazuh agent diagnostics complete!"
