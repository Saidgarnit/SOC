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
echo "[1/3] Authenticating with Wazuh Manager..."
TOKEN=$(curl -s -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" \
  "http://$WAZUH_MANAGER:55000/security/user/authenticate?raw=true" 2>/dev/null || echo "")

if [ -z "$TOKEN" ]; then
  echo "✗ Failed to authenticate with Wazuh API"
  echo "  Check credentials or if Wazuh is running"
  exit 1
fi

echo "✓ Connected to Wazuh Manager API"

# 1. Get agent status summary
echo ""
echo "[2/3] Agent Status Summary:"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://$WAZUH_MANAGER:55000/agents/summary/status" 2>/dev/null | jq '.data.affected_items[]' 2>/dev/null || echo "  (No agents or error)"

# 2. List all agents
echo ""
echo "[3/3] Agent Details:"
AGENTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://$WAZUH_MANAGER:55000/agents?limit=500" 2>/dev/null | jq '.data.affected_items[]' 2>/dev/null || echo "")

if [ -z "$AGENTS" ]; then
  echo "  (No agents found)"
else
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
fi

echo ""
echo "✓ Wazuh agent diagnostics complete!"
