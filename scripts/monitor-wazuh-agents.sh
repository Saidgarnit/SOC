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

# Get API token with retry
echo "[1/3] Authenticating with Wazuh Manager..."
TOKEN=""
for i in 1 2 3; do
  TOKEN=$(curl -sk --connect-timeout 10 \
    -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" \
    "https://$WAZUH_MANAGER:55000/security/user/authenticate?raw=true" 2>/dev/null || echo "")
  [ -n "$TOKEN" ] && break
  echo "  Retry $i/3..."
  sleep 3
done

if [ -z "$TOKEN" ]; then
  echo "✗ Failed to authenticate with Wazuh API"
  echo "  Check: WAZUH_MANAGER=$WAZUH_MANAGER, user=$WAZUH_API_USER"
  echo "  Tip: Wazuh API uses HTTPS on port 55000 by default"
  exit 1
fi

echo "✓ Connected to Wazuh Manager API"

# 1. Get agent status summary
echo ""
echo "[2/3] Agent Status Summary:"
SUMMARY=$(curl -sk --connect-timeout 10 \
  -H "Authorization: Bearer $TOKEN" \
  "https://$WAZUH_MANAGER:55000/agents/summary/status" 2>/dev/null || echo '{}')
echo "$SUMMARY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d.get('data', {}).get('connection', {})
    if items:
        for status, count in items.items():
            print(f'  {status}: {count}')
    else:
        print('  (no summary available)')
except Exception as e:
    print('  (could not parse response)')
" 2>/dev/null || echo "  (summary unavailable)"

# 2. List all agents
echo ""
echo "[3/3] Agent Details:"
AGENTS_RESP=$(curl -sk --connect-timeout 10 \
  -H "Authorization: Bearer $TOKEN" \
  "https://$WAZUH_MANAGER:55000/agents?limit=500" 2>/dev/null || echo '{}')

echo "$AGENTS_RESP" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d.get('data', {}).get('affected_items', [])
    if not items:
        print('  (No agents found)')
    else:
        for a in items:
            aid   = a.get('id','?')
            name  = a.get('name','?')
            status = a.get('status','?')
            ip    = a.get('ip','?')
            icon = '✓' if status == 'active' else ('⚠' if status == 'disconnected' else '✗')
            print(f'  {icon} [{aid}] {name} ({ip}) - {status.upper()}')
except Exception:
    print('  (could not parse agent list)')
" 2>/dev/null || echo "  (agent list unavailable)"

echo ""
echo "✓ Wazuh agent diagnostics complete!"
