#!/bin/bash
# ================================================================
# MISP Docker Connector Health Check
# Purpose: Verify MISP API connectivity and authentication
# ================================================================

set -euo pipefail

MISP_URL="${MISP_URL:-http://misp:80}"
MISP_API_KEY="${MISP_API_KEY:-}"

echo "MISP Connector Health Check"
echo "========================================="
echo "MISP URL: $MISP_URL"
echo ""

if [ -z "$MISP_API_KEY" ]; then
  echo "⚠️  MISP_API_KEY not set. Using guest access..."
fi

# 1. Check MISP service health
echo "[1/4] Testing MISP Service:"
if curl -s -k "$MISP_URL" | grep -q "MISP"; then
  echo "  ✓ MISP service is responding"
else
  echo "  ✗ MISP service not responding"
  exit 1
fi

# 2. Check API endpoint
echo ""
echo "[2/4] Testing MISP API:"
API_RESPONSE=$(curl -s -k "$MISP_URL/api/version" 2>/dev/null || echo '{"version": "unknown"}')
echo "$API_RESPONSE" | jq '.version' && echo "  ✓ API responding"

# 3. Check authentication (if key provided)
if [ -n "$MISP_API_KEY" ]; then
  echo ""
  echo "[3/4] Testing API Key Authentication:"
  AUTH_RESPONSE=$(curl -s -k -H "Authorization: $MISP_API_KEY" \
    "$MISP_URL/api/events/restSearch" 2>/dev/null | jq '.response | length' || echo "0")
  
  if [ "$AUTH_RESPONSE" != "0" ]; then
    echo "  ✓ Authentication successful"
  else
    echo "  ✗ Authentication failed or no events"
  fi
fi

# 4. Summary
echo ""
echo "[4/4] Configuration for docker-compose.yml:"
echo "  MISP_URL=$MISP_URL"
echo "  MISP_API_KEY=<your_key_here>"
echo ""
echo "✓ MISP health check complete!"
echo "  If authentication failed, verify the API key in MISP admin panel."
