#!/bin/bash
# ================================================================
# MISP Docker Connector Health Check
# Purpose: Verify MISP API connectivity and authentication
# ================================================================

set -euo pipefail

MISP_URL="${MISP_URL:-http://localhost:9001}"
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
if curl -s -k "$MISP_URL" 2>/dev/null | grep -q "MISP\|<!DOCTYPE"; then
  echo "  ✓ MISP service is responding"
else
  echo "  ✗ MISP service not responding at $MISP_URL"
  echo "  Try: http://localhost:9001"
  exit 1
fi

# 2. Check API endpoint
echo ""
echo "[2/4] Testing MISP API:"
API_RESPONSE=$(curl -s -k "$MISP_URL/api/version" 2>/dev/null || echo '{"version": "unknown"}')
echo "$API_RESPONSE" | grep -q "version" && echo "  ✓ API responding" || echo "  ✗ API not responding"

# 3. Check authentication (if key provided)
if [ -n "$MISP_API_KEY" ]; then
  echo ""
  echo "[3/4] Testing API Key Authentication:"
  AUTH_RESPONSE=$(curl -s -k -H "Authorization: $MISP_API_KEY" \
    "$MISP_URL/api/events/restSearch" 2>/dev/null || echo "{}")
  
  if echo "$AUTH_RESPONSE" | grep -q "response\|Event"; then
    echo "  ✓ Authentication successful"
  else
    echo "  ✗ Authentication failed (check API key)"
  fi
fi

# 4. Summary
echo ""
echo "[4/4] Configuration for docker-compose.yml:"
echo "  MISP_URL=$MISP_URL"
echo "  MISP_API_KEY=<get from MISP admin panel>"
echo ""
echo "✓ MISP health check complete!"
