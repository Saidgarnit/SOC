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
  echo "⚠️  MISP_API_KEY not set. Set it with: export MISP_API_KEY=<key>"
fi

# 1. Check MISP service health
echo "[1/4] Testing MISP Service:"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 10 "$MISP_URL" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" =~ ^(200|301|302)$ ]]; then
  echo "  ✓ MISP service is responding (HTTP $HTTP_CODE)"
else
  echo "  ✗ MISP service not responding at $MISP_URL (HTTP $HTTP_CODE)"
  echo "  Verify MISP container is running: docker ps | grep misp"
  exit 1
fi

# 2. Check API endpoint
echo ""
echo "[2/4] Testing MISP API:"
API_RESPONSE=$(curl -sk --connect-timeout 10 "$MISP_URL/api/version" 2>/dev/null || echo '{}')
if echo "$API_RESPONSE" | grep -q "version"; then
  echo "  ✓ API responding"
else
  echo "  ✗ API not responding (response: ${API_RESPONSE:0:100})"
fi

# 3. Check authentication (if key provided)
if [ -n "$MISP_API_KEY" ]; then
  echo ""
  echo "[3/4] Testing API Key Authentication:"
  AUTH_RESPONSE=$(curl -sk --connect-timeout 10 \
    -H "Authorization: $MISP_API_KEY" \
    -H "Accept: application/json" \
    "$MISP_URL/api/events/restSearch" 2>/dev/null || echo "{}")

  if echo "$AUTH_RESPONSE" | grep -q "response\|Event"; then
    echo "  ✓ Authentication successful"
  else
    echo "  ✗ Authentication failed (check API key)"
  fi
else
  echo ""
  echo "[3/4] Authentication test: SKIPPED (no MISP_API_KEY set)"
fi

# 4. Summary
echo ""
echo "[4/4] Configuration for docker-compose.yml:"
echo "  MISP_URL=$MISP_URL"
echo "  MISP_API_KEY=<get from MISP admin panel → Administration → Auth keys>"
echo ""
echo "✓ MISP health check complete!"
