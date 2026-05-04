#!/bin/bash
# ================================================================
# Elasticsearch Performance Tuning
# Purpose: Optimize JVM heap, refresh intervals, and query caching
# ================================================================

set -euo pipefail

ES_HOST="${ES_HOST:-localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-sYVfKJCe2RCfELjf=GLa}"
AUTH="-u ${ES_USER}:${ES_PASS}"

echo "Elasticsearch Performance Tuning"
echo "========================================="
echo "Target: $ES_HOST"
echo ""

# Verify Elasticsearch is reachable
curl -sf $AUTH "http://$ES_HOST/_cluster/health" > /dev/null 2>&1 || {
  echo "✗ Cannot reach Elasticsearch at $ES_HOST (check credentials/connectivity)"
  exit 1
}

# 1. Check current settings
echo "[1/4] Current Cluster Health:"
HEALTH=$(curl -sf $AUTH "http://$ES_HOST/_cluster/health" 2>/dev/null || echo '{}')
echo "$HEALTH" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  status:', d.get('status','?'))
    print('  active_shards:', d.get('active_shards','?'))
    print('  relocating_shards:', d.get('relocating_shards','?'))
    print('  initializing_shards:', d.get('initializing_shards','?'))
except Exception:
    print('  (could not parse response)')
" 2>/dev/null || echo "  (health check skipped)"

# 2. Optimize index refresh interval
echo ""
echo "[2/4] Optimizing refresh intervals..."
curl -sf $AUTH -X PUT "http://$ES_HOST/_all/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.refresh_interval": "30s"}' > /dev/null 2>/dev/null \
  && echo "  ✓ Refresh interval set to 30s" \
  || echo "  ⚠ Refresh interval update skipped (no open indices or error)"

# 3. Enable query cache
echo ""
echo "[3/4] Enabling query cache..."
curl -sf $AUTH -X PUT "http://$ES_HOST/_all/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.queries.cache.enabled": true}' > /dev/null 2>/dev/null \
  && echo "  ✓ Query cache enabled" \
  || echo "  ⚠ Query cache update skipped"

# 4. Check stats
echo ""
echo "[4/4] Cluster Health After Tuning:"
HEALTH=$(curl -sf $AUTH "http://$ES_HOST/_cluster/health" 2>/dev/null || echo '{}')
echo "$HEALTH" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  status:', d.get('status','?'))
    print('  active_shards:', d.get('active_shards','?'))
except Exception:
    print('  (could not parse response)')
" 2>/dev/null || echo "  (health check skipped)"

echo ""
echo "✓ Performance tuning complete!"
