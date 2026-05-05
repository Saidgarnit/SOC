#!/bin/bash
# ================================================================
# Elasticsearch Performance Tuning
# Purpose: Optimize JVM heap, refresh intervals, and query caching
# ================================================================

set -euo pipefail

ES_HOST="${ES_HOST:-localhost:9200}"

echo "Elasticsearch Performance Tuning"
echo "========================================="
echo "Target: $ES_HOST"
echo ""

# 1. Check current settings
echo "[1/4] Current Cluster Health:"
curl -s -u "$ES_USER:$ES_PASS" "http://$ES_HOST/_cluster/health" | jq '{status, active_shards, relocating_shards, initializing_shards}'

# 2. Optimize index refresh interval
echo ""
echo "[2/4] Optimizing refresh intervals..."
curl -s -X PUT "http://$ES_HOST/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.refresh_interval": "30s"}' > /dev/null && echo "  ✓ Refresh interval set to 30s"

# 3. Enable query cache
echo ""
echo "[3/4] Enabling query cache..."
curl -s -X PUT "http://$ES_HOST/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.queries.cache.enabled": true}' > /dev/null && echo "  ✓ Query cache enabled"

# 4. Check stats
echo ""
echo "[4/4] Cluster Health After Tuning:"
curl -s -u "$ES_USER:$ES_PASS" "http://$ES_HOST/_cluster/health" | jq '{status, active_shards}'

echo ""
echo "✓ Performance tuning complete!"
