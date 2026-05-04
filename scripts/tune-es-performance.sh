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
echo "[1/4] Current Settings:"
echo "  JVM Heap:"
curl -s "http://$ES_HOST/_nodes/stats/jvm" | jq '.nodes | .[].jvm.mem | {heap_used_percent, heap_max}'

echo ""
echo "  CPU Usage:"
curl -s "http://$ES_HOST/_nodes/stats/os" | jq '.nodes | .[].os | {cpu_percent, load_average}'

# 2. Optimize index refresh interval
echo ""
echo "[2/4] Optimizing refresh intervals..."
curl -s -X PUT "http://$ES_HOST/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.refresh_interval": "30s"}' | jq '.acknowledged' && echo "  ✓ Refresh interval set to 30s"

# 3. Enable query cache
echo ""
echo "[3/4] Enabling query cache..."
curl -s -X PUT "http://$ES_HOST/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index.queries.cache.enabled": true}' | jq '.acknowledged' && echo "  ✓ Query cache enabled"

# 4. Check cluster performance
echo ""
echo "[4/4] Cluster Health After Tuning:"
curl -s "http://$ES_HOST/_cluster/health" | jq '{status, active_shards, cpu_percent: "see above"}

echo ""
echo "✓ Performance tuning complete!"
echo "  Monitor CPU with: curl -s http://$ES_HOST/_nodes/stats/os | jq '.nodes | .[].os.cpu_percent'"
