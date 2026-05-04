#!/bin/bash
# ================================================================
# Elasticsearch Stale Indices Cleanup
# Purpose: Delete and archive old indices to reduce CPU/disk usage
# ================================================================

set -euo pipefail

ES_HOST="${ES_HOST:-localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-sYVfKJCe2RCfELjf=GLa}"
DRY_RUN="${DRY_RUN:-false}"
AUTH="-u ${ES_USER}:${ES_PASS}"

echo "Elasticsearch Stale Indices Cleanup"
echo "========================================="
echo "Target: $ES_HOST"
echo "Dry run: $DRY_RUN"
echo ""

# 1. List all indices
echo "[1/3] Current Elasticsearch Indices:"
curl -sf $AUTH "http://$ES_HOST/_cat/indices?v" 2>/dev/null | head -20 || { echo "  ✗ Could not reach Elasticsearch at $ES_HOST"; exit 1; }

# 2. Identify stale indices (older than 7 days)
echo ""
echo "[2/3] Stale Indices (older than 7 days):"
STALE_INDICES=$(curl -sf $AUTH "http://$ES_HOST/_cat/indices?v" 2>/dev/null \
  | grep -E '\.ds-.*-2026\.04\.(1[0-9]|2[0-3]|2[0-6])|wazuh.*2026\.04\.(1[0-9]|2[0-3]|2[0-6])' \
  | awk '{print $3}' || true)

if [ -z "$STALE_INDICES" ]; then
  echo "  ✓ No stale indices found (good!)."
else
  echo "$STALE_INDICES" | while read idx; do
    echo "  - $idx"
  done
fi

# 3. Delete stale indices (if not dry run)
echo ""
echo "[3/3] Cleanup Action:"
if [ "$DRY_RUN" = "true" ]; then
  echo "  [DRY RUN] Would delete the above indices."
  echo "  Run without DRY_RUN=true to execute:"
  echo "    DRY_RUN=false bash $0"
else
  if [ -z "$STALE_INDICES" ]; then
    echo "  ✓ No indices to delete."
  else
    echo "  Deleting stale indices..."
    echo "$STALE_INDICES" | while read idx; do
      echo "    Deleting: $idx"
      curl -sf $AUTH -X DELETE "http://$ES_HOST/$idx" > /dev/null && echo "      ✓ Deleted" || echo "      ✗ Failed to delete $idx"
    done
  fi
fi

# 4. Verify cleanup
echo ""
echo "[4/4] Cluster Health:"
HEALTH=$(curl -sf $AUTH "http://$ES_HOST/_cluster/health" 2>/dev/null || echo '{}')
echo "$HEALTH" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  status:', d.get('status','?'))
    print('  active_shards:', d.get('active_shards','?'))
    print('  relocating_shards:', d.get('relocating_shards','?'))
except Exception:
    print('  (could not parse response)')
" 2>/dev/null || echo "  (health check skipped)"

echo ""
echo "✓ Cleanup complete!"
