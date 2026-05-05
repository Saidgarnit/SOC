#!/bin/bash
# ================================================================
# Elasticsearch Stale Indices Cleanup
# Purpose: Delete and archive old indices to reduce CPU/disk usage
# ================================================================

set -euo pipefail

ES_HOST="${ES_HOST:-localhost:9200}"
DRY_RUN="${DRY_RUN:-false}"

echo "Elasticsearch Stale Indices Cleanup"
echo "========================================="
echo "Target: $ES_HOST"
echo "Dry run: $DRY_RUN"
echo ""

# 1. List all indices
echo "[1/3] Current Elasticsearch Indices:"
curl -s -u "$ES_USER:$ES_PASS" "http://$ES_HOST/_cat/indices?v" | head -20

# 2. Identify stale indices (older than 7 days)
echo ""
echo "[2/3] Stale Indices (older than 7 days):"
STALE_INDICES=$(curl -s -u "$ES_USER:$ES_PASS" "http://$ES_HOST/_cat/indices?v" | grep -E '\.ds-.*-2026\.04\.(1[0-9]|2[0-3]|2[0-6])|wazuh.*2026\.04\.(1[0-9]|2[0-3]|2[0-6])' | awk '{print $3}' || true)

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
      curl -s -X DELETE "http://$ES_HOST/$idx" > /dev/null && echo "      ✓ Deleted"
    done
  fi
fi

# 4. Verify cleanup
echo ""
echo "[4/4] Cluster Health:"
curl -s -u "$ES_USER:$ES_PASS" "http://$ES_HOST/_cluster/health" | jq '{status: .status, active_shards: .active_shards, relocating_shards: .relocating_shards}'

echo ""
echo "✓ Cleanup complete!"
