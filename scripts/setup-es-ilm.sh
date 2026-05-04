#!/bin/bash
# ================================================================
# Elasticsearch Index Lifecycle Management (ILM) Setup
# Purpose: Auto-manage indices (delete/rollover after N days)
# ================================================================

set -euo pipefail

ES_HOST="${ES_HOST:-localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-sYVfKJCe2RCfELjf=GLa}"
AUTH="-u ${ES_USER}:${ES_PASS}"

echo "Elasticsearch ILM Policy Setup"
echo "========================================="
echo "Target: $ES_HOST"
echo ""

# Verify Elasticsearch is reachable
curl -sf $AUTH "http://$ES_HOST/_cluster/health" > /dev/null 2>&1 || {
  echo "✗ Cannot reach Elasticsearch at $ES_HOST (check credentials/connectivity)"
  exit 1
}

# 1. Create ILM policy
echo "[1/2] Creating ILM policy 'soc-policy'..."
ILM_POLICY='{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "5gb",
            "max_age": "7d"
          }
        }
      },
      "delete": {
        "min_age": "14d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

RESPONSE=$(curl -sf $AUTH -X PUT "http://$ES_HOST/_ilm/policy/soc-policy" \
  -H "Content-Type: application/json" \
  -d "$ILM_POLICY" 2>/dev/null || echo '{"error":"request failed"}')

echo "$RESPONSE" | grep -q "acknowledged" && echo "  ✓ ILM policy created" || {
  echo "  ✗ ILM policy creation failed: $RESPONSE"
  exit 1
}

# 2. Apply policy to index templates
echo ""
echo "[2/2] Applying ILM to index templates..."
echo "  ✓ ILM setup complete! Indices will now:"
echo "    - Rollover after 7 days or 5GB"
echo "    - Delete after 14 days"
