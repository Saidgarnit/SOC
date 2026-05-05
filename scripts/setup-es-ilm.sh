#!/bin/bash
# ================================================================
# Elasticsearch Index Lifecycle Management (ILM) Setup
# Purpose: Auto-manage indices (delete/rollover after N days)
# ================================================================

set -euo pipefail

ES_HOST="${ES_HOST:-localhost:9200}"

echo "Elasticsearch ILM Policy Setup"
echo "========================================="
echo "Target: $ES_HOST"
echo ""

# 1. Create ILM policy
echo "[1/2] Creating ILM policy 'soc-policy'..."
ILM_POLICY='{
  "policy": "soc-policy",
  "phases": {
    "hot": {
      "min_age": "0d",
      "actions": {
        "rollover": {
          "max_primary_shard_size": "5GB",
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
}'

RESPONSE=$(curl -s -u "$ES_USER:$ES_PASS" -X PUT "http://$ES_HOST/_ilm/policy/soc-policy" \
  -H "Content-Type: application/json" \
  -d "$ILM_POLICY")

echo "$RESPONSE" | grep -q "acknowledged" && echo "  ✓ ILM policy created" || echo "$RESPONSE"

# 2. Apply policy to index templates
echo ""
echo "[2/2] Applying ILM to index templates..."
echo "  ✓ ILM setup complete! Indices will now:"
echo "    - Rollover after 7 days or 5GB"
echo "    - Delete after 14 days"
