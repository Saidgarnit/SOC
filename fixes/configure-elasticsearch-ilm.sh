#!/bin/bash
# Configure Elasticsearch Index Lifecycle Management

set -e

ES_HOST="172.18.0.11:9200"

echo "=== Configuring Elasticsearch ILM Policy ==="

# Create 30-day retention policy
curl -X PUT "http://$ES_HOST/_ilm/policy/soc-retention-30d" \
  -H 'Content-Type: application/json' \
  -d '{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_age": "1d",
            "max_primary_shard_size": "50gb"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "set_priority": {
            "priority": 50
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

echo ""
echo "ILM Policy created"

# Apply to existing indices
curl -X PUT "http://$ES_HOST/_index_template/soc-retention" \
  -H 'Content-Type: application/json' \
  -d '{
  "index_patterns": ["filebeat-*", "wazuh-alerts-*", "winlogbeat-*"],
  "template": {
    "settings": {
      "index.lifecycle.name": "soc-retention-30d",
      "index.lifecycle.rollover_alias": "soc-logs"
    }
  },
  "priority": 500
}'

echo ""
echo "Index template applied"

# Verify policy
echo ""
echo "Verifying policy..."
curl -X GET "http://$ES_HOST/_ilm/policy/soc-retention-30d?pretty"

echo ""
echo "=== ILM Configuration Complete ==="
echo "Policy: Delete indices after 30 days"
echo "Rollover: Daily or at 50GB per shard"
