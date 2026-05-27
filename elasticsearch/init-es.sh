#!/bin/bash
set -e
echo "Waiting for Elasticsearch..."
until curl -sf -u elastic:Kjd9r43ANUymjjcba0M6 http://elasticsearch:9200/_cluster/health; do sleep 5; done
echo "Setting replicas to 0 for single-node..."
curl -sf -u elastic:Kjd9r43ANUymjjcba0M6 -X PUT "http://elasticsearch:9200/_settings" -H 'Content-Type: application/json' -d '{"index.number_of_replicas": 0}' >/dev/null
echo "Init complete!"
