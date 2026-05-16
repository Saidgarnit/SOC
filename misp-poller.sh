#!/bin/bash
while true; do
  echo "$(date) - Polling MISP..."
  curl -sk --http1.1 \
    -H "Authorization: S3UcdQZ4cx6T8BhSsjOtMqJ3VdRfPj38RUNFCU0t" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -X POST https://172.18.0.27:443/events/restSearch/json \
    -d '{"limit":"100","published":"1"}' | \
  curl -sk -X POST "http://localhost:9200/misp-threat-intel-$(date +%Y.%m.%d)/doc" \
    -u elastic:sYVfKJCe2RCfELjf=GLa \
    -H "Content-Type: application/json" \
    -d @-
  echo "Sleeping 5 minutes..."
  sleep 300
done
