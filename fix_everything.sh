#!/bin/bash
cd ~/soc-stack

echo "Step 1: Fix ES green (replicas -> 0)"
curl -s -X PUT "localhost:9200/_settings" -u "elastic:SOCstack2026!" -H 'Content-Type: application/json' -d'{"index" : {"number_of_replicas" : 0}}'
curl -s -X PUT "localhost:9200/*/_settings" -u "elastic:SOCstack2026!" -H 'Content-Type: application/json' -d'{"index" : {"number_of_replicas" : 0}}'

echo "Step 2: Kibana up (recreate container)"
docker compose up -d --force-recreate kibana

echo "Step 3: Fix analysisd (remove bad rules)"
rm -f wazuh/rules/windows_event_rules.xml
docker restart wazuh-manager

echo "Step 4: Fix MISP key (disable hash)"
docker exec misp php /var/www/MISP/app/Console/cake.php Admin setSetting MISP.advanced_authkeys false || true

echo "Step 5: Network (full compose up)"
docker compose up -d --remove-orphans

echo "Done fixing."
