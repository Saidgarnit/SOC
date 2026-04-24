#!/bin/bash
# Run this after: docker-compose up -d
# Ensures all wazuh agents are enrolled and running

MANAGER="wazuh-manager"
AGENTS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database"

echo "=== Waiting for manager to be ready ==="
sleep 10

echo "=== Enrolling agents ==="
for c in $AGENTS; do
  # Check if already enrolled on manager
  KEY=$(docker exec $MANAGER grep " $c " /var/ossec/etc/client.keys 2>/dev/null)
  if [ -z "$KEY" ]; then
    docker exec $c sh -c "/var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A $c 2>&1 | tail -1"
    echo "Enrolled: $c"
  else
    # Key exists on manager but may be missing on agent - sync it
    docker exec $c sh -c "echo '$KEY' > /var/ossec/etc/client.keys && chmod 640 /var/ossec/etc/client.keys"
    echo "Key synced: $c"
  fi
done

echo "=== Starting agents ==="
for c in $AGENTS; do
  docker cp ~/soc-stack/start-wazuh.sh $c:/usr/local/bin/start-wazuh.sh 2>/dev/null
  docker exec -d $c /usr/local/bin/start-wazuh.sh
  sleep 1
done

echo "=== Waiting 20s for connections ==="
sleep 20
docker exec $MANAGER /var/ossec/bin/agent_control -l
