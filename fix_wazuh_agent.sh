#!/bin/bash
# Usage: bash fix_wazuh_agent.sh victim-ubuntu
CONTAINER=$1
if [ -z "$CONTAINER" ]; then echo "Usage: $0 <container-name>"; exit 1; fi

cd ~/soc-stack

# Find the agent ID on the manager
AGENT_ID=$(docker exec wazuh-manager /var/ossec/bin/agent_control -l \
  | grep "$CONTAINER" | grep -oP 'ID: \K[0-9]+')

if [ -z "$AGENT_ID" ]; then
  echo "Agent $CONTAINER not found on manager, skipping delete"
else
  echo "Removing agent ID $AGENT_ID ($CONTAINER) from manager..."
  docker exec -i wazuh-manager /var/ossec/bin/manage_agents << HEREDOC
R
$AGENT_ID
y
Q
HEREDOC
fi

echo "Re-enrolling $CONTAINER..."
docker exec "$CONTAINER" bash -c '
  > /var/ossec/etc/client.keys
  /var/ossec/bin/wazuh-control stop 2>/dev/null; sleep 2
  /var/ossec/bin/agent-auth -m wazuh-manager; sleep 2
  /var/ossec/bin/wazuh-control start
'

sleep 15
echo "Result:"
docker exec wazuh-manager /var/ossec/bin/agent_control -l | grep -E "$CONTAINER|server"
