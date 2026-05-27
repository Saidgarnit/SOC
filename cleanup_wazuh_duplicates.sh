#!/bin/bash
# Clean up duplicate/stale Wazuh agents on the manager

set -e
cd ~/soc-stack || exit 1

echo "🧹 WAZUH AGENT CLEANUP (Manager-Side)"
echo "════════════════════════════════════════════════════════════"
echo ""

echo "Current Wazuh agents registered on manager:"
docker exec wazuh-manager /var/ossec/bin/manage_agents -l

echo ""
echo "These agents are registered but disconnected/inactive."
echo "We need to remove them so containers can re-register."
echo ""

# Get list of all agents except 000 (manager itself)
AGENT_IDS=$(docker exec wazuh-manager /var/ossec/bin/manage_agents -l 2>/dev/null | \
    grep -oP '^\s*\K\d+(?=,)' | grep -v '^000$')

if [ -z "$AGENT_IDS" ]; then
    echo "No agents to remove!"
    exit 0
fi

echo "Agents to remove:"
for id in $AGENT_IDS; do
    agent_info=$(docker exec wazuh-manager /var/ossec/bin/manage_agents -l | grep "^   $id,")
    echo "  $agent_info"
done

echo ""
read -p "Remove all these agents? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Removing agents..."

for id in $AGENT_IDS; do
    echo -n "  Removing agent $id..."
    # Use manage_agents to remove by ID
    docker exec wazuh-manager /var/ossec/bin/manage_agents <<EOF > /dev/null 2>&1
r
$id
y
q
EOF
    echo " ✅"
done

echo ""
echo "Restarting Wazuh manager to apply changes..."
docker restart wazuh-manager
sleep 10

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "Remaining agents:"
docker exec wazuh-manager /var/ossec/bin/manage_agents -l
echo ""
echo "Now you can run enroll_missing_agents.sh to re-enroll all agents"
