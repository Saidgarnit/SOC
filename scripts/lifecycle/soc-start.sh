#!/bin/bash
cd ~/soc-stack

echo "[1/4] Starting full SOC stack..."
docker compose up -d
sleep 40

echo "[2/4] Restarting Wazuh agent on victim-ubuntu..."
docker exec victim-ubuntu /var/ossec/bin/wazuh-control restart
sleep 15

echo "[3/4] Verifying agent connection..."
docker exec victim-ubuntu grep "status\|last_ack\|msg_count" \
  /var/ossec/var/run/wazuh-agentd.state

echo "[4/4] Verifying agents on manager..."
docker exec wazuh-manager /var/ossec/bin/agent_control -l \
  | grep -E "victim|Active"

echo "SOC stack ready."
