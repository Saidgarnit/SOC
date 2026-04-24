#!/bin/sh
# Kill existing
pkill -f wazuh-watchdog 2>/dev/null
pkill -f wazuh-agentd 2>/dev/null
sleep 2
# Start agentd directly - watchdog will be the shell loop itself
while true; do
  /var/ossec/bin/wazuh-agentd
  echo "$(date): agentd exited, restarting..." >> /var/ossec/logs/watchdog.log
  sleep 5
done
