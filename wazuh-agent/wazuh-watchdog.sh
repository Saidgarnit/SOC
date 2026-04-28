#!/bin/bash
chown root:wazuh /var/ossec/etc/client.keys 2>/dev/null
chmod 640 /var/ossec/etc/client.keys 2>/dev/null
pkill -f wazuh-agentd 2>/dev/null
sleep 2
while true; do
  echo "[$(date)] Starting wazuh-agentd..." >> /var/ossec/logs/agentd-watchdog.log
  /var/ossec/bin/wazuh-agentd -f >> /var/ossec/logs/agentd-watchdog.log 2>&1
  echo "[$(date)] wazuh-agentd exited (code $?), restarting in 5s..." >> /var/ossec/logs/agentd-watchdog.log
  sleep 5
done
