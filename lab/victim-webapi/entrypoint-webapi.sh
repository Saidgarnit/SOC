#!/bin/bash

# --- Wazuh agent ---
if [ -f /var/ossec/bin/wazuh-control ]; then
    groupadd -g 1000 wazuh 2>/dev/null || true
    useradd -u 1000 -g 1000 -d /var/ossec -s /sbin/nologin wazuh 2>/dev/null || true
    sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf 2>/dev/null
    rm -f /var/ossec/var/run/*.pid 2>/dev/null
    /var/ossec/bin/wazuh-control start 2>/dev/null
    nohup /bin/bash /tmp/wazuh-watchdog.sh &>/dev/null &
fi

# --- Elastic Fleet agent ---
(
  sleep 10
  AGENT_BIN=$(find /opt/elastic-agent -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
  if [ -n "$AGENT_BIN" ]; then
    nohup $AGENT_BIN run > /tmp/fleet-agent.log 2>&1 &
    echo "[fleet] Agent started, waiting for socket..."
    for i in $(seq 1 20); do
      find /opt/elastic-agent -name '*.sock' | grep -q . && break
      sleep 2
    done
    $AGENT_BIN enroll \
      --url=http://fleet-server:8220 \
      --enrollment-token=cjF6NlA1NEJnNHpNODBSWkNib1A6N3k0dUFZcnpRNGFpNVAwYXByTncwZw== \
      --insecure -f 2>&1 | tail -3
    echo "[fleet] Enrolled."
  fi
) &

# --- Start bWAPP ---
exec /run.sh
