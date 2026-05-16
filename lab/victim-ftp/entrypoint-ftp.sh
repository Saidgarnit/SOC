#!/bin/bash
set -e
echo "[$(hostname)] Starting victim-ftp services..."

# --- Wazuh Agent Setup ---
if [ -f /var/ossec/bin/wazuh-control ]; then
    echo "[wazuh] Configuring Wazuh agent..."
    
    # Create wazuh user/group if needed
    groupadd -g 1000 wazuh 2>/dev/null || true
    useradd -u 1000 -g 1000 -d /var/ossec -s /sbin/nologin wazuh 2>/dev/null || true
    
    # Fix manager address if placeholder exists
    sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf 2>/dev/null
    
    # Set permissions on client.keys if it exists
    if [ -f /var/ossec/etc/client.keys ]; then
        chown root:wazuh /var/ossec/etc/client.keys
        chmod 640 /var/ossec/etc/client.keys
    fi
    
    # Clean up stale PIDs
    rm -f /var/ossec/var/run/*.pid 2>/dev/null
    
    # Start Wazuh agent
    /var/ossec/bin/wazuh-control start 2>/dev/null
    echo "[wazuh] Wazuh agent started"
    
    # Start watchdog to keep agent running
    nohup /bin/bash /tmp/wazuh-watchdog.sh &>/dev/null &
    echo "[wazuh] Watchdog started"
else
    echo "[wazuh] Agent not installed — skipping"
fi

# --- Elastic Fleet Agent Setup (background) ---
(
  sleep 8
  FLEET_IP=$(getent hosts fleet-server 2>/dev/null | awk '{print $1}' | head -1)
  [ -z "$FLEET_IP" ] && FLEET_IP="172.18.0.16"
  AGENT_BIN=$(find /opt/elastic-agent -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
  
  if [ -n "$AGENT_BIN" ]; then
    echo "[fleet] Starting agent daemon first..."
    nohup $AGENT_BIN run \
      --path.home=/opt/elastic-agent \
      --path.config=/opt/elastic-agent \
      > /tmp/fleet-agent.log 2>&1 &
    AGENT_PID=$!
    echo "[fleet] Agent daemon started (PID $AGENT_PID)"
    
    # Wait for socket to appear
    echo "[fleet] Waiting for socket..."
    for i in $(seq 1 20); do
      [ -S /opt/elastic-agent/elastic-agent.sock ] && break
      sleep 2
    done
    
    echo "[fleet] Enrolling to http://$FLEET_IP:8220"
    $AGENT_BIN enroll \
      --url=http://$FLEET_IP:8220 \
      --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== \
      --path.home=/opt/elastic-agent \
      --path.config=/opt/elastic-agent \
      --insecure -f 2>&1 | tail -3
    echo "[fleet] Done."
  else
    echo "[fleet] ERROR: binary not found"
  fi
) &

# --- Start FTP Server ---
exec /usr/sbin/run-vsftpd.sh
