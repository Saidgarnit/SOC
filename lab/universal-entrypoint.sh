#!/bin/bash
# Universal Victim Entrypoint — Starts all services + agents

set -e

echo "[$(hostname)] Starting victim services..."

# Start rsyslog/syslog
rsyslogd 2>/dev/null || service rsyslog start 2>/dev/null || true

# ════════════════════════════════════════════════════════════
# WAZUH AGENT AUTO-ENROLLMENT (Background)
# ════════════════════════════════════════════════════════════

(
  sleep 5
  HOSTNAME=$(hostname)
  
  if [ ! -f /var/ossec/etc/client.keys ] || [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[wazuh] Enrolling agent: $HOSTNAME"
    
    # Clear old state
    rm -f /var/ossec/var/run/wazuh-agentd*.pid 2>/dev/null
    
    # Enroll
    for attempt in {1..5}; do
      /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A "$HOSTNAME" 2>&1 && break
      echo "[wazuh] Attempt $attempt failed, retrying..."
      sleep 10
    done
  fi
  
  # Inject DNS query log collection for victim-dns
  if [ "$(hostname)" = "victim-dns" ]; then
    if ! grep -q "queries.log" /var/ossec/etc/ossec.conf 2>/dev/null; then
      sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/named/queries.log</location>\n  </localfile>\n</ossec_config>|' /var/ossec/etc/ossec.conf
      echo "[wazuh] Added queries.log to ossec.conf"
    fi
  fi
  # Start Wazuh agent
  /var/ossec/bin/wazuh-agentd 2>/dev/null &
  sleep 2
  /var/ossec/bin/wazuh-logcollector 2>/dev/null &
  
  echo "[wazuh] Agent started"
) &

# ════════════════════════════════════════════════════════════
# FLEET AGENT ENROLLMENT (Background)
# ════════════════════════════════════════════════════════════

(
  sleep 5
  
  # Get Fleet Server IP
  FLEET_IP=$(getent hosts fleet-server 2>/dev/null | awk '{print $1}' | head -1)
  if [ -z "$FLEET_IP" ]; then
    FLEET_IP="172.18.0.16"  # Fallback
  fi
  
  AGENT_BIN=$(find /opt/elastic-agent -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
  
  if [ -n "$AGENT_BIN" ] && [ ! -f /opt/elastic-agent/fleet.enc ]; then
    echo "[fleet] Enrolling to $FLEET_IP"
    
    cd /opt/elastic-agent
    timeout 60 $AGENT_BIN enroll \
      --url=http://$FLEET_IP:8220 \
      --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== \
      --insecure -f --skip-daemon-reload 2>&1 | grep -i success && \
      echo "[fleet] Enrollment successful" || echo "[fleet] Enrollment failed"
  fi
  
  # Start Fleet agent
  if [ -n "$AGENT_BIN" ]; then
    nohup $AGENT_BIN run > /tmp/fleet-agent.log 2>&1 &
    echo "[fleet] Agent started"
  fi
) &

# Keep container alive
tail -f /dev/null

# Fix auth.log permissions for rsyslog
touch /var/log/auth.log
chown syslog:adm /var/log/auth.log
chmod 664 /var/log/auth.log
# Restart rsyslog and sshd in correct order
pkill rsyslogd 2>/dev/null; rm -f /run/rsyslogd.pid; sleep 1
rsyslogd
sleep 2
pkill sshd 2>/dev/null; sleep 1; /usr/sbin/sshd 2>/dev/null &
