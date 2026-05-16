#!/bin/bash
echo "🔧 SOC stack fixes (no restart)..."
source "$(dirname "$0")/.env"
PASS="${ELASTIC_PASSWORD}"
FLEET_TOKEN="RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw=="
WAZUH_MANAGER="wazuh-manager"
ALL_VICTIMS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database victim-ftp victim-webapi victim-metasploitable"
FLEET_VICTIMS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database victim-ftp victim-webapi"

# ── Step 0: Wazuh Manager Remote Syslog ──
echo "🔧 Step 0: Ensuring Wazuh Manager accepts remote syslog..."
docker exec $WAZUH_MANAGER python3 -c "import os; p='/var/ossec/etc/ossec.conf'; c=open(p).read(); open(p,'w').write(c.replace('<remote>', '\n  <remote>\n    <connection>syslog</connection>\n    <port>514</port>\n    <protocol>udp</protocol>\n    <allowed-ips>172.18.0.0/16</allowed-ips>\n  </remote>\n\n  <remote>', 1)) if 'syslog' not in c else None"
docker exec $WAZUH_MANAGER /var/ossec/bin/wazuh-control restart >/dev/null 2>&1

# ── Step 1: Fleet-server health & recovery ──
echo "🔧 Step 1: Fleet-server health check..."
FLEET_HEALTHY=$(curl -s --max-time 5 http://localhost:8220/api/status 2>/dev/null | grep -c "HEALTHY")
if [ "$FLEET_HEALTHY" -eq 0 ]; then
    docker rm -f fleet-server 2>/dev/null
    docker compose -f ~/soc-stack/docker-compose-lab.yml up -d fleet-server 2>/dev/null
    sleep 30
fi

# ── Step 2-5: Logging & Agent Fixes ──
echo "🔧 Step 2: Logging & Agent Persistence..."
for VICTIM in $ALL_VICTIMS; do
    docker ps --format '{{.Names}}' | grep -q "^$VICTIM$" || continue
    
    # Logging Fixes
    if [ "$VICTIM" == "victim-metasploitable" ]; then
        docker exec $VICTIM bash -c "grep -q '172.18.0.30' /etc/syslog.conf || { echo 'authpriv.* @172.18.0.30' >> /etc/syslog.conf; /etc/init.d/sysklogd restart; }" >/dev/null 2>&1
    else
        docker exec $VICTIM bash -c "touch /var/log/auth.log; chmod 644 /var/log/auth.log; chown root:adm /var/log/auth.log 2>/dev/null; pgrep rsyslogd >/dev/null || rsyslogd 2>/dev/null" >/dev/null 2>&1
    fi

    # Start Wazuh
    docker exec $VICTIM /var/ossec/bin/wazuh-control start > /dev/null 2>&1
    echo "  ✅ $VICTIM fixed"
done

echo "🎉 All SOC Persistence Fixes Restored!"

# ── MISP Poller: restart background loop ──
echo "🔧 MISP Poller: starting background loop..."
docker exec -d filebeat bash -c '
  # Kill any existing poller loops
  pkill -f "misp-poller.sh" 2>/dev/null
  sleep 2
  # Start fresh loop
  while true; do
    /usr/local/bin/misp-poller.sh 2>/dev/null
    sleep 300
  done
'
echo "  ✅ MISP poller loop started"
