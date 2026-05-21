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
docker exec $WAZUH_MANAGER rm -rf /var/ossec/var/run/.wazuh-manager.lock /var/ossec/var/start-script-lock 2>/dev/null || true

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
    docker exec $VICTIM rm -rf /var/ossec/var/run/.wazuh-agent.lock /var/ossec/var/start-script-lock 2>/dev/null || true
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

# ── Auth.log + rsyslog fix for all victims ──
echo "🔧 Fixing auth.log permissions and rsyslog on all victims..."
for VICTIM in victim-ubuntu victim-dvwa victim-jenkins victim-mail victim-dns \
              victim-database victim-iot victim-webapi victim-windows; do
  docker ps --format '{{.Names}}' | grep -q "^$VICTIM$" || continue
  docker exec $VICTIM bash -c "
    touch /var/log/auth.log 2>/dev/null
    chown syslog:adm /var/log/auth.log 2>/dev/null
    chmod 664 /var/log/auth.log 2>/dev/null
    sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/' /etc/ssh/sshd_config 2>/dev/null
    pkill rsyslogd 2>/dev/null; rm -f /run/rsyslogd.pid; sleep 1
    rsyslogd 2>/dev/null; sleep 1
    pkill sshd 2>/dev/null; sleep 1; /usr/sbin/sshd 2>/dev/null
  " 2>/dev/null && echo "  ✅ $VICTIM" || echo "  ⚠️ $VICTIM skipped"
done

# Install rsyslog on victim-iot if missing
if docker ps --format '{{.Names}}' | grep -q "^victim-iot$"; then
  docker exec victim-iot bash -c "
    which rsyslogd 2>/dev/null || apt-get install -y rsyslog -qq 2>/dev/null
  " 2>/dev/null
fi

# ── victim-webapi: Wazuh not in image, copy from victim-ubuntu ──
echo "🔧 Ensuring victim-webapi has Wazuh agent..."
if docker ps --format '{{.Names}}' | grep -q "^victim-webapi$"; then
  WAZUH_RUNNING=$(docker exec victim-webapi pgrep -f wazuh-agentd 2>/dev/null)
  if [ -z "$WAZUH_RUNNING" ]; then
    echo "  Installing Wazuh into victim-webapi via host copy..."
    docker cp victim-ubuntu:/var/ossec /tmp/wazuh-webapi-copy 2>/dev/null
    docker cp /tmp/wazuh-webapi-copy victim-webapi:/var/ossec 2>/dev/null
    rm -rf /tmp/wazuh-webapi-copy
    docker exec victim-webapi bash -c "
      groupadd -g 1000 wazuh 2>/dev/null || true
      useradd -u 1000 -g 1000 -d /var/ossec -s /sbin/nologin wazuh 2>/dev/null || true
      /var/ossec/bin/agent-auth -m wazuh-manager -A victim-webapi 2>/dev/null || true
      sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
      /var/ossec/bin/wazuh-control start 2>/dev/null
    " && echo "  ✅ victim-webapi Wazuh started" || echo "  ⚠️ victim-webapi Wazuh failed"
  else
    echo "  ✅ victim-webapi Wazuh already running"
  fi
fi


# ── MITRE ElastAlert rules persistence ──
echo "🔧 Ensuring 5 MITRE ElastAlert rules are loaded..."
for RULE in execution_tactic discovery_tactic collection_tactic c2_tactic resource_dev_tactic initial_access_tactic defense_evasion_tactic impact_tactic reconnaissance_tactic exfiltration_tactic ssh_bruteforce smb_bruteforce; do
  SRC="$HOME/soc-stack/elastalert/rules/${RULE}.yaml"
  if [ -f "$SRC" ]; then
    docker cp "$SRC" elastalert:/opt/elastalert/rules/ 2>/dev/null && echo "  ✅ $RULE" || echo "  ⚠️ $RULE failed"
  fi
done
docker exec victim-ubuntu bash -c "echo 'root:toor' | chpasswd" 2>/dev/null

# Re-enable AR queue on all agents after restart
for container in victim-ubuntu victim-dvwa victim-jenkins victim-ftp victim-mail victim-dns victim-database victim-windows victim-iot victim-webapi; do
  docker exec $container rm -rf /var/ossec/var/start-script-lock 2>/dev/null; docker exec $container /var/ossec/bin/wazuh-control restart 2>/dev/null
done
docker exec wazuh-manager rm -rf /var/ossec/var/start-script-lock && docker exec wazuh-manager /var/ossec/bin/wazuh-control restart

# Stop unnecessary redis on victim containers only (MISP/OpenCTI use dedicated redis containers)
for c in victim-ubuntu victim-dvwa victim-jenkins victim-windows victim-iot victim-database victim-mail victim-dns; do
  docker exec $c pkill redis-server 2>/dev/null || true
done

# ── Clear ElastAlert dedup state for MITRE tactic rules on every start ─────
echo "🔧 Clearing ElastAlert dedup state for MITRE tactic rules..."
sleep 30
for rule in \
  "Initial Access Detected (TA0001)" \
  "Exfiltration Detected (TA0010)" \
  "Defense Evasion Detected (TA0005)" \
  "Impact Detected (TA0040)" \
  "Reconnaissance Detected (TA0043)"; do
  curl -s -u elastic:"${ELASTIC_PASSWORD}" \
    -X DELETE "http://localhost:9200/elastalert_status/_delete_by_query" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"match\":{\"rule_name\":\"${rule}\"}}}" > /dev/null
done
echo "  ✅ ElastAlert dedup state cleared"
