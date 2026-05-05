#!/bin/bash

# Start Samba
service smbd start 2>/dev/null || true
service nmbd start 2>/dev/null || true
echo "[windows] SMB started"

# ── victim-windows entrypoint ──────────────────────────────────────────
# Services
rsyslogd 2>/dev/null || true
python3 /usr/local/bin/fake-win-events.py &

# ── Wazuh auto-enroll (survives reboot) ──────────────────────
/var/ossec/bin/wazuh-modulesd 2>/dev/null &
sleep 2
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[wazuh] No enrollment — enrolling with wazuh-manager..."
    rm -f /var/ossec/var/run/wazuh-agentd-*.pid 2>/dev/null
    for attempt in 1 2 3 4 5; do
        /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A "$(hostname)" 2>/dev/null && break
        echo "[wazuh] Attempt $attempt failed, retrying in 10s..."
        sleep 10
    done
fi
rm -f /var/ossec/var/run/wazuh-agentd-*.pid 2>/dev/null
/var/ossec/bin/wazuh-agentd 2>/dev/null || true
AGENT_BIN=$(find /opt/elastic-agent/data/ -name "elastic-agent" -type f -executable 2>/dev/null | head -1)

echo "[fleet] Waiting for fleet-server..."
for i in $(seq 1 30); do
    curl -sf http://fleet-server:8220/api/status 2>/dev/null | grep -q "HEALTHY" && break
    sleep 5
done

if [ -f /opt/elastic-agent/fleet.enc ]; then
    echo "[fleet] Existing enrollment found — skipping re-enroll."
else
    echo "[fleet] No enrollment found — enrolling fresh..."
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null
    cd /opt/elastic-agent && "$AGENT_BIN" enroll \
        --url=http://fleet-server:8220 \
        --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== \
        --insecure -f --skip-daemon-reload 2>&1 | tail -3
fi

cd /opt/elastic-agent && exec "$AGENT_BIN" run
