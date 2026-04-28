#!/bin/bash
# --- Wazuh Agent ---
if [ -f /var/ossec/bin/wazuh-control ]; then
    groupadd -g 1000 wazuh 2>/dev/null || true
    useradd -u 1000 -g 1000 -d /var/ossec -s /sbin/nologin wazuh 2>/dev/null || true
    chown root:wazuh /var/ossec/etc/client.keys 2>/dev/null
    chmod 640 /var/ossec/etc/client.keys 2>/dev/null
    rm -f /var/ossec/var/run/*.pid 2>/dev/null
    sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf 2>/dev/null
    /var/ossec/bin/wazuh-control start 2>/dev/null
    nohup /bin/bash /tmp/wazuh-watchdog.sh &>/dev/null &
    echo "[wazuh] Watchdog started"
else
    echo "[wazuh] Agent not installed — skipping"
fi
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
AGENT_BIN=$(find /opt/elastic-agent/data/ -name "elastic-agent" -type f -executable 2>/dev/null | head -1)
echo "[fleet] Waiting for fleet-server..."
for i in $(seq 1 30); do
    curl -sf http://fleet-server:8220/api/status 2>/dev/null | grep -q "HEALTHY" && break
    sleep 5
done
if [ -f /opt/elastic-agent/fleet.enc ]; then
    echo "[fleet] Existing enrollment found — skipping re-enroll"
else
    echo "[fleet] No enrollment found — enrolling fresh..."
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null
    cd /opt/elastic-agent && "$AGENT_BIN" enroll \
        --url=http://fleet-server:8220 \
        --enrollment-token="${ELASTIC_TOKEN}" \
        --insecure -f --skip-daemon-reload 2>&1 | tail -3
fi
exec "$AGENT_BIN" run
