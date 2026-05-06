#!/bin/bash
# ── victim-jenkins entrypoint ──────────────────────────────────────────
# Services
rsyslogd 2>/dev/null || true
/var/ossec/bin/wazuh-modulesd &
sleep 3
/var/ossec/bin/wazuh-agentd 2>/dev/null || true

AGENT_BIN=$(find /opt/elastic-agent/data/ -name "elastic-agent" -type f -executable 2>/dev/null | head -1)
FLEET_URL="${FLEET_URL:-https://fleet-server:8220}"
FLEET_ENROLLMENT_TOKEN="${FLEET_ENROLLMENT_TOKEN:-}"
FLEET_CA_CERT="${FLEET_CA_CERT:-/etc/elastic-agent/certs/ca/ca.crt}"

echo "[fleet] Waiting for fleet-server..."
for i in $(seq 1 30); do
    curl -sf --cacert "$FLEET_CA_CERT" "$FLEET_URL/api/status" 2>/dev/null | grep -q "HEALTHY" && break
    sleep 5
done

if [ -f /opt/elastic-agent/fleet.enc ]; then
    echo "[fleet] Existing enrollment found — skipping re-enroll."
else
    echo "[fleet] No enrollment found — enrolling fresh..."
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null
    cd /opt/elastic-agent && "$AGENT_BIN" enroll \
        --url="$FLEET_URL" \
        --enrollment-token="$FLEET_ENROLLMENT_TOKEN" \
        --certificate-authorities="$FLEET_CA_CERT" -f --skip-daemon-reload 2>&1 | tail -3
fi

cd /opt/elastic-agent && exec "$AGENT_BIN" run
