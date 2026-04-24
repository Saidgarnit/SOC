#!/bin/bash
# ── victim-dns entrypoint ──────────────────────────────────────────
# Services
rsyslogd 2>/dev/null || true
service named start 2>/dev/null || true
/var/ossec/bin/wazuh-modulesd &
sleep 3
/var/ossec/bin/wazuh-agentd 2>/dev/null || true

AGENT_BIN=$(find /opt/elastic-agent/data/ -name "elastic-agent" -type f -executable 2>/dev/null | head -1)
HOSTNAME=$(hostname)

echo "[fleet] Waiting for fleet-server..."
for i in $(seq 1 30); do
    STATUS=$(curl -sf http://fleet-server:8220/api/status 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
    [ "$STATUS" = "HEALTHY" ] || [ "$STATUS" = "degraded" ] && break
    echo "[fleet] attempt $i/30 - not ready, waiting 5s..."
    sleep 5
done

ONLINE=$(curl -sf -u "elastic:SOCstack2026!" -H "Content-Type: application/json" \
    -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"local_metadata.host.hostname\":\"$HOSTNAME\"}},{\"term\":{\"status\":\"online\"}}]}}}" \
    "http://elasticsearch:9200/.fleet-agents-7/_search" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['hits']['total']['value'])" 2>/dev/null)

if [ "${ONLINE:-0}" -gt 0 ]; then
    echo "[fleet] Already ONLINE — skipping enrollment."
else
    echo "[fleet] Not online — enrolling fresh..."
    rm -f /opt/elastic-agent/fleet.enc
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null
    cd /opt/elastic-agent && "$AGENT_BIN" enroll \
        --url=http://fleet-server:8220 \
        --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== \
        --insecure -f --skip-daemon-reload 2>&1 | tail -3
fi

# Start main process
cd /opt/elastic-agent && exec "$AGENT_BIN" run
