#!/bin/sh
rm -f /var/ossec/var/start-script-lock
FLEET_URL="${FLEET_URL:-http://fleet-server:8220}"
ENROLL_TOKEN="${ENROLL_TOKEN:-OGo2amdwNEJ0WlBNTkJjRzNSTE06VkZBT3E2dkVTSVdKV0xSY3FKLUJmQQ==}"
AGENT_DIR="/opt/elastic-agent"
HOSTNAME="$(hostname)"

log() { echo "[entrypoint] $*"; }

wait_for_fleet() {
    log "Waiting for Fleet Server at $FLEET_URL ..."
    for i in $(seq 1 30); do
        STATUS=$(curl -sf "$FLEET_URL/api/status" 2>/dev/null \
                 | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
        if [ "$STATUS" = "HEALTHY" ] || [ "$STATUS" = "degraded" ]; then
            log "Fleet Server is $STATUS ✔"
            return 0
        fi
        log "  attempt $i/30 — status='$STATUS', retrying in 5s..."
        sleep 5
    done
    log "ERROR: Fleet Server never became healthy. Aborting."
    exit 1
}

already_online() {
    RESULT=$(curl -sf \
        -u "${ES_USER:-elastic}:${ES_PASS:-SOCstack2026!}" \
        -H "Content-Type: application/json" \
        -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"local_metadata.host.hostname\":\"$HOSTNAME\"}},{\"term\":{\"status\":\"online\"}}]}}}" \
        "http://${ES_HOST:-elasticsearch}:9200/.fleet-agents/_search" 2>/dev/null \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['hits']['total']['value'])" 2>/dev/null)
    [ "${RESULT:-0}" -gt 0 ]
}

enroll() {
    log "Clearing stale fleet.enc..."
    rm -f "$AGENT_DIR/fleet.enc"
    AGENT_BIN=$(find "$AGENT_DIR/data/" -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
    if [ -z "$AGENT_BIN" ]; then
        log "ERROR: elastic-agent binary not found"
        exit 1
    fi
    log "Enrolling as '$HOSTNAME' via $FLEET_URL ..."
    cd "$AGENT_DIR" && "$AGENT_BIN" enroll \
        --url="$FLEET_URL" \
        --enrollment-token="$ENROLL_TOKEN" \
        --insecure -f --skip-daemon-reload
    log "Enrollment complete ✔"
}

wait_for_fleet

if already_online; then
    log "Host '$HOSTNAME' is already ONLINE in Fleet — skipping enrollment."
else
    log "No online record found for '$HOSTNAME' — enrolling..."
    enroll
fi

AGENT_BIN=$(find "$AGENT_DIR/data/" -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
log "Starting elastic-agent..."
exec "$AGENT_BIN" run
