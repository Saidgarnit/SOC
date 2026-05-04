#!/bin/bash
# =============================================================
#  metasploitable-syslog.sh — ATK-6 Permanent Fix
#  Forwards victim-metasploitable auth events to Wazuh UDP 5140
#  Called by start-soc.sh after containers are up
# =============================================================

LOG_PREFIX="[metasploitable-syslog]"
META_CONTAINER="victim-metasploitable"
WAZUH_HOST="wazuh-manager"
WAZUH_PORT="5140"

log() { echo "$LOG_PREFIX $(date '+%H:%M:%S') — $*"; }

# -------------------------------------------------------------
# STEP 1 — Wait for both containers to be running
# -------------------------------------------------------------
log "Waiting for $META_CONTAINER and $WAZUH_HOST..."
for i in $(seq 1 30); do
    META_UP=$(docker inspect -f '{{.State.Running}}' "$META_CONTAINER" 2>/dev/null || echo "false")
    WAZUH_UP=$(docker inspect -f '{{.State.Running}}' "$WAZUH_HOST" 2>/dev/null || echo "false")
    if [ "$META_UP" = "true" ] && [ "$WAZUH_UP" = "true" ]; then
        log "Both containers Up."
        break
    fi
    log "Attempt $i/30 — waiting 10s..."
    sleep 10
done

# Wait for wazuh-remoted to fully bind port 5140
log "Waiting 30s for wazuh-remoted to bind port 5140..."
sleep 30

# -------------------------------------------------------------
# STEP 2 — Verify nc is available on metasploitable
# -------------------------------------------------------------
NC_PATH=$(docker exec "$META_CONTAINER" which nc 2>/dev/null || echo "")
if [ -z "$NC_PATH" ]; then
    log "ERROR: nc not found on $META_CONTAINER. Cannot forward syslog."
    exit 1
fi
log "nc found at $NC_PATH"

# -------------------------------------------------------------
# STEP 3 — Send startup syslog event to confirm pipeline works
# -------------------------------------------------------------
log "Sending startup syslog event to Wazuh..."
docker exec "$META_CONTAINER" bash -c "
echo '<34>\$(date +\"%b %d %H:%M:%S\") $META_CONTAINER syslog: Forwarder started — ATK-6 pipeline active' | \
  nc -u -w1 $WAZUH_HOST $WAZUH_PORT
"
log "Startup event sent."

# -------------------------------------------------------------
# STEP 4 — Start persistent forwarder loop in background
#           Forwards any new /var/log/auth.log lines to Wazuh
# -------------------------------------------------------------
log "Starting persistent auth.log forwarder in $META_CONTAINER..."
docker exec -d "$META_CONTAINER" bash -c "
tail -F /var/log/auth.log 2>/dev/null | while read line; do
    echo \"<34>\$(date +\"%b %d %H:%M:%S\") $META_CONTAINER \$line\" | \
        nc -u -w1 $WAZUH_HOST $WAZUH_PORT
done
" && log "Persistent forwarder started (tailing auth.log)." \
  || log "WARNING: Could not start persistent forwarder."

# -------------------------------------------------------------
# STEP 5 — Also send a keepalive heartbeat every 60s
# -------------------------------------------------------------
log "Starting keepalive heartbeat (every 60s)..."
docker exec -d "$META_CONTAINER" bash -c "
while true; do
    echo '<34>\$(date +\"%b %d %H:%M:%S\") $META_CONTAINER syslog: heartbeat' | \
        nc -u -w1 $WAZUH_HOST $WAZUH_PORT
    sleep 60
done
" && log "Heartbeat started." || log "WARNING: Could not start heartbeat."

# -------------------------------------------------------------
# DONE
# -------------------------------------------------------------
log "ATK-6 syslog pipeline active."
log "  victim-metasploitable auth events → Wazuh UDP $WAZUH_PORT"
log "  Rule 5760 (sshd auth failed) will fire on brute force attacks."
