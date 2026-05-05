#!/bin/bash
# ============================================================
# Wazuh Agent Watchdog
# ============================================================
# Keeps wazuh-agentd running across container restarts.
# Handles: initial enrollment, PID-file cleanup, auto-restart.
#
# Place at:  wazuh-agent/wazuh-watchdog.sh
# Mount into every victim container as:
#   /usr/local/bin/wazuh-watchdog.sh
# Call from container entrypoint or CMD.
# ============================================================

set -uo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh-manager}"
WAZUH_PORT="${WAZUH_PORT:-1515}"
WAZUH_REG_PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-TopSecret1234!}"
AGENT_NAME="${WAZUH_AGENT_NAME:-$(hostname)}"
CHECK_INTERVAL=30
MAX_ENROLL_ATTEMPTS=10

log()  { echo "[WATCHDOG][$(hostname)] $(date '+%H:%M:%S') $*"; }
logw() { echo "[WATCHDOG][$(hostname)] $(date '+%H:%M:%S') WARN: $*"; }
loge() { echo "[WATCHDOG][$(hostname)] $(date '+%H:%M:%S') ERROR: $*"; }

# ── Helpers ───────────────────────────────────────────────────
is_enrolled() {
    [ -f /var/ossec/etc/client.keys ] && [ -s /var/ossec/etc/client.keys ]
}

is_running() {
    pgrep -x wazuh-agentd > /dev/null 2>&1
}

wait_for_manager() {
    log "Waiting for Wazuh manager at ${WAZUH_MANAGER}:${WAZUH_PORT}..."
    for i in $(seq 1 60); do
        if nc -z "${WAZUH_MANAGER}" "${WAZUH_PORT}" 2>/dev/null; then
            log "Manager is reachable."
            return 0
        fi
        sleep 5
    done
    loge "Manager did not become reachable. Proceeding anyway..."
    return 1
}

enroll_agent() {
    log "Enrolling agent '${AGENT_NAME}' with manager '${WAZUH_MANAGER}'..."
    
    # Clean up stale artifacts
    rm -f /var/ossec/etc/client.keys
    rm -f /var/ossec/var/run/wazuh-agentd-*.pid

    for attempt in $(seq 1 ${MAX_ENROLL_ATTEMPTS}); do
        log "  Enrollment attempt ${attempt}/${MAX_ENROLL_ATTEMPTS}..."
        if /var/ossec/bin/agent-auth \
                -m "${WAZUH_MANAGER}" \
                -P "${WAZUH_REG_PASSWORD}" \
                -A "${AGENT_NAME}" 2>&1; then
            log "Enrollment successful."
            return 0
        fi
        logw "Enrollment failed, retrying in 15s..."
        sleep 15
    done

    loge "Enrollment failed after ${MAX_ENROLL_ATTEMPTS} attempts."
    return 1
}

start_agent() {
    log "Starting wazuh-agentd..."
    # Remove any stale PID files
    rm -f /var/ossec/var/run/wazuh-agentd-*.pid

    if /var/ossec/bin/wazuh-agentd 2>&1; then
        log "wazuh-agentd started."
    else
        logw "wazuh-agentd exited with error – will retry on next watchdog cycle."
    fi
}

# ── Main ──────────────────────────────────────────────────────
log "Watchdog starting. Agent name: ${AGENT_NAME}, Manager: ${WAZUH_MANAGER}"

# Wait until manager port is reachable
wait_for_manager || true

# Enroll if not already enrolled
if ! is_enrolled; then
    enroll_agent || logw "Could not enroll – will retry on next cycle."
fi

# Start agent for the first time
if ! is_running; then
    start_agent
fi

# ── Monitor loop ──────────────────────────────────────────────
log "Entering monitor loop (interval: ${CHECK_INTERVAL}s)..."
while true; do
    sleep "${CHECK_INTERVAL}"

    if ! is_running; then
        logw "wazuh-agentd is not running."
        
        # Re-enroll if client.keys was lost
        if ! is_enrolled; then
            log "client.keys missing – re-enrolling..."
            enroll_agent || true
        fi

        start_agent
    fi
done
