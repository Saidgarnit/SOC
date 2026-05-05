#!/bin/bash
# ============================================================
# Wazuh Agent Monitor (FIXED)
# ============================================================
# Fixes from original scripts/monitor-wazuh-agents.sh:
#   1. Uses HTTPS (not HTTP) on port 55000           ← was curl error 52
#   2. Reads WAZUH_API_PASSWORD from env              ← was hardcoded 'wazuh'
#   3. Uses -k flag for self-signed cert
#   4. Graceful error messages
#
# Usage: ./scripts/monitor-wazuh-agents.sh
# ============================================================

set -uo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER_HOST:-wazuh-manager}"
WAZUH_API_USER="${WAZUH_API_USER:-wazuh}"
WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-wazuh}"
WAZUH_API_PORT="${WAZUH_API_PORT:-55000}"

log()  { echo "[WAZUH-MONITOR] $*"; }
loge() { echo "[WAZUH-MONITOR] ERROR: $*" >&2; }

# ── Authenticate ──────────────────────────────────────────────
log "Authenticating with Wazuh API at https://${WAZUH_MANAGER}:${WAZUH_API_PORT}..."

TOKEN=$(curl -sf -k \
    -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" \
    -X POST \
    "https://${WAZUH_MANAGER}:${WAZUH_API_PORT}/security/user/authenticate?raw=true" \
    2>/dev/null)

if [ -z "${TOKEN}" ]; then
    loge "Authentication failed."
    loge "  Manager  : ${WAZUH_MANAGER}:${WAZUH_API_PORT}"
    loge "  User     : ${WAZUH_API_USER}"
    loge "  Password : (check WAZUH_API_PASSWORD in .env)"
    exit 1
fi

log "Authentication successful."

# ── Fetch agents ──────────────────────────────────────────────
log "Fetching agent list..."

AGENTS_JSON=$(curl -sf -k \
    -H "Authorization: Bearer ${TOKEN}" \
    -X GET \
    "https://${WAZUH_MANAGER}:${WAZUH_API_PORT}/agents?select=id,name,ip,status,dateAdd,lastKeepAlive&limit=500" \
    2>/dev/null)

if [ -z "${AGENTS_JSON}" ]; then
    loge "Failed to fetch agent list."
    exit 1
fi

# ── Display ───────────────────────────────────────────────────
TOTAL=$(echo "${AGENTS_JSON}" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d['data']['total_affected_items'])" \
    2>/dev/null || echo "?")

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Wazuh Agents Status  (Total: ${TOTAL})"
echo "══════════════════════════════════════════════════════════════"
printf "%-6s %-20s %-16s %-14s %s\n" "ID" "NAME" "IP" "STATUS" "LAST KEEPALIVE"
echo "──────────────────────────────────────────────────────────────"

echo "${AGENTS_JSON}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data['data']['affected_items']:
    print('{:<6} {:<20} {:<16} {:<14} {}'.format(
        a.get('id','?'),
        a.get('name','?')[:19],
        a.get('ip','?'),
        a.get('status','?'),
        a.get('lastKeepAlive') or 'Never'
    ))
" 2>/dev/null || echo "${AGENTS_JSON}"

echo "──────────────────────────────────────────────────────────────"

# ── Summary ───────────────────────────────────────────────────
NEVER=$(echo "${AGENTS_JSON}" | python3 -c \
    "import sys,json; d=json.load(sys.stdin)
items=[a for a in d['data']['affected_items'] if a.get('status')=='never_connected']
print(len(items))" 2>/dev/null || echo "?")

DISCONNECTED=$(echo "${AGENTS_JSON}" | python3 -c \
    "import sys,json; d=json.load(sys.stdin)
items=[a for a in d['data']['affected_items'] if a.get('status')=='disconnected']
print(len(items))" 2>/dev/null || echo "?")

ACTIVE=$(echo "${AGENTS_JSON}" | python3 -c \
    "import sys,json; d=json.load(sys.stdin)
items=[a for a in d['data']['affected_items'] if a.get('status')=='active']
print(len(items))" 2>/dev/null || echo "?")

echo ""
echo "  Active: ${ACTIVE}   Disconnected: ${DISCONNECTED}   Never Connected: ${NEVER}"
echo ""

if [ "${NEVER}" != "0" ] && [ "${NEVER}" != "?" ]; then
    log "WARNING: ${NEVER} agent(s) have never connected."
    log "  → Check wazuh-watchdog.sh is running in victim containers."
    log "  → Check WAZUH_REGISTRATION_PASSWORD matches manager config."
fi
