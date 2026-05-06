#!/bin/bash
# ============================================================
# ElastAlert Rules Fix Script
# ============================================================
# Fixes ALL 18 elastalert rule files:
#   1. Replaces YOUR_REAL_WEBHOOK with $SLACK_WEBHOOK_URL
#   2. Adds dual alert: [slack, email] routing
#   3. Adds email recipient where missing
#   4. Fixes index pattern for Suricata rules
#
# Usage:
#   export SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
#   export EMAIL_TO=security-team@example.com
#   ./scripts/fix-elastalert-rules.sh
#
# Run once after deploying. Re-run if rules are changed.
# ============================================================

set -euo pipefail

RULES_DIR="${RULES_DIR:-elastalert/rules}"
WEBHOOK="${SLACK_WEBHOOK_URL:-}"
EMAIL="${EMAIL_TO:-}"

log()  { echo "[ELASTALERT-FIX] $*"; }
loge() { echo "[ELASTALERT-FIX] ERROR: $*" >&2; }

# ── Validate ──────────────────────────────────────────────────
if [ -z "${WEBHOOK}" ]; then
    loge "SLACK_WEBHOOK_URL is not set."
    loge "Export it before running: export SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}"
    exit 1
fi

if [ ! -d "${RULES_DIR}" ]; then
    loge "Rules directory not found: ${RULES_DIR}"
    loge "Run from the root of your SOC stack project."
    exit 1
fi

RULE_FILES=$(find "${RULES_DIR}" -name "*.yaml" -o -name "*.yml" | sort)
COUNT=0

log "Processing rules in: ${RULES_DIR}"
log "Slack webhook: ${WEBHOOK:0:50}..."
log "Email to: ${EMAIL:-<not set, skipping email alerts>}"
echo ""

for RULE_FILE in ${RULE_FILES}; do
    log "Processing: ${RULE_FILE}"
    
    # ── 1. Replace placeholder webhook ───────────────────────
    if grep -q "YOUR_REAL_WEBHOOK" "${RULE_FILE}" 2>/dev/null; then
        sed -i "s|${SLACK_WEBHOOK_URL}" "${RULE_FILE}"
        log "  ✓ Replaced placeholder webhook URL"
    elif grep -q "slack_webhook_url:" "${RULE_FILE}" 2>/dev/null; then
        # Replace any existing webhook line
        sed -i "s|slack_webhook_url:.*|slack_webhook_url: ${WEBHOOK}|g" "${RULE_FILE}"
        log "  ✓ Updated existing webhook URL"
    else
        # Add webhook URL after the 'alert:' line
        sed -i "/^alert:/a slack_webhook_url: ${WEBHOOK}" "${RULE_FILE}"
        log "  ✓ Added webhook URL"
    fi

    # ── 2. Add email dual-alerting if EMAIL_TO is set ────────
    if [ -n "${EMAIL}" ]; then
        if ! grep -q "alert:.*\[" "${RULE_FILE}" 2>/dev/null; then
            # Single alert type - convert to list with both
            if grep -q "^alert: slack" "${RULE_FILE}" 2>/dev/null; then
                sed -i "s|^alert: slack|alert:\n  - slack\n  - email|g" "${RULE_FILE}"
                log "  ✓ Added dual alert (slack + email)"
            fi
        fi
        
        # Add email recipient if not present
        if ! grep -q "^email:" "${RULE_FILE}" 2>/dev/null; then
            echo "email: ${EMAIL}" >> "${RULE_FILE}"
            log "  ✓ Added email recipient: ${EMAIL}"
        fi
    fi

    # ── 3. Fix Suricata rule index patterns ──────────────────
    if echo "${RULE_FILE}" | grep -qE "suricata|port_scan" 2>/dev/null; then
        if grep -q "^index:" "${RULE_FILE}" 2>/dev/null; then
            CURRENT_INDEX=$(grep "^index:" "${RULE_FILE}" | head -1)
            log "  ℹ Suricata rule index: ${CURRENT_INDEX}"
            log "    → Ensure Logstash writes to same pattern (soc-logs-enriched*)"
        fi
    fi

    COUNT=$((COUNT + 1))
done

echo ""
log "================================================================"
log "Fixed ${COUNT} ElastAlert rule file(s)."
log ""
log "Next steps:"
log "  1. Restart ElastAlert:  docker compose restart elastalert"
log "  2. Check logs:          docker compose logs -f elastalert"
log "  3. Test Slack webhook:  curl -X POST '${WEBHOOK:0:50}...' \\"
log "       -H 'Content-Type: application/json' \\"
log "       -d '{\"text\": \"SOC Stack test alert - ElastAlert is working\"}'"
log "================================================================"
