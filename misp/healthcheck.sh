#!/bin/bash
# ============================================================
# MISP Healthcheck Script
# ============================================================
# Used as the HEALTHCHECK CMD in docker-compose.yml for the
# misp service so that connector-misp can use service_healthy.
#
# Place at:  misp/healthcheck.sh
# Mount as:  /healthcheck.sh  (read-only)
# docker-compose healthcheck:
#   test: ["CMD", "/bin/bash", "/healthcheck.sh"]
#   interval: 30s
#   timeout: 10s
#   retries: 10
#   start_period: 300s   ← MISP needs ~5-10 min to init
# ============================================================

# Check 1: nginx is serving HTTP 200 or 302 on the login page
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 10 \
    http://localhost:80/users/login 2>/dev/null)

if [ "${HTTP_CODE}" = "200" ] || [ "${HTTP_CODE}" = "302" ]; then
    exit 0
fi

exit 1
