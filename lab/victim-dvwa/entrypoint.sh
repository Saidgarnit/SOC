#!/bin/bash
# ── victim-dvwa entrypoint ──────────────────────────────────────────
service apache2 start 2>/dev/null || true
service mysql start 2>/dev/null || true

# Fix DVWA config — use python to avoid heredoc quoting issues
DBIP="victim-database"

python3 - << PYEOF
dbip = "$DBIP"
config = """<?php
\$_DVWA = array();
\$_DVWA['db_server']   = '{dbip}';
\$_DVWA['db_database'] = 'dvwa';
\$_DVWA['db_user']     = 'dvwa';
\$_DVWA['db_password'] = 'p@ssw0rd';
\$_DVWA['db_port']     = '3306';
\$_DVWA['default_security_level'] = 'low';
\$_DVWA['recaptcha_public_key']  = '';
\$_DVWA['recaptcha_private_key'] = '';
\$DBMS = 'MySQL';
""".format(dbip=dbip)
open('/var/www/html/dvwa/config/config.inc.php', 'w').write(config)
print(f'[dvwa] config written with db_server={dbip}')
PYEOF

# Wazuh
/var/ossec/bin/wazuh-modulesd 2>/dev/null &
sleep 2
/var/ossec/bin/wazuh-agentd 2>/dev/null || true

# Fleet
AGENT_BIN=$(find /opt/elastic-agent/data/ -name "elastic-agent" -type f -executable 2>/dev/null | head -1)
HOSTNAME=$(hostname)

echo "[fleet] Waiting for fleet-server..."
for i in $(seq 1 30); do
    STATUS=$(curl -sf http://fleet-server:8220/api/status 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
    [ "$STATUS" = "HEALTHY" ] || [ "$STATUS" = "degraded" ] && break
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

cd /opt/elastic-agent && exec "$AGENT_BIN" run
