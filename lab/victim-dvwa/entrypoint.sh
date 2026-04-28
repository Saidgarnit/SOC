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

echo "[fleet] Waiting for fleet-server..."
for i in $(seq 1 30); do
    curl -sf http://fleet-server:8220/api/status 2>/dev/null | grep -q "HEALTHY" && break
    sleep 5
done

if [ -f /opt/elastic-agent/fleet.enc ]; then
    echo "[fleet] Existing enrollment found — skipping re-enroll."
else
    echo "[fleet] No enrollment found — enrolling fresh..."
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null
    cd /opt/elastic-agent && "$AGENT_BIN" enroll \
        --url=http://fleet-server:8220 \
        --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== \
        --insecure -f --skip-daemon-reload 2>&1 | tail -3
fi

cd /opt/elastic-agent && exec "$AGENT_BIN" run
