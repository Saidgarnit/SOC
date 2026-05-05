#!/bin/bash
# ── victim-jenkins entrypoint ──────────────────────────────────────────

# Start rsyslog
rsyslogd 2>/dev/null || true

# ── Wazuh auto-enroll in BACKGROUND (don't block Jenkins) ──────────────
(
/var/ossec/bin/wazuh-modulesd 2>/dev/null &
sleep 2
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[wazuh] No enrollment — enrolling with wazuh-manager..."
    rm -f /var/ossec/var/run/wazuh-agentd-*.pid 2>/dev/null
    for attempt in 1 2 3 4 5; do
        /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A "$(hostname)" 2>/dev/null && break
        echo "[wazuh] Attempt $attempt failed, retrying in 10s..."
        sleep 10
    done
fi
rm -f /var/ossec/var/run/wazuh-agentd-*.pid 2>/dev/null
/var/ossec/bin/wazuh-agentd 2>/dev/null || true
) &

# ── Start Jenkins immediately (don't wait for Wazuh) ───────────────────
echo "[jenkins] Starting Jenkins..."
export JENKINS_HOME=/var/jenkins_home
echo '2.0' > /var/jenkins_home/jenkins.install.UpgradeWizard.state 2>/dev/null || true
echo '2.0' > /var/jenkins_home/jenkins.install.InstallUtil.lastExecVersion 2>/dev/null || true
nohup java -jar /usr/share/jenkins/jenkins.war \
    --httpPort=8080 --prefix=/ \
    > /var/log/jenkins.log 2>&1 &
echo "[jenkins] Jenkins started on port 8080"

# ── Fleet enrollment ────────────────────────────────────────────────────
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
