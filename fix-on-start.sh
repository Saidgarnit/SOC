#!/bin/bash
echo "🔧 SOC stack startup fixes..."
PASS="SOCstack2026!"
TOKEN="RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw=="
WAZUH_MANAGER="wazuh-manager"
WAZUH_AGENTS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database victim-ftp victim-webapi victim-metasploitable"
FLEET_AGENTS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database"
PKG_DIR=~/soc-stack/wazuh/packages

# ── 1. Wazuh log dirs ────────────────────────────────────────────
YEAR=$(date +%Y); MONTH=$(date +%b)
BASE=/home/said/soc-stack/wazuh/logs
sudo mkdir -p $BASE/alerts/$YEAR/$MONTH $BASE/archives/$YEAR/$MONTH $BASE/firewall/$YEAR/$MONTH
sudo touch $BASE/active-responses.log
sudo chown -R 101:101 $BASE/alerts $BASE/archives $BASE/firewall
sudo chmod -R 775 $BASE/alerts $BASE/archives $BASE/firewall
sudo chown 101:101 $BASE/active-responses.log && sudo chmod 664 $BASE/active-responses.log
echo "✅ Wazuh dirs ready"

# ── 2. Wait for Elasticsearch ────────────────────────────────────
echo "⏳ Waiting for Elasticsearch..."
for i in $(seq 1 30); do
    curl -sf -u elastic:"$PASS" http://localhost:9200/_cluster/health 2>/dev/null | grep -q "green\|yellow" && \
        echo "✅ Elasticsearch ready" && break
    sleep 5
done

# ── 3. Wait for Fleet server ─────────────────────────────────────
echo "⏳ Waiting for fleet-server..."
for i in $(seq 1 30); do
    curl -sf http://localhost:8220/api/status 2>/dev/null | grep -q "HEALTHY" && \
        echo "✅ Fleet-server ready" && break
    sleep 5
done

# ── 4. Clean old offline Fleet agents ────────────────────────────
echo "🧹 Cleaning offline Fleet agents..."
echo "⏳ Waiting 30s for old agents to go offline..."
sleep 30
OFFLINE_IDS=$(docker exec kibana curl -s -u elastic:"$PASS" \
    "http://localhost:5601/api/fleet/agents?perPage=100&showInactive=true" \
    -H "kbn-xsrf: true" 2>/dev/null | python3 -c "
import sys,json
data=json.load(sys.stdin)
ids=[a['id'] for a in data.get('list',data.get('agents',[])) if a.get('status') in ['offline','inactive']]
print(' '.join(ids))
" 2>/dev/null)
for ID in $OFFLINE_IDS; do
    docker exec kibana curl -sf -u elastic:"$PASS" -X DELETE "http://localhost:5601/api/fleet/agents/$ID" \
        -H "kbn-xsrf: true" > /dev/null 2>&1 && echo "  Removed: $ID"
done

# ── 5. Re-enroll Fleet EDR agents ────────────────────────────────
echo "🔄 Enrolling Fleet agents..."
for VICTIM in $FLEET_AGENTS; do
    docker ps --format '{{.Names}}' | grep -q "^${VICTIM}$" || { echo "⚠️  $VICTIM not running"; continue; }
    docker exec $VICTIM bash -c "
        AGENT_BIN=\$(find /opt/elastic-agent/data/ -name 'elastic-agent' -type f -executable 2>/dev/null | head -1)
        [ -z \"\$AGENT_BIN\" ] && echo 'no binary' && exit 1
        [ -f /opt/elastic-agent/fleet.enc ] && echo 'already enrolled, skipping' && exit 0
        rm -f /opt/elastic-agent/fleet.enc
        rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null
        cd /opt/elastic-agent && \"\$AGENT_BIN\" enroll \
            --url=http://fleet-server:8220 \
            --enrollment-token=$TOKEN \
            --insecure -f --skip-daemon-reload 2>&1 | tail -2
    " && echo "✅ Fleet enrolled: $VICTIM" || echo "⚠️  Fleet failed: $VICTIM"
done

# ── 6. Wait for containers ───────────────────────────────────────
echo "⏳ Waiting for containers to stabilize..."
sleep 20

# ── 7. Install Wazuh on containers that don't persist it ─────────
echo "📦 Installing Wazuh on ftp/webapi/metasploitable..."
docker cp $PKG_DIR/wazuh-agent-4.7.5-x86_64.rpm victim-ftp:/tmp/w.rpm 2>/dev/null && \
    docker exec victim-ftp sh -c "rpm -ihv /tmp/w.rpm 2>/dev/null" && echo "✅ Wazuh installed: victim-ftp"
docker cp $PKG_DIR/wazuh-agent-4.7.5-amd64.deb victim-webapi:/tmp/w.deb 2>/dev/null && \
    docker exec victim-webapi sh -c "dpkg -i /tmp/w.deb 2>/dev/null" && echo "✅ Wazuh installed: victim-webapi"
docker cp $PKG_DIR/wazuh-agent-4.7.5-i386.deb victim-metasploitable:/tmp/w.deb 2>/dev/null && \
    docker exec victim-metasploitable sh -c "dpkg -i /tmp/w.deb 2>/dev/null" && echo "✅ Wazuh installed: victim-metasploitable"

# Fix manager address placeholder
for fc in victim-ftp victim-webapi victim-metasploitable; do
    docker exec $fc sh -c "sed -i 's|<address>MANAGER_IP</address>|<address>wazuh-manager</address>|g' /var/ossec/etc/ossec.conf" 2>/dev/null
done

# ── 8. Wait for Wazuh manager ────────────────────────────────────
echo "⏳ Waiting for wazuh-manager..."
for i in $(seq 1 20); do
    docker exec $WAZUH_MANAGER /var/ossec/bin/agent_control -l > /dev/null 2>&1 && \
        echo "✅ Wazuh manager ready" && break
    sleep 5
done

# Write start-wazuh.sh
cat > /tmp/start-wazuh.sh << 'WEOF'
#!/bin/sh
pkill -f wazuh-agentd 2>/dev/null
sleep 2
while true; do
  /var/ossec/bin/wazuh-agentd
  echo "$(date): agentd exited, restarting..." >> /var/ossec/logs/watchdog.log
  sleep 5
done
WEOF
chmod +x /tmp/start-wazuh.sh

# ── 9. Fix and start all Wazuh agents ────────────────────────────
echo "🔄 Fixing Wazuh agents (all 11 victims)..."
for VICTIM in $WAZUH_AGENTS; do
    docker ps --format '{{.Names}}' | grep -q "^${VICTIM}$" || { echo "⚠️  $VICTIM not running"; continue; }

    # rsyslog and auth.log
    docker exec $VICTIM sh -c "pgrep rsyslogd > /dev/null 2>&1 || rsyslogd 2>/dev/null; chown syslog:adm /var/log/auth.log 2>/dev/null; chmod 640 /var/log/auth.log" > /dev/null 2>&1

    # Enroll if key missing on manager
    MANAGER_KEY=$(docker exec $WAZUH_MANAGER grep " $VICTIM " /var/ossec/etc/client.keys 2>/dev/null)
    if [ -z "$MANAGER_KEY" ]; then
        docker exec $VICTIM sh -c "/var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A $VICTIM 2>&1 | tail -2"
        echo "  🔑 Enrolled: $VICTIM"
        MANAGER_KEY=$(docker exec $WAZUH_MANAGER grep " $VICTIM " /var/ossec/etc/client.keys 2>/dev/null)
    fi

    # Sync key if missing on agent
    AGENT_KEY=$(docker exec $VICTIM sh -c "cat /var/ossec/etc/client.keys 2>/dev/null" 2>/dev/null)
    if [ -z "$AGENT_KEY" ]; then
        docker exec $VICTIM sh -c "echo '$MANAGER_KEY' > /var/ossec/etc/client.keys && chmod 640 /var/ossec/etc/client.keys && chown root:wazuh /var/ossec/etc/client.keys" > /dev/null 2>&1
        echo "  🔑 Key synced: $VICTIM"
    fi

    # Start watchdog
    docker cp /tmp/start-wazuh.sh $VICTIM:/usr/local/bin/start-wazuh.sh
    docker exec -d $VICTIM /usr/local/bin/start-wazuh.sh
    echo "✅ Wazuh started: $VICTIM"
done

# ── 10. Verify Wazuh ─────────────────────────────────────────────
echo "⏳ Waiting 25s for Wazuh agents to connect..."
sleep 25
echo "📊 Wazuh agent status:"
docker exec $WAZUH_MANAGER /var/ossec/bin/agent_control -l

# ── 11. Filebeat reset ───────────────────────────────────────────
docker exec filebeat sh -c "rm -rf /usr/share/filebeat/data/registry" 2>/dev/null && \
    docker rm filebeat && docker compose -f ~/soc-stack/docker-compose.yml up -d filebeat > /dev/null 2>&1 && echo "✅ Filebeat reset"

# ── 11a. Jenkins security fix
docker exec victim-jenkins sh -c "mkdir -p /var/jenkins_home/init.groovy.d && cat > /var/jenkins_home/init.groovy.d/disable-security.groovy << 'GROOVY'
import jenkins.model.*
import hudson.security.*
def instance = Jenkins.getInstance()
instance.disableSecurity()
instance.save()
GROOVY" 2>/dev/null && echo "✅ Jenkins security disabled" && docker restart victim-jenkins > /dev/null 2>&1 && echo "✅ Jenkins restarted"

# ── 11b. DVWA database setup
# Fix MySQL bind address on victim-database
docker exec victim-database sh -c "sed -i 's/bind-address.*= 127.0.0.1/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf; sed -i 's/mysqlx-bind-address.*= 127.0.0.1/mysqlx-bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf; service mysql restart" 2>/dev/null && echo "✅ MySQL accepting remote connections"
sleep 5
docker exec victim-database sh -c 'mysql -u root -e "CREATE DATABASE IF NOT EXISTS dvwa; CREATE USER IF NOT EXISTS dvwa@\"%\" IDENTIFIED BY \"p@ssw0rd\"; GRANT ALL PRIVILEGES ON dvwa.* TO dvwa@\"%\"; FLUSH PRIVILEGES;" 2>/dev/null' && echo "✅ DVWA database ready"
sleep 3
docker exec victim-dvwa sh -c "
  curl -s -c /tmp/c.txt http://localhost/dvwa/setup.php > /tmp/s.html
  TOKEN=$(grep user_token /tmp/s.html | grep -oP '(?<=value=")[^"]*' | head -1)
  curl -s -b /tmp/c.txt -c /tmp/c.txt -X POST -d "create_db=Create+%2F+Reset+Database&user_token=\$TOKEN" http://localhost/dvwa/setup.php > /dev/null
" && echo "✅ DVWA initialized"

# ── 12. bWAPP auto-install
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8892/install.php 2>/dev/null)
if [ "$STATUS" = "200" ]; then
    curl -s "http://localhost:8892/install.php?install=yes" > /dev/null 2>&1
    echo "✅ bWAPP database initialized"
fi

# ── 12. OpenCTI connectors ───────────────────────────────────────
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/graphql 2>/dev/null)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "400" ]; then
    docker restart connector-misp connector-mitre opencti-worker > /dev/null 2>&1
    echo "✅ OpenCTI connectors restarted"
else
    echo "⏳ OpenCTI not ready yet (HTTP $STATUS)"
fi

echo ""
echo "🎉 SOC stack ready!"

# ── 13. Background cleanup after 3min ────────────────────────────
(
sleep 180
OFFLINE_IDS=$(docker exec kibana curl -s -u elastic:"$PASS" \
  "http://localhost:5601/api/fleet/agents?perPage=100&showInactive=true" \
  -H "kbn-xsrf: true" 2>/dev/null | python3 -c "
import sys,json
data=json.load(sys.stdin)
ids=[a['id'] for a in data.get('list',data.get('agents',[])) if a.get('status') in ['offline','inactive']]
print(' '.join(ids))
" 2>/dev/null)
for ID in $OFFLINE_IDS; do
    docker exec kibana curl -sf -u elastic:"$PASS" -X DELETE \
      "http://localhost:5601/api/fleet/agents/$ID" \
      -H "kbn-xsrf: true" > /dev/null && echo "Cleaned offline agent $ID"
done
echo "✅ Fleet cleanup complete"
) &

# ── 14. Fix auth.log permissions on all agents (needed for rsyslog) ──
echo "🔧 Fixing auth.log ownership on all victims..."
for VICTIM in $WAZUH_AGENTS; do
    docker ps --format '{{.Names}}' | grep -q "^${VICTIM}$" || continue
    docker exec $VICTIM sh -c "
        touch /var/log/auth.log 2>/dev/null
        chown syslog:adm /var/log/auth.log 2>/dev/null || chown root:root /var/log/auth.log 2>/dev/null
        chmod 640 /var/log/auth.log 2>/dev/null
        pgrep rsyslogd > /dev/null 2>&1 || service rsyslog start 2>/dev/null || rsyslogd 2>/dev/null
    " 2>/dev/null && echo "  ✅ auth.log fixed: $VICTIM"
done

# ── 15. Fix Wazuh logcollector/syscheckd on victim-ubuntu ────────────
echo "🔧 Restarting Wazuh full agent on victim-ubuntu..."
docker exec victim-ubuntu /var/ossec/bin/wazuh-control restart 2>/dev/null
sleep 5
docker exec victim-ubuntu /var/ossec/bin/wazuh-control status 2>/dev/null | grep -E "running|not running"

# ── 16. Restart elastalert after everything is up ────────────────────
echo "🔧 Restarting elastalert to ensure clean rule load..."
docker compose -f ~/soc-stack/docker-compose.yml restart elastalert > /dev/null 2>&1
sleep 10
RULES=$(docker logs elastalert 2>&1 | grep "rules loaded" | tail -1)
echo "  ✅ ElastAlert: $RULES"
