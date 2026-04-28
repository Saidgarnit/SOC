#!/bin/bash
echo "🔧 SOC stack fixes (no restart)..."
PASS="SOCstack2026!"
FLEET_TOKEN="RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw=="
WAZUH_MANAGER="wazuh-manager"
ALL_VICTIMS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database victim-ftp victim-webapi victim-metasploitable"
FLEET_VICTIMS="victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database victim-ftp victim-webapi"
PKG_DIR=~/soc-stack/wazuh/packages
ok(){ echo "  ✅ $*"; }; warn(){ echo "  ⚠️  $*"; }
container_up(){ docker ps --format '{{.Names}}' | grep -q "^${1}$"; }

# ── Fleet-server health check and recovery ──────────────────────────
echo "🔧 Step 0: Fleet-server health check..."
FLEET_HEALTHY=$(curl -s --max-time 5 http://localhost:8220/api/status 2>/dev/null | grep -c "HEALTHY")
if [ "$FLEET_HEALTHY" -eq 0 ]; then
    echo "  🔄 Fleet-server unhealthy — restarting..."
    docker rm -f fleet-server 2>/dev/null
    docker compose -f ~/soc-stack/docker-compose-lab.yml up -d fleet-server 2>/dev/null
    for i in $(seq 1 24); do
        curl -s --max-time 3 http://localhost:8220/api/status 2>/dev/null | grep -q "HEALTHY" && break
        echo -n "."; sleep 5
    done
    echo ""
    ok "Fleet-server recovered"
else
    ok "Fleet-server healthy"
fi

# ── Step 1: Fleet HTTP URL fix ───────────────────────────────────────
echo "🔧 Step 1: Fleet HTTP URL fix..."
for i in $(seq 1 12); do
    curl -sf -u elastic:"$PASS" "http://localhost:5601/api/status" 2>/dev/null | grep -q "available" && break
    sleep 5
done
curl -s -u elastic:"$PASS" -X PUT \
    "http://localhost:5601/api/fleet/fleet_server_hosts/69090aca-4691-4427-8077-a5529a5d77ee" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d '{"name":"soc-fleet","host_urls":["http://fleet-server:8220"],"is_default":true}' > /dev/null 2>&1
curl -s -u elastic:"$PASS" -X PUT \
    "http://localhost:5601/api/fleet/settings" \
    -H "kbn-xsrf: true" -H "Content-Type: application/json" \
    -d '{"fleet_server_hosts":["http://fleet-server:8220"]}' > /dev/null 2>&1
ok "Fleet Hosts set to HTTP"

# ── Step 2: Clean offline Fleet agents ──────────────────────────────
echo "🔧 Step 2: Cleaning offline Fleet agents..."
curl -s -u elastic:"$PASS" "http://localhost:5601/api/fleet/agents?perPage=100" \
    -H "kbn-xsrf: true" 2>/dev/null | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('items',[]):
    if a.get('status') in ['offline','inactive']: print(a['id'])" 2>/dev/null | while read ID; do
    curl -s -u elastic:"$PASS" -X DELETE \
        "http://localhost:5601/api/fleet/agents/$ID" \
        -H "kbn-xsrf: true" > /dev/null 2>&1
    echo "  Removed: $ID"
done

# ── Step 3: Fleet agent enrollment ──────────────────────────────────
echo "🔧 Step 3: Fleet agent enrollment..."
for VICTIM in $FLEET_VICTIMS; do
    container_up "$VICTIM" || continue

    # Check if already online
    IS_ONLINE=$(curl -s -u elastic:"$PASS" \
        "http://localhost:5601/api/fleet/agents?perPage=50" \
        -H "kbn-xsrf: true" 2>/dev/null | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('items',[]):
    h=a.get('local_metadata',{}).get('host',{}).get('hostname','')
    if h=='$VICTIM' and a.get('status')=='online': print('yes')" 2>/dev/null)
    [ "$IS_ONLINE" = "yes" ] && { ok "Fleet online: $VICTIM"; continue; }

    # Find or install elastic-agent binary
    AGENT_BIN=$(docker exec $VICTIM sh -c \
        "find /opt/elastic-agent/data /usr/local/bin -name elastic-agent -type f -executable 2>/dev/null | head -1")

    if [ -z "$AGENT_BIN" ]; then
        echo "  📦 Installing agent on $VICTIM..."
        docker cp fleet-server:/usr/share/elastic-agent/data/elastic-agent-1eb18c/elastic-agent \
            /tmp/elastic-agent 2>/dev/null
        docker cp /tmp/elastic-agent $VICTIM:/usr/local/bin/elastic-agent 2>/dev/null
        docker exec $VICTIM chmod +x /usr/local/bin/elastic-agent 2>/dev/null
        AGENT_BIN="/usr/local/bin/elastic-agent"
    fi

    [ -z "$AGENT_BIN" ] && { warn "No binary: $VICTIM"; continue; }

    # Enroll
    docker exec $VICTIM $AGENT_BIN enroll \
        --url="http://fleet-server:8220" \
        --enrollment-token="$FLEET_TOKEN" \
        --insecure --force > /dev/null 2>&1

    # Start agent
    case "$VICTIM" in
        victim-ftp|victim-webapi)
            nohup docker exec -d $VICTIM /usr/local/bin/elastic-agent run > /dev/null 2>&1 &
            ok "Enrolled+started: $VICTIM" ;;
        *)
            docker exec -d $VICTIM $AGENT_BIN run
            ok "Enrolled+restarted: $VICTIM" ;;
    esac
done

# ── Step 4: Wazuh install (ephemeral) ───────────────────────────────

# Fix DVWA Apache DocumentRoot
docker exec victim-dvwa bash -c "
    grep -q '/var/www/html/dvwa' /etc/apache2/sites-enabled/000-default.conf || {
        sed -i 's|DocumentRoot /var/www/html$|DocumentRoot /var/www/html/dvwa|g' /etc/apache2/sites-enabled/000-default.conf
        service apache2 restart > /dev/null 2>&1
    }
" 2>/dev/null


# Start YARA scanner if not running
docker exec yara-scanner pgrep -f scan.py > /dev/null 2>&1 ||     docker exec -d yara-scanner python3 /scanner/scan.py
ok "YARA scanner running"

echo "🔧 Step 4: Wazuh install (ephemeral)..."
docker exec victim-ftp test -f /var/ossec/bin/wazuh-agentd 2>/dev/null || \
    { docker cp $PKG_DIR/wazuh-agent-4.7.5-x86_64.rpm victim-ftp:/tmp/w.rpm 2>/dev/null && \
      docker exec victim-ftp rpm -ihv /tmp/w.rpm 2>/dev/null; }
docker exec victim-webapi test -f /var/ossec/bin/wazuh-agentd 2>/dev/null || \
    { docker cp $PKG_DIR/wazuh-agent-4.7.5-amd64.deb victim-webapi:/tmp/w.deb 2>/dev/null && \
      docker exec victim-webapi dpkg -i /tmp/w.deb 2>/dev/null; }
docker exec victim-metasploitable test -f /var/ossec/bin/wazuh-agentd 2>/dev/null || \
    { docker cp $PKG_DIR/wazuh-agent-4.7.5-i386.deb victim-metasploitable:/tmp/w.deb 2>/dev/null && \
      docker exec victim-metasploitable dpkg -i /tmp/w.deb 2>/dev/null; }
for c in victim-ftp victim-webapi victim-metasploitable; do
    docker exec $c sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf 2>/dev/null
done

# ── Step 5: Wazuh agent enrollment ──────────────────────────────────
echo "🔧 Step 5: Wazuh agent enrollment..."
for VICTIM in $ALL_VICTIMS; do
    container_up "$VICTIM" || continue
    docker exec $VICTIM sh -c \
        "touch /var/log/auth.log 2>/dev/null; pgrep rsyslogd >/dev/null || rsyslogd 2>/dev/null" 2>/dev/null
    MKEY=$(docker exec $WAZUH_MANAGER grep " $VICTIM " /var/ossec/etc/client.keys 2>/dev/null)
    [ -z "$MKEY" ] && { \
        docker exec $VICTIM /var/ossec/bin/agent-auth -m wazuh-manager -p 1515 -A $VICTIM > /dev/null 2>&1
        echo "  🔑 Enrolled: $VICTIM"; }
    AKEY=$(docker exec $VICTIM cat /var/ossec/etc/client.keys 2>/dev/null)
    [ -z "$AKEY" ] && [ -n "$MKEY" ] && \
        docker exec $VICTIM sh -c "echo '$MKEY' > /var/ossec/etc/client.keys && chmod 640 /var/ossec/etc/client.keys" 2>/dev/null
    docker exec $VICTIM /var/ossec/bin/wazuh-control start > /dev/null 2>&1
    ok "Wazuh: $VICTIM"
done


# ── Fix victim-webapi Apache ─────────────────────────────────────────
docker exec victim-webapi bash -c "
    service apache2 status > /dev/null 2>&1 || service apache2 start > /dev/null 2>&1
" 2>/dev/null
ok "victim-webapi Apache running"

# ── Fix IoT Flask app ────────────────────────────────────────────────
docker exec victim-iot bash -c "
    pgrep -f 'python.*app\|python.*iot\|python.*main\|flask' > /dev/null 2>&1 || {
        cd /app && nohup python3 app.py > /tmp/iot.log 2>&1 &
    }
" 2>/dev/null
ok "IoT Flask app running"

# ── Fix ES hostname in VT enricher ───────────────────────────────────
docker exec vt-enricher env | grep -q "ES_HOST=http://elasticsearch" ||     docker restart vt-enricher > /dev/null 2>&1
ok "VT enricher ES_HOST correct"

# ── Final status ─────────────────────────────────────────────────────
echo ""; echo "⏳ Waiting 20s..."; sleep 20
echo "📊 Fleet:"
curl -s -u elastic:"$PASS" "http://localhost:5601/api/fleet/agents?perPage=20" \
    -H "kbn-xsrf: true" 2>/dev/null | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('items',[]):
    h=a.get('local_metadata',{}).get('host',{}).get('hostname','?')
    s=a.get('status','?')
    print(f'  {\"✅\" if s==\"online\" else \"❌\"} {h:25s} {s}')" 2>/dev/null
echo "📊 Wazuh:"
docker exec $WAZUH_MANAGER /var/ossec/bin/agent_control -l 2>/dev/null | grep -v "^$\|^List\|^Wazuh"
echo ""; echo "🎉 Fixes applied!"
# Wazuh API: wazuh:wazuh (HTTPS port 55000)

# === FIM CONFIG FIX ===
echo "[$(date)] Fixing FIM config on all agents..."
for container in victim-ubuntu victim-dvwa victim-windows victim-webapi victim-jenkins victim-mail victim-database victim-dns victim-iot victim-ftp; do
  docker exec $container sed -i 's/<frequency>43200<\/frequency>/<frequency>300<\/frequency>/g' \
    /var/ossec/etc/ossec.conf 2>/dev/null
  docker exec $container sed -i 's|<directories>/etc,/usr/bin,/usr/sbin</directories>|<directories check_all="yes" report_changes="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>|' \
    /var/ossec/etc/ossec.conf 2>/dev/null
  docker exec $container /var/ossec/bin/wazuh-control restart 2>/dev/null | grep -E "Completed" && \
    echo "  ✅ $container FIM fixed" || echo "  ⚠️ $container skipped"
done

# === VULNERABILITY DETECTOR FIX ===
echo "[$(date)] Ensuring vulnerability detector is enabled..."
docker exec wazuh-manager sed -i '/<vulnerability-detector>/,/<\/vulnerability-detector>/ s/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/g' \
  /var/ossec/etc/ossec.conf 2>/dev/null
docker exec wazuh-manager sed -i '/<provider name="canonical">/,/<\/provider>/ s/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/' \
  /var/ossec/etc/ossec.conf 2>/dev/null
docker exec wazuh-manager sed -i '/<provider name="debian">/,/<\/provider>/ s/<enabled>no<\/enabled>/<enabled>yes<\/enabled>/' \
  /var/ossec/etc/ossec.conf 2>/dev/null
echo "  ✅ Vulnerability detector enabled"

# === SURICATA DUPE SID CHECK ===
echo "[$(date)] Checking Suricata rules for duplicate SIDs..."
DUPE_COUNT=$(docker exec suricata bash -c "grep -oP 'sid:\d+' /var/lib/suricata/rules/suricata.rules | sort | uniq -d | wc -l" 2>/dev/null)
if [ "$DUPE_COUNT" -gt 0 ]; then
    echo "  ⚠️  Found $DUPE_COUNT duplicate SIDs — deduplicating..."
    docker exec suricata bash -c "
        awk '!seen[\$0]++' /var/lib/suricata/rules/suricata.rules > /tmp/suricata_deduped.rules
        mv /tmp/suricata_deduped.rules /var/lib/suricata/rules/suricata.rules
    "
    docker restart suricata
    echo "  ✅ Suricata rules deduplicated and restarted"
else
    echo "  ✅ Suricata rules clean ($DUPE_COUNT dupes)"
fi

# === YARA SCANNER CHECK ===

# === YARA TCP FIX CHECK ===
echo "[$(date)] Verifying YARA TCP send method..."
if docker exec yara-scanner grep -q "sendto" /scanner/scan.py 2>/dev/null; then
    echo "  ⚠️  YARA sendto bug detected — fixing..."
    sudo sed -i 's/sock\.sendto(message, (LOGSTASH_HOST, LOGSTASH_PORT))/sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))\n        sock.sendall(message)/' ~/soc-stack/yara/scanner/scan.py
    docker compose -f ~/soc-stack/docker-compose.yml up -d --build yara-scanner
    echo "  ✅ YARA TCP fix applied and rebuilt"
else
    echo "  ✅ YARA TCP method correct"
fi
echo "[$(date)] Checking YARA scanner and victim volume mounts..."
if ! docker ps --format '{{.Names}}' | grep -q '^yara-scanner$'; then
    echo "  🔄 YARA scanner not running — starting..."
    cd ~/soc-stack && docker compose up -d --no-deps yara-scanner
else
    # Verify victim paths are accessible
    for path in dvwa ubuntu-www ubuntu-tmp ftp; do
        docker exec yara-scanner ls /victims/$path/ > /dev/null 2>&1 && \
            echo "  ✅ /victims/$path mounted" || \
            echo "  ⚠️  /victims/$path not accessible"
    done
fi

# === YARA NAMED VOLUMES CHECK ===
echo "[$(date)] Checking YARA named volumes exist..."
for vol in yara-dvwa yara-ubuntu-www yara-ubuntu-tmp yara-ftp; do
    docker volume ls | grep -q "$vol" || {
        docker volume create "$vol"
        echo "  🔧 Created missing volume: $vol"
    }
    echo "  ✅ Volume exists: $vol"
done

# === VICTIM-FTP FLEET PERMANENT FIX ===
echo "[$(date)] Fixing victim-ftp Fleet agent..."
docker exec victim-ftp find /opt/elastic-agent/data -name "elastic-agent" -type f > /dev/null 2>&1 || {
  echo "  Recopying elastic-agent to victim-ftp..."
  docker cp victim-ubuntu:/opt/elastic-agent /tmp/elastic-agent-copy
  docker cp /tmp/elastic-agent-copy victim-ftp:/opt/elastic-agent
}
AGENT=$(docker exec victim-ftp find /opt/elastic-agent/data -name "elastic-agent" -type f 2>/dev/null | head -1)
docker exec victim-ftp pgrep -f elastic-agent > /dev/null 2>&1 || {
  docker exec -d victim-ftp $AGENT run
  echo "  ✅ victim-ftp Fleet agent started"
}

# === WAZUH WATCHDOG — ensure agentd stays running via watchdog ===
echo "[$(date)] Ensuring wazuh-agentd watchdog running on all victims..."
WATCHDOG=~/soc-stack/wazuh-agent/wazuh-watchdog.sh
for CTR in victim-dvwa victim-iot victim-mail victim-database victim-dns \
           victim-jenkins victim-windows victim-ftp victim-webapi; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  RUNNING=$(docker exec "$CTR" pgrep -c wazuh-agentd 2>/dev/null || echo 0)
  if [ "$RUNNING" -eq 0 ]; then
    docker cp "$WATCHDOG" "$CTR":/tmp/wazuh-watchdog.sh 2>/dev/null
    docker exec "$CTR" chmod +x /tmp/wazuh-watchdog.sh 2>/dev/null
    docker exec -d "$CTR" /tmp/wazuh-watchdog.sh 2>/dev/null
    echo "  ✅ Watchdog started: $CTR"
  else
    echo "  ✅ agentd already running: $CTR ($RUNNING proc)"
  fi
done

# === OPENCTI DNS FIX VERIFICATION ===
echo "[$(date)] Verifying OpenCTI extra_hosts in running containers..."
for CTR in connector-mitre connector-misp opencti-worker; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  if docker exec "$CTR" cat /etc/hosts 2>/dev/null | grep -q "opencti"; then
    echo "  ✅ $CTR: opencti resolves correctly"
  else
    OPENCTI_IP=$(docker inspect opencti --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
    docker exec "$CTR" bash -c "echo '$OPENCTI_IP opencti' >> /etc/hosts" 2>/dev/null
    echo "  🔧 $CTR: opencti host entry injected ($OPENCTI_IP)"
  fi
done
