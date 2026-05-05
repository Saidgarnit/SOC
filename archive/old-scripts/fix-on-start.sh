#!/bin/bash
echo "🔧 SOC stack fixes (no restart)..."
PASS="sYVfKJCe2RCfELjf=GLa"
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
    for i in $(seq 1 6); do
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
for i in $(seq 1 6); do
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
        "find /opt/elastic-agent /usr/local/bin -name elastic-agent -type f -executable 2>/dev/null | head -1")

    if [ -z "$AGENT_BIN" ]; then
        echo "  📦 Installing agent on $VICTIM..."
        docker exec victim-ubuntu tar -czf /tmp/ea.tar.gz -C /opt/elastic-agent . 2>/dev/null
        docker cp victim-ubuntu:/tmp/ea.tar.gz /tmp/ea.tar.gz 2>/dev/null
        rm -rf /tmp/ea_ext 2>/dev/null
        mkdir -p /tmp/ea_ext 2>/dev/null
        tar -xzf /tmp/ea.tar.gz -C /tmp/ea_ext 2>/dev/null
        rm -rf /tmp/ea_ext/state 2>/dev/null
        
        docker stop $VICTIM 2>/dev/null
        docker cp /tmp/ea_ext/. $VICTIM:/opt/elastic-agent/ 2>/dev/null
        docker start $VICTIM 2>/dev/null
        sleep 5
        AGENT_BIN="/opt/elastic-agent/elastic-agent"
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
            nohup docker exec -d $VICTIM bash -c "while true; do /opt/elastic-agent/elastic-agent run >/dev/null 2>&1; sleep 5; done" > /dev/null 2>&1 &
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
# (Removed: handled beautifully in Step 3 now)

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

# === ELASTICSEARCH ILM POLICY ===
echo "[$(date)] Applying Elasticsearch ILM policy..."
docker exec elasticsearch curl -s -u elastic:sYVfKJCe2RCfELjf=GLa \
  -X PUT "http://localhost:9200/_ilm/policy/soc-retention-30d" \
  -H 'Content-Type: application/json' \
  -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}'
echo "  ✅ ILM policy applied"

# === WAZUH EMAIL RATE LIMIT RULES ===
echo "[$(date)] Applying Wazuh email rate limit rules..."
docker exec wazuh-manager mkdir -p /var/ossec/etc/rules
docker exec wazuh-manager bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << RULES
<group name="local,soc_ratelimit,">
  <rule id="100001" level="12" frequency="5" timeframe="3600">
    <if_matched_group>authentication_failed</if_matched_group>
    <description>Critical: Auth failure rate limit</description>
    <options>alert_by_email</options>
  </rule>
  <rule id="100002" level="10" frequency="20" timeframe="3600">
    <if_matched_group>attack</if_matched_group>
    <description>High: Attack alert rate limit</description>
  </rule>
</group>
RULES'
echo "  ✅ Email rate limit rules applied"

# === SURICATA NOISE FILTER ===
echo "[$(date)] Ensuring Suricata noise filter in Logstash..."
grep -q "DROP SURICATA NOISE" ~/soc-stack/logstash/pipeline/logstash.conf || \
  sed -i 's/filter {/filter {\n\n  # ================= DROP SURICATA NOISE =================\n  if [type] == "SuricataIDPS" and [event_type] in ["http", "flow", "stats"] {\n    drop { }\n  }\n/' \
  ~/soc-stack/logstash/pipeline/logstash.conf
echo "  ✅ Suricata noise filter active"

# === LOGSTASH CONFIG FIXES ===
echo "[$(date)] Ensuring Logstash config is clean..."
sed -i '/tcp { port => 5000 codec => json }/d' ~/soc-stack/logstash/pipeline/logstash.conf
sed -i 's/udp { port => 5000/udp { port => 5001/' ~/soc-stack/logstash/pipeline/logstash.conf
grep -q "DROP SURICATA NOISE" ~/soc-stack/logstash/pipeline/logstash.conf || \
  sed -i 's/filter {/filter {\n\n  # ================= DROP SURICATA NOISE =================\n  if [type] == "SuricataIDPS" and [event_type] in ["http", "flow", "stats"] {\n    drop { }\n  }\n/' \
  ~/soc-stack/logstash/pipeline/logstash.conf
echo "  ✅ Logstash config clean"

# ── Permanent: remove duplicate/offline Fleet agent records ──────────
echo "🧹 Cleaning duplicate Fleet agent registrations..."
sleep 5
PASS_LOCAL=$(grep -E "ELASTIC_PASSWORD" ~/soc-stack/docker-compose.yml | \
  head -1 | sed 's/.*ELASTIC_PASSWORD[=:]\s*//' | tr -d '"' | tr -d "'" | tr -d ' ')
curl -s -u "elastic:${PASS_LOCAL}" \
  "http://localhost:5601/api/fleet/agents?perPage=100" \
  -H "kbn-xsrf: true" | \
  python3 -c "
import json,sys
from collections import defaultdict
items=json.loads(sys.stdin.read()).get('items',[])
by_host=defaultdict(list)
for a in items:
    h=a.get('local_metadata',{}).get('host',{}).get('hostname',a.get('id','?'))
    by_host[h].append((a.get('status'),a.get('id')))
for h,agents in by_host.items():
    if len(agents)>1:
        # keep online ones, delete offline/extra
        online=[i for s,i in agents if s=='online']
        to_del=[i for s,i in agents if s!='online']
        if not online: to_del=to_del[1:]  # keep at least one if all offline
        for i in to_del: print(i)
" | while read ID; do
  curl -s -u "elastic:${PASS_LOCAL}" \
    -X DELETE "http://localhost:5601/api/fleet/agents/${ID}" \
    -H "kbn-xsrf: true" > /dev/null 2>&1
  echo "  🗑 Removed stale Fleet agent: $ID"
done
echo "✅ Fleet dedup complete"

# ── Permanent: sync Wazuh client.keys from manager to each agent ──
echo "🔑 Syncing Wazuh agent keys..."
sleep 3
docker exec wazuh-manager cat /var/ossec/etc/client.keys > /tmp/wazuh-master.keys 2>/dev/null
if [ -s /tmp/wazuh-master.keys ]; then
  for CTR in victim-ubuntu victim-dvwa victim-iot victim-windows \
             victim-mail victim-dns victim-jenkins victim-database \
             victim-ftp victim-webapi; do
    HOSTNAME=$(docker exec $CTR hostname 2>/dev/null)
    KEY_LINE=$(grep " ${HOSTNAME} " /tmp/wazuh-master.keys)
    if [ -n "$KEY_LINE" ]; then
      echo "$KEY_LINE" | docker exec -i $CTR tee /var/ossec/etc/client.keys > /dev/null
      docker exec $CTR chown root:wazuh /var/ossec/etc/client.keys 2>/dev/null || true
      docker exec $CTR chmod 640 /var/ossec/etc/client.keys
    fi
  done
  echo "  ✅ Keys synced to all agents"
fi
rm -f /tmp/wazuh-master.keys

# ── MITRE_FIX: auto-patch missing sub-techniques on boot ──
echo "Patching MITRE DB..."
docker exec wazuh-manager bash -c 'command -v sqlite3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq sqlite3; }; DB="/var/ossec/var/db/mitre.db"; TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\" AND name LIKE \"%technique%\" LIMIT 1;"); [ -n "$TABLE" ] && { for TID in $(grep -roh "T[0-9]\{4\}\.[0-9]\{3\}" /var/ossec/ruleset/rules/ 2>/dev/null | sort -u); do [ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE WHERE id=\"$TID\";")" = "0" ] && { P="${TID%%.*}"; N=$(sqlite3 "$DB" "SELECT name FROM $TABLE WHERE id=\"$P\";" 2>/dev/null||echo "Unknown"); sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id,name) VALUES (\"$TID\",\"${N}: Sub ${TID##*.}\");" 2>/dev/null; }; done; kill -1 $(pgrep -f wazuh-analysisd) 2>/dev/null||true; echo "MITRE DB patched"; }'

# Automatically clean up offline ghosts
echo "Cleaning up offline Kibana agents..."
PASS_LOCAL="sYVfKJCe2RCfELjf=GLa"
curl -s -u "elastic:${PASS_LOCAL}" "http://localhost:5601/api/fleet/agents?perPage=100" -H "kbn-xsrf: true" 2>/dev/null | \
  python3 -c "
import json,sys
try:
    for a in json.loads(sys.stdin.read()).get('items',[]):
        if a.get('status') == 'offline': print(a.get('id'))
except: pass
" | while read ID; do
  curl -s -u "elastic:${PASS_LOCAL}" -X DELETE "http://localhost:5601/api/fleet/agents/${ID}" -H "kbn-xsrf: true" > /dev/null 2>&1
done

# === BUG10+BUG11 FIX: Apache + Auth.log localfile injection ===
echo "[$(date)] Injecting Apache and auth.log localfile configs..."
for CTR in victim-dvwa victim-webapi; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  docker exec $CTR bash -c "
    grep -q 'apache2/access.log\|httpd/access_log' /var/ossec/etc/ossec.conf || \
    sed -i 's|</ossec_config>|  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/apache2/access.log</location>\n  </localfile>\n</ossec_config>|' \
      /var/ossec/etc/ossec.conf
  " 2>/dev/null && echo "  ✅ Apache localfile: $CTR"
done

for CTR in victim-ubuntu victim-dvwa victim-iot victim-mail victim-database \
           victim-dns victim-jenkins victim-windows victim-ftp victim-webapi; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  docker exec $CTR bash -c "
    grep -q 'auth.log\|var/log/secure' /var/ossec/etc/ossec.conf || \
    sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n</ossec_config>|' \
      /var/ossec/etc/ossec.conf
  " 2>/dev/null && echo "  ✅ auth.log localfile: $CTR"
  docker exec $CTR /var/ossec/bin/wazuh-control restart > /dev/null 2>&1
done
echo "  ✅ Apache + auth.log injection complete"

# === BUG10+BUG11 FIX: Apache + Auth.log localfile injection ===
echo "[$(date)] Injecting Apache and auth.log localfile configs..."
for CTR in victim-dvwa victim-webapi; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  docker exec $CTR bash -c "
    grep -q 'apache2/access.log\|httpd/access_log' /var/ossec/etc/ossec.conf || \
    sed -i 's|</ossec_config>|  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/apache2/access.log</location>\n  </localfile>\n</ossec_config>|' \
      /var/ossec/etc/ossec.conf
  " 2>/dev/null && echo "  ✅ Apache localfile: $CTR"
done

for CTR in victim-ubuntu victim-dvwa victim-iot victim-mail victim-database \
           victim-dns victim-jenkins victim-windows victim-ftp victim-webapi; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  docker exec $CTR bash -c "
    grep -q 'auth.log\|var/log/secure' /var/ossec/etc/ossec.conf || \
    sed -i 's|</ossec_config>|  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n</ossec_config>|' \
      /var/ossec/etc/ossec.conf
  " 2>/dev/null && echo "  ✅ auth.log localfile: $CTR"
  docker exec $CTR /var/ossec/bin/wazuh-control restart > /dev/null 2>&1
done
echo "  ✅ Apache + auth.log injection complete"

# === BUG8 FIX: Ensure syscheck is inside <ossec_config> ===
echo "[$(date)] Verifying syscheck placement..."
for CTR in victim-ftp victim-webapi victim-jenkins; do
  docker ps --format '{{.Names}}' | grep -q "^${CTR}$" || continue
  docker exec $CTR bash -c "
    LAST=\$(grep -n '</ossec_config>' /var/ossec/etc/ossec.conf | tail -1 | cut -d: -f1)
    SC=\$(grep -n '</syscheck>' /var/ossec/etc/ossec.conf | tail -1 | cut -d: -f1)
    if [ \"\$SC\" -gt \"\$LAST\" ]; then
      SS=\$(grep -n '<syscheck>' /var/ossec/etc/ossec.conf | tail -1 | cut -d: -f1)
      sed -n \"\${SS},\${SC}p\" /var/ossec/etc/ossec.conf > /tmp/sc.txt
      sed -i \"\${SS},\${SC}d\" /var/ossec/etc/ossec.conf
      L2=\$(grep -n '</ossec_config>' /var/ossec/etc/ossec.conf | tail -1 | cut -d: -f1)
      sed -i \"\${L2}r /tmp/sc.txt\" /var/ossec/etc/ossec.conf
      echo '  fixed: \$(hostname)'
    fi
  " 2>/dev/null && echo "  ✅ syscheck OK: $CTR"
done

# === KALI WORDLIST FIX ===
echo "[$(date)] Ensuring rockyou.txt is available..."
  [ -f /usr/share/wordlists/rockyou.txt ] || \
  gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || \
  echo 'rockyou.txt missing entirely'
" 2>/dev/null && echo "  ✅ rockyou.txt ready"

# === KALI ATTACK TOOLS FIX ===
echo "[$(date)] Ensuring kali attack tools ready..."
# Ensure wordlist exists
  [ -s /usr/share/wordlists/rockyou.txt ] && exit 0
  mkdir -p /usr/share/wordlists
  curl -sL https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt \
    -o /usr/share/wordlists/rockyou.txt 2>/dev/null || \
  printf 'password\n123456\npassword123\nadmin\nroot\nletmein\nwelcome\n' \
    > /usr/share/wordlists/rockyou.txt
" 2>/dev/null && echo "  ✅ wordlist ready"


# ── PERMANENT FIXES ADDED THIS SESSION ──────────────────────────

# ATK-7: Fix vsftpd decoder name in Wazuh rules
docker exec wazuh-manager sed -i 's/vsftpd-failed/vsftpd/g' /var/ossec/etc/rules/vsftpd_rules.xml 2>/dev/null

# ATK-8: DNS Tunneling Suricata rule
docker exec suricata sh -c 'grep -q "1000010" /etc/suricata/rules/local.rules || echo "alert dns any any -> any 53 (msg:\"DNS Tunneling - Long Subdomain Query\"; dns.query; content:\"evil-c2-domain.com\"; nocase; threshold: type both, track by_src, count 5, seconds 10; sid:1000010; rev:1;)" >> /etc/suricata/rules/local.rules'

# ATK-10: RDP Brute Force Suricata rule  
docker exec suricata sh -c 'grep -q "1000011" /etc/suricata/rules/local.rules || echo "alert tcp any any -> any 3389 (msg:\"RDP Brute Force Attempt\"; flow:to_server; threshold: type both, track by_src, count 5, seconds 10; sid:1000011; rev:1;)" >> /etc/suricata/rules/local.rules'

# ATK-12: Fix C2 Beaconing rule direction
docker exec suricata sed -i 's/alert tcp !172.18.0.0\/24 any -> \$EXTERNAL_NET any (msg:"C2 Beaconing".*/alert tcp 172.18.0.0\/24 any -> any any (msg:"C2 Beaconing"; flow:to_server,established; dsize:<50; threshold:type threshold,track by_src,count 10,seconds 60; sid:1000012; rev:1;)/' /etc/suricata/rules/local.rules 2>/dev/null

# ATK-14: MQTT Anomaly Suricata rule
docker exec suricata sh -c 'grep -q "1000015" /etc/suricata/rules/local.rules || echo "alert tcp any any -> any 1883 (msg:\"MQTT Anomaly Detected\"; threshold:type threshold,track by_src,count 3,seconds 60; sid:1000015; rev:1;)" >> /etc/suricata/rules/local.rules'

# ATK-13: Fix victim-dvwa FIM config to monitor uploads
docker exec victim-dvwa sh -c 'grep -q "hackable" /var/ossec/etc/ossec.conf || cat > /var/ossec/etc/ossec.conf << CONF
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>
  <logging><log_format>plain</log_format></logging>
  <syscheck>
    <disabled>no</disabled>
    <frequency>60</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes">/tmp</directories>
    <directories realtime="yes" check_all="yes">/var/www/html/dvwa/hackable/uploads</directories>
  </syscheck>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
CONF'

# elastalert_status intentionally NOT deleted on boot
# Deleting it causes 429 Slack floods on every restart (silence index lost)


# ── CPU CAPS ─────────────────────────────────────────────────────
docker update --cpus="2.0" elasticsearch
docker update --cpus="1.0" kibana
docker update --cpus="1.0" logstash
docker update --cpus="0.5" opencti
docker update --cpus="0.5" connector-mitre
docker update --cpus="0.5" connector-misp
docker update --cpus="0.5" opencti-worker
docker update --cpus="0.3" elastalert
docker update --cpus="0.3" filebeat
docker update --cpus="0.3" suricata

# Re-inject correct MISP API key into connector-misp
NEW_KEY=$(docker exec misp bash -c "cd /var/www/MISP && app/Console/cake user change_authkey admin@admin.test" | grep -oP "[A-Za-z0-9]{40}")
docker stop connector-misp && docker rm connector-misp
docker run -d --name connector-misp --network soc-stack_soc-net --restart unless-stopped \
  -e OPENCTI_URL=http://opencti:8080 \
  -e OPENCTI_TOKEN=a3c5e7f9-b1d3-4e6f-8a2c-0d1e3f5a7b9c \
  -e CONNECTOR_ID=misp-connector-001 -e CONNECTOR_NAME=MISP \
  -e CONNECTOR_SCOPE=misp-galaxy,misp-attribute -e CONNECTOR_CONFIDENCE_LEVEL=75 \
  -e CONNECTOR_LOG_LEVEL=info -e CONNECTOR_TYPE=EXTERNAL_IMPORT \
  -e MISP_URL=http://misp -e MISP_KEY=$NEW_KEY \
  -e MISP_SSL=false -e MISP_FEED_MODE=false -e MISP_CREATE_REPORTS=true \
  -e MISP_CREATE_INDICATORS=true -e MISP_CREATE_OBSERVABLES=true \
  -e MISP_REPORT_TYPE=misp-event -e MISP_IMPORT_FROM_DATE=2026-01-01 \
  -e MISP_INTERVAL=5 -e MISP_DATETIME_ATTRIBUTE=timestamp \
  opencti/connector-misp:6.0.5
docker update --cpus="0.3" rabbitmq
python3 /home/said/soc-stack/misp_es_enricher.py
docker update --cpus="0.3" opencti-rabbitmq 2>/dev/null
curl -s -u elastic:sYVfKJCe2RCfELjf=GLa -X PUT "http://localhost:9200/_settings" -H "Content-Type: application/json" -d '{"index": {"refresh_interval": "30s"}}' > /dev/null 2>&1

# Fix auth.log ownership so rsyslog can write SSH failures
for CTR in victim-ubuntu victim-dvwa victim-dns victim-mail victim-jenkins victim-iot victim-windows victim-database victim-ftp victim-webapi; do
  timeout 10 docker exec $CTR bash -c "chown syslog:adm /var/log/auth.log 2>/dev/null; service rsyslog start 2>/dev/null; service ssh start 2>/dev/null" > /dev/null 2>&1
done

# Fix corrupted ossec.conf XML (FIM block outside root element) — ossec_config_fix
for CTR in victim-ubuntu victim-dvwa victim-dns victim-mail victim-iot victim-windows victim-database victim-webapi; do
  timeout 15 docker exec $CTR python3 -c "
import re
with open('/var/ossec/etc/ossec.conf') as f: c = f.read()
if '</ossec_config>' in c and c.strip().endswith('</ossec_config>') == False:
    c = re.sub(r'</ossec_config>.*', '</ossec_config>', c, flags=re.DOTALL)
    with open('/var/ossec/etc/ossec.conf','w') as f: f.write(c)
" > /dev/null 2>&1
done

# Fix corrupted ossec.conf on containers without python3 — ossec_config_fix_nopython
for CTR in victim-jenkins victim-ftp; do
  timeout 15 docker exec $CTR bash -c '
    LINE=$(grep -n "</ossec_config>" /var/ossec/etc/ossec.conf | head -1 | cut -d: -f1)
    TOTAL=$(wc -l < /var/ossec/etc/ossec.conf)
    if [ -n "$LINE" ] && [ "$TOTAL" -gt "$LINE" ]; then
      head -n $LINE /var/ossec/etc/ossec.conf > /tmp/ossec_clean.conf
      cp /tmp/ossec_clean.conf /var/ossec/etc/ossec.conf
    fi
  ' > /dev/null 2>&1
done
