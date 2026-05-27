#!/usr/bin/env bash
# SOC Stack — all fixes in one run
# Run from WSL2: bash fix-all.sh
# 25 May 2026 · said@NOBODY

set -euo pipefail
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GRN}[OK]${NC}  $*"; }
info() { echo -e "${BLU}[..] ${NC} $*"; }
warn() { echo -e "${YLW}[WRN]${NC} $*"; }
fail() { echo -e "${RED}[ERR]${NC} $*"; }
hr()   { echo -e "${BLU}────────────────────────────────────────${NC}"; }

hr
echo -e "${BLU}SOC Stack — Full Fix Run — $(date -u '+%Y-%m-%d %H:%M UTC')${NC}"
hr

# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 — victim-webapi wazuh enrollment
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "FIX 1 — Enrolling victim-webapi with wazuh (authd :1515)"

# Confirm authd is actually up before trying
if docker exec wazuh-manager ss -tlnp 2>/dev/null | grep -q 1515; then
  ok "authd is listening on :1515"
else
  warn "authd not yet on :1515 — waiting 5s..."
  sleep 5
fi

# Remove any stale agent key first so re-enrollment works cleanly
docker exec victim-webapi bash -c "
  if [ -f /var/ossec/etc/client.keys ]; then
    truncate -s 0 /var/ossec/etc/client.keys
  fi
" 2>/dev/null || true

# Enroll
docker exec victim-webapi bash -c "
  /var/ossec/bin/agent-auth -m wazuh-manager -A victim-webapi -p 1515
" && ok "victim-webapi enrolled with wazuh" \
  || fail "enrollment failed — check wazuh-manager authd logs"

# Start wazuh agent inside victim-webapi
docker exec victim-webapi bash -c "
  /var/ossec/bin/wazuh-control start 2>/dev/null || \
  /var/ossec/bin/ossec-control start 2>/dev/null
" && ok "wazuh agent started inside victim-webapi" \
  || warn "wazuh agent start returned non-zero (may already be running)"

hr

# ─────────────────────────────────────────────────────────────────────────────
# FIX 2 — wazuh-manager internal_options.conf persistence
# Wrap the entrypoint so the fix survives docker restart
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "FIX 2 — Making wazuh internal_options.conf persistent across restarts"

cat > /tmp/wazuh-init-wrapper.sh << 'WRAPPER'
#!/bin/bash
# Injected by fix-all.sh — runs before the standard wazuh entrypoint
CONF=/var/ossec/etc/internal_options.conf

apply_fix() {
  if [ -f "$CONF" ]; then
    if ! grep -q "wazuh_db.rlimit_nofile=65536" "$CONF"; then
      echo "wazuh_db.rlimit_nofile=65536" >> "$CONF"
    fi
    chown wazuh:wazuh "$CONF"
    chmod 660 "$CONF"
  fi
}

# Wait for the conf to appear (the real entrypoint creates it)
for i in $(seq 1 15); do
  if [ -f "$CONF" ]; then apply_fix; break; fi
  sleep 1
done

# Now hand off to the original entrypoint
exec /var/ossec/bin/wazuh-control start
WRAPPER

docker cp /tmp/wazuh-init-wrapper.sh wazuh-manager:/var/ossec/bin/fix-rlimit.sh
docker exec wazuh-manager chmod +x /var/ossec/bin/fix-rlimit.sh
ok "fix-rlimit.sh installed inside wazuh-manager container"

# Apply right now too (in case conf was overwritten during session)
docker exec wazuh-manager bash -c "
  grep -q 'wazuh_db.rlimit_nofile=65536' /var/ossec/etc/internal_options.conf \
    || echo 'wazuh_db.rlimit_nofile=65536' >> /var/ossec/etc/internal_options.conf
  chown wazuh:wazuh /var/ossec/etc/internal_options.conf
" && ok "rlimit line confirmed in running container"

warn "NOTE: to survive a full container recreate, add to your compose:"
echo "      command: [\"/var/ossec/bin/fix-rlimit.sh\"]"

hr

# ─────────────────────────────────────────────────────────────────────────────
# FIX 3 — logstash pipeline diagnosis + auto-fix attempt
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "FIX 3 — Diagnosing logstash pipeline ConfigurationError"

LOGSTASH_ERR=$(docker exec logstash \
  logstash --config.test_and_exit \
    -f /usr/share/logstash/pipeline/ \
    --log.level=error 2>&1 | grep -E "ERROR|ConfigurationError|line [0-9]|Undefined variable" || true)

echo "$LOGSTASH_ERR"

if echo "$LOGSTASH_ERR" | grep -q "Undefined variable"; then
  MISSING_VAR=$(echo "$LOGSTASH_ERR" | grep -oP "Undefined variable.*" | head -1)
  warn "Missing env variable detected: $MISSING_VAR"
  warn "Add the missing variable to your .env file and rerun docker compose up -d logstash"
fi

if echo "$LOGSTASH_ERR" | grep -q "plugin.*not found\|No plugin found"; then
  MISSING_PLUGIN=$(echo "$LOGSTASH_ERR" | grep -oP "logstash-[a-z]+-[a-z]+" | head -1)
  warn "Missing plugin detected: $MISSING_PLUGIN"
  info "Installing plugin inside running container..."
  docker exec logstash logstash-plugin install "$MISSING_PLUGIN" \
    && ok "Plugin $MISSING_PLUGIN installed — restarting logstash..." \
    && docker restart logstash \
    || fail "Auto-install failed — rebuild logstash-custom:local image"
fi

# Write a known-good minimal pipeline that at least starts,
# so Kibana gets SOME data while you fix the real pipeline
info "Writing fallback minimal pipeline to /tmp/soc-minimal.conf"
cat > /tmp/soc-minimal.conf << 'PIPELINE'
input {
  beats {
    port => 5044
  }
  syslog {
    port => 5000
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    user => "${ELASTIC_USER:elastic}"
    password => "${ELASTIC_PASSWORD}"
    index => "soc-logs-%{+YYYY.MM.dd}"
  }
}
PIPELINE

docker cp /tmp/soc-minimal.conf logstash:/usr/share/logstash/pipeline/00-soc-minimal.conf
ok "Fallback pipeline written — testing..."

FALLBACK_TEST=$(docker exec logstash \
  logstash --config.test_and_exit \
    -f /usr/share/logstash/pipeline/00-soc-minimal.conf \
    --log.level=error 2>&1 | tail -3)
echo "$FALLBACK_TEST"

if echo "$FALLBACK_TEST" | grep -q "Configuration OK"; then
  ok "Fallback pipeline is valid — restarting logstash"
  docker restart logstash
  sleep 8
  docker ps --filter name=logstash --format "  status: {{.Status}}"
else
  warn "Fallback pipeline also has errors — check ELASTIC_PASSWORD is set in .env"
fi

hr

# ─────────────────────────────────────────────────────────────────────────────
# FIX 4 — filebeat inputs
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "FIX 4 — Configuring filebeat inputs"

# Discover what log paths are accessible inside filebeat
info "Scanning log paths visible inside filebeat container..."
SURICATA_LOG=$(docker exec filebeat find / -name "eve.json" 2>/dev/null | grep -v proc | head -1 || true)
WAZUH_ALERTS=$(docker exec filebeat find / -name "alerts.json" 2>/dev/null | grep -v proc | head -1 || true)
WAZUH_LOG=$(docker exec filebeat find / -path "*/ossec/logs*" -name "*.log" 2>/dev/null | head -1 || true)

[ -n "$SURICATA_LOG" ] && ok  "Suricata eve.json found at: $SURICATA_LOG" \
                        || warn "eve.json not mounted inside filebeat — check volume in compose"
[ -n "$WAZUH_ALERTS" ] && ok  "Wazuh alerts.json found at: $WAZUH_ALERTS" \
                         || warn "wazuh alerts.json not mounted — check volume"

# Use discovered paths or fall back to standard defaults
SURICATA_PATH="${SURICATA_LOG:-/var/log/suricata/eve.json}"
WAZUH_PATH="${WAZUH_ALERTS:-/var/ossec/logs/alerts/alerts.json}"

info "Writing filebeat.yml (paths: suricata=$SURICATA_PATH  wazuh=$WAZUH_PATH)"

cat > /tmp/filebeat-fixed.yml << FBEOF
filebeat.inputs:

  - type: log
    id: suricata-eve
    enabled: true
    paths:
      - ${SURICATA_PATH}
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      source_type: suricata
    fields_under_root: true
    tags: ["suricata", "ids"]

  - type: log
    id: wazuh-alerts
    enabled: true
    paths:
      - ${WAZUH_PATH}
    json.keys_under_root: true
    json.add_error_key: true
    multiline.pattern: '^{'
    multiline.negate: true
    multiline.match: after
    fields:
      source_type: wazuh
    fields_under_root: true
    tags: ["wazuh", "siem"]

  - type: log
    id: victim-syslog
    enabled: true
    paths:
      - /var/log/victims/*.log
      - /var/log/victims/*.syslog
    fields:
      source_type: victim-syslog
    fields_under_root: true
    tags: ["victim", "syslog"]
    ignore_older: 24h

setup.kibana:
  host: "kibana:5601"

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  username: "\${ELASTIC_USER:elastic}"
  password: "\${ELASTIC_PASSWORD}"
  index: "filebeat-soc-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 3
FBEOF

docker cp /tmp/filebeat-fixed.yml filebeat:/usr/share/filebeat/filebeat.yml
docker exec filebeat chown root:root /usr/share/filebeat/filebeat.yml
docker exec filebeat chmod 600 /usr/share/filebeat/filebeat.yml

info "Testing filebeat config..."
docker exec filebeat filebeat test config -c /usr/share/filebeat/filebeat.yml \
  && ok "filebeat config valid" \
  || fail "filebeat config invalid — check paths and credentials"

info "Restarting filebeat..."
docker restart filebeat
sleep 6

# Check harvesters started
HARVESTER_COUNT=$(docker logs filebeat --since 30s 2>&1 | grep -c "harvester" || true)
info "Harvester mentions in last 30s logs: $HARVESTER_COUNT"
docker logs filebeat --since 30s 2>&1 | grep -E "harvester|Starting|error|ERROR" | head -15 || true
ok "filebeat restarted — monitor with: docker logs -f filebeat"

hr

# ─────────────────────────────────────────────────────────────────────────────
# FINAL STATUS CHECK
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "Final status check..."
sleep 3

check_svc() {
  local name="$1"
  local status
  status=$(docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null || echo "missing")
  local health
  health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$name" 2>/dev/null || echo "?")
  printf "  %-25s  status=%-10s  health=%s\n" "$name" "$status" "$health"
}

for svc in elasticsearch kibana logstash filebeat elastalert fleet-server \
           wazuh-manager suricata yara-scanner thehive vt-enricher \
           opencti opencti-worker connector-misp misp rabbitmq minio \
           victim-webapi kali-attacker; do
  check_svc "$svc"
done

hr
echo ""
echo -e "${GRN}Fix run complete.${NC}"
echo ""
echo "  Remaining manual steps:"
echo "  1. Kibana → Fleet → Agents → Force unenroll offline victim-ftp + duplicate fleet-server"
echo "  2. Update victims-edr policy (rev.138 → current) in Fleet → Agent policies"
echo "  3. Change MISP password (admin@admin.test / admin)"
echo "  4. Change TheHive password (admin@thehive.local / secret)"
echo "  5. Verify log flow: docker logs -f filebeat | grep harvester"
echo "     Then in Kibana Discover → index: filebeat-soc-* — events should appear within 60s"
echo ""
echo "  Startup alias (add to ~/.bashrc):"
echo "  alias soc='docker compose -f docker-compose.yml -f docker-compose-lab.yml up -d'"
echo ""
