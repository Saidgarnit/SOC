# ============================================================
# SOC Stack – Permanent Fixes: Deployment Guide
# ============================================================
# Version : 1.0
# Date    : 2026-05-04
# Covers  : All 18 issues identified in the root-cause analysis
# ============================================================

## Overview

All fixes in this package target **permanent** resolution — no
more per-boot workarounds in `start-soc.sh`. After applying these
fixes, the stack should survive container restarts and WSL2 reboots
without manual intervention.

---

## File Map

```
soc-fixes/
├── .env                                   ← Centralized credentials
├── configs/
│   └── system-configuration.md           ← WSL2, sysctl, Docker daemon
├── docker/
│   └── docker-compose-patches.md         ← All docker-compose.yml changes
├── elasticsearch/
│   └── init-es.sh                        ← Auto-configures ES on first boot
├── misp/
│   └── healthcheck.sh                    ← Enables service_healthy for MISP
├── scripts/
│   ├── fix-elastalert-rules.sh           ← Patches all 18 rule files
│   └── monitor-wazuh-agents.sh           ← Fixed HTTPS + correct creds
└── wazuh/
    ├── agent/wazuh-watchdog.sh           ← Keeps agents enrolled & running
    └── config/shared/default/agent.conf  ← Missing config file (was docker cp)
```

---

## Step-by-Step Deployment

### Phase 0 — Prerequisites

```bash
# Verify system resources
free -h          # Need ≥ 12 GB RAM available
df -h /          # Need ≥ 50 GB free

# Install required tools
sudo apt-get install -y curl jq netcat-openbsd python3

# Apply sysctl settings (Elasticsearch requires vm.max_map_count)
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-soc.conf
sudo sysctl -p /etc/sysctl.d/99-soc.conf
```

---

### Phase 1 — System Configuration (WSL2 users)

1. Create `C:\Users\<YOU>\.wslconfig` from `configs/system-configuration.md` §1
2. Run `wsl --shutdown` in PowerShell and reopen WSL
3. Inside WSL, apply the persistent swap from §2
4. Apply Docker daemon config from §4
5. Run `sudo systemctl restart docker`

---

### Phase 2 — Deploy Configuration Files

```bash
cd /path/to/your/soc-stack

# Copy .env (backup existing if present)
cp .env .env.backup 2>/dev/null || true
cp /path/to/soc-fixes/.env .

# Edit .env with your real values (minimum required changes):
#   SLACK_WEBHOOK_URL  ← get from https://api.slack.com/apps
#   OPENCTI_ADMIN_TOKEN ← generate: uuidgen
#   KIBANA_ENCRYPTION_KEY ← generate: openssl rand -hex 32

nano .env  # or your preferred editor

# Copy Elasticsearch init script
mkdir -p elasticsearch
cp /path/to/soc-fixes/elasticsearch/init-es.sh elasticsearch/
chmod +x elasticsearch/init-es.sh

# Copy MISP healthcheck
mkdir -p misp
cp /path/to/soc-fixes/misp/healthcheck.sh misp/
chmod +x misp/healthcheck.sh

# Copy Wazuh watchdog
mkdir -p wazuh-agent
cp /path/to/soc-fixes/wazuh-agent/wazuh-watchdog.sh wazuh-agent/
chmod +x wazuh-agent/wazuh-watchdog.sh

# Copy missing Wazuh agent config (fixes broken bind mount)
mkdir -p wazuh/config/shared/default
cp /path/to/soc-fixes/wazuh/config/shared/default/agent.conf \
   wazuh/config/shared/default/agent.conf

# Copy fixed monitoring script
cp /path/to/soc-fixes/scripts/monitor-wazuh-agents.sh scripts/
cp /path/to/soc-fixes/scripts/fix-elastalert-rules.sh scripts/
chmod +x scripts/*.sh
```

---

### Phase 3 — Apply docker-compose.yml Patches

Follow `docker/docker-compose-patches.md` section by section.
Key changes in order of importance:

| # | Change | Impact |
|---|--------|--------|
| 1 | `connector-misp`: `service_started` → `service_healthy` | Fixes exit 143 race |
| 2 | `connector-misp`: `128m` → `512m` memory | Fixes exit 143 OOM |
| 3 | `MISP_KEY`: hardcoded → `${MISP_API_KEY}` | Fixes stale key |
| 4 | Add MISP `healthcheck` | Enables #1 |
| 5 | Add `elasticsearch-init` service | Auto-configures ES auth |
| 6 | Remove Kibana `SERVICEACCOUNTTOKEN` | Fixes 401 on ES data wipe |
| 7 | Add Kibana basic auth env vars | Provides auth fallback |
| 8 | Fix Wazuh shared config mount (dir, not file) | Fixes broken bind mount |
| 9 | Add `wazuh-watchdog.sh` to all victim containers | Fixes Never Connected |
| 10 | Set Logstash `sincedb_path => "/dev/null"` | Fixes stale offsets |

Validate after editing:
```bash
docker compose config > /dev/null && echo "✓ docker-compose.yml is valid"
```

---

### Phase 4 — Initial Deployment

```bash
# Stop everything cleanly
docker compose down --remove-orphans

# Start core infrastructure
docker compose up -d elasticsearch
echo "Waiting for Elasticsearch (up to 60s)..."
docker compose ps elasticsearch   # wait for 'healthy'

# Run initialization (auto-configures passwords, kibana token, templates)
docker compose up elasticsearch-init
docker compose logs elasticsearch-init   # verify completion

# Save the Kibana token (if generated)
cat elasticsearch/kibana-token.txt 2>/dev/null && \
  echo "→ Add KIBANA_SERVICE_TOKEN to .env if desired (optional now)"

# Start remaining services
docker compose up -d redis rabbitmq minio misp-db misp-redis
sleep 15

docker compose up -d kibana opencti
sleep 30

# MISP takes 5-10 minutes on first start
docker compose up -d misp
echo "Waiting for MISP to initialize (5-10 minutes)..."
docker compose logs -f misp   # Ctrl+C when you see MISP is ready

# Start security services
docker compose up -d wazuh-manager suricata logstash elastalert
sleep 30

# Start victim containers (watchdog will auto-enroll agents)
docker compose up -d victim-ubuntu victim-dvwa victim-iot victim-mail
```

---

### Phase 5 — Post-Deployment Configuration

#### 5a. MISP API Key (CRITICAL for connector-misp)

```bash
# 1. Open http://localhost:9001
# 2. Login: admin@admin.test / admin
# 3. Navigate: Administration → My Profile → Auth key
# 4. Copy the API key
# 5. Update .env:
sed -i "s|MISP_API_KEY=RETRIEVE_FROM_MISP_UI.*|MISP_API_KEY=<YOUR_KEY>|" .env

# 6. Start connector-misp
docker compose up -d connector-misp
docker compose logs connector-misp   # should show "connector is ready"
```

#### 5b. Fix ElastAlert Webhook URLs

```bash
# Ensure SLACK_WEBHOOK_URL is set in .env, then:
export $(grep SLACK_WEBHOOK_URL .env)
export $(grep EMAIL_TO .env)
./scripts/fix-elastalert-rules.sh
docker compose restart elastalert

# Test webhook
curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{"text":"✅ SOC Stack ElastAlert test — webhook is working!"}'
```

#### 5c. Verify Wazuh Agents

```bash
# Wait 60s for watchdog to enroll agents, then:
export $(grep WAZUH_API_USER .env)
export $(grep WAZUH_API_PASSWORD .env)
./scripts/monitor-wazuh-agents.sh

# All agents should show "active" status
```

---

### Phase 6 — Verification Checklist

```bash
# Full stack health check
docker compose ps

# Elasticsearch
curl -sf -u elastic:"${ELASTIC_PASSWORD}" \
  http://localhost:9200/_cluster/health?pretty | grep status

# Kibana
curl -sf http://localhost:5601/api/status | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d['status']['overall']['level'])"

# Wazuh API
curl -sf -k -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" \
  https://localhost:55000/ | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print('Wazuh', d.get('data',{}).get('api_version','?'))"

# connector-misp (should be running, not restarting)
docker inspect connector-misp --format '{{.RestartCount}} restarts, status: {{.State.Status}}'
```

**Success criteria — all boxes should be checked:**

- [ ] `docker compose ps` shows all containers `Up` or `Up (healthy)`
- [ ] Elasticsearch cluster is `green` or `yellow`
- [ ] Kibana accessible at `http://localhost:5601`
- [ ] `connector-misp` restart count = 0 (or low and stable)
- [ ] MISP accessible at `http://localhost:9001`
- [ ] OpenCTI accessible at `http://localhost:3000`
- [ ] Wazuh agents all show `active` in `monitor-wazuh-agents.sh`
- [ ] Test Slack alert received
- [ ] Stack survives `docker compose restart` without manual fixes

---

## Rollback

If anything breaks:

```bash
# Restore original docker-compose.yml
cp docker-compose.yml.backup docker-compose.yml

# Restore original .env
cp .env.backup .env 2>/dev/null || true

# Restart from original state
docker compose down
docker compose up -d
```

---

## Issue → Fix Cross-Reference

| Issue from Analysis | Fix Applied | File |
|---------------------|-------------|------|
| connector-misp exit 143 (OOM) | Memory limit 128m→512m | docker-compose-patches.md §5 |
| connector-misp exit 143 (stale key) | `${MISP_API_KEY}` from .env | .env + patches §5 |
| connector-misp exit 143 (race) | `service_healthy` + healthcheck | patches §4, §5 |
| Elasticsearch 401 (password not bootstrapped) | `elasticsearch-init` service | init-es.sh + patches §2 |
| Elasticsearch 401 (Kibana token stale) | Basic auth replaces token | patches §3 |
| Wazuh API error 52 (HTTP→HTTPS) | Uses `https://` + `-k` | monitor-wazuh-agents.sh |
| Wazuh API error 52 (wrong password) | Reads `${WAZUH_API_PASSWORD}` | .env + monitor script |
| Wazuh agents Never Connected (no process mgr) | Watchdog script | wazuh-watchdog.sh |
| Wazuh agents Never Connected (missing conf) | Volume mount fixed | patches §6, agent.conf |
| Wazuh agents Never Connected (stale PID) | Watchdog cleans PIDs | wazuh-watchdog.sh |
| Slack alerts not delivered | Replaces 18 placeholder URLs | fix-elastalert-rules.sh |
| Memory caps not persistent | `deploy.resources` in compose | docker-compose-patches.md |
| Fleet URL reset every boot | `XPACK_FLEET_AGENTS_*` env vars | patches §3 |
| Logstash sincedb stale offsets | `sincedb_path => "/dev/null"` | patches §8 |
| ES unassigned shards (replicas=1) | Template: replicas=0 | init-es.sh |
| OpenCTI container conflict | `--remove-orphans` on startup | Deployment Phase 4 |
| Email alerts unused | Dual `alert: [slack, email]` | fix-elastalert-rules.sh |
| Missing wazuh/config dir | `agent.conf` + dir mount | agent.conf + patches §6 |
