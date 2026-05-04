# SOC Stack — Permanent Fixes
## Root Cause Analysis & Permanent Solutions

### CRITICAL ISSUE #1: No real ossec-agentd on ANY endpoint
**Root Cause**: Agents were never properly installed. Docker containers have no systemd → manual starts die on restart.

**PERMANENT FIX**:
```bash
# On each victim container (ubuntu, dvwa, jenkins, dns, database, mail, iot, ftp, webapi)
# 1. Install Wazuh agent properly
WAZUH_MANAGER="172.18.0.5" apt-get install wazuh-agent

# 2. Create init script that survives restarts
cat > /docker-entrypoint.d/01-wazuh-agent.sh << 'INIT'
#!/bin/bash
# Start ossec-agentd in background
/var/ossec/bin/wazuh-control start
# Keep checking and restart if dead
while true; do
  sleep 60
  if ! pgrep -f ossec-agentd > /dev/null; then
    /var/ossec/bin/wazuh-control start
  fi
done &
INIT

chmod +x /docker-entrypoint.d/01-wazuh-agent.sh

# 3. Rebuild Docker images with agent baked in
# Update Dockerfile:
RUN WAZUH_MANAGER="172.18.0.5" apt-get install wazuh-agent && \
    echo "DAEMON=yes" >> /etc/default/wazuh-agent
COPY 01-wazuh-agent.sh /docker-entrypoint.d/
CMD ["/docker-entrypoint.d/01-wazuh-agent.sh", "&&", "original-cmd"]
```

---

### CRITICAL ISSUE #2: victim-metasploitable — completely BLIND on host
**Root Cause**: No Filebeat installed. No syslog forwarding. No agent. Only Suricata sees its network traffic.

**PERMANENT FIX**:
```bash
# SSH into metasploitable host
ssh msfadmin@172.18.0.8

# Install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.x-amd64.deb
sudo dpkg -i filebeat-8.x-amd64.deb

# Configure to ship to Elasticsearch
cat > /etc/filebeat/filebeat.yml << 'FILEBEAT'
filebeat.inputs:
- type: filestream
  id: metasploitable-syslog
  paths:
    - /var/log/syslog
    - /var/log/auth.log
  fields:
    agent.name: victim-metasploitable

output.elasticsearch:
  hosts: ["172.18.0.6:9200"]
  index: "filebeat-metasploitable-%{+yyyy.MM.dd}"

setup.template.name: "filebeat-metasploitable"
setup.template.pattern: "filebeat-metasploitable-*"
FILEBEAT

# Enable on boot
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Install Wazuh agent
WAZUH_MANAGER="172.18.0.5" sudo apt-get install wazuh-agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

### CRITICAL ISSUE #3: victim-windows — no EDR, no log forwarding
**Root Cause**: Windows containers need Wazuh Windows agent (MSI installer). Filebeat for Windows is different binary.

**PERMANENT FIX**:
```powershell
# On victim-windows container/VM
# Download Wazuh Windows Agent
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi" -OutFile wazuh-agent.msi

# Install with WAZUH_MANAGER parameter
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="172.18.0.5" WAZUH_REGISTRATION_SERVER="172.18.0.5"

# Start service (persists on reboot)
Start-Service -Name wazuh

# Install Winlogbeat (not Filebeat)
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.x-windows-x86_64.zip" -OutFile winlogbeat.zip
Expand-Archive winlogbeat.zip -DestinationPath "C:\Program Files\Winlogbeat"

# Configure winlogbeat.yml
@"
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application

output.elasticsearch:
  hosts: ["172.18.0.6:9200"]
  index: "winlogbeat-windows-%{+yyyy.MM.dd}"

setup.template.name: "winlogbeat-windows"
setup.template.pattern: "winlogbeat-windows-*"
"@ | Out-File "C:\Program Files\Winlogbeat\winlogbeat.yml"

# Install as Windows service
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1

# Start service
Start-Service -Name winlogbeat
```

---

### HIGH ISSUE #4: 8 endpoints — Filebeat running but no ossec-agentd
**Root Cause**: Syslog forwarding to Wazuh works BUT ossec-agentd provides deeper visibility (FIM per-host, rootcheck, SCA, active response).

**PERMANENT FIX**:
```bash
# Create unified agent deployment script
cat > /opt/deploy-agents.sh << 'DEPLOY'
#!/bin/bash
ENDPOINTS="dvwa jenkins dns database mail iot ftp webapi"
WAZUH_MANAGER="172.18.0.5"

for host in $ENDPOINTS; do
  echo "Deploying agent to $host..."
  
  docker exec victim-$host bash -c "
    # Install agent
    WAZUH_MANAGER='$WAZUH_MANAGER' apt-get update && apt-get install -y wazuh-agent
    
    # Create watchdog
    cat > /usr/local/bin/wazuh-watchdog.sh << 'WATCHDOG'
#!/bin/bash
while true; do
  if ! pgrep -f ossec-agentd > /dev/null; then
    /var/ossec/bin/wazuh-control start
  fi
  sleep 60
done
WATCHDOG
    
    chmod +x /usr/local/bin/wazuh-watchdog.sh
    
    # Start agent
    /var/ossec/bin/wazuh-control start
    
    # Start watchdog in background
    nohup /usr/local/bin/wazuh-watchdog.sh &
  "
done
DEPLOY

chmod +x /opt/deploy-agents.sh
/opt/deploy-agents.sh

# Add to cron for automatic recovery
(crontab -l 2>/dev/null; echo "@reboot /opt/deploy-agents.sh") | crontab -
```

---

### MEDIUM ISSUE #5: Fleet enrollment blocked — no auto-enrollment
**Root Cause**: Fleet environment blocks hostnames `63a3...078`. Elastic Agent would unify Filebeat + Wazuh integration under single agent.

**PERMANENT FIX**:
```bash
# On Elasticsearch host
# 1. Configure Fleet to accept containers
curl -X PUT "http://172.18.0.6:9200/.fleet-policies-*/_settings" -H 'Content-Type: application/json' -d'
{
  "index": {
    "routing.allocation.include.hostname": "*"
  }
}
'

# 2. Create enrollment token
FLEET_TOKEN=$(curl -X POST "http://172.18.0.6:5601/api/fleet/enrollment-api-keys" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{"policy_id": "default-policy"}' | jq -r .item.api_key)

# 3. Deploy Elastic Agent to all endpoints
for host in ubuntu dvwa jenkins dns database mail iot ftp webapi; do
  docker exec victim-$host bash -c "
    curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.x-linux-x86_64.tar.gz
    tar xzf elastic-agent-8.x-linux-x86_64.tar.gz
    cd elastic-agent-8.x-linux-x86_64
    ./elastic-agent install --url=http://172.18.0.6:8220 --enrollment-token=$FLEET_TOKEN
  "
done
```

---

### MEDIUM ISSUE #6: Gmail daily limit — resets at midnight UTC
**Root Cause**: Catch-up storm blew daily quota. Critical rule emails (brute_force, lateral_movement, privesc, yara, webshell) will resume at 00:00 UTC. Slack unaffected.

**PERMANENT FIX**:
```bash
# Implement rate limiting + queuing
cat > /var/ossec/etc/rules/local_rules.xml << 'RULES'
<group name="gmail_ratelimit">
  <!-- High priority: immediate send -->
  <rule id="100001" level="12">
    <if_group>authentication_failed|webshell|privilege_escalation</if_group>
    <options>alert_by_email</options>
    <options>no_email_alert_after:5</options> <!-- Max 5/hour -->
  </rule>
  
  <!-- Medium priority: batch every 15min -->
  <rule id="100002" level="7">
    <if_group>attack|exploit</if_group>
    <options>alert_by_email</options>
    <options>no_email_alert_after:20</options> <!-- Max 20/hour -->
  </rule>
  
  <!-- Low priority: digest at midnight -->
  <rule id="100003" level="3">
    <match>.*</match>
    <options>no_email_alert</options> <!-- Suppress individual emails -->
  </rule>
</group>
RULES

# Configure digest in ossec.conf
cat >> /var/ossec/etc/ossec.conf << 'DIGEST'
<email_alerts>
  <email_to>guenlaa2001@gmail.com</email_to>
  <level>12</level>
  <do_not_delay/>
</email_alerts>

<email_alerts>
  <email_to>guenlaa2001@gmail.com</email_to>
  <level>7</level>
  <group>attack,exploit</group>
  <do_not_group/>
  <delay>900</delay> <!-- 15min batching -->
</email_alerts>

<!-- Daily digest for low-priority -->
<reports>
  <category>syscheck,web,ids</category>
  <title>SOC Daily Digest</title>
  <email_to>guenlaa2001@gmail.com</email_to>
  <showlogs>yes</showlogs>
</reports>
DIGEST

# Restart Wazuh manager
docker restart wazuh-manager
```

---

### LOW ISSUE #7: No index lifecycle policy — storage will bloat
**Root Cause**: New daily indices created automatically. No auto-delete after 30 days. Will accumulate indefinitely on single-node lab disk.

**PERMANENT FIX**:
```bash
# Create ILM policy
curl -X PUT "http://172.18.0.6:9200/_ilm/policy/soc-retention-30d" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_age": "1d",
            "max_primary_shard_size": "50gb"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
'

# Apply to all filebeat/wazuh indices
curl -X PUT "http://172.18.0.6:9200/_index_template/soc-retention" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["filebeat-*", "wazuh-alerts-*"],
  "template": {
    "settings": {
      "index.lifecycle.name": "soc-retention-30d",
      "index.lifecycle.rollover_alias": "soc-logs"
    }
  }
}
'
```

---

### LOW ISSUE #8: Dashboard time range still Last 30 days
**Root Cause**: Should be Last 24h + 30s auto-refresh for a live SOC dashboard.

**PERMANENT FIX**:
```bash
# Update Kibana saved object
curl -X POST "http://172.18.0.6:5601/api/saved_objects/dashboard/soc-overview" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{
    "attributes": {
      "timeRestore": true,
      "timeFrom": "now-24h",
      "timeTo": "now",
      "refreshInterval": {
        "pause": false,
        "value": 30000
      }
    }
  }'
```

---

## AUTOMATED DEPLOYMENT SCRIPT
```bash
#!/bin/bash
# run-permanent-fixes.sh — Execute all fixes in order

set -e

echo "=== SOC Stack Permanent Fixes ==="
echo "Starting at $(date)"

# Fix 1: Deploy agents to all Linux containers
echo "[1/8] Deploying Wazuh agents to containers..."
/opt/deploy-agents.sh

# Fix 2: Install on metasploitable
echo "[2/8] Installing agent + Filebeat on metasploitable..."
ssh msfadmin@172.18.0.8 'bash -s' < /opt/fix-metasploitable.sh

# Fix 3: Install on Windows
echo "[3/8] Installing agent + Winlogbeat on Windows..."
# Manual step — Windows VM requires RDP/PowerShell remoting

# Fix 4: Already covered in Fix 1

# Fix 5: Deploy Elastic Agents
echo "[5/8] Enrolling Fleet agents..."
/opt/deploy-fleet-agents.sh

# Fix 6: Configure Gmail rate limiting
echo "[6/8] Configuring email rate limits..."
docker exec wazuh-manager bash -c "
  cp /opt/local_rules.xml /var/ossec/etc/rules/
  /var/ossec/bin/wazuh-control restart
"

# Fix 7: Apply ILM policy
echo "[7/8] Configuring index lifecycle..."
curl -X PUT "http://172.18.0.6:9200/_ilm/policy/soc-retention-30d" -H 'Content-Type: application/json' -d @ilm-policy.json

# Fix 8: Update dashboard
echo "[8/8] Updating dashboard time range..."
curl -X POST "http://172.18.0.6:5601/api/saved_objects/dashboard/soc-overview" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' -d @dashboard-config.json

echo "=== Fixes Complete ==="
echo "Finished at $(date)"
echo ""
echo "NEXT STEPS:"
echo "1. Manually install Windows agent (see Fix #3)"
echo "2. Wait 5 minutes for agents to register"
echo "3. Verify: http://172.18.0.6:5601/app/wazuh#/agents-preview"
echo "4. Check Gmail at 00:00 UTC for resumed alerts"
```

---

## VERIFICATION CHECKLIST
After deployment, verify each fix:

- [ ] **Fix 1**: `docker exec victim-ubuntu pgrep ossec-agentd` → returns PID
- [ ] **Fix 2**: `ssh msfadmin@172.18.0.8 'systemctl status wazuh-agent'` → active (running)
- [ ] **Fix 3**: RDP to Windows → Services → Wazuh → Running
- [ ] **Fix 4**: All 11 agents show "Active" in Wazuh dashboard
- [ ] **Fix 5**: Fleet shows 11 enrolled agents
- [ ] **Fix 6**: Check `/var/ossec/logs/alerts/alerts.json` for batched alerts
- [ ] **Fix 7**: `curl http://172.18.0.6:9200/_cat/indices?v` → indices rotate daily
- [ ] **Fix 8**: Kibana dashboard auto-refreshes every 30s

---

## DOCKER REBUILD STRATEGY (Most Permanent)
For production, rebuild images with agents baked in:

```dockerfile
# Example: victim-ubuntu Dockerfile
FROM ubuntu:20.04

# Install Wazuh agent during build
ENV WAZUH_MANAGER=172.18.0.5
RUN apt-get update && \
    apt-get install -y curl gnupg && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent

# Watchdog script
COPY wazuh-watchdog.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/wazuh-watchdog.sh

# Start agent on container start
CMD ["/usr/local/bin/wazuh-watchdog.sh"]
```

Rebuild all victim containers:
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

This ensures agents survive container recreation.
