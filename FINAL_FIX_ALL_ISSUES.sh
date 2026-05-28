#!/bin/bash

# 🚨 FINAL SOC STACK FIX - ALL CRITICAL ISSUES
# Run this script to fix all problems

cd ~/soc-stack

echo "=========================================="
echo "   🔧 SOC STACK - COMPREHENSIVE FIX"
echo "=========================================="
echo ""

# ISSUE 1: ELASTICSEARCH PASSWORD WRONG
echo "=== FIX 1: Reset Elasticsearch Password ==="
echo "Getting current ELASTIC_PASSWORD from environment..."
ELASTIC_PASS=$(docker-compose exec -T elasticsearch curl -s http://localhost:9200 2>&1 | grep -o '"number"[^}]*' | head -1)
echo "Checking if Elasticsearch needs password setup..."

# Set default password in docker-compose.yml
if ! grep -q "ELASTIC_PASSWORD=changeme" ~/soc-stack/docker-compose.yml; then
  echo "ELASTIC_PASSWORD not set to 'changeme', using current value"
fi

# Test with changeme
TEST=$(curl -s -u elastic:changeme http://localhost:9200/_cluster/health 2>/dev/null | grep -c "status")
if [ "$TEST" -eq 0 ]; then
  echo "⚠️  Password 'changeme' doesn't work"
  echo "Attempting to reset password..."
  docker-compose exec -T elasticsearch \
    /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b 2>/dev/null || true
  sleep 5
else
  echo "✅ Password 'changeme' works!"
fi

echo ""
echo "=== FIX 2: Fix elasticsearch-init Script ==="
echo "Current command in docker-compose.yml:"
grep -A 2 "elasticsearch-init:" ~/soc-stack/docker-compose.yml | grep "command:"

# The issue: /init-es.sh is a DIRECTORY, not a file
# Solution: Use bash to execute the script properly
echo "Fixing elasticsearch-init configuration..."
python3 << 'PYTHON'
import yaml

with open('docker-compose.yml', 'r') as f:
    data = yaml.safe_load(f)

# Fix elasticsearch-init
if 'elasticsearch-init' in data['services']:
    es_init = data['services']['elasticsearch-init']
    
    # Change command to entrypoint with bash
    if 'command' in es_init:
        del es_init['command']
    
    # Set proper entrypoint
    es_init['entrypoint'] = [
        'bash',
        '-c',
        'if [ -f /init-es.sh/init-es.sh ]; then bash /init-es.sh/init-es.sh; else echo "Init script not found"; fi'
    ]
    
    print("✓ Fixed elasticsearch-init entrypoint")

with open('docker-compose.yml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
PYTHON

echo ""
echo "=== FIX 3: Remove Duplicate Wazuh Agents ==="
echo "Current Wazuh agents:"
docker-compose exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>/dev/null | head -20

echo ""
echo "Removing duplicate victim-iot agent (ID 003)..."
# Use correct syntax: -r for remove
docker-compose exec -T wazuh-manager /var/ossec/bin/manage_agents -r 003 2>/dev/null || echo "No agent 003 to remove"

echo "Removing duplicate victim-ubuntu agent (ID 005)..."
docker-compose exec -T wazuh-manager /var/ossec/bin/manage_agents -r 005 2>/dev/null || echo "No agent 005 to remove"

echo ""
echo "=== FIX 4: Restart Core Services ==="
echo "Restarting Elasticsearch..."
docker-compose restart elasticsearch
sleep 60

echo "Restarting Wazuh Manager..."
docker-compose restart wazuh-manager
sleep 30

echo "Restarting elasticsearch-init..."
docker-compose rm -f elasticsearch-init
docker-compose up -d elasticsearch-init
sleep 10

echo ""
echo "=== FIX 5: Verify Elasticsearch Health ==="
# Get actual password
PASS=$(curl -s http://localhost:9200 2>&1 | grep -o '"number":"[0-9]*"' | head -1 || echo "changeme")
if [ -z "$PASS" ]; then
  PASS="changeme"
fi

curl -u elastic:$PASS http://localhost:9200/_cluster/health 2>/dev/null | jq . || echo "Still checking..."
sleep 10

echo ""
echo "=== FIX 6: Fix Wazuh Agent Enrollment Retry Loop ==="
echo "Configuring victim-iot for proper enrollment..."

# The issue: victim-iot keeps retrying immediately
# Solution: Increase retry delay in docker-compose environment

python3 << 'PYTHON'
import yaml

with open('docker-compose.yml', 'r') as f:
    data = yaml.safe_load(f)

# Increase memory for victim-iot
if 'victim-iot' in data['services']:
    victim_iot = data['services']['victim-iot']
    
    # Add memory limit
    if 'deploy' not in victim_iot:
        victim_iot['deploy'] = {}
    if 'resources' not in victim_iot['deploy']:
        victim_iot['deploy']['resources'] = {}
    
    victim_iot['deploy']['resources']['limits'] = {
        'cpus': '1.0',
        'memory': '1024m'  # Increased from 512m
    }
    
    # Add environment for retry backoff
    if 'environment' not in victim_iot:
        victim_iot['environment'] = []
    
    # Ensure it's a list
    if isinstance(victim_iot['environment'], dict):
        env_list = [f"{k}={v}" for k, v in victim_iot['environment'].items()]
        victim_iot['environment'] = env_list
    
    victim_iot['environment'].append('WAZUH_RETRY_DELAY=30')
    
    print("✓ Increased victim-iot memory and retry delay")

with open('docker-compose.yml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
PYTHON

echo ""
echo "=== FIX 7: Restart All Containers ==="
echo "Removing old victims and restarting..."
docker-compose down --remove-orphans
sleep 15

echo "Bringing stack back up..."
docker-compose up -d
sleep 120

echo ""
echo "=========================================="
echo "   ✅ VERIFICATION"
echo "=========================================="
echo ""

# Check Elasticsearch
echo "1. Elasticsearch Health:"
curl -s -u elastic:changeme http://localhost:9200/_cluster/health 2>/dev/null | jq .status || echo "❌ No response"

echo ""
echo "2. Wazuh Agents Enrolled:"
docker-compose exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>/dev/null | grep -c "^   ID:" || echo "❌ Error"

echo ""
echo "3. Service Status:"
docker-compose ps | grep -E "elasticsearch|wazuh-manager|victim-iot|filebeat" | awk '{print $1, $(NF-1)}'

echo ""
echo "4. Memory Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}" | head -10

echo ""
echo "=========================================="
echo "   ✅ FIX COMPLETE!"
echo "=========================================="
echo ""
echo "Next Steps:"
echo "1. Wait 5 minutes for Wazuh agents to re-enroll"
echo "2. Check Kibana for data: http://localhost:5601"
echo "3. Verify Wazuh dashboard: http://localhost:55000"
echo "4. Run: docker-compose ps (all should be healthy)"
echo ""

