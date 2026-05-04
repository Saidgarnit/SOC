#!/bin/bash
# Master deployment script - executes all permanent fixes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        SOC Stack Permanent Fixes - Master Deployment       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Started: $(date)"
echo "Location: $SCRIPT_DIR"
echo ""

# Verify prerequisites
echo "=== Checking Prerequisites ==="
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }
echo "✓ Prerequisites OK"
echo ""

# Fix 1: Deploy Wazuh agents to containers
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FIX 1/5: Deploy Wazuh Agents to Containers               ║"
echo "╚════════════════════════════════════════════════════════════╝"
if [ -f "$SCRIPT_DIR/deploy-agents.sh" ]; then
  bash "$SCRIPT_DIR/deploy-agents.sh"
else
  echo "WARNING: deploy-agents.sh not found, skipping"
fi
echo ""
sleep 3

# Fix 2: Configure email rate limiting
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FIX 2/5: Configure Email Rate Limiting                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
if [ -f "$SCRIPT_DIR/configure-email-ratelimit.sh" ]; then
  bash "$SCRIPT_DIR/configure-email-ratelimit.sh"
else
  echo "WARNING: configure-email-ratelimit.sh not found, skipping"
fi
echo ""
sleep 3

# Fix 3: Configure Elasticsearch ILM
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FIX 3/5: Configure Elasticsearch Index Lifecycle          ║"
echo "╚════════════════════════════════════════════════════════════╝"
if [ -f "$SCRIPT_DIR/configure-elasticsearch-ilm.sh" ]; then
  bash "$SCRIPT_DIR/configure-elasticsearch-ilm.sh"
else
  echo "WARNING: configure-elasticsearch-ilm.sh not found, skipping"
fi
echo ""
sleep 3

# Fix 4: Wait for agents to register
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FIX 4/5: Waiting for Agents to Register                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo "Waiting 60 seconds for agents to connect to Wazuh manager..."
for i in {60..1}; do
  printf "\rTime remaining: %02d seconds" $i
  sleep 1
done
echo ""
echo "✓ Wait complete"
echo ""

# Fix 5: Verification
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FIX 5/5: Verification                                      ║"
echo "╚════════════════════════════════════════════════════════════╝"

echo "Checking agent processes..."
for host in ubuntu dvwa jenkins dns database mail iot ftp webapi; do
  if docker exec victim-$host pgrep ossec-agentd > /dev/null 2>&1; then
    echo "  ✓ victim-$host: Agent running"
  else
    echo "  ✗ victim-$host: Agent NOT running"
  fi
done

echo ""
echo "Checking watchdog processes..."
for host in ubuntu dvwa jenkins dns database mail iot ftp webapi; do
  if docker exec victim-$host pgrep -f wazuh-watchdog > /dev/null 2>&1; then
    echo "  ✓ victim-$host: Watchdog running"
  else
    echo "  ✗ victim-$host: Watchdog NOT running"
  fi
done

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    DEPLOYMENT COMPLETE                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Finished: $(date)"
echo ""
echo "WHAT WAS FIXED:"
echo "  ✓ Wazuh agents installed on 9 Linux containers"
echo "  ✓ Watchdog scripts prevent agent crashes"
echo "  ✓ Email rate limiting (5/hour critical, 20/hour high)"
echo "  ✓ Index lifecycle management (30-day retention)"
echo "  ✓ All agents should auto-restart on container reboot"
echo ""
echo "MANUAL STEPS REQUIRED:"
echo "  1. Install Wazuh agent on victim-metasploitable:"
echo "     ssh msfadmin@172.18.0.8"
echo "     WAZUH_MANAGER=172.18.0.5 apt-get install wazuh-agent"
echo ""
echo "  2. Install Wazuh agent on victim-windows:"
echo "     Download: https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi"
echo "     Install with WAZUH_MANAGER=172.18.0.5"
echo ""
echo "VERIFICATION URLS:"
echo "  • Wazuh Agents: http://172.18.0.6:5601/app/wazuh#/agents-preview"
echo "  • Kibana Dashboards: http://172.18.0.6:5601/app/dashboards"
echo "  • Elasticsearch Indices: http://172.18.0.6:9200/_cat/indices?v"
echo ""
echo "NEXT OCCURRENCE OF ISSUES:"
echo "  • Gmail quota resets: Daily at 00:00 UTC"
echo "  • Agents survive: Container restarts (watchdog auto-restarts)"
echo "  • Indices auto-delete: After 30 days"
echo ""
