#!/bin/bash

SLACK_WEBHOOK="${1:-}"

if [ -z "$SLACK_WEBHOOK" ]; then
    echo "Usage: $0 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'"
    echo ""
    echo "Getting your Slack webhook:"
    echo "1. Go to: https://api.slack.com/apps"
    echo "2. Create App → 'From scratch' → Name: 'SOC Lab Alerts'"
    echo "3. Go to: 'Incoming Webhooks' → Enable it"
    echo "4. Click: 'Add New Webhook to Workspace'"
    echo "5. Select: #soc-alerts channel"
    echo "6. Copy the Webhook URL"
    echo ""
    exit 1
fi

# Add Slack webhook integration to Wazuh
echo "[*] Configuring Wazuh Slack integration..."

docker exec wazuh-manager bash -c "
  # Add Slack integration to ossec.conf
  cat >> /var/ossec/etc/ossec.conf << 'INTEG_END'

  <!-- Slack Integration for SSH Brute-Force Alerts -->
  <integration>
    <name>slack</name>
    <hook_url>$SLACK_WEBHOOK</hook_url>
    <alert_format>json</alert_format>
    <rule_id>5760</rule_id>
  </integration>

INTEG_END

  echo '[✓] Slack integration added to config'
  
  # Validate configuration
  /var/ossec/bin/wazuh-control restart
  sleep 5
  
  echo '[✓] Wazuh restarted'
  
  # Check if integration loaded
  tail -20 /var/ossec/logs/ossec.log | grep -i slack || echo 'Checking integration...'
"

echo ""
echo "[✓] Wazuh Slack integration configured!"
echo ""
echo "Now test it:"
echo "  ./test_ssh_alerts.sh"

