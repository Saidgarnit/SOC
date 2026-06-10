#!/bin/bash

SLACK_WEBHOOK="${1:-}"

if [ -z "$SLACK_WEBHOOK" ]; then
    echo "❌ Error: Slack webhook URL required"
    echo ""
    echo "Usage: $0 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'"
    echo ""
    echo "Steps to get your webhook:"
    echo "1. Go to https://api.slack.com/apps"
    echo "2. Click 'Create New App' → 'From scratch'"
    echo "3. App name: 'SOC Lab SSH Alerts'"
    echo "4. Go to 'Incoming Webhooks' → Toggle ON"
    echo "5. Click 'Add New Webhook to Workspace'"
    echo "6. Select #soc-alerts channel (or create one)"
    echo "7. Copy the Webhook URL"
    echo "8. Run: $0 'YOUR_WEBHOOK_URL'"
    echo ""
    exit 1
fi

echo "[*] Setting up Wazuh Slack integration..."

# Create Wazuh integration config file (proper way)
docker exec wazuh-manager bash -c "
  # First, backup current config
  cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup.$(date +%s)
  
  # Create a new integration directory if needed
  mkdir -p /var/ossec/integration/

  # Create Slack integration script
  cat > /var/ossec/integration/slack-integration.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import json
import sys
import urllib.request
import urllib.error

def main():
    alert_data = json.loads(sys.stdin.read())
    webhook_url = \"$SLACK_WEBHOOK\"
    
    # Extract alert info
    rule_id = alert_data.get('rule', {}).get('id', 'unknown')
    description = alert_data.get('rule', {}).get('description', 'Alert')
    severity = alert_data.get('rule', {}).get('level', 'N/A')
    srcip = alert_data.get('data', {}).get('srcip', 'unknown')
    
    # Only send SSH brute-force alerts
    if rule_id != '5760':
        return
    
    # Build Slack message
    message = {
        'text': '🚨 SSH Brute-Force Attack Detected',
        'blocks': [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*SSH Brute-Force Attack Alert*\n\n*Rule:* {description}\n*Severity:* {severity}\n*Source IP:* {srcip}'
                }
            }
        ]
    }
    
    # Send to Slack
    try:
        req = urllib.request.Request(webhook_url)
        req.add_header('Content-Type', 'application/json')
        data = json.dumps(message).encode('utf-8')
        urllib.request.urlopen(req, data)
        print(f'[Slack] Alert {rule_id} sent successfully', file=sys.stderr)
    except Exception as e:
        print(f'[Slack] Error: {str(e)}', file=sys.stderr)

if __name__ == '__main__':
    main()
PYTHON_EOF

  chmod +x /var/ossec/integration/slack-integration.py
"

# Now add the integration to ossec.conf properly
docker exec wazuh-manager bash -c "
  # Remove any broken integration sections first
  sed -i '/<integration>/,/<\/integration>/d' /var/ossec/etc/ossec.conf
  
  # Add proper integration section before </ossec_config>
  sed -i '/<\/ossec_config>/i\
\
  <!-- Slack Integration for SSH Alerts -->\
  <integration>\
    <name>slack</name>\
    <hook_url>$SLACK_WEBHOOK</hook_url>\
    <alert_format>json</alert_format>\
    <rule_id>5760</rule_id>\
  </integration>' /var/ossec/etc/ossec.conf

  # Validate config
  /var/ossec/bin/wazuh-control validate-config
  
  # Restart Wazuh
  echo '[*] Restarting Wazuh manager...'
  /var/ossec/bin/wazuh-control restart
  sleep 5
  
  echo '[✓] Wazuh restarted with Slack integration'
"

echo ""
echo "=========================================="
echo "✅ Slack integration configured!"
echo "=========================================="
echo ""
echo "Test it by running:"
echo "  ./test_ssh_alerts.sh"
echo ""

