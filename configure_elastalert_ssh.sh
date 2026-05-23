#!/bin/bash

SLACK_WEBHOOK="${1:-}"

if [ -z "$SLACK_WEBHOOK" ]; then
    echo "Usage: $0 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'"
    echo ""
    echo "To get your Slack webhook:"
    echo "1. Go to https://api.slack.com/apps"
    echo "2. Click 'Create New App' → 'From scratch'"
    echo "3. Name: 'SOC Lab SSH Alerts'"
    echo "4. Go to 'Incoming Webhooks' → Enable it"
    echo "5. 'Add New Webhook to Workspace'"
    echo "6. Select #soc-alerts channel"
    echo "7. Copy the webhook URL"
    echo ""
    exit 1
fi

# Create SSH Brute-Force rule for ElastAlert
docker exec elastalert bash -c "
  cat > /etc/elastalert/rules/ssh_bruteforce.yaml << 'RULE_EOF'
# SSH Brute-Force Detection Rule
name: SSH Brute-Force Attack Detected
type: frequency
index: wazuh-alerts-*
num_events: 5
timeframe:
  minutes: 5

filter:
- term:
    rule.id: '5760'

alert:
- slack

slack_webhook_url: $SLACK_WEBHOOK
slack_username_override: 'Wazuh SOC Lab 🚨'
slack_emoji_override: ':warning:'

slack_alert_fields:
  - alert.data.srcip
  - alert.data.user
  - rule.description
  - rule.level

slack_title: 'SSH Brute-Force Attack Detected'
slack_title_link: 'http://wazuh-manager:5601'

# Avoid duplicate alerts
aggregation:
  minutes: 10

realert:
  minutes: 60

RULE_EOF

  echo '[✓] SSH Brute-Force rule created'
  ls -lh /etc/elastalert/rules/ssh_bruteforce.yaml
"

# Restart ElastAlert to load the new rule
echo "[*] Restarting ElastAlert..."
docker restart elastalert

sleep 5

# Verify rule is loaded
docker exec elastalert bash -c "
  echo '[*] Checking if rule is loaded...'
  tail -20 /var/log/elastalert/elastalert.log | grep -iE 'loaded|ssh|rule'
"

echo ""
echo "✅ ElastAlert SSH rule configured!"
echo ""
echo "Next: Run attack to trigger Slack alerts"
