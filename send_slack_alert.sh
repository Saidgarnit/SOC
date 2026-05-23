#!/bin/bash
# Manual Slack alert sender for testing

WEBHOOK_URL="${1:-https://hooks.slack.com/services/YOUR/WEBHOOK/URL}"

if [ "$WEBHOOK_URL" = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" ]; then
    echo "❌ Please provide Slack webhook URL as argument:"
    echo "   ./send_slack_alert.sh 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'"
    exit 1
fi

# Get attack stats
SSH_FAILURES=$(docker exec victim-ubuntu grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)
WAZUH_ALERTS=$(docker exec wazuh-manager grep -c '"id":"5760"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0)

# Create alert payload
PAYLOAD=$(cat <<PAYLOAD_EOF
{
    "text": "🚨 SSH Brute-Force Attack Detected",
    "blocks": [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*SSH Brute-Force Attack Alert*\n\n*Status:* 🔴 ACTIVE\n*Attack Source:* kali-attacker (172.18.0.16)\n*Target:* victim-ubuntu (172.18.0.20:22)\n*Target User:* root"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Failed Attempts:*\n$SSH_FAILURES"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Wazuh Alerts:*\n$WAZUH_ALERTS"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Rule ID:*\n5760"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Severity:*\nMedium"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Detection Pipeline:*\n1️⃣ SSH auth attempt → /var/log/auth.log\n2️⃣ Rsyslog collection → Auth facility\n3️⃣ Wazuh monitoring → Rule 5760 trigger\n4️⃣ Alert generation → Slack notification"
            }
        }
    ]
}
PAYLOAD_EOF
)

echo "[*] Sending alert to Slack..."
curl -X POST "$WEBHOOK_URL" \
    -H 'Content-type: application/json' \
    --data "$PAYLOAD" \
    -s -o /dev/null -w "HTTP Status: %{http_code}\n"

if [ $? -eq 0 ]; then
    echo "✅ Alert sent successfully!"
else
    echo "❌ Failed to send alert"
fi
