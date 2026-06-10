#!/bin/bash

# Wait for Elasticsearch to have data
echo "[*] Waiting for Wazuh data in Elasticsearch..."
sleep 10

# Create SSH Brute Force rule in ElastAlert
docker exec elastalert bash -c "
  mkdir -p /etc/elastalert/rules
  
  cat > /etc/elastalert/rules/ssh_brute_force.yaml << 'RULE_END'
name: SSH Brute Force Attack - Wazuh
type: frequency
index: wazuh-alerts-*

# Trigger on 5 failed SSH attempts in 5 minutes
num_events: 5
timeframe:
  minutes: 5

# Group by source IP
query_key: data.srcip

# Match Wazuh rule 5760 (SSH authentication failed)
filter:
  - term:
      rule.id: '5760'

alert:
  - slack

slack_webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
slack_username_override: Wazuh SOC Lab
slack_emoji_override: ':warning:'

alert_text: |
  🚨 SSH BRUTE-FORCE ATTACK DETECTED
  
  Source IP: {0}
  Target Host: {1}
  Failed Attempts: {2}
  Time Window: 5 minutes
  Rule ID: 5760
  
  MITRE ATT&CK: T1110.001 - Credential Access / Brute Force

alert_text_args:
  - data.srcip
  - agent.name
  - num_matches

realert:
  minutes: 30

RULE_END

  echo '[✓] SSH Brute Force rule created'
  ls -lh /etc/elastalert/rules/ssh_brute_force.yaml
"

# Restart ElastAlert to load the rule
echo "[*] Restarting ElastAlert..."
docker restart elastalert
sleep 5

echo "[✓] ElastAlert SSH rule loaded"

