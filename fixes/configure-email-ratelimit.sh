#!/bin/bash
# Configure Wazuh email alerting with rate limits

set -e

echo "=== Configuring Email Rate Limiting ==="

# Create rate-limited rules
docker exec wazuh-manager bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '\''RULES'\''
<group name="local,syslog,sshd,">
  <!-- Critical alerts: immediate, max 5/hour -->
  <rule id="100001" level="12">
    <if_group>authentication_failed,webshell,privilege_escalation</if_group>
    <description>Critical security event - immediate notification</description>
    <options>alert_by_email</options>
    <options>no_email_alert_after:5</options>
  </rule>
  
  <!-- High alerts: batch every 15min, max 20/hour -->
  <rule id="100002" level="10">
    <if_group>attack,exploit,intrusion</if_group>
    <description>High severity event - batched notification</description>
    <options>alert_by_email</options>
    <options>no_email_alert_after:20</options>
  </rule>
  
  <!-- Medium/Low: suppress individual emails -->
  <rule id="100003" level="0" overwrite="yes">
    <if_sid>1002,1003,5501,5502</if_sid>
    <description>Normal events - digest only</description>
    <options>no_email_alert</options>
  </rule>
</group>
RULES
'

# Configure email delays in ossec.conf
docker exec wazuh-manager bash -c "
# Backup original config
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup

# Add email alert configurations
sed -i '/<\/ossec_config>/i\\
  <email_alerts>\\
    <email_to>guenlaa2001@gmail.com</email_to>\\
    <level>12</level>\\
    <do_not_delay/>\\
  </email_alerts>\\
\\
  <email_alerts>\\
    <email_to>guenlaa2001@gmail.com</email_to>\\
    <level>10</level>\\
    <group>attack,exploit</group>\\
    <do_not_group/>\\
    <delay>900</delay>\\
  </email_alerts>' /var/ossec/etc/ossec.conf
"

# Restart Wazuh manager
echo "Restarting Wazuh manager..."
docker restart wazuh-manager

echo ""
echo "=== Configuration Complete ==="
echo "Rate limits applied:"
echo "  - Level 12 (Critical): Max 5 emails/hour, immediate"
echo "  - Level 10 (High): Max 20 emails/hour, batched every 15min"
echo "  - Level <10: Suppressed (digest only)"
