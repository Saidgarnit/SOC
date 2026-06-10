#!/bin/bash
# This script runs inside the wazuh container as cont-init.d/00-fix-conf
# It runs BEFORE 0-wazuh-init and ensures ossec.conf is a file not directory

CONF="/var/ossec/etc/ossec.conf"

# If it's a directory, remove it and write the proper config
if [ -d "$CONF" ]; then
    rm -rf "$CONF"
fi

# Always write the config (idempotent)
if [ ! -f "$CONF" ] || [ ! -s "$CONF" ]; then
    cat > "$CONF" << 'OSSECEOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <node_type>master</node_type>
    <key>c98b62a9b0469c9408abf9e48f55e5b2</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes><node>master-node</node></nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <indexer>
    <enabled>yes</enabled>
    <hosts><host>http://elasticsearch:9200</host></hosts>
    <username>elastic</username>
    <password>SOCstack2026!</password>
    <ssl><enabled>no</enabled></ssl>
  </indexer>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <integration>
    <name>slack</name>
    <hook_url>https://hooks.slack.com/services/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</hook_url>
    <alert_format>json</alert_format>
    <level>7</level>
  </integration>
</ossec_config>
OSSECEOF
    echo "[fix-conf] ossec.conf written ($(wc -c < $CONF) bytes)"
else
    # Ensure remote block exists
    grep -q '<remote>' "$CONF" || sed -i 's|</ossec_config>|  <remote><connection>secure</connection><port>1514</port><protocol>tcp</protocol></remote>\n</ossec_config>|' "$CONF"
    echo "[fix-conf] ossec.conf OK ($(wc -c < $CONF) bytes)"
fi

# Also fix the filebeat.yml path issue — create a stub if missing
if [ ! -f /etc/filebeat/filebeat.yml ]; then
    mkdir -p /etc/filebeat
    cp /etc/filebeat/filebeat.yml.disabled 2>/dev/null || \
    find /var/ossec -name "filebeat.yml" 2>/dev/null | head -1 | xargs -I{} cp {} /etc/filebeat/filebeat.yml 2>/dev/null || \
    echo "# Stub" > /etc/filebeat/filebeat.yml
fi
