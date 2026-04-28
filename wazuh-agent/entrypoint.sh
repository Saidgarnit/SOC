#!/bin/bash
set -e

# Fix client.keys permissions (required by agentd)
if [ -f /var/ossec/etc/client.keys ]; then
    chown root:wazuh /var/ossec/etc/client.keys
    chmod 640 /var/ossec/etc/client.keys
fi

# Install supervisord if not present (for Ubuntu-based images)
if ! command -v supervisord &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq supervisor
fi

exec supervisord -c /etc/supervisor/conf.d/wazuh.conf
