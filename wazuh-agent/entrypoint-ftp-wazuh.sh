#!/bin/bash
# Fix manager address if placeholder still present
sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf 2>/dev/null

# Start Wazuh agent
/var/ossec/bin/wazuh-control start 2>/dev/null

# Run original FTP entrypoint
exec /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
