FROM tleemcjr/metasploitable2
COPY wazuh/packages/wazuh-agent-4.7.5-i386.deb /tmp/wazuh-agent.deb
COPY lab/victim-metasploitable/fix-syscheck.py /tmp/fix-syscheck.py
RUN dpkg -i --force-all /tmp/wazuh-agent.deb 2>/dev/null; \
    rm -f /tmp/wazuh-agent.deb; \
    sed -i 's|MANAGER_IP|wazuh-manager|g' /var/ossec/etc/ossec.conf || true; \
    python /tmp/fix-syscheck.py && rm /tmp/fix-syscheck.py; \
    sed -i '/<yestify_time>/d' /var/ossec/etc/ossec.conf 2>/dev/null || true
