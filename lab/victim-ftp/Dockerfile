FROM fauria/vsftpd
USER root

# Fix dead CentOS 7 repos
RUN sed -i 's/mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    yum install -y tar hostname && yum clean all

# Install Wazuh agent (version 4.7.5 to match manager)
RUN rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && \
    echo -e "[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1" > /etc/yum.repos.d/wazuh.repo && \
    yum install -y wazuh-agent-4.7.5-1 && \
    yum clean all

# Copy pre-downloaded elastic-agent
COPY elastic-agent-bin/ /opt/elastic-agent/

# Fix permissions + create missing elastic-agent.yml from reference
RUN chmod +x /opt/elastic-agent/elastic-agent && \
    ln -sf /opt/elastic-agent/elastic-agent /usr/local/bin/elastic-agent && \
    ln -sf /opt/elastic-agent /usr/share/elastic-agent && \
    cp /opt/elastic-agent/elastic-agent.reference.yml /opt/elastic-agent/elastic-agent.yml && \
    chmod 644 /opt/elastic-agent/elastic-agent.yml

# Copy entrypoint and wazuh watchdog
COPY entrypoint-ftp.sh /entrypoint-ftp.sh
RUN chmod +x /entrypoint-ftp.sh

# Create wazuh watchdog script
RUN echo '#!/bin/bash' > /tmp/wazuh-watchdog.sh && \
    echo 'while true; do' >> /tmp/wazuh-watchdog.sh && \
    echo '  sleep 60' >> /tmp/wazuh-watchdog.sh && \
    echo '  if [ -f /var/ossec/bin/wazuh-control ]; then' >> /tmp/wazuh-watchdog.sh && \
    echo '    /var/ossec/bin/wazuh-control status >/dev/null 2>&1 || /var/ossec/bin/wazuh-control start >/dev/null 2>&1' >> /tmp/wazuh-watchdog.sh && \
    echo '  fi' >> /tmp/wazuh-watchdog.sh && \
    echo 'done' >> /tmp/wazuh-watchdog.sh && \
    chmod +x /tmp/wazuh-watchdog.sh

EXPOSE 21 20
CMD ["/entrypoint-ftp.sh"]
