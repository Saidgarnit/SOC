FROM ubuntu:20.04
RUN apt-get update && apt-get install -y tini && rm -rf /var/lib/apt/lists/*
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/elastic-agent:${PATH}"

RUN apt-get update && apt-get install -y \
    openssh-server \
    vsftpd \
    apache2 \
    curl \
    wget \
    sudo \
    lsb-release \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash victim && echo "victim:password123" | chpasswd
RUN echo "root:toor" | chpasswd
RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
RUN sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf || true

RUN curl -so wazuh-agent.deb \
    https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb \
    && WAZUH_MANAGER=wazuh-manager \
       WAZUH_AGENT_NAME=victim-ubuntu \
       dpkg -i ./wazuh-agent.deb \
    && rm wazuh-agent.deb

RUN curl -so elastic-agent.tar.gz \
    https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.0-linux-x86_64.tar.gz \
    && tar xzf elastic-agent.tar.gz \
    && mv elastic-agent-8.13.0-linux-x86_64 /opt/elastic-agent \
    && ln -s /opt/elastic-agent/elastic-agent /usr/local/bin/elastic-agent \
    && rm elastic-agent.tar.gz

RUN sed -i "s|hosts: \[127.0.0.1:9200\]|hosts: [elasticsearch:9200]|g" \
    /opt/elastic-agent/elastic-agent.yml

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 21 80
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/entrypoint.sh"]
RUN ln -sf /opt/elastic-agent /usr/share/elastic-agent

# Wazuh agent starter (called by docker-compose.wazuh-agents.yml override)

# start-wazuh.sh stub (called by docker-compose.wazuh-agents.yml)
COPY start-wazuh-stub.sh /usr/local/bin/start-wazuh.sh
RUN chmod +x /usr/local/bin/start-wazuh.sh
