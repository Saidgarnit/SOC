FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bind9 bind9utils dnsutils \
    curl wget lsb-release rsyslog \
    && rm -rf /var/lib/apt/lists/*

RUN curl -so wazuh-agent.deb \
    https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb \
    && WAZUH_MANAGER=wazuh-manager \
       WAZUH_AGENT_NAME=victim-dns \
       dpkg -i ./wazuh-agent.deb \
    && rm wazuh-agent.deb

RUN curl -so elastic-agent.tar.gz \
    https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.0-linux-x86_64.tar.gz \
    && tar xzf elastic-agent.tar.gz \
    && mv elastic-agent-8.13.0-linux-x86_64 /opt/elastic-agent \
    && rm elastic-agent.tar.gz \
    && ln -sf /opt/elastic-agent /usr/share/elastic-agent

RUN sed -i "s|hosts: \[127.0.0.1:9200\]|hosts: [elasticsearch:9200]|g" \
    /opt/elastic-agent/elastic-agent.yml

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 53/udp 53/tcp
CMD ["/entrypoint.sh"]

# Wazuh agent starter (called by docker-compose.wazuh-agents.yml override)

# start-wazuh.sh stub (called by docker-compose.wazuh-agents.yml)
COPY start-wazuh-stub.sh /usr/local/bin/start-wazuh.sh
RUN chmod +x /usr/local/bin/start-wazuh.sh
