FROM ubuntu:20.04
RUN apt-get update && apt-get install -y tini && rm -rf /var/lib/apt/lists/*

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/elastic-agent:${PATH}"

RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    curl \
    wget \
    sudo \
    python3 \
    net-tools \
    rsyslog \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Windows-like users
RUN useradd -m -s /bin/bash administrator && \
    echo "administrator:Admin123!" | chpasswd && \
    useradd -m -s /bin/bash john.doe && \
    echo "john.doe:Password1" | chpasswd && \
    useradd -m -s /bin/bash jane.smith && \
    echo "jane.smith:Welcome1" | chpasswd

# Samba config — weak auth, mimics Windows shares
RUN mkdir -p /etc/samba && cat > /etc/samba/smb.conf << 'SMBCONF'
[global]
   workgroup = WORKGROUP
   server string = WINDOWS-PC
   netbios name = WINDOWS-PC
   security = user
   map to guest = bad user
   log level = 3
   log file = /var/log/samba/samba.log
   max log size = 1000

[C$]
   path = /srv/samba/c_drive
   browseable = yes
   read only = no
   guest ok = yes

[ADMIN$]
   path = /srv/samba/admin
   browseable = yes
   read only = no
   guest ok = yes

[Users]
   path = /srv/samba/users
   browseable = yes
   read only = no
   guest ok = no
   valid users = administrator john.doe jane.smith
SMBCONF

RUN mkdir -p /srv/samba/c_drive /srv/samba/admin /srv/samba/users && \
    chmod -R 777 /srv/samba/c_drive /srv/samba/admin && \
    chmod -R 755 /srv/samba/users

RUN (echo "Admin123!"; echo "Admin123!") | smbpasswd -s -a administrator && \
    (echo "Password1"; echo "Password1") | smbpasswd -s -a john.doe && \
    (echo "Welcome1"; echo "Welcome1")   | smbpasswd -s -a jane.smith

# Fake Windows event log generator
RUN cat > /usr/local/bin/fake-win-events.py << 'PYEOF'
#!/usr/bin/env python3
import time, random, datetime, os

USERS  = ["administrator","john.doe","jane.smith","SYSTEM","Guest"]
IPS    = ["192.168.1.10","192.168.1.20","10.0.0.5","172.16.0.100"]
EVENTS = [
    "EventID=4624 Account successfully logged on. User={user} SourceIP={ip}",
    "EventID=4625 Account failed to log on. User={user} SourceIP={ip}",
    "EventID=4648 Logon with explicit credentials. User={user}",
    "EventID=4720 User account created. NewUser=svc_backup",
    "EventID=4732 Member added to security-enabled group.",
    "EventID=7045 New service installed. ServiceName=malicious_svc",
    "EventID=4688 New process created. Process=cmd.exe User={user}",
    "EventID=4698 Scheduled task created. TaskName=backdoor_task",
    "EventID=4776 Domain controller validated credentials. User={user}",
    "EventID=1102 Audit log cleared. User={user}",
    "EventID=4657 Registry value modified. User={user}",
    "EventID=4670 Permissions on object changed. User={user}",
]

os.makedirs("/var/log", exist_ok=True)
LOG = "/var/log/windows-events.log"

while True:
    evt = random.choice(EVENTS).format(
        user=random.choice(USERS),
        ip=random.choice(IPS)
    )
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG, "a") as f:
        f.write(f"{ts} WINDOWS-PC {evt}\n")
    time.sleep(random.uniform(5, 15))
PYEOF
RUN chmod +x /usr/local/bin/fake-win-events.py

# Install Wazuh agent — download only (fast, ~20MB)
RUN curl -so /tmp/wazuh-agent.deb \
    https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.5-1_amd64.deb \
    && WAZUH_MANAGER=wazuh-manager \
       WAZUH_AGENT_NAME=victim-windows \
       dpkg -i /tmp/wazuh-agent.deb \
    && rm /tmp/wazuh-agent.deb

# Configure Wazuh to read Windows event log + Samba log
RUN cat >> /var/ossec/etc/ossec.conf << 'WAZUHCONF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/windows-events.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/samba/samba.log</location>
  </localfile>
</ossec_config>
WAZUHCONF

# Copy Elastic Agent from local cache — no download needed
COPY elastic-agent-bin/ /opt/elastic-agent/
RUN ln -sf /opt/elastic-agent/elastic-agent /usr/local/bin/elastic-agent && \
    ln -sf /opt/elastic-agent /usr/share/elastic-agent && \
    sed -i "s|hosts: \[127.0.0.1:9200\]|hosts: [elasticsearch:9200]|g" \
        /opt/elastic-agent/elastic-agent.yml 2>/dev/null || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 139 445
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/entrypoint.sh"]

# Wazuh agent starter (called by docker-compose.wazuh-agents.yml override)

# start-wazuh.sh stub (called by docker-compose.wazuh-agents.yml)
COPY start-wazuh-stub.sh /usr/local/bin/start-wazuh.sh
RUN chmod +x /usr/local/bin/start-wazuh.sh
