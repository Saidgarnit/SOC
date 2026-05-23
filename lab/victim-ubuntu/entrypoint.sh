#!/bin/bash
# ── victim-ubuntu entrypoint ──────────────────────────────────────────

set -e

echo "[*] Starting victim-ubuntu entrypoint..."

# 1. REGENERATE SSH KEYS
echo "[*] Regenerating SSH keys..."
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub

# 2. CONFIGURE SSH
echo "[*] Configuring SSH..."
cat > /etc/ssh/sshd_config << 'SSHEOF'
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
StrictModes yes
MaxAuthTries 100
MaxSessions 10

SyslogFacility AUTH
LogLevel VERBOSE

UsePAM yes
X11Forwarding yes
X11UseLocalhost yes
Subsystem sftp /usr/lib/openssh/sftp-server

PermitEmptyPasswords yes
ChallengeResponseAuthentication no
UseDns no
SSHEOF

chmod 600 /etc/ssh/sshd_config

# 3. CONFIGURE RSYSLOG
echo "[*] Configuring rsyslog..."
cat > /etc/rsyslog.conf << 'RSYSLOGEOF'
module(load="imuxsock")
module(load="imklog" permitnonkernelfacility="on")

$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
$RepeatedMsgReduction on
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog

kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
mail.err                        /var/log/mail.err
daemon.*                        -/var/log/daemon.log
*.emerg                         :omusrmsg:*
RSYSLOGEOF

rm -f /etc/rsyslog.d/50-default.conf /etc/rsyslog.d/99-auth.conf

touch /var/log/auth.log
chmod 640 /var/log/auth.log
chown root:adm /var/log/auth.log

pkill -9 rsyslogd 2>/dev/null || true
rm -f /run/rsyslogd.pid /var/run/rsyslogd.pid
sleep 1

echo "[*] Starting rsyslog..."
service rsyslog start 2>&1 | grep -v "imklog" || true
sleep 2

# 4. START SSH
echo "[*] Starting SSH..."
mkdir -p /var/run/sshd
service ssh start
sleep 1

# 5. START OTHER SERVICES
service apache2 start 2>/dev/null || true
service vsftpd start 2>/dev/null || true

# 6. CONFIGURE WAZUH
echo "[*] Configuring Wazuh agent..."
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.orig
sed -i '/<localfile>/,/<\/localfile>/d' /var/ossec/etc/ossec.conf

if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    sed -i '/<\/ossec_config>/i\
\
  <!-- SSH Authentication logs -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/auth.log</location>\
  </localfile>' /var/ossec/etc/ossec.conf
fi

pkill -9 wazuh-agentd wazuh-modulesd 2>/dev/null || true
rm -f /var/ossec/var/run/*.pid
sleep 2

echo "[*] Starting Wazuh agent..."
/var/ossec/bin/wazuh-modulesd 2>/dev/null &
sleep 2
/var/ossec/bin/wazuh-agentd 2>/dev/null &

# 7. ELASTIC AGENT
echo "[*] Starting Elastic Agent..."
AGENT_BIN=$(find /opt/elastic-agent/data/ -name "elastic-agent" -type f -executable 2>/dev/null | head -1)
[ -z "$AGENT_BIN" ] && AGENT_BIN="/opt/elastic-agent/elastic-agent"

for i in {1..30}; do
    if curl -sf http://fleet-server:8220/api/status 2>/dev/null | grep -q "HEALTHY"; then
        break
    fi
    sleep 2
done

if [ ! -f /opt/elastic-agent/fleet.enc ]; then
    rm -rf /opt/elastic-agent/data/elastic-agent-*/state/ 2>/dev/null || true
    cd /opt/elastic-agent && "$AGENT_BIN" enroll \
        --url=http://fleet-server:8220 \
        --enrollment-token=RnNaRXA1MEI4VkhUS25sTHB5Wm86dE94alZLcjlTMXlPRXlISHJsODE4Zw== \
        --insecure -f --skip-daemon-reload 2>&1 | tail -2 || true
fi

cd /opt/elastic-agent && exec "$AGENT_BIN" run
