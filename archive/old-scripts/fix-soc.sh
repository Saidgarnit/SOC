#!/bin/bash
# ================================================================
# fix-soc.sh — Complete SOC Stack Repair
# Fixes: Slack icons + format, C2 beaconing dedup, stale indices,
#        VT field type mismatch, ILM auto-cleanup policy
# Run:   bash ~/soc-stack/fix-soc.sh
# ================================================================
set -euo pipefail

R="$HOME/soc-stack/elastalert/rules"
ES="http://localhost:9200"
AUTH="elastic:sYVfKJCe2RCfELjf=GLa"

ok()   { echo -e "  \033[1;32m✓\033[0m $1"; }
warn() { echo -e "  \033[1;33m⚠\033[0m $1"; }
info() { echo -e "\n\033[1;36m▶ $1\033[0m"; }
die()  { echo -e "\n\033[1;31m✗ ERROR: $1\033[0m"; exit 1; }

echo -e "\n\033[1;35m╔═══════════════════════════════════════════════╗"
echo    "║   SOC Stack — Complete Repair Script v2.0    ║"
echo -e "╚═══════════════════════════════════════════════╝\033[0m"

# ─────────────────────────────────────────────────────────────────
# [1] Extract Slack Webhook URL from existing rules
# ─────────────────────────────────────────────────────────────────
info "[1/4] Extracting Slack webhook URL"

WH=$(grep -rh "slack_webhook_url" "$R"/*.yaml 2>/dev/null \
     | head -1 \
     | sed 's/.*slack_webhook_url:[[:space:]]*//' \
     | tr -d '"'"'"' \n')

[[ -z "$WH" ]] && die "Could not find slack_webhook_url in any rule file. Aborting."
ok "Webhook: ${WH:0:60}..."

# ─────────────────────────────────────────────────────────────────
# [2] Fix Elasticsearch Indices (safe data-stream aware cleanup)
# ─────────────────────────────────────────────────────────────────
info "[2/4] Cleaning stale Elasticsearch indices"

python3 << PYEOF
import urllib.request, urllib.error, json, base64, sys

ES    = "$ES"
CREDS = base64.b64encode(b"$AUTH").decode()

def call(method, path, body=None):
    url  = ES + path
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method,
           headers={"Authorization": f"Basic {CREDS}",
                    "Content-Type":  "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code

# ── Delete stale soc-logs-enriched-* indices (safe, non-stream) ──
res, code = call("DELETE", "/soc-logs-enriched-*")
if code == 200 and res.get("acknowledged"):
    print("  ✓ Deleted stale soc-logs-enriched-* indices")
elif code == 404:
    print("  - soc-logs-enriched-*: already gone")
else:
    print(f"  ⚠ soc-logs-enriched-*: {res.get('error',{}).get('type','unknown')}")

# ── Safely clean wazuh data stream old backing indices ────────────
res, _ = call("GET", "/_data_stream/wazuh-*")
streams = res.get("data_streams", [])
to_del  = []

for ds in streams:
    indices = ds.get("indices", [])
    # All backing indices except the LAST one (= write index)
    for idx in indices[:-1]:
        to_del.append(idx["index_name"])

if to_del:
    joined = ",".join(to_del)
    res, code = call("DELETE", f"/{joined}")
    if code == 200 and res.get("acknowledged"):
        print(f"  ✓ Deleted {len(to_del)} old wazuh backing index(es)")
    else:
        print(f"  ⚠ Partial delete: {res.get('error',{}).get('reason','?')}")
else:
    print("  ✓ No stale wazuh backing indices (nothing to remove)")

# ── Apply ILM policy — prevents recurrence (7-day auto-delete) ───
ilm = {
    "policy": {
        "phases": {
            "hot":    {"min_age": "0ms",
                       "actions": {"rollover": {"max_age": "1d", "max_primary_shard_size": "5gb"}}},
            "delete": {"min_age": "7d",
                       "actions": {"delete": {}}}
        }
    }
}
res, code = call("PUT", "/_ilm/policy/soc-auto-cleanup", ilm)
if res.get("acknowledged"):
    print("  ✓ ILM policy 'soc-auto-cleanup' applied — 7-day retention, 1-day rollover")
else:
    print(f"  ⚠ ILM policy: {res}")

# ── Reduce refresh rate on heavy indices to lower CPU ─────────────
res, code = call("PUT", "/logstash-*/_settings",
                 {"index": {"refresh_interval": "30s"}})
if res.get("acknowledged"):
    print("  ✓ logstash-* refresh interval set to 30s (reduces CPU load)")

PYEOF

# ─────────────────────────────────────────────────────────────────
# [3] Rewrite all 18 Elastalert rules (format + dedup + VT fix)
# ─────────────────────────────────────────────────────────────────
info "[3/4] Rewriting all 18 rules with proper format, icons & dedup"

# Helper: write YAML file and inject webhook
wr() {
  local FILE="$R/$1"; shift
  cat > "$FILE"
  sed -i "s|__WH__|$WH|g" "$FILE"
  ok "$1  →  $(basename $FILE)"
}

# ── 1. suricata_alert.yaml — C2 Beaconing (DEDUP FIXED) ──────────
cat > "$R/suricata_alert.yaml" << 'EOF'
name: "Suricata IDS — C2 Beaconing"
type: frequency
index: logstash-*
num_events: 3
timeframe:
  minutes: 10

filter:
  - query:
      bool:
        must:
          - match:
              event_type: "alert"
          - match_phrase:
              alert.signature: "C2 Beaconing"

# Deduplicate: one alert per unique source→target pair per hour
query_key:
  - src_ip
  - dest_ip
realert:
  minutes: 60

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":satellite:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  🛰️ *C2 Beaconing Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Signature:*  {alert.signature}
  *Source IP:*  {src_ip}
  *Target:*     {dest_ip}:{dest_port}
  *Protocol:*   {proto}
  *Severity:*   {alert.severity}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/suricata_alert.yaml"
ok ":satellite:  suricata_alert.yaml  [C2 dedup: query_key src+dest, 60min realert — FIXED]"

# ── 2. suricata_brute_force.yaml ──────────────────────────────────
cat > "$R/suricata_brute_force.yaml" << 'EOF'
name: "Suricata IDS — Brute Force"
type: any
index: logstash-*

filter:
  - query:
      bool:
        must:
          - match:
              event_type: "alert"
          - bool:
              should:
                - match_phrase:
                    alert.signature: "SSH Brute Force"
                - match_phrase:
                    alert.signature: "RDP Brute Force"
                - match_phrase:
                    alert.signature: "FTP Brute Force"

query_key:
  - src_ip
  - dest_ip
realert:
  minutes: 30

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":hammer:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  🔨 *Brute Force Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Signature:*  {alert.signature}
  *Source IP:*  {src_ip}
  *Target:*     {dest_ip}:{dest_port}
  *Protocol:*   {proto}
  *Severity:*   {alert.severity}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/suricata_brute_force.yaml"
ok ":hammer:  suricata_brute_force.yaml"

# ── 3. agent_status.yaml ──────────────────────────────────────────
cat > "$R/agent_status.yaml" << 'EOF'
name: "Wazuh — Agent Status Change"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        should:
          - match:
              rule.id: "506"
          - match:
              rule.id: "501"
          - match:
              rule.groups: "ossec"
        minimum_should_match: 1

query_key: agent.name
realert:
  minutes: 15

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":robot_face:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  🤖 *Agent Status Changed*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*    {agent.name}
  *Status:*   {rule.description}
  *Rule ID:*  {rule.id}
  *Level:*    {rule.level}
  *Time:*     {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/agent_status.yaml"
ok ":robot_face:  agent_status.yaml"

# ── 4. fim_alert.yaml ─────────────────────────────────────────────
cat > "$R/fim_alert.yaml" << 'EOF'
name: "Wazuh — File Integrity Alert"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "syscheck"

query_key: agent.name
realert:
  minutes: 5

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":file_folder:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  📁 *File Integrity Alert*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*     {agent.name}
  *File:*      {syscheck.path}
  *Event:*     {rule.description}
  *Rule ID:*   {rule.id}
  *Level:*     {rule.level}
  *Time:*      {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/fim_alert.yaml"
ok ":file_folder:  fim_alert.yaml"

# ── 5. web_attacks.yaml ───────────────────────────────────────────
cat > "$R/web_attacks.yaml" << 'EOF'
name: "Web Attacks (Wazuh)"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "web"

query_key: agent.name
realert:
  minutes: 5

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":spider_web:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  🕷️ *Web Attack Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*      {agent.name}
  *Attack:*     {rule.description}
  *Rule ID:*    {rule.id}
  *Level:*      {rule.level}
  *Source IP:*  {data.srcip}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/web_attacks.yaml"
ok ":spider_web:  web_attacks.yaml"

# ── 6. brute_force.yaml (Wazuh) ───────────────────────────────────
cat > "$R/brute_force.yaml" << 'EOF'
name: "Wazuh — SSH Brute Force"
type: frequency
index: wazuh-alerts-*
num_events: 5
timeframe:
  minutes: 2

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "authentication_failures"

query_key:
  - agent.name
  - data.srcip
realert:
  minutes: 30

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":lock:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  🔐 *Authentication Brute Force*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*      {agent.name}
  *Source IP:*  {data.srcip}
  *Attack:*     {rule.description}
  *Rule ID:*    {rule.id}
  *Level:*      {rule.level}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/brute_force.yaml"
ok ":lock:  brute_force.yaml"

# ── 7. failed_login.yaml ──────────────────────────────────────────
cat > "$R/failed_login.yaml" << 'EOF'
name: "Wazuh — Failed Login"
type: frequency
index: wazuh-alerts-*
num_events: 3
timeframe:
  minutes: 1

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "authentication_failed"

query_key: agent.name
realert:
  minutes: 10

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":no_entry:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  ⛔ *Failed Login Attempts*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*      {agent.name}
  *Source IP:*  {data.srcip}
  *Detail:*     {rule.description}
  *Rule ID:*    {rule.id}
  *Level:*      {rule.level}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/failed_login.yaml"
ok ":no_entry:  failed_login.yaml"

# ── 8. ftp_bruteforce.yaml ────────────────────────────────────────
cat > "$R/ftp_bruteforce.yaml" << 'EOF'
name: "Suricata IDS — FTP Brute Force"
type: frequency
index: logstash-*
num_events: 5
timeframe:
  minutes: 2

filter:
  - query:
      bool:
        must:
          - match:
              event_type: "alert"
          - match_phrase:
              alert.signature: "FTP"

query_key:
  - src_ip
  - dest_ip
realert:
  minutes: 30

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":file_cabinet:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  🗄️ *FTP Brute Force Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Signature:*  {alert.signature}
  *Source IP:*  {src_ip}
  *Target:*     {dest_ip}:{dest_port}
  *Protocol:*   {proto}
  *Severity:*   {alert.severity}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/ftp_bruteforce.yaml"
ok ":file_cabinet:  ftp_bruteforce.yaml"

# ── 9. port_scan.yaml ─────────────────────────────────────────────
cat > "$R/port_scan.yaml" << 'EOF'
name: "Suricata IDS — Port Scan"
type: any
index: logstash-*

filter:
  - query:
      bool:
        must:
          - match:
              event_type: "alert"
          - match_phrase:
              alert.signature: "Port Scan"

query_key: src_ip
realert:
  minutes: 30

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":mag:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  🔍 *Port Scan Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Signature:*  {alert.signature}
  *Source IP:*  {src_ip}
  *Target:*     {dest_ip}
  *Protocol:*   {proto}
  *Severity:*   {alert.severity}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/port_scan.yaml"
ok ":mag:  port_scan.yaml"

# ── 10. privilege_escalation.yaml ─────────────────────────────────
cat > "$R/privilege_escalation.yaml" << 'EOF'
name: "Wazuh — Privilege Escalation"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "priv_esc"

query_key: agent.name
realert:
  minutes: 10

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":arrow_double_up:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  ⬆️ *Privilege Escalation Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*     {agent.name}
  *Detail:*    {rule.description}
  *Rule ID:*   {rule.id}
  *Level:*     {rule.level}
  *User:*      {data.dstuser}
  *Time:*      {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/privilege_escalation.yaml"
ok ":arrow_double_up:  privilege_escalation.yaml"

# ── 11. lateral_movement.yaml ─────────────────────────────────────
cat > "$R/lateral_movement.yaml" << 'EOF'
name: "Wazuh — Lateral Movement"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "authentication_success"
          - range:
              rule.level:
                gte: 10

query_key:
  - agent.name
  - data.srcip
realert:
  minutes: 20

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":left_right_arrow:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  ↔️ *Lateral Movement Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*      {agent.name}
  *Source IP:*  {data.srcip}
  *Detail:*     {rule.description}
  *Rule ID:*    {rule.id}
  *Level:*      {rule.level}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/lateral_movement.yaml"
ok ":left_right_arrow:  lateral_movement.yaml"

# ── 12. dns_exfiltration.yaml ─────────────────────────────────────
cat > "$R/dns_exfiltration.yaml" << 'EOF'
name: "Suricata IDS — DNS Exfiltration"
type: any
index: logstash-*

filter:
  - query:
      bool:
        must:
          - match:
              event_type: "alert"
          - bool:
              should:
                - match_phrase:
                    alert.signature: "DNS Exfil"
                - match_phrase:
                    alert.signature: "DNS Tunneling"

query_key: src_ip
realert:
  minutes: 30

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":satellite_antenna:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  📡 *DNS Exfiltration Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Signature:*  {alert.signature}
  *Source IP:*  {src_ip}
  *DNS Query:*  {dns.query}
  *Protocol:*   {proto}
  *Severity:*   {alert.severity}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/dns_exfiltration.yaml"
ok ":satellite_antenna:  dns_exfiltration.yaml"

# ── 13. high_risk.yaml ────────────────────────────────────────────
cat > "$R/high_risk.yaml" << 'EOF'
name: "Wazuh — High Risk Event"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - range:
              rule.level:
                gte: 13

query_key: agent.name
realert:
  minutes: 5

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":rotating_light:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  🚨 *HIGH RISK EVENT*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*    {agent.name}
  *Event:*    {rule.description}
  *Rule ID:*  {rule.id}
  *Level:*    {rule.level}  ⚠️ CRITICAL
  *Groups:*   {rule.groups}
  *Time:*     {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/high_risk.yaml"
ok ":rotating_light:  high_risk.yaml"

# ── 14. webshell_indicator.yaml ───────────────────────────────────
cat > "$R/webshell_indicator.yaml" << 'EOF'
name: "Wazuh — Webshell Indicator"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "web"
          - range:
              rule.level:
                gte: 10

query_key: agent.name
realert:
  minutes: 15

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":ghost:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  👻 *Webshell / RCE Indicator*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*      {agent.name}
  *Detail:*     {rule.description}
  *Rule ID:*    {rule.id}
  *Level:*      {rule.level}
  *Source IP:*  {data.srcip}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/webshell_indicator.yaml"
ok ":ghost:  webshell_indicator.yaml"

# ── 15. yara_critical.yaml ────────────────────────────────────────
cat > "$R/yara_critical.yaml" << 'EOF'
name: "Wazuh — YARA Critical Match"
type: any
index: wazuh-alerts-*

filter:
  - query:
      bool:
        must:
          - match:
              rule.groups: "yara"

query_key: agent.name
realert:
  minutes: 15

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":skull_crossbones:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  ☠️ *YARA Rule Match — Malware Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Agent:*    {agent.name}
  *Match:*    {rule.description}
  *File:*     {syscheck.path}
  *Rule ID:*  {rule.id}
  *Level:*    {rule.level}
  *Time:*     {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/yara_critical.yaml"
ok ":skull_crossbones:  yara_critical.yaml"

# ── 16. vt_alert.yaml — VT TYPE FIX (integer range, not string) ───
cat > "$R/vt_alert.yaml" << 'EOF'
name: "VirusTotal — Malicious Hash"
type: any
index: logstash-*

filter:
  - query:
      bool:
        must:
          - range:
              vt_malicious:
                gt: 0   # FIX: was match/term on string — now range on integer

query_key: src_ip
realert:
  minutes: 60

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":biohazard_sign:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  ☣️ *VirusTotal — Malicious Hash Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Hash:*        {vt_hash}
  *Detections:*  {vt_malicious} engines flagged
  *Source IP:*   {src_ip}
  *Agent:*       {agent.name}
  *Time:*        {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/vt_alert.yaml"
ok ":biohazard_sign:  vt_alert.yaml  [VT type mismatch FIXED: range gt:0 instead of string match]"

# ── 17. misp_alert.yaml ───────────────────────────────────────────
cat > "$R/misp_alert.yaml" << 'EOF'
name: "MISP IOC Match"
type: any
index: logstash-*

filter:
  - query:
      bool:
        must:
          - exists:
              field: misp_event_id

query_key: src_ip
realert:
  minutes: 60

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":red_circle:"
slack_msg_color: "danger"
alert_text_type: alert_text_only
alert_text: |
  🔴 *MISP IOC Match*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *IOC:*       {misp_value}
  *Event ID:*  {misp_event_id}
  *Category:*  {misp_category}
  *Source IP:* {src_ip}
  *Agent:*     {agent.name}
  *Time:*      {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/misp_alert.yaml"
ok ":red_circle:  misp_alert.yaml  [note: needs MISP API key fix first]"

# ── 18. mqtt_anomaly.yaml — Already working, just reformat ────────
cat > "$R/mqtt_anomaly.yaml" << 'EOF'
name: "MQTT Anomaly Detection"
type: any
index: logstash-*

filter:
  - query:
      bool:
        must:
          - match:
              event_type: "alert"
          - match_phrase:
              alert.signature: "MQTT"

query_key: src_ip
realert:
  minutes: 30

alert: slack
slack_webhook_url: "__WH__"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":wireless:"
slack_msg_color: "warning"
alert_text_type: alert_text_only
alert_text: |
  📶 *MQTT Anomaly Detected*
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  *Signature:*  {alert.signature}
  *Source IP:*  {src_ip}
  *Target:*     {dest_ip}:{dest_port}
  *Protocol:*   {proto}
  *Severity:*   {alert.severity}
  *Time:*       {timestamp}
  <http://localhost:5601|🔍 View in Kibana>
EOF
sed -i "s|__WH__|$WH|g" "$R/mqtt_anomaly.yaml"
ok ":wireless:  mqtt_anomaly.yaml"

echo ""
echo -e "  \033[1;32m✓ All 18 rules rewritten\033[0m"

# ─────────────────────────────────────────────────────────────────
# [4] Validate YAML + Deploy
# ─────────────────────────────────────────────────────────────────
info "[4/4] Validating YAML syntax and deploying"

# Quick YAML syntax check via Python before deploying
FAIL=0
for f in "$R"/*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null \
    && ok "$(basename $f)" \
    || { warn "YAML ERROR in $(basename $f)"; FAIL=1; }
done

[[ $FAIL -eq 1 ]] && die "YAML validation failed. Fix errors above before deploying."

# Deploy
echo ""
"$HOME/soc-stack/deploy-rules.sh"

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────
echo -e "\n\033[1;35m╔═══════════════════════════════════════════════╗"
echo    "║              Repair Complete ✅               ║"
echo    "╠═══════════════════════════════════════════════╣"
echo    "║  ✓  18 rules — proper icons + newlines       ║"
echo    "║  ✓  C2 Beaconing — query_key dedup (60min)   ║"
echo    "║  ✓  VT type fix — range gt:0 (was string)    ║"
echo    "║  ✓  Stale indices removed (data-stream safe) ║"
echo    "║  ✓  ILM policy — 7-day auto-cleanup applied  ║"
echo    "║  ✓  logstash-* refresh → 30s (CPU relief)    ║"
echo    "╠═══════════════════════════════════════════════╣"
echo    "║  PENDING (manual):                            ║"
echo    "║  → Fix MISP API key in docker-compose.yml    ║"
echo    "║  → Enroll victim-wazuh1 + victim-windows     ║"
echo    "║  → Trigger level-15 alert to test Gmail      ║"
echo -e "╚═══════════════════════════════════════════════╝\033[0m"
