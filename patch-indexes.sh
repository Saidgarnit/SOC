#!/bin/bash
# ================================================================
# patch-indexes.sh — Fix all rule indexes + field names
# Uses Python to generate rules (avoids heredoc quote issues)
# ================================================================
set -euo pipefail

R="$HOME/soc-stack/elastalert/rules"
mkdir -p "$R"

ok()   { echo -e "  \033[1;32m✓\033[0m $1"; }
info() { echo -e "\n\033[1;36m▶ $1\033[0m"; }

echo -e "\n\033[1;35m╔══════════════════════════════════════════════════╗"
echo    "║   SOC Rules — Index + Field Patch (Verified)   ║"
echo -e "╚══════════════════════════════════════════════════╝\033[0m"

# Extract webhook
WH=$(grep -rh "slack_webhook_url" "$R"/*.yaml 2>/dev/null | head -1 | sed 's/.*slack_webhook_url:[[:space:]]*//' | tr -d '"'"'"' \n)
[ -z "$WH" ] && WH="${SLACK_WEBHOOK_URL}"

info "[1/3] Suricata rules → soc-logs-enriched*"

python3 << 'PYEOF'
import yaml
import os

R = os.path.expanduser("~/soc-stack/elastalert/rules")
WH = "${SLACK_WEBHOOK_URL}"

rules = {
    "suricata_alert.yaml": {
        "name": "Suricata IDS — C2 Beaconing",
        "type": "frequency",
        "index": "soc-logs-enriched*",
        "num_events": 3,
        "timeframe": {"minutes": 10},
        "filter": [{"query": {"bool": {"must": [
            {"match": {"event_type": "alert"}},
            {"match_phrase": {"alert.signature": "C2 Beaconing"}}
        ]}}}],
        "query_key": ["src_ip", "dest_ip"],
        "realert": {"minutes": 60},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":satellite:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "C2 Beaconing: {alert.signature} from {src_ip} to {dest_ip}:{dest_port}"
    },
    "suricata_brute_force.yaml": {
        "name": "Suricata IDS — Brute Force",
        "type": "any",
        "index": "soc-logs-enriched*",
        "filter": [{"query": {"bool": {"must": [
            {"match": {"event_type": "alert"}},
            {"bool": {"should": [
                {"match_phrase": {"alert.signature": "SSH Brute Force"}},
                {"match_phrase": {"alert.signature": "RDP Brute Force"}},
                {"match_phrase": {"alert.signature": "FTP Brute Force"}}
            ]}}
        ]}}}],
        "query_key": ["src_ip", "dest_ip"],
        "realert": {"minutes": 30},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":hammer:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "Brute Force: {alert.signature} from {src_ip} to {dest_ip}:{dest_port}"
    },
    "ftp_bruteforce.yaml": {
        "name": "Suricata IDS — FTP Brute Force",
        "type": "frequency",
        "index": "soc-logs-enriched*",
        "num_events": 5,
        "timeframe": {"minutes": 2},
        "filter": [{"query": {"bool": {"must": [
            {"match": {"event_type": "alert"}},
            {"match": {"alert.category": "Attempted Administrator Privilege Gain"}}
        ]}}}],
        "query_key": ["src_ip", "dest_ip"],
        "realert": {"minutes": 30},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":file_cabinet:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "FTP Brute Force: {alert.signature} from {src_ip} to {dest_ip}:{dest_port}"
    },
    "port_scan.yaml": {
        "name": "Suricata IDS — Port Scan",
        "type": "any",
        "index": "soc-logs-enriched*",
        "filter": [{"query": {"bool": {"must": [
            {"match": {"event_type": "alert"}},
            {"bool": {"should": [
                {"match_phrase": {"alert.signature": "Port Scan"}},
                {"match_phrase": {"alert.category": "Attempted Information Leak"}}
            ]}}
        ]}}}],
        "query_key": "src_ip",
        "realert": {"minutes": 30},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":mag:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "Port Scan: {alert.signature} from {src_ip} to {dest_ip}"
    },
    "dns_exfiltration.yaml": {
        "name": "Suricata IDS — DNS Exfiltration",
        "type": "any",
        "index": "soc-logs-enriched*",
        "filter": [{"query": {"bool": {"must": [
            {"match": {"event_type": "alert"}},
            {"bool": {"should": [
                {"match_phrase": {"alert.signature": "DNS Exfil"}},
                {"match_phrase": {"alert.signature": "DNS Tunneling"}}
            ]}}
        ]}}}],
        "query_key": "src_ip",
        "realert": {"minutes": 30},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":satellite_antenna:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "DNS Exfil: {alert.signature} from {src_ip} to {dest_ip}:{dest_port}"
    },
    "mqtt_anomaly.yaml": {
        "name": "MQTT Anomaly Detection",
        "type": "any",
        "index": "soc-logs-enriched*",
        "filter": [{"query": {"bool": {"must": [
            {"match": {"event_type": "alert"}},
            {"match_phrase": {"alert.signature": "MQTT"}}
        ]}}}],
        "query_key": "src_ip",
        "realert": {"minutes": 30},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":wireless:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "MQTT Anomaly: {alert.signature} from {src_ip} to {dest_ip}:{dest_port}"
    },
    "vt_alert.yaml": {
        "name": "VirusTotal — Malicious Hash",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"must": [
            {"term": {"vt_checked": True}},
            {"range": {"vt_malicious": {"gt": 0}}}
        ]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 60},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":biohazard_sign:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "VT Alert: {agent.name} - {syscheck.path} - {vt_malicious} engines"
    },
    "misp_alert.yaml": {
        "name": "MISP IOC Match",
        "type": "any",
        "index": "soc-logs-enriched*",
        "filter": [{"query": {"bool": {"must": [{"exists": {"field": "misp_event_id"}}]}}}],
        "query_key": "src_ip",
        "realert": {"minutes": 60},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":red_circle:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "MISP: Event {misp_event_id} - {src_ip} to {dest_ip}:{dest_port}"
    },
    "agent_status.yaml": {
        "name": "Wazuh — Agent Status Change",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"should": [
            {"term": {"rule.id": "506"}},
            {"term": {"rule.id": "501"}}
        ], "minimum_should_match": 1}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 15},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":robot_face:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "Agent Status: {agent.name} - {rule.description}"
    },
    "fim_alert.yaml": {
        "name": "Wazuh — File Integrity Alert",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"must": [{"match": {"rule.groups": "syscheck"}}]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 5},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":file_folder:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "FIM: {agent.name} - {syscheck.path} - {syscheck.event}"
    },
    "web_attacks.yaml": {
        "name": "Web Attacks (Wazuh)",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"must": [{"match": {"rule.groups": "web"}}]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 5},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":spider_web:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "Web Attack: {agent.name} - {rule.description}"
    },
    "brute_force.yaml": {
        "name": "Wazuh — Authentication Brute Force",
        "type": "frequency",
        "index": "wazuh-alerts-*",
        "num_events": 5,
        "timeframe": {"minutes": 2},
        "filter": [{"query": {"bool": {"must": [{"match": {"rule.groups": "authentication_failures"}}]}}}],
        "query_key": ["agent.name", "data.srcip"],
        "realert": {"minutes": 30},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":lock:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "Auth Brute Force: {agent.name} from {data.srcip}"
    },
    "failed_login.yaml": {
        "name": "Wazuh — Failed Login",
        "type": "frequency",
        "index": "wazuh-alerts-*",
        "num_events": 3,
        "timeframe": {"minutes": 1},
        "filter": [{"query": {"bool": {"must": [{"match": {"rule.groups": "authentication_failed"}}]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 10},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":no_entry:",
        "slack_msg_color": "warning",
        "alert_text_type": "alert_text_only",
        "alert_text": "Failed Login: {agent.name} from {data.srcip}"
    },
    "privilege_escalation.yaml": {
        "name": "Wazuh — Privilege Escalation",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"should": [
            {"match": {"rule.groups": "priv_esc"}},
            {"match": {"rule.groups": "sudo"}}
        ], "minimum_should_match": 1}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 10},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":arrow_double_up:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "Priv Esc: {agent.name} - {system.auth.sudo.command}"
    },
    "lateral_movement.yaml": {
        "name": "Wazuh — Lateral Movement",
        "type": "frequency",
        "index": "wazuh-alerts-*",
        "num_events": 3,
        "timeframe": {"minutes": 5},
        "filter": [{"query": {"bool": {"must": [
            {"match": {"rule.groups": "authentication_success"}},
            {"range": {"rule.level": {"gte": 8}}}
        ]}}}],
        "query_key": ["data.srcip"],
        "realert": {"minutes": 20},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":left_right_arrow:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "Lateral Movement: {agent.name} from {data.srcip}"
    },
    "high_risk.yaml": {
        "name": "Wazuh — High Risk Event",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"must": [{"range": {"rule.level": {"gte": 13}}}]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 5},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":rotating_light:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "HIGH RISK: {agent.name} - Level {rule.level}"
    },
    "webshell_indicator.yaml": {
        "name": "Wazuh — Webshell Indicator",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"must": [
            {"match": {"rule.groups": "web"}},
            {"range": {"rule.level": {"gte": 10}}}
        ]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 15},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":ghost:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "Webshell: {agent.name} - {rule.description}"
    },
    "yara_critical.yaml": {
        "name": "Wazuh — YARA Critical Match",
        "type": "any",
        "index": "wazuh-alerts-*",
        "filter": [{"query": {"bool": {"must": [{"match": {"rule.groups": "yara"}}]}}}],
        "query_key": "agent.name",
        "realert": {"minutes": 15},
        "alert": "slack",
        "slack_webhook_url": WH,
        "slack_username_override": "SOC Alerts",
        "slack_icon_emoji": ":skull_crossbones:",
        "slack_msg_color": "danger",
        "alert_text_type": "alert_text_only",
        "alert_text": "YARA: {agent.name} - {rule.description}"
    }
}

for fname, rule in rules.items():
    with open(os.path.join(R, fname), 'w') as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True)

print(f"✓ {len(rules)} rules created")
PYEOF

ok "All 18 rules generated"

info "Validating YAML"

python3 << 'PYEOF'
import yaml
import os

R = os.path.expanduser("~/soc-stack/elastalert/rules")
fail = 0
for f in os.listdir(R):
    if f.endswith('.yaml'):
        try:
            with open(os.path.join(R, f)) as fp:
                yaml.safe_load(fp)
            print(f"  ✓ {f}")
        except Exception as e:
            print(f"  ✗ {f}: {e}")
            fail = 1

exit(fail)
PYEOF

"$HOME/soc-stack/deploy-rules.sh"

echo -e "\n\033[1;35m╔══════════════════════════════════════════════════╗"
echo    "║          Index Patch Complete ✅              ║"
echo    "╠══════════════════════════════════════════════════╣"
echo    "║  18 Rules Deployed Successfully!               ║"
echo    "║  SURICATA (6) → soc-logs-enriched*             ║"
echo    "║  VT + MISP (2) → correct indexes                ║"
echo    "║  WAZUH (10) → wazuh-alerts-*                    ║"
echo -e "╚══════════════════════════════════════════════════╝\033[0m"
