#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def write_rule(filename, name, type, index, icon, msg, args, must_match=[], must_exist=[], num_events=1):
    indented_msg = "\n".join(f"  {line}" for line in msg.split("\n"))
    must_blocks = must_match + [{"exists": {"field": f}} for f in must_exist]
    content = f"""name: "{name}"
type: {type}
index: {index}
num_events: {num_events}
timeframe: {{ minutes: 5 }}
realert: {{ minutes: 15 }}
filter:
- query:
    bool:
      must: {must_blocks}
      must_not:
      - terms: {{ src_ip: {SOC_IPS} }}
alert: ["slack", "email"]
email: ["garnitsaid01@gmail.com"]
from_addr: "garnitsaid01@gmail.com"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"
alert_text_type: alert_text_only
alert_text: |
{indented_msg}
alert_text_args: {args}
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: "{icon}"
"""
    with open(f"/home/said/soc-stack/elastalert/rules/{filename}", "w") as f: f.write(content)
    print(f"Generated {filename}")

SEC = "*[SECURITY] {0} — {1} → {2}*\nAttacker: {1} | User: {3}\nMITRE: {4}"
SYS = "*[SYSTEM] {0} — {1}*\nEvent: {2}\nDetails: {3}"

# --- THE COMPLETE 18 ---
write_rule("ftp_brute.yaml", "Suricata — FTP Brute Force", "any", "suricata-alerts-*", ":file_folder:", SEC.format("FTP Brute", "{4}", "{6}", "N/A", "{1}"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"alert.signature": "FTP"}}])
write_rule("mqtt_anomaly.yaml", "IoT — MQTT Anomaly", "any", "suricata-alerts-*", ":robot_face:", SYS.format("MQTT Anomaly", "{4}", "IoT Traffic", "Suspicious MQTT"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"alert.signature": "MQTT"}}])
write_rule("misp_match.yaml", "Threat Intel — MISP Match", "any", "suricata-alerts-*", ":red_circle:", "*[THREAT-INTEL] MISP Match — {4}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"exists": {"field": "misp_event_id"}}])
write_rule("failed_login.yaml", "Wazuh — Failed Login", "any", ".ds-wazuh-alerts-4.x-*", ":lock:", SEC.format("Failed Login", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], [{"match": {"rule.groups": "authentication_failed"}}])
write_rule("priv_esc.yaml", "Wazuh — Priv Escalation", "any", ".ds-wazuh-alerts-4.x-*", ":arrow_double_up:", SEC.format("Priv-Esc", "Local", "{1}", "{9}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.dstuser"], [{"terms": {"rule.groups": ["priv_esc", "sudo"]}}])
write_rule("webshell_indicator.yaml", "Wazuh — Webshell", "any", ".ds-wazuh-alerts-4.x-*", ":ghost:", "*[ENDPOINT] Webshell Indicator — {1}*\n🚨 CRITICAL INDICATOR", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"match": {"rule.groups": "web"}}, {"range": {"rule.level": {"gte": 10}}}])
write_rule("high_risk.yaml", "Wazuh — High Risk", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", SEC.format("High Risk", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], [{"range": {"rule.level": {"gte": 13}}}])
write_rule("lateral_movement.yaml", "Wazuh — Lateral Movement", "any", ".ds-wazuh-alerts-4.x-*", ":left_right_arrow:", SEC.format("Lateral Move", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], [{"match": {"rule.groups": "authentication_success"}}, {"range": {"rule.level": {"gte": 8}}}])
write_rule("malware_hash.yaml", "VirusTotal — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":biohazard_sign:", "*[MALWARE] VT Match — {1}*\nDetections: {6}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "vt_malicious"], [{"exists": {"field": "vt_malicious"}}])
write_rule("brute_force.yaml", "Wazuh — Brute Force", "frequency", ".ds-wazuh-alerts-4.x-*", ":hammer:", "*[ENDPOINT] Brute Force — {9} → {1}*\nAttacker: {9} | User: {10}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], [{"match": {"rule.groups": "authentication_failed"}}, {"range": {"rule.level": {"gte": 7}}}, {"exists": {"field": "data.srcip"}}], num_events=8)
write_rule("fim_alert.yaml", "Wazuh — File Integrity", "any", ".ds-wazuh-alerts-4.x-*", ":file_folder:", "*[SYSTEM] File Change — {1}*\nFile: {6}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path"], [{"match": {"rule.groups": "syscheck"}}, {"exists": {"field": "syscheck.path"}}])
write_rule("agent_status.yaml", "Wazuh — Agent Status", "any", ".ds-wazuh-alerts-4.x-*", ":satellite_antenna:", "*[SYSTEM] Agent Status — {1}*\nStatus: {3}", ["@timestamp", "agent.name", "agent.ip", "data.status"], [{"match": {"rule.id": "501"}}])
write_rule("oom_alert.yaml", "Wazuh — OOM Critical", "any", ".ds-wazuh-alerts-4.x-*", ":skull:", "*[SYSTEM] OOM Killer — {1}*\n🚨 Out of Memory Event", ["@timestamp", "agent.name", "agent.ip", "rule.description"], [{"match": {"rule.id": "100100"}}])
write_rule("yara_match.yaml", "YARA — Malware Match", "any", ".ds-wazuh-alerts-4.x-*", ":bug:", "*[SECURITY] YARA Match — {1}*\nRule: {6}", ["@timestamp", "agent.name", "agent.ip", "rule.description", "rule.id", "rule.level", "data.yara_rule"], [{"match": {"rule.id": "100200"}}])
write_rule("suricata_alert.yaml", "Suricata — IDS Alert", "any", "suricata-alerts-*", ":shield:", "*[SECURITY] IDS Alert — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"event_type": "alert"}}])
write_rule("dns_exfil.yaml", "Suricata — DNS Tunneling", "any", "suricata-alerts-*", ":satellite:", "*[SECURITY] DNS Tunnel — {4}*\nQuery: {6}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dns.query"], [{"match": {"alert.signature": "DNS"}}])
write_rule("port_scan.yaml", "Suricata — Port Scan", "any", "suricata-alerts-*", ":mag:", "*[SECURITY] Port Scan — {4} → {6}*", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"alert.signature": "Scan"}}])
write_rule("web_attacks.yaml", "Wazuh — Web Attack", "any", ".ds-wazuh-alerts-4.x-*", ":spider_web:", "*[SECURITY] Web Attack — {9} → {1}*\nSignature: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip"], [{"match": {"rule.groups": "web"}}])
