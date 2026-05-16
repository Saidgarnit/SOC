#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def write_rule(filename, name, type, index, icon, msg, args, must_match=[], must_exist=[]):
    indented_msg = "\n".join(f"  {line}" for line in msg.split("\n"))
    must_blocks = must_match + [{"exists": {"field": f}} for f in must_exist]
    
    content = f"""name: "{name}"
type: {type}
index: {index}
num_events: 1
timeframe: {{ minutes: 5 }}
realert: {{ minutes: 15 }}
filter:
- query:
    bool:
      must: {must_blocks}
      must_not:
      - terms: {{ src_ip: {SOC_IPS} }}
alert: ["slack"]
alert_text_type: alert_text_only
alert_text: |
{indented_msg}
alert_text_args: {args}
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: "{icon}"
"""
    with open(f"elastalert/rules/{filename}", "w") as f:
        f.write(content)
    print(f"Generated {filename}")

os.makedirs("elastalert/rules", exist_ok=True)

# --- NETWORK (SURICATA) - PRECISION ---
write_rule("port_scan.yaml", "Suricata — Port Scan", "any", "suricata-alerts-*", ":telescope:", "*[NETWORK] Port Scan — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"event_type": "alert"}}, {"match_phrase": {"alert.signature": "Port Scan"}}], ["alert.signature"])
write_rule("suricata_alert.yaml", "Suricata — C2 Beaconing", "any", "suricata-alerts-*", ":satellite:", "*[NETWORK] C2 Beaconing — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"event_type": "alert"}}, {"match_phrase": {"alert.signature": "C2 Beaconing"}}], ["alert.signature"])
write_rule("dns_exfil.yaml", "Suricata — DNS Exfil", "any", "suricata-alerts-*", ":satellite_antenna:", "*[NETWORK] DNS Exfiltration — {4}*", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"event_type": "alert"}}, {"match_phrase": {"alert.signature": "DNS Exfil"}}])

# --- ENDPOINT (WAZUH) - PRECISION ---
write_rule("brute_force.yaml", "Wazuh — Brute Force", "frequency", ".ds-wazuh-alerts-4.x-*", ":hammer:", "*[ENDPOINT] Brute Force — {9} → {1}*\nAttacker: {9} | User: {10}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], [{"match": {"rule.groups": "authentication_failed"}}, {"range": {"rule.level": {"gte": 7}}}], ["data.srcip"])
write_rule("fim_alert.yaml", "Wazuh — File Integrity", "any", ".ds-wazuh-alerts-4.x-*", ":file_folder:", "*[SYSTEM] File Change — {1}*\nFile: {6}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path"], [{"match": {"rule.groups": "syscheck"}}], ["syscheck.path"])
write_rule("web_attacks.yaml", "Wazuh — Web Attack", "any", ".ds-wazuh-alerts-4.x-*", ":spider_web:", "*[ENDPOINT] Web Attack — {1}*\nAttack: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip"], [{"match": {"rule.groups": "web"}}, {"range": {"rule.level": {"gte": 7}}}], ["data.srcip"])
write_rule("oom_alert.yaml", "Wazuh — OOM Critical", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", "*[SYSTEM] Memory Critical — {1}*\nEvent: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"terms": {"rule.id": ["5108", "5112"]}}])
write_rule("yara_match.yaml", "YARA — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":skull_and_crossbones:", "*[MALWARE] YARA Match — {1}*\nSignature: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"match": {"rule.groups": "yara"}}])
write_rule("agent_status.yaml", "Wazuh — Agent Status", "any", ".ds-wazuh-alerts-4.x-*", ":computer:", "*[SYSTEM] Agent Change — {1}*\nStatus: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"terms": {"rule.id": ["501", "506"]}}])

# --- GMAIL (PRECISE) ---
with open("elastalert/rules/gmail_critical_master.yaml", "w") as f:
    f.write("""name: "CRITICAL Gmail Notification"
type: any
index: .ds-wazuh-alerts-4.x-*
filter:
- range: { rule.level: { gte: 12 } }
alert: ["email"]
email: ["garnitsaid01@gmail.com"]
from_addr: "garnitsaid01@gmail.com"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"
alert_text: "[CRITICAL] {0} on {1}\\nCheck Kibana for details."
alert_text_args: ["rule.description", "agent.name"]
""")

