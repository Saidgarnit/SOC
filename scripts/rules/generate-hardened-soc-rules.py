#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def write_rule(filename, name, type, index, icon, msg, args, must_exist=[]):
    indented_msg = "\n".join(f"  {line}" for line in msg.split("\n"))
    exists_blocks = [{"exists": {"field": f}} for f in must_exist]
    content = f"""name: "{name}"
type: {type}
index: {index}
num_events: 1
timeframe: {{ minutes: 5 }}
realert: {{ minutes: 15 }}
filter:
- query:
    bool:
      must: {exists_blocks}
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

# --- STYLE A: SECURITY (Attacker/User) ---
SEC = "*[SECURITY] {0} — {1} → {2}*\nAttacker: {1} | User: {3}\nMITRE: {4}"
write_rule("brute_force.yaml", "Wazuh — Brute Force", "frequency", ".ds-wazuh-alerts-4.x-*", ":hammer:", SEC.format("Brute Force", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], ["data.srcip"])
write_rule("port_scan.yaml", "Suricata — Port Scan", "any", "suricata-alerts-*", ":telescope:", SEC.format("Port Scan", "{4}", "{6}", "N/A", "{1}"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], ["src_ip"])
write_rule("web_attacks.yaml", "Wazuh — Web Attack", "any", ".ds-wazuh-alerts-4.x-*", ":spider_web:", SEC.format("Web Attack", "{9}", "{1}", "N/A", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip"], ["data.srcip"])

# --- STYLE B: SYSTEM (Host/Details) ---
SYS = "*[SYSTEM] {0} — {1}*\nEvent: {2}\nDetails: {3}"
write_rule("fim_alert.yaml", "Wazuh — File Integrity", "any", ".ds-wazuh-alerts-4.x-*", ":file_folder:", SYS.format("File Change", "{1}", "{5}", "{6}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path"], ["syscheck.path"])
write_rule("oom_alert.yaml", "Wazuh — OOM Critical", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", SYS.format("Memory Critical", "{1}", "{5}", "System at Risk"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"])
write_rule("agent_status.yaml", "Wazuh — Agent Status", "any", ".ds-wazuh-alerts-4.x-*", ":computer:", SYS.format("Agent Change", "{1}", "{5}", "Status Update"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"])

# --- STYLE C: MALWARE ---
MAL = "*[MALWARE] {0} — {1}*\nDetections: {2}\nAction: Immediate Investigation"
write_rule("malware_hash.yaml", "VirusTotal — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":biohazard_sign:", MAL.format("VT Match", "{1}", "{6}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "vt_malicious"], ["vt_malicious"])
write_rule("yara_match.yaml", "YARA — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":skull_and_crossbones:", MAL.format("YARA Match", "{1}", "{5}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], ["rule.groups"])

# Final Gmail Master
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
alert_text: "[CRITICAL] {0} on {1}\\nDescription: {2}\\nCheck Kibana: http://localhost:5601"
alert_text_args: ["rule.description", "agent.name", "rule.description"]
""")
