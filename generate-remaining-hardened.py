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

SEC = "*[SECURITY] {0} — {1} → {2}*\nAttacker: {1} | User: {3}\nMITRE: {4}"
SYS = "*[SYSTEM] {0} — {1}*\nEvent: {2}\nDetails: {3}"

# --- THE MISSING 10 ---
write_rule("suricata_alert.yaml", "Suricata — C2 Beaconing", "any", "suricata-alerts-*", ":satellite:", SEC.format("C2 Beaconing", "{4}", "{6}", "N/A", "{1}"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], ["src_ip"])
write_rule("dns_exfil.yaml", "Suricata — DNS Exfil", "any", "suricata-alerts-*", ":satellite_antenna:", SYS.format("DNS Exfiltration", "{4}", "Tunneling detected", "{1}"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], ["src_ip"])
write_rule("ftp_brute.yaml", "Suricata — FTP Brute Force", "any", "suricata-alerts-*", ":file_folder:", SEC.format("FTP Brute", "{4}", "{6}", "N/A", "{1}"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], ["src_ip"])
write_rule("mqtt_anomaly.yaml", "IoT — MQTT Anomaly", "any", "suricata-alerts-*", ":robot_face:", SYS.format("MQTT Anomaly", "{4}", "{1}", "IoT Risk"), ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], ["src_ip"])
write_rule("misp_match.yaml", "Threat Intel — MISP Match", "any", "suricata-alerts-*", ":red_circle:", "*[THREAT-INTEL] MISP Match — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], ["src_ip"])
write_rule("failed_login.yaml", "Wazuh — Failed Login", "any", ".ds-wazuh-alerts-4.x-*", ":lock:", SEC.format("Failed Login", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], ["data.dstuser"])
write_rule("priv_esc.yaml", "Wazuh — Priv Escalation", "any", ".ds-wazuh-alerts-4.x-*", ":arrow_double_up:", SEC.format("Priv-Esc", "N/A", "{1}", "{9}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.dstuser"], ["data.dstuser"])
write_rule("webshell_indicator.yaml", "Wazuh — Webshell", "any", ".ds-wazuh-alerts-4.x-*", ":ghost:", "*[ENDPOINT] Webshell Indicator — {1}*\n🚨 CRITICAL ALERT", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], ["agent.name"])
write_rule("high_risk.yaml", "Wazuh — High Risk", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", SEC.format("High Risk", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], ["data.srcip"])
write_rule("lateral_movement.yaml", "Wazuh — Lateral Movement", "any", ".ds-wazuh-alerts-4.x-*", ":left_right_arrow:", SEC.format("Lateral Movement", "{9}", "{1}", "{10}", "{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], ["data.srcip"])
