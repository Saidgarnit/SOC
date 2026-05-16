#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def get_rule(name, type, index, icon, msg, args):
    return f"""name: "{name}"
type: {type}
index: {index}
filter:
- query:
    bool:
      must_not:
      - terms: {{ src_ip: {SOC_IPS} }}
alert: ["slack"]
alert_text: |
  {msg}
alert_text_type: alert_text_only
alert_text_args: {args}
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: "{icon}"
"""

rules = {
    "ftp_brute.yaml": ("Suricata — FTP Brute Force", "any", "suricata-alerts-*", ":file_folder:", "*[NETWORK] FTP Brute Force — {4} → {6}*", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"]),
    "mqtt_anomaly.yaml": ("IoT — MQTT Anomaly", "any", "suricata-alerts-*", ":robot_face:", "*[IOT] MQTT Anomaly — {4} → {6}*", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"]),
    "misp_match.yaml": ("Threat Intel — MISP Match", "any", "suricata-alerts-*", ":red_circle:", "*[THREAT-INTEL] MISP IOC Match — {4} → {6}*", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"]),
    "failed_login.yaml": ("Wazuh — Failed Login", "any", ".ds-wazuh-alerts-4.x-*", ":lock:", "*[ENDPOINT] Failed Login — {1}*\nUser: {10}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"]),
    "priv_esc.yaml": ("Wazuh — Priv Escalation", "any", ".ds-wazuh-alerts-4.x-*", ":arrow_double_up:", "*[ENDPOINT] Priv-Esc — {1}*\nUser: {9}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.dstuser"]),
    "agent_status.yaml": ("Wazuh — Agent Status", "any", ".ds-wazuh-alerts-4.x-*", ":computer:", "*[SYSTEM] Agent Status — {1}*", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"]),
    "high_risk.yaml": ("Wazuh — High Risk", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", "*[CRITICAL] High Risk — {1}*", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"]),
}

os.makedirs("elastalert/rules", exist_ok=True)
for file, data in rules.items():
    with open(os.path.join("elastalert/rules", file), "w") as f:
        f.write(get_rule(*data))
    print(f"Generated {file}")
