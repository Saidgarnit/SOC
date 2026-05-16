#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def get_rule(name, type, index, icon, msg, args):
    # Ensure all lines in msg are indented by 2 spaces for YAML block |
    indented_msg = "\n".join(f"  {line}" for line in msg.split("\n"))
    return f"""name: "{name}"
type: {type}
index: {index}
num_events: 1
timeframe: {{ minutes: 5 }}
filter:
- query:
    bool:
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

# Re-defining the rules with correct indentation
rules = {
    "port_scan.yaml": ("Suricata — Port Scan", "any", "suricata-alerts-*", ":telescope:", "*[NETWORK] Port Scan — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"]),
    "suricata_alert.yaml": ("Suricata — C2 Beaconing", "any", "suricata-alerts-*", ":satellite:", "*[NETWORK] C2 Beaconing — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"]),
    "brute_force.yaml": ("Wazuh — Brute Force", "frequency", ".ds-wazuh-alerts-4.x-*", ":hammer:", "*[ENDPOINT] Brute Force — {9} → {1}*\nAttacker: {9} | User: {10}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"]),
    "fim_alert.yaml": ("Wazuh — File Integrity", "any", ".ds-wazuh-alerts-4.x-*", ":file_folder:", "*[ENDPOINT] File Change — {1} → {6}*\nFile: {6}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path"]),
    "web_attacks.yaml": ("Wazuh — Web Attack", "any", ".ds-wazuh-alerts-4.x-*", ":spider_web:", "*[ENDPOINT] Web Attack — {1}*\nAttack: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip"]),
    "webshell_indicator.yaml": ("Wazuh — Webshell", "any", ".ds-wazuh-alerts-4.x-*", ":ghost:", "*[ENDPOINT] Webshell — {1}*\n🚨 CRITICAL INDICATOR", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"]),
    "malware_hash.yaml": ("VirusTotal — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":biohazard_sign:", "*[MALWARE] VT Match — {1}*\nDetections: {6}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "vt_malicious"]),
    "yara_match.yaml": ("YARA — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":skull_and_crossbones:", "*[MALWARE] YARA Match — {1}*\nSignature: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"]),
}

os.makedirs("elastalert/rules", exist_ok=True)
for file, data in rules.items():
    with open(os.path.join("elastalert/rules", file), "w") as f:
        f.write(get_rule(*data))
    print(f"Generated {file}")
