#!/usr/bin/env python3
import os

# CONFIGURATION
WEBHOOK = "https://hooks.slack.com/services/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"
DIR = "elastalert/rules"

# SOC Infrastructure IPs - Whitelist
SOC_INFRASTRUCTURE = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]
soc_whitelist = "\n".join(f'          - "{ip}"' for ip in SOC_INFRASTRUCTURE)

rules = {}

# --- NETWORK RULES (SURICATA) ---
rules["port_scan.yaml"] = f"""name: "Suricata — Port Scan"
type: frequency
index: suricata-alerts-*
num_events: 20
timeframe: {{ seconds: 20 }}
realert: {{ hours: 1 }}
query_key: src_ip
filter:
- query:
    bool:
      must:
      - match: {{ event_type: alert }}
      - bool:
          should:
          - match_phrase: {{ alert.signature: "Port Scan SYN" }}
          - match_phrase: {{ alert.signature: "Port Scan" }}
          minimum_should_match: 1
      must_not:
      - terms: {{ src_ip: [{", ".join(f'"{ip}"' for ip in SOC_INFRASTRUCTURE)}] }}
alert: ["slack"]
alert_text: |
  *[NETWORK] Port Scan — {{4}} → {{6}}*
  SURICATA IDS ALERT
  Signature: {{1}} | Severity: {{2}}
  Attacker: {{4}}:{{5}} | Target: {{6}}:{{7}}
alert_text_type: alert_text_only
alert_text_args: ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port", "proto"]
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: ":telescope:"
"""

rules["suricata_alert.yaml"] = f"""name: "Suricata — C2 Beaconing"
type: any
index: suricata-alerts-*
realert: {{ hours: 1 }}
filter:
- query:
    bool:
      must:
      - match_phrase: {{ alert.signature: "C2 Beaconing" }}
alert: ["slack"]
alert_text: |
  *[NETWORK] C2 Beaconing — {{4}} → {{6}}*
  SURICATA IDS ALERT
  Signature: {{1}}
  C2 Server: {{6}}:{{7}}
alert_text_type: alert_text_only
alert_text_args: ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"]
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: ":satellite:"
"""

# --- ENDPOINT RULES (WAZUH) ---
rules["fim_alert.yaml"] = f"""name: "Wazuh — File Integrity"
type: any
index: .ds-wazuh-alerts-4.x-*
filter:
- query:
    bool:
      must:
      - terms: {{ rule.groups: ["syscheck"] }}
alert: ["slack"]
alert_text: |
  *[ENDPOINT] File Change — {{1}} → {{6}}*
  WAZUH FIM ALERT
  File: {{6}} | Event: {{7}}
alert_text_type: alert_text_only
alert_text_args: ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path", "syscheck.event"]
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: ":file_folder:"
"""

rules["brute_force.yaml"] = f"""name: "Wazuh — Auth Brute Force"
type: frequency
index: .ds-wazuh-alerts-4.x-*
num_events: 10
timeframe: {{ minutes: 5 }}
query_key: ["agent.name", "data.srcip"]
filter:
- query:
    bool:
      must:
      - terms: {{ rule.groups: ["authentication_failed"] }}
alert: ["slack"]
alert_text: |
  *[ENDPOINT] Auth Brute Force — {{9}} → {{1}}*
  WAZUH AUTHENTICATION ALERT
  Attacker: {{9}} | User: {{10}}
alert_text_type: alert_text_only
alert_text_args: ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"]
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: ":hammer:"
"""

rules["web_attacks.yaml"] = f"""name: "Wazuh — Web Attack"
type: any
index: .ds-wazuh-alerts-4.x-*
filter:
- query:
    bool:
      must:
      - terms: {{ rule.groups: ["web"] }}
      - range: {{ rule.level: {{ gte: 7 }} }}
alert: ["slack"]
alert_text: |
  *[ENDPOINT] Web Attack — {{1}} from {{9}}*
  WAZUH WEB ALERT
  Attack: {{5}}
alert_text_type: alert_text_only
alert_text_args: ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip"]
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: ":spider_web:"
"""

rules["webshell_indicator.yaml"] = f"""name: "Wazuh — Webshell"
type: any
index: .ds-wazuh-alerts-4.x-*
filter:
- query:
    bool:
      must:
      - terms: {{ rule.groups: ["web"] }}
      - range: {{ rule.level: {{ gte: 10 }} }}
alert: ["slack"]
alert_text: |
  *[ENDPOINT] Webshell Indicator — {{1}}*
  🚨 CRITICAL WEBSHELL ALERT
  Agent: {{1}} | Path: {{5}}
alert_text_type: alert_text_only
alert_text_args: ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"]
slack_webhook_url: "{WEBHOOK}"
slack_icon_emoji: ":ghost:"
"""

# WRITE ALL
os.makedirs(DIR, exist_ok=True)
for filename, content in rules.items():
    with open(os.path.join(DIR, filename), 'w') as f:
        f.write(content)
    print(f"  ✓ {filename} generated.")
