#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def get_rule(name, type, index, icon, msg, args, must_exist=[]):
    indented_msg = "\n".join(f"  {line}" for line in msg.split("\n"))
    # Filter for existence to avoid noise
    filter_blocks = [{"exists": {"field": f}} for f in must_exist]
    
    return f"""name: "{name}"
type: {type}
index: {index}
num_events: 1
timeframe: {{ minutes: 5 }}
realert: {{ minutes: 15 }}
filter:
- query:
    bool:
      must: {filter_blocks}
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

rules = {}

# --- STYLE A: SECURITY ALERTS (With Attacker/User) ---
SECURITY_MSG = "*[SECURITY] {name} — {src} → {host}*\nAttacker: {src} | User: {user}\nMITRE: {mitre}"
rules["brute_force.yaml"] = ("Wazuh — Brute Force", "frequency", ".ds-wazuh-alerts-4.x-*", ":hammer:", SECURITY_MSG.format(name="Auth Brute Force", src="{9}", host="{1}", user="{10}", mitre="{8}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], ["data.srcip"])

# --- STYLE B: SYSTEM ALERTS (Clean, No Missing Values) ---
SYSTEM_MSG = "*[SYSTEM] {name} — {host}*\nEvent: {desc}\nDetails: {details}"
rules["fim_alert.yaml"] = ("Wazuh — File Integrity", "any", ".ds-wazuh-alerts-4.x-*", ":file_folder:", SYSTEM_MSG.format(name="File Change", host="{1}", desc="{5}", details="{6}"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path"], ["syscheck.path"])

rules["oom_alert.yaml"] = ("Wazuh — OOM Critical", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", SYSTEM_MSG.format(name="Memory Exhaustion", host="{1}", desc="{5}", details="System Health Risk"), ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [])

# (Applying the same logic to all 18 rules...)

os.makedirs("elastalert/rules", exist_ok=True)
for file, data in rules.items():
    with open(os.path.join("elastalert/rules", file), "w") as f:
        f.write(get_rule(*data))

# Final Gmail Master (Generic Template to handle both types)
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
smtp_ssl: false
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"
alert_text: |
  [CRITICAL] {0}
  Host: {1} ({2})
  Event: {4}
  
  Please check Kibana for full forensic details.
alert_text_args: ["rule.description", "agent.name", "agent.ip", "rule.level", "rule.id"]
""")
