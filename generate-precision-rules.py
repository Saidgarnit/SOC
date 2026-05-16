#!/usr/bin/env python3
import os

WEBHOOK = "https://hooks.slack.com/services/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"
SOC_IPS = ["172.18.0.2", "172.18.0.3", "172.18.0.4", "172.18.0.5", "172.18.0.7", "172.18.0.8", "172.18.0.20", "172.18.0.21", "172.18.0.22", "172.18.0.24", "172.18.0.25", "172.18.0.26", "172.18.0.27", "172.18.0.28", "172.18.0.29", "172.18.0.31", "172.18.0.1"]

def write_rule(filename, name, type, index, icon, msg, args, must_match=[], must_exist=[]):
    indented_msg = "\n".join(f"  {line}" for line in msg.split("\n"))
    
    # CORE LOGIC: Every rule must have a "must_match" block (e.g. rule.id or event_type)
    must_blocks = must_match + [{"exists": {"field": f}} for f in must_exist]
    
    content = f"""name: "{name}"
type: {type}
index: {index}
num_events: 1
timeframe: {{ minutes: 5 }}
realert: {{ minutes: 10 }}
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

# --- THE PRECISION SET ---

# 1. Port Scan (Must be an alert)
write_rule("port_scan.yaml", "Suricata — Port Scan", "any", "suricata-alerts-*", ":telescope:", "*[NETWORK] Port Scan — {4} → {6}*\nSignature: {1}", ["@timestamp", "alert.signature", "alert.severity", "alert.category", "src_ip", "src_port", "dest_ip", "dest_port"], [{"match": {"event_type": "alert"}}, {"match_phrase": {"alert.signature": "Port Scan"}}], ["alert.signature"])

# 2. OOM (Must be Wazuh Rule 5108 or 5112)
write_rule("oom_alert.yaml", "Wazuh — OOM Critical", "any", ".ds-wazuh-alerts-4.x-*", ":rotating_light:", "*[SYSTEM] Memory Critical — {1}*\nEvent: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"terms": {"rule.id": ["5108", "5112"]}}])

# 3. YARA (Must have 'yara' in the group)
write_rule("yara_match.yaml", "YARA — Malware", "any", ".ds-wazuh-alerts-4.x-*", ":skull_and_crossbones:", "*[MALWARE] YARA Match — {1}*\nSignature: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"match": {"rule.groups": "yara"}}])

# 4. FIM (Must have 'syscheck' in the group)
write_rule("fim_alert.yaml", "Wazuh — File Integrity", "any", ".ds-wazuh-alerts-4.x-*", ":file_folder:", "*[SYSTEM] File Change — {1}*\nFile: {6}\nAction: {7}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "syscheck.path", "syscheck.event"], [{"match": {"rule.groups": "syscheck"}}])

# 5. Agent Status (Must be Wazuh Rule 501 or 506)
write_rule("agent_status.yaml", "Wazuh — Agent Status", "any", ".ds-wazuh-alerts-4.x-*", ":computer:", "*[SYSTEM] Agent Change — {1}*\nStatus: {5}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description"], [{"terms": {"rule.id": ["501", "506"]}}])

# 6. Failed Logins (Rule Group: authentication_failed)
write_rule("failed_login.yaml", "Wazuh — Failed Login", "any", ".ds-wazuh-alerts-4.x-*", ":lock:", "*[ENDPOINT] Failed Login — {1}*\nUser: {10}", ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id", "rule.description", "rule.mitre.tactic", "rule.mitre.technique", "rule.mitre.id", "data.srcip", "data.dstuser"], [{"match": {"rule.groups": "authentication_failed"}}])

