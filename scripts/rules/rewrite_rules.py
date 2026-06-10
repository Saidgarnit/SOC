#!/usr/bin/env python3
"""
Complete ElastAlert rules rewrite.
Run from ~/soc-stack:  python3 /tmp/rewrite_rules.py
"""
import os

WEBHOOK = "https://hooks.slack.com/services/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"
EMAIL   = "garnitsaid01@gmail.com"
DIR     = "elastalert/rules"

# ── All internal SOC IPs (confirmed from docker network inspect) ───────
# Port scan rule excludes these so internal SOC traffic never triggers
INTERNAL = [
    "172.18.0.1",  # gateway
    "172.18.0.2",  # wazuh-manager
    "172.18.0.3",  # opencti-redis
    "172.18.0.4",  # filebeat
    "172.18.0.5",  # elastalert
    "172.18.0.6",  # victim-dns
    "172.18.0.7",  # misp-db
    "172.18.0.8",  # yara-scanner
    "172.18.0.9",  # memcached
    "172.18.0.10", # misp-redis
    "172.18.0.11", # victim-webapi
    "172.18.0.12", # victim-database
    "172.18.0.13", # rabbitmq
    "172.18.0.14", # kali-attacker
    "172.18.0.15", # minio
    "172.18.0.16", # fleet-server
    "172.18.0.17", # victim-dvwa
    "172.18.0.18", # victim-mail
    "172.18.0.19", # victim-windows
    "172.18.0.20", # victim-jenkins
    "172.18.0.21", # victim-ubuntu
    "172.18.0.22", # elasticsearch
    "172.18.0.23", # victim-metasploitable
    "172.18.0.24", # victim-iot
    "172.18.0.25", # victim-ftp
    "172.18.0.26", # logstash
    "172.18.0.27", # misp
    "172.18.0.28", # kibana
    "172.18.0.29", # connector-mitre
    "172.18.0.30", # opencti
    "172.18.0.31", # vt-enricher
    "172.18.0.32", # opencti-worker
    "172.18.0.33", # connector-misp
    "172.18.0.34", # opencti-worker (alt)
]

ip_list = "\n".join(f'          - "{ip}"' for ip in INTERNAL)

# Known legit C2-like destinations (Ubuntu update servers, AWS, CDN)
C2_WHITELIST = [
    "91.189.91.83", "91.189.91.84", "91.189.92.24",
    "34.120.127.130", "34.95.113.255", "34.54.88.138",
    "199.232.82.217", "76.223.57.73",
    "18.134.215.41", "18.169.61.189", "18.169.120.191", "18.168.172.238",
    "3.33.241.96", "99.84.9.2", "185.125.190.81",
]
c2_wl = "\n".join(f'          - "{ip}"' for ip in C2_WHITELIST)

rules = {}

# ════════════════════════════════════════════════════════════════════════
# SURICATA RULES  (index: suricata-alerts-*)
# Fields: src_ip, src_port, dest_ip, dest_port, proto, in_iface,
#         alert.signature, alert.severity, alert.category,
#         alert.action, community_id
# ════════════════════════════════════════════════════════════════════════

# ── 1. Port Scan ─────────────────────────────────────────────────────
rules["port_scan.yaml"] = f"""name: "🔍 Port Scan — Network Reconnaissance"
type: frequency
index: suricata-alerts-*
num_events: 10
timeframe:
  seconds: 10
realert:
  hours: 1
query_key: src_ip
filter:
- query:
    bool:
      must:
      - match:
          event_type: alert
      - bool:
          should:
          - match_phrase:
              alert.signature: "Port Scan SYN"
          - match_phrase:
              alert.signature: "Port Scan"
          minimum_should_match: 1
      must_not:
      - terms:
          src_ip:
{ip_list}

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🔍 *Port Scan Detected*
  `SURICATA / Network Reconnaissance`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Attacker  {{4}} : {{5}}
  🔵 Target    {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  🔗 T1595 — Active Scanning
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":mag:"
slack_msg_color: warning
"""

# ── 2. C2 Beaconing ──────────────────────────────────────────────────
rules["suricata_alert.yaml"] = f"""name: "📡 C2 Beaconing — Command & Control"
type: frequency
index: suricata-alerts-*
num_events: 3
timeframe:
  minutes: 10
realert:
  hours: 2
query_key:
- src_ip
- dest_ip
filter:
- query:
    bool:
      must:
      - match_phrase:
          alert.signature: "C2 Beaconing"
      must_not:
      - terms:
          src_ip:
{ip_list}
      - terms:
          dest_ip:
{c2_wl}

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  📡 *C2 Beaconing Detected*
  `SURICATA / Command & Control`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Infected   {{4}} : {{5}}
  🔵 C2 Server  {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  🔗 T1071 — Application Layer Protocol
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":satellite:"
slack_msg_color: danger
"""

# ── 3. Network Brute Force ────────────────────────────────────────────
rules["suricata_brute_force.yaml"] = f"""name: "💥 Network Brute Force — SSH/RDP/FTP"
type: frequency
index: suricata-alerts-*
num_events: 8
timeframe:
  minutes: 3
realert:
  minutes: 45
query_key:
- src_ip
- dest_ip
filter:
- query:
    bool:
      must:
      - match:
          event_type: alert
      - bool:
          should:
          - match_phrase:
              alert.signature: "SSH Brute Force"
          - match_phrase:
              alert.signature: "RDP Brute Force"
          - match_phrase:
              alert.signature: "FTP Brute Force"
          minimum_should_match: 1

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  💥 *Network Brute Force*
  `SURICATA / Credential Attack`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Attacker  {{4}} : {{5}}
  🔵 Target    {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  🔗 T1110 — Brute Force
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":lock:"
slack_msg_color: danger
"""

# ── 4. DNS Exfiltration ───────────────────────────────────────────────
rules["dns_exfiltration.yaml"] = f"""name: "🛸 DNS Exfiltration — Data Exfil"
type: any
index: suricata-alerts-*
realert:
  hours: 1
query_key: src_ip
filter:
- query:
    bool:
      must:
      - match:
          event_type: alert
      - bool:
          should:
          - match_phrase:
              alert.signature: "DNS Exfil"
          - match_phrase:
              alert.signature: "DNS Tunneling"
          minimum_should_match: 1

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🛸 *DNS Exfiltration Detected*
  `SURICATA / Data Exfiltration`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Source     {{4}} : {{5}}
  🔵 DNS Server {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  🔗 T1048 — Exfiltration Over Alt Protocol
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":satellite_antenna:"
slack_msg_color: danger
"""

# ── 5. FTP Brute Force ────────────────────────────────────────────────
rules["ftp_bruteforce.yaml"] = f"""name: "📁 FTP Brute Force — Credential Attack"
type: frequency
index: suricata-alerts-*
num_events: 5
timeframe:
  minutes: 2
realert:
  minutes: 30
query_key:
- src_ip
- dest_ip
filter:
- query:
    bool:
      must:
      - match:
          event_type: alert
      - match_phrase:
          alert.signature: "FTP Brute Force"

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  📁 *FTP Brute Force*
  `SURICATA / Credential Attack`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Attacker    {{4}} : {{5}}
  🔵 FTP Server  {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  🔗 T1110.001 — Password Guessing
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":file_cabinet:"
slack_msg_color: danger
"""

# ── 6. MQTT Anomaly ───────────────────────────────────────────────────
rules["mqtt_anomaly.yaml"] = f"""name: "🤖 MQTT Anomaly — IoT Attack"
type: any
index: suricata-alerts-*
realert:
  minutes: 30
query_key: src_ip
filter:
- query:
    bool:
      must:
      - match:
          event_type: alert
      - match_phrase:
          alert.signature: "MQTT"

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🤖 *MQTT Anomaly Detected*
  `SURICATA / IoT Threat`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Source   {{4}} : {{5}}
  🔵 Broker   {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  🔗 T1071.001 — Application Layer Protocol
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":robot_face:"
slack_msg_color: warning
"""

# ── 7. MISP IOC Match ─────────────────────────────────────────────────
rules["misp_alert.yaml"] = f"""name: "🎯 MISP IOC Match — Threat Intel"
type: any
index: suricata-alerts-*
realert:
  hours: 2
query_key: src_ip
filter:
- query:
    bool:
      must:
      - exists:
          field: misp_event_id

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🎯 *MISP Threat Intel Match*
  `THREAT INTELLIGENCE / IOC Hit`

  🕐 `{{0}}`
  📋 Rule: {{1}}  Severity: {{2}}

  🔴 Source  {{4}} : {{5}}
  🔵 Target  {{6}} : {{7}}
  📡 {{8}}  via  {{9}}

  ⚠️  Known Bad Actor — Investigate Now
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- alert.signature
- alert.severity
- alert.category
- src_ip
- src_port
- dest_ip
- dest_port
- proto
- in_iface

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":red_circle:"
slack_msg_color: danger
"""

# ════════════════════════════════════════════════════════════════════════
# WAZUH RULES  (index: .ds-wazuh-alerts-4.x-*)
# Fields: agent.name, agent.ip, rule.level, rule.id, rule.description,
#         rule.mitre.tactic, rule.mitre.technique, rule.mitre.id,
#         data.srcip, data.dstuser, full_log,
#         syscheck.* (FIM only), vt_* (VT only)
# ════════════════════════════════════════════════════════════════════════

# ── 8. FIM ────────────────────────────────────────────────────────────
rules["fim_alert.yaml"] = f"""name: "📂 File Integrity — FIM Alert"
type: frequency
index: .ds-wazuh-alerts-4.x-*
num_events: 1
timeframe:
  minutes: 5
realert:
  minutes: 30
query_key: agent.name
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - syscheck
      must_not:
      - wildcard:
          syscheck.path: "/tmp/*"
      - wildcard:
          syscheck.path: "/proc/*"
      - wildcard:
          syscheck.path: "/run/*"
      - wildcard:
          syscheck.path: "/sys/*"
      - wildcard:
          syscheck.path: "*/hsperfdata_*"
      - wildcard:
          syscheck.path: "*/.cache/*"

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  📂 *File Integrity Change*
  `WAZUH / File Integrity Monitor`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  📄 Path:    {{6}}
  🔄 Event:   {{7}}
  👤 Owner:   {{8}}
  🔒 Perms:   {{9}}
  📏 Size:    {{10}} bytes
  #️⃣  MD5:    `{{11}}`
  #️⃣  SHA256: `{{12}}`

  🔗 T1565 — Data Manipulation
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- syscheck.path
- syscheck.event
- syscheck.uname_after
- syscheck.perm_after
- syscheck.size_after
- syscheck.md5_after
- syscheck.sha256_after

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":open_file_folder:"
slack_msg_color: warning
"""

# ── 9. Auth Brute Force (Wazuh) ───────────────────────────────────────
rules["brute_force.yaml"] = f"""name: "🔨 Auth Brute Force — Wazuh"
type: frequency
index: .ds-wazuh-alerts-4.x-*
num_events: 8
timeframe:
  minutes: 3
realert:
  minutes: 45
query_key:
- agent.name
- data.srcip
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - authentication_failed

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🔨 *Authentication Brute Force*
  `WAZUH / Credential Attack`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔴 Attacker: {{9}}
  👤 Target:   {{10}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip
- data.dstuser

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":hammer:"
slack_msg_color: danger
"""

# ── 10. Failed Login ──────────────────────────────────────────────────
rules["failed_login.yaml"] = f"""name: "🔐 Failed Login — Wazuh"
type: frequency
index: .ds-wazuh-alerts-4.x-*
num_events: 5
timeframe:
  minutes: 2
realert:
  minutes: 20
query_key: agent.name
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - authentication_failed

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🔐 *Failed Login Attempts*
  `WAZUH / Authentication`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔴 Src IP: {{9}}
  👤 User:   {{10}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip
- data.dstuser

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":key:"
slack_msg_color: warning
"""

# ── 11. Privilege Escalation ──────────────────────────────────────────
rules["privilege_escalation.yaml"] = f"""name: "⬆️  Privilege Escalation — Wazuh"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  minutes: 15
query_key: agent.name
filter:
- query:
    bool:
      minimum_should_match: 1
      should:
      - terms:
          rule.groups:
          - priv_esc
      - terms:
          rule.groups:
          - sudo

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  ⬆️  *Privilege Escalation*
  `WAZUH / Privilege Abuse`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  👤 User: {{9}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.dstuser

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":arrow_double_up:"
slack_msg_color: danger
"""

# ── 12. High Risk ─────────────────────────────────────────────────────
rules["high_risk.yaml"] = f"""name: "🚨 High Risk Event — Level 13+"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  minutes: 20
query_key: agent.name
filter:
- query:
    bool:
      must:
      - range:
          rule.level:
            gte: 13

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🚨 *High Risk Event*
  `WAZUH / Critical Detection`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔴 Src:  {{9}}
  👤 User: {{10}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip
- data.dstuser

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":rotating_light:"
slack_msg_color: danger
"""

# ── 13. Lateral Movement ──────────────────────────────────────────────
rules["lateral_movement.yaml"] = f"""name: "↔️  Lateral Movement — Wazuh"
type: frequency
index: .ds-wazuh-alerts-4.x-*
num_events: 3
timeframe:
  minutes: 5
realert:
  minutes: 20
query_key: data.srcip
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - authentication_success
      - range:
          rule.level:
            gte: 8

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  ↔️  *Lateral Movement*
  `WAZUH / Persistence`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔴 From: {{9}}
  👤 As:   {{10}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip
- data.dstuser

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":left_right_arrow:"
slack_msg_color: warning
"""

# ── 14. Web Attack ────────────────────────────────────────────────────
rules["web_attacks.yaml"] = f"""name: "🕷️  Web Attack — Wazuh"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  minutes: 20
query_key: agent.name
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - web
      - range:
          rule.level:
            gte: 6

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🕷️  *Web Attack Detected*
  `WAZUH / Web Application`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔴 Attacker: {{9}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":spider_web:"
slack_msg_color: danger
"""

# ── 15. Webshell ──────────────────────────────────────────────────────
rules["webshell_indicator.yaml"] = f"""name: "👾 Webshell Indicator — Wazuh"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  minutes: 20
query_key: agent.name
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - web
      - range:
          rule.level:
            gte: 10

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  👾 *Webshell Indicator*
  `WAZUH / Post-Exploitation`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔴 Attacker: {{9}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  ⚠️  Immediate Investigation Required
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":ghost:"
slack_msg_color: danger
"""

# ── 16. YARA ──────────────────────────────────────────────────────────
rules["yara_critical.yaml"] = f"""name: "☣️  YARA Match — Malware"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  minutes: 20
query_key: agent.name
filter:
- query:
    bool:
      must:
      - terms:
          rule.groups:
          - yara

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  ☣️  *YARA Malware Match*
  `WAZUH / Malware Detection`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🎯 MITRE: {{8}} — {{6}} / {{7}}
  ⚠️  Malware Signature Detected
  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":skull_crossbones:"
slack_msg_color: danger
"""

# ── 17. VirusTotal ────────────────────────────────────────────────────
rules["vt_alert.yaml"] = f"""name: "🦠 VirusTotal — Malicious Hash"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  hours: 1
query_key: agent.name
filter:
- query:
    bool:
      must:
      - term:
          vt_checked: true
      - range:
          vt_malicious:
            gt: 0

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🦠 *VirusTotal Malicious Hash*
  `VIRUSTOTAL / Malware Enrichment`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  🔬 Detections: {{6}} engines
  📊 Risk Score: {{7}}
  ⚠️  Severity:  {{8}}

  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- vt_malicious
- vt_risk_score
- vt_severity

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":biohazard_sign:"
slack_msg_color: danger
"""

# ── 18. Agent Status ──────────────────────────────────────────────────
rules["agent_status.yaml"] = f"""name: "🖥️  Agent Status Change — Wazuh"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  hours: 4
query_key: agent.name
filter:
- query:
    bool:
      should:
      - term:
          rule.id: "506"
      - term:
          rule.id: "501"
      minimum_should_match: 1

alert:
- slack
alert_text_type: alert_text_only
alert_text: |
  🖥️  *Agent Status Change*
  `WAZUH / System`

  🕐 `{{0}}`
  🖥️  Host: {{1}}  ({{2}})
  📋 Level: {{3}}  Rule: {{4}}
  📝 {{5}}

  📊 http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description

slack_webhook_url: "{WEBHOOK}"
slack_username_override: "SOC Alerts"
slack_icon_emoji: ":desktop_computer:"
slack_msg_color: warning
"""

# ── 19. Gmail Critical ────────────────────────────────────────────────
rules["gmail_critical_master.yaml"] = f"""name: "📧 CRITICAL — Gmail Notification"
type: any
index: .ds-wazuh-alerts-4.x-*
realert:
  minutes: 30
filter:
- range:
    rule.level:
      gte: 12

alert:
- email
email:
- "{EMAIL}"
from_addr: "{EMAIL}"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_ssl: false
smtp_starttls: true
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"
alert_text_type: alert_text_only
alert_text: |
  CRITICAL SECURITY ALERT
  ========================
  Time        : {{0}}
  Host        : {{1}}  ({{2}})
  Level       : {{3}}  |  Rule: {{4}}
  Description : {{5}}

  MITRE ATT&CK
  Tactic    : {{6}}
  Technique : {{7}}
  ID        : {{8}}

  Network
  Attacker  : {{9}}
  User      : {{10}}

  Kibana: http://localhost:5601
alert_text_args:
- "@timestamp"
- agent.name
- agent.ip
- rule.level
- rule.id
- rule.description
- rule.mitre.tactic
- rule.mitre.technique
- rule.mitre.id
- data.srcip
- data.dstuser
"""

# ── Write all rules ───────────────────────────────────────────────────
os.makedirs(DIR, exist_ok=True)
for fname, content in rules.items():
    path = os.path.join(DIR, fname)
    with open(path, "w") as f:
        f.write(content.strip() + "\n")
    print(f"  ✅ {fname}")

print(f"\nDone — {len(rules)} rules written to {DIR}/")
