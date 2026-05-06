import os

rules = {
    "suricata_alert.yaml": """
name: Suricata Network IDS Alert
type: any
index: soc-logs-enriched*
filter:
  - term:
      event_type: "alert"

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":warning:"

alert_text: |
  SURICATA IDS ALERT
  ________________________________
  Signature   : {0}
  Category    : {1}
  Severity    : {2}
  Protocol    : {3}
  Source IP   : {4}
  Dest IP     : {5}
  Timestamp   : {6}
  ________________________________
  Kibana: http://localhost:5601

alert_text_args:
  - alert.signature
  - alert.category
  - alert.severity
  - proto
  - src_ip
  - dest_ip
  - "@timestamp"

alert_subject: "[SURICATA IDS] {0} -- {1}"
alert_subject_args:
  - alert.signature
  - src_ip
""",

    "suricata_brute_force.yaml": """
name: Suricata SSH/FTP Brute Force
type: frequency
index: soc-logs-enriched*
num_events: 5
timeframe:
  minutes: 5
filter:
  - query_string:
      query: 'alert.signature:(*Brute* OR *brute* OR *SSH* OR *FTP*) AND event_type:alert'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":rotating_light:"

alert_text: |
  BRUTE FORCE DETECTED (Suricata)
  ________________________________
  Signature   : {0}
  Source IP   : {1}
  Dest IP     : {2}
  Protocol    : {3}
  Event Count : {4}
  ________________________________

alert_text_args:
  - alert.signature
  - src_ip
  - dest_ip
  - proto
  - num_hits

alert_subject: "[BRUTE FORCE] {0} from {1}"
alert_subject_args:
  - alert.signature
  - src_ip
""",

    "port_scan.yaml": """
name: Port Scan Detection
type: frequency
index: soc-logs-enriched*
num_events: 10
timeframe:
  minutes: 2
filter:
  - query_string:
      query: 'alert.signature:(*Port*Scan* OR *SYN*) AND event_type:alert'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":mag:"

alert_text: |
  PORT SCAN DETECTED
  ________________________________
  Scanner IP  : {0}
  Target IP   : {1}
  Scan Type   : {2}
  Hits        : {3} events in 2min
  ________________________________

alert_text_args:
  - src_ip
  - dest_ip
  - alert.signature
  - num_hits

alert_subject: "[PORT SCAN] {0} scanning {1}"
alert_subject_args:
  - src_ip
  - dest_ip
""",

    "web_attacks.yaml": """
name: Web Attacks (Wazuh)
type: any
index: wazuh-alerts-*
filter:
  - query_string:
      query: 'rule.groups:"web" AND (rule.groups:"attack" OR rule.description:(*injection* OR *XSS* OR *sql*))'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":spider_web:"

alert_text: |
  WEB ATTACK DETECTED
  ________________________________
  Agent       : {0}
  Rule ID     : {1}
  Description : {2}
  Level       : {3}
  Timestamp   : {4}
  ________________________________

alert_text_args:
  - agent.name
  - rule.id
  - rule.description
  - rule.level
  - "@timestamp"

alert_subject: "[WEB ATTACK] {0} on {1}"
alert_subject_args:
  - rule.description
  - agent.name
""",

    "brute_force.yaml": """
name: Authentication Brute Force (Wazuh)
type: frequency
index: wazuh-alerts-*
num_events: 5
timeframe:
  minutes: 5
filter:
  - query_string:
      query: 'rule.groups:"authentication_failed"'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":key:"

alert_text: |
  BRUTE FORCE DETECTED (Wazuh)
  ________________________________
  Agent       : {0}
  Rule        : {1}
  Description : {2}
  Failed Count: {3}
  ________________________________

alert_text_args:
  - agent.name
  - rule.id
  - rule.description
  - num_hits

alert_subject: "[BRUTE FORCE] {0} failed logins on {1}"
alert_subject_args:
  - num_hits
  - agent.name
""",

    "fim_alert.yaml": """
name: File Integrity Monitoring
type: any
index: wazuh-alerts-*
filter:
  - query_string:
      query: 'rule.groups:"syscheck" OR rule.groups:"ossec"'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":file_folder:"

alert_text: |
  FILE CHANGE DETECTED
  ________________________________
  Agent       : {0}
  Rule        : {1}
  Description : {2}
  Level       : {3}
  ________________________________

alert_text_args:
  - agent.name
  - rule.id
  - rule.description
  - rule.level

alert_subject: "[FIM] {0} on {1}"
alert_subject_args:
  - rule.description
  - agent.name
""",

    "failed_login.yaml": """
name: Failed Login Attempts
type: frequency
index: wazuh-alerts-*
num_events: 3
timeframe:
  minutes: 10
filter:
  - query_string:
      query: 'rule.groups:"authentication_failed"'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":lock:"

alert_text: |
  FAILED LOGIN ATTEMPTS
  ________________________________
  Agent       : {0}
  Description : {1}
  Count       : {2} failures
  ________________________________

alert_text_args:
  - agent.name
  - rule.description
  - num_hits

alert_subject: "[FAILED LOGIN] {0} attempts on {1}"
alert_subject_args:
  - num_hits
  - agent.name
""",

    "high_risk.yaml": """
name: High Risk Wazuh Alerts
type: any
index: wazuh-alerts-*
filter:
  - range:
      rule.level:
        gte: 10

alert:
  - slack
  - email
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":rotating_light:"

email:
  - "saidbouig01@gmail.com"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_ssl: false
from_addr: "saidbouig01@gmail.com"
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"

alert_text: |
  HIGH RISK ALERT
  ________________________________
  Agent       : {0}
  Rule ID     : {1}
  Description : {2}
  Level       : {3}
  Groups      : {4}
  Timestamp   : {5}
  ________________________________

alert_text_args:
  - agent.name
  - rule.id
  - rule.description
  - rule.level
  - rule.groups
  - "@timestamp"

alert_subject: "[HIGH RISK] Level {0} - {1}"
alert_subject_args:
  - rule.level
  - rule.description
""",

    "privilege_escalation.yaml": """
name: Privilege Escalation
type: any
index: wazuh-alerts-*
filter:
  - query_string:
      query: 'rule.groups:("privilege_escalation" OR "escalation" OR "sudo" OR "su")'

alert:
  - slack
  - email
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":arrow_up:"

email:
  - "saidbouig01@gmail.com"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_ssl: false
from_addr: "saidbouig01@gmail.com"
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"

alert_text: |
  PRIVILEGE ESCALATION DETECTED
  ________________________________
  Agent       : {0}
  Description : {1}
  Level       : {2}
  ________________________________

alert_text_args:
  - agent.name
  - rule.description
  - rule.level

alert_subject: "[PRIVILEGE ESC] {0}"
alert_subject_args:
  - agent.name
""",

    "lateral_movement.yaml": """
name: Lateral Movement
type: any
index: wazuh-alerts-*
filter:
  - query_string:
      query: 'rule.description:(*lateral* OR *movement* OR *pivot*)'

alert:
  - slack
  - email
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":arrows_counterclockwise:"

email:
  - "saidbouig01@gmail.com"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_ssl: false
from_addr: "saidbouig01@gmail.com"
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"

alert_text: |
  LATERAL MOVEMENT DETECTED
  ________________________________
  Agent       : {0}
  Description : {1}
  Level       : {2}
  ________________________________

alert_text_args:
  - agent.name
  - rule.description
  - rule.level

alert_subject: "[LATERAL MOVEMENT] {0}"
alert_subject_args:
  - agent.name
""",

    "webshell_indicator.yaml": """
name: Webshell Indicators
type: any
index: wazuh-alerts-*
filter:
  - query_string:
      query: 'rule.description:(*webshell* OR *shell* OR *backdoor*) AND rule.groups:"web"'

alert:
  - slack
  - email
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":globe_with_meridians:"

email:
  - "saidbouig01@gmail.com"
smtp_host: "smtp.gmail.com"
smtp_port: 587
smtp_ssl: false
from_addr: "saidbouig01@gmail.com"
smtp_auth_file: "/opt/elastalert/smtp_auth.yaml"

alert_text: |
  WEBSHELL DETECTED
  ________________________________
  Agent       : {0}
  Description : {1}
  Level       : {2}
  ________________________________

alert_text_args:
  - agent.name
  - rule.description
  - rule.level

alert_subject: "[WEBSHELL] {0}"
alert_subject_args:
  - agent.name
""",

    "dns_exfiltration.yaml": """
name: DNS Exfiltration
type: any
index: soc-logs-enriched*
filter:
  - query_string:
      query: 'alert.signature:(*DNS* OR *exfil*) AND event_type:alert'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":dns:"

alert_text: |
  DNS EXFILTRATION SUSPECTED
  ________________________________
  Signature   : {0}
  Source IP   : {1}
  Dest IP     : {2}
  ________________________________

alert_text_args:
  - alert.signature
  - src_ip
  - dest_ip

alert_subject: "[DNS EXFIL] {0}"
alert_subject_args:
  - src_ip
""",

    "ftp_bruteforce.yaml": """
name: FTP Brute Force
type: frequency
index: wazuh-alerts-*
num_events: 5
timeframe:
  minutes: 5
filter:
  - query_string:
      query: 'rule.groups:"ftp" AND rule.groups:"authentication_failed"'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":file_cabinet:"

alert_text: |
  FTP BRUTE FORCE
  ________________________________
  Agent       : {0}
  Description : {1}
  Count       : {2}
  ________________________________

alert_text_args:
  - agent.name
  - rule.description
  - num_hits

alert_subject: "[FTP BRUTE] {0} attempts"
alert_subject_args:
  - num_hits
""",

    "mqtt_anomaly.yaml": """
name: MQTT Anomaly Detection
type: any
index: soc-logs-enriched*
filter:
  - query_string:
      query: 'alert.signature:(*MQTT* OR *IoT*) AND event_type:alert'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":satellite:"

alert_text: |
  MQTT ANOMALY
  ________________________________
  Signature   : {0}
  Source      : {1}
  ________________________________

alert_text_args:
  - alert.signature
  - src_ip

alert_subject: "[MQTT] {0}"
alert_subject_args:
  - alert.signature
""",

    "vt_alert.yaml": """
name: VirusTotal Malicious Detection
type: any
index: soc-logs-enriched*
filter:
  - term:
      vt_malicious: "2"

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":biohazard_sign:"

alert_text: |
  VIRUSTOTAL MALICIOUS FILE
  ________________________________
  Detection   : Malicious confirmed
  Severity    : Medium
  ________________________________

alert_text_args: []

alert_subject: "[VT MALICIOUS] File detected"
alert_subject_args: []
""",

    "misp_alert.yaml": """
name: MISP IOC Match
type: any
index: soc-logs-enriched*
filter:
  - exists:
      field: "misp_ioc"

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":warning:"

alert_text: |
  MISP IOC MATCH
  ________________________________
  IOC matched in threat feed
  Source IP   : {0}
  ________________________________

alert_text_args:
  - src_ip

alert_subject: "[MISP] IOC detected"
alert_subject_args: []
""",

    "yara_critical.yaml": """
name: YARA Critical Match
type: any
index: wazuh-alerts-*
filter:
  - query_string:
      query: 'rule.groups:"yara"'

alert:
  - slack
slack_webhook_url: "${SLACK_WEBHOOK_URL}"
slack_username_override: "SOC-RANGE-ELASTALERT"
slack_emoji_override: ":rotating_light:"

alert_text: |
  YARA MALWARE DETECTED
  ________________________________
  Agent       : {0}
  Description : {1}
  Level       : {2}
  ________________________________

alert_text_args:
  - agent.name
  - rule.description
  - rule.level

alert_subject: "[YARA] Malware on {0}"
alert_subject_args:
  - agent.name
"""
}

# Write all rules
for filename, content in rules.items():
    path = f"/home/said/soc-stack/elastalert/rules/{filename}"
    with open(path, 'w') as f:
        f.write(content.strip() + '\n')
    print(f"✓ {filename}")

print("\n✅ All 17 rules rewritten with correct field mappings")
