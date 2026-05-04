#!/usr/bin/env python3
"""Definitive alert fix - correct fields, clean formatting, proper MITRE"""
import yaml, os, glob

RULES_DIR = os.path.expanduser("~/soc-stack/elastalert/rules")

# Suricata document fields (verified from actual ES data):
# alert.signature, alert.category, alert.severity, src_ip, dest_ip, dest_port, proto
SURICATA = {'suricata_alert.yaml','suricata_brute_force.yaml','dns_exfiltration.yaml','port_scan.yaml'}

TITLES = {
    'high_risk.yaml': 'HIGH RISK ALERT',
    'brute_force.yaml': 'BRUTE FORCE ATTACK',
    'failed_login.yaml': 'FAILED LOGIN ATTEMPT',
    'fim_alert.yaml': 'FILE INTEGRITY VIOLATION',
    'ftp_bruteforce.yaml': 'FTP BRUTE FORCE',
    'lateral_movement.yaml': 'LATERAL MOVEMENT',
    'privilege_escalation.yaml': 'PRIVILEGE ESCALATION',
    'web_attacks.yaml': 'WEB ATTACK',
    'webshell_indicator.yaml': 'WEBSHELL INDICATOR',
    'yara_critical.yaml': 'YARA CRITICAL MALWARE',
    'mqtt_anomaly.yaml': 'MQTT ANOMALY',
    'suricata_alert.yaml': 'SURICATA IDS ALERT',
    'suricata_brute_force.yaml': 'SSH BRUTE FORCE (NET)',
    'dns_exfiltration.yaml': 'DNS EXFILTRATION',
    'port_scan.yaml': 'PORT SCAN',
    'misp_alert.yaml': 'MISP THREAT INTEL MATCH',
    'vt_alert.yaml': 'VIRUSTOTAL MALICIOUS',
}

COMMON = {
    'alert': ['slack', 'email'],
    'slack_webhook_url': 'https://hooks.slack.com/services/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',
    'slack_username_override': 'SOC-Alert-Bot',
    'slack_emoji_override': ':rotating_light:',
    'slack_msg_color': 'danger',
    'email': ['garnitsaid01@gmail.com'],
    'smtp_host': 'smtp.gmail.com',
    'smtp_port': 587,
    'smtp_ssl': False,
    'smtp_auth_file': '/opt/elastalert/smtp_auth.yaml',
    'from_addr': 'garnitsaid01@gmail.com',
    'realert': {'minutes': 5},
    'alert_text_type': 'alert_text_only',
}

for fp in sorted(glob.glob(f"{RULES_DIR}/*.yaml")):
    fname = os.path.basename(fp)
    title = TITLES.get(fname, fname.upper())
    
    with open(fp) as f:
        rule = yaml.safe_load(f)
    
    # Clean old keys
    for k in ['alert_text_kw','email_subject_args']:
        rule.pop(k, None)
    
    is_suricata = fname in SURICATA
    
    if is_suricata:
        # Suricata: 6 fields (no src_port in most docs)
        txt = (f"\xf0\x9f\x9a\xa8 {title}\n"
               "________________________________\n"
               "Signature  : {0}\n"
               "Category   : {1}\n"
               "Severity   : {2}\n"
               "Source      : {3}\n"
               "Destination: {4}:{5}\n"
               "Protocol   : {6}\n"
               "Timestamp  : {7}\n"
               "________________________________\n"
               "Kibana: http://localhost:5601")
        args = ['alert.signature','alert.category','alert.severity',
                'src_ip','dest_ip','dest_port','proto','@timestamp']
        subj_args = ['alert.signature','src_ip']
    elif fname == 'fim_alert.yaml':
        txt = (f"\xf0\x9f\x9a\xa8 {title}\n"
               "________________________________\n"
               "Rule       : {0} -- {1}\n"
               "Agent      : {2} ({3})\n"
               "Level      : {4}\n"
               "File       : {5}\n"
               "Change     : {6}\n"
               "MITRE      : {7} | {8}\n"
               "Timestamp  : {9}\n"
               "________________________________\n"
               "Kibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','syscheck.path','syscheck.event',
                'rule.mitre.id','rule.mitre.technique','@timestamp']
        subj_args = ['agent.name','rule.description']
    elif fname == 'vt_alert.yaml':
        txt = (f"\xf0\x9f\x9a\xa8 {title}\n"
               "________________________________\n"
               "Rule       : {0} -- {1}\n"
               "Agent      : {2} ({3})\n"
               "Level      : {4}\n"
               "VT Score   : {5}\n"
               "VT Severity: {6}\n"
               "MITRE      : {7} | {8} | {9}\n"
               "Timestamp  : {10}\n"
               "________________________________\n"
               "Kibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','vt_risk_score','vt_severity',
                'rule.mitre.id','rule.mitre.tactic','rule.mitre.technique',
                '@timestamp']
        subj_args = ['agent.name','rule.description']
    else:
        # Standard Wazuh rule
        txt = (f"\xf0\x9f\x9a\xa8 {title}\n"
               "________________________________\n"
               "Rule       : {0} -- {1}\n"
               "Agent      : {2} ({3})\n"
               "Level      : {4}\n"
               "MITRE ID   : {5}\n"
               "MITRE Tactic: {6}\n"
               "MITRE Tech : {7}\n"
               "Source IP   : {8}\n"
               "Timestamp  : {9}\n"
               "________________________________\n"
               "Kibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','rule.mitre.id','rule.mitre.tactic',
                'rule.mitre.technique','data.srcip','@timestamp']
        subj_args = ['agent.name','rule.description']
    
    rule['alert_text'] = txt
    rule['alert_text_args'] = args
    rule['alert_subject'] = f"\xf0\x9f\x9a\xa8 [{title}] {{0}} -- {{1}}"
    rule['alert_subject_args'] = subj_args
    rule['email_subject'] = f"SOC ALERT -- {title}"
    rule.update(COMMON)
    
    # Write with controlled formatting (no double-spacing)
    with open(fp, 'w') as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=200)
    print(f"  \u2705 {fname}")

print(f"\n\xf0\x9f\x8e\xaf All 17 rules patched (v3 - clean format).")
