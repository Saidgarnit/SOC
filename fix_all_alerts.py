#!/usr/bin/env python3
import yaml, os, glob

RULES_DIR = os.path.expanduser("~/soc-stack/elastalert/rules")
EMAIL = ["garnitsaid01@gmail.com"]
SMTP = {
    'smtp_host': 'smtp.gmail.com', 'smtp_port': 587, 'smtp_ssl': False,
    'smtp_auth_file': '/opt/elastalert/smtp_auth.yaml',
    'from_addr': 'garnitsaid01@gmail.com',
}
SLACK = {
    'slack_webhook_url': '${SLACK_WEBHOOK_URL}
    'slack_username_override': 'SOC-Alert-Bot',
    'slack_emoji_override': ':rotating_light:',
    'slack_msg_color': 'danger',
}
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

for fp in sorted(glob.glob(f"{RULES_DIR}/*.yaml")):
    fname = os.path.basename(fp)
    title = TITLES.get(fname, fname.replace('.yaml','').upper())
    with open(fp) as f:
        rule = yaml.safe_load(f)
    
    # Remove old broken kw fields
    for old_key in ['alert_text_kw', 'email_subject_args']:
        rule.pop(old_key, None)
    
    is_suricata = fname in SURICATA
    
    if is_suricata:
        rule['alert_text'] = (
            f"🚨 {title}\n"
            "________________________________\n"
            "Signature  : {0}\n"
            "Category   : {1}\n"
            "Severity   : {2}\n"
            "Source      : {3}:{4}\n"
            "Destination: {5}:{6}\n"
            "Timestamp  : {7}\n"
            "________________________________\n"
            "Kibana: http://localhost:5601"
        )
        rule['alert_text_args'] = [
            'alert.signature', 'alert.category', 'alert.severity',
            'src_ip', 'src_port', 'dest_ip', 'dest_port', '@timestamp'
        ]
        rule['alert_subject'] = f"🚨 [{title}] {{0}} -- {{1}}"
        rule['alert_subject_args'] = ['alert.signature', 'src_ip']
    else:
        body = (
            f"🚨 {title}\n"
            "________________________________\n"
            "Rule       : {0} -- {1}\n"
            "Agent      : {2} ({3})\n"
            "Level      : {4}\n"
            "MITRE ID   : {5}\n"
            "MITRE Tactic: {6}\n"
            "MITRE Tech : {7}\n"
            "Source IP   : {8}\n"
        )
        args = [
            'rule.id', 'rule.description', 'agent.name', 'agent.ip',
            'rule.level', 'rule.mitre.id', 'rule.mitre.tactic',
            'rule.mitre.technique', 'data.srcip'
        ]
        idx = 9
        if fname == 'fim_alert.yaml':
            body += f"File       : {{{idx}}}\nChange     : {{{idx+1}}}\n"
            args += ['syscheck.path', 'syscheck.event']
            idx += 2
        if fname == 'vt_alert.yaml':
            body += f"VT Score   : {{{idx}}}\nVT Risk    : {{{idx+1}}}\n"
            args += ['vt_risk_score', 'vt_severity']
            idx += 2
        body += (
            f"Timestamp  : {{{idx}}}\n"
            "________________________________\n"
            "Kibana: http://localhost:5601"
        )
        args.append('@timestamp')
        rule['alert_text'] = body
        rule['alert_text_args'] = args
        rule['alert_subject'] = f"🚨 [{title}] {{0}} -- {{1}}"
        rule['alert_subject_args'] = ['agent.name', 'rule.description']
    
    rule['alert_text_type'] = 'alert_text_only'
    alerts = rule.get('alert', [])
    if not isinstance(alerts, list): alerts = [alerts]
    if 'slack' not in alerts: alerts.append('slack')
    if 'email' not in alerts: alerts.append('email')
    rule['alert'] = alerts
    rule['email'] = EMAIL
    rule.update(SMTP)
    rule.update(SLACK)
    rule['email_subject'] = f"SOC ALERT -- {title}"
    
    with open(fp, 'w') as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"  ✅ {fname}")

print(f"\n🎯 All 17 rules patched with positional args format.")
