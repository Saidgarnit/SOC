#!/usr/bin/env python3
"""v4: Clean formatting, severity labels, GeoIP fields, one emoji in title"""
import yaml, os, glob

RULES_DIR = os.path.expanduser("~/soc-stack/elastalert/rules")
SURICATA = {'suricata_alert.yaml','suricata_brute_force.yaml','dns_exfiltration.yaml','port_scan.yaml'}

TITLES = {
    'high_risk.yaml':           ('HIGH RISK ALERT',     ':rotating_light:'),
    'brute_force.yaml':         ('BRUTE FORCE ATTACK',  ':hammer:'),
    'failed_login.yaml':        ('FAILED LOGIN',        ':lock:'),
    'fim_alert.yaml':           ('FILE INTEGRITY',      ':file_folder:'),
    'ftp_bruteforce.yaml':      ('FTP BRUTE FORCE',     ':floppy_disk:'),
    'lateral_movement.yaml':    ('LATERAL MOVEMENT',    ':arrow_right:'),
    'privilege_escalation.yaml':('PRIVILEGE ESCALATION', ':arrow_up:'),
    'web_attacks.yaml':         ('WEB ATTACK',          ':globe_with_meridians:'),
    'webshell_indicator.yaml':  ('WEBSHELL INDICATOR',  ':biohazard_sign:'),
    'yara_critical.yaml':       ('YARA MALWARE',        ':microscope:'),
    'mqtt_anomaly.yaml':        ('MQTT ANOMALY',        ':satellite:'),
    'suricata_alert.yaml':      ('SURICATA IDS',        ':rotating_light:'),
    'suricata_brute_force.yaml':('SSH BRUTE FORCE',     ':hammer:'),
    'dns_exfiltration.yaml':    ('DNS EXFILTRATION',    ':satellite:'),
    'port_scan.yaml':           ('PORT SCAN',           ':mag:'),
    'misp_alert.yaml':          ('MISP THREAT INTEL',   ':brain:'),
    'vt_alert.yaml':            ('VIRUSTOTAL ALERT',    ':skull:'),
}

COMMON = {
    'alert': ['slack', 'email'],
    'slack_webhook_url': 'https://hooks.slack.com/services/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',
    'slack_username_override': 'SOC-Alert-Bot',
    'slack_emoji_override': ':rotating_light:',
    'slack_msg_color': 'danger',
    'email': ['garnitsaid01@gmail.com'],
    'smtp_host': 'smtp.gmail.com', 'smtp_port': 587, 'smtp_ssl': False,
    'smtp_auth_file': '/opt/elastalert/smtp_auth.yaml',
    'from_addr': 'garnitsaid01@gmail.com',
    'realert': {'minutes': 5},
    'alert_text_type': 'alert_text_only',
}

for fp in sorted(glob.glob(f"{RULES_DIR}/*.yaml")):
    fname = os.path.basename(fp)
    title, emoji = TITLES.get(fname, (fname.upper(), ':warning:'))
    with open(fp) as f:
        rule = yaml.safe_load(f)
    for k in ['alert_text_kw','email_subject_args']:
        rule.pop(k, None)
    
    is_suricata = fname in SURICATA
    
    if is_suricata:
        txt = (f"{emoji} [{title}]\n"
               f"{'='*36}\n"
               "Signature  : {0}\n"
               "Category   : {1}\n"
               "Severity   : {2}\n"
               "Protocol   : {3}\n"
               "Source IP   : {4}\n"
               "Dest IP     : {5}:{6}\n"
               "GeoIP       : {7}, {8}\n"
               "Timestamp   : {9}\n"
               f"{'='*36}\n"
               ":link: Kibana: http://localhost:5601")
        args = ['alert.signature','alert.category','alert.severity',
                'proto','src_ip','dest_ip','dest_port',
                'geoip.country_name','geoip.city_name','@timestamp']
        subj = f"{emoji} [{title}] {{0}} -- {{1}}"
        subj_args = ['alert.signature','src_ip']
    elif fname == 'fim_alert.yaml':
        txt = (f"{emoji} [{title}]\n"
               f"{'='*36}\n"
               "Rule        : {0} -- {1}\n"
               "Agent       : {2} ({3})\n"
               "Level       : {4}\n"
               "File        : {5}\n"
               "Change      : {6}\n"
               "MITRE       : {7} | {8}\n"
               "Timestamp   : {9}\n"
               f"{'='*36}\n"
               ":link: Kibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','syscheck.path','syscheck.event',
                'rule.mitre.id','rule.mitre.technique','@timestamp']
        subj = f"{emoji} [{title}] {{0}} -- {{1}}"
        subj_args = ['agent.name','rule.description']
    else:
        txt = (f"{emoji} [{title}]\n"
               f"{'='*36}\n"
               "Rule        : {0} -- {1}\n"
               "Agent       : {2} ({3})\n"
               "Level       : {4}\n"
               "MITRE ID    : {5}\n"
               "MITRE Tactic: {6}\n"
               "MITRE Tech  : {7}\n"
               "Source IP    : {8}\n"
               "GeoIP        : {9}, {10}\n"
               "Timestamp    : {11}\n"
               f"{'='*36}\n"
               ":link: Kibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','rule.mitre.id','rule.mitre.tactic',
                'rule.mitre.technique','data.srcip',
                'geoip.country_name','geoip.city_name','@timestamp']
        subj = f"{emoji} [{title}] {{0}} -- {{1}}"
        subj_args = ['agent.name','rule.description']
    
    rule['alert_text'] = txt
    rule['alert_text_args'] = args
    rule['alert_subject'] = subj
    rule['alert_subject_args'] = subj_args
    rule['email_subject'] = f"SOC ALERT -- {title}"
    rule.update(COMMON)
    
    with open(fp, 'w') as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=200)
    print(f"  ✅ {fname} — {emoji} {title}")

print("\n🎯 All 17 rules redesigned (v4).")
