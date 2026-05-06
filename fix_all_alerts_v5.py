#!/usr/bin/env python3
"""v5: Unicode emojis for Gmail, Internal IP handling, DNS fix"""
import yaml, os, glob

RULES_DIR = os.path.expanduser("~/soc-stack/elastalert/rules")
SURICATA = {'suricata_alert.yaml','suricata_brute_force.yaml','port_scan.yaml'}
# DNS exfil is NOT suricata — it queries Wazuh index

TITLES = {
    'high_risk.yaml':           ('HIGH RISK ALERT',      '\U0001F6A8'),
    'brute_force.yaml':         ('BRUTE FORCE ATTACK',   '\U0001F528'),
    'failed_login.yaml':        ('FAILED LOGIN',         '\U0001F512'),
    'fim_alert.yaml':           ('FILE INTEGRITY',       '\U0001F4C1'),
    'ftp_bruteforce.yaml':      ('FTP BRUTE FORCE',      '\U0001F4BE'),
    'lateral_movement.yaml':    ('LATERAL MOVEMENT',     '\u27A1\uFE0F'),
    'privilege_escalation.yaml':('PRIVILEGE ESCALATION',  '\u2B06\uFE0F'),
    'web_attacks.yaml':         ('WEB ATTACK',           '\U0001F310'),
    'webshell_indicator.yaml':  ('WEBSHELL INDICATOR',   '\u2623\uFE0F'),
    'yara_critical.yaml':       ('YARA MALWARE',         '\U0001F52C'),
    'mqtt_anomaly.yaml':        ('MQTT ANOMALY',         '\U0001F4E1'),
    'suricata_alert.yaml':      ('SURICATA IDS',         '\U0001F6A8'),
    'suricata_brute_force.yaml':('SSH BRUTE FORCE',      '\U0001F528'),
    'dns_exfiltration.yaml':    ('DNS EXFILTRATION',     '\U0001F4E1'),
    'port_scan.yaml':           ('PORT SCAN',            '\U0001F50D'),
    'misp_alert.yaml':          ('MISP THREAT INTEL',    '\U0001F9E0'),
    'vt_alert.yaml':            ('VIRUSTOTAL ALERT',     '\U0001F480'),
}

COMMON = {
    'alert': ['slack', 'email'],
    'slack_webhook_url': '${SLACK_WEBHOOK_URL}
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

SEP = '=' * 36

for fp in sorted(glob.glob(f"{RULES_DIR}/*.yaml")):
    fname = os.path.basename(fp)
    title, emoji = TITLES.get(fname, (fname.upper(), '\u26A0\uFE0F'))
    with open(fp) as f:
        rule = yaml.safe_load(f)
    for k in ['alert_text_kw', 'email_subject_args']:
        rule.pop(k, None)

    if fname in SURICATA:
        txt = (f"{emoji} [{title}]\n{SEP}\n"
               "Signature   : {0}\nCategory    : {1}\nSeverity    : {2}\n"
               "Protocol    : {3}\nSource IP   : {4}\nDest IP     : {5}:{6}\n"
               "GeoIP       : {7}, {8}\n"
               "Timestamp   : {9}\n"
               f"{SEP}\nKibana: http://localhost:5601")
        args = ['alert.signature','alert.category','alert.severity',
                'proto','src_ip','dest_ip','dest_port',
                'geoip.country_name','geoip.city_name','@timestamp']
        subj_args = ['alert.signature','src_ip']

    elif fname == 'dns_exfiltration.yaml':
        # DNS exfil queries Wazuh index — use Wazuh fields
        txt = (f"{emoji} [{title}]\n{SEP}\n"
               "Rule        : {0} -- {1}\nAgent       : {2} ({3})\n"
               "Level       : {4}\nSource IP   : {5}\n"
               "GeoIP       : {6}, {7}\n"
               "Timestamp   : {8}\n"
               f"{SEP}\nKibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','data.srcip',
                'geoip.country_name','geoip.city_name','@timestamp']
        subj_args = ['agent.name','data.srcip']

    elif fname == 'fim_alert.yaml':
        # FIM: no Source IP (local file changes)
        txt = (f"{emoji} [{title}]\n{SEP}\n"
               "Rule        : {0} -- {1}\nAgent       : {2} ({3})\n"
               "Level       : {4}\nFile        : {5}\nChange      : {6}\n"
               "MITRE       : {7} | {8}\n"
               "Timestamp   : {9}\n"
               f"{SEP}\nKibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','syscheck.path','syscheck.event',
                'rule.mitre.id','rule.mitre.technique','@timestamp']
        subj_args = ['agent.name','rule.description']

    elif fname == 'vt_alert.yaml':
        txt = (f"{emoji} [{title}]\n{SEP}\n"
               "Rule        : {0} -- {1}\nAgent       : {2} ({3})\n"
               "Level       : {4}\nVT Score    : {5}\nVT Risk     : {6}\n"
               "MITRE       : {7} | {8} | {9}\n"
               "Timestamp   : {10}\n"
               f"{SEP}\nKibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','vt_risk_score','vt_severity',
                'rule.mitre.id','rule.mitre.tactic','rule.mitre.technique',
                '@timestamp']
        subj_args = ['agent.name','rule.description']

    else:
        # Standard Wazuh rule with MITRE + GeoIP
        txt = (f"{emoji} [{title}]\n{SEP}\n"
               "Rule        : {0} -- {1}\nAgent       : {2} ({3})\n"
               "Level       : {4}\nMITRE ID    : {5}\n"
               "MITRE Tactic: {6}\nMITRE Tech  : {7}\n"
               "Source IP    : {8}\nGeoIP       : {9}, {10}\n"
               "Timestamp   : {11}\n"
               f"{SEP}\nKibana: http://localhost:5601")
        args = ['rule.id','rule.description','agent.name','agent.ip',
                'rule.level','rule.mitre.id','rule.mitre.tactic',
                'rule.mitre.technique','data.srcip',
                'geoip.country_name','geoip.city_name','@timestamp']
        subj_args = ['agent.name','rule.description']

    rule['alert_text'] = txt
    rule['alert_text_args'] = args
    rule['alert_subject'] = f"{emoji} [{title}] {{0}} -- {{1}}"
    rule['alert_subject_args'] = subj_args
    rule['email_subject'] = f"{emoji} SOC ALERT -- {title}"
    rule.update(COMMON)

    with open(fp, 'w') as f:
        yaml.dump(rule, f, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=200)
    print(f"  \u2705 {fname}")

print("\n\U0001F3AF All 17 rules patched (v5 - Unicode + GeoIP + DNS fix).")
