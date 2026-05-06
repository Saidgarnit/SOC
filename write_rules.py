import os

rules_dir = '/home/said/soc-stack/elastalert/rules'
slack_url = '${SLACK_WEBHOOK_URL}
at = chr(64)
dot = chr(46)
email = 'garnitsaid01' + at + 'gmail' + dot + 'com'
smtp = 'smtp' + dot + 'gmail' + dot + 'com'

an = 'agent' + dot + 'name'
ai = 'agent' + dot + 'ip'
ri = 'rule' + dot + 'id'
rd = 'rule' + dot + 'description'
rl = 'rule' + dot + 'level'
rg = 'rule' + dot + 'groups'
rm_tactic = 'rule' + dot + 'mitre' + dot + 'tactic'
rm_tech = 'rule' + dot + 'mitre' + dot + 'technique'
rm_id = 'rule' + dot + 'mitre' + dot + 'id'
ts = chr(64) + 'timestamp'
asig = 'alert' + dot + 'signature'
acat = 'alert' + dot + 'category'
asev = 'alert' + dot + 'severity'

sep = '________________________________'

def pf(x): return '%(' + x + ')s'

def slack_only(name, idx, subject, body_lines, extra_yaml='', color='warning'):
    lines = [
        'name: ' + name,
        'type: any' if 'num_events' not in extra_yaml else '',
    ]
    return ''

def build(name, typ, index, extra_top, filters, subject, body, alert_list, email_addr=None, color='warning'):
    lines = ['name: ' + name, 'type: ' + typ, 'index: ' + index, 'ignore_unavailable: true']
    if extra_top:
        lines.append(extra_top)
    lines.append('filter:')
    lines.extend(filters)
    lines.append('realert:\n  minutes: 10')
    lines.append('alert_subject: "' + subject + '"')
    lines.append('alert_text_type: alert_text_only')
    lines.append('alert_text: |')
    for bl in body:
        lines.append('  ' + bl)
    lines.append('alert:')
    lines.append('  - slack')
    if email_addr:
        lines.append('  - email')
        lines.append('email:')
        lines.append('  - "' + email_addr + '"')
        lines.append('smtp_host: "' + smtp + '"')
        lines.append('smtp_port: 587')
        lines.append('smtp_ssl: false')
        lines.append('smtp_auth_file: /opt/elastalert/smtp_auth.yaml')
        lines.append('from_addr: "' + email_addr + '"')
    lines.append('slack_webhook_url: "' + slack_url + '"')
    lines.append('slack_username_override: "SOC-Alert-Bot"')
    lines.append('slack_emoji_override: ":rotating_light:"')
    lines.append('slack_msg_color: "' + color + '"')
    return '\n'.join(lines) + '\n'

wazuh_idx = '.ds-wazuh-alerts-4.x-*'
soc_idx = 'soc-logs-enriched*'

def wazuh_body(title, icon, extra_lines=None):
    b = [
        icon + ' ' + title,
        sep,
        'Rule        : ' + pf(ri) + ' -- ' + pf(rd),
        'Agent       : ' + pf(an) + ' (' + pf(ai) + ')',
        'Level       : ' + pf(rl),
        'MITRE Tactic: ' + pf(rm_tactic),
        'MITRE Tech  : ' + pf(rm_tech),
        'MITRE ID    : ' + pf(rm_id),
        'Timestamp   : ' + pf(ts),
        sep,
        'Kibana: http://localhost:5601',
    ]
    if extra_lines:
        b[1:1] = extra_lines
    return b

def suricata_body(title, icon):
    return [
        icon + ' ' + title,
        sep,
        'Signature   : ' + pf(asig),
        'Category    : ' + pf(acat),
        'Severity    : ' + pf(asev),
        'Protocol    : %(proto)s',
        'Source IP   : %(src_ip)s',
        'Dest IP     : %(dest_ip)s',
        'Timestamp   : ' + pf(ts),
        sep,
        'Kibana: http://localhost:5601',
    ]

rules = {}

# ── WAZUH RULES ──────────────────────────────────────────────────────────

rules['high_risk.yaml'] = build(
    'high_risk_lateral_movement', 'any', wazuh_idx, None,
    ['  - terms:', '      ' + rg + ':', '        - authentication_failed',
     '        - lateral_movement', '        - rootcheck', '        - syscheck',
     '  - range:', '      rule' + dot + 'level:', '        gte: 10'],
    ':rotating_light: [HIGH RISK ALERT] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('HIGH RISK ALERT', ':rotating_light:'),
    ['slack', 'email'], email, 'danger'
)

rules['fim_alert.yaml'] = build(
    'File Integrity Violation', 'any', wazuh_idx, None,
    ['  - terms:', '      ' + rg + ':', '        - syscheck'],
    ':file_folder: [FILE INTEGRITY] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('FILE INTEGRITY VIOLATION', ':file_folder:'),
    ['slack'], None, 'warning'
)

rules['failed_login.yaml'] = build(
    'Failed Login Attempt', 'frequency', wazuh_idx,
    'num_events: 5\ntimeframe:\n  minutes: 5\nquery_key: ' + an,
    ['  - terms:', '      ' + rg + ':', '        - authentication_failed',
     '        - sshd', '        - pam'],
    ':lock: [FAILED LOGIN] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('FAILED LOGIN DETECTED', ':lock:'),
    ['slack'], None, 'warning'
)

rules['brute_force.yaml'] = build(
    'Brute Force Attack Detected', 'frequency', wazuh_idx,
    'num_events: 10\ntimeframe:\n  minutes: 5\nquery_key: ' + an,
    ['  - terms:', '      ' + rg + ':', '        - authentication_failed',
     '        - brute_force', '        - sshd'],
    ':hammer: [BRUTE FORCE] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('BRUTE FORCE ATTACK', ':hammer:'),
    ['slack'], None, 'danger'
)

rules['ftp_bruteforce.yaml'] = build(
    'FTP Brute Force Detected', 'frequency', wazuh_idx,
    'num_events: 5\ntimeframe:\n  minutes: 5\nquery_key: ' + an,
    ['  - terms:', '      ' + rg + ':', '        - authentication_failed',
     '        - vsftpd', '        - proftpd'],
    ':floppy_disk: [FTP BRUTE FORCE] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('FTP BRUTE FORCE', ':floppy_disk:'),
    ['slack'], None, 'warning'
)

rules['privilege_escalation.yaml'] = build(
    'Privilege Escalation Detected', 'any', wazuh_idx, None,
    ['  - terms:', '      ' + rg + ':', '        - sudo', '        - su',
     '        - suid_binary', '        - privilege_escalation'],
    ':arrow_up: [PRIVILEGE ESCALATION] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('PRIVILEGE ESCALATION', ':arrow_up:'),
    ['slack', 'email'], email, 'danger'
)

rules['lateral_movement.yaml'] = build(
    'Lateral Movement Detected', 'frequency', wazuh_idx,
    'num_events: 5\ntimeframe:\n  minutes: 5\nquery_key: ' + an,
    ['  - bool:', '      should:',
     '        - term:', '            ' + rg + ': "authentication_success"',
     '        - term:', '            ' + rg + ': "sshd"',
     '        - term:', '            ' + rg + ': "win_lateral_movement"',
     '        - term:', '            ' + rg + ': "smb"',
     '      minimum_should_match: 1'],
    ':arrow_right: [LATERAL MOVEMENT] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('LATERAL MOVEMENT DETECTED', ':arrow_right:'),
    ['slack', 'email'], email, 'danger'
)

rules['web_attacks.yaml'] = build(
    'Web Attack Detected', 'frequency', wazuh_idx,
    'num_events: 3\ntimeframe:\n  minutes: 5\nquery_key: ' + an,
    ['  - terms:', '      ' + rg + ':', '        - web',
     '        - attack', '        - sql_injection', '        - xss'],
    ':globe_with_meridians: [WEB ATTACK] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('WEB ATTACK DETECTED', ':globe_with_meridians:'),
    ['slack'], None, 'warning'
)

rules['webshell_indicator.yaml'] = build(
    'Webshell Indicator - Process Spawned from Web Server', 'any', wazuh_idx, None,
    ['  - terms:', '      ' + rg + ':', '        - web',
     '        - attack', '        - syscheck'],
    ':biohazard_sign: [WEBSHELL] ' + pf(an) + ' -- ' + pf(rd),
    wazuh_body('WEBSHELL INDICATOR', ':biohazard_sign:'),
    ['slack', 'email'], email, 'danger'
)

# ── SURICATA RULES ───────────────────────────────────────────────────────

rules['suricata_brute_force.yaml'] = build(
    'Suricata SSH Brute Force Detected', 'frequency', soc_idx,
    'num_events: 8\ntimeframe:\n  minutes: 5\nquery_key: src_ip',
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - query_string:',
     '      query: "' + asig + ':*brute* OR ' + asig + ':*SSH* OR alert' + dot + 'category:*brute*"',
     '      analyze_wildcard: true'],
    ':key: [SSH BRUTE FORCE] %(src_ip)s -> %(dest_ip)s',
    suricata_body('SURICATA SSH BRUTE FORCE', ':key:'),
    ['slack'], None, 'danger'
)

rules['port_scan.yaml'] = build(
    'Port Scan / Reconnaissance Detected', 'frequency', soc_idx,
    'num_events: 5\ntimeframe:\n  minutes: 2\nquery_key: src_ip',
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - query_string:',
     '      query: "alert' + dot + 'signature_id:(1000003 OR 1000004)"',
     '      analyze_wildcard: true'],
    ':mag: [PORT SCAN] %(src_ip)s -> %(dest_ip)s',
    suricata_body('PORT SCAN DETECTED', ':mag:'),
    ['slack'], None, 'warning'
)

rules['dns_exfiltration.yaml'] = build(
    'DNS Exfiltration or Tunneling Detected', 'frequency', soc_idx,
    'num_events: 5\ntimeframe:\n  minutes: 10\nquery_key: src_ip',
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - query_string:',
     '      query: "alert' + dot + 'signature_id:(1000010 OR 1000006 OR 1000007)"',
     '      analyze_wildcard: true'],
    ':satellite: [DNS EXFILTRATION] %(src_ip)s -> %(dest_ip)s',
    suricata_body('DNS EXFILTRATION / TUNNELING', ':satellite:'),
    ['slack'], None, 'danger'
)

rules['mqtt_anomaly.yaml'] = build(
    'MQTT Anomaly Detected', 'frequency', soc_idx,
    'num_events: 3\ntimeframe:\n  minutes: 5\nquery_key: src_ip',
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - query_string:',
     '      query: "alert' + dot + 'signature_id:1000020"',
     '      analyze_wildcard: true'],
    ':electric_plug: [MQTT ANOMALY] %(src_ip)s -> %(dest_ip)s',
    suricata_body('MQTT ANOMALY DETECTED', ':electric_plug:'),
    ['slack'], None, 'warning'
)

rules['vt_alert.yaml'] = build(
    'VirusTotal Malicious IP Detected', 'any', soc_idx, None,
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - range:', '      vt_malicious:', '        gte: 1'],
    ':skull: [VIRUSTOTAL] Malicious IP %(src_ip)s',
    suricata_body('VIRUSTOTAL MALICIOUS IP', ':skull:'),
    ['slack'], None, 'danger'
)

rules['misp_alert.yaml'] = build(
    'MISP-Threat-Intel-Match', 'any', soc_idx + ',alerts-soc-threats-*', None,
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - term:', '      tags: "misp_threat_match"'],
    ':brain: [MISP THREAT INTEL] %(src_ip)s matched IOC',
    suricata_body('MISP THREAT INTELLIGENCE MATCH', ':brain:'),
    ['slack'], None, 'danger'
)

rules['yara_critical.yaml'] = build(
    'YARA Critical Malware Detection', 'any', soc_idx, None,
    ['  - term:', '      event_type' + dot + 'keyword: "alert"',
     '  - term:', '      tags: "yara_match"'],
    ':microscope: [YARA MALWARE] %(src_ip)s',
    suricata_body('YARA MALWARE DETECTED', ':microscope:'),
    ['slack'], None, 'danger'
)

# ── WRITE AND VERIFY ─────────────────────────────────────────────────────
written = 0
for fname, content in rules.items():
    path = os.path.join(rules_dir, fname)
    open(path, 'w').write(content)
    written += 1

print('Written: ' + str(written) + ' files')

# Verify
for fname in sorted(os.listdir(rules_dir)):
    if not fname.endswith('.yaml'): continue
    c = open(os.path.join(rules_dir, fname)).read()
    issues = []
    if '](http' in c: issues.append('markdown')
    if 'geoip' in c.lower(): issues.append('geoip')
    if '{0}' in c: issues.append('old_args')
    if 'alert_text: |-' in c: issues.append('empty_body')
    status = 'ISSUES ' + str(issues) if issues else 'ok'
    print(fname + ': ' + status)
