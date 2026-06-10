#!/usr/bin/env python3
"""
create-mitre-rules.py
Creates ~80 custom KQL/EQL/threshold detection rules covering all 14 MITRE
ATT&CK tactics with multiple techniques each.
All rules target: wazuh-alerts-4.x-*, suricata-alerts-*, soc-logs-enriched-*
No ML rules — all work on Basic license.
Run: python3 create-mitre-rules.py
"""
import urllib.request, json, base64, uuid, time, sys

KBN = "http://localhost:5601"
HDR = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
    "Authorization": "Basic " + base64.b64encode(b"elastic:SOCstack2026!").decode()
}

def api(method, path, body=None):
    req = urllib.request.Request(f"{KBN}{path}",
        data=json.dumps(body).encode() if body else None,
        headers=HDR, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        msg = e.read().decode()
        if "already exists" in msg or "Duplicate" in msg:
            return None, "duplicate"
        return None, f"HTTP {e.code}: {msg[:100]}"
    except Exception as e:
        return None, str(e)[:80]

def mkrule(name, desc, rtype, query, tactic_id, tactic, tech_id, tech,
           index=None, sub_id=None, sub_name=None,
           severity="medium", risk=47, threshold=None, filters=None):
    if index is None:
        index = ["wazuh-alerts-4.x-*", "suricata-alerts-*", "soc-logs-enriched-*"]

    threat = [{
        "framework": "MITRE ATT&CK",
        "tactic": {
            "id": tactic_id, "name": tactic,
            "reference": f"https://attack.mitre.org/tactics/{tactic_id}/"
        },
        "technique": [{
            "id": tech_id, "name": tech,
            "reference": f"https://attack.mitre.org/techniques/{tech_id}/",
            **({"subtechnique": [{"id": sub_id, "name": sub_name,
                "reference": f"https://attack.mitre.org/techniques/{sub_id.replace('.','/')}/"}]}
               if sub_id else {})
        }]
    }]

    rule = {
        "type": rtype,
        "name": name,
        "description": desc,
        "severity": severity,
        "risk_score": risk,
        "enabled": True,
        "index": index,
        "threat": threat,
        "tags": ["SOC-Lab", "MITRE", tactic, tech_id],
        "interval": "5m",
        "from": "now-6m",
        "to": "now",
        "rule_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
    }

    if rtype in ("query", "eql"):
        rule["language"] = "kuery" if rtype == "query" else "eql"
        rule["query"] = query
    if rtype == "threshold":
        rule["language"] = "kuery"
        rule["query"] = query
        rule["threshold"] = threshold or {"field": "source.ip", "value": 5}

    return rule

# ════════════════════════════════════════════════════════════════════
# RULE DEFINITIONS — 80 rules across all 14 MITRE tactics
# ════════════════════════════════════════════════════════════════════
RULES = [

    # ── TA0043 Reconnaissance ────────────────────────────────────────
    mkrule("[SOC] Port Scan - Active Scanning",
        "Suricata detected active port scanning activity",
        "query",
        'alert.signature: *scan* OR alert.category: *scan* OR alert.signature: *nmap* OR alert.signature: *masscan*',
        "TA0043","Reconnaissance","T1595","Active Scanning",
        index=["suricata-alerts-*"],
        sub_id="T1595.001", sub_name="Scanning IP Blocks"),

    mkrule("[SOC] DNS Enumeration - Gather Network Info",
        "High volume DNS queries suggesting zone transfer or enumeration",
        "threshold",
        'event.dataset: suricata.dns OR dns.type: query',
        "TA0043","Reconnaissance","T1590","Gather Victim Network Information",
        index=["suricata-alerts-*","soc-logs-enriched-*"],
        threshold={"field": "dns.query.name", "value": 10}),

    mkrule("[SOC] Web App Fingerprinting",
        "HTTP requests with scanner user-agents (Nikto, Nessus, etc.)",
        "query",
        'http.user_agent: *nikto* OR http.user_agent: *nessus* OR http.user_agent: *nmap* OR alert.signature: *scanner*',
        "TA0043","Reconnaissance","T1595","Active Scanning",
        index=["suricata-alerts-*","soc-logs-enriched-*"],
        sub_id="T1595.002", sub_name="Vulnerability Scanning"),

    mkrule("[SOC] OSINT - Phishing Infrastructure Probe",
        "Requests to known phishing kit paths or credential harvester URLs",
        "query",
        'http.url: *login* AND http.url: *wp-* OR http.url: */phish* OR alert.signature: *phishing*',
        "TA0043","Reconnaissance","T1597","Search Closed Sources",
        index=["suricata-alerts-*"]),

    # ── TA0042 Resource Development ──────────────────────────────────
    mkrule("[SOC] Tool Download via curl or wget",
        "System tool used to download external resource - possible resource development",
        "query",
        'rule.description: *wget* OR rule.description: *curl* OR rule.description: *download* OR rule.groups: *download*',
        "TA0042","Resource Development","T1588","Obtain Capabilities",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1588.002", sub_name="Tool"),

    mkrule("[SOC] Suspicious Script or Payload Staged",
        "New executable or script file created in temp or unusual directory",
        "query",
        'syscheck.path: */tmp/* AND syscheck.event: added OR syscheck.path: */dev/shm/* AND syscheck.event: added',
        "TA0042","Resource Development","T1608","Stage Capabilities",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1608.001", sub_name="Upload Malware"),

    mkrule("[SOC] Compilation Tool Executed",
        "Compiler or build tool run on victim - possible capability development",
        "query",
        'rule.description: *gcc* OR rule.description: *g++* OR rule.description: *make* OR rule.description: *python setup.py*',
        "TA0042","Resource Development","T1587","Develop Capabilities",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1587.001", sub_name="Malware"),

    # ── TA0001 Initial Access ─────────────────────────────────────────
    mkrule("[SOC] SQL Injection Attempt",
        "Suricata detected SQL injection in HTTP request",
        "query",
        'alert.signature: *SQL* AND (alert.signature: *injection* OR alert.signature: *sqli*) OR alert.category: *Web Application Attack*',
        "TA0001","Initial Access","T1190","Exploit Public-Facing Application",
        index=["suricata-alerts-*"], severity="high", risk=73),

    mkrule("[SOC] XSS - Cross Site Scripting Attack",
        "Cross-site scripting attempt detected in HTTP traffic",
        "query",
        'alert.signature: *XSS* OR alert.signature: *cross site scripting* OR alert.signature: *script injection*',
        "TA0001","Initial Access","T1190","Exploit Public-Facing Application",
        index=["suricata-alerts-*"], severity="high", risk=73),

    mkrule("[SOC] Directory Traversal Attack",
        "Path traversal attempt to access files outside web root",
        "query",
        'alert.signature: *traversal* OR alert.signature: *path traversal* OR alert.signature: *dot dot* OR http.url: *../*',
        "TA0001","Initial Access","T1190","Exploit Public-Facing Application",
        index=["suricata-alerts-*","soc-logs-enriched-*"]),

    mkrule("[SOC] RCE Attempt via Web",
        "Remote code execution attempt through web application",
        "query",
        'alert.signature: *RCE* OR alert.signature: *remote code* OR alert.signature: *command injection* OR alert.signature: *code execution*',
        "TA0001","Initial Access","T1190","Exploit Public-Facing Application",
        index=["suricata-alerts-*"], severity="high", risk=73),

    mkrule("[SOC] SSH Brute Force - Multiple Failures",
        "Multiple SSH authentication failures from same IP",
        "threshold",
        'rule.groups: *authentication_failed* OR rule.description: *Failed password* OR rule.description: *authentication failure*',
        "TA0001","Initial Access","T1078","Valid Accounts",
        index=["wazuh-alerts-4.x-*","soc-logs-enriched-*"],
        threshold={"field": "agent.ip", "value": 5}),

    mkrule("[SOC] Phishing Attachment Execution",
        "Suspicious script execution following file download",
        "query",
        'alert.signature: *phishing* OR alert.signature: *malicious attachment* OR rule.description: *phishing*',
        "TA0001","Initial Access","T1566","Phishing",
        sub_id="T1566.001", sub_name="Spearphishing Attachment"),

    mkrule("[SOC] External Remote Service Access",
        "Authentication to external remote service (RDP/VPN/Citrix)",
        "query",
        'destination.port: 3389 OR destination.port: 5900 OR alert.signature: *rdp* OR alert.signature: *vnc*',
        "TA0001","Initial Access","T1133","External Remote Services",
        index=["suricata-alerts-*","soc-logs-enriched-*"]),

    # ── TA0002 Execution ──────────────────────────────────────────────
    mkrule("[SOC] Shell Command via Web Request",
        "HTTP request containing shell command patterns",
        "query",
        'http.url: *cmd=* OR http.url: *exec=* OR http.url: *system(* OR alert.signature: *webshell*',
        "TA0002","Execution","T1059","Command and Scripting Interpreter",
        index=["suricata-alerts-*","soc-logs-enriched-*"],
        sub_id="T1059.004", sub_name="Unix Shell"),

    mkrule("[SOC] Python/Perl Script Execution",
        "Scripting language executed by web process or from suspicious path",
        "query",
        'rule.description: *python -c* OR rule.description: *perl -e* OR rule.description: *ruby -e* OR rule.description: *bash -i*',
        "TA0002","Execution","T1059","Command and Scripting Interpreter",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1059.006", sub_name="Python"),

    mkrule("[SOC] Cron Job Executed",
        "Scheduled task execution logged",
        "query",
        'rule.description: *cron* OR rule.groups: *cron* OR syscheck.path: */etc/cron*',
        "TA0002","Execution","T1053","Scheduled Task/Job",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1053.003", sub_name="Cron"),

    mkrule("[SOC] System Service Execution",
        "Systemd service created or started",
        "query",
        'rule.description: *systemctl* OR rule.description: *service started* OR syscheck.path: */etc/systemd/*',
        "TA0002","Execution","T1569","System Services",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1569.002", sub_name="Service Execution"),

    mkrule("[SOC] Binary Executed from Temp Directory",
        "Executable run from /tmp, /dev/shm or other temp locations",
        "query",
        'rule.description: */tmp/* AND rule.description: *executed* OR rule.description: */dev/shm/*',
        "TA0002","Execution","T1059","Command and Scripting Interpreter",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] Process Injection Attempt",
        "ptrace or LD_PRELOAD used for process injection",
        "query",
        'rule.description: *ptrace* OR rule.description: *LD_PRELOAD* OR rule.description: *process injection*',
        "TA0002","Execution","T1055","Process Injection",
        index=["wazuh-alerts-4.x-*"], severity="high", risk=73),

    # ── TA0003 Persistence ────────────────────────────────────────────
    mkrule("[SOC] SSH Authorized Keys Modified",
        "SSH authorized_keys file added or modified",
        "query",
        'syscheck.path: *authorized_keys* OR rule.description: *authorized_keys*',
        "TA0003","Persistence","T1098","Account Manipulation",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1098.004", sub_name="SSH Authorized Keys"),

    mkrule("[SOC] New Cron Job Created",
        "New entry added to crontab",
        "query",
        'syscheck.path: */cron* AND syscheck.event: added OR rule.description: *crontab -e*',
        "TA0003","Persistence","T1053","Scheduled Task/Job",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1053.003", sub_name="Cron"),

    mkrule("[SOC] New User Account Added",
        "New local user account created on system",
        "query",
        'rule.description: *useradd* OR rule.description: *new user* OR rule.description: *account created*',
        "TA0003","Persistence","T1136","Create Account",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1136.001", sub_name="Local Account"),

    mkrule("[SOC] Systemd Service Persistence",
        "New systemd service file created",
        "query",
        'syscheck.path: */systemd/system/*.service AND syscheck.event: added',
        "TA0003","Persistence","T1543","Create or Modify System Process",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1543.002", sub_name="Systemd Service"),

    mkrule("[SOC] Init Script Modified",
        "System init or rc startup file modified",
        "query",
        'syscheck.path: */etc/init* OR syscheck.path: */etc/rc* OR syscheck.path: */etc/profile.d/*',
        "TA0003","Persistence","T1037","Boot or Logon Initialization Scripts",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1037.004", sub_name="RC Scripts"),

    mkrule("[SOC] Browser Extension Added",
        "Browser extension or plugin installed",
        "query",
        'syscheck.path: */.mozilla/firefox/*/extensions* OR syscheck.path: */.config/chromium/Default/Extensions*',
        "TA0003","Persistence","T1176","Browser Extensions",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] Webshell File Created",
        "PHP or script file created in web directory",
        "query",
        '(syscheck.path: */var/www/* OR syscheck.path: */html/*) AND (syscheck.path: *.php OR syscheck.path: *.jsp) AND syscheck.event: added',
        "TA0003","Persistence","T1505","Server Software Component",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1505.003", sub_name="Web Shell", severity="high", risk=73),

    # ── TA0004 Privilege Escalation ───────────────────────────────────
    mkrule("[SOC] Sudo Command Executed",
        "User executed command via sudo",
        "query",
        'rule.description: *sudo* OR rule.groups: *sudo* OR rule.description: *NOPASSWD*',
        "TA0004","Privilege Escalation","T1548","Abuse Elevation Control Mechanism",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1548.003", sub_name="Sudo and Sudo Caching"),

    mkrule("[SOC] SUID Binary Executed",
        "SUID/SGID bit set on file or suspicious SUID binary run",
        "query",
        'rule.description: *suid* OR rule.description: *setuid* OR rule.description: *SGID*',
        "TA0004","Privilege Escalation","T1548","Abuse Elevation Control Mechanism",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1548.001", sub_name="Setuid and Setgid"),

    mkrule("[SOC] Container Escape Attempt",
        "Privileged container actions or host mount access",
        "query",
        'rule.description: *docker.sock* OR rule.description: *privileged container* OR rule.description: *container escape*',
        "TA0004","Privilege Escalation","T1611","Escape to Host",
        index=["wazuh-alerts-4.x-*"], severity="high", risk=73),

    mkrule("[SOC] Kernel Exploit Attempt",
        "Known kernel exploitation pattern detected",
        "query",
        'alert.signature: *exploit* AND alert.signature: *kernel* OR rule.description: *kernel exploit*',
        "TA0004","Privilege Escalation","T1068","Exploitation for Privilege Escalation",
        index=["suricata-alerts-*","wazuh-alerts-4.x-*"], severity="high", risk=73),

    mkrule("[SOC] /etc/passwd or sudoers Modified",
        "Critical privilege configuration file modified",
        "query",
        'syscheck.path: */etc/sudoers* OR syscheck.path: */etc/passwd* OR syscheck.path: */etc/shadow*',
        "TA0004","Privilege Escalation","T1548","Abuse Elevation Control Mechanism",
        index=["wazuh-alerts-4.x-*"], severity="high", risk=73),

    # ── TA0005 Defense Evasion ────────────────────────────────────────
    mkrule("[SOC] Audit Logs Cleared",
        "Auditd or system log file cleared or deleted",
        "query",
        'rule.description: *log cleared* OR rule.description: *audit cleared* OR rule.description: *logfile deleted* OR syscheck.event: deleted AND syscheck.path: */var/log/*',
        "TA0005","Defense Evasion","T1070","Indicator Removal",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1070.002", sub_name="Clear Linux or Mac System Logs"),

    mkrule("[SOC] File Timestamp Modified",
        "File timestamp manipulation (timestomping)",
        "query",
        'rule.description: *touch -t* OR rule.description: *timestamp* OR rule.description: *timestomp*',
        "TA0005","Defense Evasion","T1070","Indicator Removal",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1070.006", sub_name="Timestomp"),

    mkrule("[SOC] chmod to Hide Permissions",
        "File permissions changed to hide malicious activity",
        "query",
        'rule.description: *chmod 777* OR rule.description: *chmod 000* OR rule.description: *permission change*',
        "TA0005","Defense Evasion","T1222","File and Directory Permissions Modification",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1222.002", sub_name="Linux and Mac File and Directory Permissions Modification"),

    mkrule("[SOC] Rootkit Indicators",
        "Rootkit-related file or module detected",
        "query",
        'rule.description: *rootkit* OR rule.description: *lkm* OR rule.description: *kernel module loaded*',
        "TA0005","Defense Evasion","T1014","Rootkit",
        index=["wazuh-alerts-4.x-*"], severity="high", risk=73),

    mkrule("[SOC] Process Masquerading",
        "Process name matches known system binary from unusual path",
        "query",
        'rule.description: *masquerade* OR alert.signature: *masquerade* OR rule.description: *fake process*',
        "TA0005","Defense Evasion","T1036","Masquerading",
        index=["wazuh-alerts-4.x-*","suricata-alerts-*"],
        sub_id="T1036.005", sub_name="Match Legitimate Name or Location"),

    mkrule("[SOC] Obfuscated Script Execution",
        "Heavily encoded or obfuscated command detected",
        "query",
        'rule.description: *base64 -d* OR rule.description: *base64 --decode* OR http.url: *eval(base64* OR alert.signature: *obfuscat*',
        "TA0005","Defense Evasion","T1027","Obfuscated Files or Information",
        index=["wazuh-alerts-4.x-*","suricata-alerts-*"]),

    mkrule("[SOC] Security Tool Disabled",
        "IDS, firewall or other security control stopped/disabled",
        "query",
        'rule.description: *iptables -F* OR rule.description: *ufw disable* OR rule.description: *apparmor* OR rule.description: *setenforce 0*',
        "TA0005","Defense Evasion","T1562","Impair Defenses",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1562.001", sub_name="Disable or Modify Tools", severity="high", risk=73),

    # ── TA0006 Credential Access ──────────────────────────────────────
    mkrule("[SOC] /etc/shadow Read Attempt",
        "Attempt to read shadow password file",
        "query",
        'syscheck.path: */etc/shadow* OR rule.description: *shadow file* OR rule.description: *passwd file read*',
        "TA0006","Credential Access","T1003","OS Credential Dumping",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1003.008", sub_name="/etc/passwd and /etc/shadow"),

    mkrule("[SOC] SSH Key Theft",
        "Private SSH key file accessed from unusual process",
        "query",
        'syscheck.path: */.ssh/id_rsa* OR syscheck.path: */.ssh/id_ed25519* OR rule.description: *private key*',
        "TA0006","Credential Access","T1552","Unsecured Credentials",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1552.004", sub_name="Private Keys"),

    mkrule("[SOC] Credential Files in Web Request",
        "Web request attempting to read configuration files with credentials",
        "query",
        'http.url: *.env* OR http.url: *config.php* OR http.url: *wp-config* OR http.url: *.git/config*',
        "TA0006","Credential Access","T1552","Unsecured Credentials",
        index=["suricata-alerts-*","soc-logs-enriched-*"],
        sub_id="T1552.001", sub_name="Credentials In Files"),

    mkrule("[SOC] Brute Force - Multiple Failures Threshold",
        "5+ authentication failures from single source",
        "threshold",
        'rule.groups: *authentication_failed* OR rule.description: *Failed password* OR rule.description: *invalid user*',
        "TA0006","Credential Access","T1110","Brute Force",
        index=["wazuh-alerts-4.x-*","soc-logs-enriched-*"],
        threshold={"field": "agent.name", "value": 5},
        sub_id="T1110.001", sub_name="Password Guessing"),

    mkrule("[SOC] Password Spray Attempt",
        "Same password tried across multiple accounts",
        "query",
        'alert.signature: *password spray* OR rule.description: *password spray* OR rule.description: *multiple accounts failed*',
        "TA0006","Credential Access","T1110","Brute Force",
        index=["wazuh-alerts-4.x-*","suricata-alerts-*"],
        sub_id="T1110.003", sub_name="Password Spraying"),

    mkrule("[SOC] Mimikatz / Credential Dumper Signature",
        "Known credential dumping tool signature in network or logs",
        "query",
        'alert.signature: *mimikatz* OR alert.signature: *credential dump* OR rule.description: *mimikatz*',
        "TA0006","Credential Access","T1003","OS Credential Dumping",
        index=["suricata-alerts-*","wazuh-alerts-4.x-*"], severity="high", risk=73),

    # ── TA0007 Discovery ──────────────────────────────────────────────
    mkrule("[SOC] Network Scan - Port Discovery",
        "Suricata detected active network port scanning",
        "query",
        'alert.category: *Network Scan* OR alert.signature: *SCAN* OR alert.signature: *Port Scan*',
        "TA0007","Discovery","T1046","Network Service Discovery",
        index=["suricata-alerts-*"]),

    mkrule("[SOC] System Enumeration Commands",
        "System info gathering commands run (uname, hostname, whoami, id)",
        "query",
        'rule.description: *uname -a* OR rule.description: *hostname* OR rule.description: *whoami* OR rule.description: *id command*',
        "TA0007","Discovery","T1082","System Information Discovery",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] Network Interface Enumeration",
        "Network configuration enumerated (ifconfig, ip a, netstat)",
        "query",
        'rule.description: *ifconfig* OR rule.description: *ip addr* OR rule.description: *netstat -an* OR rule.description: *network interface*',
        "TA0007","Discovery","T1016","System Network Configuration Discovery",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] User and Group Enumeration",
        "User account or group information gathered",
        "query",
        'rule.description: *cat /etc/passwd* OR rule.description: *getent passwd* OR rule.description: *user enumeration*',
        "TA0007","Discovery","T1087","Account Discovery",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1087.001", sub_name="Local Account"),

    mkrule("[SOC] Process Discovery",
        "Running processes enumerated (ps aux, top)",
        "query",
        'rule.description: *ps aux* OR rule.description: *process list* OR rule.description: *ps -ef*',
        "TA0007","Discovery","T1057","Process Discovery",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] File and Directory Discovery",
        "Broad file system enumeration with find or ls",
        "query",
        'rule.description: *find / -name* OR rule.description: *find /etc* OR rule.description: *ls -la /root*',
        "TA0007","Discovery","T1083","File and Directory Discovery",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] Software Discovery",
        "Installed software enumerated (dpkg, rpm, pip list)",
        "query",
        'rule.description: *dpkg -l* OR rule.description: *rpm -qa* OR rule.description: *pip list* OR rule.description: *apt list*',
        "TA0007","Discovery","T1518","Software Discovery",
        index=["wazuh-alerts-4.x-*"]),

    # ── TA0008 Lateral Movement ───────────────────────────────────────
    mkrule("[SOC] SSH Successful Login from New Host",
        "Successful SSH authentication from previously unseen source",
        "query",
        'rule.description: *Accepted password* OR rule.description: *Accepted publickey* OR rule.id: "5715"',
        "TA0008","Lateral Movement","T1021","Remote Services",
        index=["wazuh-alerts-4.x-*","soc-logs-enriched-*"],
        sub_id="T1021.004", sub_name="SSH"),

    mkrule("[SOC] FTP Login and File Transfer",
        "FTP session with file transfer activity",
        "query",
        'destination.port: 21 OR alert.signature: *FTP Login* OR alert.signature: *FTP command* OR network.protocol: ftp',
        "TA0008","Lateral Movement","T1570","Lateral Tool Transfer",
        index=["suricata-alerts-*","soc-logs-enriched-*"]),

    mkrule("[SOC] Internal Host Scanning",
        "Host scanning internal subnet - possible lateral movement pivot",
        "query",
        'alert.signature: *internal scan* OR (alert.category: *Network Scan* AND source.ip: 172.18.*)',
        "TA0008","Lateral Movement","T1021","Remote Services",
        index=["suricata-alerts-*"],
        sub_id="T1021.001", sub_name="Remote Desktop Protocol"),

    mkrule("[SOC] RDP Connection Attempt",
        "Remote Desktop Protocol connection to or from victim host",
        "query",
        'destination.port: 3389 OR alert.signature: *RDP* OR rule.description: *remote desktop*',
        "TA0008","Lateral Movement","T1021","Remote Services",
        index=["suricata-alerts-*","wazuh-alerts-4.x-*"],
        sub_id="T1021.001", sub_name="Remote Desktop Protocol"),

    mkrule("[SOC] SMB/Network Share Access",
        "SMB connection or network share access detected",
        "query",
        'destination.port: 445 OR destination.port: 139 OR alert.signature: *SMB* OR alert.signature: *network share*',
        "TA0008","Lateral Movement","T1021","Remote Services",
        index=["suricata-alerts-*"],
        sub_id="T1021.002", sub_name="SMB/Windows Admin Shares"),

    # ── TA0009 Collection ─────────────────────────────────────────────
    mkrule("[SOC] Archive Created for Staging",
        "tar/zip/gzip archive created from multiple files",
        "query",
        'rule.description: *tar czf* OR rule.description: *zip -r* OR rule.description: *archive created* OR syscheck.path: *.tar.gz AND syscheck.event: added',
        "TA0009","Collection","T1560","Archive Collected Data",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1560.001", sub_name="Archive via Utility"),

    mkrule("[SOC] Database Dump Command",
        "Database export or dump command executed",
        "query",
        'rule.description: *mysqldump* OR rule.description: *pg_dump* OR rule.description: *mongodump* OR rule.description: *sqlite3 .dump*',
        "TA0009","Collection","T1005","Data from Local System",
        index=["wazuh-alerts-4.x-*"], severity="high", risk=73),

    mkrule("[SOC] Config File Staging",
        "Multiple config files copied to staging location",
        "query",
        'syscheck.path: */tmp/* AND (syscheck.path: *.conf OR syscheck.path: *.config OR syscheck.path: *.yml) AND syscheck.event: added',
        "TA0009","Collection","T1074","Data Staged",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1074.001", sub_name="Local Data Staging"),

    mkrule("[SOC] Email/IMAP Harvesting",
        "IMAP or SMTP connection for potential email collection",
        "query",
        'destination.port: 143 OR destination.port: 993 OR alert.signature: *IMAP* OR alert.signature: *email harvest*',
        "TA0009","Collection","T1114","Email Collection",
        index=["suricata-alerts-*"],
        sub_id="T1114.002", sub_name="Remote Email Collection"),

    mkrule("[SOC] Screen or Input Capture",
        "Tool associated with screen capture or keylogging",
        "query",
        'rule.description: *scrot* OR rule.description: *xwd* OR rule.description: *keylogger* OR alert.signature: *screen capture*',
        "TA0009","Collection","T1113","Screen Capture",
        index=["wazuh-alerts-4.x-*","suricata-alerts-*"]),

    # ── TA0011 Command and Control ────────────────────────────────────
    mkrule("[SOC] Metasploit Meterpreter Signature",
        "Known Metasploit/Meterpreter traffic detected by Suricata",
        "query",
        'alert.signature: *Meterpreter* OR alert.signature: *Metasploit* OR alert.signature: *msfconsole*',
        "TA0011","Command and Control","T1071","Application Layer Protocol",
        index=["suricata-alerts-*"], severity="high", risk=73),

    mkrule("[SOC] Netcat / Reverse Shell",
        "Netcat or reverse shell connection detected",
        "query",
        'alert.signature: *netcat* OR alert.signature: *reverse shell* OR rule.description: *nc -e* OR rule.description: *bash -i >& /dev/tcp*',
        "TA0011","Command and Control","T1071","Application Layer Protocol",
        index=["suricata-alerts-*","wazuh-alerts-4.x-*"],
        severity="high", risk=73),

    mkrule("[SOC] Beacon - Regular Interval C2",
        "Regular outbound connections at fixed interval suggesting beacon",
        "threshold",
        'destination.port: (80 OR 443 OR 8080 OR 4444 OR 1337)',
        "TA0011","Command and Control","T1071","Application Layer Protocol",
        index=["suricata-alerts-*"],
        threshold={"field": "destination.ip", "value": 20}),

    mkrule("[SOC] Non-Standard Port Outbound",
        "Outbound connection on unusual/non-standard port",
        "query",
        'alert.signature: *non-standard port* OR destination.port: 4444 OR destination.port: 1337 OR destination.port: 6666 OR destination.port: 31337',
        "TA0011","Command and Control","T1571","Non-Standard Port",
        index=["suricata-alerts-*"]),

    mkrule("[SOC] DNS Tunneling Pattern",
        "Unusually long DNS queries or high-frequency DNS suggesting tunneling",
        "query",
        'alert.signature: *DNS tunnel* OR alert.signature: *DNS exfil* OR alert.signature: *long DNS query*',
        "TA0011","Command and Control","T1071","Application Layer Protocol",
        index=["suricata-alerts-*"],
        sub_id="T1071.004", sub_name="DNS"),

    mkrule("[SOC] TOR / Dark Web Traffic",
        "Connection to known TOR exit node or dark web traffic",
        "query",
        'alert.signature: *TOR* OR alert.signature: *Tor exit* OR alert.signature: *onion*',
        "TA0011","Command and Control","T1090","Proxy",
        index=["suricata-alerts-*"],
        sub_id="T1090.003", sub_name="Multi-hop Proxy"),

    # ── TA0010 Exfiltration ───────────────────────────────────────────
    mkrule("[SOC] Large Data Upload",
        "Unusually large outbound HTTP POST transfer",
        "query",
        'alert.signature: *data exfil* OR alert.category: *Potentially Bad Traffic* AND http.request.method: POST',
        "TA0010","Exfiltration","T1048","Exfiltration Over Alternative Protocol",
        index=["suricata-alerts-*"],
        sub_id="T1048.003", sub_name="Exfiltration Over Unencrypted Non-C2 Protocol"),

    mkrule("[SOC] Cloud Storage Exfiltration",
        "Data uploaded to cloud storage service",
        "query",
        'http.hostname: *dropbox.com* OR http.hostname: *drive.google.com* OR http.hostname: *onedrive.live.com* OR alert.signature: *cloud upload*',
        "TA0010","Exfiltration","T1567","Exfiltration Over Web Service",
        index=["suricata-alerts-*","soc-logs-enriched-*"],
        sub_id="T1567.002", sub_name="Exfiltration to Cloud Storage"),

    mkrule("[SOC] FTP Exfiltration",
        "Files transferred out via FTP",
        "query",
        'destination.port: 21 AND alert.signature: *STOR* OR alert.signature: *ftp upload* OR alert.signature: *ftp exfil*',
        "TA0010","Exfiltration","T1048","Exfiltration Over Alternative Protocol",
        index=["suricata-alerts-*"],
        sub_id="T1048.003", sub_name="Exfiltration Over Unencrypted Non-C2 Protocol"),

    mkrule("[SOC] Email Exfiltration via SMTP",
        "Outbound SMTP with large attachment",
        "query",
        'destination.port: 25 OR destination.port: 587 OR alert.signature: *SMTP* OR alert.signature: *email exfil*',
        "TA0010","Exfiltration","T1048","Exfiltration Over Alternative Protocol",
        index=["suricata-alerts-*"],
        sub_id="T1048.002", sub_name="Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"),

    mkrule("[SOC] Archive Transferred Out",
        "Compressed archive file transferred to external host",
        "query",
        'http.url: *.tar.gz OR http.url: *.zip OR http.url: *.7z AND http.request.method: POST',
        "TA0010","Exfiltration","T1041","Exfiltration Over C2 Channel",
        index=["suricata-alerts-*"]),

    # ── TA0040 Impact ─────────────────────────────────────────────────
    mkrule("[SOC] Ransomware Indicators",
        "Mass file modification or ransom note file creation",
        "query",
        'alert.signature: *ransomware* OR alert.signature: *ransom* OR syscheck.path: *README_FOR_DECRYPT* OR rule.description: *ransomware*',
        "TA0040","Impact","T1486","Data Encrypted for Impact",
        index=["suricata-alerts-*","wazuh-alerts-4.x-*"], severity="critical", risk=99),

    mkrule("[SOC] Service Stopped",
        "Critical system service stopped or killed",
        "query",
        'rule.description: *service stopped* OR rule.description: *daemon killed* OR rule.groups: *service_control*',
        "TA0040","Impact","T1489","Service Stop",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] Disk Wipe or Mass Delete",
        "Mass file deletion or disk write commands",
        "query",
        'rule.description: *rm -rf* OR rule.description: *shred* OR rule.description: *dd if=/dev/zero* OR syscheck.event: deleted',
        "TA0040","Impact","T1485","Data Destruction",
        index=["wazuh-alerts-4.x-*"], severity="critical", risk=99),

    mkrule("[SOC] System Shutdown / Reboot Command",
        "Shutdown or reboot initiated",
        "query",
        'rule.description: *shutdown* OR rule.description: *reboot* OR rule.description: *halt* OR rule.description: *poweroff*',
        "TA0040","Impact","T1529","System Shutdown/Reboot",
        index=["wazuh-alerts-4.x-*"]),

    mkrule("[SOC] DDoS / Flood Traffic",
        "High volume traffic indicating DoS attack",
        "query",
        'alert.category: *Attempted Denial of Service* OR alert.signature: *DDOS* OR alert.signature: *flood*',
        "TA0040","Impact","T1498","Network Denial of Service",
        index=["suricata-alerts-*"],
        sub_id="T1498.001", sub_name="Direct Network Flood"),

    mkrule("[SOC] Website Defacement Attempt",
        "Web server index file modified",
        "query",
        '(syscheck.path: */var/www/html/index* OR syscheck.path: */htdocs/index*) AND syscheck.event: modified',
        "TA0040","Impact","T1491","Defacement",
        index=["wazuh-alerts-4.x-*"],
        sub_id="T1491.001", sub_name="Internal Defacement"),
]

# ════════════════════════════════════════════════════════════════════
# CREATE RULES
# ════════════════════════════════════════════════════════════════════
created = skipped = failed = 0
tactic_counts = {}

for r in RULES:
    tactic = r["threat"][0]["tactic"]["name"]
    res, err = api("POST", "/api/detection_engine/rules", r)
    if err == "duplicate":
        skipped += 1
        tactic_counts[tactic] = tactic_counts.get(tactic, 0)
    elif err:
        failed += 1
        print(f"  ✗ {r['name'][:55]}: {err}")
    else:
        created += 1
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    time.sleep(0.2)

print(f"\n{'='*55}")
print(f"  Created: {created}  |  Already existed: {skipped}  |  Failed: {failed}")
print(f"  Total new custom rules: {created + skipped}")
print(f"\n  New rules per tactic:")
for t, n in sorted(tactic_counts.items()):
    print(f"    {t:30} +{n}")

# Final count
res, _ = api("GET", "/api/detection_engine/rules/_find?per_page=1")
total = res.get("total", 0) if res else 0
print(f"\n  Total rules in Kibana: {total}")
print(f"{'='*55}")
