#!/usr/bin/env python3
import yara
import json
import os
import time
import socket
import datetime

RULES_PATH = "/rules/malware.yar"
LOGSTASH_HOST = "logstash"
LOGSTASH_PORT = 5000

SCAN_PATHS = [
    "/samples",
    "/victims/dvwa",
    "/victims/ubuntu-www",
    "/victims/ubuntu-tmp",
    "/victims/ftp",
]

def send_to_logstash(alert):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        message = json.dumps(alert).encode('utf-8')
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        sock.sendall(message)
        sock.close()
        print(f"[+] Alert sent: {alert['rule_name']}")
    except Exception as e:
        print(f"[-] Failed to send alert: {e}")

def scan_file(filepath, rules):
    try:
        matches = rules.match(filepath)
        if matches:
            for match in matches:
                alert = {
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "event_type": "yara_match",
                    "rule_name": match.rule,
                    "file_path": filepath,
                    "file_name": os.path.basename(filepath),
                    "mitre_technique": match.meta.get('mitre_technique', 'unknown'),
                    "mitre_tactic": match.meta.get('mitre_tactic', 'unknown'),
                    "severity": match.meta.get('severity', 'medium'),
                    "description": match.meta.get('description', ''),
                    "tags": ["yara", "malware_detection"],
                    "environment": "soc-lab"
                }
                send_to_logstash(alert)
                print(f"[!] MATCH: {match.rule} in {filepath}")
    except Exception as e:
        print(f"[-] Error scanning {filepath}: {e}")

def scan_directory(path, rules, scanned):
    if not os.path.exists(path):
        return
    try:
        for root, dirs, files in os.walk(path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if filepath not in scanned:
                    scan_file(filepath, rules)
                    scanned.add(filepath)
    except Exception as e:
        print(f"[-] Error walking {path}: {e}")

def continuous_scan():
    print("[*] Loading YARA rules...")
    rules = None
    for attempt in range(10):
        try:
            if os.path.exists(RULES_PATH):
                rules = yara.compile(RULES_PATH)
                print("[*] YARA rules loaded!")
                break
            else:
                print(f"[*] Waiting for rules... attempt {attempt+1}/10")
                time.sleep(5)
        except Exception as e:
            print(f"[-] Error loading rules: {e}, retrying...")
            time.sleep(5)

    if not rules:
        print("[-] Failed to load YARA rules. Exiting.")
        return

    print(f"[*] Watching: {SCAN_PATHS}")
    scanned = set()
    while True:
        for path in SCAN_PATHS:
            scan_directory(path, rules, scanned)
        time.sleep(10)

if __name__ == "__main__":
    continuous_scan()
