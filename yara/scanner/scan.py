#!/usr/bin/env python3
import yara
import json
import os
import time
import socket
import datetime

RULES_PATH = "/rules/malware.yar"
SCAN_PATH = "/samples"
LOGSTASH_HOST = "logstash"
LOGSTASH_PORT = 5000

def send_to_logstash(alert):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = json.dumps(alert).encode('utf-8')
        sock.sendto(message, (LOGSTASH_HOST, LOGSTASH_PORT))
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

def continuous_scan():
    print("[*] Loading YARA rules...")
    # Retry loop for volume mount race condition
    rules = None
    for attempt in range(10):
        try:
            if os.path.exists(RULES_PATH):
                rules = yara.compile(RULES_PATH)
                print("[*] YARA rules loaded successfully!")
                break
            else:
                print(f"[*] Waiting for rules file... attempt {attempt+1}/10")
                time.sleep(5)
        except Exception as e:
            print(f"[-] Error loading rules: {e}, retrying...")
            time.sleep(5)

    if not rules:
        print("[-] Failed to load YARA rules after 10 attempts. Exiting.")
        return

    print(f"[*] Scanning directory: {SCAN_PATH}")
    scanned = set()
    while True:
        try:
            for filename in os.listdir(SCAN_PATH):
                filepath = os.path.join(SCAN_PATH, filename)
                if filepath not in scanned:
                    print(f"[*] Scanning: {filename}")
                    scan_file(filepath, rules)
                    scanned.add(filepath)
        except Exception as e:
            print(f"[-] Scan loop error: {e}")
        time.sleep(10)

if __name__ == "__main__":
    continuous_scan()
