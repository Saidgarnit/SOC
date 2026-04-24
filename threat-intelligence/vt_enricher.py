#!/usr/bin/env python3
"""
VirusTotal Enrichment Service
Watches Elasticsearch for new alerts and enriches them with VT data
"""
import requests
import json
import time
import os
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "675cb5b469a88a290d69d53f4bd343bb81ea333ae5bab1ad6ae0d821e2bcabb7")
ES_HOST    = os.getenv("ES_HOST", "http://localhost:9200")
VT_API_URL = "https://www.virustotal.com/api/v3"
POLL_INTERVAL = 30  # seconds between checks

# ── VirusTotal Functions ─────────────────────────────
def check_ip(ip):
    """Check IP reputation on VirusTotal"""
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"{VT_API_URL}/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_malicious":   stats.get("malicious", 0),
                "vt_suspicious":  stats.get("suspicious", 0),
                "vt_harmless":    stats.get("harmless", 0),
                "vt_undetected":  stats.get("undetected", 0),
                "vt_checked":     True,
                "vt_type":        "ip"
            }
    except Exception as e:
        print(f"[-] VT IP check error: {e}")
    return {"vt_checked": False}

def check_hash(file_hash):
    """Check file hash reputation on VirusTotal"""
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"{VT_API_URL}/files/{file_hash}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "vt_malicious":  stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless":   stats.get("harmless", 0),
                "vt_undetected": stats.get("undetected", 0),
                "vt_checked":    True,
                "vt_type":       "file"
            }
    except Exception as e:
        print(f"[-] VT hash check error: {e}")
    return {"vt_checked": False}

def get_vt_severity(vt_result):
    """Convert VT results to severity level"""
    if not vt_result.get("vt_checked"):
        return "UNKNOWN", 0
    malicious = vt_result.get("vt_malicious", 0)
    suspicious = vt_result.get("vt_suspicious", 0)
    if malicious >= 10:
        return "CRITICAL", 95
    elif malicious >= 5:
        return "HIGH", 80
    elif malicious >= 1 or suspicious >= 3:
        return "MEDIUM", 60
    else:
        return "LOW", 10

# ── Elasticsearch Functions ──────────────────────────
def get_recent_alerts(index="alerts-soc-threats-*", size=10):
    """Get recent alerts that haven't been VT-checked"""
    query = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must_not": [
                    {"exists": {"field": "vt_checked"}}
                ]
            }
        }
    }
    try:
        response = requests.post(
            f"{ES_HOST}/{index}/_search",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()["hits"]["hits"]
    except Exception as e:
        print(f"[-] ES query error: {e}")
    return []

def update_alert(index, doc_id, vt_data, severity, score):
    """Update alert document with VT enrichment"""
    update = {
        "doc": {
            **vt_data,
            "vt_severity":   severity,
            "vt_risk_score": score,
            "vt_checked_at": datetime.now(timezone.utc).isoformat()
        }
    }
    try:
        response = requests.post(
            f"{ES_HOST}/{index}/_update/{doc_id}",
            json=update,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        print(f"[-] ES update error: {e}")
    return False

# ── Main Loop ────────────────────────────────────────
def main():
    print("🔍 VirusTotal Enrichment Service Starting...")
    print(f"   ES Host:  {ES_HOST}")
    print(f"   API Key:  {VT_API_KEY[:8]}...")
    print(f"   Interval: {POLL_INTERVAL}s")
    print("─" * 50)

    while True:
        alerts = get_recent_alerts()
        if alerts:
            print(f"\n[*] Found {len(alerts)} unchecked alerts")
            for alert in alerts:
                doc_id = alert["_id"]
                index  = alert["_index"]
                source = alert["_source"]

                src_ip    = source.get("src_ip")
                file_hash = source.get("file_hash")
                rule_name = source.get("rule_name", source.get("alert", {}).get("signature", "unknown"))

                print(f"\n[*] Processing: {rule_name}")

                vt_result = {}
                if src_ip and not src_ip.startswith("192.168") \
                          and not src_ip.startswith("10.") \
                          and not src_ip.startswith("172."):
                    print(f"    Checking IP: {src_ip}")
                    vt_result = check_ip(src_ip)
                elif file_hash:
                    print(f"    Checking hash: {file_hash}")
                    vt_result = check_hash(file_hash)
                else:
                    vt_result = {"vt_checked": False, "vt_reason": "no_ip_or_hash"}

                severity, score = get_vt_severity(vt_result)
                success = update_alert(index, doc_id, vt_result, severity, score)

                if success:
                    malicious = vt_result.get("vt_malicious", 0)
                    print(f"    ✅ Updated: severity={severity} malicious={malicious}")
                else:
                    print(f"    ❌ Update failed")

                time.sleep(1)  # respect VT rate limits
        else:
            print(f"[*] No new alerts to check — sleeping {POLL_INTERVAL}s")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
