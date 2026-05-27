#!/usr/bin/env python3
"""
EQL-based kill chain sequence detector.
Runs every 5 minutes via cron inside elastalert container.
Queries ES for ordered tactic sequences per agent, fires Slack on hit.
"""
import json, os, sys, requests
from datetime import datetime, timezone

ES_HOST  = "http://elasticsearch:9200"
ES_USER  = "elastic"
ES_PASS  = "Kjd9r43ANUymjjcba0M6"
SLACK_WH = "https://hooks.slack.com/services/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"
LOOKBACK = "30m"

SEQUENCES = [
    {
        "name": "Initial Access → Execution → Privilege Escalation",
        "mitre": ["T1190", "T1059", "T1548"],
        "eql": """sequence by agent.name with maxspan=30m
  [any where rule.mitre.id like~ "*T1190*" or rule.groups like~ "*web*"]
  [any where rule.mitre.id like~ "*T1059*" or rule.mitre.tactic like~ "*Execution*"]
  [any where rule.mitre.id like~ "*T1548*" or rule.groups like~ "*privilege_escalation*"]"""
    },
    {
        "name": "Brute Force → Successful Logon → Lateral Movement",
        "mitre": ["T1110", "T1078", "T1021"],
        "eql": """sequence by agent.name with maxspan=30m
  [any where rule.mitre.id like~ "*T1110*" or rule.groups like~ "*brute_force*"]
  [any where rule.mitre.id like~ "*T1078*" or rule.id == "500401"]
  [any where rule.mitre.id like~ "*T1021*" or rule.mitre.tactic like~ "*Lateral*"]"""
    },
    {
        "name": "Discovery → Collection → Exfiltration",
        "mitre": ["T1046", "T1560", "T1048"],
        "eql": """sequence by agent.name with maxspan=30m
  [any where rule.mitre.tactic like~ "*Discovery*"]
  [any where rule.mitre.tactic like~ "*Collection*"]
  [any where rule.mitre.id like~ "*T1048*" or rule.mitre.tactic like~ "*Exfiltration*"]"""
    },
]

def query_eql(eql):
    try:
        r = requests.post(
            f"{ES_HOST}/wazuh-alerts-*/_eql/search",
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/json"},
            json={"query": eql, "size": 5,
                  "filter": {"range": {"@timestamp": {"gte": f"now-{LOOKBACK}"}}}},
            timeout=15
        )
        return r.json()
    except Exception as e:
        print(f"EQL query error: {e}")
        return None

def slack_alert(seq_name, agent, events):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = (
        f":chains: *KILL CHAIN SEQUENCE DETECTED*\n"
        f"*Sequence:* {seq_name}\n"
        f"*Agent:* {agent}\n"
        f"*Time:* {ts}\n"
        f"*Steps matched:* {len(events)}\n"
        f"*Last rule:* {events[-1].get('rule',{}).get('description','unknown') if events else 'n/a'}\n"
        f"Investigate immediately — ordered attack chain confirmed."
    )
    try:
        r = requests.post(SLACK_WH,
            json={"text": text, "username": "SOC Alerts", "icon_emoji": ":chains:"},
            timeout=10)
        return r.status_code == 200
    except Exception as e:
        print(f"Slack error: {e}")
        return False

def main():
    print(f"[{datetime.now()}] EQL sequence check starting...")
    fired = 0
    for seq in SEQUENCES:
        result = query_eql(seq["eql"])
        if not result:
            continue
        sequences = result.get("hits", {}).get("sequences", [])
        if not sequences:
            print(f"  {seq['name']}: no matches")
            continue
        for match in sequences:
            events = [e.get("_source", {}) for e in match.get("events", [])]
            agent = events[0].get("agent", {}).get("name", "unknown") if events else "unknown"
            print(f"  MATCH: {seq['name']} on agent={agent}")
            if slack_alert(seq["name"], agent, events):
                print(f"  Slack alert sent")
                fired += 1
            else:
                print(f"  Slack alert FAILED")
    print(f"[{datetime.now()}] Done. {fired} alerts fired.")

if __name__ == "__main__":
    main()
