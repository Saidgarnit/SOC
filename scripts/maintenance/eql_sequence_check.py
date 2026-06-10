#!/usr/bin/env python3
import requests
from datetime import datetime, timezone

ES_HOST  = "http://localhost:9200"
ES_USER  = "elastic"
ES_PASS  = "Kjd9r43ANUymjjcba0M6"
SLACK_WH = "https://hooks.slack.com/services/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"

SEQUENCES = [
    {
        "name": "Initial Access → Execution → Privilege Escalation",
        "eql": """sequence by agent.name with maxspan=30m
  [any where rule.groups == "web" or rule.groups == "attack" or rule.groups == "appsec"]
  [any where rule.mitre.tactic == "Execution" or rule.groups == "execution"]
  [any where rule.mitre.tactic == "Privilege Escalation" or rule.groups == "privilege-escalation"]"""
    },
    {
        "name": "Brute Force → Successful Logon → Lateral Movement",
        "eql": """sequence by agent.name with maxspan=30m
  [any where rule.groups == "authentication_failed" or rule.groups == "brute_force"]
  [any where rule.id == "500401" or rule.groups == "authentication_success"]
  [any where rule.mitre.tactic == "Lateral Movement"]"""
    },
    {
        "name": "Discovery → Collection → Exfiltration",
        "eql": """sequence by agent.name with maxspan=30m
  [any where rule.mitre.tactic == "Discovery"]
  [any where rule.mitre.tactic == "Collection"]
  [any where rule.mitre.tactic == "Exfiltration" or rule.groups == "dns_exfiltration"]"""
    },
]

def query_eql(eql):
    try:
        r = requests.post(
            f"{ES_HOST}/wazuh-alerts-*/_eql/search",
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/json"},
            json={
                "query": eql,
                "size": 5,
                "filter": {"range": {"@timestamp": {"gte": "now-30m"}}}
            },
            timeout=15
        )
        return r.json()
    except Exception as e:
        print(f"EQL error: {e}")
        return None

def slack_alert(seq_name, agent, events):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    last_rule = events[-1].get("rule", {}).get("description", "n/a") if events else "n/a"
    text = (
        f":chains: *KILL CHAIN SEQUENCE DETECTED*\n"
        f"*Sequence:* {seq_name}\n"
        f"*Agent:* {agent}\n"
        f"*Time:* {ts}\n"
        f"*Steps matched:* {len(events)}\n"
        f"*Last rule:* {last_rule}\n"
        f"Ordered attack chain confirmed — investigate immediately."
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
    print(f"[{datetime.now()}] Done. {fired} alerts fired.")
    main()

# Run with dedup if called directly
import hashlib, json as _json, os as _os, time as _time

def main_with_dedup():
    STATE_FILE = "/tmp/eql_sequence_state.json"
    COOLDOWN = 1800  # 30 min cooldown per sequence+agent combo

    try:
        state = _json.load(open(STATE_FILE))
    except:
        state = {}

    now = _time.time()
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
            key = hashlib.md5(f"{seq['name']}:{agent}".encode()).hexdigest()
            last_fired = state.get(key, 0)
            if now - last_fired < COOLDOWN:
                print(f"  SUPPRESSED (cooldown): {seq['name']} on {agent}")
                continue
            print(f"  MATCH: {seq['name']} on agent={agent}")
            if slack_alert(seq["name"], agent, events):
                state[key] = now
                fired += 1
                print(f"  Slack alert sent")
    _json.dump(state, open(STATE_FILE, 'w'))
    print(f"[{datetime.now()}] Done. {fired} alerts fired.")

if __name__ == "__main__":
    main_with_dedup()
