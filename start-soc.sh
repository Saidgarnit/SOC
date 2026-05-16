#!/bin/bash
# === SOC SELF-HEALING STARTUP SCRIPT ===
source "$(dirname "$0")/.env"

echo "🚀 Starting SOC Infrastructure..."

# ── Wait for Fleet Server (HTTP not HTTPS) ──
echo "⏳ Waiting for Fleet Server..."
until curl -s http://localhost:8220/api/status | grep -q "HEALTHY"; do
  sleep 5
done
echo "✅ Fleet Server is UP."

# ── Ghost Purge: remove duplicate/stale agents ──
echo "👻 Running Ghost Purge..."
python3 -c "
import requests
KIBANA = 'http://localhost:5601'
auth = ('elastic', '${ELASTIC_PASSWORD}')
h = {'kbn-xsrf': 'true', 'Content-Type': 'application/json'}
r = requests.get(f'{KIBANA}/api/fleet/agents?perPage=100', auth=auth, headers=h)
agents = r.json().get('items', [])
inventory = {}
for a in agents:
    name = a.get('local_metadata', {}).get('host', {}).get('hostname', 'unknown')
    if name not in inventory: inventory[name] = []
    inventory[name].append(a)
for name, group in inventory.items():
    if len(group) > 1:
        group.sort(key=lambda x: x.get('last_checkin', ''), reverse=True)
        for g in group[1:]:
            resp = requests.post(f'{KIBANA}/api/fleet/agents/{g[\"id\"]}/unenroll',
                auth=auth, headers=h, json={'revoke': True})
            print(f'  Unenrolled stale {name}: {g[\"id\"]} -> {resp.status_code}')
"

# ── Re-enroll agents that need it ──
echo "💪 Re-enrolling agents..."
bash "$(dirname "$0")/restart-agents.sh"

echo "✅ Lab is Clean and Healthy."

# Start vt-enricher
docker start vt-enricher 2>/dev/null || true
