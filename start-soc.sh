#!/bin/bash
# === SOC SELF-HEALING STARTUP SCRIPT ===

echo "🚀 Starting SOC Infrastructure..."
docker-compose up -d

echo "⏳ Waiting 30s for core services..."
sleep 30

echo "👻 Running Ghost Purge..."
python3 -c '
import requests
KIBANA = "http://localhost:5601"; auth = ("elastic", "sYVfKJCe2RCfELjf=GLa"); h = {"kbn-xsrf": "true"}
r = requests.get(f"{KIBANA}/api/fleet/agents?perPage=100", auth=auth, headers=h)
agents = r.json().get("items", [])
inventory = {}
for a in agents:
    name = a.get("local_metadata", {}).get("host", {}).get("hostname", "unknown")
    if name not in inventory: inventory[name] = []
    inventory[name].append(a)
for name, group in inventory.items():
    if len(group) > 1:
        group.sort(key=lambda x: x.get("last_checkin", ""), reverse=True)
        for g in group[1:]: requests.delete(f"{KIBANA}/api/fleet/agents/{g["id"]}", auth=auth, headers=h)
'

echo "💪 Nudging Agents..."
for c in victim-ubuntu victim-dvwa victim-iot victim-windows victim-mail victim-dns victim-jenkins victim-database victim-ftp victim-webapi; do
  docker exec $c pkill -HUP elastic-agent 2>/dev/null
done

echo "✅ Lab is Clean and Healthy."

# Start vt-enricher (paused if quota exceeded, auto-restarts at midnight)
docker start vt-enricher 2>/dev/null || true
