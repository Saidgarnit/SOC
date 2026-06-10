#!/bin/bash
echo "[$(date)] Pulling latest signatures from Emerging Threats..."
docker exec suricata suricata-update
docker exec suricata suricatasc -c ruleset-reload 2>/dev/null || docker compose restart suricata
echo "[$(date)] Suricata successfully armed with latest intelligence."
