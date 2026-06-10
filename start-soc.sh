#!/usr/bin/env bash
LOG=~/soc-stack/startup.log
exec >> "$LOG" 2>&1
echo "[$(date '+%Y-%m-%d %H:%M:%S')] === SOC Auto-Start ==="
for i in $(seq 1 60); do
    sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
    docker info > /dev/null 2>&1 && break
    sleep 5
done
cd ~/soc-stack
docker compose up -d
docker compose -f docker-compose-lab.yml up -d 2>/dev/null || true
echo "[$(date '+%H:%M:%S')] $(docker ps -q | wc -l) containers running"
