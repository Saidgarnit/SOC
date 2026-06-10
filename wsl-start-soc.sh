#!/usr/bin/env bash
# SOC Stack Auto-Start — waits for Docker, fixes socket, starts everything
LOG=~/soc-stack/startup.log
exec >> "$LOG" 2>&1
echo "[$(date '+%Y-%m-%d %H:%M:%S')] === SOC startup ==="

# Wait for Docker socket (up to 5 minutes)
for i in $(seq 1 60); do
    sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
    sudo chmod 666 /mnt/wsl/docker-desktop/shared-sockets/guest-services/docker.proxy.sock 2>/dev/null || true
    docker info > /dev/null 2>&1 && echo "[$(date '+%H:%M:%S')] Docker ready (${i}×5s)" && break
    [ "$i" -eq 60 ] && echo "[$(date '+%H:%M:%S')] Docker FAILED after 5min" && exit 1
    sleep 5
done

cd ~/soc-stack

echo "[$(date '+%H:%M:%S')] Starting main stack..."
docker compose up -d

echo "[$(date '+%H:%M:%S')] Starting lab (victims)..."
docker compose -f docker-compose-lab.yml up -d

echo "[$(date '+%H:%M:%S')] Containers: $(docker ps -q | wc -l) running"
echo "[$(date '+%H:%M:%S')] === SOC startup complete ==="
