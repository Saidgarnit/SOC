#!/bin/bash
LOG="/home/said/soc-stack/startup.log"
echo "=== SOC Auto-Start $(date) ===" >> $LOG

# Fix Docker socket
sudo chmod 666 /var/run/docker.sock 2>/dev/null
export DOCKER_HOST=unix:///var/run/docker.sock
export PATH=$PATH:/usr/bin:/usr/local/bin

# Wait for Docker
for i in $(seq 1 30); do
    DOCKER_HOST=unix:///var/run/docker.sock docker ps >/dev/null 2>&1 && break
    sleep 2
done

cd /home/said/soc-stack
DOCKER_HOST=unix:///var/run/docker.sock docker compose up -d >> $LOG 2>&1

echo "SOC started: $(DOCKER_HOST=unix:///var/run/docker.sock docker ps -q | wc -l) containers" >> $LOG
