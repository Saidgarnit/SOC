#!/bin/bash
# SOC Stack WSL Auto-Start
# Runs when WSL session starts

LOG="/home/said/soc-stack/startup.log"
echo "[$(date)] === SOC Stack Starting ===" >> $LOG

# Wait for Docker Desktop socket to be available
echo "[$(date)] Waiting for Docker..." >> $LOG
for i in $(seq 1 30); do
    docker info > /dev/null 2>&1 && break
    sleep 3
done

if ! docker info > /dev/null 2>&1; then
    echo "[$(date)] ERROR: Docker not available" >> $LOG
    exit 1
fi

echo "[$(date)] Docker ready" >> $LOG

# Step 1: Main stack
cd /home/said/soc-stack
docker compose -f /home/said/soc-stack/docker-compose.yml up -d >> $LOG 2>&1
echo "[$(date)] Main stack up" >> $LOG

# Step 2: Lab containers (orphans)
docker start victim-webapi victim-ftp kali-attacker victim-jenkins \
  victim-dvwa victim-windows victim-iot victim-database \
  victim-mail victim-dns fleet-server >> $LOG 2>&1
echo "[$(date)] Lab containers started" >> $LOG

# Step 3: Wait for initialization
sleep 90

# Step 4: Apply all fixes + memory limits
bash /home/said/soc-stack/fix-on-start.sh >> $LOG 2>&1
echo "[$(date)] === SOC Stack Ready ===" >> $LOG
