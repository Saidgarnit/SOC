#!/bin/bash
LOG="/home/said/soc-stack/startup.log"
echo "[$(date)] === SOC Stack Starting ===" >> $LOG

# Wait for Docker
for i in $(seq 1 30); do
    docker info > /dev/null 2>&1 && break
    sleep 3
done
docker info > /dev/null 2>&1 || { echo "[$(date)] ERROR: Docker not available" >> $LOG; exit 1; }
echo "[$(date)] Docker ready" >> $LOG

cd /home/said/soc-stack

# Step 1: Main stack (excludes wazuh due to broken file mounts)
docker compose up -d >> $LOG 2>&1
echo "[$(date)] Main stack up" >> $LOG

# Step 2: Wazuh (run directly, bypassing broken compose mounts)
docker start wazuh-manager >> $LOG 2>&1 || \
docker run -d \
  --name wazuh-manager \
  --network soc-stack_soc-net \
  --restart unless-stopped \
  -p 1514:1514/tcp -p 1514:1514/udp -p 1515:1515 -p 55000:55000 \
  -e INDEXER_URL=http://elasticsearch:9200 \
  -e INDEXER_USERNAME=elastic \
  -e INDEXER_PASSWORD="sYVfKJCe2RCfELjf=GLa" \
  -e API_USERNAME=wazuh \
  -e API_PASSWORD=Wazuh1234! \
  -v /home/said/soc-stack/wazuh/rules:/var/ossec/etc/rules:rw \
  -v /home/said/soc-stack/wazuh/decoders:/var/ossec/etc/decoders:rw \
  -v /home/said/soc-stack/wazuh/logs:/var/ossec/logs \
  wazuh/wazuh-manager:4.7.5 >> $LOG 2>&1
echo "[$(date)] Wazuh started" >> $LOG

# Step 3: Start lab containers
docker start victim-webapi victim-ftp kali-attacker victim-jenkins \
  victim-dvwa victim-windows victim-iot victim-database \
  victim-mail victim-dns fleet-server >> $LOG 2>&1
echo "[$(date)] Lab containers started" >> $LOG

# Step 4: Wait then apply fixes
sleep 90
bash /home/said/soc-stack/fix-on-start.sh >> $LOG 2>&1

# Step 5: Fix wazuh ar.conf and restart analysisd
sleep 30
docker exec wazuh-manager bash -c "
  mkdir -p /var/ossec/etc/shared/default
  touch /var/ossec/etc/shared/ar.conf
  mkdir -p /var/ossec/logs/alerts
  mkdir -p /var/ossec/logs/archives/\$(date +%Y)
  mkdir -p /var/ossec/logs/firewall/\$(date +%Y)
  chown -R wazuh:wazuh /var/ossec/logs/
  chmod -R 750 /var/ossec/logs/
  /var/ossec/bin/wazuh-control restart
" >> $LOG 2>&1

echo "[$(date)] === SOC Stack Ready ===" >> $LOG
