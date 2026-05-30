#!/bin/bash
# SOC Stack Auto-Start — runs on WSL boot
# Ensures all services survive restarts

LOG="/home/said/soc-stack/startup.log"
echo "=== SOC Auto-Start $(date) ===" >> $LOG

cd /home/said/soc-stack

# Wait for Docker
for i in {1..30}; do
    docker ps >/dev/null 2>&1 && break
    sleep 2
done

# Start all services
docker-compose up -d >> $LOG 2>&1
sleep 10
docker-compose -f docker-compose-lab.yml up -d >> $LOG 2>&1

# Ensure wazuh ossec.conf is a file not directory
sleep 30
WAZUH_STATUS=$(docker ps --filter name=wazuh-manager --format '{{.Status}}')
if echo "$WAZUH_STATUS" | grep -q "Up"; then
    CONF_TYPE=$(docker exec wazuh-manager file /var/ossec/etc/ossec.conf 2>/dev/null)
    if echo "$CONF_TYPE" | grep -q "directory"; then
        docker exec wazuh-manager bash -c "
            rm -rf /var/ossec/etc/ossec.conf
            cp /tmp/ossec.conf.backup /var/ossec/etc/ossec.conf 2>/dev/null || true
        "
    fi
fi

echo "SOC started: $(docker ps -q | wc -l) containers" >> $LOG
