#!/bin/bash
# Wait for Docker
for i in $(seq 1 15); do
    docker info >/dev/null 2>&1 && break
    sleep 2
done

# Wait for soc-net network
for i in $(seq 1 15); do
    docker network inspect soc-stack_soc-net &>/dev/null && break
    echo "Waiting for soc-stack_soc-net..." && sleep 3
done

# Get bridge interface from network ID
IFACE=$(docker network inspect soc-stack_soc-net --format '{{.Id}}' 2>/dev/null | cut -c1-12)
if [ -z "$IFACE" ]; then
    echo "[!] Could not detect soc-net interface — skipping"
    exit 0
fi
IFACE="br-${IFACE}"
echo "[*] Detected interface: $IFACE"

# Update docker-compose.yml command
sed -i "s|command: -i br-[a-f0-9]*|command: -i ${IFACE}|" ~/soc-stack/docker-compose.yml
echo "[*] Updated docker-compose.yml"

# Update suricata.yaml af-packet interface
sed -i "s|interface: br-[a-f0-9]*|interface: ${IFACE}|" ~/soc-stack/suricata/config/suricata.yaml
echo "[*] Updated suricata.yaml"

# Restart Suricata
docker compose -f ~/soc-stack/docker-compose.yml up -d --no-deps --force-recreate suricata 2>/dev/null
echo "[*] Suricata restarted with interface: $IFACE"
