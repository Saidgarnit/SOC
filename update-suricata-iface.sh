#!/bin/bash
# Wait for Docker to be ready
for i in $(seq 1 15); do
    docker info >/dev/null 2>&1 && break
    sleep 2
done

# Wait for the correct soc-net network to exist
for i in $(seq 1 15); do
    docker network inspect soc-stack_soc-net &>/dev/null && break
    echo "Waiting for soc-stack_soc-net network..." && sleep 3
done

# Get the bridge interface ID from the correct network
IFACE=$(docker network inspect soc-stack_soc-net --format '{{.Id}}' 2>/dev/null | cut -c1-12)

if [ -z "$IFACE" ]; then
    echo "[!] Could not detect soc-net interface — skipping Suricata update"
    exit 0
fi

IFACE="br-${IFACE}"
echo "[*] Detected interface: $IFACE"

# Only update if interface looks valid (not just "br-")
if [ "$IFACE" = "br-" ]; then
    echo "[!] Empty interface detected — skipping"
    exit 0
fi

sed -i "s|command: -i br-[a-f0-9]*|command: -i ${IFACE}|" ~/soc-stack/docker-compose.yml
echo "[*] Updated docker-compose.yml"

docker compose -f ~/soc-stack/docker-compose.yml up -d --no-deps suricata 2>/dev/null
echo "[*] Suricata restarted with interface: $IFACE"
