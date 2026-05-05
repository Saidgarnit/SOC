#!/bin/bash
cd ~/soc-stack

# Find the active UP bridge for soc-net
NET_ID=$(docker network inspect soc-stack_soc-net --format '{{.Id}}' | cut -c1-12)
BRIDGE="br-${NET_ID}"

echo "[suricata-bridge] Detected bridge: $BRIDGE"

# Update configs
python3 - << EOF
with open('suricata/config/suricata.yaml') as f:
    c = f.read()
import re
c = re.sub(r'(- interface:) .*', r'\1 $BRIDGE', c)
open('suricata/config/suricata.yaml','w').write(c)
EOF

sed -i "s|-i br-[a-z0-9]*|-i $BRIDGE|g" docker-compose.yml

echo "[suricata-bridge] Config updated — restarting Suricata..."
docker compose -f docker-compose.yml up -d --force-recreate suricata

# Enable promisc
docker run --rm --net=host --cap-add=NET_ADMIN alpine \
  ip link set $BRIDGE promisc on 2>/dev/null

echo "[suricata-bridge] Done."
