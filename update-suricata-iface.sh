#!/bin/bash
# Suricata runs inside soc-net — always use eth0
echo "[*] Suricata uses eth0 (soc-net internal)"
# Ensure eth0 is set correctly
sed -i "s|command: -i [^ ]*|command: -i eth0|" ~/soc-stack/docker-compose.yml
sed -i "s|  - interface:.*|  - interface: eth0|" ~/soc-stack/suricata/config/suricata.yaml
echo "[*] Verified eth0 in docker-compose.yml and suricata.yaml"
