#!/bin/bash
# After every up, run this script to inject configurations that couldn't be bind-mounted in WSL2
echo "Injecting workaround configs into containers..."
docker cp /home/said/soc-stack/filebeat/filebeat.yml filebeat:/usr/share/filebeat/filebeat.yml
docker cp /home/said/soc-stack/wazuh/config/ossec.conf wazuh-manager:/var/ossec/etc/ossec.conf
docker cp /home/said/soc-stack/misp/healthcheck.sh misp:/healthcheck.sh
docker exec misp chmod +x /healthcheck.sh
docker cp /home/said/soc-stack/suricata/rules/local.rules suricata:/etc/suricata/local.rules
docker kill -s USR2 suricata || docker restart suricata
echo "Configs copied successfully."
