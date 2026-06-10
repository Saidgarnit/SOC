#!/bin/bash
set -e
RULES_DIR="/home/said/soc-stack/elastalert/rules"
echo "[*] Validating YAML syntax..."
for f in $RULES_DIR/*.yaml; do
    python3 -c "import yaml; yaml.safe_load(open('$f'))" && echo "  OK: $(basename $f)" || echo "  FAIL: $(basename $f)"
done
echo "[*] Copying rules to container..."
docker cp $RULES_DIR/. elastalert:/opt/elastalert/rules/
echo "[*] Restarting Elastalert..."
docker restart elastalert
echo "[*] Done. Watching logs..."
sleep 5
docker logs elastalert --tail=20
