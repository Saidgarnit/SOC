#!/bin/bash
set -e

echo "[entrypoint] Copying filebeat.yml..."
cp /etc/filebeat-config/filebeat.yml /usr/share/filebeat/filebeat.yml
echo "[entrypoint] Config copied. First 5 lines:"
head -5 /usr/share/filebeat/filebeat.yml

echo "[entrypoint] Enabling modules from modules.d..."
for f in /usr/share/filebeat/modules.d/*.disabled; do
  base=$(basename "$f" .yml.disabled)
  src="/etc/filebeat-config/modules.d/${base}.yml"
  if [ -f "$src" ]; then
    cp "$src" "/usr/share/filebeat/modules.d/${base}.yml"
    echo "[entrypoint] Enabled module: $base"
  fi
done

echo "[entrypoint] Starting filebeat..."
exec /usr/local/bin/docker-entrypoint -e --strict.perms=false
