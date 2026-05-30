#!/bin/bash
echo "[cont-init] Applying ossec.conf override..."
if [ -f /tmp/ossec.conf.override ]; then
    mkdir -p /var/ossec/etc
    cp /tmp/ossec.conf.override /var/ossec/etc/ossec.conf
    echo "[cont-init] ossec.conf applied successfully"
else
    echo "[cont-init] WARNING: /tmp/ossec.conf.override not found"
fi
