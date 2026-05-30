#!/bin/bash
if [ -f /tmp/ossec.conf.override ]; then
    rm -rf /var/ossec/etc/ossec.conf
    cp /tmp/ossec.conf.override /var/ossec/etc/ossec.conf
    echo "✅ ossec.conf copied from override"
fi
exec /entrypoint.sh
