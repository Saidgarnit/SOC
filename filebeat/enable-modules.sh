#!/bin/bash
# Remove all .disabled files
rm -f /usr/share/filebeat/modules.d/*.disabled

# Copy our enabled modules
if [ -d /tmp/modules-override ]; then
    cp /tmp/modules-override/*.yml /usr/share/filebeat/modules.d/
    echo "✅ Modules enabled from override"
    ls -la /usr/share/filebeat/modules.d/
fi

# Start filebeat with all passed arguments
exec /usr/local/bin/docker-entrypoint "$@"
