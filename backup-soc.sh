#!/bin/bash
BACKUP_DIR="/home/said/soc-stack/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup Kibana saved objects
curl -s "http://localhost:5601/api/saved_objects/_export" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -u "elastic:SOCstack2026!" \
  -d '{"type":["dashboard","visualization","index-pattern","lens","map","search"],"includeReferencesDeep":true}' \
  > "$BACKUP_DIR/kibana-saved-objects.ndjson" 2>/dev/null

# Backup Elasticsearch data views
curl -s "http://localhost:5601/api/data_views" \
  -u "elastic:SOCstack2026!" > "$BACKUP_DIR/data-views.json" 2>/dev/null

# Backup elastalert rules
cp -r /home/said/soc-stack/elastalert/rules "$BACKUP_DIR/elastalert-rules"

# Backup docker-compose files
cp /home/said/soc-stack/docker-compose*.yml "$BACKUP_DIR/" 2>/dev/null
cp /home/said/soc-stack/.env "$BACKUP_DIR/" 2>/dev/null
cp /home/said/soc-stack/wazuh/config/ossec.conf "$BACKUP_DIR/" 2>/dev/null

# Backup MISP API key
echo "MISP_KEY=$(grep MISP_API_KEY /home/said/soc-stack/.env)" >> "$BACKUP_DIR/credentials.txt"

# Commit to git
cd /home/said/soc-stack
git add -A && git commit -m "🔄 Automated backup $(date)" 2>/dev/null

echo "✓ Backup complete: $BACKUP_DIR"
