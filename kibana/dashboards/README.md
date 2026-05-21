# Kibana Dashboards

## Manual Export Instructions

To export dashboards from Kibana UI:
1. Navigate to http://localhost:5601
2. Go to Stack Management → Saved Objects
3. Select dashboards to export
4. Click Export and save to this directory

## API Export (if dashboards exist)

```bash
docker exec kibana curl -s "localhost:5601/api/saved_objects/_export" \
  -H "kbn-xsrf: true" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"type": "dashboard"}' > wazuh-dashboards.ndjson
```

## Current Status
- No pre-configured dashboards found
- Create custom dashboards in Kibana UI for Wazuh alerts
- Export and commit them here for team sharing
