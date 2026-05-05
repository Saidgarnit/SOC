#!/bin/bash
# ============================================================
# Elasticsearch Initialization Script
# ============================================================
# Runs once via elasticsearch-init container after ES is healthy.
# Handles: password verification, Kibana service token creation,
#          index templates (single-node replicas=0), shard recovery.
#
# Place at: elasticsearch/init-es.sh
# Make executable: chmod +x elasticsearch/init-es.sh
# ============================================================

set -euo pipefail

ES_URL="http://elasticsearch:9200"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"
TOKEN_FILE="/output/kibana-token.txt"

log() { echo "[ES-INIT] $(date '+%H:%M:%S') $*"; }

# ── Wait for ES to accept connections ────────────────────────
log "Waiting for Elasticsearch to be ready..."
for i in $(seq 1 60); do
    if curl -sf -u "elastic:${ELASTIC_PASSWORD}" \
            "${ES_URL}/_cluster/health" > /dev/null 2>&1; then
        log "Elasticsearch is ready."
        break
    fi
    log "  attempt ${i}/60 – retrying in 5s..."
    sleep 5
    if [ "$i" -eq 60 ]; then
        log "ERROR: Elasticsearch did not become ready in time."
        exit 1
    fi
done

# ── Verify / set elastic password ────────────────────────────
log "Verifying elastic user credentials..."
if ! curl -sf -u "elastic:${ELASTIC_PASSWORD}" \
        "${ES_URL}/_cluster/health" > /dev/null 2>&1; then
    log "Password mismatch – attempting reset from bootstrap credentials..."
    curl -sf -X POST "${ES_URL}/_security/user/elastic/_password" \
        -H "Content-Type: application/json" \
        -u "elastic:changeme" \
        -d "{\"password\":\"${ELASTIC_PASSWORD}\"}" \
        && log "Password reset successfully." \
        || log "WARNING: Could not reset password (may already be set)."
fi

# ── Create Kibana service account token ──────────────────────
log "Creating Kibana service account token..."
# Delete old token if it exists so we get a fresh one
curl -sf -X DELETE \
    "${ES_URL}/_security/service/elastic/kibana/credential/token/soc_kibana_token" \
    -u "elastic:${ELASTIC_PASSWORD}" > /dev/null 2>&1 || true

TOKEN_RESPONSE=$(curl -sf -X POST \
    "${ES_URL}/_security/service/elastic/kibana/credential/token/soc_kibana_token" \
    -H "Content-Type: application/json" \
    -u "elastic:${ELASTIC_PASSWORD}")

TOKEN=$(echo "${TOKEN_RESPONSE}" | grep -o '"value":"[^"]*' | cut -d'"' -f4)

if [ -z "${TOKEN}" ]; then
    log "WARNING: Could not create Kibana service account token."
    log "Kibana will fall back to basic auth (ELASTICSEARCH_USERNAME/PASSWORD)."
else
    log "Kibana service account token created."
    mkdir -p "$(dirname ${TOKEN_FILE})"
    echo "${TOKEN}" > "${TOKEN_FILE}"
    log "Token written to ${TOKEN_FILE}"
    log ">>> Add to .env:  KIBANA_SERVICE_TOKEN=${TOKEN}"
fi

# ── Default index template: 0 replicas for single-node ───────
log "Applying default index template (0 replicas, single-node)..."
curl -sf -X PUT --fail-with-body "${ES_URL}/_index_template/soc_default" \
    -H "Content-Type: application/json" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -d '{
        "index_patterns": ["*"],
        "priority": 0,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s"
            }
        }
    }' > /dev/null || true
log "Default template applied."

# ── Wazuh index template ─────────────────────────────────────
log "Applying Wazuh index template..."
curl -sf -X PUT --fail-with-body "${ES_URL}/_index_template/wazuh_alerts" \
    -H "Content-Type: application/json" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -d '{
        "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
        "priority": 10,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s"
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "@timestamp": {"type": "date"},
                    "rule": {
                        "properties": {
                            "level":       {"type": "long"},
                            "description": {"type": "text"},
                            "id":          {"type": "keyword"},
                            "groups":      {"type": "keyword"},
                            "mitre":       {"type": "object", "dynamic": true}
                        }
                    },
                    "agent": {
                        "properties": {
                            "id":   {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "ip":   {"type": "ip"}
                        }
                    },
                    "data": {"type": "object", "dynamic": true}
                }
            }
        }
    }' > /dev/null || true
log "Wazuh template applied."

# ── SOC enriched logs template ────────────────────────────────
log "Applying soc-logs-enriched index template..."
curl -sf -X PUT --fail-with-body "${ES_URL}/_index_template/soc_logs_enriched" \
    -H "Content-Type: application/json" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -d '{
        "index_patterns": ["soc-logs-enriched-*"],
        "priority": 10,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s"
            }
        }
    }' > /dev/null || true
log "soc-logs-enriched template applied."

# ── Retry failed shard allocations ───────────────────────────
log "Retrying any failed shard allocations..."
curl -sf -X POST "${ES_URL}/_cluster/reroute?retry_failed=true" \
    -u "elastic:${ELASTIC_PASSWORD}" > /dev/null || true

# ── Final health check ────────────────────────────────────────
HEALTH=$(curl -sf -u "elastic:${ELASTIC_PASSWORD}" \
    "${ES_URL}/_cluster/health?pretty" | grep '"status"' | tr -d ' ",' | cut -d: -f2)
log "Cluster health: ${HEALTH}"

log "================================================================"
log "Elasticsearch initialization COMPLETE."
log "  Cluster status : ${HEALTH}"
log "  Kibana token   : $([ -f ${TOKEN_FILE} ] && echo 'written to elasticsearch/kibana-token.txt' || echo 'not generated (check logs)')"
log "================================================================"
