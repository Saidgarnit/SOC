# ============================================================
# docker-compose.yml Permanent Patches
# ============================================================
# Apply ALL of these changes to your docker-compose.yml.
# Each section shows the FULL replacement for that service block.
# ============================================================
# SUMMARY OF CHANGES
# ============================================================
#
# elasticsearch   : Add ELASTIC_PASSWORD env var + healthcheck
#                   references .env. Remove hardcoded password.
# elasticsearch-init: NEW service – runs init-es.sh once.
# kibana          : Replace SERVICEACCOUNTTOKEN with basic auth.
#                   Add XPACK_FLEET_AGENTS env vars (no more
#                   API calls each boot).
# misp            : Add healthcheck (300s start_period).
# connector-misp  : Change mem_limit 128m→512m. Change
#                   depends_on misp: service_started →
#                   service_healthy. Move MISP_KEY to .env.
# wazuh-manager   : Add healthcheck. Fix shared/default mount.
# victim containers: Add watchdog volume + entrypoint.
# logstash        : Set sincedb_path to /dev/null.
# elastalert      : Pass SLACK_WEBHOOK_URL from .env.
# ALL services    : Replace hardcoded passwords with ${VAR}.
#                   Add mem_limit / deploy.resources.limits.
# ============================================================

# ──────────────────────────────────────────────────────────────
# TOP OF FILE  (add before any service definition)
# ──────────────────────────────────────────────────────────────

# Replace any top-level `version:` line with:
# (docker compose v2 ignores it, but keep for compatibility)

# Add directly below the version line:
# ─────────────────────
# x-common-env: &common-env
#   env_file:
#     - .env
# ─────────────────────
# Then add   <<: *common-env   to each service that needs it.


# ══════════════════════════════════════════════════════════════
# 1. ELASTICSEARCH SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES:
#   - Add ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
#   - Healthcheck now uses ${ELASTIC_PASSWORD}
#   - Add deploy.resources.limits.memory
#   - Remove any hardcoded password from healthcheck test
# ══════════════════════════════════════════════════════════════

# FIND this in your healthcheck.test line (approx line 24):
#   "curl -s http://localhost:9200 ... sYVfKJCe2RCfELjf=GLa"
# REPLACE with:
#   ["CMD-SHELL", "curl -sf -u elastic:${ELASTIC_PASSWORD} http://localhost:9200/_cluster/health | grep -qE 'green|yellow'"]

# ADD to elasticsearch environment section:
#   - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}

# ADD after environment section:
#   deploy:
#     resources:
#       limits:
#         memory: ${ELASTICSEARCH_MEM_LIMIT:-4g}
#       reservations:
#         memory: 2g


# ══════════════════════════════════════════════════════════════
# 2. NEW: elasticsearch-init SERVICE  (add after elasticsearch)
# ══════════════════════════════════════════════════════════════
#
# Copy-paste this entire block into docker-compose.yml
# after the elasticsearch service definition:
# ══════════════════════════════════════════════════════════════

  elasticsearch-init:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch-init
    restart: "no"
    depends_on:
      elasticsearch:
        condition: service_healthy
    environment:
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
    volumes:
      - ./elasticsearch/init-es.sh:/init-es.sh:ro
      - ./elasticsearch:/output   # kibana-token.txt written here
    command: ["/bin/bash", "/init-es.sh"]
    networks:
      - soc-net


# ══════════════════════════════════════════════════════════════
# 3. KIBANA SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES:
#   - REMOVE:  ELASTICSEARCH_SERVICEACCOUNTTOKEN (stale token)
#   - ADD:     ELASTICSEARCH_USERNAME + ELASTICSEARCH_PASSWORD
#   - ADD:     Fleet env vars (eliminates API call each boot)
#   - ADD:     deploy.resources.limits
# ══════════════════════════════════════════════════════════════

# REMOVE this line from kibana environment:
#   - ELASTICSEARCH_SERVICEACCOUNTTOKEN=AAEAAWVsYXN0...

# ADD these lines to kibana environment:
#   - ELASTICSEARCH_USERNAME=${ELASTIC_USERNAME}
#   - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
#   - XPACK_FLEET_AGENTS_ELASTICSEARCH_HOSTS=["http://elasticsearch:9200"]
#   - XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=["${FLEET_SERVER_HOST}"]

# UPDATE healthcheck test to use env vars:
#   test: ["CMD-SHELL", "curl -sf -u ${ELASTIC_USERNAME}:${ELASTIC_PASSWORD} http://localhost:5601/api/status | grep -q 'available'"]

# ADD deploy block:
#   deploy:
#     resources:
#       limits:
#         memory: ${KIBANA_MEM_LIMIT:-1g}


# ══════════════════════════════════════════════════════════════
# 4. MISP SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES:
#   - ADD healthcheck (critical for connector-misp dependency)
#   - ADD deploy.resources.limits
#   - ADD watchdog volume mount
# ══════════════════════════════════════════════════════════════

# ADD to misp service (after the ports or volumes section):

    healthcheck:
      test: ["CMD", "/bin/bash", "/healthcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 300s   # MISP takes 5-10 min to initialize

# ADD to misp volumes:
#   - ./misp/healthcheck.sh:/healthcheck.sh:ro

# ADD deploy block:
#   deploy:
#     resources:
#       limits:
#         memory: ${MISP_MEM_LIMIT:-2g}


# ══════════════════════════════════════════════════════════════
# 5. CONNECTOR-MISP SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES (critical – fixes exit 143):
#   - mem_limit: 128m  →  use deploy.resources (512m minimum)
#   - depends_on misp: service_started → service_healthy
#   - MISP_KEY: hardcoded → ${MISP_API_KEY}
# ══════════════════════════════════════════════════════════════

# CHANGE depends_on section for connector-misp:
#   FIND:
#     misp:
#       condition: service_started
#   REPLACE WITH:
#     misp:
#       condition: service_healthy

# CHANGE MISP_KEY line:
#   FIND:    - MISP_KEY=VEE2IPlsLIxQbq7ufQxAuB7a9zHxRZxBtS7XjFIk
#   REPLACE: - MISP_KEY=${MISP_API_KEY}

# REMOVE any mem_limit: 128m line.
# ADD deploy block:
#   deploy:
#     resources:
#       limits:
#         memory: ${MISP_CONNECTOR_MEM_LIMIT:-512m}
#       reservations:
#         memory: 256m


# ══════════════════════════════════════════════════════════════
# 6. WAZUH-MANAGER SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES:
#   - Fix broken bind mount for shared agent config
#   - Add healthcheck
#   - Add deploy.resources.limits
# ══════════════════════════════════════════════════════════════

# FIND broken mount (approx line 132):
#   - ./wazuh/config/shared/default/agent.conf:/var/ossec/etc/shared/default/agent.conf
# REPLACE WITH (mounts the whole directory):
#   - ./wazuh/config/shared/default:/var/ossec/etc/shared/default:rw

# ADD healthcheck to wazuh-manager:
    healthcheck:
      test: ["CMD-SHELL", "curl -sf -k -u ${WAZUH_API_USER}:${WAZUH_API_PASSWORD} https://localhost:55000/ | grep -q 'Wazuh'"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s

# ADD deploy block:
#   deploy:
#     resources:
#       limits:
#         memory: ${WAZUH_MANAGER_MEM_LIMIT:-1g}


# ══════════════════════════════════════════════════════════════
# 7. VICTIM CONTAINERS (ubuntu, dvwa, iot, mail, ftp, etc.)
# ══════════════════════════════════════════════════════════════
#
# ADD to EVERY victim container service:
# ══════════════════════════════════════════════════════════════

# ADD to each victim's environment section:
#   - WAZUH_MANAGER=${WAZUH_MANAGER_HOST}
#   - WAZUH_REGISTRATION_PASSWORD=${WAZUH_REGISTRATION_PASSWORD}
#   - WAZUH_AGENT_NAME=<unique-name-per-container>

# ADD to each victim's volumes section:
#   - ./wazuh-agent/wazuh-watchdog.sh:/usr/local/bin/wazuh-watchdog.sh:ro

# For containers that already have a command/entrypoint, add watchdog
# to the entrypoint script. For containers without one, add:
#   command: >
#     /bin/bash -c "
#       chmod +x /usr/local/bin/wazuh-watchdog.sh &&
#       /usr/local/bin/wazuh-watchdog.sh &
#       tail -f /dev/null
#     "

# ADD deploy block:
#   deploy:
#     resources:
#       limits:
#         memory: 512m


# ══════════════════════════════════════════════════════════════
# 8. LOGSTASH SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES:
#   - Route sincedb to ephemeral path (eliminates stale offset bug)
#   - Add deploy.resources.limits
# ══════════════════════════════════════════════════════════════

# In your logstash/pipeline/*.conf file, change every file input:
#   FIND:    sincedb_path => "..."   (or no sincedb_path line)
#   REPLACE: sincedb_path => "/dev/null"
#
# This makes Logstash re-read eve.json from the beginning on every
# start, which is safe for a lab — events are deduplicated by ES.


# ══════════════════════════════════════════════════════════════
# 9. ELASTALERT SERVICE
# ══════════════════════════════════════════════════════════════
#
# CHANGES:
#   - Pass SLACK_WEBHOOK_URL from .env so rules can use it
#   - Add ES authentication env vars
#   - Add deploy.resources.limits
# ══════════════════════════════════════════════════════════════

# ADD to elastalert environment:
#   - ELASTICSEARCH_USER=${ELASTIC_USERNAME}
#   - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
#   - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}

# ADD deploy block:
#   deploy:
#     resources:
#       limits:
#         memory: ${ELASTALERT_MEM_LIMIT:-256m}


# ══════════════════════════════════════════════════════════════
# 10. start-soc.sh LINES TO REMOVE
# ══════════════════════════════════════════════════════════════
#
# Once the above changes are applied, these start-soc.sh sections
# are no longer needed (they were workarounds for the above bugs):
# ══════════════════════════════════════════════════════════════

# REMOVE (now handled by .env + docker-compose):
#   Lines 21-23:  Hardcoded PASS, fleet token
#   Lines 57-58:  Fleet Server Host force via Kibana API
#   Lines 237-244: docker update --memory caps
#   Lines 247-260: Wazuh index template PUT (now in init-es.sh)
#   Lines 263-266: _cluster/reroute (now in init-es.sh)
#   Lines 178-180: docker cp ossec.conf (now a volume mount)

# KEEP (still valid for WSL2 environment):
#   Lines 29-32:  mkdir/chown Wazuh log dirs
#   Lines 174-176: PID file cleanup (keep until watchdog is stable)
#   Lines 227-233: swap creation (until /etc/fstab is updated)
#   Lines 271-280: restart exit-127 containers (WSL2 quirk)
#   Lines 285-298: --force-recreate bind mounts (WSL2 quirk)
#   Lines 301-307: logstash sincedb reset (keep as safety net)
