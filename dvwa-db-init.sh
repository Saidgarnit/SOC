#!/bin/bash
# =============================================================
#  dvwa-db-init.sh — EA-4 Permanent Fix
#  Automatically re-initialises DVWA + MariaDB after every reboot
#  Called by start-soc.sh after containers are up
# =============================================================

set -euo pipefail

LOG_PREFIX="[dvwa-db-init]"
DVWA_CONTAINER="victim-dvwa"
DB_CONTAINER="victim-database"
DB_NAME="dvwa"
DB_USER="dvwa"
DB_PASS="p@ssw0rd"
DB_ROOT_PASS="rootpass"

log() { echo "$LOG_PREFIX $(date '+%H:%M:%S') — $*"; }

# -------------------------------------------------------------
# STEP 1 — Wait for both containers to be running
# -------------------------------------------------------------
log "Waiting for $DVWA_CONTAINER and $DB_CONTAINER to be Up..."
for i in $(seq 1 30); do
    DVWA_UP=$(docker inspect -f '{{.State.Running}}' "$DVWA_CONTAINER" 2>/dev/null || echo "false")
    DB_UP=$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" 2>/dev/null || echo "false")
    if [ "$DVWA_UP" = "true" ] && [ "$DB_UP" = "true" ]; then
        log "Both containers are Up."
        break
    fi
    log "Attempt $i/30 — waiting 10s..."
    sleep 10
done

if [ "$DVWA_UP" != "true" ] || [ "$DB_UP" != "true" ]; then
    log "ERROR: Containers not ready after 5 minutes. Aborting."
    exit 1
fi

# Give MySQL inside victim-database a moment to be ready
log "Waiting 15s for MariaDB daemon to be ready inside $DB_CONTAINER..."
sleep 15

# -------------------------------------------------------------
# STEP 2 — Init MariaDB on victim-database container
# -------------------------------------------------------------
log "Creating DVWA database and user on $DB_CONTAINER..."

docker exec "$DB_CONTAINER" bash -c "
mysql -u root -p'${DB_ROOT_PASS}' <<'EOSQL'
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
EOSQL
" && log "Database + user created OK." || log "WARNING: DB init returned non-zero (may already exist — that's fine)."

# -------------------------------------------------------------
# STEP 3 — Install MariaDB client inside victim-dvwa (if absent)
# -------------------------------------------------------------
log "Checking MariaDB client in $DVWA_CONTAINER..."

MYSQL_PRESENT=$(docker exec "$DVWA_CONTAINER" which mysql 2>/dev/null || echo "")
if [ -z "$MYSQL_PRESENT" ]; then
    log "mysql client not found — installing..."
    docker exec "$DVWA_CONTAINER" bash -c "
        apt-get update -qq && apt-get install -y -q mariadb-client
    " && log "MariaDB client installed."
else
    log "mysql client already present — skipping install."
fi

# -------------------------------------------------------------
# STEP 4 — Write DVWA config.inc.php
# -------------------------------------------------------------
log "Writing DVWA config.inc.php..."

docker exec "$DVWA_CONTAINER" bash -c "cat > /var/www/html/config/config.inc.php <<'EOF'
<?php
\$_DVWA = array();
\$_DVWA['db_server']   = '${DB_CONTAINER}';
\$_DVWA['db_database'] = '${DB_NAME}';
\$_DVWA['db_user']     = '${DB_USER}';
\$_DVWA['db_password'] = '${DB_PASS}';
\$_DVWA['db_port']     = '3306';
\$_DVWA['default_security_level'] = 'low';
\$_DVWA['default_phpids_level']   = 'disabled';
\$_DVWA['recaptcha_public_key']   = '';
\$_DVWA['recaptcha_private_key']  = '';
EOF
" && log "config.inc.php written OK."

# -------------------------------------------------------------
# STEP 5 — Create DVWA tables via its own setup page
# -------------------------------------------------------------
log "Triggering DVWA /setup.php to create tables..."
sleep 5  # give Apache a moment

docker exec "$DVWA_CONTAINER" bash -c "
curl -s -o /dev/null -w '%{http_code}' \
  --cookie 'security=low' \
  'http://localhost/setup.php?setupDatabase=true'
" && log "DVWA setup.php triggered OK."

# -------------------------------------------------------------
# DONE
# -------------------------------------------------------------
log "EA-4 DVWA DB init complete. DVWA is ready at http://victim-dvwa/login.php"
log "  Default creds: admin / password"
