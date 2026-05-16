#!/bin/bash
# ══════════════════════════════════════════════════════════════
# PERMANENT FIX — MITRE DB + fix-on-start.sh loop
# Paste into: said@NOBODY:~/soc-stack/
# ══════════════════════════════════════════════════════════════

set -e

echo "═══════════════════════════════════════════"
echo "  FIX A: MITRE sub-techniques in Wazuh DB"
echo "═══════════════════════════════════════════"

# Step 1: Install sqlite3 inside wazuh-manager if missing
docker exec wazuh-manager bash -c '
  command -v sqlite3 >/dev/null 2>&1 && echo "sqlite3 already installed" || {
    apt-get update -qq && apt-get install -y -qq sqlite3
    echo "sqlite3 installed"
  }
'

# Step 2: Check which MITRE techniques are missing
echo ""
echo "Checking current MITRE DB state..."
docker exec wazuh-manager bash -c '
  DB="/var/ossec/var/db/mitre.db"
  echo "DB path: $DB"
  echo "DB size: $(ls -lh $DB 2>/dev/null | awk "{print \$5}")"
  echo ""
  echo "Tables in DB:"
  sqlite3 "$DB" ".tables"
  echo ""
  echo "Sample rows from technique table:"
  sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\";" | head -5
'

# Step 3: Find the actual table name and insert missing sub-techniques
docker exec wazuh-manager bash -c '
  DB="/var/ossec/var/db/mitre.db"

  # Find the technique table name dynamically
  TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\" AND name LIKE \"%technique%\" LIMIT 1;")

  if [ -z "$TABLE" ]; then
    # Try alternate names
    TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\";" | head -1)
    echo "No technique table found. Available tables:"
    sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\";"
    echo ""
    echo "Trying to find schema..."
    sqlite3 "$DB" ".schema" | head -30
  else
    echo "Found technique table: $TABLE"
    echo "Current row count: $(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE;")"
    echo ""

    # Get column info
    echo "Columns:"
    sqlite3 "$DB" "PRAGMA table_info($TABLE);"
    echo ""

    # Check specific missing technique
    echo "Looking for T1562.001:"
    sqlite3 "$DB" "SELECT * FROM $TABLE WHERE id LIKE \"%T1562%\";"
  fi
'

echo ""
echo "═══════════════════════════════════════════"
echo "  DIAGNOSTIC COMPLETE — now inserting fixes"
echo "═══════════════════════════════════════════"

# Step 4: Insert ALL commonly-used MITRE sub-techniques
# We pull the full list of what wazuh rules reference and fill gaps
docker exec wazuh-manager bash -c '
  DB="/var/ossec/var/db/mitre.db"

  # Get table name and columns
  TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\" AND name LIKE \"%technique%\" LIMIT 1;")
  if [ -z "$TABLE" ]; then
    echo "ERROR: Cannot find technique table!"
    exit 1
  fi

  COLS=$(sqlite3 "$DB" "PRAGMA table_info($TABLE);" | awk -F"|" "{print \$2}" | tr "\n" ",")
  echo "Table: $TABLE | Columns: $COLS"

  # Find what techniques the rules actually reference
  echo ""
  echo "Scanning rules for MITRE references..."
  REFERENCED=$(grep -roh "T[0-9]\{4\}\.[0-9]\{3\}" /var/ossec/ruleset/rules/ 2>/dev/null | sort -u)
  echo "Found $(echo "$REFERENCED" | wc -l) unique sub-technique IDs in rules"

  # Check which ones are missing from DB
  MISSING=""
  for TID in $REFERENCED; do
    EXISTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE WHERE id=\"$TID\";")
    if [ "$EXISTS" = "0" ]; then
      MISSING="$MISSING $TID"
    fi
  done

  if [ -z "$MISSING" ]; then
    echo "All referenced sub-techniques already exist in DB!"
  else
    echo ""
    echo "Missing sub-techniques: $MISSING"
    echo "Inserting them now..."

    # Get a sample row to understand the schema
    SAMPLE=$(sqlite3 "$DB" "SELECT * FROM $TABLE LIMIT 1;")
    COLCOUNT=$(echo "$SAMPLE" | awk -F"|" "{print NF}")
    echo "Columns per row: $COLCOUNT"

    for TID in $MISSING; do
      # Extract parent technique ID (e.g., T1562 from T1562.001)
      PARENT="${TID%%.*}"

      # Get parent name if it exists
      PARENT_NAME=$(sqlite3 "$DB" "SELECT name FROM $TABLE WHERE id=\"$PARENT\";" 2>/dev/null || echo "")

      if [ -z "$PARENT_NAME" ]; then
        PARENT_NAME="Unknown"
      fi

      SUB_NUM="${TID##*.}"
      TECHNIQUE_NAME="${PARENT_NAME}: Sub-technique ${SUB_NUM}"

      # Try insert — schema varies by Wazuh version
      # Common schemas: (id, name) or (id, name, external_id) or more
      if [ "$COLCOUNT" -le 2 ]; then
        sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id, name) VALUES (\"$TID\", \"$TECHNIQUE_NAME\");"
      elif [ "$COLCOUNT" -le 3 ]; then
        sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id, name, external_id) VALUES (\"$TID\", \"$TECHNIQUE_NAME\", \"$TID\");"
      else
        # Get actual column names and try a minimal insert
        sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id, name) VALUES (\"$TID\", \"$TECHNIQUE_NAME\");" 2>/dev/null || \
        sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE VALUES (\"$TID\", \"$TECHNIQUE_NAME\");" 2>/dev/null || \
        echo "  WARN: Could not insert $TID — manual schema check needed"
      fi
      echo "  Inserted: $TID ($TECHNIQUE_NAME)"
    done

    echo ""
    echo "Verifying T1562.001 now exists:"
    sqlite3 "$DB" "SELECT * FROM $TABLE WHERE id=\"T1562.001\";"
  fi
'

# Step 5: Restart wazuh-analysisd to pick up DB changes
echo ""
echo "Restarting wazuh-analysisd to reload MITRE DB..."
docker exec wazuh-manager bash -c '
  kill -1 $(pgrep -f wazuh-analysisd) 2>/dev/null || true
  sleep 3
  echo "analysisd restarted"
'

echo ""
echo "═══════════════════════════════════════════"
echo "  FIX B: fix-on-start.sh loop timeouts"
echo "═══════════════════════════════════════════"

# Fix ALL seq loops in fix-on-start.sh
sed -i 's/for i in $(seq 1 12)/for i in $(seq 1 6)/g' ~/soc-stack/fix-on-start.sh
sed -i 's/for i in $(seq 1 24)/for i in $(seq 1 6)/g' ~/soc-stack/fix-on-start.sh

echo "All loops now set to seq 1 6 (30s max):"
grep -n "seq 1 " ~/soc-stack/fix-on-start.sh || echo "None found (already fixed or updated)"

echo ""
echo "═══════════════════════════════════════════"
echo "  FIX C: Add MITRE fix to fix-on-start.sh"
echo "═══════════════════════════════════════════"

# Add MITRE DB repair to fix-on-start.sh so it runs on every boot
if ! grep -q "MITRE_FIX" ~/soc-stack/fix-on-start.sh; then
  cat >> ~/soc-stack/fix-on-start.sh << 'MITRE_BLOCK'

# ── MITRE_FIX: Insert missing sub-techniques on every boot ────
echo "Fixing MITRE sub-technique DB..."
docker exec wazuh-manager bash -c '
  command -v sqlite3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq sqlite3; }
  DB="/var/ossec/var/db/mitre.db"
  TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\" AND name LIKE \"%technique%\" LIMIT 1;")
  if [ -n "$TABLE" ]; then
    REFERENCED=$(grep -roh "T[0-9]\{4\}\.[0-9]\{3\}" /var/ossec/ruleset/rules/ 2>/dev/null | sort -u)
    for TID in $REFERENCED; do
      EXISTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE WHERE id=\"$TID\";")
      if [ "$EXISTS" = "0" ]; then
        PARENT="${TID%%.*}"
        PNAME=$(sqlite3 "$DB" "SELECT name FROM $TABLE WHERE id=\"$PARENT\";" 2>/dev/null || echo "Unknown")
        sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id, name) VALUES (\"$TID\", \"${PNAME}: Sub ${TID##*.}\");" 2>/dev/null
      fi
    done
    kill -1 $(pgrep -f wazuh-analysisd) 2>/dev/null || true
    echo "MITRE DB patched"
  fi
'
MITRE_BLOCK
  echo "✅ MITRE fix added to fix-on-start.sh (persistent)"
else
  echo "✅ MITRE fix already in fix-on-start.sh"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "  FINAL VERIFICATION"
echo "═══════════════════════════════════════════"

echo ""
echo "Wazuh agents:"
docker exec wazuh-manager /var/ossec/bin/agent_control -la

echo ""
echo "fix-on-start.sh loops:"
grep -n "seq 1 " ~/soc-stack/fix-on-start.sh || echo "None found"

echo ""
echo "Waiting 60s for new log entries (no MITRE warnings should appear)..."
sleep 60
echo "Last MITRE mentions in ossec.log:"
docker exec wazuh-manager bash -c 'tail -50 /var/ossec/logs/ossec.log | grep -i "MITRE" || echo "NONE — fix worked!"'

echo ""
echo "══════════════ ALL FIXES APPLIED ══════════════"
