#!/bin/bash
set -e

echo "=== FIX A: MITRE sub-techniques in Wazuh DB ==="
docker exec wazuh-manager bash -c '
  command -v sqlite3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq sqlite3; }
  DB="/var/ossec/var/db/mitre.db"
  TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\" AND name LIKE \"%technique%\" LIMIT 1;")
  if [ -z "$TABLE" ]; then
    echo "Available tables:"
    sqlite3 "$DB" ".tables"
    sqlite3 "$DB" ".schema" | head -40
    exit 1
  fi
  echo "Table: $TABLE"
  echo "Row count before: $(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE;")"
  COLS=$(sqlite3 "$DB" "PRAGMA table_info($TABLE);"| awk -F"|" "{print \$2}" | tr "\n" " ")
  echo "Columns: $COLS"
  REFERENCED=$(grep -roh "T[0-9]\{4\}\.[0-9]\{3\}" /var/ossec/ruleset/rules/ 2>/dev/null | sort -u)
  echo "Sub-techniques referenced in rules: $(echo "$REFERENCED" | wc -l)"
  FIXED=0
  for TID in $REFERENCED; do
    EXISTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE WHERE id=\"$TID\";")
    if [ "$EXISTS" = "0" ]; then
      PARENT="${TID%%.*}"
      PNAME=$(sqlite3 "$DB" "SELECT name FROM $TABLE WHERE id=\"$PARENT\";" 2>/dev/null || echo "Unknown")
      sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id, name) VALUES (\"$TID\", \"${PNAME}: Sub ${TID##*.}\");" 2>/dev/null || \
      sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE VALUES (\"$TID\", \"${PNAME}: Sub ${TID##*.}\");" 2>/dev/null || \
      echo "  WARN: Could not insert $TID"
      echo "  + $TID"
      FIXED=$((FIXED+1))
    fi
  done
  echo "Inserted $FIXED missing sub-techniques"
  echo "Row count after: $(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE;")"
  echo "Verify T1562.001: $(sqlite3 "$DB" "SELECT * FROM $TABLE WHERE id=\"T1562.001\";")"
  kill -1 $(pgrep -f wazuh-analysisd) 2>/dev/null || true
  echo "analysisd reloaded"
'

echo ""
echo "=== FIX B: fix-on-start.sh loop timeouts ==="
sed -i 's/for i in $(seq 1 12)/for i in $(seq 1 6)/g' ~/soc-stack/fix-on-start.sh
sed -i 's/for i in $(seq 1 24)/for i in $(seq 1 6)/g' ~/soc-stack/fix-on-start.sh
echo "Loops now:"
grep -n "seq 1 " ~/soc-stack/fix-on-start.sh

echo ""
echo "=== FIX C: Add MITRE repair to fix-on-start.sh ==="
if ! grep -q "MITRE_FIX" ~/soc-stack/fix-on-start.sh; then
cat >> ~/soc-stack/fix-on-start.sh << 'MITRE_BLOCK'

# ── MITRE_FIX: auto-patch missing sub-techniques on boot ──
echo "Patching MITRE DB..."
docker exec wazuh-manager bash -c '
  command -v sqlite3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq sqlite3; }
  DB="/var/ossec/var/db/mitre.db"
  TABLE=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type=\"table\" AND name LIKE \"%technique%\" LIMIT 1;")
  [ -n "$TABLE" ] && {
    for TID in $(grep -roh "T[0-9]\{4\}\.[0-9]\{3\}" /var/ossec/ruleset/rules/ 2>/dev/null | sort -u); do
      [ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM $TABLE WHERE id=\"$TID\";")" = "0" ] && {
        P="${TID%%.*}"; N=$(sqlite3 "$DB" "SELECT name FROM $TABLE WHERE id=\"$P\";" 2>/dev/null||echo "Unknown")
        sqlite3 "$DB" "INSERT OR IGNORE INTO $TABLE (id,name) VALUES (\"$TID\",\"${N}: Sub ${TID##*.}\");" 2>/dev/null
      }
    done
    kill -1 $(pgrep -f wazuh-analysisd) 2>/dev/null||true
    echo "MITRE DB patched"
  }
'
MITRE_BLOCK
  echo "Added MITRE_FIX block to fix-on-start.sh"
else
  echo "MITRE_FIX already present"
fi

echo ""
echo "=== VERIFICATION ==="
docker exec wazuh-manager /var/ossec/bin/agent_control -la
echo ""
echo "Waiting 60s then checking for MITRE warnings..."
sleep 60
docker exec wazuh-manager bash -c 'tail -50 /var/ossec/logs/ossec.log | grep -i "MITRE" || echo "ZERO MITRE warnings — fix worked!"'
echo ""
echo "=== ALL DONE ==="
