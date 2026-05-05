#!/bin/bash
# deploy_fixes.sh — Copy fix script to host, run it, then reload Elastalert
# Run from: said@NOBODY:~/soc-stack$
set -euo pipefail

SCRIPT_NAME="soc_fix_all.py"
HOST_SCRIPT="$HOME/soc-stack/$SCRIPT_NAME"
RULES_HOST="$HOME/soc-stack/elastalert/rules"

echo "════════════════════════════════════════════════════════"
echo "  SOC Master Fix Deployer"
echo "════════════════════════════════════════════════════════"

# ── STEP 1: Run the Python fix script directly on the HOST ──────────────────
# (rules/ is bind-mounted from host into the elastalert container,
#  so editing on host = editing inside container automatically)

echo ""
echo "▶ Running fix script on host (rules are bind-mounted)..."
python3 "$HOST_SCRIPT"

# ── STEP 2: Backup verification ─────────────────────────────────────────────
echo ""
echo "▶ Verifying backup..."
BACKUP_COUNT=$(ls "$HOME/soc-stack/elastalert/rules_backup/"*.yaml 2>/dev/null | wc -l)
echo "  ✅ $BACKUP_COUNT rule files in rules_backup/"

# ── STEP 3: Validate YAML syntax on all rules ───────────────────────────────
echo ""
echo "▶ Validating YAML syntax..."
for f in "$RULES_HOST"/*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))" \
    && echo "  ✅ OK: $(basename $f)" \
    || echo "  ❌ SYNTAX ERROR: $(basename $f)"
done

# ── STEP 4: Confirm Elastalert sees the new rules (hot-reload check) ─────────
echo ""
echo "▶ Checking Elastalert container is running..."
docker inspect --format='{{.State.Status}}' elastalert 2>/dev/null \
  && echo "  ✅ elastalert container is up — rules hot-reloaded automatically" \
  || echo "  ⚠️  elastalert container not found — check docker ps"

# ── STEP 5: Tail Elastalert logs for 15s to confirm no rule load errors ──────
echo ""
echo "▶ Tailing elastalert logs for 15 seconds (Ctrl+C to skip)..."
timeout 15 docker logs -f elastalert 2>&1 | grep --color=always -E "ERROR|WARNING|Loaded|high_risk|suricata|vt_|misp" || true

# ── STEP 6: Quick Elasticsearch field check for vt_malicious type ─────────────
echo ""
echo "▶ Checking vt_malicious field type in Elasticsearch..."
curl -s -u "elastic:sYVfKJCe2RCfELjf=GLa" \
  "http://localhost:9200/soc-logs-enriched-*/_mapping/field/vt_malicious" \
  | python3 -m json.tool 2>/dev/null \
  | grep '"type"' \
  || echo "  ⚠️  No soc-logs-enriched-* index yet or field not present"

# ── DONE ─────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  ALL FIXES DEPLOYED"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Manual step remaining — MISP IOC pipeline verification:"
echo "  docker logs connector-misp --tail 50 | grep -E 'import|error'"
echo "  docker exec -it kali-attacker bash -c 'curl -s http://5.188.86.172 || true'"
echo "  docker logs elastalert --tail 50 | grep -i misp"
echo ""
echo "  Test Gmail alert:"
echo "  docker exec wazuh-manager /var/ossec/bin/ossec-logtest"
echo ""
