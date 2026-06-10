#!/usr/bin/env bash
# =============================================================================
#  SOC-STACK — Full Project Reorganization
#  Run from ~/soc-stack
#  Safe: dry-run first, then execute with --apply
# =============================================================================
set -euo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

ROOT="$(pwd)"
DRY="[DRY-RUN]"
$APPLY && DRY=""

log()  { echo "  $*"; }
move() {
  local src="$1" dst="$2"
  [[ -e "$src" ]] || { log "SKIP (missing): $src"; return; }
  if $APPLY; then
    mkdir -p "$(dirname "$dst")"
    git mv "$src" "$dst" 2>/dev/null || mv "$src" "$dst"
  else
    log "$DRY  mv  $src  →  $dst"
  fi
}
remove() {
  local f="$1"
  [[ -e "$f" ]] || return
  if $APPLY; then
    git rm -f "$f" 2>/dev/null || rm -f "$f"
    log "DELETED: $f"
  else
    log "$DRY  rm  $f"
  fi
}
mkd() {
  $APPLY && mkdir -p "$1"
  $APPLY || log "$DRY  mkdir -p $1"
}

echo ""
echo "══════════════════════════════════════════════════════"
echo "  SOC-STACK Reorganization  $(date '+%Y-%m-%d %H:%M')"
$APPLY || echo "  MODE: DRY-RUN  (re-run with --apply to execute)"
$APPLY && echo "  MODE: APPLYING CHANGES"
echo "══════════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────────────────
# 1. CLEAN UP — delete known junk
# ─────────────────────────────────────────────────────────
echo "── 1. Deleting junk / obsolete files ────────────────"

# Numbered one-shot fix scripts (1_ through 15_) — superseded by permanent fixes
for f in \
  1_fix_ar_deploy.sh 2_fix_slack_integration.sh 3_super_attack.sh \
  4_health_check.sh 5_fix_suricata_connectors.sh 6_fix_remaining.sh \
  7_targeted_fixes.sh 8_final_fixes.sh 9_fix_suricata_rules.sh \
  10_fix_suricata_final.sh 10b_fix_thehive_key.sh 10c_push_hive_key.sh \
  11_fix_both_final.sh 12_fix_both_definitive.sh 13_final.sh \
  14_finish_thehive.sh 15_launch_attack_sim.sh 15b_lean_attack_sim.sh; do
  remove "$f"
done

# Intermediate fix scripts — superseded by FINAL_FIX_ALL_ISSUES.sh / soc_fix_all.py
for f in \
  definitive-fix.sh definitive-recovery.sh \
  final-fix.sh final-fleet-fix.sh finalize-soc.sh \
  fix-all.sh fix-formatting-and-agents.sh fix-on-start.sh.bak \
  fix-on-start.sh.bak-20260524 fix-remaining.sh fix-webapi.sh \
  fix-rule-apikeys.sh fix-rules-only.sh fix_everything.sh \
  fix_fleet.sh fix_fleet_delete.sh fix_fleet_final.sh \
  fix-agent-copy.py fix-agents-retry.sh fix-final-agents.sh \
  fix-fleet-agents.sh fix-fleet-server.sh fix-formatting-and-agents.sh \
  fix-kibana-crash.sh fix-kibana-now.sh kibana-atomic-fix.sh \
  fix-agent-connectivity.sh fix_agent_enrollment.sh fix_wazuh_agent.sh \
  fix_gmail_thehive.sh fix_thehive_key.sh \
  master-soc-fix.sh soc-final-fix.sh soc-permanent-fix.sh \
  soc-master-recovery.sh soc-recovery.sh \
  start-soc-permanent-fix.sh slim-and-heal.sh slim-soc.sh \
  fix-on-start.sh run-after-kibana.sh patch-indexes.sh \
  fix-fleet-server.sh fix-fleet-agents.sh Activate-soc.sh; do
  remove "$f"
done

# Versioned fix_all_alerts — keep only the latest (v5)
for f in fix_all_alerts.py fix_all_alerts_v3.py fix_all_alerts_v4.py; do
  remove "$f"
done

# Versioned rule generators — keep generate-final-master.py and generate-hardened-soc-rules.py
for f in \
  generate-all-18-rules.py generate-clean-elastalert-rules-final.py \
  generate-full-soc-rules.py generate-precision-rules.py \
  generate-remaining-hardened.py generate-remaining-rules.py \
  generate-tuned-rules.py write_rules.py; do
  remove "$f"
done

# Versioned cleanup scripts — keep _v2 / _improved
for f in cleanup_fleet_stale.sh cleanup_wazuh_stale_v2.sh cleanup_wazuh_duplicates.sh; do
  remove "$f"
done

# Bak files
for f in \
  restart-agents.sh.bak fix-on-start.sh.bak \
  fix-on-start.sh.bak-20260524 start-soc.sh.bak-2026-04-25; do
  remove "$f"
done

# All docker-compose.yml.bak* / .broken* / .fixed / .complete / .head / .original / etc.
for f in \
  docker-compose.yml.backup docker-compose.yml.backup-core-only \
  docker-compose.yml.bak docker-compose.yml.bak-1779905260 \
  docker-compose.yml.bak-1915 docker-compose.yml.bak-192155 \
  docker-compose.yml.bak-195503 docker-compose.yml.bak-20260428-2249 \
  docker-compose.yml.bak-conflict-1223 docker-compose.yml.bak-kibana-201029 \
  docker-compose.yml.bak-memfix-2236 docker-compose.yml.bak.202604261338 \
  docker-compose.yml.bak.202604261344 docker-compose.yml.bak.20260522_123157 \
  docker-compose.yml.bak.wazuh-persist docker-compose.yml.broken \
  docker-compose.yml.broken-1138 docker-compose.yml.complete \
  docker-compose.yml.fixed docker-compose.yml.git-restored \
  docker-compose.yml.head docker-compose.yml.original \
  docker-compose.yml.pre-permanent-fix \
  "docker-compose.yml.pre-unmount.2026-04-06-113455" \
  docker-compose.yml.with-victims \
  docker-compose-lab.yml.backup docker-compose-lab.yml.bak \
  docker-compose-limits.yml.bak; do
  remove "$f"
done

# Duplicate/variant OSSEC configs — ossec.conf is canonical, others are temp drafts
for f in clean_ossec.conf ossec_clean.conf ossec_pure.conf full_ossec.conf; do
  remove "$f"
done

# Variant filebeat files — filebeat/ dir is canonical
for f in filebeat-fixed.yml filebeat-new.yml; do
  remove "$f"
done

# Log files — runtime noise, not source code
for f in \
  definitive.log final.log fix-all.log hardening.log \
  misp-poller.log recovery.log soc-agent-boot.log \
  start-soc.log watchdog.log session-log.txt es-discovery.txt; do
  remove "$f"
done

# Misc one-off artefacts
for f in \
  beginning docker-cp-workaround.sh lsb-release_12.0-2_all.deb \
  wazuh-dashboard.html wazuh-monitord misp_config_backup.php \
  misp-proxy.conf nginx-proxy.conf.bak nginx-proxy.conf.bak2 \
  nginx-proxy.conf.bak3 nginx-proxy.conf.old diagnose.sh \
  es-discovery.txt DEPLOYMENT_STATUS.md; do
  remove "$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 2. CREATE TARGET FOLDERS
# ─────────────────────────────────────────────────────────
echo "── 2. Creating folder structure ─────────────────────"

mkd "compose"
mkd "scripts/lifecycle"
mkd "scripts/agents"
mkd "scripts/rules"
mkd "scripts/integrations"
mkd "scripts/maintenance"
mkd "scripts/testing"
mkd "tools"
mkd "wazuh-config/ossec"
mkd "logs"
mkd "docs"

echo ""

# ─────────────────────────────────────────────────────────
# 3. MOVE — Docker Compose variants
# ─────────────────────────────────────────────────────────
echo "── 3. Moving docker-compose variants → compose/ ─────"

move "docker-compose-lab.yml"        "compose/docker-compose-lab.yml"
move "docker-compose-limits.yml"     "compose/docker-compose-limits.yml"
move "docker-compose.override.yml"   "compose/docker-compose.override.yml"
move "docker-compose.resolved.yml"   "compose/docker-compose.resolved.yml"
move "docker-compose.wazuh-agents.yml" "compose/docker-compose.wazuh-agents.yml"

echo ""

# ─────────────────────────────────────────────────────────
# 4. MOVE — Lifecycle scripts → scripts/lifecycle/
# ─────────────────────────────────────────────────────────
echo "── 4. Lifecycle scripts → scripts/lifecycle/ ────────"

for f in \
  start-soc.sh auto-start.sh soc-start.sh \
  backup-soc.sh watchdog-soc.sh persist-agents.sh \
  restart-agents.sh wsl-start-soc.sh; do
  move "$f" "scripts/lifecycle/$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 5. MOVE — Agent scripts → scripts/agents/
# ─────────────────────────────────────────────────────────
echo "── 5. Agent scripts → scripts/agents/ ───────────────"

for f in \
  enroll_missing_agents.sh fix-on-start.sh \
  investigate_agents.sh victim-agent-entrypoint.sh \
  metasploitable-syslog.sh dvwa-db-init.sh \
  docker-compose.wazuh-agents.yml; do
  move "$f" "scripts/agents/$f"
done
# fleet manager tool
move "fleet_manager.py" "scripts/agents/fleet_manager.py"
move "cleanup_fleet_improved.sh" "scripts/agents/cleanup_fleet_improved.sh"
move "cleanup_fleet_stale_v2.sh" "scripts/agents/cleanup_fleet_stale_v2.sh"

echo ""

# ─────────────────────────────────────────────────────────
# 6. MOVE — Rule/alert generation → scripts/rules/
# ─────────────────────────────────────────────────────────
echo "── 6. Rule generators → scripts/rules/ ──────────────"

for f in \
  generate-final-master.py generate-hardened-soc-rules.py \
  rewrite_rules.py create-mitre-rules.py create_ssh_rule.sh \
  deploy-rules.sh fix_all_alerts_v5.py fix_elastalert_fields.py \
  update-suricata-rules.sh update-suricata-bridge.sh \
  local_dns_rules.xml brute_force.yaml; do
  move "$f" "scripts/rules/$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 7. MOVE — Integration scripts → scripts/integrations/
# ─────────────────────────────────────────────────────────
echo "── 7. Integration scripts → scripts/integrations/ ───"

for f in \
  configure_elastalert_ssh.sh configure_wazuh_slack.sh \
  setup_wazuh_slack_proper.sh send_slack_alert.sh \
  misp-poller.sh fix_misp.sh \
  get_hive_key.py; do
  move "$f" "scripts/integrations/$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 8. MOVE — Maintenance / health → scripts/maintenance/
# ─────────────────────────────────────────────────────────
echo "── 8. Maintenance scripts → scripts/maintenance/ ────"

for f in \
  health_check.sh soc-healthcheck.sh verify-soc-lab.sh verify-fixes.sh \
  master-hardening.sh inspect-es.py eql_sequence_check.py \
  make-permanent.py make-loop-permanent.py \
  fix_all_alerts_v5.py soc_fix_all.py FINAL_FIX_ALL_ISSUES.sh \
  fix-all.sh; do
  # only move if not already moved
  [[ -e "$f" ]] && move "$f" "scripts/maintenance/$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 9. MOVE — Attack / test scripts → scripts/testing/
# ─────────────────────────────────────────────────────────
echo "── 9. Testing scripts → scripts/testing/ ────────────"

for f in \
  attack-sim.sh demo_attack.sh test-soc-attacks.sh \
  test_ssh_alerts.sh final_test.sh; do
  move "$f" "scripts/testing/$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 10. MOVE — Python enrichment tools → tools/
# ─────────────────────────────────────────────────────────
echo "── 10. Tools → tools/ ───────────────────────────────"

for f in \
  vt_enricher.py misp_es_enricher.py; do
  move "$f" "tools/$f"
done
# Large binary installer
move "elastic-agent-8.13.0-linux-x86_64" "tools/elastic-agent-8.13.0-linux-x86_64"
move "wazuh-agent-4.7.0-r1.apk"          "tools/wazuh-agent-4.7.0-r1.apk"

echo ""

# ─────────────────────────────────────────────────────────
# 11. MOVE — Wazuh configs → wazuh-config/ossec/
# ─────────────────────────────────────────────────────────
echo "── 11. Wazuh/OSSEC configs → wazuh-config/ ──────────"

move "ossec.conf"       "wazuh-config/ossec/ossec.conf"
move "ossec_final.conf" "wazuh-config/ossec/ossec_final.conf"
move "agent.conf"       "wazuh-config/ossec/agent.conf"
move "active-response-complete.xml" "wazuh-config/ossec/active-response-complete.xml"

echo ""

# ─────────────────────────────────────────────────────────
# 12. MOVE — Docs → docs/
# ─────────────────────────────────────────────────────────
echo "── 12. Docs → docs/ ─────────────────────────────────"

for f in \
  DEPLOYMENT-GUIDE.md SLACK_SETUP.md CREDENTIALS.md; do
  move "$f" "docs/$f"
done

echo ""

# ─────────────────────────────────────────────────────────
# 13. ROOT — keep only these at top level
# ─────────────────────────────────────────────────────────
echo "── 13. Root-level files (stay at root) ──────────────"
log "  docker-compose.yml          ← main entry point"
log "  README.md                   ← project docs"
log "  .env / .gitignore           ← config"
log "  soc_dashboard.ndjson        ← Kibana export"
log "  nginx-proxy.conf            ← nginx main conf"
log "  misp-proxy.conf             ← misp proxy conf"

echo ""
echo "── Done ─────────────────────────────────────────────"
echo ""

if ! $APPLY; then
  echo "  This was a DRY-RUN. Nothing was changed."
  echo "  Review the output above, then run:"
  echo ""
  echo "    bash reorganize-soc.sh --apply"
  echo ""
fi

# ─────────────────────────────────────────────────────────
# 14. Git commit (only when applying)
# ─────────────────────────────────────────────────────────
if $APPLY; then
  echo "── Git commit ───────────────────────────────────────"
  git add -A
  git commit -m "chore: reorganize project — move scripts into folders, delete obsolete files

Structure after reorganization:
  compose/          → docker-compose variants
  scripts/
    lifecycle/      → start, stop, backup, watchdog
    agents/         → enroll, fleet, cleanup
    rules/          → generate, deploy, update rules
    integrations/   → slack, misp, thehive
    maintenance/    → health, hardening, fix-all
    testing/        → attack sims, test scripts
  tools/            → python enrichers, agent installers
  wazuh-config/
    ossec/          → ossec.conf, agent.conf, active-response
  docs/             → DEPLOYMENT-GUIDE, SLACK_SETUP, CREDENTIALS
  logs/             → runtime logs (gitignored)

Deleted: ~60 numbered fix scripts, duplicate bak/variant compose files,
  intermediate fix scripts superseded by final versions,
  versioned generate scripts (kept final only), log files, temp configs."
  echo "  Committed."
fi
