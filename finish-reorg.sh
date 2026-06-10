#!/usr/bin/env bash
# =============================================================================
#  SOC-STACK — Finish Reorganization (continuation of reorganize-soc.sh)
#
#  The original script stopped mid-way through the delete phase due to
#  set -euo pipefail exiting when a duplicate filename (fix-fleet-server.sh /
#  fix-fleet-agents.sh) appeared a second time in a loop and both `git rm`
#  and `rm` returned non-zero for an already-deleted file.
#
#  This script:
#    Phase A  — finishes the remaining deletes
#    Phase B  — creates the folder structure
#    Phase C  — moves all files into their target folders
#    Phase D  — commits everything to git
#
#  Safe: dry-run by default, execute with --apply
#  NO set -e — uses || true everywhere so missing files can never stop it.
# =============================================================================

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

# ── helpers ──────────────────────────────────────────────────────────────────

log() { echo "  $*"; }

remove() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if $APPLY; then
    git rm -f "$f" 2>/dev/null || rm -f "$f" || true
    log "DELETED: $f"
  else
    log "[DRY-RUN]  rm  $f"
  fi
}

# remove all files matching a glob (safe — no error if nothing matches)
remove_glob() {
  local pattern="$1"
  # use nullglob so the loop body never runs if nothing matches
  local f
  for f in $pattern; do
    [[ -e "$f" ]] && remove "$f"
  done
}

move() {
  local src="$1" dst="$2"
  [[ -e "$src" ]] || { log "SKIP (missing): $src"; return 0; }
  if $APPLY; then
    mkdir -p "$(dirname "$dst")"
    git mv "$src" "$dst" 2>/dev/null || mv "$src" "$dst" || true
    log "MOVED: $src  →  $dst"
  else
    log "[DRY-RUN]  mv  $src  →  $dst"
  fi
}

mkd() {
  if $APPLY; then
    mkdir -p "$1"
    log "MKDIR: $1"
  else
    log "[DRY-RUN]  mkdir -p  $1"
  fi
}

# ── header ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════"
echo "  SOC-STACK Finish-Reorg  $(date '+%Y-%m-%d %H:%M')"
$APPLY || echo "  MODE: DRY-RUN  (re-run with --apply to execute)"
$APPLY && echo "  MODE: APPLYING CHANGES"
echo "══════════════════════════════════════════════════════"
echo ""

# =============================================================================
# PHASE A — Finish remaining deletes
# (everything the original script hadn't reached yet)
# =============================================================================

echo "── Phase A: Remaining deletes ───────────────────────"

# Kibana / agent fix scripts (stopped here in original run)
for f in \
  fix-kibana-crash.sh fix-kibana-now.sh kibana-atomic-fix.sh \
  fix-agent-connectivity.sh fix_agent_enrollment.sh fix_wazuh_agent.sh \
  fix_gmail_thehive.sh fix_thehive_key.sh \
  master-soc-fix.sh soc-final-fix.sh soc-permanent-fix.sh \
  soc-master-recovery.sh soc-recovery.sh \
  start-soc-permanent-fix.sh slim-and-heal.sh slim-soc.sh \
  fix-on-start.sh run-after-kibana.sh patch-indexes.sh Activate-soc.sh; do
  remove "$f"
done

# Versioned fix_all_alerts — keep only v5
for f in fix_all_alerts.py fix_all_alerts_v3.py fix_all_alerts_v4.py; do
  remove "$f"
done

# Versioned rule generators — keep generate-final-master.py + generate-hardened-soc-rules.py
for f in \
  generate-all-18-rules.py generate-clean-elastalert-rules-final.py \
  generate-full-soc-rules.py generate-precision-rules.py \
  generate-remaining-hardened.py generate-remaining-rules.py \
  generate-tuned-rules.py write_rules.py; do
  remove "$f"
done

# Versioned cleanup scripts — keep _improved / _v2 variants
for f in cleanup_fleet_stale.sh cleanup_wazuh_stale_v2.sh cleanup_wazuh_duplicates.sh; do
  remove "$f"
done

# Remaining .bak files
for f in restart-agents.sh.bak start-soc.sh.bak-2026-04-25; do
  remove "$f"
done

# All docker-compose.yml backup/variant copies
for f in \
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

# Duplicate OSSEC configs (ossec.conf is canonical)
for f in clean_ossec.conf ossec_clean.conf ossec_pure.conf full_ossec.conf; do
  remove "$f"
done

# Variant filebeat files (filebeat/ dir is canonical)
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
  misp-proxy.conf.bak misp-proxy.conf.bak2 misp-proxy.conf.bak3 \
  nginx-proxy.conf.bak nginx-proxy.conf.bak2 nginx-proxy.conf.bak3 \
  nginx-proxy.conf.old diagnose.sh DEPLOYMENT_STATUS.md; do
  remove "$f"
done

echo ""

# =============================================================================
# PHASE B — Create folder structure
# =============================================================================

echo "── Phase B: Create folders ───────────────────────────"

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

# =============================================================================
# PHASE C — Move files into their new homes
# =============================================================================

echo "── Phase C: Moving files ─────────────────────────────"

echo ""
echo "  → compose/"
move "docker-compose-lab.yml"            "compose/docker-compose-lab.yml"
move "docker-compose-limits.yml"         "compose/docker-compose-limits.yml"
move "docker-compose.override.yml"       "compose/docker-compose.override.yml"
move "docker-compose.resolved.yml"       "compose/docker-compose.resolved.yml"
move "docker-compose.wazuh-agents.yml"   "compose/docker-compose.wazuh-agents.yml"

echo ""
echo "  → scripts/lifecycle/"
for f in \
  start-soc.sh auto-start.sh soc-start.sh \
  backup-soc.sh watchdog-soc.sh persist-agents.sh \
  restart-agents.sh wsl-start-soc.sh; do
  move "$f" "scripts/lifecycle/$f"
done

echo ""
echo "  → scripts/agents/"
for f in \
  enroll_missing_agents.sh fix-on-start.sh \
  investigate_agents.sh victim-agent-entrypoint.sh \
  metasploitable-syslog.sh dvwa-db-init.sh; do
  move "$f" "scripts/agents/$f"
done
move "fleet_manager.py"           "scripts/agents/fleet_manager.py"
move "cleanup_fleet_improved.sh"  "scripts/agents/cleanup_fleet_improved.sh"
move "cleanup_fleet_stale_v2.sh"  "scripts/agents/cleanup_fleet_stale_v2.sh"

echo ""
echo "  → scripts/rules/"
for f in \
  generate-final-master.py generate-hardened-soc-rules.py \
  rewrite_rules.py create-mitre-rules.py create_ssh_rule.sh \
  deploy-rules.sh fix_all_alerts_v5.py fix_elastalert_fields.py \
  update-suricata-rules.sh update-suricata-bridge.sh \
  local_dns_rules.xml brute_force.yaml; do
  move "$f" "scripts/rules/$f"
done

echo ""
echo "  → scripts/integrations/"
for f in \
  configure_elastalert_ssh.sh configure_wazuh_slack.sh \
  setup_wazuh_slack_proper.sh send_slack_alert.sh \
  misp-poller.sh fix_misp.sh \
  get_hive_key.py; do
  move "$f" "scripts/integrations/$f"
done

echo ""
echo "  → scripts/maintenance/"
for f in \
  health_check.sh soc-healthcheck.sh verify-soc-lab.sh verify-fixes.sh \
  master-hardening.sh inspect-es.py eql_sequence_check.py \
  make-permanent.py make-loop-permanent.py \
  fix_all_alerts_v5.py soc_fix_all.py FINAL_FIX_ALL_ISSUES.sh; do
  [[ -e "$f" ]] && move "$f" "scripts/maintenance/$f"
done

echo ""
echo "  → scripts/testing/"
for f in \
  attack-sim.sh demo_attack.sh test-soc-attacks.sh \
  test_ssh_alerts.sh final_test.sh; do
  move "$f" "scripts/testing/$f"
done

echo ""
echo "  → tools/"
for f in vt_enricher.py misp_es_enricher.py; do
  move "$f" "tools/$f"
done
move "elastic-agent-8.13.0-linux-x86_64" "tools/elastic-agent-8.13.0-linux-x86_64"
move "wazuh-agent-4.7.0-r1.apk"          "tools/wazuh-agent-4.7.0-r1.apk"

echo ""
echo "  → wazuh-config/ossec/"
move "ossec.conf"                       "wazuh-config/ossec/ossec.conf"
move "ossec_final.conf"                 "wazuh-config/ossec/ossec_final.conf"
move "agent.conf"                       "wazuh-config/ossec/agent.conf"
move "active-response-complete.xml"     "wazuh-config/ossec/active-response-complete.xml"

echo ""
echo "  → docs/"
for f in DEPLOYMENT-GUIDE.md SLACK_SETUP.md CREDENTIALS.md; do
  move "$f" "docs/$f"
done

echo ""

# =============================================================================
# PHASE D — Git commit
# =============================================================================

echo "── Phase D: Git status & commit ─────────────────────"

if $APPLY; then
  echo ""
  echo "  Staging all changes..."
  git add -A
  echo ""
  echo "  Files changed:"
  git status --short | head -60
  echo ""
  git commit -m "chore: finish reorganization — delete remaining junk, move files into folders

Continuation of interrupted reorganize-soc.sh run.
The original script stopped mid-deletion due to set -euo pipefail;
this script completed phases A–C without -e.

Deleted (Phase A):
  - Remaining kibana/agent/soc fix scripts (~20 files)
  - Versioned fix_all_alerts v1/v3/v4 (kept v5)
  - Old rule generators (kept final-master + hardened)
  - docker-compose.yml.bak* variants and broken/fixed copies
  - Duplicate OSSEC configs (clean/pure/full variants)
  - Log files, .bak files, misc one-off artefacts

Moved (Phase C):
  compose/          → docker-compose variants
  scripts/
    lifecycle/      → start, auto-start, backup, watchdog, persist-agents
    agents/         → enroll, fleet_manager, cleanup_fleet, victim-entrypoint
    rules/          → generate-final-master, deploy-rules, update-suricata, brute_force.yaml
    integrations/   → slack, misp, thehive
    maintenance/    → health_check, hardening, FINAL_FIX_ALL_ISSUES, soc_fix_all
    testing/        → attack-sim, demo_attack, test scripts
  tools/            → enrichers, agent installers
  wazuh-config/ossec/ → ossec.conf, agent.conf, active-response
  docs/             → DEPLOYMENT-GUIDE, SLACK_SETUP, CREDENTIALS

Root keeps only: docker-compose.yml, README.md, nginx-proxy.conf,
  nginx-proxy.conf (misp variant), soc_dashboard.ndjson, .env, .gitignore"

  echo ""
  echo "  ✓ Committed."
else
  echo "  [DRY-RUN] Would run: git add -A && git commit -m 'chore: finish reorganization ...'"
fi

echo ""
echo "── Done ─────────────────────────────────────────────"
echo ""

if ! $APPLY; then
  echo "  Nothing was changed — this was a dry-run."
  echo "  When happy with the output, run:"
  echo ""
  echo "    bash finish-reorg.sh --apply"
  echo ""
fi
