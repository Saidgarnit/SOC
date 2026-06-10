#!/usr/bin/env python3
"""
SOC Cyber Range — Master Fix Script
Uses Path.home() so it works for any user (said, root, etc.)
"""

import os, shutil, re, sys
from pathlib import Path

HOME        = Path.home()
RULES_DIR   = HOME / "soc-stack/elastalert/rules"
BACKUP_DIR  = HOME / "soc-stack/elastalert/rules_backup"
HIGH_RISK   = RULES_DIR / "high_risk.yaml"
SURICATA    = RULES_DIR / "suricata_alert.yaml"
VT_ALERT    = RULES_DIR / "vt_alert.yaml"

SEP = "─" * 70
def banner(t): print(f"\n{SEP}\n  {t}\n{SEP}")
def ok(m):     print(f"  OK   {m}")
def err(m):    print(f"  ERR  {m}"); sys.exit(1)
def info(m):   print(f"  -->  {m}")

print(f"\n  Home:      {HOME}")
print(f"  Rules dir: {RULES_DIR}")
print(f"  Exists:    {RULES_DIR.exists()}")

# ── FIX 1 — high_risk.yaml ────────────────────────────────────────────────────
banner("FIX 1 — high_risk.yaml  (email list-of-strings + icons)")

if not RULES_DIR.exists():
    err(f"Rules dir not found: {RULES_DIR}\nCheck: ls ~/soc-stack/elastalert/")

# Build email addr with chr() — avoids @ being mangled by chat/clipboard
email_addr = (
    chr(115)+chr(97)+chr(105)+chr(100)
    + chr(64)
    + chr(101)+chr(120)+chr(97)+chr(109)+chr(112)+chr(108)+chr(101)
    + chr(46)
    + chr(99)+chr(111)+chr(109)
)

lines = [
    "# high_risk.yaml — written by fix script",
    "name: high_risk_lateral_movement",
    "type: any",
    "index: .ds-wazuh-alerts-4.x-*",
    "",
    "filter:",
    "  - terms:",
    "      rule.groups:",
    "        - authentication_failed",
    "        - lateral_movement",
    "        - rootcheck",
    "        - syscheck",
    "",
    "realert:",
    "  minutes: 10",
    "",
    "alert:",
    "  - slack",
    "  - email",
    "",
    'slack_webhook_url: "YOUR_SLACK_WEBHOOK_HERE"',
    'slack_username_override: "SOC-Alert"',
    'slack_emoji_override: ":rotating_light:"',
    'slack_msg_color: "danger"',
    "",
    "slack_alert_fields:",
    '  - title: "Rule ID"',
    '    value: "{rule.id}"',
    "    short: true",
    '  - title: "Description"',
    '    value: "{rule.description}"',
    "    short: false",
    '  - title: "Agent"',
    '    value: "{agent.name}"',
    "    short: true",
    '  - title: "Level"',
    '    value: "{rule.level}"',
    "    short: true",
    "",
    "alert_text_type: alert_text_only",
    "alert_text: |",
    "  :rotating_light: *HIGH RISK ALERT* :rotating_light:",
    "  *Rule:* {rule.id} -- {rule.description}",
    "  *Agent:* {agent.name}  |  *Level:* {rule.level}",
    "  *Timestamp:* {timestamp}",
    "",
    "# email MUST be a list — bare string causes SMTP rejection",
    "email:",
    f"  - {email_addr}",
    "",
    'smtp_host: "localhost"',
    "smtp_port: 25",
    'from_addr: "elastalert@soc.local"',
    'email_subject: "SOC HIGH RISK -- {rule.description}"',
]
HIGH_RISK.write_text("\n".join(lines) + "\n", encoding="utf-8")
ok(f"Wrote {HIGH_RISK}")
info(f"Email address embedded: {email_addr}  (edit if needed)")

# ── FIX 2 — suricata_alert.yaml realert: minutes: 10 ─────────────────────────
banner("FIX 2 — suricata_alert.yaml  (realert: minutes: 10)")

if not SURICATA.exists():
    err(f"Not found: {SURICATA}")

content = SURICATA.read_text(encoding="utf-8")
if re.search(r"realert\s*:", content):
    content = re.sub(
        r"realert\s*:\s*\n\s*minutes\s*:\s*\d+",
        "realert:\n  minutes: 10",
        content
    )
    ok("Patched existing realert -> minutes: 10")
else:
    content = re.sub(r"(type\s*:.*\n)", r"\1\nrealert:\n  minutes: 10\n", content, count=1)
    ok("Inserted realert: minutes: 10")
SURICATA.write_text(content, encoding="utf-8")
ok(f"Saved {SURICATA}  (no restart needed)")

# ── FIX 3 — Backup all rules ──────────────────────────────────────────────────
banner("FIX 3 — Backup rules -> rules_backup/")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
backed = 0
for f in RULES_DIR.glob("*.yaml"):
    shutil.copy2(f, BACKUP_DIR / f.name)
    ok(f"  {f.name}")
    backed += 1
ok(f"Total: {backed} files -> {BACKUP_DIR}")

# ── FIX 4 — vt_alert.yaml integer range filter ────────────────────────────────
banner("FIX 4 — vt_alert.yaml  (integer range filter)")
vt_lines = [
    "# vt_alert.yaml — written by fix script",
    "# vt_malicious is INTEGER in ES — use range, not string match",
    "name: vt_malicious_enrichment_alert",
    "type: any",
    "index: soc-logs-enriched-*",
    "",
    "filter:",
    "  - range:",
    "      vt_malicious:",
    "        gte: 1",
    "",
    "realert:",
    "  minutes: 10",
    "",
    "alert:",
    "  - slack",
    "",
    'slack_webhook_url: "YOUR_SLACK_WEBHOOK_HERE"',
    'slack_username_override: "SOC-VT-Alert"',
    'slack_emoji_override: ":biohazard_sign:"',
    'slack_msg_color: "warning"',
    "",
    "alert_text_type: alert_text_only",
    "alert_text: |",
    "  :biohazard_sign: *VirusTotal Hit*",
    "  *IP:* {source_ip}",
    "  *VT Detections:* {vt_malicious}  |  *Severity:* {vt_severity}",
    "  *Timestamp:* {timestamp}",
]
VT_ALERT.write_text("\n".join(vt_lines) + "\n", encoding="utf-8")
ok(f"Wrote {VT_ALERT}")

# ── FIX 5 — MISP pipeline verification steps (printed only) ───────────────────
banner("FIX 5 — MISP IOC pipeline (run these manually)")
print("""
  A) docker logs connector-misp --tail 50 | grep -E "import|error|bundle"

  B) docker exec -it kali-attacker bash -c "curl -s http://5.188.86.172 || true"

  C) curl -s -u elastic:Kjd9r43ANUymjjcba0M6 \\
       "http://localhost:9200/soc-logs-enriched-*/_search?q=source_ip:5.188.86.172&size=1" \\
       | python3 -m json.tool | grep -E "misp|vt_"

  D) docker logs elastalert --tail 100 | grep -i misp
""")

banner("ALL DONE — verify with:")
print("  docker logs elastalert --tail 50 | grep -E 'Loaded|ERROR'\n")
