#!/usr/bin/env python3
import os
import re
from pathlib import Path

TEMPLATE_DIR = Path("/opt/elastalert")
RULES_DIR = TEMPLATE_DIR / "rules"
RENDERED_RULES_DIR = TEMPLATE_DIR / "rendered_rules"

PLACEHOLDER_RE = re.compile(r"\$\{[A-Z0-9_]+\}")

def render_file(source: Path, dest: Path) -> None:
    content = source.read_text()
    rendered = os.path.expandvars(content)
    dest.write_text(rendered)
    missing = sorted(set(PLACEHOLDER_RE.findall(rendered)))
    if missing:
        print(f"[render_config] Warning: missing env for {source.name}: {', '.join(missing)}")

def main() -> None:
    render_file(TEMPLATE_DIR / "config.yaml.template", TEMPLATE_DIR / "config.yaml")
    render_file(TEMPLATE_DIR / "smtp_auth.yaml.template", TEMPLATE_DIR / "smtp_auth.yaml")

    RENDERED_RULES_DIR.mkdir(parents=True, exist_ok=True)
    for rule in RULES_DIR.glob("*.yaml"):
        render_file(rule, RENDERED_RULES_DIR / rule.name)

if __name__ == "__main__":
    main()
