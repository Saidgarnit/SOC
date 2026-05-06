#!/usr/bin/env python3
import os
from string import Template


def render_file(path: str) -> None:
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    rendered = Template(content).safe_substitute(os.environ)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(rendered)


for target in ("/opt/elastalert/config.yaml", "/opt/elastalert/smtp_auth.yaml"):
    if os.path.exists(target):
        render_file(target)

print("[elastalert] Rendered config templates from environment.")
