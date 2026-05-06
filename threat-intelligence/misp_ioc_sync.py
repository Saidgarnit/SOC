#!/usr/bin/env python3
import json
import os
import time
from pathlib import Path

import requests

MISP_URL = os.getenv("MISP_URL", "http://misp")
MISP_KEY = os.getenv("MISP_API_KEY", "")
OUTPUT_PATH = Path(os.getenv("OUTPUT_PATH", "/data/misp_iocs.json"))
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "600"))
VERIFY_SSL = os.getenv("MISP_SSL_VERIFY", "false").lower() == "true"
ATTR_TYPES = [t.strip() for t in os.getenv("MISP_ATTRIBUTE_TYPES", "ip-src,ip-dst").split(",") if t.strip()]


def fetch_iocs() -> dict:
    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {
        "returnFormat": "json",
        "type": ATTR_TYPES,
        "to_ids": True,
        "published": True,
    }
    response = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        headers=headers,
        json=body,
        timeout=30,
        verify=VERIFY_SSL,
    )
    response.raise_for_status()
    attributes = response.json().get("response", {}).get("Attribute", [])
    iocs = {}
    for attr in attributes:
        value = attr.get("value")
        event = attr.get("Event") or {}
        if value:
            iocs[value] = event.get("info", "MISP IOC match")
    return iocs


def write_iocs(iocs: dict) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = OUTPUT_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(iocs, indent=2, sort_keys=True))
    tmp_path.replace(OUTPUT_PATH)


def main() -> None:
    if not MISP_KEY:
        raise SystemExit("MISP_API_KEY is not set.")

    while True:
        try:
            print("[misp-ioc-sync] Fetching indicators from MISP...")
            iocs = fetch_iocs()
            write_iocs(iocs)
            print(f"[misp-ioc-sync] Wrote {len(iocs)} indicators to {OUTPUT_PATH}")
        except Exception as exc:
            print(f"[misp-ioc-sync] Sync failed: {exc}")
        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    main()
