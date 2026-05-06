#!/usr/bin/env python3
"""
misp_es_enricher.py
Fetches IOC IPs from MISP, finds matching docs in soc-logs-enriched-*,
tags them with 'misp_threat_match' so Elastalert MISP rule fires.
"""
import os
import requests
import urllib3
urllib3.disable_warnings()

MISP_URL = os.getenv("MISP_URL", "http://misp")
MISP_KEY = os.getenv("MISP_API_KEY", "")
ES_URL = os.getenv("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.getenv("ELASTIC_USERNAME", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "")
ES_AUTH = (ES_USER, ES_PASS) if ES_PASS else None
ES_INDEX  = "soc-logs-enriched*"

if not MISP_KEY:
    raise SystemExit("MISP_API_KEY is not set.")

print("[1] Fetching IOC IPs from MISP...")
r = requests.get(
    f"{MISP_URL}/attributes/restSearch",
    headers={"Authorization": MISP_KEY, "Accept": "application/json",
             "Content-Type": "application/json"},
    json={"type": ["ip-dst","ip-src"], "to_ids": True, "published": True},
    verify=False
)
attrs = r.json().get("response", {}).get("Attribute", [])
ioc_ips = list({a["value"] for a in attrs})
print(f"    Found {len(ioc_ips)} IOC IPs: {ioc_ips}")

if not ioc_ips:
    print("No IOC IPs found — check MISP has published events with ip-dst attributes.")
    exit(0)

print("[2] Searching ES for matching traffic...")
query = {
    "query": {"terms": {"src_ip": ioc_ips}},
    "size": 100,
    "_source": ["src_ip", "dest_ip", "tags", "@timestamp"]
}
r = requests.get(f"{ES_URL}/{ES_INDEX}/_search",
    auth=ES_AUTH, json=query)
hits = r.json().get("hits", {}).get("hits", [])
print(f"    Found {len(hits)} matching documents")

if not hits:
    # Try dest_ip too
    query["query"] = {"bool": {"should": [
        {"terms": {"src_ip": ioc_ips}},
        {"terms": {"dest_ip": ioc_ips}}
    ]}}
    r = requests.get(f"{ES_URL}/{ES_INDEX}/_search", auth=ES_AUTH, json=query)
    hits = r.json().get("hits", {}).get("hits", [])
    print(f"    Found {len(hits)} matching documents (src+dest check)")

print("[3] Tagging matching documents with misp_threat_match...")
tagged = 0
for hit in hits:
    idx = hit["_index"]
    did = hit["_id"]
    src = hit["_source"]
    existing_tags = src.get("tags", [])
    if "misp_threat_match" in existing_tags:
        continue
    r = requests.post(
        f"{ES_URL}/{idx}/_update/{did}",
        auth=ES_AUTH,
        json={"script": {
            "source": "if (!ctx._source.containsKey('tags')) { ctx._source.tags = [] } ctx._source.tags.add('misp_threat_match'); ctx._source.threat_intel_info = params.info",
            "params": {"info": f"MISP IOC match: {src.get('src_ip', src.get('dest_ip', 'unknown'))}"}
        }}
    )
    if r.status_code == 200:
        print(f"    Tagged: {idx}/{did} (IP: {src.get('src_ip','?')})")
        tagged += 1
    else:
        print(f"    Error tagging {did}: {r.text[:100]}")

print(f"\n[DONE] Tagged {tagged} documents with misp_threat_match")
print("       Elastalert MISP-Threat-Intel-Match will fire on next poll cycle.")
