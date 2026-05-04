#!/usr/bin/env python3
# inspect-es.py — Discover all indices, mappings, and sample fields
# Run: python3 ~/soc-stack/inspect-es.py
# ================================================================

import urllib.request, urllib.error, json, base64

ES    = "http://localhost:9200"
CREDS = base64.b64encode(b"elastic:sYVfKJCe2RCfELjf=GLa").decode()

def call(path):
    req = urllib.request.Request(ES + path,
          headers={"Authorization": f"Basic {CREDS}",
                   "Content-Type":  "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def post(path, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(ES + path, data=data, method="POST",
           headers={"Authorization": f"Basic {CREDS}",
                    "Content-Type":  "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def flatten_fields(mapping, prefix="", depth=0):
    """Recursively extract all field paths from an ES mapping."""
    fields = []
    if depth > 5:
        return fields
    props = mapping.get("properties", {})
    for name, val in props.items():
        full = f"{prefix}{name}"
        ftype = val.get("type", "object")
        fields.append((full, ftype))
        if "properties" in val:
            fields.extend(flatten_fields(val, full + ".", depth + 1))
    return fields

def sample_doc(index):
    """Get one document from an index to see real field values."""
    res = post(f"/{index}/_search", {"size": 1, "query": {"match_all": {}}})
    hits = res.get("hits", {}).get("hits", [])
    if hits:
        return hits[0].get("_source", {})
    return {}

def flatten_doc(doc, prefix="", depth=0):
    """Flatten a nested doc into field: value pairs."""
    result = {}
    if depth > 4:
        return result
    for k, v in doc.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            result.update(flatten_doc(v, key + ".", depth + 1))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            result.update(flatten_doc(v[0], key + "[0].", depth + 1))
        else:
            val_str = str(v)
            result[key] = val_str[:80] + "..." if len(val_str) > 80 else val_str
    return result

# ── Get all indices ──────────────────────────────────────────────
print("\n" + "="*70)
print("  ELASTICSEARCH INDEX DISCOVERY")
print("="*70)

cat = call("/_cat/indices?h=index,health,docs.count,store.size&s=index&format=json")
# Filter out system indices
indices = [i for i in cat if not i["index"].startswith(".") 
           or i["index"].startswith(".ds-")]

# Group by pattern
patterns = {}
for idx in indices:
    name = idx["index"]
    # Determine pattern group
    if "wazuh" in name:
        group = "wazuh-alerts-*"
    elif "soc-logs-enriched" in name:
        group = "soc-logs-enriched-*"
    elif "logstash" in name:
        group = "logstash-*"
    elif "logs-" in name:
        group = "logs-*  (Fleet/Elastic Agent)"
    elif "elastalert" in name:
        group = "elastalert (internal)"
    else:
        group = "other"

    if group not in patterns:
        patterns[group] = []
    patterns[group].append(idx)

print(f"\n{'Index Pattern':<35} {'Count':>6}  {'Health'}")
print("-"*60)
for group, idxs in sorted(patterns.items()):
    total_docs = sum(int(i.get("docs.count") or 0) for i in idxs)
    health = idxs[0].get("health", "?")
    print(f"  {group:<33} {total_docs:>6} docs  [{health}]")
    for i in idxs:
        print(f"    └─ {i['index']:<45} {i.get('docs.count','?'):>8} docs  {i.get('store.size','?')}")

# ── For each pattern group, show field mappings + sample doc ─────
TARGET_GROUPS = {
    "wazuh-alerts-*":       "wazuh-alerts-*",
    "soc-logs-enriched-*":  "soc-logs-enriched-*",
    "logstash-*":           "logstash-*",
    "logs-*  (Fleet/Elastic Agent)": "logs-*",
}

for label, pattern in TARGET_GROUPS.items():
    print(f"\n{'='*70}")
    print(f"  INDEX: {pattern}")
    print(f"{'='*70}")

    # Get mapping for the pattern
    mapping_res = call(f"/{pattern}/_mapping")
    if "error" in mapping_res:
        print(f"  ⚠ No index found matching {pattern}")
        continue

    # Collect all fields across all backing indices
    all_fields = {}
    for idx_name, idx_map in mapping_res.items():
        for field, ftype in flatten_fields(idx_map.get("mappings", {})):
            all_fields[field] = ftype

    # Print fields grouped by top-level key
    top_groups = {}
    for field, ftype in sorted(all_fields.items()):
        top = field.split(".")[0]
        if top not in top_groups:
            top_groups[top] = []
        top_groups[top].append((field, ftype))

    print(f"\n  FIELDS ({len(all_fields)} total):")
    for top, fields in sorted(top_groups.items()):
        if len(fields) == 1:
            print(f"    {fields[0][0]:<50} [{fields[0][1]}]")
        else:
            print(f"    {top}.*")
            for f, t in fields[:15]:  # limit output per group
                print(f"      {f:<48} [{t}]")
            if len(fields) > 15:
                print(f"      ... and {len(fields)-15} more")

    # Show sample document
    # Find a real index name from this pattern
    sample_index = next(
        (i["index"] for i in indices
         if pattern.replace("*","") in i["index"] and
            int(i.get("docs.count") or 0) > 0),
        None
    )
    if sample_index:
        print(f"\n  SAMPLE DOCUMENT (from {sample_index}):")
        doc = sample_doc(sample_index)
        flat = flatten_doc(doc)
        for k, v in sorted(flat.items())[:40]:
            print(f"    {k:<50} = {v}")
        if len(flat) > 40:
            print(f"    ... and {len(flat)-40} more fields")
    else:
        print(f"\n  ⚠ No documents found in {pattern}")

print(f"\n{'='*70}")
print("  DONE — share this output to get perfectly mapped rules")
print(f"{'='*70}\n")
