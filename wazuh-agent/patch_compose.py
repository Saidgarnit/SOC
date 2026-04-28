import yaml, pathlib, copy

COMPOSE = pathlib.Path('/root/soc-stack/docker-compose.yml')  # adjust if needed
VICTIMS = [
    'victim-iot', 'victim-mail', 'victim-database',
    'victim-dns', 'victim-jenkins', 'victim-windows', 'victim-dvwa'
]
NEW_VOLUMES = [
    './wazuh-agent/supervisord.conf:/etc/supervisor/conf.d/wazuh.conf:ro',
    './wazuh-agent/entrypoint.sh:/entrypoint.sh:ro',
]

data = yaml.safe_load(COMPOSE.read_text())
services = data.get('services', {})

# Show available service names so we can spot mismatches
print("Services in compose:", sorted(services.keys()))

for svc in VICTIMS:
    if svc not in services:
        print(f"  SKIP (not found): {svc}")
        continue
    s = services[svc]
    existing = s.get('volumes', [])
    for v in NEW_VOLUMES:
        if v not in existing:
            existing.append(v)
    s['volumes'] = existing
    s['entrypoint'] = '/entrypoint.sh'
    print(f"  PATCHED: {svc}")

COMPOSE.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
print("Done. Restart victims to apply.")
