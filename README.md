# 🛡️ Open-Source SOC Platform

> A fully containerised, production-grade Security Operations Center built on Docker + WSL2, designed as a hands-on research and training environment covering the complete threat-detection lifecycle.

![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7-00ADEF?logo=wazuh&logoColor=white)
![Elastic](https://img.shields.io/badge/Elastic-Stack-005571?logo=elastic&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-14%20Tactics-red)
![Containers](https://img.shields.io/badge/Containers-34-brightgreen)
![Platform](https://img.shields.io/badge/Platform-WSL2%20%2F%20Ubuntu-orange?logo=ubuntu&logoColor=white)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Services](#services)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Lab Environment](#lab-environment)
- [Detection Coverage](#detection-coverage)
- [Key Scripts](#key-scripts)
- [Directory Structure](#directory-structure)
- [Default Credentials](#default-credentials)
- [Contributing](#contributing)

---

## Overview

This project deploys a **34-container SOC stack** that mirrors a real enterprise security operations center. It integrates HIDS, NIDS, SIEM, threat intelligence, case management, and automated response into a single `docker compose up` command.

The stack was built as a PFE (Final Year Engineering Project) for the *Sécurité IT & Confiance Numérique* programme at **ENSIASD Casablanca**, in partnership with **Netdefender** (Moroccan MSSP).

**Highlights:**
- **6-layer SOC architecture** — from raw log collection to automated incident response
- **34 Docker containers** across two compose files (core stack + attack lab)
- **32 ElastAlert2 detection rules** covering all **14 MITRE ATT&CK tactics**
- **11 intentionally vulnerable victim containers** for realistic attack simulation
- **Automated attack simulation** (`attack-sim.sh`) firing detections across the full kill chain
- **Full threat intelligence pipeline**: MISP + OpenCTI + VirusTotal enrichment
- **Active Response**: Wazuh AR pipeline with Slack notifications

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SOC PLATFORM — 6 LAYERS                     │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 6 │ Threat Intelligence  │ MISP · OpenCTI · VT Enricher  │
├──────────┼──────────────────────┼─────────────────────────────  │
│  LAYER 5 │ Response & Cases     │ ElastAlert2 · TheHive · AR    │
├──────────┼──────────────────────┼─────────────────────────────  │
│  LAYER 4 │ Visualisation        │ Kibana · SIEM Dashboards       │
├──────────┼──────────────────────┼─────────────────────────────  │
│  LAYER 3 │ Storage & Search     │ Elasticsearch · MinIO          │
├──────────┼──────────────────────┼─────────────────────────────  │
│  LAYER 2 │ Processing           │ Logstash · Filebeat            │
├──────────┼──────────────────────┼─────────────────────────────  │
│  LAYER 1 │ Collection           │ Wazuh Agents · Suricata        │
└──────────┴──────────────────────┴─────────────────────────────  │
           │               ATTACK LAB                              │
           │  Kali Attacker + 11 Victim Containers                 │
└─────────────────────────────────────────────────────────────────┘
```

All services communicate over an isolated Docker bridge network (`soc-stack_soc-net`).

---

## Services

### Core SOC Stack (`docker-compose.yml`)

| Service | Role | Port |
|---|---|---|
| `elasticsearch` | Central log index & search engine | 9200 |
| `kibana` | SIEM dashboards & log visualisation | 5601 |
| `logstash` | Log parsing, enrichment, routing | — |
| `filebeat` | Log shipper (Wazuh → Elasticsearch) | — |
| `wazuh-manager` | HIDS / EDR manager (agents + AR) | 1514, 1515, 55000 |
| `suricata` | Network IDS/IPS (live packet inspection) | — |
| `elastalert` | Rules engine → alerting & TheHive tickets | — |
| `thehive` | Case management & incident tracking | 9000 |
| `misp` | Malware Information Sharing Platform | 9001 |
| `opencti` | Threat intelligence platform | 3000 |
| `opencti-worker` | Background CTI processing | — |
| `connector-misp` | MISP → OpenCTI sync | — |
| `connector-mitre` | MITRE ATT&CK → OpenCTI sync | — |
| `vt-enricher` | VirusTotal hash/IOC enrichment | — |
| `fleet-server` | Elastic Agent fleet management | 8220 |
| `rabbitmq` | Message broker (OpenCTI workers) | — |
| `minio` | S3-compatible object storage (TheHive) | — |
| `memcached` | MISP caching layer | — |
| `misp-db` | MISP MySQL database | — |
| `misp-redis` | MISP Redis cache | — |
| `opencti-redis` | OpenCTI Redis cache | — |
| `yara-scanner` | YARA rule engine for malware scanning | — |

### Attack Lab (`docker-compose-lab.yml`)

| Container | Simulated Service |
|---|---|
| `kali-attacker` | Attacker machine (Hydra, Nmap, Metasploit) |
| `victim-dvwa` | Damn Vulnerable Web App (SQLi, XSS, RFI…) |
| `victim-metasploitable` | Metasploitable 2 (multi-vuln target) |
| `victim-ubuntu` | Generic Linux endpoint (SSH brute-force target) |
| `victim-ftp` | Vulnerable FTP server |
| `victim-webapi` | Vulnerable REST API |
| `victim-jenkins` | Jenkins with weak credentials |
| `victim-database` | Exposed MySQL/PostgreSQL |
| `victim-mail` | Mail server (phishing/SMTP relay) |
| `victim-dns` | DNS server (exfiltration target) |
| `victim-iot` | IoT device simulator (MQTT) |
| `victim-windows` | Windows endpoint (Sysmon + Wazuh agent) |

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| RAM | 12 GB available | 16 GB |
| Disk | 50 GB free | 80 GB |
| OS | Ubuntu 22.04 / WSL2 | WSL2 on Windows 11 |
| Docker | 24.x + Compose v2 | latest |
| Python | 3.10+ | 3.11+ |

**WSL2 memory config** (`%USERPROFILE%\.wslconfig`):
```ini
[wsl2]
memory=14GB
swap=4GB
processors=6
```

**Kernel parameters** (applied at startup):
```bash
sudo sysctl -w vm.max_map_count=262144
sudo sysctl -w net.core.somaxconn=65535
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Saidgarnit/SOC.git
cd SOC
```

### 2. Configure environment

```bash
cp .env.backup-original .env
# Edit .env to set your passwords and API keys
```

### 3. Start the core SOC stack

```bash
docker compose up -d
```

> First boot takes **5–10 minutes** while Elasticsearch, Kibana, and MISP initialise.

### 4. Start the attack lab (optional)

```bash
docker compose -f docker-compose-lab.yml up -d
```

### 5. Verify the stack

```bash
bash verify-soc-lab.sh
```

### 6. Check health

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -v "Exited"
```

### Auto-start on WSL2 boot

```bash
# Add to /etc/wsl.conf or run once:
bash auto-start.sh
```

---

## Lab Environment

### Running an Attack Simulation

The `attack-sim.sh` script fires coordinated attacks covering 7+ MITRE tactics:

```bash
bash attack-sim.sh
```

Scenarios executed:

| # | Tactic | Technique | Target |
|---|---|---|---|
| 1 | Initial Access (TA0001) | SQL injection, XSS, path traversal | DVWA |
| 2 | Execution (TA0002) | Command injection via web | DVWA |
| 3 | Credential Access (TA0006) | SSH brute force (Hydra) | victim-ubuntu |
| 4 | Credential Access (TA0006) | FTP brute force (Hydra) | victim-ftp |
| 5 | Discovery (TA0007) | Port scan (Nmap SYN) | All victims |
| 6 | Exfiltration (TA0010) | High-volume HTTP POST | victim-webapi |
| 7 | Lateral Movement (TA0008) | SMB/SSH pivoting | Internal network |

### Demo mode (single run)

```bash
bash demo_attack.sh
```

---

## Detection Coverage

### ElastAlert2 Rules (32 rules / 14 tactics)

| MITRE Tactic | Rule File |
|---|---|
| Reconnaissance (TA0043) | `reconnaissance_tactic.yaml` |
| Resource Development (TA0042) | `resource_dev_tactic.yaml` |
| Initial Access (TA0001) | `initial_access_tactic.yaml`, `web_attacks.yaml` |
| Execution (TA0002) | `execution_tactic.yaml` |
| Persistence (TA0003) | `persistence_tactic.yaml` |
| Privilege Escalation (TA0004) | `privilege_escalation.yaml` |
| Defense Evasion (TA0005) | `defense_evasion_tactic.yaml` |
| Credential Access (TA0006) | `ftp_bruteforce.yaml`, `smb_bruteforce.yaml` |
| Discovery (TA0007) | `discovery_tactic.yaml`, `port_scan.yaml` |
| Lateral Movement (TA0008) | `lateral_movement.yaml` |
| Collection (TA0009) | `collection_tactic.yaml` |
| Command & Control (TA0011) | `c2_tactic.yaml` |
| Exfiltration (TA0010) | `exfiltration_tactic.yaml`, `dns_exfiltration.yaml` |
| Impact (TA0040) | `impact_tactic.yaml` |
| Cross-tactic | `killchain_correlation.yaml`, `high_risk.yaml` |
| Integrations | `yara_match.yaml`, `vt_alert.yaml`, `misp_match.yaml`, `suricata_alert.yaml`, `fim_alert.yaml` |

### Wazuh Custom Rules

- `local_privesc_rules.xml` — Sudo-based privilege escalation (T1548.003)
- `windows_event_rules.xml` — Windows Security Event Log detections

### YARA Rules

Located in `yara/rules/`:
- **`malware.yar`**: Emotet, Mimikatz, Cobalt Strike, WannaCry, Conti, Mirai, Zeus, EICAR, webshells, reverse shells, rootkits
- **`lab_basics.yar`**: Lab-specific test patterns

### Suricata (NIDS)

Custom network signatures in `suricata/rules/local.rules` for lab traffic patterns.

---

## Key Scripts

| Script | Purpose |
|---|---|
| `auto-start.sh` | Start full SOC stack on WSL2 boot |
| `attack-sim.sh` | Automated multi-tactic attack simulation (cron: every 30 min) |
| `demo_attack.sh` | Single-run demo for presentations |
| `backup-soc.sh` | Full stack backup (daily cron at 02:00) |
| `deploy-rules.sh` | Deploy/reload ElastAlert2 & Wazuh rules |
| `configure_wazuh_slack.sh` | Set up Wazuh → Slack notifications |
| `enroll_missing_agents.sh` | Re-enroll disconnected Wazuh agents |
| `cleanup_fleet_stale.sh` | Remove phantom Fleet agents |
| `verify-soc-lab.sh` | End-to-end health check of all services |
| `watchdog-soc.sh` | Container watchdog (restarts crashed services) |
| `wsl-start-soc.sh` | WSL2 startup wrapper |

---

## Directory Structure

```
SOC/
├── docker-compose.yml              # Core SOC stack (22 services)
├── docker-compose-lab.yml          # Attack lab (12 containers)
├── .env                            # Centralised credentials (gitignored)
│
├── wazuh/                          # Wazuh manager configuration
│   ├── ossec.conf                  # Main Wazuh config
│   ├── rules/                      # Custom detection rules (XML)
│   ├── decoders/                   # Log decoders
│   ├── filebeat.yml                # Filebeat → Elasticsearch pipeline
│   └── fix-conf.sh                 # Boot-time config repair hook
│
├── elastalert/                     # ElastAlert2 alerting engine
│   ├── config.yaml                 # Global config
│   ├── rules/                      # 32 YAML detection rules
│   └── block_ip.py                 # Active IP blocking action
│
├── suricata/                       # Suricata NIDS
│   ├── config/                     # suricata.yaml
│   └── rules/                      # Network detection rules
│
├── yara/                           # YARA malware scanning
│   ├── rules/                      # .yar rule files
│   ├── samples/                    # Test malware samples
│   └── scanner/                    # Scanner scripts
│
├── lab/                            # Victim container definitions
│   ├── kali-attacker/
│   ├── victim-dvwa/
│   ├── victim-ubuntu/
│   └── ...                         # 11 victim containers
│
├── threat-intelligence/            # MISP + OpenCTI extras
│   ├── vt_enricher.py              # VirusTotal enrichment
│   └── misp_to_memcached.py        # MISP cache sync
│
├── wazuh-agent/                    # Wazuh agent entrypoints
│   └── entrypoint.sh               # Agent auto-registration
│
├── configs/                        # System configuration docs
├── docker/                         # Docker compose patch notes
├── archive/                        # Historical compose backups
│
├── attack-sim.sh                   # Multi-tactic attack simulator
├── auto-start.sh                   # WSL2 auto-start
├── backup-soc.sh                   # Daily backup script
├── deploy-rules.sh                 # Rule deployment
├── verify-soc-lab.sh               # Health checker
└── watchdog-soc.sh                 # Container watchdog
```

---

## Default Credentials



| Service | URL | Username | Default Password |
|---|---|---|---|
| Kibana | http://localhost:5601 | elastic | *(see `.env`)* |
| Elasticsearch | http://localhost:9200 | elastic | *(see `.env`)* |
| Wazuh API | http://localhost:55000 | wazuh | *(see `.env`)* |
| OpenCTI | http://localhost:3000 | admin@opencti.io | *(see `.env`)* |
| TheHive | http://localhost:9000 | admin | *(see `.env`)* |
| MISP | http://localhost:9001 | admin@admin.test | *(see `.env`)* |
| DVWA | http://localhost:8890/dvwa | admin | password |
| Jenkins | http://localhost:9090 | admin | *(see `.env`)* |

Credentials are centralised in `.env` (gitignored). See `.env.backup-original` for the template.

---

## Troubleshooting

**Elasticsearch crashes (OOM / exit 137)**
```bash
# Check heap allocation — should be ≤ 50% of container memory limit
grep -E "Xms|Xmx" docker-compose.yml
# Increase WSL2 memory in .wslconfig and restart
```

**Wazuh agents disconnecting after restart**
```bash
bash enroll_missing_agents.sh
```

**Kibana not loading / OOM**
```bash
docker restart kibana
# Wait 60s for Elasticsearch to be fully ready before starting Kibana
```

**Stale Fleet agents**
```bash
bash cleanup_fleet_stale.sh
```

**ElastAlert2 zero hits**
```bash
docker logs elastalert --tail 50
# Verify index pattern and timestamp field in elastalert/config.yaml
```

---

## Contributing

Contributions, bug reports, and new detection rules are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/new-detection-rule`)
3. Add your rule under `elastalert/rules/` or `wazuh/rules/`
4. Test with `bash verify-soc-lab.sh`
5. Open a Pull Request

---

## Acknowledgements

- [Wazuh](https://wazuh.com) — HIDS/EDR platform
- [Elastic](https://elastic.co) — SIEM stack
- [MITRE ATT&CK](https://attack.mitre.org) — Threat framework
- [OpenCTI](https://opencti.io) — Threat intelligence platform
- [MISP](https://www.misp-project.org) — Malware information sharing
- [TheHive](https://thehive-project.org) — Incident response platform
- [Suricata](https://suricata.io) — Network IDS/IPS

---

*Built at Netdefender Casablanca — Sécurité IT & Confiance Numérique · 2025–2026*

